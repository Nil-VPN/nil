// nil-android native build wiring (canonical source: crates/nil-android/android/nil-android.gradle.kts).
//
// Tauri's own `rust` Gradle plugin only builds the app WebView lib (`libnil_client_lib.so`). The VPN
// datapath engine `libnil_android.so` (crate `nil-android`, the `:vpn` process) is a SEPARATE cdylib
// and was historically a committed prebuilt binary — which can silently ship a stale engine that omits
// a fixed attestation/privacy bug (a PD-5 violation). This script builds it from source via cargo-ndk
// on every assemble, so `gradlew assemble` produces a complete, reproducible APK with no committed
// binaries.
//
// It is `apply(from = ...)`-d at the end of `app/build.gradle.kts`. Both this file and that one-line
// apply are kept in the gitignored `gen/` tree fresh by `client/src-tauri/build.rs` (so a clean
// `tauri android init` can't drop them). The canonical copy lives in git at
// `crates/nil-android/android/nil-android.gradle.kts`.
//
// Packaging decision (verified via `llvm-objdump -p`): `libnil_android.so` statically links quiche,
// tun_rs, dcap_qvl and libc++ (its only NEEDED libs are liblog/libdl/libm/libc), so cargo-ndk's
// incidental `libquiche*.so` / `libtun_rs*.so` / `libdcap_qvl*.so` cdylib artifacts are NOT shipped.
// `libc++_shared.so` IS shipped per-ABI (the Tauri WebView lib needs it; harmless for nil-android).

import org.gradle.api.tasks.Exec
import org.gradle.api.tasks.Copy

// ABIs we actually ship → (Android ABI dir, Rust target triple). Keep this in lockstep with the
// productFlavor abiFilters (arm64-v8a + x86_64). Building an ABI the flavors don't declare would
// just be wasted work; declaring an ABI we don't build here would UnsatisfiedLinkError at runtime.
val nilAbis = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "x86_64" to "x86_64-linux-android",
)

// Workspace root, relative to gen/android/app (../../../ reaches the repo root — same as `rust { rootDirRel }`).
val nilWorkspaceRoot = file("${projectDir}/../../../").canonicalFile
val nilJniLibsDir = file("${projectDir}/src/main/jniLibs")
// Build cargo-ndk output to a scratch dir so we copy ONLY libnil_android.so (not the incidental cdylibs).
val nilNdkOutDir = layout.buildDirectory.dir("nil-android-jni").get().asFile

// Resolve the NDK dir: env (ANDROID_NDK_HOME/NDK_HOME) first, else AGP's BaseExtension.ndkDirectory,
// else the highest-versioned ndk under the SDK (env ANDROID_HOME/ANDROID_SDK_ROOT or local.properties).
fun nilNdkDir(): String {
    System.getenv("ANDROID_NDK_HOME")?.let { if (it.isNotBlank()) return it }
    System.getenv("NDK_HOME")?.let { if (it.isNotBlank()) return it }
    (project.extensions.findByName("android") as? com.android.build.gradle.BaseExtension)
        ?.ndkDirectory?.takeIf { it.exists() }?.let { return it.absolutePath }
    val sdk = System.getenv("ANDROID_HOME")
        ?: System.getenv("ANDROID_SDK_ROOT")
        ?: file("${rootDir}/local.properties").takeIf { it.exists() }
            ?.readLines()?.firstOrNull { it.trim().startsWith("sdk.dir=") }
            ?.substringAfter("sdk.dir=")?.trim()
    val ndkRoot = sdk?.let { file("$it/ndk") }
    if (ndkRoot != null && ndkRoot.isDirectory) {
        ndkRoot.listFiles { f -> f.isDirectory }?.maxByOrNull { it.name }?.let { return it.absolutePath }
    }
    throw GradleException("nil-android: cannot locate the NDK (set ANDROID_NDK_HOME or android.ndkVersion).")
}

for (profile in listOf("debug", "release")) {
    val profileCap = profile.replaceFirstChar { it.uppercase() }
    val release = profile == "release"

    // One umbrella task per profile that builds + stages every shipped ABI.
    val stageAll = tasks.register("nilAndroidStage$profileCap") {
        group = "rust"
        description = "Build libnil_android.so (cargo-ndk) and stage it into jniLibs for all shipped ABIs ($profile)."
    }

    for ((abi, triple) in nilAbis) {
        val abiCap = abi.split("-", "_").joinToString("") { it.replaceFirstChar { c -> c.uppercase() } }

        val build = tasks.register<Exec>("nilAndroidBuild$abiCap$profileCap") {
            group = "rust"
            description = "cargo-ndk build of nil-android for $abi ($profile)."
            workingDir = nilWorkspaceRoot
            val ndk = nilNdkDir()
            environment("ANDROID_NDK_HOME", ndk)
            environment("NDK_HOME", ndk)
            // BoringSSL pins cmake_minimum_required(3.5); host cmake 4.x refuses it without this.
            environment("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
            // The Gradle daemon may not inherit a login shell PATH; ensure cargo + cargo-ndk resolve.
            val home = System.getProperty("user.home")
            environment("PATH", "${home}/.cargo/bin:${System.getenv("PATH") ?: ""}")
            val args = mutableListOf(
                "ndk", "-t", abi, "-P", "21", "-o", nilNdkOutDir.absolutePath,
                "build", "-p", "nil-android",
            )
            if (release) args.add("--release")
            commandLine(listOf("cargo") + args)
        }

        // Copy ONLY libnil_android.so out of the cargo-ndk output (drop the incidental cdylibs),
        // plus the NDK's libc++_shared.so for this ABI.
        val stage = tasks.register<Copy>("nilAndroidStage$abiCap$profileCap") {
            group = "rust"
            description = "Stage libnil_android.so + libc++_shared.so into jniLibs/$abi ($profile)."
            dependsOn(build)
            into(file("${nilJniLibsDir}/${abi}"))
            from("${nilNdkOutDir}/${abi}") { include("libnil_android.so") }
            val ndk = nilNdkDir()
            from(fileTree(ndk) { include("**/sysroot/usr/lib/${triple}/libc++_shared.so") }) {
                // fileTree preserves the deep path; flatten so it lands directly in jniLibs/<abi>/.
                eachFile { path = name }
                includeEmptyDirs = false
            }
        }
        stageAll.configure { dependsOn(stage) }
    }
}

// Hook into AGP's jniLibs merge so a normal assemble builds + stages the engine automatically.
// merge<Flavor><Profile>JniLibFolders is created lazily by AGP; wire up once it exists.
afterEvaluate {
    tasks.matching { it.name.matches(Regex("merge.*JniLibFolders")) }.configureEach {
        val t = name
        val profileCap = if (t.contains("Release")) "Release" else "Debug"
        dependsOn("nilAndroidStage$profileCap")
    }
}
