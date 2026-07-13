#[path = "trust_bundle.rs"]
mod trust_bundle;

fn main() {
    embed_release_trust_bundle();

    // Declare the app-embedded mobile VPN plugin (`nil-vpn`, the Kotlin `NilVpnPlugin` registered
    // at runtime via `register_android_plugin`). Its Kotlin/Swift commands are declared for mobile
    // dispatch, but deliberately receive NO default WebView permission: Rust retains the private
    // PluginHandle and enforces consent, ID-bound completion, and status itself. In particular,
    // bearer grants never cross JavaScript.
    let attributes = tauri_build::Attributes::new()
        .plugin(
            "nil-vpn",
            tauri_build::InlinedPlugin::new()
                // camelCase with title-case acronyms (Vpn, not VPN): Tauri's mobile plugin dispatch
                // lowercases a trailing all-caps acronym (startVPN → startVpn) when matching the Kotlin
                // @Command, so the command names MUST be the already-lowercased form or dispatch fails
                // at runtime with "No command … found" (the @Command methods match these verbatim).
                .commands(&[
                    "startVpn",
                    "stopVpn",
                    "statusVpn",
                    "prepareVpn",
                    "openVpnSettings",
                ]),
        )
        // Private Android secure-vault bridge. Intentionally NO default permission: JavaScript has
        // no ACL route to raw vault plaintext; only the Rust-held PluginHandle invokes it.
        .plugin(
            "nil-secure-store",
            tauri_build::InlinedPlugin::new().commands(&["seal", "open", "destroyKey"]),
        );
    tauri_build::try_build(attributes).expect("failed to run tauri-build");

    sync_android_sources();
    sync_android_secure_store_resources();
    sync_android_build_wiring();
    patch_android_manifest();
    patch_android_backup_posture();
    sync_apple_sources();
}

/// Validate and embed the independently published client trust roots.
///
/// A release-profile build without these roots would silently restore trust in values served by
/// the Portal/Coordinator. Refuse that artifact at build time. Debug builds retain the local-dev
/// behavior, but if a developer supplies a bundle it is held to the same validation rules.
fn embed_release_trust_bundle() {
    const INPUT: &str = "NIL_TRUST_BUNDLE_JSON";
    const EMBEDDED: &str = "NIL_EMBEDDED_TRUST_BUNDLE_JSON";

    println!("cargo:rerun-if-env-changed={INPUT}");
    println!("cargo:rerun-if-changed=trust_bundle.rs");

    let profile = std::env::var("PROFILE").unwrap_or_default();
    // Cargo currently reports the inherited base (`release`) in PROFILE for a named custom
    // profile. OUT_DIR retains the actual profile directory (`target/e2e/build/.../out`), so use
    // that exact component as the fallback discriminator rather than broadly exempting optimized
    // builds or trusting a user-controlled runtime flag.
    let e2e_profile = profile == "e2e"
        || std::env::var_os("OUT_DIR").is_some_and(|out_dir| {
            std::path::Path::new(&out_dir)
                .ancestors()
                .nth(3)
                .and_then(std::path::Path::file_name)
                .is_some_and(|name| name == "e2e")
        });
    // `e2e` is the one reviewed local-integration profile: it is optimized but deliberately keeps
    // debug assertions so loopback + dynamic local Portal keys remain available. Every other
    // optimized/custom profile is treated like release and must embed reviewed production roots.
    let release_profile = !e2e_profile
        && (profile == "release" || std::env::var("DEBUG").is_ok_and(|debug| debug == "false"));
    let supplied = std::env::var(INPUT)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let Some(raw) = supplied else {
        if release_profile {
            panic!(
                "release client builds require {INPUT}; provide the reviewed trust-bundle v1 JSON"
            );
        }
        // Give `option_env!` one stable value in debug builds and do not inherit a runtime env var.
        println!("cargo:rustc-env={EMBEDDED}=");
        return;
    };

    let validated = trust_bundle::validate_trust_bundle_json(&raw)
        .unwrap_or_else(|error| panic!("{INPUT} is invalid: {error}"));
    nil_crypto::token::Verifier::from_public_ders(&validated.issuer_public_keys_der)
        .unwrap_or_else(|error| {
            panic!("{INPUT} contains an unusable token issuer DER key: {error}")
        });

    // `canonical_json` is one line, so it is safe as a Cargo directive value and produces the same
    // embedded bytes regardless of whitespace in the repository variable.
    println!("cargo:rustc-env={EMBEDDED}={}", validated.canonical_json);
}

/// Mirror the canonical Android/Kotlin VPN sources (`crates/nil-android/android/*.kt`) into the
/// gitignored `gen/android/...` tree that Tauri generates and Gradle actually compiles into the APK.
///
/// Without this, the two diverge silently: a fix to the canonical file (e.g. removing a logcat line
/// that leaked the node address) would never reach the shipped APK until someone re-ran the manual
/// sync, and `tauri android init` would happily regenerate the OLD code. That is a real privacy
/// foot-gun — a fail-closed control must not depend on a developer remembering a `cp`. Running it
/// here means every `cargo`/`tauri android build` re-mirrors the canonical sources first.
///
/// Best-effort and never fatal: a desktop build has no `gen/android` tree, so we no-op when the
/// target directory is absent, and a copy error only emits a `cargo:warning` (it never fails the
/// build). We only overwrite files the gen tree already contains — Tauri owns the tree's shape.
fn sync_android_sources() {
    let manifest = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let src = manifest.join("../../crates/nil-android/android");
    // The gen tree exists iff Tauri's java root is present (`tauri android init` has been run). We
    // key on that, not on the `com/nilvpn` package dir — a FRESH init has no `com/nilvpn/*.kt` yet,
    // so we must CREATE them, not only refresh existing ones. (A plain desktop build has no gen tree
    // at all → no-op.)
    let java_root = manifest.join("gen/android/app/src/main/java");
    if !src.is_dir() || !java_root.is_dir() {
        return; // No Android gen tree (e.g. a desktop build) — nothing to mirror.
    }
    let dst = java_root.join("com/nilvpn");
    if let Err(e) = std::fs::create_dir_all(&dst) {
        println!("cargo:warning=cannot create gen com/nilvpn dir: {e}");
        return;
    }
    let entries = match std::fs::read_dir(&src) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("kt") {
            continue;
        }
        // Only mirror regular files. A symlink in the (developer-committed) source tree is never a
        // legitimate .kt source; following one could copy unintended content into the build, so skip
        // it rather than follow it (defense-in-depth).
        if path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true)
        {
            continue;
        }
        let Some(name) = path.file_name() else {
            continue;
        };
        // Re-run this build script whenever a canonical Kotlin source changes, so the gen copy is
        // refreshed on the next build instead of being skipped by cargo's freshness cache.
        println!("cargo:rerun-if-changed={}", path.display());
        // Create-or-overwrite: a fresh `tauri android init` has none of these yet, and a later build
        // must refresh them (anti-stale). Either way the canonical source wins.
        if let Err(e) = std::fs::copy(&path, dst.join(name)) {
            println!(
                "cargo:warning=failed to sync canonical Android source {} into gen/: {e}",
                name.to_string_lossy()
            );
        }
    }
}

/// Copy the canonical no-backup rules into the generated Android project. Credentials are already
/// encrypted, but cloud/device-transfer backups would separate the vault from its non-exportable
/// Keystore key and can preserve pre-migration plaintext files. The whole app-private tree is
/// therefore excluded and `allowBackup=false` is injected below.
fn sync_android_secure_store_resources() {
    let manifest = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let src = manifest.join("../../crates/nil-android/android/res/xml");
    let dst = manifest.join("gen/android/app/src/main/res/xml");
    if !src.is_dir() || !manifest.join("gen/android/app/src/main/res").is_dir() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(&dst) {
        println!("cargo:warning=cannot create generated Android xml resource dir: {e}");
        return;
    }
    for name in ["nil_backup_rules.xml", "nil_backup_rules_legacy.xml"] {
        let source = src.join(name);
        println!("cargo:rerun-if-changed={}", source.display());
        if let Err(e) = std::fs::copy(&source, dst.join(name)) {
            println!("cargo:warning=failed to sync Android backup rule {name}: {e}");
        }
    }
}

/// Keep the `nil-android` native-build Gradle wiring fresh in the gitignored `gen/android/` tree.
///
/// Tauri's own `rust` Gradle plugin builds only the app WebView lib (`libnil_client_lib.so`). The VPN
/// datapath engine `libnil_android.so` is a SEPARATE cdylib (the `:vpn` process) that must also be
/// built from source — never shipped as a committed prebuilt binary, which could silently carry a
/// stale engine that omits a fixed attestation/privacy fix (a PD-5 violation). The canonical
/// `nil-android.gradle.kts` (git-tracked) runs `cargo ndk -p nil-android` per shipped ABI and stages
/// the result into `jniLibs/`. This mirror copies it into `gen/` and ensures `app/build.gradle.kts`
/// applies it — so a clean `tauri android init` (which regenerates `gen/`) cannot drop the wiring.
///
/// Best-effort and never fatal, exactly like [`sync_android_sources`]: no-ops when there is no
/// `gen/android` tree (a desktop build), and any IO error only emits a `cargo:warning`.
fn sync_android_build_wiring() {
    let manifest = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let src = manifest.join("../../crates/nil-android/android/nil-android.gradle.kts");
    let app_dir = manifest.join("gen/android/app");
    if !src.is_file() || !app_dir.is_dir() {
        return; // No Android gen tree (e.g. a desktop build) — nothing to wire.
    }
    println!("cargo:rerun-if-changed={}", src.display());

    // 1. Mirror the canonical Gradle script into the generated app module.
    let dst = app_dir.join("nil-android.gradle.kts");
    if let Err(e) = std::fs::copy(&src, &dst) {
        println!("cargo:warning=failed to sync nil-android.gradle.kts into gen/: {e}");
        return;
    }

    // 2. Ensure `app/build.gradle.kts` applies it (idempotent — append once if missing). Tauri's
    //    generated build.gradle.kts ends with its own `apply(from = "tauri.build.gradle.kts")`, so a
    //    trailing apply line is safe to add and survives until the next `tauri android init`.
    let build_gradle = app_dir.join("build.gradle.kts");
    let apply_line = "apply(from = \"nil-android.gradle.kts\")";
    match std::fs::read_to_string(&build_gradle) {
        Ok(contents) => {
            if !contents.contains("nil-android.gradle.kts") {
                let appended = format!("{contents}\n{apply_line}\n");
                if let Err(e) = std::fs::write(&build_gradle, appended) {
                    println!(
                        "cargo:warning=failed to add nil-android apply() to build.gradle.kts: {e}"
                    );
                }
            }
        }
        Err(e) => println!("cargo:warning=cannot read gen build.gradle.kts: {e}"),
    }

    // 3. Pin the shipped ABI set. `RustPlugin.kt` reads `abiList`/`archList`/`targetList` gradle
    //    properties (index-aligned) and otherwise defaults to all four ABIs. We ship only the two
    //    that matter — arm64-v8a (real phones) and x86_64 (emulators) — and `nil-android.gradle.kts`
    //    builds exactly those, so declaring all four would package an `armeabi-v7a`/`x86` slice that
    //    has `libnil_client_lib.so` but NO `libnil_android.so` → UnsatisfiedLinkError in the :vpn
    //    process on those ABIs. Keeping declared == produced is the fix. Maintained here so a clean
    //    `tauri android init` (which regenerates gradle.properties) can't reintroduce the mismatch.
    let gradle_props = match app_dir.parent() {
        Some(root) => root.join("gradle.properties"),
        None => return,
    };
    const ABI_PINS: &[&str] = &[
        "abiList=arm64-v8a,x86_64",
        "archList=arm64,x86_64",
        "targetList=aarch64,x86_64",
    ];
    if let Ok(props) = std::fs::read_to_string(&gradle_props) {
        let mut out = props.clone();
        for pin in ABI_PINS {
            let key = pin.split('=').next().unwrap_or("");
            // Only add if the key is absent (don't fight an explicit user override).
            let already = out.lines().any(|l| {
                let t = l.trim_start();
                !t.starts_with('#') && t.split('=').next().map(str::trim) == Some(key)
            });
            if !already {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(pin);
                out.push('\n');
            }
        }
        if out != props {
            if let Err(e) = std::fs::write(&gradle_props, out) {
                println!("cargo:warning=failed to pin ABI list in gradle.properties: {e}");
            }
        }
    }
}

/// Ensure the VPN posture (FGS permissions, `VpnConsentActivity`, `NilVpnService`) is present in the
/// generated `AndroidManifest.xml`. `tauri android init` regenerates the manifest from Tauri's
/// template WITHOUT these, so a regeneration would silently strip the VpnService declaration and the
/// app would become a no-op VPN. This idempotently re-injects them on every build.
///
/// Idempotent via a marker (`com.nilvpn.NilVpnService`): if the service is already declared, do
/// nothing. Best-effort and never fatal — no-ops without a `gen/android` tree, warns on IO error.
fn patch_android_manifest() {
    let manifest = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let path = manifest.join("gen/android/app/src/main/AndroidManifest.xml");
    if !path.is_file() {
        return; // No Android gen tree — nothing to patch.
    }
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            println!("cargo:warning=cannot read gen AndroidManifest.xml: {e}");
            return;
        }
    };
    if contents.contains("com.nilvpn.NilVpnService") {
        // A generated tree may already contain the old exported activity from an earlier build.
        // Harden it in place instead of returning early, otherwise the secure source constant or
        // separate-process privacy boundary would never reach a stale manifest.
        let old = "android:name=\"com.nilvpn.VpnConsentActivity\"\n            android:theme=\"@android:style/Theme.Translucent.NoTitleBar\"\n            android:exported=\"true\"";
        let new = "android:name=\"com.nilvpn.VpnConsentActivity\"\n            android:theme=\"@android:style/Theme.Translucent.NoTitleBar\"\n            android:exported=\"false\"";
        let mut hardened = contents.replace(old, new);
        let service_name = "android:name=\"com.nilvpn.NilVpnService\"";
        if !hardened.contains("android:process=\":vpn\"") {
            hardened = hardened.replace(
                service_name,
                concat!(
                    "android:name=\"com.nilvpn.NilVpnService\"\n",
                    "            android:process=\":vpn\"",
                ),
            );
        }
        if hardened != contents {
            if let Err(e) = std::fs::write(&path, hardened) {
                println!("cargo:warning=failed to harden existing VPN manifest: {e}");
            }
        }
        return;
    }

    // Foreground-service + notification permissions the VpnService needs (INTERNET is already in the
    // Tauri template). Inserted right after the opening <manifest …> tag.
    const PERMS: &str = "\n    <uses-permission android:name=\"android.permission.FOREGROUND_SERVICE\" />\n    <uses-permission android:name=\"android.permission.FOREGROUND_SERVICE_SPECIAL_USE\" />\n    <uses-permission android:name=\"android.permission.POST_NOTIFICATIONS\" />\n";
    // The VPN consent activity + the datapath VpnService. Inserted just before </application>.
    const APP_CHILDREN: &str = concat!(
        "\n        <!-- VPN consent handshake: VpnService.prepare() + system dialog, then starts the service.\n",
        "             non-exported so only the NIL app can launch it; debug e2e uses a separate test manifest.\n",
        "             a node endpoint, never identity. Invisible (translucent) — it just routes consent. -->\n",
        "        <activity\n",
        "            android:name=\"com.nilvpn.VpnConsentActivity\"\n",
        "            android:theme=\"@android:style/Theme.Translucent.NoTitleBar\"\n",
        "            android:exported=\"false\" />\n\n",
        "        <!-- NIL VPN datapath: the MASQUE tunnel runs in this VpnService (nil-android JNI engine).\n",
        "             android:process=\":vpn\" puts it in a SEPARATE process that loads only libnil_android\n",
        "             (no WebView, no reqwest, no token/identity code — PD-3: no identity in the data plane).\n",
        "             Only a node endpoint + measurement + opaque grant cross to it via Intent extras. -->\n",
        "        <service\n",
        "            android:name=\"com.nilvpn.NilVpnService\"\n",
        "            android:process=\":vpn\"\n",
        "            android:permission=\"android.permission.BIND_VPN_SERVICE\"\n",
        "            android:foregroundServiceType=\"specialUse\"\n",
        "            android:exported=\"false\">\n",
        "            <intent-filter>\n",
        "                <action android:name=\"android.net.VpnService\" />\n",
        "            </intent-filter>\n",
        "            <property\n",
        "                android:name=\"android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE\"\n",
        "                android:value=\"vpn\" />\n",
        "        </service>\n",
    );

    // Inject perms after the opening <manifest …> tag, and the app children before </application>.
    // The end of the <manifest> opening tag is the first '>' AFTER the literal "<manifest" — NOT the
    // first '>' in the file, which closes the `<?xml …?>` declaration (inserting there would put the
    // <uses-permission> elements outside the root and break the manifest merger).
    let manifest_open_end = contents
        .find("<manifest")
        .and_then(|s| contents[s..].find('>').map(|e| s + e + 1));
    let with_perms = match manifest_open_end {
        Some(i) => {
            let (head, tail) = contents.split_at(i);
            format!("{head}{PERMS}{tail}")
        }
        None => {
            println!(
                "cargo:warning=AndroidManifest.xml has no <manifest> tag; VPN posture not injected"
            );
            return;
        }
    };
    let patched = match with_perms.rfind("</application>") {
        Some(i) => {
            let (head, tail) = with_perms.split_at(i);
            format!("{head}{APP_CHILDREN}    {tail}")
        }
        None => {
            println!(
                "cargo:warning=AndroidManifest.xml has no </application>; VPN posture not injected"
            );
            return;
        }
    };
    if let Err(e) = std::fs::write(&path, patched) {
        println!("cargo:warning=failed to write patched AndroidManifest.xml: {e}");
    }
}

/// Disable Android backup/restore and point both old and new platform APIs at explicit exclusion
/// rules. This is separate from `patch_android_manifest` so it also hardens already-generated trees
/// that contain the VPN service marker and take that function's idempotent early return.
fn patch_android_backup_posture() {
    let manifest = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let path = manifest.join("gen/android/app/src/main/AndroidManifest.xml");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return;
    };
    if contents.contains("android:allowBackup=") {
        return;
    }
    let Some(start) = contents.find("<application") else {
        println!("cargo:warning=AndroidManifest.xml has no <application> tag; backup not disabled");
        return;
    };
    let insertion = start + "<application".len();
    let (head, tail) = contents.split_at(insertion);
    let attributes = concat!(
        "\n        android:allowBackup=\"false\"",
        "\n        android:fullBackupContent=\"@xml/nil_backup_rules_legacy\"",
        "\n        android:dataExtractionRules=\"@xml/nil_backup_rules\"",
    );
    if let Err(e) = std::fs::write(&path, format!("{head}{attributes}{tail}")) {
        println!("cargo:warning=failed to disable Android backup: {e}");
    }
}

/// Mirror the canonical Apple/Swift sources (`crates/nil-apple/apple/*.swift` — the
/// `NEPacketTunnelProvider` and the system-extension control bridge) into the gitignored
/// `gen/apple/...` tree, if one exists. Same rationale and privacy foot-gun as
/// [`sync_android_sources`]: a fix to a canonical Swift source (e.g. removing a leak) must not depend
/// on a developer remembering a `cp`, and a regenerated project must not resurrect stale code.
///
/// Best-effort and never fatal: a plain `cargo`/desktop build has no `gen/apple` tree (Tauri has no
/// macOS system-extension generator today — the SE is built from a standalone Xcode project whose
/// sources point directly at `crates/nil-apple/apple/`), so this no-ops when the target is absent.
fn sync_apple_sources() {
    let manifest = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let src = manifest.join("../../crates/nil-apple/apple");
    // The Tauri-generated Apple project's packet-tunnel target source dir, when one exists.
    let dst = manifest.join("gen/apple/PacketTunnel");
    if !src.is_dir() || !dst.is_dir() {
        return; // No Apple gen tree (desktop build, or the standalone Xcode project is used) — no-op.
    }
    let entries = match std::fs::read_dir(&src) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("swift") {
            continue;
        }
        // A symlink in the committed source tree is never a legitimate .swift source — skip, don't
        // follow it (defense-in-depth, mirrors the Android sync).
        if path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(true)
        {
            continue;
        }
        let Some(name) = path.file_name() else {
            continue;
        };
        println!("cargo:rerun-if-changed={}", path.display());
        let target = dst.join(name);
        if target.exists() {
            if let Err(e) = std::fs::copy(&path, &target) {
                println!(
                    "cargo:warning=failed to sync canonical Apple source {} into gen/: {e}",
                    name.to_string_lossy()
                );
            }
        }
    }
}
