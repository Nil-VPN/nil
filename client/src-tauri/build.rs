fn main() {
    // Declare the app-embedded mobile VPN plugin (`nil-vpn`, the Kotlin `NilVpnPlugin` registered
    // at runtime via `register_android_plugin`). This generates its ACL permissions so the mobile
    // capability can grant `nil-vpn:default`, letting the WebView invoke `startVPN`/`stopVPN`.
    // The plugin has no Rust-side commands — its commands live in Kotlin/Swift — so we inline its
    // command list here for the ACL. `default_permission(AllowAllCommands)` makes `nil-vpn:default`
    // cover both commands (start + stop). Desktop builds ignore the mobile-scoped capability.
    let attributes = tauri_build::Attributes::new().plugin(
        "nil-vpn",
        tauri_build::InlinedPlugin::new()
            .commands(&["startVPN", "stopVPN", "statusVPN", "prepareVPN", "openVpnSettings"])
            .default_permission(tauri_build::DefaultPermissionRule::AllowAllCommands),
    );
    tauri_build::try_build(attributes).expect("failed to run tauri-build");

    sync_android_sources();
    sync_android_build_wiring();
    patch_android_manifest();
    sync_apple_sources();
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
        if path.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(true) {
            continue;
        }
        let Some(name) = path.file_name() else { continue };
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
                    println!("cargo:warning=failed to add nil-android apply() to build.gradle.kts: {e}");
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
        return; // Already patched.
    }

    // Foreground-service + notification permissions the VpnService needs (INTERNET is already in the
    // Tauri template). Inserted right after the opening <manifest …> tag.
    const PERMS: &str = "\n    <uses-permission android:name=\"android.permission.FOREGROUND_SERVICE\" />\n    <uses-permission android:name=\"android.permission.FOREGROUND_SERVICE_SPECIAL_USE\" />\n    <uses-permission android:name=\"android.permission.POST_NOTIFICATIONS\" />\n";
    // The VPN consent activity + the datapath VpnService. Inserted just before </application>.
    const APP_CHILDREN: &str = concat!(
        "\n        <!-- VPN consent handshake: VpnService.prepare() + system dialog, then starts the service.\n",
        "             exported so the app's Connect action (and the e2e harness) can launch it; carries only\n",
        "             a node endpoint, never identity. Invisible (translucent) — it just routes consent. -->\n",
        "        <activity\n",
        "            android:name=\"com.nilvpn.VpnConsentActivity\"\n",
        "            android:theme=\"@android:style/Theme.Translucent.NoTitleBar\"\n",
        "            android:exported=\"true\" />\n\n",
        "        <!-- NIL VPN datapath: the MASQUE tunnel runs in this VpnService (nil-android JNI engine). -->\n",
        "        <service\n",
        "            android:name=\"com.nilvpn.NilVpnService\"\n",
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
            println!("cargo:warning=AndroidManifest.xml has no <manifest> tag; VPN posture not injected");
            return;
        }
    };
    let patched = match with_perms.rfind("</application>") {
        Some(i) => {
            let (head, tail) = with_perms.split_at(i);
            format!("{head}{APP_CHILDREN}    {tail}")
        }
        None => {
            println!("cargo:warning=AndroidManifest.xml has no </application>; VPN posture not injected");
            return;
        }
    };
    if let Err(e) = std::fs::write(&path, patched) {
        println!("cargo:warning=failed to write patched AndroidManifest.xml: {e}");
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
        if path.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(true) {
            continue;
        }
        let Some(name) = path.file_name() else { continue };
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
