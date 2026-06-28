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
            .commands(&["startVPN", "stopVPN"])
            .default_permission(tauri_build::DefaultPermissionRule::AllowAllCommands),
    );
    tauri_build::try_build(attributes).expect("failed to run tauri-build");

    sync_android_sources();
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
    let dst = manifest.join("gen/android/app/src/main/java/com/nilvpn");
    if !src.is_dir() || !dst.is_dir() {
        return; // No Android gen tree (e.g. a desktop build) — nothing to mirror.
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
        let target = dst.join(name);
        if target.exists() {
            if let Err(e) = std::fs::copy(&path, &target) {
                println!(
                    "cargo:warning=failed to sync canonical Android source {} into gen/: {e}",
                    name.to_string_lossy()
                );
            }
        }
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
