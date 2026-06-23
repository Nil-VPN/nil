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
}
