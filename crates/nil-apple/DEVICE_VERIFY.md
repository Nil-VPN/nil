# iOS — on-device verification (Epic 9)

> **Status: CODE-COMPLETE, NOT yet verified on a device.** In-tree and verified-as-far-as-possible
> headlessly: the `nil-apple` engine (Rust C-ABI) **compiles for `aarch64-apple-ios`**; the appex
> (`apple/PacketTunnelProvider.swift`); the container-app Tauri plugin (`apple/NilVpnPlugin.swift`,
> the five `nil-vpn` commands over `NETunnelProviderManager`) — **API-verified against the
> `tauri 2.11.3` Swift sources and parses clean**; the iOS appex/app Info.plist + entitlements; and
> the Rust registration (`tauri::ios_plugin_binding!(init_nil_vpn_plugin)` in `lib.rs`).
> `pnpm tauri ios init` generates the Xcode project (XcodeGen `project.yml`). What remains is purely
> device/Xcode-bound: wire the generated project (below), sign with an enrolled org, and run on a
> physical device. A NEPacketTunnelProvider does not run in the Simulator, so the datapath itself can
> only be validated on hardware. Until that passes, the README keeps the honest "iOS unverified" caveat.

## Prerequisites (the long pole)
1. **Apple Developer *organization* enrollment** (D-U-N-S + legal entity) — the
   `com.apple.developer.networking.networkextension` = `[packet-tunnel-provider]` entitlement
   requires it and is discretionary (email networkextension@apple.com). Weeks of latency.
2. A physical iPhone/iPad (packet tunnels don't run in the Simulator).

## Build the engine xcframework
```
rustup target add aarch64-apple-ios
export IPHONEOS_DEPLOYMENT_TARGET=15.0 CMAKE_POLICY_VERSION_MINIMUM=3.5
NIL_APPLE_WITH_IOS=1 bash client/apple/build-engine.sh release   # HIGHEST-RISK step: quiche/BoringSSL
#   → client/apple/NilApple.xcframework with the ios-arm64 slice (device only; no simulator slice —
#     the appex is device-only and quiche's BoringSSL asm is tagged iOS, not iOS-simulator).
```
The crate's `build.rs` runs cbindgen → `include/nil_apple.h`; wire that as the appex's bridging header.

## Wire the generated Xcode project (`gen/apple/project.yml`)
`pnpm tauri ios init` emits an XcodeGen `project.yml` with one app target (`nil-client_iOS`, sources
`Sources/`, links `libapp.a`). Two additions make the build complete (this tree is gitignored +
regenerated, so re-apply after a re-init — mirror Android's `build.rs` manifest patch if you automate it):

1. **Plugin into the app target.** Add `crates/nil-apple/apple/NilVpnPlugin.swift` to the app target's
   sources and make the `Tauri` Swift package importable by it (XcodeGen `packages:` → the
   `tauri/.../mobile/ios-api` package, then `dependencies: - package: Tauri` on the app target). This
   links the `init_nil_vpn_plugin` symbol that `libapp.a`'s `register_ios_plugin` call resolves.
   Merge `apple/App-iOS.entitlements` (the `packet-tunnel-provider` capability + `group.com.nilvpn.client`)
   into `nil-client_iOS/nil-client_iOS.entitlements`.

2. **PacketTunnel appex target.** Add a new `type: app-extension` target:
   - sources: `apple/PacketTunnelProvider.swift` + a bridging header that `#import "nil_apple.h"`
   - `info: PacketTunnel-iOS-Info.plist`, `entitlements: PacketTunnel-iOS.entitlements`
   - dependencies: the `ios-arm64` slice of `NilApple.xcframework` + `NetworkExtension.framework`
     (+ `Security`, `libc++`, `libresolv`); the container app **embeds** this appex and does NOT link
     the staticlib itself.

Then set `DEVELOPMENT_TEAM` (in an untracked local xcconfig) and sign.

## Kill-switch on iOS (honest)
- The **per-flow leak protection** is the network settings in `applySettingsAndRead`: IPv4 default
  route **and now the IPv6 default route** (the engine is IPv4-only, so v6 is captured into the
  tunnel and dropped — no ISP-IPv6 leak around the tunnel).
- **"Block traffic when the VPN *process* is down"** is the OS *Always-on VPN / "Block connections
  without VPN"* SYSTEM setting (backed by `includeAllNetworks` on the `NETunnelProviderProtocol`,
  set by the **container app** at install time — it is NOT readable/settable inside the provider).
  An app **cannot silently enable** this; it can only deep-link the user to the OS VPN settings
  (mirror Android's `openVpnSettings`), and the UI must say so honestly (PD-8). There is deliberately
  **no `block_without_vpn` StartArg** — an earlier one was hardcoded `true`, never read by the
  native side, and conflated with `setBlocking` (the fd's I/O mode), implying a configurable control
  that didn't exist; it was removed (see `client/src-tauri/src/extension.rs`). This is now WIRED:
  `NilVpnPlugin.startVpn` sets `proto.includeAllNetworks = true` on the `NETunnelProviderProtocol`,
  and `NilVpnPlugin.openVpnSettings` deep-links the user to Settings (iOS has no public deep-link to
  the VPN pane, so it opens the app's Settings page — the honest, App-Review-safe target). Do NOT
  re-add the StartArg.

## Verify on device (pass/fail)
1. Redeem a token in the app → it writes `providerConfiguration` (node host/port, `measurementHex`,
   `teeName`, `grantHex`/`grantNonceHex`) → start the tunnel.
2. **No DNS / IP leak:** `dig +short myip.opendns.com @208.67.222.222` (or a v6 lookup) returns the
   **node exit IP**, never the device's real v4/v6 address.
3. **Kill-switch holds:** kill the provider process (or drop connectivity); confirm no traffic flows
   in the clear and the app surfaces Disconnected.
4. **Memory:** provider stays under the NE memory budget (~15 MB) in Instruments.
5. Record the result here. Only then drop the README's "iOS unverified" caveat.
