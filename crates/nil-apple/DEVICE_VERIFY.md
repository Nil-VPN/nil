# iOS device-verification record (Epic 9)

> **Current status (2026-07-12): compile/scaffold evidence only; no device or production
> validation.** The shared Apple native engine supports one hop as a debug/integration harness. A
> packaged non-debug client refuses with `NativeMultiHopUnavailable` before removing a pass from
> the encrypted vault or contacting the Coordinator. Signing and device wiring alone cannot make
> the current release path connect.

## Evidence currently present

The tree contains the Rust C ABI and generated header, `PacketTunnelProvider.swift`, the iOS Tauri
plugin, plist/entitlement templates, and Rust plugin registration. Earlier local work reported an
`aarch64-apple-ios` static-library build and Swift parsing against the then-installed Tauri sources.
No signed app/appex artifact, retained build log, physical-device activation record, packet trace,
leak result, or live-node record is attached here. Treat those reports as implementation history,
not current runtime evidence.

The client stores auth material and bearer passes in its encrypted vault with a device-bound Apple
Keychain key. The container app owns Coordinator redemption; the packet-tunnel provider receives
only the resolved endpoint, trust inputs, and opaque grant/nonce.

## Prerequisites for a future device run

1. Native multi-hop implemented and the non-debug refusal removed through security review.
2. A valid Apple Developer signing/provisioning setup with the packet-tunnel entitlement available
   to both the app and extension targets as required.
3. A physical iPhone or iPad and retained access to the exact release-candidate source and signed
   artifacts. Simulator or compile-only evidence does not satisfy the network checks.

## Build the engine xcframework

```sh
rustup target add aarch64-apple-ios
export IPHONEOS_DEPLOYMENT_TARGET=15.0 CMAKE_POLICY_VERSION_MINIMUM=3.5
NIL_APPLE_WITH_IOS=1 bash client/apple/build-engine.sh release
# Produces client/apple/NilApple.xcframework with the iOS device slice.
```

The crate build script regenerates `include/nil_apple.h`; import that header from the extension's
bridging header. Record the Rust, Xcode, SDK, and macOS versions plus the xcframework hash.

## Wire the generated Xcode project

`pnpm --dir client tauri ios init` creates `client/src-tauri/gen/apple/project.yml`. The generated
tree is ignored and can be replaced, so any production integration should be automated or checked
after every regeneration.

1. Add `crates/nil-apple/apple/NilVpnPlugin.swift` to the app target and link the Tauri Swift
   package so the Rust `register_ios_plugin` call resolves `init_nil_vpn_plugin`.
2. Merge `apple/App-iOS.entitlements` into the app entitlements.
3. Add the Packet Tunnel app-extension target with `apple/PacketTunnelProvider.swift`, the bridging
   header, `PacketTunnel-iOS-Info.plist`, `PacketTunnel-iOS.entitlements`, the iOS device slice of
   `NilApple.xcframework`, and the required Apple frameworks.
4. Embed the extension in the container app. The container app does not link the native engine.
5. Configure signing through untracked local or CI-managed settings; do not commit credentials or
   provisioning secrets.

This is a build recipe, not a record that the generated app or extension has run.

## Leak and persistent-blocking model

The provider's network settings capture the IPv4 and IPv6 default routes. The current engine carries
IPv4, so captured IPv6 is intentionally dropped rather than routed around the tunnel. The container
plugin sets `includeAllNetworks` on `NETunnelProviderProtocol`.

Persistent blocking when the provider is not running also depends on Apple OS policy and user/MDM
configuration. The app must describe that boundary honestly; it cannot claim that an in-process
flag silently enforces a system-wide Always-on policy.

## Future device acceptance record

After the prerequisites above are satisfied, retain sanitized logs and the signed artifact hashes
for each result:

1. The app and extension install and activate with the expected bundle identifiers, entitlements,
   App Group, and signing chain.
2. Permission/activation preflight occurs before the native connection path, so a request that
   cannot start leaves the pass count unchanged and sends no Coordinator redemption request.
3. A connection uses the required multi-hop path and validates its measurement and transparency
   inputs; malformed, synthetic, unpinned, or transparency-invalid evidence fails closed.
4. IPv4, IPv6, and DNS checks show the intended node exit or an intentional blackhole, never the
   device's clear-network address.
5. Killing the provider or node does not permit clear-network fallback, and the UI reports the
   actual disconnected/blocked state.
6. Memory remains within the Network Extension budget under sustained traffic; sleep/wake and
   Wi-Fi/mobile handoff do not leak or leave a false connected state.

| Date | Commit/artifact | Device/iOS | Activation | Multi-hop/trust | v4/v6/DNS | Provider death | Memory/lifecycle | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _pending_ | | | | | | | | |
