# nil-apple

The Apple native engine for NIL VPN. It is a C-ABI static library linked into an
`NEPacketTunnelProvider` and shared by the iOS app extension and macOS system extension. Packet I/O
is callback-driven through `NEPacketTunnelFlow`: Swift passes inbound packets to
`nil_ingest_packets`, and Rust returns outbound packets through the registered write callback. The
crate reuses the MASQUE transport without depending on `nil-datapath` or a TUN fd.

The account identifier, payment context, auth seed, and bearer Privacy Pass do not enter the packet
tunnel provider. The container app redeems the pass and gives the provider only the node endpoint,
server name, attestation inputs, and opaque per-connection grant/nonce. As with any VPN, the selected
node can still observe the client's network address and traffic metadata.

## Current status (2026-07-12)

- The repository contains the Rust C ABI/header, shared packet-tunnel provider, iOS Tauri plugin,
  app/extension plist and entitlement templates, and macOS XcodeGen scaffolding. A clean unsigned
  System Extension build now passes with macOS 13.0 encoded in representative native C++/assembly
  archive members, the final Mach-O, and the bundle plist. This remains build evidence only.
- The client vault encrypts auth material and bearer passes with a device-bound key held in Apple
  Keychain. The bearer pass stays in the container app during redemption; the provider receives the
  resulting grant rather than the pass.
- The native engine currently implements one hop only. Packaged non-debug clients deliberately
  return `NativeMultiHopUnavailable` before removing a pass from the vault or contacting the
  Coordinator. The one-hop path is a debug/integration harness, not a releasable connection mode.
- The current Swift/C ABI does not carry NIL's complete TDX workload policy. The app bridge and
  native entry point reject TDX before engine startup; the debug attested harness is SEV-SNP-only
  rather than falling back to raw MRTD.
- For SEV-SNP, `tlsSpkiSha256Hex` and `minTcbSevsnp` carry the stable TLS identity and optional FMC
  plus bootloader/TEE/SNP/microcode floor through the private Tauri arguments and provider
  configuration into the C ABI and `AttestExpectation`. Malformed values and any policy paired with
  unattested mode fail closed. Host Rust tests cover serialization/conversion and the Swift bridge
  sources parse; an Xcode target build, signed-extension run, and physical-device conformance remain
  outstanding.
- After attestation, the provider reads the node's ADDRESS_ASSIGN value before installing its IPv4
  network settings. The Rust ingress queue is bounded to 256 packets with a non-identifying
  saturating drop counter exposed through the C ABI; overload drops instead of growing memory.
- Neither iOS nor macOS has current device/live-tunnel or production validation. A successful Rust,
  Swift, Xcode, or unsigned-extension build does not establish activation, traffic, leak,
  kill-switch, lifecycle, memory, signing, notarization, or App Store behavior.

See `DEVICE_VERIFY.md` and `MACOS_DEVICE_VERIFY.md` for future acceptance runbooks and clearly
labelled historical observations.

## Build the engine

```sh
# Host build: validates the Rust C ABI and regenerates include/nil_apple.h.
cargo build -p nil-apple

# iOS device slice.
rustup target add aarch64-apple-ios
export IPHONEOS_DEPLOYMENT_TARGET=15.0 CMAKE_POLICY_VERSION_MINIMUM=3.5
NIL_APPLE_WITH_IOS=1 bash client/apple/build-engine.sh release

# macOS slices are produced by the same script/toolchain setup.
rustup target add aarch64-apple-darwin x86_64-apple-darwin
bash client/apple/build-engine.sh release

# Clean unsigned System Extension acceptance, including native/final minimum-OS gates.
bash deploy/verify-macos-se-build.sh
```

The generated `client/apple/NilApple.xcframework` is a build input, not proof that either extension
has run. Pin the exact Rust/Xcode/macOS toolchain and retain artifact hashes for a release candidate.

## iOS project integration

`pnpm --dir client tauri ios init` creates the git-ignored XcodeGen project under
`client/src-tauri/gen/apple/`. The generated project must then include:

1. `apple/NilVpnPlugin.swift` in the container-app target, with the Tauri Swift package available so
   `init_nil_vpn_plugin` links to the Rust registration.
2. A Packet Tunnel app-extension target containing `apple/PacketTunnelProvider.swift`, a bridging
   header importing `nil_apple.h`, `PacketTunnel-iOS-Info.plist`, and
   `PacketTunnel-iOS.entitlements`.
3. The iOS device slice of `NilApple.xcframework` and the required Apple frameworks linked to the
   extension. The container app embeds the extension but does not link the engine static library.
4. The app entitlement values from `App-iOS.entitlements`, including the shared App Group used by
   the app and extension.
5. Valid signing/provisioning for the packet-tunnel entitlement and installation on physical
   hardware for runtime validation.

Generated-project wiring and signing do not remove the current non-debug multi-hop refusal.

## Validation still required

Native multi-hop must be implemented before a packaged Apple connection can be considered. After
that, validation must retain signed artifact hashes and cover extension activation, multi-hop
attestation/transparency checks, v4/v6/DNS leak behavior, provider-death blocking, OS Always-on
semantics, credential-consumption ordering, memory limits, sleep/wake and network handoff, signing,
notarization on macOS, and the applicable iOS distribution review path.
