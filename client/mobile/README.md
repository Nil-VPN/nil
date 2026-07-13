# Mobile datapath boundary (iOS and Android)

Mobile packet handling runs in an operating-system VPN extension or service rather than the Tauri
app process:

- The **Tauri app process** owns UI, account authentication, encrypted pass storage, Coordinator
  redemption, trust selection, and connection lifecycle decisions. It does not handle user packets.
- On **iOS and macOS**, an `NEPacketTunnelProvider` owns `NEPacketTunnelFlow` and calls the shared
  Rust engine through the `nil-apple` C ABI.
- On **Android**, a private `VpnService` owns the TUN descriptor and calls the `nil-android` JNI
  library. Its tunnel socket is protected from routing back into the VPN.

The app redeems the bearer pass. The native process receives only the resolved endpoint, server
name, attestation/transparency inputs, and opaque per-connection grant and nonce; it does not receive
the account secret, payment context, auth seed, or bearer pass.

## Current status (2026-07-12)

The native engine currently implements one hop. A packaged non-debug client requires a multi-hop
profile and therefore returns `NativeMultiHopUnavailable` before pass removal or Coordinator
redemption. The one-hop implementation is a debug/device-integration harness, not a release mode.
That native IPC/FFI also lacks the complete TDX workload-policy fields, so TDX is rejected before
engine startup; the attested one-hop harness is SEV-SNP-only and never falls back to raw MRTD.
The SEV-SNP path does carry the Coordinator's stable TLS-SPKI identity, complete optional
minimum-TCB floor (FMC plus bootloader/TEE/SNP/microcode components), and independently checked
transparency key through both native bridges; malformed or contradictory policy fails closed.
Apple applies the negotiated ADDRESS_ASSIGN value and bounds its copied-packet queue. Android's
one-phase `VpnService` ABI cannot re-address an established TUN, so it currently requires the first
pool address (`10.74.0.2`) and rejects any other/missing assignment instead of claiming success.

The repository contains the Rust, Swift, Kotlin, Tauri-plugin, manifest, entitlement, and build
scaffolding. That is source/compile evidence only. It does not establish signed installation,
extension activation, multi-hop traffic, leak behavior, provider-death blocking, lifecycle behavior,
or distribution approval on a current physical device.

## Routing and persistent blocking

The service/provider installs IPv4 and IPv6 default routes while active. The current engine carries
IPv4; captured IPv6 is intentionally dropped rather than allowed to bypass the tunnel. Persistent
blocking when the VPN process is not active also depends on OS policy—Android Always-on plus Block
connections without VPN, or the applicable Apple Always-on/on-demand configuration. The app cannot
silently guarantee those system-wide settings.

Native multi-hop and retained physical-device evidence are required before removing the release
refusal. Use the platform-specific records for the future acceptance work:

- [Android implementation](../../crates/nil-android/README.md) and
  [device record](../../crates/nil-android/DEVICE_VERIFY.md)
- [Apple implementation](../../crates/nil-apple/README.md),
  [iOS record](../../crates/nil-apple/DEVICE_VERIFY.md), and
  [macOS record](../../crates/nil-apple/MACOS_DEVICE_VERIFY.md)
