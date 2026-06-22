# Mobile datapath boundary (iOS + Android)

On mobile, the tunnel datapath cannot run inside the app's main process — it must live in a
platform **network-extension process** (architecture spec §9). The split:

- **Tauri app process** — UI, account/control, path selection, connect/disconnect. Never
  touches packets.
- **Network-extension process** — hosts the shared `nil-transport` datapath (the same
  `Transport` engine the desktop uses):
  - **iOS:** an `NEPacketTunnelProvider` app extension. The provider owns `packetFlow`; the
    Rust engine reads/writes IP packets through it via a small C FFI (staticlib).
  - **Android:** a `VpnService`. The OS hands it the TUN file descriptor via
    `VpnService.Builder.establish()`; the Rust engine (a JNI `cdylib`) reads/writes that fd.

## Status

- The reusable Rust engine (`nil-core` + `nil-transport`) **cross-compiles for
  `aarch64-apple-ios` and `aarch64-linux-android`** (`cargo check --target …`). The `Transport`
  seam, `connectip` framing, and the cascade controller are platform-agnostic and ready to host.
- The **native extension code** (Swift `NEPacketTunnelProvider`, Kotlin `VpnService`), the
  app↔extension IPC, code-signing/entitlements, and the QUIC/BoringSSL cross-build for the
  mobile targets are the **heavier lift** flagged in spec §9. They require Xcode (iOS) and the
  Android SDK + NDK to build, plus an Apple Developer org account + the Network Extension
  entitlement for iOS — so they are not buildable in a desktop CI and are tracked separately.

The OS owns routing/DNS/kill-switch on both platforms (the `Builder` / `NEPacketTunnelNetworkSettings`),
so the desktop `NetControl` layer is replaced by OS configuration there; only the packet pump
and the `Transport` engine carry over.
