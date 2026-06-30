# iOS — on-device verification (Epic 9)

> **Status: authored, NOT verified on a device.** The `nil-apple` engine (Rust C-ABI) and
> `apple/PacketTunnelProvider.swift` are in-tree, but a NEPacketTunnelProvider cannot run in the
> Simulator and the Swift cannot be compiled here (no Xcode on the dev host). Everything below must
> be done on a Mac with Xcode + an enrolled Apple org + a physical device before iOS ships. Until
> then the README keeps the honest "iOS unverified" caveat.

## Prerequisites (the long pole)
1. **Apple Developer *organization* enrollment** (D-U-N-S + legal entity) — the
   `com.apple.developer.networking.networkextension` = `[packet-tunnel-provider]` entitlement
   requires it and is discretionary (email networkextension@apple.com). Weeks of latency.
2. A physical iPhone/iPad (packet tunnels don't run in the Simulator).

## Build
```
rustup target add aarch64-apple-ios
cargo build -p nil-apple --target aarch64-apple-ios --release   # HIGHEST-RISK step: quiche/BoringSSL
                                                              # must cross-compile for the iOS sysroot
```
The crate's `build.rs` runs cbindgen → `include/nil_apple.h`; wire that as the appex's bridging header.
Add the **PacketTunnel appex** target in Xcode, link `libnil_apple.a` + `NetworkExtension.framework`
(+ `Security`, `libc++`, `libresolv`). The container app does **not** link the staticlib.

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
  that didn't exist; it was removed (see `client/src-tauri/src/extension.rs`). The container-app
  `includeAllNetworks` wiring + the settings deep-link are the remaining iOS work — do NOT re-add the
  StartArg.

## Verify on device (pass/fail)
1. Redeem a token in the app → it writes `providerConfiguration` (node host/port, `measurementHex`,
   `teeName`, `grantHex`/`grantNonceHex`) → start the tunnel.
2. **No DNS / IP leak:** `dig +short myip.opendns.com @208.67.222.222` (or a v6 lookup) returns the
   **node exit IP**, never the device's real v4/v6 address.
3. **Kill-switch holds:** kill the provider process (or drop connectivity); confirm no traffic flows
   in the clear and the app surfaces Disconnected.
4. **Memory:** provider stays under the NE memory budget (~15 MB) in Instruments.
5. Record the result here. Only then drop the README's "iOS unverified" caveat.
