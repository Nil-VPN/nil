# Android — on-device verification (Epic 9)

> **Status: authored, NOT verified on a device.** The `nil-android` JNI engine (Rust) and the Kotlin
> in `android/*.kt` are in-tree, but the Kotlin/APK cannot be built here (no Android SDK/NDK on the
> dev host). Verify on a real device with the SDK before Android ships.

## Leak protection (what enforces no-leak on Android)
On Android the **routes are the kill-switch**: `NilVpnService` routes both `0.0.0.0/0` and now
**`::/0`** into the TUN. The Rust engine is IPv4-only, so IPv6 packets entering the TUN are dropped —
this closes the IPv6 leak where the device's ISP-assigned v6 address would otherwise bypass the
tunnel. Honest tradeoff: **IPv6 connectivity is disabled while connected** (surface this in the UI).

## "Block connections without VPN" (honest)
This is a **user setting**, not something the app can enable programmatically:
**Settings → Network → VPN → NIL VPN → Always-on VPN + Block connections without VPN.** The app must
direct users there. (`VpnService.Builder.setBlocking(true)` is only the fd's blocking I/O mode, not
the system kill-switch.) The Rust `StartArgs.block_without_vpn` flag is the app-side intent to show
that guidance / gate connect on it.

## Sync to the APK project (now automatic — `build.rs`)
`crates/nil-android/android/*.kt` is the **source of truth**, but the Gradle project lives in the
git-ignored `client/src-tauri/gen/android/` (created by `tauri android init`). A build compiles
`gen/`, NOT `crates/` — so a stale `gen/` would ship the OLD Kotlin (e.g. WITHOUT the IPv6 leak
fix or the logcat sanitisation), silently re-opening the leak.

`client/src-tauri/build.rs` now mirrors the canonical `android/*.kt` into `gen/android/...` on
**every** build (`tauri android build` runs the src-tauri `cargo build` first), so the two can no
longer diverge — no manual step. It is best-effort (no-ops on a desktop build with no `gen/` tree,
and a copy failure only emits a `cargo:warning`). If you ever need to force a sync by hand:
```
cp crates/nil-android/android/*.kt \
   client/src-tauri/gen/android/app/src/main/java/com/nilvpn/
```

## Build + verify
```
rustup target add aarch64-linux-android      # + the NDK; configure cargo linkers
cargo build -p nil-android --target aarch64-linux-android --release   # libnil_android.so
# re-sync android/*.kt into gen/ (above), then assemble the APK (Gradle), install on a device
```
On device:
1. Grant the VPN consent prompt (`VpnConsentActivity`), connect.
2. **No leak:** check a v4 AND a v6 "what's my IP" — both must show the node exit (or v6 must be
   unreachable, i.e. blackholed), never the device's real address.
3. **Tunnel-dead hold:** when the engine reports down, confirm traffic blackholes (routes still via
   the TUN) rather than leaking; the app should transition to Disconnected.
4. Record the result here, then drop the README's Android caveat.

## Follow-up (not done here)
A `nativeStatus` poll that keeps the TUN fd open on a dead tunnel (active blackhole) is a small
Kotlin coroutine left for the on-device pass — it needs the SDK to compile/verify.
