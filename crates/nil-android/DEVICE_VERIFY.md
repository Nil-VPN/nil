# Android — on-device verification (Epic 9)

> **Status: VERIFIED on an arm64 emulator (2026-06-28), including a live real-SEV-SNP attested connect.**
> The APK builds end-to-end (engine compiled from source by Gradle, not a committed binary — see
> below) and the datapath was exercised on an `arm64-v8a` AVD against a local node. What was proven
> live on the emulator:
>
> - **Build is reproducible:** `libnil_android.so` is built by `cargo-ndk` wired into Gradle
>   (`nil-android.gradle.kts`, applied via `client/src-tauri/build.rs`), not a committed prebuilt.
>   A clean (emptied) `jniLibs/` is repopulated by the build; APK assembles, installs, launches.
> - **Datapath works:** consent → `establish()` → `detachFd` → `nativeStart` → `nil-android tunnel
>   up`. `tun_rs::AsyncDevice::from_fd` works on `target_os="android"`; the `protect()` JNI upcall
>   succeeds; `spawn_pumps` moves packets. The exit node's data-plane counters showed bidirectional
>   flow (`from_client_pkts`/`to_client_pkts` increment, `to_client_drop_pkts=0`); `ping 1.1.1.1`
>   and `ping example.com` (DNS-through-tunnel) returned 0% loss with the node's egress TTL.
> - **Attestation gate is wired and fails closed:** the ONLY change of flipping `allowUnattested`
>   to `false` (with a pinned measurement) turned a working tunnel into
>   `attestation failed: unsupported TEE tag: 0xff` → `nativeStart handle=0` → no tunnel. A release
>   client (no `synthetic` feature) correctly refuses a synthetic/unverifiable node — no packet ever
>   egresses unattested (Pillar 2).
> - **Real SEV-SNP acceptance (live):** with `allowUnattested=false` + the client's pinned live
>   measurement, the engine attested the live alpha node (genuine AMD vendor-root chain + measurement
>   match) → tunnel up; egress confirmed (ping/DNS 0% loss, with RTT consistent with the real remote
>   node vs the local one). Token redeemed at the live Coordinator (the alpha hop is ungranted, so
>   `grantHex=""`).
> - **No leak:** IPv4 egresses through the tunnel; IPv6 (`ping6`) is 100% blackholed (engine is
>   IPv4-only; `::/0` is captured into the TUN and dropped) so the device's real address can't leak.
>
> **Hardening landed (Phase C/D), verified on the arm64 emulator unless noted:**
> - **C1 independent attestation pin** — the mobile redeem (`extension.rs`) cross-checks the
>   Coordinator-provided measurement against the client's own pin (`client_pins_from_env`),
>   fail-closed on mismatch (`PinMismatch`). Unit-tested (8/8). Closes the Coordinator-trust gap (PD-5).
> - **C2 real status channel** — `nativeStatus` reports `up|dead|down` from `Tunnel::is_up()`; the
>   service publishes connecting→up (only after the gate passes) →dead to a shared-`filesDir` file via
>   a poll thread, with honest FGS notification text; `commands.ts` reports connected ONLY on `up`.
>   Verified: connect→up; killing the node flips →dead (the TUN keeps blackholing throughout).
> - **C3 consent preflight** — `prepareVPN` obtains VPN consent BEFORE `extension_connect` redeems,
>   so a denied/pending permission never burns a single-use token. (The token store is already
>   privacy-correct — only `{msg,token}`, `0600`, atomic, fail-closed; Keystore-at-rest encryption is
>   deferred defense-in-depth on non-identity data, not a privacy gap.)
> - **C4 honest Always-on** — `openVpnSettings` deep-links to the OS VPN settings (verified resolves
>   to `Settings$VpnSettingsActivity`); a Settings row states the app cannot enable Always-on /
>   "Block without VPN" itself (PD-8). No-PII log audit: PASS (lengths/states only; no analytics SDKs).
> - **D4 JNI symbol guard / D3 START_STICKY / D1 foreground service** — present (the datapath runs as
>   an FGS; a build-time guard binds the JNI symbols), but see the design-gated items below.
>
> **Remaining before Android *ships* (design-gated or device-bound — deliberately NOT rushed):**
> - **Reconnect-with-backoff (Wi-Fi↔LTE handoff, D2)** — a dead tunnel currently blackholes + reports
>   `dead` honestly, but does NOT auto-reconnect. True reconnect needs design: the grant/token is
>   single-use, so re-establishing requires a FRESH token redeemed in the app process and re-armed
>   across to the `:vpn` service (or QUIC connection migration). `START_STICKY` restart is also a
>   no-op today (null intent + spent token) — honest auto-restart needs the same design.
> - **Dead-tunnel detection latency** — bounded by the QUIC `max_idle_timeout` (30s), set to a
>   **browser-plausible** value on purpose (Pillar 1 anti-fingerprinting). Lowering it for mobile
>   responsiveness/battery is a fingerprint tradeoff that needs a deliberate decision, not a tweak.
> - **Real-device behaviors** (Doze deep-sleep network limits, carrier MTU, boot Always-on) an
>   emulator can't exercise.

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
