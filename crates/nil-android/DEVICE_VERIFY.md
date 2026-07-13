# Android device-verification record (Epic 9)

> **Current status (2026-07-12): not release-validated.** The Android native engine is a one-hop
> debug/device-integration harness. A packaged non-debug client refuses with
> `NativeMultiHopUnavailable` before a pass is removed from the encrypted vault or sent to the
> Coordinator. No current APK/device run, production multi-hop run, signed artifact, or retained
> evidence bundle establishes release readiness.

## How to read the older record

The observations below were recorded on 2026-06-28. They remain useful for locating integration
risks, but their APK, build logs, node logs, packet captures, configuration, and artifact hashes were
not retained in this repository. They therefore cannot be independently repeated or treated as
current release evidence.

The historical report stated that:

- Gradle rebuilt `libnil_android.so` from source with `cargo-ndk`, repopulated an emptied
  `jniLibs/` directory, assembled an APK, and installed it on an `arm64-v8a` emulator.
- The debug harness followed consent → `establish()` → `detachFd()` → JNI start → tunnel up. A
  local node reported bidirectional counters, and IPv4 ping and DNS traffic were reported through
  the node.
- A synthetic/unverifiable node was reported rejected after the harness was placed in pinned,
  fail-closed attestation mode. A separate live alpha-node run was reported to accept an AMD
  SEV-SNP attestation and carry traffic.
- IPv6 was reported captured by the TUN and dropped while the IPv4-only engine was active, rather
  than bypassing the VPN.
- The status path was reported to move from connecting to up and then dead after the node was
  killed, while the TUN continued to blackhole traffic.

These notes predate the current release gate and do not establish multi-hop behavior, the current
trust bundle, a current production deployment, or real-device behavior.

## Current code-backed controls

- `client/src-tauri/src/extension.rs` checks the supported connection profile before token-vault
  mutation or Coordinator redemption. Debug-assertion builds retain the one-hop harness; non-debug
  builds fail closed until native multi-hop exists.
- The app-facing start contract contains the node endpoint, server name, pinned measurement,
  transparency-log key, TEE name, and opaque grant/nonce. It exposes no user-selectable attestation
  bypass and no per-connection persistent kill-switch flag. Because it does not yet contain the
  complete TDX workload policy, both bridge and JNI reject TDX before engine startup; this harness
  is SEV-SNP-only.
- `prepareVpn` obtains Android VPN consent before the app invokes the native connection path. The
  consent activity and `NilVpnService` are not exported. Any external test launcher must be a
  separate debug-only harness, not a production manifest exception.
- Auth material and passes share an encrypted, versioned vault. Android Keystore generates and
  retains the non-exportable AES key used by the private Rust-to-native bridge. The app has no
  plaintext fallback, and Android backup/device-transfer rules exclude the private data tree.
- `nativeStatus` reports the engine state to the service/UI. This is implemented source behavior;
  it still needs retained device evidence under failure and lifecycle conditions.

## Leak and persistent-blocking model

While the service is active, `NilVpnService` routes both `0.0.0.0/0` and `::/0` into the TUN. The
current engine carries IPv4; captured IPv6 is intentionally dropped. A dead engine must leave the
TUN in a blocking state rather than allowing clear-network fallback.

Blocking traffic when the VPN process is not active is an Android system policy: the user enables
**Always-on VPN** and **Block connections without VPN** in system VPN settings. The app can open
those settings and explain the requirement, but it cannot silently enable that policy.

## Source synchronization and build

`crates/nil-android/android/*.kt` is the source of truth. The generated Gradle tree under
`client/src-tauri/gen/android/` is ignored and may be regenerated. `client/src-tauri/build.rs`
mirrors the Kotlin sources, applies the native Gradle integration, injects the manifest posture,
and installs backup rules during Android builds.

```sh
rustup target add aarch64-linux-android
export ANDROID_HOME=$HOME/Library/Android/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.2.12479018
export NDK_HOME=$ANDROID_NDK_HOME
export CMAKE_POLICY_VERSION_MINIMUM=3.5
cargo ndk -t arm64-v8a -t x86_64 -P 21 \
  -o client/src-tauri/gen/android/app/src/main/jniLibs \
  build -p nil-android --release
```

## Future acceptance record

Do not run this as a release-readiness checklist until native multi-hop is implemented and the
non-debug refusal is intentionally removed through security review. Then retain the signed
artifact hash, source revision, toolchain versions, sanitized logs, node deployment identity, and
the result of every check below:

1. A clean build rebuilds all native libraries from source and installs the signed APK/AAB.
2. Before VPN consent is granted, connection preflight leaves the pass count unchanged and sends no
   redemption request.
3. The accepted connection uses the required multi-hop path and validates each required trust
   input; malformed, synthetic, unpinned, or transparency-invalid evidence fails closed.
4. IPv4, IPv6, and DNS tests show the intended exit or an intentional blackhole, never the device's
   clear-network address.
5. Killing the node and VPN process exercises both active-TUN blackholing and the documented
   Android Always-on/Block-without-VPN posture.
6. A real device covers Doze, reboot, Wi-Fi/mobile handoff, carrier MTU, notification/foreground
   service behavior, and recovery with fresh single-use credentials.

| Date | Commit/artifact | Device/Android | Multi-hop | Trust rejection | v4/v6/DNS | Dead tunnel | Lifecycle | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _pending_ | | | | | | | | |
