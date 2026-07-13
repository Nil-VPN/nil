# nil-android

The Android JNI engine for NIL VPN. It builds as `libnil_android.so` and runs the MASQUE datapath
inside the `VpnService` `:vpn` process. `MasqueTransport` uses a socket hook that calls
`VpnService.protect(fd)`, so the tunnel's own QUIC connection bypasses the TUN, and
`nil_datapath::Tunnel::up_with_fd` consumes the fd returned by
`VpnService.Builder.establish().detachFd()`.

The account identifier, payment context, auth seed, and bearer Privacy Pass do not enter the VPN
process. The app process redeems the pass and gives the VPN process only the node endpoint, server
name, attestation inputs, and opaque per-connection grant/nonce. As with any VPN, the selected node
can still observe the client's network address and traffic metadata.

## Current status (2026-07-12)

- The Rust library has been rebuilt from source for `arm64-v8a` and `x86_64`, including the quiche /
  BoringSSL dependency, and the Gradle integration builds it with `cargo-ndk` rather than shipping a
  committed native binary.
- The repository contains the JNI, `VpnService`, consent, status, route, and Tauri-plugin wiring.
  These are source/build-integration facts, not evidence of a current device or production run.
- The encrypted client vault holds auth material and bearer passes. Its key is non-exportable in
  Android Keystore; there is no plaintext fallback, Android backup/device transfer is excluded, and
  the VPN consent activity is private to the app (`android:exported="false"`).
- The native engine currently implements one hop only. Packaged non-debug clients deliberately
  return `NativeMultiHopUnavailable` before removing a pass from the vault or contacting the
  Coordinator. The one-hop path is a debug/device-integration harness, not a releasable connection
  mode.
- The current JNI contract also lacks NIL's complete TDX workload policy. Both the app bridge and
  JNI entry point reject TDX before starting the engine; raw MRTD is never treated as sufficient.
  The debug one-hop attested harness is therefore SEV-SNP-only until that ABI is extended.
- For SEV-SNP, the app bridge carries the stable TLS-SPKI SHA-256 identity plus optional FMC and
  bootloader/TEE/SNP/microcode minimum-TCB floor through private Tauri arguments, Intent extras, and
  JNI into `AttestExpectation`. Native conversion rejects malformed pins/out-of-range components
  and refuses any attestation policy paired with unattested mode rather than silently discarding it.
  The JNI crate cross-checks for `aarch64-linux-android` and the generated app's arm64 Kotlin task
  compiles offline; a packaged APK/device conformance run is still required.
- `VpnService` must still configure its IPv4 address before native connect. The engine now requires
  the node to assign exactly `10.74.0.2` and fails the connection otherwise, so a second concurrent
  client is rejected rather than falsely reporting a tunnel whose packets are dropped. A two-phase
  address ABI is still required for concurrent Android clients.
- There is no current production validation. The 2026-06-28 emulator and live-node notes in
  `DEVICE_VERIFY.md` are retained as historical, unarchived engineering observations; they are not
  release proof and have not been repeated against the current tree.

## Build the native library

```sh
export ANDROID_HOME=$HOME/Library/Android/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.2.12479018
export NDK_HOME=$ANDROID_NDK_HOME
export CMAKE_POLICY_VERSION_MINIMUM=3.5
cargo ndk -t arm64-v8a -t x86_64 -P 21 \
  -o ../../client/src-tauri/gen/android/app/src/main/jniLibs \
  build -p nil-android --release
# Copy the NDK's libc++_shared.so for each ABI into the same jniLibs directories.
```

The exact NDK/JDK versions used for a release must be pinned by the release toolchain; the values
above describe the known source-build setup, not a deterministic release-build attestation.

## Generated Android project integration

`pnpm --dir client tauri android init` creates the git-ignored Gradle project under
`client/src-tauri/gen/android/`. `client/src-tauri/build.rs` then performs the integration work on
each Android build:

- mirrors `crates/nil-android/android/*.kt` into the generated project;
- applies `nil-android.gradle.kts`, which invokes `cargo-ndk` and packages `libc++_shared.so`;
- injects the `VpnService` and private consent activity manifest entries;
- registers the private Android Keystore bridge and installs backup exclusions; and
- pins the supported ABI list.

The relevant manifest posture is:

```xml
<activity android:name="com.nilvpn.VpnConsentActivity"
          android:theme="@android:style/Theme.Translucent.NoTitleBar"
          android:exported="false"/>
<service android:name="com.nilvpn.NilVpnService"
         android:process=":vpn"
         android:permission="android.permission.BIND_VPN_SERVICE"
         android:foregroundServiceType="specialUse"
         android:exported="false">
  <intent-filter><action android:name="android.net.VpnService"/></intent-filter>
  <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="vpn"/>
</service>
```

Use a supported Gradle JDK (currently JDK 17 or 21 for this setup), then build from `client/` with
`pnpm tauri android dev` for the debug harness or the appropriate Tauri Android build command.

## Validation still required

Native multi-hop must be implemented before a packaged connection can be considered. After that,
validation must cover a clean source build, signed APK/AAB installation, real-device VPN consent,
attestation and transparency verification, multi-hop traffic, v4/v6/DNS leak behavior, dead-tunnel
blackholing, Doze, Wi-Fi/mobile handoff, carrier MTU, reboot/Always-on behavior, and Play policy
requirements. Record retained logs and artifact hashes in `DEVICE_VERIFY.md`; an emulator-only run
does not satisfy the real-device or production checks.
