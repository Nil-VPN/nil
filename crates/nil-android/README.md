# nil-android

The Android JNI engine for NIL VPN. Builds as `libnil_android.so` and runs the MASQUE datapath
inside the `VpnService` `:vpn` process: it builds the `MasqueTransport` with a `socket_hook` that
calls `VpnService.protect(fd)` (so the tunnel's own QUIC to the node bypasses the TUN), then runs
`nil_datapath::Tunnel::up_with_fd` over the fd handed over by `Builder.establish().detachFd()`.

Identity never reaches this process — only a node endpoint + an optional pinned measurement. The
unlinkable Privacy Pass token is redeemed in the app (WebView) process.

## Status (verified)

- ✅ **BoringSSL / quiche cross-compile for Android** (`aarch64` + `x86_64`) — the historically hard
  part. Requires `CMAKE_POLICY_VERSION_MINIMUM=3.5` with a cmake-4 host.
- ✅ **`libnil_android.so` builds** for both ABIs, warning-free.
- ✅ Shared-Rust hooks landed: `MasqueConfig.socket_hook` (nil-transport) + `Tunnel::up_with_fd`
  (nil-datapath `android.rs`).
- ✅ Kotlin integration written (`android/NilNative.kt`, `NilVpnService.kt`, `NilVpnPlugin.kt`).

## Build the native lib

```sh
export ANDROID_HOME=$HOME/Library/Android/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.2.12479018
export NDK_HOME=$ANDROID_NDK_HOME
export CMAKE_POLICY_VERSION_MINIMUM=3.5        # BoringSSL's cmake_minimum_required(3.5) under cmake 4.x
cargo ndk -t arm64-v8a -t x86_64 -P 21 \
  -o ../../client/src-tauri/gen/android/app/src/main/jniLibs \
  build -p nil-android --release
# Also copy the NDK's libc++_shared.so per ABI into the same jniLibs dirs.
```

## Remaining to produce an installable APK (the documented next step)

1. `cd client && pnpm tauri android init` — generates `gen/android/` (a Gradle project).
   - **Blocker:** Gradle/AGP do not support **JDK 26** (present on this machine). Use JDK 17 or 21
     (`brew install temurin@21`; `export JAVA_HOME=...`).
2. Copy `android/*.kt` into `gen/android/app/src/main/java/com/nilvpn/` and register `NilVpnPlugin`.
3. `AndroidManifest.xml` additions:
   ```xml
   <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
   <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>
   <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
   <application ...>
     <!-- VPN consent handshake (VpnService.prepare + system dialog), then starts the service. -->
     <activity android:name="com.nilvpn.VpnConsentActivity"
               android:theme="@android:style/Theme.Translucent.NoTitleBar"
               android:exported="true"/>
     <service android:name="com.nilvpn.NilVpnService"
              android:permission="android.permission.BIND_VPN_SERVICE"
              android:foregroundServiceType="specialUse" android:exported="false">
       <intent-filter><action android:name="android.net.VpnService"/></intent-filter>
       <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="vpn"/>
     </service>
   </application>
   ```
Steps 2–4 are now **automated by `client/src-tauri/build.rs`** (it mirrors `android/*.kt`, applies
`nil-android.gradle.kts` so `cargo-ndk` builds `libnil_android.so` + ships `libc++_shared.so` on every
assemble, injects the manifest fragment, and pins the ABI list) — no manual copy/edit needed.

5. `pnpm tauri android dev` (or `build --apk`), then the emulator e2e. **Verified on an `arm64-v8a`
   AVD (2026-06-28) against a LOCAL node:** `adb install` → launch `VpnConsentActivity` (the app's
   Connect routes here) → consent → `NilVpnService` → `establish()` → `detachFd` → `nativeStart` →
   `nil-android tunnel up` → real traffic egresses (ICMP/DNS, 0% loss, node egress TTL); IPv6
   blackholed. Headless consent: `adb shell appops set <pkg> ACTIVATE_VPN allow` makes `prepare()`
   return null. With `allowUnattested=false` + a pinned measurement, the engine returns a 0 handle on
   any attestation failure (proven: a synthetic node is rejected with `unsupported TEE tag: 0xff`).
   **Live real-SEV-SNP accept run also verified** (2026-06-28): with `allowUnattested=false` + the
   pinned live measurement, the engine attested the live node and brought the tunnel up with egress —
   see `DEVICE_VERIFY.md`.

Real-device behaviors (Doze, Wi-Fi↔LTE handoff, carrier MTU, boot always-on) and the Play-Store
VpnService policy form are device/account-bound and out of scope for headless CI.
