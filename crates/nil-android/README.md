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
     <service android:name="com.nilvpn.NilVpnService"
              android:process=":vpn"
              android:permission="android.permission.BIND_VPN_SERVICE"
              android:foregroundServiceType="specialUse" android:exported="false">
       <intent-filter><action android:name="android.net.VpnService"/></intent-filter>
     </service>
   </application>
   ```
4. Wire the cargo-ndk jniLibs build (above) into the Gradle build; ensure `libc++_shared.so` ships.
5. `pnpm tauri android build --apk`, then emulator smoke:
   `adb install`, Connect → VPN consent → `establish()` → `nativeStart` → expect logcat
   `MASQUE CONNECT-IP established` against the node. For a reachability-only smoke against a live
   node whose pinned measurement you don't have, pass `allowUnattested=true` (NOT an attestation
   validation — documented caveat).

Real-device behaviors (Doze, Wi-Fi↔LTE handoff, carrier MTU, boot always-on) and the Play-Store
VpnService policy form are device/account-bound and out of scope for headless CI.
