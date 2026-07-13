# macOS — on-device verification (no-sudo System Extension epic, M2–M6)

> **Current status (2026-07-12): compile/scaffold evidence only; no activation, live-tunnel, or
> production validation.** The shared Apple native engine implements one hop as a debug/integration
> harness. A packaged non-debug client returns `NativeMultiHopUnavailable` before removing a pass
> from the encrypted vault or contacting the Coordinator. M2–M6 below are acceptance procedures,
> not recorded passing results, and signing cannot bypass the current release-profile refusal.

## Historical local build note (2026-06-28; unarchived)

An earlier developer report recorded an unsigned arm64 build on Apple Silicon with then-current
Xcode/macOS. That exercise found and fixed a build-graph cycle, Swift `UInt`/`Int` FFI mismatches,
and the missing macOS system-extension entry point (`PacketTunnelMain.swift` calling
`NEProvider.startSystemExtensionMode()`). The report used:

```sh
./build-engine.sh debug
cd client/apple
xcodegen generate
xcodebuild -target PacketTunnel -configuration Debug \
  -destination 'platform=macOS,arch=arm64' ARCHS=arm64 CODE_SIGNING_ALLOWED=NO build
```

It stated that the resulting arm64 Mach-O linked the expected `_nil_*` symbols and that a universal
build encountered an SDK build-sandbox issue. A later personal-team signing attempt reportedly
could not provision the Network/System Extension capabilities. No build artifact, hash, full log,
activation record, or live traffic evidence is retained here, so these are historical engineering
observations rather than current release proof. Do not reuse personal team identifiers or signing
details in tracked evidence.

The current gates are native multi-hop, valid Apple signing/provisioning, extension activation, and
the runtime/distribution checks below. Dev mode can relax parts of local activation/notarization
handling, but it does not establish a production signing or security posture.

The shared identifiers below are load-bearing and must agree across `project.yml`, both
`.entitlements`, the `Info.plist`s, and the container-app code. Do not paraphrase them:

| Thing | Value |
| --- | --- |
| App bundle id | `com.nilvpn.client` |
| System Extension bundle id | `com.nilvpn.client.PacketTunnel` (child of the app id) |
| App Group | `group.com.nilvpn.client` |
| VPN display name | NIL VPN |
| Min deployment target | macOS 13.0 |
| SE principal class | `PacketTunnelProvider` (`apple/PacketTunnelProvider.swift`) |
| SE `NSExtensionPointIdentifier` | `com.apple.networkextension.packet-tunnel` |
| Engine | `NilApple.xcframework` (macOS arm64 + x86_64 slices of `libnil_apple.a` + `include/`) |

The SE links `NilApple.xcframework` + `NetworkExtension` / `Security` / `libc++` / `libresolv`. The
**container app does NOT link the staticlib** — it only drives the SE.

---

## Prerequisites

1. **Xcode** (full install, not just Command Line Tools) on macOS 13.0+.
2. **xcodegen** (`brew install xcodegen`) — generates the `.xcodeproj` from `project.yml` so the
   Xcode project itself never has to be committed (keeps the tree diffable and AI-tooling-free).
3. **Rust iOS/macOS targets** for the engine slices:
   ```sh
   rustup target add aarch64-apple-darwin x86_64-apple-darwin
   ```
4. **Dev mode ON** (M2–M5): in a terminal on the *target* Mac, once per machine:
   ```sh
   systemextensionsctl developer on
   ```
   This supports local development activation for a correctly entitled development build without
   a notarized Developer ID artifact. It does not grant missing capabilities or provisioning and
   does **not** require disabling SIP. M6 is the SIP-enabled, dev-mode-OFF path (see M6).
5. **The app must live in `/Applications`.** Outside dev mode, macOS only activates a System
   Extension whose container app is in `/Applications` (not `~/Desktop`, not a `DerivedData` build
   dir). In dev mode it is more lenient, but build the habit now — copy the `.app` to `/Applications`
   before launching, or M6 will surprise you.

> Privacy note (PD-2/PD-8): nothing in this runbook should produce a log line containing the node
> address, token, grant, measurement, or the user's real IP. If you see one while verifying, that is
> a **bug**, not a passing run — stop and file it.

---

## M2 — future build acceptance: generate the project and build both targets

`project.yml` (committed) describes two targets — the **container app** (`com.nilvpn.client`) and
the **System Extension appex** (`com.nilvpn.client.PacketTunnel`) — and references the two
`.entitlements` files and `NilApple.xcframework`.

```sh
# from crates/nil-apple (or wherever project.yml lives for the macOS shell)
xcodegen generate                       # project.yml -> NilVPN.xcodeproj
xcodebuild -project NilVPN.xcodeproj \
  -scheme NilVPN -configuration Debug \
  -destination 'platform=macOS' build
```

**Pass:** both targets compile and link; the `.app` contains the SE at
`Contents/Library/SystemExtensions/com.nilvpn.client.PacketTunnel.systemextension`, and the SE links
the xcframework (verify with `otool -L .../com.nilvpn.client.PacketTunnel`).

Before signing or device work, run `bash deploy/verify-macos-se-build.sh` from the repository root.
It rebuilds the Apple engine in its deployment-target-specific cache, rejects representative native
C++/assembly archive members that do not declare macOS 13.0, fails on newer-object linker warnings,
and verifies the unsigned extension executable and plist both declare macOS 13.0. Passing this gate
does not replace the macOS 13 runtime milestones below.

**Entitlements to confirm now** (cheap to check, expensive to miss):
- App **and** SE both carry
  `com.apple.developer.networking.networkextension = [packet-tunnel-provider-systemextension]`
  and `com.apple.security.application-groups = [group.com.nilvpn.client]`.
- The **app additionally** carries `com.apple.developer.system-extension.install = true`.
- Note this is the **`-systemextension`** NE flavor (macOS), *not* the bare
  `packet-tunnel-provider` flavor used by the iOS appex — they are different entitlement values.

**Fail signs:** "embedded binary is not signed with the same certificate as the parent app" (sign
both with the same identity/team), or a missing-entitlement error at activation time (M3).

---

## M3 — future runtime acceptance: activate the System Extension

`client/scripts/embed-systemextension.sh` (committed) does the post-build copy into `/Applications`
and any re-sign, so activation isn't a manual drag:

```sh
bash client/scripts/embed-systemextension.sh   # copies the built .app to /Applications, fixes up signing
open /Applications/NilVPN.app                  # launch the container app
```

In the running app, trigger activation — the container app issues
`OSSystemExtensionRequest.activationRequest(...)`. macOS then prompts:

> **System Settings → General → Login Items & Extensions → Extensions → Network Extensions**
> → enable **NIL VPN**.

This is a **one-time** per-machine approval and **must be done by the human at the GUI** — there is
no sudo/CLI bypass on a normal Mac, and there should not be one (that is the whole point of the
"no-sudo" posture: the user approves once, in their own settings, and can revoke there).

```sh
systemextensionsctl list               # expect: com.nilvpn.client.PacketTunnel ... [activated enabled]
```

**Pass:** `systemextensionsctl list` shows the SE `activated enabled`; the delegate's
`request:didFinishWithResult:` reported `.completed`.

**Fail signs:** stuck at `activated waiting for user`, or `OSSystemExtensionErrorAuthorizationRequired`
(approve in System Settings), or `...ErrorValidationFailed` (entitlement/signing mismatch from M2),
or "extension must be in /Applications" (you launched it from `DerivedData` — re-run the embed
script).

---

## M4 — future runtime acceptance: configure and connect

The container app, once the SE is approved, uses `NETunnelProviderManager` to install an
`NETunnelProviderProtocol` with:
- `providerBundleIdentifier = "com.nilvpn.client.PacketTunnel"`
- `providerConfiguration` = the current app contract keys:
  `nodeHost` (String), `nodePort` (Int), `serverName` (String), `measurementHex` (String),
  `tlsSpkiSha256Hex` (String), `transparencyLogKeyHex` (String), `teeName` (String), optional
  `minTcbSevsnp` (dictionary with optional `fmc` and required `bootloader`, `tee`, `snp`, and
  `microcode` byte values), `grantHex` (String), and `grantNonceHex` (String).

The blind-signed Privacy Pass token is redeemed **in the container app**; the issuance transcript
does not provide a direct cryptographic join to that bearer token, although timing and network
correlation remain possible. Only the resulting node endpoint, trust inputs, and per-connection
grant cross into the SE (PD-3). Subscribe to
`NEVPNStatusDidChange` for status. The current packaged non-debug path never reaches redemption or
this configuration step: its connection-profile guard returns before vault mutation or a
Coordinator request. The flow below is therefore for a debug harness or a future multi-hop engine.

```
supported profile -> redeem in app -> write providerConfiguration -> saveToPreferences -> startVPNTunnel
```

**Pass:** status walks `connecting → connected`; the menu/UI reflects it via
`NEVPNStatusDidChange`.

**Fail signs:** `NEVPNError.configurationInvalid` (engine rejected the config — usually a bad
`nodeHost`/`measurementHex`), or `connectionFailed` surfaced from the status callback (`state == 2`
in `PacketTunnelProvider`), or it never leaves `connecting` (node unreachable / attestation gate held
— which is correct behavior, see the token check in M5).

---

## M5 — future pass/fail checks (none recorded yet)

Run all four. A run is only "passed" when all four hold and none produced a forbidden log line.

### 5.1 No DNS / IP leak — exit IP is the node's, not yours
With the tunnel up:
```sh
curl -s https://api.ipify.org ; echo
dig +short myip.opendns.com @208.67.222.222
```
**Pass:** both return the **node exit IP**, never the Mac's real v4/v6 ISP address. The SE's
`applySettingsAndRead` installs IPv4 **and** IPv6 default routes (the engine is IPv4-only, so v6 is
captured into the tunnel and dropped — no ISP-IPv6 leak around the tunnel). Sanity-check v6 too:
```sh
curl -s -6 https://api6.ipify.org ; echo      # must NOT return your ISP v6; expect failure or node IP
```
**Fail:** your real address appears in any of these. That is a leak — block the release.

### 5.2 Kill-switch holds when the provider dies
"Block all traffic when VPN is down" on macOS is `includeAllNetworks` on the
`NETunnelProviderProtocol`, plus the OS **Always-on / on-demand** setting. The app can *request* this
(set `protocolConfiguration.includeAllNetworks = true` before start, fail-closed default), but it
**cannot silently force** the user's system-wide posture — be honest about that in the UI (PD-8). Do
not imply more protection than `includeAllNetworks` actually gives.

```sh
# find and kill the running provider process to simulate a crash
pkill -f com.nilvpn.client.PacketTunnel
# immediately re-test from 5.1
curl -s --max-time 5 https://api.ipify.org ; echo
```
**Pass:** with the provider dead and the kill-switch armed, the curl **fails / times out** — no
traffic leaks in the clear during the gap before the OS restarts or tears down the tunnel; the app
surfaces a disconnected/blocked state.
**Fail:** traffic flows in the clear with your real IP while the provider is down.

### 5.3 Memory stays within the platform budget

Network Extensions run under OS memory limits that can vary by platform and release. Establish the
applicable limit for the tested macOS version and keep a conservative margin; an OS memory kill
looks like a flapping/unstable tunnel. Profile the **SE process**, not the app:
```
Xcode → Product → Profile → Allocations / Activity Monitor instrument,
attach to com.nilvpn.client.PacketTunnel, drive sustained traffic (e.g. a large download).
```
**Pass:** the SE's resident footprint stays comfortably under the budget under sustained load and
does not grow unbounded over a multi-minute transfer (watch for a leak slope).
**Fail:** steady climb toward the ceiling, or a `Jetsam`/memory-pressure kill in Console.

### 5.4 Unsupported profiles and incomplete activation fail before token use

This check covers only failures that occur before `extension_connect` begins redemption:

1. In a packaged non-debug build with the current one-hop engine, attempt a connection and confirm
   `NativeMultiHopUnavailable` is returned.
2. Separately, leave the System Extension unapproved (or activation waiting for the user) and
   confirm the app's activation/permission preflight does not invoke `extension_connect`.
3. For both cases, compare the encrypted-vault pass count before and after and confirm the
   Coordinator received no redemption request.

**Pass:** the pass count is unchanged and no redemption request is observed for either preflight
failure. **Fail:** the app invokes redemption before it knows that the connection profile and OS
activation state can proceed.

Do not extend this claim to failures after redemption begins. On a supported debug/future profile,
the app deliberately removes a single-use pass from the vault before posting it to the Coordinator;
a later network, attestation, provider, or tunnel failure can consume that pass. The current code
does not implement "redeem only after connected," and this record must not imply otherwise.

---

## M6 — future clean-Mac acceptance: signing + notarization (human-gated)

After M2–M5 have actually passed and retained evidence exists, M6 repeats the work on a **stock
Mac** (SIP on, dev mode OFF), the state expected for users. It requires appropriate paid-program
credentials and cannot be completed with ad-hoc signing.

Apple account and entitlement policy can change. Confirm the current requirements in Apple's
developer portal and documentation for the exact distribution channel. At minimum, this path
expects a suitable **Developer ID Application** certificate, hardened runtime on the app and SE,
correct entitlements/provisioning, and notarization for outside-App-Store distribution.

Steps (human, on a Mac with the cert installed):
```sh
# 1) build Release signed with Developer ID + hardened runtime (configured in project.yml)
xcodebuild -project NilVPN.xcodeproj -scheme NilVPN -configuration Release \
  CODE_SIGN_IDENTITY="Developer ID Application" \
  OTHER_CODE_SIGN_FLAGS="--options runtime" archive -archivePath build/NilVPN.xcarchive

# 2) export the .app, then notarize with notarytool (needs an app-specific password / API key)
xcrun notarytool submit build/NilVPN.app.zip \
  --apple-id "<apple-id>" --team-id "<team-id>" --password "<app-specific-pw>" --wait

# 3) staple the ticket so it verifies offline
xcrun stapler staple /Applications/NilVPN.app
spctl -a -vvv --type install /Applications/NilVPN.app    # expect: accepted, source=Notarized Developer ID
```

Then **turn dev mode OFF** (`systemextensionsctl developer off`), reboot, install from
`/Applications`, and re-run **all of M3–M5** on that clean machine.

**Pass:** the SE activates after the one-time System Settings approval with **no dev mode**, and
M5.1–M5.4 all hold. This establishes the distribution/runtime checks only; the product is not
shippable until native multi-hop and the rest of the release checklist also pass.

> Secrets reminder: notarization creds (Apple ID, app-specific password, API key) are human-held —
> never commit them, never paste them into a tracked file or a log.

---

## What stays unverified until a device

Everything above. Specifically, until a human runs this on real hardware we cannot claim any of:
- the SE actually activates and the macOS approval flow works end to end (M3);
- the datapath carries real traffic with no v4/v6/DNS leak (M5.1);
- the kill-switch holds on a provider crash (M5.2);
- the SE lives within the NE memory budget under load (M5.3);
- unsupported-profile and incomplete-activation preflights leave passes untouched (M5.4);
- a notarized build activates on a stock SIP-enabled Mac (M6).

An Apple-target compile job, when it actually runs, establishes only that the selected source and
toolchain compiled. It does not establish extension activation or device behavior.

## Record the result here

Once a human completes a milestone on real hardware, append the date, the Mac/macOS/Xcode versions,
dev-mode vs notarized, signed artifact hash, sanitized evidence location, and the four M5 outcomes.
Do not describe macOS as release-validated until M6, native multi-hop, and the full release checklist
have all passed.

| Date | macOS / Xcode | Mode (dev / notarized) | M3 activate | M5.1 no-leak | M5.2 kill-switch | M5.3 memory | M5.4 preflight/no-spend | Artifact/evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _pending_ | | | | | | | | |
