# macOS — on-device verification (no-sudo System Extension epic, M2–M6)

> **Status: authored, NOT verified.** The macOS System Extension wrapper around the shared
> `NEPacketTunnelProvider` (`apple/PacketTunnelProvider.swift`) and its build/activation scaffolding
> are integration code that **cannot be compiled or run here** — there is no Xcode, no dev-mode /
> SIP-relaxed Mac, and no Apple Developer account on the host. Everything below must be done on a Mac
> by a human. Two gates stand between here and a verified macOS client:
> 1. **M2–M5** need a **dev-mode Mac** (`systemextensionsctl developer on`, which relaxes the
>    code-signing requirement for SE activation). SIP can stay enabled; dev mode is the only relaxation.
> 2. **M6** (clean install on a stock SIP-enabled Mac with no dev mode) additionally needs a **paid
>    Apple Developer account** for a Developer ID cert, hardened runtime, and notarization.
>
> Until a human walks this and records the result at the bottom, the README keeps the honest
> "macOS unverified" caveat. A green CI build is **not** a substitute — none of this datapath runs here.

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
   This lets an ad-hoc / development-signed SE activate without a notarized Developer ID build. It
   does **not** require disabling SIP. M6 is the SIP-enabled, dev-mode-OFF path and is gated on real
   certs instead (see M6).
5. **The app must live in `/Applications`.** Outside dev mode, macOS only activates a System
   Extension whose container app is in `/Applications` (not `~/Desktop`, not a `DerivedData` build
   dir). In dev mode it is more lenient, but build the habit now — copy the `.app` to `/Applications`
   before launching, or M6 will surprise you.

> Privacy note (PD-2/PD-8): nothing in this runbook should produce a log line containing the node
> address, token, grant, measurement, or the user's real IP. If you see one while verifying, that is
> a **bug**, not a passing run — stop and file it.

---

## M2 — generate the project and build the two targets

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

## M3 — activate the System Extension

`embed-systemextension.sh` (committed) does the post-build copy into `/Applications` and any
re-sign, so activation isn't a manual drag:

```sh
./embed-systemextension.sh            # copies the built .app to /Applications, fixes up signing
open /Applications/NilVPN.app          # launch the container app
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

## M4 — configure and connect

The container app, once the SE is approved, uses `NETunnelProviderManager` to install an
`NETunnelProviderProtocol` with:
- `providerBundleIdentifier = "com.nilvpn.client.PacketTunnel"`
- `providerConfiguration` = exactly the keys the SE reads:
  `nodeHost` (String), `nodePort` (Int), `serverName` (String), `measurementHex` (String),
  `teeName` (String), `allowUnattested` (Bool), `grantHex` (String), `grantNonceHex` (String).

The unlinkable Privacy Pass token is redeemed **in the container app**; only the resulting
node endpoint + measurement + per-connection grant cross into the SE (PD-3). Subscribe to
`NEVPNStatusDidChange` for status.

```
Redeem token in app  ->  writes providerConfiguration  ->  saveToPreferences  ->  startVPNTunnel
```

**Pass:** status walks `connecting → connected`; the menu/UI reflects it via
`NEVPNStatusDidChange`.

**Fail signs:** `NEVPNError.configurationInvalid` (engine rejected the config — usually a bad
`nodeHost`/`measurementHex`), or `connectionFailed` surfaced from the status callback (`state == 2`
in `PacketTunnelProvider`), or it never leaves `connecting` (node unreachable / attestation gate held
— which is correct behavior, see the token check in M5).

---

## M5 — the pass/fail checks (this is the real verification)

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

### 5.3 Memory under the NE budget
macOS gives a Network Extension a hard memory ceiling (~50 MB; treat it as a hard wall — exceed it
and the OS kills the SE, which then reads as a flapping/unstable tunnel). Profile the **SE process**,
not the app:
```
Xcode → Product → Profile → Allocations / Activity Monitor instrument,
attach to com.nilvpn.client.PacketTunnel, drive sustained traffic (e.g. a large download).
```
**Pass:** the SE's resident footprint stays comfortably under the budget under sustained load and
does not grow unbounded over a multi-minute transfer (watch for a leak slope).
**Fail:** steady climb toward the ceiling, or a `Jetsam`/memory-pressure kill in Console.

### 5.4 Token is NOT consumed if the SE was never approved
This is the privacy-economics check: a user who declines the System Settings approval must not have
burned their Privacy Pass token.
- Redeem a token in the app, then **decline / never approve** the SE in System Settings (or test on
  a machine where activation is still `waiting for user`).
- Attempt to connect; it will fail because the SE isn't active.
**Pass:** the grant is **still spendable** afterward — the app did not redeem/consume the token
until the SE actually came up and `startTunnel` ran. (Redeem-late, on `connected`, not on
"user clicked Connect".)
**Fail:** the token shows consumed/spent despite no tunnel ever forming. That wastes a user's
unlinkable token on a failed activation — fix the redeem ordering.

---

## M6 — clean SIP-enabled Mac: signing + notarization (human-gated)

M2–M5 prove the datapath in **dev mode**. M6 proves it on a **stock Mac** (SIP on, dev mode OFF) —
the state every real user is in. This is gated on a **paid Apple Developer account** and cannot be
done with ad-hoc signing.

Honest scoping of what Apple does and does not require:
- The **`packet-tunnel-provider-systemextension` capability needs no special Apple approval / email
  review** — unlike the iOS `packet-tunnel-provider` entitlement (which is org-gated, see
  `DEVICE_VERIFY.md`). On macOS you can enable it in your provisioning profile yourself.
- What you **do** need for a clean Mac: a **Developer ID Application** certificate, the **hardened
  runtime** enabled on both the app and the SE, correct provisioning, and **notarization** —
  otherwise a SIP-enabled Mac with dev mode off refuses to activate the SE.

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
M5.1–M5.4 all hold. Only then is macOS genuinely shippable.

> Secrets reminder: notarization creds (Apple ID, app-specific password, API key) are human-held —
> never commit them, never paste them into a tracked file or a log.

---

## What stays unverified until a device

Everything above. Specifically, until a human runs this on real hardware we cannot claim any of:
- the SE actually activates and the macOS approval flow works end to end (M3);
- the datapath carries real traffic with no v4/v6/DNS leak (M5.1);
- the kill-switch holds on a provider crash (M5.2);
- the SE lives within the NE memory budget under load (M5.3);
- tokens survive a declined activation (M5.4);
- a notarized build activates on a stock SIP-enabled Mac (M6).

A green workspace CI build proves the Rust engine compiles for the macOS slices — nothing more. Do
not let it masquerade as device verification.

## Record the result here

Once a human completes a milestone on real hardware, append the date, the Mac/macOS/Xcode versions,
dev-mode vs notarized, and the four M5 outcomes. **Only after M6 passes on a clean SIP-enabled Mac**
may the README's "macOS unverified" caveat be dropped.

| Date | macOS / Xcode | Mode (dev / notarized) | M3 activate | M5.1 no-leak | M5.2 kill-switch | M5.3 memory | M5.4 token | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _pending_ | | | | | | | | |
