#!/usr/bin/env bash
# verify-macos-se-build.sh — headless, UNSIGNED build verification of the macOS System Extension
# (the NEPacketTunnelProvider packet tunnel). Catches Apple-target bitrot in the SE build graph
# (the XcodeGen spec, the Swift provider + its bridging header, the linked NilApple.xcframework)
# WITHOUT any signing, Developer account, or device — so it runs in CI on a macOS runner.
#
# It does NOT (and cannot, headlessly) verify signing, activation, or runtime — a system extension
# must be signed + approved in System Settings to actually load. Those stay on-device handoffs
# (crates/nil-apple/MACOS_DEVICE_VERIFY.md, steps M2+).
#
# Usage:  bash deploy/verify-macos-se-build.sh
# Needs:  macOS + Xcode + xcodegen (brew install xcodegen) + rust darwin targets. PII-free.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLE_DIR="$ROOT/client/apple"
OUT_DIR="${TMPDIR:-/tmp}/nil-macos-se-verify"
PROJ="$APPLE_DIR/NilVPNSystemExtension.xcodeproj"

echo "== macOS System Extension build verification (unsigned) =="

# 1. Build the engine xcframework the SE target links (out-of-band, per build-engine.sh's cycle note).
bash "$APPLE_DIR/build-engine.sh" release
[[ -d "$APPLE_DIR/NilApple.xcframework" ]] || { echo "FAIL: NilApple.xcframework not produced"; exit 1; }

# 2. Generate the Xcode project from the XcodeGen spec (the .xcodeproj is gitignored/regenerated).
( cd "$APPLE_DIR" && xcodegen generate )
[[ -f "$PROJ/project.pbxproj" ]] || { echo "FAIL: xcodegen did not produce $PROJ"; exit 1; }

# 3. Build ONLY the PacketTunnel (system-extension) scheme, UNSIGNED. XcodeGen auto-generates a
#    per-target scheme (visible via `xcodebuild -list`); signing is fully disabled so no
#    certs/team/provisioning are needed. -scheme is required alongside -derivedDataPath.
rm -rf "$OUT_DIR"
BUILD_LOG="$OUT_DIR/xcodebuild.log"
mkdir -p "$OUT_DIR"
if ! xcodebuild \
  -project "$PROJ" \
  -scheme PacketTunnel \
  -configuration Release \
  -sdk macosx \
  -derivedDataPath "$OUT_DIR/DerivedData" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO DEVELOPMENT_TEAM="" \
  build 2>&1 | tee "$BUILD_LOG"; then
  echo "FAIL: xcodebuild failed" >&2
  exit 1
fi
if grep -Eiq "(object file|was built).*newer.*(macOS|deployment|being linked)" "$BUILD_LOG"; then
  echo "FAIL: a native object was built for a newer macOS deployment target" >&2
  grep -Ei "(object file|was built).*newer.*(macOS|deployment|being linked)" "$BUILD_LOG" >&2
  exit 1
fi

# 4. Assert the artifact: a .systemextension bundle with an arm64 Mach-O executable inside.
SE="$(find "$OUT_DIR/DerivedData/Build/Products" -type d -name '*.systemextension' | head -1)"
[[ -n "$SE" && -d "$SE" ]] || { echo "FAIL: no .systemextension bundle in the build output"; exit 1; }
MACH_O="$SE/Contents/MacOS/com.nilvpn.client.PacketTunnel"
[[ -f "$MACH_O" ]] || { echo "FAIL: no Mach-O executable inside the SE bundle"; exit 1; }
file "$MACH_O" | grep -q "Mach-O.*arm64" || { echo "FAIL: SE executable is not an arm64 Mach-O"; exit 1; }
MIN_OS=$(xcrun vtool -show-build "$MACH_O" | awk '/minos/{print $2; exit}')
[[ "$MIN_OS" == "13.0" ]] \
  || { echo "FAIL: SE Mach-O minimum OS is ${MIN_OS:-missing}, expected 13.0" >&2; exit 1; }
PLIST_MIN=$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' "$SE/Contents/Info.plist")
[[ "$PLIST_MIN" == "13.0" ]] \
  || { echo "FAIL: SE Info.plist minimum OS is ${PLIST_MIN:-missing}, expected 13.0" >&2; exit 1; }

# 5. Best-effort: confirm the nil-apple engine symbols linked in (not fatal — a stripped release
#    build may hide them; the link itself already succeeded above if we got here).
if nm "$MACH_O" 2>/dev/null | grep -q "_nil_start"; then
  echo "  engine symbols present (nil_start linked)"
else
  echo "  note: nil_start not visible in nm (likely stripped) — link succeeded regardless"
fi

echo "== BUILD SUCCEEDED =="
echo "SE bundle: $SE"
file "$MACH_O"
