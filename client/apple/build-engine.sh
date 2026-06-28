#!/usr/bin/env bash
# build-engine.sh — build the nil-apple C-ABI engine as NilApple.xcframework (macOS universal),
# the PREREQUISITE the XcodeGen System Extension target links.
#
# Run this BEFORE `xcodebuild` (embed-systemextension.sh calls it for you). It is deliberately NOT
# an Xcode in-target script phase: a phase that generates a framework the SAME target also *links*
# creates a build cycle ("Cycle inside PacketTunnel"), because Xcode resolves the linked framework
# before the phase that would produce it. Building the xcframework out-of-band breaks that cycle —
# the SE target then simply links an artifact that already exists on disk.
#
# Usage: ./build-engine.sh [release|debug]   (default: release)
#
# Cannot run on a non-macOS host (needs the Apple toolchain: cargo + lipo + xcodebuild). PII-free.
set -euo pipefail

PROFILE="${1:-release}"
case "$PROFILE" in
  release) PROFILE_FLAG="--release" ;;
  debug)   PROFILE_FLAG="" ;;
  *) echo "usage: $0 [release|debug]" >&2; exit 2 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # client/apple
ROOT="$(cd "$HERE/../.." && pwd)"                       # repo root (the cargo workspace)
TARGETDIR="$ROOT/target"
HEADERS="$ROOT/crates/nil-apple/include"
OUT="$HERE/NilApple.xcframework"

echo "== build-engine: nil-apple ($PROFILE) -> $OUT =="
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true

cargo build -p nil-apple $PROFILE_FLAG --target aarch64-apple-darwin --target-dir "$TARGETDIR"
cargo build -p nil-apple $PROFILE_FLAG --target x86_64-apple-darwin  --target-dir "$TARGETDIR"

LIB_ARM="$TARGETDIR/aarch64-apple-darwin/$PROFILE/libnil_apple.a"
LIB_X86="$TARGETDIR/x86_64-apple-darwin/$PROFILE/libnil_apple.a"
[[ -f "$LIB_ARM" && -f "$LIB_X86" ]] || { echo "missing static lib(s): $LIB_ARM / $LIB_X86" >&2; exit 1; }

FAT="$(mktemp -d)/libnil_apple-macos-universal.a"
lipo -create "$LIB_ARM" "$LIB_X86" -output "$FAT"

rm -rf "$OUT"
xcodebuild -create-xcframework -library "$FAT" -headers "$HEADERS" -output "$OUT"
echo "== build-engine: wrote $OUT =="
