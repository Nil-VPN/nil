#!/usr/bin/env bash
#
# embed-systemextension.sh — embed + sign the NIL VPN macOS System Extension into the
# packaged .app produced by `tauri build`.
#
# ─────────────────────────────────────────────────────────────────────────────
# THIS SCRIPT CANNOT RUN IN THIS ENVIRONMENT.
# It requires the full macOS developer toolchain on a real Mac:
#   - Xcode + command-line tools (xcodebuild, codesign), and
#   - the System Extension Xcode project under client/apple (built via xcodegen,
#     which generates the .xcodeproj from client/apple/project.yml — run
#     `xcodegen generate` in client/apple first if the .xcodeproj is absent), and
#   - an Apple Developer org + the Network Extension entitlement to do a real
#     (non-ad-hoc) signature.
# None of that exists here (no Xcode, no dev-mode Mac, no Apple account). This is
# integration scaffolding: it is written to be correct and run later, on a Mac,
# AFTER `tauri build` has produced "NIL VPN.app".
# ─────────────────────────────────────────────────────────────────────────────
#
# What it does, in order:
#   1. Locate the built "NIL VPN.app" (positional arg, or the default Tauri path).
#   2. Build the System Extension (com.nilvpn.client.PacketTunnel.systemextension)
#      from client/apple via xcodebuild.
#   3. Copy the .systemextension into <App>/Contents/Library/SystemExtensions/.
#   4. codesign the SE (--options runtime, hardened, with the SE entitlements).
#   5. RE-SIGN the outer .app with the app entitlements — MANDATORY: injecting a
#      nested bundle invalidates the app's existing signature, so the whole app
#      must be re-sealed from the inside out or it will be rejected at launch.
#   6. Verify with `codesign --verify --deep --strict` and note the
#      `systemextensionsctl developer` state.
#
# PRIVACY (NIL SOUL): this script handles only build artifacts + signing. It must
# NEVER print or embed any node address, token, grant, or measurement — those
# never live in the bundle; the container app passes them at runtime via
# providerConfiguration (PD-2/PD-3). Nothing user-linkable is logged here.

set -euo pipefail

# ── Shared contract (must match every other file in the integration) ──────────
readonly APP_BUNDLE_ID="com.nilvpn.client"
readonly SE_BUNDLE_ID="com.nilvpn.client.PacketTunnel"
readonly SE_FILE_NAME="${SE_BUNDLE_ID}.systemextension"
readonly APP_NAME="NIL VPN"               # Tauri productName
readonly INSTALL_REQUIREMENT="/Applications"

# ── Resolve repo-relative absolute paths (independent of the caller's CWD) ────
# This script lives at <repo>/client/scripts/embed-systemextension.sh.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
readonly SCRIPT_DIR
readonly CLIENT_DIR="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd -P)"
readonly REPO_ROOT="$(cd -- "${CLIENT_DIR}/.." >/dev/null 2>&1 && pwd -P)"

readonly APPLE_PROJECT_DIR="${CLIENT_DIR}/apple"
readonly DEFAULT_APP_PATH="${CLIENT_DIR}/src-tauri/target/release/bundle/macos/${APP_NAME}.app"

# Entitlements (authored elsewhere in the integration; required inputs here).
readonly SE_ENTITLEMENTS="${REPO_ROOT}/crates/nil-apple/apple/PacketTunnel.entitlements"
readonly APP_ENTITLEMENTS="${REPO_ROOT}/crates/nil-apple/apple/NILVPN-App.entitlements"

# ── Signing identity: ad-hoc ("-") for local dev; override via env for a real ID
# e.g. CODESIGN_IDENTITY="Developer ID Application: Nil VPN (TEAMID)"
readonly CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"

# ── Logging helpers (stderr; never log anything user-linkable) ────────────────
log()  { printf '[embed-se] %s\n' "$*" >&2; }
err()  { printf '[embed-se] ERROR: %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [path/to/${APP_NAME}.app]

  Embeds + signs the System Extension (${SE_BUNDLE_ID}) into a packaged macOS app.
  Run AFTER 'tauri build'.

  Arg:        path to the built .app (default: ${DEFAULT_APP_PATH})
  Env:        CODESIGN_IDENTITY   signing identity (default: "-" ad-hoc for local dev)

  Requires a Mac with Xcode (xcodebuild, codesign) — cannot run in CI without the
  Apple toolchain. See the header comment.
EOF
}

# ── Preconditions: this only works on macOS with the Apple toolchain ──────────
[[ "$(uname -s)" == "Darwin" ]] || die "must run on macOS (Darwin); this host is $(uname -s). See header."
command -v xcodebuild >/dev/null 2>&1 || die "xcodebuild not found — install Xcode + command-line tools."
command -v codesign  >/dev/null 2>&1 || die "codesign not found — install Xcode command-line tools."
command -v systemextensionsctl >/dev/null 2>&1 \
  || log "WARN: systemextensionsctl not found; skipping the dev-mode state check (it ships with macOS)."

# ── Arg parsing ───────────────────────────────────────────────────────────────
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

APP_PATH_RAW="${1:-$DEFAULT_APP_PATH}"
# Normalize to an absolute path without requiring the .app to pre-exist's parent CWD.
if [[ -d "$APP_PATH_RAW" ]]; then
  APP_PATH="$(cd -- "$APP_PATH_RAW" >/dev/null 2>&1 && pwd -P)"
else
  APP_PATH="$APP_PATH_RAW"
fi
readonly APP_PATH

[[ -d "$APP_PATH" ]] || die "app bundle not found: ${APP_PATH}
  Build it first:  (cd \"${CLIENT_DIR}\" && pnpm tauri build)
  or pass the path explicitly:  $(basename "$0") /path/to/${APP_NAME}.app"

[[ "$APP_PATH" == *.app ]] || die "expected a .app bundle, got: ${APP_PATH}"
[[ -d "${APP_PATH}/Contents/MacOS" ]] || die "not a valid app bundle (no Contents/MacOS): ${APP_PATH}"

[[ -f "$SE_ENTITLEMENTS" ]] || die "SE entitlements missing: ${SE_ENTITLEMENTS}
  (must declare com.apple.developer.networking.networkextension = [packet-tunnel-provider-systemextension]
   and com.apple.security.application-groups = [group.${APP_BUNDLE_ID}])"
[[ -f "$APP_ENTITLEMENTS" ]] || die "app entitlements missing: ${APP_ENTITLEMENTS}
  (must additionally declare com.apple.developer.system-extension.install = true)"

[[ -d "$APPLE_PROJECT_DIR" ]] || die "System Extension Xcode project dir missing: ${APPLE_PROJECT_DIR}
  Generate it first:  (cd \"${APPLE_PROJECT_DIR}\" && xcodegen generate)"

# ── 1. Build the System Extension via xcodebuild ──────────────────────────────
# Locate an .xcodeproj / .xcworkspace under client/apple. If only project.yml is
# present, the project must be generated first with xcodegen.
log "Locating Xcode project under ${APPLE_PROJECT_DIR} ..."
XCWORKSPACE="$(/usr/bin/find "$APPLE_PROJECT_DIR" -maxdepth 1 -name '*.xcworkspace' -print -quit 2>/dev/null || true)"
XCODEPROJ="$(/usr/bin/find "$APPLE_PROJECT_DIR" -maxdepth 1 -name '*.xcodeproj' -print -quit 2>/dev/null || true)"

if [[ -z "$XCWORKSPACE" && -z "$XCODEPROJ" ]]; then
  if [[ -f "${APPLE_PROJECT_DIR}/project.yml" ]]; then
    if command -v xcodegen >/dev/null 2>&1; then
      log "No .xcodeproj found; running 'xcodegen generate' from project.yml ..."
      ( cd "$APPLE_PROJECT_DIR" && xcodegen generate )
      XCODEPROJ="$(/usr/bin/find "$APPLE_PROJECT_DIR" -maxdepth 1 -name '*.xcodeproj' -print -quit 2>/dev/null || true)"
    else
      die "no .xcodeproj/.xcworkspace and xcodegen not installed.
  Install xcodegen (brew install xcodegen) and run:  (cd \"${APPLE_PROJECT_DIR}\" && xcodegen generate)"
    fi
  fi
fi
[[ -n "$XCWORKSPACE" || -n "$XCODEPROJ" ]] \
  || die "no Xcode project found under ${APPLE_PROJECT_DIR} (need a .xcworkspace, .xcodeproj, or project.yml)."

# Build into a dedicated DerivedData dir so we can find the artifact deterministically.
readonly DERIVED_DATA="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/nilvpn-se-XXXXXX")"
cleanup() { [[ -n "${DERIVED_DATA:-}" && -d "$DERIVED_DATA" ]] && rm -rf "$DERIVED_DATA"; }
trap cleanup EXIT

XCODE_TARGET_FLAG=()
if [[ -n "$XCWORKSPACE" ]]; then
  XCODE_TARGET_FLAG=(-workspace "$XCWORKSPACE")
  log "Building SE from workspace: ${XCWORKSPACE}"
else
  XCODE_TARGET_FLAG=(-project "$XCODEPROJ")
  log "Building SE from project: ${XCODEPROJ}"
fi

# Build the SE scheme. The scheme name matches the SE target by convention;
# override with SE_SCHEME if the project names it differently.
readonly SE_SCHEME="${SE_SCHEME:-PacketTunnel}"
log "xcodebuild scheme='${SE_SCHEME}' config=Release (this needs Xcode + may take a while)..."
xcodebuild \
  "${XCODE_TARGET_FLAG[@]}" \
  -scheme "$SE_SCHEME" \
  -configuration Release \
  -derivedDataPath "$DERIVED_DATA" \
  -destination 'generic/platform=macOS' \
  CODE_SIGNING_ALLOWED=NO \
  build \
  || die "xcodebuild failed for scheme '${SE_SCHEME}'. Check the SE target/scheme name (override via SE_SCHEME)."
# (We sign explicitly below, so we let xcodebuild produce an unsigned artifact.)

# Find the produced .systemextension.
log "Locating built ${SE_FILE_NAME} ..."
BUILT_SE="$(/usr/bin/find "${DERIVED_DATA}/Build/Products" -type d -name "${SE_FILE_NAME}" -print -quit 2>/dev/null || true)"
[[ -n "$BUILT_SE" && -d "$BUILT_SE" ]] \
  || die "could not find ${SE_FILE_NAME} under ${DERIVED_DATA}/Build/Products after the build.
  Confirm the SE target's product name is exactly '${SE_BUNDLE_ID}' with a .systemextension wrapper."
log "Built SE: ${BUILT_SE}"

# ── 2. Copy the SE into the app bundle ────────────────────────────────────────
readonly SE_DEST_DIR="${APP_PATH}/Contents/Library/SystemExtensions"
readonly SE_DEST="${SE_DEST_DIR}/${SE_FILE_NAME}"
log "Embedding SE into ${SE_DEST_DIR}/ ..."
/bin/mkdir -p "$SE_DEST_DIR"
/bin/rm -rf "$SE_DEST"
/bin/cp -R "$BUILT_SE" "$SE_DEST"
[[ -d "$SE_DEST" ]] || die "failed to copy SE into the app bundle."

# ── 3. codesign the embedded SE (hardened runtime + SE entitlements) ──────────
# Inside-out: sign the nested SE FIRST, then re-seal the outer app.
log "Signing embedded SE  (identity='${CODESIGN_IDENTITY}', hardened runtime, SE entitlements)..."
codesign --force --sign "$CODESIGN_IDENTITY" \
  --options runtime \
  --timestamp=none \
  --entitlements "$SE_ENTITLEMENTS" \
  --identifier "$SE_BUNDLE_ID" \
  "$SE_DEST" \
  || die "codesign of the SE failed."

# ── 4. RE-SIGN the outer app (MANDATORY after injecting the nested SE) ─────────
# Injecting Contents/Library/SystemExtensions/... changed the app's contents and
# broke its existing seal. Re-sign the whole app (it re-seals nested code too).
log "Re-signing the outer app  (identity='${CODESIGN_IDENTITY}', hardened runtime, app entitlements)..."
codesign --force --sign "$CODESIGN_IDENTITY" \
  --options runtime \
  --timestamp=none \
  --entitlements "$APP_ENTITLEMENTS" \
  --identifier "$APP_BUNDLE_ID" \
  "$APP_PATH" \
  || die "codesign (re-sign) of the app failed."

# ── 5. Verify ─────────────────────────────────────────────────────────────────
log "Verifying signatures (codesign --verify --deep --strict)..."
codesign --verify --deep --strict --verbose=2 "$APP_PATH" \
  || die "codesign verification failed for ${APP_PATH}."
codesign --verify --deep --strict --verbose=2 "$SE_DEST" \
  || die "codesign verification failed for the embedded SE."
log "Signature verification OK."

# systemextensionsctl developer state (informational; needs root to toggle).
DEV_MODE_NOTE="(could not read; run 'systemextensionsctl developer' yourself)"
if command -v systemextensionsctl >/dev/null 2>&1; then
  DEV_MODE_NOTE="$(systemextensionsctl developer 2>/dev/null | /usr/bin/head -n1 || true)"
  [[ -n "$DEV_MODE_NOTE" ]] || DEV_MODE_NOTE="(no output)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
cat >&2 <<EOF

──────────────────────────────────────────────────────────────────────────────
 NIL VPN — System Extension embedded + signed
──────────────────────────────────────────────────────────────────────────────
 App bundle      : ${APP_PATH}
 Embedded SE     : ${SE_DEST}
 App bundle id   : ${APP_BUNDLE_ID}
 SE  bundle id   : ${SE_BUNDLE_ID}
 Signing identity: ${CODESIGN_IDENTITY}$( [[ "$CODESIGN_IDENTITY" == "-" ]] && printf '  (ad-hoc — LOCAL DEV ONLY; not distributable/notarizable)' )
 codesign verify : PASSED (--deep --strict)
 systemextensions: ${DEV_MODE_NOTE}

 NEXT STEPS (on this Mac):
   1. Enable SE developer mode (required to load an ad-hoc / non-App-Store SE):
          sudo systemextensionsctl developer on
   2. The app MUST live in ${INSTALL_REQUIREMENT} to install its System Extension.
      Copy it there before launching:
          cp -R "${APP_PATH}" ${INSTALL_REQUIREMENT}/
   3. Launch the app from ${INSTALL_REQUIREMENT}; it calls OSSystemExtensionRequest
      to activate the SE — approve it ONCE in
      System Settings > General > Login Items & Extensions.

 PRIVACY: nothing identifying is in this bundle. The node endpoint, pinned
 measurement, and per-connection grant are passed at runtime via the SE's
 providerConfiguration — never persisted, never logged. (NIL PD-2/PD-3)
──────────────────────────────────────────────────────────────────────────────
EOF

echo "OK: embedded + signed ${SE_FILE_NAME} into ${APP_PATH} and re-signed the app (verify PASSED)."
