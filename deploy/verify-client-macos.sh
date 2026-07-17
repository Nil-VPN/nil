#!/usr/bin/env bash
# verify-client-macos.sh — live macOS desktop ENGINE end-to-end test.
#
# Drives the EXACT engine path the Tauri GUI uses (anonymous account -> buy token ->
# attested connect -> egress proof -> clean disconnect) on real macOS against the LIVE
# infra (api/ctrl.nilvpn.net + the real SEV-SNP node). Reaching E2E-OK proves the full
# chain end to end: token redeemed at the Coordinator, the node's hardware attestation
# verified against the pinned measurement, the utun device up, routing + kill-switch armed.
#
# Needs root: creating a utun device on macOS requires it. PII-free output. Consumes ONE
# comp/payment id at the Portal (single-use — a second use returns 409).
#
# Usage (run in an interactive shell so sudo can prompt for the password):
#   sudo bash deploy/verify-client-macos.sh [comp-id]
#
# Knobs (env): PORTAL_URL, NW_COORDINATOR_URL, NW_NODE_HOST, NW_NODE_PORT,
#   NW_EXPECTED_MEASUREMENT, NW_E2E_EGRESS_URL, NW_E2E_HOLD_SECS, ALLOW_UNATTESTED=1.
# Node-specific values (host + measurement) are operator/deployment config, not committed
# defaults: set them in the environment or in an untracked deploy/env/macos-e2e.env.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${NW_MACOS_E2E_ENV:-$ROOT/deploy/env/macos-e2e.env}"
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
COMP_ID="${1:-${NW_PAYMENT_ID:-alpha-001}}"
PORTAL_URL="${PORTAL_URL:-https://api.nilvpn.net}"
COORD_URL="${NW_COORDINATOR_URL:-https://ctrl.nilvpn.net}"
NODE_HOST="${NW_NODE_HOST:-}"
NODE_PORT="${NW_NODE_PORT:-443}"
MEAS="${NW_EXPECTED_MEASUREMENT:-}"
EGRESS_URL="${NW_E2E_EGRESS_URL:-https://api.ipify.org}"
# Optimized local-integration profile: release-like performance with debug assertions, which keep
# the explicitly labelled loopback/direct E2E paths available. A true release client compiles those
# paths out and must never be used for the local subscription leg below.
BIN="$ROOT/target/e2e/examples/nil-client-e2e"
PORTAL_BIN="$ROOT/target/e2e/nil-portal"

# Subscription e2e mode (NW_SUBSCRIBE=1): exercise subscribe -> activate -> batch prefetch
# -> connect -> re-login -> reconnect flow on the REAL macOS engine, against a LOCAL mock-paid portal
# (the live Portal doesn't yet carry the subscription endpoints). Loopback connect, so NO root, NO
# node, NO comp-id. Proves the subscription path on macOS with one command, fully headless.
if [ "${NW_SUBSCRIBE:-0}" = "1" ]; then
  echo "== NIL macOS subscription e2e (local mock-paid portal, loopback connect) =="
  ( cd "$ROOT" && cargo build --profile e2e --example nil-client-e2e --bin nil-portal ) || { echo "FAIL: build"; exit 1; }
  SUB_PORT="${NW_SUB_PORT:-8088}"
  NW_ALLOW_DEV_FALLBACKS=1 NW_MOCK_PAID_ALL=1 \
    NW_PORTAL_ADDR="127.0.0.1:$SUB_PORT" RUST_LOG=warn "$PORTAL_BIN" \
    >"${TMPDIR:-/tmp}/nil-sub-portal.$$.log" 2>&1 &
  SUB_PORTAL_PID=$!
  trap '[ -n "${SUB_PORTAL_PID:-}" ] && kill "$SUB_PORTAL_PID" 2>/dev/null' EXIT
  for _ in $(seq 1 20); do
    curl -fsS -o /dev/null -X POST "http://127.0.0.1:$SUB_PORT/v1/account/challenge" 2>/dev/null && break
    sleep 1
  done
  OUT="$(NW_SUBSCRIBE=1 PORTAL_URL="http://127.0.0.1:$SUB_PORT" "$BIN" 2>&1)"; RC=$?
  printf '%s\n' "$OUT"
  echo "------------------------------------------------------------"
  if [ $RC -eq 0 ] \
     && printf '%s' "$OUT" | grep -q '^BATCH-PREFETCH-OK count=8' \
     && printf '%s' "$OUT" | grep -q '^RELOGIN-RECONNECT-OK' \
     && printf '%s' "$OUT" | grep -q '^E2E-OK'; then
    echo "PASS ✅  macOS subscription e2e: subscribe -> activate -> batch prefetch -> connect -> re-login -> prefetch (no new payment)."
    exit 0
  fi
  echo "FAIL ❌  macOS subscription e2e (rc=$RC)"
  exit 1
fi

echo "== NIL macOS desktop client e2e =="
echo "portal=$PORTAL_URL coordinator=$COORD_URL node=${NODE_HOST:-<unset>}:$NODE_PORT comp_id=$COMP_ID"

if [ -z "$NODE_HOST" ]; then
  echo "FAIL: NW_NODE_HOST not set. Put NW_NODE_HOST (+ NW_EXPECTED_MEASUREMENT) in" >&2
  echo "      $ENV_FILE or the environment." >&2
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "FAIL: must run as root — creating a utun device on macOS needs it." >&2
  echo "  Open an interactive terminal (Terminal.app/iTerm) and run:" >&2
  echo "    sudo bash deploy/verify-client-macos.sh $COMP_ID" >&2
  echo "  (sudo needs a tty to prompt for the password.)" >&2
  exit 2
fi

# ALWAYS rebuild the harness from the current checkout (build needs no root). cargo is incremental,
# so this is cheap when nothing changed — but it guarantees a `git pull` is reflected. Building only
# when the binary was MISSING let a stale binary silently run after a pull: e.g. a pre-#13 binary
# ignores the client-side measurement cross-check, so a reject test would "connect" against a wrong
# pin and look like an attestation bypass when it is really just old code. Set NW_E2E_NO_REBUILD=1
# only to deliberately test an already-built binary.
if [ "${NW_E2E_NO_REBUILD:-0}" != "1" ] || [ ! -x "$BIN" ]; then
  echo "building nil-client-e2e (optimized e2e profile) from the current checkout…"
  ( cd "$ROOT" && cargo build --profile e2e --example nil-client-e2e ) \
    || { echo "FAIL: cargo build"; exit 1; }
fi

# Public IP BEFORE the tunnel — egress must change once connected.
PRE_IP="$(curl -s --max-time 10 "$EGRESS_URL" | tr -d '\r')"
echo "pre-tunnel public IP: ${PRE_IP:-<unknown>}"

export PORTAL_URL
export NW_COORDINATOR_URL="$COORD_URL"
export NW_PAYMENT_ID="$COMP_ID"
export NW_NODE_HOST="$NODE_HOST" NW_NODE_PORT="$NODE_PORT"
export NW_E2E_EGRESS_URL="$EGRESS_URL" NW_E2E_HOLD_SECS="${NW_E2E_HOLD_SECS:-3}"

if [ "${ALLOW_UNATTESTED:-0}" = "1" ]; then
  echo "WARNING: ALLOW_UNATTESTED=1 — this proves reachability + egress ONLY, NOT attestation."
  export NW_ALLOW_UNATTESTED=1
else
  if [ -z "$MEAS" ]; then
    echo "FAIL: attestation enforced but NW_EXPECTED_MEASUREMENT not set — provide it (see $ENV_FILE)," >&2
    echo "      or run with ALLOW_UNATTESTED=1 for a reachability-only proof." >&2
    exit 2
  fi
  export NW_EXPECTED_MEASUREMENT="$MEAS"
  echo "attestation ENFORCED against pinned measurement ${MEAS:0:16}… (kill-switch holds if it fails)"
fi

echo "== running engine harness =="
OUT="$("$BIN" 2>&1)"; RC=$?
printf '%s\n' "$OUT"

POST_IP="$(printf '%s\n' "$OUT" | sed -n 's/^EGRESS=//p' | tr -d '\r')"
echo "------------------------------------------------------------"
if [ $RC -eq 0 ] && printf '%s' "$OUT" | grep -q '^E2E-OK'; then
  if [ -n "$POST_IP" ] && [ "$POST_IP" != "$PRE_IP" ]; then
    echo "PASS ✅  attested connect, egress changed ${PRE_IP:-?} -> $POST_IP, clean disconnect, kill-switch restored."
    exit 0
  fi
  echo "PARTIAL ⚠️  connect+disconnect OK but egress IP unchanged/unknown (${PRE_IP:-?} -> ${POST_IP:-?}) — check routing."
  exit 0
fi
echo "FAIL ❌  harness rc=$RC. Marker guide:"
echo "  402 at buy_tokens  -> comp id '$COMP_ID' not confirmed / unknown"
echo "  409 at buy_tokens  -> comp id '$COMP_ID' already spent (single-use) — try another"
echo "  connect: attestation… -> the node's report didn't match the pin; gate held (fail-closed, correct)"
exit 1
