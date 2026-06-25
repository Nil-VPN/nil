#!/usr/bin/env bash
# Full-stack end-to-end verification — the WHOLE NIL pipeline in Docker, host untouched.
#
#   nil-portal   issues an unlinkable Privacy Pass token (gated on a confirmed payment)
#        ↓ (blinded; the issuer never sees the token the verifier later does — Pillar 4)
#   nil-coordinator  verifies the token, enforces single-use (nullifier), grants a trust-split path
#        ↓
#   the datapath  redeems the token, builds the 3-hop attested MASQUE onion over the granted path
#        ↓
#   real HTTPS traffic flows end to end.
#
# Each piece is unit/integration-tested in isolation elsewhere; this proves they COMPOSE. The
# synthetic RA-TLS report stands in for real TEE hardware (the nil-attest KATs cover the genuine
# vendor-root path).
set -uo pipefail
cd "$(dirname "$0")"
fail=0
DC="docker compose -f compose.e2e.yaml"

# Must equal the entry/middle/exit NW_NODE_MEASUREMENT in compose.e2e.yaml.
M="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
PORTAL=10.82.0.5; COORD=10.82.0.6
ENTRY=10.82.0.11; MIDDLE=10.82.0.12; EXIT=10.82.0.13
DEST=1.1.1.1

cleanup() { echo; echo "==> teardown"; $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "==> build + start portal, coordinator, entry/middle/exit, client"
$DC up -d --build || { echo "compose up failed"; exit 1; }
sleep 6

echo "==> read the Portal's Privacy Pass issuer public key from its log"
PUBKEY=$($DC logs portal 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'token_pubkey=[0-9a-f]+' | head -1 | cut -d= -f2)
if [ -z "$PUBKEY" ]; then
  echo "  FAIL: Portal did not report an issuer public key"; $DC logs portal 2>/dev/null | tail -8; exit 1
fi
echo "  issuer pubkey: ${PUBKEY:0:32}… (${#PUBKEY} hex chars)"

echo "==> write the Coordinator node registry (3 operator/jurisdiction-diverse nodes, all pinned to \$M)"
$DC exec -T coordinator sh -c 'cat > /tmp/registry.json' <<EOF
[
  {"host":"$ENTRY","port":443,"tee":"sev-snp","measurement":"$M","operator":"op-a","jurisdiction":"jur-a"},
  {"host":"$MIDDLE","port":443,"tee":"sev-snp","measurement":"$M","operator":"op-b","jurisdiction":"jur-b"},
  {"host":"$EXIT","port":443,"tee":"sev-snp","measurement":"$M","operator":"op-c","jurisdiction":"jur-c"}
]
EOF

echo "==> start the Coordinator (verifier = the Portal's PUBLIC key only; 3-hop diverse paths)"
# NW_NULLIFIER_PATH points the spent-token set at a durable file, so this e2e exercises the REAL
# production nullifier path (the fail-closed DurableSet with fsync) — not the volatile dev escape
# hatch. The Coordinator refuses to boot with a volatile set unless NW_ALLOW_DEV_FALLBACKS=1; an
# end-to-end test should prove the durable path composes, so we give it a real file rather than
# opting out of the guard.
$DC exec -e NW_COORDINATOR_ADDR=0.0.0.0:9000 -e NW_TOKEN_PUBKEY="$PUBKEY" \
  -e NW_NODE_REGISTRY=/tmp/registry.json -e NW_PATH_HOPS=3 \
  -e NW_NULLIFIER_PATH=/tmp/nullifiers.log \
  -d coordinator sh -c 'nil-coordinator > /tmp/coord.log 2>&1'
cup=0
for _ in $(seq 1 20); do
  if $DC exec -T client curl -s -o /dev/null --max-time 2 "http://$COORD:9000/healthz"; then cup=1; break; fi
  sleep 1
done
[ "$cup" = 1 ] && echo "  coordinator listening" \
  || { echo "  FAIL: coordinator did not start"; $DC exec -T coordinator tail -n 15 /tmp/coord.log 2>/dev/null; exit 1; }

# Acquire an unlinkable token via the REAL client flow. nil-provision now does the whole thing:
# POST /v1/billing/checkout to mint a server reference, then blind-issue against it. The Portal runs
# with NW_MOCK_PAID_ALL=1, so the minted reference reads as paid (standing in for a confirmed Monero
# payment) — but the front-running guard still requires it to be a reference we minted, so this
# exercises the composed checkout→issue path through the production client code (no NW_PAYMENT_ID).
# Echoes the NW_TOKEN_* lines on STDOUT; nil-provision's human prompts/errors go to STDERR (left
# visible, not /dev/null'd) so an issuance refusal shows in the log instead of a silent empty result.
acquire() {
  $DC exec -T -e NW_PORTAL_URL="http://$PORTAL:8080" client nil-provision | tr -d '\r'
}

echo
echo "================ CONTROL PLANE: issue → redeem → single-use ================"
prov=$(acquire)
MSG=$(printf '%s\n' "$prov" | grep '^NW_TOKEN_MSG=' | cut -d= -f2)
TOK=$(printf '%s\n' "$prov" | grep '^NW_TOKEN=' | cut -d= -f2)
if [ -z "$MSG" ] || [ -z "$TOK" ]; then
  echo "  FAIL: token acquisition produced no token"; printf '%s\n' "$prov"; fail=1
else
  echo "  PASS: acquired an unlinkable token from the Portal (msg ${MSG:0:16}…)"
  body="{\"msg\":\"$MSG\",\"token\":\"$TOK\"}"
  c1=$($DC exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'content-type: application/json' -d "$body" "http://$COORD:9000/v1/redeem")
  c2=$($DC exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'content-type: application/json' -d "$body" "http://$COORD:9000/v1/redeem")
  echo "  redeem #1 → HTTP $c1   redeem #2 → HTTP $c2"
  [ "$c1" = "200" ] && echo "  PASS: first redemption granted a trust-split path" || { echo "  FAIL: first redemption not 200"; fail=1; }
  [ "$c2" = "409" ] && echo "  PASS: replay rejected — single-use nullifier holds" || { echo "  FAIL: replay not rejected (want 409, got $c2)"; fail=1; }
fi

echo
echo "================ ATTESTATION CROSS-CHECK: client-side measurement pin (audit #13) ================"
# Pillar 2, client side: when the client pins a measurement (NW_EXPECTED_MEASUREMENT), the datapath
# must REFUSE a Coordinator-granted path whose per-hop measurement isn't in that pin set
# (redeem::cross_check_pins, fail-closed). The automated, CI-guarded analogue of the live macOS
# reject test (here against synthetic attestation; the nil-attest KATs cover the real vendor-root
# path). Runs BEFORE the positive tunnel: cross_check_pins refuses during redeem, before the
# datapath arms the kill-switch, so NO tunnel/kill-switch lingers to block the Portal afterward.
WRONG=$(printf 'ee%.0s' $(seq 1 48)) # 96 hex chars, guaranteed != $M
prov=$(acquire); MSG=$(printf '%s\n' "$prov" | grep '^NW_TOKEN_MSG=' | cut -d= -f2)
TOK=$(printf '%s\n' "$prov" | grep '^NW_TOKEN=' | cut -d= -f2)
if [ -z "$TOK" ]; then echo "  FAIL: token acquisition (reject test) failed"; fail=1; else
  $DC exec -e NW_COORDINATOR_URL="http://$COORD:9000" -e NW_EXPECTED_MEASUREMENT="$WRONG" \
    -e NW_TOKEN_MSG="$MSG" -e NW_TOKEN="$TOK" -d client sh -c 'nil-cli > /tmp/reject.log 2>&1'
  rup=0
  for _ in $(seq 1 30); do
    $DC exec -T client grep -q "tunnel up" /tmp/reject.log 2>/dev/null && { rup=1; break; }
    $DC exec -T client grep -qiE "pinned set|cross.?check|refus|measurement" /tmp/reject.log 2>/dev/null && break
    sleep 1
  done
  if [ "$rup" = 1 ]; then
    echo "  FAIL: onion came up despite a WRONG client pin — cross-check did NOT fail closed"; fail=1
    $DC exec -T client sed 's/\x1b\[[0-9;]*m//g' /tmp/reject.log 2>/dev/null | tail -n 8
  else
    echo "  PASS: a wrong client measurement pin is refused — no tunnel (cross-check holds, fail-closed)"
  fi
  $DC exec -T client pkill -f nil-cli 2>/dev/null; sleep 1 # ensure nothing lingers (it shouldn't)
fi

echo
echo "================ DATA PLANE: token → coordinator-granted onion → real traffic ================"
# Positive runs LAST (it leaves the tunnel + kill-switch up). NW_EXPECTED_MEASUREMENT=\$M doubles as
# the ACCEPT half of the cross-check: the CORRECT pin must still bring the onion up (cross-check
# allows the genuine Coordinator-granted measurement, not just refuse a wrong one).
prov=$(acquire)
MSG=$(printf '%s\n' "$prov" | grep '^NW_TOKEN_MSG=' | cut -d= -f2)
TOK=$(printf '%s\n' "$prov" | grep '^NW_TOKEN=' | cut -d= -f2)
if [ -z "$TOK" ]; then
  echo "  FAIL: token acquisition (tunnel) failed"; fail=1
else
  echo "==> nil-cli redeems the token (pinned to \$M) and brings up the GRANTED 3-hop onion"
  $DC exec -e NW_COORDINATOR_URL="http://$COORD:9000" -e NW_EXPECTED_MEASUREMENT="$M" \
    -e NW_TOKEN_MSG="$MSG" -e NW_TOKEN="$TOK" -d client \
    sh -c 'nil-cli > /tmp/e2e.log 2>&1'
  up=0
  for _ in $(seq 1 50); do
    $DC exec -T client grep -q "tunnel up" /tmp/e2e.log 2>/dev/null && { up=1; break; }
    $DC exec -T client grep -qE "Error|panicked|refus" /tmp/e2e.log 2>/dev/null && break
    sleep 1
  done
  echo "---- client log ----"; $DC exec -T client sed 's/\x1b\[[0-9;]*m//g' /tmp/e2e.log 2>/dev/null | tail -n 20
  if [ "$up" != 1 ]; then
    echo "  FAIL: onion did not come up from the coordinator-granted path (with the matching pin)"; fail=1
  else
    echo "  PASS: the matching client pin is accepted — datapath built the granted 3-hop onion"
    # Retry the through-onion probe. Even after "tunnel up", a freshly-built 3-hop nested onion
    # needs a moment for routes to settle and the FIRST request to warm each hop's QUIC handshake,
    # so a single immediate curl can transiently time out on a slow CI runner — a flake confirmed
    # by identical trees both passing and failing here. Retrying absorbs that first-packet warmup;
    # a genuine no-traffic condition still fails after every attempt (the assertion isn't weakened).
    code=""
    for _ in $(seq 1 6); do
      code=$($DC exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 25 "https://$DEST/cdn-cgi/trace" 2>/dev/null)
      { [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; } 2>/dev/null && break
      sleep 2
    done
    echo "  tunneled HTTP ${code:-none}"
    if { [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; } 2>/dev/null; then
      echo "  PASS: real traffic flows Portal-issued → Coordinator-granted → onion → $DEST"
    else
      echo "  FAIL: no traffic through the granted onion"; fail=1
      # Diagnostics for this intermittent failure: the handshake succeeded ("tunnel up") but NO data
      # traversed the 3-hop onion (HTTP 000 for the whole probe window). The client log alone can't
      # show WHERE — entry/middle/exit — the data dies, so dump each hop's log + the coordinator's and
      # the client's tunnel routing. Runs only on this failure path; never affects a passing run.
      echo "================ DIAGNOSTICS (intermittent onion no-traffic) ================"
      for svc in coordinator entry middle exit; do
        echo "---- $svc log (tail 40) ----"
        $DC logs --tail 40 "$svc" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
      done
      echo "---- client tunnel addr + routes ----"
      $DC exec -T client sh -c 'ip -br addr show nil0; ip route show' 2>/dev/null
    fi
  fi
fi

echo
[ "$fail" = 0 ] && echo "RESULT: FULL-STACK E2E PASSED ✅" || echo "RESULT: FAILURES ❌"
exit "$fail"
