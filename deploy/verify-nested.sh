#!/usr/bin/env bash
# Phase 2 nested datapath — all in Docker, host untouched.
#
# Proves real traffic flows: client IP packet → inner PQ-WireGuard (boringtun, keyed by the
# ML-KEM-1024 + Classic McEliece 460896 hybrid PSK) → MASQUE/CONNECT-IP datagram → node →
# MASQUE decapsulate → PQ-WireGuard decapsulate → IP → NAT exit → internet. On the wire it is
# still QUIC on UDP 443 (the WireGuard layer rides inside the datagrams).
#
# The node attests (synthetic report) AND runs the PQ-WireGuard responder; the client pins the
# measurement and the node's WireGuard public key (extracted from the node log).
set -uo pipefail
cd "$(dirname "$0")"
fail=0
DC="docker compose -f compose.yaml -f compose.pqwg.yaml"

# Must match NW_NODE_MEASUREMENT in compose.yaml (the value the node attests to).
M="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"

echo "==> build + start node (attested + PQ-WireGuard responder)"
$DC up -d --build || { echo "compose up failed"; exit 1; }
sleep 5

echo "==> extract the node's WireGuard public key from its log"
WG_PUB=$($DC logs node 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'wg_pub=[0-9a-f]{64}' | head -1 | cut -d= -f2)
echo "  node WG pubkey: ${WG_PUB:-<none>}"
if [ -z "$WG_PUB" ]; then
  echo "  FAIL: node did not report a WireGuard public key (is NW_NODE_PQWG set?)"
  $DC logs node 2>/dev/null | tail -8
  $DC down -v >/dev/null 2>&1
  exit 1
fi

echo "==> start nil-cli with the inner PQ-WireGuard layer (NW_NODE_WG_PUB set)"
$DC exec -e NW_NODE_WG_PUB="$WG_PUB" -e NW_EXPECTED_MEASUREMENT="$M" -e NW_EXPECTED_TEE=sev-snp -d client \
  sh -c 'nil-cli > /tmp/nested.log 2>&1'

up=0
for _ in $(seq 1 40); do
  if $DC exec -T client grep -q "tunnel up" /tmp/nested.log 2>/dev/null; then up=1; break; fi
  sleep 1
done
echo "---- nested log ----"; $DC exec -T client tail -n 25 /tmp/nested.log 2>/dev/null

if [ "$up" = 1 ]; then
  echo "  PASS: PQ-WireGuard tunnel established inside MASQUE"
  code=$($DC exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://example.com 2>/dev/null)
  echo "  tunneled HTTP ${code:-none}"
  if [ "$code" = "200" ]; then
    echo "  PASS: real traffic flows IP → PQ-WG → MASQUE → PQ-WG → IP → NAT → internet"
  else
    echo "  FAIL: no traffic through the nested tunnel"; fail=1
  fi
else
  echo "  FAIL: nested PQ-WireGuard tunnel did not come up"; fail=1
fi

echo; echo "==> teardown"; $DC down -v >/dev/null 2>&1
echo
[ "$fail" = 0 ] && echo "RESULT: NESTED PQ-WIREGUARD-OVER-MASQUE PASSED ✅" || echo "RESULT: FAILURES ❌"
exit "$fail"
