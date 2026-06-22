#!/usr/bin/env bash
# wstunnel-failover verification (architecture spec §4.3, cascade rung 3) — all in Docker, host
# untouched. With the MASQUE rung blocked (UDP 443 dropped), the client must step down to the
# wstunnel rung (WireGuard over WebSocket-over-TLS, on TCP) and still carry traffic. wstunnel is
# the *only* fallback configured here, so a successful tunnel proves the wstunnel path.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
DC="docker compose -f compose.wstunnel.yaml"

M="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
MASQUE=10.81.0.10
WST=10.81.0.11
DEST=1.1.1.1

cleanup() { echo; echo "==> teardown"; $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "==> build + start the MASQUE node, the wstunnel node, and the client"
$DC up -d --build || { echo "compose up failed"; exit 1; }
sleep 6

echo "==> read the wstunnel node's WireGuard public key from its log"
WG_PUB=$($DC logs wst-node 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'wg_pub=[0-9a-f]{64}' | head -1 | cut -d= -f2)
echo "  wst-node WG pubkey: ${WG_PUB:-<none>}"
if [ -z "$WG_PUB" ]; then
  echo "  FAIL: wstunnel node did not report a WireGuard public key"; $DC logs wst-node 2>/dev/null | tail -8; exit 1
fi

echo "==> BLOCK the MASQUE rung on the client (drop UDP 443 to the MASQUE node)"
$DC exec -T client iptables -A OUTPUT -p udp -d "$MASQUE" --dport 443 -j DROP

echo "==> start nil-cli with the cascade (MASQUE primary → wstunnel fallback)"
$DC exec \
  -e NW_CASCADE=1 \
  -e NW_NODE_HOST="$MASQUE" -e NW_NODE_PORT=443 \
  -e NW_EXPECTED_MEASUREMENT="$M" -e NW_EXPECTED_TEE=sev-snp \
  -e NW_NODE_WSTUNNEL_HOST="$WST" -e NW_NODE_WSTUNNEL_PORT=443 -e NW_NODE_WSTUNNEL_WG_PUB="$WG_PUB" \
  -e NW_KILLSWITCH=0 \
  -d client sh -c 'nil-cli > /tmp/wstunnel.log 2>&1'

# MASQUE must time out first before the cascade steps down, so allow plenty of time.
up=0
for _ in $(seq 1 45); do
  if $DC exec -T client grep -q "tunnel up" /tmp/wstunnel.log 2>/dev/null; then up=1; break; fi
  sleep 1
done
echo "---- client log ----"; $DC exec -T client sed 's/\x1b\[[0-9;]*m//g' /tmp/wstunnel.log 2>/dev/null | tail -n 22

if [ "$up" != 1 ]; then
  echo "  FAIL: no tunnel came up (cascade did not fail over)"; fail=1
else
  echo "  PASS: a tunnel came up"
  # The winning rung must be wstunnel (the MASQUE primary was blocked).
  if $DC exec -T client grep -qiE "wstunnel tunnel established|cascade connected.*Wstunnel" /tmp/wstunnel.log 2>/dev/null; then
    echo "  PASS: failed over to the wstunnel rung"
  else
    echo "  FAIL: tunnel came up but not via wstunnel"; fail=1
  fi
  echo "==> curl the destination THROUGH the wstunnel fallback (https://$DEST/cdn-cgi/trace)"
  code=$($DC exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 25 "https://$DEST/cdn-cgi/trace" 2>/dev/null)
  echo "  tunneled HTTP ${code:-none}"
  if { [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; } 2>/dev/null; then
    echo "  PASS: real traffic flows over WireGuard-in-WebSocket-over-TLS"
  else
    echo "  FAIL: no traffic through the fallback"; fail=1
  fi
fi

echo
[ "$fail" = 0 ] && echo "RESULT: WSTUNNEL FAILOVER PASSED ✅" || echo "RESULT: FAILURES ❌"
exit "$fail"
