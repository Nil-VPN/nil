#!/usr/bin/env bash
# Leak-prevention verification (go-live gate, runbook §11) — all in Docker, host untouched.
#
# With the tunnel UP and the fail-closed kill-switch armed, proves there is no path for traffic
# to leave except through the tunnel:
#   1. IPv6 egress is blocked wholesale (the tunnel is IPv4-only) — the classic IPv6 leak.
#   2. Real traffic flows through the tunnel.
#   3. A direct egress that bypasses the TUN (forced out eth0 to a non-node host) is dropped.
set -uo pipefail
cd "$(dirname "$0")"
fail=0

# Must equal NW_NODE_MEASUREMENT in compose.yaml (the value the node attests to).
M="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
DEST=1.1.1.1   # a fixed public IP, never the node (10.80.0.10)

cleanup() { echo; echo "==> teardown"; docker compose down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "==> build + start the attested node"
docker compose up -d --build || { echo "compose up failed"; exit 1; }
sleep 4

echo "==> start nil-cli (tunnel up, fail-closed kill-switch armed)"
docker compose exec -e NW_EXPECTED_MEASUREMENT="$M" -e NW_EXPECTED_TEE=sev-snp -d client \
  sh -c 'nil-cli > /tmp/leak.log 2>&1'
up=0
for _ in $(seq 1 25); do
  if docker compose exec -T client grep -q "tunnel up" /tmp/leak.log 2>/dev/null; then up=1; break; fi
  sleep 1
done
if [ "$up" != 1 ]; then
  echo "  FAIL: tunnel did not come up"; docker compose exec -T client tail -n 15 /tmp/leak.log 2>/dev/null
  exit 1
fi
echo "  tunnel up"

echo "==> ASSERT 1: IPv6 egress is blocked (kill-switch ip6tables DROP policy)"
v6pol=$(docker compose exec -T client ip6tables -S OUTPUT 2>/dev/null | head -1 | tr -d '\r')
echo "    ip6tables OUTPUT policy: ${v6pol:-<none>}"
if [ "$v6pol" = "-P OUTPUT DROP" ]; then echo "  PASS: IPv6 leak path is closed"; else echo "  FAIL: IPv6 egress not blocked"; fail=1; fi

echo "==> ASSERT 2: real traffic flows through the tunnel"
code=$(docker compose exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://$DEST/cdn-cgi/trace" 2>/dev/null)
echo "    tunneled HTTP ${code:-none}"
if { [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; } 2>/dev/null; then echo "  PASS: tunneled traffic works"; else echo "  FAIL: no traffic through the tunnel"; fail=1; fi

echo "==> ASSERT 3: a direct egress bypassing the tunnel (out eth0) is dropped"
if docker compose exec -T client curl -s -o /dev/null --max-time 6 --interface eth0 "https://$DEST/" 2>/dev/null; then
  echo "  FAIL: traffic leaked directly out eth0 (bypassed the tunnel)"; fail=1
else
  echo "  PASS: direct (non-tunnel) egress is blocked by the kill-switch"
fi

echo
[ "$fail" = 0 ] && echo "RESULT: LEAK PREVENTION PASSED ✅" || echo "RESULT: FAILURES ❌"
exit "$fail"
