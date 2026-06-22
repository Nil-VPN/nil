#!/usr/bin/env bash
# Phase 1 end-to-end verification — all in Docker, host untouched.
# Proves: (a) traffic flows through the MASQUE tunnel, (c) the kill-switch blocks traffic
# fail-closed when the node stops. (b) egress IP is informational — a *local* node exits
# via the same host uplink, so it matches the baseline; only a remote node changes it.
set -uo pipefail
cd "$(dirname "$0")"
fail=0

echo "==> building images + starting node"
docker compose up -d --build || { echo "compose up failed"; exit 1; }
sleep 4
echo "---- node log ----"; docker compose logs node 2>/dev/null | tail -8

echo; echo "==> baseline egress IP (client, NO tunnel)"
echo "  $(docker compose exec -T client curl -s --max-time 8 https://ifconfig.me 2>/dev/null || echo '(failed)')"

echo; echo "==> starting the tunnel (nil-cli) in the client"
docker compose exec -d client sh -c 'nil-cli > /tmp/cli.log 2>&1'

echo "==> waiting for 'tunnel up' (max 15s)"
up=0
for _ in $(seq 1 15); do
  if docker compose exec -T client grep -q "tunnel up" /tmp/cli.log 2>/dev/null; then up=1; break; fi
  sleep 1
done
echo "---- nil-cli log ----"; docker compose exec -T client tail -n 20 /tmp/cli.log 2>/dev/null
echo "---- client routes ----"; docker compose exec -T client ip route 2>/dev/null
[ "$up" = 1 ] && echo "  PASS: tunnel up" || { echo "  FAIL: tunnel did not come up"; fail=1; }

echo; echo "==> (a) traffic through the tunnel: curl https://example.com"
code=$(docker compose exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com 2>/dev/null)
echo "  HTTP ${code:-none}"
[ "$code" = "200" ] && echo "  PASS (a): tunneled HTTPS works" || { echo "  FAIL (a)"; fail=1; }

echo; echo "==> (b) egress IP through tunnel (local node → expected same as baseline)"
echo "  $(docker compose exec -T client curl -s --max-time 15 https://ifconfig.me 2>/dev/null || echo '(failed)')"

echo; echo "==> (c) kill-switch: stop the node — traffic MUST fail closed"
docker compose stop node >/dev/null 2>&1
sleep 1
if docker compose exec -T client curl -s -o /dev/null --max-time 6 https://example.com 2>/dev/null; then
  echo "  FAIL (c): traffic STILL flowed after node stopped — LEAK"; fail=1
else
  echo "  PASS (c): blocked fail-closed"
fi

echo; echo "==> teardown"; docker compose down -v >/dev/null 2>&1
echo
[ "$fail" = 0 ] && echo "RESULT: ALL CHECKS PASSED ✅" || echo "RESULT: FAILURES ❌"
exit "$fail"
