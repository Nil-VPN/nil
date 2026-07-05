#!/usr/bin/env bash
# ALL-PQ trust-split (multi-hop) verification — all in Docker, host untouched.
#
# Every hop is a PQ-WireGuard responder (NW_NODE_PQWG): the client stacks attested MASQUE/CONNECT-IP
# tunnels EACH wrapped in an inner ML-KEM-1024 + Classic McEliece hybrid-PSK WireGuard session
# (spec §4.2 over §6). This proves intermediate nodes terminate their PQ responder and FORWARD the
# decapsulated inner QUIC to the next hop — the "all-PQ onion" is live, not just in-process-proven.
#
# MTU reality (honest): each PQ hop adds WireGuard's 32 B on top of the CONNECT-IP + udpip nesting
# overhead, so on a standard (<=1500 B) path a **2-hop** all-PQ onion fits but a **3-hop** all-PQ
# onion overruns the 1200 B QUIC floor and FAILS CLOSED (`connect_nested` refuses rather than
# corrupt). We therefore (1) prove traffic + trust-split over a 2-hop all-PQ onion, and (2) assert
# the 3-hop all-PQ path fails closed — turning the MTU limit into a tested property. A 3-hop
# trust-split today uses plain nested MASQUE (lower overhead); reducing the per-hop tax to make
# 3-hop all-PQ fit is tracked separately.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
DC="docker compose -f compose.trustsplit.yaml -f compose.trustsplit-pq.yaml"

M="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
ENTRY=10.80.0.11; MIDDLE=10.80.0.12; EXIT=10.80.0.13
CLIENT=10.80.0.30
DEST=1.1.1.1

cleanup() { echo; echo "==> teardown"; $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "==> build + start entry, middle, exit + client (all synthetic-attest + NW_NODE_PQWG)"
$DC up -d --build entry middle exit client || { echo "compose up failed"; exit 1; }

# Each node generates an EPHEMERAL WireGuard static key at boot and logs it as wg_pub=<64 hex>.
get_wg() { $DC logs "$1" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'wg_pub=[0-9a-f]{64}' | head -1 | cut -d= -f2; }
WG_ENTRY=""; WG_MIDDLE=""; WG_EXIT=""
for _ in $(seq 1 20); do
  WG_ENTRY=$(get_wg entry); WG_MIDDLE=$(get_wg middle); WG_EXIT=$(get_wg exit)
  [ -n "$WG_ENTRY" ] && [ -n "$WG_MIDDLE" ] && [ -n "$WG_EXIT" ] && break
  sleep 1
done
echo "    entry  wg_pub: ${WG_ENTRY:-<none>}"
echo "    middle wg_pub: ${WG_MIDDLE:-<none>}"
echo "    exit   wg_pub: ${WG_EXIT:-<none>}"
if [ -z "$WG_ENTRY" ] || [ -z "$WG_MIDDLE" ] || [ -z "$WG_EXIT" ]; then
  echo "  FAIL: not every hop reported a wg_pub (is NW_NODE_PQWG set on all three?)"; exit 1
fi
echo "  PASS: all three hops are PQ-WireGuard responders"

for n in entry exit; do
  $DC exec -T "$n" iptables -I FORWARD 1 -d "$DEST"   -j ACCEPT 2>/dev/null
  $DC exec -T "$n" iptables -I INPUT   1 -s "$CLIENT" -j ACCEPT 2>/dev/null
done
count_fwd_dst() { $DC exec -T "$1" iptables -nvxL FORWARD 2>/dev/null | awk -v ip="$2" '$9==ip{print $1; f=1} END{if(!f)print "NA"}'; }
count_in_src()  { $DC exec -T "$1" iptables -nvxL INPUT   2>/dev/null | awk -v ip="$2" '$8==ip{print $1; f=1} END{if(!f)print "NA"}'; }
gt0() { case "$1" in ''|*[!0-9]*) return 1;; esac; [ "$1" -gt 0 ]; }

# Per-hop PQ keys via the NW_PATH `@wg_pub` grammar → the client PQ-wraps every hop.
PQ_PATH_2="$ENTRY:443@$WG_ENTRY,$EXIT:443@$WG_EXIT"
PQ_PATH_3="$ENTRY:443@$WG_ENTRY,$MIDDLE:443@$WG_MIDDLE,$EXIT:443@$WG_EXIT"

echo
echo "======= 2-hop ALL-PQ onion carries traffic (entry+exit, both PQ) ======="
echo "==> start nil-cli with a 2-hop per-hop-PQ NW_PATH"
$DC exec -e NW_PATH="$PQ_PATH_2" -e NW_EXPECTED_MEASUREMENT="$M" -e NW_EXPECTED_TEE=sev-snp -d client \
  sh -c 'nil-cli > /tmp/pq2.log 2>&1'

up=0
for _ in $(seq 1 60); do
  if $DC exec -T client grep -q "tunnel up" /tmp/pq2.log 2>/dev/null; then up=1; break; fi
  if $DC exec -T client grep -qE "Error|panicked" /tmp/pq2.log 2>/dev/null; then break; fi
  sleep 1
done
echo "---- client log ----"; $DC exec -T client tail -n 22 /tmp/pq2.log 2>/dev/null

if [ "$up" != 1 ]; then
  echo "  FAIL: 2-hop all-PQ tunnel did not come up"; fail=1
else
  echo "  PASS: 2-hop all-PQ trust-split path established (entry → exit, both PQ-WireGuard)"

  # Two PQ-WireGuard tunnels established inside two nested CONNECT-IP tunnels.
  pq=$($DC exec -T client grep -c "PQ-WireGuard tunnel established" /tmp/pq2.log 2>/dev/null)
  echo "    client established $pq inner PQ-WireGuard tunnel(s)"
  [ "$pq" = 2 ] && echo "  PASS: both hops PQ-wrapped (a non-exit PQ hop forwards to the exit)" \
                || { echo "  FAIL: expected 2 inner PQ-WireGuard tunnels"; fail=1; }

  echo "==> curl the destination THROUGH the 2-hop all-PQ onion"
  code=$($DC exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 30 "https://$DEST/cdn-cgi/trace" 2>/dev/null)
  echo "  tunneled HTTP ${code:-none}"
  if { [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; } 2>/dev/null; then
    echo "  PASS: real traffic flows client → entry(PQ) → exit(PQ) → $DEST"
  else
    echo "  FAIL: no traffic through the 2-hop all-PQ onion"; fail=1
  fi

  echo "==> trust-split assertions"
  e_fwd=$(count_fwd_dst entry "$DEST"); x_fwd=$(count_fwd_dst exit "$DEST")
  e_in=$(count_in_src entry "$CLIENT"); x_in=$(count_in_src exit "$CLIENT")
  echo "    entry → dest forwarded: $e_fwd   exit → dest forwarded: $x_fwd"
  echo "    entry ← client recv'd : $e_in    exit ← client recv'd : $x_in"
  if [ "$e_fwd" = "0" ] && gt0 "$x_fwd"; then
    echo "  PASS: only the EXIT forwards to the destination — the entry never sees it"
  else
    echo "  FAIL: destination visibility leaked to the non-exit node"; fail=1
  fi
  if gt0 "$e_in" && [ "$x_in" = "0" ]; then
    echo "  PASS: only the ENTRY sees the client's IP — the exit never does"
  else
    echo "  FAIL: client IP visibility leaked to the exit node"; fail=1
  fi

  echo "==> stop the 2-hop client (restore its routes) before the 3-hop limit check"
  $DC exec -T client pkill -INT -f nil-cli 2>/dev/null
  sleep 3
fi

echo
echo "===== 3-hop ALL-PQ fails CLOSED on a standard MTU (honest limit) ====="
echo "==> start nil-cli with a 3-hop per-hop-PQ NW_PATH (expected to refuse: MTU too tight)"
$DC exec -e NW_PATH="$PQ_PATH_3" -e NW_EXPECTED_MEASUREMENT="$M" -e NW_EXPECTED_TEE=sev-snp -d client \
  sh -c 'nil-cli > /tmp/pq3.log 2>&1'
sleep 12
echo "---- client log ----"; $DC exec -T client tail -n 12 /tmp/pq3.log 2>/dev/null
# The client must REFUSE (fail closed) with the MTU/path-too-deep error and bring up NO tunnel —
# never silently corrupt or truncate. This asserts the documented limit is enforced, not a surprise.
if $DC exec -T client grep -qiE "path too deep|leaves < 1200|inner QUIC" /tmp/pq3.log 2>/dev/null \
   && ! $DC exec -T client grep -q "tunnel up" /tmp/pq3.log 2>/dev/null; then
  echo "  PASS: 3-hop all-PQ refused fail-closed on the MTU floor (no tunnel, no corruption)"
else
  echo "  FAIL: expected a fail-closed MTU refusal for the 3-hop all-PQ path"; fail=1
fi

echo
[ "$fail" = 0 ] && echo "RESULT: ALL-PQ TRUST-SPLIT PASSED ✅ (2-hop live; 3-hop fails closed on MTU)" \
                || echo "RESULT: FAILURES ❌"
exit "$fail"
