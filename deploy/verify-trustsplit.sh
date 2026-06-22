#!/usr/bin/env bash
# Phase 3 trust-split (multi-hop) verification — all in Docker, host untouched.
#
# Proves the nested-MASQUE onion (architecture spec §6): the client stacks three attested
# MASQUE/CONNECT-IP tunnels (entry → middle → exit) and real traffic flows end to end, while no
# single node can link the client to the destination:
#
#   • entry  sees the client's IP and the middle, never the destination
#   • exit    sees the middle and the destination, never the client's IP
#   • middle  sees neither endpoint
#
# Each hop is appraised independently against the pinned measurement before any packet flows; a
# rogue middle (attesting the wrong measurement) makes the onion fail at that hop (kill-switch
# holds). The synthetic RA-TLS report stands in for real SEV-SNP/TDX hardware (it exercises the
# verifier's decision logic; the genuine vendor-root path is covered by the nil-attest KATs).
set -uo pipefail
cd "$(dirname "$0")"
fail=0
DC="docker compose -f compose.trustsplit.yaml"

# Must equal the entry/middle/exit NW_NODE_MEASUREMENT in compose.trustsplit.yaml.
M="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
ENTRY=10.80.0.11; MIDDLE=10.80.0.12; EXIT=10.80.0.13; ROGUE=10.80.0.14
CLIENT=10.80.0.30
# A fixed public destination (Cloudflare) — single stable IP, no DNS, returns 200 over HTTPS.
DEST=1.1.1.1
GOOD_PATH="$ENTRY:443,$MIDDLE:443,$EXIT:443"
ROGUE_PATH="$ENTRY:443,$ROGUE:443,$EXIT:443"

cleanup() { echo; echo "==> teardown"; $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "==> build + start entry, middle, exit, middle-rogue (all synthetic-attest)"
$DC up -d --build || { echo "compose up failed"; exit 1; }
sleep 6

# Per-node packet counters used as the trust-split proof (iptables, no tcpdump needed):
#   FORWARD -d DEST    → IP packets this node forwards toward the destination
#   INPUT   -s CLIENT  → QUIC packets this node receives directly from the client's real IP
for n in entry exit; do
  $DC exec -T "$n" iptables -I FORWARD 1 -d "$DEST"   -j ACCEPT 2>/dev/null
  $DC exec -T "$n" iptables -I INPUT   1 -s "$CLIENT" -j ACCEPT 2>/dev/null
done
count_fwd_dst() { $DC exec -T "$1" iptables -nvxL FORWARD 2>/dev/null | awk -v ip="$2" '$9==ip{print $1; f=1} END{if(!f)print "NA"}'; }
count_in_src()  { $DC exec -T "$1" iptables -nvxL INPUT   2>/dev/null | awk -v ip="$2" '$8==ip{print $1; f=1} END{if(!f)print "NA"}'; }
gt0() { case "$1" in ''|*[!0-9]*) return 1;; esac; [ "$1" -gt 0 ]; }

echo
echo "================ POSITIVE: 3-hop onion carries traffic ================"
echo "==> start nil-cli with NW_PATH=$GOOD_PATH (every hop pins the measurement)"
$DC exec -e NW_PATH="$GOOD_PATH" -e NW_EXPECTED_MEASUREMENT="$M" -e NW_EXPECTED_TEE=sev-snp -d client \
  sh -c 'nil-cli > /tmp/pos.log 2>&1'

up=0
for _ in $(seq 1 45); do
  if $DC exec -T client grep -q "tunnel up" /tmp/pos.log 2>/dev/null; then up=1; break; fi
  if $DC exec -T client grep -qE "Error|panicked" /tmp/pos.log 2>/dev/null; then break; fi
  sleep 1
done
echo "---- client log ----"; $DC exec -T client tail -n 20 /tmp/pos.log 2>/dev/null

if [ "$up" != 1 ]; then
  echo "  FAIL: 3-hop tunnel did not come up"; fail=1
else
  echo "  PASS: trust-split path established (entry → middle → exit)"

  # Three independent CONNECT-IP tunnels — one terminated at each node.
  tunnels=0
  for n in entry middle exit; do
    c=$($DC logs "$n" 2>/dev/null | grep -c "CONNECT-IP tunnel up")
    echo "    $n: $c CONNECT-IP tunnel(s)"
    gt0 "$c" && tunnels=$((tunnels + 1))
  done
  [ "$tunnels" = 3 ] && echo "  PASS: three nested tunnels established" \
                      || { echo "  FAIL: expected a tunnel at all 3 nodes"; fail=1; }

  echo "==> curl the destination THROUGH the onion (https://$DEST/cdn-cgi/trace)"
  code=$($DC exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 25 "https://$DEST/cdn-cgi/trace" 2>/dev/null)
  echo "  tunneled HTTP ${code:-none}"
  # Any real HTTP status (2xx/3xx) proves the TLS+HTTP round-trip completed through all 3 hops.
  if { [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; } 2>/dev/null; then
    echo "  PASS: real traffic flows client → entry → middle → exit → $DEST"
  else
    echo "  FAIL: no traffic through the onion"; fail=1
  fi

  echo "==> trust-split assertions (per-node packet counters)"
  e_fwd=$(count_fwd_dst entry "$DEST"); x_fwd=$(count_fwd_dst exit "$DEST")
  e_in=$(count_in_src entry "$CLIENT"); x_in=$(count_in_src exit "$CLIENT")
  echo "    entry → dest forwarded: $e_fwd   exit → dest forwarded: $x_fwd"
  echo "    entry ← client recv'd : $e_in    exit ← client recv'd : $x_in"
  # exit reaches the destination; entry never does.
  if [ "$e_fwd" = "0" ] && gt0 "$x_fwd"; then
    echo "  PASS: only the EXIT forwards to the destination — entry never sees it"
  else
    echo "  FAIL: destination visibility leaked to a non-exit node"; fail=1
  fi
  # entry talks to the client; the exit never does.
  if gt0 "$e_in" && [ "$x_in" = "0" ]; then
    echo "  PASS: only the ENTRY sees the client's IP — exit never does"
  else
    echo "  FAIL: client IP visibility leaked to the exit node"; fail=1
  fi

  echo "==> stop the positive client (restore its routes) before the negative run"
  $DC exec -T client pkill -INT -f nil-cli 2>/dev/null
  sleep 3
fi

echo
echo "========= NEGATIVE: per-hop attestation (rogue middle) =========="
echo "==> start nil-cli with NW_PATH=$ROGUE_PATH (middle attests the WRONG measurement)"
$DC exec -e NW_PATH="$ROGUE_PATH" -e NW_EXPECTED_MEASUREMENT="$M" -e NW_EXPECTED_TEE=sev-snp -d client \
  sh -c 'nil-cli > /tmp/neg.log 2>&1'
sleep 14
echo "---- client log ----"; $DC exec -T client tail -n 20 /tmp/neg.log 2>/dev/null

echo; echo "==== node logs (diagnostics) ===="
for n in entry middle exit; do
  echo "---- $n ----"; $DC logs "$n" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | tail -n 12
done
if $DC exec -T client grep -q "measurement mismatch" /tmp/neg.log 2>/dev/null \
   && ! $DC exec -T client grep -q "tunnel up" /tmp/neg.log 2>/dev/null; then
  echo "  PASS: the onion is refused at the rogue middle hop; no tunnel (kill-switch holds)"
else
  echo "  FAIL: expected 'measurement mismatch' at the middle hop and no 'tunnel up'"; fail=1
fi

echo
[ "$fail" = 0 ] && echo "RESULT: TRUST-SPLIT MULTI-HOP PASSED ✅" || echo "RESULT: FAILURES ❌"
exit "$fail"
