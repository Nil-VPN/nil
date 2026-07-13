#!/usr/bin/env bash
# Multi-client MASQUE/CONNECT-IP verification — one node, THREE concurrent clients, all in Docker,
# host untouched. The end-to-end proof for ADR-0005: a single node serves many clients with
# correctly ISOLATED per-client routing (no address collision, no reply cross-talk, no misroute).
#
# What it proves (and how a regression would fail it):
#   1. All three clients' tunnels are up SIMULTANEOUSLY. The node deliberately does not log a
#      per-tunnel event; the three live interfaces plus concurrent traffic below are the stronger,
#      privacy-preserving concurrency proof (the old single-client node could not satisfy them).
#   2. Each client's inner TUN address is DISTINCT and inside the pool CIDR — the node handed out
#      three unique /32s via ADDRESS_ASSIGN (`nil-node/src/pool.rs`). The pre-fix bug hardcoded
#      10.74.0.2 for everyone; this assertion catches that deterministically.
#   3. With all three tunnels live at once, all three concurrently carry real traffic to an external
#      destination. This is the return-path isolation proof: the node dispatches each internet reply
#      by its inner DESTINATION IP (`client_routes` in server.rs) and the kernel's conntrack un-NATs
#      each flow back to the client that opened it — so a reply for client A's inner IP can only be
#      written into client A's tunnel. A node that routed replies to "the first client" (the old bug)
#      cannot satisfy three simultaneous flows: two would time out. Concurrent all-success ⇒ isolated.
#
# Uses an OFF-bridge external destination (like the rest of deploy/verify-*.sh) so traffic must
# traverse the tunnel — a same-bridge origin would be reachable directly and prove nothing.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
DC="docker compose -f compose.multiclient.yaml"

# Must equal NW_NODE_MEASUREMENT / the clients' NW_EXPECTED_MEASUREMENT in compose.multiclient.yaml.
M="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
CLIENTS="client1 client2 client3"
DEST="https://1.1.1.1/cdn-cgi/trace"   # off-bridge → must go through the tunnel

cleanup() { echo; echo "==> teardown"; $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "==> build + start node + three clients (synthetic-attest, single node)"
$DC up -d --build || { echo "compose up failed"; exit 1; }
sleep 4

echo "==> bring up all three tunnels concurrently (nil-cli in each client)"
for c in $CLIENTS; do
  $DC exec -d "$c" sh -c 'nil-cli > /tmp/cli.log 2>&1'
done

echo "==> wait for all three tunnels to report 'tunnel up' (max 60s)"
allup=0
for _ in $(seq 1 60); do
  up_count=0
  for c in $CLIENTS; do
    $DC exec -T "$c" grep -q "tunnel up" /tmp/cli.log 2>/dev/null && up_count=$((up_count + 1))
  done
  [ "$up_count" -eq 3 ] && { allup=1; break; }
  sleep 1
done
for c in $CLIENTS; do
  echo "---- $c log (tail) ----"; $DC exec -T "$c" sed 's/\x1b\[[0-9;]*m//g' /tmp/cli.log 2>/dev/null | tail -n 6
done
if [ "$allup" = 1 ]; then
  echo "  PASS: all three clients' tunnels are up simultaneously"
else
  echo "  FAIL: not all three tunnels came up ($up_count/3)"; fail=1
fi

echo
echo "==> each client got a UNIQUE inner address from the pool (ADDRESS_ASSIGN)"
ips=""
for c in $CLIENTS; do
  ip=$($DC exec -T "$c" ip -4 -o addr show nil0 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  echo "    $c inner IP: ${ip:-<none>}"
  case "$ip" in
    10.74.*) ips="$ips $ip" ;;
    *) echo "  FAIL: $c has no pool-assigned inner IP in 10.74.0.0/16"; fail=1 ;;
  esac
done
distinct=$(printf '%s\n' $ips | sort -u | grep -c .)
if [ "$distinct" -eq 3 ]; then
  echo "  PASS: three distinct inner addresses — no two clients collide on one tunnel IP"
else
  echo "  FAIL: expected 3 distinct inner IPs, got $distinct (address collision)"; fail=1
fi

echo
echo "==> all three clients carry real traffic CONCURRENTLY through the one node"
# Fire the probes inside each container so they overlap in real time; each retries to absorb the
# first-packet QUIC warmup (same rationale as verify-e2e.sh). A genuine no-traffic condition still
# fails after every attempt — the assertion isn't weakened.
for c in $CLIENTS; do
  $DC exec -d "$c" sh -c '
    for i in $(seq 1 6); do
      code=$(curl -s -o /tmp/body.txt -w "%{http_code}" --max-time 25 "'"$DEST"'" 2>/dev/null)
      echo "$code" > /tmp/probe.code
      case "$code" in 2??|3??) exit 0 ;; esac
      sleep 2
    done'
done

echo "==> collect concurrent probe results (max 60s)"
ok=0
for _ in $(seq 1 60); do
  ok=0
  for c in $CLIENTS; do
    code=$($DC exec -T "$c" cat /tmp/probe.code 2>/dev/null | tr -dc '0-9')
    case "$code" in 2??|3??) ok=$((ok + 1)) ;; esac
  done
  [ "$ok" -eq 3 ] && break
  sleep 1
done
for c in $CLIENTS; do
  code=$($DC exec -T "$c" cat /tmp/probe.code 2>/dev/null | tr -dc '0-9')
  echo "    $c tunneled HTTP: ${code:-none}"
done
if [ "$ok" -eq 3 ]; then
  echo "  PASS: all three clients egress concurrently — replies route to the correct client (isolated)"
else
  echo "  FAIL: only $ok/3 clients carried traffic — concurrent per-client routing broke"; fail=1
fi

echo
echo "==> (info) all three egress via the SAME node (shared egress IP, distinct inner IPs)"
egress=""
for c in $CLIENTS; do
  e=$($DC exec -T "$c" sh -c 'grep -oE "^ip=[0-9a-fA-F:.]+" /tmp/body.txt 2>/dev/null | head -1')
  echo "    $c egress: ${e:-<unknown>}"
  egress="$egress ${e:-x}"
done
uniq_egress=$(printf '%s\n' $egress | sort -u | grep -c .)
[ "$uniq_egress" = "1" ] && echo "  (info) confirmed: one shared egress IP for all three inner tunnels"

echo
[ "$fail" = 0 ] && echo "RESULT: MULTI-CLIENT ISOLATION PASSED ✅ (one node, three concurrent isolated clients)" \
                || echo "RESULT: FAILURES ❌"
exit "$fail"
