#!/usr/bin/env bash
# Phase 2 attestation accept/reject verification — all in Docker, host untouched.
#
# The node (image built with `synthetic-attest`) returns an RA-TLS report bound to its TLS key
# and the client's per-connection nonce; the client appraises it against a pinned measurement
# before any traffic flows. This proves the client REJECTS a node whose measurement doesn't
# match the pinned value and ACCEPTS one that does (architecture spec §5).
#
# The synthetic report stands in for a real SEV-SNP/TDX report so this runs without TEE
# hardware. It exercises the verifier's decision logic (binding + measurement compare +
# reject-on-mismatch); the genuine vendor-root path is covered by the nil-attest KAT tests.
set -uo pipefail
cd "$(dirname "$0")"
fail=0

# Must equal NW_NODE_MEASUREMENT in compose.yaml (the value the node attests to).
M="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
WRONG="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

echo "==> building images + starting node (synthetic-attest)"
docker compose up -d --build || { echo "compose up failed"; exit 1; }
sleep 4
echo "---- node log ----"; docker compose logs node 2>/dev/null | tail -6

echo; echo "==> REJECT: client pins a WRONG measurement — must refuse to tunnel"
docker compose exec -e NW_EXPECTED_MEASUREMENT="$WRONG" -e NW_EXPECTED_TEE=sev-snp -d client \
  sh -c 'nil-cli > /tmp/reject.log 2>&1'
sleep 6
echo "---- reject log ----"; docker compose exec -T client tail -n 15 /tmp/reject.log 2>/dev/null
if docker compose exec -T client grep -q "measurement mismatch" /tmp/reject.log 2>/dev/null \
   && ! docker compose exec -T client grep -q "tunnel up" /tmp/reject.log 2>/dev/null; then
  echo "  PASS (reject): mismatched measurement refused; no tunnel established"
else
  echo "  FAIL (reject): expected 'measurement mismatch' and no 'tunnel up'"; fail=1
fi

echo; echo "==> ACCEPT: client pins the CORRECT measurement — tunnel must come up"
docker compose exec -e NW_EXPECTED_MEASUREMENT="$M" -e NW_EXPECTED_TEE=sev-snp -d client \
  sh -c 'nil-cli > /tmp/accept.log 2>&1'
up=0
for _ in $(seq 1 20); do
  if docker compose exec -T client grep -q "tunnel up" /tmp/accept.log 2>/dev/null; then up=1; break; fi
  sleep 1
done
echo "---- accept log ----"; docker compose exec -T client tail -n 15 /tmp/accept.log 2>/dev/null
if [ "$up" = 1 ]; then
  code=$(docker compose exec -T client curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com 2>/dev/null)
  echo "  tunnel up; tunneled HTTP ${code:-none}"
  if [ "$code" = "200" ]; then echo "  PASS (accept): attested tunnel carries traffic"; else echo "  FAIL (accept): no tunneled traffic"; fail=1; fi
else
  echo "  FAIL (accept): tunnel did not come up with the correct measurement"; fail=1
fi

echo; echo "==> teardown"; docker compose down -v >/dev/null 2>&1
echo
[ "$fail" = 0 ] && echo "RESULT: ATTESTATION ACCEPT/REJECT PASSED ✅" || echo "RESULT: FAILURES ❌"
exit "$fail"
