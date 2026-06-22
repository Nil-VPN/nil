#!/usr/bin/env bash
# Publish the nil-node measurement (+ an SBOM) to the Sigstore/Rekor transparency log, so
# anyone can verify "this measurement = this audited, open-source nil-node" — the difference
# between a no-logs *promise* and a verifiable one (architecture spec §5, runbook §4).
#
#   ./publish-measurement.sh [--mode offline|real]
#
# offline (default): compute the measurement + SBOM, emit an in-toto attestation JSON, and
#   print the exact Rekor/cosign command it WOULD run. No network. This is what local
#   verification uses.
# real: keyless `cosign attest` — Fulcio issues a short-lived cert from the CI OIDC identity
#   and the entry lands in the public Rekor log. Requires network + an OIDC token (CI only).
#
# No secrets are committed or required: real mode uses keyless OIDC, not a stored key.
set -uo pipefail
cd "$(dirname "$0")/.."

MODE="offline"
[ "${1:-}" = "--mode" ] && MODE="${2:-offline}"

OUT="$(mktemp -d)/measurement"; mkdir -p "$OUT"
SDE=$(git log -1 --pretty=%ct 2>/dev/null || echo 0)   # commit time, for the deterministic re-extract

echo "==> computing the nil-node measurement (reproducible build)"
MEASUREMENT=$(./deploy/reproducible-build.sh | awk -F= '/^MEASUREMENT=/{print $2}')
if [ -z "${MEASUREMENT:-}" ]; then
  echo "could not obtain a reproducible measurement (see reproducible-build.sh output)"; exit 1
fi
echo "  measurement (sha256 nil-node): $MEASUREMENT"

echo "==> SBOM"
if command -v cargo-cyclonedx >/dev/null 2>&1; then
  cargo cyclonedx --format json -q 2>/dev/null && find . -maxdepth 2 -name '*.cdx.json' -newer Cargo.lock -exec cp {} "$OUT/sbom.cdx.json" \; 2>/dev/null
  echo "  CycloneDX SBOM → $OUT/sbom.cdx.json"
else
  # Fallback: a minimal dependency inventory from the lockfile (no extra tooling).
  grep -A1 '^name = ' Cargo.lock | paste - - 2>/dev/null | sed 's/name = //;s/version = //;s/"//g' > "$OUT/deps.txt" || true
  echo "  cargo-cyclonedx not installed; wrote a lockfile dep inventory → $OUT/deps.txt"
  echo "  (CI installs cargo-cyclonedx for a full CycloneDX SBOM)"
fi

GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)
STMT="$OUT/attestation.intoto.json"
cat > "$STMT" <<JSON
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [{ "name": "nil-node", "digest": { "sha256": "$MEASUREMENT" } }],
  "predicate": {
    "buildType": "https://nilvpn/reproducible-build/v1",
    "builder": { "id": "deploy/reproducible-build.sh" },
    "metadata": { "gitCommit": "$GIT_COMMIT", "toolchain": "rust 1.96.0", "measurementKind": "dev-binary-sha256" }
  }
}
JSON
echo "  attestation → $STMT"

case "$MODE" in
  offline)
    echo; echo "==> OFFLINE (dry run) — would publish to Rekor with:"
    echo "    cosign attest-blob --yes --type slsaprovenance --predicate $STMT \\"
    echo "      --bundle nil-node.attestation.bundle <nil-node binary>"
    echo "  Pin the resulting Rekor log index in the Coordinator (NW_PINNED_MEASUREMENT=$MEASUREMENT)."
    ;;
  real)
    if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
      echo "real mode needs a CI OIDC identity (keyless signing); run this from the release workflow."; exit 1
    fi
    command -v cosign >/dev/null 2>&1 || { echo "cosign not installed"; exit 1; }
    # Attest the actual production nil-node BINARY (a blob) — the measurement IS the binary's
    # hash, so `attest-blob` is the right primitive and needs no pushed OCI image / ARTIFACT_REF.
    # Re-extract the reproducibly-built binary and confirm its hash matches the published value
    # before signing (never attest a binary that doesn't match the measurement we publish).
    echo "==> extracting the production nil-node binary for attestation"
    docker build --no-cache --build-arg SOURCE_DATE_EPOCH="$SDE" \
      -f deploy/Dockerfile.repro --target builder -t nil-node-repro:publish . >/dev/null
    docker run --rm --entrypoint cat nil-node-repro:publish /nil-node > "$OUT/nil-node"
    GOT=$(sha256sum "$OUT/nil-node" | awk '{print $1}')
    if [ "$GOT" != "$MEASUREMENT" ]; then
      echo "extracted binary hash $GOT != published measurement $MEASUREMENT — aborting"; exit 1
    fi
    # Keyless: Fulcio issues a short-lived cert from the CI OIDC identity and the entry lands in
    # the public Rekor log; the bundle carries the inclusion proof + Rekor log index.
    cosign attest-blob --yes --type slsaprovenance --predicate "$STMT" \
      --bundle "$OUT/nil-node.attestation.bundle" "$OUT/nil-node"
    echo "  published to Rekor (keyless); bundle → $OUT/nil-node.attestation.bundle"
    echo "  pin NW_PINNED_MEASUREMENT=$MEASUREMENT in the Coordinator (and the Rekor index from the bundle)."
    ;;
  *) echo "unknown mode: $MODE (use offline|real)"; exit 1 ;;
esac
