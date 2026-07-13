#!/usr/bin/env bash
# verify-image.sh — operator pre-deploy gate for a NIL service image.
#
# Proves a specific image *by digest* belongs to one complete signed release-candidate set BEFORE
# you run it: signed aggregate/component manifests, a cosign keyless image signature, required
# CycloneDX attestation, and required GitHub build provenance.
# PD-5 made operational — you verify, you don't trust. Requires: cosign (>= v2.4) and gh (authed).
#
# Usage:  ./deploy/verify-image.sh ghcr.io/nil-vpn/nil-node@sha256:<64-hex-digest> RELEASE_SET_DIR
# A mutable tag is REFUSED: pin and verify the immutable @sha256: digest you will actually deploy.
#
# Overridable env (defaults target this repo's pipeline):
#   NIL_REPO            owner/repo            (Nil-VPN/nil)
#   NIL_WORKFLOW        workflow file path    (.github/workflows/release.yml)
#   COSIGN_OIDC_ISSUER  Fulcio OIDC issuer    (https://token.actions.githubusercontent.com)
set -euo pipefail

IMG="${1:-}"
RELEASE_SET="${2:-${NIL_RELEASE_SET_DIR:-}}"
NIL_REPO="${NIL_REPO:-Nil-VPN/nil}"
NIL_WORKFLOW="${NIL_WORKFLOW:-.github/workflows/release.yml}"
COSIGN_OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

die(){ printf 'FAIL: %s\n' "$*" >&2; exit 2; }
[ -n "$IMG" ] || die "usage: $0 <image>@sha256:<digest> RELEASE_SET_DIR"
[ -d "$RELEASE_SET" ] || die "a downloaded release-set directory is required"

# 1. Refuse anything that is not a digest-pinned ref (no mutable tags).
case "$IMG" in
  *@sha256:*) : ;;
  *) die "refusing '$IMG' — pin the immutable digest, e.g. ghcr.io/nil-vpn/nil-node@sha256:<64 hex>" ;;
esac
digest="${IMG##*@sha256:}"
printf '%s' "$digest" | grep -qE '^[0-9a-f]{64}$' \
  || die "malformed digest in '$IMG' (need @sha256:<64 lowercase hex>)"

command -v cosign >/dev/null 2>&1 || die "cosign not found — install sigstore/cosign (>= v2.4)"
command -v gh >/dev/null 2>&1 || die "gh not found — install the GitHub CLI (verifies the SBOM + provenance attestations)"
command -v jq >/dev/null 2>&1 || die "jq not found — required to bind the digest to the release set"

# Escape regex dots so the identity matches LITERALLY (a bare '.' is a regex wildcard — a
# security verifier must not widen the trusted identity). Only protected version tags may publish
# production images; branch and manually-dispatched refs are not release artifacts.
esc(){ printf '%s' "$1" | sed 's/\./\\./g'; }
IDENTITY_RE="^https://github\.com/$(esc "$NIL_REPO")/$(esc "$NIL_WORKFLOW")@refs/tags/v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"
echo "== verify-image :: $IMG =="
echo "   identity ~ $IDENTITY_RE"
echo "   issuer     $COSIGN_OIDC_ISSUER"
fail=0

echo; echo "==> [1/5] signed complete release-set manifest"
if [ -s "$RELEASE_SET/release.json" ] \
    && [ -s "$RELEASE_SET/release.sigstore.json" ] \
    && [ -s "$RELEASE_SET/images/images.json" ] \
    && [ -s "$RELEASE_SET/client/clients.json" ] \
    && [ -s "$RELEASE_SET/node/evidence.json" ] \
    && cosign verify-blob --bundle "$RELEASE_SET/release.sigstore.json" \
         --certificate-identity-regexp "$IDENTITY_RE" \
         --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
         "$RELEASE_SET/release.json" >/dev/null 2>&1 \
    && cosign verify-blob --bundle "$RELEASE_SET/client/clients.sigstore.json" \
         --certificate-identity-regexp "$IDENTITY_RE" \
         --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
         "$RELEASE_SET/client/clients.json" >/dev/null 2>&1 \
    && cosign verify-blob --bundle "$RELEASE_SET/images/images.sigstore.json" \
         --certificate-identity-regexp "$IDENTITY_RE" \
         --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
         "$RELEASE_SET/images/images.json" >/dev/null 2>&1 \
    && [ "$(sha256sum "$RELEASE_SET/images/images.json" | awk '{print $1}')" = \
         "$(jq -r '.image_manifest_sha256' "$RELEASE_SET/release.json")" ] \
    && [ "$(sha256sum "$RELEASE_SET/client/clients.json" | awk '{print $1}')" = \
         "$(jq -r '.client_manifest_sha256' "$RELEASE_SET/release.json")" ] \
    && [ "$(sha256sum "$RELEASE_SET/node/evidence.json" | awk '{print $1}')" = \
         "$(jq -r '.node_evidence_sha256' "$RELEASE_SET/release.json")" ] \
    && [ "$(jq -r '.source_sha' "$RELEASE_SET/images/images.json")" = \
         "$(jq -r '.source_sha' "$RELEASE_SET/release.json")" ] \
    && [ "$(jq -r '.source_sha' "$RELEASE_SET/client/clients.json")" = \
         "$(jq -r '.source_sha' "$RELEASE_SET/release.json")" ] \
    && [ "$(jq -r '.github_run_id' "$RELEASE_SET/images/images.json")" = \
         "$(jq -r '.github_run_id' "$RELEASE_SET/release.json")" ] \
    && [ "$(jq -r '.github_run_id' "$RELEASE_SET/client/clients.json")" = \
         "$(jq -r '.github_run_id' "$RELEASE_SET/release.json")" ] \
    && [ "$(jq -r '.github_run_attempt' "$RELEASE_SET/images/images.json")" = \
         "$(jq -r '.github_run_attempt' "$RELEASE_SET/release.json")" ] \
    && [ "$(jq -r '.github_run_attempt' "$RELEASE_SET/client/clients.json")" = \
         "$(jq -r '.github_run_attempt' "$RELEASE_SET/release.json")" ] \
    && jq -e --arg image "$IMG" '.images | to_entries | any(.value == $image)' \
         "$RELEASE_SET/images/images.json" >/dev/null; then
  echo "  PASS: digest is a member of the signed complete candidate set"
else
  echo "  FAIL: release-set signature/hash/membership verification failed"; fail=1
fi
for service in portal coordinator node; do
  sbom="$RELEASE_SET/images/nil-${service}.cdx.json"
  scan="$RELEASE_SET/images/nil-${service}.trivy.json"
  [ -s "$sbom" ] \
    && [ "$(sha256sum "$sbom" | awk '{print $1}')" = \
         "$(jq -r --arg service "$service" '.sbom_sha256[$service]' "$RELEASE_SET/images/images.json")" ] \
    || { echo "  FAIL: $service SBOM hash mismatch"; fail=1; }
  [ -s "$scan" ] \
    && [ "$(sha256sum "$scan" | awk '{print $1}')" = \
         "$(jq -r --arg service "$service" '.trivy_report_sha256[$service]' "$RELEASE_SET/images/images.json")" ] \
    || { echo "  FAIL: $service Trivy-report hash mismatch"; fail=1; }
done
[ -s "$RELEASE_SET/client/client.cdx.json" ] \
  && [ "$(sha256sum "$RELEASE_SET/client/client.cdx.json" | awk '{print $1}')" = \
       "$(jq -r '.combined_sbom_sha256' "$RELEASE_SET/client/clients.json")" ] \
  || { echo "  FAIL: combined client SBOM hash mismatch"; fail=1; }
[ -s "$RELEASE_SET/node/nil-node.cdx.json" ] \
  && [ "$(sha256sum "$RELEASE_SET/node/nil-node.cdx.json" | awk '{print $1}')" = \
       "$(jq -r '.sbom_sha256' "$RELEASE_SET/node/evidence.json")" ] \
  || { echo "  FAIL: node source SBOM hash mismatch"; fail=1; }

echo; echo "==> [2/5] image signature — cosign verify (keyless)"
if cosign verify \
      --certificate-identity-regexp "$IDENTITY_RE" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "$IMG" >/dev/null 2>&1; then
  echo "  PASS: signed by the release orchestrator identity"
else
  echo "  FAIL: no valid keyless signature from the expected identity"; fail=1
fi

echo; echo "==> [3/5] SBOM attestation — CycloneDX (required)"
if cosign verify-attestation --type cyclonedx \
      --certificate-identity-regexp "$IDENTITY_RE" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "$IMG" >/dev/null 2>&1; then
  echo "  PASS: CycloneDX SBOM attestation present + verified"
else
  echo "  FAIL: missing / invalid CycloneDX SBOM attestation"; fail=1
fi

echo; echo "==> [4/5] GitHub build provenance (required)"
if gh attestation verify "oci://$IMG" --repo "$NIL_REPO" \
      --signer-workflow "$NIL_REPO/$NIL_WORKFLOW" >/dev/null 2>&1; then
  echo "  PASS: SLSA build provenance verified (from the release workflow)"
else
  echo "  FAIL: missing / invalid SLSA provenance (requires gh auth + network)."; fail=1
fi

echo; echo "==> [5/5] release is intentionally unpromoted"
if [ "$(jq -r '.promotion.status' "$RELEASE_SET/release.json" 2>/dev/null)" = blocked ] \
    && [ "$(jq -r '.promotion.public_version_tags' "$RELEASE_SET/release.json" 2>/dev/null)" = false ]; then
  echo "  PASS: verifier did not mistake a candidate for a public promoted release"
  echo "  NOTE: an externally controlled atomic promotion is still required before production use"
else
  echo "  FAIL: unexpected or missing promotion state"; fail=1
fi

echo
if [ "$fail" = 0 ]; then
  echo "RESULT: VERIFIED ✅  ($IMG)"
  echo "Candidate evidence verified. Production promotion/approval is still a separate external gate."
  exit 0
else
  echo "RESULT: FAILED ❌  — do NOT deploy $IMG"
  exit 1
fi
