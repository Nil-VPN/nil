#!/usr/bin/env bash
# verify-image.sh — operator pre-deploy gate for a NIL service image.
#
# Proves a specific image *by digest* came from the project's signed release pipeline BEFORE you run
# it: a cosign keyless signature (Fulcio identity == our release-images workflow), a required
# CycloneDX SBOM attestation, and (warn-only) SLSA build provenance. PD-5 made operational — you
# verify, you don't trust.
#
# Usage:  ./deploy/verify-image.sh ghcr.io/nil-vpn/nil-node@sha256:<64-hex-digest>
# A mutable tag is REFUSED: pin and verify the immutable @sha256: digest you will actually deploy.
#
# Overridable env (defaults target this repo's pipeline):
#   NIL_REPO            owner/repo            (Nil-VPN/nil)
#   NIL_WORKFLOW        workflow file path    (.github/workflows/release-images.yml)
#   COSIGN_OIDC_ISSUER  Fulcio OIDC issuer    (https://token.actions.githubusercontent.com)
set -euo pipefail

IMG="${1:-}"
NIL_REPO="${NIL_REPO:-Nil-VPN/nil}"
NIL_WORKFLOW="${NIL_WORKFLOW:-.github/workflows/release-images.yml}"
COSIGN_OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

die(){ printf 'FAIL: %s\n' "$*" >&2; exit 2; }
[ -n "$IMG" ] || die "usage: $0 <image>@sha256:<digest>   (a mutable tag is refused)"

# 1. Refuse anything that is not a digest-pinned ref (no mutable tags).
case "$IMG" in
  *@sha256:*) : ;;
  *) die "refusing '$IMG' — pin the immutable digest, e.g. ghcr.io/nil-vpn/nil-node@sha256:<64 hex>" ;;
esac
digest="${IMG##*@sha256:}"
printf '%s' "$digest" | grep -qE '^[0-9a-f]{64}$' \
  || die "malformed digest in '$IMG' (need @sha256:<64 lowercase hex>)"

command -v cosign >/dev/null 2>&1 || die "cosign not found — install sigstore/cosign (>= v2.4)"

IDENTITY_RE="^https://github.com/${NIL_REPO}/${NIL_WORKFLOW}@refs/"
echo "== verify-image :: $IMG =="
echo "   identity ~ $IDENTITY_RE"
echo "   issuer     $COSIGN_OIDC_ISSUER"
fail=0

echo; echo "==> [1/3] signature — cosign verify (keyless)"
if cosign verify \
      --certificate-identity-regexp "$IDENTITY_RE" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "$IMG" >/dev/null 2>&1; then
  echo "  PASS: signed by the release-images workflow identity"
else
  echo "  FAIL: no valid keyless signature from the expected identity"; fail=1
fi

echo; echo "==> [2/3] SBOM attestation — CycloneDX (required)"
if cosign verify-attestation --type cyclonedx \
      --certificate-identity-regexp "$IDENTITY_RE" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "$IMG" >/dev/null 2>&1; then
  echo "  PASS: CycloneDX SBOM attestation present + verified"
else
  echo "  FAIL: missing / invalid CycloneDX SBOM attestation"; fail=1
fi

echo; echo "==> [3/3] SLSA build provenance (warn-only)"
if cosign verify-attestation --type slsaprovenance \
      --certificate-identity-regexp "$IDENTITY_RE" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "$IMG" >/dev/null 2>&1; then
  echo "  PASS: SLSA provenance attestation verified"
else
  echo "  WARN: cosign did not verify SLSA provenance (it is attached as a GitHub attestation)."
  echo "        Confirm it directly with:"
  echo "          gh attestation verify oci://$IMG --repo $NIL_REPO"
fi

echo
if [ "$fail" = 0 ]; then
  echo "RESULT: VERIFIED ✅  ($IMG)"
  echo "Pin THIS digest in your compose/Nomad config; never deploy a mutable tag."
  exit 0
else
  echo "RESULT: FAILED ❌  — do NOT deploy $IMG"
  exit 1
fi
