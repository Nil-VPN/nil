#!/usr/bin/env bash
# Static fail-closed guard for the release and Docker-context invariants established after the
# 2026-07 audit. This intentionally avoids a YAML dependency so it can run before tool bootstrap.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() {
  echo "verify-release-config: $*" >&2
  exit 1
}

# Every external Action must use an immutable 40-character commit and record the reviewed tag.
while IFS= read -r entry; do
  file="${entry%%:*}"
  rest="${entry#*:}"
  line_no="${rest%%:*}"
  line="${rest#*:}"
  [[ "$line" =~ uses:[[:space:]]+([^[:space:]#]+) ]] || fail "cannot parse $file:$line_no"
  ref="${BASH_REMATCH[1]}"
  case "$ref" in
    ./*) continue ;;
  esac
  [[ "$ref" =~ @[0-9a-f]{40}$ ]] || fail "mutable Action ref at $file:$line_no: $ref"
  case "$ref" in
    actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683) version=v4.2.2 ;;
    actions/cache@5a3ec84eff668545956fd18022155c47e93e2684) version=v4.2.3 ;;
    actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020) version=v4.4.0 ;;
    actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02) version=v4.6.2 ;;
    actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093) version=v4.3.0 ;;
    pnpm/action-setup@a7487c7e89a18df4991f7f222e4898a00d66ddda) version=v4.1.0 ;;
    docker/setup-buildx-action@e468171a9de216ec08956ac3ada2f0791b6bd435) version=v3.11.1 ;;
    docker/login-action@184bdaa0721073962dff0199f1fb9940f07167d1) version=v3.5.0 ;;
    docker/metadata-action@c1e51972afc2121e065aed6d45c65596fe445f3f) version=v5.8.0 ;;
    docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83) version=v6.18.0 ;;
    sigstore/cosign-installer@3454372f43399081ed03b604cb2d021dabca52bb) version=v3.8.2 ;;
    aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25) version=v0.36.0 ;;
    anchore/sbom-action@9246b90769f852b3a8921f330c59e0b3f439d6e9) version=v0.20.6 ;;
    actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be) version=v2.4.0 ;;
    *) fail "Action ref is not in the reviewed pin allowlist at $file:$line_no: $ref" ;;
  esac
  case "$line" in
    *"# $version"*) ;;
    *) fail "Action pin/version comment mismatch at $file:$line_no (expected $version)" ;;
  esac
done < <(grep -rnE '^[[:space:]]*-?[[:space:]]*uses:' .github/workflows)

# release.yml is the only version-tag trigger. Component stages are reusable and cannot publish
# independently when a tag is pushed.
tag_workflows="$(grep -rlE '^    tags:' .github/workflows || true)"
[ "$(printf '%s\n' "$tag_workflows" | sed '/^$/d' | wc -l | tr -d ' ')" -eq 1 ] || \
  fail "expected exactly one tag-triggered workflow"
[ "$tag_workflows" = ".github/workflows/release.yml" ] || \
  fail "version tags must enter only through release.yml"
for workflow in release-attest.yml release-images.yml release-sign.yml; do
  grep -qE '^[[:space:]]+workflow_call:' ".github/workflows/$workflow" || \
    fail "$workflow must be reusable"
  if grep -qE '^  push:' ".github/workflows/$workflow"; then
    fail "$workflow must not have an independent push trigger"
  fi
done

grep -qE 'environment: release-candidates' .github/workflows/release-images.yml || \
  fail "candidate registry authority is not protected by an Environment"
grep -qE 'environment: release-approval' .github/workflows/release.yml || \
  fail "release-set approval Environment missing"
for bundle in clients.sigstore.json images.sigstore.json; do
  grep -qE "cosign verify-blob --bundle release-set/.*/${bundle}" .github/workflows/release.yml || \
    fail "release-set composition does not verify $bundle"
done
[ "$(grep -cE 'environment: release-signing-' .github/workflows/release-sign.yml)" -eq 3 ] || \
  fail "each client platform needs its own protected signing Environment"
if grep -qE 'secrets:[[:space:]]+inherit|APPLE_CERTIFICATE:|WINDOWS_CERTIFICATE:|GPG_PRIVATE_KEY:' \
    .github/workflows/release.yml; then
  fail "the orchestrator must not pass repository/org signing secrets into the reusable workflow"
fi
[ "$(grep -cE 'before exposing secrets' .github/workflows/release-sign.yml)" -eq 3 ] || \
  fail "every protected signing job must validate archive paths before secrets"
grep -qE 'member\.issym\(\) or member\.islnk\(\)' .github/workflows/release-sign.yml || \
  fail "tar validation does not reject symlinks and hardlinks"
grep -qE 'ExternalAttributes.*0xF000' .github/workflows/release-sign.yml || \
  fail "Windows archive validation does not reject link/special entry modes"
[ "$(grep -cE 'tar -xzf unsigned-(macos|linux)' .github/workflows/release-sign.yml)" -eq 2 ] || \
  fail "tar candidates must be extracted exactly once in pre-secret validation steps"
[ "$(grep -cE 'ZipFile\]::ExtractToDirectory' .github/workflows/release-sign.yml)" -eq 1 ] || \
  fail "Windows candidate must be extracted exactly once before signing secrets"
[ "$(grep -cE 'actions/checkout@' .github/workflows/release-sign.yml)" -eq 3 ] || \
  fail "signing jobs must not check out repository code"
if grep -qE 'tauri-apps/tauri-action|type=ref,event=tag|type=raw,value=latest' \
    .github/workflows/release-sign.yml .github/workflows/release-images.yml; then
  fail "release stages contain a combined build/sign action or public tag promotion"
fi
if grep -qE 'continue-on-error:' .github/workflows/ci.yml .github/workflows/release*.yml; then
  fail "release, SBOM, and advisory gates may not be warning-only"
fi

# CI and all client release builders use one reviewed Node/pnpm pair.
grep -qE 'node-version: 22\.17\.1' .github/workflows/ci.yml || fail "CI Node version is not 22.17.1"
grep -qE 'version: 10\.33\.0' .github/workflows/ci.yml || fail "CI pnpm version is not 10.33.0"
grep -qE 'NODE_VERSION: "22\.17\.1"' .github/workflows/release-sign.yml || \
  fail "release Node version is not 22.17.1"
grep -qE 'PNPM_VERSION: "10\.33\.0"' .github/workflows/release-sign.yml || \
  fail "release pnpm version is not 10.33.0"
grep -qE 'pnpm --dir client audit --audit-level high' .github/workflows/ci.yml || \
  fail "frontend advisory gate missing"
grep -qE 'verify-frontend-licenses.sh' .github/workflows/ci.yml || \
  fail "frontend license gate missing"
grep -qE 'output-file: workspace.cdx.json' .github/workflows/ci.yml || \
  fail "mandatory workspace SBOM missing"

# The Docker context is default-deny and production/test Dockerfiles copy only explicit source
# roots. Sensitive patterns remain excluded after all negations.
[ "$(awk 'NF && $1 !~ /^#/ { print; exit }' .dockerignore)" = "**" ] || \
  fail ".dockerignore must begin with a default-deny ** rule"
for pattern in '**/gen/**' '**/*.env' '**/secrets/**' '**/*.key' '**/*.pem' '**/*.p12' '**/*.p8'; do
  grep -Fqx "$pattern" .dockerignore || fail ".dockerignore missing $pattern"
done
for dockerfile in deploy/Dockerfile deploy/Dockerfile.*; do
  if grep -qE '^[[:space:]]*(COPY|ADD)[[:space:]]+\.[[:space:]]+\.' "$dockerfile"; then
    fail "$dockerfile copies the entire repository context"
  fi
  while IFS= read -r base; do
    case "$base" in
      *'@sha256:'*) ;;
      *) fail "$dockerfile contains an unpinned base image: $base" ;;
    esac
  done < <(grep -E '^FROM ' "$dockerfile")
done

echo "verify-release-config: release workflow and Docker context invariants pass"
