#!/usr/bin/env bash
# Reproducible build of the production nil-node: build it twice from a clean tree and assert
# the binary hashes identically. That SHA-256 is the dev "measurement" — the value the
# Coordinator pins and clients appraise (see deploy/Dockerfile.repro for the honest caveat:
# it stands in for a true SEV-SNP/TDX guest-launch measurement; the appraisal interface is
# the same when the real source swaps in).
#
# Host untouched: everything runs in throwaway Docker images.
set -uo pipefail
cd "$(dirname "$0")/.."

SDE=$(git log -1 --pretty=%ct 2>/dev/null || echo 0)
echo "==> SOURCE_DATE_EPOCH=$SDE (commit time)"

build() {
  local tag="$1"
  docker build --no-cache --build-arg SOURCE_DATE_EPOCH="$SDE" \
    -f deploy/Dockerfile.repro --target builder -t "nil-node-repro:$tag" . >/dev/null 2>&1 || return 1
  docker run --rm --entrypoint sha256sum "nil-node-repro:$tag" /nil-node | awk '{print $1}'
}

echo "==> build A (clean)"; A=$(build a) || { echo "build A failed"; exit 1; }
echo "==> build B (clean)"; B=$(build b) || { echo "build B failed"; exit 1; }
echo "  A: ${A:-<none>}"
echo "  B: ${B:-<none>}"

if [ -n "$A" ] && [ "$A" = "$B" ]; then
  echo "MEASUREMENT=$A"
  echo "RESULT: nil-node build is reproducible ✅"
  exit 0
else
  echo "RESULT: builds are NOT byte-identical ❌"
  echo "  In place: pinned toolchain (rust-toolchain.toml), codegen-units=1, --locked + vendored"
  echo "  deps built --offline, CARGO_INCREMENTAL=0, --remap-path-prefix, --build-id=none, and a"
  echo "  digest-pinned linux/amd64 base. If it still diverges, suspect: a dep build.rs that embeds"
  echo "  a timestamp/abspath, BoringSSL/cmake nondeterminism, or qemu-vs-native codegen (build on a"
  echo "  real amd64 host, not an emulated arm64 one). This is a finding to chase, not a script bug."
  exit 1
fi
