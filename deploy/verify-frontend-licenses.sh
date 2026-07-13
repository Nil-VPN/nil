#!/usr/bin/env bash
# Fail closed when a frontend dependency introduces a license outside the reviewed policy.
# Run after `pnpm --dir client install --frozen-lockfile`. It reads the installed pnpm virtual
# store directly so a missing global-store index cannot turn a complete dependency graph into a
# false pass or an infrastructure-only warning.
set -euo pipefail

command -v jq >/dev/null 2>&1 || {
  echo "verify-frontend-licenses: jq is required" >&2
  exit 1
}

shopt -s nullglob
packages=(
  client/node_modules/.pnpm/*/node_modules/*/package.json
  client/node_modules/.pnpm/*/node_modules/@*/*/package.json
)
[ "${#packages[@]}" -gt 0 ] || {
  echo "verify-frontend-licenses: installed pnpm dependency graph is missing" >&2
  exit 1
}

failed=0
for package in "${packages[@]}"; do
  name="$(jq -r '.name // empty' "$package")"
  version="$(jq -r '.version // empty' "$package")"
  license="$(jq -r '.license // empty' "$package")"
  if [ -z "$name" ] || [ -z "$version" ] || [ -z "$license" ]; then
    echo "verify-frontend-licenses: incomplete package/license metadata: $package" >&2
    failed=1
    continue
  fi
  case "$license" in
    # MPL-2.0 is the same reviewed, file-level-copyleft license accepted by deny.toml. NIL does not
    # modify or redistribute dependency source files in its client bundles; any future vendoring or
    # modified-source distribution still has to preserve MPL notices and make those files available.
    MIT|MIT-0|ISC|Apache-2.0|BSD-2-Clause|BSD-3-Clause|CC-BY-4.0|MPL-2.0|\
    "Apache-2.0 OR MIT"|"MIT OR Apache-2.0")
      ;;
    *)
      echo "verify-frontend-licenses: $name@$version has unreviewed license: $license" >&2
      failed=1
      ;;
  esac
done

if [ "$failed" -ne 0 ]; then
  echo "Update this explicit allowlist only after legal/security review." >&2
  exit 1
fi

echo "verify-frontend-licenses: all dependency licenses match the reviewed allowlist"
