#!/usr/bin/env bash
# Fail-closed supply-chain guard: deny any cargo `source.replace` that re-points crates.io at a
# non-registry source (git repo, filesystem path, or any non-crates.io URL). Such a replacement
# would silently redirect dependency resolution off the audited crates.io index without changing
# Cargo.lock's "registry+https://github.com/rust-lang/crates.io-index" entries, so it can't be
# caught by `cargo deny` alone. deny.toml already sets `unknown-registry/unknown-git = "deny"`; this
# script closes the gap where a `[source.crates-io] replace-with = "..."` points at an allowed-but-
# unreviewed source.
set -euo pipefail

ALLOWED_REGISTRY="https://github.com/rust-lang/crates.io-index"

# Collect every [source.<name>] definition that is a replacement target (has replace-with or a
# registry/git/path spec) from .cargo/config.toml, .cargo/config, and Cargo.toml [source] tables.
configs=()
for f in .cargo/config.toml .cargo/config Cargo.toml; do
  [ -f "$f" ] && configs+=("$f")
done

if [ "${#configs[@]}" -eq 0 ]; then
  echo "OK: no cargo source configuration present (crates.io is the only source)."
  exit 0
fi

# Extract source-replacement targets. A replacement is declared by either:
#   [source.crates-io] replace-with = "X"     (redirects the default registry)
#   [source.X] replace-with = "Y"             (redirects a named source)
# and resolved by the target source's own registry/git/path. We deny any target that is not the
# exact allowed crates.io registry URL.
bad=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  echo "FAIL: forbidden source replacement / non-registry source: $line"
  bad=1
done < <(python3 - "$ALLOWED_REGISTRY" "${configs[@]}" <<'PY'
import sys, re, tomllib
allowed = sys.argv[1]
files = sys.argv[2:]
repl_re = re.compile(r'^\s*replace-with\s*=\s*["\']([^"\']+)["\']')
for path in files:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception as e:
        # Non-TOML cargo configs (.cargo/config without .toml) — scan textually.
        with open(path) as fh:
            txt = fh.read()
        for m in repl_re.finditer(txt):
            print(f"{path}: replace-with = {m.group(1)}")
        continue
    sources = data.get("source", {})
    for name, spec in sources.items():
        if not isinstance(spec, dict):
            continue
        if "replace-with" in spec:
            target = spec["replace-with"]
            tgt = sources.get(target, {})
            if isinstance(tgt, dict) and tgt.get("registry") == allowed:
                continue  # allowed: redirects only to the official crates.io registry
            print(f"{path}: [source.{name}] replace-with = {target} (resolves to a non-crates.io source)")
        elif "registry" in spec and spec["registry"] != allowed:
            print(f"{path}: [source.{name}] registry = {spec['registry']} (non-crates.io registry)")
        elif "git" in spec or "path" in spec:
            kind = "git" if "git" in spec else "path"
            print(f"{path}: [source.{name}] {kind} source (non-registry source replacement)")
PY
)

if [ "$bad" -ne 0 ]; then
  echo "Supply-chain guard FAILED: a source replacement points outside the audited crates.io registry."
  exit 1
fi
echo "OK: no forbidden source replacements; crates.io is the only allowed registry."
