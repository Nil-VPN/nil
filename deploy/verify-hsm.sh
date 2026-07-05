#!/usr/bin/env bash
# SoftHSM-backed verification of the PKCS#11 issuer signer (the `hsm` feature), in Docker (host
# untouched — the repo is mounted read-only and the build target is container-local).
#
# Proves the RSABSSA blind-token round-trip works with the RSA private key living in a PKCS#11
# device: provision an RSA-2048 keypair in a fresh SoftHSM2 token → client blinds a token message →
# the HSM blind-signs it (raw RSA, CKM_RSA_X_509) → client finalizes → verifier accepts. This is
# exactly what the in-memory Issuer does, but the key never leaves the device. SoftHSM stands in for
# a real HSM/KMS here; the Pkcs11Signer code is identical against either.
set -uo pipefail
cd "$(dirname "$0")/.." # repo root
img=rust:1.96.0-bookworm

docker run --rm -v "$PWD":/src:ro -w /src -e CARGO_TARGET_DIR=/tmp/target "$img" bash -euo pipefail -c '
  echo "==> install SoftHSM2 + build deps"
  apt-get update -qq
  apt-get install -y --no-install-recommends softhsm2 cmake clang pkg-config >/dev/null

  mod=$(find /usr/lib -name libsofthsm2.so 2>/dev/null | head -1)
  [ -n "$mod" ] || { echo "libsofthsm2.so not found"; exit 1; }
  echo "    PKCS#11 module: $mod"

  echo "==> init a fresh SoftHSM token"
  export SOFTHSM2_CONF=/tmp/softhsm2.conf
  mkdir -p /tmp/tokens
  printf "directories.tokendir = /tmp/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" > "$SOFTHSM2_CONF"
  softhsm2-util --init-token --free --label niltest --pin 1234 --so-pin 5678 >/dev/null
  softhsm2-util --show-slots | grep -E "Slot|Label|Initialized" | head -6

  echo "==> run the blind-token round-trip with the HSM doing the blind-sign"
  export NW_TOKEN_HSM_MODULE="$mod"
  export NW_TOKEN_HSM_PIN=1234
  export NW_TOKEN_HSM_KEY_LABEL=nil-issuer-test
  cargo test -p nil-portal --features hsm --locked hsm_blind_sign_round_trips -- --nocapture
'
rc=$?
echo
[ "$rc" -eq 0 ] && echo "RESULT: HSM ISSUER SIGNER VERIFIED ✅" || echo "RESULT: HSM VERIFICATION FAILED ❌"
exit "$rc"
