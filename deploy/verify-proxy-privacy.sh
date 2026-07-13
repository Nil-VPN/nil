#!/usr/bin/env bash
# Regression guard for the versioned public Caddy/Compose privacy boundary.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

require_line() {
  local file=$1 line=$2
  grep -Fq -- "$line" "$file" || fail "$file is missing required policy: $line"
}

immutable_ref() {
  local name=$1 value=$2 digest
  case "$value" in
    *@sha256:*) ;;
    *) fail "$name must be an immutable image@sha256 reference" ;;
  esac
  digest=${value##*@sha256:}
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "$name has a malformed sha256 digest"
}

caddyfiles=(
  deploy/caddy/Caddyfile
  deploy/caddy/Caddyfile.coordinator
)

required_header_policy=(
  "header_up -Forwarded"
  "header_up -X-Forwarded-*"
  "header_up -X-Real-IP"
  "header_up -X-Original-Forwarded-For"
  "header_up -X-Client-IP"
  "header_up -X-Cluster-Client-IP"
  "header_up -X-ProxyUser-Ip"
  "header_up -CF-Connecting-IP"
  "header_up -True-Client-IP"
  "header_up -Fastly-Client-IP"
  "header_up -Fly-Client-IP"
  "header_up -X-Envoy-External-Address"
  "header_up -X-Appengine-User-IP"
  "header_up -X-Azure-ClientIP"
  "header_up -X-Request-ID"
  "header_up -Request-ID"
  "header_up -X-Correlation-ID"
  "header_up -Correlation-ID"
  "header_up -Traceparent"
  "header_up -Tracestate"
  "header_up -Baggage"
  "header_up -X-Amzn-Trace-Id"
  "header_up -X-B3-*"
  "header_up -B3"
  "header_up -Uber-Trace-Id"
  "header_up -X-Nil-Client-IP"
  "header_up X-Nil-Client-IP {http.request.remote.host}"
)

for file in "${caddyfiles[@]}"; do
  [[ -s "$file" ]] || fail "missing Caddy config: $file"

  # In a site block, Caddy's `log` directive enables HTTP access logging. Runtime logging is
  # controlled separately by Compose and must not be used to smuggle access logs back in here.
  if grep -En '^[[:space:]]*log([[:space:]]|\{)' "$file"; then
    fail "$file enables HTTP access logging"
  fi

  [[ $(grep -Ec '^[[:space:]]*reverse_proxy[[:space:]]' "$file") -eq 1 ]] \
    || fail "$file must have exactly one normalized reverse_proxy boundary"

  for line in "${required_header_policy[@]}"; do
    require_line "$file" "$line"
  done

  [[ $(grep -Fc 'header_up X-Nil-Client-IP {http.request.remote.host}' "$file") -eq 1 ]] \
    || fail "$file must overwrite X-Nil-Client-IP exactly once from the direct socket peer"

  if grep -En 'header_up[[:space:]]+[^-].*\{http\.request\.header\.' "$file"; then
    fail "$file forwards an untrusted inbound request header"
  fi
done

composes=(
  deploy/compose.portal.yaml
  deploy/compose.coordinator.yaml
)

for file in "${composes[@]}"; do
  [[ -s "$file" ]] || fail "missing Compose config: $file"
  require_line "$file" 'image: ${CADDY_IMAGE:?set CADDY_IMAGE to an approved immutable caddy@sha256 reference}'
  if grep -En '^[[:space:]]*image:[[:space:]]*caddy([^$]|$)' "$file"; then
    fail "$file contains a mutable or literal Caddy image instead of the required digest input"
  fi

  caddy_block=$(awk '
    /^  caddy:$/ { inside=1 }
    inside && /^  [A-Za-z0-9_.-]+:$/ && $0 != "  caddy:" { exit }
    inside { print }
  ' "$file")
  grep -Fq 'driver: "none"' <<<"$caddy_block" \
    || fail "$file must discard Caddy operational stdout/stderr"
  require_line "$file" 'ipv4_address: ${NW_TRUSTED_PROXY_IP:?set the fixed Caddy IP}'
  require_line "$file" 'ipam:'
  expected_services=2
  [[ "$file" == *portal* ]] && expected_services=3
  [[ $(grep -Fc 'read_only: true' "$file") -eq $expected_services ]] \
    || fail "$file must make every service root filesystem read-only"
  [[ $(grep -Fc 'cap_drop: ["ALL"]' "$file") -eq $expected_services ]] \
    || fail "$file must drop all Linux capabilities from every service"
  [[ $(grep -Fc 'security_opt: ["no-new-privileges:true"]' "$file") -eq $expected_services ]] \
    || fail "$file must set no-new-privileges on every service"
  [[ $(grep -Ec '^[[:space:]]+pids_limit:[[:space:]]+[1-9][0-9]*$' "$file") -eq $expected_services ]] \
    || fail "$file must bound process counts for every service"
  [[ $(grep -Ec '^[[:space:]]+mem_limit:' "$file") -eq $expected_services ]] \
    || fail "$file must bound memory for every service"
  [[ $(grep -Ec '^[[:space:]]+cpus:' "$file") -eq $expected_services ]] \
    || fail "$file must bound CPU for every service"
  [[ $(grep -Ec '^[[:space:]]+- /tmp:.*noexec.*nosuid.*nodev' "$file") -eq $expected_services ]] \
    || fail "$file must give every service only a bounded, hardened temporary filesystem"
done

[[ $(grep -Fc 'cap_add: ["NET_BIND_SERVICE"]' deploy/compose.portal.yaml) -eq 1 ]] \
  || fail "Portal Compose must add only NET_BIND_SERVICE to Caddy"
[[ $(grep -Fc 'cap_add: ["NET_BIND_SERVICE"]' deploy/compose.coordinator.yaml) -eq 1 ]] \
  || fail "Coordinator Compose must add only NET_BIND_SERVICE to Caddy"

require_line deploy/compose.portal.yaml \
  'ipv4_address: ${PORTAL_BACKEND_IP:-172.30.10.3}'
require_line deploy/compose.portal.yaml \
  'subnet: ${PORTAL_NETWORK_SUBNET:-172.30.10.0/24}'
require_line deploy/compose.portal.yaml 'network_mode: "service:monero-wallet-rpc"'
require_line deploy/compose.portal.yaml 'aliases: [portal]'
require_line deploy/Dockerfile.portal \
  'RUN cargo build --release --locked -p nil-portal --features hsm'
require_line deploy/compose.portal.yaml \
  'NW_TOKEN_HSM_MODULE=/opt/nil/pkcs11/provider.so'
require_line deploy/compose.portal.yaml \
  'NW_TOKEN_HSM_PIN_FILE=/run/secrets/portal_hsm_pin'
require_line deploy/compose.portal.yaml \
  '${PORTAL_PKCS11_MODULE_FILE:?set the approved host PKCS#11 module path}:/opt/nil/pkcs11/provider.so:ro'
require_line deploy/compose.portal.yaml \
  'file: ${PORTAL_HSM_PIN_FILE:?set the host path to the owner-only HSM PIN file}'
require_line deploy/compose.portal.yaml \
  './secrets/portal_result_key.bin:/etc/nil/portal_result_key.bin:ro'
if grep -En 'issuer_key\.der|^[[:space:]]*-[[:space:]]+NW_TOKEN_SECRET(_FILE)?=' \
  deploy/compose.portal.yaml; then
  fail "Production Portal Compose retains a software issuer private key"
fi
if grep -REn 'NW_TOKEN_SECRET_FILE=|issuer_key\.der|issuer\.der' deploy \
  --include='*.yaml' --include='*.yml' --include='*.env.example' --include='Dockerfile*'; then
  fail "a deployment example teaches the release-forbidden software issuer path"
fi
require_line deploy/compose.portal.yaml \
  '--password-file=/run/secrets/monero_wallet_password'
require_line deploy/compose.portal.yaml \
  'file: ${MONERO_WALLET_PASSWORD_FILE:?set the host path to the owner-only wallet password file}'
if grep -En -- '--password=' deploy/compose.portal.yaml; then
  fail "Portal Compose exposes the wallet password in the process command"
fi
# The deploy/monero/ operator sketches are intentionally kept out of the public repo (git-excluded),
# so validate their archived-only + owner-only-password policy only when they are present locally.
if [ -d deploy/monero ]; then
  require_line deploy/monero/compose.portal-monero.yaml \
    '# ARCHIVED / NON-EXECUTABLE DEPLOYMENT SKETCH. DO NOT RUN.'
  require_line deploy/monero/portal.env.example \
    '# ARCHIVED Portal environment fragment — documentation only, not a deployable release template.'
  require_line deploy/monero/monero-wallet-rpc.service \
    '--password-file ${WALLET_PASSWORD_FILE}'
  require_line deploy/monero/create-watch-only-wallet.sh \
    '--password-file "${WALLET_PASSWORD_FILE}"'
  require_line deploy/monero/setup-monerod.sh \
    'openssl rand -base64 48 > "${PW_FILE}"'
  if grep -En -- '--password([=[:space:]])' \
    deploy/monero/monero-wallet-rpc.service deploy/monero/create-watch-only-wallet.sh; then
    fail "Monero systemd path passes a password value instead of an owner-only file"
  fi
fi
require_line deploy/compose.coordinator.yaml \
  'ipv4_address: ${COORDINATOR_BACKEND_IP:-172.31.10.3}'
require_line deploy/compose.coordinator.yaml \
  'subnet: ${COORDINATOR_NETWORK_SUBNET:-172.31.10.0/24}'

for file in deploy/env/portal.env.example deploy/env/portal-staging.env.example; do
  require_line "$file" 'NW_TRUSTED_PROXY_IP='
  require_line "$file" 'PORTAL_NETWORK_SUBNET='
  require_line "$file" 'PORTAL_BACKEND_IP='
  require_line "$file" 'MONERO_WALLET_PASSWORD_FILE='
  require_line "$file" 'NW_TOKEN_HSM_KEY_LABEL='
  require_line "$file" 'NW_TOKEN_HSM_SLOT='
  require_line "$file" 'PORTAL_PKCS11_MODULE_FILE='
  require_line "$file" 'PORTAL_HSM_PIN_FILE='
  if grep -En '^MONERO_WALLET_PASSWORD=' "$file"; then
    fail "$file exposes the wallet password value through Compose interpolation"
  fi
  if grep -En '^(NW_TOKEN_HSM_PIN|NW_TOKEN_SECRET|NW_TOKEN_SECRET_FILE|NW_TOKEN_HSM_PROVISION)=' "$file"; then
    fail "$file configures a release-forbidden inline/software/provisioning issuer secret"
  fi
done
for file in deploy/env/coordinator.env.example deploy/env/coordinator-staging.env.example; do
  require_line "$file" 'NW_TRUSTED_PROXY_IP='
  require_line "$file" 'COORDINATOR_NETWORK_SUBNET='
  require_line "$file" 'COORDINATOR_BACKEND_IP='
done

# If a caller supplies real release inputs, validate them rather than merely relying on Compose's
# presence check. CI uses a clearly synthetic all-zero digest only to render the shape below.
[[ -z ${CADDY_IMAGE:-} ]] || immutable_ref CADDY_IMAGE "$CADDY_IMAGE"
[[ -z ${MONERO_WALLET_RPC_IMAGE:-} ]] \
  || immutable_ref MONERO_WALLET_RPC_IMAGE "$MONERO_WALLET_RPC_IMAGE"

if docker compose version >/dev/null 2>&1; then
  command -v jq >/dev/null 2>&1 || fail "jq is required for rendered Compose verification"
  zero_digest=$(printf '%064d' 0)
  test_caddy="caddy@sha256:$zero_digest"
  test_wallet="ghcr.io/example/wallet@sha256:$zero_digest"

  # compose.portal/coordinator declare `env_file: env/<svc>.env`. Under --no-path-resolution docker
  # keeps that path relative to the current working directory (repo root), so `docker compose config`
  # stats ./env/<svc>.env — the git-excluded operator secret. In environments without it (e.g. CI)
  # provide empty stand-ins under ./env and remove them on exit.
  stub_env_files=()
  mkdir -p env
  for envf in env/portal.env env/coordinator.env; do
    if [ ! -f "$envf" ]; then
      : > "$envf"
      stub_env_files+=("$envf")
    fi
  done
  trap '[ ${#stub_env_files[@]} -gt 0 ] && rm -f "${stub_env_files[@]}"; rmdir env 2>/dev/null || true' EXIT

  for file in "${composes[@]}"; do
    proxy_ip=172.30.10.2
    backend_ip=172.30.10.3
    network_subnet=172.30.10.0/24
    network=portalnet
    if [[ "$file" == *coordinator* ]]; then
      proxy_ip=172.31.10.2
      backend_ip=172.31.10.3
      network_subnet=172.31.10.0/24
      network=coordnet
    fi
    rendered=$(CADDY_IMAGE="$test_caddy" MONERO_WALLET_RPC_IMAGE="$test_wallet" \
      NW_TRUSTED_PROXY_IP="$proxy_ip" PORTAL_BACKEND_IP="$backend_ip" \
      PORTAL_NETWORK_SUBNET="$network_subnet" COORDINATOR_BACKEND_IP="$backend_ip" \
      COORDINATOR_NETWORK_SUBNET="$network_subnet" \
      PORTAL_PUBLIC_HOST=portal.invalid CTRL_PUBLIC_HOST=control.invalid \
      ACME_EMAIL=security@example.invalid MONEROD_RPC=http://127.0.0.1:18081 \
      MONERO_WALLET_FILE=test-wallet MONERO_WALLET_PASSWORD_FILE=./secrets/test-wallet-password \
      PORTAL_PKCS11_MODULE_FILE=/opt/test-vendor-pkcs11.so \
      PORTAL_HSM_PIN_FILE=./secrets/test-hsm-pin \
      NW_TOKEN_HSM_KEY_LABEL=test-release-issuer NW_TOKEN_HSM_SLOT=7 \
      docker compose -f "$file" config --no-env-resolution --no-path-resolution --format json)
    jq -e --arg image "$test_caddy" \
      '.services.caddy.image == $image and .services.caddy.logging.driver == "none"' \
      <<<"$rendered" >/dev/null \
      || fail "$file rendered an unpinned Caddy image or retained Caddy logs"
    jq -e \
      'all(.services[];
        .read_only == true and
        ((.cap_drop // []) | index("ALL")) != null and
        ((.security_opt // []) | index("no-new-privileges:true")) != null and
        .pids_limit > 0 and .mem_limit > 0 and .cpus > 0 and
        any((.tmpfs // [])[];
          startswith("/tmp:") and contains("noexec") and contains("nosuid") and contains("nodev"))) and
       .services.caddy.cap_add == ["NET_BIND_SERVICE"] and
       all(.services | to_entries[];
         .key == "caddy" or ((.value.cap_add // []) | length == 0))' \
      <<<"$rendered" >/dev/null \
      || fail "$file lost a read-only/capability/privilege/PID/memory/tmpfs service boundary"
    jq -e --arg network "$network" --arg proxy "$proxy_ip" --arg subnet "$network_subnet" \
      '.services.caddy.networks[$network].ipv4_address == $proxy and
       .networks[$network].ipam.config[0].subnet == $subnet' \
      <<<"$rendered" >/dev/null \
      || fail "$file did not render the authenticated fixed-proxy network boundary"

    upstream=coordinator
    [[ "$file" == *portal* ]] && upstream=portal
    jq -e --arg upstream "$upstream" \
      '(.services[$upstream].ports // []) | length == 0' <<<"$rendered" >/dev/null \
      || fail "$file publishes the application upstream directly"

    if [[ "$file" == *portal* ]]; then
      jq -e --arg backend "$backend_ip" \
        '.services.portal.network_mode == "service:monero-wallet-rpc" and
         .services.portal.environment.NW_TOKEN_HSM_MODULE == "/opt/nil/pkcs11/provider.so" and
         .services.portal.environment.NW_TOKEN_HSM_PIN_FILE == "/run/secrets/portal_hsm_pin" and
         .services.portal.environment.NW_TOKEN_HSM_KEY_LABEL == "test-release-issuer" and
         .services.portal.environment.NW_TOKEN_HSM_SLOT == "7" and
         (.services.portal.environment.NW_TOKEN_SECRET // null) == null and
         (.services.portal.environment.NW_TOKEN_SECRET_FILE // null) == null and
         any(.services.portal.volumes[];
           .source == "/opt/test-vendor-pkcs11.so" and
           .target == "/opt/nil/pkcs11/provider.so" and .read_only == true) and
         any(.services.portal.volumes[];
           .source == "portal_result_key.bin" or
           (.source == "./secrets/portal_result_key.bin" and
             .target == "/etc/nil/portal_result_key.bin" and .read_only == true)) and
         any(.services.portal.secrets[];
           .source == "portal_hsm_pin" and
           .target == "portal_hsm_pin" and
           .uid == "10001" and .gid == "10001" and .mode == "0400") and
         .secrets.portal_hsm_pin.file == "./secrets/test-hsm-pin" and
         .services["monero-wallet-rpc"].networks.portalnet.ipv4_address == $backend and
         (.services["monero-wallet-rpc"].networks.portalnet.aliases | index("portal")) != null and
         (.services["monero-wallet-rpc"].command |
           index("--password-file=/run/secrets/monero_wallet_password")) != null and
         (.services["monero-wallet-rpc"].command |
           all(.[]; startswith("--password=") | not)) and
         (.services["monero-wallet-rpc"].secrets |
           any(.[]; .source == "monero_wallet_password" and
             .target == "/run/secrets/monero_wallet_password")) and
         .secrets.monero_wallet_password.file == "./secrets/test-wallet-password"' \
        <<<"$rendered" >/dev/null \
        || fail "$file did not render the private Portal/wallet network and credential boundary"
    else
      jq -e --arg backend "$backend_ip" \
        '.services.coordinator.networks.coordnet.ipv4_address == $backend' \
        <<<"$rendered" >/dev/null \
        || fail "$file did not render the private Coordinator backend address"
    fi
  done
else
  echo "NOTE: docker compose unavailable; static Compose policy checks passed" >&2
fi

# Adapted JSON catches Caddyfile syntax/order regressions when Caddy is installed. The static guard
# remains mandatory so this check still protects source trees without a local Caddy binary.
if command -v caddy >/dev/null 2>&1; then
  command -v jq >/dev/null 2>&1 || fail "jq is required for adapted Caddy verification"
  for file in "${caddyfiles[@]}"; do
    adapted=$(PORTAL_PUBLIC_HOST=portal.invalid CTRL_PUBLIC_HOST=control.invalid \
      ACME_EMAIL=security@example.invalid caddy adapt --adapter caddyfile --config "$file")
    jq -e '[.apps.http.servers[]? | select(has("logs"))] | length == 0' \
      <<<"$adapted" >/dev/null || fail "$file adapts to an access-logging server"
  done
else
  echo "NOTE: caddy unavailable; static Caddyfile policy checks passed" >&2
fi

echo "PASS: proxy privacy configuration is fail-closed"
