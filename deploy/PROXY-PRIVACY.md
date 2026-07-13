# Public proxy privacy and attribution boundary

- **Status date:** 2026-07-12
- **Release status:** **production NO-GO**

This document describes the checked-in Portal and Coordinator Caddy boundary. It is a narrow
deployment control, not evidence that a hosting provider, load balancer, DNS service, firewall,
container runtime, or modified deployment retains no metadata.

## Logging contract

The two Caddyfiles deliberately contain no site-level `log` directive, so Caddy HTTP access logs
are disabled. Their Compose services additionally use Docker's `none` logging driver, discarding
Caddy operational stdout and stderr. This trades proxy diagnostics for a privacy-first default.

Portal, Coordinator, and wallet operational output uses Docker's `local` driver with an explicit
5 MiB by two-file bound. That output is **not assumed anonymous**. The bound is per container and
does not control host backups, Docker events, kernel/firewall logs, support agents, an upstream
edge, or provider telemetry. Any temporary Caddy logging override must be treated as a new
sensitive retention surface, with an owner, short expiry, access control, and verified deletion.

## Header-normalization contract

Caddy is the only published HTTP service. Before proxying, each Caddyfile removes:

- RFC `Forwarded`, every `X-Forwarded-*` field, `X-Real-IP`, and common CDN/vendor client-IP
  fields;
- request and correlation identifiers; and
- W3C, B3, AWS, and Jaeger-style trace propagation fields.

It then overwrites exactly one reserved field:

```text
X-Nil-Client-IP: {http.request.remote.host}
```

The value comes from Caddy's direct socket peer, never an inbound header. Portal and Coordinator
consume it through a narrow extractor that enforces all of these conditions together:

1. the immediate TCP peer exactly matches the separately pinned Caddy peer configured for that
   deployment; trusting an arbitrary private/Docker subnet is forbidden;
2. the upstream application port remains unpublished and unreachable from public networks;
3. the field contains exactly one canonical IPv4 or IPv6 address, with no list, whitespace,
   alternate spelling, port, or second header instance;
4. missing, malformed, duplicate, or untrusted-peer attribution is rejected before the handler,
   never mapped to caller-supplied forwarding headers; and
5. tests prove two authenticated source addresses receive independent budgets while forged standard,
   vendor, custom, duplicate, and multi-value headers cannot select another budget.

Release binaries refuse to start without one canonical `NW_TRUSTED_PROXY_IP`. The Compose files
assign that exact address to Caddy on a dedicated bridge subnet and assign a separate fixed address
to the unpublished backend. Development builds may omit the setting and use the direct socket peer,
but they reject `X-Nil-Client-IP` in that mode so a caller cannot opt into proxy trust.

The verified address exists only as an in-memory, fixed-window rate-limit key. It is not returned,
persisted, or intentionally logged. NAT users that share one public address also share a budget.
Distributed sources retain distributed budgets, so this is abuse resistance rather than a complete
DoS defense.

This contract identifies the peer connected directly to Caddy. If a CDN, load balancer, or another
reverse proxy sits in front of Caddy, every caller behind that edge will share the edge's address;
the current boundary intentionally ignores that edge's forwarded-address fields. Such a topology
needs a separately designed authenticated attribution boundary or public rate limiting at the edge
and a new security review. The source implementation remediates the application-side cause of
`NIL-011`, but the finding remains open pending independent hostile-path and live-topology
validation.

## Container and secret boundary

Every service in the two reviewed Compose files has a read-only root filesystem, drops all Linux
capabilities, sets `no-new-privileges`, and has explicit PID, memory, and hardened `/tmp` limits.
Caddy alone regains `NET_BIND_SERVICE`; Portal, Coordinator, and wallet-rpc regain no capability.
Only named state/certificate volumes and reviewed read-only configuration/key mounts remain
writable or readable beyond the immutable image. Portal and Coordinator run as fixed non-root
UIDs, and the setup comments require their result/grant key files to be owned by those exact UIDs
with mode `0400`.

The production Portal image includes the PKCS#11 backend and optimized startup refuses the software
RSA issuer. Compose mounts an approved module read-only and supplies only the HSM user PIN as an
owner-only secret at `/run/secrets/portal_hsm_pin`; the non-extractable issuer private key stays in
the HSM. Neither a raw issuer DER file nor an inline PIN is present in the production template. The
module, its dependencies, HSM firmware/object attributes, secret-mount permissions, mechanism, and
runtime behavior remain external release inputs described in [`PORTAL-HSM.md`](PORTAL-HSM.md).

The watch-only wallet password is a Compose secret mounted at
`/run/secrets/monero_wallet_password`. `monero-wallet-rpc` receives only that path through its
documented `--password-file` option; the value is absent from the environment, rendered command,
and process command line. The source file must remain owner-only and outside version control. An
approved wallet image still needs a clean-host check proving its actual runtime UID can read the
secret without broadening host permissions. See the upstream
[`monero-wallet-rpc` option reference](https://docs.getmonero.org/interacting/monero-wallet-rpc-reference/).

These are source-level defaults, not proof of the live container runtime. Named-volume ownership,
secret mount ownership, PKCS#11 module ABI, HSM availability, cgroup enforcement, seccomp/AppArmor
policy, host access, backup behavior, and the exact runtime user of each approved third-party image
must be recorded and tested in the protected deployment pipeline. The data-plane node bootstrap is
also outside these two Compose files and remains blocked by the separately-tracked production-node
requirements.

## Immutable proxy image blocker

The Compose files have no mutable Caddy fallback: `CADDY_IMAGE` is required. The Portal stack also
requires an immutable `MONERO_WALLET_RPC_IMAGE`. No digest is filled in here because the current NIL
release workflow does not resolve, verify, sign, or publish an approved platform-specific digest
for either third-party runtime image. Before a deployment can be accepted, those exact
`@sha256:` references must be verified and included in the signed release manifest. Substituting a
plausible current registry digest would not close that provenance gap.

## Regression check

Run:

```bash
bash deploy/verify-proxy-privacy.sh
```

The verifier rejects an access-log directive, missing header scrubbing, non-overwritten
`X-Nil-Client-IP`, a mutable Caddy reference, a Caddy log driver other than `none`, loss of the
fixed proxy/backend addresses and private bridge subnet, weakened root/capability/privilege/resource
controls, or a wallet password value in Compose/environment templates. It also requires the
file-backed wallet secret in the rendered command. For Portal it requires the HSM-enabled image
build, fixed module/PIN paths, owner-only PIN secret declaration, read-only module/result-key
mounts, exact label/slot, and absence of a software issuer key. It renders both Compose files when
Docker Compose is available and adapts both Caddyfiles when a local Caddy binary is available.

Passing the check covers only the versioned configuration. It does not attest to a live rendered
configuration, runtime packet source, external edge, host logging policy, or per-client rate-limit
behavior.
