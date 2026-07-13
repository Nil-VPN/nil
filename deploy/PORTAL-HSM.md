# Portal PKCS#11 issuer gate

- **Status date:** 2026-07-12
- **Release status:** **production NO-GO pending a real-HSM ceremony and review**

The production Portal image is built with the `hsm` feature and optimized builds refuse the
software RSA issuer. The reviewed Compose stack supplies an approved PKCS#11 module read-only and
the HSM user PIN through an owner-only Docker secret. The RSA private key must be generated in the
HSM as sensitive and non-extractable; it is never a host file, image layer, environment variable,
or Portal heap value.

This is a deployment contract, not approval of a particular HSM, PKCS#11 module, or cloud KMS.
SoftHSM proves API integration only and is forbidden as the production issuer.

## Required HSM object and mechanism

Provision one and only one RSA-2048 public/private keypair under the configured label and slot.
The private object must be token-resident, private, sensitive, non-extractable, and sign-capable.
The module must implement raw RSA private operations through `CKM_RSA_X_509`; NIL supplies an
already blinded full-width RSA message. Duplicate objects with the same label fail closed.

Use the vendor's reviewed, separately authenticated provisioning ceremony. Do not set
`NW_TOKEN_HSM_PROVISION` on the long-running Portal service. If the NIL provisioning command is
evaluated for a specific device, run it as a separate one-shot administrative ceremony with
audited access and confirm all object attributes afterward.

Before approval, record the HSM model/firmware, FIPS or equivalent validation scope where required,
HA/backup design, exact module hash and dependencies, mechanism behavior, key attributes, operator
roles, PIN retry/lockout policy, audit-log retention, and destruction/rotation procedure.

## Host inputs

Fill these non-secret fields in `deploy/env/portal.env`:

```text
NW_TOKEN_HSM_KEY_LABEL=nil-issuer-production
NW_TOKEN_HSM_SLOT=<numeric token slot id>
PORTAL_PKCS11_MODULE_FILE=/absolute/host/path/vendor-pkcs11.so
PORTAL_HSM_PIN_FILE=./secrets/portal_hsm_pin
```

The Compose stack maps the module to `/opt/nil/pkcs11/provider.so` and sets
`NW_TOKEN_HSM_MODULE` to that fixed path. The module and every runtime dependency must be compatible
with the digest-pinned Debian image. Include their hashes in the signed release manifest; a mutable
host package or unrecorded side library breaks the reviewed artifact boundary.

Create the PIN file without `name=value` syntax. One final LF is accepted, while embedded line
breaks, NULs, empty values, symlinks, non-regular files, oversized values, or group/world access are
rejected:

```bash
install -d -m 0700 deploy/secrets
install -m 0400 /secure/provisioning/portal_hsm_pin deploy/secrets/portal_hsm_pin
sudo chown 10001:10001 deploy/secrets/portal_hsm_pin
sudo chmod 0400 deploy/secrets/portal_hsm_pin
```

Local Docker Compose file-backed secrets cannot be assumed to remap ownership on every runtime.
The source file is therefore installed for the Portal's fixed uid/gid `10001`, and a protected
clean-host test must verify that `/run/secrets/portal_hsm_pin` is a regular owner-only file readable
by that process. Never set `NW_TOKEN_HSM_PIN`, `NW_TOKEN_SECRET`, or `NW_TOKEN_SECRET_FILE` in a
release environment.

## Bring-up and rotation evidence

Start only with approved immutable Caddy, wallet, and NIL image digests. On a normal Portal start,
retrieve `/v1/tokens/pubkey`, independently compare that public DER with the provisioned HSM object,
and add it to the Coordinator/client trust rollout before accepting paid issuance.

Key rotation requires overlap: distribute the new public key to every verifier/client trust root,
switch the Portal to the distinct new HSM object, wait through the maximum token validity and clock
skew, then retire the old public key and destroy the old object under dual control. A label change
without that verifier rollout causes failure or invalid tokens.

Production acceptance still requires real-device tests for startup with wrong module/slot/label/PIN,
PIN lockout, HSM outage and latency, session exhaustion, concurrent signing, failover, duplicate
labels, rotation, backup/restore, and audit logging. It also requires focused review that the chosen
device's `CKM_RSA_X_509` implementation and integration address the timing concern tracked as
`NIL-018`; selecting PKCS#11 alone does not prove constant-time remote behavior.
