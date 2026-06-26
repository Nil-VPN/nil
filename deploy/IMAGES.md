# NIL service images — public, signed, verify-before-deploy

NIL publishes three production service images to the GitHub Container Registry (GHCR):

| Image | Plane | Built from |
|-------|-------|------------|
| `ghcr.io/nil-vpn/nil-node` | Data plane (runs inside a confidential VM) | `deploy/Dockerfile.node` (`hw-attest`) |
| `ghcr.io/nil-vpn/nil-portal` | Business plane (Privacy Pass issuer + PII-free accounts) | `deploy/Dockerfile.portal` |
| `ghcr.io/nil-vpn/nil-coordinator` | Control plane (token verifier + trust-split path selection) | `deploy/Dockerfile.coordinator` |

## Posture

- **The images are public by design.** They are open-source binaries built from this public repo
  and carry **no secrets** — every key, endpoint, account, payment reference, and measurement is
  injected at runtime via env vars / mounted files. Publishing the image lets anyone verify the
  running binary; it leaks nothing (PD-1 / PD-3).
- **The build *method* is public; the operational *recipe* is not.** What's public is exactly what
  PD-5 ("prove, don't promise") requires — the reproducible build and the signed artifact. The
  internal design spec and the production deployment wiring (stack composition, host provisioning,
  edge proxy, payment plumbing) are kept private; none of it is needed to verify an image.
- Every image is built by `.github/workflows/release-images.yml` on a `v*` tag.

## What each image guarantees

| Guarantee | How |
|-----------|-----|
| **Pinned base** | builder + runtime bases pinned by `@sha256:` — the **same two digests** across all three images, so the whole fleet shares one attestable base |
| **Non-root (services)** | `nil-portal` (uid/gid 10001) and `nil-coordinator` (uid/gid 10002) run as a fixed non-root user with no shell — PD-7. `nil-node` is the deliberate exception: it owns the datapath TUN and NATs egress, so it runs with `CAP_NET_ADMIN` inside an isolated confidential VM (a different, contained model). |
| **Signed by digest** | cosign **keyless** (Fulcio/Rekor); the signing identity is the `release-images.yml` workflow, checkable offline |
| **SBOM** | a CycloneDX SBOM is generated and attested to the image (`cosign attest --type cyclonedx`) |
| **Provenance** | SLSA build provenance via GitHub attestations (`actions/attest-build-provenance`) |
| **Vuln-gated** | a Trivy scan (`HIGH,CRITICAL`, fixable only) must pass **before** the image is signed |

## Operator flow — never deploy a mutable tag

1. **Resolve the tag to a digest once** — from the release job summary, or
   `docker buildx imagetools inspect ghcr.io/nil-vpn/<image>:<tag>`.
2. **Verify the digest** before trusting it:
   ```
   ./deploy/verify-image.sh ghcr.io/nil-vpn/<image>@sha256:<digest>
   ```
   It refuses any non-digest ref, requires a valid signature **and** a CycloneDX SBOM attestation,
   and confirms SLSA provenance (with a `gh attestation verify` fallback if cosign can't).
3. **Pin the `@sha256:` digest** in your deployment config (compose / Nomad). A mutable tag can be
   silently re-pointed; a digest cannot.
4. **Rollback is deterministic:** re-pin the previous known-good `@sha256:` digest — the exact prior
   bytes, re-verified the same way.

Together this closes the chain from reproducible source → signed artifact → the exact binary you run.
