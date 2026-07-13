# NIL service image candidates and verification

- **Status date:** 2026-07-12
- **Release status:** **NO-GO for production or a public/paid beta.**

The release pipeline builds three Linux/amd64 images:

| Image | Plane | Dockerfile |
|---|---|---|
| `nil-node` | Data plane | `deploy/Dockerfile.node` (`hw-attest`) |
| `nil-portal` | Business plane | `deploy/Dockerfile.portal` (`hsm`) |
| `nil-coordinator` | Control plane | `deploy/Dockerfile.coordinator` |

Builder/runtime bases are digest-pinned and the Docker context is default-deny. Dockerfiles copy
only the workspace manifests, crates, and narrowly required Tauri trust/build sources. Rust
dependencies are locked; the node build vendors them and compiles offline. Debian packages are
still installed from current repositories rather than an immutable snapshot, so across-time
hermetic reproducibility is not yet established.

The public proxy examples also require reviewed platform-specific Caddy and Monero wallet-RPC
digests. The repository intentionally does not invent those values: Compose requires explicit
`@sha256:` inputs. See `PROXY-PRIVACY.md`.

The Portal candidate contains the PKCS#11 backend and optimized startup requires it; a software/file
RSA issuer is not a release fallback. The deployment's vendor PKCS#11 module is mounted at runtime,
so its exact hash, dependencies, HSM model/firmware, and object/mechanism policy must be added to the
signed release set before promotion. Repository SoftHSM tests establish integration shape only.
See [`PORTAL-HSM.md`](PORTAL-HSM.md).

## Candidate flow

`.github/workflows/release.yml` is the only `v*` trigger. After validating an annotated,
GitHub-verified tag at the exact `main`-reachable SHA and re-running CI/dataplane gates, it calls
the reusable image stage:

1. Build all three images locally with no registry credentials.
2. Fail each image on fixable `HIGH`/`CRITICAL` Trivy findings.
3. Generate a required CycloneDX SBOM for each image.
4. Export and hash all three local archives as Actions artifacts. The matrix uses `fail-fast: true`;
   nothing is pushed in these build jobs.
5. Extract `/usr/local/bin/nil-node` from the exact candidate image and require its SHA-256 to equal
   the independently double-built reproducible node ELF.
6. Only after the entire image set and all signed client candidates are complete, enter the
   externally protected `release-candidates` Environment. This job has no checkout and executes no
   repository scripts.
7. Push all three images under run-scoped `candidate-<run>-<attempt>` refs, resolve immutable
   digests, keyless-sign each digest, attach a keyless CycloneDX attestation, and attach mandatory
   GitHub provenance.
8. Verify all evidence, record the three digests plus the matched node ELF hash in one manifest,
   keyless-sign that manifest, and include its hash in the final signed release-set manifest.

The final protected release-set job verifies both the image-manifest and client-manifest Sigstore
bundles against the expected `release.yml@refs/tags/v...` identity and GitHub OIDC issuer before it
signs their hashes into the aggregate manifest. Component hashes alone are not treated as trust.

Run-scoped candidate refs may remain if a registry/evidence operation fails. They are not version
or `latest` tags and are never represented as a release. Operators and clients must not consume
them outside isolated release validation.

## Why version and `latest` tags are not published

GHCR has no cross-repository transaction for the three image repositories. Sequentially moving
`vX` or `latest` can expose a partial set if a later operation fails. Client publication is another
independent system, making the consistency boundary larger still.

The repository therefore stops before public promotion: no checked-in workflow writes image
version/`latest` tags or creates a GitHub Release, and `deploy-production.yml` exits nonzero. The
required external gate is specified in `../RELEASE.md`. This is an intentional fail-closed
boundary, not evidence that atomic promotion has been solved.

## Verify a candidate digest

Download the complete `release-set-<tag>-<attempt>` Actions artifact from the same orchestrator run, install
`cosign`, `gh`, and `jq`, authenticate `gh`, then run:

```bash
./deploy/verify-image.sh \
  ghcr.io/nil-vpn/nil-node@sha256:<64-hex-digest> \
  ./release-set-<tag>-<attempt>
```

The verifier refuses mutable refs and requires:

- a valid keyless signature on the aggregate release-set manifest;
- image-manifest hash binding and membership of the supplied digest in that complete set;
- a keyless image signature from the tag-triggered `release.yml` identity;
- a keyless CycloneDX image attestation; and
- required GitHub provenance from that workflow.

It also requires the signed manifest to say promotion is blocked. `RESULT: VERIFIED` therefore
means the candidate evidence is internally consistent, not that deployment is authorized.

## Remaining artifact-chain gaps

The candidate manifest binds the source SHA, Cargo/toolchain inputs, service OCI digests, exact node
ELF, and client manifests/SBOM. It does not yet bind an immutable guest-image digest or real
SEV-SNP launch measurement / complete NIL TDX identity to that ELF. No public workflow run, signing identity, registry
object, protected Environment configuration, or external promotion transaction has been verified
from this workspace. Those remain release blockers tracked in `../RELEASE.md`.
