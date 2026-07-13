# NIL VPN — release posture

> **Status: engineering alpha; production/public paid deployment is NO-GO.** A successful build or
> synthetic harness proves only the behavior it exercises. Live hardware, privileged OS behavior,
> independent operators, payment operations, and published artifacts require separate evidence.

## Production-profile boundary implemented in code

- **Client trust:** a release client build fails without a validated embedded bundle of issuer
  public keys, node measurements, and a transparency-log key. Runtime configuration may narrow
  those values but cannot add a new trusted root.
- **Control links:** release clients require HTTPS for Portal and Coordinator traffic, including
  bearer-token redemption. Plaintext loopback is a debug-only convenience.
- **Connection path:** desktop release code requires a Coordinator-redeemed path of at least two
  hops and one already-prefetched local pass. Connect does not contact the issuer.
- **Development capability isolation:** single-hop, direct/static nodes, in-memory loopback,
  synthetic attestation, dev tracing, AmneziaWG, wstunnel, REALITY, and automatic fallback
  selection are rejected or compiled out when debug assertions are disabled.
- **Service startup:** release Portal builds require a PKCS#11 issuer module and owner-only PIN file
  and refuse software/file issuer fallback. Portal/Coordinator configurations also require real
  keys, a real payment rail, durable replay/nullifier stores, a strictly validated node registry,
  token verification, owner-only Ed25519 grant-signing and independent redemption-result
  encryption key files, a deployment realm, and at least two Coordinator hops. Hardware nodes
  receive only a public
  verification-key ring plus their stable ID/role. Mock
  payments, ephemeral issuers, inline signing seeds, volatile stores, and ungranted nodes are
  development-only.

## Account, credentials, and correlation

- Account scheme v2 uses a client-generated, checksummed 12-word BIP39 phrase with 128 bits of
  entropy. The Portal receives no recovery material and stores only the account identifier,
  entitlement/expiry, and public auth key. There is no server recovery endpoint or recovery code.
- The client caches the derived auth seed and bearer passes in an encrypted vault protected by the
  platform credential service. The phrase is not cached. Legacy plaintext files are removed only
  after a sealed migration has been reopened and verified.
- An active subscription refills toward eight passes in a bounded blind-signature batch, on a
  randomized background schedule. Messages in one batch share an hourly rounded, roughly one-day
  expiry. This separates Connect from issuer access, but does not eliminate timing, IP,
  payment-record, or small-population correlation.
- Blind signing prevents a direct cryptographic issuance-to-redemption join. It is not a guarantee
  that payment, account activity, and traffic can never be correlated by colluding or modified
  infrastructure.

## Transport and attestation evidence

- The production transport code is MASQUE/QUIC with authorization before client datagrams reach the
  TUN. Nested multi-hop, per-hop grants, measurement appraisal, and transparency-proof enforcement
  have unit/synthetic integration coverage.
- Per-hop `NWG2` grants are Ed25519-signed and bind realm, stable node ID, intended role, MASQUE,
  TEE, measurement, stable TLS-SPKI digest, expiry, and nonce. Nodes carry public verifier rings
  rather than a fleet-wide shared minting secret. Verifier files load only at startup, so rotation
  and revocation require an atomic file rollout plus node restart/roll; that has not been live-drilled.
- The Docker paths use synthetic reports. NIL has not validated this full chain on its own live
  SEV-SNP/TDX fleet or across legally independent operators.
- The candidate pipeline now requires the `nil-node` ELF extracted from the exact candidate OCI
  image to match the separately double-built reproducible ELF. It records that hash with all three
  OCI digests in a signed manifest. The immutable guest-image digest and real SEV-SNP/TDX launch
  measurement are still not bound to that manifest, so the runtime chain remains incomplete.
- TDX source appraisal now requires exact attributes, configuration/owner identities, RTMR0–3,
  report-body/service-TD identity, non-debug state, and a clean `UpToDate`/no-advisory DCAP result.
  These fields and MRTD are bound into one client-pinned SHA-384 identity; raw MRTD is not an
  accepted production policy. Local units cover complete synthetic report bodies; the genuine
  quote KAT verifies Intel collateral and then correctly rejects that generic fixture because its
  RTMR3 is empty. An accepted NIL image still needs independent review, a signed measured-boot
  manifest, and live-hardware validation. TEE.Fail-class
  physical attacks remain a real limitation.

## Platform status

- Linux, macOS, and Windows desktop datapath code implements TUN/routing/DNS and fail-closed
  firewall control. Source teardown tracks owned route/DNS/firewall mutations, reports incomplete
  restoration, and does not release the firewall after an earlier rollback failure; Linux preserves
  exact default/host-route snapshots and uses private chains. A failed desktop Disconnect retains
  its journal for an explicit retry. Focused host tests and platform
  compile checks pass. External-command fault injection, privileged leak/rollback behavior, process
  crash/reboot recovery, sleep/wake, and signed-package execution still require validation on each
  supported OS; Windows still relies on global firewall-profile defaults rather than dynamic WFP.
- Android, iOS, and the macOS network extension currently implement one native MASQUE hop. Because
  the release policy requires at least two, packaged native builds deliberately refuse to connect
  before consuming a pass until native multi-hop is implemented.
- Persistent mobile blocking while the VPN process is down depends on the user's platform
  Always-on/Block-without-VPN setting; the app cannot silently promise that system setting is on.

## Intended release checks

The local verification baseline is:

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check
pnpm --dir client build
pnpm --dir client test
```

Feature checks also cover synthetic appraisal, development fallback round trips, Postgres mappings,
the optional card-payment build, the production HSM issuer profile, hardware-attestation
compilation, and negative release compile guards. These checks are useful evidence; they do not by
themselves authorize a production release.

## Supply-chain status

`.github/workflows/release.yml` is the sole `v*` entrypoint. It accepts only canonical semantic
versions, requires an annotated tag whose signature GitHub verifies, checks that the tag commit is
the workflow event SHA and an ancestor of `origin/main`, and then re-runs the reusable CI and
dataplane workflows at that exact SHA. Independent image, client-signing, and measurement tag
workflows no longer exist.

The release stages now enforce these local controls:

- every external Action in every workflow is pinned to a 40-character commit SHA with its reviewed
  human-readable version recorded; Dependabot proposes updates for Actions, Cargo, and pnpm;
- `.dockerignore` is default-deny, production Dockerfiles use explicit source-root copies, and a
  static regression guard rejects sensitive context patterns or a returned `COPY . .`;
- all three images build locally without registry credentials, pass fixable-HIGH/CRITICAL Trivy
  gates, receive CycloneDX SBOMs, and complete as one matrix before package/OIDC authority exists;
- the exact node ELF extracted from the candidate image must equal the double-built reproducible
  ELF; only then are all three images pushed under run-scoped `candidate-<run>-<attempt>` refs,
  signed by digest, SBOM-attested, provenance-attested, and recorded in one signed image manifest;
- macOS, Windows, and Linux clients build in jobs without signing secrets and with checkout
  credentials disabled. Separate protected-Environment jobs download those artifacts and execute
  only platform signing/notarization tools—no checkout or repository build scripts. Before secrets
  are exposed, each job verifies the archive hash, rejects absolute/traversal/colliding paths,
  symlinks, hardlinks, special entries, and oversized archives, and extracts into a checked local
  tree. Every signed archive receives provenance and is bound to a combined Rust/npm CycloneDX
  SBOM and signed client manifest;
- Exact Node 22.17.1 and pnpm 10.33.0 versions are used in CI and release builds. `pnpm audit --audit-level high`, an
  explicit frontend license allowlist, `cargo deny check`, and required (not warning-only) SBOM
  uploads gate the pipeline; and
- a final protected job verifies the client/image manifest Sigstore bundles against the exact
  `release.yml` tag identity and issuer, then binds source SHA, tag object, node evidence/ELF,
  client manifest, and image manifest into one keyless-signed release-set artifact.

### Deliberately blocked publication boundary

GHCR cannot atomically update `vX`/`latest` across three repositories, and GitHub Releases cannot
atomically publish those images together with three signed client families. A sequential promotion
can leave a partial public release if any later write fails. The checked-in workflows therefore do
not publish version/`latest` image tags or a GitHub Release. They stop at signed, run-scoped
candidates, and `deploy-production.yml` fails closed.

The missing external gate must provide a transaction (or an equivalent immutable commit/rollback
protocol invisible to consumers) across all six artifact families, accept only one verified signed
release-set manifest, publish every member, independently read the committed state back, and expose
version/`latest` only after that verification. Until that system exists and is re-audited, a
candidate is not a release and production remains NO-GO.

### Administrative controls required outside this repository

Repository code cannot prove or configure the live GitHub administration plane. Before even a
candidate run is trusted, administrators must independently evidence:

- protected `main` with the full CI job set required for merge and no direct pushes;
- a tag rule that restricts `v*` creation/deletion and requires signed annotated tags;
- required reviewers and deployment-branch restrictions on `release-candidates`,
  `release-signing-macos`, `release-signing-windows`, `release-signing-linux`, `release-approval`,
  and `production` Environments;
- least-privilege, environment-scoped signing credentials with rotation/audit policy; and
- Actions artifact retention and GHCR permissions that preserve evidence and prevent candidate
  mutation by untrusted principals.

`deploy/verify-image.sh` now requires a downloaded complete release-set directory as well as an
immutable digest and checks signed-set membership, signature, SBOM, and provenance. It deliberately
reports that the candidate is unpromoted; passing it is not production approval.

Remaining local supply-chain gaps include distribution packages installed from current Debian
repositories instead of immutable snapshots, host Xcode/Windows SDK packaging inputs that are not
hermetic, and the missing guest-image/TEE-measurement binding. This candidate workflow covers the
three desktop families only; Android/iOS distribution signing, provenance, and device execution
remain blocked with the native multi-hop/runtime work and are not implied by the desktop manifest.
