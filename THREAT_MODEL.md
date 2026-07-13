# NIL VPN — threat model

> **Status: working engineering draft.** Limitations below are current disclosures. Affirmative
> protections describe code paths and test evidence unless this page explicitly says they were
> validated on live infrastructure. They are not an independent security or legal assurance.

A VPN moves trust from the user's local network and ISP to the VPN path. It does not make a user
anonymous. NIL's goal is to minimize what each application plane learns and persists, then make the
remaining boundaries testable.

## Adversary-by-adversary

### Local network, ISP, or Wi-Fi operator

- After a real tunnel is successfully established, the implementation routes client traffic and
  DNS through an encrypted MASQUE/QUIC path and installs platform firewall controls.
- Desktop firewall/routing setup and rollback are not yet fully transactional. A failure between
  host mutations can leave stale state, and privileged fault-injection/crash-recovery evidence is
  still required; “fail-closed” must not be inferred from the happy-path state machine alone.
- Packet sizes, timing, connection duration, and endpoint behavior remain visible. NIL does not yet
  ship an evaluated padding or timing defense, so website fingerprinting and end-to-end flow
  correlation remain possible.
- These routing/leak properties still require privileged runtime validation on every supported OS;
  compilation and synthetic tests are not equivalent to a device leak test.

### Active censor or DPI regime

- The production-profile transport is MASQUE/QUIC on UDP 443. It may share protocol traits with
  ordinary HTTP/3 traffic, but its full wire image is not proven indistinguishable from a browser or
  a large cover protocol.
- AmneziaWG, wstunnel, REALITY, and the network selector exist only in debug-assertion development
  artifacts. Their responders do not yet have production-equivalent grant and hardware-attestation
  semantics, so release builds compile them out instead of silently weakening security.
- A censor can still fingerprint, throttle, block UDP, or actively probe NIL. Guaranteed
  circumvention is not a claim.

### NIL, a compelled operator, or a malicious future operator

- Release clients accept only token issuer keys embedded at build time, preventing a Portal from
  silently introducing an unreviewed per-user key as a tagging channel. A reviewed rotation bundle
  can contain more than one accepted key, so its scope and lifetime still matter. The Portal
  blind-signs values it cannot unblind; the Coordinator sees a bearer message/signature but no
  account field.
- Blind signing prevents a direct cryptographic join between an issuance transcript and the later
  bearer credential. It does **not** make linkage information-theoretically impossible. The Portal
  sees the stable pseudonymous account during an authenticated batch mint, and timing, IP metadata,
  payment records, a small anonymity set, or modified infrastructure can correlate issuance and
  redemption. Randomized background batches reduce direct timing coupling; they do not create
  anonymity or make collusion harmless.
- Current code DTOs keep account/payment fields out of the Coordinator and node. Schema tripwires
  cover specific application stores; they do not prove that a future operator, reverse proxy,
  hosting platform, or modified binary cannot collect additional metadata.
- Multi-hop selection enforces operator/jurisdiction diversity fields in code, but deployment across
  genuinely independent operators has not been demonstrated. NIL must not represent in-code plane
  separation as independent-company non-collusion.

### Global passive adversary

Out of scope. A low-latency VPN does not defeat an observer able to watch both the client side and
the destination side and correlate timing and volume. That requires a different latency/cover-
traffic tradeoff, such as a mixnet.

### Node host, seizure, or physical hardware attacker

- Nodes hold only Coordinator Ed25519 public grant keys. `NWG2` binds a signature to the deployment
  realm, stable node ID, intended role, MASQUE transport, TEE, measurement, stable TLS-SPKI digest,
  expected predecessor IPv4, exact next-hop IPv4/UDP socket, lifetime, and nonce. A same-measurement
  clone with another TLS key cannot accept the victim's grant; a client cannot directly redeem a
  middle/exit grant from the wrong source; and an intermediate admits only its signed next hop.
  Compromise of one node does not expose a fleet-wide grant-minting secret. Compromise of the
  Coordinator signer, its configuration authority, source-address routing, or enough independent
  operators remains in scope and requires rotation/revocation procedures.
- A verified NWG2 bearer grant is accepted once per node process. Nodes retain only its anonymous
  key ID, nonce, and expiry in a bounded memory cache, fail closed at capacity, and reject grants
  issued before process start after a restart. One-second grant timestamps leave a disclosed
  sub-second same-timestamp restart residual; eliminating it requires durable anonymous replay
  state or a Coordinator-signed node boot identifier, neither of which is claimed here.
- The MASQUE client code checks the registry-pinned live TLS-SPKI digest, TEE family, vendor evidence
  chain, fresh nonce and report TLS-key binding, expected measurement, TCB status, and—when
  configured—a stapled transparency proof before accepting a hop.
- This path has unit, known-answer, and synthetic integration coverage, not a completed NIL
  production deployment on real SEV-SNP/TDX hardware. TDX appraisal now pins non-debug attributes,
  configuration/owner identities, all four RTMRs, report-body/service identity, and a clean
  `UpToDate`/no-advisory collateral result in one client-pinned SHA-384 identity. The exact measured
  boot policy, live collateral handling, and artifact-to-RTMR chain still require independent review
  and hardware validation.
- A guest-launch measurement does not currently prove that the dynamically launched container or
  `nil-node` binary is the reviewed release artifact. Until an immutable measured image or verified
  runtime digest closes that link, attestation must not be described as proof of the exact running
  application.
- TEE.Fail-class physical memory attacks weaken the meaning of an otherwise valid report. Hardware
  attestation raises the cost of some remote/software attacks; it is not a physical-adversary shield.
- The reviewed Caddyfiles disable HTTP access logging and their Compose services discard Caddy
  operational output. Portal/Coordinator/wallet operational logs are bounded but not assumed
  anonymous. `nil-node` contains no application traffic-log store, but it writes operational events
  to stdout. Journald, container runtimes, external edges, firewalls, backups, support systems, and
  infrastructure providers can still persist metadata; source configuration does not control or
  attest to those layers.

### The user's endpoints and behavior

No VPN can hide identity deliberately disclosed to a destination. Logged-in accounts, cookies,
browser/device fingerprints, malware, unencrypted application traffic, and recognizable behavior
can identify a user regardless of the tunnel.

## Verifiability status

Implemented and test-covered:

- release builds require an embedded trust-bundle v1 containing accepted issuer keys, node
  measurements, and a transparency-log public key; runtime environment values may narrow but not
  expand those roots;
- per-hop report appraisal and fail-closed measurement/transparency checks;
- production-profile compile guards for loopback, direct/single-hop paths, synthetic attestation,
  diagnostics, and alternate fallback transports;
- a nested multi-hop Docker harness using synthetic attestation.

Not yet established:

- a live multi-operator path on real TEE hardware;
- a signed mapping from reviewed source and OCI digest through the guest measurement to the exact
  running node artifact, including production generation of the stapled log proof;
- independently reproduced and transparency-logged client packages on every platform;
- packaged native mobile/system-extension multi-hop (release native clients currently refuse to
  connect before spending a pass);
- a tag publication process gated on the exact CI-tested commit and independently verified public
  signatures, SBOMs, provenance, and transparency entries.

## Operator posture

The project states that NIL is US-based, has a public named founder, and intends to comply with
valid legal process. The engineering defense is data minimization, not a promise to resist lawful
demands. See [RETAINED_DATA.md](RETAINED_DATA.md) for application-controlled persistence and
[RELEASE.md](RELEASE.md) for current release readiness.
