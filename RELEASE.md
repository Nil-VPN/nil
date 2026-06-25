# NIL VPN — release posture

> Status: **closed alpha.** A VPN is not anonymity (see [README](README.md)). This page maps each
> architectural pillar to where it is proven and states the honest residual caveats — so the
> guarantees are checkable, not promised.

## The four pillars

### 1. Empty by design (no PII)
- Anonymous accounts store only `H(secret)` + entitlement; `nil-node` keeps no disk logs; rate
  limiters are in-memory. Proven by: the compile-time `AccountRecord` tripwire, the runtime
  `schema_audit` tests (`nil-portal` / `nil-coordinator`, run under the `postgres` CI feature), the
  `no_pii_in_logs` test, and [RETAINED_DATA.md](RETAINED_DATA.md).
- **Residual:** none known at the alpha scope; the storage audit gates any new persisted field.

### 2. Hardest-to-block transport
- Default is a real attested MASQUE/QUIC tunnel on UDP 443; an AmneziaWG → wstunnel → REALITY
  obfuscation cascade backs it up. An opt-in network-aware **selector** (`NW_SELECTOR`) probes the
  path (one identity-free QUIC reachability datagram) and orders the cascade fast-first on a clean
  network or resistant-first on a hostile one, always retaining the resistant rungs as the tail.
- **Residual (honest):** REALITY's outer TLS is a real *self-signed* session, **not** yet a
  forged-ClientHello borrow of a foreign site — an active prober can still distinguish it (the inner
  PQ-WireGuard is the security boundary regardless). Auto-selection is opt-in, not the default. UDP
  GSO/GRO fast-path acceleration is a Linux-runtime follow-up.

### 3. Verifiable trust (attestation + trust-split)
- The client verifies each node's SEV-SNP/TDX RA-TLS report against a pinned measurement before any
  packet flows — fail-closed (no proof → kill-switch holds). Multi-hop trust-split
  (entry/middle/exit across diverse operators/jurisdictions) is exercised end-to-end by the Docker
  data-plane e2e harness. A hardware-attested (`hw-attest`) build refuses the dev escape hatches: it
  cannot be built with the synthetic test-report provider, and it refuses `NW_ALLOW_UNGRANTED` or a
  missing measurement at startup.
- **Residual (honest):** **TEE.Fail (Oct 2025)** — a physical-memory attacker can forge an
  attestation report; vendor/jurisdiction diversity across hops is the mitigation, and the
  single-hop path does not have it (it warns it is not trust-split). Live hardware attestation needs
  provisioned SEV-SNP/TDX nodes (VCEK / TDX collateral, per-node measurements). Endpoint rotation and
  all-PQ-per-hop intermediate forwarding are tracked follow-ups.

### 4. Unlinkable payments
- Privacy Pass blind tokens (issuer in `nil-portal`, verifier in `nil-coordinator` — separate trust
  domains) plus self-hosted Monero. A front-running guard ties issuance to a server-minted checkout
  reference; the reference indexes a payment, never a person (PD-4).
- **Residual (honest):** a card (Merchant-of-Record) rail is a tracked follow-up and would provide
  *pseudonymity* (the MoR knows the payer), not anonymity — Monero remains the unlinkable rail. Any
  Cuba gift/redeem feature stays gated off pending a sanctions-attorney (OFAC) sign-off.

## Kill-switch
Fail-closed OS firewall default-block — Windows (WFP/NetSecurity), macOS (pf), Linux
(nftables/iptables) — armed at tunnel-up and torn down last, so a drop or crash holds. The desktop
GUI toggle bridges to it via `NW_KILLSWITCH`; mobile uses the platform VPN block-without-VPN flag.
Per-OS runtime behaviour is verified on that OS / a VM.

## Release gate
All of: `cargo build/test --workspace --locked`; `cargo clippy --workspace --all-targets -- -D
warnings`; `cargo deny check`; the feature-gated security suites (attestation accept/reject,
wstunnel round-trip, network selector, Postgres stores + storage audit, synthetic-attest datapath,
`hw-attest` compile-check); and the reproducible `nil-node` build published to a transparency log
(Rekor) — must pass before a release.
