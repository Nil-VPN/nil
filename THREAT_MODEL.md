# NIL VPN — Threat model (what we do and, honestly, do not defend)

> **Status: working draft.** The *limitations* below are stated plainly and are safe to rely on as
> honest disclosure. The *affirmative* protections describe design intent and current implementation;
> several are not yet live in production (see "Verifiability status") and the affirmative claims are
> pending independent security + counsel review before being represented to users as guarantees.
> This page is versioned; when a claim changes, the change is visible in git history.

A VPN **moves trust** — from your local network and ISP to NIL's egress. It does not erase trust,
and it is **not anonymity**. NIL's design goal is to minimize what any single party can be trusted
*with*, and to make that checkable rather than promised (see `RETAINED_DATA.md` for exactly what is
stored). This page is indexed by adversary so you can see exactly where the line is.

## Adversary-by-adversary

### Your local network / ISP / Wi-Fi operator (passive)
- **Defended:** the tunnel (MASQUE/QUIC on UDP 443, looking like ordinary HTTPS/QUIC) hides your
  destinations and content from the local network. DNS resolves through the tunnel.
- **Not fully defended:** traffic-analysis. Packet sizes and timing can leak information even inside
  a tunnel. Website-fingerprinting and flow-correlation attacks are effective in the literature
  (e.g. DeepCoFFEA, IEEE S&P 2022; ESPRESSO, APNet 2024). NIL does **not yet** ship a
  traffic-analysis defense (padding/timing, e.g. a DAITA/Maybenot-style layer) — this is planned,
  not present.

### An active-probing censor / DPI regime (GFW, Iran, Russia)
- **Defended (partially):** MASQUE/QUIC-on-443 is the same protocol family Apple iCloud Private
  Relay and Cloudflare WARP use, so it rides a large legitimate cover population; a cascade of
  fallback transports exists for when it's blocked. Raw WireGuard's fixed fingerprint is never
  exposed.
- **Not yet achieved / honest limits:** the REALITY fallback rung is currently a *cosmetic*
  self-signed-TLS borrow — an active prober can distinguish it; it is not yet a forged
  foreign-site handshake. The outer QUIC/TLS ClientHello is not yet matched to a specific real
  browser fingerprint (JA4-class). A determined, sophisticated censor may still detect or block
  NIL. We do not claim guaranteed circumvention.

### NIL itself (the operator) — and a compelled or malicious future operator
- **Defended, structurally:** the design splits *who-pays* from *what-flows*. Payments use blind
  Privacy Pass tokens (RFC 9578): the issuer (business plane) and verifier (control plane) share
  only a public key, and blind-signature unlinkability is **information-theoretic** — a redemption
  cannot be linked to a payment even if the two planes collude, and no future quantum computer can
  retroactively un-blind past redemptions. The data plane sees only short-lived, unlinkable grants,
  never an account (PD-3). Nodes keep **no disk logs**. See `RETAINED_DATA.md` for the complete,
  minimal list of what is persisted.
- **In-code separation vs. operator non-collusion — the honest distinction:** NIL's crate
  boundaries enforce, *in code*, that identity-linking fields and joins do not exist (checked by a
  compile-time tripwire, a runtime schema audit, and the open-source code). That is a real,
  verifiable structural guarantee. It is **not** the same as OHTTP/Apple-Private-Relay-style
  operational non-collusion between *independent companies*. **In the current alpha, NIL operates
  all planes itself (single operator).** The multi-hop trust-split across legally-independent
  operators and jurisdictions is the design target and roadmap, not a property you can assume is
  live today. The guarantees that *are* live today are the blind-token payment unlinkability and
  the no-logs data plane.
- **Anonymity-set caveat:** blind-token unlinkability is defined relative to the set of other users
  redeeming in the same window. With few users, that set is small and timing-correlatable in
  practice, even though the cryptography is sound. Unlinkability strengthens as the user base grows.

### A global passive adversary (watches the network at both ends simultaneously)
- **Out of scope — and this is a mathematical limit, not a missing feature.** Any low-latency,
  low-overhead system (which NIL is, deliberately, to be usable) provably cannot be strongly
  anonymous against an adversary observing both ends (the anonymity trilemma, IEEE S&P 2018).
  Defeating a global passive adversary is a mixnet's job — it costs seconds of added latency and
  cover traffic (e.g. Nym). NIL is a fast VPN, not a mixnet, and does not claim GPA resistance.

### A physical adversary at a node (server seizure, coercive host, hardware attack)
- **Partially defended, with an honest post-TEE.Fail correction.** NIL verifies each node's TEE
  attestation (AMD SEV-SNP / Intel TDX) against a pinned measurement before any packet flows, and
  the node keeps nothing on disk — so a seizure finds no traffic records. But as of the "TEE.Fail"
  results (Oct 2025), TEE attestation can be **forged under physical memory access**; the CPU
  vendors themselves declare physical attacks out of scope. So attestation should be understood as
  raising the cost of *remote / software-only* host compromise and proving the *integrity of the
  running code*, **not** as a shield against a physical adversary. The mitigation for the physical
  case is architectural: trust-split across independent jurisdictions + AMD/Intel vendor diversity
  (so no single seized machine, and no single TEE vendor, is load-bearing) plus the no-logs posture
  (nothing identifying exists to seize).

### The user's own behavior / endpoints
- **Not defendable by any VPN.** Logging into an identifying service (email, social, bank),
  browser and device fingerprinting, cookies, and correlating behavior deanonymize you regardless
  of the tunnel. A VPN protects the transport; it cannot protect what you tell the far end about
  yourself.

## Verifiability status ("prove, don't promise" — where the chain is and isn't complete)
- The `nil-node` build is reproducible and its measurement is published to a transparency log
  (Sigstore/Rekor); the pinned measurement the client enforces should trace to that.
- **Incomplete today (disclosed honestly):** the client currently matches a *Coordinator-pinned*
  measurement rather than fetching and checking a transparency-log inclusion proof itself at connect
  time; and full-platform **client** reproducibility + binary transparency is not established for
  desktop (Tauri) and iOS (Android is reproducible). A targeted malicious client build is therefore
  the largest residual transparency gap. These are tracked as work, not claimed as done.
- **Attestation has not yet run against real TEE hardware in production** — the CI/e2e path uses a
  synthetic attestation report standing in for the hardware vendor chain (the vendor-root
  verification logic itself is unit-tested). Treat every attestation-dependent protection above as
  "as designed / to be verified live," not "proven in production," until that is stated otherwise.

## Operator posture
NIL is US-based with a public, named founder (Alejandro Conde) and complies with valid legal
process — the defense is that there is nothing identifying to produce, not that we resist lawful
demands. We do not pretend to be a faceless offshore entity.

---
*See also: `RETAINED_DATA.md` (every field NIL persists). Honesty about limits is part of the
product, not a footnote.*
