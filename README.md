# NIL VPN

> *"What do we have on you? Nil."*

NIL is an experimental privacy-first VPN. Its goal is to minimize application-controlled
persistent data and separate account/payment activity from tunnel authorization. A VPN still
**moves trust** from the local network and ISP to the VPN path; it is not anonymity and does not
defeat endpoint identification or a global observer.

> **Status: engineering alpha, not production-ready.** The code contains the security boundaries
> described below and exercises many of them in unit and synthetic integration tests. A live
> multi-operator service, real-TEE deployment, native mobile multi-hop path, and complete signed
> release-to-runtime evidence chain have not been validated.

## Design pillars and current boundary

1. **Censorship-resistant transport.** Production-profile artifacts contain the attested
   MASQUE/QUIC CONNECT-IP path. AmneziaWG, wstunnel, REALITY, automatic selection, direct-node
   mode, and loopback are development capabilities; compile guards exclude them from builds
   without debug assertions until they enforce the same grant and attestation contract.
2. **Verifiable trust.** Release clients cannot be built without an embedded bundle of accepted
   issuer keys, node measurements, and a transparency-log key. The MASQUE path appraises a fresh
   SEV-SNP/TDX report before accepting a hop. This logic is test-covered, but has not yet been
   proven against NIL's own live TEE fleet, and the guest measurement is not yet a complete binding
   to the dynamically launched `nil-node` artifact.
3. **Trust-split multi-hop.** Builds without debug assertions reject paths shorter than two hops.
   The nested path is exercised with synthetic attestation in Docker; operation across genuinely
   independent companies, jurisdictions, and hardware has not yet been demonstrated.
4. **Payment/session separation.** The Portal blind-signs Privacy Pass credentials and the
   Coordinator verifies them without receiving an account number. Subscription clients prefetch a
   small batch at a randomized time and Connect spends only a locally stored pass. Blinding blocks
   a direct cryptographic issuance-to-redemption join; timing, network metadata, a small user set,
   and external payment records can still correlate events.

## Implemented account and client model

- The client generates a standard checksummed 12-word BIP39 phrase from 128 bits of OS entropy and
  derives the account identifier and Ed25519 authentication key locally.
- Registration sends only the 32-byte account identifier, public authentication key, and a proof
  of possession. The Portal never receives or returns the phrase, and there is no server recovery
  endpoint or separate recovery code.
- The Portal account record contains only the stable account identifier, entitlement/expiry, and
  public authentication key. The identifier is pseudonymous, not proof of a real-world identity,
  but it links that account's authenticated Portal operations.
- The client stores its auth seed and bearer passes in one encrypted vault protected by Apple
  Keychain, Android Keystore, Windows DPAPI, or Linux Secret Service. The recovery phrase is not
  cached.
- Subscription refill targets eight passes, refills at or below three, waits a random 30–300
  seconds after a hint, and also wakes on a random 3–6 hour interval. One authenticated request
  carries a bounded batch (at most 16) whose messages share an hourly rounded, roughly one-day
  expiry; Connect never contacts the issuer.

## Workspace map

| Crate | Plane | Role |
|---|---|---|
| `nil-core` | shared | domain types, grants, durable primitives, and network-policy helpers |
| `nil-proto` | shared | wire/API DTOs |
| `nil-crypto` | shared | account derivation, blind tokens, PQ helpers, and transparency proofs |
| `nil-attest` | user/data | SEV-SNP/TDX evidence parsing and appraisal |
| `nil-transport` | data | transport seam; production MASQUE plus development-only alternatives |
| `nil-datapath` | user | TUN, routing, DNS, kill-switch, redemption, and multi-hop assembly |
| `nil-portal` | business | accounts, subscriptions, payment confirmation, and token issuer |
| `nil-coordinator` | control | token verifier, atomic nullifier/encrypted retry ledger, registry, grants, and path selection |
| `nil-node` | data | authorized MASQUE datapath and entry/middle/exit roles |
| `client/` | user | Tauri/React client and native platform bridges |

## Release versus development

- Release desktop code accepts only an HTTPS Coordinator path, requires a prefetched pass and
  embedded trust roots, and rejects one-hop, direct, loopback, synthetic-attestation, diagnostic,
  and alternate-fallback modes.
- The Android, iOS, and macOS network-extension engines currently support one hop. Packaged builds
  therefore refuse to connect before consuming a pass until native multi-hop is implemented.
- Debug and the reviewed `e2e` profile retain local loopback, direct/single-hop, synthetic, and
  alternate-transport harnesses. Their success is development evidence, not a production claim.

## Build and verify

```bash
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check

pnpm --dir client install --frozen-lockfile
pnpm --dir client build
pnpm --dir client test
```

Account creation is intentionally client-driven; the old bare `POST /v1/account` example is not a
valid signup flow because recovery material must never be generated by the Portal.

## Canonical documentation

- [Retained data](RETAINED_DATA.md) and [threat model](THREAT_MODEL.md) — scoped data inventory and
  adversary limits.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
