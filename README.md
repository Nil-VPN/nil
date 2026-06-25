# NIL VPN

> *"What do we have on you? Nil."*

A privacy-first VPN. **Lawful by posture, empty by design**: a US-based operator that
complies with valid legal process, but is engineered so that nothing identifying
*exists* to produce.

**Honest scope:** a VPN hides your traffic from your local network and ISP and resists
DPI fingerprinting. It is **not** anonymity — a logged-in account deanonymizes you
regardless of any VPN, and a global passive adversary watching both ends is out of
scope (that is a mixnet's job). We say so plainly, in the product and in the code.

## The four pillars
1. **Resistance-first transport cascade** — MASQUE/QUIC (RFC 9484 CONNECT-IP) is the
   primary transport: it looks like ordinary HTTPS/QUIC on UDP 443. If MASQUE is blocked,
   the cascade falls back through AmneziaWG → wstunnel → REALITY in that order. Raw
   WireGuard (the 148/92-byte handshake fingerprint) is never exposed directly; every
   transport lives behind the `Transport` trait in `nil-transport`.
2. **Verifiable trust via TEE attestation** — the client verifies a node's SEV-SNP/TDX
   report (RA-TLS) against a pinned measurement before any packet flows.
3. **Trust-split multi-hop** across legally independent operators/jurisdictions.
4. **Unlinkable payments** — Privacy Pass blind tokens (RFC 9578), issuer and verifier
   kept in separate trust domains, plus self-hosted Monero.

## Workspace map
| Crate | Plane | Role |
|---|---|---|
| `nil-core` | — | shared domain types, errors (no I/O) |
| `nil-proto` | — | wire formats / API DTOs (serde) |
| `nil-crypto` | — | account derivation; PQ PSK + RA-TLS helpers (later phases) |
| `nil-transport` | data | the `Transport` trait + pluggable impls (MASQUE/QUIC default; AmneziaWG + wstunnel cascade; loopback for dev) |
| `nil-attest` | control/user | SEV-SNP/TDX report parse + appraisal (Phase 2) |
| `nil-portal` | business | Axum REST: accounts, billing, Privacy Pass issuer |
| `nil-coordinator` | control | node registry, path selection, token *verifier* |
| `nil-node` | data | MASQUE datapath, RA-TLS, entry/middle/exit roles |
| `client/` | user | Tauri v2 desktop+mobile app (reuses the shared crates) |

## Status: single-hop attested MASQUE (closed alpha)
The default transport is a **real attested MASQUE/QUIC tunnel**: the client redeems an
unlinkable Privacy Pass token at the Coordinator, verifies each node's TEE attestation
report against the pinned measurement, and only then lets packets flow (no proof →
kill-switch holds → no traffic). This datapath is wired end to end and exercised on
Linux, macOS, and Android; the desktop and Android in-app Connect drive it directly, and
an AmneziaWG → wstunnel obfuscation cascade backs up the primary MASQUE rung.

**Honest about what's still alpha:**
- **Single-hop**, not yet trust-split — one node sees both your IP and your destination.
  Multi-hop across legally independent operators is the next milestone.
- **iOS** has the native `PacketTunnelProvider` engine in-tree but is not yet verified on
  a real device; some platform paths (e.g. the packaged iOS datapath) remain unproven.
- **Attestation caveat (TEE.Fail, Oct 2025):** an attacker with physical memory access to
  a node could forge a report. Vendor/jurisdiction diversity across hops is the mitigation;
  the single-hop alpha does not yet have it.
- With no Coordinator configured, the client falls back to an in-memory loopback transport
  (no real tunnel) so the engine/state machine can be exercised in dev — the UI says so,
  so it never reads as protection it isn't providing.
- **Automatic transport probing and cascade selection are not yet implemented.** The active
  rung is operator-configured; the client does not yet probe the network and auto-select the
  hardest-to-block transport that works.

## Build & verify
```bash
cargo build --workspace && cargo test --workspace   # green = workspace builds + tests pass
cargo deny check                                     # supply-chain gate

# anonymous signup smoke test (Business plane)
cargo run -p nil-portal &                            # http://127.0.0.1:8080
curl -s -X POST http://127.0.0.1:8080/v1/account \
  -H 'content-type: application/json' -d '{"type":"anonymous"}'
# → { "account_number": "...", "recovery_phrase": [7 words], "recovery_code": "..." }

# client
cd client && pnpm install && pnpm tauri dev
```

## License
AGPL-3.0-or-later. See [LICENSE](LICENSE).
