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
1. **MASQUE/QUIC default transport** (RFC 9484 CONNECT-IP) — looks like ordinary
   HTTPS/QUIC on UDP 443; never raw WireGuard. Everything sits behind the `Transport`
   trait in `nil-transport`.
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
| `nil-transport` | data | the `Transport` trait + pluggable impls (loopback today) |
| `nil-attest` | control/user | SEV-SNP/TDX report parse + appraisal (Phase 2) |
| `nil-portal` | business | Axum REST: accounts, billing, Privacy Pass issuer |
| `nil-coordinator` | control | node registry, path selection, token *verifier* |
| `nil-node` | data | MASQUE datapath, RA-TLS, entry/middle/exit roles |
| `client/` | user | Tauri v2 desktop+mobile app (reuses the shared crates) |

## Status: Phase 0 (buildable skeleton)
Everything compiles; `nil-transport` ships the trait + a loopback echo impl; `nil-portal`
implements the no-email anonymous account flow; Coordinator/Node start; the Tauri client
launches with a first-run screen and a mocked connect/disconnect state machine over
loopback. No real tunnel yet — that is Phase 1 (MASQUE via `quiche`).

## Build & verify
```bash
cargo build --workspace && cargo test --workspace   # green = skeleton intact
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
