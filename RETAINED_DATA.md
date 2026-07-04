# What NIL stores, and why

> *"What do we have on you? Nil."* This page enumerates **every** field NIL persists, its retention,
> and why it exists. If it is not on this page, NIL does not store it. The `schema_audit` storage-audit
> tests (`nil-portal`, `nil-coordinator`) fail the build if a persisted **SQL column** drifts from this
> document; the Portal's file-backed anti-replay sets (§3) hold only opaque keys, PII-free by the
> `durable.rs` contract.

Two identity-relevant stores hold the account/token model: the accounts table (§1) and the nullifiers
table (§2). The Portal additionally keeps a handful of **opaque, PII-free** durable anti-replay sets
(§3) — random references and one-way hashes, never identity — to stop double-issue / double-spend /
double-extend across restarts. The **data plane** (`nil-node`) persists **nothing** — no disk logs, no
connection/DNS records, no source-IP retention. Rate-limiter counters are in memory and die with the
process. There is no analytics, no crash SDK, no usage telemetry.

## 1. Business plane — `nil-portal` accounts table

| Field | What it is | Retention | Why |
|---|---|---|---|
| `account_number` | `H(secret)` — a hash of the account secret; **not** an email or name | While the account exists | Authenticate the account on use. Nothing identifying is derivable from the hash. (PD-1) |
| `recovery_code_hash` | SHA-256 of the recovery code | While the account exists | Let a holder recover their account. (PD-1) |
| `entitlement` | Enum `none` / `active` / `expired`; an `active` subscription also carries its **expiry** (a unix-seconds deadline) | While the account exists | Gate token issuance to a subscribed account, and know when the subscription lapses. The expiry is tied to the anonymous account, never to a person. Carries no identity. (PD-1) |
| `auth_pubkey` | The **public** half of a per-account Ed25519 key derived from the account secret | While the account exists | Verify a signed challenge so a subscriber can mint fresh connection tokens. An anonymous per-account key — not an email, name, or device id; the secret half never leaves the client. (PD-1/PD-4) |

There is **no** email, name, signup IP, signup timestamp, payment identifier, or session/activity
field. The **only** timestamp stored in this accounts table is the subscription expiry carried inside
`entitlement` — a coarse billing deadline tied to the anonymous account, never to a person — and the
**only** key stored is the *public* `auth_pubkey` (the account proves ownership by signing with the private half,
which stays on the client). (An optional email-account flow, if ever built, would store only an
*encrypted* email — out of scope here.) Both a compile-time tripwire (`account/model.rs`) and the
runtime schema audit enforce this.

## 2. Control plane — `nil-coordinator` nullifiers table

| Field | What it is | Retention | Why |
|---|---|---|---|
| `msg` | An opaque spent-token message (a Privacy Pass token's unblinded message); **not** linkable to an account | Until its issuer epoch is retired, then bulk-deleted | Enforce one-time use of an unlinkable token (double-spend prevention). (PD-2) |
| `epoch` | Integer issuer-key epoch tag | Same as `msg` | Partition the set so a whole epoch's nullifiers drop once its issuer key is retired (a token from a retired epoch can never verify again, so the drop is fail-safe). (PD-2) |

The nullifier set is **unlinkable to identity by construction**: the Coordinator (the verifier) never
sees the account, only the anonymous token. The payment reference that ties a token to a payment
lives only in the Portal (the issuer), in a separate trust domain (PD-4).

## 3. Business plane — `nil-portal` durable anti-replay sets

To stop double-issue / double-spend / double-extend across a restart, the Portal durably records a
few **opaque, PII-free** single-use sets. They are file-backed when their `NW_*_PATH` env vars are set
(the intended production posture) and in-memory otherwise. Every entry is a random reference or a
one-way keyed hash — **never** an account, email, payment identity, or destination — so a full disk
compromise yields only a list of unlinkable opaque keys (the `durable.rs` contract).

| Set | Entry | Retention | Why |
|---|---|---|---|
| pending checkout refs (`NW_PENDING_PATH`) | opaque 256-bit checkout reference + insertion unix-seconds | until TTL-pruned | Front-running guard: only a reference the Portal actually minted can be paid/activated. The timestamp is coarse TTL metadata on an opaque value. |
| issued refs (`NW_ISSUED_PATH`) | opaque payment/checkout reference | while the record exists | One token per payment (no double-issue after a restart). |
| subscription bindings (`NW_SUB_BINDINGS_PATH`) | `H(domain‖reference‖account)` + insertion unix-seconds | until TTL-pruned | Bind a payment reference to an anonymous account so only that account can activate it. The hash reveals nothing without the unguessable reference. |
| activated subs (`NW_SUB_ACTIVATED_PATH`) | `H(domain‖reference‖account)` | while the record exists | A payment reference can extend a subscription only once (no double-extend). |
| card-revoked refs (`NW_CARD_REVOKED_PATH`; `card-payments` only) | opaque payment reference | permanent | A refunded / charged-back reference can never be re-issued. |

These are **anonymous by construction** (PD-3/PD-4): a reference indexes a payment, never a person,
and the binding/activation hashes are one-way over an unguessable reference. The two insertion
timestamps are coarse TTL-pruning metadata on opaque values, not activity records.

## 4. Everything else: nil

- **`nil-node` (data plane):** no disk logs, no connection logs, no DNS logs, no source-IP retention.
- **Rate limiters (Portal + Coordinator):** in-memory per-IP counters that reset per window and die
  with the process — never persisted, never logged (PD-2 / PD-3).
- **Logs:** operational health only; no PII at any level, enforced by the `no_pii_in_logs` test.

## Adding a persisted field

If you add a column to any store's `SCHEMA`, add it to the table above **first** — the `schema_audit`
tests assert the live DDL matches this document and reject any PII-looking column name.
