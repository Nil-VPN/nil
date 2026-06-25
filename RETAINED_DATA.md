# What NIL stores, and why

> *"What do we have on you? Nil."* This page enumerates **every** field NIL persists, its retention,
> and why it exists. If it is not on this page, NIL does not store it. The storage-audit tests
> (`schema_audit` in `nil-portal` and `nil-coordinator`) fail the build if a persisted column drifts
> from this document.

NIL persists data in exactly two places. The **data plane** (`nil-node`) persists **nothing** — no
disk logs, no connection/DNS records, no source-IP retention. Rate-limiter counters are in memory
and die with the process. There is no analytics, no crash SDK, no usage telemetry.

## 1. Business plane — `nil-portal` accounts table

| Field | What it is | Retention | Why |
|---|---|---|---|
| `account_number` | `H(secret)` — a hash of the account secret; **not** an email or name | While the account exists | Authenticate the account on use. Nothing identifying is derivable from the hash. (PD-1) |
| `recovery_code_hash` | SHA-256 of the recovery code | While the account exists | Let a holder recover their account. (PD-1) |
| `entitlement` | Enum (`none` / `active` / `expired`) | While the account exists | Gate token issuance to a paid account. Carries no identity. (PD-1) |

There is **no** email, name, signup IP, signup timestamp, payment identifier, or session/activity
field. (An optional email-account flow, if ever built, would store only an *encrypted* email — out
of scope here.) Both a compile-time tripwire (`account/model.rs`) and the runtime schema audit
enforce this.

## 2. Control plane — `nil-coordinator` nullifiers table

| Field | What it is | Retention | Why |
|---|---|---|---|
| `msg` | An opaque spent-token message (a Privacy Pass token's unblinded message); **not** linkable to an account | Until its issuer epoch is retired, then bulk-deleted | Enforce one-time use of an unlinkable token (double-spend prevention). (PD-2) |
| `epoch` | Integer issuer-key epoch tag | Same as `msg` | Partition the set so a whole epoch's nullifiers drop once its issuer key is retired (a token from a retired epoch can never verify again, so the drop is fail-safe). (PD-2) |

The nullifier set is **unlinkable to identity by construction**: the Coordinator (the verifier) never
sees the account, only the anonymous token. The payment reference that ties a token to a payment
lives only in the Portal (the issuer), in a separate trust domain (PD-4).

## 3. Everything else: nil

- **`nil-node` (data plane):** no disk logs, no connection logs, no DNS logs, no source-IP retention.
- **Rate limiters (Portal + Coordinator):** in-memory per-IP counters that reset per window and die
  with the process — never persisted, never logged (PD-2 / PD-3).
- **Logs:** operational health only; no PII at any level, enforced by the `no_pii_in_logs` test.

## Adding a persisted field

If you add a column to any store's `SCHEMA`, add it to the table above **first** — the `schema_audit`
tests assert the live DDL matches this document and reject any PII-looking column name.
