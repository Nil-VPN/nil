# What NIL persists, and why

> This inventory covers persistence controlled by the current NIL applications. It does **not**
> claim that a reverse proxy, hosting provider, OS log service, Monero infrastructure, card
> processor, or modified deployment holds nothing else. Those systems require their own configured
> retention policy and audit. The reviewed Compose default disables Caddy HTTP access logs and
> discards Caddy operational output; that source configuration is not proof of a live edge or
> provider's behavior.

The server-side schema tests cover specific SQL columns, and the account model has a compile-time
field tripwire. File-backed replay sets and the encrypted client vault are documented separately
because SQL schema tests cannot cover them.

## 1. Business plane — `nil-portal` account records

| Field | What it is | Retention | Purpose |
|---|---|---|---|
| `account_number` | Stable 32-byte hash derived from the client-held account secret | While the account exists | Lookup key and pseudonymous account identifier |
| `entitlement` | `none`, `expired`, or `active` with a Unix-seconds expiry | While the account exists | Authorize subscription minting and show expiry |
| `auth_pubkey` | Public Ed25519 key derived independently from the recovery phrase entropy | While the account exists | Verify registration and single-use challenge signatures |

Account scheme v2 generates a checksummed 12-word BIP39 phrase on the client. The Portal never
receives or returns that phrase and stores no recovery verifier. There is no recovery code and no
server recovery endpoint. File-store migration can read an obsolete legacy `recovery_code_hash`
only to preserve the remaining record; it is not serialized again, and the Postgres migration drops
that legacy column.

The account number is not an email, name, or device identifier, and 128 bits of phrase entropy make
preimage guessing impractical. It is still a stable pseudonymous identifier: the Portal can link the
authenticated status, subscribe, activate, and batch-mint operations performed by that account.

The account record contains no email, name, signup timestamp, signup IP, payment identifier, device
identifier, connection, DNS, or destination field. The optional email request variant is an
unimplemented API stub; no email-account store exists.

Subscription activation is committed in the same durability boundary as the account entitlement:
the file backend includes an `activation_results` map in the account JSON snapshot, and Postgres
uses a `subscription_activations` table in the same transaction as the account update.

| Activation field | What it is | Retention | Purpose |
|---|---|---|---|
| `activation_key` | `SHA-256(domain || reference || account)` | Indefinite in current code | Deduplicate a confirmed subscription activation without storing the reference or an account mapping |
| `until` | Unix-seconds expiry returned by the first activation | Same as `activation_key` | Return the original result on retry without extending again |

The activation table/map deliberately has no `account_number`, plaintext payment reference, or
timestamp. The hash is still correlatable by a party that already knows both the unguessable
reference and anonymous account number.

The same account Store owns completed one-payment issuance and authenticated mint results. File
snapshots use equivalent maps; Postgres uses `one_shot_issuances`, `mint_results`, and
`mint_quotas`. Response payloads are AES-256-GCM ciphertext under a separate shared 32-byte key
loaded from the owner-only `NW_PORTAL_RESULT_KEY_FILE`. AAD binds the result kind, operation key,
request hash, and logical expiry, so rows cannot be transplanted between requests or tables.

| Result/quota field | What it is | Retention | Purpose |
|---|---|---|---|
| `issuance_key` | `SHA-256(domain || opaque checkout reference)` | Permanent spent claim in current code | Enforce one token per paid reference without storing that reference in the account Store |
| one-shot `request_hash` | Hash of the decoded blinded request | Same as `issuance_key` | Reject rebinding one payment to another blinded token |
| one-shot `result_blob` | AEAD ciphertext of the first blind signature | Until `replay_until` (at most the token validity plus epoch allowance), then logically cleared | Recover an exact response after loss without signing twice |
| `request_key` | Domain-separated hash of a random v2 request ID, or deterministic v1 account/blinded-message operation key | Until mint-result expiry | Locate an authenticated mint retry without storing the v2 request ID |
| mint `request_hash` | Hash binding canonical account plus the ordered decoded blinded batch | Same as `request_key` | Reject request-ID/body/account rebinding |
| mint `result_blob` | AEAD ciphertext of the same-order blind signatures | Until mint-result expiry, then deleted | Return an exact completed mint response |
| `quota_key` | Stable pseudonymous account-derived key, `SHA-256(domain || account_number)` | Each quota row lasts until its `window_end`, then is deleted | Share the authoritative per-account mint budget across replicas |
| `window_start`, `window_end`, `used`, `max_value` | Epoch-aligned quota window, charged token count, and configured cap | Until `window_end`, then deleted | Atomically charge only the winning first result and reject replica configuration drift |

`quota_key` is not unlinkable from the accounts table: the Portal can enumerate its stored account
numbers and derive the same value. It is intentionally a pseudonymous account-derived enforcement
key, not an anonymity boundary. Result ciphertext and quota-window cleanup runs at startup and every
five minutes. Logical clearing/deletion does not promise forensic erasure from snapshots, backups,
WAL, SSD wear-leveling, or provider replicas. A missing/wrong result key, legacy clear-result row,
or unauthentic ciphertext remains a conflict/spent marker and never authorizes replacement signing.

## 2. Business plane — durable replay and payment-reference sets

Production-profile startup requires the following stores to be durable. Debug builds may opt into
volatile integration stores; that is not a production posture.

| Set | Persisted entry | Retention | Purpose |
|---|---|---|---|
| pending checkout refs (`NW_PENDING_PATH`) | Random 256-bit reference + insertion time | Until TTL-pruned | Accept only a checkout minted by the Portal |
| legacy issued refs (`NW_ISSUED_PATH`) | Opaque payment/checkout reference | Read-only stop-the-world migration fence; current production build requires it | Keep payments consumed by pre-idempotency Portal versions fail-closed |
| subscription bindings (`NW_SUB_BINDINGS_PATH`) | `SHA-256(domain || reference || account)` + insertion time | Until TTL-pruned | Restrict activation to the account that opened it |
| legacy activated subscriptions (`NW_SUB_ACTIVATED_PATH`) | Same domain-separated binding hash | Read-only migration fence; current production build still requires it | Prevent re-extension of activations committed by older Portal versions |
| card-revoked refs (`NW_CARD_REVOKED_PATH`, optional feature) | Opaque payment reference | Indefinite in current code | Prevent refunded/charged-back reference reuse |

New activations are deduplicated by the atomic account Store described above; this version does not
append them to `NW_SUB_ACTIVATED_PATH`. Define T0 as the time the last old Portal instance stopped
and every replacement was healthy. The legacy fence becomes eligible for retirement only after T0
plus the maximum `NW_CHECKOUT_TTL_SECS` used during rollout plus 600 seconds (two prune intervals),
with no binding-prune failures. This release still requires the path; remove it only after a later
release removes that startup check.

New one-payment completions are likewise committed only to the account Store. Production startup
requires `NW_ISSUANCE_STOP_THE_WORLD_CUTOVER=1` as an operator assertion that every old Portal
instance was stopped before the new schema became authoritative. Mixed old/new versions are not a
safe rolling deployment: their independent claim mechanisms could sign the same payment twice.

These files do not contain a plaintext account-to-reference row. A reference can nevertheless be
correlated with separately observed payment, request, or account activity; “opaque” does not mean
that operational correlation is impossible.

## 3. Control plane — `nil-coordinator` nullifiers

| Field | What it is | Retention | Purpose |
|---|---|---|---|
| `msg` | Spent token's unblinded 32-byte message, encoded as text | Epoch backend: until its key epoch is retired; flat-file backend: until operator removal | Enforce one-time token use |
| `epoch` | Identifier derived from the verifying issuer public key | Same as `msg` | Partition nullifiers for key retirement |
| `replay_until` | Grant expiry in Unix seconds | Cleared with the replay ciphertext at expiry | Decide whether an ambiguous retry may receive the first result |
| `replay_blob` / file-record ciphertext | AES-256-GCM ciphertext of the exact first `PathResponse`, including grants/nonces | Until grant expiry; swept every 30 seconds while running and at startup | Return the same authorization after response loss without minting another grant set |

The ciphertext AAD binds its format version, epoch, canonical nullifier, and expiry, preventing row
swaps. Its independent raw 32-byte key is loaded from the owner-only
`NW_REDEMPTION_RESULT_KEY_FILE`; replicas sharing Postgres must share that key. A missing/wrong key,
legacy row, expired row, or unauthentic ciphertext stays permanently spent and returns no path.

The redemption DTO and ledger contain no account, payment-reference, source-IP, destination, or
traffic field. The message is still a persistent bearer-token identifier seen by the Coordinator
and must not be represented as nonexistent data. During the short replay window, compromise of
both the ledger and result key can reveal which path/grants were issued for that anonymous token.
Logical cleanup clears the database blob or atomically rewrites the file record to a spent-only
marker. It cannot promise forensic secure deletion from SSD wear-leveling, filesystem snapshots,
backups, or storage-provider replicas; those layers need independent expiry and backup policies.

## 4. User device — client persistence

The client stores credentials locally because Connect must not contact the issuer. One encrypted,
versioned vault contains:

| Value | Stored form | Purpose |
|---|---|---|
| `account_number` | 64 lowercase hex characters | Identify the Portal account during signed operations |
| `auth_seed` | 32-byte Ed25519 seed, lowercase hex | Sign Portal challenges without retaining the phrase |
| token `msg` | 32-byte versioned message, lowercase hex | Redeem and nullify one connection pass |
| token `token` | RSA blind-signature bytes, lowercase hex | Prove the pass was issued |
| pending mint | Random 32-byte request ID, anonymous account number, pinned issuer public DER, and 1–16 ordered blinded messages/token messages/blinding factors | Retry an ambiguous authenticated batch mint byte-for-byte, then atomically add its tokens |
| pending paid issue | Opaque payment reference, pinned issuer public DER, and the exact one-token blinded request/message/blinding factor | Retry an ambiguous one-payment issuance byte-for-byte rather than buying or blinding again |
| most recently completed payment-ref hash | One bounded domain-separated hash of the completed opaque payment reference | Replaced by the next completion | Recognize a retry after the token-add/pending-clear vault transaction committed but the caller did not observe success; it is not linked to a particular stored token |
| pending redemption | One `{msg, token}` pass plus a random 32-byte local reservation ID | Retry an ambiguous Coordinator response without selecting another pass; bind asynchronous tunnel completion to the exact vault entry |

On Unix, the vault ciphertext file is created with mode `0600`. Its key/protection boundary is
Apple Keychain (macOS/iOS), Android Keystore, Windows current-user DPAPI, or Linux Secret Service.
There is no plaintext credential fallback. Legacy plaintext auth/token files are unlinked only after
the encrypted vault has been written, reopened, authenticated, and compared. Destroying a vault key
does not claim forensic secure deletion from flash storage.

Pending-mint state is removed in the same encrypted-vault transaction that adds the finalized batch.
Pending-paid-issue state is likewise replaced by the finalized token and completed-reference hash
in one vault transaction. The hash is bounded to one entry and does not create a payment-to-token
row.
Pending-redemption state is removed only by a completion carrying its exact random reservation ID;
a stale native/desktop callback cannot clear a newer pass after logout, recovery, or expiry.

The 12-word recovery phrase is shown by the client and is not cached in the vault. Losing it means
there is no email or server-side reset.

A separate configuration file (mode `0600` on Unix) stores operator endpoints, a display-only
Monero address, measurement/TEE settings, the kill-switch toggle, and a debug-only direct-node host.
It stores no account secret, token, payment reference, or recovery phrase.

## 5. Transient state and operational output

- Portal and Coordinator rate limiters hold verified source-address strings in memory for a
  bounded window. Checkout creation has a separate per-source budget and an atomic
  `NW_PENDING_MAX_ENTRIES` hard cap before durable allocation. In the reviewed Compose topology,
  Caddy overwrites a transient `X-Nil-Client-IP` value from its direct socket peer; the Rust
  extractor accepts exactly one canonical address only when the application socket peer equals the
  separately pinned `NW_TRUSTED_PROXY_IP`. Missing, malformed, duplicate, direct-mode, or
  untrusted-peer headers are rejected. These addresses are neither persisted nor intentionally
  logged. NAT users share a budget, and an additional edge in front of Caddy collapses attribution
  to that edge unless a separately reviewed boundary enforces limits there; see
  `deploy/PROXY-PRIVACY.md`.
- Portal authentication challenges and payment-watcher confirmation caches are in memory.
- The checked-in public Caddyfiles have no HTTP access-log directive, and their Compose services
  use Docker's `none` logging driver. Portal, Coordinator, and wallet operational output uses a
  bounded local driver, but is not assumed anonymous. These settings do not govern external load
  balancers, DNS/ACME services, host and firewall logs, Docker events, backups, support tooling, or
  provider telemetry; a live deployment must audit those separately.
- `nil-node` has no application database or traffic-log file and does not intentionally retain DNS,
  destinations, or source IPs. Its bounded in-memory grant replay cache retains only the anonymous
  Coordinator key ID, grant nonce, and expiry until that grant expires; capacity exhaustion rejects
  new tunnels. A process restart clears the cache, so the node also rejects grants issued before
  the current process start (with a residual sub-second window from NWG2 timestamp precision). It
  emits operational events to stdout; the deployment's journald, container log driver, and proxy
  settings determine whether those events or access metadata persist.
- The client contains no third-party analytics or crash-reporting SDK in the audited tree.

## Adding persistence

Any new account/nullifier SQL column must update this document and the corresponding schema audit.
Any new file, platform credential, log field, analytics event, payment-processor field, or external
retention path also requires an explicit review even though the SQL tests cannot detect it.
