//! Postgres-backed account [`Store`] (ADR-0003) — the clustered/durable backend that slots in
//! behind the same trait as the in-memory and file stores, so multiple `nil-portal` instances can
//! share one account table. Behind the `postgres` feature (off by default) so the default build
//! pulls no database driver.
//!
//! **Still PII-minimized.** The account table persists exactly the three [`AccountRecord`] fields:
//! `H(secret)`, entitlement, and the public authentication key. Separate tables hold hashed
//! activation/issuance/mint keys, encrypted completed responses, and logical expiry/quota-window
//! values documented in `RETAINED_DATA.md`; the quota key is account-derived and therefore
//! pseudonymously joinable by the Portal. No recovery material, email, name, source IP,
//! destination, or traffic record reaches these tables. Startup migration removes the obsolete
//! recovery verifier while preserving the anonymous account record.
//!
//! **Transport security is enforced, not promised.** The account row key is `account_number =
//! H(secret)` — the *bearer credential* a client presents — so the link to the DB must never be
//! plaintext on an untrusted path. [`PgStore::connect`] uses `NoTls` and therefore **refuses any
//! non-loopback host at runtime** (mirroring `monero::validate_rpc_url`): it is for a co-located
//! (loopback / unix-socket) database only. A remote/clustered database MUST use [`PgStore::new`]
//! with an already-`rustls`-TLS-connected `tokio_postgres::Client` (e.g. via `tokio-postgres-rustls`,
//! the project's TLS standard). There is no code path that sends credentials in cleartext across a
//! network.
//!
//! **Integration status:** compiles, the row↔record mapping and the loopback guard are
//! unit-tested; the live-database query path is exercised against a real Postgres in deployment
//! (no DB image in the build sandbox), exactly as the file store is the durable default until then.

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio_postgres::Client;

use super::{
    auth_from, auth_str, decode_mint_payload, encode_mint_payload, ent_from, ent_str, hex32,
    unhex32, IssuanceCommit, IssuanceLookup, IssuanceResult, MintCommit, MintLookup, MintQuota,
    MintResult, ResultCipher, ResultKind, Store, StoreError, SubscriptionActivation,
};
use crate::account::model::AccountRecord;

/// Bound every DB round-trip: a reachable-but-stalled database (lock contention, slow failover)
/// must surface as a clean `Backend` error, not hang the request task indefinitely.
const DB_TIMEOUT: Duration = Duration::from_secs(5);

/// Refuse a `NoTls` connection to anything but a loopback / unix-socket host — credentials must
/// never cross an untrusted network in cleartext (a remote DB must use [`PgStore::new`] with a
/// TLS-connected client). Mirrors `monero::validate_rpc_url`.
pub(crate) fn ensure_loopback_for_notls(conn_str: &str) -> Result<(), StoreError> {
    let cfg: tokio_postgres::Config = conn_str
        .parse()
        .map_err(|e| StoreError::Backend(format!("invalid postgres connection string: {e}")))?;
    for host in cfg.get_hosts() {
        if let tokio_postgres::config::Host::Tcp(h) = host {
            let loopback = h == "localhost"
                || h.parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
            if !loopback {
                return Err(StoreError::Backend(format!(
                    "refusing NoTls Postgres connection to non-loopback host {h:?}: co-locate the \
                     database on loopback, or use PgStore::new(tls_client, result_key) with a \
                     rustls-TLS-connected client for a remote/clustered database"
                )));
            }
        }
        // Unix-socket (and any future local transport) hosts are local — allowed.
    }
    Ok(())
}

/// The accounts table and idempotent legacy migration. `auth_pubkey` has a `DEFAULT ''` so a table
/// created before account authentication gains the column without losing rows; such rows read as
/// an all-zero key and fail authentication closed. The obsolete `recovery_code_hash` is dropped:
/// client-generated accounts have no server-side recovery verifier, and retaining old verifiers
/// would violate the new storage contract.
pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS accounts (\
    account_number TEXT PRIMARY KEY, \
    entitlement TEXT NOT NULL, \
    auth_pubkey TEXT NOT NULL DEFAULT ''); \
    ALTER TABLE accounts ADD COLUMN IF NOT EXISTS auth_pubkey TEXT NOT NULL DEFAULT ''; \
    ALTER TABLE accounts DROP COLUMN IF EXISTS recovery_code_hash; \
    CREATE TABLE IF NOT EXISTS subscription_activations (\
        activation_key TEXT PRIMARY KEY, \
        until BIGINT NOT NULL CHECK (until >= 0)); \
    CREATE TABLE IF NOT EXISTS one_shot_issuances (\
        issuance_key TEXT PRIMARY KEY, \
        request_hash TEXT NOT NULL, \
        result_blob BYTEA, \
        replay_until BIGINT NOT NULL DEFAULT 0 CHECK (replay_until >= 0)); \
    ALTER TABLE one_shot_issuances ADD COLUMN IF NOT EXISTS result_blob BYTEA; \
    ALTER TABLE one_shot_issuances ADD COLUMN IF NOT EXISTS replay_until BIGINT NOT NULL DEFAULT 0; \
    DO $$ BEGIN \
        IF EXISTS (SELECT 1 FROM information_schema.columns \
            WHERE table_schema = current_schema() AND table_name = 'one_shot_issuances' \
              AND column_name = 'blind_sig') THEN \
            ALTER TABLE one_shot_issuances ALTER COLUMN blind_sig DROP NOT NULL; \
            UPDATE one_shot_issuances SET blind_sig = NULL WHERE blind_sig IS NOT NULL; \
        END IF; \
    END $$; \
    CREATE TABLE IF NOT EXISTS mint_results (\
        request_key TEXT PRIMARY KEY, \
        request_hash TEXT NOT NULL, \
        result_blob BYTEA, \
        expires_at BIGINT NOT NULL CHECK (expires_at >= 0)); \
    ALTER TABLE mint_results ADD COLUMN IF NOT EXISTS result_blob BYTEA; \
    DO $$ BEGIN \
        IF EXISTS (SELECT 1 FROM information_schema.columns \
            WHERE table_schema = current_schema() AND table_name = 'mint_results' \
              AND column_name = 'blind_sigs') THEN \
            ALTER TABLE mint_results ALTER COLUMN blind_sigs DROP NOT NULL; \
            UPDATE mint_results SET blind_sigs = NULL WHERE blind_sigs IS NOT NULL; \
        END IF; \
    END $$; \
    CREATE TABLE IF NOT EXISTS mint_quotas (\
        quota_key TEXT NOT NULL, \
        window_start BIGINT NOT NULL, \
        window_end BIGINT NOT NULL, \
        used BIGINT NOT NULL, \
        max_value BIGINT NOT NULL, \
        CHECK (window_start >= 0 AND window_end > window_start \
            AND used >= 0 AND max_value > 0), \
        PRIMARY KEY (quota_key, window_start)); \
    ALTER TABLE mint_quotas ADD COLUMN IF NOT EXISTS max_value BIGINT NOT NULL DEFAULT 0; \
    CREATE INDEX IF NOT EXISTS one_shot_issuances_replay_until_idx \
        ON one_shot_issuances (replay_until) WHERE result_blob IS NOT NULL; \
    CREATE INDEX IF NOT EXISTS mint_results_expires_at_idx ON mint_results (expires_at); \
    CREATE INDEX IF NOT EXISTS mint_quotas_window_end_idx ON mint_quotas (window_end)";

/// Atomic create: `ON CONFLICT DO NOTHING` makes a duplicate account number a no-op (0 rows),
/// which `insert` maps to [`StoreError::Duplicate`] — no read-then-write race.
const INSERT_SQL: &str = "INSERT INTO accounts (account_number, entitlement, auth_pubkey) \
    VALUES ($1, $2, $3) ON CONFLICT (account_number) DO NOTHING";

const GET_SQL: &str = "SELECT entitlement, auth_pubkey FROM accounts WHERE account_number = $1";

/// Atomically extend a subscription by `$3` seconds, stacking on the row's OWN current expiry:
/// `new_until = max($2, current_until) + $3`, computed and written in one statement under the
/// implicit row lock (no lost update across concurrent activations). The current expiry is parsed
/// from the `active:<secs>` encoding; `none`/`expired`/legacy bare `active` parse to 0, so
/// `max($2, 0) = now` — a fresh or lapsed subscription re-starts from now. `RETURNING` gives the
/// new value so the caller can report it. 0 rows ⇒ no such account.
const EXTEND_SUBSCRIPTION_SQL: &str = "UPDATE accounts SET entitlement = 'active:' || \
    (GREATEST($2::bigint, COALESCE(NULLIF(split_part(entitlement, ':', 2), '')::bigint, 0)) + $3::bigint)::text \
    WHERE account_number = $1 RETURNING entitlement";

/// Insert-first is important: the unique index serializes two replicas racing on the same key.
/// The loser waits for the winner's transaction, observes zero inserted rows, then reads the
/// winner's cached expiry in a fresh READ COMMITTED statement snapshot.
const CLAIM_ACTIVATION_SQL: &str = "INSERT INTO subscription_activations (activation_key, until) \
    VALUES ($1, 0) ON CONFLICT (activation_key) DO NOTHING";
const GET_ACTIVATION_SQL: &str =
    "SELECT until FROM subscription_activations WHERE activation_key = $1";
const FINISH_ACTIVATION_SQL: &str =
    "UPDATE subscription_activations SET until = $2 WHERE activation_key = $1";

const GET_ISSUANCE_SQL: &str =
    "SELECT request_hash, result_blob, replay_until FROM one_shot_issuances WHERE issuance_key = $1";
const INSERT_ISSUANCE_SQL: &str = "INSERT INTO one_shot_issuances \
    (issuance_key, request_hash, result_blob, replay_until) VALUES ($1, $2, $3, $4) \
    ON CONFLICT (issuance_key) DO NOTHING";
const PRUNE_ISSUANCE_SQL: &str = "UPDATE one_shot_issuances SET result_blob = NULL \
    WHERE replay_until <= $1 AND result_blob IS NOT NULL";

const GET_MINT_SQL: &str =
    "SELECT request_hash, result_blob, expires_at FROM mint_results WHERE request_key = $1";
const DELETE_EXPIRED_MINT_KEY_SQL: &str =
    "DELETE FROM mint_results WHERE request_key = $1 AND expires_at <= $2";
const PRUNE_MINT_SQL: &str = "DELETE FROM mint_results WHERE expires_at <= $1";
const INSERT_MINT_SQL: &str = "INSERT INTO mint_results \
    (request_key, request_hash, result_blob, expires_at) VALUES ($1, $2, $3, $4) \
    ON CONFLICT (request_key) DO UPDATE SET request_hash = EXCLUDED.request_hash, \
    result_blob = EXCLUDED.result_blob, expires_at = EXCLUDED.expires_at \
    WHERE mint_results.expires_at <= $5";
const CHARGE_MINT_QUOTA_SQL: &str = "INSERT INTO mint_quotas \
    (quota_key, window_start, window_end, used, max_value) VALUES ($1, $2, $3, $4, $5) \
    ON CONFLICT (quota_key, window_start) DO UPDATE \
    SET used = mint_quotas.used + EXCLUDED.used \
    WHERE mint_quotas.window_end = EXCLUDED.window_end \
      AND mint_quotas.max_value = EXCLUDED.max_value \
      AND mint_quotas.used <= EXCLUDED.max_value - EXCLUDED.used \
    RETURNING used";
const GET_MINT_QUOTA_SQL: &str =
    "SELECT window_end, used, max_value FROM mint_quotas WHERE quota_key = $1 AND window_start = $2";
const PRUNE_MINT_QUOTA_SQL: &str = "DELETE FROM mint_quotas WHERE window_end <= $1";

/// A Postgres-backed account store.
pub struct PgStore {
    /// `tokio_postgres::Client::transaction` needs exclusive access. One serialized client per
    /// Portal instance is sufficient; database row/unique-index locks coordinate other replicas.
    client: Mutex<Client>,
    cipher: ResultCipher,
}

impl PgStore {
    /// Wrap an already-connected client. Production uses this with a **TLS**-connected client.
    pub fn new(client: Client, result_key: [u8; 32]) -> Self {
        Self {
            client: Mutex::new(client),
            cipher: ResultCipher::new(result_key),
        }
    }

    /// Connect over **`NoTls`** to a **loopback-only** database (see the module docs) and ensure
    /// the schema exists. Refuses a non-loopback host so credentials are never sent in cleartext
    /// across a network. Spawns the connection's background driver task.
    pub async fn connect(conn_str: &str, result_key: [u8; 32]) -> Result<Self, StoreError> {
        ensure_loopback_for_notls(conn_str)?;
        let (client, connection) = tokio_postgres::connect(conn_str, tokio_postgres::NoTls)
            .await
            .map_err(|e| StoreError::Backend(format!("postgres connect: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                // Connection-level error (the socket dropped): operational, carries no user data.
                tracing::error!("postgres connection closed: {e}");
            }
        });
        client
            .batch_execute(SCHEMA)
            .await
            .map_err(|e| StoreError::Backend(format!("postgres schema: {e}")))?;
        Ok(Self::new(client, result_key))
    }

    async fn lock_client(
        &self,
        operation: &str,
    ) -> Result<tokio::sync::MutexGuard<'_, Client>, StoreError> {
        tokio::time::timeout(DB_TIMEOUT, self.client.lock())
            .await
            .map_err(|_| StoreError::Backend(format!("postgres {operation} client wait timed out")))
    }
}

/// The three text columns persisted for a record (PII-free). Free function so the encoding is
/// unit-testable without a live database.
fn columns(r: &AccountRecord) -> [String; 3] {
    [
        hex32(&r.account_number),
        ent_str(r.entitlement),
        auth_str(&r.auth_pubkey),
    ]
}

/// Rebuild a record from its persisted columns, or `None` if any column is malformed.
fn from_columns(account_hex: &str, ent: &str, auth: &str) -> Option<AccountRecord> {
    Some(AccountRecord {
        account_number: unhex32(account_hex)?,
        entitlement: ent_from(ent)?,
        auth_pubkey: auth_from(auth)?,
    })
}

fn issuance_from_row(
    row: &tokio_postgres::Row,
    cipher: &ResultCipher,
    issuance_key: &[u8; 32],
    expected_hash: &[u8; 32],
    now_secs: u64,
) -> Result<IssuanceLookup, StoreError> {
    let request_hash: String = row
        .try_get(0)
        .map_err(|e| StoreError::Backend(format!("one_shot_issuances.request_hash: {e}")))?;
    let stored_hash = unhex32(&request_hash).ok_or_else(|| {
        StoreError::Backend("one_shot_issuances.request_hash is malformed".into())
    })?;
    if &stored_hash != expected_hash {
        return Ok(IssuanceLookup::Conflict);
    }
    let replay_until: i64 = row
        .try_get(2)
        .map_err(|e| StoreError::Backend(format!("one_shot_issuances.replay_until: {e}")))?;
    let replay_until = u64::try_from(replay_until)
        .map_err(|_| StoreError::Backend("one_shot_issuances.replay_until is negative".into()))?;
    let result_blob: Option<Vec<u8>> = row
        .try_get(1)
        .map_err(|e| StoreError::Backend(format!("one_shot_issuances.result_blob: {e}")))?;
    if replay_until <= now_secs {
        return Ok(IssuanceLookup::Conflict);
    }
    let Some(result_blob) = result_blob else {
        // A scrubbed result (or a legacy cleartext row removed by the cutover migration) remains
        // a permanent spent marker. It must never become eligible for a second signature.
        return Ok(IssuanceLookup::Conflict);
    };
    let blind_sig = match cipher.open(
        ResultKind::OneShot,
        issuance_key,
        &stored_hash,
        replay_until,
        &result_blob,
    ) {
        Ok(value) if value.len() * 2 == nil_proto::token::BLIND_TOKEN_HEX_LEN => value.to_vec(),
        Ok(_) | Err(_) => return Ok(IssuanceLookup::Conflict),
    };
    Ok(IssuanceLookup::Replay { blind_sig })
}

fn mint_from_row(
    row: &tokio_postgres::Row,
    cipher: &ResultCipher,
    request_key: &[u8; 32],
    expected_hash: &[u8; 32],
    now_secs: u64,
) -> Result<MintLookup, StoreError> {
    let request_hash: String = row
        .try_get(0)
        .map_err(|e| StoreError::Backend(format!("mint_results.request_hash: {e}")))?;
    let stored_hash = unhex32(&request_hash)
        .ok_or_else(|| StoreError::Backend("mint_results.request_hash is malformed".into()))?;
    let expires_at: i64 = row
        .try_get(2)
        .map_err(|e| StoreError::Backend(format!("mint_results.expires_at: {e}")))?;
    let expires_at = u64::try_from(expires_at)
        .map_err(|_| StoreError::Backend("mint_results.expires_at is negative".into()))?;
    if expires_at <= now_secs {
        return Ok(MintLookup::Missing);
    }
    if &stored_hash != expected_hash {
        return Ok(MintLookup::Conflict);
    }
    let result_blob: Option<Vec<u8>> = row
        .try_get(1)
        .map_err(|e| StoreError::Backend(format!("mint_results.result_blob: {e}")))?;
    let Some(result_blob) = result_blob else {
        return Ok(MintLookup::Conflict);
    };
    let blind_sigs = match cipher
        .open(
            ResultKind::SubscriptionMint,
            request_key,
            &stored_hash,
            expires_at,
            &result_blob,
        )
        .and_then(|payload| decode_mint_payload(&payload))
    {
        Ok(signatures) => signatures,
        Err(_) => return Ok(MintLookup::Conflict),
    };
    Ok(MintLookup::Replay { blind_sigs })
}

#[async_trait]
impl Store for PgStore {
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError> {
        let [acct, ent, auth] = columns(&record);
        let client = self.lock_client("insert").await?;
        let affected = tokio::time::timeout(
            DB_TIMEOUT,
            client.execute(INSERT_SQL, &[&acct, &ent, &auth]),
        )
        .await
        .map_err(|_| StoreError::Backend("postgres insert timed out".into()))?
        .map_err(|e| StoreError::Backend(format!("postgres insert: {e}")))?;
        if affected == 0 {
            return Err(StoreError::Duplicate); // ON CONFLICT DO NOTHING → row already existed
        }
        Ok(())
    }

    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError> {
        let acct = hex32(account_number);
        let client = self.lock_client("get").await?;
        let row = tokio::time::timeout(DB_TIMEOUT, client.query_opt(GET_SQL, &[&acct]))
            .await
            .map_err(|_| StoreError::Backend("postgres get timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres get: {e}")))?;
        match row {
            Some(row) => {
                // try_get (not get) — a non-TEXT/NULL column must fail closed as a Backend error,
                // not panic the request task (no unwrap-like panics in non-test code).
                let ent: String = row
                    .try_get(0)
                    .map_err(|e| StoreError::Backend(format!("accounts.entitlement: {e}")))?;
                let auth: String = row
                    .try_get(1)
                    .map_err(|e| StoreError::Backend(format!("accounts.auth_pubkey: {e}")))?;
                from_columns(&acct, &ent, &auth)
                    .ok_or_else(|| StoreError::Backend("malformed row in accounts table".into()))
                    .map(Some)
            }
            None => Ok(None),
        }
    }

    async fn activate_subscription(
        &self,
        account_number: &[u8; 32],
        activation_key: &[u8; 32],
        now_secs: u64,
        by_secs: u64,
    ) -> Result<Option<SubscriptionActivation>, StoreError> {
        let acct = hex32(account_number);
        let key = hex32(activation_key);
        let now_i = i64::try_from(now_secs).unwrap_or(i64::MAX);
        let by_i = i64::try_from(by_secs).unwrap_or(i64::MAX);
        let mut client = self.lock_client("activate_subscription").await?;
        let transaction = tokio::time::timeout(DB_TIMEOUT, client.transaction())
            .await
            .map_err(|_| {
                StoreError::Backend("postgres activate_subscription begin timed out".into())
            })?
            .map_err(|e| {
                StoreError::Backend(format!("postgres activate_subscription begin: {e}"))
            })?;

        // Claim first. The unique key is the cross-replica mutex; ON CONFLICT waits for an
        // in-flight winner to commit or roll back before telling us whether this call owns it.
        let claimed = tokio::time::timeout(
            DB_TIMEOUT,
            transaction.execute(CLAIM_ACTIVATION_SQL, &[&key]),
        )
        .await
        .map_err(|_| StoreError::Backend("postgres activate_subscription claim timed out".into()))?
        .map_err(|e| StoreError::Backend(format!("postgres activate_subscription claim: {e}")))?;

        if claimed == 0 {
            let row = tokio::time::timeout(
                DB_TIMEOUT,
                transaction.query_opt(GET_ACTIVATION_SQL, &[&key]),
            )
            .await
            .map_err(|_| {
                StoreError::Backend("postgres activate_subscription replay timed out".into())
            })?
            .map_err(|e| {
                StoreError::Backend(format!("postgres activate_subscription replay: {e}"))
            })?
            .ok_or_else(|| {
                StoreError::Backend(
                    "activation conflict resolved without a persisted result".into(),
                )
            })?;
            let until_i: i64 = row
                .try_get(0)
                .map_err(|e| StoreError::Backend(format!("subscription_activations.until: {e}")))?;
            let until = u64::try_from(until_i).map_err(|_| {
                StoreError::Backend("subscription_activations.until is negative".into())
            })?;
            tokio::time::timeout(DB_TIMEOUT, transaction.commit())
                .await
                .map_err(|_| {
                    StoreError::Backend(
                        "postgres activate_subscription replay commit timed out".into(),
                    )
                })?
                .map_err(|e| {
                    StoreError::Backend(format!(
                        "postgres activate_subscription replay commit: {e}"
                    ))
                })?;
            return Ok(Some(SubscriptionActivation::Replay { until }));
        }
        if claimed != 1 {
            return Err(StoreError::Backend(format!(
                "activation claim affected {claimed} rows"
            )));
        }

        // The account UPDATE takes its row lock and computes from the latest committed
        // entitlement. Distinct activation keys racing on one account therefore stack.
        let row = tokio::time::timeout(
            DB_TIMEOUT,
            transaction.query_opt(EXTEND_SUBSCRIPTION_SQL, &[&acct, &now_i, &by_i]),
        )
        .await
        .map_err(|_| StoreError::Backend("postgres activate_subscription extend timed out".into()))?
        .map_err(|e| StoreError::Backend(format!("postgres activate_subscription extend: {e}")))?;
        let Some(row) = row else {
            tokio::time::timeout(DB_TIMEOUT, transaction.rollback())
                .await
                .map_err(|_| {
                    StoreError::Backend(
                        "postgres activate_subscription missing-account rollback timed out".into(),
                    )
                })?
                .map_err(|e| {
                    StoreError::Backend(format!(
                        "postgres activate_subscription missing-account rollback: {e}"
                    ))
                })?;
            return Ok(None);
        };
        let ent: String = row
            .try_get(0)
            .map_err(|e| StoreError::Backend(format!("accounts.entitlement (activation): {e}")))?;
        let until = ent_from(&ent)
            .and_then(|e| e.active_until(now_secs))
            .ok_or_else(|| {
                StoreError::Backend("activation produced a non-active entitlement".into())
            })?;
        let until_i = i64::try_from(until)
            .map_err(|_| StoreError::Backend("activation expiry exceeds Postgres bigint".into()))?;
        let finished = tokio::time::timeout(
            DB_TIMEOUT,
            transaction.execute(FINISH_ACTIVATION_SQL, &[&key, &until_i]),
        )
        .await
        .map_err(|_| {
            StoreError::Backend("postgres activate_subscription result write timed out".into())
        })?
        .map_err(|e| {
            StoreError::Backend(format!("postgres activate_subscription result write: {e}"))
        })?;
        if finished != 1 {
            return Err(StoreError::Backend(format!(
                "activation result write affected {finished} rows"
            )));
        }
        tokio::time::timeout(DB_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| {
                StoreError::Backend("postgres activate_subscription commit timed out".into())
            })?
            .map_err(|e| {
                StoreError::Backend(format!("postgres activate_subscription commit: {e}"))
            })?;
        Ok(Some(SubscriptionActivation::NewlyActivated { until }))
    }

    async fn lookup_issuance(
        &self,
        issuance_key: &[u8; 32],
        request_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<IssuanceLookup, StoreError> {
        let key = hex32(issuance_key);
        let client = self.lock_client("lookup_issuance").await?;
        let row = tokio::time::timeout(DB_TIMEOUT, client.query_opt(GET_ISSUANCE_SQL, &[&key]))
            .await
            .map_err(|_| StoreError::Backend("postgres lookup_issuance timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres lookup_issuance: {e}")))?;
        row.as_ref()
            .map(|row| issuance_from_row(row, &self.cipher, issuance_key, request_hash, now_secs))
            .unwrap_or(Ok(IssuanceLookup::Missing))
    }

    async fn commit_issuance(
        &self,
        issuance_key: &[u8; 32],
        result: IssuanceResult,
        now_secs: u64,
    ) -> Result<IssuanceCommit, StoreError> {
        if result.replay_until <= now_secs
            || result.blind_sig.len() * 2 != nil_proto::token::BLIND_TOKEN_HEX_LEN
        {
            return Err(StoreError::Backend(
                "refusing to persist an expired or wrong-length issuance result".into(),
            ));
        }
        let key = hex32(issuance_key);
        let request_hash = hex32(&result.request_hash);
        let result_blob = self.cipher.seal(
            ResultKind::OneShot,
            issuance_key,
            &result.request_hash,
            result.replay_until,
            &result.blind_sig,
        )?;
        let replay_until = i64::try_from(result.replay_until).map_err(|_| {
            StoreError::Backend("issuance replay bound exceeds Postgres bigint".into())
        })?;
        let client = self.lock_client("commit_issuance").await?;
        let affected = tokio::time::timeout(
            DB_TIMEOUT,
            client.execute(
                INSERT_ISSUANCE_SQL,
                &[&key, &request_hash, &result_blob, &replay_until],
            ),
        )
        .await
        .map_err(|_| StoreError::Backend("postgres commit_issuance timed out".into()))?
        .map_err(|e| StoreError::Backend(format!("postgres commit_issuance: {e}")))?;
        if affected == 1 {
            return Ok(IssuanceCommit::Stored);
        }
        if affected != 0 {
            return Err(StoreError::Backend(format!(
                "issuance insert affected {affected} rows"
            )));
        }
        let row = tokio::time::timeout(DB_TIMEOUT, client.query_one(GET_ISSUANCE_SQL, &[&key]))
            .await
            .map_err(|_| StoreError::Backend("postgres commit_issuance replay timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres commit_issuance replay: {e}")))?;
        Ok(
            match issuance_from_row(
                &row,
                &self.cipher,
                issuance_key,
                &result.request_hash,
                now_secs,
            )? {
                IssuanceLookup::Replay { blind_sig } => IssuanceCommit::Replay { blind_sig },
                IssuanceLookup::Conflict => IssuanceCommit::Conflict,
                IssuanceLookup::Missing => {
                    return Err(StoreError::Backend(
                        "issuance conflict resolved without a persisted row".into(),
                    ));
                }
            },
        )
    }

    async fn prune_issuance_results(&self, now_secs: u64) -> Result<usize, StoreError> {
        let now_i = i64::try_from(now_secs).unwrap_or(i64::MAX);
        let client = self.lock_client("prune_issuance_results").await?;
        let affected =
            tokio::time::timeout(DB_TIMEOUT, client.execute(PRUNE_ISSUANCE_SQL, &[&now_i]))
                .await
                .map_err(|_| {
                    StoreError::Backend("postgres prune_issuance_results timed out".into())
                })?
                .map_err(|e| {
                    StoreError::Backend(format!("postgres prune_issuance_results: {e}"))
                })?;
        usize::try_from(affected)
            .map_err(|_| StoreError::Backend("issuance prune count exceeds usize".into()))
    }

    async fn lookup_mint(
        &self,
        request_key: &[u8; 32],
        request_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<MintLookup, StoreError> {
        let key = hex32(request_key);
        let now_i = i64::try_from(now_secs).unwrap_or(i64::MAX);
        let client = self.lock_client("lookup_mint").await?;
        let row = tokio::time::timeout(DB_TIMEOUT, client.query_opt(GET_MINT_SQL, &[&key]))
            .await
            .map_err(|_| StoreError::Backend("postgres lookup_mint timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres lookup_mint: {e}")))?;
        let Some(row) = row else {
            return Ok(MintLookup::Missing);
        };
        let result = mint_from_row(&row, &self.cipher, request_key, request_hash, now_secs)?;
        if result == MintLookup::Missing {
            tokio::time::timeout(
                DB_TIMEOUT,
                client.execute(DELETE_EXPIRED_MINT_KEY_SQL, &[&key, &now_i]),
            )
            .await
            .map_err(|_| StoreError::Backend("postgres expired mint delete timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres expired mint delete: {e}")))?;
        }
        Ok(result)
    }

    async fn commit_mint(
        &self,
        request_key: &[u8; 32],
        result: MintResult,
        quota: MintQuota,
        now_secs: u64,
    ) -> Result<MintCommit, StoreError> {
        if result.expires_at <= now_secs {
            return Err(StoreError::Backend(
                "refusing to store an already-expired mint result".into(),
            ));
        }
        if !quota.is_well_formed(now_secs) {
            return Err(StoreError::Backend("invalid mint quota window".into()));
        }
        if quota.cost > quota.max {
            return Ok(MintCommit::QuotaExceeded);
        }
        let key = hex32(request_key);
        let request_hash = hex32(&result.request_hash);
        let payload = encode_mint_payload(&result.blind_sigs)?;
        let result_blob = self.cipher.seal(
            ResultKind::SubscriptionMint,
            request_key,
            &result.request_hash,
            result.expires_at,
            &payload,
        )?;
        let expires_i = i64::try_from(result.expires_at)
            .map_err(|_| StoreError::Backend("mint expiry exceeds Postgres bigint".into()))?;
        let now_i = i64::try_from(now_secs).unwrap_or(i64::MAX);
        let quota_key = hex32(&quota.quota_key);
        let window_start_i = i64::try_from(quota.window_start).map_err(|_| {
            StoreError::Backend("mint quota window start exceeds Postgres bigint".into())
        })?;
        let window_end_i = i64::try_from(quota.window_end).map_err(|_| {
            StoreError::Backend("mint quota window end exceeds Postgres bigint".into())
        })?;
        let cost_i = i64::from(quota.cost);
        let max_i = i64::from(quota.max);
        let mut client = self.lock_client("commit_mint").await?;
        let transaction = tokio::time::timeout(DB_TIMEOUT, client.transaction())
            .await
            .map_err(|_| StoreError::Backend("postgres commit_mint begin timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres commit_mint begin: {e}")))?;
        let affected = tokio::time::timeout(
            DB_TIMEOUT,
            transaction.execute(
                INSERT_MINT_SQL,
                &[&key, &request_hash, &result_blob, &expires_i, &now_i],
            ),
        )
        .await
        .map_err(|_| StoreError::Backend("postgres commit_mint result write timed out".into()))?
        .map_err(|e| StoreError::Backend(format!("postgres commit_mint result write: {e}")))?;
        if affected == 1 {
            let charged = tokio::time::timeout(
                DB_TIMEOUT,
                transaction.query_opt(
                    CHARGE_MINT_QUOTA_SQL,
                    &[&quota_key, &window_start_i, &window_end_i, &cost_i, &max_i],
                ),
            )
            .await
            .map_err(|_| StoreError::Backend("postgres mint quota charge timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres mint quota charge: {e}")))?;
            if charged.is_none() {
                let existing = tokio::time::timeout(
                    DB_TIMEOUT,
                    transaction.query_opt(GET_MINT_QUOTA_SQL, &[&quota_key, &window_start_i]),
                )
                .await
                .map_err(|_| StoreError::Backend("postgres mint quota inspect timed out".into()))?
                .map_err(|e| StoreError::Backend(format!("postgres mint quota inspect: {e}")))?;
                tokio::time::timeout(DB_TIMEOUT, transaction.rollback())
                    .await
                    .map_err(|_| {
                        StoreError::Backend("postgres mint quota rollback timed out".into())
                    })?
                    .map_err(|e| {
                        StoreError::Backend(format!("postgres mint quota rollback: {e}"))
                    })?;
                let Some(existing) = existing else {
                    return Err(StoreError::Backend(
                        "mint quota charge failed without a persisted quota row".into(),
                    ));
                };
                let stored_end: i64 = existing
                    .try_get(0)
                    .map_err(|e| StoreError::Backend(format!("mint_quotas.window_end: {e}")))?;
                let stored_max: i64 = existing
                    .try_get(2)
                    .map_err(|e| StoreError::Backend(format!("mint_quotas.max_value: {e}")))?;
                if stored_end != window_end_i || stored_max != max_i {
                    return Err(StoreError::Backend(
                        "mint quota window/max conflicts with persisted state".into(),
                    ));
                }
                return Ok(MintCommit::QuotaExceeded);
            }
            tokio::time::timeout(DB_TIMEOUT, transaction.commit())
                .await
                .map_err(|_| StoreError::Backend("postgres commit_mint commit timed out".into()))?
                .map_err(|e| StoreError::Backend(format!("postgres commit_mint commit: {e}")))?;
            return Ok(MintCommit::Stored);
        }
        if affected != 0 {
            return Err(StoreError::Backend(format!(
                "mint result insert affected {affected} rows"
            )));
        }
        let row = tokio::time::timeout(DB_TIMEOUT, transaction.query_one(GET_MINT_SQL, &[&key]))
            .await
            .map_err(|_| StoreError::Backend("postgres commit_mint replay timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres commit_mint replay: {e}")))?;
        let outcome = match mint_from_row(
            &row,
            &self.cipher,
            request_key,
            &result.request_hash,
            now_secs,
        )? {
            MintLookup::Replay { blind_sigs } => MintCommit::Replay { blind_sigs },
            MintLookup::Conflict => MintCommit::Conflict,
            MintLookup::Missing => {
                return Err(StoreError::Backend(
                    "mint conflict resolved without a live result".into(),
                ));
            }
        };
        tokio::time::timeout(DB_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| {
                StoreError::Backend("postgres commit_mint replay commit timed out".into())
            })?
            .map_err(|e| StoreError::Backend(format!("postgres commit_mint replay commit: {e}")))?;
        Ok(outcome)
    }

    async fn prune_mint_results(&self, now_secs: u64) -> Result<usize, StoreError> {
        let now_i = i64::try_from(now_secs).unwrap_or(i64::MAX);
        let client = self.lock_client("prune_mint_results").await?;
        let result_rows =
            tokio::time::timeout(DB_TIMEOUT, client.execute(PRUNE_MINT_SQL, &[&now_i]))
                .await
                .map_err(|_| StoreError::Backend("postgres prune_mint_results timed out".into()))?
                .map_err(|e| StoreError::Backend(format!("postgres prune_mint_results: {e}")))?;
        let quota_rows =
            tokio::time::timeout(DB_TIMEOUT, client.execute(PRUNE_MINT_QUOTA_SQL, &[&now_i]))
                .await
                .map_err(|_| StoreError::Backend("postgres prune_mint_quotas timed out".into()))?
                .map_err(|e| StoreError::Backend(format!("postgres prune_mint_quotas: {e}")))?;
        usize::try_from(result_rows.saturating_add(quota_rows))
            .map_err(|_| StoreError::Backend("mint prune count exceeds usize".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::model::Entitlement;

    #[test]
    fn columns_round_trip_through_record() {
        let rec = AccountRecord {
            account_number: [0xab; 32],
            entitlement: Entitlement::Active {
                until: 1_900_000_000,
            },
            auth_pubkey: [0x34; 32],
        };
        let [acct, ent, auth] = columns(&rec);
        assert_eq!(acct.len(), 64); // 32 bytes hex
        assert_eq!(ent, "active:1900000000");
        assert_eq!(auth.len(), 64);
        let back = from_columns(&acct, &ent, &auth).expect("round-trips");
        assert_eq!(back, rec);
    }

    #[test]
    fn legacy_row_without_auth_pubkey_reads_as_sentinel() {
        // A pre-ADR-0007 row (auth_pubkey defaulted to '') must still load, with the all-zero key.
        let back = from_columns(&"a".repeat(64), "none", "").expect("legacy row loads");
        assert_eq!(back.auth_pubkey, [0u8; 32]);
    }

    #[test]
    fn malformed_columns_rejected() {
        // Wrong-length hex and unknown entitlement both yield None (mapped to a Backend error, not
        // a silently-wrong record).
        assert!(from_columns("dead", "active", "").is_none());
        assert!(from_columns(&"a".repeat(64), "bogus", "").is_none());
        // A non-empty but malformed auth_pubkey is rejected too.
        assert!(from_columns(&"a".repeat(64), "none", "xyz").is_none());
    }

    #[test]
    fn schema_uses_encrypted_results_and_transactional_quota_rows() {
        assert!(SCHEMA.contains("result_blob BYTEA"));
        assert!(SCHEMA.contains("CREATE TABLE IF NOT EXISTS mint_quotas"));
        assert!(SCHEMA.contains("max_value BIGINT"));
        assert!(SCHEMA.contains("ALTER COLUMN blind_sig DROP NOT NULL"));
        assert!(SCHEMA.contains("SET blind_sig = NULL"));
        assert!(SCHEMA.contains("ALTER COLUMN blind_sigs DROP NOT NULL"));
        assert!(SCHEMA.contains("SET blind_sigs = NULL"));
        assert!(!SCHEMA.contains("DROP COLUMN IF EXISTS blind_sig"));
        assert!(!SCHEMA.contains("DROP COLUMN IF EXISTS blind_sigs"));
        assert!(CHARGE_MINT_QUOTA_SQL.contains("max_value = EXCLUDED.max_value"));
        assert!(CHARGE_MINT_QUOTA_SQL.contains("RETURNING used"));
    }

    #[test]
    fn notls_connect_refuses_non_loopback() {
        // Loopback / localhost / unix-socket are allowed for NoTls; a remote host is refused so
        // bearer-credential rows never cross a network in cleartext.
        assert!(ensure_loopback_for_notls("postgres://u@127.0.0.1:5432/db").is_ok());
        assert!(ensure_loopback_for_notls("postgres://u@localhost/db").is_ok());
        assert!(ensure_loopback_for_notls("host=/var/run/postgresql user=u dbname=db").is_ok());
        assert!(
            ensure_loopback_for_notls("postgres://u@db.internal:5432/db").is_err(),
            "remote refused"
        );
        assert!(
            ensure_loopback_for_notls("postgres://u@10.0.0.5/db").is_err(),
            "remote IP refused"
        );
    }
}

#[cfg(test)]
mod schema_audit {
    //! Runtime-schema PII tripwire — the storage-audit check (Epic 10). It complements the
    //! compile-time `AccountRecord` tripwire in `account/model.rs`: that guards the in-code struct,
    //! this guards the DDL that actually creates the table. The accounts table must hold ONLY the
    //! documented non-identifying columns; adding one fails this test until it is documented in
    //! `RETAINED_DATA.md` — so no persisted field goes undocumented (PD-1/PD-5).
    use super::SCHEMA;

    /// Exact columns mirrored in RETAINED_DATA.md. Keep both tables and the inventory in sync.
    const DOCUMENTED_ACCOUNT_COLUMNS: &[&str] = &["account_number", "entitlement", "auth_pubkey"];
    const DOCUMENTED_ACTIVATION_COLUMNS: &[&str] = &["activation_key", "until"];
    const DOCUMENTED_ISSUANCE_COLUMNS: &[&str] = &[
        "issuance_key",
        "request_hash",
        "result_blob",
        "replay_until",
    ];
    const DOCUMENTED_MINT_COLUMNS: &[&str] =
        &["request_key", "request_hash", "result_blob", "expires_at"];
    const DOCUMENTED_MINT_QUOTA_COLUMNS: &[&str] = &[
        "quota_key",
        "window_start",
        "window_end",
        "used",
        "max_value",
    ];

    /// Substrings that betray a personally-identifying column.
    const PII_TOKENS: &[&str] = &[
        "email",
        "ip",
        "name",
        "phone",
        "addr",
        "timestamp",
        "user_id",
        "account_id",
        "payment",
        "session",
        "identity",
        "device",
    ];

    /// Every column the SCHEMA creates on `table`: the `CREATE TABLE … ( … )` list AND any later
    /// `ALTER TABLE … ADD COLUMN [IF NOT EXISTS] <name>`. The CREATE-TABLE scan alone is blind to
    /// migration-added columns, so a column added only via ALTER would escape the tripwire — fixed
    /// by also scanning ADD COLUMN clauses.
    fn schema_columns(ddl: &str, table: &str) -> Vec<String> {
        // SQL keywords + identifiers are case-insensitive in Postgres; fold to uppercase for
        // matching and lowercase the parsed names for a stable compare against the documented
        // (lowercase) set (ASCII DDL ⇒ uppercasing preserves byte offsets). Parse PER STATEMENT
        // (split on `;`) so the result is independent of statement order and an index/constraint DDL
        // that names the table (e.g. `CREATE INDEX … ON accounts (…)`) can't be mistaken for the
        // column list. Handles `ALTER … ADD COLUMN <name>` AND bare `ALTER … ADD <name>` (COLUMN is
        // optional in Postgres), skipping constraint clauses. Assumes simple column defs (no
        // parenthesised types like `NUMERIC(10,2)`) — true for these schemas; documented so a future
        // type change updates the parser too.
        fn is_constraint(t: &str) -> bool {
            matches!(
                t,
                "CONSTRAINT" | "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | "EXCLUDE" | "COLUMN"
            )
        }
        fn push_col(cols: &mut Vec<String>, name: &str) {
            let name = name.to_ascii_lowercase();
            if !name.is_empty() && !cols.contains(&name) {
                cols.push(name);
            }
        }
        let upper = ddl.to_ascii_uppercase();
        let table = table.to_ascii_uppercase();
        let mut cols: Vec<String> = Vec::new();
        for stmt in upper.split(';') {
            let stmt = stmt.trim_start();
            if let Some(rest) = stmt.strip_prefix("CREATE TABLE") {
                // THIS table's definition: its name must precede the column-list `(`.
                let Some(open) = rest.find('(') else { continue };
                if !rest[..open].contains(&table) {
                    continue;
                }
                let close = rest[open + 1..]
                    .find(')')
                    .map(|i| open + 1 + i)
                    .unwrap_or(rest.len());
                for seg in rest[open + 1..close].split(',') {
                    if let Some(tok) = seg.split_whitespace().next() {
                        if !is_constraint(tok) {
                            push_col(&mut cols, tok);
                        }
                    }
                }
            } else if let Some(rest) = stmt.strip_prefix("ALTER TABLE") {
                let rest = rest.trim_start();
                // Only this table (its name is the first token after ALTER TABLE).
                if rest.split_whitespace().next() != Some(table.as_str()) {
                    continue;
                }
                for piece in rest.split(" ADD ").skip(1) {
                    let mut toks = piece.split_whitespace();
                    let mut tok = toks.next();
                    if tok == Some("COLUMN") {
                        tok = toks.next();
                    }
                    if tok == Some("IF") {
                        let _ = toks.next(); // NOT
                        let _ = toks.next(); // EXISTS
                        tok = toks.next();
                    }
                    if let Some(name) = tok {
                        if !is_constraint(name) {
                            push_col(&mut cols, name);
                        }
                    }
                }
            }
        }
        cols
    }

    #[test]
    fn accounts_table_has_exactly_the_documented_columns() {
        let cols = schema_columns(SCHEMA, "accounts");
        assert_eq!(
            cols, DOCUMENTED_ACCOUNT_COLUMNS,
            "accounts schema drifted — document any new/removed column in RETAINED_DATA.md and update DOCUMENTED_ACCOUNT_COLUMNS"
        );
    }

    #[test]
    fn activation_table_has_exactly_the_documented_columns() {
        let cols = schema_columns(SCHEMA, "subscription_activations");
        assert_eq!(
            cols, DOCUMENTED_ACTIVATION_COLUMNS,
            "subscription_activations schema drifted — document any new/removed column in RETAINED_DATA.md and update DOCUMENTED_ACTIVATION_COLUMNS"
        );
    }

    #[test]
    fn issuance_table_has_exactly_the_documented_columns() {
        let cols = schema_columns(SCHEMA, "one_shot_issuances");
        assert_eq!(
            cols, DOCUMENTED_ISSUANCE_COLUMNS,
            "one_shot_issuances schema drifted — document any new/removed column in RETAINED_DATA.md and update DOCUMENTED_ISSUANCE_COLUMNS"
        );
    }

    #[test]
    fn mint_result_table_has_exactly_the_documented_columns() {
        let cols = schema_columns(SCHEMA, "mint_results");
        assert_eq!(
            cols, DOCUMENTED_MINT_COLUMNS,
            "mint_results schema drifted — document any new/removed column in RETAINED_DATA.md and update DOCUMENTED_MINT_COLUMNS"
        );
    }

    #[test]
    fn mint_quota_table_has_exactly_the_documented_columns() {
        let cols = schema_columns(SCHEMA, "mint_quotas");
        assert_eq!(
            cols, DOCUMENTED_MINT_QUOTA_COLUMNS,
            "mint_quotas schema drifted — document any new/removed column in RETAINED_DATA.md and update DOCUMENTED_MINT_QUOTA_COLUMNS"
        );
    }

    #[test]
    fn accounts_schema_has_no_pii_column_names() {
        for table in [
            "accounts",
            "subscription_activations",
            "one_shot_issuances",
            "mint_results",
            "mint_quotas",
        ] {
            for col in schema_columns(SCHEMA, table) {
                for tok in PII_TOKENS {
                    assert!(
                        !col.contains(tok),
                        "column '{table}.{col}' looks like PII (matched '{tok}') — must not be persisted (PD-1)"
                    );
                }
            }
        }
    }

    #[test]
    fn accounts_schema_removes_the_legacy_recovery_verifier_idempotently() {
        let normalized = SCHEMA
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_uppercase();
        assert!(
            normalized.contains("DROP COLUMN IF EXISTS RECOVERY_CODE_HASH"),
            "startup schema must remove obsolete recovery material from legacy rows"
        );
        assert!(
            !schema_columns(SCHEMA, "accounts")
                .iter()
                .any(|c| c == "recovery_code_hash"),
            "new schemas must never create the obsolete recovery verifier"
        );
    }

    #[test]
    fn parser_catches_lowercase_and_mixed_case_add_column() {
        // Regression: SQL keywords are case-insensitive, so a column added with lowercase or
        // mixed-case DDL must still be seen by the audit (else an undocumented column would
        // silently pass `assert_eq!(cols, DOCUMENTED_COLUMNS)`).
        let ddl = "CREATE TABLE t (account_number TEXT PRIMARY KEY); \
                   alter table t add column Sneaky_Ip TEXT; \
                   ALTER TABLE t Add Column another_one INT;";
        let cols = schema_columns(ddl, "t");
        assert!(
            cols.contains(&"sneaky_ip".to_string()),
            "lowercase `add column` must parse"
        );
        assert!(
            cols.contains(&"another_one".to_string()),
            "mixed-case `Add Column` must parse"
        );
    }

    #[test]
    fn parser_catches_bare_add_without_column_keyword() {
        // Regression: Postgres `ALTER TABLE … ADD <name>` (COLUMN omitted) is valid; the audit must
        // catch it too, or a tool-generated migration could slip an undocumented column past.
        let cols = schema_columns(
            "CREATE TABLE t (account_number TEXT PRIMARY KEY); ALTER TABLE t ADD leaked_ip TEXT;",
            "t",
        );
        assert!(
            cols.contains(&"leaked_ip".to_string()),
            "bare `ADD <col>` must parse"
        );
    }

    #[test]
    fn parser_ignores_index_ddl_and_is_order_independent() {
        // Regression: a `CREATE INDEX … ON t (…)` mentions the table + a `(`, but is NOT a column
        // source; and the result must not depend on statement order.
        let cols = schema_columns(
            "CREATE INDEX t_idx ON t (entitlement); CREATE TABLE t (account_number TEXT, entitlement TEXT);",
            "t",
        );
        assert_eq!(
            cols,
            vec!["account_number".to_string(), "entitlement".to_string()]
        );
    }

    #[test]
    fn parser_does_not_count_add_constraint_as_a_column() {
        let cols = schema_columns(
            "CREATE TABLE t (account_number TEXT); ALTER TABLE t ADD CONSTRAINT pk PRIMARY KEY (account_number);",
            "t",
        );
        assert_eq!(cols, vec!["account_number".to_string()]);
    }
}
