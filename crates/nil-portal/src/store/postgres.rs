//! Postgres-backed account [`Store`] (ADR-0003) — the clustered/durable backend that slots in
//! behind the same trait as the in-memory and file stores, so multiple `nil-portal` instances can
//! share one account table. Behind the `postgres` feature (off by default) so the default build
//! pulls no database driver.
//!
//! **Still PII-free.** It persists exactly the three non-identifying [`AccountRecord`] fields
//! (`H(secret)`, the recovery-code hash, the entitlement) as the *same* hex/string encoding the
//! file store uses (shared `super::` helpers — anti-drift). No email, name, IP, or timestamp ever
//! reaches the table; a full database compromise yields no personal identity for an anonymous
//! account.
//!
//! **Transport security is the deployment's responsibility.** [`PgStore::new`] takes an
//! already-connected `tokio_postgres::Client`, so production wires a rustls TLS connector (e.g.
//! `tokio-postgres-rustls`, matching the project's TLS standard) before handing the client over.
//! The convenience [`PgStore::connect`] uses `NoTls` and is for **local/loopback dev only** — it
//! is documented as such and must not be used across an untrusted network.
//!
//! **Integration status:** compiles and the row↔record mapping is unit-tested; the live-database
//! query path is exercised against a real Postgres in deployment (no DB image in the build
//! sandbox), exactly as the file store is the durable default until then.

use async_trait::async_trait;
use tokio_postgres::Client;

use super::{ent_from, ent_str, hex32, unhex32, Store, StoreError};
use crate::account::model::AccountRecord;

/// The accounts table. Idempotent so `connect` can run it on startup.
pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS accounts (\
    account_number TEXT PRIMARY KEY, \
    recovery_code_hash TEXT NOT NULL, \
    entitlement TEXT NOT NULL)";

/// Atomic create: `ON CONFLICT DO NOTHING` makes a duplicate account number a no-op (0 rows),
/// which `insert` maps to [`StoreError::Duplicate`] — no read-then-write race.
const INSERT_SQL: &str = "INSERT INTO accounts (account_number, recovery_code_hash, entitlement) \
    VALUES ($1, $2, $3) ON CONFLICT (account_number) DO NOTHING";

const GET_SQL: &str = "SELECT recovery_code_hash, entitlement FROM accounts WHERE account_number = $1";

/// A Postgres-backed account store.
pub struct PgStore {
    client: Client,
}

impl PgStore {
    /// Wrap an already-connected client. Production uses this with a **TLS**-connected client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Connect over **`NoTls`** (local/loopback dev only — see the module docs) and ensure the
    /// schema exists. Spawns the connection's background driver task.
    pub async fn connect(conn_str: &str) -> Result<Self, StoreError> {
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
        Ok(Self::new(client))
    }
}

/// The three text columns persisted for a record (PII-free). Free function so the encoding is
/// unit-testable without a live database.
fn columns(r: &AccountRecord) -> [String; 3] {
    [hex32(&r.account_number), hex32(&r.recovery_code_hash), ent_str(r.entitlement).to_string()]
}

/// Rebuild a record from its persisted columns, or `None` if any column is malformed.
fn from_columns(account_hex: &str, recovery_hex: &str, ent: &str) -> Option<AccountRecord> {
    Some(AccountRecord {
        account_number: unhex32(account_hex)?,
        recovery_code_hash: unhex32(recovery_hex)?,
        entitlement: ent_from(ent)?,
    })
}

#[async_trait]
impl Store for PgStore {
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError> {
        let [acct, recovery, ent] = columns(&record);
        let affected = self
            .client
            .execute(INSERT_SQL, &[&acct, &recovery, &ent])
            .await
            .map_err(|e| StoreError::Backend(format!("postgres insert: {e}")))?;
        if affected == 0 {
            return Err(StoreError::Duplicate); // ON CONFLICT DO NOTHING → row already existed
        }
        Ok(())
    }

    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError> {
        let acct = hex32(account_number);
        let row = self
            .client
            .query_opt(GET_SQL, &[&acct])
            .await
            .map_err(|e| StoreError::Backend(format!("postgres get: {e}")))?;
        match row {
            Some(row) => {
                let recovery: String = row.get(0);
                let ent: String = row.get(1);
                from_columns(&acct, &recovery, &ent)
                    .ok_or_else(|| StoreError::Backend("malformed row in accounts table".into()))
                    .map(Some)
            }
            None => Ok(None),
        }
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
            recovery_code_hash: [0x12; 32],
            entitlement: Entitlement::Active,
        };
        let [acct, recovery, ent] = columns(&rec);
        assert_eq!(acct.len(), 64); // 32 bytes hex
        assert_eq!(ent, "active");
        let back = from_columns(&acct, &recovery, &ent).expect("round-trips");
        assert_eq!(back, rec);
    }

    #[test]
    fn malformed_columns_rejected() {
        // Wrong-length hex and unknown entitlement both yield None (mapped to a Backend error, not
        // a silently-wrong record).
        assert!(from_columns("dead", &"1".repeat(64), "active").is_none());
        assert!(from_columns(&"a".repeat(64), &"b".repeat(64), "bogus").is_none());
    }
}
