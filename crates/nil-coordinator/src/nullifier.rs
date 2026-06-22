//! The spent-token nullifier set behind a trait, so its backend is swappable like the account
//! [`crate::store`]-style seam: in-memory (dev), the file-backed [`DurableSet`] (durable,
//! single-instance), or Postgres (clustered, cross-instance) behind the `postgres` feature.
//!
//! Identity-free by construction: the key is the opaque Privacy Pass token *message* — there is
//! no account, payment, or identity in the set (Pillar 4 / PD-3). It records only "this token was
//! already redeemed".

use std::io;

use async_trait::async_trait;
use nil_core::durable::DurableSet;

/// Atomic single-use check-and-record for spent token messages.
#[async_trait]
pub trait NullifierStore: Send + Sync {
    /// Record `key` as spent. `Ok(true)` ⇒ newly recorded (first redemption); `Ok(false)` ⇒
    /// already present (double-spend); `Err` ⇒ could not be durably recorded — callers fail
    /// closed (grant nothing) rather than risk a double-spend.
    async fn insert_once(&self, key: &str) -> io::Result<bool>;
}

#[async_trait]
impl NullifierStore for DurableSet {
    async fn insert_once(&self, key: &str) -> io::Result<bool> {
        // `DurableSet::insert` is synchronous (it fsyncs before returning, so `Ok` means durably
        // recorded). Run it inline — parity with the prior direct call; the fsync is a brief
        // blocking syscall on the redeem path.
        self.insert(key)
    }
}

#[cfg(feature = "postgres")]
pub use pg::PgNullifierStore;

#[cfg(feature = "postgres")]
mod pg {
    use super::*;
    use tokio_postgres::Client;

    /// The nullifier table. Idempotent so `connect` can run it on startup. The PRIMARY KEY makes
    /// the single-use check a single atomic statement.
    pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS nullifiers (msg TEXT PRIMARY KEY)";

    /// Atomic single-use: `ON CONFLICT DO NOTHING` makes a replay a no-op (0 rows), which
    /// `insert_once` maps to `Ok(false)` — no read-then-write race, even across instances.
    const INSERT_SQL: &str = "INSERT INTO nullifiers (msg) VALUES ($1) ON CONFLICT (msg) DO NOTHING";

    /// Cluster-shared nullifier set. Unlike the single-instance file [`DurableSet`], an atomic
    /// `INSERT ... ON CONFLICT DO NOTHING` gives **cross-instance** single-use: a token redeemed
    /// at any coordinator is spent at every coordinator. Transport security (TLS to the DB) is the
    /// deployment's responsibility — `new` takes an already-connected client; `connect` is
    /// `NoTls`, for local/loopback dev only.
    ///
    /// Integration status: compiles; the live-database path is exercised in deployment (no DB
    /// image in the build sandbox), with the file `DurableSet` as the durable default until then.
    pub struct PgNullifierStore {
        client: Client,
    }

    impl PgNullifierStore {
        /// Wrap an already-connected client (production uses a **TLS**-connected client).
        pub fn new(client: Client) -> Self {
            Self { client }
        }

        /// Connect over **`NoTls`** (local/loopback dev only) and ensure the schema exists.
        pub async fn connect(conn_str: &str) -> io::Result<Self> {
            let (client, connection) = tokio_postgres::connect(conn_str, tokio_postgres::NoTls)
                .await
                .map_err(|e| io::Error::other(format!("postgres connect: {e}")))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::error!("postgres connection closed: {e}");
                }
            });
            client
                .batch_execute(SCHEMA)
                .await
                .map_err(|e| io::Error::other(format!("postgres schema: {e}")))?;
            Ok(Self::new(client))
        }
    }

    #[async_trait]
    impl NullifierStore for PgNullifierStore {
        async fn insert_once(&self, key: &str) -> io::Result<bool> {
            let affected = self
                .client
                .execute(INSERT_SQL, &[&key])
                .await
                .map_err(|e| io::Error::other(format!("postgres nullifier insert: {e}")))?;
            Ok(affected == 1) // 1 ⇒ newly recorded; 0 ⇒ ON CONFLICT (already spent)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn durable_set_insert_once_is_single_use() {
        let s = DurableSet::in_memory();
        assert!(s.insert_once("tok-a").await.unwrap(), "first insert newly records");
        assert!(!s.insert_once("tok-a").await.unwrap(), "replay is rejected");
        assert!(s.insert_once("tok-b").await.unwrap(), "a distinct token records independently");
    }
}
