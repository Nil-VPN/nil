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
    use std::time::Duration;

    use super::*;
    use tokio_postgres::Client;

    /// The nullifier table. Idempotent so `connect` can run it on startup. The PRIMARY KEY makes
    /// the single-use check a single atomic statement.
    pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS nullifiers (msg TEXT PRIMARY KEY)";

    /// Atomic single-use: `ON CONFLICT DO NOTHING` makes a replay a no-op (0 rows), which
    /// `insert_once` maps to `Ok(false)` — no read-then-write race, even across instances.
    const INSERT_SQL: &str = "INSERT INTO nullifiers (msg) VALUES ($1) ON CONFLICT (msg) DO NOTHING";

    /// Bound the single-use check (it sits on the hot redeem path): a stalled DB must surface as a
    /// clean error → `RedeemError::Unavailable` (503), never hang the redeem request indefinitely.
    const DB_TIMEOUT: Duration = Duration::from_secs(2);

    /// Refuse a `NoTls` connection to a non-loopback host (mirrors `monero::validate_rpc_url` and
    /// the account store's guard). The nullifier rows are Privacy Pass token messages; a remote
    /// clustered DB MUST use [`PgNullifierStore::new`] with a TLS-connected client.
    pub(super) fn ensure_loopback_for_notls(conn_str: &str) -> io::Result<()> {
        let cfg: tokio_postgres::Config = conn_str
            .parse()
            .map_err(|e| io::Error::other(format!("invalid postgres connection string: {e}")))?;
        for host in cfg.get_hosts() {
            if let tokio_postgres::config::Host::Tcp(h) = host {
                let loopback = h == "localhost"
                    || h.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false);
                if !loopback {
                    return Err(io::Error::other(format!(
                        "refusing NoTls Postgres connection to non-loopback host {h:?}: co-locate \
                         the database on loopback, or use PgNullifierStore::new(client) with a \
                         rustls-TLS-connected client for a remote/clustered database"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Cluster-shared nullifier set. Unlike the single-instance file [`DurableSet`], an atomic
    /// `INSERT ... ON CONFLICT DO NOTHING` gives **cross-instance** single-use: a token redeemed
    /// at any coordinator is spent at every coordinator.
    ///
    /// **Transport security is enforced, not promised.** The rows are Privacy Pass token messages,
    /// so the DB link must never be plaintext on an untrusted path: [`PgNullifierStore::connect`]
    /// uses `NoTls` and **refuses any non-loopback host at runtime**. A remote/clustered DB MUST
    /// use [`PgNullifierStore::new`] with a `rustls`-TLS-connected client.
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

        /// Connect over **`NoTls`** to a **loopback-only** database and ensure the schema exists.
        /// Refuses a non-loopback host so token messages are never sent in cleartext over a network.
        pub async fn connect(conn_str: &str) -> io::Result<Self> {
            ensure_loopback_for_notls(conn_str)?;
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
            let affected = tokio::time::timeout(DB_TIMEOUT, self.client.execute(INSERT_SQL, &[&key]))
                .await
                .map_err(|_| io::Error::other("postgres nullifier insert timed out"))?
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

    #[cfg(feature = "postgres")]
    #[test]
    fn notls_connect_refuses_non_loopback() {
        use super::pg::ensure_loopback_for_notls;
        assert!(ensure_loopback_for_notls("postgres://u@127.0.0.1:5432/db").is_ok());
        assert!(ensure_loopback_for_notls("postgres://u@localhost/db").is_ok());
        assert!(ensure_loopback_for_notls("postgres://u@coord-db.internal/db").is_err(), "remote refused");
        assert!(ensure_loopback_for_notls("postgres://u@10.0.0.5/db").is_err(), "remote IP refused");
    }
}
