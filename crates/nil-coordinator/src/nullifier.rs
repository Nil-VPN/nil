//! The spent-token nullifier set behind a trait, so its backend is swappable like the account
//! [`crate::store`]-style seam: in-memory (dev), the file-backed [`DurableSet`] (durable,
//! single-instance), or Postgres (clustered, cross-instance) behind the `postgres` feature.
//!
//! Identity-free by construction: the key is the opaque Privacy Pass token *message* — there is
//! no account, payment, or identity in the set (Pillar 4 / PD-3). It records only "this token was
//! already redeemed".
//!
//! **Bounded by epoch (fail-closed).** Tokens now carry an epoch via their *signing key* (the
//! nil-crypto multi-key [`Verifier`](nil_crypto::Verifier) holds one key per issuer key-generation).
//! The set is partitioned by the epoch that verified each token, and a retired epoch's partition is
//! dropped wholesale via [`NullifierStore::drop_epochs`]. This is the ONLY eviction primitive —
//! there is NO age- or size-based trimming. It is SAFE because a token whose epoch key is retired no
//! longer verifies (it is rejected at redeem BEFORE it can touch the set), so a dropped nullifier
//! can never be re-inserted — a partition is dropped only after its key is already gone. See
//! `redeem_logic` for the verify-then-record ordering and the single-use invariant + proof. The
//! size-threshold WARN ([`should_warn`]) stays **operational alerting only** — it never trims.

use std::collections::BTreeSet;
use std::io;

use async_trait::async_trait;
use nil_core::durable::{DurableSet, EpochDurableSet};

/// Atomic single-use check-and-record for spent token messages, partitioned by issuer epoch.
///
/// Eviction is **only** by retired epoch ([`drop_epochs`](NullifierStore::drop_epochs)) — never by
/// age or size. A spent token stays spent for as long as its epoch key is still accepted; once that
/// key is retired the token no longer verifies, so dropping its partition cannot reopen a
/// double-spend. [`approx_len`](NullifierStore::approx_len) is for operational visibility, not
/// eviction.
#[async_trait]
pub trait NullifierStore: Send + Sync {
    /// Record `key` as spent under `epoch` (the issuer epoch whose key verified the token).
    /// `Ok(true)` ⇒ newly recorded (first redemption); `Ok(false)` ⇒ already present
    /// (double-spend); `Err` ⇒ could not be durably recorded — callers fail closed (grant nothing)
    /// rather than risk a double-spend.
    async fn insert_once_in_epoch(&self, epoch: u32, key: &str) -> io::Result<bool>;

    /// Drop every partition whose epoch is NOT in `retained`, returning the number of entries
    /// removed. The default is a no-op (`Ok(0)`) for non-partitioned backends (in-memory / a single
    /// legacy file) — those simply never GC, which is safe (more retention is always safe). The
    /// caller MUST pass the set of epochs the verifier still accepts; a partition is dropped only
    /// after its key is retired, so its tokens are already unverifiable.
    async fn drop_epochs(&self, _retained: &BTreeSet<u32>) -> io::Result<usize> {
        Ok(0)
    }

    /// Whether this backend actually evicts by epoch (a real [`drop_epochs`](Self::drop_epochs), not
    /// the no-op default). The flat single-file / in-memory store returns `false` — it never GCs
    /// (safe: it over-retains forever), so the Coordinator can warn an operator that rotating issuer
    /// keys will NOT shrink the spent-token set unless they use the epoch-partitioned backend.
    fn supports_epoch_gc(&self) -> bool {
        false
    }

    /// Approximate number of recorded (spent) entries, for operational visibility only — never to
    /// drive eviction. `None` (the default) means the backend does not cheaply expose a size; a
    /// backend MUST NOT run an expensive count on the hot redeem path just to answer this.
    async fn approx_len(&self) -> Option<usize> {
        None
    }
}

/// A single flat (non-partitioned) store — dev/in-memory and the legacy single-file
/// `NW_NULLIFIER_PATH`. It ignores the epoch (one partition) and never GCs (`drop_epochs` is the
/// trait default no-op). Correct for a single-key deployment that never rotates; use
/// [`EpochDurableSet`] (a directory/epoch-tagged file) to get bounded-by-epoch GC.
#[async_trait]
impl NullifierStore for DurableSet {
    async fn insert_once_in_epoch(&self, _epoch: u32, key: &str) -> io::Result<bool> {
        // `DurableSet::insert` is synchronous (it fsyncs before returning, so `Ok` means durably
        // recorded). Run it inline — the fsync is a brief blocking syscall on the redeem path.
        self.insert(key)
    }

    async fn approx_len(&self) -> Option<usize> {
        // The in-memory index size is O(1) to read — cheap enough for the redeem path.
        Some(self.len())
    }
}

/// The epoch-partitioned durable store: records each nullifier under its verifying epoch and drops
/// a retired epoch's partition wholesale, keeping the set bounded by epoch (not monotonic).
#[async_trait]
impl NullifierStore for EpochDurableSet {
    async fn insert_once_in_epoch(&self, epoch: u32, key: &str) -> io::Result<bool> {
        self.insert_in_epoch(epoch, key)
    }

    async fn drop_epochs(&self, retained: &BTreeSet<u32>) -> io::Result<usize> {
        self.drop_epochs(retained)
    }

    async fn approx_len(&self) -> Option<usize> {
        Some(self.len())
    }

    fn supports_epoch_gc(&self) -> bool {
        true
    }
}

/// Whether crossing `n` recorded entries should fire the soft size WARN. True only on the exact
/// crossing (`n == threshold`) so the alert fires **once**, not on every subsequent redeem; a
/// zero threshold disables it. Pure decision split out so it is unit-tested without I/O.
pub fn should_warn(n: usize, threshold: usize) -> bool {
    threshold != 0 && n == threshold
}

#[cfg(feature = "postgres")]
pub use pg::PgNullifierStore;

#[cfg(feature = "postgres")]
mod pg {
    use std::time::Duration;

    use super::*;
    use tokio_postgres::Client;

    /// The nullifier table. Idempotent so `connect` can run it on startup. `msg` stays the PRIMARY
    /// KEY (a token message is globally unique, so it is the dedup key); `epoch` is an added column
    /// used ONLY for partition GC. The `ALTER ... ADD COLUMN IF NOT EXISTS` migrates an old table
    /// (pre-epoch rows default to epoch 0, matching the file store's legacy migration); the index
    /// makes `drop_epochs` a cheap single statement.
    pub const SCHEMA: &str = "\
        CREATE TABLE IF NOT EXISTS nullifiers (msg TEXT PRIMARY KEY, epoch INT NOT NULL DEFAULT 0); \
        ALTER TABLE nullifiers ADD COLUMN IF NOT EXISTS epoch INT NOT NULL DEFAULT 0; \
        CREATE INDEX IF NOT EXISTS nullifiers_epoch_idx ON nullifiers (epoch)";

    /// Atomic single-use: `ON CONFLICT DO NOTHING` makes a replay a no-op (0 rows), which
    /// `insert_once_in_epoch` maps to `Ok(false)` — no read-then-write race, even across instances.
    const INSERT_SQL: &str =
        "INSERT INTO nullifiers (msg, epoch) VALUES ($1, $2) ON CONFLICT (msg) DO NOTHING";

    /// Drop every partition whose epoch is NOT retained: a single indexed statement. The current
    /// epoch is always in `retained`, so this never contends with hot inserts.
    const DROP_SQL: &str = "DELETE FROM nullifiers WHERE epoch <> ALL($1)";

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
        async fn insert_once_in_epoch(&self, epoch: u32, key: &str) -> io::Result<bool> {
            let epoch = epoch as i32;
            let affected =
                tokio::time::timeout(DB_TIMEOUT, self.client.execute(INSERT_SQL, &[&key, &epoch]))
                    .await
                    .map_err(|_| io::Error::other("postgres nullifier insert timed out"))?
                    .map_err(|e| io::Error::other(format!("postgres nullifier insert: {e}")))?;
            Ok(affected == 1) // 1 ⇒ newly recorded; 0 ⇒ ON CONFLICT (already spent)
        }

        async fn drop_epochs(&self, retained: &BTreeSet<u32>) -> io::Result<usize> {
            if retained.is_empty() {
                // Defensive: `epoch <> ALL('{}')` is TRUE for every row and would wipe the table.
                // The verifier always holds >=1 epoch, so this is unreachable — refuse rather than nuke.
                return Ok(0);
            }
            let epochs: Vec<i32> = retained.iter().map(|e| *e as i32).collect();
            let affected = tokio::time::timeout(DB_TIMEOUT, self.client.execute(DROP_SQL, &[&epochs]))
                .await
                .map_err(|_| io::Error::other("postgres nullifier drop_epochs timed out"))?
                .map_err(|e| io::Error::other(format!("postgres nullifier drop_epochs: {e}")))?;
            Ok(affected as usize)
        }

        fn supports_epoch_gc(&self) -> bool {
            true
        }
    }

    #[cfg(test)]
    mod schema_audit {
        //! Runtime-schema PII tripwire — the storage-audit check (Epic 10). The nullifiers table
        //! holds ONLY an opaque token message + an epoch partition tag; both are non-identifying.
        //! Adding a column fails this test until it is documented in `RETAINED_DATA.md` (PD-2/PD-5).
        use super::SCHEMA;

        const DOCUMENTED_COLUMNS: &[&str] = &["msg", "epoch"];
        const PII_TOKENS: &[&str] = &[
            "email", "ip", "name", "phone", "addr", "timestamp", "user_id", "account_id",
            "payment", "session", "identity", "device",
        ];

        // Every column the SCHEMA creates: the CREATE TABLE list AND any later `ALTER TABLE …
        // ADD COLUMN [IF NOT EXISTS] <name>`. The nullifier SCHEMA migrates `epoch` in via ALTER, so
        // a CREATE-only scan would be blind to migration-added columns — scan ADD COLUMN too.
        fn schema_columns(ddl: &str, table: &str) -> Vec<String> {
            // SQL keywords + identifiers are case-insensitive in Postgres; fold to uppercase for
            // matching and lowercase the parsed names for a stable compare against the documented
            // (lowercase) set (ASCII DDL ⇒ uppercasing preserves byte offsets). Parse PER STATEMENT
            // (split on `;`) so the result is independent of statement order and an index/constraint
            // DDL that names the table (e.g. `CREATE INDEX … ON nullifiers (epoch)`) can't be
            // mistaken for the column list. Handles `ALTER … ADD COLUMN <name>` AND bare
            // `ALTER … ADD <name>` (COLUMN is optional in Postgres), skipping constraint clauses.
            // Assumes simple column defs (no parenthesised types like `NUMERIC(10,2)`) — true for
            // these schemas; documented so a future type change updates the parser too.
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
                    let close = rest[open + 1..].find(')').map(|i| open + 1 + i).unwrap_or(rest.len());
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
        fn nullifiers_table_has_exactly_the_documented_columns() {
            // CREATE TABLE columns + the ALTER-migrated `epoch` (deduped); the later `nullifiers (`
            // in the index DDL is not a column source.
            let cols = schema_columns(SCHEMA, "nullifiers");
            assert_eq!(
                cols, DOCUMENTED_COLUMNS,
                "nullifiers schema drifted — document any new/removed column in RETAINED_DATA.md"
            );
        }

        #[test]
        fn nullifiers_schema_has_no_pii_column_names() {
            for col in schema_columns(SCHEMA, "nullifiers") {
                for tok in PII_TOKENS {
                    assert!(
                        !col.contains(tok),
                        "column '{col}' looks like PII (matched '{tok}') — must not be persisted"
                    );
                }
            }
        }

        #[test]
        fn parser_catches_lowercase_and_mixed_case_add_column() {
            // Regression: SQL keywords are case-insensitive, so a column added with lowercase or
            // mixed-case DDL must still be seen by the audit (else an undocumented column would
            // silently pass `assert_eq!(cols, DOCUMENTED_COLUMNS)`).
            let ddl = "CREATE TABLE t (msg TEXT PRIMARY KEY); \
                       alter table t add column Sneaky_Ip TEXT; \
                       ALTER TABLE t Add Column another_one INT;";
            let cols = schema_columns(ddl, "t");
            assert!(cols.contains(&"sneaky_ip".to_string()), "lowercase `add column` must parse");
            assert!(cols.contains(&"another_one".to_string()), "mixed-case `Add Column` must parse");
        }

        #[test]
        fn parser_catches_bare_add_without_column_keyword() {
            // Regression: Postgres `ALTER TABLE … ADD <name>` (COLUMN omitted) is valid; the audit
            // must catch it too, or a tool-generated migration could slip an undocumented column past.
            let cols = schema_columns(
                "CREATE TABLE t (msg TEXT PRIMARY KEY); ALTER TABLE t ADD leaked_ip TEXT;",
                "t",
            );
            assert!(cols.contains(&"leaked_ip".to_string()), "bare `ADD <col>` must parse");
        }

        #[test]
        fn parser_ignores_index_ddl_and_is_order_independent() {
            // Regression: a `CREATE INDEX … ON t (epoch)` mentions the table + a `(`, but is NOT a
            // column source; and the result must not depend on statement order. With the index
            // listed FIRST, the parser must still return the CREATE TABLE columns, not `[epoch]`.
            let cols = schema_columns(
                "CREATE INDEX t_idx ON t (epoch); CREATE TABLE t (msg TEXT PRIMARY KEY, epoch INT);",
                "t",
            );
            assert_eq!(cols, vec!["msg".to_string(), "epoch".to_string()]);
        }

        #[test]
        fn parser_does_not_count_add_constraint_as_a_column() {
            // `ALTER TABLE … ADD CONSTRAINT/PRIMARY/UNIQUE …` is not a column — it must not inflate
            // the column set (which would mask a real drift or trip a false positive).
            let cols = schema_columns(
                "CREATE TABLE t (msg TEXT); ALTER TABLE t ADD CONSTRAINT pk PRIMARY KEY (msg);",
                "t",
            );
            assert_eq!(cols, vec!["msg".to_string()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn durable_set_insert_once_is_single_use() {
        let s = DurableSet::in_memory();
        assert!(s.insert_once_in_epoch(0, "tok-a").await.unwrap(), "first insert newly records");
        assert!(!s.insert_once_in_epoch(0, "tok-a").await.unwrap(), "replay is rejected");
        assert!(s.insert_once_in_epoch(0, "tok-b").await.unwrap(), "a distinct token records independently");
        // A non-partitioned store never GCs — drop_epochs is the trait default no-op.
        assert_eq!(s.drop_epochs(&BTreeSet::from([0])).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn epoch_store_partitions_and_gcs_by_epoch() {
        // Exercise via the trait object (EpochDurableSet has an inherent sync `drop_epochs` that
        // would otherwise shadow the async trait method on the concrete type).
        let store: &dyn NullifierStore = &EpochDurableSet::in_memory();
        assert!(store.insert_once_in_epoch(7, "tok-old").await.unwrap());
        assert!(store.insert_once_in_epoch(8, "tok-new").await.unwrap());
        assert!(!store.insert_once_in_epoch(7, "tok-old").await.unwrap(), "replay rejected within epoch");
        assert_eq!(store.approx_len().await, Some(2));
        // Retire epoch 7: its partition is dropped; epoch 8 survives. (At redeem, a retired-epoch
        // token would already fail verify_with_epoch, so it can never re-enter — see redeem_logic.)
        assert_eq!(store.drop_epochs(&BTreeSet::from([8])).await.unwrap(), 1);
        assert_eq!(store.approx_len().await, Some(1));
        assert!(!store.insert_once_in_epoch(8, "tok-new").await.unwrap(), "epoch-8 entry intact");
    }

    #[test]
    fn should_warn_fires_once_on_the_crossing() {
        let threshold = 1_000_000;
        assert!(!should_warn(threshold - 1, threshold), "below threshold: silent");
        assert!(should_warn(threshold, threshold), "exactly at threshold: fire once");
        assert!(
            !should_warn(threshold + 1, threshold),
            "past threshold: do not re-fire (it fires only on the exact crossing)"
        );
        assert!(!should_warn(0, threshold), "empty set: silent");
        assert!(!should_warn(0, 0), "zero threshold disables the alert");
    }

    /// A mock store that records nothing and inherits every default — used to confirm the
    /// `approx_len` default is `None` (a backend with no cheap size opts out, not in).
    struct OpaqueStore;

    #[async_trait]
    impl NullifierStore for OpaqueStore {
        async fn insert_once_in_epoch(&self, _epoch: u32, _key: &str) -> io::Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn approx_len_defaults_to_none() {
        assert_eq!(OpaqueStore.approx_len().await, None, "the trait default is None");
    }

    #[tokio::test]
    async fn durable_set_reports_its_size() {
        let s = DurableSet::in_memory();
        assert_eq!(s.approx_len().await, Some(0));
        let _ = s.insert_once_in_epoch(0, "tok-a").await.unwrap();
        assert_eq!(s.approx_len().await, Some(1), "DurableSet exposes a cheap size");
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
