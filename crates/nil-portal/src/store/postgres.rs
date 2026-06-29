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
use tokio_postgres::Client;

use super::{ent_from, ent_str, hex32, unhex32, Store, StoreError};
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
                || h.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false);
            if !loopback {
                return Err(StoreError::Backend(format!(
                    "refusing NoTls Postgres connection to non-loopback host {h:?}: co-locate the \
                     database on loopback, or use PgStore::new(client) with a rustls-TLS-connected \
                     client for a remote/clustered database"
                )));
            }
        }
        // Unix-socket (and any future local transport) hosts are local — allowed.
    }
    Ok(())
}

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

    /// Connect over **`NoTls`** to a **loopback-only** database (see the module docs) and ensure
    /// the schema exists. Refuses a non-loopback host so credentials are never sent in cleartext
    /// across a network. Spawns the connection's background driver task.
    pub async fn connect(conn_str: &str) -> Result<Self, StoreError> {
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
        Ok(Self::new(client))
    }
}

/// The three text columns persisted for a record (PII-free). Free function so the encoding is
/// unit-testable without a live database.
fn columns(r: &AccountRecord) -> [String; 3] {
    [hex32(&r.account_number), hex32(&r.recovery_code_hash), ent_str(r.entitlement)]
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
        let affected = tokio::time::timeout(DB_TIMEOUT, self.client.execute(INSERT_SQL, &[&acct, &recovery, &ent]))
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
        let row = tokio::time::timeout(DB_TIMEOUT, self.client.query_opt(GET_SQL, &[&acct]))
            .await
            .map_err(|_| StoreError::Backend("postgres get timed out".into()))?
            .map_err(|e| StoreError::Backend(format!("postgres get: {e}")))?;
        match row {
            Some(row) => {
                // try_get (not get) — a non-TEXT/NULL column must fail closed as a Backend error,
                // not panic the request task (no unwrap-like panics in non-test code).
                let recovery: String = row
                    .try_get(0)
                    .map_err(|e| StoreError::Backend(format!("accounts.recovery_code_hash: {e}")))?;
                let ent: String = row
                    .try_get(1)
                    .map_err(|e| StoreError::Backend(format!("accounts.entitlement: {e}")))?;
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
            entitlement: Entitlement::Active { until: 1_900_000_000 },
        };
        let [acct, recovery, ent] = columns(&rec);
        assert_eq!(acct.len(), 64); // 32 bytes hex
        assert_eq!(ent, "active:1900000000");
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

    #[test]
    fn notls_connect_refuses_non_loopback() {
        // Loopback / localhost / unix-socket are allowed for NoTls; a remote host is refused so
        // bearer-credential rows never cross a network in cleartext.
        assert!(ensure_loopback_for_notls("postgres://u@127.0.0.1:5432/db").is_ok());
        assert!(ensure_loopback_for_notls("postgres://u@localhost/db").is_ok());
        assert!(ensure_loopback_for_notls("host=/var/run/postgresql user=u dbname=db").is_ok());
        assert!(ensure_loopback_for_notls("postgres://u@db.internal:5432/db").is_err(), "remote refused");
        assert!(ensure_loopback_for_notls("postgres://u@10.0.0.5/db").is_err(), "remote IP refused");
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

    /// The exact accounts columns, mirrored in RETAINED_DATA.md. Keep the two in sync.
    const DOCUMENTED_COLUMNS: &[&str] = &["account_number", "recovery_code_hash", "entitlement"];

    /// Substrings that betray a personally-identifying column.
    const PII_TOKENS: &[&str] = &[
        "email", "ip", "name", "phone", "addr", "timestamp", "user_id", "account_id", "payment",
        "session", "identity", "device",
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
    fn accounts_table_has_exactly_the_documented_columns() {
        let cols = schema_columns(SCHEMA, "accounts");
        assert_eq!(
            cols, DOCUMENTED_COLUMNS,
            "accounts schema drifted — document any new/removed column in RETAINED_DATA.md and update DOCUMENTED_COLUMNS"
        );
    }

    #[test]
    fn accounts_schema_has_no_pii_column_names() {
        for col in schema_columns(SCHEMA, "accounts") {
            for tok in PII_TOKENS {
                assert!(
                    !col.contains(tok),
                    "column '{col}' looks like PII (matched '{tok}') — must not be persisted (PD-1)"
                );
            }
        }
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
        assert!(cols.contains(&"sneaky_ip".to_string()), "lowercase `add column` must parse");
        assert!(cols.contains(&"another_one".to_string()), "mixed-case `Add Column` must parse");
    }

    #[test]
    fn parser_catches_bare_add_without_column_keyword() {
        // Regression: Postgres `ALTER TABLE … ADD <name>` (COLUMN omitted) is valid; the audit must
        // catch it too, or a tool-generated migration could slip an undocumented column past.
        let cols = schema_columns(
            "CREATE TABLE t (account_number TEXT PRIMARY KEY); ALTER TABLE t ADD leaked_ip TEXT;",
            "t",
        );
        assert!(cols.contains(&"leaked_ip".to_string()), "bare `ADD <col>` must parse");
    }

    #[test]
    fn parser_ignores_index_ddl_and_is_order_independent() {
        // Regression: a `CREATE INDEX … ON t (…)` mentions the table + a `(`, but is NOT a column
        // source; and the result must not depend on statement order.
        let cols = schema_columns(
            "CREATE INDEX t_idx ON t (entitlement); CREATE TABLE t (account_number TEXT, entitlement TEXT);",
            "t",
        );
        assert_eq!(cols, vec!["account_number".to_string(), "entitlement".to_string()]);
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
