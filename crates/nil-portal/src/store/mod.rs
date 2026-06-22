//! Account persistence behind a trait, so the backend is swappable (in-memory for
//! Phase 0; Postgres in Phase 1 — ADR-0003).

pub mod file;
pub mod memory;

use async_trait::async_trait;

use crate::account::model::AccountRecord;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("account already exists")]
    Duplicate,
    /// The store backend failed (e.g. the durable file could not be written). Callers fail
    /// closed: the account is not created.
    #[error("store backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Persist a new account record. Errors if the account number already exists.
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError>;
    /// Fetch an account by its number (= `H(secret)`), if present.
    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError>;
}
