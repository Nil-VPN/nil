//! Account persistence behind a trait, so the backend is swappable (in-memory for
//! Phase 0; Postgres in Phase 1 — ADR-0003).

pub mod file;
pub mod memory;
#[cfg(feature = "postgres")]
pub mod postgres;

use async_trait::async_trait;

use crate::account::model::{AccountRecord, Entitlement};

// ---- Shared PII-free encoding for the durable backends (file + Postgres), kept here so the two
// can never drift on how an account is serialized. Each persists exactly H(secret), the recovery-
// code hash, and the entitlement (as hex/string) — nothing identifying. ------------------------

pub(crate) fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex32(s: &str) -> Option<[u8; 32]> {
    let h = s.as_bytes();
    if h.len() != 64 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = [0u8; 32];
    for (i, p) in h.chunks_exact(2).enumerate() {
        out[i] = (nib(p[0])? << 4) | nib(p[1])?;
    }
    Some(out)
}

pub(crate) fn ent_str(e: Entitlement) -> &'static str {
    match e {
        Entitlement::None => "none",
        Entitlement::Active => "active",
        Entitlement::Expired => "expired",
    }
}

pub(crate) fn ent_from(s: &str) -> Option<Entitlement> {
    match s {
        "none" => Some(Entitlement::None),
        "active" => Some(Entitlement::Active),
        "expired" => Some(Entitlement::Expired),
        _ => None,
    }
}

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
