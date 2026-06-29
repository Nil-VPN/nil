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

/// Serialize an entitlement to the store's TEXT column. An active subscription encodes its expiry as
/// `active:<unix_secs>` so the durable record round-trips the `until`; `none`/`expired` are bare.
pub(crate) fn ent_str(e: Entitlement) -> String {
    match e {
        Entitlement::None => "none".to_string(),
        Entitlement::Active { until } => format!("active:{until}"),
        Entitlement::Expired => "expired".to_string(),
    }
}

pub(crate) fn ent_from(s: &str) -> Option<Entitlement> {
    match s {
        "none" => Some(Entitlement::None),
        "expired" => Some(Entitlement::Expired),
        // Back-compat: a legacy bare "active" (pre-expiry rows) reads as already-lapsed, so a
        // pre-ADR-0007 row can never grant unlimited access — it must be re-activated by a payment.
        "active" => Some(Entitlement::Expired),
        other => other
            .strip_prefix("active:")
            .and_then(|u| u.parse::<u64>().ok())
            .map(|until| Entitlement::Active { until }),
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

#[cfg(test)]
mod ent_encoding_tests {
    use super::*;

    #[test]
    fn ent_str_round_trips_through_ent_from() {
        for e in [
            Entitlement::None,
            Entitlement::Expired,
            Entitlement::Active { until: 0 },
            Entitlement::Active { until: 1_900_000_000 },
            Entitlement::Active { until: u64::MAX },
        ] {
            let s = ent_str(e);
            assert_eq!(ent_from(&s), Some(e), "round-trip failed for {e:?} -> {s:?}");
        }
    }

    #[test]
    fn active_encodes_its_expiry() {
        assert_eq!(ent_str(Entitlement::Active { until: 1_234 }), "active:1234");
        assert_eq!(ent_str(Entitlement::None), "none");
        assert_eq!(ent_str(Entitlement::Expired), "expired");
    }

    #[test]
    fn legacy_bare_active_reads_as_expired_not_unlimited() {
        // A pre-ADR-0007 row had a bare "active" with no expiry; it must NOT grant unlimited access.
        assert_eq!(ent_from("active"), Some(Entitlement::Expired));
    }

    #[test]
    fn malformed_entitlement_columns_are_rejected() {
        assert_eq!(ent_from("active:"), None);
        assert_eq!(ent_from("active:notanumber"), None);
        assert_eq!(ent_from("bogus"), None);
    }
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Persist a new account record. Errors if the account number already exists.
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError>;
    /// Fetch an account by its number (= `H(secret)`), if present.
    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError>;
}
