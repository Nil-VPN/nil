//! On-device cache of the account's auth material (ADR-0007).
//!
//! To mint connection tokens on demand while subscribed — so re-login reconnects without retyping
//! the 7-word phrase — the client caches the account's **Ed25519 auth seed** plus its account
//! number. We persist the derived auth seed, **NOT the phrase**: the phrase recovers the entire
//! account, whereas the auth seed only signs Portal challenges for an already-anonymous account, so
//! it is the least-powerful credential that still enables mint-on-demand (chosen deliberately).
//!
//! It is still sensitive (it authenticates as the account), so it is stored owner-only (`0600`),
//! written atomically, and never logged — exactly like the token store. The account number is
//! `H(secret)` (the Portal's lookup key, not itself secret); it is cached so the client can name the
//! account in a mint/status request without re-deriving it from the phrase.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::tokenstore::write_private_atomic;

#[derive(Debug, thiserror::Error)]
pub enum AuthStoreError {
    #[error("auth store io: {0}")]
    Io(String),
    #[error("auth store parse: {0}")]
    Parse(String),
}

/// Cached auth material. Both fields are lowercase hex of 32 bytes: the account number
/// (`H(secret)`) and the Ed25519 auth seed (SECRET — re-derives the auth signing key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountAuthMaterial {
    pub account_number: String,
    pub auth_seed: String,
}

/// File-backed, owner-only cache of a single account's auth material.
pub struct AuthStore {
    path: PathBuf,
}

impl AuthStore {
    /// Back the store with `path` (e.g. `<app-local-data>/auth.json`).
    pub fn open(path: PathBuf) -> Self {
        AuthStore { path }
    }

    /// The cached material, or `None` if no account is cached yet.
    pub fn load(&self) -> Result<Option<AccountAuthMaterial>, AuthStoreError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| AuthStoreError::Parse(format!("parse auth store: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AuthStoreError::Io(format!("read auth store: {e}"))),
        }
    }

    /// Cache the auth material, replacing any previous account (one cached account at a time).
    pub fn save(&self, material: &AccountAuthMaterial) -> Result<(), AuthStoreError> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| AuthStoreError::Io(format!("create auth dir: {e}")))?;
        }
        let body = serde_json::to_vec_pretty(material)
            .map_err(|e| AuthStoreError::Parse(e.to_string()))?;
        write_private_atomic(&self.path, &body)
            .map_err(|e| AuthStoreError::Io(format!("write auth store: {e}")))
    }

    /// Forget the cached account (e.g. on logout / switch account). Idempotent.
    pub fn clear(&self) -> Result<(), AuthStoreError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AuthStoreError::Io(format!("remove auth store: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_store() -> (AuthStore, PathBuf) {
        static N: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        let n = N.fetch_add(1, Ordering::Relaxed);
        p.push(format!("nil-authstore-test-{}-{n}/auth.json", std::process::id()));
        (AuthStore::open(p.clone()), p)
    }

    fn material() -> AccountAuthMaterial {
        AccountAuthMaterial {
            account_number: "ab".repeat(32),
            auth_seed: "cd".repeat(32),
        }
    }

    #[test]
    fn missing_file_loads_none() {
        let (s, _p) = tmp_store();
        assert!(s.load().unwrap().is_none());
    }

    #[test]
    fn save_then_load_round_trips_and_persists() {
        let (s, path) = tmp_store();
        s.save(&material()).unwrap();
        assert_eq!(s.load().unwrap().unwrap(), material());
        // A fresh handle on the same file sees it (persisted).
        assert_eq!(AuthStore::open(path).load().unwrap().unwrap(), material());
    }

    #[test]
    fn save_overwrites_the_previous_account() {
        let (s, _p) = tmp_store();
        s.save(&material()).unwrap();
        let other = AccountAuthMaterial { account_number: "11".repeat(32), auth_seed: "22".repeat(32) };
        s.save(&other).unwrap();
        assert_eq!(s.load().unwrap().unwrap(), other, "only the latest account is cached");
    }

    #[test]
    fn clear_forgets_the_account_and_is_idempotent() {
        let (s, _p) = tmp_store();
        s.save(&material()).unwrap();
        s.clear().unwrap();
        assert!(s.load().unwrap().is_none());
        s.clear().unwrap(); // idempotent — clearing an absent store is fine
    }

    #[test]
    fn stored_file_never_contains_the_phrase_or_a_word_list() {
        // The cache holds only hex material — never the recovery phrase. A device-image grab reveals
        // an opaque auth seed, not the words that recover the whole account.
        let (s, path) = tmp_store();
        s.save(&material()).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("auth_seed") && raw.contains("account_number"));
        assert!(!raw.contains("phrase"), "the recovery phrase must never be persisted");
        assert!(!raw.contains("recovery"), "no recovery material at rest");
    }

    #[cfg(unix)]
    #[test]
    fn auth_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (s, path) = tmp_store();
        s.save(&material()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the auth seed is a bearer credential — owner-only");
    }
}
