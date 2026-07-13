//! Encrypted on-device cache of the account's auth material (ADR-0007).
//!
//! To authenticate randomized background batch refills while subscribed, the client caches the
//! account's Ed25519 auth seed plus its account number. It persists the derived seed, never the
//! 12-word recovery phrase. [`AuthStore`] is only a narrow view over the shared [`SecureVault`]; it
//! has no file path, serializer, or plaintext fallback of its own.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::securestore::{SecureVault, VaultError};

#[derive(Debug, thiserror::Error)]
pub enum AuthStoreError {
    #[error("auth store io: {0}")]
    Io(String),
    #[error("auth store parse: {0}")]
    Parse(String),
}

/// Cached auth material. Both fields are lowercase hex of 32 bytes: the account number
/// (`H(secret)`) and the Ed25519 auth seed (SECRET — re-derives the auth signing key).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AccountAuthMaterial {
    pub account_number: String,
    pub auth_seed: String,
}

impl std::fmt::Debug for AccountAuthMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountAuthMaterial([REDACTED])")
    }
}

/// Auth-material facade over the process-shared encrypted credential vault.
#[derive(Clone)]
pub struct AuthStore {
    vault: SecureVault,
}

impl AuthStore {
    pub fn new(vault: SecureVault) -> Self {
        Self { vault }
    }

    /// The cached material, or `None` if no account is cached yet.
    pub fn load(&self) -> Result<Option<AccountAuthMaterial>, AuthStoreError> {
        self.vault
            .load()
            .map(|vault| vault.auth.clone())
            .map_err(map_vault_error)
    }

    /// Cache the auth material, replacing only the previous account. Tokens in the same vault are
    /// left untouched.
    pub fn save(&self, material: &AccountAuthMaterial) -> Result<(), AuthStoreError> {
        let material = material.clone();
        self.vault
            .mutate(move |vault| {
                if let Some(previous) = vault.auth.as_mut() {
                    previous.account_number.zeroize();
                    previous.auth_seed.zeroize();
                }
                vault.auth = Some(material);
                Ok(())
            })
            .map_err(map_vault_error)
    }

    /// Forget only the cached account. Anonymous bearer tokens remain available. Idempotent.
    pub fn clear(&self) -> Result<(), AuthStoreError> {
        self.vault
            .mutate(|vault| {
                if let Some(auth) = vault.auth.as_mut() {
                    auth.account_number.zeroize();
                    auth.auth_seed.zeroize();
                }
                vault.auth = None;
                Ok(())
            })
            .map_err(map_vault_error)
    }
}

fn map_vault_error(error: VaultError) -> AuthStoreError {
    let is_parse = matches!(
        &error,
        VaultError::Envelope(_)
            | VaultError::EnvelopeVersion(_)
            | VaultError::SchemaVersion(_)
            | VaultError::Parse(_)
            | VaultError::Validation(_)
    );
    if is_parse {
        AuthStoreError::Parse(error.to_string())
    } else {
        AuthStoreError::Io(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_store() -> (AuthStore, PathBuf) {
        static N: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        let n = N.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "nil-authstore-test-{}-{n}/secure/vault.bin",
            std::process::id()
        ));
        (
            AuthStore::new(crate::securestore::test_vault(path.clone())),
            path,
        )
    }

    fn material() -> AccountAuthMaterial {
        AccountAuthMaterial {
            account_number: "ab".repeat(32),
            auth_seed: "cd".repeat(32),
        }
    }

    #[test]
    fn missing_vault_loads_none_without_creating_plaintext() {
        let (store, path) = tmp_store();
        assert!(store.load().unwrap().is_none());
        assert!(!path.exists());
    }

    #[test]
    fn save_then_load_round_trips_and_persists() {
        let (store, path) = tmp_store();
        store.save(&material()).unwrap();
        assert_eq!(store.load().unwrap().unwrap(), material());

        let reopened = AuthStore::new(crate::securestore::test_vault(path));
        assert_eq!(reopened.load().unwrap().unwrap(), material());
    }

    #[test]
    fn save_overwrites_only_the_previous_account() {
        let (store, _) = tmp_store();
        store.save(&material()).unwrap();
        let other = AccountAuthMaterial {
            account_number: "11".repeat(32),
            auth_seed: "22".repeat(32),
        };
        store.save(&other).unwrap();
        assert_eq!(
            store.load().unwrap().unwrap(),
            other,
            "only the latest account is cached"
        );
    }

    #[test]
    fn clear_forgets_the_account_and_is_idempotent() {
        let (store, _) = tmp_store();
        store.save(&material()).unwrap();
        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
        store.clear().unwrap();
    }

    #[test]
    fn vault_file_contains_neither_auth_material_nor_recovery_words() {
        let (store, path) = tmp_store();
        store.save(&material()).unwrap();
        let raw = std::fs::read(&path).unwrap();
        for forbidden in [
            "ab".repeat(32),
            "cd".repeat(32),
            "account_number".to_string(),
            "auth_seed".to_string(),
            "phrase".to_string(),
            "recovery".to_string(),
        ] {
            assert!(
                !raw.windows(forbidden.len())
                    .any(|window| window == forbidden.as_bytes()),
                "vault ciphertext exposed forbidden auth material"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_vault_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (store, path) = tmp_store();
        store.save(&material()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the encrypted credential vault is owner-only");
    }
}
