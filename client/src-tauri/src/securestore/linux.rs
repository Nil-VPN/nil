// Linux Secret Service-backed vault key.

use std::sync::Arc;

use keyring::{Entry, Error as KeyringError};
use zeroize::{Zeroize, Zeroizing};

use super::aes::{AesGcmSealer, KeyProvider};
use super::{Sealer, VaultError};

const SERVICE: &str = "com.nilvpn.client";
const USER: &str = "secure-vault-key-v1";

pub(crate) fn platform_sealer() -> Result<Arc<dyn Sealer>, VaultError> {
    // This target enables only `sync-secret-service`; keyring's mock provider is not compiled as
    // the Linux default. If D-Bus/the collection is absent or locked, operations fail closed.
    Ok(Arc::new(AesGcmSealer::new(SecretServiceKeyProvider)))
}

struct SecretServiceKeyProvider;

impl SecretServiceKeyProvider {
    fn entry() -> Result<Entry, VaultError> {
        Entry::new(SERVICE, USER)
            .map_err(|e| VaultError::Sealer(format!("open Linux Secret Service entry: {e}")))
    }

    fn decode(mut bytes: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let result = <[u8; 32]>::try_from(bytes.as_slice()).map(Zeroizing::new);
        bytes.zeroize();
        result.map_err(|_| {
            VaultError::Sealer("Linux Secret Service vault key has an invalid length".into())
        })
    }
}

impl KeyProvider for SecretServiceKeyProvider {
    fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        match Self::entry()?.get_secret() {
            Ok(bytes) => Self::decode(bytes).map(Some),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(VaultError::Sealer(format!(
                "read Linux Secret Service vault key: {error}"
            ))),
        }
    }

    fn load_or_create(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if let Some(key) = self.load()? {
            return Ok(key);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(key.as_mut())
            .map_err(|e| VaultError::Sealer(format!("generate Secret Service vault key: {e}")))?;
        Self::entry()?.set_secret(key.as_ref()).map_err(|e| {
            VaultError::Sealer(format!("write Linux Secret Service vault key: {e}"))
        })?;
        let persisted = self.load()?.ok_or_else(|| {
            VaultError::Sealer("Linux Secret Service did not persist the vault key".into())
        })?;
        if persisted.as_ref() != key.as_ref() {
            return Err(VaultError::Sealer(
                "Linux Secret Service returned a different vault key".into(),
            ));
        }
        Ok(persisted)
    }

    fn destroy(&self) -> Result<(), VaultError> {
        match Self::entry()?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(VaultError::Sealer(format!(
                "delete Linux Secret Service vault key: {error}"
            ))),
        }
    }
}
