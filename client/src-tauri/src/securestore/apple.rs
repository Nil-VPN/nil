//! Apple Keychain-backed vault key (macOS and iOS).

use std::path::Path;
use std::sync::Arc;

use objc2_foundation::{NSNumber, NSURLIsExcludedFromBackupKey, NSURL};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    delete_generic_password_options, generic_password, set_generic_password_options,
    PasswordOptions,
};
use security_framework_sys::base::errSecItemNotFound;
use zeroize::{Zeroize, Zeroizing};

use super::aes::{AesGcmSealer, KeyProvider};
use super::{Sealer, VaultError};

const SERVICE: &str = "com.nilvpn.client.secure-vault";
const ACCOUNT: &str = "master-key-v1";

pub(crate) fn platform_sealer() -> Result<Arc<dyn Sealer>, VaultError> {
    Ok(Arc::new(AesGcmSealer::new(AppleKeyProvider)))
}

pub(crate) fn exclude_from_backup(path: &Path) -> Result<(), VaultError> {
    let url = NSURL::from_directory_path(path).ok_or_else(|| {
        VaultError::Sealer("vault directory is not a valid Apple file URL".into())
    })?;
    let excluded = NSNumber::new_bool(true);
    // SAFETY: NSURLIsExcludedFromBackupKey requires an NSNumber boolean, supplied above.
    unsafe {
        url.setResourceValue_forKey_error(Some(&excluded), NSURLIsExcludedFromBackupKey)
            .map_err(|_| VaultError::Sealer("could not exclude vault directory from backup".into()))
    }
}

struct AppleKeyProvider;

impl AppleKeyProvider {
    fn lookup_options() -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        options.set_access_synchronized(Some(false));
        options.use_protected_keychain();
        options
    }

    fn insert_options() -> Result<PasswordOptions, VaultError> {
        let mut options = Self::lookup_options();
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .map_err(|e| VaultError::Sealer(format!("create Keychain access control: {e}")))?;
        options.set_access_control(access);
        options.set_label("NIL VPN encrypted vault key");
        Ok(options)
    }

    fn decode(mut bytes: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let result = <[u8; 32]>::try_from(bytes.as_slice()).map(Zeroizing::new);
        bytes.zeroize();
        result.map_err(|_| VaultError::Sealer("Keychain vault key has an invalid length".into()))
    }
}

impl KeyProvider for AppleKeyProvider {
    fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        match generic_password(Self::lookup_options()) {
            Ok(bytes) => Self::decode(bytes).map(Some),
            Err(error) if error.code() == errSecItemNotFound => Ok(None),
            Err(error) => Err(VaultError::Sealer(format!(
                "read Apple Keychain vault key: {error}"
            ))),
        }
    }

    fn load_or_create(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if let Some(key) = self.load()? {
            return Ok(key);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(key.as_mut())
            .map_err(|e| VaultError::Sealer(format!("generate Keychain vault key: {e}")))?;
        set_generic_password_options(key.as_ref(), Self::insert_options()?)
            .map_err(|e| VaultError::Sealer(format!("write Apple Keychain vault key: {e}")))?;

        // Re-read through the exact non-synchronizable query and compare before any vault write.
        // This catches an entitlement/keychain-domain mismatch rather than creating ciphertext
        // that a later launch cannot open.
        let persisted = self.load()?.ok_or_else(|| {
            VaultError::Sealer("Apple Keychain did not persist the vault key".into())
        })?;
        if persisted.as_ref() != key.as_ref() {
            return Err(VaultError::Sealer(
                "Apple Keychain returned a different vault key".into(),
            ));
        }
        Ok(persisted)
    }

    fn destroy(&self) -> Result<(), VaultError> {
        match delete_generic_password_options(Self::lookup_options()) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == errSecItemNotFound => Ok(()),
            Err(error) => Err(VaultError::Sealer(format!(
                "delete Apple Keychain vault key: {error}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_directory_can_be_excluded_from_apple_backups() {
        let path =
            std::env::temp_dir().join(format!("nil-vault-backup-exclusion-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        exclude_from_backup(&path).expect("set NSURLIsExcludedFromBackupKey");
        let _ = std::fs::remove_dir_all(path);
    }
}
