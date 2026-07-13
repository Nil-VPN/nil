// AES-256-GCM vault sealer used with OS stores that can safely hold a random raw key.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::{Zeroize, Zeroizing};

use super::{Sealer, VaultError};

const MAGIC: &[u8; 5] = b"NILG\x01";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub(super) trait KeyProvider: Send + Sync {
    /// Load an existing key without creating one. `None` while ciphertext exists is fatal.
    fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError>;
    /// Load the existing key or create one inside the platform credential store.
    fn load_or_create(&self) -> Result<Zeroizing<[u8; 32]>, VaultError>;
    fn destroy(&self) -> Result<(), VaultError>;
}

pub(super) struct AesGcmSealer<P> {
    provider: P,
}

impl<P> AesGcmSealer<P> {
    pub(super) fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: KeyProvider> Sealer for AesGcmSealer<P> {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        let key = self.provider.load_or_create()?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| VaultError::Sealer("invalid protected-storage key length".into()))?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| VaultError::Sealer(format!("secure random nonce: {e}")))?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| VaultError::Sealer("vault encryption failed".into()))?;
        let mut envelope = Vec::with_capacity(MAGIC.len() + NONCE_LEN + encrypted.len());
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        nonce.zeroize();
        Ok(envelope)
    }

    fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if ciphertext.len() < MAGIC.len() + NONCE_LEN + TAG_LEN
            || &ciphertext[..MAGIC.len()] != MAGIC
        {
            return Err(VaultError::Authentication);
        }
        let key = self.provider.load()?.ok_or_else(|| {
            VaultError::Sealer("protected-storage key is unavailable for an existing vault".into())
        })?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| VaultError::Sealer("invalid protected-storage key length".into()))?;
        let nonce_end = MAGIC.len() + NONCE_LEN;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&ciphertext[MAGIC.len()..nonce_end]),
                Payload {
                    msg: &ciphertext[nonce_end..],
                    aad,
                },
            )
            .map_err(|_| VaultError::Authentication)?;
        Ok(Zeroizing::new(plaintext))
    }

    fn destroy_key(&self) -> Result<(), VaultError> {
        self.provider.destroy()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct MemoryProvider(Mutex<Option<[u8; 32]>>);

    impl KeyProvider for MemoryProvider {
        fn load(&self) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
            Ok(self.0.lock().unwrap().map(Zeroizing::new))
        }

        fn load_or_create(&self) -> Result<Zeroizing<[u8; 32]>, VaultError> {
            let mut key = self.0.lock().unwrap();
            Ok(Zeroizing::new(*key.get_or_insert([0x42; 32])))
        }

        fn destroy(&self) -> Result<(), VaultError> {
            let mut key = self.0.lock().unwrap();
            if let Some(value) = key.as_mut() {
                value.zeroize();
            }
            *key = None;
            Ok(())
        }
    }

    fn sealer() -> AesGcmSealer<MemoryProvider> {
        AesGcmSealer::new(MemoryProvider(Mutex::new(None)))
    }

    #[test]
    fn authenticates_ciphertext_and_aad() {
        let sealer = sealer();
        let sealed = sealer.seal(b"account-secret", b"vault-v1").unwrap();
        assert!(!sealed.windows(14).any(|w| w == b"account-secret"));
        assert_eq!(
            sealer.open(&sealed, b"vault-v1").unwrap().as_slice(),
            b"account-secret"
        );

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            sealer.open(&tampered, b"vault-v1"),
            Err(VaultError::Authentication)
        ));
        assert!(matches!(
            sealer.open(&sealed, b"other-domain"),
            Err(VaultError::Authentication)
        ));
    }

    #[test]
    fn missing_key_never_regenerates_while_opening() {
        let sealer = sealer();
        let sealed = sealer.seal(b"secret", b"vault-v1").unwrap();
        sealer.destroy_key().unwrap();
        assert!(matches!(
            sealer.open(&sealed, b"vault-v1"),
            Err(VaultError::Sealer(_))
        ));
    }
}
