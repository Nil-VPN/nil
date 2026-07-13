//! Anonymous account derivation (architecture spec §7.5, ADR-0001).
//!
//! The recovery **phrase** is the root of the account. Everything else — a domain-separated
//! 32-byte secret and the account number — is derived deterministically from it, so an account is
//! fully recoverable from the phrase alone. The v2 phrase is a standard 12-word BIP39 English
//! mnemonic with 128 bits of entropy and a checksum; derivation expands representation size, not
//! the phrase's entropy.

mod auth;
mod derive;
mod encoding;
mod phrase;

pub use auth::{
    verify_auth_signature, verify_registration_signature, AuthKeypair, AUTH_PUBKEY_LEN,
    AUTH_SIG_LEN,
};
pub use phrase::Phrase;

use rand_core::{CryptoRng, RngCore};

use crate::error::CryptoError;

/// Version of the account derivation and registration-proof scheme.
pub const ACCOUNT_SCHEME_VERSION: u8 = 2;

/// Number of words in a v2 BIP39 recovery phrase (128-bit entropy plus checksum).
pub const PHRASE_WORDS: usize = 12;

/// An account's identity-free identifier: `SHA-256(secret)`. The canonical value is
/// the raw 32 bytes (the Portal's lookup key); [`AccountNumber::display`] is cosmetic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountNumber {
    canonical: [u8; 32],
}

impl AccountNumber {
    /// The raw 32-byte hash — the canonical lookup key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.canonical
    }

    /// Human-facing form: grouped Crockford base32.
    pub fn display(&self) -> String {
        encoding::group(&encoding::base32(&self.canonical), 5)
    }
}

/// Everything produced when creating a fresh anonymous account. The client keeps the
/// phrase; a Portal registration needs only `account_number`, `auth_public_key`, and a
/// proof of possession produced by [`AuthKeypair::sign_registration`].
pub struct DerivedAccount {
    pub account_number: AccountNumber,
    pub recovery_phrase: Phrase,
    /// Public half of the account's Ed25519 auth key (derived from the phrase). Stored by the
    /// Portal to verify a signed challenge later (ADR-0007). Anonymous — carries no identity.
    pub auth_public_key: [u8; AUTH_PUBKEY_LEN],
}

/// Create a fresh anonymous account from the given CSPRNG. The RNG is injected so
/// tests can seed it deterministically; production uses [`create_account_os`].
pub fn create_account<R: RngCore + CryptoRng>(rng: &mut R) -> DerivedAccount {
    let entropy = phrase::PhraseEntropy::random(rng);
    let recovery_phrase = Phrase::from_entropy(&entropy);
    let secret = derive::secret_from_entropy(&entropy);
    let account_number = AccountNumber {
        canonical: derive::account_hash(&secret),
    };
    let auth_public_key = AuthKeypair::from_entropy(&entropy).public_key_bytes();
    DerivedAccount {
        account_number,
        recovery_phrase,
        auth_public_key,
    }
    // `entropy` and `secret` are zeroized as they drop here.
}

/// Create a fresh anonymous account using the operating-system CSPRNG.
pub fn create_account_os() -> DerivedAccount {
    create_account(&mut rand_core::OsRng)
}

/// Re-derive an account number from a recovery phrase (the recovery path).
pub fn account_number_from_phrase(phrase: &Phrase) -> Result<AccountNumber, CryptoError> {
    let entropy = phrase.to_entropy()?;
    let secret = derive::secret_from_entropy(&entropy);
    Ok(AccountNumber {
        canonical: derive::account_hash(&secret),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn seeded() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0x4E_494C) // "NIL"
    }

    #[test]
    fn create_yields_twelve_valid_words() {
        let acct = create_account(&mut seeded());
        assert_eq!(acct.recovery_phrase.words().len(), PHRASE_WORDS);
        // Every word and the BIP39 checksum must round-trip back to entropy.
        assert!(acct.recovery_phrase.to_entropy().is_ok());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = create_account(&mut seeded());
        let b = create_account(&mut seeded());
        assert_eq!(a.account_number, b.account_number);
        assert_eq!(a.recovery_phrase.to_vec(), b.recovery_phrase.to_vec());
    }

    #[test]
    fn recovery_reproduces_the_account_number() {
        let acct = create_account(&mut seeded());
        let recovered = account_number_from_phrase(&acct.recovery_phrase).expect("valid phrase");
        assert_eq!(recovered, acct.account_number);
    }

    #[test]
    fn distinct_seeds_give_distinct_accounts() {
        let a = create_account(&mut ChaCha20Rng::seed_from_u64(1));
        let b = create_account(&mut ChaCha20Rng::seed_from_u64(2));
        assert_ne!(a.account_number, b.account_number);
    }
}
