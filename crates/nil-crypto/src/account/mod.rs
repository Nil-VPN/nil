//! Anonymous account derivation (architecture spec §7.5, ADR-0001).
//!
//! The recovery **phrase** is the root of the account. Everything else — the 256-bit
//! secret, the account number — is derived deterministically from it, so an account is
//! fully recoverable from the phrase alone. The one-time recovery code is an
//! independent second factor.

mod auth;
mod derive;
mod encoding;
mod phrase;
mod recovery;
mod words;

pub use auth::{verify_auth_signature, AuthKeypair, AUTH_PUBKEY_LEN, AUTH_SIG_LEN};
pub use phrase::Phrase;
pub use recovery::RecoveryCode;

use rand_core::{CryptoRng, RngCore};

use crate::error::CryptoError;

/// Number of words in a recovery phrase. The single knob if the entropy/word-count
/// trade-off is ever revisited (see ADR-0001).
pub const PHRASE_WORDS: usize = 7;

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

/// Everything produced when creating a fresh anonymous account. The Portal keeps only
/// `account_number` (= `H(secret)`), `recovery_code_hash`, and `auth_public_key`; the phrase and
/// code are returned to the user and never stored.
pub struct DerivedAccount {
    pub account_number: AccountNumber,
    pub recovery_phrase: Phrase,
    pub recovery_code: RecoveryCode,
    pub recovery_code_hash: [u8; 32],
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
    let recovery_code = RecoveryCode::random(rng);
    let recovery_code_hash = recovery_code.hash();
    DerivedAccount {
        account_number,
        recovery_phrase,
        recovery_code,
        recovery_code_hash,
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

/// Constant-time check of a submitted recovery code against a stored hash.
pub fn verify_recovery_code(submitted: &RecoveryCode, stored_hash: &[u8; 32]) -> bool {
    recovery::verify(submitted, stored_hash)
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
    fn create_yields_seven_valid_words() {
        let acct = create_account(&mut seeded());
        assert_eq!(acct.recovery_phrase.words().len(), 7);
        // Every word must round-trip back to entropy (i.e. be a valid wordlist word).
        assert!(acct.recovery_phrase.to_entropy().is_ok());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = create_account(&mut seeded());
        let b = create_account(&mut seeded());
        assert_eq!(a.account_number, b.account_number);
        assert_eq!(a.recovery_phrase.to_vec(), b.recovery_phrase.to_vec());
        assert_eq!(a.recovery_code_hash, b.recovery_code_hash);
    }

    #[test]
    fn recovery_reproduces_the_account_number() {
        let acct = create_account(&mut seeded());
        let recovered = account_number_from_phrase(&acct.recovery_phrase).expect("valid phrase");
        assert_eq!(recovered, acct.account_number);
    }

    #[test]
    fn recovery_code_verifies_round_trip() {
        let acct = create_account(&mut seeded());
        let resubmitted = RecoveryCode::parse(&acct.recovery_code.display());
        assert!(verify_recovery_code(&resubmitted, &acct.recovery_code_hash));
        let wrong = RecoveryCode::parse("WRONGCODE");
        assert!(!verify_recovery_code(&wrong, &acct.recovery_code_hash));
    }

    #[test]
    fn distinct_seeds_give_distinct_accounts() {
        let a = create_account(&mut ChaCha20Rng::seed_from_u64(1));
        let b = create_account(&mut ChaCha20Rng::seed_from_u64(2));
        assert_ne!(a.account_number, b.account_number);
    }
}
