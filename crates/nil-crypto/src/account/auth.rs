//! Account authentication key (ADR-0007).
//!
//! A subscription lets a recognised *anonymous* account mint fresh blind tokens on demand. To
//! recognise the account without it revealing the secret, the client proves possession of an
//! Ed25519 key **derived from the recovery phrase** by signing a Portal-issued challenge. The
//! Portal stores only the PUBLIC half (in `AccountRecord.auth_pubkey`).
//!
//! Privacy: the keypair is deterministic from the phrase (so any device that has the phrase can
//! authenticate), and the public key is a per-account *anonymous* value — it carries no identity,
//! exactly like the account number. It never reaches the control or data plane.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::derive;
use super::phrase::{Phrase, PhraseEntropy};
use crate::error::CryptoError;

/// Length of a detached Ed25519 signature, in bytes.
pub const AUTH_SIG_LEN: usize = 64;
/// Length of an Ed25519 public key, in bytes.
pub const AUTH_PUBKEY_LEN: usize = 32;

/// The account's auth keypair, derived deterministically from the recovery phrase. The signing
/// key is held by the client only and is zeroized on drop (ed25519-dalek `zeroize` feature).
pub struct AuthKeypair {
    signing: SigningKey,
}

impl AuthKeypair {
    /// Derive the auth keypair from the phrase entropy (the internal path; create/recover already
    /// hold the entropy, so this avoids re-parsing the phrase).
    pub(crate) fn from_entropy(e: &PhraseEntropy) -> Self {
        let seed = derive::auth_seed_from_entropy(e);
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    /// Derive the auth keypair from a recovery phrase. Deterministic: the same phrase always yields
    /// the same keypair, so re-logging in on any device reproduces it.
    pub fn from_phrase(phrase: &Phrase) -> Result<Self, CryptoError> {
        Ok(Self::from_entropy(&phrase.to_entropy()?))
    }

    /// The 32-byte public key — the only half the Portal persists.
    pub fn public_key_bytes(&self) -> [u8; AUTH_PUBKEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign a Portal-issued challenge, returning the 64-byte detached signature.
    pub fn sign(&self, challenge: &[u8]) -> [u8; AUTH_SIG_LEN] {
        self.signing.sign(challenge).to_bytes()
    }
}

/// Verify a challenge signature against a stored public key (the Portal side — no secret needed).
/// Returns `false` (never errors) on any malformed key or signature, and on the all-zero sentinel
/// key that marks a legacy/pre-ADR-0007 account with no auth key (so such an account can never pass
/// auth without being re-created — fail-closed).
pub fn verify_auth_signature(
    public_key: &[u8; AUTH_PUBKEY_LEN],
    challenge: &[u8],
    signature: &[u8; AUTH_SIG_LEN],
) -> bool {
    if public_key == &[0u8; AUTH_PUBKEY_LEN] {
        return false; // sentinel: no auth key on this account
    }
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false; // not a valid curve point
    };
    vk.verify(challenge, &Signature::from_bytes(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::create_account;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn seeded() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0x4E_494C) // "NIL"
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let acct = create_account(&mut seeded());
        let kp = AuthKeypair::from_phrase(&acct.recovery_phrase).expect("derive");
        let challenge = b"portal-issued-nonce-0123456789ab";
        let sig = kp.sign(challenge);
        assert!(verify_auth_signature(&kp.public_key_bytes(), challenge, &sig));
        assert_eq!(kp.public_key_bytes(), acct.auth_public_key, "create exposes the same pubkey");
    }

    #[test]
    fn a_different_challenge_does_not_verify() {
        let acct = create_account(&mut seeded());
        let kp = AuthKeypair::from_phrase(&acct.recovery_phrase).expect("derive");
        let sig = kp.sign(b"challenge-A-padding-padding-0123");
        assert!(!verify_auth_signature(&kp.public_key_bytes(), b"challenge-B-padding-padding-0123", &sig));
    }

    #[test]
    fn a_different_account_key_does_not_verify() {
        let a = AuthKeypair::from_phrase(&create_account(&mut ChaCha20Rng::seed_from_u64(1)).recovery_phrase).unwrap();
        let b = create_account(&mut ChaCha20Rng::seed_from_u64(2));
        let challenge = b"shared-challenge-padding-01234567";
        let sig_a = a.sign(challenge);
        // A's signature must not verify under B's public key.
        let b_pub = AuthKeypair::from_phrase(&b.recovery_phrase).unwrap().public_key_bytes();
        assert!(!verify_auth_signature(&b_pub, challenge, &sig_a));
    }

    #[test]
    fn derivation_is_deterministic_across_devices() {
        // Same phrase → same keypair (the property that lets re-login on a fresh device authenticate).
        let acct = create_account(&mut seeded());
        let k1 = AuthKeypair::from_phrase(&acct.recovery_phrase).unwrap();
        let k2 = AuthKeypair::from_phrase(&acct.recovery_phrase).unwrap();
        assert_eq!(k1.public_key_bytes(), k2.public_key_bytes());
    }

    #[test]
    fn auth_seed_is_independent_of_the_account_secret() {
        // The auth pubkey must not equal the account number (distinct HKDF labels → independent).
        let acct = create_account(&mut seeded());
        assert_ne!(&acct.auth_public_key, acct.account_number.as_bytes());
    }

    #[test]
    fn all_zero_sentinel_key_never_verifies() {
        let kp = AuthKeypair::from_phrase(&create_account(&mut seeded()).recovery_phrase).unwrap();
        let challenge = b"any-challenge-padding-0123456789";
        let sig = kp.sign(challenge);
        assert!(!verify_auth_signature(&[0u8; AUTH_PUBKEY_LEN], challenge, &sig));
    }
}
