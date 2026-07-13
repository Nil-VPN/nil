//! Account authentication key (ADR-0007).
//!
//! A subscription lets a recognised *anonymous* account request fresh blind-signature batches in
//! the background. To recognise the account without it revealing the secret, the client proves
//! possession of an Ed25519 key **derived from the recovery phrase** by signing a Portal-issued
//! challenge. The Portal stores only the PUBLIC half (in `AccountRecord.auth_pubkey`).
//!
//! Privacy: the keypair is deterministic from the phrase (so any device that has the phrase can
//! authenticate), and the public key is a per-account *anonymous* value — it carries no identity,
//! exactly like the account number. It never reaches the control or data plane.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use super::derive;
use super::phrase::{Phrase, PhraseEntropy};
use super::ACCOUNT_SCHEME_VERSION;
use crate::error::CryptoError;

/// Length of a detached Ed25519 signature, in bytes.
pub const AUTH_SIG_LEN: usize = 64;
/// Length of an Ed25519 public key, in bytes.
pub const AUTH_PUBKEY_LEN: usize = 32;

const REGISTRATION_DOMAIN: &[u8] = b"nil.account.registration-proof";
const REGISTRATION_MESSAGE_LEN: usize = REGISTRATION_DOMAIN.len() + 1 + 32 + AUTH_PUBKEY_LEN;

fn registration_message(
    account_number: &[u8; 32],
    public_key: &[u8; AUTH_PUBKEY_LEN],
) -> [u8; REGISTRATION_MESSAGE_LEN] {
    let mut message = [0u8; REGISTRATION_MESSAGE_LEN];
    let mut offset = 0;
    message[offset..offset + REGISTRATION_DOMAIN.len()].copy_from_slice(REGISTRATION_DOMAIN);
    offset += REGISTRATION_DOMAIN.len();
    message[offset] = ACCOUNT_SCHEME_VERSION;
    offset += 1;
    message[offset..offset + account_number.len()].copy_from_slice(account_number);
    offset += account_number.len();
    message[offset..].copy_from_slice(public_key);
    message
}

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
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Derive the auth keypair from a recovery phrase. Deterministic: the same phrase always yields
    /// the same keypair, so re-logging in on any device reproduces it.
    pub fn from_phrase(phrase: &Phrase) -> Result<Self, CryptoError> {
        Ok(Self::from_entropy(&phrase.to_entropy()?))
    }

    /// Reconstruct the keypair from a previously persisted 32-byte seed (the value returned by
    /// [`AuthKeypair::to_seed_bytes`]). Lets a client re-derive the auth key after a restart without
    /// re-entering the phrase (ADR-0007). The seed is SECRET — treat it exactly like the phrase.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte Ed25519 seed, for at-rest persistence by a client that caches the auth key
    /// (ADR-0007). SECRET: the holder must store it the way it stores tokens (owner-only, atomic,
    /// never logged) and zeroize copies. Reconstruct the keypair via [`AuthKeypair::from_seed`].
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// The 32-byte public key — the only half the Portal persists.
    pub fn public_key_bytes(&self) -> [u8; AUTH_PUBKEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign a Portal-issued challenge, returning the 64-byte detached signature.
    pub fn sign(&self, challenge: &[u8]) -> [u8; AUTH_SIG_LEN] {
        self.signing.sign(challenge).to_bytes()
    }

    /// Sign the v2 account-registration statement.
    ///
    /// The signed statement binds the account scheme version, raw account number,
    /// and this keypair's public key. A Portal can therefore verify that a client
    /// registering public account material possesses the corresponding private key,
    /// without receiving the recovery phrase.
    pub fn sign_registration(&self, account_number: &[u8; 32]) -> [u8; AUTH_SIG_LEN] {
        let public_key = self.public_key_bytes();
        self.signing
            .sign(&registration_message(account_number, &public_key))
            .to_bytes()
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
    vk.verify(challenge, &Signature::from_bytes(signature))
        .is_ok()
}

/// Verify a v2 account-registration proof of possession.
///
/// The signature is valid only for the exact tuple of scheme version, raw account
/// number, and authentication public key. Malformed and all-zero public keys fail
/// closed.
pub fn verify_registration_signature(
    account_number: &[u8; 32],
    public_key: &[u8; AUTH_PUBKEY_LEN],
    signature: &[u8; AUTH_SIG_LEN],
) -> bool {
    verify_auth_signature(
        public_key,
        &registration_message(account_number, public_key),
        signature,
    )
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
        assert!(verify_auth_signature(
            &kp.public_key_bytes(),
            challenge,
            &sig
        ));
        assert_eq!(
            kp.public_key_bytes(),
            acct.auth_public_key,
            "create exposes the same pubkey"
        );
    }

    #[test]
    fn a_different_challenge_does_not_verify() {
        let acct = create_account(&mut seeded());
        let kp = AuthKeypair::from_phrase(&acct.recovery_phrase).expect("derive");
        let sig = kp.sign(b"challenge-A-padding-padding-0123");
        assert!(!verify_auth_signature(
            &kp.public_key_bytes(),
            b"challenge-B-padding-padding-0123",
            &sig
        ));
    }

    #[test]
    fn a_different_account_key_does_not_verify() {
        let a = AuthKeypair::from_phrase(
            &create_account(&mut ChaCha20Rng::seed_from_u64(1)).recovery_phrase,
        )
        .unwrap();
        let b = create_account(&mut ChaCha20Rng::seed_from_u64(2));
        let challenge = b"shared-challenge-padding-01234567";
        let sig_a = a.sign(challenge);
        // A's signature must not verify under B's public key.
        let b_pub = AuthKeypair::from_phrase(&b.recovery_phrase)
            .unwrap()
            .public_key_bytes();
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
    fn seed_round_trips_through_from_seed() {
        // Persisting the seed and reconstructing reproduces the same keypair (the client cache path).
        let acct = create_account(&mut seeded());
        let kp = AuthKeypair::from_phrase(&acct.recovery_phrase).unwrap();
        let seed = kp.to_seed_bytes();
        let restored = AuthKeypair::from_seed(&seed);
        assert_eq!(restored.public_key_bytes(), kp.public_key_bytes());
        let challenge = b"persisted-then-restored-01234567";
        assert!(verify_auth_signature(
            &kp.public_key_bytes(),
            challenge,
            &restored.sign(challenge)
        ));
    }

    #[test]
    fn all_zero_sentinel_key_never_verifies() {
        let kp = AuthKeypair::from_phrase(&create_account(&mut seeded()).recovery_phrase).unwrap();
        let challenge = b"any-challenge-padding-0123456789";
        let sig = kp.sign(challenge);
        assert!(!verify_auth_signature(
            &[0u8; AUTH_PUBKEY_LEN],
            challenge,
            &sig
        ));
    }

    #[test]
    fn registration_signature_binds_account_and_public_key() {
        let acct = create_account(&mut seeded());
        let kp = AuthKeypair::from_phrase(&acct.recovery_phrase).unwrap();
        let account_number = acct.account_number.as_bytes();
        let public_key = kp.public_key_bytes();
        let signature = kp.sign_registration(account_number);

        assert!(verify_registration_signature(
            account_number,
            &public_key,
            &signature
        ));

        let mut changed_account = *account_number;
        changed_account[0] ^= 1;
        assert!(!verify_registration_signature(
            &changed_account,
            &public_key,
            &signature
        ));

        let other = create_account(&mut ChaCha20Rng::seed_from_u64(2));
        assert!(!verify_registration_signature(
            account_number,
            &other.auth_public_key,
            &signature
        ));

        let mut changed_signature = signature;
        changed_signature[0] ^= 1;
        assert!(!verify_registration_signature(
            account_number,
            &public_key,
            &changed_signature
        ));
    }
}
