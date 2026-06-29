//! Key derivation: phrase entropy → 256-bit account secret → account number.
//!
//! All inputs are domain-separated with versioned labels (`nil.account.v1.*`) so the
//! scheme can evolve without ambiguity and the same material is never reused across
//! contexts.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::phrase::PhraseEntropy;

const HKDF_SALT: &[u8] = b"nil.account.v1.hkdf-salt";
const SECRET_INFO: &[u8] = b"nil.account.v1.secret";
const ACCOUNT_DOMAIN: &[u8] = b"nil.account.v1.number";
const AUTH_SEED_INFO: &[u8] = b"nil.account.v1.auth-ed25519-seed";

/// Derive the 256-bit account secret from the phrase entropy via HKDF-SHA256.
/// Returned wrapped so it is zeroized on drop.
pub(crate) fn secret_from_entropy(e: &PhraseEntropy) -> Zeroizing<[u8; 32]> {
    let ikm = Zeroizing::new(e.ikm());
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &*ikm);
    let mut secret = Zeroizing::new([0u8; 32]);
    // Infallible: 32 bytes is far under HKDF-SHA256's 255×32-byte output limit.
    hk.expand(SECRET_INFO, secret.as_mut())
        .expect("HKDF-SHA256 expand of 32 bytes never fails");
    secret
}

/// Derive the 32-byte Ed25519 *seed* for the account's auth key from the phrase entropy, via the
/// same HKDF as the account secret but a DISTINCT `info` label (`...auth-ed25519-seed`). Domain
/// separation guarantees the auth seed and the account secret are independent values — neither can
/// be derived from the other. Returned wrapped so it is zeroized on drop. (ADR-0007.)
pub(crate) fn auth_seed_from_entropy(e: &PhraseEntropy) -> Zeroizing<[u8; 32]> {
    let ikm = Zeroizing::new(e.ikm());
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &*ikm);
    let mut seed = Zeroizing::new([0u8; 32]);
    // Infallible: 32 bytes is far under HKDF-SHA256's 255×32-byte output limit.
    hk.expand(AUTH_SEED_INFO, seed.as_mut())
        .expect("HKDF-SHA256 expand of 32 bytes never fails");
    seed
}

/// `account_number = SHA-256(domain || secret)` — the 32-byte canonical identifier.
/// This is the only thing the Portal persists for an anonymous account (plus the
/// recovery-code hash and entitlement).
pub(crate) fn account_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ACCOUNT_DOMAIN);
    h.update(secret);
    h.finalize().into()
}
