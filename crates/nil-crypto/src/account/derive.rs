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

/// `account_number = SHA-256(domain || secret)` — the 32-byte canonical identifier.
/// This is the only thing the Portal persists for an anonymous account (plus the
/// recovery-code hash and entitlement).
pub(crate) fn account_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ACCOUNT_DOMAIN);
    h.update(secret);
    h.finalize().into()
}
