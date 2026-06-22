//! The one-time recovery code: an independent second factor for account recovery.
//!
//! It is NOT derived from the phrase — deriving it would add no security, since anyone
//! with the phrase could recompute it. Keeping it independent makes recovery genuinely
//! two-factor (two things you wrote down separately). The Portal stores only its hash.

use rand_core::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::encoding;

const RECOVERY_DOMAIN: &[u8] = b"nil.account.v1.recovery-code";
const RECOVERY_BYTES: usize = 16; // 128-bit

/// A one-time recovery code in canonical form (uppercase Crockford base32, no
/// separators). Hashed for storage; never persisted in the clear.
pub struct RecoveryCode {
    canonical: String,
}

impl RecoveryCode {
    /// Generate a fresh 128-bit recovery code.
    pub(crate) fn random(rng: &mut impl RngCore) -> Self {
        let mut bytes = Zeroizing::new([0u8; RECOVERY_BYTES]);
        rng.fill_bytes(bytes.as_mut());
        Self {
            canonical: encoding::base32(bytes.as_ref()),
        }
    }

    /// Parse a user-submitted code, normalizing case and stripping any separators or
    /// whitespace so the user can re-type it in any reasonable format.
    pub fn parse(input: &str) -> Self {
        let canonical = input
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect();
        Self { canonical }
    }

    /// `SHA-256(domain || canonical)` — the value the Portal stores.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(RECOVERY_DOMAIN);
        h.update(self.canonical.as_bytes());
        h.finalize().into()
    }

    /// Human-facing form: grouped in 4-character blocks for transcription.
    pub fn display(&self) -> String {
        encoding::group(&self.canonical, 4)
    }
}

/// Constant-time comparison of a submitted code against a stored hash.
pub(crate) fn verify(submitted: &RecoveryCode, stored_hash: &[u8; 32]) -> bool {
    submitted.hash().ct_eq(stored_hash).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn verify_accepts_matching_and_rejects_tampered() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let code = RecoveryCode::random(&mut rng);
        let stored = code.hash();

        // Re-typed from the displayed (grouped) form must still verify.
        let resubmitted = RecoveryCode::parse(&code.display());
        assert!(verify(&resubmitted, &stored));

        // A different code must not.
        let wrong = RecoveryCode::parse("00000000000000000000000000");
        assert!(!verify(&wrong, &stored));
    }
}
