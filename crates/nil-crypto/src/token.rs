//! Privacy Pass unlinkable blind tokens (architecture spec §7) — RFC 9474 blind RSA
//! signatures (RSABSSA-SHA384-PSS) under the RFC 9578 token model.
//!
//! Trust split (Pillar 4): the **issuer** (in `nil-portal`) holds the RSA *private* key and
//! blind-signs; the **verifier** (in `nil-coordinator`) holds only the *public* key and checks
//! redeemed tokens. The blinding makes redemption **unlinkable** to issuance — the issuer only
//! ever sees a blinded message, never the token it is later asked to (cannot) link, and the
//! verifier can check but not mint. The two never share the private key.
//!
//! Flow: client picks a random token message → `blind` → issuer `blind_sign` → client
//! `finalize` (unblind) → presents `(msg, token)` to the verifier → `verify`. The Coordinator
//! additionally keeps a spent-token nullifier set (no identity) to stop double-spends.

use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, Error as RsaError, Signature,
    KeyPairSha384PSSDeterministic as KeyPair, PublicKeySha384PSSDeterministic as PublicKey,
    SecretKeySha384PSSDeterministic as SecretKey,
};

/// RSA modulus size for the token key (RFC 9474 requires ≥ 2048).
pub const TOKEN_MODULUS_BITS: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("blind-rsa error: {0}")]
    Rsa(String),
}

fn map_rsa(e: RsaError) -> TokenError {
    TokenError::Rsa(format!("{e:?}"))
}

/// Issuer side (Portal trust domain): holds the private signing key.
pub struct Issuer {
    kp: KeyPair,
}

impl Issuer {
    /// Generate a fresh issuance key.
    pub fn generate() -> Result<Self, TokenError> {
        let kp = KeyPair::generate(&mut DefaultRng, TOKEN_MODULUS_BITS).map_err(map_rsa)?;
        Ok(Self { kp })
    }

    /// Reload an issuer from its private key (DER).
    pub fn from_secret_der(der: &[u8]) -> Result<Self, TokenError> {
        let sk = SecretKey::from_der(der).map_err(map_rsa)?;
        let pk = sk.public_key().map_err(map_rsa)?;
        Ok(Self { kp: KeyPair { pk, sk } })
    }

    /// Export the private key (DER) — Portal-only; never leaves the issuer trust domain.
    pub fn secret_der(&self) -> Result<Vec<u8>, TokenError> {
        self.kp.sk.to_der().map_err(map_rsa)
    }

    /// Export the public key (DER) — handed to clients and the verifier.
    pub fn public_der(&self) -> Result<Vec<u8>, TokenError> {
        self.kp.pk.to_der().map_err(map_rsa)
    }

    /// Blind-sign a client's blinded token request. The issuer never sees the unblinded token,
    /// so it cannot later link the redeemed token to this issuance.
    pub fn blind_sign(&self, blind_msg: &[u8]) -> Result<Vec<u8>, TokenError> {
        self.kp.sk.blind_sign(blind_msg).map(|s| s.0).map_err(map_rsa)
    }
}

/// Verifier side (Coordinator trust domain): holds only public key(s).
///
/// It can hold MORE THAN ONE public key so issuer keys rotate without downtime: during a
/// rotation both the old and new key are accepted, so a token minted under either verifies
/// (architecture spec §7 / runbook §9). The private key never reaches this trust domain.
pub struct Verifier {
    keys: Vec<PublicKey>,
}

impl Verifier {
    /// A single-key verifier.
    pub fn from_public_der(der: &[u8]) -> Result<Self, TokenError> {
        Ok(Self { keys: vec![PublicKey::from_der(der).map_err(map_rsa)?] })
    }

    /// A multi-key verifier (rotation window): a token verifies if ANY held key accepts it.
    pub fn from_public_ders(ders: &[Vec<u8>]) -> Result<Self, TokenError> {
        if ders.is_empty() {
            return Err(TokenError::Rsa("verifier needs at least one public key".into()));
        }
        let keys = ders
            .iter()
            .map(|d| PublicKey::from_der(d).map_err(map_rsa))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }

    /// Verify a redeemed token: is `token_sig` a signature over `msg` under any held key?
    pub fn verify(&self, token_sig: &[u8], msg: &[u8]) -> bool {
        let sig = Signature(token_sig.to_vec());
        self.keys.iter().any(|pk| pk.verify(&sig, None, msg).is_ok())
    }

    /// Number of public keys held (> 1 during a rotation window).
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

/// Client-held blinding state, kept between `blind` and `finalize`.
pub struct TokenRequest {
    /// The blinded message to send to the issuer.
    pub blind_msg: Vec<u8>,
    /// The original (unblinded) token message.
    pub msg: Vec<u8>,
    state: BlindingResult,
}

/// Client: blind a fresh random token `msg` under the issuer's public key.
pub fn blind(public_der: &[u8], msg: &[u8]) -> Result<TokenRequest, TokenError> {
    let pk = PublicKey::from_der(public_der).map_err(map_rsa)?;
    let result = pk.blind(&mut DefaultRng, msg).map_err(map_rsa)?;
    Ok(TokenRequest { blind_msg: result.blind_message.0.clone(), msg: msg.to_vec(), state: result })
}

/// Client: unblind the issuer's blind signature into the final token signature.
pub fn finalize(public_der: &[u8], req: &TokenRequest, blind_sig: &[u8]) -> Result<Vec<u8>, TokenError> {
    let pk = PublicKey::from_der(public_der).map_err(map_rsa)?;
    let sig = pk
        .finalize(&BlindSignature(blind_sig.to_vec()), &req.state, &req.msg)
        .map_err(map_rsa)?;
    Ok(sig.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_msg() -> Vec<u8> {
        let mut m = [0u8; 32];
        getrandom_fill(&mut m);
        m.to_vec()
    }
    fn getrandom_fill(b: &mut [u8]) {
        // The PSK module already pulls an OS RNG transitively; use a simple counter+hash here
        // to avoid an extra dep — randomness only needs to differ per token for the test.
        use sha2::{Digest, Sha256};
        let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let h = Sha256::digest(seed.to_le_bytes());
        b.copy_from_slice(&h[..b.len().min(32)]);
    }

    #[test]
    fn issue_then_verify_round_trips() {
        let issuer = Issuer::generate().unwrap();
        let pub_der = issuer.public_der().unwrap();
        let msg = token_msg();

        // Client blinds; issuer signs the blinded message; client unblinds.
        let req = blind(&pub_der, &msg).unwrap();
        let blind_sig = issuer.blind_sign(&req.blind_msg).unwrap();
        let token = finalize(&pub_der, &req, &blind_sig).unwrap();

        // Verifier (public key only) accepts the redeemed token.
        let verifier = Verifier::from_public_der(&pub_der).unwrap();
        assert!(verifier.verify(&token, &msg), "issued token must verify");
        assert!(!verifier.verify(&token, b"a different message"), "token must not verify for another msg");
        assert!(!verifier.verify(&vec![0u8; token.len()], &msg), "a forged signature must not verify");
    }

    #[test]
    fn issuer_view_is_unlinkable_to_the_token() {
        // The issuer sees only the blinded message; the verifier sees the unblinded token.
        // They are different byte strings, so the issuer cannot recognize the token it signed
        // (the cryptographic unlinkability of blind RSA — here asserted at the byte level).
        let issuer = Issuer::generate().unwrap();
        let pub_der = issuer.public_der().unwrap();
        let msg = token_msg();
        let req = blind(&pub_der, &msg).unwrap();
        let blind_sig = issuer.blind_sign(&req.blind_msg).unwrap();
        let token = finalize(&pub_der, &req, &blind_sig).unwrap();
        assert_ne!(req.blind_msg, token, "the issuer's blinded view differs from the token");
        assert_ne!(blind_sig, token, "the blind signature differs from the unblinded token");
    }

    #[test]
    fn verifier_cannot_be_built_from_a_bad_key() {
        assert!(Verifier::from_public_der(b"not a der key").is_err());
    }

    #[test]
    fn multi_key_verifier_accepts_either_key_during_rotation() {
        // Old + new issuer keys (a rotation window).
        let old = Issuer::generate().unwrap();
        let new = Issuer::generate().unwrap();
        let old_pk = old.public_der().unwrap();
        let new_pk = new.public_der().unwrap();

        // A token minted under the OLD key.
        let msg = token_msg();
        let req = blind(&old_pk, &msg).unwrap();
        let token = finalize(&old_pk, &req, &old.blind_sign(&req.blind_msg).unwrap()).unwrap();

        // The verifier holding BOTH keys still accepts it (zero-downtime rotation).
        let rotating = Verifier::from_public_ders(&[old_pk.clone(), new_pk.clone()]).unwrap();
        assert_eq!(rotating.key_count(), 2);
        assert!(rotating.verify(&token, &msg), "old-key token must verify during the rotation window");

        // Once the old key is retired (verifier holds only the new key), the old token is refused.
        let new_only = Verifier::from_public_ders(&[new_pk]).unwrap();
        assert!(!new_only.verify(&token, &msg), "after rotation completes, old-key tokens are refused");
    }
}
