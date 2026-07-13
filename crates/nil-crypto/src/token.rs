//! Privacy Pass blind bearer tokens (architecture spec §7) — RFC 9474 blind RSA
//! signatures (RSABSSA-SHA384-PSS) under the RFC 9578 token model.
//!
//! Trust split (Pillar 4): the **issuer** (in `nil-portal`) holds the RSA *private* key and
//! blind-signs; the **verifier** (in `nil-coordinator`) holds only the *public* key and checks
//! redeemed tokens. Blinding prevents a direct cryptographic join from the issuer's blinded
//! transcript to the later unblinded credential: the issuer never sees the message it signs, and
//! the verifier can check but not mint. This does not remove timing, network, batch-size, payment,
//! or small-population correlation; see `THREAT_MODEL.md`.
//!
//! Flow: client picks a random token message → `blind` → issuer `blind_sign` → client
//! `finalize` (unblind) → presents `(msg, token)` to the verifier → `verify`. The Coordinator
//! additionally keeps a spent-token nullifier set (no identity) to stop double-spends.

use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng, Error as RsaError,
    KeyPairSha384PSSDeterministic as KeyPair, MessageRandomizer,
    PublicKeySha384PSSDeterministic as PublicKey, Secret,
    SecretKeySha384PSSDeterministic as SecretKey, Signature,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RSA modulus size for the token key (RFC 9474 requires ≥ 2048).
pub const TOKEN_MODULUS_BITS: usize = 2048;
/// Versioned token-message prefix. The expiry is inside the blinded message, so the issuer never
/// learns it but the Coordinator can enforce a bounded bearer lifetime at redemption.
pub const V2_MAGIC: [u8; 4] = *b"NTV2";
pub const V2_VALIDITY_SECS: u64 = 24 * 60 * 60;
pub const V2_EPOCH_SECS: u64 = 60 * 60;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("blind-rsa error: {0}")]
    Rsa(String),
}

/// Create a v2 token message with a one-day coarse expiry and 20 bytes of fresh entropy.
pub fn new_v2_message() -> Result<[u8; 32], TokenError> {
    let mut messages = new_v2_message_batch(1)?;
    messages
        .pop()
        .ok_or_else(|| TokenError::Rsa("token batch unexpectedly empty".to_string()))
}

/// Create a batch whose messages all use one expiry calculated from one clock read. This keeps an
/// issuance batch in a single coarse anonymity cohort even if generation crosses an hourly
/// boundary; every message still carries independent OS-generated entropy.
pub fn new_v2_message_batch(count: usize) -> Result<Vec<[u8; 32]>, TokenError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| TokenError::Rsa(format!("clock: {e}")))?
        .as_secs();
    let expiry = ((now / V2_EPOCH_SECS) + (V2_VALIDITY_SECS / V2_EPOCH_SECS)) * V2_EPOCH_SECS;
    let mut messages = Vec::new();
    messages
        .try_reserve_exact(count)
        .map_err(|e| TokenError::Rsa(format!("token batch allocation: {e}")))?;
    for _ in 0..count {
        let mut msg = [0u8; 32];
        msg[..4].copy_from_slice(&V2_MAGIC);
        msg[4..12].copy_from_slice(&expiry.to_be_bytes());
        getrandom::getrandom(&mut msg[12..])
            .map_err(|e| TokenError::Rsa(format!("token entropy: {e}")))?;
        messages.push(msg);
    }
    Ok(messages)
}

pub fn is_v2_message(msg: &[u8]) -> bool {
    msg.len() == 32 && msg[..4] == V2_MAGIC
}

/// Validate a v2 expiry at redemption. A client may choose an expiry within the configured window,
/// but cannot create a token valid arbitrarily far in the future.
pub fn v2_message_is_current(msg: &[u8], now: u64) -> bool {
    if !is_v2_message(msg) {
        return false;
    }
    let Ok(expiry_bytes) = <[u8; 8]>::try_from(&msg[4..12]) else {
        return false;
    };
    let expiry = u64::from_be_bytes(expiry_bytes);
    expiry >= now && expiry <= now.saturating_add(V2_VALIDITY_SECS + V2_EPOCH_SECS)
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
        Ok(Self {
            kp: KeyPair { pk, sk },
        })
    }

    /// Export the private key (DER) — Portal-only; never leaves the issuer trust domain.
    pub fn secret_der(&self) -> Result<Vec<u8>, TokenError> {
        self.kp.sk.to_der().map_err(map_rsa)
    }

    /// Export the public key (DER) — handed to clients and the verifier.
    pub fn public_der(&self) -> Result<Vec<u8>, TokenError> {
        self.kp.pk.to_der().map_err(map_rsa)
    }

    /// Blind-sign a client's blinded token request. The issuer never sees the unblinded token, so
    /// this transcript contains no direct cryptographic join key for a later redemption. External
    /// timing/network observations remain outside this primitive's guarantee.
    pub fn blind_sign(&self, blind_msg: &[u8]) -> Result<Vec<u8>, TokenError> {
        self.kp
            .sk
            .blind_sign(blind_msg)
            .map(|s| s.0)
            .map_err(map_rsa)
    }
}

/// The reserved epoch for MIGRATED legacy nullifiers (tokens spent before key-derived epochs
/// existed, under a single untagged issuer key). [`key_epoch`] never produces 0, so this never
/// collides with a real key's epoch; the Coordinator always retains this partition.
pub const LEGACY_EPOCH: u32 = 0;

/// The epoch id DERIVED from an issuer public key (DER): the first 4 bytes of SHA-256(DER) as a
/// big-endian u32, forced to be `>= 1` (0 is reserved — see [`LEGACY_EPOCH`]).
///
/// Deriving the epoch from the KEY — never from an operator-assigned number — is what makes
/// nullifier GC safe: a token's stored epoch and the *retained* epoch of its signing key can never
/// diverge, so a partition is dropped if and only if its signing key is no longer held. Renumbering
/// a still-held key (which would drop its live nullifiers and reopen a double-spend) is impossible
/// by construction. A 32-bit id can collide across keys with probability ~2^-32; a collision only
/// ever causes two keys to SHARE a partition, so GC over-retains (safe), never under-retains.
pub fn key_epoch(public_der: &[u8]) -> u32 {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(public_der);
    let id = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    if id == LEGACY_EPOCH {
        1 // keep 0 reserved for legacy migration
    } else {
        id
    }
}

/// Verifier side (Coordinator trust domain): holds only public key(s).
///
/// It can hold MORE THAN ONE public key so issuer keys rotate without downtime: during a
/// rotation both the old and new key are accepted, so a token minted under either verifies
/// (architecture spec §7 / runbook §9). The private key never reaches this trust domain.
pub struct Verifier {
    /// Each key is tagged with its KEY-DERIVED epoch ([`key_epoch`]) — a stable function of the key
    /// itself, NOT an operator-chosen number. A token verifies if any held key accepts it;
    /// `verify_with_epoch` reports the deriving key's epoch so the Coordinator partitions spent-token
    /// nullifiers by it. Because the epoch is BOUND to the key, a partition is GC'd exactly when its
    /// key is retired — never while the key is still held (the renumbering double-spend is impossible).
    keys: Vec<(u32, PublicKey)>,
}

impl Verifier {
    /// A single-key verifier (epoch derived from the key).
    pub fn from_public_der(der: &[u8]) -> Result<Self, TokenError> {
        let key = PublicKey::from_der(der).map_err(map_rsa)?;
        Ok(Self {
            keys: vec![(key_epoch(der), key)],
        })
    }

    /// A multi-key verifier (rotation window): a token verifies if ANY held key accepts it. Each
    /// key's epoch is DERIVED from the key ([`key_epoch`]). Duplicate keys are harmless — they map
    /// to the same epoch (same partition), so attribution and GC stay consistent.
    pub fn from_public_ders(ders: &[Vec<u8>]) -> Result<Self, TokenError> {
        if ders.is_empty() {
            return Err(TokenError::Rsa(
                "verifier needs at least one public key".into(),
            ));
        }
        let keys = ders
            .iter()
            .map(|d| {
                PublicKey::from_der(d)
                    .map(|k| (key_epoch(d), k))
                    .map_err(map_rsa)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }

    /// Verify a redeemed token: is `token_sig` a signature over `msg` under any held key?
    pub fn verify(&self, token_sig: &[u8], msg: &[u8]) -> bool {
        self.verify_with_epoch(token_sig, msg).is_some()
    }

    /// Like [`Self::verify`], but on success returns the KEY-DERIVED EPOCH of the key that verified
    /// the token. A token whose signing key is no longer held returns `None` — that redeem-time
    /// rejection is exactly what makes dropping that epoch's nullifiers safe (a token that can't
    /// verify can never re-enter the nullifier set). A token is signed by exactly one key.
    pub fn verify_with_epoch(&self, token_sig: &[u8], msg: &[u8]) -> Option<u32> {
        let sig = Signature(token_sig.to_vec());
        self.keys
            .iter()
            .find(|(_, pk)| pk.verify(&sig, None, msg).is_ok())
            .map(|(e, _)| *e)
    }

    /// The set of (key-derived) epochs this verifier currently accepts. The Coordinator unions this
    /// with [`LEGACY_EPOCH`] as the `retained` set for nullifier GC: a partition is dropped iff its
    /// epoch is NOT here — i.e. iff its signing key is no longer held.
    pub fn epochs(&self) -> std::collections::BTreeSet<u32> {
        self.keys.iter().map(|(e, _)| *e).collect()
    }

    /// Number of public keys held (> 1 during a rotation window / when multiple epochs are live).
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

/// Serializable-equivalent client blinding state. Persistence policy belongs to the caller; every
/// field is secret/bearer-adjacent and is eagerly scrubbed on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PersistedTokenRequest {
    pub blind_msg: Vec<u8>,
    pub msg: Vec<u8>,
    pub secret: Vec<u8>,
    pub msg_randomizer: Option<[u8; 32]>,
}

impl std::fmt::Debug for PersistedTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersistedTokenRequest([REDACTED])")
    }
}

impl TokenRequest {
    pub fn export_persisted(&self) -> PersistedTokenRequest {
        PersistedTokenRequest {
            blind_msg: self.blind_msg.clone(),
            msg: self.msg.clone(),
            secret: self.state.secret.0.clone(),
            msg_randomizer: self.state.msg_randomizer.map(|value| value.0),
        }
    }

    pub fn from_persisted(persisted: &PersistedTokenRequest) -> Result<Self, TokenError> {
        let modulus_bytes = TOKEN_MODULUS_BITS / 8;
        if persisted.blind_msg.len() != modulus_bytes
            || persisted.secret.len() != modulus_bytes
            || persisted.msg.len() != 32
        {
            return Err(TokenError::Rsa(
                "persisted token request has invalid field lengths".to_string(),
            ));
        }
        Ok(Self {
            blind_msg: persisted.blind_msg.clone(),
            msg: persisted.msg.clone(),
            state: BlindingResult {
                blind_message: BlindMessage(persisted.blind_msg.clone()),
                secret: Secret(persisted.secret.clone()),
                msg_randomizer: persisted.msg_randomizer.map(MessageRandomizer),
            },
        })
    }
}

impl Drop for TokenRequest {
    fn drop(&mut self) {
        self.blind_msg.zeroize();
        self.msg.zeroize();
        self.state.blind_message.0.zeroize();
        self.state.secret.0.zeroize();
        if let Some(randomizer) = self.state.msg_randomizer.as_mut() {
            randomizer.0.zeroize();
        }
    }
}

/// Client: blind a fresh random token `msg` under the issuer's public key.
pub fn blind(public_der: &[u8], msg: &[u8]) -> Result<TokenRequest, TokenError> {
    let pk = PublicKey::from_der(public_der).map_err(map_rsa)?;
    let result = pk.blind(&mut DefaultRng, msg).map_err(map_rsa)?;
    Ok(TokenRequest {
        blind_msg: result.blind_message.0.clone(),
        msg: msg.to_vec(),
        state: result,
    })
}

/// Client: unblind the issuer's blind signature into the final token signature.
pub fn finalize(
    public_der: &[u8],
    req: &TokenRequest,
    blind_sig: &[u8],
) -> Result<Vec<u8>, TokenError> {
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
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
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
        assert!(
            !verifier.verify(&token, b"a different message"),
            "token must not verify for another msg"
        );
        assert!(
            !verifier.verify(&vec![0u8; token.len()], &msg),
            "a forged signature must not verify"
        );
    }

    #[test]
    fn exported_blinding_state_reconstructs_the_exact_request() {
        let issuer = Issuer::generate().unwrap();
        let public = issuer.public_der().unwrap();
        let msg = token_msg();
        let original = blind(&public, &msg).unwrap();
        let persisted = original.export_persisted();
        let restored = TokenRequest::from_persisted(&persisted).unwrap();
        assert_eq!(restored.blind_msg, original.blind_msg);
        assert_eq!(restored.msg, original.msg);

        let blind_signature = issuer.blind_sign(&original.blind_msg).unwrap();
        assert_eq!(
            finalize(&public, &original, &blind_signature).unwrap(),
            finalize(&public, &restored, &blind_signature).unwrap()
        );
        assert_eq!(
            format!("{persisted:?}"),
            "PersistedTokenRequest([REDACTED])"
        );
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
        assert_ne!(
            req.blind_msg, token,
            "the issuer's blinded view differs from the token"
        );
        assert_ne!(
            blind_sig, token,
            "the blind signature differs from the unblinded token"
        );
    }

    #[test]
    fn verifier_cannot_be_built_from_a_bad_key() {
        assert!(Verifier::from_public_der(b"not a der key").is_err());
    }

    #[test]
    fn v2_message_has_a_bounded_future_expiry() {
        let msg = new_v2_message().expect("v2 message");
        assert!(is_v2_message(&msg));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        assert!(v2_message_is_current(&msg, now));
        assert!(!v2_message_is_current(
            &msg,
            now + V2_VALIDITY_SECS + V2_EPOCH_SECS + 1
        ));
    }

    #[test]
    fn v2_batch_shares_one_coarse_expiry_and_has_fresh_entropy() {
        let messages = new_v2_message_batch(8).expect("v2 batch");
        assert_eq!(messages.len(), 8);
        let expiry = &messages[0][4..12];
        assert!(messages.iter().all(|message| &message[4..12] == expiry));
        for (index, message) in messages.iter().enumerate() {
            assert!(is_v2_message(message));
            assert!(messages[index + 1..]
                .iter()
                .all(|other| other[12..] != message[12..]));
        }
    }

    #[test]
    fn v2_message_rejects_far_future_expiry() {
        let mut msg = [0u8; 32];
        msg[..4].copy_from_slice(&V2_MAGIC);
        msg[4..12].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
        assert!(!v2_message_is_current(&msg, 1));
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
        assert!(
            rotating.verify(&token, &msg),
            "old-key token must verify during the rotation window"
        );

        // Once the old key is retired (verifier holds only the new key), the old token is refused.
        let new_only = Verifier::from_public_ders(&[new_pk]).unwrap();
        assert!(
            !new_only.verify(&token, &msg),
            "after rotation completes, old-key tokens are refused"
        );
    }

    #[test]
    fn verify_with_epoch_reports_the_key_derived_epoch_and_none_when_retired() {
        // Two distinct issuer keys → two distinct KEY-DERIVED epochs. A token minted under key A.
        let a = Issuer::generate().unwrap();
        let b = Issuer::generate().unwrap();
        let a_pk = a.public_der().unwrap();
        let b_pk = b.public_der().unwrap();
        let ea = key_epoch(&a_pk);
        let eb = key_epoch(&b_pk);
        assert_ne!(ea, eb, "distinct keys derive distinct epochs");
        assert_ne!(
            ea, LEGACY_EPOCH,
            "a derived epoch is never the reserved legacy 0"
        );

        let msg = token_msg();
        let req = blind(&a_pk, &msg).unwrap();
        let token = finalize(&a_pk, &req, &a.blind_sign(&req.blind_msg).unwrap()).unwrap();

        // While both keys are held, the token verifies AND reports key A's derived epoch — the
        // partition the Coordinator records the nullifier under.
        let v = Verifier::from_public_ders(&[a_pk.clone(), b_pk.clone()]).unwrap();
        assert_eq!(v.verify_with_epoch(&token, &msg), Some(ea));
        assert_eq!(v.epochs(), std::collections::BTreeSet::from([ea, eb]));

        // Retire key A (verifier holds only key B): the token no longer verifies → None. This is
        // the redeem-time rejection that makes dropping key A's nullifier partition safe.
        let retired = Verifier::from_public_ders(&[b_pk]).unwrap();
        assert_eq!(retired.verify_with_epoch(&token, &msg), None);
        assert!(!retired.verify(&token, &msg));

        // A forged signature verifies under no epoch.
        assert_eq!(v.verify_with_epoch(b"forged-not-a-signature", &msg), None);

        // The epoch is STABLE per key: re-adding the SAME key (cannot be "renumbered") yields the
        // same partition, so its live nullifiers are never dropped while the key is held.
        assert_eq!(
            key_epoch(&a_pk),
            ea,
            "key_epoch is a stable function of the key"
        );
        let re_added = Verifier::from_public_der(&a_pk).unwrap();
        assert_eq!(re_added.verify_with_epoch(&token, &msg), Some(ea));
    }
}
