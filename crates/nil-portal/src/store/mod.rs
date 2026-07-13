//! Account persistence behind a trait, so the backend is swappable (in-memory for
//! Phase 0; Postgres in Phase 1 — ADR-0003).

pub mod file;
pub mod memory;
#[cfg(feature = "postgres")]
pub mod postgres;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::account::model::{AccountRecord, Entitlement};

// ---- Shared PII-free encoding for the durable backends (file + Postgres), kept here so the two
// can never drift on how an account is serialized. Each persists exactly H(secret), entitlement,
// and the anonymous public authentication key — no recovery material or identity. ---------------

pub(crate) fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex32(s: &str) -> Option<[u8; 32]> {
    let h = s.as_bytes();
    if h.len() != 64 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = [0u8; 32];
    for (i, p) in h.chunks_exact(2).enumerate() {
        out[i] = (nib(p[0])? << 4) | nib(p[1])?;
    }
    Some(out)
}

/// Serialize an entitlement to the store's TEXT column. An active subscription encodes its expiry as
/// `active:<unix_secs>` so the durable record round-trips the `until`; `none`/`expired` are bare.
pub(crate) fn ent_str(e: Entitlement) -> String {
    match e {
        Entitlement::None => "none".to_string(),
        Entitlement::Active { until } => format!("active:{until}"),
        Entitlement::Expired => "expired".to_string(),
    }
}

pub(crate) fn ent_from(s: &str) -> Option<Entitlement> {
    match s {
        "none" => Some(Entitlement::None),
        "expired" => Some(Entitlement::Expired),
        // Back-compat: a legacy bare "active" (pre-expiry rows) reads as already-lapsed, so a
        // pre-ADR-0007 row can never grant unlimited access — it must be re-activated by a payment.
        "active" => Some(Entitlement::Expired),
        other => other
            .strip_prefix("active:")
            .and_then(|u| u.parse::<u64>().ok())
            .map(|until| Entitlement::Active { until }),
    }
}

/// Serialize the account auth public key (ADR-0007) to the store's TEXT column: lowercase hex.
pub(crate) fn auth_str(pk: &[u8; 32]) -> String {
    hex32(pk)
}

/// Parse an auth-public-key column. An EMPTY column is a legacy/pre-ADR-0007 row that predates the
/// auth key: it maps to the all-zero sentinel, which can never pass auth (so such an account simply
/// can't use the subscription flows until re-created — fail-closed). Any other value must be valid
/// 32-byte hex.
pub(crate) fn auth_from(s: &str) -> Option<[u8; 32]> {
    if s.is_empty() {
        return Some([0u8; 32]);
    }
    unhex32(s)
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("account already exists")]
    Duplicate,
    /// The store backend failed (e.g. the durable file could not be written). Callers fail
    /// closed: the account is not created.
    #[error("store backend error: {0}")]
    Backend(String),
}

const RESULT_AAD_DOMAIN: &[u8] = b"nilvpn.portal-result.v1";
const RESULT_NONCE_LEN: usize = 12;
const RESULT_TAG_LEN: usize = 16;
const RAW_SIGNATURE_BYTES: usize = nil_proto::token::BLIND_TOKEN_HEX_LEN / 2;
const MAX_RESULT_PLAINTEXT_BYTES: usize =
    1 + nil_proto::token::MAX_MINT_BATCH_SIZE * RAW_SIGNATURE_BYTES;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ResultKind {
    OneShot = 1,
    SubscriptionMint = 2,
}

/// Encrypts replay payloads independently from the issuer signing key. Associated data binds a
/// ciphertext to its table purpose, hashed operation key, request hash, and logical expiry, so a
/// database/file attacker cannot transplant a valid result into another operation.
#[derive(Clone)]
pub(crate) struct ResultCipher {
    key: zeroize::Zeroizing<[u8; 32]>,
}

impl ResultCipher {
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self {
            key: zeroize::Zeroizing::new(key),
        }
    }

    fn aad(
        kind: ResultKind,
        operation_key: &[u8; 32],
        request_hash: &[u8; 32],
        expires_at: u64,
    ) -> zeroize::Zeroizing<Vec<u8>> {
        let mut aad = zeroize::Zeroizing::new(Vec::with_capacity(
            RESULT_AAD_DOMAIN.len() + 1 + 32 + 32 + 8,
        ));
        aad.extend_from_slice(RESULT_AAD_DOMAIN);
        aad.push(kind as u8);
        aad.extend_from_slice(operation_key);
        aad.extend_from_slice(request_hash);
        aad.extend_from_slice(&expires_at.to_be_bytes());
        aad
    }

    pub(crate) fn seal(
        &self,
        kind: ResultKind,
        operation_key: &[u8; 32],
        request_hash: &[u8; 32],
        expires_at: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        if plaintext.is_empty() || plaintext.len() > MAX_RESULT_PLAINTEXT_BYTES {
            return Err(StoreError::Backend(
                "portal replay result is empty or exceeds its fixed bound".into(),
            ));
        }
        let mut nonce = [0u8; RESULT_NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| StoreError::Backend("portal replay nonce entropy unavailable".into()))?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| StoreError::Backend("invalid portal result key".into()))?;
        let aad = Self::aad(kind, operation_key, request_hash, expires_at);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Backend("encrypt portal replay result".into()))?;
        let mut stored = Vec::with_capacity(RESULT_NONCE_LEN + encrypted.len());
        stored.extend_from_slice(&nonce);
        stored.extend_from_slice(&encrypted);
        Ok(stored)
    }

    pub(crate) fn open(
        &self,
        kind: ResultKind,
        operation_key: &[u8; 32],
        request_hash: &[u8; 32],
        expires_at: u64,
        stored: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError> {
        if !(RESULT_NONCE_LEN + RESULT_TAG_LEN
            ..=RESULT_NONCE_LEN + RESULT_TAG_LEN + MAX_RESULT_PLAINTEXT_BYTES)
            .contains(&stored.len())
        {
            return Err(StoreError::Backend(
                "portal replay ciphertext has an invalid length".into(),
            ));
        }
        let (nonce, ciphertext) = stored.split_at(RESULT_NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| StoreError::Backend("invalid portal result key".into()))?;
        let aad = Self::aad(kind, operation_key, request_hash, expires_at);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Backend("portal replay authentication failed".into()))?;
        if plaintext.is_empty() || plaintext.len() > MAX_RESULT_PLAINTEXT_BYTES {
            return Err(StoreError::Backend(
                "portal replay plaintext has an invalid length".into(),
            ));
        }
        Ok(zeroize::Zeroizing::new(plaintext))
    }
}

pub(crate) fn encode_mint_payload(
    signatures: &[Vec<u8>],
) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError> {
    if signatures.is_empty() || signatures.len() > nil_proto::token::MAX_MINT_BATCH_SIZE {
        return Err(StoreError::Backend(
            "refusing to persist an invalid mint signature batch size".into(),
        ));
    }
    let mut encoded = zeroize::Zeroizing::new(Vec::with_capacity(
        1 + signatures.len() * RAW_SIGNATURE_BYTES,
    ));
    encoded.push(signatures.len() as u8);
    for signature in signatures {
        if signature.len() != RAW_SIGNATURE_BYTES {
            return Err(StoreError::Backend(
                "refusing to persist a wrong-length mint signature".into(),
            ));
        }
        encoded.extend_from_slice(signature);
    }
    Ok(encoded)
}

pub(crate) fn decode_mint_payload(payload: &[u8]) -> Result<Vec<Vec<u8>>, StoreError> {
    let Some((&count, signatures)) = payload.split_first() else {
        return Err(StoreError::Backend("mint replay payload is empty".into()));
    };
    let count = usize::from(count);
    if count == 0
        || count > nil_proto::token::MAX_MINT_BATCH_SIZE
        || signatures.len() != count * RAW_SIGNATURE_BYTES
    {
        return Err(StoreError::Backend(
            "mint replay payload has an invalid shape".into(),
        ));
    }
    Ok(signatures
        .chunks_exact(RAW_SIGNATURE_BYTES)
        .map(ToOwned::to_owned)
        .collect())
}

/// Authoritative account/window charge coupled to the first stored mint result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintQuota {
    pub quota_key: [u8; 32],
    pub window_start: u64,
    pub window_end: u64,
    pub cost: u32,
    pub max: u32,
}

impl MintQuota {
    pub(crate) fn is_well_formed(self, now_secs: u64) -> bool {
        self.window_start <= now_secs
            && now_secs < self.window_end
            && self.cost != 0
            && self.max != 0
    }
}

/// Result of atomically applying one confirmed subscription payment.
///
/// The store persists the `until` alongside the hashed activation key. A retry therefore returns
/// the exact first result without extending the account a second time, including after an
/// ambiguous network response or process restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionActivation {
    NewlyActivated { until: u64 },
    Replay { until: u64 },
}

/// Completed one-shot blind issuance, stored under a domain-separated hash of the opaque checkout
/// reference. The blinded request hash prevents one paid reference from being rebound to a second
/// token, while the cached signature makes an ambiguous response safely replayable.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct IssuanceResult {
    pub request_hash: [u8; 32],
    pub blind_sig: Vec<u8>,
    /// After this bound the signature is scrubbed while the request-bound spent claim remains.
    pub replay_until: u64,
}

impl std::fmt::Debug for IssuanceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuanceResult([REDACTED])")
    }
}

#[derive(PartialEq, Eq)]
pub enum IssuanceLookup {
    Missing,
    Replay { blind_sig: Vec<u8> },
    Conflict,
}

impl std::fmt::Debug for IssuanceLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("IssuanceLookup::Missing"),
            Self::Replay { .. } => f.write_str("IssuanceLookup::Replay([REDACTED])"),
            Self::Conflict => f.write_str("IssuanceLookup::Conflict"),
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum IssuanceCommit {
    Stored,
    Replay { blind_sig: Vec<u8> },
    Conflict,
}

/// Short-lived completed subscription mint. V2 keys a batch by a random client request ID; v1
/// deterministically keys its single item by canonical account plus blinded request.
/// `request_hash` binds the authenticated account and exact ordered decoded messages.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MintResult {
    pub request_hash: [u8; 32],
    pub blind_sigs: Vec<Vec<u8>>,
    pub expires_at: u64,
}

impl std::fmt::Debug for MintResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintResult")
            .field("signature_count", &self.blind_sigs.len())
            .finish_non_exhaustive()
    }
}

#[derive(PartialEq, Eq)]
pub enum MintLookup {
    Missing,
    Replay { blind_sigs: Vec<Vec<u8>> },
    Conflict,
}

impl std::fmt::Debug for MintLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("MintLookup::Missing"),
            Self::Replay { blind_sigs } => f
                .debug_struct("MintLookup::Replay")
                .field("signature_count", &blind_sigs.len())
                .finish_non_exhaustive(),
            Self::Conflict => f.write_str("MintLookup::Conflict"),
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum MintCommit {
    Stored,
    Replay { blind_sigs: Vec<Vec<u8>> },
    Conflict,
    QuotaExceeded,
}

impl std::fmt::Debug for MintCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stored => f.write_str("MintCommit::Stored"),
            Self::Replay { blind_sigs } => f
                .debug_struct("MintCommit::Replay")
                .field("signature_count", &blind_sigs.len())
                .finish_non_exhaustive(),
            Self::Conflict => f.write_str("MintCommit::Conflict"),
            Self::QuotaExceeded => f.write_str("MintCommit::QuotaExceeded"),
        }
    }
}

impl std::fmt::Debug for IssuanceCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stored => f.write_str("IssuanceCommit::Stored"),
            Self::Replay { .. } => f.write_str("IssuanceCommit::Replay([REDACTED])"),
            Self::Conflict => f.write_str("IssuanceCommit::Conflict"),
        }
    }
}

impl SubscriptionActivation {
    pub fn until(self) -> u64 {
        match self {
            Self::NewlyActivated { until } | Self::Replay { until } => until,
        }
    }
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Persist a new account record. Errors if the account number already exists.
    async fn insert(&self, record: AccountRecord) -> Result<(), StoreError>;
    /// Fetch an account by its number (= `H(secret)`), if present.
    async fn get(&self, account_number: &[u8; 32]) -> Result<Option<AccountRecord>, StoreError>;
    /// Atomically claim `activation_key` and extend the account by `by_secs`.
    ///
    /// A previously unseen key updates the account and stores the resulting expiry as one commit.
    /// A retry returns [`SubscriptionActivation::Replay`] with that cached expiry and performs no
    /// update. Distinct keys stack on the account's current persisted expiry. `None` means the
    /// account does not exist; in that case the key must remain unclaimed so a valid retry is still
    /// possible.
    async fn activate_subscription(
        &self,
        account_number: &[u8; 32],
        activation_key: &[u8; 32],
        now_secs: u64,
        by_secs: u64,
    ) -> Result<Option<SubscriptionActivation>, StoreError>;

    /// Read a completed one-shot issuance before invoking the external signer. `Conflict` means
    /// the checkout reference already completed for a different blinded request.
    async fn lookup_issuance(
        &self,
        issuance_key: &[u8; 32],
        request_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<IssuanceLookup, StoreError>;

    /// Atomically store the first completed signature, or return the cross-replica winner. A
    /// different request hash can never replace an existing result.
    async fn commit_issuance(
        &self,
        issuance_key: &[u8; 32],
        result: IssuanceResult,
        now_secs: u64,
    ) -> Result<IssuanceCommit, StoreError>;

    /// Scrub expired one-shot blind signatures while retaining each permanent request-bound spent
    /// claim. Returns the number of response payloads removed.
    async fn prune_issuance_results(&self, now_secs: u64) -> Result<usize, StoreError>;

    /// Look up an unexpired authenticated batch-mint result. Expired entries behave as missing and
    /// may be replaced; a live row with a different request hash is a conflict.
    async fn lookup_mint(
        &self,
        request_key: &[u8; 32],
        request_hash: &[u8; 32],
        now_secs: u64,
    ) -> Result<MintLookup, StoreError>;

    /// Atomically store the first live result for a random request id, or return the winner.
    async fn commit_mint(
        &self,
        request_key: &[u8; 32],
        result: MintResult,
        quota: MintQuota,
        now_secs: u64,
    ) -> Result<MintCommit, StoreError>;

    /// Delete logically expired mint responses and quota windows while preserving unrelated
    /// account/activation/issuance state. Returns the number of records removed.
    async fn prune_mint_results(&self, now_secs: u64) -> Result<usize, StoreError>;
}

#[cfg(test)]
mod ent_encoding_tests {
    use super::*;

    #[test]
    fn ent_str_round_trips_through_ent_from() {
        for e in [
            Entitlement::None,
            Entitlement::Expired,
            Entitlement::Active { until: 0 },
            Entitlement::Active {
                until: 1_900_000_000,
            },
            Entitlement::Active { until: u64::MAX },
        ] {
            let s = ent_str(e);
            assert_eq!(
                ent_from(&s),
                Some(e),
                "round-trip failed for {e:?} -> {s:?}"
            );
        }
    }

    #[test]
    fn active_encodes_its_expiry() {
        assert_eq!(ent_str(Entitlement::Active { until: 1_234 }), "active:1234");
        assert_eq!(ent_str(Entitlement::None), "none");
        assert_eq!(ent_str(Entitlement::Expired), "expired");
    }

    #[test]
    fn legacy_bare_active_reads_as_expired_not_unlimited() {
        // A pre-ADR-0007 row had a bare "active" with no expiry; it must NOT grant unlimited access.
        assert_eq!(ent_from("active"), Some(Entitlement::Expired));
    }

    #[test]
    fn malformed_entitlement_columns_are_rejected() {
        assert_eq!(ent_from("active:"), None);
        assert_eq!(ent_from("active:notanumber"), None);
        assert_eq!(ent_from("bogus"), None);
    }

    #[test]
    fn auth_pubkey_round_trips_and_handles_legacy_empty() {
        let pk = [0xab; 32];
        assert_eq!(auth_from(&auth_str(&pk)), Some(pk));
        // A legacy/pre-ADR-0007 row has no auth column → all-zero sentinel.
        assert_eq!(auth_from(""), Some([0u8; 32]));
        // Anything non-empty must be valid 32-byte hex.
        assert_eq!(auth_from("xyz"), None);
        assert_eq!(auth_from("ab"), None);
    }

    #[test]
    fn replay_cipher_authenticates_kind_key_request_and_expiry() {
        let cipher = ResultCipher::new([0x11; 32]);
        let operation = [0x22; 32];
        let request = [0x33; 32];
        let plaintext = vec![0x44; RAW_SIGNATURE_BYTES];
        let stored = cipher
            .seal(ResultKind::OneShot, &operation, &request, 1_234, &plaintext)
            .unwrap();
        assert_eq!(
            cipher
                .open(ResultKind::OneShot, &operation, &request, 1_234, &stored)
                .unwrap()
                .as_slice(),
            plaintext
        );
        assert!(cipher
            .open(
                ResultKind::SubscriptionMint,
                &operation,
                &request,
                1_234,
                &stored,
            )
            .is_err());
        assert!(cipher
            .open(ResultKind::OneShot, &[0x23; 32], &request, 1_234, &stored)
            .is_err());
        assert!(cipher
            .open(ResultKind::OneShot, &operation, &[0x34; 32], 1_234, &stored)
            .is_err());
        assert!(cipher
            .open(ResultKind::OneShot, &operation, &request, 1_235, &stored)
            .is_err());
    }

    #[test]
    fn mint_payload_encoding_is_fixed_width_and_bounded() {
        let signatures = vec![
            vec![0x51; RAW_SIGNATURE_BYTES],
            vec![0x52; RAW_SIGNATURE_BYTES],
        ];
        let payload = encode_mint_payload(&signatures).unwrap();
        assert_eq!(decode_mint_payload(&payload).unwrap(), signatures);
        assert!(encode_mint_payload(&[]).is_err());
        assert!(decode_mint_payload(&[1, 2, 3]).is_err());
    }
}
