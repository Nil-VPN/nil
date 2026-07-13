//! Short-lived, audience-bound node grants.
//!
//! A grant is an opaque byte string carried by the client in CONNECT-IP. The Coordinator signs
//! one grant for each selected node; a node holds only Coordinator public keys and verifies that
//! the grant names its exact deployment realm, stable node identifier, path role, transport, TEE,
//! and 48-byte attested measurement.
//!
//! NWG2 has one canonical binary encoding. Every integer is unsigned big-endian and the Ed25519
//! signature covers every preceding byte:
//!
//! ```text
//! "NWG2"
//! || key_id[32]
//! || issued_at_unix_secs[8]
//! || expires_at_unix_secs[8]
//! || nonce[32]
//! || role[1]
//! || transport[1]
//! || tee[1]
//! || realm_len[2]
//! || node_id_len[2]
//! || realm[realm_len]
//! || node_id[node_id_len]
//! || measurement[48]
//! || tls_spki_sha256[32]
//! || previous_hop_present[1]
//! || previous_hop_ipv4[4]
//! || next_hop_present[1]
//! || next_hop_ipv4[4]
//! || next_hop_port[2]
//! || ed25519_signature[64]
//! ```
//!
//! `key_id` is `SHA-256("nilvpn.nwg2.key-id" || ed25519_public_key)`. It permits verifier-key
//! rotation without putting a shared signing secret on every node. The old symmetric NWG1 format
//! is intentionally rejected; there is no downgrade or migration parser in this module.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{Grant, Tee};

const MAGIC: &[u8; 4] = b"NWG2";
const LEGACY_MAGIC: &[u8; 4] = b"NWG1";
const KEY_ID_DOMAIN: &[u8] = b"nilvpn.nwg2.key-id";
const KEY_ID_LEN: usize = 32;
const NONCE_LEN: usize = 32;
const MEASUREMENT_LEN: usize = 48;
const TLS_SPKI_SHA256_LEN: usize = 32;
const PREVIOUS_HOP_LEN: usize = 1 + 4;
const NEXT_HOP_LEN: usize = 1 + 4 + 2;
const SIGNATURE_LEN: usize = 64;

const KEY_ID_OFFSET: usize = MAGIC.len();
const ISSUED_AT_OFFSET: usize = KEY_ID_OFFSET + KEY_ID_LEN;
const EXPIRES_AT_OFFSET: usize = ISSUED_AT_OFFSET + 8;
const NONCE_OFFSET: usize = EXPIRES_AT_OFFSET + 8;
const ROLE_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;
const TRANSPORT_OFFSET: usize = ROLE_OFFSET + 1;
const TEE_OFFSET: usize = TRANSPORT_OFFSET + 1;
const REALM_LEN_OFFSET: usize = TEE_OFFSET + 1;
const NODE_ID_LEN_OFFSET: usize = REALM_LEN_OFFSET + 2;
const IDENTIFIERS_OFFSET: usize = NODE_ID_LEN_OFFSET + 2;
const MIN_TOKEN_LEN: usize = IDENTIFIERS_OFFSET
    + 2
    + MEASUREMENT_LEN
    + TLS_SPKI_SHA256_LEN
    + PREVIOUS_HOP_LEN
    + NEXT_HOP_LEN
    + SIGNATURE_LEN;

/// Longest accepted deployment-realm or node identifier, in ASCII bytes.
pub const MAX_GRANT_IDENTIFIER_LEN: usize = 64;
/// Largest canonical NWG2 token, used by public protocol parsers to bound allocation before
/// decoding attacker-controlled header text.
pub const MAX_GRANT_TOKEN_LEN: usize = IDENTIFIERS_OFFSET
    + (2 * MAX_GRANT_IDENTIFIER_LEN)
    + MEASUREMENT_LEN
    + TLS_SPKI_SHA256_LEN
    + PREVIOUS_HOP_LEN
    + NEXT_HOP_LEN
    + SIGNATURE_LEN;
/// Largest lifetime the issuer may encode in a grant.
pub const MAX_GRANT_TTL_SECS: u64 = 600;
/// Maximum amount by which an issuer clock may be ahead of a verifier clock.
///
/// This tolerance applies only to `issued_at`. Expiry is exact: a grant is rejected when
/// `now >= expires_at`, with no grace period.
pub const MAX_GRANT_CLOCK_SKEW_SECS: u64 = 30;

/// The data-plane position authorized by a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GrantRole {
    Entry = 1,
    Middle = 2,
    Exit = 3,
}

impl GrantRole {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "entry" => Some(Self::Entry),
            "middle" => Some(Self::Middle),
            "exit" => Some(Self::Exit),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Middle => "middle",
            Self::Exit => "exit",
        }
    }

    fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Entry),
            2 => Some(Self::Middle),
            3 => Some(Self::Exit),
            _ => None,
        }
    }
}

/// The tunnel protocol authorized by a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GrantTransport {
    Masque = 1,
    AmneziaWg = 2,
    Wstunnel = 3,
    Reality = 4,
}

impl GrantTransport {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "masque" => Some(Self::Masque),
            "amnezia-wg" => Some(Self::AmneziaWg),
            "wstunnel" => Some(Self::Wstunnel),
            "reality" => Some(Self::Reality),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Masque => "masque",
            Self::AmneziaWg => "amnezia-wg",
            Self::Wstunnel => "wstunnel",
            Self::Reality => "reality",
        }
    }

    fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Masque),
            2 => Some(Self::AmneziaWg),
            3 => Some(Self::Wstunnel),
            4 => Some(Self::Reality),
            _ => None,
        }
    }
}

/// The stable node identity and capability to which a grant is bound.
///
/// Fields are private so every value necessarily passed canonical identifier validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantNodeIdentity {
    realm: String,
    node_id: String,
    role: GrantRole,
    transport: GrantTransport,
    tee: Tee,
    measurement: [u8; MEASUREMENT_LEN],
    tls_spki_sha256: [u8; TLS_SPKI_SHA256_LEN],
}

impl GrantNodeIdentity {
    pub fn new(
        realm: impl Into<String>,
        node_id: impl Into<String>,
        role: GrantRole,
        transport: GrantTransport,
        tee: Tee,
        measurement: [u8; MEASUREMENT_LEN],
        tls_spki_sha256: [u8; TLS_SPKI_SHA256_LEN],
    ) -> Result<Self, GrantError> {
        let realm = realm.into();
        validate_named_identifier("grant realm", &realm)?;
        let node_id = node_id.into();
        validate_named_identifier("grant node_id", &node_id)?;
        Ok(Self {
            realm,
            node_id,
            role,
            transport,
            tee,
            measurement,
            tls_spki_sha256,
        })
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub const fn role(&self) -> GrantRole {
        self.role
    }

    pub const fn transport(&self) -> GrantTransport {
        self.transport
    }

    pub const fn tee(&self) -> Tee {
        self.tee
    }

    pub const fn measurement(&self) -> &[u8; MEASUREMENT_LEN] {
        &self.measurement
    }

    /// SHA-256 of the exact DER SubjectPublicKeyInfo presented by this node's TLS certificate.
    /// This stable registry pin turns a node ID from a self-asserted label into a cryptographic
    /// audience: a clone with the same code measurement cannot redeem another node's grant.
    pub const fn tls_spki_sha256(&self) -> &[u8; TLS_SPKI_SHA256_LEN] {
        &self.tls_spki_sha256
    }
}

/// The exact node and ordered path neighbors authorized by a grant.
///
/// Entry grants name no predecessor and one exact IPv4/UDP next-hop socket. Middle grants name an
/// exact predecessor IPv4 and next-hop socket. Exit grants name no next hop; a multi-hop exit also
/// names its predecessor, while an explicit one-hop debug path has none. Keeping these invariants
/// in the constructor prevents open intermediate relays and role-reordered paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAudience {
    node: GrantNodeIdentity,
    previous_hop: Option<Ipv4Addr>,
    next_hop: Option<SocketAddrV4>,
}

impl GrantAudience {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        realm: impl Into<String>,
        node_id: impl Into<String>,
        role: GrantRole,
        transport: GrantTransport,
        tee: Tee,
        measurement: [u8; MEASUREMENT_LEN],
        tls_spki_sha256: [u8; TLS_SPKI_SHA256_LEN],
        previous_hop: Option<Ipv4Addr>,
        next_hop: Option<SocketAddrV4>,
    ) -> Result<Self, GrantError> {
        let node = GrantNodeIdentity::new(
            realm,
            node_id,
            role,
            transport,
            tee,
            measurement,
            tls_spki_sha256,
        )?;
        Self::from_node_identity(node, previous_hop, next_hop)
    }

    pub fn from_node_identity(
        node: GrantNodeIdentity,
        previous_hop: Option<Ipv4Addr>,
        next_hop: Option<SocketAddrV4>,
    ) -> Result<Self, GrantError> {
        match (node.role(), previous_hop, next_hop) {
            (GrantRole::Entry, None, Some(endpoint)) if endpoint.port() != 0 => {}
            (GrantRole::Middle, Some(_), Some(endpoint)) if endpoint.port() != 0 => {}
            (GrantRole::Exit, _, None) => {}
            _ => return Err(GrantError::InvalidNextHopPolicy),
        }
        Ok(Self {
            node,
            previous_hop,
            next_hop,
        })
    }

    pub fn node_identity(&self) -> &GrantNodeIdentity {
        &self.node
    }

    pub fn realm(&self) -> &str {
        self.node.realm()
    }

    pub fn node_id(&self) -> &str {
        self.node.node_id()
    }

    pub const fn role(&self) -> GrantRole {
        self.node.role()
    }

    pub const fn transport(&self) -> GrantTransport {
        self.node.transport()
    }

    pub const fn tee(&self) -> Tee {
        self.node.tee()
    }

    pub const fn measurement(&self) -> &[u8; MEASUREMENT_LEN] {
        self.node.measurement()
    }

    pub const fn tls_spki_sha256(&self) -> &[u8; TLS_SPKI_SHA256_LEN] {
        self.node.tls_spki_sha256()
    }

    pub const fn next_hop(&self) -> Option<SocketAddrV4> {
        self.next_hop
    }

    pub const fn previous_hop(&self) -> Option<Ipv4Addr> {
        self.previous_hop
    }
}

/// An Ed25519 grant issuer key.
///
/// The input is exactly the 32-byte Ed25519 seed. The inner key is zeroized on drop by
/// `ed25519-dalek`; `Debug` deliberately omits all key material.
#[derive(Clone)]
pub struct GrantSigningKey {
    signing_key: SigningKey,
}

impl fmt::Debug for GrantSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GrantSigningKey([REDACTED])")
    }
}

impl GrantSigningKey {
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { signing_key }
    }

    pub fn try_from_slice(seed: &[u8]) -> Result<Self, GrantError> {
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| GrantError::InvalidSigningKeyLength)?;
        Ok(Self::from_seed(seed))
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        key_id_for_public_key(&self.public_key_bytes())
    }
}

/// A rotation-capable set of trusted Coordinator grant-verification keys.
#[derive(Debug, Clone, Default)]
pub struct GrantVerifier {
    keys: HashMap<[u8; KEY_ID_LEN], VerifyingKey>,
}

impl GrantVerifier {
    /// Build a verifier from one or more raw Ed25519 public keys.
    pub fn new<I>(public_keys: I) -> Result<Self, GrantError>
    where
        I: IntoIterator<Item = [u8; 32]>,
    {
        let mut verifier = Self::default();
        for public_key in public_keys {
            verifier.add_public_key(public_key)?;
        }
        if verifier.keys.is_empty() {
            return Err(GrantError::NoVerificationKeys);
        }
        Ok(verifier)
    }

    pub fn from_public_key(public_key: [u8; 32]) -> Result<Self, GrantError> {
        Self::new([public_key])
    }

    /// Add a key for a staged rotation. Adding the same key twice is idempotent.
    pub fn add_public_key(&mut self, public_key: [u8; 32]) -> Result<[u8; KEY_ID_LEN], GrantError> {
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| GrantError::InvalidPublicKey)?;
        if verifying_key.is_weak() {
            return Err(GrantError::InvalidPublicKey);
        }
        let key_id = key_id_for_public_key(&public_key);
        if let Some(existing) = self.keys.get(&key_id) {
            if existing.to_bytes() != public_key {
                return Err(GrantError::KeyIdCollision);
            }
            return Ok(key_id);
        }
        self.keys.insert(key_id, verifying_key);
        Ok(key_id)
    }

    pub fn key_ids(&self) -> Vec<[u8; KEY_ID_LEN]> {
        let mut ids = self.keys.keys().copied().collect::<Vec<_>>();
        ids.sort_unstable();
        ids
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn contains_key_id(&self, key_id: &[u8; KEY_ID_LEN]) -> bool {
        self.keys.contains_key(key_id)
    }

    pub fn verify(
        &self,
        token: &[u8],
        expected_audience: &GrantAudience,
        now: u64,
    ) -> Result<VerifiedGrant, GrantError> {
        verify(token, self, expected_audience, now)
    }

    /// Verify a grant for this stable node identity and return its Coordinator-signed route.
    ///
    /// A node cannot know its next hop before reading the grant because path selection is dynamic.
    /// This method authenticates the entire token first, then compares every stable node field and
    /// returns the signed [`GrantAudience`] (including its exact next-hop policy).
    pub fn verify_for_node(
        &self,
        token: &[u8],
        expected_node: &GrantNodeIdentity,
        now: u64,
    ) -> Result<VerifiedGrant, GrantError> {
        verify_for_node(token, self, expected_node, now)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub key_id: [u8; KEY_ID_LEN],
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; NONCE_LEN],
    pub audience: GrantAudience,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("grant signing key must be exactly 32 bytes")]
    InvalidSigningKeyLength,
    #[error("grant verification key is not a valid, non-weak Ed25519 public key")]
    InvalidPublicKey,
    #[error("at least one grant verification key is required")]
    NoVerificationKeys,
    #[error("grant verification key ID collision")]
    KeyIdCollision,
    #[error("{0} must be 1..={MAX_GRANT_IDENTIFIER_LEN} bytes of canonical lowercase ASCII")]
    InvalidIdentifier(&'static str),
    #[error("grant TTL must be a whole number of seconds in 1..={MAX_GRANT_TTL_SECS}")]
    InvalidTtl,
    #[error("grant expiry overflows the Unix timestamp")]
    TimeOverflow,
    #[error("legacy NWG1 grants are not accepted")]
    LegacyGrantRejected,
    #[error("grant version is unsupported")]
    UnsupportedVersion,
    #[error("grant is malformed")]
    Malformed,
    #[error("grant names an unknown verification key")]
    UnknownKey,
    #[error("grant signature is invalid")]
    BadSignature,
    #[error("grant encodes an invalid lifetime")]
    InvalidLifetime,
    #[error("grant was issued too far in the future")]
    NotYetValid,
    #[error("grant expired")]
    Expired,
    #[error("grant predecessor/next-hop shape is incompatible with its path role")]
    InvalidNextHopPolicy,
    #[error("grant does not match this node audience")]
    WrongAudience,
}

/// Validate the canonical identifier grammar used by grant realms and node IDs.
///
/// Identifiers are 1 to 64 ASCII bytes, begin and end with a lowercase ASCII letter or digit, and
/// otherwise contain only lowercase letters, digits, `.`, `_`, `:`, or `-`. Validation never trims
/// or folds case, so each semantic identifier has one byte representation.
pub fn validate_identifier(identifier: &str) -> Result<(), GrantError> {
    validate_named_identifier("grant identifier", identifier)
}

fn validate_named_identifier(name: &'static str, identifier: &str) -> Result<(), GrantError> {
    let bytes = identifier.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_GRANT_IDENTIFIER_LEN {
        return Err(GrantError::InvalidIdentifier(name));
    }
    let is_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let is_inner = |byte: u8| is_edge(byte) || matches!(byte, b'.' | b'_' | b':' | b'-');
    if !is_edge(bytes[0])
        || !is_edge(bytes[bytes.len() - 1])
        || !bytes.iter().copied().all(is_inner)
    {
        return Err(GrantError::InvalidIdentifier(name));
    }
    Ok(())
}

/// Derive the on-wire key ID for an Ed25519 public key.
pub fn key_id_for_public_key(public_key: &[u8; 32]) -> [u8; KEY_ID_LEN] {
    let mut digest = Sha256::new();
    digest.update(KEY_ID_DOMAIN);
    digest.update(public_key);
    digest.finalize().into()
}

/// Decode lowercase/uppercase hex; `None` on odd length or a non-hex byte.
pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
    let h = hex.as_bytes();
    if h.len() % 2 != 0 {
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
    let mut out = Vec::with_capacity(h.len() / 2);
    for p in h.chunks_exact(2) {
        out.push((nib(p[0])? << 4) | nib(p[1])?);
    }
    Some(out)
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Current Unix time in seconds. On the (essentially impossible) clock-before-1970 error this
/// returns 0 — the fail-closed choice for issuance and TTL housekeeping: a grant or pending record
/// stamped at `now = 0` lands in the distant past, so it is born-expired / immediately prunable.
/// To test whether a deadline has passed, use [`now_unix_secs_for_expiry`] instead.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

/// Current Unix time for expiry gates. A clock-before-1970 failure returns `u64::MAX`, causing all
/// real grants to fail the exact-expiry check. Never use this value for minting.
pub fn now_unix_secs_for_expiry() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

pub fn mint(
    signing_key: &GrantSigningKey,
    audience: &GrantAudience,
    nonce: [u8; NONCE_LEN],
    ttl: Duration,
    now: u64,
) -> Result<Grant, GrantError> {
    validate_named_identifier("grant realm", audience.realm())?;
    validate_named_identifier("grant node_id", audience.node_id())?;
    let ttl_secs = ttl.as_secs();
    if ttl.subsec_nanos() != 0 || !(1..=MAX_GRANT_TTL_SECS).contains(&ttl_secs) {
        return Err(GrantError::InvalidTtl);
    }
    let expires_at = now.checked_add(ttl_secs).ok_or(GrantError::TimeOverflow)?;

    let realm = audience.realm().as_bytes();
    let node_id = audience.node_id().as_bytes();
    let realm_len =
        u16::try_from(realm.len()).map_err(|_| GrantError::InvalidIdentifier("grant realm"))?;
    let node_id_len =
        u16::try_from(node_id.len()).map_err(|_| GrantError::InvalidIdentifier("grant node_id"))?;
    let payload_len = IDENTIFIERS_OFFSET
        .checked_add(realm.len())
        .and_then(|len| len.checked_add(node_id.len()))
        .and_then(|len| len.checked_add(MEASUREMENT_LEN))
        .and_then(|len| len.checked_add(TLS_SPKI_SHA256_LEN))
        .and_then(|len| len.checked_add(PREVIOUS_HOP_LEN))
        .and_then(|len| len.checked_add(NEXT_HOP_LEN))
        .ok_or(GrantError::Malformed)?;
    let mut token = Vec::with_capacity(payload_len + SIGNATURE_LEN);
    token.extend_from_slice(MAGIC);
    token.extend_from_slice(&signing_key.key_id());
    token.extend_from_slice(&now.to_be_bytes());
    token.extend_from_slice(&expires_at.to_be_bytes());
    token.extend_from_slice(&nonce);
    token.push(audience.role() as u8);
    token.push(audience.transport() as u8);
    token.push(tee_to_wire(audience.tee()));
    token.extend_from_slice(&realm_len.to_be_bytes());
    token.extend_from_slice(&node_id_len.to_be_bytes());
    token.extend_from_slice(realm);
    token.extend_from_slice(node_id);
    token.extend_from_slice(audience.measurement());
    token.extend_from_slice(audience.tls_spki_sha256());
    match audience.previous_hop() {
        Some(ip) => {
            token.push(1);
            token.extend_from_slice(&ip.octets());
        }
        None => token.extend_from_slice(&[0; PREVIOUS_HOP_LEN]),
    }
    match audience.next_hop() {
        Some(endpoint) => {
            token.push(1);
            token.extend_from_slice(&endpoint.ip().octets());
            token.extend_from_slice(&endpoint.port().to_be_bytes());
        }
        None => token.extend_from_slice(&[0; NEXT_HOP_LEN]),
    }
    debug_assert_eq!(token.len(), payload_len);
    let signature = signing_key.signing_key.sign(&token);
    token.extend_from_slice(&signature.to_bytes());
    Ok(Grant { token, nonce })
}

pub fn verify(
    token: &[u8],
    verifier: &GrantVerifier,
    expected_audience: &GrantAudience,
    now: u64,
) -> Result<VerifiedGrant, GrantError> {
    let parsed = verify_authentic(token, verifier, now)?;
    if parsed.audience != *expected_audience {
        return Err(GrantError::WrongAudience);
    }

    Ok(parsed.into_verified())
}

pub fn verify_for_node(
    token: &[u8],
    verifier: &GrantVerifier,
    expected_node: &GrantNodeIdentity,
    now: u64,
) -> Result<VerifiedGrant, GrantError> {
    let parsed = verify_authentic(token, verifier, now)?;
    if parsed.audience.node_identity() != expected_node {
        return Err(GrantError::WrongAudience);
    }

    Ok(parsed.into_verified())
}

fn verify_authentic<'a>(
    token: &'a [u8],
    verifier: &GrantVerifier,
    now: u64,
) -> Result<ParsedGrant<'a>, GrantError> {
    let parsed = parse(token)?;
    let verifying_key = verifier
        .keys
        .get(&parsed.key_id)
        .ok_or(GrantError::UnknownKey)?;
    verifying_key
        .verify_strict(parsed.signed_payload, &parsed.signature)
        .map_err(|_| GrantError::BadSignature)?;

    let lifetime = parsed
        .expires_at
        .checked_sub(parsed.issued_at)
        .ok_or(GrantError::InvalidLifetime)?;
    if !(1..=MAX_GRANT_TTL_SECS).contains(&lifetime) {
        return Err(GrantError::InvalidLifetime);
    }
    if now >= parsed.expires_at {
        return Err(GrantError::Expired);
    }
    if parsed.issued_at.saturating_sub(now) > MAX_GRANT_CLOCK_SKEW_SECS {
        return Err(GrantError::NotYetValid);
    }
    Ok(parsed)
}

impl<'a> ParsedGrant<'a> {
    fn into_verified(self) -> VerifiedGrant {
        VerifiedGrant {
            key_id: self.key_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            nonce: self.nonce,
            audience: self.audience,
        }
    }
}

struct ParsedGrant<'a> {
    key_id: [u8; KEY_ID_LEN],
    issued_at: u64,
    expires_at: u64,
    nonce: [u8; NONCE_LEN],
    audience: GrantAudience,
    signed_payload: &'a [u8],
    signature: Signature,
}

fn parse(token: &[u8]) -> Result<ParsedGrant<'_>, GrantError> {
    if token.starts_with(LEGACY_MAGIC) {
        return Err(GrantError::LegacyGrantRejected);
    }
    if token.len() < MIN_TOKEN_LEN {
        return Err(GrantError::Malformed);
    }
    if token.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(GrantError::UnsupportedVersion);
    }

    let signature_offset = token
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(GrantError::Malformed)?;
    let realm_len = read_u16(token, REALM_LEN_OFFSET)? as usize;
    let node_id_len = read_u16(token, NODE_ID_LEN_OFFSET)? as usize;
    if realm_len == 0
        || realm_len > MAX_GRANT_IDENTIFIER_LEN
        || node_id_len == 0
        || node_id_len > MAX_GRANT_IDENTIFIER_LEN
    {
        return Err(GrantError::Malformed);
    }
    let realm_end = IDENTIFIERS_OFFSET
        .checked_add(realm_len)
        .ok_or(GrantError::Malformed)?;
    let node_id_end = realm_end
        .checked_add(node_id_len)
        .ok_or(GrantError::Malformed)?;
    let measurement_end = node_id_end
        .checked_add(MEASUREMENT_LEN)
        .ok_or(GrantError::Malformed)?;
    let tls_spki_sha256_end = measurement_end
        .checked_add(TLS_SPKI_SHA256_LEN)
        .ok_or(GrantError::Malformed)?;
    let previous_hop_end = tls_spki_sha256_end
        .checked_add(PREVIOUS_HOP_LEN)
        .ok_or(GrantError::Malformed)?;
    let next_hop_end = previous_hop_end
        .checked_add(NEXT_HOP_LEN)
        .ok_or(GrantError::Malformed)?;
    if next_hop_end != signature_offset {
        return Err(GrantError::Malformed);
    }

    let realm = std::str::from_utf8(
        token
            .get(IDENTIFIERS_OFFSET..realm_end)
            .ok_or(GrantError::Malformed)?,
    )
    .map_err(|_| GrantError::Malformed)?;
    let node_id = std::str::from_utf8(
        token
            .get(realm_end..node_id_end)
            .ok_or(GrantError::Malformed)?,
    )
    .map_err(|_| GrantError::Malformed)?;
    let role = GrantRole::from_wire(*token.get(ROLE_OFFSET).ok_or(GrantError::Malformed)?)
        .ok_or(GrantError::Malformed)?;
    let transport =
        GrantTransport::from_wire(*token.get(TRANSPORT_OFFSET).ok_or(GrantError::Malformed)?)
            .ok_or(GrantError::Malformed)?;
    let tee = tee_from_wire(*token.get(TEE_OFFSET).ok_or(GrantError::Malformed)?)
        .ok_or(GrantError::Malformed)?;
    let mut measurement = [0u8; MEASUREMENT_LEN];
    measurement.copy_from_slice(
        token
            .get(node_id_end..measurement_end)
            .ok_or(GrantError::Malformed)?,
    );
    let tls_spki_sha256 = token
        .get(measurement_end..tls_spki_sha256_end)
        .ok_or(GrantError::Malformed)?
        .try_into()
        .map_err(|_| GrantError::Malformed)?;
    let previous_hop_wire = token
        .get(tls_spki_sha256_end..previous_hop_end)
        .ok_or(GrantError::Malformed)?;
    let previous_hop = match previous_hop_wire {
        [0, 0, 0, 0, 0] => None,
        [1, a, b, c, d] => Some(Ipv4Addr::new(*a, *b, *c, *d)),
        _ => return Err(GrantError::Malformed),
    };
    let next_hop_wire = token
        .get(previous_hop_end..next_hop_end)
        .ok_or(GrantError::Malformed)?;
    let next_hop = match next_hop_wire {
        [0, 0, 0, 0, 0, 0, 0] => None,
        [1, a, b, c, d, port_hi, port_lo] => {
            let port = u16::from_be_bytes([*port_hi, *port_lo]);
            if port == 0 {
                return Err(GrantError::Malformed);
            }
            Some(SocketAddrV4::new(
                std::net::Ipv4Addr::new(*a, *b, *c, *d),
                port,
            ))
        }
        _ => return Err(GrantError::Malformed),
    };
    let audience = GrantAudience::new(
        realm,
        node_id,
        role,
        transport,
        tee,
        measurement,
        tls_spki_sha256,
        previous_hop,
        next_hop,
    )
    .map_err(|_| GrantError::Malformed)?;

    let signature =
        Signature::from_slice(token.get(signature_offset..).ok_or(GrantError::Malformed)?)
            .map_err(|_| GrantError::Malformed)?;
    Ok(ParsedGrant {
        key_id: read_array(token, KEY_ID_OFFSET)?,
        issued_at: read_u64(token, ISSUED_AT_OFFSET)?,
        expires_at: read_u64(token, EXPIRES_AT_OFFSET)?,
        nonce: read_array(token, NONCE_OFFSET)?,
        audience,
        signed_payload: &token[..signature_offset],
        signature,
    })
}

fn read_u16(token: &[u8], offset: usize) -> Result<u16, GrantError> {
    Ok(u16::from_be_bytes(read_array(token, offset)?))
}

fn read_u64(token: &[u8], offset: usize) -> Result<u64, GrantError> {
    Ok(u64::from_be_bytes(read_array(token, offset)?))
}

fn read_array<const N: usize>(token: &[u8], offset: usize) -> Result<[u8; N], GrantError> {
    token
        .get(offset..offset.checked_add(N).ok_or(GrantError::Malformed)?)
        .ok_or(GrantError::Malformed)?
        .try_into()
        .map_err(|_| GrantError::Malformed)
}

const fn tee_to_wire(tee: Tee) -> u8 {
    match tee {
        Tee::SevSnp => 1,
        Tee::Tdx => 2,
    }
}

const fn tee_from_wire(value: u8) -> Option<Tee> {
    match value {
        1 => Some(Tee::SevSnp),
        2 => Some(Tee::Tdx),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn key(byte: u8) -> GrantSigningKey {
        GrantSigningKey::from_seed([byte; 32])
    }

    fn audience() -> GrantAudience {
        GrantAudience::new(
            "prod.us-east",
            "node-17",
            GrantRole::Exit,
            GrantTransport::Masque,
            Tee::SevSnp,
            [0xa5; 48],
            [0x6b; 32],
            Some(Ipv4Addr::new(198, 51, 100, 20)),
            None,
        )
        .unwrap()
    }

    fn verifier_for(signing_key: &GrantSigningKey) -> GrantVerifier {
        GrantVerifier::from_public_key(signing_key.public_key_bytes()).unwrap()
    }

    fn resign(token: &mut [u8], signing_key: &GrantSigningKey) {
        let signature_offset = token.len() - SIGNATURE_LEN;
        let signature = signing_key.signing_key.sign(&token[..signature_offset]);
        token[signature_offset..].copy_from_slice(&signature.to_bytes());
    }

    #[test]
    fn grant_round_trips_every_signed_field() {
        let signing_key = key(7);
        let expected_audience = audience();
        let nonce = [9; 32];
        let grant = mint(
            &signing_key,
            &expected_audience,
            nonce,
            Duration::from_secs(90),
            NOW,
        )
        .unwrap();
        let verified = verify(
            &grant.token,
            &verifier_for(&signing_key),
            &expected_audience,
            NOW + 1,
        )
        .unwrap();

        assert_eq!(grant.nonce, nonce);
        assert_eq!(verified.key_id, signing_key.key_id());
        assert_eq!(verified.issued_at, NOW);
        assert_eq!(verified.expires_at, NOW + 90);
        assert_eq!(verified.nonce, nonce);
        assert_eq!(verified.audience, expected_audience);
    }

    #[test]
    fn encoding_has_the_documented_exact_layout() {
        let signing_key = key(1);
        let expected_audience = audience();
        let grant = mint(
            &signing_key,
            &expected_audience,
            [2; 32],
            Duration::from_secs(60),
            NOW,
        )
        .unwrap();
        let token = &grant.token;
        assert_eq!(&token[..4], b"NWG2");
        assert_eq!(
            &token[KEY_ID_OFFSET..ISSUED_AT_OFFSET],
            &signing_key.key_id()
        );
        assert_eq!(read_u64(token, ISSUED_AT_OFFSET).unwrap(), NOW);
        assert_eq!(read_u64(token, EXPIRES_AT_OFFSET).unwrap(), NOW + 60);
        assert_eq!(&token[NONCE_OFFSET..ROLE_OFFSET], &[2; 32]);
        assert_eq!(token[ROLE_OFFSET], GrantRole::Exit as u8);
        assert_eq!(token[TRANSPORT_OFFSET], GrantTransport::Masque as u8);
        assert_eq!(token[TEE_OFFSET], 1);
        assert_eq!(read_u16(token, REALM_LEN_OFFSET).unwrap(), 12);
        assert_eq!(read_u16(token, NODE_ID_LEN_OFFSET).unwrap(), 7);
        let next_hop_offset = token.len() - SIGNATURE_LEN - NEXT_HOP_LEN;
        let previous_hop_offset = next_hop_offset - PREVIOUS_HOP_LEN;
        assert_eq!(
            &token[previous_hop_offset..next_hop_offset],
            &[1, 198, 51, 100, 20]
        );
        assert_eq!(
            &token[next_hop_offset..next_hop_offset + NEXT_HOP_LEN],
            &[0; 7]
        );
        assert_eq!(
            token.len(),
            IDENTIFIERS_OFFSET
                + 12
                + 7
                + MEASUREMENT_LEN
                + TLS_SPKI_SHA256_LEN
                + PREVIOUS_HOP_LEN
                + NEXT_HOP_LEN
                + SIGNATURE_LEN
        );
    }

    #[test]
    fn relay_encoding_carries_one_exact_ipv4_socket() {
        let signer = key(17);
        let endpoint: SocketAddrV4 = "192.0.2.44:443".parse().unwrap();
        let relay = GrantAudience::new(
            "prod.us-east",
            "middle-4",
            GrantRole::Middle,
            GrantTransport::Masque,
            Tee::SevSnp,
            [0x31; 48],
            [0x41; 32],
            Some(Ipv4Addr::new(192, 0, 2, 10)),
            Some(endpoint),
        )
        .unwrap();
        let grant = mint(&signer, &relay, [0x51; 32], Duration::from_secs(60), NOW).unwrap();
        let next_hop_offset = grant.token.len() - SIGNATURE_LEN - NEXT_HOP_LEN;
        assert_eq!(
            &grant.token[next_hop_offset - PREVIOUS_HOP_LEN..next_hop_offset],
            &[1, 192, 0, 2, 10]
        );
        assert_eq!(
            &grant.token[next_hop_offset..next_hop_offset + NEXT_HOP_LEN],
            &[1, 192, 0, 2, 44, 0x01, 0xbb]
        );

        let node = relay.node_identity().clone();
        let verified = verifier_for(&signer)
            .verify_for_node(&grant.token, &node, NOW)
            .unwrap();
        assert_eq!(verified.audience.next_hop(), Some(endpoint));
        assert_eq!(
            verified.audience.previous_hop(),
            Some(Ipv4Addr::new(192, 0, 2, 10))
        );

        let wrong_route = GrantAudience::from_node_identity(
            node,
            Some(Ipv4Addr::new(192, 0, 2, 10)),
            Some("203.0.113.99:443".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(
            verifier_for(&signer).verify(&grant.token, &wrong_route, NOW),
            Err(GrantError::WrongAudience)
        );
    }

    #[test]
    fn role_and_next_hop_shape_is_fail_closed() {
        let endpoint: SocketAddrV4 = "192.0.2.1:443".parse().unwrap();
        for role in [GrantRole::Entry, GrantRole::Middle] {
            assert_eq!(
                GrantAudience::new(
                    "prod",
                    "node-1",
                    role,
                    GrantTransport::Masque,
                    Tee::SevSnp,
                    [1; 48],
                    [2; 32],
                    None,
                    None,
                ),
                Err(GrantError::InvalidNextHopPolicy)
            );
        }
        assert_eq!(
            GrantAudience::new(
                "prod",
                "node-1",
                GrantRole::Exit,
                GrantTransport::Masque,
                Tee::SevSnp,
                [1; 48],
                [2; 32],
                None,
                Some(endpoint),
            ),
            Err(GrantError::InvalidNextHopPolicy)
        );
        assert_eq!(
            GrantAudience::new(
                "prod",
                "node-1",
                GrantRole::Middle,
                GrantTransport::Masque,
                Tee::SevSnp,
                [1; 48],
                [2; 32],
                None,
                Some(endpoint),
            ),
            Err(GrantError::InvalidNextHopPolicy)
        );
        assert_eq!(
            GrantAudience::new(
                "prod",
                "node-1",
                GrantRole::Entry,
                GrantTransport::Masque,
                Tee::SevSnp,
                [1; 48],
                [2; 32],
                Some(Ipv4Addr::new(192, 0, 2, 9)),
                Some(endpoint),
            ),
            Err(GrantError::InvalidNextHopPolicy)
        );
        assert_eq!(
            GrantAudience::new(
                "prod",
                "node-1",
                GrantRole::Entry,
                GrantTransport::Masque,
                Tee::SevSnp,
                [1; 48],
                [2; 32],
                None,
                Some(SocketAddrV4::new(*endpoint.ip(), 0)),
            ),
            Err(GrantError::InvalidNextHopPolicy)
        );
    }

    #[test]
    fn exported_token_bound_covers_the_largest_canonical_encoding_exactly() {
        let max_identifier = "a".repeat(MAX_GRANT_IDENTIFIER_LEN);
        let max_audience = GrantAudience::new(
            max_identifier.clone(),
            max_identifier,
            GrantRole::Exit,
            GrantTransport::Masque,
            Tee::SevSnp,
            [0x11; 48],
            [0x22; 32],
            None,
            None,
        )
        .unwrap();
        let grant = mint(
            &key(2),
            &max_audience,
            [0x33; 32],
            Duration::from_secs(1),
            NOW,
        )
        .unwrap();
        assert_eq!(grant.token.len(), MAX_GRANT_TOKEN_LEN);
    }

    #[test]
    fn key_id_uses_the_fixed_domain_and_public_key() {
        let signing_key = key(3);
        let mut digest = Sha256::new();
        digest.update(b"nilvpn.nwg2.key-id");
        digest.update(signing_key.public_key_bytes());
        let expected: [u8; 32] = digest.finalize().into();
        assert_eq!(signing_key.key_id(), expected);
    }

    #[test]
    fn verifier_supports_rotation_and_selects_by_key_id() {
        let old = key(4);
        let current = key(5);
        let verifier =
            GrantVerifier::new([old.public_key_bytes(), current.public_key_bytes()]).unwrap();
        assert_eq!(verifier.len(), 2);
        assert!(verifier.contains_key_id(&old.key_id()));
        assert!(verifier.contains_key_id(&current.key_id()));

        for signing_key in [&old, &current] {
            let grant = mint(
                signing_key,
                &audience(),
                [6; 32],
                Duration::from_secs(60),
                NOW,
            )
            .unwrap();
            verifier.verify(&grant.token, &audience(), NOW).unwrap();
        }
    }

    #[test]
    fn verifier_rejects_empty_invalid_and_unknown_key_sets() {
        assert!(matches!(
            GrantVerifier::new([]),
            Err(GrantError::NoVerificationKeys)
        ));
        assert!(matches!(
            GrantVerifier::from_public_key([0; 32]),
            Err(GrantError::InvalidPublicKey)
        ));

        let signer = key(8);
        let other = key(9);
        let grant = mint(&signer, &audience(), [0; 32], Duration::from_secs(60), NOW).unwrap();
        assert!(matches!(
            verify(&grant.token, &verifier_for(&other), &audience(), NOW),
            Err(GrantError::UnknownKey)
        ));
    }

    #[test]
    fn identifiers_are_bounded_canonical_ascii() {
        for valid in ["a", "prod", "prod.us-east_2:blue", &"a".repeat(64)] {
            validate_identifier(valid).unwrap();
        }
        for invalid in [
            "",
            "Prod",
            " prod",
            "prod ",
            "-prod",
            "prod-",
            "prod/us",
            "prød",
            &"a".repeat(65),
        ] {
            assert!(matches!(
                validate_identifier(invalid),
                Err(GrantError::InvalidIdentifier(_))
            ));
        }
    }

    #[test]
    fn rejects_noncanonical_ttls_and_timestamp_overflow() {
        let signing_key = key(10);
        for ttl in [
            Duration::ZERO,
            Duration::from_secs(MAX_GRANT_TTL_SECS + 1),
            Duration::new(1, 1),
        ] {
            assert_eq!(
                mint(&signing_key, &audience(), [0; 32], ttl, NOW),
                Err(GrantError::InvalidTtl)
            );
        }
        assert_eq!(
            mint(
                &signing_key,
                &audience(),
                [0; 32],
                Duration::from_secs(1),
                u64::MAX
            ),
            Err(GrantError::TimeOverflow)
        );
        mint(
            &signing_key,
            &audience(),
            [0; 32],
            Duration::from_secs(MAX_GRANT_TTL_SECS),
            NOW,
        )
        .unwrap();
    }

    #[test]
    fn expiry_is_exact_and_future_skew_is_bounded() {
        let signing_key = key(11);
        let verifier = verifier_for(&signing_key);
        let grant = mint(
            &signing_key,
            &audience(),
            [0; 32],
            Duration::from_secs(60),
            NOW,
        )
        .unwrap();
        verify(&grant.token, &verifier, &audience(), NOW + 59).unwrap();
        assert_eq!(
            verify(&grant.token, &verifier, &audience(), NOW + 60),
            Err(GrantError::Expired)
        );
        assert_eq!(
            verify(&grant.token, &verifier, &audience(), u64::MAX),
            Err(GrantError::Expired)
        );

        verify(
            &grant.token,
            &verifier,
            &audience(),
            NOW - MAX_GRANT_CLOCK_SKEW_SECS,
        )
        .unwrap();
        assert_eq!(
            verify(
                &grant.token,
                &verifier,
                &audience(),
                NOW - MAX_GRANT_CLOCK_SKEW_SECS - 1
            ),
            Err(GrantError::NotYetValid)
        );
    }

    #[test]
    fn verifier_rejects_signed_invalid_lifetimes() {
        let signing_key = key(12);
        let verifier = verifier_for(&signing_key);
        let grant = mint(
            &signing_key,
            &audience(),
            [0; 32],
            Duration::from_secs(60),
            NOW,
        )
        .unwrap();
        for expires_at in [NOW, NOW - 1, NOW + MAX_GRANT_TTL_SECS + 1] {
            let mut token = grant.token.clone();
            token[EXPIRES_AT_OFFSET..EXPIRES_AT_OFFSET + 8]
                .copy_from_slice(&expires_at.to_be_bytes());
            resign(&mut token, &signing_key);
            assert_eq!(
                verify(&token, &verifier, &audience(), NOW),
                Err(GrantError::InvalidLifetime)
            );
        }
    }

    #[test]
    fn every_audience_dimension_is_bound() {
        let signing_key = key(13);
        let expected = audience();
        let grant = mint(
            &signing_key,
            &expected,
            [0; 32],
            Duration::from_secs(60),
            NOW,
        )
        .unwrap();
        let verifier = verifier_for(&signing_key);
        let alternatives = [
            GrantAudience::new(
                "staging.us-east",
                expected.node_id(),
                expected.role(),
                expected.transport(),
                expected.tee(),
                *expected.measurement(),
                *expected.tls_spki_sha256(),
                expected.previous_hop(),
                expected.next_hop(),
            )
            .unwrap(),
            GrantAudience::new(
                expected.realm(),
                "node-18",
                expected.role(),
                expected.transport(),
                expected.tee(),
                *expected.measurement(),
                *expected.tls_spki_sha256(),
                expected.previous_hop(),
                expected.next_hop(),
            )
            .unwrap(),
            GrantAudience::new(
                expected.realm(),
                expected.node_id(),
                GrantRole::Middle,
                expected.transport(),
                expected.tee(),
                *expected.measurement(),
                *expected.tls_spki_sha256(),
                expected.previous_hop(),
                Some("192.0.2.19:443".parse().unwrap()),
            )
            .unwrap(),
            GrantAudience::new(
                expected.realm(),
                expected.node_id(),
                expected.role(),
                GrantTransport::Reality,
                expected.tee(),
                *expected.measurement(),
                *expected.tls_spki_sha256(),
                expected.previous_hop(),
                expected.next_hop(),
            )
            .unwrap(),
            GrantAudience::new(
                expected.realm(),
                expected.node_id(),
                expected.role(),
                expected.transport(),
                Tee::Tdx,
                *expected.measurement(),
                *expected.tls_spki_sha256(),
                expected.previous_hop(),
                expected.next_hop(),
            )
            .unwrap(),
            GrantAudience::new(
                expected.realm(),
                expected.node_id(),
                expected.role(),
                expected.transport(),
                expected.tee(),
                [0x5a; 48],
                *expected.tls_spki_sha256(),
                expected.previous_hop(),
                expected.next_hop(),
            )
            .unwrap(),
            GrantAudience::new(
                expected.realm(),
                expected.node_id(),
                expected.role(),
                expected.transport(),
                expected.tee(),
                *expected.measurement(),
                [0x5c; 32],
                expected.previous_hop(),
                expected.next_hop(),
            )
            .unwrap(),
            GrantAudience::new(
                expected.realm(),
                expected.node_id(),
                expected.role(),
                expected.transport(),
                expected.tee(),
                *expected.measurement(),
                *expected.tls_spki_sha256(),
                Some(Ipv4Addr::new(198, 51, 100, 21)),
                expected.next_hop(),
            )
            .unwrap(),
        ];
        for alternative in alternatives {
            assert_eq!(
                verify(&grant.token, &verifier, &alternative, NOW),
                Err(GrantError::WrongAudience)
            );
        }
    }

    #[test]
    fn payload_and_signature_tampering_fail_strict_verification() {
        let signing_key = key(14);
        let verifier = verifier_for(&signing_key);
        let grant = mint(
            &signing_key,
            &audience(),
            [1; 32],
            Duration::from_secs(60),
            NOW,
        )
        .unwrap();
        for offset in [NONCE_OFFSET, IDENTIFIERS_OFFSET, grant.token.len() - 1] {
            let mut token = grant.token.clone();
            token[offset] ^= 1;
            assert_eq!(
                verify(&token, &verifier, &audience(), NOW),
                Err(GrantError::BadSignature)
            );
        }
    }

    #[test]
    fn parser_rejects_legacy_unknown_truncated_and_extended_encodings() {
        let signing_key = key(15);
        let verifier = verifier_for(&signing_key);
        assert_eq!(
            verify(b"NWG1anything", &verifier, &audience(), NOW),
            Err(GrantError::LegacyGrantRejected)
        );
        assert_eq!(
            verify(b"NWG3anything", &verifier, &audience(), NOW),
            Err(GrantError::Malformed)
        );

        let grant = mint(
            &signing_key,
            &audience(),
            [0; 32],
            Duration::from_secs(60),
            NOW,
        )
        .unwrap();
        for end in 0..grant.token.len() {
            assert!(verify(&grant.token[..end], &verifier, &audience(), NOW).is_err());
        }
        let mut extended = grant.token.clone();
        extended.push(0);
        assert_eq!(
            verify(&extended, &verifier, &audience(), NOW),
            Err(GrantError::Malformed)
        );
    }

    #[test]
    fn parser_rejects_unknown_wire_enums_and_noncanonical_identifiers() {
        let signing_key = key(16);
        let verifier = verifier_for(&signing_key);
        let grant = mint(
            &signing_key,
            &audience(),
            [0; 32],
            Duration::from_secs(60),
            NOW,
        )
        .unwrap();
        for offset in [ROLE_OFFSET, TRANSPORT_OFFSET, TEE_OFFSET] {
            let mut token = grant.token.clone();
            token[offset] = 0xff;
            resign(&mut token, &signing_key);
            assert_eq!(
                verify(&token, &verifier, &audience(), NOW),
                Err(GrantError::Malformed)
            );
        }
        let mut uppercase_realm = grant.token.clone();
        uppercase_realm[IDENTIFIERS_OFFSET] = b'P';
        resign(&mut uppercase_realm, &signing_key);
        assert_eq!(
            verify(&uppercase_realm, &verifier, &audience(), NOW),
            Err(GrantError::Malformed)
        );
    }

    #[test]
    fn parser_rejects_noncanonical_or_role_incompatible_next_hops() {
        let signing_key = key(18);
        let verifier = verifier_for(&signing_key);
        let grant = mint(
            &signing_key,
            &audience(),
            [0; 32],
            Duration::from_secs(60),
            NOW,
        )
        .unwrap();
        let next_hop_offset = grant.token.len() - SIGNATURE_LEN - NEXT_HOP_LEN;
        let previous_hop_offset = next_hop_offset - PREVIOUS_HOP_LEN;

        let mut noncanonical_previous = grant.token.clone();
        noncanonical_previous[previous_hop_offset] = 0;
        resign(&mut noncanonical_previous, &signing_key);
        assert_eq!(
            verify(&noncanonical_previous, &verifier, &audience(), NOW),
            Err(GrantError::Malformed)
        );

        let mut unknown_previous_presence = grant.token.clone();
        unknown_previous_presence[previous_hop_offset] = 2;
        resign(&mut unknown_previous_presence, &signing_key);
        assert_eq!(
            verify(&unknown_previous_presence, &verifier, &audience(), NOW),
            Err(GrantError::Malformed)
        );

        let mut nonzero_absent = grant.token.clone();
        nonzero_absent[next_hop_offset + 1] = 1;
        resign(&mut nonzero_absent, &signing_key);
        assert_eq!(
            verify(&nonzero_absent, &verifier, &audience(), NOW),
            Err(GrantError::Malformed)
        );

        let mut unknown_presence = grant.token.clone();
        unknown_presence[next_hop_offset] = 2;
        resign(&mut unknown_presence, &signing_key);
        assert_eq!(
            verify(&unknown_presence, &verifier, &audience(), NOW),
            Err(GrantError::Malformed)
        );

        let mut entry_without_route = grant.token.clone();
        entry_without_route[ROLE_OFFSET] = GrantRole::Entry as u8;
        resign(&mut entry_without_route, &signing_key);
        assert_eq!(
            verify(&entry_without_route, &verifier, &audience(), NOW),
            Err(GrantError::Malformed)
        );
    }

    #[test]
    fn hex_codec_remains_strict_and_canonical() {
        assert_eq!(from_hex("00aAFF"), Some(vec![0, 0xaa, 0xff]));
        assert_eq!(to_hex(&[0, 0xaa, 0xff]), "00aaff");
        assert_eq!(from_hex("0"), None);
        assert_eq!(from_hex("gg"), None);
    }
}
