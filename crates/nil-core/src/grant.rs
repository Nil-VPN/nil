//! Short-lived node grants.
//!
//! A grant is a compact opaque byte string carried by the client in CONNECT-IP. The Coordinator
//! mints it after Privacy Pass redemption; the node verifies it before opening the data plane.
//! The format is deliberately binary and dependency-light:
//!
//! ```text
//! "NWG1" || exp_unix_secs_be || nonce[32] || binding_len_be || binding || hmac_sha256
//! ```
//!
//! The binding is the node's attested identity (`tee:measurement_hex`), so a grant selected for
//! one measured node cannot be replayed against a different measured node sharing the key.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::{Grant, Tee};

const MAGIC: &[u8; 4] = b"NWG1";
const MAC_LEN: usize = 32;
const FIXED_LEN: usize = 4 + 8 + 32 + 2 + MAC_LEN;
const HMAC_BLOCK: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub expires_at: u64,
    pub nonce: [u8; 32],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("grant key must be at least 32 bytes")]
    WeakKey,
    #[error("grant is malformed")]
    Malformed,
    #[error("grant does not match this node")]
    WrongNode,
    #[error("grant signature is invalid")]
    BadSignature,
    #[error("grant expired")]
    Expired,
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

pub fn validate_key(key: &[u8]) -> Result<(), GrantError> {
    if key.len() < MAC_LEN {
        return Err(GrantError::WeakKey);
    }
    Ok(())
}

pub fn binding_for(tee: Tee, measurement: &[u8]) -> String {
    let tee = match tee {
        Tee::SevSnp => "sev-snp",
        Tee::Tdx => "tdx",
    };
    format!("{tee}:{}", to_hex(measurement))
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

pub fn mint(
    key: &[u8],
    node_binding: &str,
    nonce: [u8; 32],
    ttl: Duration,
    now: u64,
) -> Result<Grant, GrantError> {
    validate_key(key)?;
    let binding = node_binding.as_bytes();
    if binding.len() > u16::MAX as usize {
        return Err(GrantError::Malformed);
    }
    let exp = now.saturating_add(ttl.as_secs());
    let mut token = Vec::with_capacity(FIXED_LEN + binding.len());
    token.extend_from_slice(MAGIC);
    token.extend_from_slice(&exp.to_be_bytes());
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&(binding.len() as u16).to_be_bytes());
    token.extend_from_slice(binding);
    let mac = hmac_sha256(key, &token);
    token.extend_from_slice(&mac);
    Ok(Grant { token, nonce })
}

pub fn verify(
    token: &[u8],
    key: &[u8],
    expected_binding: &str,
    now: u64,
) -> Result<VerifiedGrant, GrantError> {
    validate_key(key)?;
    if token.len() < FIXED_LEN || &token[..4] != MAGIC {
        return Err(GrantError::Malformed);
    }
    let mac_start = token.len() - MAC_LEN;
    let payload = &token[..mac_start];
    let mac = &token[mac_start..];
    let expected_mac = hmac_sha256(key, payload);
    if !constant_time_eq(mac, &expected_mac) {
        return Err(GrantError::BadSignature);
    }

    let exp = u64::from_be_bytes(token[4..12].try_into().map_err(|_| GrantError::Malformed)?);
    if exp < now {
        return Err(GrantError::Expired);
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&token[12..44]);
    let binding_len = u16::from_be_bytes(
        token[44..46]
            .try_into()
            .map_err(|_| GrantError::Malformed)?,
    ) as usize;
    if 46 + binding_len != mac_start {
        return Err(GrantError::Malformed);
    }
    let binding = std::str::from_utf8(&token[46..mac_start]).map_err(|_| GrantError::Malformed)?;
    if binding != expected_binding {
        return Err(GrantError::WrongNode);
    }
    Ok(VerifiedGrant {
        expires_at: exp,
        nonce,
    })
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; MAC_LEN] {
    let mut k0 = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        k0[..MAC_LEN].copy_from_slice(&Sha256::digest(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK];
    let mut opad = [0x5cu8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn grant_round_trips_and_binds_nonce() {
        let nonce = [7u8; 32];
        let grant = mint(KEY, "sev-snp:abcd", nonce, Duration::from_secs(60), 100).unwrap();
        let verified = verify(&grant.token, KEY, "sev-snp:abcd", 120).unwrap();
        assert_eq!(verified.nonce, nonce);
        assert_eq!(verified.expires_at, 160);
    }

    #[test]
    fn rejects_wrong_node_and_tampering() {
        let grant = mint(KEY, "sev-snp:abcd", [1u8; 32], Duration::from_secs(60), 100).unwrap();
        assert!(matches!(
            verify(&grant.token, KEY, "tdx:abcd", 100),
            Err(GrantError::WrongNode)
        ));
        let mut tampered = grant.token.clone();
        tampered[20] ^= 1;
        assert!(matches!(
            verify(&tampered, KEY, "sev-snp:abcd", 100),
            Err(GrantError::BadSignature)
        ));
    }

    #[test]
    fn rejects_expired_and_weak_key() {
        let grant = mint(KEY, "sev-snp:abcd", [1u8; 32], Duration::from_secs(1), 100).unwrap();
        assert!(matches!(
            verify(&grant.token, KEY, "sev-snp:abcd", 102),
            Err(GrantError::Expired)
        ));
        assert!(matches!(
            mint(
                b"short",
                "sev-snp:abcd",
                [1u8; 32],
                Duration::from_secs(1),
                100
            ),
            Err(GrantError::WeakKey)
        ));
    }
}
