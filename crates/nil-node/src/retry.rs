//! Stateless QUIC source-address validation (RFC 9000 §8.1, "Retry"). Before committing any
//! connection state to a client's Initial, the node challenges the client to prove it can receive
//! at its claimed source address: it replies with a Retry packet carrying an opaque token, and
//! only accepts the connection once the client echoes that token back in a fresh Initial.
//!
//! Why this matters here:
//!   - **Anti-amplification / anti-DoS.** Without it, a single spoofed-source Initial makes the
//!     node allocate a `quiche::Connection` and emit a larger handshake flight to a victim address
//!     — a reflection/amplification primitive. Retry caps the node's response to one small packet
//!     until the source is validated.
//!   - **Fingerprint realism (Pillar 1).** Real HTTPS/QUIC servers (Cloudflare's quiche included)
//!     use Retry under load; a node that *never* does stands out. This makes UDP 443 look ordinary.
//!
//! The token is **stateless**: it binds the client's source address and the original DCID under an
//! HMAC keyed by a per-process random secret, so the node keeps NO per-handshake table (PD-2:
//! nothing retained) and a token cannot be forged or replayed from a different source address. The
//! key is ephemeral (regenerated each process start), so tokens do not survive a restart — fine,
//! the client simply gets re-challenged.
//!
//! No source address is logged anywhere in this module (PD-3: the data plane retains no source IP).

use std::net::SocketAddr;

use sha2::{Digest, Sha256};

/// Domain-separation tag prefixed to every token so the bytes are unambiguous and a token can
/// never be mistaken for some other node blob.
const TOKEN_TAG: &[u8] = b"nil-quic-retry-v1";
/// HMAC truncation length (bytes). 16 bytes (128-bit) is ample for an address-validation MAC.
const MAC_LEN: usize = 16;

/// A per-process secret keying the Retry-token HMAC. Generated from the OS CSPRNG at startup and
/// never persisted (PD-2). All address-validation tokens this process mints are verifiable only by
/// this same process — exactly the property we want for stateless validation.
pub struct RetryKey {
    key: [u8; 32],
}

impl RetryKey {
    /// Fresh random key from the OS CSPRNG.
    pub fn generate() -> std::io::Result<Self> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key)
            .map_err(|e| std::io::Error::other(format!("retry key entropy: {e}")))?;
        Ok(Self { key })
    }

    /// Mint a Retry token binding `src` (the client's UDP source address) and `odcid` (the
    /// original destination connection ID from the client's first Initial). The client must echo
    /// this verbatim in its next Initial; [`Self::validate`] then recovers `odcid` and confirms the
    /// source address matches.
    ///
    /// Layout: `TAG || odcid_len(1) || odcid || HMAC(key, TAG || src || odcid)[..MAC_LEN]`.
    pub fn mint(&self, src: &SocketAddr, odcid: &[u8]) -> Vec<u8> {
        let mut token = Vec::with_capacity(TOKEN_TAG.len() + 1 + odcid.len() + MAC_LEN);
        token.extend_from_slice(TOKEN_TAG);
        token.push(odcid.len() as u8);
        token.extend_from_slice(odcid);
        token.extend_from_slice(&self.mac(src, odcid));
        token
    }

    /// Validate a token echoed by a client claiming source address `src`. Returns the original
    /// DCID (to pass to `quiche::accept` as `odcid`) iff the token is well-formed, its MAC verifies
    /// for THIS source address, and it was minted by this process. Constant-time MAC comparison.
    pub fn validate(&self, src: &SocketAddr, token: &[u8]) -> Option<Vec<u8>> {
        let rest = token.strip_prefix(TOKEN_TAG)?;
        let (&odcid_len, rest) = rest.split_first()?;
        let odcid_len = odcid_len as usize;
        if rest.len() != odcid_len + MAC_LEN {
            return None;
        }
        let (odcid, mac) = rest.split_at(odcid_len);
        let expected = self.mac(src, odcid);
        // Constant-time compare so a forger learns nothing from timing.
        if ct_eq(mac, &expected) {
            Some(odcid.to_vec())
        } else {
            None
        }
    }

    /// `HMAC-SHA256(key, TAG || src_bytes || odcid)` truncated to [`MAC_LEN`]. Binding the source
    /// address is what makes the token un-replayable from a different address.
    fn mac(&self, src: &SocketAddr, odcid: &[u8]) -> [u8; MAC_LEN] {
        let mut msg = Vec::with_capacity(TOKEN_TAG.len() + 19 + odcid.len());
        msg.extend_from_slice(TOKEN_TAG);
        msg.extend_from_slice(&addr_bytes(src));
        msg.extend_from_slice(odcid);
        let full = hmac_sha256(&self.key, &msg);
        let mut out = [0u8; MAC_LEN];
        out.copy_from_slice(&full[..MAC_LEN]);
        out
    }
}

/// Canonical bytes for a socket address: the IP octets (4 for v4, 16 for v6, tagged so a v4 and a
/// v4-mapped v6 never collide) followed by the big-endian port.
fn addr_bytes(src: &SocketAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(19);
    match src {
        SocketAddr::V4(a) => {
            v.push(4);
            v.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            v.push(6);
            v.extend_from_slice(&a.ip().octets());
        }
    }
    v.extend_from_slice(&src.port().to_be_bytes());
    v
}

/// HMAC-SHA256 (RFC 2104). Small local impl to avoid pulling an HMAC crate for one use.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k0[..32].copy_from_slice(&d);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
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

/// Constant-time byte-slice equality (length-independent: returns false on a length mismatch).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SocketAddr {
        "203.0.113.5:443".parse().unwrap()
    }

    #[test]
    fn round_trip_recovers_odcid() {
        let k = RetryKey::generate().unwrap();
        let odcid = [0xab; 8];
        let token = k.mint(&src(), &odcid);
        assert_eq!(k.validate(&src(), &token), Some(odcid.to_vec()));
    }

    #[test]
    fn token_is_bound_to_source_address() {
        let k = RetryKey::generate().unwrap();
        let odcid = [0x01, 0x02, 0x03, 0x04];
        let token = k.mint(&src(), &odcid);
        // Same token from a DIFFERENT source address must NOT validate (anti-spoof core property).
        let other: SocketAddr = "198.51.100.9:443".parse().unwrap();
        assert_eq!(k.validate(&other, &token), None);
        // Different port too.
        let other_port: SocketAddr = "203.0.113.5:1234".parse().unwrap();
        assert_eq!(k.validate(&other_port, &token), None);
    }

    #[test]
    fn forged_or_corrupt_tokens_are_rejected() {
        let k = RetryKey::generate().unwrap();
        let odcid = [0x09; 6];
        let mut token = k.mint(&src(), &odcid);
        // Flip a MAC byte.
        *token.last_mut().unwrap() ^= 0xff;
        assert_eq!(k.validate(&src(), &token), None);
        // Garbage / empty / wrong tag.
        assert_eq!(k.validate(&src(), b""), None);
        assert_eq!(k.validate(&src(), b"not-a-nil-token-at-all"), None);
        // A token minted by a different key (different process) must not validate here.
        let k2 = RetryKey::generate().unwrap();
        assert_eq!(k.validate(&src(), &k2.mint(&src(), &odcid)), None);
    }

    #[test]
    fn empty_odcid_round_trips() {
        let k = RetryKey::generate().unwrap();
        let token = k.mint(&src(), &[]);
        assert_eq!(k.validate(&src(), &token), Some(Vec::new()));
    }
}
