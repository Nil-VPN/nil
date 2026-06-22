//! RA-TLS plumbing: the attestation-evidence wire codec, the TLS public-key extractor, and
//! the binding that ties a report to *this* TLS key and *this* connection's nonce.
//!
//! ## Why the report rides an H3 header, not an X.509 extension
//! Standard RA-TLS embeds the report in the server cert. But the client's freshness nonce
//! arrives in the H3 CONNECT request — *after* the TLS handshake — so a handshake-presented
//! cert cannot bind a client-chosen nonce. We therefore keep the node's TLS cert plain (it
//! supplies the channel key), and the node returns its report — bound to that key's SPKI **and**
//! the client nonce — in the CONNECT response over the established TLS channel. Same security
//! property (report bound to the TLS session key), and it lets the *client* drive freshness.
//!
//! Evidence layout: `[tee_tag: u8][payload]`, payload parts length-prefixed (`u32` big-endian).

use sha2::{Digest, Sha256, Sha512};
use x509_parser::prelude::*;

use crate::error::AttestError;

pub const TAG_SEVSNP: u8 = 1;
pub const TAG_TDX: u8 = 2;
/// Synthetic (test-only) evidence; rejected unless `nil-attest` is built with `synthetic`.
pub const TAG_SYNTHETIC: u8 = 0xFF;

/// Encode the evidence blob for a SEV-SNP node: report + the per-chip VCEK (DER).
pub fn encode_sevsnp(report: &[u8], vcek_der: &[u8]) -> Vec<u8> {
    encode(TAG_SEVSNP, &[report, vcek_der])
}

/// Encode the evidence blob for a TDX node: the DCAP quote + its JSON collateral.
pub fn encode_tdx(quote: &[u8], collateral_json: &[u8]) -> Vec<u8> {
    encode(TAG_TDX, &[quote, collateral_json])
}

/// Encode `[tag][len|part]...` with `u32` big-endian length prefixes.
pub fn encode(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![tag];
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Split the post-tag payload into its length-prefixed parts.
pub fn decode_parts(mut rest: &[u8]) -> Result<Vec<&[u8]>, AttestError> {
    let mut parts = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(AttestError::Malformed("truncated length prefix".into()));
        }
        let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return Err(AttestError::Malformed("truncated evidence part".into()));
        }
        parts.push(&rest[..len]);
        rest = &rest[len..];
    }
    Ok(parts)
}

/// Extract the TLS SubjectPublicKeyInfo (DER) from the node's leaf cert (from
/// `quiche::Connection::peer_cert()`). This is the key the report must be bound to.
pub fn spki_of(cert_der: &[u8]) -> Result<Vec<u8>, AttestError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AttestError::Cert(format!("leaf parse: {e}")))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// The 64-byte `report_data` binding: ties the report to the node's TLS key and the client
/// nonce. `report_data = SHA-512( SHA-256(spki) || nonce )`. Both SEV-SNP and TDX expose a
/// 64-byte `report_data`/`REPORTDATA` slot, which SHA-512 fills exactly.
pub fn bind_report_data(spki: &[u8], nonce: &[u8]) -> [u8; 64] {
    let spki_hash = Sha256::digest(spki);
    let mut h = Sha512::new();
    h.update(spki_hash);
    h.update(nonce);
    h.finalize().into()
}
