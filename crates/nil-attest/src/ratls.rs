//! RA-TLS plumbing: the custom X.509 extension that carries attestation evidence, how to
//! pull it (and the TLS public key) out of a node's leaf certificate, and the binding that
//! ties a report to *this* TLS key and *this* connection's nonce.
//!
//! Extension value layout: `[tee_tag: u8][payload]`, where the payload is TEE-specific and
//! the per-TEE parts are length-prefixed (`u32` big-endian) so verifiers never guess offsets.

use sha2::{Digest, Sha256, Sha512};
use x509_parser::prelude::*;

use crate::error::AttestError;

/// NIL RA-TLS attestation extension OID, under a private-enterprise arc.
/// NOTE: `58270` is a placeholder PEN to be replaced with a registered IANA enterprise number.
pub const OID_STR: &str = "1.3.6.1.4.1.58270.1.1";
/// The same OID as integer arcs, for cert builders (e.g. `rcgen`).
pub const OID_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 58270, 1, 1];

pub const TAG_SEVSNP: u8 = 1;
pub const TAG_TDX: u8 = 2;
/// Synthetic (test-only) evidence; rejected unless `nil-attest` is built with `synthetic`.
pub const TAG_SYNTHETIC: u8 = 0xFF;

/// Encode the extension value for a SEV-SNP node: report + the per-chip VCEK (DER).
pub fn encode_sevsnp(report: &[u8], vcek_der: &[u8]) -> Vec<u8> {
    encode(TAG_SEVSNP, &[report, vcek_der])
}

/// Encode the extension value for a TDX node: the DCAP quote + its JSON collateral.
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

/// Parsed RA-TLS evidence: the TEE tag, the post-tag payload, and the cert's TLS SPKI (DER).
pub struct CertEvidence<'a> {
    pub tag: u8,
    pub payload: &'a [u8],
    pub spki: Vec<u8>,
}

/// Pull the attestation extension + the TLS SubjectPublicKeyInfo out of a leaf cert (DER).
pub fn parse_cert(cert_der: &[u8]) -> Result<CertEvidence<'_>, AttestError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AttestError::Cert(format!("leaf parse: {e}")))?;
    let spki = cert.tbs_certificate.subject_pki.raw.to_vec();

    let ext = cert
        .tbs_certificate
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == OID_STR)
        .ok_or(AttestError::MissingExtension)?;

    let value = ext.value;
    let (&tag, payload) = value
        .split_first()
        .ok_or_else(|| AttestError::Malformed("empty attestation extension".into()))?;
    Ok(CertEvidence { tag, payload, spki })
}

/// Extract just the TLS SubjectPublicKeyInfo (DER) from a leaf cert — used when building a
/// cert in two passes (learn the SPKI before embedding the report bound to it).
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
