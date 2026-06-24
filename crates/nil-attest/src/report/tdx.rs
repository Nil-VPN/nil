//! Intel TDX quote verification via `dcap-qvl` (pure-Rust `rustcrypto` path), offline.
//!
//! The node embeds the DCAP quote plus pre-fetched collateral (TCB info, QE identity, PCK
//! chain, CRLs) so verification needs no live call to Intel's PCS. The collateral has a
//! validity window: the caller supplies `now_secs`, which must fall inside it.

use dcap_qvl::quote::Report;
use dcap_qvl::QuoteCollateralV3;

use crate::error::AttestError;
use crate::policy::TcbStatus;
use crate::report::Evidence;
use nil_core::Tee;

// --- DCAP quote layout constants (Intel "Quote v4/v5" wire format) ---
//
// These mirror the fixed-layout values `dcap-qvl` itself enforces deeper in its decoder; we
// re-state them here so a structurally broken blob is rejected *before* it reaches the
// cryptographic verifier, with a clear, testable error instead of an opaque decode failure.
// The genuine DCAP verifier remains the authority — these are fail-fast pre-checks, not a
// substitute for signature/chain verification.

/// Quote header length in bytes (`version` .. `user_data`).
const HEADER_BYTE_LEN: usize = 48;
/// `tee_type` value identifying an Intel TDX quote (little-endian `0x0000_0081`).
const TEE_TYPE_TDX: u32 = 0x0000_0081;
/// Quote format versions Intel defines for TDX evidence (v4 standard, v5 with TD15 body).
const ALLOWED_TDX_QUOTE_VERSIONS: [u16; 2] = [4, 5];
/// Smallest TD report body (`TD10`); a TDX quote must carry at least header + this body.
const TD_REPORT10_BYTE_LEN: usize = 584;

/// Structural pre-validation of a raw DCAP quote / configfs-TSM outblob before it is handed to
/// the `dcap-qvl` verifier. This is defensive depth: the verifier already fails closed on a
/// malformed blob, but these checks turn an opaque decode error into a precise, logged-safe
/// `Malformed` reason and reject obviously-wrong input (truncated outblob, SGX-typed quote,
/// unknown version) without spending work in the crypto path.
///
/// It deliberately does NOT attempt to re-parse the whole quote — that is the verifier's job
/// and duplicating it would be a second, drift-prone source of truth. It only checks the
/// fixed-offset header fields and an overall minimum length.
fn prevalidate_quote(quote_bytes: &[u8]) -> Result<(), AttestError> {
    // Must at least contain the header plus the smallest valid TD report body.
    let min_len = HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN;
    if quote_bytes.len() < min_len {
        return Err(AttestError::Malformed(format!(
            "TDX quote too short: {} bytes, need >= {min_len}",
            quote_bytes.len()
        )));
    }

    // Header is fixed little-endian: version: u16, attestation_key_type: u16, tee_type: u32.
    // Indexing is safe: we verified `len() >= HEADER_BYTE_LEN` (48) above.
    let version = u16::from_le_bytes([quote_bytes[0], quote_bytes[1]]);
    if !ALLOWED_TDX_QUOTE_VERSIONS.contains(&version) {
        return Err(AttestError::Malformed(format!(
            "TDX quote header version {version} not in {ALLOWED_TDX_QUOTE_VERSIONS:?}"
        )));
    }

    let tee_type = u32::from_le_bytes([
        quote_bytes[4],
        quote_bytes[5],
        quote_bytes[6],
        quote_bytes[7],
    ]);
    if tee_type != TEE_TYPE_TDX {
        return Err(AttestError::Malformed(format!(
            "quote tee_type {tee_type:#010x} is not TDX ({TEE_TYPE_TDX:#010x})"
        )));
    }

    Ok(())
}

/// Verify a TDX `quote` against its JSON `collateral` at time `now_secs`. Returns `MRTD` +
/// `report_data` on success.
pub fn verify(quote_bytes: &[u8], collateral_json: &[u8], now_secs: u64) -> Result<Evidence, AttestError> {
    // Fail fast on a structurally malformed outblob before touching the crypto verifier.
    prevalidate_quote(quote_bytes)?;

    let collateral: QuoteCollateralV3 = serde_json::from_slice(collateral_json)
        .map_err(|e| AttestError::Malformed(format!("TDX collateral JSON: {e}")))?;

    let verified = dcap_qvl::verify::rustcrypto::verify(quote_bytes, &collateral, now_secs)
        .map_err(|e| AttestError::ChainVerification(format!("TDX DCAP verify: {e:?}")))?;

    let (mr_td, report_data) = match verified.report {
        Report::TD10(td) => (td.mr_td, td.report_data),
        Report::TD15(td) => (td.base.mr_td, td.base.report_data),
        Report::SgxEnclave(_) => {
            return Err(AttestError::Malformed("expected a TDX quote, got an SGX enclave report".into()))
        }
    };

    let tcb_status = if verified.status == "UpToDate" {
        TcbStatus::UpToDate
    } else {
        TcbStatus::OutOfDate(verified.status)
    };

    Ok(Evidence { tee: Tee::Tdx, measurement: mr_td.to_vec(), report_data, tcb_status })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header that would otherwise pass the structural pre-checks (TDX v4), padded out to the
    /// minimum quote length. The bytes are not a real signed quote — these tests only exercise
    /// `prevalidate_quote`; genuine end-to-end verification is covered by the TDX KAT.
    fn well_formed_header_blob() -> Vec<u8> {
        let mut blob = vec![0u8; HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN];
        blob[0..2].copy_from_slice(&4u16.to_le_bytes()); // version = 4
        blob[4..8].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());
        blob
    }

    #[test]
    fn too_short_outblob_is_rejected() {
        let err = prevalidate_quote(&[0u8; 16]).unwrap_err();
        match err {
            AttestError::Malformed(m) => assert!(m.contains("too short"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn empty_outblob_is_rejected() {
        assert!(matches!(prevalidate_quote(&[]), Err(AttestError::Malformed(_))));
    }

    #[test]
    fn unknown_quote_version_is_rejected() {
        let mut blob = well_formed_header_blob();
        blob[0..2].copy_from_slice(&3u16.to_le_bytes()); // v3 = SGX-era, not a TDX quote
        let err = prevalidate_quote(&blob).unwrap_err();
        match err {
            AttestError::Malformed(m) => assert!(m.contains("version"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn non_tdx_tee_type_is_rejected() {
        let mut blob = well_formed_header_blob();
        blob[4..8].copy_from_slice(&0u32.to_le_bytes()); // TEE_TYPE_SGX
        let err = prevalidate_quote(&blob).unwrap_err();
        match err {
            AttestError::Malformed(m) => assert!(m.contains("tee_type"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_header_passes_prevalidation() {
        // Structural pre-checks pass; this says nothing about signature validity, which the
        // genuine DCAP verifier (exercised by the KAT) enforces afterward.
        assert!(prevalidate_quote(&well_formed_header_blob()).is_ok());
    }
}
