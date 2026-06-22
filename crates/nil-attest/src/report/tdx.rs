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

/// Verify a TDX `quote` against its JSON `collateral` at time `now_secs`. Returns `MRTD` +
/// `report_data` on success.
pub fn verify(quote_bytes: &[u8], collateral_json: &[u8], now_secs: u64) -> Result<Evidence, AttestError> {
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
