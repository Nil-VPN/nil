//! Attestation for NIL VPN's verifiable-trust pillar (architecture spec §5).
//!
//! Parses and appraises AMD SEV-SNP and Intel TDX attestation reports and verifies a node's
//! RA-TLS certificate (the report embedded in an X.509 extension) against a measurement the
//! Coordinator publishes. The client refuses to tunnel unless the report's signature chain
//! verifies to the hardware vendor root, the measurement matches the pinned policy, and a
//! client nonce is bound into `report_data` to prove freshness — "prove it, don't promise it".
//!
//! [`appraise`] is the single entrypoint the transport calls with the node's leaf cert
//! (from `quiche::Connection::peer_cert()`); only a returned [`Verdict`] lets the tunnel come
//! up, so any failure holds the kill-switch.

pub mod error;
pub mod policy;
pub mod ratls;
pub mod report;
#[cfg(feature = "synthetic")]
pub mod testkit;

use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;

pub use error::AttestError;
pub use policy::{AppraisalPolicy, Measurement, TcbStatus, Tee, Verdict};
pub use report::Evidence;

/// Appraise a node's RA-TLS leaf certificate (DER) against the pinned `policy`, requiring the
/// report to be bound to the cert's TLS key and the per-connection `nonce`.
///
/// On `Ok`, and only then, the transport signals the tunnel ready. Every failure mode is a
/// typed [`AttestError`]; the caller turns any of them into a refused connection.
pub fn appraise(
    cert_der: &[u8],
    policy: &AppraisalPolicy,
    nonce: &[u8; 32],
) -> Result<Verdict, AttestError> {
    let ev = ratls::parse_cert(cert_der)?;
    let parts = ratls::decode_parts(ev.payload)?;

    let evidence = match ev.tag {
        ratls::TAG_SEVSNP => match parts.as_slice() {
            [report, vcek] => report::sevsnp::verify(report, vcek)?,
            _ => return Err(AttestError::Malformed("SEV-SNP evidence expects [report, vcek]".into())),
        },
        ratls::TAG_TDX => match parts.as_slice() {
            [quote, collateral] => report::tdx::verify(quote, collateral, now_unix())?,
            _ => return Err(AttestError::Malformed("TDX evidence expects [quote, collateral]".into())),
        },
        #[cfg(feature = "synthetic")]
        ratls::TAG_SYNTHETIC => match parts.as_slice() {
            [synthetic] => testkit::verify(synthetic)?,
            _ => return Err(AttestError::Malformed("synthetic evidence expects [report]".into())),
        },
        other => return Err(AttestError::UnsupportedTee(other)),
    };

    // The report must come from the TEE family the policy pinned.
    if evidence.tee != policy.tee {
        return Err(AttestError::TeeMismatch { expected: policy.tee, found: evidence.tee });
    }

    // Freshness + key binding: the report's report_data must equal H(this cert's key, nonce).
    let expected_rd = ratls::bind_report_data(&ev.spki, nonce);
    if !bool::from(evidence.report_data.ct_eq(&expected_rd)) {
        return Err(AttestError::ReportDataMismatch);
    }

    // The measured code must be exactly what the Coordinator pinned (constant-time).
    let pinned = &policy.expected_measurement.0;
    if evidence.measurement.len() != pinned.len()
        || !bool::from(evidence.measurement.as_slice().ct_eq(pinned.as_slice()))
    {
        return Err(AttestError::MeasurementMismatch);
    }

    // Platform patch level.
    if let TcbStatus::OutOfDate(reason) = &evidence.tcb_status {
        if !policy.allow_tcb_out_of_date {
            return Err(AttestError::TcbNotUpToDate(reason.clone()));
        }
    }

    Ok(Verdict {
        tee: evidence.tee,
        measurement: Measurement(evidence.measurement),
        tcb_status: evidence.tcb_status,
    })
}

/// Wall-clock seconds since the Unix epoch, for TDX collateral validity. A skewed clock can
/// at worst widen acceptance of out-of-date collateral; replay is stopped by the nonce, not
/// the clock (documented limitation, architecture spec §5).
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
