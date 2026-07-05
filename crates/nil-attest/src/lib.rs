//! Attestation for NIL VPN's verifiable-trust pillar (architecture spec §5).
//!
//! Parses and appraises AMD SEV-SNP and Intel TDX attestation reports and verifies a node's
//! RA-TLS certificate (the report embedded in an X.509 extension) against a measurement the
//! Coordinator publishes. The client refuses to tunnel unless the report's signature chain
//! verifies to the hardware vendor root, the measurement matches the pinned policy, and a
//! client nonce is bound into `report_data` to prove freshness, and — when a transparency-log key
//! is pinned — the measurement is proven present in the public log via a stapled inclusion proof:
//! "prove it, don't promise it".
//!
//! [`appraise`] is the single entrypoint the transport calls — with the node's report
//! evidence (delivered over the established channel) and the TLS key it's bound to (the SPKI
//! from `quiche::Connection::peer_cert()`). Only a returned [`Verdict`] lets the tunnel come
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
pub use policy::{AppraisalPolicy, Measurement, SevSnpTcbFloor, TcbStatus, Tee, Verdict};
pub use report::Evidence;

/// Appraise a node's attestation `evidence` (the `[tag][parts]` blob the node returned over
/// the channel) against the pinned `policy`, requiring the report to be bound to the node's
/// TLS key (`tls_spki`, from `peer_cert()`) and the per-connection `nonce`.
///
/// On `Ok`, and only then, the transport signals the tunnel ready. Every failure mode is a
/// typed [`AttestError`]; the caller turns any of them into a refused connection.
pub fn appraise(
    evidence: &[u8],
    tls_spki: &[u8],
    policy: &AppraisalPolicy,
    nonce: &[u8; 32],
) -> Result<Verdict, AttestError> {
    let (&tag, rest) = evidence
        .split_first()
        .ok_or_else(|| AttestError::Malformed("empty attestation evidence".into()))?;
    let parts = ratls::decode_parts(rest)?;

    // A node MAY staple a transparency-log inclusion proof as one extra trailing evidence part.
    // Peel it off up front (backward compatible: evidence without a proof has exactly the base part
    // count) so each TEE arm matches only its own parts. The base count also validates the tag.
    let base = match tag {
        ratls::TAG_SEVSNP | ratls::TAG_TDX => 2,
        #[cfg(feature = "synthetic")]
        ratls::TAG_SYNTHETIC => 1,
        other => return Err(AttestError::UnsupportedTee(other)),
    };
    let (base_parts, stapled): (&[&[u8]], Option<&[u8]>) = if parts.len() == base {
        (&parts, None)
    } else if parts.len() == base + 1 {
        (&parts[..base], Some(parts[base]))
    } else {
        return Err(AttestError::Malformed("unexpected attestation evidence part count".into()));
    };

    let report = match tag {
        ratls::TAG_SEVSNP => match base_parts {
            [report, vcek] => report::sevsnp::verify(report, vcek, policy.min_tcb_sevsnp)?,
            _ => return Err(AttestError::Malformed("SEV-SNP evidence expects [report, vcek]".into())),
        },
        ratls::TAG_TDX => match base_parts {
            [quote, collateral] => report::tdx::verify(quote, collateral, now_unix())?,
            _ => return Err(AttestError::Malformed("TDX evidence expects [quote, collateral]".into())),
        },
        #[cfg(feature = "synthetic")]
        ratls::TAG_SYNTHETIC => match base_parts {
            [synthetic] => testkit::verify(synthetic)?,
            _ => return Err(AttestError::Malformed("synthetic evidence expects [report]".into())),
        },
        // Unreachable: `base` above already rejected any other tag. Kept for match exhaustiveness.
        other => return Err(AttestError::UnsupportedTee(other)),
    };

    // The report must come from the TEE family the policy pinned.
    if report.tee != policy.tee {
        return Err(AttestError::TeeMismatch { expected: policy.tee, found: report.tee });
    }

    // Freshness + key binding: report_data must equal H(node's TLS key, this connection's nonce).
    let expected_rd = ratls::bind_report_data(tls_spki, nonce);
    if !bool::from(report.report_data.ct_eq(&expected_rd)) {
        return Err(AttestError::ReportDataMismatch);
    }

    // The measured code must be exactly what the Coordinator pinned (constant-time).
    let pinned = &policy.expected_measurement.0;
    if report.measurement.len() != pinned.len()
        || !bool::from(report.measurement.as_slice().ct_eq(pinned.as_slice()))
    {
        return Err(AttestError::MeasurementMismatch);
    }

    // Platform patch level.
    if let TcbStatus::OutOfDate(reason) = &report.tcb_status {
        if !policy.allow_tcb_out_of_date {
            return Err(AttestError::TcbNotUpToDate(reason.clone()));
        }
    }

    // Transparency gate (fail closed): when a log key is pinned, the now-verified measurement must
    // be provably present in that public append-only log via the stapled RFC 6962 inclusion proof.
    // This is the "asserted → client-verified" step — even a coerced Coordinator cannot pin a
    // measurement that was never publicly logged without leaving a log-detectable trace (PD-5/PD-7).
    // Offline by design: the proof + signed checkpoint are stapled, so the client never phones the
    // log (which would leak which node it is verifying, PD-3).
    if let Some(log_key) = &policy.transparency_log_key {
        let proof_bytes = stapled
            .ok_or_else(|| AttestError::TransparencyNotLogged("no stapled inclusion proof".into()))?;
        let proof = nil_crypto::translog::LogProof::decode(proof_bytes)
            .ok_or_else(|| AttestError::TransparencyNotLogged("malformed inclusion proof".into()))?;
        if !nil_crypto::translog::verify_logged(&report.measurement, &proof, log_key) {
            return Err(AttestError::TransparencyNotLogged(
                "measurement not included under the pinned log checkpoint".into(),
            ));
        }
    }

    Ok(Verdict {
        tee: report.tee,
        measurement: Measurement(report.measurement),
        tcb_status: report.tcb_status,
    })
}

/// Wall-clock seconds since the Unix epoch, for TDX collateral validity. On a clock error this
/// fails CLOSED: it returns a far-future value (`u64::MAX / 2`) so an unknown clock treats the
/// collateral as past its validity window (→ out-of-date / refused) rather than the old `0`, which
/// reads as "before any window" and could widen acceptance of stale collateral. The sentinel is
/// `MAX/2`, not `MAX`, to leave headroom in case the DCAP verifier adds a leeway to `now` (no
/// overflow). Replay of a report within a valid window is stopped by the per-connection nonce, not
/// the clock — a separate axis (architecture spec §5).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX / 2)
}
