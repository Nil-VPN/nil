//! End-to-end appraisal over a synthetic RA-TLS cert (the path the Docker accept/reject
//! harness uses). Proves the verifier ACCEPTS a matching measurement and REJECTS on
//! measurement mismatch, wrong nonce, and TEE mismatch. Requires `--features synthetic`.
#![cfg(feature = "synthetic")]

use nil_attest::{appraise, AppraisalPolicy, AttestError, Measurement, Tee};
use nil_attest::testkit::synthetic_cert;

const M: [u8; 48] = [0x11; 48];
const OTHER: [u8; 48] = [0x22; 48];
const NONCE: [u8; 32] = [0xAB; 32];

fn policy(tee: Tee, m: [u8; 48]) -> AppraisalPolicy {
    AppraisalPolicy::new(tee, Measurement(m.to_vec()))
}

#[test]
fn accepts_matching_measurement() {
    let cert = synthetic_cert(Tee::SevSnp, &M, &NONCE).unwrap();
    let verdict = appraise(&cert, &policy(Tee::SevSnp, M), &NONCE).expect("matching measurement accepted");
    assert_eq!(verdict.measurement.0, M.to_vec());
    assert_eq!(verdict.tee, Tee::SevSnp);
}

#[test]
fn rejects_measurement_mismatch() {
    let cert = synthetic_cert(Tee::SevSnp, &M, &NONCE).unwrap();
    let err = appraise(&cert, &policy(Tee::SevSnp, OTHER), &NONCE).unwrap_err();
    assert!(matches!(err, AttestError::MeasurementMismatch), "got {err:?}");
    // The Display string the Docker harness greps for.
    assert_eq!(err.to_string(), "measurement mismatch");
}

#[test]
fn rejects_stale_or_wrong_nonce() {
    let cert = synthetic_cert(Tee::SevSnp, &M, &NONCE).unwrap();
    let wrong_nonce = [0xCD; 32];
    let err = appraise(&cert, &policy(Tee::SevSnp, M), &wrong_nonce).unwrap_err();
    assert!(matches!(err, AttestError::ReportDataMismatch), "got {err:?}");
}

#[test]
fn rejects_tee_mismatch() {
    let cert = synthetic_cert(Tee::SevSnp, &M, &NONCE).unwrap();
    let err = appraise(&cert, &policy(Tee::Tdx, M), &NONCE).unwrap_err();
    assert!(matches!(err, AttestError::TeeMismatch { .. }), "got {err:?}");
}
