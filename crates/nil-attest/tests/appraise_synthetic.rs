//! End-to-end appraisal over synthetic evidence (the path the Docker accept/reject harness
//! uses). Proves the verifier ACCEPTS a matching measurement and REJECTS on measurement
//! mismatch, wrong nonce, and TEE mismatch. Requires `--features synthetic`.
#![cfg(feature = "synthetic")]

use nil_attest::testkit::synthetic_evidence;
use nil_attest::{appraise, AppraisalPolicy, AttestError, Measurement, Tee};

const M: [u8; 48] = [0x11; 48];
const OTHER: [u8; 48] = [0x22; 48];
const NONCE: [u8; 32] = [0xAB; 32];
// Stands in for the node's TLS SubjectPublicKeyInfo (appraise only hashes it; the node would
// pass its real peer_cert() SPKI). The same bytes are used to build and to appraise.
const SPKI: &[u8] = b"synthetic-node-tls-subject-public-key-info";

fn policy(tee: Tee, m: [u8; 48]) -> AppraisalPolicy {
    AppraisalPolicy::new(tee, Measurement(m.to_vec()))
}

#[test]
fn accepts_matching_measurement() {
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let verdict = appraise(&ev, SPKI, &policy(Tee::SevSnp, M), &NONCE).expect("matching measurement accepted");
    assert_eq!(verdict.measurement.0, M.to_vec());
    assert_eq!(verdict.tee, Tee::SevSnp);
}

#[test]
fn rejects_measurement_mismatch() {
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(&ev, SPKI, &policy(Tee::SevSnp, OTHER), &NONCE).unwrap_err();
    assert!(matches!(err, AttestError::MeasurementMismatch), "got {err:?}");
    // The Display string the Docker harness greps for.
    assert_eq!(err.to_string(), "measurement mismatch");
}

#[test]
fn rejects_stale_or_wrong_nonce() {
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(&ev, SPKI, &policy(Tee::SevSnp, M), &[0xCD; 32]).unwrap_err();
    assert!(matches!(err, AttestError::ReportDataMismatch), "got {err:?}");
}

#[test]
fn rejects_wrong_tls_key_binding() {
    // A report lifted onto a different TLS key (different SPKI) must fail the binding.
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(&ev, b"a-different-tls-key", &policy(Tee::SevSnp, M), &NONCE).unwrap_err();
    assert!(matches!(err, AttestError::ReportDataMismatch), "got {err:?}");
}

#[test]
fn rejects_tee_mismatch() {
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(&ev, SPKI, &policy(Tee::Tdx, M), &NONCE).unwrap_err();
    assert!(matches!(err, AttestError::TeeMismatch { .. }), "got {err:?}");
}
