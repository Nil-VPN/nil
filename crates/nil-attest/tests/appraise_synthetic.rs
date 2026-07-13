//! End-to-end appraisal over synthetic evidence (the path the Docker accept/reject harness
//! uses). Proves the verifier ACCEPTS a matching measurement and REJECTS on measurement
//! mismatch, wrong nonce, and TEE mismatch. Requires `--features synthetic`.
#![cfg(feature = "synthetic")]

use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};
use nil_attest::testkit::{synthetic_evidence, synthetic_evidence_logged};
use nil_attest::{appraise, AppraisalPolicy, AttestError, Measurement, Tee};
use nil_crypto::translog::{leaf_hash, LogProof};
use sha2::{Digest, Sha256};

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
    let verdict = appraise(&ev, SPKI, &policy(Tee::SevSnp, M), &NONCE)
        .expect("matching measurement accepted");
    assert_eq!(verdict.measurement.0, M.to_vec());
    assert_eq!(verdict.tee, Tee::SevSnp);
}

#[test]
fn rejects_measurement_mismatch() {
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(&ev, SPKI, &policy(Tee::SevSnp, OTHER), &NONCE).unwrap_err();
    assert!(
        matches!(err, AttestError::MeasurementMismatch),
        "got {err:?}"
    );
    // The Display string the Docker harness greps for.
    assert_eq!(err.to_string(), "measurement mismatch");
}

#[test]
fn rejects_stale_or_wrong_nonce() {
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(&ev, SPKI, &policy(Tee::SevSnp, M), &[0xCD; 32]).unwrap_err();
    assert!(
        matches!(err, AttestError::ReportDataMismatch),
        "got {err:?}"
    );
}

#[test]
fn rejects_wrong_tls_key_binding() {
    // A report lifted onto a different TLS key (different SPKI) must fail the binding.
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(&ev, b"a-different-tls-key", &policy(Tee::SevSnp, M), &NONCE).unwrap_err();
    assert!(
        matches!(err, AttestError::ReportDataMismatch),
        "got {err:?}"
    );
}

#[test]
fn registry_spki_pin_accepts_exact_key_and_rejects_a_clone_key_first() {
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let digest: [u8; 32] = Sha256::digest(SPKI).into();
    let pinned = policy(Tee::SevSnp, M).with_tls_spki_sha256(Some(digest));
    appraise(&ev, SPKI, &pinned, &NONCE).expect("the registry-pinned TLS key is accepted");

    let clone_spki = b"clone-with-the-same-measurement-but-a-different-key";
    let clone_ev = synthetic_evidence(Tee::SevSnp, &M, clone_spki, &NONCE);
    let err = appraise(&clone_ev, clone_spki, &pinned, &NONCE).unwrap_err();
    assert!(matches!(err, AttestError::TlsSpkiMismatch), "got {err:?}");
}

#[test]
fn rejects_tee_mismatch() {
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(&ev, SPKI, &policy(Tee::Tdx, M), &NONCE).unwrap_err();
    assert!(
        matches!(err, AttestError::TeeMismatch { .. }),
        "got {err:?}"
    );
}

// --- Transparency-log gate ---------------------------------------------------------------------
// A minimal single-leaf log (tree_size 1, empty audit path) whose only leaf IS the measurement:
// the root is leaf_hash(measurement) and the checkpoint is signed by our test log key.

const ORIGIN: &str = "nil.transparency.test.v1";

fn log_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5A; 32])
}

/// Serialized inclusion proof committing `measurement` as the sole leaf of a log signed by `sk`.
fn logged_proof(measurement: &[u8; 48], sk: &SigningKey, origin: &str) -> Vec<u8> {
    let root = leaf_hash(measurement); // single-leaf tree: root == the leaf hash
                                       // Checkpoint body mirrors translog's Go/Sigstore note layout: `origin\n<size>\n<b64 root>\n`.
    let body = format!("{origin}\n1\n{}\n", BASE64.encode(&root));
    LogProof {
        origin: origin.to_string(),
        tree_size: 1,
        leaf_index: 0,
        root,
        audit_path: Vec::new(),
        checkpoint_sig: sk.sign(body.as_bytes()).to_bytes().to_vec(),
    }
    .encode()
}

fn policy_logged(m: [u8; 48], log_pubkey: [u8; 32]) -> AppraisalPolicy {
    policy(Tee::SevSnp, m).with_transparency_log_key(Some(log_pubkey))
}

#[test]
fn accepts_when_measurement_is_provably_logged() {
    let sk = log_key();
    let proof = logged_proof(&M, &sk, ORIGIN);
    let ev = synthetic_evidence_logged(Tee::SevSnp, &M, SPKI, &NONCE, &proof);
    let verdict = appraise(
        &ev,
        SPKI,
        &policy_logged(M, sk.verifying_key().to_bytes()),
        &NONCE,
    )
    .expect("a logged measurement with a valid stapled proof is accepted");
    assert_eq!(verdict.measurement.0, M.to_vec());
}

#[test]
fn rejects_when_log_pinned_but_no_proof_stapled() {
    // Pinned log key but the node stapled nothing → fail closed.
    let ev = synthetic_evidence(Tee::SevSnp, &M, SPKI, &NONCE);
    let err = appraise(
        &ev,
        SPKI,
        &policy_logged(M, log_key().verifying_key().to_bytes()),
        &NONCE,
    )
    .unwrap_err();
    assert!(
        matches!(err, AttestError::TransparencyNotLogged(_)),
        "got {err:?}"
    );
}

#[test]
fn rejects_proof_signed_by_the_wrong_log_key() {
    // A proof for the right measurement, but signed by a DIFFERENT log than the pinned one.
    let attacker = SigningKey::from_bytes(&[0x11; 32]);
    let proof = logged_proof(&M, &attacker, ORIGIN);
    let ev = synthetic_evidence_logged(Tee::SevSnp, &M, SPKI, &NONCE, &proof);
    let err = appraise(
        &ev,
        SPKI,
        &policy_logged(M, log_key().verifying_key().to_bytes()),
        &NONCE,
    )
    .unwrap_err();
    assert!(
        matches!(err, AttestError::TransparencyNotLogged(_)),
        "got {err:?}"
    );
}

#[test]
fn rejects_proof_for_a_different_measurement() {
    // The stapled proof commits OTHER, but the report (and pin) is M → inclusion fails.
    let sk = log_key();
    let proof = logged_proof(&OTHER, &sk, ORIGIN);
    let ev = synthetic_evidence_logged(Tee::SevSnp, &M, SPKI, &NONCE, &proof);
    let err = appraise(
        &ev,
        SPKI,
        &policy_logged(M, sk.verifying_key().to_bytes()),
        &NONCE,
    )
    .unwrap_err();
    assert!(
        matches!(err, AttestError::TransparencyNotLogged(_)),
        "got {err:?}"
    );
}

#[test]
fn rejects_malformed_stapled_proof() {
    let ev = synthetic_evidence_logged(Tee::SevSnp, &M, SPKI, &NONCE, b"not a valid logproof");
    let err = appraise(
        &ev,
        SPKI,
        &policy_logged(M, log_key().verifying_key().to_bytes()),
        &NONCE,
    )
    .unwrap_err();
    assert!(
        matches!(err, AttestError::TransparencyNotLogged(_)),
        "got {err:?}"
    );
}

#[test]
fn ignores_stapled_proof_when_no_log_key_pinned() {
    // With no pinned log key, a stapled proof is simply ignored (backward compatible) — accepted.
    let proof = logged_proof(&M, &log_key(), ORIGIN);
    let ev = synthetic_evidence_logged(Tee::SevSnp, &M, SPKI, &NONCE, &proof);
    let verdict = appraise(&ev, SPKI, &policy(Tee::SevSnp, M), &NONCE)
        .expect("no pinned log key ⇒ stapled proof ignored, measurement pin still gates");
    assert_eq!(verdict.measurement.0, M.to_vec());
}
