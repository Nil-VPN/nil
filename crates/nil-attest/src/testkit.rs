//! Synthetic attestation — **test/dev only**, compiled solely under the `synthetic` feature.
//!
//! There is no SEV-SNP/TDX hardware in CI or on a laptop, so the Docker accept/reject harness
//! needs a way to mint a node "report" with a chosen measurement. This module signs a report
//! with an Ed25519 CA **we control** and verifies it against that CA's compiled-in public key.
//!
//! This proves the *verifier's decision logic* — `report_data` binding, measurement compare,
//! reject-on-tamper, TEE match — NOT that a real CPU attested. The genuine vendor-root paths
//! are covered separately by the SEV-SNP/TDX known-answer tests. A release client is built
//! WITHOUT this feature, so the synthetic tag (`0xFF`) is rejected outright and this trust
//! anchor is unreachable.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::AttestError;
use crate::policy::TcbStatus;
use crate::ratls;
use crate::report::Evidence;
use nil_core::Tee;

/// Fixed test-CA seed. Test-only; the matching public key is the synthetic trust anchor.
const TEST_CA_SEED: [u8; 32] = *b"nil-vpn.synthetic-attest.testca.";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_CA_SEED)
}

fn tee_byte(tee: Tee) -> u8 {
    match tee {
        Tee::SevSnp => 0,
        Tee::Tdx => 1,
    }
}

fn tee_from_byte(b: u8) -> Result<Tee, AttestError> {
    match b {
        0 => Ok(Tee::SevSnp),
        1 => Ok(Tee::Tdx),
        other => Err(AttestError::Malformed(format!("synthetic tee byte {other}"))),
    }
}

/// Sign a synthetic report. Payload = `tee(1) || measurement(48) || report_data(64) || sig(64)`,
/// where the Ed25519 signature covers `tee || measurement || report_data`.
pub fn sign(tee: Tee, measurement: &[u8; 48], report_data: &[u8; 64]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(1 + 48 + 64);
    signed.push(tee_byte(tee));
    signed.extend_from_slice(measurement);
    signed.extend_from_slice(report_data);
    let sig = signing_key().sign(&signed);
    let mut out = signed;
    out.extend_from_slice(&sig.to_bytes());
    out
}

/// Verify a synthetic report payload against the compiled-in test CA. Returns normalized
/// evidence on success.
pub fn verify(payload: &[u8]) -> Result<Evidence, AttestError> {
    if payload.len() != 1 + 48 + 64 + 64 {
        return Err(AttestError::Malformed("synthetic payload length".into()));
    }
    let (signed, sig_bytes) = payload.split_at(1 + 48 + 64);
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|e| AttestError::Malformed(format!("synthetic signature: {e}")))?;
    let vk: VerifyingKey = signing_key().verifying_key();
    vk.verify(signed, &sig)
        .map_err(|_| AttestError::ChainVerification("synthetic CA signature".into()))?;

    let tee = tee_from_byte(signed[0])?;
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&signed[49..113]);
    Ok(Evidence { tee, measurement: signed[1..49].to_vec(), report_data, tcb_status: TcbStatus::UpToDate })
}

/// Build a synthetic evidence blob (the `[tag][parts]` bytes the node returns over the
/// channel) for `measurement`, bound to the node's TLS key (`spki`) and the client `nonce`.
/// This is what a synthetic node computes after reading the client's nonce header.
pub fn synthetic_evidence(tee: Tee, measurement: &[u8; 48], spki: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    let report_data = ratls::bind_report_data(spki, nonce);
    let report = sign(tee, measurement, &report_data);
    ratls::encode(ratls::TAG_SYNTHETIC, &[&report])
}

/// Like [`synthetic_evidence`], but staples `log_proof` (serialized [`nil_crypto::translog::LogProof`]
/// bytes) as the trailing evidence part — exercising the client's transparency-log gate end to end.
pub fn synthetic_evidence_logged(
    tee: Tee,
    measurement: &[u8; 48],
    spki: &[u8],
    nonce: &[u8; 32],
    log_proof: &[u8],
) -> Vec<u8> {
    let report_data = ratls::bind_report_data(spki, nonce);
    let report = sign(tee, measurement, &report_data);
    ratls::encode(ratls::TAG_SYNTHETIC, &[&report, log_proof])
}
