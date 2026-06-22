//! SEV-SNP known-answer test against a REAL AMD Milan report + its VCEK, rooted in the
//! built-in AMD ARK/ASK. This exercises the genuine vendor-root verification path (distinct
//! from the synthetic Docker harness). Vectors copied from the `sev` crate's test data.

use nil_attest::report::sevsnp;

const REPORT_HEX: &str = include_str!("data/report_milan.hex");
const VCEK_DER: &[u8] = include_bytes!("data/vcek_milan.der");

fn report_bytes() -> Vec<u8> {
    let cleaned: String = REPORT_HEX.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex::decode(cleaned).expect("valid hex report vector")
}

#[test]
fn genuine_milan_report_verifies_to_amd_root() {
    let report = report_bytes();
    let ev = sevsnp::verify(&report, VCEK_DER).expect("real Milan report verifies to the AMD root");
    assert_eq!(ev.measurement.len(), 48, "SEV-SNP launch measurement is 48 bytes");
    assert_eq!(ev.report_data.len(), 64);
}

#[test]
fn tampered_report_is_rejected() {
    let mut report = report_bytes();
    // Flip a byte inside the measurement region (offset 0x90); the ECDSA signature over the
    // report body must now fail to verify against the VCEK.
    report[0x90] ^= 0xFF;
    assert!(
        sevsnp::verify(&report, VCEK_DER).is_err(),
        "a tampered report must fail chain/report verification"
    );
}

#[test]
fn wrong_vcek_is_rejected() {
    let report = report_bytes();
    // A VCEK that didn't sign this report (truncated/garbage) must not verify.
    let bogus = vec![0x30u8; VCEK_DER.len()];
    assert!(sevsnp::verify(&report, &bogus).is_err(), "a non-matching VCEK must be rejected");
}
