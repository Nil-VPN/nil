//! SEV-SNP known-answer test against a REAL AMD Milan report + its VCEK, rooted in the
//! built-in AMD ARK/ASK. This exercises the genuine vendor-root verification path (distinct
//! from the synthetic Docker harness). Vectors copied from the `sev` crate's test data.

use nil_attest::report::sevsnp;

const REPORT_HEX: &str = include_str!("data/report_milan.hex");
const VCEK_DER: &[u8] = include_bytes!("data/vcek_milan.der");

fn report_bytes() -> Vec<u8> {
    let cleaned: String = REPORT_HEX
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    hex::decode(cleaned).expect("valid hex report vector")
}

#[test]
fn genuine_milan_report_verifies_to_amd_root() {
    let report = report_bytes();
    let ev = sevsnp::verify(&report, VCEK_DER, None)
        .expect("real Milan report verifies to the AMD root");
    assert_eq!(
        ev.measurement.len(),
        48,
        "SEV-SNP launch measurement is 48 bytes"
    );
    assert_eq!(ev.report_data.len(), 64);
}

#[test]
fn tampered_report_is_rejected() {
    let mut report = report_bytes();
    // Flip a byte inside the measurement region (offset 0x90); the ECDSA signature over the
    // report body must now fail to verify against the VCEK.
    report[0x90] ^= 0xFF;
    assert!(
        sevsnp::verify(&report, VCEK_DER, None).is_err(),
        "a tampered report must fail chain/report verification"
    );
}

#[test]
fn wrong_vcek_is_rejected() {
    let report = report_bytes();
    // A VCEK that didn't sign this report (truncated/garbage) must not verify.
    let bogus = vec![0x30u8; VCEK_DER.len()];
    assert!(
        sevsnp::verify(&report, &bogus, None).is_err(),
        "a non-matching VCEK must be rejected"
    );
}

#[test]
fn min_tcb_floor_above_real_report_is_out_of_date() {
    // The pinned minimum-TCB floor, exercised against a REAL Milan report (not a synthetic one).
    // An unreachably-high floor (all 0xFF) is above any real platform TCB, so the genuinely-verified
    // report must be classified OutOfDate — which `appraise` then refuses under default policy.
    let report = report_bytes();
    let floor = nil_attest::SevSnpTcbFloor {
        fmc: Some(0xFF),
        bootloader: 0xFF,
        tee: 0xFF,
        snp: 0xFF,
        microcode: 0xFF,
    };
    let ev = sevsnp::verify(&report, VCEK_DER, Some(floor))
        .expect("chain still verifies; the floor only classifies TCB");
    assert!(
        matches!(ev.tcb_status, nil_attest::TcbStatus::OutOfDate(_)),
        "a real report below an unreachable pinned floor must be OutOfDate"
    );
}
