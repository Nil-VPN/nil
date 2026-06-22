//! Intel TDX known-answer test against a REAL DCAP quote + collateral (offline). Exercises
//! the genuine Intel verification path. Vectors copied from the `dcap-qvl` crate's samples.
//!
//! The collateral has a validity window; like `dcap-qvl`'s own test we evaluate at a fixed
//! point INSIDE that window (not wall-clock), so the vector keeps verifying as time passes.

use dcap_qvl::QuoteCollateralV3;
use der::Decode;
use nil_attest::report::tdx;
use serde_json::Value;
use x509_cert::crl::CertificateList;

const QUOTE: &[u8] = include_bytes!("data/tdx_quote");
const COLLATERAL: &[u8] = include_bytes!("data/tdx_quote_collateral.json");

/// A timestamp inside the intersection of every collateral validity window.
fn now_within_window() -> u64 {
    let collateral: QuoteCollateralV3 = serde_json::from_slice(COLLATERAL).expect("collateral JSON");

    fn issue_next(json_str: &str) -> (u64, u64) {
        let v: Value = serde_json::from_str(json_str).expect("valid JSON");
        let issue = v["issueDate"].as_str().expect("issueDate");
        let next = v["nextUpdate"].as_str().expect("nextUpdate");
        let i = chrono::DateTime::parse_from_rfc3339(issue).unwrap().timestamp() as u64;
        let n = chrono::DateTime::parse_from_rfc3339(next).unwrap().timestamp() as u64;
        (i, n)
    }
    fn crl_bounds(crl_der: &[u8]) -> (u64, Option<u64>) {
        let crl = CertificateList::from_der(crl_der).expect("CRL");
        let this = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let next = crl.tbs_cert_list.next_update.map(|t| t.to_unix_duration().as_secs());
        (this, next)
    }

    let (ti, tn) = issue_next(&collateral.tcb_info);
    let (qi, qn) = issue_next(&collateral.qe_identity);
    let mut not_before = ti.max(qi);
    let mut not_after = tn.min(qn);
    for crl in [&collateral.root_ca_crl[..], &collateral.pck_crl[..]] {
        let (this, next) = crl_bounds(crl);
        not_before = not_before.max(this);
        if let Some(n) = next {
            not_after = not_after.min(n);
        }
    }
    assert!(not_before <= not_after, "collateral window invalid");
    not_after.saturating_sub(1)
}

#[test]
fn genuine_tdx_quote_verifies_offline() {
    let now = now_within_window();
    let ev = tdx::verify(QUOTE, COLLATERAL, now).expect("real TDX quote verifies against its collateral");
    assert_eq!(ev.measurement.len(), 48, "TDX MRTD is 48 bytes");
    assert_eq!(ev.report_data.len(), 64);
}

#[test]
fn tampered_tdx_quote_is_rejected() {
    let now = now_within_window();
    let mut quote = QUOTE.to_vec();
    // Corrupt a byte well inside the signed TD report body.
    let i = quote.len() / 2;
    quote[i] ^= 0xFF;
    assert!(tdx::verify(&quote, COLLATERAL, now).is_err(), "a tampered TDX quote must be rejected");
}
