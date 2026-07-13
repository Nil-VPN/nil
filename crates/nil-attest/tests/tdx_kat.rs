//! Intel TDX known-answer test against a REAL DCAP quote + collateral (offline). Exercises
//! the genuine Intel verification path. Vectors copied from the `dcap-qvl` crate's samples.
//!
//! The collateral has a validity window; like `dcap-qvl`'s own test we evaluate at a fixed
//! point INSIDE that window (not wall-clock), so the vector keeps verifying as time passes.

use dcap_qvl::quote::{Quote, Report, TDReport10};
use dcap_qvl::QuoteCollateralV3;
use der::Decode;
use nil_attest::report::tdx;
use nil_attest::{AttestError, TdxPolicy};
use serde_json::Value;
use x509_cert::crl::CertificateList;

const QUOTE: &[u8] = include_bytes!("data/tdx_quote");
const COLLATERAL: &[u8] = include_bytes!("data/tdx_quote_collateral.json");

fn policy_from_base(base: &TDReport10, mr_service_td: Option<[u8; 48]>) -> TdxPolicy {
    TdxPolicy {
        td_attributes: base.td_attributes,
        xfam: base.xfam,
        mr_config_id: base.mr_config_id.into(),
        mr_owner: base.mr_owner.into(),
        mr_owner_config: base.mr_owner_config.into(),
        rt_mr0: base.rt_mr0.into(),
        rt_mr1: base.rt_mr1.into(),
        rt_mr2: base.rt_mr2.into(),
        rt_mr3: base.rt_mr3.into(),
        mr_service_td: mr_service_td.map(Into::into),
    }
}

/// The KAT policy is copied from the reviewed fixture only to prove field extraction and matching.
/// Production never learns policy from an untrusted quote; it receives independently published
/// values from the embedded/Coordinator-narrowed trust bundle.
fn fixture_policy() -> TdxPolicy {
    let quote = Quote::parse(QUOTE).expect("parse fixture quote");
    match quote.report {
        Report::TD10(td) => policy_from_base(&td, None),
        Report::TD15(td) => policy_from_base(&td.base, Some(td.mr_service_td)),
        Report::SgxEnclave(_) => panic!("fixture must be TDX"),
    }
}

/// A timestamp inside the intersection of every collateral validity window.
fn now_within_window() -> u64 {
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(COLLATERAL).expect("collateral JSON");

    fn issue_next(json_str: &str) -> (u64, u64) {
        let v: Value = serde_json::from_str(json_str).expect("valid JSON");
        let issue = v["issueDate"].as_str().expect("issueDate");
        let next = v["nextUpdate"].as_str().expect("nextUpdate");
        let i = chrono::DateTime::parse_from_rfc3339(issue)
            .unwrap()
            .timestamp() as u64;
        let n = chrono::DateTime::parse_from_rfc3339(next)
            .unwrap()
            .timestamp() as u64;
        (i, n)
    }
    fn crl_bounds(crl_der: &[u8]) -> (u64, Option<u64>) {
        let crl = CertificateList::from_der(crl_der).expect("CRL");
        let this = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let next = crl
            .tbs_cert_list
            .next_update
            .map(|t| t.to_unix_duration().as_secs());
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
fn genuine_tdx_quote_verifies_cryptographically_but_incomplete_workload_is_rejected() {
    let now = now_within_window();
    let collateral: QuoteCollateralV3 = serde_json::from_slice(COLLATERAL).unwrap();
    let verified = dcap_qvl::verify::rustcrypto::verify(QUOTE, &collateral, now)
        .expect("real TDX quote verifies against Intel collateral");
    assert_eq!(verified.status, "UpToDate");
    assert!(verified.advisory_ids.is_empty());

    let err = tdx::verify(QUOTE, COLLATERAL, now, &fixture_policy()).unwrap_err();
    assert!(
        matches!(err, AttestError::PolicyViolation(message) if message.contains("RTMR3") && message.contains("nonzero")),
        "the generic fixture leaves RTMR3 empty and must not qualify as a NIL workload"
    );
}

#[test]
fn verified_candidate_refuses_a_quote_without_every_runtime_measurement() {
    let now = now_within_window();
    let err = tdx::verified_identity_candidate(QUOTE, COLLATERAL, now).unwrap_err();
    assert!(
        matches!(err, AttestError::PolicyViolation(message) if message.contains("RTMR3") && message.contains("nonzero")),
        "operator tooling must not emit an incomplete registry candidate"
    );
}

#[test]
fn tampered_tdx_quote_is_rejected() {
    let now = now_within_window();
    let mut quote = QUOTE.to_vec();
    // Corrupt a byte well inside the signed TD report body.
    let i = quote.len() / 2;
    quote[i] ^= 0xFF;
    let collateral: QuoteCollateralV3 = serde_json::from_slice(COLLATERAL).unwrap();
    assert!(dcap_qvl::verify::rustcrypto::verify(&quote, &collateral, now).is_err());
}

#[test]
fn genuine_quote_with_missing_runtime_policy_is_rejected() {
    let now = now_within_window();
    let mut policy = fixture_policy();
    policy.rt_mr2 = [0u8; 48].into();
    let err = tdx::verify(QUOTE, COLLATERAL, now, &policy).unwrap_err();
    assert!(
        matches!(err, AttestError::PolicyViolation(message) if message.contains("RTMR2")),
        "a valid quote must still fail when its runtime measurement is not pinned"
    );
}
