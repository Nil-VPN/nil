//! Intel TDX quote verification via `dcap-qvl` (pure-Rust `rustcrypto` path), offline.
//!
//! The node embeds the DCAP quote plus pre-fetched collateral (TCB info, QE identity, PCK
//! chain, CRLs) so verification needs no live call to Intel's PCS. The collateral has a
//! validity window: the caller supplies `now_secs`, which must fall inside it.

use dcap_qvl::quote::Report;
use dcap_qvl::verify::{QuoteVerifier, VerifiedReport};
use dcap_qvl::QuoteCollateralV3;
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;

use crate::error::AttestError;
use crate::policy::{TcbStatus, TdxPolicy};
use crate::report::Evidence;
use nil_core::Tee;

// --- DCAP quote layout constants (Intel "Quote v4/v5" wire format) ---
//
// These mirror the fixed-layout values `dcap-qvl` itself enforces deeper in its decoder; we
// re-state them here so a structurally broken blob is rejected *before* it reaches the
// cryptographic verifier, with a clear, testable error instead of an opaque decode failure.
// The genuine DCAP verifier remains the authority — these are fail-fast pre-checks, not a
// substitute for signature/chain verification.

/// Quote header length in bytes (`version` .. `user_data`).
const HEADER_BYTE_LEN: usize = 48;
/// `tee_type` value identifying an Intel TDX quote (little-endian `0x0000_0081`).
const TEE_TYPE_TDX: u32 = 0x0000_0081;
/// Quote format versions Intel defines for TDX evidence (v4 standard, v5 with TD15 body).
const ALLOWED_TDX_QUOTE_VERSIONS: [u16; 2] = [4, 5];
/// Smallest TD report body (`TD10`); a TDX quote must carry at least header + this body.
const TD_REPORT10_BYTE_LEN: usize = 584;
/// Domain separator for the 48-byte TDX identity placed in [`Evidence::measurement`]. SHA-384
/// deliberately matches the width of MRTD/RTMR values and the existing measurement protocol slot.
const TDX_IDENTITY_DOMAIN: &[u8] = b"nil/attestation/tdx-identity/v1\0";

/// A clean, cryptographically verified TDX quote rendered as a candidate deployment identity.
///
/// This is deliberately named a candidate: copying claims out of one valid machine is not a
/// substitute for comparing them with the reviewed measured-boot manifest. It exists so release
/// tooling never mistakes raw MRTD for NIL's complete, client-pinned TDX identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentityCandidate {
    /// Raw MRTD, exposed for comparison with the image build/measurement record.
    pub mr_td: [u8; 48],
    /// Exact report policy that matched the verified quote.
    pub policy: TdxPolicy,
    /// NIL's domain-separated SHA-384 digest over MRTD and every field in `policy`.
    pub measurement: [u8; 48],
}

/// Structural pre-validation of a raw DCAP quote / configfs-TSM outblob before it is handed to
/// the `dcap-qvl` verifier. This is defensive depth: the verifier already fails closed on a
/// malformed blob, but these checks turn an opaque decode error into a precise, logged-safe
/// `Malformed` reason and reject obviously-wrong input (truncated outblob, SGX-typed quote,
/// unknown version) without spending work in the crypto path.
///
/// It deliberately does NOT attempt to re-parse the whole quote — that is the verifier's job
/// and duplicating it would be a second, drift-prone source of truth. It only checks the
/// fixed-offset header fields and an overall minimum length.
fn prevalidate_quote(quote_bytes: &[u8]) -> Result<(), AttestError> {
    // Must at least contain the header plus the smallest valid TD report body.
    let min_len = HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN;
    if quote_bytes.len() < min_len {
        return Err(AttestError::Malformed(format!(
            "TDX quote too short: {} bytes, need >= {min_len}",
            quote_bytes.len()
        )));
    }

    // Header is fixed little-endian: version: u16, attestation_key_type: u16, tee_type: u32.
    // Indexing is safe: we verified `len() >= HEADER_BYTE_LEN` (48) above.
    let version = u16::from_le_bytes([quote_bytes[0], quote_bytes[1]]);
    if !ALLOWED_TDX_QUOTE_VERSIONS.contains(&version) {
        return Err(AttestError::Malformed(format!(
            "TDX quote header version {version} not in {ALLOWED_TDX_QUOTE_VERSIONS:?}"
        )));
    }

    let tee_type = u32::from_le_bytes([
        quote_bytes[4],
        quote_bytes[5],
        quote_bytes[6],
        quote_bytes[7],
    ]);
    if tee_type != TEE_TYPE_TDX {
        return Err(AttestError::Malformed(format!(
            "quote tee_type {tee_type:#010x} is not TDX ({TEE_TYPE_TDX:#010x})"
        )));
    }

    Ok(())
}

fn verify_dcap(
    quote_bytes: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    allow_service_td: bool,
) -> Result<VerifiedReport, AttestError> {
    QuoteVerifier::new_prod()
        // A nonzero service-TD identity is accepted only when the relying-party policy explicitly
        // opted into TDREPORT 1.5; appraise_report then pins the exact signed value.
        .allow_service_td(allow_service_td)
        .verify_with::<dcap_qvl::configs::RustCryptoConfig>(quote_bytes, collateral, now_secs)
        .map_err(|e| AttestError::ChainVerification(format!("TDX DCAP verify: {e:?}")))
}

/// Compare one public quote claim in constant time.  These measurements are not secrets, but using
/// one comparison discipline prevents a future caller from accidentally turning a policy field
/// into a prefix/early-exit check.
fn require_exact(label: &'static str, actual: &[u8], expected: &[u8]) -> Result<(), AttestError> {
    if actual.len() != expected.len() || !bool::from(actual.ct_eq(expected)) {
        return Err(AttestError::PolicyViolation(format!(
            "TDX {label} does not match the pinned policy"
        )));
    }
    Ok(())
}

/// Enforce NIL's workload policy over a cryptographically verified TD report.  `dcap-qvl` has
/// already authenticated the report, rejected debug/reserved TD attributes, required
/// `SEPT_VE_DISABLE`, and appraised Intel's signed platform/QE/module collateral.  This layer pins
/// the application-specific values that a generic QVL cannot decide for NIL.
fn appraise_report(report: &Report, policy: &TdxPolicy) -> Result<[u8; 48], AttestError> {
    let (base, service_td) = match report {
        Report::TD10(td) => (td, None),
        Report::TD15(td) => (&td.base, Some(&td.mr_service_td)),
        Report::SgxEnclave(_) => {
            return Err(AttestError::Malformed(
                "expected a TDX quote, got an SGX enclave report".into(),
            ))
        }
    };

    // QVL's production verifier already rejects this bit in the signed report. Reject it in the
    // independently supplied policy as well so a malformed release registry can never express
    // "debug is expected" and so the invariant remains visible/tested in NIL's own layer.
    if policy.td_attributes[0] & 0x01 != 0 || base.td_attributes[0] & 0x01 != 0 {
        return Err(AttestError::PolicyViolation(
            "TDX debug mode is forbidden".into(),
        ));
    }

    for (name, actual, expected) in [
        ("RTMR0", &base.rt_mr0[..], policy.rt_mr0.as_ref()),
        ("RTMR1", &base.rt_mr1[..], policy.rt_mr1.as_ref()),
        ("RTMR2", &base.rt_mr2[..], policy.rt_mr2.as_ref()),
        ("RTMR3", &base.rt_mr3[..], policy.rt_mr3.as_ref()),
    ] {
        if actual.iter().all(|byte| *byte == 0) || expected.iter().all(|byte| *byte == 0) {
            return Err(AttestError::PolicyViolation(format!(
                "TDX {name} must be nonzero in NIL production workload policy"
            )));
        }
    }

    require_exact("TDATTRIBUTES", &base.td_attributes, &policy.td_attributes)?;
    require_exact("XFAM", &base.xfam, &policy.xfam)?;
    require_exact(
        "MRCONFIGID",
        &base.mr_config_id,
        policy.mr_config_id.as_ref(),
    )?;
    require_exact("MROWNER", &base.mr_owner, policy.mr_owner.as_ref())?;
    require_exact(
        "MROWNERCONFIG",
        &base.mr_owner_config,
        policy.mr_owner_config.as_ref(),
    )?;
    require_exact("RTMR0", &base.rt_mr0, policy.rt_mr0.as_ref())?;
    require_exact("RTMR1", &base.rt_mr1, policy.rt_mr1.as_ref())?;
    require_exact("RTMR2", &base.rt_mr2, policy.rt_mr2.as_ref())?;
    require_exact("RTMR3", &base.rt_mr3, policy.rt_mr3.as_ref())?;

    match (service_td, policy.mr_service_td.as_ref()) {
        (None, None) => {}
        (Some(actual), Some(expected)) => require_exact("MRSERVICETD", actual, expected.as_ref())?,
        (None, Some(_)) => {
            return Err(AttestError::PolicyViolation(
                "TDX quote uses a TDREPORT 1.0 body but policy requires TDREPORT 1.5".into(),
            ))
        }
        (Some(_), None) => {
            return Err(AttestError::PolicyViolation(
                "TDX quote uses an unpinned TDREPORT 1.5 body".into(),
            ))
        }
    }
    // Normalize all independently pinned workload claims into the same 48-byte identity slot used
    // by SEV-SNP. This is essential: if the embedded/transparency-logged root contained raw MRTD
    // alone, a compromised Coordinator could keep that MRTD while supplying attacker-chosen RTMR
    // and configuration expectations. The digest makes any such broadening a preimage/collision
    // attack against the client's independent root.
    let mut identity = Sha384::new();
    identity.update(TDX_IDENTITY_DOMAIN);
    identity.update(base.mr_td);
    identity.update(base.td_attributes);
    identity.update(base.xfam);
    identity.update(base.mr_config_id);
    identity.update(base.mr_owner);
    identity.update(base.mr_owner_config);
    identity.update(base.rt_mr0);
    identity.update(base.rt_mr1);
    identity.update(base.rt_mr2);
    identity.update(base.rt_mr3);
    match service_td {
        None => identity.update([0u8]),
        Some(value) => {
            identity.update([1u8]);
            identity.update(value);
        }
    }
    Ok(identity.finalize().into())
}

fn strict_tcb_status(status: String, advisory_ids: &[String]) -> TcbStatus {
    if status == "UpToDate" && advisory_ids.is_empty() {
        TcbStatus::UpToDate
    } else {
        TcbStatus::OutOfDate(format!("{} ({} advisory IDs)", status, advisory_ids.len()))
    }
}

/// Verify a quote and collateral at `now_secs`, require a clean TCB verdict, and return the exact
/// TDX identity values observed in that quote. Operators must still compare the candidate with the
/// signed measured-boot/release manifest before publishing it as policy.
pub fn verified_identity_candidate(
    quote_bytes: &[u8],
    collateral_json: &[u8],
    now_secs: u64,
) -> Result<VerifiedIdentityCandidate, AttestError> {
    prevalidate_quote(quote_bytes)?;
    let collateral: QuoteCollateralV3 = serde_json::from_slice(collateral_json)
        .map_err(|e| AttestError::Malformed(format!("TDX collateral JSON: {e}")))?;
    // Candidate extraction may observe a service TD, but it still pins that exact value into the
    // returned identity and is explicitly not an approval decision.
    let verified = verify_dcap(quote_bytes, &collateral, now_secs, true)?;
    if strict_tcb_status(verified.status.clone(), &verified.advisory_ids) != TcbStatus::UpToDate {
        return Err(AttestError::PolicyViolation(
            "TDX identity candidates require an UpToDate collateral verdict with no advisories"
                .into(),
        ));
    }

    let (base, mr_service_td) = match &verified.report {
        Report::TD10(td) => (td, None),
        Report::TD15(td) => (&td.base, Some(td.mr_service_td.into())),
        Report::SgxEnclave(_) => {
            return Err(AttestError::Malformed(
                "expected a TDX quote, got an SGX enclave report".into(),
            ))
        }
    };
    let policy = TdxPolicy {
        td_attributes: base.td_attributes,
        xfam: base.xfam,
        mr_config_id: base.mr_config_id.into(),
        mr_owner: base.mr_owner.into(),
        mr_owner_config: base.mr_owner_config.into(),
        rt_mr0: base.rt_mr0.into(),
        rt_mr1: base.rt_mr1.into(),
        rt_mr2: base.rt_mr2.into(),
        rt_mr3: base.rt_mr3.into(),
        mr_service_td,
    };
    let measurement = appraise_report(&verified.report, &policy)?;
    Ok(VerifiedIdentityCandidate {
        mr_td: base.mr_td,
        policy,
        measurement,
    })
}

/// Verify a TDX `quote` against its JSON `collateral` at time `now_secs`, then enforce the exact
/// NIL workload `policy`. Returns the domain-separated complete TDX identity + `report_data` on
/// success; raw MRTD alone is intentionally never exposed as the normalized trusted measurement.
pub fn verify(
    quote_bytes: &[u8],
    collateral_json: &[u8],
    now_secs: u64,
    policy: &TdxPolicy,
) -> Result<Evidence, AttestError> {
    // Fail fast on a structurally malformed outblob before touching the crypto verifier.
    prevalidate_quote(quote_bytes)?;

    let collateral: QuoteCollateralV3 = serde_json::from_slice(collateral_json)
        .map_err(|e| AttestError::Malformed(format!("TDX collateral JSON: {e}")))?;

    let verified = verify_dcap(
        quote_bytes,
        &collateral,
        now_secs,
        policy.mr_service_td.is_some(),
    )?;

    let measurement = appraise_report(&verified.report, policy)?;

    let report_data = match verified.report {
        Report::TD10(td) => td.report_data,
        Report::TD15(td) => td.base.report_data,
        Report::SgxEnclave(_) => {
            return Err(AttestError::Malformed(
                "expected a TDX quote, got an SGX enclave report".into(),
            ))
        }
    };

    // A status of UpToDate with advisory IDs is not equivalent to a clean quote for NIL. Preserve
    // the strict result as OutOfDate so the top-level policy rejects it; do not log/persist the IDs.
    let tcb_status = strict_tcb_status(verified.status, &verified.advisory_ids);

    Ok(Evidence {
        tee: Tee::Tdx,
        measurement: measurement.to_vec(),
        report_data,
        tcb_status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_qvl::quote::{TDReport10, TDReport15};

    fn sample_report() -> TDReport10 {
        TDReport10 {
            tee_tcb_svn: [1u8; 16],
            mr_seam: [2u8; 48],
            mr_signer_seam: [3u8; 48],
            seam_attributes: [0u8; 8],
            td_attributes: [4u8; 8],
            xfam: [5u8; 8],
            mr_td: [6u8; 48],
            mr_config_id: [7u8; 48],
            mr_owner: [8u8; 48],
            mr_owner_config: [9u8; 48],
            rt_mr0: [10u8; 48],
            rt_mr1: [11u8; 48],
            rt_mr2: [12u8; 48],
            rt_mr3: [13u8; 48],
            report_data: [14u8; 64],
        }
    }

    fn sample_policy(report: &TDReport10) -> TdxPolicy {
        TdxPolicy {
            td_attributes: report.td_attributes,
            xfam: report.xfam,
            mr_config_id: report.mr_config_id.into(),
            mr_owner: report.mr_owner.into(),
            mr_owner_config: report.mr_owner_config.into(),
            rt_mr0: report.rt_mr0.into(),
            rt_mr1: report.rt_mr1.into(),
            rt_mr2: report.rt_mr2.into(),
            rt_mr3: report.rt_mr3.into(),
            mr_service_td: None,
        }
    }

    /// A header that would otherwise pass the structural pre-checks (TDX v4), padded out to the
    /// minimum quote length. The bytes are not a real signed quote — these tests only exercise
    /// `prevalidate_quote`; genuine end-to-end verification is covered by the TDX KAT.
    fn well_formed_header_blob() -> Vec<u8> {
        let mut blob = vec![0u8; HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN];
        blob[0..2].copy_from_slice(&4u16.to_le_bytes()); // version = 4
        blob[4..8].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());
        blob
    }

    #[test]
    fn too_short_outblob_is_rejected() {
        let err = prevalidate_quote(&[0u8; 16]).unwrap_err();
        match err {
            AttestError::Malformed(m) => assert!(m.contains("too short"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn empty_outblob_is_rejected() {
        assert!(matches!(
            prevalidate_quote(&[]),
            Err(AttestError::Malformed(_))
        ));
    }

    #[test]
    fn unknown_quote_version_is_rejected() {
        let mut blob = well_formed_header_blob();
        blob[0..2].copy_from_slice(&3u16.to_le_bytes()); // v3 = SGX-era, not a TDX quote
        let err = prevalidate_quote(&blob).unwrap_err();
        match err {
            AttestError::Malformed(m) => assert!(m.contains("version"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn non_tdx_tee_type_is_rejected() {
        let mut blob = well_formed_header_blob();
        blob[4..8].copy_from_slice(&0u32.to_le_bytes()); // TEE_TYPE_SGX
        let err = prevalidate_quote(&blob).unwrap_err();
        match err {
            AttestError::Malformed(m) => assert!(m.contains("tee_type"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_header_passes_prevalidation() {
        // Structural pre-checks pass; this says nothing about signature validity, which the
        // genuine DCAP verifier (exercised by the KAT) enforces afterward.
        assert!(prevalidate_quote(&well_formed_header_blob()).is_ok());
    }

    #[test]
    fn exact_td10_workload_policy_is_accepted() {
        let report = sample_report();
        appraise_report(&Report::TD10(report), &sample_policy(&report)).unwrap();
    }

    #[test]
    fn debug_td_or_debug_policy_is_rejected() {
        let clean = sample_report();
        let clean_policy = sample_policy(&clean);

        let mut debug_report = clean;
        debug_report.td_attributes[0] |= 1;
        let err = appraise_report(&Report::TD10(debug_report), &clean_policy).unwrap_err();
        assert!(matches!(
            err,
            AttestError::PolicyViolation(message) if message.contains("debug")
        ));

        let mut debug_policy = clean_policy;
        debug_policy.td_attributes[0] |= 1;
        let err = appraise_report(&Report::TD10(clean), &debug_policy).unwrap_err();
        assert!(matches!(
            err,
            AttestError::PolicyViolation(message) if message.contains("debug")
        ));
    }

    #[test]
    fn every_tdx_workload_identity_field_is_pinned() {
        let report = sample_report();
        let exact = sample_policy(&report);
        let mut cases = Vec::new();

        let mut changed = exact.clone();
        changed.td_attributes[1] ^= 1;
        cases.push(("TDATTRIBUTES", changed));
        let mut changed = exact.clone();
        changed.xfam[0] ^= 1;
        cases.push(("XFAM", changed));
        let mut changed = exact.clone();
        changed.mr_config_id.0[0] ^= 1;
        cases.push(("MRCONFIGID", changed));
        let mut changed = exact.clone();
        changed.mr_owner.0[0] ^= 1;
        cases.push(("MROWNER", changed));
        let mut changed = exact.clone();
        changed.mr_owner_config.0[0] ^= 1;
        cases.push(("MROWNERCONFIG", changed));
        let mut changed = exact.clone();
        changed.rt_mr0.0[0] ^= 1;
        cases.push(("RTMR0", changed));
        let mut changed = exact.clone();
        changed.rt_mr1.0[0] ^= 1;
        cases.push(("RTMR1", changed));
        let mut changed = exact.clone();
        changed.rt_mr2.0[0] ^= 1;
        cases.push(("RTMR2", changed));
        let mut changed = exact;
        changed.rt_mr3.0[0] ^= 1;
        cases.push(("RTMR3", changed));

        for (field, policy) in cases {
            let err = appraise_report(&Report::TD10(report), &policy).unwrap_err();
            assert!(
                matches!(err, AttestError::PolicyViolation(message) if message.contains(field)),
                "a mismatch in {field} must fail closed"
            );
        }
    }

    #[test]
    fn every_tdx_claim_changes_the_client_pinned_composite_identity() {
        let original = sample_report();
        let baseline = appraise_report(&Report::TD10(original), &sample_policy(&original)).unwrap();
        let mut cases = Vec::new();

        let mut changed = original;
        changed.mr_td[0] ^= 1;
        cases.push(("MRTD", changed));
        let mut changed = original;
        changed.td_attributes[1] ^= 1;
        cases.push(("TDATTRIBUTES", changed));
        let mut changed = original;
        changed.xfam[0] ^= 1;
        cases.push(("XFAM", changed));
        let mut changed = original;
        changed.mr_config_id[0] ^= 1;
        cases.push(("MRCONFIGID", changed));
        let mut changed = original;
        changed.mr_owner[0] ^= 1;
        cases.push(("MROWNER", changed));
        let mut changed = original;
        changed.mr_owner_config[0] ^= 1;
        cases.push(("MROWNERCONFIG", changed));
        let mut changed = original;
        changed.rt_mr0[0] ^= 1;
        cases.push(("RTMR0", changed));
        let mut changed = original;
        changed.rt_mr1[0] ^= 1;
        cases.push(("RTMR1", changed));
        let mut changed = original;
        changed.rt_mr2[0] ^= 1;
        cases.push(("RTMR2", changed));
        let mut changed = original;
        changed.rt_mr3[0] ^= 1;
        cases.push(("RTMR3", changed));

        for (field, report) in cases {
            let identity = appraise_report(&Report::TD10(report), &sample_policy(&report)).unwrap();
            assert_ne!(identity, baseline, "{field} must be bound into the digest");
        }

        let td15 = Report::TD15(TDReport15 {
            base: original,
            tee_tcb_svn2: [15u8; 16],
            mr_service_td: [16u8; 48],
        });
        let mut td15_policy = sample_policy(&original);
        td15_policy.mr_service_td = Some([16u8; 48].into());
        let td15_identity = appraise_report(&td15, &td15_policy).unwrap();
        assert_ne!(
            td15_identity, baseline,
            "body kind/service TD must be bound"
        );
    }

    #[test]
    fn every_runtime_register_is_required_to_be_nonzero() {
        for index in 0..4 {
            let mut report = sample_report();
            match index {
                0 => report.rt_mr0 = [0u8; 48],
                1 => report.rt_mr1 = [0u8; 48],
                2 => report.rt_mr2 = [0u8; 48],
                3 => report.rt_mr3 = [0u8; 48],
                _ => unreachable!(),
            }
            let policy = sample_policy(&report);
            let error = appraise_report(&Report::TD10(report), &policy).unwrap_err();
            assert!(
                matches!(error, AttestError::PolicyViolation(message) if message.contains(&format!("RTMR{index}")) && message.contains("nonzero"))
            );
        }
    }

    #[test]
    fn td_report_body_version_and_service_identity_are_pinned() {
        let base = sample_report();
        let td15 = Report::TD15(TDReport15 {
            base,
            tee_tcb_svn2: [15u8; 16],
            // The production QVL requires this to be zero unless service-TD support is explicitly
            // enabled. NIL still pins the field and body shape instead of relying on that default.
            mr_service_td: [0u8; 48],
        });
        let td10_policy = sample_policy(&base);
        assert!(matches!(
            appraise_report(&td15, &td10_policy),
            Err(AttestError::PolicyViolation(_))
        ));

        let mut td15_policy = td10_policy.clone();
        td15_policy.mr_service_td = Some([0u8; 48].into());
        appraise_report(&td15, &td15_policy).unwrap();
        assert!(matches!(
            appraise_report(&Report::TD10(base), &td15_policy),
            Err(AttestError::PolicyViolation(_))
        ));

        td15_policy.mr_service_td = Some([1u8; 48].into());
        let err = appraise_report(&td15, &td15_policy).unwrap_err();
        assert!(matches!(
            err,
            AttestError::PolicyViolation(message) if message.contains("MRSERVICETD")
        ));
    }

    #[test]
    fn tdx_tcb_requires_up_to_date_with_no_advisories() {
        assert_eq!(
            strict_tcb_status("UpToDate".into(), &[]),
            TcbStatus::UpToDate
        );
        assert!(matches!(
            strict_tcb_status("OutOfDate".into(), &[]),
            TcbStatus::OutOfDate(_)
        ));
        assert!(matches!(
            strict_tcb_status("UpToDate".into(), &["INTEL-SA-00000".into()]),
            TcbStatus::OutOfDate(_)
        ));
    }
}
