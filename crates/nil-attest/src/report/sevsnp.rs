//! AMD SEV-SNP report verification via the `sev` crate (pure-Rust `crypto_nossl` path).
//!
//! Chain of trust: AMD root key (ARK, built into the `sev` crate per CPU generation) →
//! signing key (ASK) → the per-chip VCEK (transmitted by the node alongside the report) →
//! the attestation report's ECDSA-P384 signature. We verify the whole chain offline against
//! the built-in AMD roots; the only chip-specific input is the VCEK.

use sev::certs::snp::{builtin, ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

use crate::error::AttestError;
use crate::policy::TcbStatus;
use crate::report::Evidence;
use nil_core::{SevSnpTcbFloor, Tee};

/// Verify a SEV-SNP `report` against its `vcek` (DER), rooted in the built-in AMD ARK/ASK.
/// `min_tcb` is the caller's pinned minimum platform TCB floor (`None` = no floor).
/// Returns the launch measurement + `report_data` on success.
pub fn verify(
    report_bytes: &[u8],
    vcek_der: &[u8],
    min_tcb: Option<SevSnpTcbFloor>,
) -> Result<Evidence, AttestError> {
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|e| AttestError::Malformed(format!("SEV-SNP report decode: {e}")))?;

    let vek = Certificate::from_der(vcek_der)
        .map_err(|e| AttestError::Cert(format!("VCEK DER: {e}")))?;

    // The report doesn't cheaply self-describe its CPU generation, so try each built-in AMD
    // root in turn; the correct one verifies ARK→ASK→VCEK→report and the rest fail fast.
    let chain = verifying_chain(&vek, &report)?;
    (&chain, &report)
        .verify()
        .map_err(|e| AttestError::ChainVerification(format!("SEV-SNP chain/report: {e}")))?;

    // Appraise the now-cryptographically-trusted report's claims (policy + TCB).
    appraise_report(&report, min_tcb)
}

/// Appraise an already chain-verified report's claims: reject an unsafe guest policy, classify
/// the TCB (rollback and pinned-floor), and normalize to [`Evidence`]. Split out from [`verify`]
/// so the policy/TCB logic can be unit-tested on a constructed report without forging an AMD chain.
fn appraise_report(
    report: &AttestationReport,
    min_tcb: Option<SevSnpTcbFloor>,
) -> Result<Evidence, AttestError> {
    // Guest policy gate (fail closed). A DEBUG-enabled guest lets the host/operator read and
    // tamper with guest memory through the PSP debug interface — that defeats the entire
    // confidential-computing guarantee, so a verified-but-debuggable report must be rejected
    // BEFORE any measurement/binding check would otherwise admit it.
    if report.policy.debug_allowed() {
        return Err(AttestError::PolicyViolation(
            "SEV-SNP guest policy permits DEBUG (memory introspection)".into(),
        ));
    }

    // Reject a guest whose policy permits MIGRATION. A migratable guest can be live-migrated by the
    // host — via a migration agent — to another machine the operator controls, moving the running
    // node (and whatever transient state it holds) outside the attested measurement's guarantees.
    // For a no-logs privacy node that must never be relocatable by the host, migration must be
    // disabled; fail closed like DEBUG.
    if report.policy.migrate_ma_allowed() {
        return Err(AttestError::PolicyViolation(
            "SEV-SNP guest policy permits migration (MIGRATE_MA)".into(),
        ));
    }

    // TCB status (parity with the TDX path, which propagates a signed verdict). SEV-SNP carries
    // no signed status string, but the report does carry the running `current_tcb` and the
    // platform's `committed_tcb` — the minimum the firmware promised never to drop below. A
    // `current_tcb` that has rolled back beneath `committed_tcb` is a down-revved platform
    // running a patch level it already superseded (e.g. to re-expose a fixed vulnerability),
    // so we surface it as OutOfDate. `appraise` then rejects it unless policy opts in, exactly
    // as it does for an out-of-date TDX quote.
    // A pinned minimum-TCB floor (offline, caller-supplied) catches the case the rollback check
    // cannot: a node whose current_tcb is at/above its OWN committed_tcb but still below the patch
    // level NIL requires fleet-wide (e.g. a platform never updated past a level with a known fix).
    // Compared component-wise (see SevSnpTcbFloor::is_met_by), never lexicographically.
    let tcb = &report.current_tcb;
    let tcb_status = if *tcb < report.committed_tcb {
        TcbStatus::OutOfDate("SEV-SNP current_tcb below committed_tcb".into())
    } else if min_tcb
        .is_some_and(|f| !f.is_met_by(tcb.fmc, tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode))
    {
        TcbStatus::OutOfDate("SEV-SNP current_tcb below pinned minimum floor".into())
    } else {
        TcbStatus::UpToDate
    };

    Ok(Evidence {
        tee: Tee::SevSnp,
        measurement: report.measurement.to_vec(),
        report_data: report.report_data,
        tcb_status,
    })
}

/// Build the `ARK→ASK→VCEK` chain whose ARK/ASK actually verify this report, trying each
/// built-in AMD generation. Returns the first chain that fully verifies.
fn verifying_chain(vek: &Certificate, report: &AttestationReport) -> Result<Chain, AttestError> {
    let cas = [
        ("milan", builtin::milan::ark(), builtin::milan::ask()),
        ("genoa", builtin::genoa::ark(), builtin::genoa::ask()),
        ("turin", builtin::turin::ark(), builtin::turin::ask()),
    ];
    let mut last = String::from("no built-in AMD generation matched");
    for (name, ark, ask) in cas {
        let (Ok(ark), Ok(ask)) = (ark, ask) else { continue };
        let chain = Chain { ca: ca::Chain { ark, ask }, vek: vek.clone() };
        match (&chain, report).verify() {
            Ok(()) => return Ok(chain),
            Err(e) => last = format!("{name}: {e}"),
        }
    }
    Err(AttestError::ChainVerification(last))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::firmware::host::TcbVersion;

    /// A baseline report whose chain check is irrelevant (we call `appraise_report` directly):
    /// safe guest policy, current TCB at or above committed. Mutate it per test.
    fn baseline_report() -> AttestationReport {
        let mut report = AttestationReport::default();
        // Default GuestPolicy has DEBUG + MIGRATE_MA clear; be explicit so the baseline can't drift.
        report.policy.set_debug_allowed(false);
        report.policy.set_migrate_ma_allowed(false);
        let tcb = TcbVersion::new(None, 5, 0, 10, 20);
        report.committed_tcb = tcb;
        report.current_tcb = tcb;
        report
    }

    #[test]
    fn safe_policy_uptodate_tcb_is_accepted() {
        let report = baseline_report();
        let ev = appraise_report(&report, None).expect("safe, up-to-date report must appraise");
        assert_eq!(ev.tee, Tee::SevSnp);
        assert_eq!(ev.tcb_status, TcbStatus::UpToDate);
    }

    #[test]
    fn debug_enabled_policy_is_rejected() {
        let mut report = baseline_report();
        // Operator-debuggable guest: can read VM memory. Must fail closed.
        report.policy.set_debug_allowed(true);
        match appraise_report(&report, None) {
            Err(AttestError::PolicyViolation(_)) => {}
            other => panic!("DEBUG-enabled guest policy must be a PolicyViolation, got {other:?}"),
        }
    }

    #[test]
    fn migration_enabled_policy_is_rejected() {
        let mut report = baseline_report();
        // Migratable guest: the host can relocate the running node to a machine it controls,
        // outside the attested measurement's guarantees. Must fail closed.
        report.policy.set_migrate_ma_allowed(true);
        match appraise_report(&report, None) {
            Err(AttestError::PolicyViolation(_)) => {}
            other => panic!("MIGRATE_MA-enabled guest policy must be a PolicyViolation, got {other:?}"),
        }
    }

    #[test]
    fn down_revved_tcb_is_out_of_date() {
        let mut report = baseline_report();
        // current_tcb rolled back below committed_tcb: a superseded (vulnerable) patch level.
        report.committed_tcb = TcbVersion::new(None, 5, 0, 10, 20);
        report.current_tcb = TcbVersion::new(None, 5, 0, 10, 19);
        let ev = appraise_report(&report, None).expect("a down-revved report still appraises (classified)");
        // Parity with TDX: surfaced as OutOfDate so `appraise` rejects it under default policy.
        assert!(matches!(ev.tcb_status, TcbStatus::OutOfDate(_)), "down-revved TCB must be OutOfDate");
    }

    #[test]
    fn below_pinned_min_tcb_floor_is_out_of_date() {
        // Baseline microcode is 20; require 21. current_tcb is NOT below committed_tcb (no rollback),
        // so only the pinned floor catches it — exactly the fleet-wide-minimum case.
        let report = baseline_report();
        let floor = SevSnpTcbFloor { fmc: None, bootloader: 5, tee: 0, snp: 10, microcode: 21 };
        let ev = appraise_report(&report, Some(floor)).expect("still appraises (classified)");
        assert!(
            matches!(ev.tcb_status, TcbStatus::OutOfDate(_)),
            "current_tcb below the pinned floor must be OutOfDate"
        );
    }

    #[test]
    fn at_pinned_min_tcb_floor_is_uptodate() {
        // Floor exactly equals the baseline TCB — every component is met.
        let report = baseline_report();
        let floor = SevSnpTcbFloor { fmc: None, bootloader: 5, tee: 0, snp: 10, microcode: 20 };
        let ev = appraise_report(&report, Some(floor)).expect("at-floor report must appraise");
        assert_eq!(ev.tcb_status, TcbStatus::UpToDate);
    }

    #[test]
    fn min_tcb_floor_is_componentwise_not_lexicographic() {
        // Report is (bl=5, mc=20); floor is (bl=4, mc=21). A lexicographic TcbVersion compare would
        // pass (bootloader 5 > 4 dominates), but a lagging microcode can be the one with the fix —
        // so the component-wise check must FAIL closed.
        let report = baseline_report();
        let floor = SevSnpTcbFloor { fmc: None, bootloader: 4, tee: 0, snp: 10, microcode: 21 };
        let ev = appraise_report(&report, Some(floor)).expect("still appraises (classified)");
        assert!(
            matches!(ev.tcb_status, TcbStatus::OutOfDate(_)),
            "ahead-on-one-component-behind-on-another must be OutOfDate (component-wise floor)"
        );
    }

    #[test]
    fn fmc_floor_unmet_by_pre_turin_report_is_out_of_date() {
        // A pre-Turin node reports no FMC (fmc = None → treated as 0); a floor requiring FMC >= 3
        // cannot be satisfied, so it must fail closed rather than silently pass.
        let report = baseline_report(); // fmc is None on the default report
        let floor = SevSnpTcbFloor { fmc: Some(3), bootloader: 5, tee: 0, snp: 10, microcode: 20 };
        let ev = appraise_report(&report, Some(floor)).expect("still appraises (classified)");
        assert!(
            matches!(ev.tcb_status, TcbStatus::OutOfDate(_)),
            "an unmet FMC floor must be OutOfDate"
        );
    }
}
