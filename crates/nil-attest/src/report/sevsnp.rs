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
use nil_core::Tee;

/// Verify a SEV-SNP `report` against its `vcek` (DER), rooted in the built-in AMD ARK/ASK.
/// Returns the launch measurement + `report_data` on success.
pub fn verify(report_bytes: &[u8], vcek_der: &[u8]) -> Result<Evidence, AttestError> {
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

    Ok(Evidence {
        tee: Tee::SevSnp,
        measurement: report.measurement.to_vec(),
        report_data: report.report_data,
        // SEV-SNP carries no signed TCB-status verdict; the reported TCB is in the (verified)
        // report and a future policy can gate on it. For now a verified report is UpToDate.
        tcb_status: TcbStatus::UpToDate,
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
