//! Production attestation report provider via the kernel **configfs-TSM** interface
//! (`/sys/kernel/config/tsm/report`, Linux ≥ 6.7), which unifies AMD SEV-SNP and Intel TDX
//! report generation behind one filesystem API.
//!
//! This closes the gap where a non-`synthetic-attest` node emitted no report at all (so a
//! pinning client refused every node). It is **compile-checked in CI but only exercised on real
//! TEE hardware** — without `/sys/kernel/config/tsm` the fetch fails and the node falls back to
//! "no report", which keeps the client fail-closed.
//!
//! The report is bound to the node's TLS key + the client's freshness nonce via the 64-byte
//! `report_data` (`SHA-512(SHA-256(spki) ‖ nonce)`), the SAME binding the client recomputes, and
//! packed in the SAME `nil-attest` `[tag][parts]` codec the client decodes — so the two can't
//! drift. The material needed for OFFLINE verification (the SEV-SNP VCEK, or the TDX DCAP
//! collateral) is operator-provisioned via `NW_VCEK_PATH` / `NW_TDX_COLLATERAL` (the guest fetches
//! the VCEK from AMD KDS once at provisioning; the TDX collateral comes from Intel's PCS).

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use nil_core::Tee;

/// The configfs-TSM report directory. Creating a sub-directory allocates a fresh report slot.
const TSM_REPORT: &str = "/sys/kernel/config/tsm/report";

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Build the RA-TLS evidence blob the client appraises (`[tag][parts]`), bound to `spki` +
/// `nonce`. Errors if the TSM interface or the provisioned VCEK/collateral is unavailable; the
/// caller then returns no report and the client fails closed.
pub fn report_evidence(tee: Tee, spki: &[u8], nonce: &[u8; 32]) -> Result<Vec<u8>> {
    use nil_attest::ratls;

    let report_data = ratls::bind_report_data(spki, nonce);
    let outblob = fetch_outblob(&report_data).context("configfs-TSM report fetch")?;
    // Optional stapled transparency-log inclusion proof (the client verifies it iff it pinned a log
    // key). Appended as one trailing evidence part, which the codec already tolerates.
    let stapled = transparency_bundle()?;
    let (tag, base): (u8, Vec<Vec<u8>>) = match tee {
        Tee::SevSnp => {
            let path = std::env::var("NW_VCEK_PATH")
                .map_err(|_| anyhow::anyhow!("NW_VCEK_PATH unset (need the VCEK DER for offline SEV-SNP verification)"))?;
            let vcek = std::fs::read(&path).with_context(|| format!("read VCEK {path}"))?;
            (ratls::TAG_SEVSNP, vec![outblob, vcek])
        }
        Tee::Tdx => {
            let path = std::env::var("NW_TDX_COLLATERAL")
                .map_err(|_| anyhow::anyhow!("NW_TDX_COLLATERAL unset (need DCAP collateral JSON for offline TDX verification)"))?;
            let collateral = std::fs::read(&path).with_context(|| format!("read TDX collateral {path}"))?;
            (ratls::TAG_TDX, vec![outblob, collateral])
        }
    };
    let mut parts: Vec<&[u8]> = base.iter().map(Vec::as_slice).collect();
    if let Some(proof) = &stapled {
        parts.push(proof);
    }
    Ok(ratls::encode(tag, &parts))
}

/// Read the operator-provisioned stapled transparency-log inclusion proof, if any.
/// `NW_TRANSPARENCY_BUNDLE` points at a file of serialized `nil_crypto::translog::LogProof` bytes
/// (the deploy pipeline emits it from a Rekor bundle). Unset ⇒ `None` ⇒ evidence carries no proof,
/// and a client that pins a log key will then refuse — fail closed, never silently unlogged.
fn transparency_bundle() -> Result<Option<Vec<u8>>> {
    match std::env::var("NW_TRANSPARENCY_BUNDLE") {
        Ok(path) => {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("read transparency bundle {path}"))?;
            Ok(Some(bytes))
        }
        Err(_) => Ok(None),
    }
}

/// Request one report from the kernel: create a TSM report slot, write the 64-byte `report_data`
/// to `inblob`, read the raw report/quote from `outblob`, and remove the slot.
fn fetch_outblob(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    let name = format!("nil-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
    let dir = std::path::Path::new(TSM_REPORT).join(&name);
    std::fs::create_dir(&dir).with_context(|| {
        format!("create {} (is this a TEE guest with configfs-TSM mounted?)", dir.display())
    })?;
    // Always remove the slot, even on error.
    let result = (|| -> Result<Vec<u8>> {
        std::fs::write(dir.join("inblob"), &report_data[..]).context("write inblob (report_data)")?;
        let outblob = std::fs::read(dir.join("outblob")).context("read outblob (report)")?;
        if outblob.is_empty() {
            anyhow::bail!("configfs-TSM returned an empty report");
        }
        Ok(outblob)
    })();
    let _ = std::fs::remove_dir(&dir);
    result
}
