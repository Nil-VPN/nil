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

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use nil_core::Tee;

/// The configfs-TSM report directory. Creating a sub-directory allocates a fresh report slot.
const TSM_REPORT: &str = "/sys/kernel/config/tsm/report";
const MAX_VCEK_BYTES: u64 = 64 * 1024;
const MAX_TDX_COLLATERAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TRANSPARENCY_PROOF_BYTES: u64 = 256 * 1024;

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
            let path = std::env::var("NW_VCEK_PATH").map_err(|_| {
                anyhow::anyhow!(
                    "NW_VCEK_PATH unset (need the VCEK DER for offline SEV-SNP verification)"
                )
            })?;
            let vcek = read_bounded_regular(Path::new(&path), "VCEK", MAX_VCEK_BYTES)?;
            (ratls::TAG_SEVSNP, vec![outblob, vcek])
        }
        Tee::Tdx => {
            let path = std::env::var("NW_TDX_COLLATERAL")
                .map_err(|_| anyhow::anyhow!("NW_TDX_COLLATERAL unset (need DCAP collateral JSON for offline TDX verification)"))?;
            let collateral =
                read_bounded_regular(Path::new(&path), "TDX collateral", MAX_TDX_COLLATERAL_BYTES)?;
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
/// `NW_TRANSPARENCY_BUNDLE` points at a file of serialized `nil_crypto::translog::LogProof` bytes.
/// That is currently the NIL-specific Ed25519/RFC-6962 format, not a cosign/Sigstore bundle; no
/// reviewed Rekor conversion path exists yet. Unset ⇒ `None` ⇒ evidence carries no proof, and a
/// client that pins a log key will then refuse — fail closed, never silently unlogged.
fn transparency_bundle() -> Result<Option<Vec<u8>>> {
    match std::env::var("NW_TRANSPARENCY_BUNDLE") {
        Ok(path) => {
            let bytes = read_bounded_regular(
                Path::new(&path),
                "transparency proof",
                MAX_TRANSPARENCY_PROOF_BYTES,
            )?;
            Ok(Some(bytes))
        }
        Err(_) => Ok(None),
    }
}

/// Read one operator-provisioned public artifact without following a symlink or accepting a
/// device/FIFO, empty file, or unbounded allocation. These files are parsed on the connection path;
/// a bad mount must fail closed quickly rather than block or exhaust the attested node.
fn read_bounded_regular(path: &Path, label: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat opened {label} {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.len() == 0 || metadata.len() > max_bytes {
        anyhow::bail!(
            "{label} {} must contain 1..={max_bytes} bytes",
            path.display()
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label} {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        anyhow::bail!(
            "{label} {} changed size while reading or exceeds {max_bytes} bytes",
            path.display()
        );
    }
    Ok(bytes)
}

/// Request one report from the kernel: create a TSM report slot, write the 64-byte `report_data`
/// to `inblob`, read the raw report/quote from `outblob`, and remove the slot.
fn fetch_outblob(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    let name = format!(
        "nil-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let dir = std::path::Path::new(TSM_REPORT).join(&name);
    std::fs::create_dir(&dir).with_context(|| {
        format!(
            "create {} (is this a TEE guest with configfs-TSM mounted?)",
            dir.display()
        )
    })?;
    // Always remove the slot, even on error.
    let result = (|| -> Result<Vec<u8>> {
        std::fs::write(dir.join("inblob"), &report_data[..])
            .context("write inblob (report_data)")?;
        let outblob = std::fs::read(dir.join("outblob")).context("read outblob (report)")?;
        if outblob.is_empty() {
            anyhow::bail!("configfs-TSM returned an empty report");
        }
        Ok(outblob)
    })();
    let _ = std::fs::remove_dir(&dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "nil-node-hw-{label}-{}-{}",
            std::process::id(),
            TEST_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn provisioned_artifact_reader_is_bounded_and_regular() {
        let path = test_path("bounded");
        std::fs::write(&path, [1u8, 2, 3]).unwrap();
        assert_eq!(
            read_bounded_regular(&path, "fixture", 3).unwrap(),
            [1, 2, 3]
        );
        assert!(read_bounded_regular(&path, "fixture", 2).is_err());
        std::fs::write(&path, []).unwrap();
        assert!(read_bounded_regular(&path, "fixture", 3).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn provisioned_artifact_reader_refuses_symlinks() {
        use std::os::unix::fs::symlink;

        let path = test_path("target");
        let link = test_path("link");
        std::fs::write(&path, [7u8; 4]).unwrap();
        symlink(&path, &link).unwrap();
        assert!(read_bounded_regular(&link, "fixture", 4).is_err());
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(path);
    }
}
