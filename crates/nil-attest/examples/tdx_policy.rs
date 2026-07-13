//! Render a cryptographically verified TDX quote as a candidate NIL registry policy.
//!
//! The output is not self-approving: an operator/reviewer must compare every value with the signed
//! measured-boot manifest before copying `measurement` and `tdx_policy` into a registry entry.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, io::Read};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid_input(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

fn read_bounded(path: &Path, label: &str, max: u64) -> Result<Vec<u8>> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(invalid_input(format!("{label} must not be a symbolic link")).into());
    }
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > max {
        return Err(invalid_input(format!(
            "{label} must be a non-empty regular file no larger than {max} bytes"
        ))
        .into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref().take(max + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err(invalid_input(format!(
            "{label} changed size while reading or exceeds {max} bytes"
        ))
        .into());
    }
    Ok(bytes)
}

fn main() -> Result<()> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err(invalid_input(
            "usage: cargo run -p nil-attest --example tdx_policy -- QUOTE COLLATERAL_JSON",
        )
        .into());
    }
    let quote = read_bounded(Path::new(&args[1]), "TDX quote", 1024 * 1024)?;
    let collateral = read_bounded(Path::new(&args[2]), "TDX collateral", 4 * 1024 * 1024)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid_input("system clock is before the Unix epoch"))?
        .as_secs();
    let candidate = nil_attest::report::tdx::verified_identity_candidate(&quote, &collateral, now)?;
    let policy = candidate.policy;
    let output = serde_json::json!({
        "measurement": hex(&candidate.measurement),
        "raw_mrtd_for_review": hex(&candidate.mr_td),
        "tdx_policy": {
            "td_attributes": hex(&policy.td_attributes),
            "xfam": hex(&policy.xfam),
            "mr_config_id": hex(policy.mr_config_id.as_ref()),
            "mr_owner": hex(policy.mr_owner.as_ref()),
            "mr_owner_config": hex(policy.mr_owner_config.as_ref()),
            "rt_mr0": hex(policy.rt_mr0.as_ref()),
            "rt_mr1": hex(policy.rt_mr1.as_ref()),
            "rt_mr2": hex(policy.rt_mr2.as_ref()),
            "rt_mr3": hex(policy.rt_mr3.as_ref()),
            "mr_service_td": policy.mr_service_td.as_ref().map(|value| hex(value.as_ref())),
        }
    });
    eprintln!(
        "REVIEW REQUIRED: compare this clean verified quote with the signed measured-boot manifest; raw MRTD is not the NIL registry measurement"
    );
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
