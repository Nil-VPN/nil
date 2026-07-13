//! Shared trust-bundle v1 schema and structural validation.
//!
//! This file is compiled twice: by `build.rs` before a client binary is produced, and by the
//! runtime `trust` module. Keeping one parser prevents a release build and the shipped client from
//! disagreeing about which roots were approved.

use serde::{Deserialize, Serialize};

pub const TRUST_BUNDLE_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBundleV1 {
    pub version: u8,
    /// Globally published token-issuer public keys, SPKI DER encoded as lowercase hex.
    pub issuer_public_keys_der: Vec<String>,
    /// Accepted confidential-guest launch measurements (48 bytes each), as lowercase hex.
    pub node_measurements: Vec<String>,
    /// Ed25519 public key for the independent measurement transparency log, as lowercase hex.
    pub transparency_log_ed25519_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTrustBundle {
    pub canonical_json: String,
    pub issuer_public_keys_der: Vec<Vec<u8>>,
    pub node_measurements: Vec<Vec<u8>>,
    pub transparency_log_ed25519_key: [u8; 32],
}

pub fn validate_trust_bundle_json(raw: &str) -> Result<ValidatedTrustBundle, String> {
    let bundle: TrustBundleV1 =
        serde_json::from_str(raw).map_err(|e| format!("invalid trust-bundle JSON: {e}"))?;
    if bundle.version != TRUST_BUNDLE_VERSION {
        return Err(format!(
            "unsupported trust-bundle version {} (expected {TRUST_BUNDLE_VERSION})",
            bundle.version
        ));
    }
    if bundle.issuer_public_keys_der.is_empty() {
        return Err("issuer_public_keys_der must contain at least one key".to_string());
    }
    if bundle.node_measurements.is_empty() {
        return Err("node_measurements must contain at least one measurement".to_string());
    }

    let mut issuer_public_keys_der = Vec::with_capacity(bundle.issuer_public_keys_der.len());
    for (index, value) in bundle.issuer_public_keys_der.iter().enumerate() {
        let der = decode_lower_hex(value, &format!("issuer_public_keys_der[{index}]"))?;
        if der.is_empty() || !is_complete_der_sequence(&der) {
            return Err(format!(
                "issuer_public_keys_der[{index}] must be one complete DER SEQUENCE"
            ));
        }
        if issuer_public_keys_der.contains(&der) {
            return Err(format!("issuer_public_keys_der[{index}] is a duplicate"));
        }
        issuer_public_keys_der.push(der);
    }

    let mut node_measurements = Vec::with_capacity(bundle.node_measurements.len());
    for (index, value) in bundle.node_measurements.iter().enumerate() {
        let measurement = decode_lower_hex(value, &format!("node_measurements[{index}]"))?;
        if measurement.len() != 48 {
            return Err(format!(
                "node_measurements[{index}] must be 48 bytes (96 lowercase hex characters)"
            ));
        }
        if node_measurements.contains(&measurement) {
            return Err(format!("node_measurements[{index}] is a duplicate"));
        }
        node_measurements.push(measurement);
    }

    let transparency = decode_lower_hex(
        &bundle.transparency_log_ed25519_key,
        "transparency_log_ed25519_key",
    )?;
    let transparency_log_ed25519_key: [u8; 32] = transparency.try_into().map_err(|_| {
        "transparency_log_ed25519_key must be 32 bytes (64 lowercase hex characters)".to_string()
    })?;

    let canonical_json = serde_json::to_string(&bundle)
        .map_err(|e| format!("could not canonicalize trust bundle: {e}"))?;
    Ok(ValidatedTrustBundle {
        canonical_json,
        issuer_public_keys_der,
        node_measurements,
        transparency_log_ed25519_key,
    })
}

fn decode_lower_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() % 2 != 0 {
        return Err(format!(
            "{field} must be non-empty, even-length lowercase hex"
        ));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!("{field} must contain lowercase hex only"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => unreachable!("validated lowercase hex"),
            };
            Ok((nibble(pair[0]) << 4) | nibble(pair[1]))
        })
        .collect()
}

/// Minimal DER framing check. The build script additionally asks the token crypto implementation
/// to parse every key, but checking the exact top-level TLV here gives useful schema errors first.
fn is_complete_der_sequence(der: &[u8]) -> bool {
    if der.len() < 2 || der[0] != 0x30 {
        return false;
    }
    let first = der[1];
    let (body_len, header_len) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || der.len() < 2 + count {
            return false;
        }
        if der[2] == 0 {
            return false; // non-minimal DER length
        }
        let mut len = 0usize;
        for byte in &der[2..2 + count] {
            let Some(next) = len
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*byte)))
            else {
                return false;
            };
            len = next;
        }
        if len < 128 {
            return false; // long form is non-minimal for short lengths
        }
        (len, 2 + count)
    };
    header_len.checked_add(body_len) == Some(der.len())
}
