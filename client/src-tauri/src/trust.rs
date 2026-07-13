//! Client-embedded, independently published trust roots.
//!
//! Release builds cannot exist without a validated v1 bundle (`build.rs`). The runtime parser is
//! deliberately lazy and immutable (`OnceLock`): network responses and process environment values
//! can only be checked against or narrow these roots; they can never add a trusted issuer, guest
//! measurement, or transparency-log key.

use std::sync::OnceLock;

#[path = "../trust_bundle.rs"]
mod schema;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoots {
    pub issuer_public_keys_der: Vec<Vec<u8>>,
    pub node_measurements: Vec<Vec<u8>>,
    pub transparency_log_ed25519_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuerPins {
    pub keys: Vec<Vec<u8>>,
    /// Distinguishes debug's legacy unpinned mode from an embedded set narrowed to no keys.
    pub required: bool,
}

static EMBEDDED_ROOTS: OnceLock<Option<TrustRoots>> = OnceLock::new();

pub fn embedded() -> Option<&'static TrustRoots> {
    EMBEDDED_ROOTS.get_or_init(load_embedded).as_ref()
}

fn load_embedded() -> Option<TrustRoots> {
    let raw = option_env!("NIL_EMBEDDED_TRUST_BUNDLE_JSON").unwrap_or("");
    if raw.is_empty() {
        return None;
    }
    Some(parse_roots(raw).expect("build.rs embedded an invalid trust bundle"))
}

fn parse_roots(raw: &str) -> Result<TrustRoots, String> {
    let validated = schema::validate_trust_bundle_json(raw)?;
    nil_crypto::token::Verifier::from_public_ders(&validated.issuer_public_keys_der)
        .map_err(|e| format!("unusable token issuer DER key: {e}"))?;
    Ok(TrustRoots {
        issuer_public_keys_der: validated.issuer_public_keys_der,
        node_measurements: validated.node_measurements,
        transparency_log_ed25519_key: validated.transparency_log_ed25519_key,
    })
}

/// Effective token-issuer pins. With embedded roots, the legacy env pin can only select a subset;
/// a disjoint or malformed env value produces an empty *required* set, so minting fails closed.
/// Without an embedded bundle (debug only), this preserves the previous optional env-pin behavior.
pub(crate) fn effective_issuer_pins() -> IssuerPins {
    let env_value = std::env::var("NW_TOKEN_ISSUER_PUBKEYS").ok();
    let env_keys = env_value
        .as_deref()
        .map(parse_hex_list_permissive)
        .unwrap_or_default();
    let Some(roots) = embedded() else {
        let required = !env_keys.is_empty();
        return IssuerPins {
            keys: env_keys,
            required,
        };
    };

    if env_value
        .as_deref()
        .map_or(true, |value| value.trim().is_empty())
    {
        return IssuerPins {
            keys: roots.issuer_public_keys_der.clone(),
            required: true,
        };
    }
    IssuerPins {
        keys: intersection(&roots.issuer_public_keys_der, &env_keys),
        required: true,
    }
}

/// Measurements used to cross-check a Coordinator-redeemed path. User/config pins select a subset
/// of embedded measurements; they never union new measurements into the release trust set.
pub fn effective_node_measurements_from_env() -> Result<Vec<Vec<u8>>, String> {
    let configured = configured_measurements(embedded().is_some())?;
    let Some(roots) = embedded() else {
        return Ok(configured);
    };
    if configured.is_empty() {
        return Ok(roots.node_measurements.clone());
    }
    let effective = intersection(&roots.node_measurements, &configured);
    if effective.is_empty() {
        return Err(
            "configured node measurement pins do not match the embedded release trust bundle"
                .to_string(),
        );
    }
    Ok(effective)
}

/// Transparency-log key used to cross-check every Coordinator-redeemed hop. An env key may equal
/// (narrow to) the embedded singleton, but a different key is rejected rather than added.
pub fn effective_transparency_log_key_from_env() -> Result<Option<[u8; 32]>, String> {
    let configured = std::env::var("NW_TRANSPARENCY_LOG_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| decode_fixed_32(value.trim(), "NW_TRANSPARENCY_LOG_KEY"))
        .transpose()?;
    let Some(roots) = embedded() else {
        return Ok(configured);
    };
    match configured {
        Some(key) if key != roots.transparency_log_ed25519_key => Err(
            "NW_TRANSPARENCY_LOG_KEY does not match the embedded release trust bundle".to_string(),
        ),
        _ => Ok(Some(roots.transparency_log_ed25519_key)),
    }
}

fn configured_measurements(strict: bool) -> Result<Vec<Vec<u8>>, String> {
    let mut values = Vec::new();
    if let Ok(value) = std::env::var("NW_EXPECTED_MEASUREMENT") {
        if !value.trim().is_empty() {
            push_measurement(&mut values, value.trim(), "NW_EXPECTED_MEASUREMENT", strict)?;
        }
    }
    if let Ok(list) = std::env::var("NW_PINNED_MEASUREMENTS") {
        for (index, value) in list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .enumerate()
        {
            push_measurement(
                &mut values,
                value,
                &format!("NW_PINNED_MEASUREMENTS[{index}]"),
                strict,
            )?;
        }
    }
    Ok(values)
}

fn push_measurement(
    values: &mut Vec<Vec<u8>>,
    value: &str,
    field: &str,
    strict: bool,
) -> Result<(), String> {
    let Some(bytes) = decode_hex(value) else {
        if strict {
            return Err(format!("{field} is not valid hex"));
        }
        return Ok(()); // preserve debug/mobile's historical malformed-pin behavior
    };
    if strict && bytes.len() != 48 {
        return Err(format!("{field} must be 48 bytes"));
    }
    if !values.contains(&bytes) {
        values.push(bytes);
    }
    Ok(())
}

fn parse_hex_list_permissive(value: &str) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(key) = decode_hex(item) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

fn decode_fixed_32(value: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(value).ok_or_else(|| format!("{field} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be 32 bytes"))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| (b as char).to_digit(16).map(|n| n as u8);
            Some((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

fn intersection(embedded: &[Vec<u8>], configured: &[Vec<u8>]) -> Vec<Vec<u8>> {
    embedded
        .iter()
        .filter(|root| configured.contains(root))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_json() -> String {
        static DER: OnceLock<String> = OnceLock::new();
        let der = DER.get_or_init(|| {
            let issuer = nil_crypto::token::Issuer::generate().expect("test issuer");
            issuer
                .public_der()
                .expect("public DER")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        });
        serde_json::json!({
            "version": 1,
            "issuer_public_keys_der": [der],
            "node_measurements": ["ab".repeat(48)],
            "transparency_log_ed25519_key": "cd".repeat(32),
        })
        .to_string()
    }

    #[test]
    fn parses_complete_v1_bundle() {
        let roots = parse_roots(&valid_json()).expect("valid roots");
        assert_eq!(roots.issuer_public_keys_der.len(), 1);
        assert_eq!(roots.node_measurements, vec![vec![0xab; 48]]);
        assert_eq!(roots.transparency_log_ed25519_key, [0xcd; 32]);
    }

    #[test]
    fn documented_example_matches_the_runtime_schema() {
        parse_roots(include_str!("../../trust/bundle.example.json"))
            .expect("the documented placeholder bundle must stay structurally valid");
    }

    #[test]
    fn rejects_unknown_fields_duplicates_and_bad_lengths() {
        let mut value: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(parse_roots(&value.to_string()).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        let measurement = value["node_measurements"][0].clone();
        value["node_measurements"] = serde_json::json!([measurement.clone(), measurement]);
        assert!(parse_roots(&value.to_string()).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        value["transparency_log_ed25519_key"] = serde_json::json!("aa");
        assert!(parse_roots(&value.to_string()).is_err());
    }

    #[test]
    fn rejects_uppercase_hex_and_unusable_der() {
        let mut value: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        value["node_measurements"][0] = serde_json::json!("AB".repeat(48));
        assert!(parse_roots(&value.to_string()).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&valid_json()).unwrap();
        // Complete DER SEQUENCE framing, but not a token RSA public key.
        value["issuer_public_keys_der"][0] = serde_json::json!("3003020101");
        assert!(parse_roots(&value.to_string()).is_err());
    }

    #[test]
    fn intersection_never_adds_configured_values() {
        let embedded = vec![vec![1], vec![2]];
        let configured = vec![vec![2], vec![3]];
        assert_eq!(intersection(&embedded, &configured), vec![vec![2]]);
    }
}
