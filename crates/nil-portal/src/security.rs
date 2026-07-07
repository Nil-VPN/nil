//! RFC 9116 security disclosure (`/.well-known/security.txt`) and the optional PGP key it points to.
//!
//! A privacy product needs a documented, verifiable channel for responsible disclosure — security
//! researchers, and the account/enrollment reviews a launch goes through, both expect it. This
//! endpoint carries NO user-linkable data: only role contact addresses and canonical URLs (PD-1).
//! Nothing here touches the control or data plane.
//!
//! The `Expires` field is recomputed on every request (now + 180 days) so the file never goes
//! stale — RFC 9116 requires a future timestamp under a year out. The PGP public key is served
//! only when an operator points `NW_SECURITY_PGP_KEY_PATH` at it (self-hosted, verifiable — SOUL
//! §5); until then the `Encryption` line is omitted rather than dangling at a 404.

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

use nil_core::grant::now_unix_secs;

/// `Expires` window: 180 days out, recomputed per request. RFC 9116 §2.5.5 wants a future value
/// under one year.
const EXPIRES_WINDOW_SECS: u64 = 180 * 24 * 60 * 60;

/// Read an env var, falling back to `default` when unset or blank.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Path to a PGP public key to serve at `/.well-known/nil-security.asc`, if configured.
fn pgp_key_path() -> Option<String> {
    std::env::var("NW_SECURITY_PGP_KEY_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// The stateless disclosure router, merged into the portal app at the top level.
pub fn security_router() -> Router {
    Router::new()
        .route("/.well-known/security.txt", get(security_txt))
        .route("/.well-known/nil-security.asc", get(pgp_key))
}

/// The `security.txt` body. Contact + canonical base are env-overridable so ops can point them at
/// the real domain without a code change.
fn security_txt_body(now: u64) -> String {
    let base = env_or("NW_SECURITY_CANONICAL_BASE", "https://nilvpn.net");
    let contact = env_or("NW_SECURITY_CONTACT", "mailto:security@nilvpn.net");
    let expires = iso8601_utc(now.saturating_add(EXPIRES_WINDOW_SECS));
    let mut body = String::new();
    body.push_str("# NIL VPN — security disclosure. Lawful by posture, empty by design.\n");
    body.push_str(&format!("Contact: {contact}\n"));
    body.push_str(&format!("Expires: {expires}\n"));
    // Only advertise the key when we actually serve one (no dead references).
    if pgp_key_path().is_some() {
        body.push_str(&format!("Encryption: {base}/.well-known/nil-security.asc\n"));
    }
    body.push_str(&format!("Canonical: {base}/.well-known/security.txt\n"));
    body.push_str("Preferred-Languages: en\n");
    body.push_str(&format!("Policy: {base}/security-policy\n"));
    body
}

async fn security_txt() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        security_txt_body(now_unix_secs()),
    )
}

async fn pgp_key() -> impl IntoResponse {
    match pgp_key_path() {
        Some(path) => match tokio::fs::read(&path).await {
            Ok(bytes) => {
                ([(header::CONTENT_TYPE, "application/pgp-keys")], bytes).into_response()
            }
            // Configured but unreadable → fail closed rather than serve nothing silently.
            Err(_) => (StatusCode::NOT_FOUND, "PGP key not available").into_response(),
        },
        None => (StatusCode::NOT_FOUND, "PGP key not configured").into_response(),
    }
}

/// Format a unix timestamp (seconds) as ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`) with no dependency on
/// a date crate (the portal keeps time as raw unix seconds). Date part via Howard Hinnant's
/// `civil_from_days` algorithm, which is exact across the proleptic Gregorian calendar.
fn iso8601_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Convert days since the Unix epoch (1970-01-01) to a `(year, month, day)` civil date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_formats_known_epochs() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        // 2001-09-09T01:46:40Z — the classic 1e9 epoch.
        assert_eq!(iso8601_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // A leap day: 2020-02-29T00:00:00Z = 1582934400.
        assert_eq!(iso8601_utc(1_582_934_400), "2020-02-29T00:00:00Z");
    }

    #[test]
    fn security_txt_has_required_fields_and_future_expiry() {
        // now = 1e9 → Expires must be strictly later, well-formed, and present with Contact/Canonical.
        let now = 1_000_000_000u64;
        let body = security_txt_body(now);
        assert!(body.contains("Contact: mailto:security@nilvpn.net"), "default contact present");
        assert!(body.contains("Canonical: https://nilvpn.net/.well-known/security.txt"));
        let expires_line = body
            .lines()
            .find(|l| l.starts_with("Expires: "))
            .expect("Expires field is mandatory (RFC 9116)");
        let expires = expires_line.trim_start_matches("Expires: ");
        assert_eq!(expires, iso8601_utc(now + EXPIRES_WINDOW_SECS));
        assert!(expires > iso8601_utc(now).as_str(), "Expires is in the future");
    }

    #[test]
    fn encryption_line_only_when_a_key_is_configured() {
        // No key configured (default in tests) → no dangling Encryption reference.
        std::env::remove_var("NW_SECURITY_PGP_KEY_PATH");
        assert!(!security_txt_body(1_000_000_000).contains("Encryption:"));
    }
}
