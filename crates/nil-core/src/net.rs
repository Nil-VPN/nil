//! Small network-safety guards shared across the planes.
//!
//! The recurring rule: a connection that carries anything sensitive (a Privacy Pass token, a
//! blinded request, an unauthenticated RPC) must be either **TLS** or to a **loopback** host —
//! never plaintext across an untrusted network. The Portal (token issuance), the client
//! (Coordinator redemption), and the Monero wallet-rpc guard all enforce this; keeping the check
//! in one place stops it from drifting (and from re-introducing the prefix-match bug where
//! `127.0.0.1.evil.com` looked like loopback, or the userinfo bug where `127.0.0.1@evil.com`
//! looked like loopback while the real connection went to `evil.com`).

use url::{Host, Url};

/// Read a boolean env flag the safe way: `true` ONLY for an explicit truthy value (`"1"` or
/// `"true"`, case-insensitive). Absent, empty, `"0"`, and `"false"` all read as `false`.
///
/// This avoids the `std::env::var(name).is_ok()` footgun, where `VAR=0` — which an operator sets
/// meaning "off" — would read as *enabled*. Use it for every security-relevant opt-out so the
/// polarity is consistent and a falsy value never loosens a gate.
pub fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// Read a development-only escape hatch. In builds with debug assertions this has the same strict
/// truthy parsing as [`env_flag`]. When `debug_assertions` is disabled (the production posture),
/// the environment is not consulted and the result is unconditionally false, so an operator cannot
/// activate a development bypass at runtime. Integration profiles may intentionally retain debug
/// assertions and therefore retain these test-only flags even when otherwise optimized.
pub fn dev_env_flag(name: &str) -> bool {
    #[cfg(debug_assertions)]
    {
        env_flag(name)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = name;
        false
    }
}

/// Require HTTPS whenever debug assertions are disabled. Builds with debug assertions additionally
/// permit plaintext HTTP to a genuine loopback host for local integration; every other scheme/host
/// combination is rejected.
pub fn require_https_or_debug_loopback(url: &str) -> Result<(), String> {
    let parsed = parse_network_url(url)?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    if parsed.scheme() != "http" {
        return Err(format!(
            "unsupported URL scheme {:?}: sensitive control links require https://",
            parsed.scheme()
        ));
    }
    #[cfg(debug_assertions)]
    if url_is_loopback(&parsed) {
        return Ok(());
    }
    Err(format!(
        "refusing plaintext control connection to host {:?}: this build requires https://",
        parsed.host_str().unwrap_or("<missing>")
    ))
}

/// Require `url` to be `https://` OR point at a loopback host (`localhost`, `127.0.0.0/8`, `::1`).
/// Returns `Err(message)` for a plaintext (`http://`) URL to any non-loopback host. The host is
/// compared exactly (IPs are parsed, not prefix-matched), so `http://127.0.0.1.evil.com` is
/// correctly rejected.
pub fn require_tls_or_loopback(url: &str) -> Result<(), String> {
    let parsed = parse_network_url(url)?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    if parsed.scheme() != "http" {
        return Err(format!(
            "unsupported URL scheme {:?}: use https:// or loopback http://",
            parsed.scheme()
        ));
    }
    if url_is_loopback(&parsed) {
        return Ok(());
    }
    Err(format!(
        "refusing plaintext (http) connection to non-loopback host {:?}: use https:// or a \
         loopback host (the data on this link is sensitive)",
        parsed.host_str().unwrap_or("<missing>")
    ))
}

fn parse_network_url(raw: &str) -> Result<Url, String> {
    let parsed =
        Url::parse(raw.trim()).map_err(|error| format!("invalid absolute URL: {error}"))?;
    if parsed.host().is_none() {
        return Err("URL must include a network host".to_string());
    }
    Ok(parsed)
}

fn url_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Whether an already-extracted host is loopback: `localhost` or an IP address whose standard
/// library representation reports `is_loopback()`. URL guards use [`Url::host`] directly so
/// authority/userinfo/query parsing cannot drift from the HTTP client's WHATWG parser.
pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_always_ok() {
        assert!(require_tls_or_loopback("https://coordinator.example.com/v1/redeem").is_ok());
        assert!(require_tls_or_loopback("https://10.0.0.5:9000").is_ok());
    }

    #[test]
    fn http_loopback_ok() {
        assert!(require_tls_or_loopback("http://127.0.0.1:9000/v1/redeem").is_ok());
        assert!(require_tls_or_loopback("http://localhost:8080").is_ok());
        assert!(require_tls_or_loopback("http://[::1]:9000").is_ok());
    }

    #[test]
    fn http_remote_refused() {
        assert!(require_tls_or_loopback("http://coordinator.example.com/v1/redeem").is_err());
        assert!(require_tls_or_loopback("http://10.0.0.5:9000").is_err());
        // The classic prefix-match bypass must be refused.
        assert!(require_tls_or_loopback("http://127.0.0.1.evil.com:9000").is_err());
        assert!(require_tls_or_loopback("not-a-url").is_err());
    }

    #[test]
    fn http_userinfo_spoof_refused() {
        // RFC-3986 userinfo bypass: the real host is what follows the LAST '@' — `evil.com` — which
        // is what reqwest dials. A loopback-looking userinfo must NOT smuggle a plaintext remote
        // connection past the gate.
        assert!(require_tls_or_loopback("http://127.0.0.1:80@evil.com/v1/redeem").is_err());
        assert!(require_tls_or_loopback("http://localhost:1@evil.com/").is_err());
        assert!(require_tls_or_loopback("http://user:pass@evil.com/").is_err());
        assert!(require_tls_or_loopback("http://user:p@ss@evil.com/").is_err());
        // A genuine loopback host with harmless userinfo is still fine (reqwest dials 127.0.0.1).
        assert!(require_tls_or_loopback("http://user@127.0.0.1:9000/v1/redeem").is_ok());
        assert!(require_tls_or_loopback("http://user@[::1]:9000/").is_ok());
    }

    #[test]
    fn query_fragment_and_backslash_spoofs_follow_the_real_url_parser() {
        assert!(require_tls_or_loopback("http://evil.example/?next=http://127.0.0.1").is_err());
        assert!(require_tls_or_loopback("http://evil.example/#localhost").is_err());
        assert!(require_tls_or_loopback("http:\\\\127.0.0.1@evil.example/path").is_err());
        assert!(require_tls_or_loopback("http://127.0.0.1%5c@evil.example/").is_err());
        assert!(require_tls_or_loopback("https://").is_err());
    }

    #[test]
    fn env_flag_only_explicit_truthy_enables() {
        // The footgun guard: a falsy value must NEVER read as enabled.
        std::env::set_var("NW_TEST_FLAG", "0");
        assert!(!env_flag("NW_TEST_FLAG"), "=0 must be false");
        std::env::set_var("NW_TEST_FLAG", "false");
        assert!(!env_flag("NW_TEST_FLAG"), "=false must be false");
        std::env::set_var("NW_TEST_FLAG", "");
        assert!(!env_flag("NW_TEST_FLAG"), "empty must be false");
        std::env::set_var("NW_TEST_FLAG", "1");
        assert!(env_flag("NW_TEST_FLAG"), "=1 enables");
        std::env::set_var("NW_TEST_FLAG", "TRUE");
        assert!(env_flag("NW_TEST_FLAG"), "=TRUE enables");
        std::env::remove_var("NW_TEST_FLAG");
        assert!(!env_flag("NW_TEST_FLAG"), "absent is false");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn development_flags_and_loopback_http_work_only_in_debug() {
        std::env::set_var("NW_TEST_DEV_FLAG", "true");
        assert!(dev_env_flag("NW_TEST_DEV_FLAG"));
        std::env::remove_var("NW_TEST_DEV_FLAG");
        assert!(require_https_or_debug_loopback("http://127.0.0.1:8080").is_ok());
        assert!(require_https_or_debug_loopback("http://remote.example").is_err());
        assert!(require_https_or_debug_loopback("ftp://127.0.0.1").is_err());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_ignores_development_flags_and_requires_https_even_for_loopback() {
        std::env::set_var("NW_TEST_DEV_FLAG", "true");
        assert!(!dev_env_flag("NW_TEST_DEV_FLAG"));
        std::env::remove_var("NW_TEST_DEV_FLAG");
        assert!(require_https_or_debug_loopback("https://127.0.0.1:8443").is_ok());
        assert!(require_https_or_debug_loopback("http://127.0.0.1:8080").is_err());
        assert!(require_https_or_debug_loopback("http://localhost:8080").is_err());
    }
}
