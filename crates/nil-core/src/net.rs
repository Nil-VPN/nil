//! Small network-safety guards shared across the planes.
//!
//! The recurring rule: a connection that carries anything sensitive (a Privacy Pass token, a
//! blinded request, an unauthenticated RPC) must be either **TLS** or to a **loopback** host —
//! never plaintext across an untrusted network. The Portal (token issuance), the client
//! (Coordinator redemption), and the Monero wallet-rpc guard all enforce this; keeping the check
//! in one place stops it from drifting (and from re-introducing the prefix-match bug where
//! `127.0.0.1.evil.com` looked like loopback, or the userinfo bug where `127.0.0.1@evil.com`
//! looked like loopback while the real connection went to `evil.com`).

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

/// Require `url` to be `https://` OR point at a loopback host (`localhost`, `127.0.0.0/8`, `::1`).
/// Returns `Err(message)` for a plaintext (`http://`) URL to any non-loopback host. The host is
/// compared exactly (IPs are parsed, not prefix-matched), so `http://127.0.0.1.evil.com` is
/// correctly rejected.
pub fn require_tls_or_loopback(url: &str) -> Result<(), String> {
    let (scheme, rest) = url
        .trim()
        .split_once("://")
        .ok_or_else(|| format!("URL must be http(s)://… , got {url:?}"))?;
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }
    let host = url_host(rest);
    if is_loopback_host(host) {
        return Ok(());
    }
    Err(format!(
        "refusing plaintext (http) connection to non-loopback host {host:?}: use https:// or a \
         loopback host (the data on this link is sensitive)"
    ))
}

/// Whether `host` is a loopback host. `localhost`, or an IP address (v4 or v6, with optional
/// brackets stripped by [`url_host`]) that `is_loopback()`. A hostname like `127.0.0.1.evil.com`
/// fails to parse as an IP and is therefore NOT loopback.
pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Extract the host from the part of a URL after `://`: drop the path, strip any RFC-3986
/// `userinfo@` prefix, strip an optional `[ipv6]` bracket form, else drop a trailing `:port`.
///
/// Stripping userinfo is security-critical: the WHATWG/RFC-3986 host is what follows the LAST `@`
/// in the authority, which is exactly what `reqwest`'s `url` crate dials. Without this,
/// `http://127.0.0.1:80@evil.com/` would parse here as host `127.0.0.1` (looking like loopback and
/// passing the plaintext gate) while the actual connection goes in cleartext to `evil.com`.
fn url_host(rest: &str) -> &str {
    let authority = rest.split('/').next().unwrap_or("");
    // Host is what follows the LAST '@' (userinfo may itself contain '@'/':'), matching WHATWG.
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    if let Some(after) = authority.strip_prefix('[') {
        // [ipv6]:port → the host is up to the closing bracket.
        return after.split(']').next().unwrap_or(after);
    }
    // host[:port] → drop a single trailing :port (host has no other colon when not bracketed).
    match authority.rsplit_once(':') {
        Some((h, _)) => h,
        None => authority,
    }
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
}
