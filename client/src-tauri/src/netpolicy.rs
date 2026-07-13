//! Client control-plane URL policy.
//!
//! Debug builds may opt into an explicit insecure override and may use genuine HTTP loopback URLs
//! for local integration. Release builds ignore the override and require HTTPS, including for
//! localhost, so a packaged client cannot be redirected to plaintext by runtime configuration.

pub(crate) fn require_safe_control_url(url: &str) -> Result<(), String> {
    if nil_core::net::dev_env_flag("NW_INSECURE_CONTROL_PLANE") {
        return Ok(());
    }
    nil_core::net::require_https_or_debug_loopback(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_in_every_build_mode() {
        assert!(require_safe_control_url("https://control.example.test").is_ok());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_accepts_genuine_http_loopback() {
        assert!(require_safe_control_url("http://127.0.0.1:8080").is_ok());
        assert!(require_safe_control_url("http://localhost:8080").is_ok());
        assert!(require_safe_control_url("http://[::1]:8080").is_ok());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn release_rejects_http_loopback_even_with_the_dev_override() {
        let _guard = crate::env_test_lock().blocking_lock();
        let previous = std::env::var("NW_INSECURE_CONTROL_PLANE").ok();
        std::env::set_var("NW_INSECURE_CONTROL_PLANE", "1");
        let result = require_safe_control_url("http://127.0.0.1:8080");
        match previous {
            Some(value) => std::env::set_var("NW_INSECURE_CONTROL_PLANE", value),
            None => std::env::remove_var("NW_INSECURE_CONTROL_PLANE"),
        }
        assert!(result.is_err());
    }

    #[test]
    fn rejects_plaintext_remote_control_plane() {
        assert!(require_safe_control_url("http://control.example.test").is_err());
    }
}
