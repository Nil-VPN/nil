//! Split-tunnel routing — the client-facing config (architecture spec §9).
//!
//! Split-tunnel lets specific apps/routes bypass the tunnel. It does **NOT** weaken the
//! kill-switch: the datapath's default-block remains the governing layer, and a bypass is only ever
//! an Allow rule at higher priority for the explicitly-listed targets. Desktop per-app/per-route OS
//! application (macOS host routes via the original gateway, Linux `ip rule` + a secondary table,
//! Windows per-prefix metric route) is the datapath/VM-verified follow-up; this layer **validates**
//! the requested config so a malformed request fails closed *before* any routing is touched.

/// A validated split-tunnel request. No PII: app identifiers are local config the user chose, not
/// user-linkable network data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitTunnelConfig {
    pub enabled: bool,
    /// App identifiers (bundle id / executable name / package) to route OUTSIDE the tunnel.
    pub bypass_apps: Vec<String>,
}

/// Validate the requested split-tunnel config. Fails closed on a malformed entry (an
/// empty/whitespace app identifier) rather than silently dropping it. OS-level route application is
/// the datapath follow-up (VM-verified); this records nothing identifying.
pub fn configure(enabled: bool, apps: &[String]) -> anyhow::Result<()> {
    let cfg = validate(enabled, apps)?;
    tracing::info!(
        enabled = cfg.enabled,
        bypass_apps = cfg.bypass_apps.len(),
        "split-tunnel config validated; OS-level per-app/per-route application is the datapath follow-up"
    );
    Ok(())
}

fn validate(enabled: bool, apps: &[String]) -> anyhow::Result<SplitTunnelConfig> {
    let mut bypass_apps = Vec::with_capacity(apps.len());
    for a in apps {
        let a = a.trim();
        if a.is_empty() {
            anyhow::bail!("split-tunnel app identifier must not be empty");
        }
        bypass_apps.push(a.to_string());
    }
    Ok(SplitTunnelConfig { enabled, bypass_apps })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_an_empty_app_id() {
        // Fail closed: a blank identifier is a config error, not a silent drop.
        assert!(validate(true, &["ok.app".into(), "   ".into()]).is_err());
    }

    #[test]
    fn validate_trims_and_keeps_apps() {
        let c = validate(true, &[" com.foo.bar ".into()]).expect("valid");
        assert_eq!(c.bypass_apps, vec!["com.foo.bar".to_string()]);
        assert!(c.enabled);
    }

    #[test]
    fn configure_validates_ok() {
        assert!(configure(true, &["com.example.app".into()]).is_ok());
        assert!(configure(false, &[]).is_ok());
    }
}
