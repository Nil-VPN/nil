//! Split-tunnel routing (architecture spec §9).
//!
//! Phase 0 stub. Per-app / per-route routing arrives with the desktop TUN device in
//! Phase 1 (per-app on Android, per-route within iOS limits on mobile).

/// Configure split-tunnel. Phase 0: a documented no-op.
pub fn configure(_enabled: bool, _apps: &[String]) -> anyhow::Result<()> {
    Ok(())
}
