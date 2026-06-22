//! Fail-closed kill-switch (architecture spec §9).
//!
//! Phase 0 stub. Real enforcement (OS firewall: WFP / pf / nftables on desktop, the
//! platform VPN API's "block on disconnect" on mobile) lands in Phase 1. The invariant
//! it must uphold: when the tunnel drops, the kill-switch HOLDS and no traffic leaks.

/// Enable or disable the kill-switch. Phase 0: a documented no-op.
pub fn set_enabled(_enabled: bool) -> anyhow::Result<()> {
    Ok(())
}
