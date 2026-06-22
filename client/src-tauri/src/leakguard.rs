//! Leak protection (architecture spec §9).
//!
//! Phase 0 stub. DNS pinning, IPv6 handling, and WebRTC guidance arrive in Phase 1
//! alongside the real datapath.

/// Arm leak protection. Phase 0: a documented no-op.
pub fn arm() -> anyhow::Result<()> {
    Ok(())
}
