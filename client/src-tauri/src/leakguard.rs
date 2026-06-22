//! Leak protection (architecture spec §9).
//!
//! The real enforcement lives in the datapath's fail-closed kill-switch (`nil-datapath`
//! `NetControl`): while the tunnel is up it drops every egress except loopback, the TUN, and
//! QUIC/TCP to the node — **including all IPv6** (the tunnel is IPv4-only, so v6 is blocked
//! wholesale to stop the classic IPv6 leak), and it pins DNS to the tunnel resolver. So when the
//! desktop engine brings up a real tunnel (see `engine.rs`), leak protection is armed and torn
//! down atomically with it; this hook stays a no-op rather than installing a second, divergent
//! firewall policy that could fight the datapath's.
//!
//! On the loopback mock (or before a real tunnel exists) there is nothing to leak — no route is
//! changed — so arming here would be theatre.

/// Arm leak protection. The datapath kill-switch is the real guard (armed by `engine.connect`);
/// this is a deliberate no-op so the two don't install conflicting firewall policies.
pub fn arm() -> anyhow::Result<()> {
    Ok(())
}
