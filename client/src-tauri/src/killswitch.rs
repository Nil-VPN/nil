//! Fail-closed kill-switch — the client-facing toggle (architecture spec §9).
//!
//! ENFORCEMENT is NOT here: it lives in `nil-datapath`, which arms an OS firewall **default-block**
//! (Windows WFP/NetSecurity, macOS pf, Linux nftables/iptables) at `Tunnel::up` and tears it down
//! last at `Tunnel::down`, so a tunnel drop or crash HOLDS — no traffic leaks. The datapath reads
//! the toggle from the `NW_KILLSWITCH` env var (default ON) when it brings the tunnel up.
//!
//! The SINGLE writer of `NW_KILLSWITCH` is `config::ConfigState::set` (via `apply_env`), which
//! writes it UNDER the config write lock — so a concurrent connect (`reapply_env`, read lock) can
//! never observe or clobber a half-applied value. This hook therefore must NOT write the shared env
//! itself: an unlocked write here would race `reapply_env` and could leave the switch OFF
//! (fail-OPEN). The GUI toggle persists through `config.set`. Mobile uses the platform VPN API's
//! block-on-disconnect (see `mobile::StartArgs::block_without_vpn`).

/// No-op seam. The kill-switch toggle is applied to `NW_KILLSWITCH` by `config::ConfigState::set`
/// (atomically, under the config write lock). This hook intentionally does NOT write the shared env
/// — doing so outside that lock would race a concurrent `reapply_env` and could fail OPEN. Retained
/// as the place a future per-OS/per-session toggle would route through (via the same locked path).
pub fn set_enabled(_enabled: bool) -> anyhow::Result<()> {
    Ok(())
}
