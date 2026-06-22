//! Windows routing / DNS via `netsh`, plus the kill-switch seam.
//!
//! Status: **routing + DNS are implemented and cross-compile-checked; behavior is verified
//! in a Windows-on-ARM VM (the host stays untouched), same discipline as the Linux (Docker)
//! and macOS (tart VM) paths.** The TUN is wintun via `tun-rs`.
//!
//! Ordering mirrors Linux/macOS so there is never a leak window: pin the node route and arm
//! the kill-switch *before* flipping the default route; on teardown remove our routes and
//! disarm the kill-switch *last*. We add two `/1` routes through the TUN (leaving the real
//! default in the table) so teardown is just "delete what we added".
//!
//! ## Kill-switch via the Windows Firewall (NetSecurity cmdlets) — PENDING VM VERIFICATION
//! `netsh advfirewall` can only scope allow-rules by `interfacetype` (lan/wireless/ras), never
//! by a specific adapter — so a coarse "block all except the node" rule would block real app
//! traffic before it enters the tunnel (its destination is an arbitrary internet IP, not the
//! node). The newer **NetSecurity** cmdlets do not have that limitation: `New-NetFirewallRule
//! -InterfaceAlias <tun>` matches traffic by its *outgoing interface*, which is exactly the
//! tunneled-app case `netsh` couldn't express, and these rules are WFP-backed under the hood.
//!
//! So the kill-switch is: set the per-profile default **outbound action to Block** (the default
//! action is overridden by Allow rules, and we add no Block rules, so there is no block-wins
//! conflict), then Allow outbound on the TUN interface and the encapsulated QUIC/TCP to the
//! node. Loopback is exempt from the firewall by default. Teardown removes our rule group and
//! restores the captured default action.
//!
//! **This is implemented but NOT yet verified** — it cannot be compiled or run on the build
//! host (no Windows target/linker), only on the Windows-on-ARM VM. It is built as plain
//! `std::process` cmdlet shell-outs (no unsafe FFI), and arming is fail-closed: any cmdlet
//! error aborts the bring-up (the tunnel refuses to come up) rather than running unprotected.
//! A future hardening pass may replace it with a dynamic WFP filter set (WireGuard-for-Windows
//! style: a `FwpmEngineOpen0` session whose filters auto-remove if the process dies), which
//! avoids mutating the user's firewall profile at all — see the recipe in `arm_kill_switch`.

use std::net::IpAddr;
use std::process::Command;

use crate::{ArmParams, NetControl};

#[derive(Default)]
pub struct WinNet {
    armed: bool,
    node_ip: Option<IpAddr>,
    tun_name: Option<String>,
    /// Interface index of the TUN (wintun) adapter.
    tun_idx: Option<u32>,
    /// Interface index of the original default-route adapter (for the node /32 pin).
    orig_idx: Option<u32>,
    kill_switch: bool,
    /// Saved per-profile `DefaultOutboundAction` (e.g. `Domain=Allow;Private=Allow;Public=Allow`)
    /// to restore on teardown.
    ks_saved: Option<String>,
}

impl NetControl for WinNet {
    fn arm(&mut self, p: &ArmParams) -> anyhow::Result<()> {
        self.node_ip = Some(p.node_ip);
        self.tun_name = Some(p.tun_name.clone());

        // Fail-closed: arm the kill-switch BEFORE flipping the default route (no leak window).
        // Any cmdlet error aborts the whole bring-up rather than running unprotected.
        if p.kill_switch {
            self.ks_saved = Some(arm_kill_switch(p.node_ip, &p.tun_name)?);
            self.kill_switch = true;
        }

        // Resolve interface indices we need for routing.
        let tun_idx = if_index_for_name(&p.tun_name)
            .ok_or_else(|| anyhow::anyhow!("could not find interface index for TUN {}", p.tun_name))?;
        self.tun_idx = Some(tun_idx);

        // 1. Pin a /32 to the node via the original default gateway so the tunnel's own QUIC
        //    packets to the node bypass the TUN (best-effort: an on-link node is already
        //    covered by its connected route).
        if let Some((orig_idx, gw)) = default_route() {
            self.orig_idx = Some(orig_idx);
            let pfx = format!("prefix={}/32", p.node_ip);
            let ifc = format!("interface={orig_idx}");
            let nh = format!("nexthop={gw}");
            if let Err(e) = sh("netsh", &["interface", "ipv4", "add", "route", &pfx, &ifc, &nh, "metric=1", "store=active"]) {
                tracing::warn!("pin node route (continuing; may be on-link): {e}");
            }
        } else {
            tracing::warn!("no default route found; skipping node host-route pin");
        }

        // 2. Route all traffic through the TUN via two /1 routes (on-link nexthop). This leaves
        //    the real default route untouched, so teardown only deletes our additions.
        let ifc = format!("interface={tun_idx}");
        sh("netsh", &["interface", "ipv4", "add", "route", "prefix=0.0.0.0/1", &ifc, "store=active"])?;
        sh("netsh", &["interface", "ipv4", "add", "route", "prefix=128.0.0.0/1", &ifc, "store=active"])?;

        // 3. Point the TUN adapter's DNS at the tunnel resolver(s). With the TUN as the
        //    default route, the system prefers its resolvers; the (future) WFP kill-switch
        //    additionally blocks DNS that tries to bypass the tunnel.
        if !p.dns.is_empty() {
            set_dns(&p.tun_name, &p.dns);
        }

        self.armed = true;
        tracing::info!(tun = %p.tun_name, tun_idx, kill_switch = p.kill_switch, "Windows datapath armed");
        Ok(())
    }

    fn teardown(&mut self) {
        if !self.armed {
            return;
        }
        // Remove our default routes.
        if let Some(idx) = self.tun_idx {
            let ifc = format!("interface={idx}");
            let _ = sh("netsh", &["interface", "ipv4", "delete", "route", "prefix=0.0.0.0/1", &ifc]);
            let _ = sh("netsh", &["interface", "ipv4", "delete", "route", "prefix=128.0.0.0/1", &ifc]);
        }
        // Remove the pinned node route.
        if let (Some(ip), Some(orig)) = (self.node_ip, self.orig_idx) {
            let pfx = format!("prefix={ip}/32");
            let ifc = format!("interface={orig}");
            let _ = sh("netsh", &["interface", "ipv4", "delete", "route", &pfx, &ifc]);
        }
        // The wintun adapter (and its per-interface DNS) disappears when tun-rs drops the
        // device, so there is no host DNS state to restore.
        //
        // Disarm the kill-switch LAST so connectivity only returns once routes are sane.
        if self.kill_switch {
            disarm_kill_switch(self.ks_saved.as_deref());
        }
        self.armed = false;
        tracing::info!("Windows datapath torn down; networking restored");
    }
}

/// Map an interface name (the wintun adapter name, e.g. `nil0`) to its interface index by
/// parsing `netsh interface ipv4 show interfaces`. Columns: `Idx Met MTU State Name`.
fn if_index_for_name(name: &str) -> Option<u32> {
    let out = Command::new("netsh").args(["interface", "ipv4", "show", "interfaces"]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let t = line.trim();
        // Data rows start with the numeric index; the Name is the trailing field.
        let mut toks = t.split_whitespace();
        let Some(first) = toks.next() else { continue };
        let Ok(idx) = first.parse::<u32>() else { continue };
        if t.trim_end().ends_with(name) {
            return Some(idx);
        }
    }
    None
}

/// Parse the IPv4 default route (`0.0.0.0/0`) from `netsh interface ipv4 show route`,
/// returning `(interface_index, gateway)`. Columns: `Publish Type Met Prefix Idx Gateway`.
fn default_route() -> Option<(u32, String)> {
    let out = Command::new("netsh").args(["interface", "ipv4", "show", "route"]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = toks.iter().position(|t| *t == "0.0.0.0/0") {
            let idx = toks.get(pos + 1)?.parse::<u32>().ok()?;
            let gw = toks.get(pos + 2)?.to_string();
            return Some((idx, gw));
        }
    }
    None
}

/// Set the TUN adapter's DNS servers (best-effort; logs on failure).
fn set_dns(tun: &str, dns: &[IpAddr]) {
    let name = format!("name={tun}");
    let mut first = true;
    for (i, ip) in dns.iter().enumerate() {
        let res = if first {
            first = false;
            sh("netsh", &["interface", "ipv4", "set", "dnsservers", &name, "static", &ip.to_string(), "primary", "validate=no"])
        } else {
            let idx = format!("index={}", i + 1);
            sh("netsh", &["interface", "ipv4", "add", "dnsservers", &name, &ip.to_string(), &idx, "validate=no"])
        };
        if let Err(e) = res {
            tracing::warn!("set tunnel DNS {ip} on {tun}: {e}");
        }
    }
}

/// Firewall rule group, so teardown removes exactly our rules.
const KS_GROUP: &str = "NIL-VPN-killswitch";

/// Arm the fail-closed kill-switch via the Windows Firewall (NetSecurity cmdlets). Returns the
/// captured per-profile `DefaultOutboundAction` to restore on teardown.
///
/// PENDING WINDOWS-VM VERIFICATION (cannot be compiled or run on the build host). The mechanism:
///   1. capture each profile's current default outbound action,
///   2. add Allow rules (our group) for the TUN interface and the encapsulated QUIC/TCP to the
///      node — loopback is firewall-exempt by default,
///   3. flip the default outbound action to Block, so any egress not matching an Allow (i.e.
///      anything trying to bypass the tunnel) is dropped.
/// Allows precede the Block flip, so the only transient state is "more blocked", never a leak.
/// Any cmdlet error returns `Err`, aborting the bring-up (fail-closed) rather than running open.
///
/// A future hardening pass may swap this for a dynamic WFP filter set (WireGuard-for-Windows
/// style) that avoids mutating the user's firewall profile and auto-removes if the process dies
/// (`FwpmEngineOpen0` dynamic session; PERMIT on `FWPM_CONDITION_IP_LOCAL_INTERFACE` == the TUN
/// LUID + the node endpoint; default-block sublayer) — union-heavy unsafe FFI better written
/// with a Windows compiler in the loop.
fn arm_kill_switch(node_ip: IpAddr, tun: &str) -> anyhow::Result<String> {
    let node = node_ip.to_string();
    // 1. Capture the current default outbound action per profile (e.g. "Domain=Allow;...").
    let saved = ps(
        "(Get-NetFirewallProfile -Profile Domain,Private,Public | \
         ForEach-Object { \"$($_.Name)=$($_.DefaultOutboundAction)\" }) -join ';'",
    )?;
    // Clear any stale rules from a previous run (idempotent).
    let _ = ps(&format!("Remove-NetFirewallRule -Group '{KS_GROUP}' -ErrorAction SilentlyContinue"));
    // 2. Allow the tunnel interface and the encapsulated QUIC/TCP to the node.
    ps(&format!(
        "New-NetFirewallRule -DisplayName 'NIL allow TUN' -Group '{KS_GROUP}' -Direction Outbound \
         -Action Allow -InterfaceAlias '{tun}' -Profile Any | Out-Null"
    ))?;
    ps(&format!(
        "New-NetFirewallRule -DisplayName 'NIL allow node UDP' -Group '{KS_GROUP}' -Direction Outbound \
         -Action Allow -RemoteAddress {node} -Protocol UDP -RemotePort 443 -Profile Any | Out-Null"
    ))?;
    ps(&format!(
        "New-NetFirewallRule -DisplayName 'NIL allow node TCP' -Group '{KS_GROUP}' -Direction Outbound \
         -Action Allow -RemoteAddress {node} -Protocol TCP -RemotePort 443 -Profile Any | Out-Null"
    ))?;
    // 3. Default-deny the rest (Allow rules override the default; we add no Block rules, so there
    //    is no block-wins conflict that could break tunneled traffic).
    ps("Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block")?;
    Ok(saved)
}

/// Tear down the kill-switch: restore each profile's saved default action, then remove our rules.
fn disarm_kill_switch(saved: Option<&str>) {
    if let Some(saved) = saved {
        for entry in saved.split(';') {
            if let Some((name, action)) = entry.split_once('=') {
                let (name, action) = (name.trim(), action.trim());
                if !name.is_empty() && !action.is_empty() {
                    let _ = ps(&format!(
                        "Set-NetFirewallProfile -Profile {name} -DefaultOutboundAction {action}"
                    ));
                }
            }
        }
    }
    let _ = ps(&format!("Remove-NetFirewallRule -Group '{KS_GROUP}' -ErrorAction SilentlyContinue"));
}

/// Run a PowerShell command, returning trimmed stdout. Errors on a non-zero exit.
fn ps(script: &str) -> anyhow::Result<String> {
    tracing::debug!("$ powershell -Command {script}");
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| anyhow::anyhow!("spawn powershell: {e}"))?;
    if !out.status.success() {
        anyhow::bail!("powershell `{script}` failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn sh(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    tracing::debug!("$ {cmd} {}", args.join(" "));
    let status = Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| anyhow::anyhow!("spawn {cmd}: {e}"))?;
    if !status.success() {
        anyhow::bail!("`{cmd} {}` exited with {status}", args.join(" "));
    }
    Ok(())
}
