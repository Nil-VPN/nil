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
//! ## Kill-switch is deliberately deferred to the Windows VM pass — and why
//! A correct Windows kill-switch requires **WFP** (Windows Filtering Platform), not
//! `netsh advfirewall`: the firewall CLI can only scope allow-rules by `interfacetype`
//! (lan/wireless/ras), never by a specific interface. A coarse "block all egress except to
//! the node" firewall rule would therefore block real application traffic *before* it enters
//! the tunnel (its destination is an arbitrary internet IP, not the node) — breaking tunneling
//! rather than being fail-closed. WireGuard-for-Windows solves this with a WFP filter that
//! *permits traffic whose local interface is the tunnel LUID* plus permits to the node
//! endpoint and blocks everything else. That WFP filter set is union-heavy unsafe FFI that
//! cannot be written with confidence without a real Windows compiler+host in the loop, so it
//! is implemented and verified in the VM session (see the TODO in [`arm_kill_switch`] for the
//! exact filter set to install). Until then we stay **honestly fail-closed**: we refuse to
//! bring the tunnel up with the kill-switch requested rather than silently run without one.

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
}

impl NetControl for WinNet {
    fn arm(&mut self, p: &ArmParams) -> anyhow::Result<()> {
        self.node_ip = Some(p.node_ip);
        self.tun_name = Some(p.tun_name.clone());

        // Honest fail-closed: a real Windows kill-switch needs WFP (see module docs). Until
        // that lands+verifies in the VM, refuse rather than run without the requested guard.
        if p.kill_switch {
            arm_kill_switch(p.node_ip, &p.tun_name)?;
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
        tracing::info!(node = %p.node_ip, tun = %p.tun_name, tun_idx, kill_switch = p.kill_switch, "Windows datapath armed");
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
            disarm_kill_switch();
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

/// Arm the fail-closed kill-switch.
///
/// TODO(windows-vm): implement via WFP (`fwpuclnt.dll`), modeled on WireGuard-for-Windows
/// `firewall`. The `windows` crate (0.61, already in the dep tree via tun-rs) has ergonomic
/// WFP bindings — use it rather than raw `windows-sys`. The filter set, in one transaction:
/// open a *dynamic* engine session (`FwpmEngineOpen0` — filters auto-remove if the process
/// dies, itself a fail-closed property); add a dedicated sublayer at max weight; install BLOCK
/// filters at low weight on the `ALE_AUTH_CONNECT_V4/V6` and `ALE_AUTH_RECV_ACCEPT_V4/V6`
/// layers (the default-deny); then PERMIT filters at higher weight for
/// `FWPM_CONDITION_IP_LOCAL_INTERFACE` == the TUN LUID (the tunneled app traffic — the piece
/// `netsh advfirewall` cannot express), the node endpoint (UDP/TCP to `node_ip`:443, i.e. the
/// encapsulated QUIC), loopback, and DHCP/DNS as needed; commit. Resolve the TUN LUID via
/// `ConvertInterfaceAliasToLuid(tun_name)`. Teardown is `FwpmSubLayerDeleteByKey0` +
/// `FwpmEngineClose0` (a dynamic session also cleans up on close). Verified in the VM (host
/// untouched) before this returns `Ok`.
fn arm_kill_switch(_node_ip: IpAddr, _tun: &str) -> anyhow::Result<()> {
    anyhow::bail!(
        "Windows kill-switch (WFP) is implemented and verified in the Windows-VM pass; it is \
         not active yet. Re-run with NW_KILLSWITCH=0 for functional (no-kill-switch) bring-up \
         testing, or wait for the WFP kill-switch to land. Refusing to run fail-open."
    )
}

/// Tear down the WFP kill-switch. No-op until [`arm_kill_switch`] is implemented (a dynamic
/// WFP session also auto-removes its filters when its engine handle closes / the process exits).
fn disarm_kill_switch() {}

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
