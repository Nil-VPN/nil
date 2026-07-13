//! Windows routing / DNS via `netsh`, plus the kill-switch seam.
//!
//! Status: routing, DNS, and the fail-closed kill-switch are implemented and cross-compiled. A
//! privileged Windows VM fault/crash/reboot matrix remains required before production claims. The
//! TUN is wintun via `tun-rs`.
//!
//! Ordering mirrors Linux/macOS so there is never a leak window: pin the node route and arm
//! the kill-switch *before* flipping the default route; on teardown remove our routes and
//! disarm the kill-switch *last*. We add two `/1` routes through the TUN (leaving the real
//! default in the table) so teardown is just "delete what we added".
//!
//! ## Kill-switch via the Windows Firewall (NetSecurity cmdlets) — fail-closed, on by default
//! `netsh advfirewall` can only scope allow-rules by `interfacetype` (lan/wireless/ras), never
//! by a specific adapter — so a coarse "block all except the node" rule would block real app
//! traffic before it enters the tunnel (its destination is an arbitrary internet IP, not the
//! node). The newer **NetSecurity** cmdlets do not have that limitation: `New-NetFirewallRule
//! -InterfaceAlias <tun>` matches traffic by its *outgoing interface*, which is exactly the
//! tunneled-app case `netsh` couldn't express, and these rules are WFP-backed under the hood.
//!
//! So the kill-switch is: Allow outbound on the TUN interface and the encapsulated QUIC/TCP to
//! the node, then set the per-profile default **outbound action to Block** (the default action is
//! overridden by Allow rules, and we add no Block rules, so there is no block-wins conflict that
//! could break tunneled traffic). Loopback is exempt from the firewall by default. Teardown
//! removes our rule group and restores the captured default action. Any cmdlet error aborts the
//! bring-up (fail-closed), and the kill-switch is recorded as armed-for-teardown BEFORE the rules
//! go in, so a partially-applied set is still fully unwound.
//!
//! This NetSecurity implementation mutates the per-profile default outbound action (captured and
//! restored on teardown). A future hardening pass swaps it for a dynamic WFP filter set
//! (WireGuard-for-Windows style: filters tied to a process-owned `FwpmEngineOpen0` dynamic session
//! that auto-removes on crash), which avoids touching the user's firewall profile at all.

use std::net::IpAddr;
use std::process::Command;

use crate::{ArmParams, CleanupErrors, NetControl};

#[derive(Clone, Copy)]
struct PinnedRoute {
    ip: IpAddr,
    interface: u32,
}

#[derive(Default)]
pub struct WinNet {
    armed: bool,
    /// Interface index of the TUN (wintun) adapter.
    tun_idx: Option<u32>,
    firewall_touched: bool,
    /// Saved per-profile `DefaultOutboundAction` (e.g. `Domain=Allow;Private=Allow;Public=Allow`)
    /// to restore on teardown.
    ks_saved: Option<String>,
    low_default_added: bool,
    high_default_added: bool,
    /// Host routes that this instance actually added. Pre-existing routes are never deleted.
    pinned_routes: Vec<PinnedRoute>,
}

impl NetControl for WinNet {
    fn arm(&mut self, p: &ArmParams) -> anyhow::Result<()> {
        if self.armed {
            anyhow::bail!("Windows datapath is already armed or still requires rollback");
        }
        // Routing can fail partway even when the user disabled the kill-switch. Record rollback
        // eligibility before the first host mutation in every mode.
        self.armed = true;

        // Fail-closed: arm the kill-switch BEFORE flipping the default route (no leak window).
        // Any cmdlet error aborts the whole bring-up rather than running unprotected. The
        // Windows Firewall (NetSecurity) default-block kill-switch is the working implementation;
        // a dynamic WFP filter set is a future hardening (it avoids mutating the user's firewall
        // profile and auto-removes on crash — see the module docs), not a correctness gate.
        if p.kill_switch {
            // Capture + record the prior default action FIRST so that even a partially-applied
            // kill-switch (e.g. allow rules added but the Block flip errored) is fully cleaned up
            // by teardown. Mark armed-for-teardown before the rules go in.
            let saved = capture_default_outbound()?;
            self.ks_saved = Some(saved);
            self.firewall_touched = true;
            apply_kill_switch(p.node_ip, &p.also_except, &p.tun_name)?;
        }

        // Resolve interface indices we need for routing.
        let tun_idx = if_index_for_name(&p.tun_name).ok_or_else(|| {
            anyhow::anyhow!("could not find interface index for TUN {}", p.tun_name)
        })?;
        self.tun_idx = Some(tun_idx);

        // 1. Pin a /32 to the node via the original default gateway so the tunnel's own QUIC
        //    packets to the node bypass the TUN (best-effort: an on-link node is already
        //    covered by its connected route).
        if let Some((orig_idx, gw)) = default_route() {
            let pfx = format!("prefix={}/32", p.node_ip);
            let ifc = format!("interface={orig_idx}");
            let nh = format!("nexthop={gw}");
            match sh(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    &pfx,
                    &ifc,
                    &nh,
                    "metric=1",
                    "store=active",
                ],
            ) {
                Ok(()) => self.pinned_routes.push(PinnedRoute {
                    ip: p.node_ip,
                    interface: orig_idx,
                }),
                Err(e) => tracing::warn!("pin node route (continuing; may be on-link): {e}"),
            }
            // Pin any cascade fallback nodes too, so their traffic also bypasses the TUN.
            for ip in &p.also_except {
                let pfx = format!("prefix={ip}/32");
                match sh(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        &pfx,
                        &ifc,
                        &nh,
                        "metric=1",
                        "store=active",
                    ],
                ) {
                    Ok(()) => self.pinned_routes.push(PinnedRoute {
                        ip: *ip,
                        interface: orig_idx,
                    }),
                    Err(e) => tracing::warn!("pin fallback node route (continuing): {e}"),
                }
            }
        } else {
            tracing::warn!("no default route found; skipping node host-route pin");
        }

        // 2. Route all traffic through the TUN via two /1 routes (on-link nexthop). This leaves
        //    the real default route untouched, so teardown only deletes our additions.
        let ifc = format!("interface={tun_idx}");
        sh(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=0.0.0.0/1",
                &ifc,
                "store=active",
            ],
        )?;
        self.low_default_added = true;
        sh(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=128.0.0.0/1",
                &ifc,
                "store=active",
            ],
        )?;
        self.high_default_added = true;

        // 3. Point the TUN adapter's DNS at the tunnel resolver(s). With the TUN as the
        //    default route, the system prefers its resolvers; the (future) WFP kill-switch
        //    additionally blocks DNS that tries to bypass the tunnel.
        if !p.dns.is_empty() {
            set_dns(&p.tun_name, &p.dns);
        }

        tracing::info!(tun = %p.tun_name, tun_idx, kill_switch = p.kill_switch, "Windows datapath armed");
        Ok(())
    }

    fn teardown(&mut self) -> anyhow::Result<()> {
        if !self.armed {
            return Ok(());
        }
        let mut errors = CleanupErrors::default();

        // Remove our default routes.
        if let Some(idx) = self.tun_idx {
            let ifc = format!("interface={idx}");
            if self.high_default_added
                && errors.attempt(
                    "remove upper tunnel route",
                    sh(
                        "netsh",
                        &[
                            "interface",
                            "ipv4",
                            "delete",
                            "route",
                            "prefix=128.0.0.0/1",
                            &ifc,
                        ],
                    ),
                )
            {
                self.high_default_added = false;
            }
            if self.low_default_added
                && errors.attempt(
                    "remove lower tunnel route",
                    sh(
                        "netsh",
                        &[
                            "interface",
                            "ipv4",
                            "delete",
                            "route",
                            "prefix=0.0.0.0/1",
                            &ifc,
                        ],
                    ),
                )
            {
                self.low_default_added = false;
            }
        }

        let mut failed_routes = Vec::new();
        for route in self.pinned_routes.drain(..) {
            let ifc = format!("interface={}", route.interface);
            if !errors.attempt(
                "remove pinned node route",
                sh(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "delete",
                        "route",
                        &format!("prefix={}/32", route.ip),
                        &ifc,
                    ],
                ),
            ) {
                failed_routes.push(route);
            }
        }
        self.pinned_routes = failed_routes;
        // The wintun adapter (and its per-interface DNS) disappears when tun-rs drops the
        // device, so there is no host DNS state to restore.
        //
        // Disarm the kill-switch LAST so connectivity only returns once routes are sane.
        if errors.is_empty()
            && self.firewall_touched
            && errors.attempt(
                "restore Windows Firewall profiles",
                disarm_kill_switch(self.ks_saved.as_deref()),
            )
        {
            self.firewall_touched = false;
        }

        self.armed = self.low_default_added
            || self.high_default_added
            || !self.pinned_routes.is_empty()
            || self.firewall_touched;
        if !self.armed {
            tracing::info!("Windows datapath torn down; networking restored");
        }
        errors.finish()
    }
}

/// Map an interface name (the wintun adapter name, e.g. `nil0`) to its interface index by
/// parsing `netsh interface ipv4 show interfaces`. Columns: `Idx Met MTU State Name`.
fn if_index_for_name(name: &str) -> Option<u32> {
    let out = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        let t = line.trim();
        // Data rows start with the numeric index; the Name is the trailing field.
        let mut toks = t.split_whitespace();
        let Some(first) = toks.next() else { continue };
        let Ok(idx) = first.parse::<u32>() else {
            continue;
        };
        if t.trim_end().ends_with(name) {
            return Some(idx);
        }
    }
    None
}

/// Parse the IPv4 default route (`0.0.0.0/0`) from `netsh interface ipv4 show route`,
/// returning `(interface_index, gateway)`. Columns: `Publish Type Met Prefix Idx Gateway`.
fn default_route() -> Option<(u32, String)> {
    let out = Command::new("netsh")
        .args(["interface", "ipv4", "show", "route"])
        .output()
        .ok()?;
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
            sh(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    &name,
                    "static",
                    &ip.to_string(),
                    "primary",
                    "validate=no",
                ],
            )
        } else {
            let idx = format!("index={}", i + 1);
            sh(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "add",
                    "dnsservers",
                    &name,
                    &ip.to_string(),
                    &idx,
                    "validate=no",
                ],
            )
        };
        if let Err(e) = res {
            tracing::warn!("set tunnel DNS {ip} on {tun}: {e}");
        }
    }
}

/// Firewall rule group, so teardown removes exactly our rules.
const KS_GROUP: &str = "NIL-VPN-killswitch";

/// Capture each firewall profile's current `DefaultOutboundAction` (e.g. `"Domain=Allow;..."`)
/// so teardown can restore it. Done as its own step, BEFORE any rule is added, so the saved value
/// is recorded even if the rule application below fails partway (teardown then restores + cleans).
fn capture_default_outbound() -> anyhow::Result<String> {
    let saved = ps("(Get-NetFirewallProfile -Profile Domain,Private,Public | \
         ForEach-Object { \"$($_.Name)=$($_.DefaultOutboundAction)\" }) -join ';'")?;
    saved_firewall_profiles(&saved)?;
    Ok(saved)
}

fn saved_firewall_profiles(saved: &str) -> anyhow::Result<Vec<(&str, &str)>> {
    let mut profiles = Vec::new();
    for entry in saved.split(';') {
        let (name, action) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("malformed saved firewall profile"))?;
        let (name, action) = (name.trim(), action.trim());
        if !matches!(name, "Domain" | "Private" | "Public")
            || !matches!(action, "Allow" | "Block" | "NotConfigured")
            || profiles.iter().any(|(existing, _)| *existing == name)
        {
            anyhow::bail!("invalid or duplicate saved firewall profile");
        }
        profiles.push((name, action));
    }
    if profiles.len() != 3 {
        anyhow::bail!("saved firewall state does not contain exactly three profiles");
    }
    Ok(profiles)
}

/// Arm the fail-closed kill-switch via the Windows Firewall (NetSecurity cmdlets).
///
/// Source implementation (privileged runtime validation remains required). The mechanism:
///   1. add Allow rules (our group) for the TUN interface and the encapsulated QUIC/TCP to the
///      node — loopback is firewall-exempt by default,
///   2. flip the default outbound action to Block, so any egress not matching an Allow (i.e.
///      anything trying to bypass the tunnel) is dropped.
///
/// Allows precede the Block flip, so the only transient state is "more blocked", never a leak.
/// Any cmdlet error returns `Err`, aborting the bring-up (fail-closed) rather than running open;
/// `WinNet::arm` records the kill-switch as armed-for-teardown before calling this, so a partial
/// application is still fully unwound.
///
/// A future hardening pass may swap this for a dynamic WFP filter set (WireGuard-for-Windows
/// style) that avoids mutating the user's firewall profile and auto-removes if the process dies
/// (`FwpmEngineOpen0` dynamic session; PERMIT on `FWPM_CONDITION_IP_LOCAL_INTERFACE` == the TUN
/// LUID + the node endpoint; default-block sublayer) — union-heavy unsafe FFI better written
/// with a Windows compiler in the loop.
fn apply_kill_switch(node_ip: IpAddr, also_except: &[IpAddr], tun: &str) -> anyhow::Result<()> {
    let node = node_ip.to_string();
    // Clear any stale rules from a previous run (idempotent).
    ps(&format!(
        "Remove-NetFirewallRule -Group '{KS_GROUP}' -ErrorAction SilentlyContinue"
    ))?;
    // 1. Allow the tunnel interface and the encapsulated QUIC/TCP to the node.
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
    // Allow the tunnel's own traffic to any cascade fallback node (any port/protocol).
    for ip in also_except {
        ps(&format!(
            "New-NetFirewallRule -DisplayName 'NIL allow fallback {ip}' -Group '{KS_GROUP}' \
             -Direction Outbound -Action Allow -RemoteAddress {ip} -Profile Any | Out-Null"
        ))?;
    }
    // 2. Default-deny the rest (Allow rules override the default; we add no Block rules, so there
    //    is no block-wins conflict that could break tunneled traffic).
    ps("Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block")?;
    Ok(())
}

/// Tear down the kill-switch: restore each profile's saved default action, then remove our rules.
fn disarm_kill_switch(saved: Option<&str>) -> anyhow::Result<()> {
    let mut errors = CleanupErrors::default();
    if let Some(saved) = saved {
        match saved_firewall_profiles(saved) {
            Ok(profiles) => {
                for (name, action) in profiles {
                    errors.attempt(
                        "restore firewall profile",
                        ps(&format!(
                            "Set-NetFirewallProfile -Profile {name} -DefaultOutboundAction {action}"
                        ))
                        .map(|_| ()),
                    );
                }
            }
            Err(error) => {
                errors.attempt("validate saved firewall profiles", Err(error));
            }
        }
    } else {
        errors.attempt(
            "restore firewall profile",
            Err(anyhow::anyhow!("saved profile defaults are missing")),
        );
    }
    if errors.is_empty() {
        errors.attempt(
            "remove NIL firewall rules",
            ps(&format!(
                "Remove-NetFirewallRule -Group '{KS_GROUP}' -ErrorAction SilentlyContinue"
            ))
            .map(|_| ()),
        );
    }
    errors.finish()
}

/// Run a PowerShell command, returning trimmed stdout. Errors on a non-zero exit.
fn ps(script: &str) -> anyhow::Result<String> {
    tracing::debug!("$ powershell -Command {script}");
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| anyhow::anyhow!("spawn powershell: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "powershell `{script}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
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
