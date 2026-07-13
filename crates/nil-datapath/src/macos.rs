//! macOS routing / kill-switch / DNS via `route`, `pfctl`, and `networksetup`.
//!
//! Designed for privileged macOS VM validation (the development host must stay untouched).
//! Ordering matches the Linux path:
//! pin the node route and arm the kill-switch *before* flipping the default route, and
//! disarm the kill-switch *last* on teardown — so there is never a leak window.
//!
//! The kill-switch loads only a dedicated pf anchor (`com.apple/nilvpn`) under macOS's default
//! `com.apple/*` anchor. It does not replace the host's root pf ruleset, so it coexists with
//! other local firewall users and can be removed independently on teardown.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::{ArmParams, CleanupErrors, NetControl};

#[derive(Default)]
pub struct MacNet {
    armed: bool,
    pf_was_enabled: bool,
    pf_touched: bool,
    dns_service: Option<String>,
    dns_backup: Option<Vec<String>>,
    dns_touched: bool,
    low_default_added: bool,
    high_default_added: bool,
    /// Host routes that this instance actually added. Pre-existing routes are never deleted.
    pinned_routes: Vec<IpAddr>,
}

impl NetControl for MacNet {
    fn arm(&mut self, p: &ArmParams) -> anyhow::Result<()> {
        if self.armed {
            anyhow::bail!("macOS datapath is already armed or still requires rollback");
        }
        // Roll back even if route/PF setup fails before the final success marker.
        self.armed = true;

        // 1. Capture the original default route.
        let (gw, ifc) = capture_default()?;

        // 2. Pin the node via the original gateway so the tunnel's QUIC bypasses the TUN
        //    (best-effort: an on-link node is already covered by the connected route).
        match sh(
            "route",
            &["-n", "add", "-host", &p.node_ip.to_string(), &gw],
        ) {
            Ok(()) => self.pinned_routes.push(p.node_ip),
            Err(e) => tracing::warn!("pin node route (continuing; may be on-link): {e}"),
        }
        // Pin any cascade fallback nodes too, so their traffic also bypasses the TUN.
        for ip in &p.also_except {
            match sh("route", &["-n", "add", "-host", &ip.to_string(), &gw]) {
                Ok(()) => self.pinned_routes.push(*ip),
                Err(e) => tracing::warn!("pin fallback node route (continuing): {e}"),
            }
        }
        // 3. Arm the kill-switch BEFORE flipping the default route.
        if p.kill_switch {
            self.arm_pf(p.node_ip, &p.also_except, &p.tun_name)?;
        }

        // 4. Route all traffic through the TUN via two /1 routes (leaves the real default
        //    in the table, so teardown just removes our additions).
        sh(
            "route",
            &["-n", "add", "-net", "0.0.0.0/1", "-interface", &p.tun_name],
        )?;
        self.low_default_added = true;
        sh(
            "route",
            &[
                "-n",
                "add",
                "-net",
                "128.0.0.0/1",
                "-interface",
                &p.tun_name,
            ],
        )?;
        self.high_default_added = true;

        // 5. Point DNS at the tunnel resolver(s).
        if !p.dns.is_empty() {
            if let Some(service) = primary_service(&ifc) {
                self.dns_backup = Some(get_dns(&service)?);
                self.dns_service = Some(service.clone());
                let dns: Vec<String> = p.dns.iter().map(|d| d.to_string()).collect();
                // Record before the mutating command: networksetup may change one resolver before
                // returning an error, and that partial write must still be restored.
                self.dns_touched = true;
                set_dns(&service, &dns)?;
            } else {
                tracing::warn!("could not find a network service for {ifc}; DNS not changed");
            }
        }

        tracing::info!(tun = %p.tun_name, kill_switch = p.kill_switch, "macOS datapath armed");
        Ok(())
    }

    fn teardown(&mut self) -> anyhow::Result<()> {
        if !self.armed {
            return Ok(());
        }
        let mut errors = CleanupErrors::default();

        // Restore DNS.
        if self.dns_touched {
            let restored = match (self.dns_service.as_deref(), self.dns_backup.as_deref()) {
                (Some(service), Some(backup)) => {
                    errors.attempt("restore DNS", restore_dns(service, backup))
                }
                _ => errors.attempt("restore DNS", Err(anyhow::anyhow!("backup is missing"))),
            };
            if restored {
                self.dns_touched = false;
                if let Err(error) = flush_dns() {
                    tracing::warn!("flush restored DNS cache: {error:#}");
                }
            }
        }

        if self.high_default_added
            && errors.attempt(
                "remove upper tunnel route",
                sh("route", &["-n", "delete", "-net", "128.0.0.0/1"]),
            )
        {
            self.high_default_added = false;
        }
        if self.low_default_added
            && errors.attempt(
                "remove lower tunnel route",
                sh("route", &["-n", "delete", "-net", "0.0.0.0/1"]),
            )
        {
            self.low_default_added = false;
        }

        let mut failed_routes = Vec::new();
        for ip in self.pinned_routes.drain(..) {
            if !errors.attempt(
                "remove pinned node route",
                sh("route", &["-n", "delete", "-host", &ip.to_string()]),
            ) {
                failed_routes.push(ip);
            }
        }
        self.pinned_routes = failed_routes;

        // Release PF only after every route and DNS mutation is known restored. A failed cleanup
        // deliberately leaves the anchor active, producing an obvious blackhole instead of a leak.
        if errors.is_empty()
            && self.pf_touched
            && errors.attempt(
                "flush NIL PF anchor",
                sh("pfctl", &["-a", PF_ANCHOR, "-F", "all"]),
            )
            && (self.pf_was_enabled
                || errors.attempt("restore disabled PF state", sh("pfctl", &["-d"])))
        {
            self.pf_touched = false;
        }

        self.armed = self.dns_touched
            || self.low_default_added
            || self.high_default_added
            || !self.pinned_routes.is_empty()
            || self.pf_touched;
        if !self.armed {
            tracing::info!("macOS datapath torn down; networking restored");
        }
        errors.finish()
    }
}

impl MacNet {
    fn arm_pf(&mut self, node_ip: IpAddr, also_except: &[IpAddr], tun: &str) -> anyhow::Result<()> {
        // macOS's default pf.conf evaluates `com.apple/*`; use a private child anchor under it
        // so we do not replace or snapshot the host ruleset. If an operator removed that root
        // anchor, fail closed instead of loading inert rules.
        let root = output("pfctl", &["-sr"])?;
        let root_rules = String::from_utf8_lossy(&root.stdout);
        if !root_rules.contains("anchor \"com.apple/*\"") {
            anyhow::bail!("macOS pf root ruleset does not evaluate com.apple/* anchors");
        }
        let info = output("pfctl", &["-s", "info"])?;
        self.pf_was_enabled = String::from_utf8_lossy(&info.stdout).contains("Status: Enabled");

        let node = node_ip.to_string();
        let mut rules = format!(
            "set block-policy drop\n\
             set skip on lo0\n\
             block drop all\n\
             pass quick on {tun} all\n\
             pass out quick proto udp from any to {node} port 443\n\
             pass in  quick proto udp from {node} port 443 to any\n\
             pass out quick proto tcp from any to {node} port 443\n\
             pass in  quick proto tcp from {node} port 443 to any\n"
        );
        // Allow the tunnel's own traffic to any cascade fallback node (any port).
        for ip in also_except {
            rules.push_str(&format!("pass quick from any to {ip}\n"));
        }
        // IPv6 fail-closed. `block drop all` already covers both families, but the tunnel is
        // IPv4-only, so v6 is a pure leak surface (a dual-stack app may prefer a v6 route around
        // the tunnel). Add an explicit, terminal `block drop quick inet6 all` AFTER the per-node
        // `pass quick` rules so a v6 node/fallback is still reachable (its earlier quick-pass wins),
        // but ALL other v6 egress is dropped wholesale — no dual-stack leak. Loopback v6 is exempt
        // via `set skip on lo0`. Placed last so it cannot shadow an intended v6 pass.
        rules.push_str("block drop quick inet6 all\n");
        // The anchor may be partially changed even if spawn/write/wait later reports an error.
        self.pf_touched = true;
        let mut child = Command::new("pfctl")
            .args(["-a", PF_ANCHOR, "-f", "-"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn pfctl: {e}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("pfctl stdin unavailable"))?
            .write_all(rules.as_bytes())?;
        if !child.wait()?.success() {
            anyhow::bail!("pfctl failed to load kill-switch ruleset");
        }
        // Enable pf and verify the kernel reports it enabled. A loaded anchor with PF disabled is
        // not a kill-switch and must never be reported as a successful arm.
        if !self.pf_was_enabled {
            sh("pfctl", &["-e"])?;
        }
        let info = output("pfctl", &["-s", "info"])?;
        if !String::from_utf8_lossy(&info.stdout).contains("Status: Enabled") {
            anyhow::bail!("pfctl rules loaded but PF is not enabled");
        }
        Ok(())
    }
}

const PF_ANCHOR: &str = "com.apple/nilvpn";

fn capture_default() -> anyhow::Result<(String, String)> {
    let out = output("route", &["-n", "get", "default"])?;
    let s = String::from_utf8_lossy(&out.stdout);
    let gw = field_after(&s, "gateway:").ok_or_else(|| anyhow::anyhow!("no default gateway"))?;
    let ifc =
        field_after(&s, "interface:").ok_or_else(|| anyhow::anyhow!("no default interface"))?;
    Ok((gw, ifc))
}

/// Map a BSD interface name (e.g. `en0`) to its `networksetup` service name (e.g. `Wi-Fi`).
fn primary_service(ifc: &str) -> Option<String> {
    let out = Command::new("networksetup")
        .args(["-listnetworkserviceorder"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut current: Option<String> = None;
    for line in s.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix('(') {
            // "(1) Wi-Fi" — a service header (not the "(Hardware Port: ...)" line).
            if !rest.starts_with("Hardware Port") {
                if let Some((_, name)) = rest.split_once(") ") {
                    current = Some(name.trim().to_string());
                }
            } else if t.contains(&format!("Device: {ifc})")) {
                return current.clone();
            }
        }
    }
    None
}

fn get_dns(service: &str) -> anyhow::Result<Vec<String>> {
    let out = output("networksetup", &["-getdnsservers", service])?;
    let s = String::from_utf8_lossy(&out.stdout);
    if s.contains("aren't any") {
        return Ok(Vec::new()); // empty sentinel → restore as DHCP-provided
    }
    let servers: Vec<String> = s
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.parse::<IpAddr>().is_ok())
        .map(String::from)
        .collect();
    if servers.is_empty() && !s.trim().is_empty() {
        anyhow::bail!(
            "networksetup returned an unrecognized DNS configuration; refusing a lossy backup"
        );
    }
    Ok(servers)
}

fn set_dns(service: &str, dns: &[String]) -> anyhow::Result<()> {
    let mut args = vec!["-setdnsservers", service];
    args.extend(dns.iter().map(String::as_str));
    sh("networksetup", &args)
}

fn restore_dns(service: &str, backup: &[String]) -> anyhow::Result<()> {
    if backup.is_empty() {
        sh("networksetup", &["-setdnsservers", service, "empty"])
    } else {
        set_dns(service, backup)
    }
}

fn flush_dns() -> anyhow::Result<()> {
    let _ = sh("dscacheutil", &["-flushcache"]);
    sh("killall", &["-HUP", "mDNSResponder"])
}

fn field_after(s: &str, key: &str) -> Option<String> {
    s.lines()
        .find_map(|l| l.trim().strip_prefix(key))
        .map(|v| v.trim().to_string())
}

fn output(cmd: &str, args: &[&str]) -> anyhow::Result<std::process::Output> {
    tracing::debug!("$ {cmd} {}", args.join(" "));
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("spawn {cmd}: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`{cmd} {}` exited with {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out)
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
