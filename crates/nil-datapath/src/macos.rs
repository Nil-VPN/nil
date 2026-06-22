//! macOS routing / kill-switch / DNS via `route`, `pfctl`, and `networksetup`.
//!
//! Verified in a macOS VM (the host stays untouched). Ordering matches the Linux path:
//! pin the node route and arm the kill-switch *before* flipping the default route, and
//! disarm the kill-switch *last* on teardown — so there is never a leak window.
//!
//! The kill-switch replaces the whole pf ruleset (snapshotting the original) rather than
//! using an anchor; that is fine in the clean VM. A production host (where pf may be shared
//! with Tailscale/Docker) should instead use a dedicated `nil.killswitch` anchor.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::{ArmParams, NetControl};

#[derive(Default)]
pub struct MacNet {
    armed: bool,
    node_ip: Option<IpAddr>,
    tun_name: Option<String>,
    kill_switch: bool,
    pf_backup: Option<String>,
    pf_was_enabled: bool,
    dns_service: Option<String>,
    dns_backup: Option<Vec<String>>,
}

impl NetControl for MacNet {
    fn arm(&mut self, p: &ArmParams) -> anyhow::Result<()> {
        self.node_ip = Some(p.node_ip);
        self.tun_name = Some(p.tun_name.clone());

        // 1. Capture the original default route.
        let (gw, ifc) = capture_default()?;

        // 2. Pin the node via the original gateway so the tunnel's QUIC bypasses the TUN
        //    (best-effort: an on-link node is already covered by the connected route).
        if let Err(e) = sh("route", &["-n", "add", "-host", &p.node_ip.to_string(), &gw]) {
            tracing::warn!("pin node route (continuing; may be on-link): {e}");
        }

        // 3. Arm the kill-switch BEFORE flipping the default route.
        if p.kill_switch {
            self.arm_pf(p.node_ip, &p.tun_name)?;
            self.kill_switch = true;
        }

        // 4. Route all traffic through the TUN via two /1 routes (leaves the real default
        //    in the table, so teardown just removes our additions).
        sh("route", &["-n", "add", "-net", "0.0.0.0/1", "-interface", &p.tun_name])?;
        sh("route", &["-n", "add", "-net", "128.0.0.0/1", "-interface", &p.tun_name])?;

        // 5. Point DNS at the tunnel resolver(s).
        if !p.dns.is_empty() {
            if let Some(service) = primary_service(&ifc) {
                self.dns_backup = Some(get_dns(&service));
                let dns: Vec<String> = p.dns.iter().map(|d| d.to_string()).collect();
                if let Err(e) = set_dns(&service, &dns) {
                    tracing::warn!("set tunnel DNS: {e}");
                }
                self.dns_service = Some(service);
            } else {
                tracing::warn!("could not find a network service for {ifc}; DNS not changed");
            }
        }

        self.armed = true;
        tracing::info!(tun = %p.tun_name, kill_switch = p.kill_switch, "macOS datapath armed");
        Ok(())
    }

    fn teardown(&mut self) {
        if !self.armed {
            return;
        }
        // Restore DNS.
        if let (Some(service), Some(backup)) = (self.dns_service.clone(), self.dns_backup.clone()) {
            let _ = restore_dns(&service, &backup);
            let _ = flush_dns();
        }
        // Remove our default routes.
        let _ = sh("route", &["-n", "delete", "-net", "0.0.0.0/1"]);
        let _ = sh("route", &["-n", "delete", "-net", "128.0.0.0/1"]);
        // Remove the pinned node route.
        if let Some(ip) = self.node_ip {
            let _ = sh("route", &["-n", "delete", "-host", &ip.to_string()]);
        }
        // Disarm the kill-switch LAST (connectivity only returns once routes/DNS are sane).
        if self.kill_switch {
            if let Some(backup) = &self.pf_backup {
                let _ = sh("pfctl", &["-f", backup]);
            }
            if !self.pf_was_enabled {
                let _ = sh("pfctl", &["-d"]);
            }
        }
        self.armed = false;
        tracing::info!("macOS datapath torn down; networking restored");
    }
}

impl MacNet {
    fn arm_pf(&mut self, node_ip: IpAddr, tun: &str) -> anyhow::Result<()> {
        // Snapshot the current ruleset + enabled state.
        let backup = std::env::temp_dir().join(format!("nil-pf-backup-{}.conf", std::process::id()));
        let cur = Command::new("pfctl").args(["-sr"]).output()?;
        std::fs::write(&backup, &cur.stdout)?;
        self.pf_backup = Some(backup.to_string_lossy().into_owned());
        let info = Command::new("pfctl").args(["-s", "info"]).output()?;
        self.pf_was_enabled = String::from_utf8_lossy(&info.stdout).contains("Status: Enabled");

        let node = node_ip.to_string();
        let rules = format!(
            "set block-policy drop\n\
             set skip on lo0\n\
             block drop all\n\
             pass quick on {tun} all\n\
             pass out quick proto udp from any to {node} port 443\n\
             pass in  quick proto udp from {node} port 443 to any\n\
             pass out quick proto tcp from any to {node} port 443\n\
             pass in  quick proto tcp from {node} port 443 to any\n"
        );
        let mut child = Command::new("pfctl")
            .args(["-f", "-"])
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
        // Enable pf (best-effort: errors if already enabled).
        let _ = sh("pfctl", &["-e"]);
        Ok(())
    }
}

fn capture_default() -> anyhow::Result<(String, String)> {
    let out = Command::new("route").args(["-n", "get", "default"]).output()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let gw = field_after(&s, "gateway:").ok_or_else(|| anyhow::anyhow!("no default gateway"))?;
    let ifc = field_after(&s, "interface:").ok_or_else(|| anyhow::anyhow!("no default interface"))?;
    Ok((gw, ifc))
}

/// Map a BSD interface name (e.g. `en0`) to its `networksetup` service name (e.g. `Wi-Fi`).
fn primary_service(ifc: &str) -> Option<String> {
    let out = Command::new("networksetup").args(["-listnetworkserviceorder"]).output().ok()?;
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

fn get_dns(service: &str) -> Vec<String> {
    let out = match Command::new("networksetup").args(["-getdnsservers", service]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let s = String::from_utf8_lossy(&out.stdout);
    if s.contains("aren't any") {
        return Vec::new(); // empty sentinel → restore as DHCP-provided
    }
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.parse::<IpAddr>().is_ok())
        .map(String::from)
        .collect()
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
