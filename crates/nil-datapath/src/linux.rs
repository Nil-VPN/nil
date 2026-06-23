//! Linux routing / kill-switch / DNS via `ip` and `iptables` (run inside the Docker
//! client container with `NET_ADMIN`). Ordering is chosen so there is never a leak window:
//! arm the kill-switch and pin the node route *before* flipping the default route, and on
//! teardown disarm the kill-switch *last*.

use std::net::IpAddr;
use std::process::Command;

use crate::{ArmParams, NetControl};

#[derive(Default)]
pub struct LinuxNet {
    armed: bool,
    node_ip: Option<IpAddr>,
    tun_name: Option<String>,
    kill_switch: bool,
    /// Original default route spec, e.g. `via 172.20.0.1 dev eth0`.
    orig_default: Option<String>,
    /// Original `/etc/resolv.conf` contents.
    resolv_backup: Option<String>,
    /// Extra node IPs host-route-excepted (cascade fallback nodes), to clean up on teardown.
    also_except: Vec<IpAddr>,
}

impl NetControl for LinuxNet {
    fn arm(&mut self, p: &ArmParams) -> anyhow::Result<()> {
        self.node_ip = Some(p.node_ip);
        self.tun_name = Some(p.tun_name.clone());

        // 0. Disable TX checksum offload on the TUN — otherwise the kernel hands us packets
        //    with partial L4 checksums that the node/peer then drops (TUN offload gotcha).
        if let Err(e) = sh("ethtool", &["-K", &p.tun_name, "tx", "off"]) {
            tracing::warn!("ethtool disable tx offload on {}: {e}", p.tun_name);
        }

        // 1. Capture the original default route so we can restore it.
        self.orig_default = capture_default_route();

        // 2. Pin a host route to the node (and any cascade fallback nodes) via the original path,
        //    so the tunnel's own QUIC/UDP to them bypasses the TUN (avoids a routing loop).
        pin_node_route(p.node_ip)?;
        for ip in &p.also_except {
            if let Err(e) = pin_node_route(*ip) {
                tracing::warn!("pin fallback node route (continuing): {e}");
            }
        }
        self.also_except = p.also_except.clone();

        // 3. Arm the fail-closed kill-switch BEFORE flipping the default route — no window
        //    in which the default points at the TUN but traffic can still escape directly.
        if p.kill_switch {
            arm_kill_switch(p.node_ip, &p.also_except, &p.tun_name)?;
            self.kill_switch = true;
        }

        // 4. Route all traffic through the TUN.
        sh("ip", &["route", "replace", "default", "dev", &p.tun_name])?;

        // 5. Point DNS at the tunnel resolver(s) (queries now egress through the TUN).
        if !p.dns.is_empty() {
            self.resolv_backup = set_dns(&p.dns);
        }

        self.armed = true;
        tracing::info!(tun = %p.tun_name, kill_switch = p.kill_switch, "datapath armed");
        Ok(())
    }

    fn teardown(&mut self) {
        if !self.armed {
            return;
        }
        // Reverse order; each step best-effort so a partial state still gets cleaned up.
        if let Some(orig) = &self.resolv_backup {
            let _ = std::fs::write("/etc/resolv.conf", orig);
        }
        if let Some(def) = self.orig_default.clone() {
            let mut args = vec!["route", "replace", "default"];
            args.extend(def.split_whitespace());
            let _ = sh("ip", &args);
        } else if let Some(tun) = &self.tun_name {
            let _ = sh("ip", &["route", "del", "default", "dev", tun]);
        }
        if let Some(ip) = self.node_ip {
            let _ = sh("ip", &["route", "del", &format!("{ip}/32")]);
        }
        for ip in &self.also_except {
            let _ = sh("ip", &["route", "del", &format!("{ip}/32")]);
        }
        // Disarm the kill-switch LAST, so connectivity only returns once routes/DNS are sane.
        if self.kill_switch {
            let _ = sh("iptables", &["-P", "OUTPUT", "ACCEPT"]);
            let _ = sh("iptables", &["-F", "OUTPUT"]);
            let _ = sh("ip6tables", &["-P", "OUTPUT", "ACCEPT"]);
            let _ = sh("ip6tables", &["-F", "OUTPUT"]);
        }
        self.armed = false;
        tracing::info!("datapath torn down; networking restored");
    }
}

/// Capture the default route as a `via .. dev ..` spec, or `dev ..` if on-link.
fn capture_default_route() -> Option<String> {
    let out = Command::new("ip").args(["-4", "route", "show", "default"]).output().ok()?;
    let line = String::from_utf8_lossy(&out.stdout);
    let first = line.lines().next()?; // "default via 172.20.0.1 dev eth0 ..."
    let toks: Vec<&str> = first.split_whitespace().collect();
    let via = field(&toks, "via");
    let dev = field(&toks, "dev")?;
    Some(match via {
        Some(gw) => format!("via {gw} dev {dev}"),
        None => format!("dev {dev}"),
    })
}

/// Pin a /32 route to the node replicating its current next-hop, so it stays off the TUN.
fn pin_node_route(node_ip: IpAddr) -> anyhow::Result<()> {
    let out = Command::new("ip").args(["route", "get", &node_ip.to_string()]).output()?;
    let line = String::from_utf8_lossy(&out.stdout);
    let toks: Vec<&str> = line.split_whitespace().collect();
    let dev = field(&toks, "dev")
        .ok_or_else(|| anyhow::anyhow!("no device for node route {node_ip}"))?;
    let cidr = format!("{node_ip}/32");
    match field(&toks, "via") {
        Some(gw) => sh("ip", &["route", "replace", &cidr, "via", gw, "dev", dev]),
        None => sh("ip", &["route", "replace", &cidr, "dev", dev]),
    }
}

/// Fail-closed: drop all egress except loopback, the TUN, and QUIC/TCP to the node:443.
/// Anything that tries to leave directly (bypassing the TUN) is dropped — INCLUDING IPv6.
/// The tunnel is IPv4-only, so IPv6 is dropped wholesale (except loopback / the TUN); otherwise
/// v6 traffic would sail around the v4 kill-switch — the classic VPN IPv6 leak.
fn arm_kill_switch(node_ip: IpAddr, also_except: &[IpAddr], tun: &str) -> anyhow::Result<()> {
    sh("iptables", &["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
    sh("iptables", &["-A", "OUTPUT", "-o", tun, "-j", "ACCEPT"])?;
    // Allow the tunnel's own packets to the node — and to any cascade fallback node, on any port
    // (a fallback rung may use a different UDP port than 443).
    let node = node_ip.to_string();
    sh("iptables", &["-A", "OUTPUT", "-p", "udp", "-d", &node, "--dport", "443", "-j", "ACCEPT"])?;
    sh("iptables", &["-A", "OUTPUT", "-p", "tcp", "-d", &node, "--dport", "443", "-j", "ACCEPT"])?;
    for ip in also_except {
        let d = ip.to_string();
        sh("iptables", &["-A", "OUTPUT", "-d", &d, "-j", "ACCEPT"])?;
    }
    sh("iptables", &["-P", "OUTPUT", "DROP"])?;

    // Block all IPv6 egress. The tunnel is IPv4-only, so any v6 packet that escaped would sail
    // around the v4 kill-switch — the classic dual-stack VPN leak. This must FAIL CLOSED: if we
    // cannot install the v6 default-DROP we abort the whole bring-up (the caller tears down what
    // we armed), rather than running with a v6 leak. The single tolerated case is a host with no
    // IPv6 stack at all, where the DROP policy itself is the load-bearing step: we try lo/tun
    // ACCEPTs best-effort but REQUIRE the `-P OUTPUT DROP` to succeed.
    let v6_accept = |args: &[&str]| {
        if let Err(e) = sh("ip6tables", args) {
            // An ACCEPT rule failing is non-fatal as long as the DROP policy below lands: at worst
            // the host's own loopback/tun v6 is blocked, which never leaks.
            tracing::debug!("ip6tables {args:?} failed ({e})");
        }
    };
    v6_accept(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]);
    v6_accept(&["-A", "OUTPUT", "-o", tun, "-j", "ACCEPT"]);
    // The load-bearing step: default-deny all IPv6 egress. Fail closed if it does not apply.
    sh("ip6tables", &["-P", "OUTPUT", "DROP"]).map_err(|e| {
        anyhow::anyhow!(
            "failed to install IPv6 default-DROP kill-switch ({e}); refusing to run with a \
             potential IPv6 leak. Ensure ip6tables is available (or disable IPv6 on the host)."
        )
    })?;
    Ok(())
}

fn set_dns(dns: &[IpAddr]) -> Option<String> {
    let backup = std::fs::read_to_string("/etc/resolv.conf").ok();
    let body: String = dns.iter().map(|ip| format!("nameserver {ip}\n")).collect();
    if std::fs::write("/etc/resolv.conf", body).is_err() {
        tracing::warn!("could not set tunnel DNS in /etc/resolv.conf");
    }
    backup
}

/// Return the token following `key` (e.g. the value after `via` or `dev`).
fn field<'a>(toks: &'a [&'a str], key: &str) -> Option<&'a str> {
    toks.iter().position(|t| *t == key).and_then(|i| toks.get(i + 1).copied())
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
