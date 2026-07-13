//! Linux routing / kill-switch / DNS via `ip` and `iptables` (run inside the Docker
//! client container with `NET_ADMIN`). Ordering is chosen so there is never a leak window:
//! arm the kill-switch and pin the node route *before* flipping the default route, and on
//! teardown disarm the kill-switch *last*.

use std::net::IpAddr;
use std::process::Command;

use crate::{ArmParams, CleanupErrors, NetControl};

#[derive(Clone)]
struct PinnedRoute {
    ip: IpAddr,
    cidr: String,
    /// Exact pre-existing route specification, including the destination prefix.
    previous: Option<String>,
}

#[derive(Default)]
pub struct LinuxNet {
    armed: bool,
    /// Exact original IPv4 default route lines, including metrics/protocol attributes.
    orig_defaults: Vec<String>,
    default_changed: bool,
    /// Original `/etc/resolv.conf` bytes. Bytes avoid corrupting an unusual non-UTF-8 file.
    resolv_backup: Option<Vec<u8>>,
    dns_touched: bool,
    firewall_touched: bool,
    /// Host routes this instance replaced, paired with the exact prior route for restoration.
    pinned_routes: Vec<PinnedRoute>,
}

impl NetControl for LinuxNet {
    fn arm(&mut self, p: &ArmParams) -> anyhow::Result<()> {
        if self.armed {
            anyhow::bail!("Linux datapath is already armed or still requires rollback");
        }
        // Mark the object rollback-eligible before the first host mutation. If a later command
        // fails, Tunnel::up must still restore routes, DNS, and our firewall state.
        self.armed = true;

        // 0. Disable TX checksum offload on the TUN — otherwise the kernel hands us packets
        //    with partial L4 checksums that the node/peer then drops (TUN offload gotcha).
        if let Err(e) = sh("ethtool", &["-K", &p.tun_name, "tx", "off"]) {
            tracing::warn!("ethtool disable tx offload on {}: {e}", p.tun_name);
        }

        // 1. Capture the original default route so we can restore it.
        self.orig_defaults = capture_default_routes()?;

        // 2. Pin a host route to the node (and any cascade fallback nodes) via the original path,
        //    so the tunnel's own QUIC/UDP to them bypasses the TUN (avoids a routing loop).
        let node_route = prepare_node_route(p.node_ip)?;
        self.pinned_routes.push(node_route.clone());
        apply_node_route(p.node_ip)?;
        for ip in &p.also_except {
            match prepare_node_route(*ip) {
                Ok(route) => {
                    self.pinned_routes.push(route);
                    if let Err(e) = apply_node_route(*ip) {
                        tracing::warn!("pin fallback node route (continuing): {e}");
                    }
                }
                Err(e) => tracing::warn!("capture fallback node route (continuing): {e}"),
            }
        }
        // 3. Arm the fail-closed kill-switch BEFORE flipping the default route — no window
        //    in which the default points at the TUN but traffic can still escape directly.
        if p.kill_switch {
            // A command can partially build a chain before a later append fails.
            self.firewall_touched = true;
            arm_kill_switch(p.node_ip, &p.also_except, &p.tun_name)?;
        }

        // 4. Route all traffic through the TUN.
        // Record before executing: if the netlink request applies and reporting then fails, the
        // original route is still available for rollback.
        self.default_changed = true;
        sh("ip", &["route", "replace", "default", "dev", &p.tun_name])?;

        // 5. Point DNS at the tunnel resolver(s) (queries now egress through the TUN).
        if !p.dns.is_empty() {
            self.resolv_backup =
                Some(std::fs::read("/etc/resolv.conf").map_err(|e| {
                    anyhow::anyhow!("read /etc/resolv.conf before changing DNS: {e}")
                })?);
            self.dns_touched = true;
            set_dns(&p.dns)?;
        }

        tracing::info!(tun = %p.tun_name, kill_switch = p.kill_switch, "datapath armed");
        Ok(())
    }

    fn teardown(&mut self) -> anyhow::Result<()> {
        if !self.armed {
            return Ok(());
        }
        let mut errors = CleanupErrors::default();

        // Reverse order; attempt every independent restoration, but do not release the firewall
        // unless all host networking mutations are known to be sane.
        if self.dns_touched {
            let restored = match self.resolv_backup.as_deref() {
                Some(orig) => errors.attempt(
                    "restore /etc/resolv.conf",
                    std::fs::write("/etc/resolv.conf", orig).map_err(anyhow::Error::from),
                ),
                None => errors.attempt(
                    "restore /etc/resolv.conf",
                    Err(anyhow::anyhow!("backup is missing")),
                ),
            };
            if restored {
                self.dns_touched = false;
            }
        }

        if self.default_changed {
            let restore = restore_default_routes(&self.orig_defaults);
            if errors.attempt("restore default route", restore) {
                self.default_changed = false;
            }
        }

        let mut failed_routes = Vec::new();
        for route in self.pinned_routes.drain(..).rev() {
            let restore = if let Some(previous) = route.previous.as_deref() {
                let mut args = vec!["route", "replace"];
                args.extend(previous.split_whitespace());
                let mut family_args = vec![route_family(route.ip)];
                family_args.extend(args);
                sh("ip", &family_args)
            } else {
                remove_route_if_present(&route)
            };
            if !errors.attempt("restore pinned node route", restore) {
                failed_routes.push(route);
            }
        }
        failed_routes.reverse();
        self.pinned_routes = failed_routes;

        // Disarm the kill-switch LAST, so connectivity only returns once routes/DNS are sane.
        if errors.is_empty()
            && self.firewall_touched
            && errors.attempt("remove NIL firewall chains", disarm_kill_switch())
        {
            self.firewall_touched = false;
        }

        self.armed = self.dns_touched
            || self.default_changed
            || !self.pinned_routes.is_empty()
            || self.firewall_touched;
        if !self.armed {
            tracing::info!("datapath torn down; networking restored");
        }
        errors.finish()
    }
}

/// Capture every exact default route. Keeping the complete line preserves metric, protocol,
/// scope, source, and multipath attributes instead of flattening the host to one `via/dev` pair.
fn capture_default_routes() -> anyhow::Result<Vec<String>> {
    let out = output("ip", &["-4", "route", "show", "default"])?;
    let line = String::from_utf8_lossy(&out.stdout);
    let routes: Vec<String> = line
        .lines()
        .map(str::trim)
        .filter(|route| !route.is_empty())
        .map(str::to_string)
        .collect();
    if routes.len() > 64 {
        anyhow::bail!("more than 64 IPv4 default routes; refusing an unbounded snapshot");
    }
    if routes.iter().any(|route| !route.starts_with("default ")) {
        anyhow::bail!("unexpected entry while capturing IPv4 default routes");
    }
    Ok(routes)
}

fn restore_default_routes(original: &[String]) -> anyhow::Result<()> {
    // Delete the temporary TUN default and any partial prior retry, then replay the exact bounded
    // snapshot. The operation is retryable: a later call starts from the same empty main table.
    for _ in 0..65 {
        if capture_default_routes()?.is_empty() {
            for route in original {
                let mut args = vec!["-4", "route", "add"];
                args.extend(route.split_whitespace());
                sh("ip", &args)?;
            }
            return Ok(());
        }
        sh("ip", &["-4", "route", "del", "default"])?;
    }
    anyhow::bail!("IPv4 default-route cleanup exceeded its 65-route safety bound")
}

fn route_cidr(ip: IpAddr) -> String {
    format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
}

fn route_family(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "-4"
    } else {
        "-6"
    }
}

/// Snapshot an exact pre-existing host route before replacing it.
fn prepare_node_route(node_ip: IpAddr) -> anyhow::Result<PinnedRoute> {
    let cidr = route_cidr(node_ip);
    let out = output(
        "ip",
        &[route_family(node_ip), "route", "show", "exact", &cidr],
    )?;
    let rendered = String::from_utf8_lossy(&out.stdout);
    let mut lines = rendered.lines().filter(|line| !line.trim().is_empty());
    let previous = lines.next().map(str::to_string);
    if lines.next().is_some() {
        anyhow::bail!("multiple exact routes exist for {cidr}; refusing a lossy replacement");
    }
    Ok(PinnedRoute {
        ip: node_ip,
        cidr,
        previous,
    })
}

fn remove_route_if_present(route: &PinnedRoute) -> anyhow::Result<()> {
    let out = output(
        "ip",
        &[
            route_family(route.ip),
            "route",
            "show",
            "exact",
            &route.cidr,
        ],
    )?;
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        Ok(())
    } else {
        sh("ip", &[route_family(route.ip), "route", "del", &route.cidr])
    }
}

/// Pin a host route to the node replicating its current next-hop, so it stays off the TUN.
fn apply_node_route(node_ip: IpAddr) -> anyhow::Result<()> {
    let out = output(
        "ip",
        &[route_family(node_ip), "route", "get", &node_ip.to_string()],
    )?;
    let line = String::from_utf8_lossy(&out.stdout);
    let toks: Vec<&str> = line.split_whitespace().collect();
    let dev =
        field(&toks, "dev").ok_or_else(|| anyhow::anyhow!("no device for node route {node_ip}"))?;
    let cidr = route_cidr(node_ip);
    match field(&toks, "via") {
        Some(gw) => sh(
            "ip",
            &[
                route_family(node_ip),
                "route",
                "replace",
                &cidr,
                "via",
                gw,
                "dev",
                dev,
            ],
        ),
        None => sh(
            "ip",
            &[route_family(node_ip), "route", "replace", &cidr, "dev", dev],
        ),
    }
}

/// Fail-closed: drop all egress except loopback, the TUN, and QUIC/TCP to the node:443.
/// Anything that tries to leave directly (bypassing the TUN) is dropped — INCLUDING IPv6.
/// The tunnel is IPv4-only, so IPv6 is dropped wholesale (except loopback / the TUN); otherwise
/// v6 traffic would sail around the v4 kill-switch — the classic VPN IPv6 leak.
fn arm_kill_switch(node_ip: IpAddr, also_except: &[IpAddr], tun: &str) -> anyhow::Result<()> {
    const CHAIN: &str = "NILVPN_OUTPUT";
    const V6_CHAIN: &str = "NILVPN_OUTPUT6";
    // Own a dedicated chain. Never mutate or flush the host's global OUTPUT chain/policy.
    let _ = sh("iptables", &["-N", CHAIN]);
    sh("iptables", &["-F", CHAIN])?;
    if sh("iptables", &["-C", "OUTPUT", "-j", CHAIN]).is_err() {
        sh("iptables", &["-I", "OUTPUT", "1", "-j", CHAIN])?;
    }
    sh("iptables", &["-A", CHAIN, "-o", "lo", "-j", "ACCEPT"])?;
    sh("iptables", &["-A", CHAIN, "-o", tun, "-j", "ACCEPT"])?;
    // Allow the tunnel's own packets to the node — and to any cascade fallback node, on any port
    // (a fallback rung may use a different UDP port than 443).
    let node = node_ip.to_string();
    sh(
        "iptables",
        &[
            "-A", CHAIN, "-p", "udp", "-d", &node, "--dport", "443", "-j", "ACCEPT",
        ],
    )?;
    sh(
        "iptables",
        &[
            "-A", CHAIN, "-p", "tcp", "-d", &node, "--dport", "443", "-j", "ACCEPT",
        ],
    )?;
    for ip in also_except {
        let d = ip.to_string();
        sh("iptables", &["-A", CHAIN, "-d", &d, "-j", "ACCEPT"])?;
    }
    sh("iptables", &["-A", CHAIN, "-j", "DROP"])?;

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
    let _ = sh("ip6tables", &["-N", V6_CHAIN]);
    sh("ip6tables", &["-F", V6_CHAIN])?;
    if sh("ip6tables", &["-C", "OUTPUT", "-j", V6_CHAIN]).is_err() {
        sh("ip6tables", &["-I", "OUTPUT", "1", "-j", V6_CHAIN])?;
    }
    v6_accept(&["-A", V6_CHAIN, "-o", "lo", "-j", "ACCEPT"]);
    v6_accept(&["-A", V6_CHAIN, "-o", tun, "-j", "ACCEPT"]);
    // The load-bearing step: default-deny all IPv6 egress. Fail closed if it does not apply.
    sh("ip6tables", &["-A", V6_CHAIN, "-j", "DROP"]).map_err(|e| {
        anyhow::anyhow!(
            "failed to install IPv6 default-DROP kill-switch ({e}); refusing to run with a \
             potential IPv6 leak. Ensure ip6tables is available (or disable IPv6 on the host)."
        )
    })?;
    Ok(())
}

fn disarm_kill_switch() -> anyhow::Result<()> {
    let mut errors = CleanupErrors::default();
    for (cmd, chain) in [
        ("iptables", "NILVPN_OUTPUT"),
        ("ip6tables", "NILVPN_OUTPUT6"),
    ] {
        match command_present(cmd, &["-C", "OUTPUT", "-j", chain]) {
            Ok(true) => {
                errors.attempt(
                    "remove firewall jump",
                    sh(cmd, &["-D", "OUTPUT", "-j", chain]),
                );
            }
            Ok(false) => {}
            Err(error) => {
                errors.attempt("inspect firewall jump", Err(error));
            }
        }
        match command_present(cmd, &["-L", chain]) {
            Ok(true) => {
                if errors.attempt("flush firewall chain", sh(cmd, &["-F", chain])) {
                    errors.attempt("delete firewall chain", sh(cmd, &["-X", chain]));
                }
            }
            Ok(false) => {}
            Err(error) => {
                errors.attempt("inspect firewall chain", Err(error));
            }
        }
    }
    errors.finish()
}

fn set_dns(dns: &[IpAddr]) -> anyhow::Result<()> {
    let body: String = dns.iter().map(|ip| format!("nameserver {ip}\n")).collect();
    std::fs::write("/etc/resolv.conf", body)
        .map_err(|e| anyhow::anyhow!("write tunnel DNS to /etc/resolv.conf: {e}"))
}

/// Return the token following `key` (e.g. the value after `via` or `dev`).
fn field<'a>(toks: &'a [&'a str], key: &str) -> Option<&'a str> {
    toks.iter()
        .position(|t| *t == key)
        .and_then(|i| toks.get(i + 1).copied())
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

/// iptables uses status 1 for a negative membership/existence query and >1 for an actual error.
fn command_present(cmd: &str, args: &[&str]) -> anyhow::Result<bool> {
    tracing::debug!("$ {cmd} {}", args.join(" "));
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("spawn {cmd}: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => anyhow::bail!(
            "`{cmd} {}` exited with {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
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
