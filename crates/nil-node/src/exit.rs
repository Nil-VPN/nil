//! The node's datapath: a TUN device plus Linux NAT/forward so decapsulated client packets reach
//! the next hop (or the internet, at the exit) and replies route back. Runs inside the Linux
//! container (needs root for the TUN, `sysctl`, and `iptables`). NAT state is torn down on drop.
//!
//! **Role-scoped egress (trust-split hardening).** An `Exit` NATs the tunnel subnet openly to the
//! internet — it is the only hop that should reach arbitrary destinations. An `Entry`/`Middle`
//! forwards ONLY node-to-node QUIC (UDP/443) toward the next hop and DROPs anything else from the
//! tunnel: this stops a malicious client from turning an intermediate node into an open internet
//! relay / destination-revealing exit (PD-3/PD-7). The decapsulated inner packet on an intermediate
//! is always the next hop's QUIC wrapped in udpip (spec §6), i.e. UDP/443 — so the legitimate path
//! is unaffected. (The struct keeps the historical name `Exit`; it is the datapath for every role.)

use std::process::Command;
use std::sync::Arc;

use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::config::{NodeConfig, NodeRole};

/// The UDP port nil-nodes listen on (CONNECT-IP/QUIC). An intermediate hop only ever forwards the
/// next hop's QUIC, which is destined here — so this is the single port a Middle/Entry NATs.
const NODE_QUIC_PORT: &str = "443";

pub struct Exit {
    tun: Arc<AsyncDevice>,
    cfg: NodeConfig,
}

impl Exit {
    pub fn setup(cfg: &NodeConfig) -> anyhow::Result<Exit> {
        let tun = DeviceBuilder::new()
            .name(cfg.tun_name.clone())
            .ipv4(cfg.node_tun_ip, cfg.prefix, None)
            .mtu(cfg.mtu)
            .build_async()
            .map_err(|e| anyhow::anyhow!("create TUN {}: {e}", cfg.tun_name))?;
        // PD-1: keep node startup logging minimal. The interface name + MTU are enough to debug the
        // datapath; the tunnel gateway IP and the node's role are not needed in the logs and only
        // add path-topology detail that could be correlated if a node's logs ever leaked.
        tracing::info!(tun = %cfg.tun_name, mtu = cfg.mtu, "TUN up");

        // Disable TX checksum offload: a TUN otherwise hands userspace forwarded packets
        // with partial (CHECKSUM_PARTIAL) L4 checksums, which we'd relay verbatim and the
        // peer would drop. With it off the kernel finalizes checksums.
        if let Err(e) = sh("ethtool", &["-K", &cfg.tun_name, "tx", "off"]) {
            tracing::warn!("ethtool disable tx offload on {}: {e}", cfg.tun_name);
        }

        // Forward + NAT the tunnel subnet (Linux). ip_forward is also set via the compose
        // `sysctls:` key, so this is best-effort. The rule SET is role-scoped (see `nat_rules`).
        if let Err(e) = sh("sysctl", &["-w", "net.ipv4.ip_forward=1"]) {
            tracing::warn!("sysctl ip_forward (continuing; likely already set by the container): {e}");
        }
        for rule in nat_rules(cfg) {
            sh("iptables", &rule.iter().map(String::as_str).collect::<Vec<_>>())?;
        }
        tracing::info!(
            egress = %cfg.egress, subnet = %cfg.tunnel_cidr, role = ?cfg.role,
            open_egress = role_has_open_egress(cfg.role),
            "datapath NAT/forward armed (open egress only at the exit)"
        );

        Ok(Exit { tun: Arc::new(tun), cfg: cfg.clone() })
    }

    pub fn tun(&self) -> Arc<AsyncDevice> {
        self.tun.clone()
    }
}

impl Drop for Exit {
    fn drop(&mut self) {
        // Best-effort: remove exactly the rules we added (delete-form = the add-form with -A→-D).
        for rule in nat_rules(&self.cfg) {
            let del: Vec<String> = rule
                .iter()
                .map(|tok| if tok == "-A" { "-D".to_string() } else { tok.clone() })
                .collect();
            let _ = sh("iptables", &del.iter().map(String::as_str).collect::<Vec<_>>());
        }
    }
}

/// Whether this role may NAT the tunnel openly to the internet. ONLY the exit — an intermediate hop
/// that did so could be coerced into an open relay / destination-revealing exit (trust-split / PD-7).
fn role_has_open_egress(role: NodeRole) -> bool {
    matches!(role, NodeRole::Exit)
}

/// The iptables rules (add-form, `-A`) this node installs, scoped by role. Pure so the policy is
/// unit-testable without iptables: an exit gets open MASQUERADE + open FORWARD; an entry/middle gets
/// UDP/443-only MASQUERADE and a FORWARD chain that permits only QUIC-to-the-next-hop out of the
/// tunnel (plus replies back in) and DROPs everything else — so it can never be a general exit.
fn nat_rules(cfg: &NodeConfig) -> Vec<Vec<String>> {
    let s = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let tun = cfg.tun_name.as_str();
    let cidr = cfg.tunnel_cidr.as_str();
    let eg = cfg.egress.as_str();
    if role_has_open_egress(cfg.role) {
        vec![
            s(&["-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-o", eg, "-j", "MASQUERADE"]),
            s(&["-A", "FORWARD", "-i", tun, "-j", "ACCEPT"]),
            s(&["-A", "FORWARD", "-o", tun, "-j", "ACCEPT"]),
        ]
    } else {
        // Entry/Middle: only node-to-node QUIC (UDP/443) leaves the tunnel; replies return; all
        // other tunnel-sourced traffic is dropped (the open-relay guard). First match wins, so the
        // reply + QUIC ACCEPTs precede the catch-all DROP.
        vec![
            s(&["-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-o", eg, "-p", "udp", "--dport", NODE_QUIC_PORT, "-j", "MASQUERADE"]),
            s(&["-A", "FORWARD", "-o", tun, "-j", "ACCEPT"]),
            s(&["-A", "FORWARD", "-i", tun, "-p", "udp", "--dport", NODE_QUIC_PORT, "-j", "ACCEPT"]),
            s(&["-A", "FORWARD", "-i", tun, "-j", "DROP"]),
        ]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn cfg(role: NodeRole) -> NodeConfig {
        NodeConfig {
            bind: "0.0.0.0:443".parse::<SocketAddr>().unwrap(),
            tun_name: "nil0".into(),
            node_tun_ip: "10.74.0.1".parse().unwrap(),
            prefix: 24,
            tunnel_cidr: "10.74.0.0/24".into(),
            egress: "eth0".into(),
            mtu: 1420,
            attest: None,
            role,
            grant_key: None,
            allow_ungranted: false,
        }
    }

    #[test]
    fn only_the_exit_has_open_egress() {
        assert!(role_has_open_egress(NodeRole::Exit));
        assert!(!role_has_open_egress(NodeRole::Middle));
        assert!(!role_has_open_egress(NodeRole::Entry));
    }

    #[test]
    fn exit_rules_masquerade_openly_no_drop() {
        let rules = nat_rules(&cfg(NodeRole::Exit));
        let flat: Vec<String> = rules.iter().map(|r| r.join(" ")).collect();
        // Open MASQUERADE (no --dport restriction) and no DROP guard.
        assert!(flat.iter().any(|r| r.contains("POSTROUTING") && r.contains("MASQUERADE") && !r.contains("--dport")));
        assert!(!flat.iter().any(|r| r.contains("-j DROP")), "the exit drops nothing from the tunnel");
    }

    #[test]
    fn intermediate_rules_restrict_to_quic_and_drop_the_rest() {
        for role in [NodeRole::Middle, NodeRole::Entry] {
            let rules = nat_rules(&cfg(role));
            let flat: Vec<String> = rules.iter().map(|r| r.join(" ")).collect();
            // MASQUERADE is UDP/443-only (no open MASQUERADE).
            assert!(flat.iter().any(|r| r.contains("MASQUERADE") && r.contains("--dport") && r.contains("443")), "{role:?}");
            assert!(!flat.iter().any(|r| r.contains("MASQUERADE") && !r.contains("--dport")), "{role:?}: no open MASQUERADE");
            // A catch-all DROP for non-QUIC tunnel-sourced traffic (the open-relay guard).
            assert!(flat.iter().any(|r| r.contains("FORWARD") && r.contains("-i nil0") && r.contains("-j DROP")), "{role:?}");
            // QUIC out + replies in are permitted, and the QUIC ACCEPT precedes the DROP.
            let quic = flat.iter().position(|r| r.contains("-i nil0") && r.contains("443") && r.contains("ACCEPT"));
            let drop = flat.iter().position(|r| r.contains("-i nil0") && r.contains("DROP"));
            assert!(quic.is_some() && drop.is_some() && quic < drop, "{role:?}: QUIC ACCEPT must precede DROP");
        }
    }
}
