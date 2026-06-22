//! The node's exit: a TUN device plus Linux NAT so decapsulated client packets egress to
//! the internet and replies route back. Runs inside the Linux container (needs root for the
//! TUN, `sysctl`, and `iptables`). NAT state is torn down on drop (best-effort).

use std::process::Command;
use std::sync::Arc;

use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::config::NodeConfig;

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
        tracing::info!(tun = %cfg.tun_name, ip = %cfg.node_tun_ip, mtu = cfg.mtu, "TUN up");

        // Disable TX checksum offload: a TUN otherwise hands userspace forwarded packets
        // with partial (CHECKSUM_PARTIAL) L4 checksums, which we'd relay verbatim and the
        // peer would drop. With it off the kernel finalizes checksums.
        if let Err(e) = sh("ethtool", &["-K", &cfg.tun_name, "tx", "off"]) {
            tracing::warn!("ethtool disable tx offload on {}: {e}", cfg.tun_name);
        }

        // Forward + NAT the tunnel subnet out the egress interface (Linux).
        // ip_forward is also set via the compose `sysctls:` key, so this is best-effort.
        if let Err(e) = sh("sysctl", &["-w", "net.ipv4.ip_forward=1"]) {
            tracing::warn!("sysctl ip_forward (continuing; likely already set by the container): {e}");
        }
        sh(
            "iptables",
            &["-t", "nat", "-A", "POSTROUTING", "-s", &cfg.tunnel_cidr, "-o", &cfg.egress, "-j", "MASQUERADE"],
        )?;
        sh("iptables", &["-A", "FORWARD", "-i", &cfg.tun_name, "-j", "ACCEPT"])?;
        sh("iptables", &["-A", "FORWARD", "-o", &cfg.tun_name, "-j", "ACCEPT"])?;
        tracing::info!(egress = %cfg.egress, subnet = %cfg.tunnel_cidr, "NAT exit armed");

        Ok(Exit { tun: Arc::new(tun), cfg: cfg.clone() })
    }

    pub fn tun(&self) -> Arc<AsyncDevice> {
        self.tun.clone()
    }
}

impl Drop for Exit {
    fn drop(&mut self) {
        // Best-effort: remove our NAT/forward rules (the container is throwaway anyway).
        let _ = sh(
            "iptables",
            &["-t", "nat", "-D", "POSTROUTING", "-s", &self.cfg.tunnel_cidr, "-o", &self.cfg.egress, "-j", "MASQUERADE"],
        );
        let _ = sh("iptables", &["-D", "FORWARD", "-i", &self.cfg.tun_name, "-j", "ACCEPT"]);
        let _ = sh("iptables", &["-D", "FORWARD", "-o", &self.cfg.tun_name, "-j", "ACCEPT"]);
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
