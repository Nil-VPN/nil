//! NIL VPN Data plane node (`nil-node`) — Phase 1 MASQUE/CONNECT-IP exit.
//!
//! Accepts an HTTP/3 extended `CONNECT` with `:protocol=connect-ip` over QUIC (UDP 443),
//! decapsulates IP packets from QUIC DATAGRAMs onto a TUN device, and NATs them to the
//! internet (Linux). Replies route back through the TUN and are re-encapsulated to the
//! client. Runs inside a Linux container/TEE; keeps **no disk logs** (stdout only) and
//! persists nothing identifying.
//!
//! Phase 1 presents a self-signed dev TLS cert (NOT attestation — RA-TLS is Phase 2, §5).

mod attest;
mod cert;
mod config;
mod exit;
#[cfg(feature = "hw-attest")]
mod hw;
mod pqwg;
mod server;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Logs to stdout only — never to disk (datapath must stay logless).
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cfg = config::NodeConfig::from_env()?;
    // `bind`/`egress` are the node operator's own infra addresses (operational, not
    // user-linkable); the tunnel-internal addressing (node/client IPs) is deliberately
    // NOT logged — it reads as user data and the datapath must stay logless (SOUL §3 / PD-3).
    tracing::info!(
        bind = %cfg.bind, egress = %cfg.egress, tun = %cfg.tun_name, role = ?cfg.role,
        "nil-node starting (MASQUE/CONNECT-IP; no disk logs)"
    );

    let cert = cert::DevCert::generate(vec!["nil-node".to_string(), "localhost".to_string()])?;
    let exit = exit::Exit::setup(&cfg)?;

    // Runs until Ctrl-C; `exit` drops here and tears down the NAT rules.
    server::run(&cfg, &cert, exit.tun()).await?;
    Ok(())
}
