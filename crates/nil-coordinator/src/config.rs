//! Coordinator configuration from the environment. Phase 2 publishes one pinned node + its
//! measurement; Phase 3 turns this into a node registry with trust-split path selection.

use std::net::SocketAddr;

use nil_proto::path::{Hop, Tee};

/// The synthetic dev measurement (matches deploy/compose.yaml). A real deployment sets
/// `NW_PINNED_MEASUREMENT` from the reproducible build's transparency-log entry.
const DEFAULT_MEASUREMENT: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

pub struct CoordConfig {
    pub addr: SocketAddr,
    /// Phase 2: a single configured hop + the measurement it must attest to.
    pub hop: Hop,
}

impl CoordConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let addr = std::env::var("NW_COORDINATOR_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9090".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("NW_COORDINATOR_ADDR: {e}"))?;
        let host = std::env::var("NW_NODE_HOST").unwrap_or_else(|_| "node".to_string());
        let port: u16 = std::env::var("NW_NODE_PORT")
            .unwrap_or_else(|_| "443".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("NW_NODE_PORT: {e}"))?;
        let measurement =
            std::env::var("NW_PINNED_MEASUREMENT").unwrap_or_else(|_| DEFAULT_MEASUREMENT.to_string());
        let tee = match std::env::var("NW_PINNED_TEE").unwrap_or_else(|_| "sev-snp".into()).as_str() {
            "tdx" => Tee::Tdx,
            _ => Tee::SevSnp,
        };
        let wg_pub = std::env::var("NW_NODE_WG_PUB").ok().filter(|s| !s.is_empty());
        Ok(Self { addr, hop: Hop { host, port, tee, measurement, wg_pub } })
    }
}
