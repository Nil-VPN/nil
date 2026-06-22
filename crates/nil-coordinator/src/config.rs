//! Coordinator configuration from the environment.

use std::net::SocketAddr;
use std::path::PathBuf;

use nil_crypto::Verifier;

use crate::pathsel::NodeRegistry;

pub struct CoordConfig {
    pub addr: SocketAddr,
    /// Nodes the Coordinator can route through (trust-split selection picks from here).
    pub registry: NodeRegistry,
    /// Hops per path (default 3: entry/middle/exit).
    pub path_hops: usize,
    /// The Privacy Pass token verifier (public key only). `None` → `/v1/redeem` is disabled
    /// because no issuer public key was configured.
    pub verifier: Option<Verifier>,
    /// Where to durably persist the spent-token nullifier set (`NW_NULLIFIER_PATH`). `None` ⇒
    /// volatile in-memory nullifiers (dev only — a restart re-permits double-spend).
    pub nullifier_path: Option<PathBuf>,
}

impl CoordConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let addr = std::env::var("NW_COORDINATOR_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9090".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("NW_COORDINATOR_ADDR: {e}"))?;
        let path_hops: usize = std::env::var("NW_PATH_HOPS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        // The token verifier loads the issuer's PUBLIC key (hex DER) — it can check tokens but
        // never mint them (the private key stays in the Portal).
        let verifier = match std::env::var("NW_TOKEN_PUBKEY") {
            Ok(hex) => match from_hex(hex.trim()) {
                Some(der) => Some(
                    Verifier::from_public_der(&der)
                        .map_err(|e| anyhow::anyhow!("NW_TOKEN_PUBKEY: {e}"))?,
                ),
                None => anyhow::bail!("NW_TOKEN_PUBKEY is not valid hex"),
            },
            Err(_) => None,
        };
        let nullifier_path = std::env::var("NW_NULLIFIER_PATH").ok().map(PathBuf::from);
        Ok(Self { addr, registry: NodeRegistry::dev_default(), path_hops, verifier, nullifier_path })
    }
}

/// Decode lowercase/uppercase hex; `None` on odd length or a non-hex byte.
pub fn from_hex(hex: &str) -> Option<Vec<u8>> {
    let h = hex.as_bytes();
    if h.len() % 2 != 0 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    for p in h.chunks_exact(2) {
        out.push((nib(p[0])? << 4) | nib(p[1])?);
    }
    Some(out)
}
