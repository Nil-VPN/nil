//! Coordinator configuration from the environment.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
    /// Directory for the EPOCH-PARTITIONED nullifier store (`NW_NULLIFIER_DIR`). When set, the set
    /// is bounded by epoch (a retired epoch's partition is GC'd); `nullifier_path`, if also set, is
    /// migrated in as the epoch-0 partition. `None` ⇒ the flat single-file / in-memory store (no GC).
    pub nullifier_dir: Option<PathBuf>,
    /// Shared Coordinator→node grant MAC key (`NW_GRANT_KEY`, hex). Production nodes require
    /// grants; leaving this unset keeps old local/dev coordinator flows grantless.
    pub grant_key: Option<Vec<u8>>,
    /// Lifetime of node grants minted after token redemption.
    pub grant_ttl: Duration,
    /// Soft alerting threshold for the spent-token nullifier set's size (`NW_NULLIFIER_WARN_AT`,
    /// default 1_000_000). The set is bounded BY EPOCH (retired epochs are GC'd via `drop_epochs`);
    /// crossing this size logs a single PII-free WARN for operational visibility — a hint to rotate
    /// issuer keys. It is not a cap and never drops an entry on the redeem path. See [`crate::nullifier`].
    pub nullifier_warn_at: usize,
}

/// Default soft alerting threshold for the nullifier set size when `NW_NULLIFIER_WARN_AT` is unset.
pub const DEFAULT_NULLIFIER_WARN_AT: usize = 1_000_000;

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
        // The token verifier loads the issuer's PUBLIC key(s) — it can check tokens but never mint
        // them (the private key stays in the Portal). NW_TOKEN_PUBKEY is a COMMA-SEPARATED list of
        // hex DER public keys: hold the current issuer key plus a GRACE window of recent keys so
        // tokens minted under any verify with zero downtime. The Coordinator derives each key's
        // EPOCH from the key itself (`nil_crypto::key_epoch`) — there are NO operator-assigned epoch
        // numbers, so a still-held key can never be "renumbered" out from under its live nullifiers.
        // The derived epochs of the held keys ARE the retention set for nullifier GC: a partition is
        // dropped only once its key leaves this list (i.e. is retired). See main.rs / nullifier.rs.
        let verifier = match std::env::var("NW_TOKEN_PUBKEY") {
            Ok(list) => {
                let ders: Vec<Vec<u8>> = list
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|h| {
                        from_hex(h)
                            .ok_or_else(|| anyhow::anyhow!("NW_TOKEN_PUBKEY entry is not valid hex"))
                    })
                    .collect::<anyhow::Result<_>>()?;
                if ders.is_empty() {
                    None
                } else {
                    Some(
                        Verifier::from_public_ders(&ders)
                            .map_err(|e| anyhow::anyhow!("NW_TOKEN_PUBKEY: {e}"))?,
                    )
                }
            }
            Err(_) => None,
        };
        let nullifier_path = std::env::var("NW_NULLIFIER_PATH").ok().map(PathBuf::from);
        // NW_NULLIFIER_DIR enables the EPOCH-PARTITIONED durable store (bounded-by-epoch GC). When
        // set, the spent-token set lives in an epoch-tagged file under this dir and a retired
        // epoch's partition is dropped at startup; NW_NULLIFIER_PATH (if also set) is migrated in as
        // the epoch-0 partition. Without it, NW_NULLIFIER_PATH alone is a single flat file (no GC).
        let nullifier_dir = std::env::var("NW_NULLIFIER_DIR").ok().map(PathBuf::from);
        let grant_key = load_grant_key()?;
        let grant_ttl = std::env::var("NW_GRANT_TTL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(300));
        let nullifier_warn_at = std::env::var("NW_NULLIFIER_WARN_AT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NULLIFIER_WARN_AT);
        let registry = NodeRegistry::from_env()?;
        Ok(Self {
            addr,
            registry,
            path_hops,
            verifier,
            nullifier_path,
            nullifier_dir,
            grant_key,
            grant_ttl,
            nullifier_warn_at,
        })
    }
}

fn load_grant_key() -> anyhow::Result<Option<Vec<u8>>> {
    let raw = if let Ok(path) = std::env::var("NW_GRANT_KEY_FILE") {
        Some(
            std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("read NW_GRANT_KEY_FILE {path}: {e}"))?,
        )
    } else {
        std::env::var("NW_GRANT_KEY").ok()
    };
    let Some(raw) = raw else { return Ok(None) };
    let key = nil_core::grant::from_hex(raw.trim())
        .ok_or_else(|| anyhow::anyhow!("NW_GRANT_KEY must be hex"))?;
    nil_core::grant::validate_key(&key).map_err(|e| anyhow::anyhow!("NW_GRANT_KEY: {e}"))?;
    Ok(Some(key))
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
