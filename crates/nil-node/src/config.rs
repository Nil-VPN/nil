//! Node configuration from environment. No identifying state is persisted.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use nil_core::grant::{GrantRole, GrantVerifier};

const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Bound one source address below the process-wide ceiling. This is deliberately configurable for
/// carrier-NAT deployments, but an attacker with one reachable address must not be able to occupy
/// every retained QUIC connection by default.
const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 32;
const DEFAULT_GRANT_REPLAY_CAPACITY: usize = 65_536;

/// A node's position in a trust-split path (architecture spec §6). Entry sees the client IP
/// but not the destination; exit sees the destination but not the client IP; middle sees
/// neither. The exit NATs the tunnel openly to the internet; entry/middle forward the next hop's
/// QUIC (UDP/443) onward and DROP anything else from the tunnel, so an intermediate node can never
/// be coerced into an open internet relay (the role-scoped egress in [`crate::exit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Entry,
    Middle,
    Exit,
}

impl NodeRole {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "entry" => Ok(NodeRole::Entry),
            "middle" => Ok(NodeRole::Middle),
            "exit" => Ok(NodeRole::Exit),
            _ => anyhow::bail!("NW_NODE_ROLE must be one of: entry, middle, exit"),
        }
    }

    pub const fn grant_role(self) -> GrantRole {
        match self {
            Self::Entry => GrantRole::Entry,
            Self::Middle => GrantRole::Middle,
            Self::Exit => GrantRole::Exit,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// UDP listen address (default `0.0.0.0:443`; privileged port → needs root).
    pub bind: SocketAddr,
    /// Name of the node's TUN device.
    pub tun_name: String,
    /// Address assigned to the node end of the tunnel.
    pub node_tun_ip: Ipv4Addr,
    /// Tunnel subnet prefix length.
    pub prefix: u8,
    /// `network/prefix` CIDR for the NAT source match (e.g. `10.74.0.0/24`).
    pub tunnel_cidr: String,
    /// Egress interface for NAT (default `eth0` — the container's uplink).
    pub egress: String,
    /// TUN MTU (kept under the QUIC datagram limit; see nil-transport MTU notes).
    pub mtu: u16,
    /// What this node attests to (from the environment). `None` ⇒ serve unattested (dev).
    pub attest: Option<crate::attest::NodeAttest>,
    /// This node's position in a trust-split path (`NW_NODE_ROLE`: entry|middle|exit).
    pub role: NodeRole,
    /// Rotation-capable Coordinator grant verifier. Nodes hold public keys only; the corresponding
    /// signing seeds remain exclusively in the Coordinator.
    pub grant_verifier: Option<GrantVerifier>,
    /// Deployment realm and stable node identifier forming the exact NWG2 audience.
    pub grant_realm: Option<String>,
    pub node_id: Option<String>,
    /// Stable owner-only TLS private key. Required for hardware/release posture so registry SPKI
    /// pins and NWG2 audiences survive process restarts; debug may generate an ephemeral key.
    pub tls_key_file: Option<PathBuf>,
    /// Explicit local/dev bypass for nodes that intentionally accept grantless clients.
    pub allow_ungranted: bool,
    /// Maximum concurrent QUIC connections retained by the event loop.
    pub max_connections: usize,
    /// Maximum concurrent QUIC connections whose Retry-validated peer address is the same. The
    /// address is retained only in the live in-memory connection and is never logged or persisted.
    pub max_connections_per_ip: usize,
    /// Maximum number of anonymous, unexpired grant identifiers retained for single-use
    /// enforcement. Exhaustion rejects new authorized tunnels rather than permitting replay.
    pub grant_replay_capacity: usize,
}

impl NodeConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let bind = std::env::var("NW_NODE_BIND")
            .unwrap_or_else(|_| "0.0.0.0:443".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("NW_NODE_BIND: {e}"))?;
        let egress = std::env::var("NW_NODE_EGRESS").unwrap_or_else(|_| "eth0".to_string());
        // Phase 1 fixed addressing (no ADDRESS_ASSIGN capsule yet — see ADR/plan).
        reject_legacy_grant_key_env()?;
        let strict = cfg!(feature = "hw-attest") || !cfg!(debug_assertions);
        let (grant_verifier, verifier_from_file) = load_grant_verifier()?;
        let grant_realm = optional_identifier_env("NW_GRANT_REALM")?;
        let node_id = optional_identifier_env("NW_NODE_ID")?;
        validate_complete_grant_identity(
            grant_verifier.as_ref(),
            grant_realm.as_deref(),
            node_id.as_deref(),
        )?;
        if strict && (!verifier_from_file || grant_verifier.is_none()) {
            anyhow::bail!("hardware/release nodes require file-backed NW_GRANT_VERIFY_KEYS_FILE");
        }
        if strict && grant_realm.is_none() {
            anyhow::bail!("hardware/release nodes require NW_GRANT_REALM");
        }
        if strict && node_id.is_none() {
            anyhow::bail!("hardware/release nodes require NW_NODE_ID");
        }
        let tls_key_file = std::env::var_os("NW_NODE_TLS_KEY_FILE").map(PathBuf::from);
        if strict && tls_key_file.is_none() {
            anyhow::bail!("hardware/release nodes require owner-only NW_NODE_TLS_KEY_FILE");
        }

        let role = match std::env::var("NW_NODE_ROLE") {
            Ok(value) => NodeRole::parse(&value)?,
            Err(std::env::VarError::NotPresent) if !strict => NodeRole::Exit,
            Err(std::env::VarError::NotPresent) => {
                anyhow::bail!("hardware/release nodes require explicit NW_NODE_ROLE")
            }
            Err(e) => anyhow::bail!("NW_NODE_ROLE: {e}"),
        };
        // Compile-time development gate: optimized production builds always read this as false,
        // regardless of their process environment.
        let allow_ungranted = nil_core::net::dev_env_flag("NW_ALLOW_UNGRANTED");
        if strict && allow_ungranted {
            anyhow::bail!("hardware/release nodes refuse NW_ALLOW_UNGRANTED");
        }
        let max_connections =
            positive_usize_env("NW_NODE_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS)?;
        let max_connections_per_ip = positive_usize_env(
            "NW_NODE_MAX_CONNECTIONS_PER_IP",
            DEFAULT_MAX_CONNECTIONS_PER_IP.min(max_connections),
        )?;
        if max_connections_per_ip > max_connections {
            anyhow::bail!("NW_NODE_MAX_CONNECTIONS_PER_IP must not exceed NW_NODE_MAX_CONNECTIONS");
        }
        let grant_replay_capacity = positive_usize_env(
            "NW_NODE_GRANT_REPLAY_CAPACITY",
            DEFAULT_GRANT_REPLAY_CAPACITY,
        )?;
        if grant_replay_capacity < max_connections {
            anyhow::bail!("NW_NODE_GRANT_REPLAY_CAPACITY must be at least NW_NODE_MAX_CONNECTIONS");
        }
        Ok(Self {
            bind,
            tun_name: std::env::var("NW_NODE_TUN").unwrap_or_else(|_| "nil0".to_string()),
            node_tun_ip: "10.74.0.1".parse().expect("valid ip"),
            prefix: 24,
            tunnel_cidr: "10.74.0.0/24".to_string(),
            egress,
            // The TUN carries decapsulated client IP packets out to the next hop / internet. For
            // a trust-split path those packets are the next hop's QUIC wrapped in udpip (spec
            // §6), up to the outer tunnel's MTU (~1411 B at the 1420 B payload ceiling), in BOTH
            // directions. A 1280 TUN silently drops the larger nested handshake/response packets,
            // so it must clear the wrapped size; 1420 matches the QUIC payload ceiling. (Single
            // hop is unaffected: real packets stay ≤ the client's ~1280 TUN.)
            mtu: 1420,
            attest: crate::attest::NodeAttest::from_env()?,
            role,
            grant_verifier,
            grant_realm,
            node_id,
            tls_key_file,
            allow_ungranted,
            max_connections,
            max_connections_per_ip,
            grant_replay_capacity,
        })
    }
}

fn positive_usize_env(name: &'static str, default: usize) -> anyhow::Result<usize> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .map_err(|e| anyhow::anyhow!("{name}: {e}"))
            .and_then(|value| {
                if value == 0 {
                    anyhow::bail!("{name} must be greater than zero");
                }
                Ok(value)
            }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(anyhow::anyhow!("{name}: {e}")),
    }
}

fn reject_legacy_grant_key_env() -> anyhow::Result<()> {
    if std::env::vars_os().any(|(name, _)| name.to_string_lossy().starts_with("NW_GRANT_KEY")) {
        anyhow::bail!(
            "legacy NW_GRANT_KEY* is not supported; configure NWG2 public keys with NW_GRANT_VERIFY_KEYS_FILE"
        );
    }
    Ok(())
}

fn optional_identifier_env(name: &'static str) -> anyhow::Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => {
            nil_core::grant::validate_identifier(&value)
                .map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
            Ok(Some(value))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("{name}: {e}")),
    }
}

fn validate_complete_grant_identity(
    verifier: Option<&GrantVerifier>,
    realm: Option<&str>,
    node_id: Option<&str>,
) -> anyhow::Result<()> {
    let configured = [verifier.is_some(), realm.is_some(), node_id.is_some()];
    if configured.iter().any(|value| *value) && !configured.iter().all(|value| *value) {
        anyhow::bail!(
            "NW_GRANT_VERIFY_KEYS_FILE/NW_GRANT_VERIFY_KEYS, NW_GRANT_REALM, and NW_NODE_ID must be configured together"
        );
    }
    Ok(())
}

/// Load the trusted Coordinator public-key set. The boolean reports whether the set came from the
/// file-backed production input rather than the debug-only inline input.
fn load_grant_verifier() -> anyhow::Result<(Option<GrantVerifier>, bool)> {
    let file = std::env::var("NW_GRANT_VERIFY_KEYS_FILE").ok();
    let inline = std::env::var("NW_GRANT_VERIFY_KEYS").ok();
    if file.is_some() && inline.is_some() {
        anyhow::bail!("set only one of NW_GRANT_VERIFY_KEYS_FILE or NW_GRANT_VERIFY_KEYS");
    }

    if let Some(path) = file {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("read NW_GRANT_VERIFY_KEYS_FILE {path}: {e}"))?;
        return Ok((
            Some(parse_grant_verifier(&raw, "NW_GRANT_VERIFY_KEYS_FILE")?),
            true,
        ));
    }
    if let Some(raw) = inline {
        if !cfg!(debug_assertions) || cfg!(feature = "hw-attest") {
            anyhow::bail!(
                "NW_GRANT_VERIFY_KEYS is debug-only; hardware/release nodes require NW_GRANT_VERIFY_KEYS_FILE"
            );
        }
        return Ok((
            Some(parse_grant_verifier(&raw, "NW_GRANT_VERIFY_KEYS")?),
            false,
        ));
    }
    Ok((None, false))
}

fn parse_grant_verifier(raw: &str, source: &'static str) -> anyhow::Result<GrantVerifier> {
    let mut keys = Vec::new();
    for line in raw.lines() {
        // Full-line and inline comments are accepted so an operator can record key IDs/rotation
        // stages without changing the machine-readable key material.
        let data = line.split_once('#').map_or(line, |(data, _)| data);
        for encoded in data
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let decoded = nil_core::grant::from_hex(encoded)
                .ok_or_else(|| anyhow::anyhow!("{source}: public key must be hex"))?;
            let key: [u8; 32] = decoded.try_into().map_err(|_| {
                anyhow::anyhow!(
                    "{source}: each Ed25519 public key must be exactly 64 hex characters"
                )
            })?;
            keys.push(key);
        }
    }
    GrantVerifier::new(keys).map_err(|e| anyhow::anyhow!("{source}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nil_core::grant::GrantSigningKey;

    #[test]
    fn role_parser_never_turns_unknown_input_into_exit() {
        assert_eq!(NodeRole::parse("entry").unwrap(), NodeRole::Entry);
        assert_eq!(NodeRole::parse("middle").unwrap(), NodeRole::Middle);
        assert_eq!(NodeRole::parse("exit").unwrap(), NodeRole::Exit);
        assert!(NodeRole::parse("typo").is_err());
        assert!(NodeRole::parse("").is_err());
    }

    #[test]
    fn verifier_parser_accepts_rotation_files_commas_and_comments() {
        let a = GrantSigningKey::from_seed([0x11; 32]).public_key_bytes();
        let b = GrantSigningKey::from_seed([0x22; 32]).public_key_bytes();
        let raw = format!(
            "# active and staged keys\n{} # active\n{}, {}\n",
            nil_core::grant::to_hex(&a),
            nil_core::grant::to_hex(&a),
            nil_core::grant::to_hex(&b),
        );
        let verifier = parse_grant_verifier(&raw, "test").unwrap();
        assert_eq!(verifier.len(), 2, "duplicate keys are idempotent");
    }

    #[test]
    fn verifier_parser_rejects_empty_malformed_and_wrong_length_keys() {
        assert!(parse_grant_verifier("# no keys\n", "test").is_err());
        assert!(parse_grant_verifier("zz", "test").is_err());
        assert!(parse_grant_verifier("00", "test").is_err());
    }

    #[test]
    fn grant_identity_is_all_or_nothing() {
        let key = GrantSigningKey::from_seed([0x33; 32]).public_key_bytes();
        let verifier = GrantVerifier::from_public_key(key).unwrap();
        assert!(
            validate_complete_grant_identity(Some(&verifier), Some("prod-us"), Some("exit-1"))
                .is_ok()
        );
        assert!(validate_complete_grant_identity(Some(&verifier), Some("prod-us"), None).is_err());
        assert!(validate_complete_grant_identity(None, Some("prod-us"), Some("exit-1")).is_err());
        assert!(validate_complete_grant_identity(None, None, None).is_ok());
    }
}
