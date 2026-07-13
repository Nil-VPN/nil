//! Coordinator configuration from the environment.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use nil_core::grant::{GrantSigningKey, MAX_GRANT_TTL_SECS};
use nil_crypto::Verifier;
use zeroize::Zeroizing;

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
    /// Where to durably persist the permanent nullifier/encrypted-result ledger
    /// (`NW_NULLIFIER_PATH`). `None` means volatile memory (development only; a restart
    /// re-permits double-spend).
    pub nullifier_path: Option<PathBuf>,
    /// Directory for the epoch-partitioned nullifier store (`NW_NULLIFIER_DIR`). This prepares for
    /// future fleet-coordinated GC, but automatic deletion is currently disabled; storage remains
    /// growing. `nullifier_path`, if also set, is migrated in as epoch 0.
    pub nullifier_dir: Option<PathBuf>,
    /// Coordinator-only Ed25519 grant signer. Nodes receive public verification keys only, so a
    /// compromised node cannot mint credentials for itself or the rest of the fleet.
    pub grant_signer: Option<GrantSigningKey>,
    /// Deployment realm signed into every grant. Production and staging must use different realms
    /// even if an operator accidentally reuses a key.
    pub grant_realm: String,
    /// Lifetime of node grants minted after token redemption.
    pub grant_ttl: Duration,
    /// AES-256-GCM key used only to encrypt the short-lived replayable `PathResponse`. Production
    /// loads it from an owner-only file shared by every Coordinator replica.
    pub redemption_result_key: Zeroizing<[u8; 32]>,
    /// Soft alerting threshold for the permanent redemption ledger's size
    /// (`NW_NULLIFIER_WARN_AT`, default 1_000_000). Epoch partitioning prepares for future
    /// fleet-coordinated deletion, but automatic GC is disabled and the ledger still grows.
    /// Crossing this size logs one PII-free WARN; it is not a cap and never drops an entry on the
    /// redeem path. See [`crate::nullifier`].
    pub nullifier_warn_at: usize,
}

/// Default soft alerting threshold for the redemption ledger size when `NW_NULLIFIER_WARN_AT` is
/// unset.
pub const DEFAULT_NULLIFIER_WARN_AT: usize = 1_000_000;
const GRANT_SEED_HEX_LEN: usize = 64;
const MAX_GRANT_SEED_FILE_BYTES: usize = GRANT_SEED_HEX_LEN + 1;
const REDEMPTION_RESULT_KEY_BYTES: usize = 32;

impl CoordConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let addr = std::env::var("NW_COORDINATOR_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9090".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("NW_COORDINATOR_ADDR: {e}"))?;
        let path_hops: usize = match std::env::var("NW_PATH_HOPS") {
            Ok(raw) => raw
                .parse()
                .map_err(|e| anyhow::anyhow!("NW_PATH_HOPS: {e}"))?,
            Err(_) => 3,
        };
        if !(1..=8).contains(&path_hops) {
            anyhow::bail!("NW_PATH_HOPS must be between 1 and 8");
        }
        // The token verifier loads the issuer's PUBLIC key(s) — it can check tokens but never mint
        // them (the private key stays in the Portal). NW_TOKEN_PUBKEY is a COMMA-SEPARATED list of
        // hex DER public keys: hold the current issuer key plus a GRACE window of recent keys so
        // tokens minted under any verify with zero downtime. The Coordinator derives each key's
        // EPOCH from the key itself (`nil_crypto::key_epoch`) — there are NO operator-assigned epoch
        // numbers, so a still-held key can never be "renumbered" out from under its live nullifiers.
        // Derived epochs label nullifier partitions. Automatic deletion is disabled until a
        // fleet-coordinated GC protocol can prove retired keys are absent from every verifier.
        let verifier = match std::env::var("NW_TOKEN_PUBKEY") {
            Ok(list) => {
                let ders: Vec<Vec<u8>> = list
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|h| {
                        from_hex(h).ok_or_else(|| {
                            anyhow::anyhow!("NW_TOKEN_PUBKEY entry is not valid hex")
                        })
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
        // NW_NULLIFIER_DIR enables epoch partitioning for future fleet-coordinated GC. Automatic
        // deletion is disabled today. NW_NULLIFIER_PATH (if also set) migrates into epoch 0;
        // without the directory it remains one flat file.
        let nullifier_dir = std::env::var("NW_NULLIFIER_DIR").ok().map(PathBuf::from);
        let release_build = !cfg!(debug_assertions);
        let (grant_signer, signer_from_file) = load_grant_signer(release_build)?;
        let (redemption_result_key, result_key_from_file) =
            load_redemption_result_key(release_build)?;
        let grant_realm = std::env::var("NW_GRANT_REALM").unwrap_or_default();
        if !grant_realm.is_empty() {
            nil_core::grant::validate_identifier(&grant_realm)
                .map_err(|e| anyhow::anyhow!("NW_GRANT_REALM: {e}"))?;
        }
        if grant_signer.is_some() && grant_realm.is_empty() {
            anyhow::bail!("NW_GRANT_REALM is required whenever grant signing is configured");
        }
        let grant_ttl_secs = match std::env::var("NW_GRANT_TTL_SECS") {
            Ok(raw) => raw
                .parse::<u64>()
                .map_err(|e| anyhow::anyhow!("NW_GRANT_TTL_SECS: {e}"))?,
            Err(_) => 300,
        };
        if !(1..=MAX_GRANT_TTL_SECS).contains(&grant_ttl_secs) {
            anyhow::bail!("NW_GRANT_TTL_SECS must be between 1 and {MAX_GRANT_TTL_SECS} seconds");
        }
        let grant_ttl = Duration::from_secs(grant_ttl_secs);
        let nullifier_warn_at = std::env::var("NW_NULLIFIER_WARN_AT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_NULLIFIER_WARN_AT);
        let registry = NodeRegistry::from_env()?;
        if path_hops > registry.nodes.len() {
            anyhow::bail!(
                "NW_PATH_HOPS ({path_hops}) exceeds the {} nodes in NW_NODE_REGISTRY",
                registry.nodes.len()
            );
        }
        validate_registry_feasibility(&registry, path_hops)?;
        validate_release_posture(ReleasePosture {
            path_hops,
            has_verifier: verifier.is_some(),
            has_grant_signer: grant_signer.is_some(),
            has_grant_realm: !grant_realm.is_empty(),
            signer_from_file,
            result_key_from_file,
            registry_tls_pinned: registry.all_nodes_have_tls_spki(),
            registry_transparency_pinned: registry.all_nodes_have_transparency_key(),
            registry_sev_tcb_pinned: registry.all_sev_nodes_have_min_tcb(),
            registry_nested_ipv4_ready: registry.all_nodes_have_nested_ipv4_endpoints(),
            release_build,
        })?;
        Ok(Self {
            addr,
            registry,
            path_hops,
            verifier,
            nullifier_path,
            nullifier_dir,
            grant_signer,
            grant_realm,
            grant_ttl,
            redemption_result_key,
            nullifier_warn_at,
        })
    }
}

/// Refuse an impossible topology before the HTTP listener can burn otherwise-valid tokens on a
/// path that can never be assembled. This is an all-profile startup invariant, not only release
/// hardening: local integration config should fail just as early and clearly.
fn validate_registry_feasibility(registry: &NodeRegistry, path_hops: usize) -> anyhow::Result<()> {
    if registry.select_path(path_hops).is_none() {
        anyhow::bail!(
            "NW_NODE_REGISTRY cannot form a {path_hops}-hop role-compatible, operator- and jurisdiction-diverse path"
        );
    }
    Ok(())
}

/// Coordinators built without debug assertions must actually enforce paid redemption, grant
/// authorization, and a trust-split path. Kept pure so normal tests can exercise the production
/// posture without depending on the compile profile or process-global environment.
#[derive(Debug, Clone, Copy)]
struct ReleasePosture {
    path_hops: usize,
    has_verifier: bool,
    has_grant_signer: bool,
    has_grant_realm: bool,
    signer_from_file: bool,
    result_key_from_file: bool,
    registry_tls_pinned: bool,
    registry_transparency_pinned: bool,
    registry_sev_tcb_pinned: bool,
    registry_nested_ipv4_ready: bool,
    release_build: bool,
}

fn validate_release_posture(posture: ReleasePosture) -> anyhow::Result<()> {
    if !posture.release_build {
        return Ok(());
    }
    if posture.path_hops < 2 {
        anyhow::bail!(
            "coordinator builds without debug assertions require NW_PATH_HOPS >= 2; a single hop \
             is not trust-split"
        );
    }
    if !posture.has_verifier {
        anyhow::bail!(
            "coordinator builds without debug assertions require NW_TOKEN_PUBKEY; refusing to \
             start with redemption disabled"
        );
    }
    if !posture.has_grant_signer {
        anyhow::bail!(
            "coordinator builds without debug assertions require NW_GRANT_SIGNING_KEY_FILE; \
             refusing grantless paths"
        );
    }
    if !posture.has_grant_realm {
        anyhow::bail!(
            "coordinator builds without debug assertions require NW_GRANT_REALM; refusing \
             grants without a deployment boundary"
        );
    }
    if !posture.signer_from_file {
        anyhow::bail!(
            "coordinator builds without debug assertions require the Ed25519 seed through \
             NW_GRANT_SIGNING_KEY_FILE; an environment-held private key is development-only"
        );
    }
    if !posture.result_key_from_file {
        anyhow::bail!(
            "coordinator builds without debug assertions require an owner-only 32-byte NW_REDEMPTION_RESULT_KEY_FILE shared by all replicas"
        );
    }
    if !posture.registry_tls_pinned {
        anyhow::bail!(
            "coordinator builds without debug assertions require tls_spki_sha256 for every node in NW_NODE_REGISTRY"
        );
    }
    if !posture.registry_transparency_pinned {
        anyhow::bail!(
            "coordinator builds without debug assertions require transparency_log_key for every node in NW_NODE_REGISTRY"
        );
    }
    if !posture.registry_sev_tcb_pinned {
        anyhow::bail!(
            "coordinator builds without debug assertions require min_tcb_sevsnp for every SEV-SNP node in NW_NODE_REGISTRY"
        );
    }
    if !posture.registry_nested_ipv4_ready {
        anyhow::bail!(
            "coordinator builds without debug assertions require every NW_NODE_REGISTRY host to be a usable unicast IPv4 address on port 443; nested MASQUE grants bind and enforce exact path neighbors"
        );
    }
    Ok(())
}

fn load_grant_signer(release_build: bool) -> anyhow::Result<(Option<GrantSigningKey>, bool)> {
    for legacy in ["NW_GRANT_KEY_FILE", "NW_GRANT_KEY"] {
        if std::env::var_os(legacy).is_some() {
            anyhow::bail!(
                "{legacy} configures the retired fleet-wide NWG1 MAC key. Migrate to \
                 NW_GRANT_SIGNING_KEY_FILE on the Coordinator and public NW_GRANT_VERIFY_KEYS \
                 on nodes; legacy grants are not accepted"
            );
        }
    }

    let file = std::env::var("NW_GRANT_SIGNING_KEY_FILE").ok();
    let inline = std::env::var("NW_GRANT_SIGNING_KEY")
        .ok()
        .map(Zeroizing::new);
    if file.is_some() && inline.is_some() {
        anyhow::bail!(
            "set only NW_GRANT_SIGNING_KEY_FILE; NW_GRANT_SIGNING_KEY is a debug-only alternative"
        );
    }
    match (file, inline) {
        (Some(path), None) => Ok((
            Some(load_grant_signing_key_file(&path, release_build)?),
            true,
        )),
        (None, Some(raw)) => {
            if release_build {
                anyhow::bail!(
                    "NW_GRANT_SIGNING_KEY is forbidden without debug assertions; mount an \
                     owner-only NW_GRANT_SIGNING_KEY_FILE instead"
                );
            }
            let seed = decode_canonical_grant_seed(raw.as_bytes())?;
            Ok((Some(GrantSigningKey::from_seed(*seed)), false))
        }
        (None, None) => Ok((None, false)),
        (Some(_), Some(_)) => unreachable!("handled above"),
    }
}

fn load_redemption_result_key(
    release_build: bool,
) -> anyhow::Result<(Zeroizing<[u8; REDEMPTION_RESULT_KEY_BYTES]>, bool)> {
    match std::env::var("NW_REDEMPTION_RESULT_KEY_FILE") {
        Ok(path) => Ok((load_redemption_result_key_file(&path, release_build)?, true)),
        Err(std::env::VarError::NotPresent) if release_build => anyhow::bail!(
            "coordinator builds without debug assertions require NW_REDEMPTION_RESULT_KEY_FILE; replayable bearer grants must never be persisted in clear"
        ),
        Err(std::env::VarError::NotPresent) => {
            let mut key = Zeroizing::new([0u8; REDEMPTION_RESULT_KEY_BYTES]);
            getrandom::getrandom(key.as_mut())
                .map_err(|_| anyhow::anyhow!("redemption-result key entropy unavailable"))?;
            tracing::warn!(
                "NW_REDEMPTION_RESULT_KEY_FILE unset: using an ephemeral development key; durable result ciphertext becomes fail-closed spent state after restart"
            );
            Ok((key, false))
        }
        Err(error) => anyhow::bail!("NW_REDEMPTION_RESULT_KEY_FILE: {error}"),
    }
}

pub(crate) fn load_redemption_result_key_file(
    path: &str,
    enforce_private_permissions: bool,
) -> anyhow::Result<Zeroizing<[u8; REDEMPTION_RESULT_KEY_BYTES]>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("open NW_REDEMPTION_RESULT_KEY_FILE {path}: {error}"))?;
    let metadata = file.metadata().map_err(|error| {
        anyhow::anyhow!("stat opened NW_REDEMPTION_RESULT_KEY_FILE {path}: {error}")
    })?;
    if !metadata.is_file() {
        anyhow::bail!("NW_REDEMPTION_RESULT_KEY_FILE {path} is not a regular file");
    }
    if metadata.len() != REDEMPTION_RESULT_KEY_BYTES as u64 {
        anyhow::bail!(
            "NW_REDEMPTION_RESULT_KEY_FILE {path} must contain exactly {REDEMPTION_RESULT_KEY_BYTES} raw bytes"
        );
    }
    #[cfg(unix)]
    if enforce_private_permissions {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "NW_REDEMPTION_RESULT_KEY_FILE {path} must not be accessible by group/other (mode {:04o}; require 0600 or stricter)",
                mode & 0o7777
            );
        }
    }
    #[cfg(not(unix))]
    let _ = enforce_private_permissions;
    let mut key = Zeroizing::new([0u8; REDEMPTION_RESULT_KEY_BYTES]);
    file.read_exact(key.as_mut())
        .map_err(|error| anyhow::anyhow!("read NW_REDEMPTION_RESULT_KEY_FILE {path}: {error}"))?;
    let mut extra = [0u8; 1];
    if file
        .read(&mut extra)
        .map_err(|error| anyhow::anyhow!("read NW_REDEMPTION_RESULT_KEY_FILE {path}: {error}"))?
        != 0
    {
        anyhow::bail!(
            "NW_REDEMPTION_RESULT_KEY_FILE {path} must contain exactly {REDEMPTION_RESULT_KEY_BYTES} raw bytes"
        );
    }
    Ok(key)
}

/// Load one exact Ed25519 seed from a file. Shared with the operator-facing public-key derivation
/// command so provisioning and service startup apply the same parsing and permission rules.
pub(crate) fn load_grant_signing_key_file(
    path: &str,
    enforce_private_permissions: bool,
) -> anyhow::Result<GrantSigningKey> {
    let mut file = open_grant_signing_key_file(path, enforce_private_permissions)?;
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_GRANT_SEED_FILE_BYTES + 1));
    (&mut file)
        .take((MAX_GRANT_SEED_FILE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|e| anyhow::anyhow!("read grant signing key file {path}: {e}"))?;
    if raw.len() > MAX_GRANT_SEED_FILE_BYTES {
        anyhow::bail!(
            "NW_GRANT_SIGNING_KEY_FILE {path} exceeds the {MAX_GRANT_SEED_FILE_BYTES}-byte limit"
        );
    }
    let seed = decode_canonical_grant_seed(&raw)?;
    Ok(GrantSigningKey::from_seed(*seed))
}

fn open_grant_signing_key_file(
    path: &str,
    enforce_private_permissions: bool,
) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| anyhow::anyhow!("open NW_GRANT_SIGNING_KEY_FILE {path}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| anyhow::anyhow!("stat opened NW_GRANT_SIGNING_KEY_FILE {path}: {e}"))?;
    if !meta.is_file() {
        anyhow::bail!("NW_GRANT_SIGNING_KEY_FILE {path} is not a regular file");
    }
    if meta.len() > MAX_GRANT_SEED_FILE_BYTES as u64 {
        anyhow::bail!(
            "NW_GRANT_SIGNING_KEY_FILE {path} exceeds the {MAX_GRANT_SEED_FILE_BYTES}-byte limit"
        );
    }
    #[cfg(unix)]
    if enforce_private_permissions {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "NW_GRANT_SIGNING_KEY_FILE {path} must not be accessible by group/other \
                 (mode {:04o}; require 0600 or stricter)",
                mode & 0o7777
            );
        }
    }
    #[cfg(not(unix))]
    let _ = enforce_private_permissions;
    Ok(file)
}

fn decode_canonical_grant_seed(raw: &[u8]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let hex = match raw {
        bytes if bytes.len() == GRANT_SEED_HEX_LEN => bytes,
        bytes
            if bytes.len() == MAX_GRANT_SEED_FILE_BYTES
                && bytes.last() == Some(&b'\n') =>
        {
            &bytes[..GRANT_SEED_HEX_LEN]
        }
        _ => anyhow::bail!(
            "grant signing key must be exactly 64 lowercase hex characters with at most one trailing newline"
        ),
    };
    if !hex
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        anyhow::bail!("grant signing key must use canonical lowercase hexadecimal");
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated lowercase hexadecimal"),
    };
    let mut seed = Zeroizing::new([0u8; 32]);
    for (output, pair) in seed.iter_mut().zip(hex.chunks_exact(2)) {
        *output = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(seed)
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

#[cfg(test)]
mod tests {
    use super::{
        load_grant_signing_key_file, load_redemption_result_key_file,
        validate_registry_feasibility, validate_release_posture, ReleasePosture,
    };
    use crate::pathsel::{NodeRegistry, Role};

    #[test]
    fn release_posture_requires_multi_hop_verification_and_grants() {
        let valid = ReleasePosture {
            path_hops: 3,
            has_verifier: true,
            has_grant_signer: true,
            has_grant_realm: true,
            signer_from_file: true,
            result_key_from_file: true,
            registry_tls_pinned: true,
            registry_transparency_pinned: true,
            registry_sev_tcb_pinned: true,
            registry_nested_ipv4_ready: true,
            release_build: true,
        };
        assert!(validate_release_posture(valid).is_ok());
        for invalid in [
            ReleasePosture {
                path_hops: 1,
                ..valid
            },
            ReleasePosture {
                has_verifier: false,
                ..valid
            },
            ReleasePosture {
                has_grant_signer: false,
                ..valid
            },
            ReleasePosture {
                has_grant_realm: false,
                ..valid
            },
            ReleasePosture {
                signer_from_file: false,
                ..valid
            },
            ReleasePosture {
                result_key_from_file: false,
                ..valid
            },
            ReleasePosture {
                registry_tls_pinned: false,
                ..valid
            },
            ReleasePosture {
                registry_transparency_pinned: false,
                ..valid
            },
            ReleasePosture {
                registry_sev_tcb_pinned: false,
                ..valid
            },
            ReleasePosture {
                registry_nested_ipv4_ready: false,
                ..valid
            },
        ] {
            assert!(validate_release_posture(invalid).is_err());
        }
    }

    #[test]
    fn debug_posture_keeps_single_hop_integration_configuration() {
        assert!(validate_release_posture(ReleasePosture {
            path_hops: 1,
            has_verifier: false,
            has_grant_signer: false,
            has_grant_realm: false,
            signer_from_file: false,
            result_key_from_file: false,
            registry_tls_pinned: false,
            registry_transparency_pinned: false,
            registry_sev_tcb_pinned: false,
            registry_nested_ipv4_ready: false,
            release_build: false,
        })
        .is_ok());
    }

    #[test]
    fn every_profile_refuses_an_impossible_registry_topology_at_startup() {
        let mut registry = NodeRegistry::dev_default();
        assert!(validate_registry_feasibility(&registry, 3).is_ok());
        for node in &mut registry.nodes {
            node.role = Role::Exit;
        }
        let error = validate_registry_feasibility(&registry, 3).unwrap_err();
        assert!(error.to_string().contains("cannot form a 3-hop"));
    }

    #[test]
    fn release_nested_topology_requires_exact_ipv4_port_443_endpoints() {
        let mut registry = NodeRegistry::dev_default();
        assert!(registry.all_nodes_have_nested_ipv4_endpoints());

        registry.nodes[0].host = "entry.example".into();
        assert!(!registry.all_nodes_have_nested_ipv4_endpoints());
        registry.nodes[0].host = "2001:db8::1".into();
        assert!(!registry.all_nodes_have_nested_ipv4_endpoints());
        registry.nodes[0].host = "192.0.2.1".into();
        registry.nodes[0].port = 8443;
        assert!(!registry.all_nodes_have_nested_ipv4_endpoints());

        registry.nodes[0].port = 443;
        for unusable in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
            registry.nodes[0].host = unusable.into();
            assert!(
                !registry.all_nodes_have_nested_ipv4_endpoints(),
                "release topology must reject unusable neighbor {unusable}"
            );
        }
        registry.nodes[0].host = "10.0.0.10".into();
        assert!(registry.all_nodes_have_nested_ipv4_endpoints());
    }

    #[test]
    fn release_registry_requires_transparency_keys_and_sev_tcb_floors() {
        let mut registry = NodeRegistry::dev_default();
        assert!(!registry.all_nodes_have_transparency_key());
        assert!(!registry.all_sev_nodes_have_min_tcb());

        for node in &mut registry.nodes {
            node.transparency_log_key = Some("11".repeat(32));
            node.min_tcb_sevsnp = Some(nil_proto::path::SevSnpTcbFloor {
                fmc: None,
                bootloader: 1,
                tee: 0,
                snp: 1,
                microcode: 1,
            });
        }
        assert!(registry.all_nodes_have_transparency_key());
        assert!(registry.all_sev_nodes_have_min_tcb());

        registry.nodes[0].transparency_log_key = None;
        assert!(!registry.all_nodes_have_transparency_key());
        registry.nodes[0].transparency_log_key = Some("11".repeat(32));
        registry.nodes[0].min_tcb_sevsnp = None;
        assert!(!registry.all_sev_nodes_have_min_tcb());
    }

    #[cfg(unix)]
    #[test]
    fn grant_signing_key_file_is_bounded_canonical_owner_only_and_not_a_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::atomic::{AtomicU64, Ordering};

        static N: AtomicU64 = AtomicU64::new(0);
        let suffix = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nil-coordinator-grant-seed-{}-{suffix}",
            std::process::id()
        ));
        let link = path.with_extension("link");
        std::fs::write(&path, format!("{}\n", "11".repeat(32))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let signer = load_grant_signing_key_file(path.to_str().unwrap(), true).unwrap();
        assert_ne!(signer.public_key_bytes(), [0u8; 32]);

        std::fs::write(&path, "11".repeat(32)).unwrap();
        assert!(load_grant_signing_key_file(path.to_str().unwrap(), true).is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_grant_signing_key_file(path.to_str().unwrap(), true).is_err());
        assert!(load_grant_signing_key_file(path.to_str().unwrap(), false).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        symlink(&path, &link).unwrap();
        assert!(load_grant_signing_key_file(link.to_str().unwrap(), true).is_err());

        for malformed in [
            "11".repeat(31),
            "AA".repeat(32),
            format!(" {}", "11".repeat(32)),
            format!("{}\r\n", "11".repeat(32)),
            format!("{}\n\n", "11".repeat(32)),
            "11".repeat(33),
        ] {
            std::fs::write(&path, malformed).unwrap();
            assert!(load_grant_signing_key_file(path.to_str().unwrap(), true).is_err());
        }

        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn redemption_result_key_file_is_exact_raw_owner_only_and_not_a_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::sync::atomic::{AtomicU64, Ordering};

        static N: AtomicU64 = AtomicU64::new(0);
        let suffix = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nil-coordinator-result-key-{}-{suffix}",
            std::process::id()
        ));
        let link = path.with_extension("link");
        std::fs::write(&path, [0x7a; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            *load_redemption_result_key_file(path.to_str().unwrap(), true).unwrap(),
            [0x7a; 32]
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_redemption_result_key_file(path.to_str().unwrap(), true).is_err());
        assert!(load_redemption_result_key_file(path.to_str().unwrap(), false).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        symlink(&path, &link).unwrap();
        assert!(load_redemption_result_key_file(link.to_str().unwrap(), true).is_err());
        for malformed in [vec![0x7a; 31], vec![0x7a; 33]] {
            std::fs::write(&path, malformed).unwrap();
            assert!(load_redemption_result_key_file(path.to_str().unwrap(), true).is_err());
        }
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(path);
    }
}
