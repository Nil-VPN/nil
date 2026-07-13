//! Trust-split path selection (architecture spec §6): choose entry/middle/exit hops run by
//! *legally independent operators in distinct jurisdictions*, so no single party — and no
//! single legal regime — sits on more than one hop. Entry sees the client IP but not the
//! destination; exit sees the destination but not the client IP; the middle sees neither.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use nil_core::{TdxMeasurement, TdxPolicy};
use nil_proto::path::{Hop, TdxPolicy as WireTdxPolicy, Tee};
use serde::Deserialize;

/// The position a node occupies in a path. A node's *egress capability* is physical and fixed by how
/// its operator configured it (see `nil-node`'s `exit.rs`): an `Exit` node opens egress to the whole
/// internet; an `Entry`/`Middle` node only ever forwards QUIC to the *next NIL node* (UDP/443) and
/// DROPs everything else (the open-relay guard). So a path's LAST hop — the one that decapsulates the
/// user's real IP packets and must route them to an arbitrary destination — can only be served by an
/// `Exit`-capable node. Selection therefore matches each position to a role-compatible node; getting
/// this wrong silently black-holes the data plane (a non-egress node at the exit DROPs the traffic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Entry,
    Middle,
    Exit,
}

impl Role {
    fn parse(s: &str) -> Option<Role> {
        match s {
            "entry" => Some(Role::Entry),
            "middle" => Some(Role::Middle),
            "exit" => Some(Role::Exit),
            _ => None,
        }
    }

    /// The role required at position `i` of a `hops`-long path: first is the entry, last is the exit
    /// (the only egress hop), the rest are middles. A 1-hop path is a lone exit (it must egress).
    fn for_position(i: usize, hops: usize) -> Role {
        if i + 1 == hops {
            Role::Exit
        } else if i == 0 {
            Role::Entry
        } else {
            Role::Middle
        }
    }
}

/// On-disk node registry entry (`NW_NODE_REGISTRY` JSON).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFileNode {
    id: String,
    host: String,
    port: u16,
    tee: String,
    measurement: String,
    /// SHA-256 of the node's stable TLS SubjectPublicKeyInfo (lowercase hex). Structurally optional
    /// for debug registries; release startup requires every node to carry it.
    #[serde(default)]
    tls_spki_sha256: Option<String>,
    operator: String,
    jurisdiction: String,
    #[serde(default)]
    wg_pub: Option<String>,
    /// The node's configured position capability (`"entry"`/`"middle"`/`"exit"`), matching its
    /// `NW_NODE_ROLE`. This is mandatory: silently treating an absent or misspelled role as
    /// universal can place a non-egress node at the exit and black-hole the data plane.
    role: String,
    /// Optional per-node pinned minimum SEV-SNP TCB floor, published to the client and enforced
    /// offline by its attestation gate. Absent ⇒ no floor.
    #[serde(default)]
    min_tcb_sevsnp: Option<nil_proto::path::SevSnpTcbFloor>,
    /// Exact Intel TDX workload policy. Required for TDX nodes and forbidden for SEV-SNP nodes.
    /// Every value is canonical lowercase hex and is converted to fixed-size core types before
    /// this registry is admitted.
    #[serde(default)]
    tdx_policy: Option<WireTdxPolicy>,
    /// Optional per-node pinned transparency-log Ed25519 pubkey (lowercase hex). Absent ⇒ the
    /// measurement pin alone gates the hop.
    #[serde(default)]
    transparency_log_key: Option<String>,
}

/// A node known to the Coordinator, with the diversity attributes path selection enforces.
#[derive(Debug, Clone)]
pub struct RegistryNode {
    /// Stable node identity used as the audience of a node grant. It is never sent to the client
    /// as a separate protocol field; the Coordinator carries it alongside the selected hop until
    /// it has signed the hop's authorization claim.
    pub id: String,
    pub host: String,
    pub port: u16,
    pub tee: Tee,
    pub measurement: String,
    pub tls_spki_sha256: Option<String>,
    /// Legal operator (independent entity). Two hops must never share one.
    pub operator: String,
    /// Jurisdiction (country / legal regime). Two hops must never share one.
    pub jurisdiction: String,
    pub wg_pub: Option<String>,
    /// Position capability (see [`Role`]). Registry files must declare it explicitly.
    pub role: Role,
    /// Pinned minimum SEV-SNP TCB floor published to the client for this node. `None` = no floor.
    pub min_tcb_sevsnp: Option<nil_proto::path::SevSnpTcbFloor>,
    /// Exact Intel TDX workload identity. Required for TDX registry nodes and absent for SEV-SNP.
    pub tdx_policy: Option<TdxPolicy>,
    /// Pinned transparency-log Ed25519 pubkey (lowercase hex). `None` = measurement pin alone.
    pub transparency_log_key: Option<String>,
}

impl RegistryNode {
    /// Whether this node may serve at a path position requiring `pos`.
    fn fills(&self, pos: Role) -> bool {
        self.role == pos
    }

    fn to_hop(&self) -> Hop {
        Hop {
            host: self.host.clone(),
            port: self.port,
            tee: self.tee,
            measurement: self.measurement.clone(),
            tls_spki_sha256: self.tls_spki_sha256.clone(),
            wg_pub: self.wg_pub.clone(),
            grant: None,
            grant_nonce: None,
            min_tcb_sevsnp: self.min_tcb_sevsnp,
            tdx_policy: self.tdx_policy.as_ref().map(tdx_policy_to_wire),
            transparency_log_key: self.transparency_log_key.clone(),
        }
    }
}

/// Coordinator-internal path-selection result. [`Hop`] remains the public wire DTO, while the
/// stable node audience and intended path role stay attached long enough for the API layer to sign
/// an audience-bound grant. The API then discards this metadata before serializing the response.
#[derive(Debug, Clone)]
pub(crate) struct SelectedHop {
    pub(crate) hop: Hop,
    pub(crate) node_id: String,
    pub(crate) intended_role: Role,
}

fn validate_registry_node(dto: RegistryFileNode) -> anyhow::Result<RegistryNode> {
    // Grant audiences cap stable identifiers at 64 bytes. Enforce that at startup so a registry
    // entry cannot consume a token and only then fail during grant minting.
    nil_core::grant::validate_identifier(&dto.id).map_err(|e| anyhow::anyhow!("id: {e}"))?;
    validate_slug("operator", &dto.operator, 128)?;
    validate_jurisdiction(&dto.jurisdiction)?;
    validate_host(&dto.host)?;
    if dto.port == 0 {
        anyhow::bail!("port must be nonzero");
    }

    let tee = match dto.tee.as_str() {
        "sev-snp" => Tee::SevSnp,
        "tdx" => Tee::Tdx,
        other => anyhow::bail!("tee must be exactly \"sev-snp\" or \"tdx\", got {other:?}"),
    };
    let role = Role::parse(&dto.role).ok_or_else(|| {
        anyhow::anyhow!(
            "role must be exactly \"entry\", \"middle\", or \"exit\", got {:?}",
            dto.role
        )
    })?;
    validate_lower_hex("measurement", &dto.measurement, 48)?;
    if let Some(digest) = dto.tls_spki_sha256.as_deref() {
        validate_lower_hex("tls_spki_sha256", digest, 32)?;
    }
    if let Some(key) = dto.wg_pub.as_deref() {
        validate_lower_hex("wg_pub", key, 32)?;
    }
    if let Some(key) = dto.transparency_log_key.as_deref() {
        validate_lower_hex("transparency_log_key", key, 32)?;
    }
    if tee == Tee::Tdx && dto.min_tcb_sevsnp.is_some() {
        anyhow::bail!("min_tcb_sevsnp is invalid for a tdx node");
    }
    let tdx_policy = match (tee, dto.tdx_policy) {
        (Tee::Tdx, Some(policy)) => Some(validate_tdx_policy(policy)?),
        (Tee::Tdx, None) => anyhow::bail!("tdx_policy is required for a tdx node"),
        (Tee::SevSnp, Some(_)) => anyhow::bail!("tdx_policy is invalid for a sev-snp node"),
        (Tee::SevSnp, None) => None,
    };

    Ok(RegistryNode {
        id: dto.id,
        host: dto.host,
        port: dto.port,
        tee,
        measurement: dto.measurement,
        tls_spki_sha256: dto.tls_spki_sha256,
        operator: dto.operator,
        jurisdiction: dto.jurisdiction,
        wg_pub: dto.wg_pub,
        role,
        min_tcb_sevsnp: dto.min_tcb_sevsnp,
        tdx_policy,
        transparency_log_key: dto.transparency_log_key,
    })
}

fn decode_fixed_hex<const N: usize>(field: &str, value: &str) -> anyhow::Result<[u8; N]> {
    validate_lower_hex(field, value, N)?;
    nil_core::grant::from_hex(value)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("{field} is not valid canonical hex"))
}

fn validate_tdx_policy(dto: WireTdxPolicy) -> anyhow::Result<TdxPolicy> {
    let td_attributes = decode_fixed_hex::<8>("tdx_policy.td_attributes", &dto.td_attributes)?;
    if td_attributes[0] & 0x01 != 0 {
        anyhow::bail!("tdx_policy.td_attributes must not enable TDX debug mode");
    }
    let rt_mr0 = decode_fixed_hex::<48>("tdx_policy.rt_mr0", &dto.rt_mr0)?;
    let rt_mr1 = decode_fixed_hex::<48>("tdx_policy.rt_mr1", &dto.rt_mr1)?;
    let rt_mr2 = decode_fixed_hex::<48>("tdx_policy.rt_mr2", &dto.rt_mr2)?;
    let rt_mr3 = decode_fixed_hex::<48>("tdx_policy.rt_mr3", &dto.rt_mr3)?;
    for (name, value) in [
        ("rt_mr0", &rt_mr0),
        ("rt_mr1", &rt_mr1),
        ("rt_mr2", &rt_mr2),
        ("rt_mr3", &rt_mr3),
    ] {
        if value.iter().all(|byte| *byte == 0) {
            anyhow::bail!(
                "tdx_policy.{name} must be nonzero so the production workload identity cannot be omitted"
            );
        }
    }

    Ok(TdxPolicy {
        td_attributes,
        xfam: decode_fixed_hex("tdx_policy.xfam", &dto.xfam)?,
        mr_config_id: TdxMeasurement(decode_fixed_hex(
            "tdx_policy.mr_config_id",
            &dto.mr_config_id,
        )?),
        mr_owner: TdxMeasurement(decode_fixed_hex("tdx_policy.mr_owner", &dto.mr_owner)?),
        mr_owner_config: TdxMeasurement(decode_fixed_hex(
            "tdx_policy.mr_owner_config",
            &dto.mr_owner_config,
        )?),
        rt_mr0: TdxMeasurement(rt_mr0),
        rt_mr1: TdxMeasurement(rt_mr1),
        rt_mr2: TdxMeasurement(rt_mr2),
        rt_mr3: TdxMeasurement(rt_mr3),
        mr_service_td: dto
            .mr_service_td
            .as_deref()
            .map(|value| decode_fixed_hex("tdx_policy.mr_service_td", value).map(TdxMeasurement))
            .transpose()?,
    })
}

fn tdx_policy_to_wire(policy: &TdxPolicy) -> WireTdxPolicy {
    WireTdxPolicy {
        td_attributes: encode_lower_hex(&policy.td_attributes),
        xfam: encode_lower_hex(&policy.xfam),
        mr_config_id: encode_lower_hex(policy.mr_config_id.as_ref()),
        mr_owner: encode_lower_hex(policy.mr_owner.as_ref()),
        mr_owner_config: encode_lower_hex(policy.mr_owner_config.as_ref()),
        rt_mr0: encode_lower_hex(policy.rt_mr0.as_ref()),
        rt_mr1: encode_lower_hex(policy.rt_mr1.as_ref()),
        rt_mr2: encode_lower_hex(policy.rt_mr2.as_ref()),
        rt_mr3: encode_lower_hex(policy.rt_mr3.as_ref()),
        mr_service_td: policy
            .mr_service_td
            .as_ref()
            .map(|measurement| encode_lower_hex(measurement.as_ref())),
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Stable registry identities are deliberately boring ASCII slugs. Rejecting alternate case,
/// whitespace, and leading/trailing separators prevents two textual spellings from becoming two
/// grant audiences or two diversity principals.
fn validate_slug(field: &str, value: &str, max_len: usize) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > max_len {
        anyhow::bail!("{field} must be a nonempty canonical slug of at most {max_len} bytes");
    }
    let bytes = value.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_lowercase)
        && !bytes.first().is_some_and(u8::is_ascii_digit)
    {
        anyhow::bail!("{field} must start with a lowercase ASCII letter or digit");
    }
    if !bytes.last().is_some_and(u8::is_ascii_lowercase)
        && !bytes.last().is_some_and(u8::is_ascii_digit)
    {
        anyhow::bail!("{field} must end with a lowercase ASCII letter or digit");
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(*b, b'-' | b'_' | b'.'))
    {
        anyhow::bail!(
            "{field} must contain only lowercase ASCII letters, digits, '.', '_', or '-'"
        );
    }
    Ok(())
}

fn validate_jurisdiction(value: &str) -> anyhow::Result<()> {
    if value.len() != 2 || !value.bytes().all(|b| b.is_ascii_uppercase()) {
        anyhow::bail!("jurisdiction must be exactly two uppercase ASCII letters");
    }
    Ok(())
}

fn validate_host(value: &str) -> anyhow::Result<()> {
    if value.is_empty() || value.len() > 253 {
        anyhow::bail!("host must be nonempty and at most 253 bytes");
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        if value != ip.to_string() {
            anyhow::bail!("host IP address is not in canonical text form");
        }
        return Ok(());
    }
    // A malformed IP-shaped string must not fall through and be accepted as a DNS name.
    if value.bytes().all(|b| b.is_ascii_digit() || b == b'.') || value.contains(':') {
        anyhow::bail!("host is not a canonical IP address");
    }
    if value.starts_with('.') || value.ends_with('.') {
        anyhow::bail!("host DNS name must not start or end with '.'");
    }
    for label in value.split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("host DNS labels must contain 1..=63 bytes");
        }
        if label.starts_with('-') || label.ends_with('-') {
            anyhow::bail!("host DNS labels must not start or end with '-'");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            anyhow::bail!(
                "host must be a canonical lowercase ASCII DNS name or canonical IP address"
            );
        }
    }
    Ok(())
}

fn validate_lower_hex(field: &str, value: &str, bytes: usize) -> anyhow::Result<()> {
    if value.len() != bytes * 2 {
        anyhow::bail!(
            "{field} must be exactly {bytes} bytes ({}) lowercase hex characters",
            bytes * 2
        );
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        anyhow::bail!("{field} must contain lowercase hexadecimal characters only");
    }
    Ok(())
}

/// Hosts currently considered dead (health). Shared so a health checker can mark a node down
/// without rebuilding the registry; path selection skips these. Identity-free — just hostnames.
type DeadHosts = Arc<Mutex<HashSet<String>>>;

/// The set of nodes the Coordinator can route through.
#[derive(Debug, Clone, Default)]
pub struct NodeRegistry {
    pub nodes: Vec<RegistryNode>,
    /// Hosts a health check has marked down. Excluded from selection until marked back up.
    /// Empty by default (every node assumed live) so existing call sites are unaffected.
    dead: DeadHosts,
}

impl NodeRegistry {
    /// Whether every registry entry pins a stable TLS SPKI digest. Release Coordinator posture
    /// requires this before serving; debug registries may omit it for legacy local fixtures.
    pub(crate) fn all_nodes_have_tls_spki(&self) -> bool {
        self.nodes.iter().all(|node| node.tls_spki_sha256.is_some())
    }

    /// Whether every registry entry carries the public transparency-log key that release clients
    /// independently pin. Requiring it at release Coordinator startup prevents spending a token
    /// on a path that every packaged client must reject later.
    pub(crate) fn all_nodes_have_transparency_key(&self) -> bool {
        self.nodes
            .iter()
            .all(|node| node.transparency_log_key.is_some())
    }

    /// Whether each SEV-SNP node carries an explicit component-wise firmware floor. TDX nodes use
    /// their separate complete workload policy instead.
    pub(crate) fn all_sev_nodes_have_min_tcb(&self) -> bool {
        self.nodes
            .iter()
            .all(|node| node.tee != Tee::SevSnp || node.min_tcb_sevsnp.is_some())
    }

    /// Whether every endpoint can be embedded verbatim into an intermediate NWG2 relay policy.
    /// The current nested MASQUE data plane carries IPv4 UDP packets, so release Coordinators must
    /// not publish DNS/IPv6 endpoints that a node cannot compare exactly after decapsulation.
    pub(crate) fn all_nodes_have_nested_ipv4_endpoints(&self) -> bool {
        self.nodes.iter().all(|node| {
            node.port == 443
                && node.host.parse::<Ipv4Addr>().is_ok_and(|ip| {
                    !ip.is_unspecified()
                        && !ip.is_loopback()
                        && !ip.is_multicast()
                        && ip != Ipv4Addr::BROADCAST
                })
        })
    }

    /// Load the registry from `NW_NODE_REGISTRY` (a JSON file of nodes, each with its own
    /// operator/jurisdiction and independently reviewed measurement), or fall back to the
    /// built-in dev registry (one shared placeholder measurement) only when debug assertions and
    /// the explicit development fallback are both enabled. Pinning a distinct measurement per
    /// operator is what makes attestation meaningful — the dev default pins one constant for every
    /// node and must never reach production.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var("NW_NODE_REGISTRY") {
            Ok(path) => Self::from_file(&path),
            Err(_) => {
                // The dev registry pins ONE shared placeholder measurement for every node, which
                // makes attestation meaningless (any node passes any hop's pin). Refuse to fall
                // back to it unless an operator has explicitly opted into dev fallbacks.
                if !nil_core::net::dev_env_flag("NW_ALLOW_DEV_FALLBACKS") {
                    anyhow::bail!(
                        "NW_NODE_REGISTRY unset: the built-in DEV registry pins one shared \
                         placeholder measurement for every node, defeating attestation. Set \
                         NW_NODE_REGISTRY to a JSON registry that pins a per-operator measurement \
                         per node. The built-in registry is available only to debug-assertion \
                         integration builds."
                    );
                }
                tracing::warn!(
                    "NW_ALLOW_DEV_FALLBACKS=1: using the built-in DEV registry (one shared \
                     placeholder measurement); production must pin a per-operator measurement per node"
                );
                Ok(Self::dev_default())
            }
        }
    }

    /// Parse and fully validate a JSON node registry file. Registry fields are deliberately
    /// canonical and fail closed: every node has a stable unique `id`, an exact TEE and role, a
    /// lowercase 48-byte measurement, and a unique endpoint. Optional public keys are validated at
    /// startup rather than after a redeemed token has already been consumed.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let bytes =
            std::fs::read(path).map_err(|e| anyhow::anyhow!("read node registry {path}: {e}"))?;
        let dtos: Vec<RegistryFileNode> = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parse node registry {path}: {e}"))?;
        if dtos.is_empty() {
            anyhow::bail!("node registry {path} lists no nodes");
        }
        let mut ids = HashSet::with_capacity(dtos.len());
        let mut endpoints = HashSet::with_capacity(dtos.len());
        let mut nodes = Vec::with_capacity(dtos.len());
        for (index, dto) in dtos.into_iter().enumerate() {
            let node = validate_registry_node(dto)
                .map_err(|e| anyhow::anyhow!("node registry {path} entry {index}: {e}"))?;
            if !ids.insert(node.id.clone()) {
                anyhow::bail!(
                    "node registry {path} entry {index}: duplicate node id {:?}",
                    node.id
                );
            }
            if !endpoints.insert((node.host.clone(), node.port)) {
                anyhow::bail!(
                    "node registry {path} entry {index}: duplicate endpoint {}:{}",
                    node.host,
                    node.port
                );
            }
            nodes.push(node);
        }
        Ok(Self {
            nodes,
            dead: DeadHosts::default(),
        })
    }

    /// A small built-in dev registry: three operators in three jurisdictions, enough for a
    /// trust-split 3-hop path. A real deployment loads this from the node registry.
    pub fn dev_default() -> Self {
        let m = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let mk = |id: &str, host: &str, op: &str, jur: &str, role: Role| RegistryNode {
            id: id.into(),
            host: host.into(),
            port: 443,
            tee: Tee::SevSnp,
            measurement: m.into(),
            // Debug-only placeholder. Real registries pin the digest printed by
            // `nil-node tls-keygen`; this value does not correspond to the dev node cert.
            tls_spki_sha256: Some("00".repeat(32)),
            operator: op.into(),
            jurisdiction: jur.into(),
            wg_pub: None,
            role,
            min_tcb_sevsnp: None,
            tdx_policy: None,
            transparency_log_key: None,
        };
        Self {
            nodes: vec![
                mk("entry-us", "192.0.2.10", "op-anvil", "US", Role::Entry),
                mk(
                    "middle-de",
                    "198.51.100.20",
                    "op-borealis",
                    "DE",
                    Role::Middle,
                ),
                mk("exit-ch", "203.0.113.30", "op-cirrus", "CH", Role::Exit),
                mk("exit-se", "203.0.113.31", "op-dune", "SE", Role::Exit),
            ],
            dead: DeadHosts::default(),
        }
    }

    /// Mark `host` down (health). It is excluded from path selection until [`mark_up`] is called.
    /// Idempotent; identity-free (a hostname, not a user). The health seam a checker drives; the
    /// selector consumes it via [`live_nodes`]. Exercised by the unit tests.
    #[allow(dead_code)] // health-checker seam: wired by tests now, by a probe task in deployment.
    pub fn mark_down(&self, host: &str) {
        // Recover the set even from a poisoned lock (a panicked health checker doesn't corrupt the
        // HashSet) — otherwise a `mark_down` would be silently dropped after a poison, leaving a dead
        // node admitted to selection (fail-open).
        self.dead
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(host.to_string());
    }

    /// Mark `host` back up (health), re-admitting it to selection.
    #[allow(dead_code)] // health-checker seam (see `mark_down`).
    pub fn mark_up(&self, host: &str) {
        self.dead
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(host);
    }

    fn live_nodes(&self) -> Vec<&RegistryNode> {
        // FAIL-CLOSED: recover the dead-set even from a poisoned lock rather than treating every node
        // (including the dead ones) as live. A panic in a health-checker task while holding this lock
        // must NOT silently re-admit nodes the checker marked unreachable — that would break the
        // trust-split guarantee that verified-dead nodes are excluded from path selection.
        let dead = self.dead.lock().unwrap_or_else(|e| e.into_inner());
        self.nodes
            .iter()
            .filter(|n| !dead.contains(&n.host))
            .collect()
    }

    /// Select an ordered `hops`-long path whose operators are ALL distinct AND whose
    /// jurisdictions are ALL distinct, drawn only from currently-live nodes.
    ///
    /// Two correctness properties over the old greedy-by-registry-order selector:
    ///  - **Complete:** it backtracks, so it returns a diverse path whenever one exists. The greedy
    ///    version could commit to an early node that blocked diversity and then falsely `None` (503)
    ///    a request a valid diverse path could have served.
    ///  - **Randomized:** candidates are shuffled, so it does not return the identical entry/middle/
    ///    exit every time — load is spread and the path is not trivially predictable.
    ///
    /// Returns `None` only if no operator/jurisdiction-diverse `hops`-long path of live nodes
    /// exists. `hops == 0` yields an empty path.
    pub fn select_path(&self, hops: usize) -> Option<Vec<SelectedHop>> {
        let mut candidates = self.live_nodes();
        shuffle(&mut candidates);

        let mut chosen: Vec<&RegistryNode> = Vec::with_capacity(hops);
        if Self::extend_path(&candidates, hops, &mut chosen) {
            Some(
                chosen
                    .iter()
                    .enumerate()
                    .map(|(index, node)| SelectedHop {
                        hop: node.to_hop(),
                        node_id: node.id.clone(),
                        intended_role: Role::for_position(index, hops),
                    })
                    .collect(),
            )
        } else {
            None
        }
    }

    /// Depth-first search with backtracking: try each remaining candidate that (a) is role-compatible
    /// with the position being filled — crucially, the LAST hop (exit) only accepts an egress-capable
    /// node — and (b) keeps operators and jurisdictions all-distinct; recurse; undo on a dead end.
    /// Candidate order is already shuffled, so the first complete path found is a random valid one.
    fn extend_path<'a>(
        candidates: &[&'a RegistryNode],
        hops: usize,
        chosen: &mut Vec<&'a RegistryNode>,
    ) -> bool {
        if chosen.len() == hops {
            return true;
        }
        let pos = Role::for_position(chosen.len(), hops);
        for node in candidates {
            // The exit position needs open egress; entry/middle only relay QUIC. A node may only
            // fill only the position its registry role permits.
            if !node.fills(pos) {
                continue;
            }
            let clash = chosen
                .iter()
                .any(|c| c.operator == node.operator || c.jurisdiction == node.jurisdiction);
            if clash
                || chosen
                    .iter()
                    .any(|c| c.id == node.id || (c.host == node.host && c.port == node.port))
            {
                continue;
            }
            chosen.push(node);
            if Self::extend_path(candidates, hops, chosen) {
                return true;
            }
            chosen.pop();
        }
        false
    }
}

/// In-place Fisher–Yates shuffle seeded from the OS CSPRNG. Used to randomize path selection so the
/// Coordinator does not hand out the identical entry/middle/exit every redemption. Best-effort: if
/// the OS RNG is unavailable the slice is left in its (already arbitrary) order — selection
/// correctness does not depend on the shuffle.
fn shuffle<T>(items: &mut [T]) {
    if items.len() < 2 {
        return;
    }
    let mut buf = vec![0u8; items.len() * 8];
    if getrandom::getrandom(&mut buf).is_err() {
        return;
    }
    for i in (1..items.len()).rev() {
        let mut r = [0u8; 8];
        r.copy_from_slice(&buf[i * 8..i * 8 + 8]);
        let j = (u64::from_le_bytes(r) % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicU64, Ordering};

    static REGISTRY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn load_json(value: &Value) -> anyhow::Result<NodeRegistry> {
        let path = std::env::temp_dir().join(format!(
            "nil-coord-registry-validation-{}-{}.json",
            std::process::id(),
            REGISTRY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &path,
            serde_json::to_vec(value).expect("serialize registry fixture"),
        )
        .expect("write registry fixture");
        let result = NodeRegistry::from_file(path.to_str().expect("UTF-8 temp path"));
        let _ = std::fs::remove_file(path);
        result
    }

    fn valid_file_node() -> Value {
        json!({
            "id": "entry-us-1",
            "host": "entry.us.example",
            "port": 443,
            "tee": "sev-snp",
            "measurement": "ab".repeat(48),
            "operator": "operator-anvil",
            "jurisdiction": "US",
            "role": "entry"
        })
    }

    fn valid_tdx_policy() -> Value {
        json!({
            "td_attributes": "0000001000000000",
            "xfam": "02".repeat(8),
            "mr_config_id": "03".repeat(48),
            "mr_owner": "04".repeat(48),
            "mr_owner_config": "05".repeat(48),
            "rt_mr0": "06".repeat(48),
            "rt_mr1": "07".repeat(48),
            "rt_mr2": "08".repeat(48),
            "rt_mr3": "09".repeat(48),
            "mr_service_td": "0a".repeat(48)
        })
    }

    fn valid_tdx_node() -> Value {
        let node = with_field(valid_file_node(), "tee", json!("tdx"));
        with_field(node, "tdx_policy", valid_tdx_policy())
    }

    fn with_field(mut node: Value, field: &str, value: Value) -> Value {
        node.as_object_mut()
            .expect("node fixture is an object")
            .insert(field.to_string(), value);
        node
    }

    fn without_field(mut node: Value, field: &str) -> Value {
        node.as_object_mut()
            .expect("node fixture is an object")
            .remove(field);
        node
    }

    fn assert_invalid_node(node: Value, expected: &str) {
        let err = load_json(&json!([node])).expect_err("invalid registry must fail closed");
        let message = err.to_string();
        assert!(
            message.contains(expected),
            "expected error containing {expected:?}, got {message:?}"
        );
    }

    #[test]
    fn selects_an_operator_and_jurisdiction_diverse_path() {
        let reg = NodeRegistry::dev_default();
        let path = reg.select_path(3).expect("a 3-hop diverse path exists");
        assert_eq!(path.len(), 3);

        // Re-derive operators/jurisdictions by matching hosts back to the registry.
        let ops: Vec<&str> = path
            .iter()
            .map(|h| {
                reg.nodes
                    .iter()
                    .find(|n| n.host == h.hop.host)
                    .unwrap()
                    .operator
                    .as_str()
            })
            .collect();
        let jurs: Vec<&str> = path
            .iter()
            .map(|h| {
                reg.nodes
                    .iter()
                    .find(|n| n.host == h.hop.host)
                    .unwrap()
                    .jurisdiction
                    .as_str()
            })
            .collect();
        assert_eq!(
            ops.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "distinct operators"
        );
        assert_eq!(
            jurs.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "distinct jurisdictions"
        );
    }

    #[test]
    fn registry_file_requires_all_identity_and_routing_fields() {
        for (field, expected) in [
            ("id", "missing field `id`"),
            ("host", "missing field `host`"),
            ("port", "missing field `port`"),
            ("tee", "missing field `tee`"),
            ("measurement", "missing field `measurement`"),
            ("operator", "missing field `operator`"),
            ("jurisdiction", "missing field `jurisdiction`"),
            ("role", "missing field `role`"),
        ] {
            assert_invalid_node(without_field(valid_file_node(), field), expected);
        }
    }

    #[test]
    fn registry_id_uses_the_exact_nwg2_identifier_grammar() {
        let node = with_field(valid_file_node(), "id", json!("entry:us-1"));
        let registry = load_json(&json!([node])).expect("':' is valid in an NWG2 identifier");
        assert_eq!(registry.nodes[0].id, "entry:us-1");
    }

    #[test]
    fn registry_file_rejects_noncanonical_identity_endpoint_and_enum_values() {
        let cases = [
            (
                with_field(valid_file_node(), "id", json!("")),
                "id: grant identifier must be",
            ),
            (
                with_field(valid_file_node(), "id", json!("Node-A")),
                "id: grant identifier must be",
            ),
            (
                with_field(valid_file_node(), "id", json!("-node-a")),
                "id: grant identifier must be",
            ),
            (
                with_field(valid_file_node(), "id", json!("a".repeat(65))),
                "id: grant identifier must be",
            ),
            (
                with_field(valid_file_node(), "operator", json!("Operator Anvil")),
                "operator must start",
            ),
            (
                with_field(valid_file_node(), "jurisdiction", json!("us")),
                "jurisdiction must be exactly two uppercase",
            ),
            (
                with_field(valid_file_node(), "jurisdiction", json!("USA")),
                "jurisdiction must be exactly two uppercase",
            ),
            (
                with_field(valid_file_node(), "host", json!("")),
                "host must be nonempty",
            ),
            (
                with_field(valid_file_node(), "host", json!("Entry.US.example")),
                "host must be a canonical lowercase",
            ),
            (
                with_field(valid_file_node(), "host", json!("entry.us.example.")),
                "must not start or end",
            ),
            (
                with_field(valid_file_node(), "host", json!("https://entry.example")),
                "host is not a canonical IP address",
            ),
            (
                with_field(valid_file_node(), "host", json!("127.000.0.1")),
                "host is not a canonical IP address",
            ),
            (
                with_field(valid_file_node(), "port", json!(0)),
                "port must be nonzero",
            ),
            (
                with_field(valid_file_node(), "tee", json!("SEV-SNP")),
                "tee must be exactly",
            ),
            (
                with_field(valid_file_node(), "tee", json!("sev")),
                "tee must be exactly",
            ),
            (
                with_field(valid_file_node(), "role", json!("egress")),
                "role must be exactly",
            ),
            (
                with_field(valid_file_node(), "role", json!(" Exit")),
                "role must be exactly",
            ),
        ];
        for (node, expected) in cases {
            assert_invalid_node(node, expected);
        }

        assert_invalid_node(
            with_field(valid_file_node(), "unexpected", json!(true)),
            "unknown field `unexpected`",
        );
    }

    #[test]
    fn registry_file_rejects_malformed_or_noncanonical_cryptographic_material() {
        let cases = [
            (
                with_field(valid_file_node(), "measurement", json!("ab".repeat(47))),
                "measurement must be exactly 48 bytes",
            ),
            (
                with_field(valid_file_node(), "measurement", json!("AB".repeat(48))),
                "measurement must contain lowercase hexadecimal",
            ),
            (
                with_field(valid_file_node(), "wg_pub", json!("cd".repeat(31))),
                "wg_pub must be exactly 32 bytes",
            ),
            (
                with_field(valid_file_node(), "wg_pub", json!("CD".repeat(32))),
                "wg_pub must contain lowercase hexadecimal",
            ),
            (
                with_field(valid_file_node(), "tls_spki_sha256", json!("ab".repeat(31))),
                "tls_spki_sha256 must be exactly 32 bytes",
            ),
            (
                with_field(valid_file_node(), "tls_spki_sha256", json!("AB".repeat(32))),
                "tls_spki_sha256 must contain lowercase hexadecimal",
            ),
            (
                with_field(
                    valid_file_node(),
                    "transparency_log_key",
                    json!("ef".repeat(31)),
                ),
                "transparency_log_key must be exactly 32 bytes",
            ),
            (
                with_field(
                    valid_file_node(),
                    "transparency_log_key",
                    json!("EF".repeat(32)),
                ),
                "transparency_log_key must contain lowercase hexadecimal",
            ),
        ];
        for (node, expected) in cases {
            assert_invalid_node(node, expected);
        }

        let tdx = with_field(valid_file_node(), "tee", json!("tdx"));
        let tdx_with_sev_floor = with_field(
            tdx,
            "min_tcb_sevsnp",
            json!({"bootloader": 1, "tee": 2, "snp": 3, "microcode": 4}),
        );
        assert_invalid_node(tdx_with_sev_floor, "invalid for a tdx node");
    }

    #[test]
    fn registry_requires_complete_canonical_tdx_policy() {
        let missing = with_field(valid_file_node(), "tee", json!("tdx"));
        assert_invalid_node(missing, "tdx_policy is required for a tdx node");

        let mut incomplete_policy = valid_tdx_policy();
        incomplete_policy
            .as_object_mut()
            .expect("TDX policy object")
            .remove("rt_mr3");
        let incomplete = with_field(
            with_field(valid_file_node(), "tee", json!("tdx")),
            "tdx_policy",
            incomplete_policy,
        );
        assert_invalid_node(incomplete, "missing field `rt_mr3`");

        for (field, value, expected) in [
            (
                "td_attributes",
                json!("01".repeat(7)),
                "tdx_policy.td_attributes must be exactly 8 bytes",
            ),
            (
                "xfam",
                json!("AA".repeat(8)),
                "tdx_policy.xfam must contain lowercase hexadecimal",
            ),
            (
                "mr_owner",
                json!("04".repeat(47)),
                "tdx_policy.mr_owner must be exactly 48 bytes",
            ),
            (
                "mr_service_td",
                json!("0A".repeat(48)),
                "tdx_policy.mr_service_td must contain lowercase hexadecimal",
            ),
        ] {
            let mut policy = valid_tdx_policy();
            policy
                .as_object_mut()
                .expect("TDX policy object")
                .insert(field.into(), value);
            assert_invalid_node(with_field(valid_tdx_node(), "tdx_policy", policy), expected);
        }

        let mut debug_policy = valid_tdx_policy();
        debug_policy
            .as_object_mut()
            .expect("TDX policy object")
            .insert("td_attributes".into(), json!("0100001000000000"));
        assert_invalid_node(
            with_field(valid_tdx_node(), "tdx_policy", debug_policy),
            "must not enable TDX debug mode",
        );
    }

    #[test]
    fn registry_rejects_zero_tdx_runtime_measurements() {
        for field in ["rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3"] {
            let mut policy = valid_tdx_policy();
            policy
                .as_object_mut()
                .expect("TDX policy object")
                .insert(field.into(), json!("00".repeat(48)));
            assert_invalid_node(
                with_field(valid_tdx_node(), "tdx_policy", policy),
                &format!("tdx_policy.{field} must be nonzero"),
            );
        }
    }

    #[test]
    fn registry_rejects_cross_tee_policy_fields() {
        assert_invalid_node(
            with_field(valid_file_node(), "tdx_policy", valid_tdx_policy()),
            "tdx_policy is invalid for a sev-snp node",
        );
        assert_invalid_node(
            with_field(
                valid_tdx_node(),
                "min_tcb_sevsnp",
                json!({"bootloader": 1, "tee": 2, "snp": 3, "microcode": 4}),
            ),
            "min_tcb_sevsnp is invalid for a tdx node",
        );
    }

    #[test]
    fn registry_tdx_policy_round_trips_through_core_and_wire_types() {
        let registry = load_json(&json!([valid_tdx_node()])).expect("valid TDX registry");
        let core = registry.nodes[0]
            .tdx_policy
            .as_ref()
            .expect("validated core policy");
        assert_eq!(core.td_attributes, [0, 0, 0, 0x10, 0, 0, 0, 0]);
        assert_eq!(core.rt_mr3, TdxMeasurement([0x09; 48]));
        assert_eq!(core.mr_service_td, Some(TdxMeasurement([0x0a; 48])));

        let wire = registry.nodes[0]
            .to_hop()
            .tdx_policy
            .expect("published wire policy");
        assert_eq!(wire, serde_json::from_value(valid_tdx_policy()).unwrap());
    }

    #[test]
    fn registry_file_rejects_duplicate_ids_and_endpoints() {
        let first = valid_file_node();
        let same_id = with_field(
            with_field(first.clone(), "host", json!("other.example")),
            "role",
            json!("exit"),
        );
        let err = load_json(&json!([first.clone(), same_id])).expect_err("duplicate id");
        assert!(err.to_string().contains("duplicate node id \"entry-us-1\""));

        let same_endpoint = with_field(
            with_field(first.clone(), "id", json!("exit-us-2")),
            "role",
            json!("exit"),
        );
        let err = load_json(&json!([first, same_endpoint])).expect_err("duplicate endpoint");
        assert!(err
            .to_string()
            .contains("duplicate endpoint entry.us.example:443"));
    }

    #[test]
    fn registry_file_rejects_an_empty_node_set() {
        let err = load_json(&json!([])).expect_err("empty registry");
        assert!(err.to_string().contains("lists no nodes"));
    }

    #[test]
    fn loads_per_operator_measurements_from_a_registry_file() {
        let entry = with_field(
            with_field(valid_file_node(), "id", json!("entry-a")),
            "measurement",
            json!("aa".repeat(48)),
        );
        let middle = with_field(
            with_field(
                with_field(
                    with_field(
                        with_field(
                            with_field(valid_tdx_node(), "id", json!("middle-b")),
                            "host",
                            json!("middle.de.example"),
                        ),
                        "operator",
                        json!("op-b"),
                    ),
                    "jurisdiction",
                    json!("DE"),
                ),
                "role",
                json!("middle"),
            ),
            "measurement",
            json!("bb".repeat(48)),
        );
        let exit = with_field(
            with_field(
                with_field(
                    with_field(
                        with_field(
                            with_field(valid_file_node(), "id", json!("exit-c")),
                            "host",
                            json!("exit.ch.example"),
                        ),
                        "operator",
                        json!("op-c"),
                    ),
                    "jurisdiction",
                    json!("CH"),
                ),
                "role",
                json!("exit"),
            ),
            "measurement",
            json!("cc".repeat(48)),
        );
        let reg = load_json(&json!([entry, middle, exit])).expect("parse registry");
        assert_eq!(reg.nodes.len(), 3);
        // Distinct, per-operator measurements survived the load (the production property).
        let measurements: std::collections::HashSet<&str> =
            reg.nodes.iter().map(|n| n.measurement.as_str()).collect();
        assert_eq!(measurements.len(), 3, "each node keeps its own measurement");
        assert_eq!(reg.nodes[1].tee, Tee::Tdx, "tee parsed");
        assert_eq!(reg.nodes[2].tee, Tee::SevSnp, "tee parsed exactly");
        let path3 = reg.select_path(3).expect("a 3-hop diverse path exists");
        assert_eq!(path3.len(), 3);
    }

    #[test]
    fn registry_publishes_per_node_min_tcb_floor_and_transparency_key_into_the_hop() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nil-coord-registry-tcb-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &path,
            r#"[
              {"id":"exit-c","host":"x.example","port":443,"tee":"sev-snp","measurement":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","operator":"op-c","jurisdiction":"CH","role":"exit",
               "tls_spki_sha256":"edededededededededededededededededededededededededededededededed",
               "wg_pub":"abababababababababababababababababababababababababababababababab",
               "min_tcb_sevsnp":{"bootloader":3,"tee":0,"snp":8,"microcode":115},
               "transparency_log_key":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}
            ]"#,
        )
        .unwrap();
        let reg = NodeRegistry::from_file(path.to_str().unwrap()).expect("parse registry");
        // The published floor + key must survive load AND reach the emitted Hop (what the client reads).
        let hop = reg.nodes[0].to_hop();
        assert_eq!(
            hop.min_tcb_sevsnp,
            Some(nil_proto::path::SevSnpTcbFloor {
                fmc: None,
                bootloader: 3,
                tee: 0,
                snp: 8,
                microcode: 115
            })
        );
        assert_eq!(
            hop.transparency_log_key.as_deref(),
            Some("cd".repeat(32).as_str())
        );
        assert_eq!(hop.wg_pub.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(
            hop.tls_spki_sha256.as_deref(),
            Some("ed".repeat(32).as_str())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuses_a_path_when_diversity_cannot_be_met() {
        // Two nodes, same operator → cannot build even a 2-hop diverse path.
        let reg = NodeRegistry {
            nodes: vec![
                RegistryNode {
                    id: "entry-a".into(),
                    host: "a".into(),
                    port: 443,
                    tee: Tee::SevSnp,
                    measurement: "aa".into(),
                    tls_spki_sha256: None,
                    operator: "op-x".into(),
                    jurisdiction: "US".into(),
                    wg_pub: None,
                    role: Role::Entry,
                    min_tcb_sevsnp: None,
                    tdx_policy: None,
                    transparency_log_key: None,
                },
                RegistryNode {
                    id: "exit-b".into(),
                    host: "b".into(),
                    port: 443,
                    tee: Tee::SevSnp,
                    measurement: "bb".into(),
                    tls_spki_sha256: None,
                    operator: "op-x".into(),
                    jurisdiction: "DE".into(),
                    wg_pub: None,
                    role: Role::Exit,
                    min_tcb_sevsnp: None,
                    tdx_policy: None,
                    transparency_log_key: None,
                },
            ],
            dead: Default::default(),
        };
        assert!(
            reg.select_path(2).is_none(),
            "same-operator hops must be refused"
        );
        assert!(reg.select_path(1).is_some(), "a single hop is always fine");
    }

    /// Build a node with a distinct operator/jurisdiction and explicit role (test helper).
    fn node(host: &str, op: &str, jur: &str, role: Role) -> RegistryNode {
        RegistryNode {
            id: format!("node-{host}"),
            host: host.into(),
            port: 443,
            tee: Tee::SevSnp,
            measurement: "aa".into(),
            tls_spki_sha256: None,
            operator: op.into(),
            jurisdiction: jur.into(),
            wg_pub: None,
            role,
            min_tcb_sevsnp: None,
            tdx_policy: None,
            transparency_log_key: None,
        }
    }

    #[test]
    fn backtracks_instead_of_falsely_refusing_a_valid_diverse_path() {
        // Registry order is a trap for a greedy selector: a 2-hop path needs distinct operators AND
        // jurisdictions. Greedy picks node[0] (op-a/US) then node[1] (op-a/DE) → operator clash →
        // dead end → false 503. node[2] (op-b/CH) completes a valid path with node[0]. Backtracking
        // must find it.
        let reg = NodeRegistry {
            nodes: vec![
                node("a", "op-a", "US", Role::Entry),
                node("b", "op-a", "DE", Role::Exit),
                node("c", "op-b", "CH", Role::Exit),
            ],
            dead: Default::default(),
        };
        let path = reg
            .select_path(2)
            .expect("a valid diverse 2-hop path exists and must be found");
        assert_eq!(path.len(), 2);
        let ops: HashSet<&str> = path
            .iter()
            .map(|h| {
                reg.nodes
                    .iter()
                    .find(|n| n.host == h.hop.host)
                    .unwrap()
                    .operator
                    .as_str()
            })
            .collect();
        assert_eq!(ops.len(), 2, "operators stay distinct");
    }

    #[test]
    fn skips_nodes_marked_down_by_health() {
        // Three operators/jurisdictions → a 3-hop path exists. Mark one host down: now only two
        // live nodes remain, so a 3-hop diverse path is impossible and selection must refuse.
        let reg = NodeRegistry {
            nodes: vec![
                node("a", "op-a", "US", Role::Entry),
                node("b", "op-b", "DE", Role::Exit),
                node("c", "op-c", "CH", Role::Middle),
            ],
            dead: Default::default(),
        };
        assert!(reg.select_path(3).is_some(), "all live → 3-hop path exists");
        reg.mark_down("c");
        assert!(
            reg.select_path(3).is_none(),
            "a down node must be excluded, leaving too few for a 3-hop diverse path"
        );
        // A 2-hop path still works from the two remaining live nodes, and never includes the dead one.
        let path = reg.select_path(2).expect("2-hop path from live nodes");
        assert!(
            path.iter().all(|h| h.hop.host != "c"),
            "the down node must never appear in a path"
        );
        // Recovery: marking it back up restores the 3-hop path.
        reg.mark_up("c");
        assert!(
            reg.select_path(3).is_some(),
            "marked back up → path returns"
        );
    }

    #[test]
    fn poisoned_dead_lock_still_excludes_dead_nodes() {
        // A health-checker task that panics while holding the dead-set lock poisons it. The selector
        // must STILL exclude the dead node (fail-closed) — not re-admit every node because the lock
        // is poisoned (the bug: `.lock().ok()...unwrap_or(true)`).
        let reg = NodeRegistry {
            nodes: vec![
                node("a", "op-a", "US", Role::Entry),
                node("b", "op-b", "DE", Role::Exit),
                node("c", "op-c", "CH", Role::Middle),
            ],
            dead: Default::default(),
        };
        reg.mark_down("c");
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = reg.dead.lock().expect("lock");
            panic!("simulate a health-checker panic while holding the dead-set lock");
        }));
        assert!(poisoned.is_err(), "the dead-set lock is now poisoned");
        // The dead node must NOT reappear in a path despite the poison.
        let path = reg
            .select_path(2)
            .expect("2-hop path from the two live nodes");
        assert!(
            path.iter().all(|h| h.hop.host != "c"),
            "fail-closed: a poisoned lock must not re-admit the dead node"
        );
        // And health updates still apply after poison (into_inner recovery, not a silent no-op).
        reg.mark_up("c");
        assert!(
            reg.select_path(3).is_some(),
            "mark_up applies even after poison"
        );
    }

    #[test]
    fn randomizes_across_valid_diverse_paths() {
        // Many distinct operators/jurisdictions and a short path → many valid orderings. Over many
        // draws we should observe more than one distinct first hop (the old greedy selector always
        // returned the identical path).
        let reg = NodeRegistry {
            nodes: (0..9)
                .map(|i| {
                    let h = format!("h{i}");
                    let role = match i % 3 {
                        0 => Role::Entry,
                        1 => Role::Middle,
                        _ => Role::Exit,
                    };
                    node_owned(h, format!("op-{i}"), format!("jur-{i}"), role)
                })
                .collect(),
            dead: Default::default(),
        };
        let mut first_hops = HashSet::new();
        for _ in 0..50 {
            let path = reg.select_path(3).expect("a diverse path exists");
            assert_eq!(path.len(), 3);
            // Diversity invariant holds on every draw.
            let ops: HashSet<&str> = path
                .iter()
                .map(|h| {
                    reg.nodes
                        .iter()
                        .find(|n| n.host == h.hop.host)
                        .unwrap()
                        .operator
                        .as_str()
                })
                .collect();
            assert_eq!(ops.len(), 3, "operators distinct on every draw");
            first_hops.insert(path[0].hop.host.clone());
        }
        assert!(
            first_hops.len() > 1,
            "selection should not be deterministic across draws (saw only {first_hops:?})"
        );
    }

    fn node_owned(host: String, op: String, jur: String, role: Role) -> RegistryNode {
        RegistryNode {
            id: format!("node-{host}"),
            host,
            port: 443,
            tee: Tee::SevSnp,
            measurement: "aa".into(),
            tls_spki_sha256: None,
            operator: op,
            jurisdiction: jur,
            wg_pub: None,
            role,
            min_tcb_sevsnp: None,
            tdx_policy: None,
            transparency_log_key: None,
        }
    }

    /// Build a node with an explicit position role (test helper).
    fn role_node(host: &str, op: &str, jur: &str, role: Role) -> RegistryNode {
        node(host, op, jur, role)
    }

    /// The regression guard for the trust-split data-plane bug: when nodes declare roles, the EXIT
    /// position must always land on an egress-capable (`exit`-role) node — never an entry/middle node
    /// (whose open-relay guard would silently DROP the user's real egress traffic, HTTP 000). Run many
    /// times because selection is randomized; every valid path must still end at the exit node.
    #[test]
    fn exit_position_always_gets_an_egress_capable_node() {
        let reg = NodeRegistry {
            nodes: vec![
                role_node("entry", "op-a", "US", Role::Entry),
                role_node("middle", "op-b", "DE", Role::Middle),
                role_node("exit", "op-c", "CH", Role::Exit),
            ],
            dead: Default::default(),
        };
        for _ in 0..200 {
            let path = reg
                .select_path(3)
                .expect("a 3-hop role-correct diverse path exists");
            assert_eq!(path.len(), 3);
            assert_eq!(
                path[0].hop.host, "entry",
                "entry position → entry-role node"
            );
            assert_eq!(
                path[1].hop.host, "middle",
                "middle position → middle-role node"
            );
            assert_eq!(
                path[2].hop.host, "exit",
                "exit position → the only egress-capable node"
            );
        }
    }

    /// If no egress-capable node exists, selection must REFUSE (None) rather than hand back a path
    /// that ends at a non-exit node — fail-closed beats a silently-black-holed data plane.
    #[test]
    fn refuses_when_no_exit_capable_node_exists() {
        let reg = NodeRegistry {
            nodes: vec![
                role_node("entry", "op-a", "US", Role::Entry),
                role_node("middle", "op-b", "DE", Role::Middle),
            ],
            dead: Default::default(),
        };
        assert!(
            reg.select_path(2).is_none(),
            "no exit-capable node → no path"
        );
    }

    /// Selection retains stable grant audiences and the exact intended position without adding
    /// either field to the public `nil-proto::path::Hop` DTO.
    #[test]
    fn selected_hops_retain_node_id_and_intended_role() {
        let reg = NodeRegistry {
            nodes: vec![
                node("a", "op-a", "US", Role::Entry),
                node("b", "op-b", "DE", Role::Middle),
                node("c", "op-c", "CH", Role::Exit),
            ],
            dead: Default::default(),
        };
        let path = reg.select_path(3).expect("role-complete path");
        assert_eq!(path[0].node_id, "node-a");
        assert_eq!(path[0].intended_role, Role::Entry);
        assert_eq!(path[1].node_id, "node-b");
        assert_eq!(path[1].intended_role, Role::Middle);
        assert_eq!(path[2].node_id, "node-c");
        assert_eq!(path[2].intended_role, Role::Exit);
    }
}
