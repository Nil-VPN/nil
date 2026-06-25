//! Trust-split path selection (architecture spec §6): choose entry/middle/exit hops run by
//! *legally independent operators in distinct jurisdictions*, so no single party — and no
//! single legal regime — sits on more than one hop. Entry sees the client IP but not the
//! destination; exit sees the destination but not the client IP; the middle sees neither.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use nil_proto::path::{Hop, Tee};
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
        match s.trim().to_ascii_lowercase().as_str() {
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

/// On-disk node registry entry (`NW_NODE_REGISTRY` JSON). `tee` defaults to `sev-snp`.
#[derive(Debug, Deserialize)]
struct RegistryFileNode {
    host: String,
    port: u16,
    #[serde(default = "default_tee")]
    tee: String,
    measurement: String,
    operator: String,
    jurisdiction: String,
    #[serde(default)]
    wg_pub: Option<String>,
    /// The node's configured position capability (`"entry"`/`"middle"`/`"exit"`), matching its
    /// `NW_NODE_ROLE`. Optional for back-compat: a node with no `role` is treated as universal (it
    /// may fill any position). A registry that declares roles MUST give them honestly — only an
    /// `exit`-role node has the open egress an exit position needs; placing a non-exit node there
    /// black-holes the data plane.
    #[serde(default)]
    role: Option<String>,
}

fn default_tee() -> String {
    "sev-snp".to_string()
}

/// A node known to the Coordinator, with the diversity attributes path selection enforces.
#[derive(Debug, Clone)]
pub struct RegistryNode {
    pub host: String,
    pub port: u16,
    pub tee: Tee,
    pub measurement: String,
    /// Legal operator (independent entity). Two hops must never share one.
    pub operator: String,
    /// Jurisdiction (country / legal regime). Two hops must never share one.
    pub jurisdiction: String,
    pub wg_pub: Option<String>,
    /// Position capability (see [`Role`]). `None` = universal (may fill any position) — the
    /// back-compat default for registries that don't declare roles.
    pub role: Option<Role>,
}

impl RegistryNode {
    /// Whether this node may serve at a path position requiring `pos`. A node with no declared role
    /// is universal (back-compat); a declared role must equal the position's required role.
    fn fills(&self, pos: Role) -> bool {
        self.role.map_or(true, |r| r == pos)
    }

    fn to_hop(&self) -> Hop {
        Hop {
            host: self.host.clone(),
            port: self.port,
            tee: self.tee,
            measurement: self.measurement.clone(),
            wg_pub: self.wg_pub.clone(),
            grant: None,
            grant_nonce: None,
        }
    }
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
    /// Load the registry from `NW_NODE_REGISTRY` (a JSON file of nodes, each with its own
    /// operator/jurisdiction and its **own** Rekor-published measurement), or fall back to the
    /// built-in dev registry (one shared placeholder measurement) with a loud warning. Pinning a
    /// distinct measurement per operator is what makes attestation meaningful — the dev default
    /// pins one constant for every node and must never reach production.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var("NW_NODE_REGISTRY") {
            Ok(path) => Self::from_file(&path),
            Err(_) => {
                // The dev registry pins ONE shared placeholder measurement for every node, which
                // makes attestation meaningless (any node passes any hop's pin). Refuse to fall
                // back to it unless an operator has explicitly opted into dev fallbacks.
                if !nil_core::net::env_flag("NW_ALLOW_DEV_FALLBACKS") {
                    anyhow::bail!(
                        "NW_NODE_REGISTRY unset: the built-in DEV registry pins one shared \
                         placeholder measurement for every node, defeating attestation. Set \
                         NW_NODE_REGISTRY to a JSON registry that pins a per-operator measurement \
                         per node, or set NW_ALLOW_DEV_FALLBACKS=1 to explicitly accept the DEV \
                         registry."
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

    /// Parse a JSON node registry file: an array of `{host, port, tee, measurement, operator,
    /// jurisdiction, wg_pub?}`. `tee` is `"sev-snp"` (default) or `"tdx"`.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let bytes =
            std::fs::read(path).map_err(|e| anyhow::anyhow!("read node registry {path}: {e}"))?;
        let dtos: Vec<RegistryFileNode> = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parse node registry {path}: {e}"))?;
        if dtos.is_empty() {
            anyhow::bail!("node registry {path} lists no nodes");
        }
        let nodes = dtos
            .into_iter()
            .map(|d| RegistryNode {
                host: d.host,
                port: d.port,
                tee: match d.tee.as_str() {
                    "tdx" => Tee::Tdx,
                    _ => Tee::SevSnp,
                },
                measurement: d.measurement,
                operator: d.operator,
                jurisdiction: d.jurisdiction,
                wg_pub: d.wg_pub,
                role: {
                    let parsed = d.role.as_deref().and_then(Role::parse);
                    // A PRESENT-but-unrecognized role (a typo like "exi"/"egress") would otherwise
                    // degrade silently to universal (None) — which lets a non-egress node land at the
                    // exit position and black-hole the data plane. Warn loudly so the misconfig is
                    // visible. (Logs only the role string — a config value, no user-linkable data.)
                    if parsed.is_none() {
                        if let Some(r) = &d.role {
                            tracing::warn!(
                                "node registry: unrecognized role {r:?}; treating this node as \
                                 universal (placeable at ANY position, including exit) — fix the role \
                                 to entry/middle/exit"
                            );
                        }
                    }
                    parsed
                },
            })
            .collect();
        Ok(Self {
            nodes,
            dead: DeadHosts::default(),
        })
    }

    /// A small built-in dev registry: three operators in three jurisdictions, enough for a
    /// trust-split 3-hop path. A real deployment loads this from the node registry.
    pub fn dev_default() -> Self {
        let m = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let mk = |host: &str, op: &str, jur: &str, role: Role| RegistryNode {
            host: host.into(),
            port: 443,
            tee: Tee::SevSnp,
            measurement: m.into(),
            operator: op.into(),
            jurisdiction: jur.into(),
            wg_pub: None,
            role: Some(role),
        };
        Self {
            nodes: vec![
                mk("entry.us.example", "op-anvil", "US", Role::Entry),
                mk("middle.de.example", "op-borealis", "DE", Role::Middle),
                mk("exit.ch.example", "op-cirrus", "CH", Role::Exit),
                mk("alt.se.example", "op-dune", "SE", Role::Exit),
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
        self.dead.lock().unwrap_or_else(|e| e.into_inner()).insert(host.to_string());
    }

    /// Mark `host` back up (health), re-admitting it to selection.
    #[allow(dead_code)] // health-checker seam (see `mark_down`).
    pub fn mark_up(&self, host: &str) {
        self.dead.lock().unwrap_or_else(|e| e.into_inner()).remove(host);
    }

    fn live_nodes(&self) -> Vec<&RegistryNode> {
        // FAIL-CLOSED: recover the dead-set even from a poisoned lock rather than treating every node
        // (including the dead ones) as live. A panic in a health-checker task while holding this lock
        // must NOT silently re-admit nodes the checker marked unreachable — that would break the
        // trust-split guarantee that verified-dead nodes are excluded from path selection.
        let dead = self.dead.lock().unwrap_or_else(|e| e.into_inner());
        self.nodes.iter().filter(|n| !dead.contains(&n.host)).collect()
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
    pub fn select_path(&self, hops: usize) -> Option<Vec<Hop>> {
        let mut candidates = self.live_nodes();
        shuffle(&mut candidates);

        let mut chosen: Vec<&RegistryNode> = Vec::with_capacity(hops);
        if Self::extend_path(&candidates, hops, &mut chosen) {
            Some(chosen.iter().map(|n| n.to_hop()).collect())
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
            // fill a position its configured role permits (an undeclared role is universal).
            if !node.fills(pos) {
                continue;
            }
            let clash = chosen
                .iter()
                .any(|c| c.operator == node.operator || c.jurisdiction == node.jurisdiction);
            if clash || chosen.iter().any(|c| c.host == node.host) {
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
                    .find(|n| n.host == h.host)
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
                    .find(|n| n.host == h.host)
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
    fn loads_per_operator_measurements_from_a_registry_file() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nil-coord-registry-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        // Three operators/jurisdictions, each with its OWN measurement (not one shared constant).
        std::fs::write(
            &path,
            r#"[
              {"host":"e.example","port":443,"tee":"sev-snp","measurement":"aa","operator":"op-a","jurisdiction":"US"},
              {"host":"m.example","port":443,"tee":"tdx","measurement":"bb","operator":"op-b","jurisdiction":"DE"},
              {"host":"x.example","port":443,"measurement":"cc","operator":"op-c","jurisdiction":"CH"}
            ]"#,
        )
        .unwrap();

        let reg = NodeRegistry::from_file(path.to_str().unwrap()).expect("parse registry");
        assert_eq!(reg.nodes.len(), 3);
        // Distinct, per-operator measurements survived the load (the production property).
        let measurements: std::collections::HashSet<&str> =
            reg.nodes.iter().map(|n| n.measurement.as_str()).collect();
        assert_eq!(measurements.len(), 3, "each node keeps its own measurement");
        assert_eq!(reg.nodes[1].tee, Tee::Tdx, "tee parsed");
        assert_eq!(reg.nodes[2].tee, Tee::SevSnp, "tee defaults to sev-snp");
        let path3 = reg.select_path(3).expect("a 3-hop diverse path exists");
        assert_eq!(path3.len(), 3);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuses_a_path_when_diversity_cannot_be_met() {
        // Two nodes, same operator → cannot build even a 2-hop diverse path.
        let reg = NodeRegistry {
            nodes: vec![
                RegistryNode {
                    host: "a".into(),
                    port: 443,
                    tee: Tee::SevSnp,
                    measurement: "aa".into(),
                    operator: "op-x".into(),
                    jurisdiction: "US".into(),
                    wg_pub: None,
                    role: None,
                },
                RegistryNode {
                    host: "b".into(),
                    port: 443,
                    tee: Tee::SevSnp,
                    measurement: "bb".into(),
                    operator: "op-x".into(),
                    jurisdiction: "DE".into(),
                    wg_pub: None,
                    role: None,
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

    /// Build a node with a distinct operator/jurisdiction (test helper). Role-less = universal, so
    /// these exercise the pure operator/jurisdiction diversity logic independent of position roles.
    fn node(host: &str, op: &str, jur: &str) -> RegistryNode {
        RegistryNode {
            host: host.into(),
            port: 443,
            tee: Tee::SevSnp,
            measurement: "aa".into(),
            operator: op.into(),
            jurisdiction: jur.into(),
            wg_pub: None,
            role: None,
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
                node("a", "op-a", "US"),
                node("b", "op-a", "DE"),
                node("c", "op-b", "CH"),
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
                    .find(|n| n.host == h.host)
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
                node("a", "op-a", "US"),
                node("b", "op-b", "DE"),
                node("c", "op-c", "CH"),
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
            path.iter().all(|h| h.host != "c"),
            "the down node must never appear in a path"
        );
        // Recovery: marking it back up restores the 3-hop path.
        reg.mark_up("c");
        assert!(reg.select_path(3).is_some(), "marked back up → path returns");
    }

    #[test]
    fn poisoned_dead_lock_still_excludes_dead_nodes() {
        // A health-checker task that panics while holding the dead-set lock poisons it. The selector
        // must STILL exclude the dead node (fail-closed) — not re-admit every node because the lock
        // is poisoned (the bug: `.lock().ok()...unwrap_or(true)`).
        let reg = NodeRegistry {
            nodes: vec![
                node("a", "op-a", "US"),
                node("b", "op-b", "DE"),
                node("c", "op-c", "CH"),
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
        let path = reg.select_path(2).expect("2-hop path from the two live nodes");
        assert!(
            path.iter().all(|h| h.host != "c"),
            "fail-closed: a poisoned lock must not re-admit the dead node"
        );
        // And health updates still apply after poison (into_inner recovery, not a silent no-op).
        reg.mark_up("c");
        assert!(reg.select_path(3).is_some(), "mark_up applies even after poison");
    }

    #[test]
    fn randomizes_across_valid_diverse_paths() {
        // Many distinct operators/jurisdictions and a short path → many valid orderings. Over many
        // draws we should observe more than one distinct first hop (the old greedy selector always
        // returned the identical path).
        let reg = NodeRegistry {
            nodes: (0..8)
                .map(|i| {
                    let h = format!("h{i}");
                    node_owned(h, format!("op-{i}"), format!("jur-{i}"))
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
                        .find(|n| n.host == h.host)
                        .unwrap()
                        .operator
                        .as_str()
                })
                .collect();
            assert_eq!(ops.len(), 3, "operators distinct on every draw");
            first_hops.insert(path[0].host.clone());
        }
        assert!(
            first_hops.len() > 1,
            "selection should not be deterministic across draws (saw only {first_hops:?})"
        );
    }

    fn node_owned(host: String, op: String, jur: String) -> RegistryNode {
        RegistryNode {
            host,
            port: 443,
            tee: Tee::SevSnp,
            measurement: "aa".into(),
            operator: op,
            jurisdiction: jur,
            wg_pub: None,
            role: None,
        }
    }

    /// Build a node with an explicit position role (test helper).
    fn role_node(host: &str, op: &str, jur: &str, role: Role) -> RegistryNode {
        RegistryNode { role: Some(role), ..node(host, op, jur) }
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
            let path = reg.select_path(3).expect("a 3-hop role-correct diverse path exists");
            assert_eq!(path.len(), 3);
            assert_eq!(path[0].host, "entry", "entry position → entry-role node");
            assert_eq!(path[1].host, "middle", "middle position → middle-role node");
            assert_eq!(path[2].host, "exit", "exit position → the only egress-capable node");
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
        assert!(reg.select_path(2).is_none(), "no exit-capable node → no path");
    }

    /// Back-compat: a registry with NO declared roles still selects (every node is universal), so
    /// existing role-less deployments are unaffected by the position constraint.
    #[test]
    fn role_less_registry_is_universal() {
        let reg = NodeRegistry {
            nodes: vec![
                node("a", "op-a", "US"),
                node("b", "op-b", "DE"),
                node("c", "op-c", "CH"),
            ],
            dead: Default::default(),
        };
        assert_eq!(reg.select_path(3).map(|p| p.len()), Some(3));
    }
}
