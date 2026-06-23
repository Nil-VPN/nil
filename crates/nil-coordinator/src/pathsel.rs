//! Trust-split path selection (architecture spec §6): choose entry/middle/exit hops run by
//! *legally independent operators in distinct jurisdictions*, so no single party — and no
//! single legal regime — sits on more than one hop. Entry sees the client IP but not the
//! destination; exit sees the destination but not the client IP; the middle sees neither.

use nil_proto::path::{Hop, Tee};
use serde::Deserialize;

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
}

impl RegistryNode {
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

/// The set of nodes the Coordinator can route through.
#[derive(Debug, Clone, Default)]
pub struct NodeRegistry {
    pub nodes: Vec<RegistryNode>,
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
                tracing::warn!(
                    "NW_NODE_REGISTRY unset — using the built-in DEV registry (one shared \
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
            })
            .collect();
        Ok(Self { nodes })
    }

    /// A small built-in dev registry: three operators in three jurisdictions, enough for a
    /// trust-split 3-hop path. A real deployment loads this from the node registry.
    pub fn dev_default() -> Self {
        let m = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let mk = |host: &str, op: &str, jur: &str| RegistryNode {
            host: host.into(),
            port: 443,
            tee: Tee::SevSnp,
            measurement: m.into(),
            operator: op.into(),
            jurisdiction: jur.into(),
            wg_pub: None,
        };
        Self {
            nodes: vec![
                mk("entry.us.example", "op-anvil", "US"),
                mk("middle.de.example", "op-borealis", "DE"),
                mk("exit.ch.example", "op-cirrus", "CH"),
                mk("alt.se.example", "op-dune", "SE"),
            ],
        }
    }

    /// Select an ordered `hops`-long path whose operators are ALL distinct AND whose
    /// jurisdictions are ALL distinct. Greedy over registry order (deterministic; a production
    /// selector would randomize across eligible sets for load-balancing). Returns `None` if no
    /// such diverse path exists.
    pub fn select_path(&self, hops: usize) -> Option<Vec<Hop>> {
        let mut chosen: Vec<&RegistryNode> = Vec::new();
        for node in &self.nodes {
            if chosen.len() == hops {
                break;
            }
            let operator_clash = chosen.iter().any(|c| c.operator == node.operator);
            let jurisdiction_clash = chosen.iter().any(|c| c.jurisdiction == node.jurisdiction);
            if !operator_clash && !jurisdiction_clash {
                chosen.push(node);
            }
        }
        if chosen.len() < hops {
            return None;
        }
        Some(chosen.iter().map(|n| n.to_hop()).collect())
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
                },
                RegistryNode {
                    host: "b".into(),
                    port: 443,
                    tee: Tee::SevSnp,
                    measurement: "bb".into(),
                    operator: "op-x".into(),
                    jurisdiction: "DE".into(),
                    wg_pub: None,
                },
            ],
        };
        assert!(
            reg.select_path(2).is_none(),
            "same-operator hops must be refused"
        );
        assert!(reg.select_path(1).is_some(), "a single hop is always fine");
    }
}
