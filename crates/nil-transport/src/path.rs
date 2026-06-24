//! Trust-split multi-hop orchestration (architecture spec §6): a [`PathTransport`] that chains
//! an ordered list of MASQUE hops `[entry, …, exit]` into a nested CONNECT-IP onion.
//!
//! The outermost hop (`entry`) is a real QUIC/UDP connection. Each subsequent hop is connected
//! *through* the previous one via [`MasqueTransport::connect_nested`]: the inner QUIC rides the
//! outer tunnel as IPv4/UDP packets, which the outer node NATs onward. So **entry** sees the
//! client's IP and the middle's address but never the destination; **exit** sees the middle's
//! address and the destination but never the client's IP; **middle** sees neither endpoint.
//! No single node — and no single operator/jurisdiction, when the Coordinator selects diverse
//! hops — can link client to destination.
//!
//! Trust is per-hop and independent: each hop gets a **fresh attestation nonce** and is
//! appraised against its own pinned measurement at its own ready gate before the next hop is
//! dialed. A failure anywhere aborts the whole path (no partial tunnel, kill-switch holds).
//!
//! [`PathTransport`] implements [`Transport`], exposing the *innermost* (exit) session — so the
//! datapath and cascade drive a 3-hop onion exactly like a single tunnel. The seam holds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use nil_core::{
    Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind,
};

use crate::{MasqueTransport, Transport};

/// A multi-hop MASQUE path: entry → … → exit, nested as a CONNECT-IP onion.
pub struct PathTransport {
    inner: Arc<MasqueTransport>,
    /// Ordered hops, outermost (entry) first, innermost (exit) last. Non-empty.
    hops: Vec<NodeEndpoint>,
    /// Map an active exit session id → the intermediate sessions (entry…second-to-last) kept
    /// alive behind it, so `close` can tear the whole onion down.
    intermediates: Mutex<HashMap<SessionId, Vec<Session>>>,
    /// Guards the connect→register critical section so concurrent `connect`s don't interleave
    /// hops on the shared inner transport in a way that confuses teardown bookkeeping.
    connect_lock: tokio::sync::Mutex<()>,
}

impl PathTransport {
    /// Build a path over `hops` (outermost first). The caller routes the host's own QUIC to the
    /// **entry** hop (see [`PathTransport::entry`]); everything past entry is reached *through*
    /// the tunnel and needs no host-route exception.
    pub fn new(inner: Arc<MasqueTransport>, hops: Vec<NodeEndpoint>) -> Self {
        Self {
            inner,
            hops,
            intermediates: Mutex::new(HashMap::new()),
            connect_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The entry hop — the only node directly reachable from the host (its IP is the kill-switch
    /// host-route exception so the tunnel's own QUIC doesn't loop). `None` if the path is empty.
    pub fn entry(&self) -> Option<&NodeEndpoint> {
        self.hops.first()
    }

    /// Number of hops in the path.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// A fresh dev/direct-node [`Grant`] when a hop did not come from a Coordinator response.
    /// Coordinator-redeemed paths carry per-hop grants on the endpoint itself.
    fn fresh_grant(base: &Grant) -> Result<Grant> {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| Error::Transport(format!("path nonce entropy: {e}")))?;
        Ok(Grant {
            token: base.token.clone(),
            nonce,
        })
    }

    fn grant_for(hop: &NodeEndpoint, fallback: &Grant) -> Result<Grant> {
        match hop.grant.clone() {
            Some(grant) => Ok(grant),
            None => Self::fresh_grant(fallback),
        }
    }
}

#[async_trait]
impl Transport for PathTransport {
    /// Connect the whole onion and return the innermost (exit) session. `target` is ignored —
    /// the hops are fixed at construction (the datapath passes the entry endpoint as `target`
    /// for routing symmetry).
    async fn connect(&self, _target: NodeEndpoint, creds: Grant) -> Result<Session> {
        if self.hops.is_empty() {
            return Err(Error::Transport("path has no hops".into()));
        }
        let _guard = self.connect_lock.lock().await;

        // Outermost hop: a real QUIC/UDP connection (attestation appraised inside).
        let entry = self.hops[0].clone();
        let entry_grant = Self::grant_for(&entry, &creds)?;
        let mut prev = self
            .inner
            .connect(entry, entry_grant)
            .await
            .map_err(|e| Error::Transport(format!("path hop 0 (entry): {e}")))?;

        // Each subsequent hop rides the previous tunnel.
        let mut intermediates: Vec<Session> = Vec::new();
        for (i, hop) in self.hops.iter().enumerate().skip(1) {
            let nested = self
                .inner
                .connect_nested(
                    hop.clone(),
                    Self::grant_for(hop, &creds)?,
                    self.inner.clone(),
                    prev,
                )
                .await;
            match nested {
                Ok(next) => {
                    intermediates.push(prev); // prev is now an intermediate
                    prev = next;
                }
                Err(e) => {
                    // Tear down everything dialed so far — no partial onion may linger.
                    let _ = self.inner.close(prev).await;
                    for s in intermediates.into_iter().rev() {
                        let _ = self.inner.close(s).await;
                    }
                    return Err(Error::Transport(format!("path hop {i}: {e}")));
                }
            }
        }

        // `prev` is the exit session; record the rest for teardown, keyed by the exit id.
        self.intermediates
            .lock()
            .map_err(|_| Error::Transport("path map poisoned".into()))?
            .insert(prev.id, intermediates);
        tracing::info!(
            hops = self.hops.len(),
            "trust-split path established (entry→…→exit)"
        );
        Ok(prev)
    }

    async fn send(&self, session: &Session, packet: IpPacket) -> Result<()> {
        // The exit session carries the user's real IP packets; the onion is transparent here.
        self.inner.send(session, packet).await
    }

    async fn recv(&self, session: &Session) -> Result<IpPacket> {
        self.inner.recv(session).await
    }

    async fn close(&self, session: Session) -> Result<()> {
        let intermediates = self
            .intermediates
            .lock()
            .map_err(|_| Error::Transport("path map poisoned".into()))?
            .remove(&session.id)
            .unwrap_or_default();
        // Close innermost (exit) first, then unwind outward — mirror of the build order.
        let res = self.inner.close(session).await;
        for s in intermediates.into_iter().rev() {
            let _ = self.inner.close(s).await;
        }
        res
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Masque // every hop is MASQUE/QUIC on the wire
    }

    fn fingerprint_profile(&self) -> Profile {
        Profile::HttpsQuic
    }

    fn tunnel_mtu(&self, session: &Session) -> Option<usize> {
        // The exit session's datagram capacity is the end-to-end usable MTU through the onion.
        self.inner.tunnel_mtu(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: &str) -> NodeEndpoint {
        NodeEndpoint {
            host: host.into(),
            port: 443,
            kind: TransportKind::Masque,
            wg_pub: None,
            expected: None,
            grant: None,
        }
    }

    #[test]
    fn exposes_entry_hops_and_wire_profile() {
        let t = PathTransport::new(
            Arc::new(MasqueTransport::new()),
            vec![ep("entry"), ep("middle"), ep("exit")],
        );
        assert_eq!(t.hop_count(), 3);
        assert_eq!(t.entry().expect("entry hop").host, "entry");
        // The onion is MASQUE/QUIC on every hop — indistinguishable from a single tunnel.
        assert_eq!(t.kind(), TransportKind::Masque);
        assert_eq!(t.fingerprint_profile(), Profile::HttpsQuic);
    }

    #[tokio::test]
    async fn empty_path_refuses_to_connect() {
        let t = PathTransport::new(Arc::new(MasqueTransport::new()), vec![]);
        let creds = Grant {
            token: Vec::new(),
            nonce: [0u8; 32],
        };
        let err = t
            .connect(ep("ignored"), creds)
            .await
            .expect_err("empty path must fail");
        assert!(matches!(err, Error::Transport(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn three_hop_path_exposes_entry_and_holds_per_hop_grant_independence() {
        // A 3-hop onion: entry→middle→exit. The seam exposes the onion as a single MASQUE tunnel
        // (kind/profile), routes via the entry hop, and mints an INDEPENDENT fresh nonce per hop
        // for hops that carry no Coordinator grant (so no cross-hop correlation via a shared nonce).
        let t = PathTransport::new(
            Arc::new(MasqueTransport::new()),
            vec![ep("entry"), ep("middle"), ep("exit")],
        );
        assert_eq!(t.hop_count(), 3);
        assert_eq!(t.entry().expect("entry hop").host, "entry");
        assert_eq!(t.kind(), TransportKind::Masque, "every hop is MASQUE on the wire");

        let base = Grant { token: vec![9, 9, 9], nonce: [0u8; 32] };
        // Each hop with no pinned grant gets a fresh per-hop grant; nonces must all differ.
        let g_entry = PathTransport::grant_for(&t.hops[0], &base).expect("entry grant");
        let g_middle = PathTransport::grant_for(&t.hops[1], &base).expect("middle grant");
        let g_exit = PathTransport::grant_for(&t.hops[2], &base).expect("exit grant");
        assert_ne!(g_entry.nonce, g_middle.nonce, "entry and middle nonces independent");
        assert_ne!(g_middle.nonce, g_exit.nonce, "middle and exit nonces independent");
        assert_ne!(g_entry.nonce, g_exit.nonce, "entry and exit nonces independent");
        assert_eq!(g_entry.token, base.token, "the payment token carries through every hop");
    }

    #[test]
    fn a_freshly_built_path_registers_no_intermediates() {
        // The teardown bookkeeping starts empty: only a completed `connect` ever inserts an entry,
        // and the connect path tears everything down on any hop failure (no partial onion). The
        // real over-the-wire accept/reject of a hop is covered by tests/masque_attest.rs.
        let t = PathTransport::new(
            Arc::new(MasqueTransport::new()),
            vec![ep("entry"), ep("middle"), ep("exit")],
        );
        assert!(
            t.intermediates.lock().expect("map").is_empty(),
            "no intermediate sessions exist before a successful connect"
        );
    }

    #[test]
    fn fresh_grants_have_independent_nonces() {
        let base = Grant {
            token: vec![1, 2, 3],
            nonce: [0u8; 32],
        };
        let a = PathTransport::fresh_grant(&base).expect("grant a");
        let b = PathTransport::fresh_grant(&base).expect("grant b");
        assert_ne!(
            a.nonce, b.nonce,
            "each hop must get a fresh attestation nonce"
        );
        assert_eq!(
            a.token, base.token,
            "the payment token carries through unchanged"
        );
    }
}
