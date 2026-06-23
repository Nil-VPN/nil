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
