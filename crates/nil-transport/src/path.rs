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
//!
//! **Per-hop PQ-WireGuard (spec §4.2 over §6):** when a hop carries a `wg_pub`, that hop runs the
//! ML-KEM-1024 + Classic McEliece hybrid-PSK WireGuard handshake *inside* its MASQUE tunnel
//! (`PqWgTransport::wrap_session`), exactly like the single-hop primary transport. The **exit**
//! hop is wired today (it carries the user's real IP packets, so PQ-protecting it is the
//! highest-value rung); intermediate hops with a `wg_pub` are NOT yet PQ-wrapped — see the note on
//! [`PathTransport::connect`]. A hop with no `wg_pub` stays plain nested MASQUE.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use nil_core::{
    Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind,
};

use crate::{MasqueTransport, PqWgTransport, Transport};

/// A multi-hop MASQUE path: entry → … → exit, nested as a CONNECT-IP onion.
pub struct PathTransport {
    inner: Arc<MasqueTransport>,
    /// PQ-WireGuard wrapper over the **same** inner MASQUE transport — used to PQ-key a hop's
    /// nested session when that hop carries a `wg_pub`. Shares `inner` so the wrapped session's
    /// control/datagram channels are the very ones the nested hop established.
    pqwg: Arc<PqWgTransport>,
    /// Ordered hops, outermost (entry) first, innermost (exit) last. Non-empty.
    hops: Vec<NodeEndpoint>,
    /// Map an active exit session id → the intermediate sessions (entry…second-to-last) kept
    /// alive behind it, so `close` can tear the whole onion down.
    intermediates: Mutex<HashMap<SessionId, Vec<Session>>>,
    /// Exit session ids whose data plane is PQ-WireGuard-wrapped: `send`/`recv`/`close` for these
    /// route through `pqwg` (the PQ pump), not the raw MASQUE session. A plain (no-`wg_pub`) exit
    /// is absent here and uses `inner` directly.
    pq_exits: Mutex<HashSet<SessionId>>,
    /// Guards the connect→register critical section so concurrent `connect`s don't interleave
    /// hops on the shared inner transport in a way that confuses teardown bookkeeping.
    connect_lock: tokio::sync::Mutex<()>,
}

impl PathTransport {
    /// Build a path over `hops` (outermost first). The caller routes the host's own QUIC to the
    /// **entry** hop (see [`PathTransport::entry`]); everything past entry is reached *through*
    /// the tunnel and needs no host-route exception.
    pub fn new(inner: Arc<MasqueTransport>, hops: Vec<NodeEndpoint>) -> Self {
        let pqwg = Arc::new(PqWgTransport::new(inner.clone()));
        Self {
            inner,
            pqwg,
            hops,
            intermediates: Mutex::new(HashMap::new()),
            pq_exits: Mutex::new(HashSet::new()),
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

    /// Whether `id` names a PQ-WireGuard-wrapped exit session (its data plane rides the PQ pump).
    fn is_pq_exit(&self, id: SessionId) -> Result<bool> {
        Ok(self
            .pq_exits
            .lock()
            .map_err(|_| Error::Transport("path pq set poisoned".into()))?
            .contains(&id))
    }
}

#[async_trait]
impl Transport for PathTransport {
    /// Connect the whole onion and return the innermost (exit) session. `target` is ignored —
    /// the hops are fixed at construction (the datapath passes the entry endpoint as `target`
    /// for routing symmetry).
    ///
    /// **Per-hop PQ:** if the **exit** hop carries a `wg_pub`, its nested MASQUE session is then
    /// PQ-WireGuard-wrapped (`pqwg.wrap_session`), so the user's IP packets ride the PQ hybrid-PSK
    /// WireGuard tunnel end-to-end — not just plain nested MASQUE (TLS-1.3 only). PARTIAL (honest):
    /// only the exit hop is PQ-wrapped here. Intermediate hops that carry a `wg_pub` are NOT yet
    /// PQ-keyed — doing so requires re-keying each *inner* carrier before dialing the next hop
    /// through it (the carrier for hop N+1 would become hop N's PQ-WG tunnel, not its MASQUE
    /// session), a deeper change to the nesting in `connect_nested`. Wrapping the exit is the
    /// highest-value rung (it carries the real client IP packets); the rest is deferred and
    /// tracked here rather than silently skipped.
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

        // `prev` is the exit hop's MASQUE session. If the exit hop carries a node WG key, PQ-key
        // its data plane (hybrid-PSK WireGuard inside the nested MASQUE tunnel). On any failure,
        // tear the whole onion down — no partial / unattested-data-plane tunnel may linger.
        let exit_hop = &self.hops[self.hops.len() - 1];
        let exit = if let Some(wg_pub) = exit_hop.wg_pub {
            // `Session` is `Copy`, so keep the MASQUE exit handle to tear down on PQ failure (a
            // failed `wrap_session` does not register/own the inner session, so its driver would
            // otherwise leak until the connection idle-times out).
            let masque_exit = prev;
            match self.pqwg.wrap_session(prev, wg_pub).await {
                Ok(pq) => {
                    self.pq_exits
                        .lock()
                        .map_err(|_| Error::Transport("path pq set poisoned".into()))?
                        .insert(pq.id);
                    pq
                }
                Err(e) => {
                    // Tear the whole onion down — exit first, then unwind outward. No partial /
                    // non-PQ-keyed data plane may linger (kill-switch holds).
                    let _ = self.inner.close(masque_exit).await;
                    for s in intermediates.into_iter().rev() {
                        let _ = self.inner.close(s).await;
                    }
                    return Err(Error::Transport(format!("path exit hop PQ-WireGuard: {e}")));
                }
            }
        } else {
            prev
        };

        // Record the intermediates for teardown, keyed by the (possibly PQ-wrapped) exit id.
        self.intermediates
            .lock()
            .map_err(|_| Error::Transport("path map poisoned".into()))?
            .insert(exit.id, intermediates);
        tracing::info!(
            hops = self.hops.len(),
            pq_exit = exit_hop.wg_pub.is_some(),
            "trust-split path established (entry→…→exit)"
        );
        Ok(exit)
    }

    async fn send(&self, session: &Session, packet: IpPacket) -> Result<()> {
        // The exit session carries the user's real IP packets. A PQ-wrapped exit routes through the
        // PQ-WireGuard pump; a plain exit rides the MASQUE session transparently.
        if self.is_pq_exit(session.id)? {
            self.pqwg.send(session, packet).await
        } else {
            self.inner.send(session, packet).await
        }
    }

    async fn recv(&self, session: &Session) -> Result<IpPacket> {
        if self.is_pq_exit(session.id)? {
            self.pqwg.recv(session).await
        } else {
            self.inner.recv(session).await
        }
    }

    async fn close(&self, session: Session) -> Result<()> {
        let intermediates = self
            .intermediates
            .lock()
            .map_err(|_| Error::Transport("path map poisoned".into()))?
            .remove(&session.id)
            .unwrap_or_default();
        let was_pq = self
            .pq_exits
            .lock()
            .map_err(|_| Error::Transport("path pq set poisoned".into()))?
            .remove(&session.id);
        // Close innermost (exit) first, then unwind outward — mirror of the build order. A
        // PQ-wrapped exit is closed via `pqwg` (which also closes its own MASQUE inner session);
        // a plain exit via `inner`.
        let res = if was_pq {
            self.pqwg.close(session).await
        } else {
            self.inner.close(session).await
        };
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
        // The exit session's datagram capacity is the end-to-end usable MTU through the onion. A
        // PQ-wrapped exit reports the MASQUE MTU minus WireGuard's 32-byte transport overhead.
        if self.is_pq_exit(session.id).unwrap_or(false) {
            self.pqwg.tunnel_mtu(session)
        } else {
            self.inner.tunnel_mtu(session)
        }
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

    /// An endpoint that pins a node WireGuard key — marks the hop for per-hop PQ-WireGuard.
    fn ep_pq(host: &str, wg_pub: [u8; 32]) -> NodeEndpoint {
        NodeEndpoint {
            wg_pub: Some(wg_pub),
            ..ep(host)
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
    fn a_plain_path_marks_no_pq_exit_and_dispatches_to_masque() {
        // A path whose exit hop carries NO wg_pub is plain nested MASQUE: nothing is recorded in
        // `pq_exits`, so send/recv/close/MTU dispatch to the inner MASQUE transport (the
        // pre-existing behaviour is preserved exactly for the no-key case).
        let t = PathTransport::new(
            Arc::new(MasqueTransport::new()),
            vec![ep("entry"), ep("middle"), ep("exit")],
        );
        assert!(
            t.pq_exits.lock().expect("pq set").is_empty(),
            "a freshly built path has no PQ exits until a successful PQ-wrapped connect"
        );
        // Any id is treated as a plain (non-PQ) exit while the set is empty.
        assert!(
            !t.is_pq_exit(SessionId(0)).expect("dispatch"),
            "with no PQ exit recorded, dispatch routes through inner MASQUE"
        );
    }

    #[test]
    fn pq_exit_membership_drives_the_send_recv_dispatch() {
        // The dispatch decision is purely `pq_exits` membership. Simulate a recorded PQ exit and a
        // plain exit and assert `is_pq_exit` routes each correctly — this is the branch `send`,
        // `recv`, `close`, and `tunnel_mtu` key off. (The full over-the-wire PQ handshake through a
        // nested exit needs a PQ-WireGuard-capable MASQUE node; that lives in the node e2e harness,
        // not this pure unit — exit-hop PQ wrapping is wired in `connect` above.)
        let t = PathTransport::new(
            Arc::new(MasqueTransport::new()),
            vec![ep("entry"), ep_pq("exit", [3u8; 32])],
        );
        t.pq_exits.lock().expect("pq set").insert(SessionId(7));
        assert!(t.is_pq_exit(SessionId(7)).expect("pq id"), "recorded id is a PQ exit");
        assert!(
            !t.is_pq_exit(SessionId(8)).expect("plain id"),
            "an unrecorded id is a plain MASQUE exit"
        );
    }

    #[test]
    fn exit_hop_wg_pub_is_what_selects_per_hop_pq() {
        // The selection signal for PQ-wrapping is the EXIT hop carrying a wg_pub. A path with a
        // PQ exit hop exposes it on the last hop; the entry/middle carrying keys does not (today)
        // make the exit PQ — only the exit hop's own key does (documented partial).
        let t = PathTransport::new(
            Arc::new(MasqueTransport::new()),
            vec![ep_pq("entry", [1u8; 32]), ep("middle"), ep_pq("exit", [9u8; 32])],
        );
        let exit_hop = &t.hops[t.hops.len() - 1];
        assert_eq!(exit_hop.wg_pub, Some([9u8; 32]), "exit hop carries its PQ key");
        // On the wire the onion is still MASQUE/QUIC regardless of the inner PQ-WireGuard layer.
        assert_eq!(t.kind(), TransportKind::Masque);
        assert_eq!(t.fingerprint_profile(), Profile::HttpsQuic);
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
