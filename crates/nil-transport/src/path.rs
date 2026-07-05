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
//! (`PqWgTransport::wrap_session`). This is wired for **every** hop, not just the exit: dialing and
//! PQ-wrapping are interleaved (dial hop N → PQ-wrap it → dial hop N+1 *through that PQ-WG tunnel*),
//! so the carrier for the next hop is hop N's PQ-WG session, and every leg's payload rides a hybrid
//! PSK — not just the exit's. `connect_nested` is already carrier-generic (it only calls
//! `send`/`recv`/`tunnel_mtu` on the outer transport, which `PqWgTransport` implements), so a PQ-WG
//! session is a valid nesting carrier with no change to the nesting code. A hop with no `wg_pub`
//! stays plain nested MASQUE and forwards the next hop over its MASQUE session.
//!
//! **Live status (honest):** a *live* all-PQ onion needs each intermediate node to terminate its
//! PQ-WireGuard responder and forward the decapsulated inner QUIC to the next hop. Both the node PQ
//! responder (`nil-node`, behind `NW_NODE_PQWG`) and the forwarding (the decapsulated inner packet —
//! the next hop's UDP/443 QUIC — goes to the node's TUN and the role-scoped NAT forwards it) exist,
//! and `deploy/verify-trustsplit-pq.sh` proves a **2-hop** all-PQ onion carries real traffic with the
//! trust-split intact (per-hop keys via the `NW_PATH` `@wg_pub` grammar; a non-exit PQ hop forwards).
//! MTU LIMIT (measured, honest): each PQ hop adds WireGuard's 32 B on top of the CONNECT-IP + udpip
//! nesting tax, so a **3-hop** all-PQ onion overruns the 1200 B QUIC floor on a standard (≤1500 B)
//! path and `connect_nested` **fails closed** (refuses, never corrupts) — the harness asserts this.
//! A 3-hop trust-split therefore uses plain nested MASQUE today; trimming the per-hop tax to fit
//! 3-hop all-PQ is a separate encapsulation change.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use nil_core::{
    Error, Grant, IpPacket, NodeEndpoint, Profile, Result, Session, SessionId, TransportKind,
};

use crate::{MasqueTransport, PqWgTransport, Transport};

/// One established hop of the onion, tagged by how its data plane is carried — so teardown closes
/// each hop through the right transport (innermost first). `Pq` hops are closed via `pqwg` (which
/// also closes the underlying MASQUE session); `Plain` hops via the inner MASQUE transport.
#[derive(Clone, Copy)]
enum HopHandle {
    /// A PQ-WireGuard-wrapped hop; the `Session` is the PQ session (its inner MASQUE session is
    /// owned by `pqwg` and torn down with it).
    Pq(Session),
    /// A plain nested-MASQUE hop (no `wg_pub`).
    Plain(Session),
}

impl HopHandle {
    fn session(&self) -> Session {
        match self {
            HopHandle::Pq(s) | HopHandle::Plain(s) => *s,
        }
    }
    fn is_pq(&self) -> bool {
        matches!(self, HopHandle::Pq(_))
    }
}

/// A multi-hop MASQUE path: entry → … → exit, nested as a CONNECT-IP onion.
pub struct PathTransport {
    inner: Arc<MasqueTransport>,
    /// PQ-WireGuard wrapper over the **same** inner MASQUE transport — used to PQ-key a hop's
    /// nested session when that hop carries a `wg_pub`. Shares `inner` so the wrapped session's
    /// control/datagram channels are the very ones the nested hop established.
    pqwg: Arc<PqWgTransport>,
    /// Ordered hops, outermost (entry) first, innermost (exit) last. Non-empty.
    hops: Vec<NodeEndpoint>,
    /// Map an active exit session id → the FULL ordered list of established hop handles (entry…exit,
    /// dial order), each tagged PQ/plain, so `close` tears the whole onion down innermost-first
    /// through the correct transport for each hop.
    onion: Mutex<HashMap<SessionId, Vec<HopHandle>>>,
    /// Exit session ids whose data plane is PQ-WireGuard-wrapped: the datapath only ever drives the
    /// EXIT session, so `send`/`recv`/`tunnel_mtu` dispatch on this set. (Intermediate PQ sessions
    /// are driven as nesting carriers by `connect_nested`, never through this dispatch.) A plain
    /// (no-`wg_pub`) exit is absent here and uses `inner` directly.
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
            onion: Mutex::new(HashMap::new()),
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

    /// Close a list of established hops innermost-first (reverse of dial order) through the correct
    /// transport for each. Best-effort — used both for mid-connect unwinding (no partial onion may
    /// linger) and as the body of `close`. Returns the first error encountered, if any.
    async fn teardown(&self, hops: Vec<HopHandle>) -> Result<()> {
        let mut first_err = Ok(());
        for h in hops.into_iter().rev() {
            let r = match h {
                HopHandle::Pq(s) => self.pqwg.close(s).await,
                HopHandle::Plain(s) => self.inner.close(s).await,
            };
            if first_err.is_ok() {
                first_err = r;
            }
        }
        first_err
    }
}

#[async_trait]
impl Transport for PathTransport {
    /// Connect the whole onion and return the innermost (exit) session. `target` is ignored —
    /// the hops are fixed at construction (the datapath passes the entry endpoint as `target`
    /// for routing symmetry).
    ///
    /// **Per-hop PQ:** every hop carrying a `wg_pub` is PQ-WireGuard-wrapped, interleaved with the
    /// dial: dial hop N (over real UDP for entry, else *through the previous hop's carrier*), then if
    /// it has a `wg_pub` PQ-wrap it, then use that PQ-WG session as the carrier to dial hop N+1. So
    /// the carrier for hop N+1 is hop N's PQ-WG tunnel (not its MASQUE session), and every leg's
    /// payload rides a hybrid PSK. Wrapping happens BEFORE the next hop is dialed, so no downstream
    /// driver is running on a hop's datagram channel during its PQ handshake (no re-keying race). A
    /// hop with no `wg_pub` forwards the next hop over its plain MASQUE session. Any failure tears
    /// the whole onion down innermost-first — no partial / unattested-data-plane tunnel may linger.
    async fn connect(&self, _target: NodeEndpoint, creds: Grant) -> Result<Session> {
        if self.hops.is_empty() {
            return Err(Error::Transport("path has no hops".into()));
        }
        let _guard = self.connect_lock.lock().await;

        // Established hops in dial order (entry…exit), for teardown. The carrier for the NEXT nested
        // dial is the previous hop's (transport, session): a PQ-WG carrier if that hop was wrapped,
        // else the inner MASQUE transport. `None` for hop 0 (a real QUIC/UDP connection).
        let mut hops: Vec<HopHandle> = Vec::new();
        let mut carrier: Option<(Arc<dyn Transport>, Session)> = None;

        for (i, hop) in self.hops.iter().enumerate() {
            let grant = Self::grant_for(hop, &creds)?;
            // Dial this hop: hop 0 over real UDP; hop i>0 nested through the previous carrier.
            // (Attestation is appraised inside connect/connect_nested before either returns.)
            let masque = match &carrier {
                None => self.inner.connect(hop.clone(), grant).await,
                Some((ct, cs)) => self.inner.connect_nested(hop.clone(), grant, ct.clone(), *cs).await,
            };
            let masque = match masque {
                Ok(s) => s,
                Err(e) => {
                    let _ = self.teardown(hops).await;
                    return Err(Error::Transport(format!("path hop {i}: {e}")));
                }
            };
            // PQ-wrap this hop if it carries a node WG key; the wrapped session becomes the carrier
            // for the next hop. `Session` is `Copy`, so on wrap failure we still hold `masque` to
            // close it (a failed `wrap_session` does not register the inner session in `pqwg`).
            if let Some(wg_pub) = hop.wg_pub {
                match self.pqwg.wrap_session(masque, wg_pub).await {
                    Ok(pq) => {
                        hops.push(HopHandle::Pq(pq));
                        carrier = Some((self.pqwg.clone(), pq));
                    }
                    Err(e) => {
                        let _ = self.inner.close(masque).await;
                        let _ = self.teardown(hops).await;
                        return Err(Error::Transport(format!("path hop {i} PQ-WireGuard: {e}")));
                    }
                }
            } else {
                hops.push(HopHandle::Plain(masque));
                carrier = Some((self.inner.clone(), masque));
            }
        }

        // The last hop is the exit — the session the datapath drives. (hops is non-empty: the path
        // has >= 1 hop and every iteration pushes exactly one handle.)
        let exit = *hops.last().expect("non-empty path established at least one hop");
        let pq_hops = hops.iter().filter(|h| h.is_pq()).count();
        // Register the path for teardown. If a registration lock is poisoned, tear the freshly-dialed
        // hops down BEFORE returning — otherwise every hop's QUIC session leaks (stays open on each
        // node until idle timeout, holding an address-pool slot), exactly like the dial/wrap error
        // paths above. (A failure here is fail-closed: the caller gets no session, so the kill-switch
        // holds; we only need to avoid the orphaned sessions + a half-registered pq_exits/onion pair.)
        // Each lock is taken, used, and dropped inside its own expression so no MutexGuard is held
        // across the `teardown().await` (that would make this future `!Send`).
        let pq_registered = if exit.is_pq() {
            match self.pq_exits.lock() {
                Ok(mut set) => {
                    set.insert(exit.session().id);
                    true
                }
                Err(_) => false,
            }
        } else {
            true
        };
        if !pq_registered {
            let _ = self.teardown(hops).await;
            return Err(Error::Transport("path pq set poisoned".into()));
        }
        // Record the full ordered hop list for teardown, keyed by the exit session id. On poison,
        // hand `hops` back out of the match so we can tear it down after the guard is dropped.
        let exit_id = exit.session().id;
        let orphaned = match self.onion.lock() {
            Ok(mut map) => {
                map.insert(exit_id, hops);
                None
            }
            Err(_) => Some(hops),
        };
        if let Some(hops) = orphaned {
            let _ = self.teardown(hops).await;
            return Err(Error::Transport("path map poisoned".into()));
        }
        tracing::info!(
            hops = self.hops.len(),
            pq_hops,
            "trust-split path established (entry→…→exit)"
        );
        Ok(exit.session())
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
        let hops = self
            .onion
            .lock()
            .map_err(|_| Error::Transport("path map poisoned".into()))?
            .remove(&session.id)
            .unwrap_or_default();
        self.pq_exits
            .lock()
            .map_err(|_| Error::Transport("path pq set poisoned".into()))?
            .remove(&session.id);
        // Tear the onion down innermost (exit) first, then outward — the mirror of the dial order.
        // Each hop closes through its own transport (PQ hops via `pqwg`, which also closes their
        // underlying MASQUE session); a plain hop via `inner`. See `teardown`.
        self.teardown(hops).await
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
    fn a_freshly_built_path_registers_no_onion_hops() {
        // The teardown bookkeeping starts empty: only a completed `connect` ever inserts an entry,
        // and the connect path tears everything down on any hop failure (no partial onion). The
        // real over-the-wire accept/reject of a hop is covered by tests/masque_attest.rs.
        let t = PathTransport::new(
            Arc::new(MasqueTransport::new()),
            vec![ep("entry"), ep("middle"), ep("exit")],
        );
        assert!(
            t.onion.lock().expect("map").is_empty(),
            "no onion hops exist before a successful connect"
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
    fn each_hops_wg_pub_selects_per_hop_pq() {
        // Every hop carrying a wg_pub is PQ-wrapped (not just the exit): the per-hop key is the
        // selection signal, applied at each hop as it is dialed. Here entry and exit carry keys
        // (so both legs they terminate are PQ); the middle has none (plain nested MASQUE).
        let t = PathTransport::new(
            Arc::new(MasqueTransport::new()),
            vec![ep_pq("entry", [1u8; 32]), ep("middle"), ep_pq("exit", [9u8; 32])],
        );
        assert_eq!(t.hops[0].wg_pub, Some([1u8; 32]), "entry hop carries its PQ key");
        assert_eq!(t.hops[1].wg_pub, None, "middle hop is plain nested MASQUE");
        assert_eq!(t.hops[2].wg_pub, Some([9u8; 32]), "exit hop carries its PQ key");
        // On the wire the onion is still MASQUE/QUIC regardless of the inner PQ-WireGuard layer.
        assert_eq!(t.kind(), TransportKind::Masque);
        assert_eq!(t.fingerprint_profile(), Profile::HttpsQuic);
    }

    #[test]
    fn hop_handle_reports_its_session_and_pq_kind() {
        // teardown + the exit-dispatch decision both key off these: a Pq hop closes via pqwg (which
        // also closes its inner MASQUE session) and is the dispatch target only when it is the exit;
        // a Plain hop closes via inner. Lock the accessor semantics the connect/close paths rely on.
        let s = Session { id: SessionId(42), kind: TransportKind::Masque };
        assert_eq!(HopHandle::Pq(s).session().id, SessionId(42));
        assert_eq!(HopHandle::Plain(s).session().id, SessionId(42));
        assert!(HopHandle::Pq(s).is_pq(), "a PQ hop reports PQ");
        assert!(!HopHandle::Plain(s).is_pq(), "a plain hop reports not-PQ");
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
