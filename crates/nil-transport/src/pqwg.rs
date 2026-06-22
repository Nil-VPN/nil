//! Inner PQ-WireGuard crypto core (architecture spec §4.2): a `boringtun` Noise tunnel keyed
//! by the `nil-crypto` post-quantum hybrid PSK (ML-KEM-1024 + Classic McEliece 460896). The
//! tunnel is safe if *either* the classical X25519 Noise handshake or the PQ PSK holds.
//!
//! [`PqWgCore`] is the reusable building block: it owns one `Tunn`, seeded with the hybrid PSK,
//! and exposes socket-agnostic handshake / encapsulate / decapsulate steps. A full
//! `Transport` wrapper that carries these over an inner MASQUE tunnel (and the matching node
//! responder) is the remaining integration — it shares this core with the Phase 4 AmneziaWG
//! transport, so the crypto lives here once. The PQ PSK exchange itself is in
//! [`nil_crypto::psk`]; here we just consume the derived [`Psk`].

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use nil_crypto::psk::Psk;

/// A WireGuard static X25519 keypair.
pub struct WgKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl WgKeypair {
    /// Generate a fresh keypair from the OS CSPRNG (via `getrandom`, avoiding an rand_core
    /// version pin).
    pub fn generate() -> std::io::Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| std::io::Error::other(format!("wg key entropy: {e}")))?;
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }
}

/// The result of feeding one inbound WireGuard datagram to [`PqWgCore::decapsulate`].
#[derive(Debug)]
pub enum WgStep {
    /// A decapsulated inner IP packet to hand to the TUN.
    Ip(Vec<u8>),
    /// A WireGuard control datagram (handshake response, keepalive, cookie) to send back.
    Network(Vec<u8>),
    /// Nothing to do.
    Done,
    /// WireGuard rejected the datagram (e.g. PSK mismatch, replay, bad MAC).
    Err(WireGuardError),
}

/// One end of a PQ-keyed WireGuard tunnel.
pub struct PqWgCore {
    tunn: Tunn,
}

impl PqWgCore {
    /// Build a tunnel end: our static secret, the peer's static public, and the hybrid PSK
    /// (mixed into the Noise IKpsk2 handshake). `index` disambiguates concurrent sessions.
    pub fn new(my_secret: StaticSecret, peer_public: PublicKey, psk: &Psk, index: u32) -> Self {
        let tunn = Tunn::new(my_secret, peer_public, Some(*psk.as_bytes()), Some(25), index, None);
        Self { tunn }
    }

    /// Initiator: produce the first handshake datagram to send to the peer.
    pub fn handshake_init(&mut self) -> Result<Vec<u8>, WireGuardError> {
        let mut dst = vec![0u8; 2048];
        match self.tunn.format_handshake_initiation(&mut dst, false) {
            TunnResult::WriteToNetwork(p) => Ok(p.to_vec()),
            TunnResult::Err(e) => Err(e),
            _ => Err(WireGuardError::ConnectionExpired),
        }
    }

    /// Feed one inbound WireGuard datagram; returns what to do next.
    pub fn decapsulate(&mut self, datagram: &[u8]) -> WgStep {
        let mut dst = vec![0u8; 65535];
        match self.tunn.decapsulate(None, datagram, &mut dst) {
            TunnResult::WriteToNetwork(p) => WgStep::Network(p.to_vec()),
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => WgStep::Ip(p.to_vec()),
            TunnResult::Done => WgStep::Done,
            TunnResult::Err(e) => WgStep::Err(e),
        }
    }

    /// Encapsulate an inner IP packet into a WireGuard transport datagram for the peer.
    pub fn encapsulate(&mut self, ip: &[u8]) -> Result<Vec<u8>, WireGuardError> {
        let mut dst = vec![0u8; ip.len() + 32];
        match self.tunn.encapsulate(ip, &mut dst) {
            TunnResult::WriteToNetwork(p) => Ok(p.to_vec()),
            TunnResult::Err(e) => Err(e),
            // `Done` here means the packet was queued pending a handshake — caller should have
            // completed the handshake first.
            _ => Err(WireGuardError::ConnectionExpired),
        }
    }

    /// Drive periodic WireGuard timers (rekey, keepalive, handshake retransmit). Returns a
    /// datagram to send if the timers produced one.
    pub fn tick(&mut self) -> Option<Vec<u8>> {
        let mut dst = vec![0u8; 2048];
        match self.tunn.update_timers(&mut dst) {
            TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nil_crypto::psk::{responder_encapsulate, PqInitiator};

    /// A minimal IPv4/UDP packet (header + 4-byte payload) to round-trip through the tunnel.
    fn sample_ipv4() -> Vec<u8> {
        // version/IHL, DSCP, total len(28), id, flags/frag, ttl, proto=UDP(17), checksum(0),
        // src 10.74.0.2, dst 10.74.0.1, then an 8-byte UDP header + 0 payload.
        let mut p = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
            10, 74, 0, 2, 10, 74, 0, 1,
            0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];
        // fix length already 28; leave checksum 0 (boringtun doesn't validate L3 checksum).
        p.truncate(28);
        p
    }

    fn complete_handshake(client: &mut PqWgCore, node: &mut PqWgCore) {
        let init = client.handshake_init().expect("init");
        let resp = match node.decapsulate(&init) {
            WgStep::Network(b) => b,
            other => panic!("expected handshake response, got {other:?}"),
        };
        let keepalive = match client.decapsulate(&resp) {
            WgStep::Network(b) => b,
            other => panic!("expected keepalive, got {other:?}"),
        };
        match node.decapsulate(&keepalive) {
            WgStep::Done | WgStep::Network(_) => {}
            other => panic!("expected handshake completion, got {other:?}"),
        }
    }

    #[test]
    fn pq_psk_drives_a_wireguard_tunnel_and_packet_round_trips() {
        // 1. PQ hybrid PSK exchange (client = KEM initiator).
        let (initiator, offer) = PqInitiator::generate();
        let (cts, node_psk) = responder_encapsulate(&offer).expect("node encapsulate");
        let client_psk = initiator.finish(&cts).expect("client finish");
        assert_eq!(client_psk.as_bytes(), node_psk.as_bytes(), "both sides derive the same PQ PSK");

        // 2. WG static keypairs + two cores fed the same PQ PSK.
        let client_kp = WgKeypair::generate().unwrap();
        let node_kp = WgKeypair::generate().unwrap();
        let mut client = PqWgCore::new(client_kp.secret, node_kp.public, &client_psk, 1);
        let mut node = PqWgCore::new(node_kp.secret, client_kp.public, &node_psk, 2);

        // 3. Noise IKpsk2 handshake (mixes the PQ PSK).
        complete_handshake(&mut client, &mut node);

        // 4. A real IP packet survives encrypt → (wire) → decrypt.
        let ip = sample_ipv4();
        let wire = client.encapsulate(&ip).expect("encapsulate");
        match node.decapsulate(&wire) {
            WgStep::Ip(got) => assert_eq!(got, ip, "the inner IP packet survives the PQ-WG tunnel"),
            other => panic!("expected decapsulated IP, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_psk_fails_the_handshake() {
        let (initiator, offer) = PqInitiator::generate();
        let (cts, _node_psk) = responder_encapsulate(&offer).expect("node encapsulate");
        let client_psk = initiator.finish(&cts).expect("client finish");

        // The node uses a DIFFERENT PSK (a fresh independent exchange) — the IKpsk2 handshake
        // must fail because the preshared key doesn't match.
        let (other_init, other_offer) = PqInitiator::generate();
        let (other_cts, _) = responder_encapsulate(&other_offer).unwrap();
        let wrong_psk = other_init.finish(&other_cts).unwrap();
        assert_ne!(client_psk.as_bytes(), wrong_psk.as_bytes());

        let client_kp = WgKeypair::generate().unwrap();
        let node_kp = WgKeypair::generate().unwrap();
        let mut client = PqWgCore::new(client_kp.secret, node_kp.public, &client_psk, 1);
        let mut node = PqWgCore::new(node_kp.secret, client_kp.public, &wrong_psk, 2);

        // In Noise IKpsk2 the PSK is mixed during the *response*, so the mismatch surfaces
        // when the initiator processes the response (or the responder rejects the init).
        let init = client.handshake_init().expect("init");
        let resp = match node.decapsulate(&init) {
            WgStep::Network(b) => b,
            WgStep::Err(_) => return, // responder rejected outright — also fine
            other => panic!("unexpected responder step {other:?}"),
        };
        assert!(
            matches!(client.decapsulate(&resp), WgStep::Err(_)),
            "a mismatched PQ PSK must make the WireGuard handshake fail"
        );
    }
}
