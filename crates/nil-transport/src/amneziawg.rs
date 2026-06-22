//! AmneziaWG-style obfuscation (architecture spec §4.3, cascade rung 2): WireGuard whose
//! on-wire bytes don't carry WireGuard's tell-tale fingerprint. Plain WireGuard is trivially
//! DPI-classified by its fixed 4-byte message-type word (`1/2/3/4`) and its fixed handshake
//! packet sizes (init **148** B, response **92** B, cookie **64** B) — the very "148/92-byte
//! fingerprint" NIL must never expose. This module hides both, reusing [`crate::pqwg::PqWgCore`]
//! for the actual crypto (so there is no new cryptography — only framing).
//!
//! Obfuscation (both ends run our code, so we define our own framing — not Amnezia
//! wire-compatible):
//!   - **Magic headers** replace the 4-byte WG type word: a distinct 4-byte `H[t]` per type
//!     `t∈{1,2,3,4}`, so the `1/2/3/4` constant disappears.
//!   - **Junk tails** of random length are appended to the *fixed-size* handshake packets, so
//!     the 148/92/64-byte sizes disappear. The receiver knows the real WG length per type and
//!     strips the tail. Data packets are already variable-length, so they get no tail.
//!   - **Junk packets**: a few random datagrams sent before the handshake. They match no magic
//!     header, so [`ObfsParams::deobfuscate`] returns `None` and the responder ignores them.
//!
//! The live UDP datapath + node responder that pump WireGuard through this codec are the
//! remaining integration; the codec + crypto composition are verified in-memory below (a full
//! WG handshake and data packet survive the round-trip, and the WG fingerprint is gone).

/// Fixed WireGuard packet lengths (bytes) by message type — the sizes a censor matches on.
const WG_LEN: [usize; 4] = [
    148, // 1: handshake initiation
    92,  // 2: handshake response
    64,  // 3: cookie reply
    0,   // 4: transport data (variable; 0 ⇒ "keep the whole body")
];

/// Obfuscation parameters shared by both ends (a deployment derives these from a shared key; the
/// defaults below are distinct, non-WireGuard 4-byte magics). `junk_*` size the pre-handshake
/// junk datagrams; `tail_*` size the junk appended to handshake packets.
#[derive(Clone, Debug)]
pub struct ObfsParams {
    /// `H[t-1]` = the 4-byte magic that replaces the WG type word for message type `t`.
    pub headers: [[u8; 4]; 4],
    pub junk_count: usize,
    pub junk_min: usize,
    pub junk_max: usize,
    pub tail_min: usize,
    pub tail_max: usize,
}

impl Default for ObfsParams {
    fn default() -> Self {
        Self {
            // Distinct from each other and from WG's 01/02/03/04 00 00 00 type words.
            headers: [
                [0x9e, 0x21, 0xc4, 0x07],
                [0x3b, 0xd5, 0x88, 0x1a],
                [0x6f, 0x0c, 0xa3, 0xe2],
                [0xd4, 0x77, 0x19, 0x5b],
            ],
            junk_count: 4,
            junk_min: 32,
            junk_max: 192,
            tail_min: 8,
            tail_max: 64,
        }
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    // Best-effort entropy; on failure the buffer stays zero (still valid junk).
    let _ = getrandom::getrandom(&mut v);
    v
}

/// A length in `[min, max]` (inclusive), chosen from the OS CSPRNG. `min` if the range is empty.
fn rand_len(min: usize, max: usize) -> usize {
    if max <= min {
        return min;
    }
    let span = (max - min + 1) as u64;
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    min + (u64::from_le_bytes(b) % span) as usize
}

impl ObfsParams {
    /// Obfuscate one WireGuard packet for the wire. `wg` must begin with the 4-byte WG type word.
    pub fn obfuscate(&self, wg: &[u8]) -> Vec<u8> {
        if wg.len() < 4 {
            return wg.to_vec();
        }
        let t = wg[0];
        let idx = match t {
            1..=4 => (t - 1) as usize,
            _ => {
                // Unknown type — pass through with no obfuscation (shouldn't happen from WG).
                return wg.to_vec();
            }
        };
        let mut out = Vec::with_capacity(wg.len() + self.tail_max);
        out.extend_from_slice(&self.headers[idx]); // magic header replaces the type word
        out.extend_from_slice(&wg[4..]); // the rest of the WG packet
        // Append a junk tail to the fixed-size handshake/cookie packets to erase their size tell.
        if WG_LEN[idx] != 0 {
            out.extend_from_slice(&rand_bytes(rand_len(self.tail_min, self.tail_max)));
        }
        out
    }

    /// Recover the WireGuard packet from a wire datagram, or `None` if it isn't one of ours
    /// (e.g. a junk packet) — the caller ignores `None`.
    pub fn deobfuscate(&self, wire: &[u8]) -> Option<Vec<u8>> {
        if wire.len() < 4 {
            return None;
        }
        let header = &wire[0..4];
        let idx = self.headers.iter().position(|h| h == header)?;
        let t = (idx + 1) as u8;
        let mut wg = Vec::with_capacity(wire.len());
        wg.extend_from_slice(&[t, 0, 0, 0]); // restore the WG type word
        if WG_LEN[idx] == 0 {
            // Variable-length data packet: the whole remaining body is real.
            wg.extend_from_slice(&wire[4..]);
        } else {
            // Fixed-size packet: take exactly the WG body, dropping the junk tail.
            let body = WG_LEN[idx].checked_sub(4)?;
            if wire.len() < 4 + body {
                return None; // truncated — not a valid packet of this type
            }
            wg.extend_from_slice(&wire[4..4 + body]);
        }
        Some(wg)
    }

    /// Pre-handshake junk datagrams to send before the real WireGuard initiation. They match no
    /// magic header, so the peer's `deobfuscate` drops them.
    pub fn junk_packets(&self) -> Vec<Vec<u8>> {
        (0..self.junk_count).map(|_| rand_bytes(rand_len(self.junk_min, self.junk_max))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqwg::{PqWgCore, WgKeypair, WgStep};
    use nil_crypto::psk::{responder_encapsulate, PqInitiator};

    fn wg_packet(t: u8, body_len: usize) -> Vec<u8> {
        let mut p = vec![t, 0, 0, 0];
        p.extend(std::iter::repeat(0xAB).take(body_len));
        p
    }

    #[test]
    fn round_trips_every_message_type_and_hides_the_fingerprint() {
        let p = ObfsParams::default();
        // (type, total WG length) for the three fixed-size packets + a data packet.
        for (t, len) in [(1u8, 148usize), (2, 92), (3, 64), (4, 80)] {
            let wg = wg_packet(t, len - 4);
            let wire = p.obfuscate(&wg);
            // The WG type word (1/2/3/4 at byte 0) must NOT appear at the wire's start.
            assert_ne!(wire[0], t, "type-{t} word must be replaced by a magic header");
            assert_eq!(&wire[0..4], &p.headers[(t - 1) as usize], "magic header present");
            // Fixed-size handshakes must not be their tell-tale length on the wire.
            if len != 80 {
                assert!(wire.len() > len, "handshake packet padded past its WG size");
            }
            let back = p.deobfuscate(&wire).expect("our packet deobfuscates");
            assert_eq!(back, wg, "type-{t} WG packet survives the round-trip exactly");
        }
    }

    #[test]
    fn junk_packets_are_ignored_by_the_peer() {
        let p = ObfsParams::default();
        let junk = p.junk_packets();
        assert_eq!(junk.len(), p.junk_count);
        for j in junk {
            // Astronomically unlikely to match a 4-byte magic; treat any match as a test miss.
            assert!(p.deobfuscate(&j).is_none(), "junk must not look like a real packet");
        }
    }

    /// The real proof: a full PQ-WireGuard handshake + a data packet, with EVERY datagram passed
    /// through the obfuscation codec, completes and round-trips — obfuscation composes with the
    /// crypto and never corrupts a packet.
    #[test]
    fn wireguard_handshake_and_data_survive_the_obfuscation_layer() {
        let obfs = ObfsParams::default();
        // Shared PQ hybrid PSK (as the AmneziaWG rung will derive it).
        let (initiator, offer) = PqInitiator::generate();
        let (cts, node_psk) = responder_encapsulate(&offer).expect("node encapsulate");
        let client_psk = initiator.finish(&cts).expect("client finish");
        let client_kp = WgKeypair::generate().unwrap();
        let node_kp = WgKeypair::generate().unwrap();
        let mut client = PqWgCore::new(client_kp.secret, node_kp.public, &client_psk, 1);
        let mut node = PqWgCore::new(node_kp.secret, client_kp.public, &node_psk, 2);

        // Send a wire helper: obfuscate at the sender, deobfuscate at the receiver.
        let hop = |obfs: &ObfsParams, pkt: &[u8]| -> Vec<u8> {
            let wire = obfs.obfuscate(pkt);
            obfs.deobfuscate(&wire).expect("peer recovers our packet")
        };

        // Handshake init → response → keepalive, each crossing the obfuscation layer.
        let init = client.handshake_init().expect("init");
        let resp = match node.decapsulate(&hop(&obfs, &init)) {
            WgStep::Network(b) => b,
            other => panic!("expected handshake response, got {other:?}"),
        };
        let keepalive = match client.decapsulate(&hop(&obfs, &resp)) {
            WgStep::Network(b) => b,
            other => panic!("expected keepalive, got {other:?}"),
        };
        match node.decapsulate(&hop(&obfs, &keepalive)) {
            WgStep::Done | WgStep::Network(_) => {}
            other => panic!("expected handshake completion, got {other:?}"),
        }

        // A real IP packet survives encrypt → obfuscate → (wire) → deobfuscate → decrypt.
        let ip = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 74, 0, 2,
            10, 74, 0, 1, 0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];
        let wire = client.encapsulate(&ip).expect("encapsulate");
        match node.decapsulate(&hop(&obfs, &wire)) {
            WgStep::Ip(got) => assert_eq!(got, ip, "the inner IP packet survives obfuscated PQ-WG"),
            other => panic!("expected decapsulated IP, got {other:?}"),
        }
    }
}
