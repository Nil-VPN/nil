//! Node-side PQ-WireGuard responder (architecture spec §4.2): the matching half of the
//! client's `PqWgTransport`. The node holds a WireGuard static key, derives the PQ hybrid PSK
//! from the client's offer (over the reliable control channel), runs a boringtun responder,
//! and the server loop decapsulates client datagrams to the exit TUN (and encapsulates replies).
//!
//! Enabled at runtime by `NW_NODE_PQWG`; the node logs its WireGuard public key so the client
//! can pin it (`NW_NODE_WG_PUB`). Two framing layers on the control stream: the outer
//! `[u32 len][payload]` matches the MASQUE control channel; the payload is `encode_parts(...)`
//! shared with the client (anti-drift).

use std::collections::VecDeque;

use boringtun::x25519::{PublicKey, StaticSecret};
use nil_crypto::psk::{responder_encapsulate, PqOffer};
use nil_transport::pqwg::{decode_parts, encode_parts, PqWgCore};

/// Per-client PQ-WireGuard responder state.
#[derive(Default)]
pub struct ClientPqWg {
    /// Reassembly buffer for inbound control-stream bytes.
    ctrl_in: Vec<u8>,
    /// Control bytes queued to send back (the ciphertexts), already outer-framed.
    pub ctrl_out: VecDeque<u8>,
    /// The boringtun responder, built once the client's offer arrives.
    pub tunn: Option<PqWgCore>,
}

impl ClientPqWg {
    /// Feed control-stream bytes. On a complete offer, derive the PSK, build the responder
    /// `Tunn`, and queue the ciphertexts reply (outer-framed) in `ctrl_out`.
    pub fn on_control_bytes(&mut self, node_secret: &StaticSecret, bytes: &[u8]) {
        self.ctrl_in.extend_from_slice(bytes);
        while self.ctrl_in.len() >= 4 {
            let len =
                u32::from_be_bytes([self.ctrl_in[0], self.ctrl_in[1], self.ctrl_in[2], self.ctrl_in[3]]) as usize;
            if self.ctrl_in.len() < 4 + len {
                break;
            }
            let offer_msg = self.ctrl_in[4..4 + len].to_vec();
            self.ctrl_in.drain(..4 + len);
            if let Some(cts_msg) = self.handle_offer(node_secret, &offer_msg) {
                self.ctrl_out.extend((cts_msg.len() as u32).to_be_bytes());
                self.ctrl_out.extend(cts_msg);
            }
        }
    }

    fn handle_offer(&mut self, node_secret: &StaticSecret, offer_msg: &[u8]) -> Option<Vec<u8>> {
        let parts = decode_parts(offer_msg)?;
        if parts.len() != 3 {
            tracing::warn!("PQ offer: expected 3 parts (wg_pub, ml-kem ek, mceliece pk)");
            return None;
        }
        let client_wg_pub: [u8; 32] = parts[0].as_slice().try_into().ok()?;
        let offer = PqOffer { mlkem_ek: parts[1].clone(), mceliece_pk: parts[2].clone() };
        let (cts, psk) = responder_encapsulate(&offer)
            .map_err(|e| tracing::warn!("PQ responder_encapsulate: {e}"))
            .ok()?;
        // Node is the WireGuard responder: our static secret + the client's static public.
        self.tunn = Some(PqWgCore::new(node_secret.clone(), PublicKey::from(client_wg_pub), &psk, 2));
        tracing::info!("PQ-WireGuard responder: hybrid PSK derived, Tunn built");
        Some(encode_parts(&[&cts.mlkem_ct, &cts.mceliece_ct]))
    }
}
