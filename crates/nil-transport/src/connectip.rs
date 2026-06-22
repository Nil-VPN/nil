//! RFC 9484 CONNECT-IP datagram framing — the byte-exact contract shared by the client
//! [`MasqueTransport`](crate::masque) and the `nil-node` server.
//!
//! An HTTP Datagram payload on a CONNECT-IP flow is `varint(context_id) || data`
//! (RFC 9297 + RFC 9484 §6). Context id **0** means "a full, uncompressed IP packet".
//! Phase 1 uses only context 0.
//!
//! quiche 0.22 exposes only transport-level `Connection::dgram_send`/`dgram_recv` (there is
//! no `h3::send_dgram`/`recv_dgram` helper), so we frame the **whole** H3 datagram ourselves:
//! `varint(flow_id) || varint(context_id) || ip`, where `flow_id = stream_id / 4`
//! (quarter-stream-id, RFC 9297). [`encode_datagram`]/[`decode_datagram`] are the functions
//! the transport and node actually hand to `dgram_send`/`dgram_recv`. The lower-level
//! [`encode`]/[`decode`] handle just the `[context-id | ip]` portion (useful for the H2
//! capsule path, where the flow-id is absent). The module is pure (no quiche, no async) and
//! depends only on `nil-core`, so client and node can never drift.

use nil_core::{Error, Result};

/// Context ID for a full IP packet (RFC 9484 §6). The only context used in Phase 1.
pub const CONTEXT_ID_IP_PACKET: u64 = 0;

/// The CONNECT-IP `:path` template for an unrestricted full tunnel (RFC 9484 §3).
/// Both client and node reference this one constant so the handshake can't drift.
pub const IP_FULL_TUNNEL_TEMPLATE: &str = "/.well-known/masque/ip/*/*/";

/// HTTP/3 request header carrying the client's RA-TLS freshness nonce (lowercase hex). The
/// node binds it into its attestation report's `report_data` (architecture spec §5).
pub const ATTEST_NONCE_HEADER: &str = "nil-attest-nonce";

/// HTTP/3 response header carrying the node's attestation evidence (lowercase hex of the
/// `[tag][parts]` blob), bound to the node's TLS key + the client nonce and appraised by
/// `nil-attest` before the tunnel is accepted.
pub const ATTEST_REPORT_HEADER: &str = "nil-attest-report";

/// Largest QUIC varint, `2^62 - 1` (RFC 9000 §16).
pub const MAX_VARINT: u64 = (1u64 << 62) - 1;

/// Worst-case bytes [`encode_datagram`] prepends to an IP packet: an 8-byte flow-id varint
/// plus the 1-byte context-id. The datapath subtracts this from the negotiated datagram
/// payload to pick a safe TUN MTU.
pub const MAX_FRAMING_OVERHEAD: usize = 8 + 1;

/// Encode an IP packet into a CONNECT-IP HTTP Datagram payload: `[ varint(0) | ip ]`.
/// Context 0 encodes to a single `0x00` byte, so the result is `1 + ip.len()` bytes.
pub fn encode(ip: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ip.len() + 1);
    encode_varint(CONTEXT_ID_IP_PACKET, &mut out);
    out.extend_from_slice(ip);
    out
}

/// Encode into a caller-provided buffer to avoid a per-packet allocation on the hot path.
/// Returns the number of bytes written, or [`Error::InvalidPacket`] if `dst` is too small.
pub fn encode_into(ip: &[u8], dst: &mut [u8]) -> Result<usize> {
    let ctx_len = varint_len(CONTEXT_ID_IP_PACKET);
    let needed = ctx_len + ip.len();
    if dst.len() < needed {
        return Err(Error::InvalidPacket(format!(
            "datagram buffer too small: need {needed}, have {}",
            dst.len()
        )));
    }
    // context-id 0 fits in one byte; write it directly, then the packet.
    let mut tmp = [0u8; 8];
    let n = write_varint(CONTEXT_ID_IP_PACKET, &mut tmp);
    dst[..n].copy_from_slice(&tmp[..n]);
    dst[n..needed].copy_from_slice(ip);
    Ok(needed)
}

/// Decode a CONNECT-IP HTTP Datagram payload back to the IP packet bytes (borrowed, no copy).
/// A non-zero context id is unsupported in Phase 1; the caller should drop+count, not panic
/// (RFC 9484 permits a receiver to discard datagrams with unknown context ids).
pub fn decode(payload: &[u8]) -> Result<&[u8]> {
    let (ctx, rest) =
        decode_varint(payload).ok_or_else(|| Error::InvalidPacket("truncated context-id".into()))?;
    if ctx != CONTEXT_ID_IP_PACKET {
        return Err(Error::InvalidPacket(format!("unsupported context id {ctx}")));
    }
    Ok(rest)
}

/// Encode a full H3 CONNECT-IP datagram for `Connection::dgram_send`:
/// `varint(flow_id) || varint(context_id=0) || ip`. `flow_id` is the quarter-stream-id
/// (`stream_id / 4`) of the CONNECT-IP request stream.
pub fn encode_datagram(flow_id: u64, ip: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ip.len() + 2);
    encode_varint(flow_id, &mut out);
    encode_varint(CONTEXT_ID_IP_PACKET, &mut out);
    out.extend_from_slice(ip);
    out
}

/// Decode a full H3 datagram (as returned by `Connection::dgram_recv`) into
/// `(flow_id, ip)`. Validates the context id is 0 (full IP packet).
pub fn decode_datagram(buf: &[u8]) -> Result<(u64, &[u8])> {
    let (flow_id, rest) =
        decode_varint(buf).ok_or_else(|| Error::InvalidPacket("truncated flow-id".into()))?;
    let ip = decode(rest)?;
    Ok((flow_id, ip))
}

// ---- QUIC variable-length integers (RFC 9000 §16) ----

/// Number of bytes the QUIC varint encoding of `v` occupies.
fn varint_len(v: u64) -> usize {
    match v {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

/// Write `v` as a QUIC varint into `buf` (must be >= 8 bytes); returns bytes written.
fn write_varint(v: u64, buf: &mut [u8; 8]) -> usize {
    debug_assert!(v <= MAX_VARINT, "value exceeds 62-bit QUIC varint range");
    match varint_len(v) {
        1 => {
            buf[0] = v as u8; // top 2 bits 00
            1
        }
        2 => {
            let b = (v as u16) | 0x4000; // top 2 bits 01
            buf[..2].copy_from_slice(&b.to_be_bytes());
            2
        }
        4 => {
            let b = (v as u32) | 0x8000_0000; // top 2 bits 10
            buf[..4].copy_from_slice(&b.to_be_bytes());
            4
        }
        _ => {
            let b = v | 0xc000_0000_0000_0000; // top 2 bits 11
            buf[..8].copy_from_slice(&b.to_be_bytes());
            8
        }
    }
}

fn encode_varint(v: u64, out: &mut Vec<u8>) {
    let mut buf = [0u8; 8];
    let n = write_varint(v, &mut buf);
    out.extend_from_slice(&buf[..n]);
}

/// Decode a QUIC varint from the front of `buf`. Returns `(value, remainder)` or `None`
/// if `buf` is truncated.
fn decode_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6); // 00→1, 01→2, 10→4, 11→8
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | b as u64;
    }
    Some((val, &buf[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_zero_is_single_byte_then_packet() {
        let ip = [0x45u8, 0x00, 0x00, 0x14, 0xde, 0xad];
        let framed = encode(&ip);
        assert_eq!(framed[0], 0x00, "context 0 is one 0x00 byte");
        assert_eq!(&framed[1..], &ip, "packet follows verbatim");
        assert_eq!(framed.len(), ip.len() + 1);
    }

    #[test]
    fn round_trip() {
        let ip = b"\x45\x00\x00\x28 a full-ish ip packet payload".to_vec();
        let framed = encode(&ip);
        assert_eq!(decode(&framed).expect("decode"), &ip[..]);
    }

    #[test]
    fn encode_into_matches_encode() {
        let ip = [1u8, 2, 3, 4, 5];
        let mut buf = [0u8; 16];
        let n = encode_into(&ip, &mut buf).expect("fits");
        assert_eq!(&buf[..n], &encode(&ip)[..]);
    }

    #[test]
    fn encode_into_rejects_small_buffer() {
        let ip = [0u8; 100];
        let mut buf = [0u8; 8];
        assert!(encode_into(&ip, &mut buf).is_err());
    }

    #[test]
    fn datagram_round_trip_with_flow_id() {
        let ip = b"\x45\x00\x00\x3c hello tunnel".to_vec();
        for flow_id in [0u64, 1, 63, 64, 16_383, 16_384] {
            let dg = encode_datagram(flow_id, &ip);
            let (got_flow, got_ip) = decode_datagram(&dg).expect("decode datagram");
            assert_eq!(got_flow, flow_id);
            assert_eq!(got_ip, &ip[..]);
        }
    }

    #[test]
    fn decode_rejects_unknown_context() {
        // context id 1 → first varint byte 0x01, then "ip".
        let payload = [0x01u8, 0xaa, 0xbb];
        assert!(decode(&payload).is_err());
    }

    #[test]
    fn decode_rejects_empty() {
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn varint_boundaries_round_trip() {
        for v in [0u64, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fff_ffff, 0x4000_0000, MAX_VARINT] {
            let mut out = Vec::new();
            encode_varint(v, &mut out);
            assert_eq!(out.len(), varint_len(v));
            let (got, rest) = decode_varint(&out).expect("decode varint");
            assert_eq!(got, v);
            assert!(rest.is_empty());
        }
    }
}
