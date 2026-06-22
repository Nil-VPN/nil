//! Minimal userspace IPv4/UDP encapsulation for nested tunnels (architecture spec §6).
//!
//! To build a trust-split onion, an inner MASQUE tunnel's QUIC packets must travel *through*
//! an outer CONNECT-IP tunnel, which carries IP packets. So the inner QUIC is wrapped in a
//! UDP datagram inside an IPv4 packet addressed to the next hop; the outer node forwards it as
//! ordinary IP traffic (NAT), and the next hop sees a normal QUIC connection from the previous
//! node — never the original client. This is just enough IP/UDP to carry the payload; checksums
//! are finalized by [`nil_core::checksum`].

use std::net::{Ipv4Addr, SocketAddrV4};

const IPV4_HDR: usize = 20;
const UDP_HDR: usize = 8;
const PROTO_UDP: u8 = 17;

/// Wrap `payload` (an inner QUIC packet) in an IPv4+UDP packet from `src` to `dst`.
pub fn wrap(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let total = IPV4_HDR + UDP_HDR + payload.len();
    let mut p = vec![0u8; total];
    // IPv4 header.
    p[0] = 0x45; // version 4, IHL 5 (no options)
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40; // Don't Fragment
    p[8] = 64; // TTL
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&src.ip().octets());
    p[16..20].copy_from_slice(&dst.ip().octets());
    // UDP header.
    p[20..22].copy_from_slice(&src.port().to_be_bytes());
    p[22..24].copy_from_slice(&dst.port().to_be_bytes());
    p[24..26].copy_from_slice(&((UDP_HDR + payload.len()) as u16).to_be_bytes());
    // Checksums left zero, then finalized.
    p[28..].copy_from_slice(payload);
    nil_core::checksum::fix_ipv4_checksums(&mut p);
    p
}

/// Strip the IPv4+UDP headers off `pkt`, returning `(src, dst, payload)`. `None` if it isn't a
/// well-formed IPv4 UDP packet.
pub fn unwrap(pkt: &[u8]) -> Option<(SocketAddrV4, SocketAddrV4, Vec<u8>)> {
    if pkt.len() < IPV4_HDR || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < IPV4_HDR || pkt[9] != PROTO_UDP || pkt.len() < ihl + UDP_HDR {
        return None;
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    let udp_len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;
    if udp_len < UDP_HDR || pkt.len() < ihl + udp_len {
        return None;
    }
    let payload = pkt[ihl + UDP_HDR..ihl + udp_len].to_vec();
    Some((
        SocketAddrV4::new(src_ip, src_port),
        SocketAddrV4::new(dst_ip, dst_port),
        payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trips() {
        let src = "192.0.2.1:51820".parse().unwrap();
        let dst = "10.80.0.11:443".parse().unwrap();
        let payload = b"a quic packet payload \x00\x01\x02\xff";
        let pkt = wrap(src, dst, payload);
        // 20 (IPv4) + 8 (UDP) + payload.
        assert_eq!(pkt.len(), 28 + payload.len());
        assert_eq!(pkt[9], PROTO_UDP);
        let (s, d, p) = unwrap(&pkt).expect("valid packet");
        assert_eq!(s, src);
        assert_eq!(d, dst);
        assert_eq!(p, payload);
    }

    #[test]
    fn rejects_non_udp_or_truncated() {
        assert!(unwrap(b"short").is_none());
        let mut pkt = wrap("192.0.2.1:1".parse().unwrap(), "192.0.2.2:2".parse().unwrap(), b"x");
        pkt[9] = 6; // TCP, not UDP
        assert!(unwrap(&pkt).is_none());
    }
}
