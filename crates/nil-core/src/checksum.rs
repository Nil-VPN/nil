//! IPv4/IPv6 + TCP/UDP/ICMPv6 checksum finalization.
//!
//! Packets read from a TUN device can carry *incomplete* L4 checksums: when the kernel
//! forwards a packet and expects hardware offload to finish the checksum (CHECKSUM_PARTIAL),
//! userspace reads the packet with only the pseudo-header partial in the checksum field.
//! Relaying that to a peer (which validates checksums) gets it dropped. Before we send a
//! TUN-read packet across the tunnel we finalize its checksums here. Idempotent: a packet
//! that is already correct is rewritten to the same bytes.

/// Finalize L4 checksums for either IP version (dispatch on the version nibble). Use this on
/// the datapath so an IPv6 tunnel doesn't relay packets with unfinished checksums.
pub fn fix_l4_checksums(pkt: &mut [u8]) {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => fix_ipv4_checksums(pkt),
        Some(6) => fix_ipv6_checksums(pkt),
        _ => {}
    }
}

/// Recompute the IPv4 header checksum and the TCP/UDP checksum in place. No-op for
/// non-IPv4 packets or anything too short to parse (Phase 1 tunnels IPv4 only).
pub fn fix_ipv4_checksums(pkt: &mut [u8]) {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return;
    }

    // IPv4 header checksum (zero the field, then sum the header).
    pkt[10] = 0;
    pkt[11] = 0;
    let ip_csum = ones_complement(&pkt[..ihl], 0);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    let proto = pkt[9];
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let end = total_len.min(pkt.len());
    if end <= ihl {
        return;
    }
    // TCP checksum is 16 bytes into the segment; UDP's is 6.
    let csum_off = match proto {
        6 => 16,
        17 => 6,
        _ => return,
    };
    let l4_len = end - ihl;
    if l4_len < csum_off + 2 {
        return;
    }
    pkt[ihl + csum_off] = 0;
    pkt[ihl + csum_off + 1] = 0;

    // Pseudo-header: src(4) + dst(4) + zero + proto + L4 length.
    let mut sum: u32 = 0;
    for c in pkt[12..20].chunks(2) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    sum += proto as u32;
    sum += l4_len as u32;

    let mut csum = ones_complement(&pkt[ihl..end], sum);
    if proto == 17 && csum == 0 {
        csum = 0xffff; // UDP: a computed 0 is transmitted as 0xffff (RFC 768)
    }
    pkt[ihl + csum_off..ihl + csum_off + 2].copy_from_slice(&csum.to_be_bytes());
}

/// Recompute the TCP/UDP/ICMPv6 checksum of an IPv6 packet in place. IPv6 has no header
/// checksum, so only the L4 checksum is rewritten. No-op for non-IPv6 packets, anything too
/// short, or a packet whose first Next Header is an extension header rather than TCP/UDP/ICMPv6
/// (tunneled traffic rarely carries extension headers; we conservatively skip those).
pub fn fix_ipv6_checksums(pkt: &mut [u8]) {
    const HDR: usize = 40;
    if pkt.len() < HDR || (pkt[0] >> 4) != 6 {
        return;
    }
    let next_header = pkt[6];
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    // Offset of the checksum field within the L4 header: TCP 16, UDP 6, ICMPv6 2.
    let csum_off = match next_header {
        6 => 16,
        17 => 6,
        58 => 2,
        _ => return, // extension header or unsupported upper layer
    };
    let end = (HDR + payload_len).min(pkt.len());
    if end <= HDR {
        return;
    }
    let l4_len = end - HDR;
    if l4_len < csum_off + 2 {
        return;
    }
    pkt[HDR + csum_off] = 0;
    pkt[HDR + csum_off + 1] = 0;

    // Pseudo-header (RFC 8200 §8.1): src(16) + dst(16) + u32 upper-layer length + 3 zero + NH.
    let mut sum: u32 = 0;
    for c in pkt[8..HDR].chunks(2) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    sum += (l4_len as u32) >> 16;
    sum += (l4_len as u32) & 0xffff;
    sum += next_header as u32;

    let mut csum = ones_complement(&pkt[HDR..end], sum);
    // UDP and ICMPv6 over IPv6 MUST carry a non-zero checksum (RFC 8200 §8.1 / RFC 4443).
    if (next_header == 17 || next_header == 58) && csum == 0 {
        csum = 0xffff;
    }
    pkt[HDR + csum_off..HDR + csum_off + 2].copy_from_slice(&csum.to_be_bytes());
}

/// 16-bit one's-complement checksum over `data`, seeded with `initial` (the pseudo-header
/// sum for L4, or 0 for the IP header).
fn ones_complement(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixes_a_known_tcp_packet() {
        // IPv4 + TCP SYN, 40 bytes (20 IP + 20 TCP), checksums zeroed.
        let mut pkt = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, // IP hdr
            10, 0, 0, 2, 1, 1, 1, 1, // src 10.0.0.2, dst 1.1.1.1
            0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00,
        ];
        fix_ipv4_checksums(&mut pkt);
        // IP header checksum must now verify (full-header sum == 0).
        assert_eq!(ones_complement(&pkt[..20], 0), 0);
        // TCP checksum field is non-zero after fixing.
        assert_ne!(&pkt[36..38], &[0, 0]);
        // Idempotent: running again yields the same bytes.
        let again = {
            let mut p = pkt.clone();
            fix_ipv4_checksums(&mut p);
            p
        };
        assert_eq!(again, pkt);
    }

    #[test]
    fn ignores_non_ipv4() {
        let mut v6 = vec![0x60u8; 40];
        let before = v6.clone();
        fix_ipv4_checksums(&mut v6);
        assert_eq!(v6, before);
    }

    /// A minimal IPv6 + UDP packet (40 IPv6 + 8 UDP), checksum zeroed.
    fn ipv6_udp() -> Vec<u8> {
        let mut p = vec![
            0x60, 0x00, 0x00, 0x00, // version 6, TC/flow 0
            0x00, 0x08, // payload length = 8 (UDP header)
            17,   // next header = UDP
            0x40, // hop limit
        ];
        p.extend_from_slice(&[0x20, 0x01, 0xdb, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
        p.extend_from_slice(&[0x20, 0x01, 0xdb, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // dst
        p.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]); // UDP, csum 0
        p
    }

    #[test]
    fn fixes_an_ipv6_udp_packet_and_is_idempotent() {
        let mut pkt = ipv6_udp();
        fix_ipv6_checksums(&mut pkt);
        // UDP-over-IPv6 must carry a non-zero checksum.
        assert_ne!(&pkt[46..48], &[0, 0], "IPv6 UDP checksum must be set");
        // Idempotent.
        let mut again = pkt.clone();
        fix_ipv6_checksums(&mut again);
        assert_eq!(again, pkt);
    }

    #[test]
    fn dispatcher_routes_by_version() {
        // v4 packet → IPv4 path sets the header checksum; v6 packet → IPv6 path sets the L4 csum.
        let mut v6 = ipv6_udp();
        fix_l4_checksums(&mut v6);
        assert_ne!(&v6[46..48], &[0, 0]);

        let mut v4 = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 2, 1,
            1, 1, 1, 0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];
        fix_l4_checksums(&mut v4);
        assert_eq!(
            ones_complement(&v4[..20], 0),
            0,
            "IPv4 header checksum verifies"
        );
    }
}
