//! Inner-packet MTU adaptation for reduced-MTU underlay paths.
//!
//! When the QUIC path MTU cannot carry a full-size inner packet inside one
//! datagram (underlay path MTU below ~1350: train/satellite/cellular
//! backhauls, nested tunnels), the datapath silently black-holes full-MSS
//! traffic while small packets pass: the tunnel looks Connected yet no page
//! loads. Two pure remedies, shared by the client
//! pumps and the exit:
//!
//! - [`clamp_syn_mss`]: rewrite the TCP MSS option of SYN/SYN-ACK packets
//!   crossing the tunnel-to-TUN boundary so end-to-end TCP never emits a
//!   segment larger than the live datagram budget. Deterministic, works even
//!   where ICMP is filtered; a no-op whenever the budget already fits the
//!   default inner MTU.
//! - [`build_frag_needed`]: synthesize ICMPv4 Fragmentation-Needed / ICMPv6
//!   Packet-Too-Big toward the sender of a dropped too-large packet, so
//!   non-TCP flows (inner QUIC, UDP) converge via classic PMTUD.
//!
//! Both operate on raw inner IP packets and know nothing about QUIC or the
//! multihop envelope: callers derive `max_inner` from their own live
//! transmit budget (`max_datagram_size()` minus wire-frame overhead).

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_MIN_HEADER: usize = 20;
/// Lowest MSS we will ever clamp DOWN to: clamping below the classic IPv4
/// minimum-reassembly-derived floor would hurt flows that a tunnel this
/// narrow cannot carry anyway.
const MSS_FLOOR: u16 = 536;

/// Largest TCP payload per segment that fits a `max_inner`-sized IP packet
/// (IP header + TCP header subtracted; the sender's own TCP options are
/// accounted for by its stack, which shrinks the payload accordingly).
#[must_use]
pub fn effective_mss(max_inner: u16, v6: bool) -> u16 {
    let hdrs = if v6 { 60 } else { 40 };
    max_inner.saturating_sub(hdrs).max(MSS_FLOOR)
}

/// RFC 1624 incremental internet-checksum update for one 16-bit word.
fn incremental_checksum_update(ck: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!ck) + u32::from(!old) + u32::from(new);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ones-complement internet checksum over `data` (padded with a zero byte
/// when the length is odd).
fn internet_checksum(seed: u32, data: &[u8]) -> u16 {
    let mut sum = seed;
    let mut chunks = data.chunks_exact(2);
    for w in &mut chunks {
        sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Locates the TCP header offset of a SYN-flagged, non-fragmented inner
/// packet. Returns `(tcp_offset, is_v6)`.
fn syn_tcp_offset(pkt: &[u8]) -> Option<(usize, bool)> {
    let first = *pkt.first()?;
    match first >> 4 {
        4 => {
            let ihl = usize::from(first & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER || pkt.len() < ihl + TCP_MIN_HEADER {
                return None;
            }
            if pkt[9] != 6 {
                return None;
            }
            // Fragment offset != 0: not the fragment carrying the header.
            if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff != 0 {
                return None;
            }
            Some((ihl, false))
        }
        6 => {
            if pkt.len() < IPV6_HEADER + TCP_MIN_HEADER {
                return None;
            }
            // Extension-header chains are not walked: a SYN with extension
            // headers is vanishingly rare and skipping it is a safe no-op.
            if pkt[6] != 6 {
                return None;
            }
            Some((IPV6_HEADER, true))
        }
        _ => None,
    }
}

/// Cheap SYN-flag pre-filter so pumps only pay the live-budget lookup for
/// the rare packets [`clamp_syn_mss`] could actually rewrite.
#[must_use]
pub fn is_tcp_syn(pkt: &[u8]) -> bool {
    syn_tcp_offset(pkt)
        .is_some_and(|(tcp, _)| pkt.get(tcp + 13).is_some_and(|flags| flags & 0x02 != 0))
}

/// Clamps the TCP MSS option of an inner SYN/SYN-ACK packet to what fits a
/// `max_inner`-sized packet. Returns `Some((old_mss, new_mss))` when the
/// packet was rewritten (TCP checksum updated in place); `None` for
/// non-TCP, non-SYN, fragmented, malformed, or already-fitting packets.
///
/// Call this at the tunnel-to-TUN boundary with the local transmit budget:
/// the MSS option announces what its sender can *receive*, i.e. it governs
/// the segments that will later cross this node's own transmit direction.
#[must_use]
pub fn clamp_syn_mss(pkt: &mut [u8], max_inner: u16) -> Option<(u16, u16)> {
    let (tcp, v6) = syn_tcp_offset(pkt)?;
    if pkt[tcp + 13] & 0x02 == 0 {
        return None;
    }
    let doff = usize::from(pkt[tcp + 12] >> 4) * 4;
    if doff < TCP_MIN_HEADER || pkt.len() < tcp + doff {
        return None;
    }
    let max_mss = effective_mss(max_inner, v6);
    let mut i = tcp + TCP_MIN_HEADER;
    let end = tcp + doff;
    while i < end {
        match pkt[i] {
            0 => return None,
            1 => i += 1,
            kind => {
                if i + 1 >= end {
                    return None;
                }
                let optlen = usize::from(pkt[i + 1]);
                if optlen < 2 || i + optlen > end {
                    return None;
                }
                if kind == 2 && optlen == 4 {
                    let old = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]);
                    if old <= max_mss {
                        return None;
                    }
                    pkt[i + 2..i + 4].copy_from_slice(&max_mss.to_be_bytes());
                    let ck_at = tcp + 16;
                    let old_ck = u16::from_be_bytes([pkt[ck_at], pkt[ck_at + 1]]);
                    let new_ck = incremental_checksum_update(old_ck, old, max_mss);
                    pkt[ck_at..ck_at + 2].copy_from_slice(&new_ck.to_be_bytes());
                    return Some((old, max_mss));
                }
                i += optlen;
            }
        }
    }
    None
}

/// True when the packet is an ICMP/ICMPv6 *error* message, about which no
/// further ICMP error may be generated (RFC 1122 / RFC 4443 loop guard).
fn is_icmp_error(pkt: &[u8]) -> bool {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            pkt.len() > ihl && pkt[9] == 1 && matches!(pkt[ihl], 3 | 4 | 5 | 11 | 12)
        }
        Some(6) if pkt.len() > IPV6_HEADER => pkt[6] == 58 && pkt[IPV6_HEADER] < 128,
        _ => false,
    }
}

/// Synthesizes the ICMP "packet too big" reply for a dropped too-large
/// inner packet: ICMPv4 type 3 code 4 (Fragmentation Needed) or ICMPv6
/// type 2 (Packet Too Big), destination = the dropped packet's source,
/// source = the tunnel gateway for that family, next-hop MTU =
/// `effective_mtu`. Returns `None` for non-IP input, ICMP errors (loop
/// guard), or non-unicast senders.
///
/// The caller writes the result into its TUN: on the client the local
/// stack lowers its per-destination PMTU; on the exit the packet traverses
/// the kernel forward+NAT path (conntrack marks it `related` and rewrites
/// the embedded quote) toward the origin server.
#[must_use]
pub fn build_frag_needed(
    dropped: &[u8],
    effective_mtu: u16,
    gw_v4: std::net::Ipv4Addr,
    gw_v6: std::net::Ipv6Addr,
) -> Option<Vec<u8>> {
    if is_icmp_error(dropped) {
        return None;
    }
    match dropped.first().map(|b| b >> 4) {
        Some(4) => {
            let ihl = usize::from(dropped[0] & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER || dropped.len() < ihl {
                return None;
            }
            let src: [u8; 4] = dropped[12..16].try_into().ok()?;
            let src_ip = std::net::Ipv4Addr::from(src);
            if src_ip.is_multicast()
                || src_ip.is_broadcast()
                || src_ip.is_unspecified()
                || src_ip.is_loopback()
            {
                return None;
            }
            // RFC 1191: quote the IP header + first 8 bytes of L4.
            let quote_len = (ihl + 8).min(dropped.len());
            let total = IPV4_MIN_HEADER + 8 + quote_len;
            let mut pkt = vec![0u8; total];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            pkt[8] = 64;
            pkt[9] = 1;
            pkt[12..16].copy_from_slice(&gw_v4.octets());
            pkt[16..20].copy_from_slice(&src);
            let ip_ck = internet_checksum(0, &pkt[..IPV4_MIN_HEADER]);
            pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());
            let icmp = IPV4_MIN_HEADER;
            pkt[icmp] = 3;
            pkt[icmp + 1] = 4;
            pkt[icmp + 6..icmp + 8].copy_from_slice(&effective_mtu.to_be_bytes());
            pkt[icmp + 8..icmp + 8 + quote_len].copy_from_slice(&dropped[..quote_len]);
            let icmp_ck = internet_checksum(0, &pkt[icmp..]);
            pkt[icmp + 2..icmp + 4].copy_from_slice(&icmp_ck.to_be_bytes());
            Some(pkt)
        }
        Some(6) => {
            if dropped.len() < IPV6_HEADER {
                return None;
            }
            let src: [u8; 16] = dropped[8..24].try_into().ok()?;
            let src_ip = std::net::Ipv6Addr::from(src);
            if src_ip.is_multicast() || src_ip.is_unspecified() || src_ip.is_loopback() {
                return None;
            }
            // RFC 4443: quote as much of the packet as fits in 1280 bytes.
            let quote_len = dropped.len().min(1280 - IPV6_HEADER - 8);
            let icmp_len = 8 + quote_len;
            let total = IPV6_HEADER + icmp_len;
            let mut pkt = vec![0u8; total];
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
            pkt[6] = 58;
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&gw_v6.octets());
            pkt[24..40].copy_from_slice(&src);
            let icmp = IPV6_HEADER;
            pkt[icmp] = 2;
            pkt[icmp + 4..icmp + 8].copy_from_slice(&u32::from(effective_mtu).to_be_bytes());
            pkt[icmp + 8..icmp + 8 + quote_len].copy_from_slice(&dropped[..quote_len]);
            // ICMPv6 checksum over the pseudo-header + ICMPv6 message.
            let mut seed: u32 = 0;
            for w in pkt[8..40].chunks_exact(2) {
                seed += u32::from(u16::from_be_bytes([w[0], w[1]]));
            }
            seed += icmp_len as u32;
            seed += 58;
            let icmp_ck = internet_checksum(seed, &pkt[icmp..]);
            pkt[icmp + 2..icmp + 4].copy_from_slice(&icmp_ck.to_be_bytes());
            Some(pkt)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const GW4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
    const GW6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0xf, 0x1, 0, 0, 0, 0, 1);

    /// Full TCP checksum over the v4 pseudo-header + segment; a valid
    /// packet sums to zero when its stored checksum is included.
    fn tcp_v4_checksum_residual(pkt: &[u8]) -> u16 {
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        let seg = &pkt[ihl..];
        let mut seed: u32 = 0;
        for w in pkt[12..20].chunks_exact(2) {
            seed += u32::from(u16::from_be_bytes([w[0], w[1]]));
        }
        seed += 6;
        seed += seg.len() as u32;
        internet_checksum(seed, seg)
    }

    fn tcp_v6_checksum_residual(pkt: &[u8]) -> u16 {
        let seg = &pkt[40..];
        let mut seed: u32 = 0;
        for w in pkt[8..40].chunks_exact(2) {
            seed += u32::from(u16::from_be_bytes([w[0], w[1]]));
        }
        seed += 6;
        seed += seg.len() as u32;
        internet_checksum(seed, seg)
    }

    /// Builds a valid IPv4 TCP SYN with the given TCP options (MSS etc.),
    /// with correct IP and TCP checksums.
    fn v4_syn(options: &[u8], flags: u8) -> Vec<u8> {
        assert!(options.len() % 4 == 0);
        let doff = TCP_MIN_HEADER + options.len();
        let total = IPV4_MIN_HEADER + doff;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[93, 184, 216, 34]);
        pkt[16..20].copy_from_slice(&[10, 66, 0, 139]);
        let ck = internet_checksum(0, &pkt[..IPV4_MIN_HEADER]);
        pkt[10..12].copy_from_slice(&ck.to_be_bytes());
        let t = IPV4_MIN_HEADER;
        pkt[t..t + 2].copy_from_slice(&443u16.to_be_bytes());
        pkt[t + 2..t + 4].copy_from_slice(&51000u16.to_be_bytes());
        pkt[t + 12] = ((doff / 4) as u8) << 4;
        pkt[t + 13] = flags;
        pkt[t + 14..t + 16].copy_from_slice(&65535u16.to_be_bytes());
        pkt[t + 20..t + 20 + options.len()].copy_from_slice(options);
        let residual = tcp_v4_checksum_residual(&pkt);
        pkt[t + 16..t + 18].copy_from_slice(&residual.to_be_bytes());
        assert_eq!(
            tcp_v4_checksum_residual(&pkt),
            0,
            "test packet must be valid"
        );
        pkt
    }

    fn v6_syn(options: &[u8], flags: u8) -> Vec<u8> {
        assert!(options.len() % 4 == 0);
        let doff = TCP_MIN_HEADER + options.len();
        let total = IPV6_HEADER + doff;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(doff as u16).to_be_bytes());
        pkt[6] = 6;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1).octets());
        pkt[24..40].copy_from_slice(&GW6.octets());
        let t = IPV6_HEADER;
        pkt[t + 12] = ((doff / 4) as u8) << 4;
        pkt[t + 13] = flags;
        pkt[t + 20..t + 20 + options.len()].copy_from_slice(options);
        let residual = tcp_v6_checksum_residual(&pkt);
        pkt[t + 16..t + 18].copy_from_slice(&residual.to_be_bytes());
        assert_eq!(
            tcp_v6_checksum_residual(&pkt),
            0,
            "test packet must be valid"
        );
        pkt
    }

    #[test]
    fn is_tcp_syn_matches_only_syn_flagged_tcp() {
        assert!(is_tcp_syn(&v4_syn(&linux_syn_options(1460), 0x02)));
        assert!(is_tcp_syn(&v4_syn(&linux_syn_options(1460), 0x12)));
        assert!(is_tcp_syn(&v6_syn(&linux_syn_options(1440), 0x02)));
        // Established segment, UDP, dummy, runt: all false.
        assert!(!is_tcp_syn(&v4_syn(&linux_syn_options(1460), 0x10)));
        let mut udp = v4_syn(&linux_syn_options(1460), 0x02);
        udp[9] = 17;
        assert!(!is_tcp_syn(&udp));
        assert!(!is_tcp_syn(&[0xff; 64]));
        assert!(!is_tcp_syn(&[]));
    }

    /// MSS option surrounded by realistic neighbors: MSS, SACK-permitted,
    /// timestamps, NOP, window scale (Linux SYN layout).
    fn linux_syn_options(mss: u16) -> Vec<u8> {
        let mut o = vec![2, 4, 0, 0];
        o[2..4].copy_from_slice(&mss.to_be_bytes());
        o.extend_from_slice(&[4, 2]); // SACK permitted
        o.extend_from_slice(&[8, 10, 0, 1, 2, 3, 0, 0, 0, 0]); // timestamps
        o.extend_from_slice(&[1]); // NOP
        o.extend_from_slice(&[3, 3, 7]); // window scale
        assert!(o.len() % 4 == 0);
        o
    }

    #[test]
    fn clamps_v4_syn_mss_and_keeps_checksum_valid() {
        let mut pkt = v4_syn(&linux_syn_options(1460), 0x02);
        let r = clamp_syn_mss(&mut pkt, 1198);
        assert_eq!(r, Some((1460, 1158)));
        assert_eq!(
            tcp_v4_checksum_residual(&pkt),
            0,
            "checksum must stay valid"
        );
        // Re-clamp is a no-op (already fitting).
        assert_eq!(clamp_syn_mss(&mut pkt, 1198), None);
    }

    #[test]
    fn clamps_syn_ack_too() {
        let mut pkt = v4_syn(&linux_syn_options(1460), 0x12);
        assert_eq!(clamp_syn_mss(&mut pkt, 1000), Some((1460, 960)));
        assert_eq!(tcp_v4_checksum_residual(&pkt), 0);
    }

    #[test]
    fn clamps_v6_syn_with_60_byte_headers() {
        let mut pkt = v6_syn(&linux_syn_options(1440), 0x02);
        assert_eq!(clamp_syn_mss(&mut pkt, 1198), Some((1440, 1138)));
        assert_eq!(tcp_v6_checksum_residual(&pkt), 0);
    }

    #[test]
    fn leaves_fitting_mss_alone() {
        let mut pkt = v4_syn(&linux_syn_options(1160), 0x02);
        assert_eq!(clamp_syn_mss(&mut pkt, 1200), None);
    }

    #[test]
    fn never_clamps_below_floor() {
        let mut pkt = v4_syn(&linux_syn_options(1460), 0x02);
        assert_eq!(clamp_syn_mss(&mut pkt, 100), Some((1460, MSS_FLOOR)));
        assert_eq!(tcp_v4_checksum_residual(&pkt), 0);
    }

    #[test]
    fn ignores_non_syn_non_tcp_fragments_and_malformed() {
        // Established segment (ACK only).
        let mut ack = v4_syn(&linux_syn_options(1460), 0x10);
        assert_eq!(clamp_syn_mss(&mut ack, 1000), None);
        // UDP.
        let mut udp = v4_syn(&linux_syn_options(1460), 0x02);
        udp[9] = 17;
        assert_eq!(clamp_syn_mss(&mut udp, 1000), None);
        // Non-first fragment.
        let mut frag = v4_syn(&linux_syn_options(1460), 0x02);
        frag[6..8].copy_from_slice(&0x00b9u16.to_be_bytes());
        assert_eq!(clamp_syn_mss(&mut frag, 1000), None);
        // SYN without an MSS option.
        let mut bare = v4_syn(&[1, 1, 1, 1], 0x02);
        assert_eq!(clamp_syn_mss(&mut bare, 1000), None);
        // Truncated runt.
        let mut runt = vec![0x45, 0, 0, 10];
        assert_eq!(clamp_syn_mss(&mut runt, 1000), None);
        // DAITA dummy (non-IP first nibble).
        let mut dummy = vec![0xff; 64];
        assert_eq!(clamp_syn_mss(&mut dummy, 1000), None);
    }

    #[test]
    fn ptb_v4_is_well_formed() {
        let dropped = v4_syn(&linux_syn_options(1460), 0x02);
        let ptb = build_frag_needed(&dropped, 1198, GW4, GW6).expect("ptb");
        assert_eq!(ptb[0] >> 4, 4);
        assert_eq!(ptb[9], 1, "ICMP");
        assert_eq!(&ptb[12..16], &GW4.octets(), "src = tunnel gateway");
        assert_eq!(&ptb[16..20], &dropped[12..16], "dst = dropped src");
        assert_eq!(ptb[20], 3, "dest unreachable");
        assert_eq!(ptb[21], 4, "frag needed");
        assert_eq!(u16::from_be_bytes([ptb[26], ptb[27]]), 1198, "next-hop MTU");
        assert_eq!(&ptb[28..48], &dropped[..20], "quotes the dropped header");
        assert_eq!(internet_checksum(0, &ptb[..20]), 0, "IP checksum valid");
        assert_eq!(internet_checksum(0, &ptb[20..]), 0, "ICMP checksum valid");
    }

    #[test]
    fn ptb_v6_is_well_formed() {
        let dropped = v6_syn(&linux_syn_options(1440), 0x02);
        let ptb = build_frag_needed(&dropped, 1198, GW4, GW6).expect("ptb");
        assert_eq!(ptb[0] >> 4, 6);
        assert_eq!(ptb[6], 58);
        assert_eq!(&ptb[8..24], &GW6.octets());
        assert_eq!(&ptb[24..40], &dropped[8..24]);
        assert_eq!(ptb[40], 2, "packet too big");
        assert_eq!(
            u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]),
            1198
        );
        // Pseudo-header checksum residual must be zero.
        let mut seed: u32 = 0;
        for w in ptb[8..40].chunks_exact(2) {
            seed += u32::from(u16::from_be_bytes([w[0], w[1]]));
        }
        seed += (ptb.len() - 40) as u32;
        seed += 58;
        assert_eq!(internet_checksum(seed, &ptb[40..]), 0);
    }

    #[test]
    fn ptb_never_answers_icmp_errors_or_non_unicast() {
        // ICMPv4 time-exceeded as the dropped packet: no PTB about it.
        let mut icmp_err = vec![0u8; 56];
        icmp_err[0] = 0x45;
        icmp_err[9] = 1;
        icmp_err[12..16].copy_from_slice(&[1, 2, 3, 4]);
        icmp_err[20] = 11;
        assert!(build_frag_needed(&icmp_err, 1198, GW4, GW6).is_none());
        // Echo request IS answered (it is not an error message).
        icmp_err[20] = 8;
        assert!(build_frag_needed(&icmp_err, 1198, GW4, GW6).is_some());
        // Multicast source: never.
        let mut mcast = v4_syn(&linux_syn_options(1460), 0x02);
        mcast[12..16].copy_from_slice(&[224, 0, 0, 1]);
        assert!(build_frag_needed(&mcast, 1198, GW4, GW6).is_none());
        // Non-IP garbage.
        assert!(build_frag_needed(&[0xff; 32], 1198, GW4, GW6).is_none());
        assert!(build_frag_needed(&[], 1198, GW4, GW6).is_none());
    }

    #[test]
    fn ptb_v6_quote_respects_1280_total() {
        let mut big = v6_syn(&linux_syn_options(1440), 0x02);
        big.resize(1500, 0xab);
        let orig_len = (big.len() - IPV6_HEADER) as u16;
        big[4..6].copy_from_slice(&orig_len.to_be_bytes());
        let t = IPV6_HEADER;
        let residual = tcp_v6_checksum_residual(&big);
        let old = u16::from_be_bytes([big[t + 16], big[t + 17]]);
        let fixed = incremental_checksum_update(old, residual, 0);
        let _ = fixed; // payload checksum irrelevant to the builder
        let ptb = build_frag_needed(&big, 1198, GW4, GW6).expect("ptb");
        assert_eq!(ptb.len(), 1280);
    }

    #[test]
    fn incremental_update_matches_full_recompute() {
        let mut pkt = v4_syn(&linux_syn_options(1460), 0x02);
        // Clamp, then verify against a from-scratch checksum.
        clamp_syn_mss(&mut pkt, 1198).expect("clamped");
        let t = IPV4_MIN_HEADER;
        let stored = u16::from_be_bytes([pkt[t + 16], pkt[t + 17]]);
        pkt[t + 16..t + 18].fill(0);
        let residual = tcp_v4_checksum_residual(&pkt);
        assert_eq!(stored, residual);
    }
}
