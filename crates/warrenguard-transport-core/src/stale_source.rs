//! The answer to an uplink packet the exit can never admit.
//!
//! A socket connected before the tunnel came up keeps the physical interface's
//! address as its source. Once the default route moves onto the TUN, its next
//! packets enter the tunnel with that source, and the exit's anti-spoof gate
//! ([`crate::classify_source`]) drops them. Nothing ever answers: a browser's
//! QUIC session, an SSH session or a streaming connection sits on a path that
//! looks alive until the application's own timeout, which the user sees as
//! "connected, no internet" after every connect. Measured on macOS on
//! 2026-09-29: a connected UDP socket opened before the connect stayed silent
//! for the whole tunnel lifetime and answered again at disconnect.
//!
//! [`reject_stale_source`] turns that silence into the error a router gives:
//! a TCP reset for TCP, which aborts the connection at once on every stack,
//! and an ICMP destination unreachable for anything else, which a connected
//! UDP socket reports on its next call. The application reconnects, and its
//! new socket takes the tunnel's address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::inner_mtu::{build_icmp_error, internet_checksum, is_icmp_error, l4_pseudo_sum};
use crate::ip_parse::SpoofRefusal;

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_MIN_HEADER: usize = 20;
const PROTO_TCP: u8 = 6;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// ICMPv4 destination unreachable, code 1 (host unreachable): a connected
/// socket reports it as `EHOSTUNREACH`.
const ICMPV4_HOST_UNREACHABLE: (u8, u8) = (3, 1);
/// ICMPv6 destination unreachable, code 3 (address unreachable).
const ICMPV6_ADDRESS_UNREACHABLE: (u8, u8) = (1, 3);

/// The packet to write back into the TUN for an uplink packet the exit's
/// anti-spoof gate refuses with `refusal`, or `None` when it must go
/// unanswered.
///
/// Only a source the host could have opened a flow from is answered:
/// [`SpoofRefusal::V4Mismatch`], [`SpoofRefusal::V6Unallocated`] and
/// [`SpoofRefusal::V6Mismatch`]. Link-local chatter and malformed packets
/// belong to no application and stay silent, and so do resets, ICMP errors
/// (the RFC 1122 / RFC 4443 loop guard), non-first fragments and anything
/// sent to or from a multicast, broadcast, unspecified or loopback address.
///
/// A TCP segment is answered by a reset from its destination that the sending
/// socket accepts: the exact acknowledged sequence for a segment carrying an
/// ACK (RFC 5961 section 3), a reset acknowledging the segment otherwise
/// (RFC 9293 section 3.10.7.1). Any other packet is answered by an ICMP
/// destination unreachable from the tunnel gateway, quoting the refused packet.
#[must_use]
pub fn reject_stale_source(
    pkt: &[u8],
    refusal: SpoofRefusal,
    gw_v4: Ipv4Addr,
    gw_v6: Ipv6Addr,
) -> Option<Vec<u8>> {
    match refusal {
        SpoofRefusal::V4Mismatch | SpoofRefusal::V6Unallocated | SpoofRefusal::V6Mismatch => {}
        SpoofRefusal::Malformed | SpoofRefusal::V6LinkLocal => return None,
    }
    if is_icmp_error(pkt) {
        return None;
    }
    let head = Head::parse(pkt)?;
    if !head.answerable() {
        return None;
    }
    if head.proto == PROTO_TCP {
        return tcp_reset(pkt, &head);
    }
    build_icmp_error(
        pkt,
        ICMPV4_HOST_UNREACHABLE,
        ICMPV6_ADDRESS_UNREACHABLE,
        [0; 4],
        gw_v4,
        gw_v6,
    )
}

/// [`reject_stale_source`] preconfigured for the client uplink, answering
/// from the tunnel gateway ([`warrenguard_config::TUNNEL_GATEWAY_IP`] /
/// `_IPV6`) like [`crate::uplink_frag_needed`].
#[must_use]
pub fn uplink_reject_stale_source(pkt: &[u8], refusal: SpoofRefusal) -> Option<Vec<u8>> {
    reject_stale_source(
        pkt,
        refusal,
        warrenguard_config::TUNNEL_GATEWAY_IP,
        warrenguard_config::TUNNEL_GATEWAY_IPV6,
    )
}

/// The addressing of one inner packet, as far as the answer needs it.
struct Head {
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    /// Offset of the transport header, `None` for a non-first fragment.
    l4: Option<usize>,
    /// End of the packet as its IP header declares it, capped at the buffer.
    end: usize,
}

impl Head {
    fn parse(pkt: &[u8]) -> Option<Self> {
        match pkt.first().map(|b| b >> 4) {
            Some(4) => {
                let ihl = usize::from(pkt[0] & 0x0f) * 4;
                if ihl < IPV4_MIN_HEADER || pkt.len() < ihl {
                    return None;
                }
                let src: [u8; 4] = pkt[12..16].try_into().ok()?;
                let dst: [u8; 4] = pkt[16..20].try_into().ok()?;
                let frag_offset = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
                let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
                Some(Self {
                    src: Ipv4Addr::from(src).into(),
                    dst: Ipv4Addr::from(dst).into(),
                    proto: pkt[9],
                    l4: (frag_offset == 0).then_some(ihl),
                    end: total.clamp(ihl, pkt.len()),
                })
            }
            Some(6) => {
                if pkt.len() < IPV6_HEADER {
                    return None;
                }
                let src: [u8; 16] = pkt[8..24].try_into().ok()?;
                let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
                let payload = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
                // Extension headers are not walked: a TCP segment behind one
                // gets an ICMP error instead of a reset, which its socket
                // still reports.
                Some(Self {
                    src: Ipv6Addr::from(src).into(),
                    dst: Ipv6Addr::from(dst).into(),
                    proto: pkt[6],
                    l4: Some(IPV6_HEADER),
                    end: (IPV6_HEADER + payload).min(pkt.len()),
                })
            }
            _ => None,
        }
    }

    fn answerable(&self) -> bool {
        fn unicast(ip: IpAddr) -> bool {
            match ip {
                IpAddr::V4(a) => {
                    !(a.is_multicast() || a.is_broadcast() || a.is_unspecified() || a.is_loopback())
                }
                IpAddr::V6(a) => !(a.is_multicast() || a.is_unspecified() || a.is_loopback()),
            }
        }
        self.l4.is_some() && unicast(self.src) && unicast(self.dst)
    }
}

/// A reset from the segment's destination back to its sender, or `None` for
/// a reset (never answered) or a truncated header.
fn tcp_reset(pkt: &[u8], head: &Head) -> Option<Vec<u8>> {
    let l4 = head.l4?;
    let tcp = pkt.get(l4..l4 + TCP_MIN_HEADER)?;
    let flags = tcp[13];
    if flags & TCP_RST != 0 {
        return None;
    }
    let doff = usize::from(tcp[12] >> 4) * 4;
    let payload_len = head.end.saturating_sub(l4 + doff);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);

    let (rst_seq, rst_ack, rst_flags) = if flags & TCP_ACK != 0 {
        (ack, 0, TCP_RST)
    } else {
        let consumed = u32::try_from(payload_len)
            .unwrap_or(u32::MAX)
            .wrapping_add(u32::from(flags & TCP_SYN != 0))
            .wrapping_add(u32::from(flags & TCP_FIN != 0));
        (0, seq.wrapping_add(consumed), TCP_RST | TCP_ACK)
    };

    let mut seg = [0u8; TCP_MIN_HEADER];
    seg[0..2].copy_from_slice(&tcp[2..4]);
    seg[2..4].copy_from_slice(&tcp[0..2]);
    seg[4..8].copy_from_slice(&rst_seq.to_be_bytes());
    seg[8..12].copy_from_slice(&rst_ack.to_be_bytes());
    seg[12] = 5 << 4;
    seg[13] = rst_flags;
    let seed = l4_pseudo_sum(head.dst, head.src, PROTO_TCP, TCP_MIN_HEADER as u32);
    let ck = internet_checksum(seed, &seg);
    seg[16..18].copy_from_slice(&ck.to_be_bytes());

    let mut out = match (head.dst, head.src) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let mut ip = vec![0u8; IPV4_MIN_HEADER];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&((IPV4_MIN_HEADER + TCP_MIN_HEADER) as u16).to_be_bytes());
            ip[8] = 64;
            ip[9] = PROTO_TCP;
            ip[12..16].copy_from_slice(&from.octets());
            ip[16..20].copy_from_slice(&to.octets());
            let ip_ck = internet_checksum(0, &ip);
            ip[10..12].copy_from_slice(&ip_ck.to_be_bytes());
            ip
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            let mut ip = vec![0u8; IPV6_HEADER];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&(TCP_MIN_HEADER as u16).to_be_bytes());
            ip[6] = PROTO_TCP;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&from.octets());
            ip[24..40].copy_from_slice(&to.octets());
            ip
        }
        _ => return None,
    };
    out.extend_from_slice(&seg);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
    const GW6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0xf, 0x1, 0, 0, 0, 0, 1);
    const HOST: [u8; 4] = [192, 168, 1, 12];
    const SERVER: [u8; 4] = [93, 184, 216, 34];

    fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
        let total = IPV4_MIN_HEADER + l4.len();
        let mut pkt = vec![0u8; IPV4_MIN_HEADER];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        let ck = internet_checksum(0, &pkt);
        pkt[10..12].copy_from_slice(&ck.to_be_bytes());
        pkt.extend_from_slice(l4);
        pkt
    }

    fn v6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; IPV6_HEADER];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(l4.len() as u16).to_be_bytes());
        pkt[6] = proto;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src.octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt.extend_from_slice(l4);
        pkt
    }

    fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut seg = vec![0u8; TCP_MIN_HEADER];
        seg[0..2].copy_from_slice(&sport.to_be_bytes());
        seg[2..4].copy_from_slice(&dport.to_be_bytes());
        seg[4..8].copy_from_slice(&seq.to_be_bytes());
        seg[8..12].copy_from_slice(&ack.to_be_bytes());
        seg[12] = 5 << 4;
        seg[13] = flags;
        seg.extend_from_slice(payload);
        seg
    }

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut seg = vec![0u8; 8];
        seg[0..2].copy_from_slice(&sport.to_be_bytes());
        seg[2..4].copy_from_slice(&dport.to_be_bytes());
        seg[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        seg.extend_from_slice(payload);
        seg
    }

    /// Upper-layer checksum over the pseudo-header and the segment: a valid
    /// packet sums to zero with its stored checksum included.
    fn l4_residual(pkt: &[u8]) -> u16 {
        let (addrs, l4, proto) = if pkt[0] >> 4 == 4 {
            (&pkt[12..20], IPV4_MIN_HEADER, pkt[9])
        } else {
            (&pkt[8..40], IPV6_HEADER, pkt[6])
        };
        let seg = &pkt[l4..];
        let mut seed: u32 = 0;
        for w in addrs.chunks_exact(2) {
            seed += u32::from(u16::from_be_bytes([w[0], w[1]]));
        }
        seed += u32::from(proto) + seg.len() as u32;
        internet_checksum(seed, seg)
    }

    fn be32(b: &[u8]) -> u32 {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    #[test]
    fn an_established_stale_segment_is_answered_with_the_reset_its_socket_accepts() {
        let pkt = v4(
            HOST,
            SERVER,
            PROTO_TCP,
            &tcp(50_000, 443, 1_000, 5_000, TCP_ACK, b"GET"),
        );

        let rst = reject_stale_source(&pkt, SpoofRefusal::V4Mismatch, GW4, GW6)
            .expect("a stale TCP segment is answered");

        assert_eq!(
            &rst[12..16],
            &SERVER,
            "sourced from the segment's destination"
        );
        assert_eq!(&rst[16..20], &HOST, "sent back to the stale source");
        assert_eq!(
            internet_checksum(0, &rst[..IPV4_MIN_HEADER]),
            0,
            "IPv4 header checksum"
        );
        let seg = &rst[IPV4_MIN_HEADER..];
        assert_eq!(u16::from_be_bytes([seg[0], seg[1]]), 443);
        assert_eq!(u16::from_be_bytes([seg[2], seg[3]]), 50_000);
        assert_eq!(be32(&seg[4..8]), 5_000, "exactly the acknowledged sequence");
        assert_eq!(seg[13], TCP_RST);
        assert_eq!(l4_residual(&rst), 0, "TCP checksum");
    }

    #[test]
    fn a_stale_syn_is_refused_with_a_reset_acknowledging_it() {
        let pkt = v4(
            HOST,
            SERVER,
            PROTO_TCP,
            &tcp(50_001, 443, 77, 0, TCP_SYN, &[]),
        );

        let rst = reject_stale_source(&pkt, SpoofRefusal::V4Mismatch, GW4, GW6)
            .expect("a stale SYN is answered");

        let seg = &rst[IPV4_MIN_HEADER..];
        assert_eq!(be32(&seg[4..8]), 0);
        assert_eq!(be32(&seg[8..12]), 78, "acknowledges the SYN");
        assert_eq!(seg[13], TCP_RST | TCP_ACK);
        assert_eq!(l4_residual(&rst), 0);
    }

    #[test]
    fn a_stale_reset_stays_unanswered() {
        let pkt = v4(
            HOST,
            SERVER,
            PROTO_TCP,
            &tcp(50_002, 443, 9, 9, TCP_RST | TCP_ACK, &[]),
        );

        assert!(reject_stale_source(&pkt, SpoofRefusal::V4Mismatch, GW4, GW6).is_none());
    }

    #[test]
    fn a_stale_datagram_is_answered_host_unreachable_from_the_gateway() {
        let pkt = v4(HOST, SERVER, 17, &udp(60_005, 443, b"quic"));

        let icmp = reject_stale_source(&pkt, SpoofRefusal::V4Mismatch, GW4, GW6)
            .expect("a stale datagram is answered");

        assert_eq!(icmp[9], 1, "ICMP");
        assert_eq!(&icmp[12..16], &GW4.octets());
        assert_eq!(&icmp[16..20], &HOST);
        assert_eq!((icmp[20], icmp[21]), ICMPV4_HOST_UNREACHABLE);
        assert_eq!(
            &icmp[28..56],
            &pkt[..28],
            "quotes the header and 8 bytes of UDP"
        );
        assert_eq!(
            internet_checksum(0, &icmp[IPV4_MIN_HEADER..]),
            0,
            "ICMP checksum"
        );
    }

    #[test]
    fn a_stale_ipv6_datagram_is_answered_address_unreachable() {
        let host: Ipv6Addr = "2a01:db8::12".parse().expect("literal");
        let server: Ipv6Addr = "2606:4700::1111".parse().expect("literal");
        let pkt = v6(host, server, 17, &udp(60_006, 443, b"quic"));

        let icmp = reject_stale_source(&pkt, SpoofRefusal::V6Unallocated, GW4, GW6)
            .expect("a stale v6 datagram is answered");

        assert_eq!(icmp[6], 58, "ICMPv6");
        assert_eq!(&icmp[8..24], &GW6.octets());
        assert_eq!(&icmp[24..40], &host.octets());
        assert_eq!((icmp[40], icmp[41]), ICMPV6_ADDRESS_UNREACHABLE);
        assert_eq!(l4_residual(&icmp), 0, "ICMPv6 checksum");
    }

    #[test]
    fn a_stale_ipv6_segment_is_answered_with_a_reset() {
        let host: Ipv6Addr = "2a01:db8::12".parse().expect("literal");
        let server: Ipv6Addr = "2606:4700::1111".parse().expect("literal");
        let pkt = v6(
            host,
            server,
            PROTO_TCP,
            &tcp(50_003, 443, 1, 42, TCP_ACK, &[]),
        );

        let rst = reject_stale_source(&pkt, SpoofRefusal::V6Mismatch, GW4, GW6)
            .expect("a stale v6 segment is answered");

        assert_eq!(&rst[8..24], &server.octets());
        assert_eq!(&rst[24..40], &host.octets());
        assert_eq!(be32(&rst[IPV6_HEADER + 4..IPV6_HEADER + 8]), 42);
        assert_eq!(
            l4_residual(&rst),
            0,
            "TCP checksum over the v6 pseudo-header"
        );
    }

    #[test]
    fn link_local_chatter_and_malformed_packets_stay_unanswered() {
        let pkt = v4(HOST, SERVER, 17, &udp(1, 2, &[]));

        assert!(reject_stale_source(&pkt, SpoofRefusal::V6LinkLocal, GW4, GW6).is_none());
        assert!(reject_stale_source(&pkt, SpoofRefusal::Malformed, GW4, GW6).is_none());
        assert!(reject_stale_source(&[0x45, 0, 0], SpoofRefusal::V4Mismatch, GW4, GW6).is_none());
    }

    #[test]
    fn a_stale_datagram_to_a_multicast_group_stays_unanswered() {
        let pkt = v4(
            [10, 88, 0, 100],
            [239, 255, 255, 250],
            17,
            &udp(60_871, 1900, b"M-SEARCH"),
        );

        assert!(reject_stale_source(&pkt, SpoofRefusal::V4Mismatch, GW4, GW6).is_none());
    }

    #[test]
    fn an_icmp_error_stays_unanswered() {
        let quoted = v4(SERVER, HOST, 17, &udp(443, 60_005, &[]));
        let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&quoted);
        let pkt = v4(HOST, SERVER, 1, &icmp);

        assert!(reject_stale_source(&pkt, SpoofRefusal::V4Mismatch, GW4, GW6).is_none());
    }

    #[test]
    fn a_non_first_fragment_stays_unanswered() {
        let mut pkt = v4(HOST, SERVER, 17, &udp(60_005, 443, b"tail"));
        pkt[6..8].copy_from_slice(&185u16.to_be_bytes());

        assert!(reject_stale_source(&pkt, SpoofRefusal::V4Mismatch, GW4, GW6).is_none());
    }
}
