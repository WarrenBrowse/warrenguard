//! Pure IP-header parsing and the exit-side anti-spoof gate, shared by the pump
//! and the server TUN dispatcher. No allocation, no I/O: just byte slicing over
//! IPv4/IPv6 headers.

use std::net::{Ipv4Addr, Ipv6Addr};

const IPV4_MIN_HEADER: usize = 20;
const IPV6_MIN_HEADER: usize = 40;

/// Source IPv4 address (bytes 12..16), or `None` if the packet is too short or
/// not IPv4.
#[must_use]
pub fn extract_src_ipv4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < IPV4_MIN_HEADER {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let octets: [u8; 4] = pkt[12..16].try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// Source IPv6 address (bytes 8..24), or `None` if the packet is too short or
/// not IPv6.
#[must_use]
pub fn extract_src_ipv6(pkt: &[u8]) -> Option<Ipv6Addr> {
    if pkt.len() < IPV6_MIN_HEADER {
        return None;
    }
    if pkt[0] >> 4 != 6 {
        return None;
    }
    let octets: [u8; 16] = pkt[8..24].try_into().ok()?;
    Some(Ipv6Addr::from(octets))
}

/// Returns `true` if the packet's source IP matches the client's allocated
/// tunnel IP. DAITA dummies (non-IP) pass unconditionally because they are
/// filtered separately by `is_daita_dummy`.
///
/// This is the anti-spoof gate shared by every exit-side uplink path (single-hop
/// pump, single-hop dispatcher, multihop termination): a packet whose inner
/// source IP is not the address the exit allocated to that connection must never
/// reach the TUN, otherwise one tunnel client could impersonate another on the
/// inner subnet. An IPv6 packet from a client without a v6 allocation is rejected
/// (`client_ipv6 == None`).
#[must_use]
pub fn source_ip_matches(pkt: &[u8], client_ipv4: Ipv4Addr, client_ipv6: Option<Ipv6Addr>) -> bool {
    if pkt.is_empty() {
        return false;
    }
    match pkt[0] >> 4 {
        4 => extract_src_ipv4(pkt).is_some_and(|src| src == client_ipv4),
        6 => match client_ipv6 {
            Some(expected) => extract_src_ipv6(pkt).is_some_and(|src| src == expected),
            None => false,
        },
        _ => true, // non-IP (DAITA dummy): pass through, filtered elsewhere
    }
}

/// Destination IPv4 address (bytes 16..20), or `None` if the packet is too short
/// or not IPv4.
#[must_use]
pub fn extract_dst_ipv4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < IPV4_MIN_HEADER {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let octets: [u8; 4] = pkt[16..20].try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// Destination IPv6 address (bytes 24..40), or `None` if the packet is too short
/// or not IPv6.
#[must_use]
pub fn extract_dst_ipv6(pkt: &[u8]) -> Option<Ipv6Addr> {
    if pkt.len() < IPV6_MIN_HEADER {
        return None;
    }
    if pkt[0] >> 4 != 6 {
        return None;
    }
    let octets: [u8; 16] = pkt[24..40].try_into().ok()?;
    Some(Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&1234u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
        pkt
    }

    fn make_ipv6_packet(src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60;
        pkt[6] = 6;
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt[40..42].copy_from_slice(&1234u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&80u16.to_be_bytes());
        pkt
    }

    #[test]
    fn extract_dst_ipv4_valid_packet() {
        let pkt = make_ipv4_packet([192, 168, 1, 1], [10, 66, 0, 5]);
        assert_eq!(extract_dst_ipv4(&pkt), Some(Ipv4Addr::new(10, 66, 0, 5)));
    }

    #[test]
    fn extract_dst_ipv4_too_short() {
        assert_eq!(extract_dst_ipv4(&[0x45; 19]), None);
    }

    #[test]
    fn extract_dst_ipv4_ipv6_returns_none() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        assert_eq!(extract_dst_ipv4(&pkt), None);
    }

    #[test]
    fn extract_dst_ipv4_daita_dummy_returns_none() {
        let pkt = vec![0xFFu8; 40];
        assert_eq!(extract_dst_ipv4(&pkt), None);
    }

    #[test]
    fn extract_dst_ipv6_valid_packet() {
        let dst = [0xfd, 0xcc, 0, 0xf, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        let pkt = make_ipv6_packet([0; 16], dst);
        assert_eq!(extract_dst_ipv6(&pkt), Some(Ipv6Addr::from(dst)));
    }

    #[test]
    fn extract_dst_ipv6_too_short() {
        assert_eq!(extract_dst_ipv6(&[0x60; 39]), None);
    }

    #[test]
    fn extract_dst_ipv6_ipv4_returns_none() {
        let pkt = make_ipv4_packet([10, 0, 0, 1], [10, 66, 0, 2]);
        assert_eq!(extract_dst_ipv6(&pkt), None);
    }

    #[test]
    fn extract_src_ipv4_valid_packet() {
        let pkt = make_ipv4_packet([192, 168, 1, 42], [10, 66, 0, 5]);
        assert_eq!(
            extract_src_ipv4(&pkt),
            Some(Ipv4Addr::new(192, 168, 1, 42)),
            "must extract source IP from bytes 12..16"
        );
    }

    #[test]
    fn extract_src_ipv4_too_short() {
        assert_eq!(extract_src_ipv4(&[0x45; 15]), None);
    }

    #[test]
    fn extract_src_ipv4_rejects_ipv6() {
        let pkt = make_ipv6_packet([0; 16], [0; 16]);
        assert_eq!(extract_src_ipv4(&pkt), None);
    }

    #[test]
    fn extract_src_ipv6_valid_packet() {
        let src = [0xfd, 0xcc, 0, 0xf, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42];
        let pkt = make_ipv6_packet(src, [0; 16]);
        assert_eq!(
            extract_src_ipv6(&pkt),
            Some(Ipv6Addr::from(src)),
            "must extract source IP from bytes 8..24"
        );
    }

    #[test]
    fn extract_src_ipv6_too_short() {
        assert_eq!(extract_src_ipv6(&[0x60; 23]), None);
    }

    #[test]
    fn extract_src_ipv6_rejects_ipv4() {
        let pkt = make_ipv4_packet([10, 0, 0, 1], [10, 66, 0, 2]);
        assert_eq!(extract_src_ipv6(&pkt), None);
    }

    #[test]
    fn source_ip_matches_ipv4_correct() {
        let client_ip = Ipv4Addr::new(10, 66, 0, 5);
        let pkt = make_ipv4_packet([10, 66, 0, 5], [8, 8, 8, 8]);
        assert!(
            source_ip_matches(&pkt, client_ip, None),
            "packet with matching source must pass"
        );
    }

    #[test]
    fn source_ip_matches_ipv4_spoofed() {
        let client_ip = Ipv4Addr::new(10, 66, 0, 5);
        let pkt = make_ipv4_packet([10, 66, 0, 99], [8, 8, 8, 8]);
        assert!(
            !source_ip_matches(&pkt, client_ip, None),
            "packet with wrong source IP must be rejected"
        );
    }

    #[test]
    fn source_ip_matches_ipv6_correct() {
        let client_ip = Ipv4Addr::new(10, 66, 0, 5);
        let client_ipv6 = Ipv6Addr::from([0xfd, 0xcc, 0, 0xf, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        let pkt = make_ipv6_packet(client_ipv6.octets(), [0; 16]);
        assert!(
            source_ip_matches(&pkt, client_ip, Some(client_ipv6)),
            "IPv6 packet with matching source must pass"
        );
    }

    #[test]
    fn source_ip_matches_ipv6_spoofed() {
        let client_ip = Ipv4Addr::new(10, 66, 0, 5);
        let client_ipv6 = Ipv6Addr::from([0xfd, 0xcc, 0, 0xf, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]);
        let spoofed_src = [0xfd, 0xcc, 0, 0xf, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99];
        let pkt = make_ipv6_packet(spoofed_src, [0; 16]);
        assert!(
            !source_ip_matches(&pkt, client_ip, Some(client_ipv6)),
            "IPv6 packet with wrong source must be rejected"
        );
    }

    #[test]
    fn source_ip_matches_ipv6_without_allocation_drops() {
        let client_ip = Ipv4Addr::new(10, 66, 0, 5);
        let src = [0xfd, 0xcc, 0, 0xf, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        let pkt = make_ipv6_packet(src, [0; 16]);
        assert!(
            !source_ip_matches(&pkt, client_ip, None),
            "IPv6 packet must be rejected when client has no IPv6 allocation"
        );
    }

    #[test]
    fn source_ip_matches_truncated_drops() {
        let client_ip = Ipv4Addr::new(10, 66, 0, 5);
        assert!(
            !source_ip_matches(&[0x45; 10], client_ip, None),
            "truncated packet must be rejected"
        );
    }

    #[test]
    fn source_ip_matches_daita_dummy_passes() {
        let client_ip = Ipv4Addr::new(10, 66, 0, 5);
        let pkt = vec![0xFFu8; 40];
        assert!(
            source_ip_matches(&pkt, client_ip, None),
            "DAITA dummies must pass (they are filtered separately)"
        );
    }
}
