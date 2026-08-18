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

/// Why the anti-spoof gate could not match a packet's inner source against
/// the address its connection was assigned.
///
/// The set is closed on purpose and carries no `_` escape: the exit's drop
/// accounting matches on it exhaustively, so a new class cannot be added
/// without also being given a counter. Every variant describes a property of
/// the PACKET, never of who sent it, which is what makes it safe to expose as
/// a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoofRefusal {
    /// The version nibble claims IPv4 or IPv6 but the packet is too short to
    /// carry the source address that version puts at that offset.
    Malformed,
    /// An IPv4 packet sourced from some other address than the one this
    /// connection was assigned. The gate exists for exactly this.
    V4Mismatch,
    /// An IPv6 packet sourced from `fe80::/10` or from the unspecified
    /// address: the client's own on-link stack chatter (neighbour discovery,
    /// duplicate-address detection, MLD reports). Never routable, so it is
    /// not an impersonation attempt and would be dropped even on a session
    /// that HAS a v6 allocation.
    V6LinkLocal,
    /// A routable IPv6 packet on a session the exit granted no v6 address to.
    /// The gate has nothing to compare against, so it can only refuse.
    V6Unallocated,
    /// A routable IPv6 packet on a dual-stack session, sourced from some
    /// other address than the one granted.
    V6Mismatch,
}

/// `fe80::/10`, the link-local unicast prefix. Hand-rolled because
/// `Ipv6Addr::is_unicast_link_local` is still unstable.
fn is_link_local_ipv6(addr: Ipv6Addr) -> bool {
    let o = addr.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

/// Anti-spoof verdict on one decrypted uplink packet: `None` admits it,
/// `Some(refusal)` names why it cannot be admitted.
///
/// This is the anti-spoof gate shared by every exit-side uplink path (the exit
/// dispatcher and multihop termination): a packet whose inner source IP is not
/// the address the exit allocated to that connection must never reach the TUN,
/// otherwise one tunnel client could impersonate another on the inner subnet.
/// DAITA dummies (non-IP) are admitted here because they are filtered
/// separately by `is_daita_dummy`.
///
/// The refusal is classified rather than merged into one verdict because the
/// classes have opposite meanings: `V4Mismatch` is the attack the gate was
/// built for, while `V6LinkLocal` is a client's own stack talking to a link
/// that does not exist. Reporting both as "spoofed source" made a benign,
/// universal packet class read as an attack for months (2026-08-02).
#[must_use]
pub fn classify_source(
    pkt: &[u8],
    client_ipv4: Ipv4Addr,
    client_ipv6: Option<Ipv6Addr>,
) -> Option<SpoofRefusal> {
    if pkt.is_empty() {
        return Some(SpoofRefusal::Malformed);
    }
    match pkt[0] >> 4 {
        4 => match extract_src_ipv4(pkt) {
            None => Some(SpoofRefusal::Malformed),
            Some(src) if src == client_ipv4 => None,
            Some(_) => Some(SpoofRefusal::V4Mismatch),
        },
        6 => match extract_src_ipv6(pkt) {
            None => Some(SpoofRefusal::Malformed),
            Some(src) if src.is_unspecified() || is_link_local_ipv6(src) => {
                Some(SpoofRefusal::V6LinkLocal)
            }
            Some(src) => match client_ipv6 {
                None => Some(SpoofRefusal::V6Unallocated),
                Some(expected) if src == expected => None,
                Some(_) => Some(SpoofRefusal::V6Mismatch),
            },
        },
        _ => None, // non-IP (DAITA dummy): pass through, filtered elsewhere
    }
}

/// Returns `true` if the packet's source IP matches the client's allocated
/// tunnel IP: [`classify_source`] reduced to its admit/refuse bit, for the
/// callers that do not account for the reason.
#[must_use]
pub fn source_ip_matches(pkt: &[u8], client_ipv4: Ipv4Addr, client_ipv6: Option<Ipv6Addr>) -> bool {
    classify_source(pkt, client_ipv4, client_ipv6).is_none()
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

/// The inner subnet an exit allocates its clients from, and the gateway
/// address inside it. Carried by value into a pump, so the destination gate
/// reads no lock and no allocator on the datapath.
///
/// Generic on purpose: the engine holds no Warren address literal. A
/// deployer's own pool is whatever its allocator was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelPool {
    v4_network: Ipv4Addr,
    v4_prefix_len: u8,
    v4_gateway: Ipv4Addr,
    /// `/64` prefix and its gateway, on a dual-stack exit.
    v6: Option<(Ipv6Addr, Ipv6Addr)>,
}

impl TunnelPool {
    /// The v4 half, which every exit has: the network the allocator hands
    /// addresses out of, its prefix length, and the gateway address the
    /// exit-side TUN owns.
    #[must_use]
    pub const fn new(v4_network: Ipv4Addr, v4_prefix_len: u8, v4_gateway: Ipv4Addr) -> Self {
        Self {
            v4_network,
            v4_prefix_len,
            v4_gateway,
            v6: None,
        }
    }

    /// Add the `/64` half of a dual-stack exit.
    #[must_use]
    pub const fn with_v6(mut self, network: Ipv6Addr, gateway: Ipv6Addr) -> Self {
        self.v6 = Some((network, gateway));
        self
    }

    /// `true` when `addr` is inside the v4 pool prefix.
    fn holds_v4(&self, addr: Ipv4Addr) -> bool {
        // A shift of 32 is undefined, so a /0 pool is answered directly
        // rather than by masking.
        if self.v4_prefix_len == 0 {
            return true;
        }
        if self.v4_prefix_len > 32 {
            return false;
        }
        let mask = u32::MAX << (32 - self.v4_prefix_len);
        (u32::from(addr) & mask) == (u32::from(self.v4_network) & mask)
    }
}

/// Why the destination gate refused an uplink packet. The set is closed and
/// carries no `_` escape, same reason as [`SpoofRefusal`]: the exit's drop
/// accounting matches on it exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolRefusal {
    /// An IPv4 packet addressed into the pool, at something other than the
    /// gateway: another client's assigned address, or an address no client
    /// holds yet.
    V4Peer,
    /// The same, on the `/64` of a dual-stack exit.
    V6Peer,
}

/// Destination policy on the exit's uplink write path: an inner packet
/// addressed into the exit's own client pool never reaches the TUN, except
/// at the gateway address.
///
/// `None` admits the packet, `Some(refusal)` names why it cannot be
/// admitted.
///
/// The kernel already refuses tunnel-to-tunnel forwarding through an
/// nftables rule on the exit; this is the same policy on our own side of
/// the wire, so an exit whose ruleset is wrong, missing or replaced still
/// keeps two sessions off each other's assigned addresses
/// (`incidents/2026-08-16-two-sessions-on-one-exit-reach-each-other-s-pool-addresses.md`).
///
/// **Scope: the pool, not the segment.** The pool is what the allocator
/// hands out, which is the set of addresses a session can actually hold. The
/// exit's TUN may sit on a wider on-link subnet than that (the Warren fleet
/// runs a `/24` allocator on a `/16` interface), and a destination inside
/// that wider subnet but outside the pool is admitted here and left to the
/// kernel rule. Measured on the DE exit, 2026-08-18: three packets aimed
/// inside the pool moved this gate's counter by 27 with the nftables counter
/// unmoved, while four aimed at the same segment outside the pool moved the
/// nftables counter and not this one. Nothing is reachable out there, since
/// no session is ever assigned an address outside the pool, so what the gap
/// costs is scanning empty space.
///
/// The exception is the GATEWAY ADDRESS, not a port: the resolver answers
/// on `:53` there and the NAT-PMP server on `:5351`, so a port-scoped
/// exception would black-hole every port mapping a client asks for.
///
/// A packet the gate cannot read a destination out of is refused rather
/// than admitted: a truncated IPv4 or IPv6 header has nothing this policy
/// could clear. Non-IP payloads (DAITA dummies) pass through, they are
/// classified before this gate ever runs.
#[must_use]
pub fn classify_destination(pkt: &[u8], pool: &TunnelPool) -> Option<PoolRefusal> {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => match extract_dst_ipv4(pkt) {
            None => Some(PoolRefusal::V4Peer),
            Some(dst) if dst == pool.v4_gateway => None,
            Some(dst) if pool.holds_v4(dst) => Some(PoolRefusal::V4Peer),
            Some(_) => None,
        },
        Some(6) => {
            let (network, gateway) = pool.v6?;
            match extract_dst_ipv6(pkt) {
                None => Some(PoolRefusal::V6Peer),
                Some(dst) if dst == gateway => None,
                // The v6 pool is always a `/64`: the allocator masks the
                // low 64 bits off its network and hands out interface IDs
                // inside it.
                Some(dst) if (u128::from(dst) >> 64) == (u128::from(network) >> 64) => {
                    Some(PoolRefusal::V6Peer)
                }
                Some(_) => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POOL_NET: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 0);
    const POOL_GW: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
    const POOL6_NET: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 0);
    const POOL6_GW: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0xf, 1, 0, 0, 0, 0, 1);

    fn pool() -> TunnelPool {
        TunnelPool::new(POOL_NET, 16, POOL_GW).with_v6(POOL6_NET, POOL6_GW)
    }

    #[test]
    fn a_packet_addressed_to_a_neighbour_of_the_pool_is_refused() {
        let pkt = make_ipv4_packet([10, 66, 3, 7], [10, 66, 9, 12]);
        assert_eq!(
            classify_destination(&pkt, &pool()),
            Some(PoolRefusal::V4Peer),
            "one client must not address another client's assigned tunnel IP"
        );
    }

    #[test]
    fn the_gateway_stays_addressable_because_the_resolver_and_natpmp_live_there() {
        let pkt = make_ipv4_packet([10, 66, 3, 7], [10, 66, 0, 1]);
        assert_eq!(
            classify_destination(&pkt, &pool()),
            None,
            "every client legitimately talks to the gateway address"
        );
    }

    #[test]
    fn an_internet_destination_is_admitted() {
        let pkt = make_ipv4_packet([10, 66, 3, 7], [1, 1, 1, 1]);
        assert_eq!(classify_destination(&pkt, &pool()), None);
    }

    #[test]
    fn a_destination_just_outside_the_prefix_is_admitted() {
        // 10.67.0.0 differs from the pool in the second octet, so a gate
        // masking the wrong number of bits refuses it and black-holes a
        // legitimate private destination.
        let pkt = make_ipv4_packet([10, 66, 3, 7], [10, 67, 0, 5]);
        assert_eq!(classify_destination(&pkt, &pool()), None);
    }

    #[test]
    fn a_v6_packet_addressed_into_the_pool_prefix_is_refused() {
        let mut dst = POOL6_NET.octets();
        dst[15] = 9;
        let pkt = make_ipv6_packet(POOL6_NET.octets(), dst);
        assert_eq!(
            classify_destination(&pkt, &pool()),
            Some(PoolRefusal::V6Peer)
        );
    }

    #[test]
    fn the_v6_gateway_stays_addressable() {
        let pkt = make_ipv6_packet(POOL6_NET.octets(), POOL6_GW.octets());
        assert_eq!(classify_destination(&pkt, &pool()), None);
    }

    #[test]
    fn a_v6_packet_is_admitted_on_a_pool_that_has_no_v6_half() {
        // A v4-only exit has nothing to compare a v6 destination against,
        // and the source gate already refuses an unallocated v6 source.
        let mut dst = POOL6_NET.octets();
        dst[15] = 9;
        let pkt = make_ipv6_packet(POOL6_NET.octets(), dst);
        let v4_only = TunnelPool::new(POOL_NET, 16, POOL_GW);
        assert_eq!(classify_destination(&pkt, &v4_only), None);
    }

    #[test]
    fn a_non_ip_payload_is_admitted_because_another_gate_owns_it() {
        // DAITA dummies are classified before this gate ever runs.
        assert_eq!(classify_destination(&[0xFFu8; 40], &pool()), None);
        assert_eq!(classify_destination(&[], &pool()), None);
    }

    #[test]
    fn a_truncated_ipv4_header_is_refused_rather_than_admitted_unread() {
        // Too short to carry a destination, so the gate cannot clear it.
        let mut pkt = vec![0u8; 19];
        pkt[0] = 0x45;
        assert_eq!(
            classify_destination(&pkt, &pool()),
            Some(PoolRefusal::V4Peer),
            "a header the gate cannot read must not pass it"
        );
    }

    #[test]
    fn a_prefix_of_zero_covers_every_destination() {
        // Degenerate but arithmetically real: shifting by 32 is undefined
        // in C and panics in debug Rust, so the mask must be computed
        // without an unguarded shift.
        let all = TunnelPool::new(Ipv4Addr::UNSPECIFIED, 0, POOL_GW);
        let pkt = make_ipv4_packet([10, 66, 3, 7], [1, 1, 1, 1]);
        assert_eq!(classify_destination(&pkt, &all), Some(PoolRefusal::V4Peer));
    }

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

    const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 5);
    const CLIENT_V6: [u8; 16] = [0xfd, 0xcc, 0, 0xf, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];

    #[test]
    fn classify_admits_the_address_the_connection_was_assigned() {
        let v4 = make_ipv4_packet([10, 66, 0, 5], [8, 8, 8, 8]);
        assert_eq!(classify_source(&v4, CLIENT_V4, None), None);

        let v6 = make_ipv6_packet(
            CLIENT_V6,
            [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        assert_eq!(
            classify_source(&v6, CLIENT_V4, Some(Ipv6Addr::from(CLIENT_V6))),
            None
        );
    }

    #[test]
    fn classify_names_a_foreign_v4_source_a_mismatch() {
        let pkt = make_ipv4_packet([10, 66, 0, 99], [8, 8, 8, 8]);
        assert_eq!(
            classify_source(&pkt, CLIENT_V4, None),
            Some(SpoofRefusal::V4Mismatch),
            "impersonating another tunnel address is what the gate exists for"
        );
    }

    #[test]
    fn classify_separates_link_local_v6_from_an_impersonation_attempt() {
        // A client's own stack chatter on a link that does not exist:
        // neighbour discovery, MLD reports, duplicate-address detection.
        // Refused either way, but it is not an attack and must not be
        // accounted as one.
        let link_local = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x1c, 0x2d, 0x3e, 0x4f, 0, 0, 0, 1,
        ];
        let mld = make_ipv6_packet(
            link_local,
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16],
        );
        assert_eq!(
            classify_source(&mld, CLIENT_V4, None),
            Some(SpoofRefusal::V6LinkLocal)
        );
        assert_eq!(
            classify_source(&mld, CLIENT_V4, Some(Ipv6Addr::from(CLIENT_V6))),
            Some(SpoofRefusal::V6LinkLocal),
            "a v6 grant does not make link-local traffic routable"
        );

        let dad = make_ipv6_packet(
            [0; 16],
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 5],
        );
        assert_eq!(
            classify_source(&dad, CLIENT_V4, None),
            Some(SpoofRefusal::V6LinkLocal),
            "duplicate-address detection sources from the unspecified address"
        );
    }

    #[test]
    fn classify_separates_a_v6_packet_with_no_grant_from_one_with_the_wrong_grant() {
        let routable = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
        let pkt = make_ipv6_packet(routable, [0; 16]);
        assert_eq!(
            classify_source(&pkt, CLIENT_V4, None),
            Some(SpoofRefusal::V6Unallocated),
            "the session was granted no v6, so the gate has nothing to match"
        );
        assert_eq!(
            classify_source(&pkt, CLIENT_V4, Some(Ipv6Addr::from(CLIENT_V6))),
            Some(SpoofRefusal::V6Mismatch),
            "the session has a v6 and this is not it"
        );
    }

    #[test]
    fn classify_names_a_packet_too_short_for_its_own_version_malformed() {
        assert_eq!(
            classify_source(&[0x45; 10], CLIENT_V4, None),
            Some(SpoofRefusal::Malformed)
        );
        assert_eq!(
            classify_source(&[0x60; 23], CLIENT_V4, None),
            Some(SpoofRefusal::Malformed)
        );
        assert_eq!(
            classify_source(&[], CLIENT_V4, None),
            Some(SpoofRefusal::Malformed)
        );
    }

    #[test]
    fn classify_admits_a_daita_dummy_which_carries_no_version_at_all() {
        assert_eq!(
            classify_source(&[0xFFu8; 40], CLIENT_V4, None),
            None,
            "cover traffic is filtered by its own classifier, not by this gate"
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
