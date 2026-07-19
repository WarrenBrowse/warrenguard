//! 5-tuple flow hashing, shared by every bonded dispatch point.
//!
//! Lives in a neutral module (not the client-side `multi_session`) so the
//! server TUN router (`tun_dispatch`) keys flows with the **same** function the
//! client bundle uses, without a server module importing from a client module.

/// FNV-1a 64-bit hash of an IP packet's 5-tuple
/// `(proto, src_ip, dst_ip, src_port, dst_port)`. Returns `None` if:
/// - packet empty or too short
/// - IP version != 4 and != 6
/// - protocol != TCP (6) and != UDP (17)
///
/// FNV-1a algorithm:
/// - offset basis: 0xcbf29ce484222325 (RFC-style)
/// - prime: 0x100000001b3
///
/// Not SipHash: we don't need adversarial resistance and FNV-1a is ~3x
/// faster on the hot path. Distribution is fine for N=2..16 conns.
///
/// Public so every bonded dispatch point (the exit `DispatchSlot`, the
/// multi-hop client bundle, and the exit TUN router) keys flows with the
/// same function.
#[must_use]
pub fn flow_hash_5tuple(pkt: &[u8]) -> Option<u64> {
    let first = *pkt.first()?;
    let version = first >> 4;

    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let mut h: u64 = FNV_OFFSET;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
    };

    if version == 4 {
        // IPv4 minimum header = 20 bytes, +4 bytes for the 2 ports.
        if pkt.len() < 24 {
            return None;
        }
        let ihl = (first & 0x0f) as usize * 4;
        // IHL must point inside the buffer to read the 4 port bytes.
        if ihl < 20 || pkt.len() < ihl + 4 {
            return None;
        }
        let proto = pkt[9];
        if proto != 6 && proto != 17 {
            return None; // not TCP/UDP
        }
        feed(&[proto]);
        feed(&pkt[12..20]); // src IP (4) + dst IP (4)
        feed(&pkt[ihl..ihl + 4]); // src port (2) + dst port (2)
        Some(h)
    } else if version == 6 {
        // IPv6 fixed header = 40 bytes, +4 bytes for the 2 ports.
        if pkt.len() < 44 {
            return None;
        }
        let next = pkt[6];
        if next != 6 && next != 17 {
            // We ignore IPv6 extension headers for POC simplicity; a
            // Hop-by-Hop or Routing header falls back to round-robin.
            // Acceptable, we lose stickiness on these rare packets.
            return None;
        }
        feed(&[next]);
        feed(&pkt[8..40]); // src (16) + dst (16)
        feed(&pkt[40..44]); // src port + dst port
        Some(h)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesize a minimal IPv4/TCP packet for hash testing.
    /// Fixed 20-byte IPv4 header + minimum 20-byte TCP header.
    fn make_ipv4_tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version 4 + IHL 5 (x4 = 20 bytes)
        pkt[9] = 6; // proto TCP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    fn make_ipv4_udp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = make_ipv4_tcp(src_ip, dst_ip, src_port, dst_port);
        pkt[9] = 17; // proto UDP
        pkt
    }

    #[test]
    fn flow_hash_returns_none_on_empty_or_short() {
        assert_eq!(flow_hash_5tuple(&[]), None);
        assert_eq!(flow_hash_5tuple(&[0x45]), None);
        assert_eq!(flow_hash_5tuple(&[0x45; 23]), None); // 1 byte short of required
    }

    #[test]
    fn flow_hash_returns_none_on_unsupported_version() {
        let mut pkt = make_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 5678);
        pkt[0] = 0x55; // version 5 = invalid
        assert_eq!(flow_hash_5tuple(&pkt), None);
    }

    #[test]
    fn flow_hash_returns_none_on_icmp() {
        let mut pkt = make_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
        pkt[9] = 1; // proto ICMP -> expect round-robin fallback
        assert_eq!(flow_hash_5tuple(&pkt), None);
    }

    #[test]
    fn flow_hash_is_deterministic_for_same_5tuple() {
        let pkt1 = make_ipv4_tcp([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80);
        let pkt2 = make_ipv4_tcp([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80);
        // Different payload past the 5-tuple -> same hash (sticky per flow).
        let mut pkt3 = pkt2.clone();
        pkt3.push(0x42);
        pkt3.push(0x43);
        assert_eq!(flow_hash_5tuple(&pkt1), flow_hash_5tuple(&pkt2));
        assert_eq!(flow_hash_5tuple(&pkt1), flow_hash_5tuple(&pkt3));
    }

    #[test]
    fn flow_hash_differs_when_5tuple_changes() {
        let base = make_ipv4_tcp([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80);
        let other_dst = make_ipv4_tcp([10, 0, 0, 1], [192, 168, 1, 2], 1234, 80);
        let other_port = make_ipv4_tcp([10, 0, 0, 1], [192, 168, 1, 1], 1234, 443);
        let other_proto = make_ipv4_udp([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80);
        // These 4 packets must produce 4 distinct hashes (not
        // mathematically guaranteed by FNV but true for these chosen
        // values).
        let h0 = flow_hash_5tuple(&base).unwrap();
        let h1 = flow_hash_5tuple(&other_dst).unwrap();
        let h2 = flow_hash_5tuple(&other_port).unwrap();
        let h3 = flow_hash_5tuple(&other_proto).unwrap();
        assert!(
            h0 != h1 && h0 != h2 && h0 != h3 && h1 != h2 && h1 != h3 && h2 != h3,
            "expected distinct hashes; got h0={h0:x} h1={h1:x} h2={h2:x} h3={h3:x}"
        );
    }

    #[test]
    fn flow_hash_works_for_ipv6() {
        // Fixed IPv6 header 40 bytes + 4 port bytes.
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x60; // version 6
        pkt[6] = 6; // next header = TCP
        pkt[8..24].copy_from_slice(&[0xfd; 16]); // src
        pkt[24..40].copy_from_slice(&[0xfe; 16]); // dst
        pkt[40..42].copy_from_slice(&1234u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&80u16.to_be_bytes());
        let h = flow_hash_5tuple(&pkt).expect("ipv6 tcp must hash");
        // Idempotent.
        assert_eq!(Some(h), flow_hash_5tuple(&pkt));
    }
}
