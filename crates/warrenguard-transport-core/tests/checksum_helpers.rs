//! The internet-checksum helpers are part of the engine's public surface: a
//! consumer that rewrites inner IP packets (a NAT in front of the tunnel, a
//! probe generator) must reuse this arithmetic instead of writing its own.
//! These tests exercise them through the public path only.

use std::net::Ipv6Addr;

use warrenguard_transport_core::{
    icmpv6_pseudo_sum, incremental_checksum_update, internet_checksum,
};

/// RFC 1624 section 4: a header whose other octets sum to 0xCD7A carries the
/// field m = 0x5555 and the checksum 0xDD2F; recomputing after m becomes
/// 0x3285 gives +0 (0x0000), the boundary case RFC 1141's equation got wrong.
#[test]
fn internet_checksum_reproduces_the_rfc1624_example() {
    let before = [0xCD, 0x7A, 0x55, 0x55];
    let after = [0xCD, 0x7A, 0x32, 0x85];

    assert_eq!(internet_checksum(0, &before), 0xDD2F);
    assert_eq!(internet_checksum(0, &after), 0x0000);
}

/// RFC 1624 equation 3: the incremental update of the same example must land
/// on the value a full recomputation gives, +0 rather than -0.
#[test]
fn incremental_update_reproduces_the_rfc1624_example() {
    assert_eq!(incremental_checksum_update(0xDD2F, 0x5555, 0x3285), 0x0000);
}

/// A known ICMPv6 Echo Request (RFC 4443 section 4.1) from `fdcc:f:1::1` to
/// `2001:db8::1`: identifier 0x1234, sequence 1, a 16-byte payload. Its
/// checksum is 0x891F, computed independently from the RFC 8200 section 8.1
/// pseudo-header. Seeding [`internet_checksum`] with [`icmpv6_pseudo_sum`]
/// must reproduce it, and the message carrying it must sum to zero.
#[test]
fn icmpv6_pseudo_sum_checksums_a_known_echo_request() {
    let src: Ipv6Addr = "fdcc:f:1::1".parse().expect("literal address");
    let dst: Ipv6Addr = "2001:db8::1".parse().expect("literal address");
    let mut msg = [
        0x80, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];

    let seed = icmpv6_pseudo_sum(src, dst, msg.len() as u32);
    let checksum = internet_checksum(seed, &msg);
    assert_eq!(checksum, 0x891F);

    msg[2..4].copy_from_slice(&checksum.to_be_bytes());
    assert_eq!(internet_checksum(seed, &msg), 0);
}
