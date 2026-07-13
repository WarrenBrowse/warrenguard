//! NAT-PMP wire parser must
//! refuse malformed packets cleanly rather than panic. The protocol
//! runs on UDP and accepts unsolicited packets from any source on
//! the tunnel side; an attacker who can reach the gateway IP on
//! port 5351 can spray garbage to harvest a denial-of-service.
//!
//! The 588-LOC `warrenguard-natpmp-protocol` crate did not have a fuzz
//! / proptest harness on its decoders. This file fills the gap with
//! a high-iteration proptest that exercises both `parse_request`
//! and `parse_response` against arbitrary bytes.

use proptest::prelude::*;
use warrenguard_natpmp_protocol::{parse_request, parse_response};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        ..ProptestConfig::default()
    })]

    /// `parse_request` must never panic on arbitrary input. RFC 6886
    /// requires the server to silently drop malformed packets;
    /// surfacing as `Err` lets the caller log and move on.
    #[test]
    fn parse_request_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let _ = parse_request(&bytes);
    }

    /// Same contract for `parse_response`.
    #[test]
    fn parse_response_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let _ = parse_response(&bytes);
    }
}

// ---- Concrete malformed packet anchors ------------------------------------

#[test]
fn empty_buffer_returns_truncated_err() {
    let err = parse_request(&[]).expect_err("empty must be rejected");
    let _ = format!("{err:?}");
}

#[test]
fn one_byte_buffer_is_truncated() {
    // RFC 6886 minimum request = 2 bytes (version + opcode). A 1-byte
    // packet must surface as `Err`, not panic.
    let _ = parse_request(&[0]).expect_err("1-byte truncated must be Err");
}

#[test]
fn future_version_byte_is_rejected() {
    // version != 0 must be refused (RFC 6886 reserves byte 0 for
    // version 0 and warrenguard-natpmp-protocol does not implement PCP).
    let _ = parse_request(&[0xFF, 0x00]).expect_err("future version must be Err");
}

#[test]
fn unknown_opcode_is_rejected() {
    // version 0 (OK), opcode 0x42 (= not in {0, 1, 2}).
    let _ = parse_request(&[0x00, 0x42]).expect_err("unknown opcode must be Err");
}
