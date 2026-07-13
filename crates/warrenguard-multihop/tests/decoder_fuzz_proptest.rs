//! Proptest stand-in for the missing `cargo-fuzz` target on
//! `WarrenMultihopFrame::decode`. Same panic-free invariant as the
//! warren-protocol decoder proptest.
//!
//! `WarrenMultihopFrame::decode` is on the hot path of the multi-hop
//! tunnel: every datagram arriving at the relay (and the exit)
//! flows through it. A panic on a malformed wire frame would take
//! down the entire pump task and disconnect every co-routed
//! tunnel.

use proptest::prelude::*;
use warrenguard_multihop::{WarrenMultihopFrame, WarrenMultihopFrameV2};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        ..ProptestConfig::default()
    })]

    /// `WarrenMultihopFrame::decode` must never panic on arbitrary
    /// bytes. Postcard surfaces malformed input as `Err`; we lock
    /// the contract through the public Warren wrapper.
    #[test]
    fn decode_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _: Result<WarrenMultihopFrame, _> = WarrenMultihopFrame::decode(&bytes);
    }

    /// `/v2` sibling of the check above. `pq_ct` is an attacker-length-controlled
    /// `Vec<u8>` on the datagram hot path (up to the full ML-KEM-768 ciphertext),
    /// so a malformed length prefix must fail closed via `Err`, never panic or
    /// over-allocate unboundedly. The `/v1` frame already had this proptest;
    /// `/v2` had none until this test existed.
    #[test]
    fn decode_v2_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _: Result<WarrenMultihopFrameV2, _> = WarrenMultihopFrameV2::decode(&bytes);
    }
}

#[test]
fn decode_empty_input_returns_err_not_panic() {
    let err = WarrenMultihopFrame::decode(&[]).expect_err("empty bytes must decode as Err");
    let _ = format!("{err:?}");
}

#[test]
fn decode_v2_empty_input_returns_err_not_panic() {
    let err = WarrenMultihopFrameV2::decode(&[]).expect_err("empty bytes must decode as Err");
    let _ = format!("{err:?}");
}
