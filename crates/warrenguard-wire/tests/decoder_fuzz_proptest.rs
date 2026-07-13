//! Proptest stand-in for the
//! missing `cargo-fuzz` targets on the wire-format decoders. There
//! is no fuzz harness on
//! `decode_setup` / `decode_setup_ack`; cargo-fuzz requires a
//! nightly toolchain and dedicated CI infrastructure, so we settle
//! for a high-iteration proptest that exercises the same panic-free
//! invariant on random inputs.
//!
//! The contract under test: **a decoder must never panic on
//! arbitrary input bytes**. Returning `Err` is fine; panicking
//! turns a malformed wire frame into a tunnel DoS vector. With
//! `axum::serve` catching panics at the request boundary the blast
//! radius is one task, but the Warren tunnel pump does not have
//! that safety net.

use proptest::prelude::*;
use warrenguard_wire::{
    WarrenExitAddr, decode_setup, decode_setup_ack, decode_setup_ack_v7, decode_setup_any,
    decode_setup_v7,
};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        ..ProptestConfig::default()
    })]

    /// `decode_setup` must never panic on arbitrary bytes.
    /// Postcard's decoder is supposed to surface any malformed input
    /// as a `DeserializeError` rather than aborting; we lock that
    /// guarantee through the warren-protocol wrapper here.
    #[test]
    fn decode_setup_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _ = decode_setup(&bytes);
    }

    /// Same contract for `decode_setup_ack`.
    #[test]
    fn decode_setup_ack_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _ = decode_setup_ack(&bytes);
    }

    /// `decode_setup_v7` must never panic on arbitrary bytes. It is the
    /// anonymous-token setup decoder, attacker-facing throughout the v6/v7
    /// dual-accept migration window.
    #[test]
    fn decode_setup_v7_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _ = decode_setup_v7(&bytes);
    }

    /// Same contract for `decode_setup_ack_v7`.
    #[test]
    fn decode_setup_ack_v7_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _ = decode_setup_ack_v7(&bytes);
    }

    /// `decode_setup_any` is the dual-accept entry point a v7-capable exit
    /// actually calls on every incoming connection: it must never panic
    /// regardless of which version byte (or garbage) leads the buffer.
    #[test]
    fn decode_setup_any_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _ = decode_setup_any(&bytes);
    }

    /// `WarrenExitAddr` JSON decoder must never panic on arbitrary
    /// strings - a client's `--info-in` path reads this
    /// from disk and a malformed file must surface as a clean
    /// `serde_json::Error`, not a panic that takes down the daemon.
    #[test]
    fn warren_exit_addr_json_decode_does_not_panic(s in "\\PC*") {
        let _: Result<WarrenExitAddr, _> = serde_json::from_str(&s);
    }

    /// `WarrenExitAddr` postcard decoder must never panic on
    /// arbitrary bytes.
    #[test]
    fn warren_exit_addr_postcard_decode_does_not_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let _: Result<WarrenExitAddr, _> = postcard::from_bytes(&bytes);
    }
}

/// Sanity guard: the no-panic property must catch a regression that
/// reintroduces an explicit panic on a malformed path. We don't
/// actually inject a panic in the production code; this test just
/// documents the property and trips loud if a future contributor
/// turns a `Result::Err` into a `panic!` inside one of the
/// decoders.
#[test]
fn decode_setup_known_empty_input_returns_err() {
    let err = decode_setup(&[]).expect_err("empty bytes must decode as Err");
    let _ = format!("{err:?}");
    let _ = err.to_string();
}

#[test]
fn decode_setup_ack_known_empty_input_returns_err() {
    let err = decode_setup_ack(&[]).expect_err("empty bytes must decode as Err");
    let _ = format!("{err:?}");
    let _ = err.to_string();
}
