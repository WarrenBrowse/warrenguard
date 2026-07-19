//! Proptest stand-in for the missing `cargo-fuzz` targets on the wire-format
//! decoders. cargo-fuzz requires a nightly toolchain and dedicated CI
//! infrastructure, so we settle for a high-iteration proptest that exercises
//! the same panic-free invariant on random inputs.
//!
//! The contract under test: **a decoder must never panic on arbitrary input
//! bytes**. Returning `Err` is fine; panicking turns a malformed wire frame
//! into a tunnel DoS vector. With `axum::serve` catching panics at the request
//! boundary the blast radius is one task, but the Warren tunnel pump does not
//! have that safety net.

use proptest::prelude::*;
use warrenguard_wire::WarrenExitAddr;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        ..ProptestConfig::default()
    })]

    /// `WarrenExitAddr` JSON decoder must never panic on arbitrary strings - a
    /// client's `--info-in` path reads this from disk and a malformed file must
    /// surface as a clean `serde_json::Error`, not a panic that takes down the
    /// daemon.
    #[test]
    fn warren_exit_addr_json_decode_does_not_panic(s in "\\PC*") {
        let _: Result<WarrenExitAddr, _> = serde_json::from_str(&s);
    }

    /// `WarrenExitAddr` postcard decoder must never panic on arbitrary bytes.
    #[test]
    fn warren_exit_addr_postcard_decode_does_not_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let _: Result<WarrenExitAddr, _> = postcard::from_bytes(&bytes);
    }
}
