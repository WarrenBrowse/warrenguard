//! Proptest stand-in for the missing `cargo-fuzz` target on the JA4
//! pipeline (mirrors the wire-crate and multihop-crate decoder proptests).
//!
//! Every function here parses a pre-auth, fully attacker-controlled QUIC
//! Initial datagram or TLS ClientHello: `decrypt_client_initial` only needs
//! the (public) Destination Connection ID to derive its keys, so anyone on
//! path, including a censor's DPI, can hand this crate an arbitrary
//! datagram before any handshake completes. The reassembly step
//! (`reassemble_client_hello`) additionally stitches CRYPTO frames from
//! several such datagrams by offset, which is extra attacker-controlled
//! bookkeeping (offsets, lengths, overlaps) that must never panic either.
//!
//! The contract under test: **none of these parsers may panic on
//! arbitrary input bytes**. Returning `Err` is fine.

use proptest::prelude::*;
use warrenguard_ja4::{
    decrypt_client_initial, ja4_from_initials, parse_client_hello, reassemble_client_hello,
};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4096,
        ..ProptestConfig::default()
    })]

    /// `parse_client_hello` must never panic on arbitrary bytes: this is
    /// the final stage of the pipeline, fed either a genuine reassembled
    /// handshake or, via `ja4_from_initials`, anything an attacker can get
    /// through the CRYPTO reassembly first.
    #[test]
    fn parse_client_hello_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _ = parse_client_hello(&bytes);
    }

    /// `reassemble_client_hello` must never panic on an arbitrary set of
    /// decrypted Initial payloads, regardless of how their CRYPTO frame
    /// offsets/lengths/overlaps are shaped.
    #[test]
    fn reassemble_client_hello_does_not_panic_on_arbitrary_input(
        payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..=256), 0..=6)
    ) {
        let _ = reassemble_client_hello(&payloads);
    }

    /// `decrypt_client_initial` must never panic on an arbitrary datagram:
    /// header-protection removal and length/offset arithmetic run on
    /// attacker bytes before the AEAD tag is ever checked.
    #[test]
    fn decrypt_client_initial_does_not_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..=1500)) {
        let _ = decrypt_client_initial(&bytes);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    /// `ja4_from_initials` is the full public pipeline (decrypt each
    /// datagram, reassemble the CRYPTO stream, parse the ClientHello): it
    /// must never panic on an arbitrary multi-datagram first flight. Lower
    /// case count than the single-stage tests above: it repeats an AES-GCM
    /// open per datagram, so this stays proportionate.
    #[test]
    fn ja4_from_initials_does_not_panic_on_arbitrary_input(
        datagrams in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..=1500), 0..=4)
    ) {
        let refs: Vec<&[u8]> = datagrams.iter().map(Vec::as_slice).collect();
        let _ = ja4_from_initials(&refs);
    }
}
