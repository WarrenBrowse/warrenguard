//! Change-detector lock for the frozen `/v1` QUIC application close codes.
//!
//! `src/constants.rs` documents each value as frozen wire contract ("the
//! client matches it byte-for-byte"), but nothing pinned the numeric literal
//! itself: every behavioural test in the repo (e.g. the client decode path,
//! `warrenguard-server`'s drain / auth-rejection tests) compares a received
//! close code against the SAME shared constant, so mutating a literal here
//! passes every one of them while silently breaking recognition across
//! mixed-version deployments (an old client vs. a redeployed exit).

use warrenguard_transport_core::constants::{
    H3_GENERAL_PROTOCOL_ERROR, WARREN_AUTH_FAILED, WARREN_DEVICE_LIMIT, WARREN_EXIT_DRAINING,
    WARREN_NO_CAPACITY,
};

#[test]
fn v1_close_codes_are_frozen() {
    assert_eq!(
        WARREN_AUTH_FAILED.into_inner(),
        0x5741_5252,
        "WARREN_AUTH_FAILED (\"WARR\") is part of the /v1 wire contract: the \
         client matches this exact code on Connection::close_reason() to \
         detect an auth rejection. Bump the protocol version instead of \
         mutating the literal."
    );
    assert_eq!(
        WARREN_DEVICE_LIMIT.into_inner(),
        0x574c_494d,
        "WARREN_DEVICE_LIMIT (\"WLIM\") is part of the /v1 wire contract."
    );
    assert_eq!(
        WARREN_NO_CAPACITY.into_inner(),
        0x5746_554c,
        "WARREN_NO_CAPACITY (\"WFUL\") is part of the /v1 wire contract."
    );
    assert_eq!(
        WARREN_EXIT_DRAINING.into_inner(),
        0x5744_524e,
        "WARREN_EXIT_DRAINING (\"WDRN\") is part of the /v1 wire contract."
    );
    assert_eq!(
        H3_GENERAL_PROTOCOL_ERROR.into_inner(),
        0x0101,
        "H3_GENERAL_PROTOCOL_ERROR is the standard HTTP/3 RFC 9114 close code \
         used for the decoy / unauthenticated path; it must stay the spec value \
         so an active prober cannot distinguish it from a real HTTP/3 endpoint."
    );
}
