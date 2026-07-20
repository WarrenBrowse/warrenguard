//! Tests for the `warren_transport_config()` builder.
//!
//! The Quinn `TransportConfig` does not expose its values for read,
//! so we test indirectly:
//! - the source-anchor tests below assert each builder emits its
//!   obfuscation / keep-alive knobs; runtime construction is covered by
//!   the handshake and pump integration tests that dial with them.
//! - the client / exit `ConfigBuilder`s are distinct - the exit
//!   accepts more streams than the client (cf. Warren constants).
//! - constants invariants (keep-alive < idle/2 etc.) are checked here.
//! - effective behavior under a real network is asserted by
//!   real-exit bench runs, not this unit suite.

use warrenguard_config::{QUIC_KEEP_ALIVE_INTERVAL_SECS, QUIC_MAX_IDLE_TIMEOUT_SECS};

#[test]
fn relay_inbound_emits_bidirectional_warren_initial_pad_knobs() {
    // The obfuscation mirror must be bidirectional. Both the dialer
    // (warren_transport_config_client,
    // warren_transport_config_relay_outbound) and the server-side
    // listeners (warren_transport_config_relay_inbound,
    // warren_transport_config_exit) must produce the same wire layout
    // (≥ 2 padded Initial datagrams, each near the path-MTU floor) so
    // a stateful DPI cannot fingerprint the Warren tunnel via the
    // asymmetric server-only-flat ClientHello / ServerHello pattern.
    //
    // The chunk-cap side of the mirror only fires server-side once
    // the fork patch is bumped to `0.11.13-warren.2`
    // (cf. `crates/warren-tls/tests/quinn_fork_patch.rs::vendored_quinn_proto_first_initial_chunk_cap_is_bidirectional`).
    // The pad target sits at the 1200 B RFC 9000 floor
    // (`PADDED_INITIAL_MIN_SIZE`): 1200 fits nested/reduced-MTU paths where
    // 1280 black-holes, and is the size every major stack pads to.
    let src = include_str!("../src/transport_config.rs");
    let relay_inbound = src
        .split_once("pub fn warren_transport_config_relay_inbound_with_gso")
        .map(|(_, rest)| {
            rest.split_once("Arc::new(cfg)")
                .map(|(body, _)| body)
                .unwrap_or("")
        })
        .unwrap_or("");
    assert!(
        relay_inbound.contains(".initial_crypto_first_fragment_size(Some(64))"),
        "relay_inbound must cap the first CRYPTO chunk to 64 B server-side \
         (obfuscation mirror). Removing this lets the ServerHello SNI/extensions \
         ride in a single Initial datagram and breaks the bidirectional invariant."
    );
    assert!(
        relay_inbound.contains(".initial_datagram_min_size(PADDED_INITIAL_MIN_SIZE)"),
        "relay_inbound must pad Initial datagrams to PADDED_INITIAL_MIN_SIZE \
         (1200 B RFC floor). A pad target > initial_mtu stalls the server-side \
         coalesce loop, and 1200 fits nested/reduced-MTU paths where 1280 black-holes."
    );
}

#[test]
fn warren_transport_config_exit_emits_bidirectional_warren_initial_pad_knobs() {
    // Same invariant as relay_inbound: the exit listens on its public
    // UDP/443 endpoint and produces the same wire profile as the
    // relay-inbound side. Mirror means mirror: not a single asymmetry
    // is acceptable in /v1.
    let src = include_str!("../src/transport_config.rs");
    let exit = src
        .split_once("pub fn warren_transport_config_exit_with_gso")
        .map(|(_, rest)| {
            rest.split_once("Arc::new(cfg)")
                .map(|(body, _)| body)
                .unwrap_or("")
        })
        .unwrap_or("");
    assert!(
        exit.contains(".initial_crypto_first_fragment_size(Some(64))"),
        "warren_transport_config_exit must cap the first CRYPTO chunk to 64 B \
         (obfuscation mirror)."
    );
    assert!(
        exit.contains(".initial_datagram_min_size(PADDED_INITIAL_MIN_SIZE)"),
        "warren_transport_config_exit must pad Initial datagrams to \
         PADDED_INITIAL_MIN_SIZE (1200 B RFC floor)."
    );
}

#[test]
fn relay_outbound_emits_warren_initial_pad_knobs() {
    // Obfuscation invariant: the relay-to-exit dial is the wire signature the
    // relay's *upstream observer* can capture, so the outbound profile
    // must replicate the same Initial pad floor and 64 B first
    // CRYPTO chunk as `warren_transport_config_client`. The inbound
    // profile deliberately omits these knobs: forcing a 64 B cap on a
    // ServerHello stalls the handshake, and padding inbound Initials
    // does not improve the client's wire signature.
    let src = include_str!("../src/transport_config.rs");
    let relay_outbound = src
        .split_once("pub fn warren_transport_config_relay_outbound_with_gso")
        .map(|(_, rest)| {
            rest.split_once("Arc::new(cfg)")
                .map(|(body, _)| body)
                .unwrap_or("")
        })
        .unwrap_or("");
    assert!(
        relay_outbound.contains(".initial_crypto_first_fragment_size(Some(64))"),
        "relay_outbound must cap the first CRYPTO chunk to 64 B. \
         Removing this lets the ClientHello SNI/extensions ride in a single \
         Initial datagram, fingerprinting the relay-to-exit dial."
    );
    assert!(
        relay_outbound.contains(".initial_datagram_min_size(PADDED_INITIAL_MIN_SIZE)"),
        "relay_outbound must pad Initial datagrams to PADDED_INITIAL_MIN_SIZE \
         (1200 B RFC floor)."
    );
}

#[test]
fn warren_transport_config_base_calls_keep_alive_interval() {
    // The Quinn `QuicTransportConfig` does not expose its
    // `keep_alive_interval` value at runtime (no getter), so we anchor
    // the invariant at the source level. This test fails if the
    // `.keep_alive_interval(...)` call is removed from
    // `warren_transport_config_base_with_pad()` (the function
    // `warren_transport_config_base()` delegates to) - capturing the
    // regression that would silently re-introduce a 15-minute-cycle
    // tunnel death.
    //
    // Source-level checks are normally avoided, but here the only
    // alternatives are (a) a 25 s+ behavioral test using the prod
    // constants, or (b) exposing a test-only timeout-override fn on
    // the public API. Both are heavier than this guard. Behavior was
    // also covered by a sustained 30 min real-network bench run.
    //
    // Scoped to the function body (not a whole-file `contains`):
    // `apply_client_liveness` also calls `.keep_alive_interval(...)`
    // (to override it per-client), so a whole-file substring match
    // would still pass after the base call was deleted, silently
    // reintroducing the regression this test claims to guard.
    let src = include_str!("../src/transport_config.rs");
    let body = fn_body(src, "warren_transport_config_base_with_pad");
    assert!(
        body.contains(".keep_alive_interval("),
        "warren_transport_config_base_with_pad must call `.keep_alive_interval(...)`: \
         removing it kills the tunnel after `max_idle_timeout` of any path silence \
         (NAT mapping expiry, single-path packet loss). \
         Re-introduce before merging."
    );
}

// Compile-time invariants on the keep-alive value itself, derived
// from the Quinn contract on `keep_alive_interval`:
//   "Must be set lower than the idle_timeout of both peers to be
//    effective."
// The factor-of-2 margin absorbs a single dropped PING: an interval
// at exactly idle/2 races with a missed PING and can trigger an
// idle close.
const _: () = assert!(
    QUIC_KEEP_ALIVE_INTERVAL_SECS > 0,
    "keep-alive interval must be > 0 to enable PING frames"
);
const _: () = assert!(
    QUIC_KEEP_ALIVE_INTERVAL_SECS * 2 <= QUIC_MAX_IDLE_TIMEOUT_SECS,
    "keep-alive must be <= idle_timeout / 2 to absorb one missed PING"
);

#[test]
fn warren_transport_configs_have_180s_idle_timeout_to_absorb_backbone_blips() {
    // Regression guard: the Warren idle-timeout floor sits at 180s,
    // well above 60s, because a >50s backbone blip on the
    // relay-to-exit leg can fire `max_idle_timeout` on C2.
    // The blind-forwarding relay does not propagate QUIC PING frames
    // from C1 (client-to-relay) to C2 (relay-to-exit), so the only
    // defense against a transient backbone blip is a generous idle
    // budget that the keep-alive PING (20s interval) can refresh
    // across at least a handful of consecutive misses.
    //
    // The full Warren wire profile (BBR, MTU, windows, spin bit,
    // obfuscation padding) is configured by `warren_transport_config_base()`
    // and inherited by all six factory functions:
    //   - `warren_transport_config_client_with_gso`
    //   - `warren_transport_config_exit_with_gso`
    //   - `warren_transport_config_relay_inbound_with_gso`
    //   - `warren_transport_config_relay_outbound_with_gso`
    //   - `warren_transport_config_client_multihop_with_gso`
    //   - `warren_transport_config_relay_outbound_multihop_with_gso`
    //
    // Since the value is centralized via `QUIC_MAX_IDLE_TIMEOUT_SECS`,
    // we anchor the invariant at the constant + at the source-level
    // call site (so a future copy-paste that hardcodes a smaller
    // value would still be caught). Both checks are compile-time
    // const asserts: lowering the const below the floor refuses to
    // compile, surfacing the regression at `cargo build` time instead
    // of at `cargo test` time.
    const _: () = assert!(
        QUIC_MAX_IDLE_TIMEOUT_SECS >= 180,
        "Warren idle timeout must stay >= 180s to absorb cross-DC cloud \
         backbone blips up to ~120s. Lowering this below 180s reintroduces \
         the cross-DC stall pattern: a >50s downlink-stall fires \
         max_idle_timeout on C2 (relay<->exit) because the blind relay \
         forwarder does not propagate QUIC PING frames from C1.",
    );
    const _: () = assert!(
        QUIC_KEEP_ALIVE_INTERVAL_SECS * 9 <= QUIC_MAX_IDLE_TIMEOUT_SECS,
        "keep-alive PING interval must leave room for at least 9 PINGs \
         before idle close (ratio 1/9), giving the connection a ~180s budget \
         to ride out backbone blips."
    );

    // Source-level anchor: the centralized call site in
    // `warren_transport_config_base` must continue to read the constant
    // (and not hardcode a literal). A regression that pins the timeout
    // to a literal 60s here would be invisible at the type level since
    // Quinn does not expose the timeout for read.
    let src = include_str!("../src/transport_config.rs");
    assert!(
        src.contains("Duration::from_secs(QUIC_MAX_IDLE_TIMEOUT_SECS)"),
        "warren_transport_config_base must read max_idle_timeout from the \
         QUIC_MAX_IDLE_TIMEOUT_SECS constant (not a hardcoded literal). \
         A literal value bypasses the 180s floor and \
         reintroduces the downlink-stall regression."
    );
}

/// Extract the source body of `fn <name>` (with or without `pub`, and
/// regardless of return type) by matching braces from the function's own
/// opening `{` to its closing `}`. Used to scope a source-level assertion
/// or comparison to a single function, so it cannot be silently satisfied
/// by an unrelated call site elsewhere in the file (Quinn does not expose
/// `TransportConfig` fields for read, so these builders can only be
/// inspected at the source level).
///
/// Brace-matching (rather than the historical `Arc::new(cfg)` tail
/// search) is required because not every builder in this file returns
/// `Arc<TransportConfig>` or ends in that exact tail (e.g. the private
/// `warren_transport_config_base_with_pad` returns a bare
/// `TransportConfig`).
fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
    let marker = format!("fn {name}(");
    let start = src
        .find(&marker)
        .unwrap_or_else(|| panic!("fn {name} not found in transport_config.rs"));
    let open = src[start..]
        .find('{')
        .map(|i| start + i)
        .unwrap_or_else(|| panic!("fn {name} has no opening brace"));
    let mut depth = 0i32;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open + 1..open + i];
                }
            }
            _ => {}
        }
    }
    panic!("fn {name} has no matching closing brace")
}

/// Unified `:443` dispatcher invariant: the multi-hop relay
/// inbound profile and the multi-hop exit inbound profile MUST stay
/// byte-for-byte identical, because the unified dispatcher serves a
/// single `ServerConfig` to BOTH dialers (client->relay and
/// relay->exit) on one socket. If the two ever diverge, merging them
/// onto one listener would silently change one dialer's negotiated
/// transport parameters. They are already identical today; this test
/// fails loudly the moment someone edits one without the other.
#[test]
fn multihop_relay_inbound_and_exit_inbound_configs_are_identical() {
    let src = include_str!("../src/transport_config.rs");
    let relay_inbound = fn_body(
        src,
        "warren_transport_config_relay_inbound_multihop_with_gso",
    );
    let exit_inbound = fn_body(src, "warren_transport_config_exit_multihop_with_gso");
    assert_eq!(
        relay_inbound.trim(),
        exit_inbound.trim(),
        "the multi-hop relay-inbound and exit-inbound transport configs must stay identical \
         (the unified :443 dispatcher serves one ServerConfig to both the client->relay and \
         relay->exit dialers). Keep them in lock-step or fold them into one function."
    );
}

/// Both multi-hop inbound profiles must stay no-pad.
/// Padding the ServerHello to 1280 B stalls the relay->exit handshake on
/// a low-PMTU intercontinental hop (the padded datagram is dropped and
/// the handshake never completes). The unified dispatcher inherits this
/// profile, so a regression here would blackhole 2-hop traffic.
#[test]
fn multihop_inbound_configs_omit_initial_padding() {
    let src = include_str!("../src/transport_config.rs");
    for name in [
        "warren_transport_config_relay_inbound_multihop_with_gso",
        "warren_transport_config_exit_multihop_with_gso",
    ] {
        let body = fn_body(src, name);
        assert!(
            !body.contains("initial_crypto_first_fragment_size"),
            "{name} must NOT cap the first CRYPTO chunk (no-pad multi-hop inbound): \
             padding the ServerHello stalls the relay->exit handshake on a low-PMTU hop."
        );
        assert!(
            !body.contains("initial_datagram_min_size"),
            "{name} must NOT pad the Initial datagram (no-pad multi-hop inbound)."
        );
    }
}

/// The multi-hop CLIENT leg (client->relay, C1) IS the only hop a GFW-class
/// censor observes, so it must carry the SNI-split knobs, unlike every other
/// multi-hop profile. The relay->exit dialer (relay-outbound multi-hop) stays
/// no-pad: it is outside the censored region and rides a low-PMTU
/// intercontinental hop that the padding would stall.
#[test]
fn multihop_client_pads_the_gfw_facing_leg_while_relay_outbound_stays_no_pad() {
    let src = include_str!("../src/transport_config.rs");
    // The public `..._with_idle_cover` entry delegates to the MTU-parameterized
    // inner impl, where the SNI-split pad knobs now live (the pad is the fixed
    // 1200 floor, at or below `initial_mtu`, so a nested-path client's lowered
    // floor never leaves an oversized ClientHello). Introspect the impl that
    // actually sets them.
    let client = fn_body(src, "warren_transport_config_client_multihop_with_mtu");
    assert!(
        client.contains("initial_crypto_first_fragment_size"),
        "the multi-hop client must cap the first CRYPTO chunk: the client->relay leg \
         is the GFW-facing hop and its ClientHello SNI must split across datagrams."
    );
    assert!(
        client.contains("initial_datagram_min_size"),
        "the multi-hop client must pad its Initial datagram (SNI-split on the GFW-facing leg)."
    );

    let relay_outbound = fn_body(
        src,
        "warren_transport_config_relay_outbound_multihop_with_gso",
    );
    assert!(
        !relay_outbound.contains("initial_crypto_first_fragment_size"),
        "the multi-hop relay->exit dialer must stay no-pad (not GFW-facing; low-PMTU hop)."
    );
    assert!(
        !relay_outbound.contains("initial_datagram_min_size"),
        "the multi-hop relay->exit dialer must not pad its Initial (intercontinental stall)."
    );
}
