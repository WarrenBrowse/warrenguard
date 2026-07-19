//! Lock the obfuscation baseline knobs ON by construction. By design,
//! the obfuscation knobs are **always-on** - they are not opt-in /
//! opt-out feature flags.
//! A future refactor that flips `.allow_spin(true)` or drops
//! `initial_crypto_first_fragment_size(Some(64))` would silently
//! degrade traffic-analysis resistance. This test pins each invariant
//! at the source level.
//!
//! Knobs covered:
//! - **I1 - ALPN h3**: `ALPN_H3 = b"h3"` (locked in
//!   `warrenguard_config::ALPN_H3`, covered by `warren-config`'s own
//!   `alpn_h3_is_locked` test).
//! - **I2 - Spin bit off**: `.allow_spin(false)` on both client and
//!   exit `TransportConfig`.
//! - **I3 - Initial split** (≥ 2 Initial datagrams):
//!   `initial_crypto_first_fragment_size(Some(64))` on client + server
//!   mirror.
//! - **SNI**: covered by `warren-tls/name` test suite.

#[test]
fn allow_spin_is_disabled_in_transport_config_base() {
    let src = include_str!("../src/transport_config.rs");
    assert!(
        src.contains(".allow_spin(false)"),
        "Obfuscation invariant I2 violated: warren_transport_config_base must \
         set .allow_spin(false). The spin bit is a passive RTT signal \
         that lets on-path observers fingerprint Warren tunnels."
    );
    assert!(
        !src.contains(".allow_spin(true)"),
        "Found .allow_spin(true) in transport_config.rs - obfuscation invariant \
         I2 requires the spin bit OFF on every Warren TransportConfig"
    );
}

#[test]
fn initial_crypto_first_fragment_size_present_on_client_path() {
    let src = include_str!("../src/transport_config.rs");
    // Exact count, not a lower bound: a `>= 2` floor let the single-hop
    // client's own call site (the GFW-facing leg the SNI-split actually
    // protects) be silently removed without failing this test, as long
    // as at least 2 of the OTHER 4 call sites stayed in place. Pin the
    // exact number of call sites today so removing any one of them
    // (including the client's) trips this test:
    //   1. warren_transport_config_client_full (client)
    //   2. warren_transport_config_exit_full (server mirror)
    //   3. warren_transport_config_relay_inbound_with_gso (server mirror)
    //   4. warren_transport_config_relay_outbound_with_gso (relay-to-exit dial)
    //   5. warren_transport_config_client_multihop_with_idle_cover
    //      (multi-hop client, GFW-facing C1 leg)
    // Bumping this count is fine when a new call site is deliberately
    // added; a drop means the SNI-split protection regressed somewhere.
    let count = src
        .matches(".initial_crypto_first_fragment_size(Some(")
        .count();
    assert_eq!(
        count, 5,
        "Obfuscation invariant I3 (Initial split) expects exactly 5 \
         `.initial_crypto_first_fragment_size(Some(...))` call sites (client, \
         multi-hop client, exit, relay-inbound, relay-outbound); found {count}. \
         A drop means a GFW-facing leg lost its SNI-split protection."
    );
}

#[test]
fn doctrine_doc_reference_present_in_transport_config() {
    let src = include_str!("../src/transport_config.rs");
    assert!(
        src.contains("obfuscation baseline"),
        "transport_config.rs must reference the obfuscation \
         baseline so a future reader understands the knobs are \
         load-bearing, not vestigial"
    );
}

/// Negative: the obfuscation knobs MUST NOT be feature-gated. The
/// baseline is always-on by design; any conditional compilation
/// would create a configuration in which Warren ships with weaker
/// traffic-analysis resistance than advertised.
#[test]
fn obfuscation_knobs_are_not_feature_gated() {
    let src = include_str!("../src/transport_config.rs");
    let forbidden_patterns = [
        // Forbidden: a feature flag that would let a downstream
        // consumer compile out the obfuscation invariants.
        "#[cfg(feature = \"obfuscation",
        "cfg(not(feature = \"obfuscation",
        "#[cfg(any(feature = \"no-obfuscation",
    ];
    for pat in forbidden_patterns {
        assert!(
            !src.contains(pat),
            "Obfuscation doctrine violated: obfuscation knob is feature-gated \
             ({pat:?} found). The obfuscation baseline is always-on; opt-out \
             would create a weak shipping configuration."
        );
    }
}
