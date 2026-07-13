//! Regression on datagram buffer sizing. The Quinn defaults (1.25 MB
//! recv / 1 MB send, derived from a `12.5 Mbps × 100 ms` BDP
//! assumption) are dramatically under-sized for the Warren 1+ Gbps
//! target.
//!
//! These constants are exposed by `warrenguard-config` and consumed by
//! `warrenguard_transport_core::transport_config::warren_transport_config_base`.
//! The test pins the values so a future "let's bump QUIC_RECV_WINDOW"
//! refactor can't silently regress them.

use warrenguard_config::{QUIC_DATAGRAM_RECV_BUFFER, QUIC_DATAGRAM_SEND_BUFFER};

/// 8 MiB matches the calibration in the docstring: 1 Gbps × MTU 1280
/// × 80 ms jitter absorption ≈ 10 MB, rounded up to a comfortable
/// 8 MiB power-of-two. Below this, sustained 1 Gbps cross-DC
/// transfers stall under jitter.
#[test]
fn datagram_recv_buffer_handles_1gbps_jitter_budget() {
    assert_eq!(
        QUIC_DATAGRAM_RECV_BUFFER,
        8 * 1024 * 1024,
        "QUIC_DATAGRAM_RECV_BUFFER must be 8 MiB to absorb 80 ms of \
         1 Gbps jitter (≈ 10 MB) with headroom. Quinn's 1.25 MB default \
         is calibrated for 12.5 Mbps which would cap Warren at < 100 Mbps \
         under jitter."
    );
}

#[test]
fn datagram_send_buffer_handles_40ms_backpressure_at_1gbps() {
    assert_eq!(
        QUIC_DATAGRAM_SEND_BUFFER,
        4 * 1024 * 1024,
        "QUIC_DATAGRAM_SEND_BUFFER must be 4 MiB to handle ≈ 40 ms of \
         backpressure at 1 Gbps. Below this, brief NIC stalls cascade \
         into dropped outbound datagrams on the pump."
    );
}

// Compile-time invariant (caught at `cargo build`, not `cargo test`).
// Cf. clippy `assertions_on_constants`: an `assert!` on a const-true
// condition would be optimized out, so we use `const _: () =`
// compile-time eval which DOES fire if the invariant is violated.
const _: () = {
    // Quinn 0.11 defaults (cf. vendor/quinn-fork/quinn-proto/src/config/transport.rs):
    //   datagram_receive_buffer_size = STREAM_RWND = 12_500_000 / 1000 * 100 = 1_250_000 B
    //   datagram_send_buffer_size    = 1 * 1024 * 1024 = 1_048_576 B
    const QUINN_DEFAULT_RECV: usize = 1_250_000;
    const QUINN_DEFAULT_SEND: usize = 1_048_576;
    assert!(
        QUIC_DATAGRAM_RECV_BUFFER >= 3 * QUINN_DEFAULT_RECV,
        "QUIC_DATAGRAM_RECV_BUFFER must be ≥ 3 × Quinn default"
    );
    assert!(
        QUIC_DATAGRAM_SEND_BUFFER >= 3 * QUINN_DEFAULT_SEND,
        "QUIC_DATAGRAM_SEND_BUFFER must be ≥ 3 × Quinn default"
    );
};

/// Source-level: `warren_transport_config_base` MUST explicitly set
/// both datagram buffers. A drop of either line would silently regress
/// the tunnel to Quinn defaults.
#[test]
fn transport_config_base_explicitly_sets_datagram_buffers() {
    let src = include_str!("../../warrenguard-transport-core/src/transport_config.rs");
    assert!(
        src.contains("datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECV_BUFFER))"),
        "warren_transport_config_base must explicitly set datagram_receive_buffer_size; \
         dropping the line reverts to Quinn's 1.25 MB default"
    );
    assert!(
        src.contains("datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER)"),
        "warren_transport_config_base must explicitly set datagram_send_buffer_size"
    );
}
