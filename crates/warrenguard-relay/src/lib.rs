//! Warren relay daemon library: cryptographically blind QUIC forwarder.
//!
//! `warren-relay` is the data-plane intermediate hop in the Warren
//! two-relayed QUIC + HPKE multi-hop topology. It terminates the QUIC connection
//! from the client (`C1`), parses the first applicative DATAGRAM only to
//! extract the unencrypted [`warrenguard_multihop::ExitId`] routing tag, then
//! opens (or reuses from a pool) a second QUIC connection (`C2`) to the
//! matching exit. Everything beyond that first frame is bidirectional
//! pass-through of opaque ciphertext datagrams: the relay never holds
//! the HPKE key and is cryptographically incapable of reading payloads.
//!
//! The crate is exposed as a library only: it ships no binary. Integration
//! tests in `tests/` spin up a real [`server::RelayServer`] in-process
//! against fake clients and exits without forking a subprocess. A deployer
//! consuming this crate as the WarrenGuard engine's relay primitive builds
//! their own binary (clap/tracing/whatever they prefer) around
//! [`server::RelayServer`], [`config::RelayConfig`], [`exit_pool::ExitConnPool`],
//! and [`forward::forward_session`].
#![forbid(unsafe_code)]

pub mod config;
pub mod exit_pool;
pub mod forward;
pub mod metrics;
pub mod pki;
pub mod server;
pub mod session;

pub use config::{ConfigError, ExitDescriptorSigned, RelayConfig};
pub use exit_pool::{ExitConnPool, ExitPoolError};
pub use forward::{ForwardError, ForwardSummary, forward_session};
pub use metrics::{RelayMetrics, RelayMetricsSnapshot, record_forward_summary};
pub use pki::{PkiError, exit_descriptor_signing_payload, verify_exit_descriptor};
pub use server::{RelayServer, ServerError};
pub use session::{
    DispatchFrame, DispatchedExit, MAX_MULTIHOP_SETUP_FRAME_BYTES, SessionError,
    WARREN_VARINT_INVALID_FRAME, WARREN_VARINT_NO_FIRST_DATAGRAM, WARREN_VARINT_UNKNOWN_EXIT,
    extract_dispatched_exit, extract_dispatched_exit_with_deadline, read_dispatch_frame,
    read_dispatch_frame_or_unauth, shuttle_setup_to_exit, shuttle_setup_to_exit_with_timeout,
};

/// Returns the package version string declared in `Cargo.toml`. Used by
/// the binary `--version` plumbing and by tests verifying the crate
/// metadata stays in sync with the user-facing output.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_non_empty_cargo_pkg_version() {
        let v = version();
        assert!(!v.is_empty(), "CARGO_PKG_VERSION must not be empty");
        assert!(
            v.split('.').count() >= 2,
            "expected semver-shaped version, got {v}"
        );
    }
}
