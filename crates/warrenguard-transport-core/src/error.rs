//! Sealed error type for the public [`crate`] surface.
//!
//! Every fallible function in `warrenguard-transport-core` returns `Result<T,
//! TunnelError>`. The enum partitions failures by *cause* (network,
//! TLS, protocol, persistence, ...) so callers can match on a specific
//! variant rather than parsing string messages out of an
//! `anyhow::Error`.
//!
//! The variants carry the underlying source error via `#[source]`
//! whenever one is available; otherwise they carry a `String` context
//! lifted from the previous `.with_context(|| format!(...))` calls.

use std::borrow::Cow;
use std::io;

use warrenguard_daita::DaitaError;

/// Public error surface of `warrenguard-transport-core`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// Failed to bind a UDP socket on the local interface (typical
    /// when the requested port is already in use or the kernel refuses
    /// the bind ip).
    #[error("failed to bind UDP socket on {addr}: {source}")]
    Bind {
        /// The address we tried to bind to.
        addr: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The [`warrenguard_wire::WarrenExitAddr`] does not carry a usable
    /// `SocketAddr` to dial. Surfaces only on the client side.
    #[error("warren exit address has no socket addr to dial")]
    NoExitAddr,

    /// QUIC `connect` failed (typically: peer unreachable, certificate
    /// rejected, idle timeout).
    #[error("QUIC connect to {target} failed: {source}")]
    QuicConnect {
        /// Stringified target address (no PII, no pubkey).
        target: String,
        /// Underlying Quinn error.
        #[source]
        source: quinn::ConnectError,
    },

    /// QUIC connection lost or refused after the initial connect
    /// (transport-level error during open_bi, accept, datagram, ...).
    #[error("QUIC connection error: {context}: {source}")]
    QuicConnection {
        /// Short tag describing what was being attempted.
        context: &'static str,
        /// Underlying Quinn error.
        #[source]
        source: quinn::ConnectionError,
    },

    /// `Endpoint::config` rejected a setting (typically: invalid bind
    /// IPv6 / IPv4 combination, or a transport config tuning value
    /// outside the accepted range).
    #[error("QUIC endpoint configuration error: {0}")]
    QuicEndpoint(String),

    /// Errors raised when reading or writing the unidirectional /
    /// bidirectional setup stream (truncated read, write reset, ...).
    #[error("QUIC stream error: {context}: {source}")]
    QuicStream {
        /// Short tag describing the side / direction. `Cow` keeps a
        /// `&'static str` literal allocation-free; the few `format!`
        /// call sites in `pump.rs` / `client.rs` use the `Owned`
        /// variant.
        context: Cow<'static, str>,
        /// Underlying stream error reason.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to send a QUIC datagram (typical: payload exceeded the
    /// negotiated `max_datagram_size`, or the connection is closing).
    #[error("QUIC datagram send error: {context}: {source}")]
    QuicSendDatagram {
        /// Short tag describing the path (e.g. "uplink", "conn[2]").
        /// `Cow` keeps a `&'static str` literal allocation-free; the
        /// few `format!("conn[{idx}]")` sites in `pump.rs` use the
        /// `Owned` variant.
        context: Cow<'static, str>,
        /// Underlying send-datagram error reason.
        #[source]
        source: quinn::SendDatagramError,
    },

    /// Failed to read a QUIC datagram (typical: connection closed by
    /// peer, idle timeout). Carries the underlying Quinn error.
    #[error("QUIC datagram read error: {context}: {source}")]
    QuicReadDatagram {
        /// Short tag describing the path (e.g. "downlink", "conn[2]").
        /// `Cow` keeps a `&'static str` literal allocation-free.
        context: Cow<'static, str>,
        /// Underlying read-datagram error reason.
        #[source]
        source: quinn::ConnectionError,
    },

    /// The QUIC TLS channel binding could not be exported (e.g. the
    /// handshake state is not where the in-band auth expected it).
    /// Surfaces a server-side rejection. See in-band auth in
    /// `warrenguard-tls`.
    #[error("could not export QUIC TLS channel binding for in-band auth")]
    ChannelBindingExport,

    /// The in-band client auth proof in `Setup` did not verify against the
    /// asserted `client_pubkey` (wrong key, replayed proof, or tamper).
    /// Surfaces a server-side rejection before the allowlist gate.
    #[error("in-band client auth signature did not verify")]
    InbandAuthFailed,

    /// The in-band EXIT proof in `SetupAck` (`exit_auth_sig`) did not verify
    /// against the exit pubkey the client dialed (v6 X.509 exit mode). The
    /// peer holds a valid TLS cert but not the expected Warren exit's
    /// Ed25519 identity: a man-in-the-middle, or the wrong exit. The client
    /// MUST abort rather than tunnel through an unauthenticated exit.
    #[error("in-band exit identity proof did not verify")]
    ExitAuthFailed,

    /// Not a real error: the connection completed the handshake but was not an
    /// authenticated Warren client, and a decoy handler was configured, so the
    /// exit handed the live connection to it instead of closing.
    /// The accept loop treats this as a quiet, expected outcome.
    #[error("unauthenticated connection diverted to the decoy handler")]
    DivertedToDecoy,

    /// The peer pubkey did not match any entry of the allowlist.
    /// Surfaces on the exit side when a client tries to attach without
    /// being enrolled.
    #[error("peer pubkey not in allowlist")]
    AllowlistDenied,

    /// The global per-account device cap (v2) refused this PRIMARY
    /// connection: the account already has the maximum number of
    /// distinct devices live. Surfaces on the exit side; the connection
    /// is closed with `WARREN_DEVICE_LIMIT` so the client can show a
    /// clear "device limit reached" message.
    #[error("device limit reached for this account")]
    DeviceLimitReached,

    /// The exit is draining for planned maintenance and refuses NEW
    /// sessions; established sessions are untouched (the drain deadline
    /// governs their eventual hard-close). Surfaces on the exit side when
    /// the admission gate fires (the connection is closed with
    /// `WARREN_EXIT_DRAINING`), and on the CLIENT side when its handshake
    /// was refused with that code: unlike an auth rejection this is not
    /// fatal for the identity, the client must simply re-select another
    /// exit (retrying this one re-derives the same refusal).
    #[error("exit is draining: new sessions refused")]
    ExitDrainingRefused,

    /// The exit explicitly rejected the handshake by closing the QUIC
    /// connection with the `WARREN_AUTH_FAILED` application code: this
    /// client's identity is not authorized (no active subscription /
    /// not enrolled in the exit's allowlist). Surfaces on the **client**
    /// side and is deliberately distinct from a transient
    /// [`TunnelError::QuicConnection`] / [`TunnelError::QuicStream`]
    /// loss: the caller MUST NOT silently retry it (retrying produces
    /// the same outcome and, upstream, a misleading "no matching relay"
    /// state) - the user needs to provision or renew their
    /// subscription. No identity material is carried (no-log Warren).
    #[error("exit rejected the handshake: identity not authorized (no active subscription)")]
    AuthRejected,

    /// The exit closed the handshake with `WARREN_NO_CAPACITY`: its tunnel IP
    /// pool has no free address left. Surfaces on the **client** side. Unlike
    /// [`TunnelError::AuthRejected`] the account is fine, and unlike a transient
    /// loss redialing the SAME exit re-hits the exhaustion, so the caller should
    /// reselect a different exit. The multi-hop equivalent is
    /// `RejectionReason::IpExhausted`; both classify as
    /// [`warrenguard_wire::Retryability::RetryReselect`]. No
    /// identity material is carried.
    #[error("exit rejected the handshake: ip pool exhausted")]
    PoolExhausted,

    /// Failed to encode or decode a Setup / SetupAck frame (postcard
    /// returned an error, or the wire bytes were malformed).
    #[error("setup wire format error: {context}: {source}")]
    SetupWire {
        /// Short tag describing the direction (encode / decode). `Cow`
        /// keeps literal call sites allocation-free.
        context: Cow<'static, str>,
        /// Underlying postcard / protocol error reason.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The peer answered a Setup with semantically invalid SetupAck
    /// fields (multiconn flag mismatch, tunnel_ip changed across
    /// secondary attaches, version downgrade, ...).
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// Filesystem I/O on the persisted exit state (path = the file
    /// being touched, source = the underlying io error). The
    /// allow-list refresh, the state snapshot, and the identity store
    /// all funnel through this.
    #[error("filesystem I/O on {path}: {source}")]
    Fs {
        /// The path being read or written when the error occurred.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Invalid Ed25519 pubkey hex string (wrong length, non-hex, or
    /// uppercase). Surfaces on the exit side when reading a state
    /// file that was tampered with.
    #[error("invalid pubkey hex: {0}")]
    PubkeyHex(String),

    /// `MultiSession` was constructed with zero `quinn::Connection`s
    /// or used after every connection was closed.
    #[error("multi-session has no live connection: {0}")]
    MultiSessionEmpty(&'static str),

    /// Failed I/O on the local TUN device (typical: `EAGAIN`, or the
    /// device was removed mid-flight). `context` says whether the path
    /// was a read or a write.
    #[error("TUN device I/O: {context}: {source}")]
    Tun {
        /// Short tag describing the call site
        /// (`recv_batch`, `try_recv`, `send`, ...). `Cow` keeps the
        /// per-error-path allocation-free for the common literal case.
        context: Cow<'static, str>,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The Quinn endpoint was closed (`Endpoint::accept().await`
    /// returned `None`). Used by the `accept_forever{_with_tun}` loops
    /// to terminate cleanly; bubbles up to the caller as a clean
    /// "service shutdown" rather than an error.
    #[error("Quinn endpoint closed")]
    EndpointClosed,

    /// The accept loop issued a stateless retry token to the incoming
    /// peer (anti-DDoS). The peer must
    /// re-initiate the handshake with the token attached; the loop
    /// silently continues to the next `accept()` iteration. Surfaced
    /// as a distinct variant so the caller can match it without
    /// confusing a real handshake failure with a routine retry.
    #[error("issued stateless retry to incoming peer")]
    StatelessRetryIssued,

    /// Catch-all for internal invariant breaches we do not expect to
    /// surface in production (e.g. a tokio JoinHandle that panicked,
    /// a debug assertion that was disabled). Treated as a 500 by
    /// callers.
    #[error("internal tunnel error: {0}")]
    Internal(String),

    /// A serialized `maybenot::Machine` string could not be parsed.
    /// Surfaces when the exit sends a malformed `DaitaConfig`
    /// or when the wire blob was truncated. The carried string is the
    /// upstream `maybenot` error message (no PII).
    #[error("invalid DAITA machine spec: {0}")]
    DaitaInvalidMachine(String),

    /// `maybenot::Framework::new` rejected the supplied parameters
    /// (typical: `max_padding_frac` or `max_blocking_frac` outside
    /// `0.0..=1.0`).
    #[error("DAITA framework construction failed: {0}")]
    DaitaFramework(String),
}

impl TunnelError {
    /// The engine's supervisor-facing verdict for a (re)connect failure.
    ///
    /// The fatal set matches the app's proven single-hop classification
    /// (`AuthRejected`/`DeviceLimitReached` are non-retryable business
    /// rejections) plus the exit-side authorization refusals; the draining and
    /// pool-exhaustion refusals reselect another exit; everything else is a
    /// transient network/QUIC failure worth an immediate redial of the same
    /// target. The client `match`es this instead of re-deriving the policy.
    #[must_use]
    pub fn retryability(&self) -> warrenguard_wire::Retryability {
        use warrenguard_wire::{FatalCause, Retryability};
        match self {
            TunnelError::AuthRejected
            | TunnelError::AllowlistDenied
            | TunnelError::InbandAuthFailed => Retryability::Fatal(FatalCause::NotAuthorized),
            TunnelError::DeviceLimitReached => Retryability::Fatal(FatalCause::DeviceLimit),
            TunnelError::ExitDrainingRefused | TunnelError::PoolExhausted => {
                Retryability::RetryReselect
            }
            _ => Retryability::RetrySameTarget,
        }
    }
}

/// Convenience alias for `Result<T, TunnelError>`. Mirrors the
/// `anyhow::Result` ergonomics callers had before the migration.
pub type Result<T> = std::result::Result<T, TunnelError>;

/// Surfaces a DAITA spec failure as a transport error at the boundary.
///
/// The DAITA module ([`warrenguard_daita`]) was carved out with its own
/// [`DaitaError`], so a consumer that builds a [`warrenguard_daita::DaitaState`]
/// directly (outside the pump, e.g. the app's tunnel adapter when an exit ships
/// a `DaitaConfig`) needs to fold that failure into the pump-level
/// [`TunnelError`] it already returns. The variants map onto the existing
/// DAITA-flavoured [`TunnelError`] variants; the carried strings are upstream
/// `maybenot` messages (no PII).
impl From<DaitaError> for TunnelError {
    fn from(err: DaitaError) -> Self {
        match err {
            DaitaError::InvalidMachine(msg) => TunnelError::DaitaInvalidMachine(msg),
            DaitaError::InvalidFraction => {
                TunnelError::DaitaFramework("DAITA fractions outside 0.0..=1.0".to_owned())
            }
            DaitaError::Framework(msg) => TunnelError::DaitaFramework(msg),
            // `DaitaError` is non-exhaustive: fold any future variant into the
            // framework bucket rather than panicking, preserving its message.
            other => TunnelError::DaitaFramework(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daita_invalid_machine_maps_to_transport_machine_variant() {
        let te: TunnelError = DaitaError::InvalidMachine("bad spec".to_owned()).into();
        assert!(
            matches!(te, TunnelError::DaitaInvalidMachine(ref s) if s == "bad spec"),
            "machine-parse failure must surface as DaitaInvalidMachine, got {te:?}"
        );
    }

    #[test]
    fn daita_invalid_fraction_maps_to_framework_variant() {
        let te: TunnelError = DaitaError::InvalidFraction.into();
        // The fraction error is payload-less, so the mapping synthesises the
        // message: assert both the variant AND that the synthesised text names
        // the offending range (a silent message regression must be caught).
        assert!(
            matches!(te, TunnelError::DaitaFramework(ref s) if s.contains("0.0..=1.0")),
            "fraction-range failure must surface as DaitaFramework naming the range, got {te:?}"
        );
    }

    #[test]
    fn daita_framework_preserves_message() {
        let te: TunnelError = DaitaError::Framework("rejected".to_owned()).into();
        assert!(
            matches!(te, TunnelError::DaitaFramework(ref s) if s == "rejected"),
            "framework failure must keep its message, got {te:?}"
        );
    }

    #[test]
    fn business_rejections_are_fatal_transport_errors_are_transient() {
        use warrenguard_wire::{FatalCause, Retryability};
        // The fatal set must STOP a supervisor. If any of these flips to a
        // retryable verdict, a rejected user loops "Reconnecting" forever.
        assert_eq!(
            TunnelError::AuthRejected.retryability(),
            Retryability::Fatal(FatalCause::NotAuthorized)
        );
        assert_eq!(
            TunnelError::DeviceLimitReached.retryability(),
            Retryability::Fatal(FatalCause::DeviceLimit)
        );
        // Reselect set: not the account's fault, but the same exit re-hits it.
        assert_eq!(
            TunnelError::ExitDrainingRefused.retryability(),
            Retryability::RetryReselect
        );
        assert_eq!(
            TunnelError::PoolExhausted.retryability(),
            Retryability::RetryReselect,
            "pool exhaustion aligns single-hop with multi-hop IpExhausted"
        );
        // A plain network loss retries the same target.
        assert_eq!(
            TunnelError::NoExitAddr.retryability(),
            Retryability::RetrySameTarget
        );
    }
}
