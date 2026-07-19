//! Application-level frames exchanged on the Warren tunnel.
//!
//! Encoding: `postcard` (deterministic, no-std friendly, more compact than
//! CBOR for our use case).

mod exit_addr;
mod exit_id;
mod pubkey;
mod retry;
mod setup_v7;

pub use exit_addr::{WarrenExitAddr, WarrenTransportAddr};
pub use exit_id::{EXIT_ID_LEN, ExitId, ExitIdError};
pub use pubkey::{PUBKEY_LEN, WarrenPubkey, WarrenPubkeyError};
pub use retry::{FatalCause, Retryability};
pub use setup_v7::{ATTACH_SECRET_LEN, MAX_SESSION_TOKENS, SESSION_TOKEN_LEN, SessionToken};

use serde::{Deserialize, Serialize};

/// Warren application protocol version. Bumped on every
/// wire-format-incompatible change to the tunnel setup exchange (now carried
/// by the multi-hop control plane, `warrenguard_multihop`). v6 is the baseline
/// this crate's shared constants and [`DaitaConfig`] are frozen against.
pub const PROTOCOL_VERSION: u8 = 6;

/// The anonymous-session-credential protocol version (Privacy Pass session
/// tokens: [`SessionToken`], replacing a wallet-pubkey subscription proof).
pub const PROTOCOL_VERSION_V7: u8 = 7;

/// Length in bytes of a per-run ephemeral `device_id` (128-bit random ⇒
/// collision probability negligible across an account's lifetime of
/// reconnects). Keys the exit's session map and multi-conn grouping.
pub const DEVICE_ID_LEN: usize = 16;

/// Length in bytes of a client Ed25519 public key.
pub const CLIENT_PUBKEY_LEN: usize = 32;

/// Memory cap when reading a setup frame: 16 KB, generous enough to absorb a
/// [`DaitaConfig`] carrying several serialized maybenot machines while still
/// preventing a hostile peer from amplifying heap allocations through an
/// over-sized frame.
pub const MAX_SETUP_FRAME_BYTES: usize = 16 * 1024;

/// Wire-transmissible DAITA v2 configuration negotiated at handshake.
///
/// Carried in the exit's setup reply as an optional `daita_spec`. The exit
/// selects one (or more) [`maybenot::Machine`] from its server-side pool,
/// serializes each via `Machine::serialize()`, and ships the strings here. Both
/// endpoints instantiate a [`maybenot::Framework`] from the
/// reconstructed machines and the two fractional caps. Empty
/// `machine_specs` is **not** a valid wire shape: the exit MUST set
/// `daita_spec = None` instead to signal "DAITA off".
///
/// Type lives in this wire crate (pure wire surface, no maybenot
/// runtime dep) so that the transport and multihop crates can
/// share the same `DaitaConfig` type without circular crate deps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaitaConfig {
    /// Serialized maybenot machines, one entry per machine.
    /// Format: the string returned by `Machine::serialize` (base64 of
    /// version-prefixed bincode + flate2). Vector empty = config is
    /// semantically invalid (use `daita_spec: None` instead).
    pub machine_specs: Vec<String>,
    /// Hard cap on the fraction of total packets that may be padding,
    /// `0.0..=1.0`. `0.0` means machines can still send padding within
    /// their per-machine internal budget, but no fraction cap on top.
    pub max_padding_frac: f64,
    /// Hard cap on the fraction of total time that may be blocked,
    /// `0.0..=1.0`. Same semantics as `max_padding_frac`.
    pub max_blocking_frac: f64,
}

impl DaitaConfig {
    /// Builds a config from serialized maybenot machine specs and the fractional
    /// caps. The caps are stored as given; call [`Self::fractions_valid`] before
    /// handing the config to maybenot.
    #[must_use]
    pub fn from_specs(
        machine_specs: Vec<String>,
        max_padding_frac: f64,
        max_blocking_frac: f64,
    ) -> Self {
        Self {
            machine_specs,
            max_padding_frac,
            max_blocking_frac,
        }
    }

    /// True if the config has at least one machine spec. An empty
    /// [`DaitaConfig`] is a wire-format error (the exit must use
    /// `IpAssign::daita_spec = None` instead).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.machine_specs.is_empty()
    }

    /// Returns `true` if the fractional caps are within `[0.0, 1.0]`
    /// and finite. A remote peer can send arbitrary values via
    /// `IpAssign`; callers must validate before passing to maybenot.
    #[must_use]
    pub fn fractions_valid(&self) -> bool {
        (0.0..=1.0).contains(&self.max_padding_frac)
            && (0.0..=1.0).contains(&self.max_blocking_frac)
    }
}

impl Default for DaitaConfig {
    /// `Default::default()` returns an empty (`is_enabled() == false`)
    /// config: no machines, both fractional caps set to `0.0`. Useful
    /// as a struct-update base in tests and as the sentinel for "this
    /// session does not run DAITA". On the wire we still prefer
    /// `IpAssign::daita_spec = None`.
    fn default() -> Self {
        Self {
            machine_specs: Vec::new(),
            max_padding_frac: 0.0,
            max_blocking_frac: 0.0,
        }
    }
}

/// Feature bitmask. Extended over time.
pub mod features {
    /// Client supports QUIC multipath (settings toggle).
    pub const MULTIPATH: u32 = 1 << 0;
    /// Client requests a NAT-PMP external port at startup.
    pub const PORT_FORWARD: u32 = 1 << 1;
    /// Client supports IPv6 inside the tunnel.
    pub const IPV6: u32 = 1 << 2;
    /// Advisory: the client pads its own uplink QUIC packets to the path MTU
    /// (uniform packet sizes, a traffic-analysis defense for the Stealth
    /// profile). The client enables uplink padding locally; this bit
    /// signals it did so. Exit
    /// downlink padding is a per-deployment transport-config choice: the
    /// pre-handshake config model does not reconfigure padding per connection
    /// from this bit.
    pub const PAD_TO_MTU: u32 = 1 << 3;
    /// Client offers a hybrid post-quantum multihop HPKE seal (X25519 + ML-KEM-768,
    /// X-Wing style combiner) toward the exit. The client sets this bit only when
    /// it holds a `/v2` exit descriptor that carries a signed ML-KEM recipient key
    /// AND post-quantum is enabled; the exit answers with the `/v2` PQ-sealed setup
    /// frame iff it advertised an ML-KEM key AND this bit is set. If either side
    /// lacks PQ, both fall back to the `/v1` classical X25519 seal, which is exactly
    /// as secure as production ships today. The fallback is authenticated by the
    /// exit descriptor signature (the client knows whether the exit published a PQ
    /// key), so a middlebox cannot silently strip PQ by clearing this bit without
    /// the client detecting the mismatch against the signed descriptor. Additive:
    /// this is a negotiation signal only; the `/v1` wire is untouched when unset.
    pub const PQ_HPKE: u32 = 1 << 4;
}

/// Errors raised when encoding / decoding a Warren frame.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// `postcard` encode / decode error.
    #[error("postcard codec error: {0}")]
    Codec(#[from] postcard::Error),
    /// The decoded frame was followed by unexpected trailing bytes.
    #[error("trailing bytes after valid frame")]
    TrailingBytes,
    /// A decoded setup frame has an invalid `connection_index >=
    /// total_connections` or `total_connections == 0`.
    #[error("invalid multi-conn indices: index={index}, total={total}")]
    InvalidMultiConn {
        /// `connection_index` from the frame.
        index: u8,
        /// `total_connections` from the frame.
        total: u8,
    },
    /// The received frame announces a protocol version that differs
    /// from [`PROTOCOL_VERSION`].
    #[error("protocol version mismatch: expected {expected}, got {got}")]
    VersionMismatch {
        /// Expected version (= [`PROTOCOL_VERSION`]).
        expected: u8,
        /// Version announced by the peer.
        got: u8,
    },
    /// A v7 setup carried more than [`MAX_SESSION_TOKENS`] [`SessionToken`]s
    /// (a bounded-allocation guard against a hostile peer).
    #[error("too many session tokens: {count} (max {max})")]
    TooManyTokens {
        /// Token count in the frame.
        count: usize,
        /// The allowed ceiling ([`MAX_SESSION_TOKENS`]).
        max: usize,
    },
    /// A v7 primary setup (`connection_index == 0`) carried no session token;
    /// the primary must spend one to open the session.
    #[error("v7 primary setup carries no session token")]
    MissingSessionToken,
    /// A v7 secondary setup (`connection_index != 0`) carried a session token;
    /// a secondary attaches via `attach_secret`, never a token.
    #[error("v7 secondary setup carries an unexpected session token")]
    UnexpectedSessionToken,
}

/// Compile-time assertion that `ProtocolError` implements `std::error::Error`,
/// which is what allows `?`-propagation from any `anyhow::Result` fn. Not a
/// runtime test: if this bound ever breaks, the crate fails to typecheck.
#[allow(dead_code)]
fn _protocol_error_implements_std_error() {
    fn accepts<E: std::error::Error>(_: &E) {}
    accepts(&ProtocolError::VersionMismatch {
        expected: 1,
        got: 2,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_bits_are_distinct_powers_of_two_and_do_not_overlap() {
        // Features are bitmasks: if someone accidentally derives
        // PORT_FORWARD = 1 << 0 (collision with MULTIPATH), flags
        // silently mix together.
        assert_eq!(features::MULTIPATH, 1 << 0);
        assert_eq!(features::PORT_FORWARD, 1 << 1);
        assert_eq!(features::IPV6, 1 << 2);
        assert_eq!(features::PAD_TO_MTU, 1 << 3);
        assert_eq!(features::PQ_HPKE, 1 << 4);
        let all = features::MULTIPATH
            | features::PORT_FORWARD
            | features::IPV6
            | features::PAD_TO_MTU
            | features::PQ_HPKE;
        assert_eq!(all.count_ones(), 5, "feature bits must not overlap");
    }

    #[test]
    fn protocol_error_from_postcard_works() {
        // Verifies that `?` works on a `postcard::Error`. If someone
        // removes `#[from]`, the `?` operator stops working in the
        // frame codecs and call sites break.
        fn use_question_mark(buf: &[u8]) -> Result<DaitaConfig, ProtocolError> {
            let s: DaitaConfig = postcard::from_bytes(buf)?;
            Ok(s)
        }
        let err = use_question_mark(&[]).unwrap_err();
        assert!(matches!(err, ProtocolError::Codec(_)));
    }

    #[test]
    fn protocol_version_constant_matches_what_we_emit() {
        // Tripwire: if someone bumps PROTOCOL_VERSION without bumping the
        // corresponding postcard schema (in particular, the wire-format vector
        // tests), this test breaks.
        assert_eq!(PROTOCOL_VERSION, 6);
    }
}
