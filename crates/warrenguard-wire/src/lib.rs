//! Application-level frames exchanged on the Warren tunnel.
//!
//! Encoding: `postcard` (deterministic, no-std friendly, more compact than
//! CBOR for our use case).

mod exit_addr;
mod exit_id;
mod pubkey;
mod setup_v7;

pub use exit_addr::{WarrenExitAddr, WarrenTransportAddr};
pub use exit_id::{EXIT_ID_LEN, ExitId, ExitIdError};
pub use pubkey::{PUBKEY_LEN, WarrenPubkey, WarrenPubkeyError};
pub use setup_v7::{
    ATTACH_SECRET_LEN, AnySetup, MAX_SESSION_TOKENS, SESSION_TOKEN_LEN, SessionToken, SetupAckV7,
    SetupV7, decode_setup_ack_v7, decode_setup_any, decode_setup_v7, encode_setup_ack_v7,
    encode_setup_v7,
};

use serde::{Deserialize, Serialize};

/// Warren application protocol version; must be bumped on every
/// wire-format-incompatible change to [`Setup`] / [`SetupAck`].
///
/// Version 2 added `connection_index` + `total_connections` in [`Setup`]
/// and `multiconn_attached` in [`SetupAck`], allowing a client to open
/// N parallel QUIC connections to the same exit to break the throughput
/// ceiling of a single `quinn::Connection`'s internal serialization.
///
/// Version 3 (DAITA v2) added `daita_support: bool` in
/// [`Setup`] and `daita_spec: Option<DaitaConfig>` in [`SetupAck`]. The
/// exit picks one machine from a server-side pool per session, sends
/// the [`DaitaConfig`] back to the client, and both sides instantiate
/// the [`maybenot::Framework`] from that same config. ALPN remains
/// `ALPN_H3` (obfuscation invariant) so the version negotiation
/// happens in-band on the setup stream.
///
/// Version 4 added `device_id: [u8; DEVICE_ID_LEN]` in [`Setup`]: a
/// random, ephemeral per-run identifier that lets the exit count
/// distinct simultaneous *devices* of one account (all of which share
/// the same wallet pubkey) and enforce a server-side per-account device
/// cap (a deployment policy of the exit operator). All connections of one
/// client run carry the same `device_id`, so multi-conn does not inflate
/// the count.
///
/// Version 5 moved client authentication off the TLS layer and into
/// [`Setup`] via `client_pubkey` + `auth_sig`. The exit no longer
/// requests a TLS client certificate (that mutual-auth CertificateRequest
/// was an active-probing tell: no public HTTP/3 server demands a client
/// cert). Instead the client proves possession of its Ed25519 identity by
/// signing the QUIC TLS exporter (channel binding) in-band.
///
/// Existing deployments must be upgraded in lockstep: postcard with
/// `deny_unknown_fields` does not allow soft backward-compatibility.
///
/// Version 7 (anonymous session-token admission, Privacy Pass) replaces the
/// `client_pubkey` + `auth_sig` subscription proof in [`Setup`] with a stack
/// of Privacy Pass tokens the exit verifies offline and spends anonymously
/// (see [`SetupV7`]). Because postcard is positional, v7 is a SEPARATE frame
/// type ([`SetupV7`] / [`SetupAckV7`]) rather than an edit to the frozen v6
/// layout; a v7-capable exit dual-accepts both via [`decode_setup_any`] for
/// the whole migration window. v6 stays the default [`PROTOCOL_VERSION`]
/// until the fleet is fully v7-capable and clients cut over.
pub const PROTOCOL_VERSION: u8 = 6;

/// The anonymous-session-credential protocol version (see [`SetupV7`]). Not
/// yet the default [`PROTOCOL_VERSION`]: exits accept it alongside v6 during
/// the dual-accept migration, and clients emit it only once the whole fleet
/// is known v7-capable.
pub const PROTOCOL_VERSION_V7: u8 = 7;

/// Length in bytes of a [`Setup::device_id`] (128-bit random ⇒ collision
/// probability negligible across an account's lifetime of reconnects).
pub const DEVICE_ID_LEN: usize = 16;

/// Length in bytes of a [`Setup::client_pubkey`] (Ed25519 public key).
pub const CLIENT_PUBKEY_LEN: usize = 32;

/// Length in bytes of a [`Setup::auth_sig`] (Ed25519 signature over the
/// QUIC TLS exporter, proving possession of `client_pubkey` and binding
/// the proof to this specific connection).
pub const AUTH_SIG_LEN: usize = 64;

/// Memory cap when reading a Setup or SetupAck frame.
///
/// - Setup is 5 wire bytes (ceiling ~10 bytes with varint extension).
/// - SetupAck is ~60 bytes at the baseline (pubkey, IPs, MTU, flags,
///   varints), and may grow to ~1-4 KB when carrying a
///   [`DaitaConfig`] populated with one or more serialized maybenot
///   machines (a single machine spec encodes typically to 50-500
///   bytes base64; complex defenses with hundreds of states can reach
///   several KB).
///
/// 16 KB is generous enough to absorb future machine pool growth
/// while still preventing a hostile peer from amplifying heap
/// allocations through an over-sized frame.
pub const MAX_SETUP_FRAME_BYTES: usize = 16 * 1024;

/// Ed25519 in-band client-auth signature, carried on the wire as 64 raw
/// bytes (no length prefix). Newtype because serde has no built-in
/// `[u8; 64]` impls; the manual impl serialises as a fixed 64-tuple so
/// postcard emits exactly the 64 signature bytes, deterministically.
/// Mirrors the established `warrenguard-multihop` `PopSignature` pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSig(pub [u8; AUTH_SIG_LEN]);

impl Serialize for AuthSig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(AUTH_SIG_LEN)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for AuthSig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = AuthSig;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("64 raw Ed25519 signature bytes")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; AUTH_SIG_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(AuthSig(out))
            }
        }
        deserializer.deserialize_tuple(AUTH_SIG_LEN, SigVisitor)
    }
}

/// First frame sent by the client when opening a bidirectional stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    /// Warren application protocol version.
    pub protocol_version: u8,
    /// Bitmask of features requested by the client (see [`features`]).
    pub features: u32,
    /// 0-based index of this connection within the client's multi-conn
    /// session. `0` = primary connection (the exit assigns or reuses a
    /// tunnel IP for this identity). `1..total_connections-1` =
    /// secondary connections that must attach to the existing session
    /// of the same Ed25519 identity. For a mono-conn client:
    /// `connection_index = 0` and `total_connections = 1`.
    pub connection_index: u8,
    /// Total number of QUIC connections for this client session. The
    /// exit validates that `connection_index < total_connections`. All
    /// connections of a session must come from the same Ed25519 identity
    /// (verified in-band via `client_pubkey` + `auth_sig`).
    pub total_connections: u8,
    /// Client advertises DAITA v2 support. When `true`, the exit MAY
    /// respond with a [`SetupAck::daita_spec`] carrying the negotiated
    /// machine; when `false`, the exit MUST set `daita_spec = None`
    /// and no traffic-analysis defense is applied. The UI toggle
    /// `WarrenDaitaSwitch` directly maps to this field.
    pub daita_support: bool,
    /// Random, **ephemeral per-run** device identifier (16 bytes). All
    /// connections opened by one client run (including every multi-conn
    /// secondary) carry the *same* value, so it identifies a *device*,
    /// not a connection. The exit counts the distinct, currently-live
    /// `device_id`s per wallet pubkey to enforce its per-account device
    /// cap (a server-side deployment policy), and keys its session map
    /// by `(pubkey, device_id)` so distinct devices get distinct tunnel
    /// IPs instead of colliding. Never persisted on disk - a reinstall
    /// just yields a fresh id, costing no slot (live-session semantics).
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Client's Ed25519 identity public key. Since protocol v5 the exit no
    /// longer learns the client identity from a TLS client certificate
    /// (that mutual-auth handshake was an active-probing tell); the client
    /// declares it here and proves possession via `auth_sig`. The exit
    /// runs its `Authorizer` gate on this value. All zeros is the sentinel
    /// for "not yet stamped" (see [`Setup::with_auth`]); a real client
    /// always stamps its key, and the exit rejects an unverifiable proof.
    pub client_pubkey: [u8; CLIENT_PUBKEY_LEN],
    /// Ed25519 signature by `client_pubkey` over the 32-byte QUIC TLS
    /// exporter of THIS connection (channel binding). Binding the proof to
    /// the per-connection exporter makes a captured `Setup` useless on any
    /// other connection: a different exit derives a different exporter, so
    /// the signature fails to verify. This replaces the TLS
    /// CertificateVerify transcript binding removed in v5.
    pub auth_sig: AuthSig,
}

impl Setup {
    /// Builds a single-connection [`Setup`]: `connection_index = 0`,
    /// `total_connections = 1`, `daita_support = false`. Default case
    /// when the client does not use QUIC multi-conn and DAITA is off.
    #[must_use]
    pub fn single_conn(features: u32) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            features,
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            // Default sentinel; the real client sets a random per-run id
            // via [`Self::with_device_id`]. Tests that do not exercise the
            // device cap keep the all-zero default.
            device_id: [0u8; DEVICE_ID_LEN],
            // Auth sentinels; the real client stamps its identity and the
            // channel-binding proof via [`Self::with_auth`] once the QUIC
            // exporter is available. The exit rejects the all-zero proof.
            client_pubkey: [0u8; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0u8; AUTH_SIG_LEN]),
        }
    }

    /// Sets the per-run [`Self::device_id`]. The client generates one
    /// random 16-byte id at startup and stamps it on **every** `Setup`
    /// it sends (primary + all multi-conn secondaries) so the exit sees
    /// one device, not N.
    #[must_use]
    pub fn with_device_id(mut self, device_id: [u8; DEVICE_ID_LEN]) -> Self {
        self.device_id = device_id;
        self
    }

    /// Stamps the in-band client authentication (protocol v5). `client_pubkey`
    /// is the client's Ed25519 identity; `auth_sig` is that key's signature
    /// over the connection's 32-byte QUIC TLS exporter (channel binding). The
    /// client calls this after the handshake completes and the exporter is
    /// derivable. Every `Setup` of a multi-conn session carries the same
    /// `client_pubkey`, but each carries its OWN `auth_sig` because each QUIC
    /// connection has a distinct exporter.
    #[must_use]
    pub fn with_auth(
        mut self,
        client_pubkey: [u8; CLIENT_PUBKEY_LEN],
        auth_sig: [u8; AUTH_SIG_LEN],
    ) -> Self {
        self.client_pubkey = client_pubkey;
        self.auth_sig = AuthSig(auth_sig);
        self
    }

    /// Builds a single-connection [`Setup`] that advertises DAITA v2
    /// support. The exit decides whether to actually deploy a machine.
    #[must_use]
    pub fn single_conn_with_daita(features: u32) -> Self {
        Self {
            daita_support: true,
            ..Self::single_conn(features)
        }
    }

    /// Builds a [`Setup`] for the `idx`-th connection of a multi-conn
    /// session containing `total` connections. `daita_support = false`.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= total` or `total == 0` (protocol invariant:
    /// the exit would reject the connection otherwise, so fail fast).
    #[must_use]
    pub fn multi_conn(features: u32, idx: u8, total: u8) -> Self {
        assert!(total >= 1, "total_connections must be >= 1");
        assert!(
            idx < total,
            "connection_index ({idx}) must be < total_connections ({total})"
        );
        Self {
            protocol_version: PROTOCOL_VERSION,
            features,
            connection_index: idx,
            total_connections: total,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
            client_pubkey: [0u8; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0u8; AUTH_SIG_LEN]),
        }
    }

    /// Builds a [`Setup`] for the `idx`-th connection of a multi-conn
    /// session, advertising DAITA v2 support.
    ///
    /// # Panics
    ///
    /// Same panics as [`Self::multi_conn`].
    #[must_use]
    pub fn multi_conn_with_daita(features: u32, idx: u8, total: u8) -> Self {
        Self {
            daita_support: true,
            ..Self::multi_conn(features, idx, total)
        }
    }
}

/// Exit's response. Gives the client its assigned tunnel IP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupAck {
    /// Protocol version accepted by the exit (equal to [`PROTOCOL_VERSION`]).
    pub protocol_version: u8,
    /// Tunnel IPv4 `10.66.x.y/32` assigned to this session.
    /// For secondary connections of a multi-conn session, the exit
    /// returns the IP **already assigned** to the primary connection -
    /// all connections of a session share the same client-visible IP.
    pub tunnel_ipv4: [u8; 4],
    /// Optional tunnel IPv6 (`fdwa::/64`).
    pub tunnel_ipv6: Option<[u8; 16]>,
    /// Confirmation of the exit's Ed25519 pubkey.
    pub exit_pubkey: [u8; 32],
    /// Conservative session MTU the exit advertises (a fixed value, not the
    /// result of a negotiation). Advisory ceiling only: the real usable
    /// datagram size is governed by QUIC DPLPMTUD path-MTU discovery, so a
    /// consumer must not size a TUN straight to this without its own PMTU
    /// probing or it risks a black hole until discovery converges.
    pub max_mtu: u16,
    /// `true` if this connection was correctly attached to the client
    /// session (nominal case). `false` if the exit refused attachment
    /// (e.g. `connection_index >= total_connections` announced in
    /// `Setup`, or the session primary has not been established yet
    /// when a secondary arrives). The client must then close this
    /// connection and retry, or fall back to mono-conn.
    pub multiconn_attached: bool,
    /// DAITA v2 machine spec selected by the exit for this session, or
    /// `None` if DAITA is disabled (because the client did not request
    /// it via [`Setup::daita_support`], or because the exit policy
    /// declined for this session). When `Some(_)`, the client MUST
    /// instantiate a [`crate::DaitaConfig`]-driven framework mirroring
    /// the spec. Secondary connections of a multi-conn session share
    /// the same `daita_spec` as the primary; the exit returns the
    /// already-negotiated spec on every attach so all N tasks driving
    /// the N Quinn connections see the same defense.
    pub daita_spec: Option<DaitaConfig>,
    /// Ed25519 signature by the exit's identity key over the 32-byte QUIC
    /// TLS exporter of THIS connection (the same channel binding the client
    /// proves possession against in `Setup::auth_sig`), under the
    /// `warrenguard/inband-server-auth/v1` context. Lets the client confirm
    /// it reached the expected Warren exit (the pubkey it dialed) even when
    /// the exit presents an ordinary X.509 certificate instead of an RFC
    /// 7250 raw public key (v6 X.509 exit mode). All-zero is the sentinel for
    /// paths that do not carry a single-hop client<->exit channel binding
    /// (e.g. the HPKE-framed multi-hop setup); the single-hop client always
    /// verifies a real proof. See [`crate::AuthSig`] and the engine
    /// `warrenguard_tls::auth::{sign_server_auth, verify_server_auth}`.
    pub exit_auth_sig: AuthSig,
}

/// Wire-transmissible DAITA v2 configuration negotiated at handshake.
///
/// Carried inside [`SetupAck::daita_spec`]. The exit selects one (or
/// more) [`maybenot::Machine`] from its server-side pool, serializes
/// each via `Machine::serialize()`, and ships the strings here. Both
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
    /// `SetupAck::daita_spec = None` instead).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.machine_specs.is_empty()
    }

    /// Returns `true` if the fractional caps are within `[0.0, 1.0]`
    /// and finite. A remote peer can send arbitrary values via
    /// `SetupAck`; callers must validate before passing to maybenot.
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
    /// `SetupAck::daita_spec = None`.
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
    /// profile). The client enables uplink padding locally via
    /// `ClientTunnel::with_pad_to_mtu`; this bit signals it did so. Exit
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
    /// A decoded `Setup` frame has an invalid `connection_index >=
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
    /// A v7 [`SetupV7`] carried more than [`MAX_SESSION_TOKENS`] tokens
    /// (a bounded-allocation guard against a hostile peer).
    #[error("too many session tokens: {count} (max {max})")]
    TooManyTokens {
        /// Token count in the frame.
        count: usize,
        /// The allowed ceiling ([`MAX_SESSION_TOKENS`]).
        max: usize,
    },
    /// A v7 primary [`SetupV7`] (`connection_index == 0`) carried no session
    /// token; the primary must spend one to open the session.
    #[error("v7 primary Setup carries no session token")]
    MissingSessionToken,
    /// A v7 secondary [`SetupV7`] (`connection_index != 0`) carried a session
    /// token; a secondary attaches via `attach_secret`, never a token.
    #[error("v7 secondary Setup carries an unexpected session token")]
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

/// Encodes a [`Setup`] frame to bytes (postcard).
///
/// # Errors
///
/// Returns [`ProtocolError::Codec`] if `postcard` encoding fails (should
/// never happen in practice for this fixed type).
pub fn encode_setup(setup: &Setup) -> Result<Vec<u8>, ProtocolError> {
    Ok(postcard::to_allocvec(setup)?)
}

/// Decodes a [`Setup`] frame from bytes.
///
/// Uses `postcard::take_from_bytes` rather than `from_bytes` to reject
/// trailing bytes after the valid Setup. `#[serde(deny_unknown_fields)]`
/// is ignored by postcard (sequential binary format without field tags),
/// so a malicious peer could otherwise amplify heap allocations by
/// sending 64 KB of garbage after a valid Setup.
///
/// # Errors
///
/// - [`ProtocolError::Codec`] if the buffer does not decode as
///   [`Setup`] or contains bytes after the frame.
/// - [`ProtocolError::VersionMismatch`] if the announced version
///   differs.
pub fn decode_setup(buf: &[u8]) -> Result<Setup, ProtocolError> {
    let (s, rest): (Setup, _) = postcard::take_from_bytes(buf)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes);
    }
    if s.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            got: s.protocol_version,
        });
    }
    if s.total_connections == 0 || s.connection_index >= s.total_connections {
        return Err(ProtocolError::InvalidMultiConn {
            index: s.connection_index,
            total: s.total_connections,
        });
    }
    Ok(s)
}

/// Encodes a [`SetupAck`] frame to bytes (postcard).
///
/// # Errors
///
/// See [`encode_setup`].
pub fn encode_setup_ack(ack: &SetupAck) -> Result<Vec<u8>, ProtocolError> {
    Ok(postcard::to_allocvec(ack)?)
}

/// Decodes a [`SetupAck`] frame from bytes. Rejects trailing bytes
/// (see [`decode_setup`]).
///
/// # Errors
///
/// See [`decode_setup`].
pub fn decode_setup_ack(buf: &[u8]) -> Result<SetupAck, ProtocolError> {
    let (a, rest): (SetupAck, _) = postcard::take_from_bytes(buf)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes);
    }
    if a.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            got: a.protocol_version,
        });
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_setup() {
        let s = Setup::single_conn(features::MULTIPATH | features::PORT_FORWARD);
        let bytes = encode_setup(&s).unwrap();
        let decoded = decode_setup(&bytes).unwrap();
        assert_eq!(
            s, decoded,
            "Setup encode/decode must be a perfect bijection: a missed field \
             would silently let the exit interpret a different feature set"
        );
    }

    #[test]
    fn with_auth_survives_roundtrip() {
        // The in-band client auth (v5) must encode and decode byte-for-byte:
        // a dropped pubkey or signature byte would make the exit reject a
        // legitimate client or, worse, misattribute its session.
        let pk = [0x11u8; CLIENT_PUBKEY_LEN];
        let sig = [0x22u8; AUTH_SIG_LEN];
        let s = Setup::single_conn(features::MULTIPATH).with_auth(pk, sig);
        let decoded = decode_setup(&encode_setup(&s).unwrap()).unwrap();
        assert_eq!(decoded.client_pubkey, pk, "client_pubkey must round-trip");
        assert_eq!(decoded.auth_sig.0, sig, "auth_sig must round-trip");
        assert_eq!(s, decoded, "full Setup must be a perfect bijection");
    }

    /// Test helper: a baseline `SetupAck` with DAITA disabled, used to
    /// keep the bulk of v2-era assertions terse now that the struct has
    /// an extra mandatory field.
    fn ack_no_daita(version: u8) -> SetupAck {
        SetupAck {
            protocol_version: version,
            tunnel_ipv4: [10, 66, 42, 7],
            tunnel_ipv6: None,
            exit_pubkey: [0xab; 32],
            max_mtu: 1350,
            multiconn_attached: true,
            daita_spec: None,
            exit_auth_sig: AuthSig([0x99; AUTH_SIG_LEN]),
        }
    }

    #[test]
    fn roundtrip_setup_ack() {
        let a = ack_no_daita(PROTOCOL_VERSION);
        let bytes = encode_setup_ack(&a).unwrap();
        let decoded = decode_setup_ack(&bytes).unwrap();
        assert_eq!(
            a, decoded,
            "SetupAck encode/decode must be a perfect bijection: drift means \
             the client computes a different tunnel IP than the exit assigned"
        );
    }

    #[test]
    fn setup_wire_format_is_stable_v5() {
        // Vector test: if anyone changes the encoding, this test breaks
        // and PROTOCOL_VERSION must be bumped.
        let s = Setup {
            protocol_version: 5,
            features: 0x03, // MULTIPATH | PORT_FORWARD
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            device_id: [0xAB; DEVICE_ID_LEN],
            client_pubkey: [0xCD; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0xEF; AUTH_SIG_LEN]),
        };
        let bytes = encode_setup(&s).unwrap();
        // postcard layout (PROTOCOL_VERSION=5):
        //   - protocol_version u8        = 0x05
        //   - features u32 varint(3)     = 0x03
        //   - connection_index u8        = 0x00
        //   - total_connections u8       = 0x01
        //   - daita_support bool false   = 0x00
        //   - device_id [u8; 16]         = 16 raw bytes (no length prefix)
        //   - client_pubkey [u8; 32]     = 32 raw bytes (no length prefix)
        //   - auth_sig [u8; 64]          = 64 raw bytes (no length prefix)
        let mut expected = vec![0x05, 0x03, 0x00, 0x01, 0x00];
        expected.extend_from_slice(&[0xAB; DEVICE_ID_LEN]);
        expected.extend_from_slice(&[0xCD; CLIENT_PUBKEY_LEN]);
        expected.extend_from_slice(&[0xEF; AUTH_SIG_LEN]);
        assert_eq!(
            bytes, expected,
            "Setup v5 wire layout is frozen: any change here MUST bump \
             PROTOCOL_VERSION and ship a vector test for the new version"
        );
    }

    #[test]
    fn setup_wire_format_multi_conn_secondary() {
        // Vector test: the 3rd connection (idx=2) of a 4-conn session.
        let s = Setup {
            protocol_version: 5,
            features: 0,
            connection_index: 2,
            total_connections: 4,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
            client_pubkey: [0u8; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0u8; AUTH_SIG_LEN]),
        };
        let bytes = encode_setup(&s).unwrap();
        let mut expected = vec![0x05, 0x00, 0x02, 0x04, 0x00];
        expected.extend_from_slice(&[0u8; DEVICE_ID_LEN]);
        expected.extend_from_slice(&[0u8; CLIENT_PUBKEY_LEN]);
        expected.extend_from_slice(&[0u8; AUTH_SIG_LEN]);
        assert_eq!(
            bytes, expected,
            "multi-conn secondary Setup wire layout is frozen: an off-by-one \
             on connection_index would attach to the wrong session on the exit"
        );
    }

    #[test]
    fn setup_wire_format_with_daita_support_sets_trailing_byte() {
        // When the client advertises DAITA support, only the trailing
        // bool byte flips to 0x01; the rest of the layout is identical.
        let s = Setup {
            protocol_version: 5,
            features: 0,
            connection_index: 0,
            total_connections: 1,
            daita_support: true,
            device_id: [0u8; DEVICE_ID_LEN],
            client_pubkey: [0u8; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0u8; AUTH_SIG_LEN]),
        };
        let bytes = encode_setup(&s).unwrap();
        let mut expected = vec![0x05, 0x00, 0x00, 0x01, 0x01];
        expected.extend_from_slice(&[0u8; DEVICE_ID_LEN]);
        expected.extend_from_slice(&[0u8; CLIENT_PUBKEY_LEN]);
        expected.extend_from_slice(&[0u8; AUTH_SIG_LEN]);
        assert_eq!(
            bytes, expected,
            "Setup v5 with daita_support=true must encode the trailing \
             bool as 0x01 (postcard layout)"
        );
    }

    #[test]
    fn roundtrip_setup_with_pad_to_mtu() {
        let s = Setup::single_conn(features::PAD_TO_MTU | features::IPV6);
        let bytes = encode_setup(&s).unwrap();
        let decoded = decode_setup(&bytes).unwrap();
        assert_eq!(s, decoded, "PAD_TO_MTU feature bit must survive roundtrip");
        assert_eq!(
            decoded.features & features::PAD_TO_MTU,
            features::PAD_TO_MTU,
            "PAD_TO_MTU bit must be preserved in decoded features"
        );
    }

    #[test]
    fn pad_to_mtu_feature_bit_is_bit_3() {
        assert_eq!(features::PAD_TO_MTU, 0x08, "PAD_TO_MTU must be 1 << 3");
    }

    #[test]
    fn pq_hpke_feature_bit_is_bit_4() {
        assert_eq!(features::PQ_HPKE, 0x10, "PQ_HPKE must be 1 << 4");
    }

    #[test]
    fn setup_ack_wire_format_is_stable_v3() {
        let a = SetupAck {
            protocol_version: 3,
            tunnel_ipv4: [10, 66, 42, 7],
            tunnel_ipv6: None,
            exit_pubkey: [0u8; 32],
            max_mtu: 1350,
            multiconn_attached: true,
            daita_spec: None,
            exit_auth_sig: AuthSig([0x77; AUTH_SIG_LEN]),
        };
        let bytes = encode_setup_ack(&a).unwrap();
        // postcard layout (PROTOCOL_VERSION=3):
        //   - protocol_version: 0x03
        //   - tunnel_ipv4 fixed array 4 bytes: 0x0a 0x42 0x2a 0x07
        //   - tunnel_ipv6 Option None: 0x00
        //   - exit_pubkey fixed array 32 zero bytes
        //   - max_mtu u16 varint(1350): 0xc6 0x0a
        //   - multiconn_attached bool true: 0x01
        //   - daita_spec Option None: 0x00
        let expected_prefix: &[u8] = &[0x03, 0x0a, 0x42, 0x2a, 0x07, 0x00];
        assert_eq!(
            &bytes[..6],
            expected_prefix,
            "SetupAck v3 header (version + tunnel_ipv4 + ipv6=None) is frozen \
             wire format - any drift breaks every deployed client"
        );
        assert_eq!(
            &bytes[6..38],
            &[0u8; 32],
            "SetupAck exit_pubkey must encode as 32 raw bytes (no length prefix)"
        );
        assert_eq!(
            &bytes[38..40],
            &[0xc6, 0x0a],
            "SetupAck max_mtu must encode as postcard u16 varint(1350)"
        );
        assert_eq!(
            &bytes[40..42],
            &[0x01, 0x00],
            "SetupAck trailing bytes = multiconn_attached(true=0x01) + \
             daita_spec(None=0x00). Any change MUST bump PROTOCOL_VERSION"
        );
        assert_eq!(
            &bytes[42..106],
            &[0x77; AUTH_SIG_LEN],
            "SetupAck exit_auth_sig (v6) must encode as 64 raw bytes \
             (no length prefix) immediately after daita_spec"
        );
        assert_eq!(bytes.len(), 106, "SetupAck v6 total length is frozen");
    }

    #[test]
    fn setup_single_conn_helper_produces_canonical_default() {
        let s = Setup::single_conn(features::MULTIPATH);
        assert_eq!(s.protocol_version, PROTOCOL_VERSION);
        assert_eq!(s.features, features::MULTIPATH);
        assert_eq!(s.connection_index, 0);
        assert_eq!(s.total_connections, 1);
        assert!(!s.daita_support, "single_conn default MUST be DAITA-off");
    }

    #[test]
    fn setup_single_conn_with_daita_helper_sets_daita_flag() {
        let s = Setup::single_conn_with_daita(features::MULTIPATH);
        assert!(s.daita_support, "single_conn_with_daita MUST opt in");
        assert_eq!(s.connection_index, 0);
        assert_eq!(s.total_connections, 1);
        assert_eq!(s.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn setup_multi_conn_helper_validates_idx_lt_total() {
        let s = Setup::multi_conn(features::MULTIPATH, 1, 4);
        assert_eq!(s.connection_index, 1);
        assert_eq!(s.total_connections, 4);
        assert!(!s.daita_support, "multi_conn default MUST be DAITA-off");
    }

    #[test]
    fn setup_multi_conn_with_daita_helper_sets_daita_flag() {
        let s = Setup::multi_conn_with_daita(features::MULTIPATH, 2, 4);
        assert!(s.daita_support, "multi_conn_with_daita MUST opt in");
        assert_eq!(s.connection_index, 2);
        assert_eq!(s.total_connections, 4);
    }

    #[test]
    #[should_panic(expected = "connection_index")]
    fn setup_multi_conn_helper_panics_on_idx_eq_total() {
        // Protocol invariant: idx < total. If a caller uses idx = total,
        // the exit would reject the connection - fail fast client-side
        // at Setup construction.
        let _ = Setup::multi_conn(0, 4, 4);
    }

    #[test]
    #[should_panic(expected = "total_connections")]
    fn setup_multi_conn_helper_panics_on_total_zero() {
        let _ = Setup::multi_conn(0, 0, 0);
    }

    #[test]
    fn version_mismatch_is_detected() {
        let bytes = postcard::to_allocvec(&Setup {
            protocol_version: 99,
            features: 0,
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
            client_pubkey: [0u8; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0u8; AUTH_SIG_LEN]),
        })
        .unwrap();
        let err = decode_setup(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                got: 99
            }
        ));
    }

    #[test]
    fn previous_protocol_v4_is_rejected_no_interop() {
        // Cutover guard: v5 moved client auth off the TLS layer
        // and into Setup. There is deliberately NO v4<->v5 interop: a v4
        // exit speaks mutual-TLS (the active-probing tell) and a v5 exit
        // requests no client cert, so accepting a v4 client on a v5 exit
        // would either re-introduce the tell or admit an unauthenticated
        // peer. The upgrade is lockstep; this test pins that a v4-shaped
        // frame (the previous wire layout: no client_pubkey/auth_sig
        // trailer) is rejected rather than silently half-parsed.
        let mut v4_bytes = vec![0x04, 0x00, 0x00, 0x01, 0x00];
        v4_bytes.extend_from_slice(&[0u8; DEVICE_ID_LEN]);
        let err =
            decode_setup(&v4_bytes).expect_err("a v4 frame must not be accepted by a v5 build");
        // Either the version byte is caught, or the missing v5 auth
        // trailer makes postcard fail; both are a clean rejection, never
        // a silent partial parse.
        assert!(
            matches!(
                err,
                ProtocolError::VersionMismatch { got: 4, .. } | ProtocolError::Codec(_)
            ),
            "v4 frame must be rejected (version gate or truncated trailer), got {err:?}"
        );
    }

    #[test]
    fn previous_v5_setup_ack_is_rejected_no_interop() {
        // Cutover guard: v6 added the in-band exit-identity
        // proof `exit_auth_sig` as a 64-byte trailer on SetupAck (the exit now
        // presents an ordinary X.509 cert, so it must prove its Warren identity
        // in-band instead of via the RPK pinned in the SNI). A v5 exit emits no
        // such trailer. Accepting a v5-shaped SetupAck on a v6 client would
        // leave the exit identity unverified, so the upgrade is lockstep. Pin
        // that a v5-shaped frame (the previous wire layout: no exit_auth_sig
        // trailer) is rejected rather than silently half-parsed.
        // Case A: the actual v5 wire layout (no exit_auth_sig trailer). postcard
        // decodes fields in order and runs out of bytes at the missing 64-byte
        // trailer BEFORE the version gate runs, so the deterministic outcome is
        // a Codec error. This pins that the trailer is mandatory (the real
        // interop barrier): a v5 exit's SetupAck cannot be half-parsed into one
        // with exit-identity verification skipped.
        let mut v5_bytes = vec![0x05]; // protocol_version = 5
        v5_bytes.extend_from_slice(&[0x0a, 0x42, 0x00, 0x02]); // tunnel_ipv4 10.66.0.2
        v5_bytes.push(0x00); // tunnel_ipv6 None
        v5_bytes.extend_from_slice(&[0u8; 32]); // exit_pubkey
        v5_bytes.extend_from_slice(&[0xc6, 0x0a]); // max_mtu varint(1350)
        v5_bytes.push(0x00); // multiconn_attached false
        v5_bytes.push(0x00); // daita_spec None
        // NOTE: deliberately no 64-byte exit_auth_sig trailer (the v5 layout).
        let err = decode_setup_ack(&v5_bytes)
            .expect_err("a v5-shaped SetupAck (no exit_auth_sig trailer) must be rejected");
        assert!(
            matches!(err, ProtocolError::Codec(_)),
            "a truncated v5 SetupAck must fail decoding (missing exit_auth_sig trailer), got {err:?}"
        );

        // Case B: a structurally-complete v6 frame carrying a v5 version byte
        // (full exit_auth_sig present) must be caught by the version gate. This
        // exercises the VersionMismatch arm independently of the trailer-length
        // accident in case A, so a regression that dropped the version check
        // would not stay green here.
        let v5_versioned = postcard::to_allocvec(&ack_no_daita(5)).unwrap();
        let err = decode_setup_ack(&v5_versioned).expect_err("version 5 must be gated");
        assert!(
            matches!(err, ProtocolError::VersionMismatch { got: 5, .. }),
            "a v5 version byte must be rejected by the version gate, got {err:?}"
        );
    }

    #[test]
    fn invalid_multi_conn_zero_total_is_detected() {
        // A hostile peer forges total_connections = 0, which
        // Setup::multi_conn's builder assert protects against for a
        // well-behaved client but a decoder must still reject on the wire.
        let bytes = postcard::to_allocvec(&Setup {
            protocol_version: PROTOCOL_VERSION,
            features: 0,
            connection_index: 0,
            total_connections: 0,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
            client_pubkey: [0u8; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0u8; AUTH_SIG_LEN]),
        })
        .unwrap();
        let err = decode_setup(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::InvalidMultiConn { index: 0, total: 0 }
        ));
    }

    #[test]
    fn invalid_multi_conn_index_out_of_range_is_detected() {
        // connection_index (5) >= total_connections (3): the exit must
        // reject rather than attach to a session slot that does not exist.
        let bytes = postcard::to_allocvec(&Setup {
            protocol_version: PROTOCOL_VERSION,
            features: 0,
            connection_index: 5,
            total_connections: 3,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
            client_pubkey: [0u8; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0u8; AUTH_SIG_LEN]),
        })
        .unwrap();
        let err = decode_setup(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::InvalidMultiConn { index: 5, total: 3 }
        ));
    }

    #[test]
    fn setup_ack_version_mismatch_is_detected() {
        // Mirror of `version_mismatch_is_detected` on the SetupAck side.
        // Without this test, the ProtocolError::VersionMismatch path in
        // decode_setup_ack is never executed.
        let bytes = postcard::to_allocvec(&ack_no_daita(42)).unwrap();
        let err = decode_setup_ack(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                got: 42
            }
        ));
    }

    #[test]
    fn decode_setup_rejects_empty_buffer() {
        // Ensures we do not crash on an empty buffer (network case:
        // peer closes the connection before sending the frame).
        let err = decode_setup(&[]).expect_err("empty buffer must fail");
        assert!(matches!(err, ProtocolError::Codec(_)));
    }

    /// `#[serde(deny_unknown_fields)]` is ignored by postcard
    /// (sequential binary without field tags). Without explicit trailing
    /// byte rejection, `postcard::from_bytes` would consume the valid
    /// prefix and silently ignore trailing bytes - a malicious peer
    /// could send 64 KB of garbage after a valid Setup to amplify heap
    /// allocations on the exit.
    #[test]
    fn decode_setup_rejects_trailing_bytes() {
        let valid = encode_setup(&Setup {
            protocol_version: PROTOCOL_VERSION,
            features: 0,
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            device_id: [0u8; DEVICE_ID_LEN],
            client_pubkey: [0u8; CLIENT_PUBKEY_LEN],
            auth_sig: AuthSig([0u8; AUTH_SIG_LEN]),
        })
        .unwrap();
        let mut payload = valid.clone();
        payload.extend_from_slice(&[0xFF; 32]);
        let err = decode_setup(&payload).expect_err("trailing bytes must fail");
        assert!(matches!(err, ProtocolError::TrailingBytes));
    }

    #[test]
    fn decode_setup_ack_rejects_trailing_bytes() {
        let valid = encode_setup_ack(&ack_no_daita(PROTOCOL_VERSION)).unwrap();
        let mut payload = valid.clone();
        payload.extend_from_slice(&[0xAA; 16]);
        let err = decode_setup_ack(&payload).expect_err("trailing bytes must fail");
        assert!(matches!(err, ProtocolError::TrailingBytes));
    }

    #[test]
    fn decode_setup_ack_rejects_truncated_buffer() {
        // Buffer shorter than the 39+ expected SetupAck bytes.
        let err = decode_setup_ack(&[0x01, 0x0a]).expect_err("truncated must fail");
        assert!(matches!(err, ProtocolError::Codec(_)));
    }

    #[test]
    fn setup_ack_with_ipv6_roundtrips() {
        // Covers the tunnel_ipv6: Some(...) branch which is missing
        // from the other roundtrip tests (all using ipv6: None).
        let v6 = [
            0xfd, 0xc0, 0xff, 0xee, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let a = SetupAck {
            tunnel_ipv6: Some(v6),
            max_mtu: 1280,
            ..ack_no_daita(PROTOCOL_VERSION)
        };
        let bytes = encode_setup_ack(&a).unwrap();
        let decoded = decode_setup_ack(&bytes).unwrap();
        assert_eq!(decoded.tunnel_ipv6, Some(v6));
    }

    #[test]
    fn setup_ack_multiconn_rejected_roundtrips() {
        // multiconn_attached: false path (attachment refusal) - the
        // exit emits this SetupAck when a secondary arrives before its
        // primary. Vector test to lock the wire format for this case.
        let a = SetupAck {
            tunnel_ipv4: [0, 0, 0, 0],
            tunnel_ipv6: None,
            exit_pubkey: [0u8; 32],
            max_mtu: 0,
            multiconn_attached: false,
            ..ack_no_daita(PROTOCOL_VERSION)
        };
        let bytes = encode_setup_ack(&a).unwrap();
        let decoded = decode_setup_ack(&bytes).unwrap();
        assert!(!decoded.multiconn_attached);
        // exit_auth_sig (64 raw bytes) is the trailing field; immediately
        // before it sit multiconn(false=0x00) + daita_spec(None=0x00).
        assert_eq!(
            &bytes[bytes.len() - AUTH_SIG_LEN - 2..bytes.len() - AUTH_SIG_LEN],
            &[0x00, 0x00]
        );
        assert_eq!(&bytes[bytes.len() - AUTH_SIG_LEN..], &[0x99; AUTH_SIG_LEN]);
    }

    #[test]
    fn setup_ack_with_daita_spec_roundtrips() {
        // Covers the `daita_spec: Some(...)` branch with one machine
        // and non-default fractional caps.
        let spec = DaitaConfig {
            machine_specs: vec!["02eNpjYEAHjOgCAAA0AAI=".to_owned()],
            max_padding_frac: 0.05,
            max_blocking_frac: 0.1,
        };
        let a = SetupAck {
            daita_spec: Some(spec.clone()),
            ..ack_no_daita(PROTOCOL_VERSION)
        };
        let bytes = encode_setup_ack(&a).unwrap();
        let decoded = decode_setup_ack(&bytes).unwrap();
        let got = decoded.daita_spec.expect("daita_spec must round-trip");
        assert_eq!(got.machine_specs, spec.machine_specs);
        assert!((got.max_padding_frac - 0.05).abs() < 1e-12);
        assert!((got.max_blocking_frac - 0.1).abs() < 1e-12);
        assert!(
            got.is_enabled(),
            "round-tripped DaitaConfig must be enabled"
        );
    }

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
        // removes `#[from]`, the `?` operator stops working in
        // encode/decode and call sites break.
        fn use_question_mark(buf: &[u8]) -> Result<Setup, ProtocolError> {
            let s: Setup = postcard::from_bytes(buf)?;
            Ok(s)
        }
        let err = use_question_mark(&[]).unwrap_err();
        assert!(matches!(err, ProtocolError::Codec(_)));
    }

    #[test]
    fn protocol_version_constant_matches_what_we_emit() {
        // Tripwire: if someone bumps PROTOCOL_VERSION without bumping
        // the corresponding postcard schema (in particular, the
        // wire-format vector tests), this test breaks. v6 (X.509 exit
        // mode) added `SetupAck::exit_auth_sig`.
        assert_eq!(PROTOCOL_VERSION, 6);
    }
}
