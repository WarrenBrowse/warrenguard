//! Protocol v7 handshake frames: anonymous session-token admission
//! (Privacy Pass).
//!
//! v7 is the privacy endgame: the client proves "I hold a
//! currently-subscribed account, under its device cap" WITHOUT naming the
//! account. The v6 [`crate::Setup`] carried
//! `client_pubkey` + `auth_sig` (the exit learned the subscriber identity);
//! v7 replaces that subscription proof with a stack of Privacy Pass
//! [session tokens](SessionToken) the exit verifies OFFLINE and spends
//! anonymously. The exit never sees the wallet.
//!
//! These are DISTINCT types from the v6 [`crate::Setup`] / [`crate::SetupAck`]
//! on purpose: postcard is a positional codec, so the only way to add a field
//! without disturbing the frozen v6 byte layout is a separate struct with its
//! own codec. The v6 structs and their golden vectors are untouched; a
//! v7-capable exit dispatches on the leading version byte via
//! [`crate::decode_setup_any`] and keeps accepting v6 for the whole dual-accept
//! migration window.
//!
//! Multi-conn in v7 drops the "same Ed25519 identity" secondary-attach check
//! (there is no identity anymore). Instead the exit returns an unguessable
//! [`SetupAckV7::attach_secret`] to the primary, and secondaries echo it in
//! [`SetupV7::attach_secret`] to prove session membership: a capability, not an
//! identity.

use serde::{Deserialize, Serialize};

use crate::{
    AuthSig, DEVICE_ID_LEN, DaitaConfig, PROTOCOL_VERSION, PROTOCOL_VERSION_V7, ProtocolError,
    Setup,
};

/// Length of one serialized Privacy Pass session token, matching
/// `warrenguard_token::TOKEN_LEN` (token_input 98 + authenticator 256). The
/// wire crate deliberately does not depend on `warrenguard-token` (layering:
/// wire is the low-level frame codec, it treats a token as an opaque bearer
/// blob), so the constant is duplicated here and pinned equal to the token
/// crate's value by a test in that crate.
pub const SESSION_TOKEN_LEN: usize = 354;

/// Length of the multi-conn attach capability (128-bit, unguessable).
pub const ATTACH_SECRET_LEN: usize = 16;

/// Upper bound on the number of tokens a v7 primary may present in one Setup
/// (current epoch + a lookahead so a long session never re-handshakes at an
/// epoch boundary). Bounds the decode allocation from a hostile peer.
pub const MAX_SESSION_TOKENS: usize = 8;

/// One serialized Privacy Pass token, carried as [`SESSION_TOKEN_LEN`] raw
/// bytes with no length prefix (like [`AuthSig`]). The wire crate does not
/// interpret the bytes; the exit parses them with `warrenguard_token::Token`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionToken(pub [u8; SESSION_TOKEN_LEN]);

impl core::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A token is a bearer credential: never render its bytes.
        f.write_str("SessionToken(..)")
    }
}

impl Serialize for SessionToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(SESSION_TOKEN_LEN)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for SessionToken {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenVisitor;
        impl<'de> serde::de::Visitor<'de> for TokenVisitor {
            type Value = SessionToken;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{SESSION_TOKEN_LEN} raw session-token bytes")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; SESSION_TOKEN_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(SessionToken(out))
            }
        }
        deserializer.deserialize_tuple(SESSION_TOKEN_LEN, TokenVisitor)
    }
}

/// First frame sent by a v7 client. Same session parameters as [`Setup`], but
/// the subscription proof is a stack of anonymous [`SessionToken`]s instead of
/// `client_pubkey` + `auth_sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupV7 {
    /// Warren application protocol version (always [`PROTOCOL_VERSION_V7`]).
    pub protocol_version: u8,
    /// Bitmask of features requested (see [`crate::features`]).
    pub features: u32,
    /// 0-based index of this connection within the multi-conn session.
    pub connection_index: u8,
    /// Total QUIC connections in this session (`connection_index < total`).
    pub total_connections: u8,
    /// Client advertises DAITA v2 support.
    pub daita_support: bool,
    /// Random ephemeral per-run device id. Unchanged role from v6, but in v7
    /// it carries NO identity: it only keys the exit's session map and
    /// multi-conn grouping. One value per client run, on every connection.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// The subscription proof: for the PRIMARY connection
    /// (`connection_index == 0`) a non-empty stack of Privacy Pass tokens
    /// (current epoch first, then a lookahead for epoch rollover); the exit
    /// verifies token[0] offline and spends it. For a SECONDARY connection
    /// this is empty (it attaches via [`Self::attach_secret`] instead).
    pub session_tokens: Vec<SessionToken>,
    /// The multi-conn attach capability. All-zero for the primary. For a
    /// secondary, the [`SetupAckV7::attach_secret`] the exit returned to the
    /// primary, proving this connection belongs to the same session without
    /// revealing any identity.
    pub attach_secret: [u8; ATTACH_SECRET_LEN],
}

impl SetupV7 {
    /// Builds a v7 PRIMARY single-connection setup carrying `tokens`
    /// (`connection_index = 0`, `total_connections = 1`, DAITA off).
    #[must_use]
    pub fn primary_single(
        features: u32,
        device_id: [u8; DEVICE_ID_LEN],
        tokens: Vec<SessionToken>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION_V7,
            features,
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            device_id,
            session_tokens: tokens,
            attach_secret: [0u8; ATTACH_SECRET_LEN],
        }
    }

    /// Builds a v7 PRIMARY connection of a `total`-connection multi-conn
    /// session (`connection_index = 0`).
    ///
    /// # Panics
    /// If `total == 0`.
    #[must_use]
    pub fn primary_multi(
        features: u32,
        device_id: [u8; DEVICE_ID_LEN],
        tokens: Vec<SessionToken>,
        total: u8,
    ) -> Self {
        assert!(total >= 1, "total_connections must be >= 1");
        Self {
            total_connections: total,
            ..Self::primary_single(features, device_id, tokens)
        }
    }

    /// Builds a v7 SECONDARY connection (`idx` of `total`) echoing the
    /// `attach_secret` the exit returned to the primary. Carries no tokens.
    ///
    /// # Panics
    /// If `idx == 0` (that is the primary), `idx >= total`, or `total == 0`.
    #[must_use]
    pub fn secondary(
        features: u32,
        device_id: [u8; DEVICE_ID_LEN],
        attach_secret: [u8; ATTACH_SECRET_LEN],
        idx: u8,
        total: u8,
    ) -> Self {
        assert!(total >= 1, "total_connections must be >= 1");
        assert!(
            idx >= 1,
            "connection_index 0 is the primary, not a secondary"
        );
        assert!(
            idx < total,
            "connection_index ({idx}) must be < total_connections ({total})"
        );
        Self {
            protocol_version: PROTOCOL_VERSION_V7,
            features,
            connection_index: idx,
            total_connections: total,
            daita_support: false,
            device_id,
            session_tokens: Vec::new(),
            attach_secret,
        }
    }

    /// Opts this setup into DAITA v2 support.
    #[must_use]
    pub fn with_daita(mut self) -> Self {
        self.daita_support = true;
        self
    }

    /// `true` if this is the session primary (`connection_index == 0`).
    #[must_use]
    pub fn is_primary(&self) -> bool {
        self.connection_index == 0
    }
}

/// Exit response to a [`SetupV7`]. Same shape as [`crate::SetupAck`] plus the
/// multi-conn [`Self::attach_secret`] the primary hands to its secondaries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupAckV7 {
    /// Protocol version accepted (always [`PROTOCOL_VERSION_V7`]).
    pub protocol_version: u8,
    /// Tunnel IPv4 assigned to this session.
    pub tunnel_ipv4: [u8; 4],
    /// Optional tunnel IPv6.
    pub tunnel_ipv6: Option<[u8; 16]>,
    /// Confirmation of the exit's Ed25519 pubkey.
    pub exit_pubkey: [u8; 32],
    /// Advisory session MTU ceiling.
    pub max_mtu: u16,
    /// `true` if this connection attached to the session (nominal).
    pub multiconn_attached: bool,
    /// Negotiated DAITA v2 machine spec, or `None` if DAITA is off.
    pub daita_spec: Option<DaitaConfig>,
    /// Exit's in-band identity proof over this connection's QUIC TLS exporter
    /// (same channel binding as v6 [`crate::SetupAck::exit_auth_sig`]).
    pub exit_auth_sig: AuthSig,
    /// The capability a secondary echoes in [`SetupV7::attach_secret`] to join
    /// this session. Returned to the PRIMARY only (all-zero on a secondary's
    /// ack). Derived deterministically by the exit from the session's anonymous
    /// serial (`attach_secret_for_serial`), which never leaves the exit, so a
    /// primary reconnect regenerates the same capability without persisting it,
    /// yet it stays unguessable to anyone without the serial. Replaces v6's
    /// "same Ed25519 identity" attach check, which no longer exists (there is
    /// no identity in v7).
    pub attach_secret: [u8; ATTACH_SECRET_LEN],
}

/// Encodes a [`SetupV7`] (postcard).
///
/// # Errors
/// [`ProtocolError::Codec`] on a postcard failure (never in practice).
pub fn encode_setup_v7(setup: &SetupV7) -> Result<Vec<u8>, ProtocolError> {
    Ok(postcard::to_allocvec(setup)?)
}

/// Decodes a [`SetupV7`] and enforces the v7 invariants: exact version,
/// no trailing bytes, valid multi-conn indices, a bounded token count, and
/// the primary/secondary token-vs-attach_secret shape.
///
/// # Errors
/// [`ProtocolError`]; see each variant.
pub fn decode_setup_v7(buf: &[u8]) -> Result<SetupV7, ProtocolError> {
    let (s, rest): (SetupV7, _) = postcard::take_from_bytes(buf)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes);
    }
    if s.protocol_version != PROTOCOL_VERSION_V7 {
        return Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION_V7,
            got: s.protocol_version,
        });
    }
    if s.total_connections == 0 || s.connection_index >= s.total_connections {
        return Err(ProtocolError::InvalidMultiConn {
            index: s.connection_index,
            total: s.total_connections,
        });
    }
    if s.session_tokens.len() > MAX_SESSION_TOKENS {
        return Err(ProtocolError::TooManyTokens {
            count: s.session_tokens.len(),
            max: MAX_SESSION_TOKENS,
        });
    }
    // Shape gate: the primary MUST bring at least one token (it spends one to
    // open the session); a secondary MUST bring none (it attaches via the
    // capability). A malformed shape is rejected rather than half-admitted.
    if s.connection_index == 0 && s.session_tokens.is_empty() {
        return Err(ProtocolError::MissingSessionToken);
    }
    if s.connection_index != 0 && !s.session_tokens.is_empty() {
        return Err(ProtocolError::UnexpectedSessionToken);
    }
    Ok(s)
}

/// Encodes a [`SetupAckV7`] (postcard).
///
/// # Errors
/// See [`encode_setup_v7`].
pub fn encode_setup_ack_v7(ack: &SetupAckV7) -> Result<Vec<u8>, ProtocolError> {
    Ok(postcard::to_allocvec(ack)?)
}

/// Decodes a [`SetupAckV7`], rejecting trailing bytes and a wrong version.
///
/// # Errors
/// See [`decode_setup_v7`].
pub fn decode_setup_ack_v7(buf: &[u8]) -> Result<SetupAckV7, ProtocolError> {
    let (a, rest): (SetupAckV7, _) = postcard::take_from_bytes(buf)?;
    if !rest.is_empty() {
        return Err(ProtocolError::TrailingBytes);
    }
    if a.protocol_version != PROTOCOL_VERSION_V7 {
        return Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION_V7,
            got: a.protocol_version,
        });
    }
    Ok(a)
}

/// A decoded setup frame of either accepted protocol version. The exit accept
/// loop matches on this: the [`AnySetup::V6`] arm runs the legacy
/// wallet-pubkey admission, the [`AnySetup::V7`] arm the anonymous-token one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnySetup {
    /// Legacy wallet-authenticated setup (`client_pubkey` + `auth_sig`).
    V6(Setup),
    /// Anonymous token setup.
    V7(SetupV7),
}

impl AnySetup {
    /// The protocol version of the decoded frame.
    #[must_use]
    pub fn version(&self) -> u8 {
        match self {
            AnySetup::V6(_) => PROTOCOL_VERSION,
            AnySetup::V7(_) => PROTOCOL_VERSION_V7,
        }
    }
}

/// Dual-accept decode: dispatch on the leading version byte and decode the
/// matching layout. This is what a v7-capable exit calls; a peer speaking any
/// other version is rejected with [`ProtocolError::VersionMismatch`]. Keeps
/// the strict single-version [`crate::decode_setup`] untouched for callers
/// that have not migrated.
///
/// # Errors
/// [`ProtocolError`]; see each variant.
pub fn decode_setup_any(buf: &[u8]) -> Result<AnySetup, ProtocolError> {
    let version = *buf.first().ok_or(ProtocolError::Codec(
        postcard::Error::DeserializeUnexpectedEnd,
    ))?;
    match version {
        PROTOCOL_VERSION => crate::decode_setup(buf).map(AnySetup::V6),
        PROTOCOL_VERSION_V7 => decode_setup_v7(buf).map(AnySetup::V7),
        got => Err(ProtocolError::VersionMismatch {
            expected: PROTOCOL_VERSION_V7,
            got,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_token(fill: u8) -> SessionToken {
        SessionToken([fill; SESSION_TOKEN_LEN])
    }

    #[test]
    fn primary_setup_roundtrips() {
        let s = SetupV7::primary_single(
            crate::features::MULTIPATH,
            [0x11; DEVICE_ID_LEN],
            vec![a_token(0xAB)],
        );
        let decoded = decode_setup_v7(&encode_setup_v7(&s).unwrap()).unwrap();
        assert_eq!(s, decoded, "v7 primary Setup must be a perfect bijection");
        assert!(decoded.is_primary());
    }

    #[test]
    fn secondary_setup_roundtrips() {
        let s = SetupV7::secondary(0, [0x22; DEVICE_ID_LEN], [0x33; ATTACH_SECRET_LEN], 2, 4);
        let decoded = decode_setup_v7(&encode_setup_v7(&s).unwrap()).unwrap();
        assert_eq!(s, decoded);
        assert!(!decoded.is_primary());
        assert!(decoded.session_tokens.is_empty());
        assert_eq!(decoded.attach_secret, [0x33; ATTACH_SECRET_LEN]);
    }

    #[test]
    fn setup_v7_wire_layout_is_frozen() {
        // Golden vector: pin the exact v7 primary byte layout. A drift here is
        // a wire break that MUST bump the version and ship a new vector.
        let s = SetupV7 {
            protocol_version: 7,
            features: 0x03, // MULTIPATH | PORT_FORWARD
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            device_id: [0xAB; DEVICE_ID_LEN],
            session_tokens: vec![a_token(0xCD)],
            attach_secret: [0xEF; ATTACH_SECRET_LEN],
        };
        let bytes = encode_setup_v7(&s).unwrap();
        // postcard layout:
        //   protocol_version u8            = 0x07
        //   features u32 varint(3)         = 0x03
        //   connection_index u8            = 0x00
        //   total_connections u8           = 0x01
        //   daita_support bool false       = 0x00
        //   device_id [16] raw             = 16 * 0xAB
        //   session_tokens Vec len varint  = 0x01
        //     token[0] [354] raw           = 354 * 0xCD
        //   attach_secret [16] raw         = 16 * 0xEF
        let mut expected = vec![0x07, 0x03, 0x00, 0x01, 0x00];
        expected.extend_from_slice(&[0xAB; DEVICE_ID_LEN]);
        expected.push(0x01); // Vec length = 1
        expected.extend_from_slice(&[0xCD; SESSION_TOKEN_LEN]);
        expected.extend_from_slice(&[0xEF; ATTACH_SECRET_LEN]);
        assert_eq!(bytes, expected, "v7 Setup wire layout is frozen");
        assert_eq!(
            bytes.len(),
            5 + DEVICE_ID_LEN + 1 + SESSION_TOKEN_LEN + ATTACH_SECRET_LEN
        );
    }

    #[test]
    fn setup_ack_v7_wire_layout_is_frozen() {
        let a = SetupAckV7 {
            protocol_version: 7,
            tunnel_ipv4: [10, 66, 42, 7],
            tunnel_ipv6: None,
            exit_pubkey: [0u8; 32],
            max_mtu: 1350,
            multiconn_attached: true,
            daita_spec: None,
            exit_auth_sig: AuthSig([0x77; crate::AUTH_SIG_LEN]),
            attach_secret: [0x55; ATTACH_SECRET_LEN],
        };
        let bytes = encode_setup_ack_v7(&a).unwrap();
        // version + tunnel_ipv4 + ipv6(None) + exit_pubkey(32) + mtu varint +
        // multiconn(true) + daita(None) + exit_auth_sig(64) + attach_secret(16)
        assert_eq!(&bytes[..6], &[0x07, 0x0a, 0x42, 0x2a, 0x07, 0x00]);
        assert_eq!(&bytes[6..38], &[0u8; 32]);
        assert_eq!(&bytes[38..40], &[0xc6, 0x0a]); // max_mtu varint(1350)
        assert_eq!(&bytes[40..42], &[0x01, 0x00]); // multiconn true + daita None
        assert_eq!(&bytes[42..106], &[0x77; crate::AUTH_SIG_LEN]);
        assert_eq!(&bytes[106..122], &[0x55; ATTACH_SECRET_LEN]);
        assert_eq!(bytes.len(), 122, "v7 SetupAck total length is frozen");
        let decoded = decode_setup_ack_v7(&bytes).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn primary_without_a_token_is_rejected() {
        let s = SetupV7 {
            protocol_version: 7,
            features: 0,
            connection_index: 0,
            total_connections: 1,
            daita_support: false,
            device_id: [0; DEVICE_ID_LEN],
            session_tokens: Vec::new(),
            attach_secret: [0; ATTACH_SECRET_LEN],
        };
        assert!(matches!(
            decode_setup_v7(&encode_setup_v7(&s).unwrap()),
            Err(ProtocolError::MissingSessionToken)
        ));
    }

    #[test]
    fn secondary_carrying_a_token_is_rejected() {
        let s = SetupV7 {
            protocol_version: 7,
            features: 0,
            connection_index: 1,
            total_connections: 2,
            daita_support: false,
            device_id: [0; DEVICE_ID_LEN],
            session_tokens: vec![a_token(1)],
            attach_secret: [0; ATTACH_SECRET_LEN],
        };
        assert!(matches!(
            decode_setup_v7(&encode_setup_v7(&s).unwrap()),
            Err(ProtocolError::UnexpectedSessionToken)
        ));
    }

    #[test]
    fn too_many_tokens_is_rejected() {
        let s = SetupV7::primary_single(
            0,
            [0; DEVICE_ID_LEN],
            (0..=MAX_SESSION_TOKENS as u8).map(a_token).collect(),
        );
        assert!(matches!(
            decode_setup_v7(&encode_setup_v7(&s).unwrap()),
            Err(ProtocolError::TooManyTokens { .. })
        ));
    }

    #[test]
    fn trailing_bytes_after_v7_setup_are_rejected() {
        let s = SetupV7::primary_single(0, [0; DEVICE_ID_LEN], vec![a_token(9)]);
        let mut bytes = encode_setup_v7(&s).unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            decode_setup_v7(&bytes),
            Err(ProtocolError::TrailingBytes)
        ));
    }

    #[test]
    fn invalid_multi_conn_zero_total_is_detected() {
        // A hostile peer forges total_connections = 0; the builder asserts
        // catch this for a well-behaved client but the decoder must still
        // reject it directly off the wire.
        let s = SetupV7 {
            protocol_version: PROTOCOL_VERSION_V7,
            features: 0,
            connection_index: 0,
            total_connections: 0,
            daita_support: false,
            device_id: [0; DEVICE_ID_LEN],
            session_tokens: Vec::new(),
            attach_secret: [0; ATTACH_SECRET_LEN],
        };
        assert!(matches!(
            decode_setup_v7(&encode_setup_v7(&s).unwrap()),
            Err(ProtocolError::InvalidMultiConn { index: 0, total: 0 })
        ));
    }

    #[test]
    fn invalid_multi_conn_index_out_of_range_is_detected() {
        // connection_index (3) >= total_connections (2).
        let s = SetupV7 {
            protocol_version: PROTOCOL_VERSION_V7,
            features: 0,
            connection_index: 3,
            total_connections: 2,
            daita_support: false,
            device_id: [0; DEVICE_ID_LEN],
            session_tokens: Vec::new(),
            attach_secret: [0; ATTACH_SECRET_LEN],
        };
        assert!(matches!(
            decode_setup_v7(&encode_setup_v7(&s).unwrap()),
            Err(ProtocolError::InvalidMultiConn { index: 3, total: 2 })
        ));
    }

    #[test]
    fn dual_accept_dispatches_on_the_version_byte() {
        // A v6 frame decodes to the V6 arm, a v7 frame to the V7 arm, through
        // the SAME entry point the exit uses.
        let v6 = crate::Setup::single_conn(crate::features::MULTIPATH).with_auth(
            [0xCD; crate::CLIENT_PUBKEY_LEN],
            [0xEF; crate::AUTH_SIG_LEN],
        );
        let v6_bytes = crate::encode_setup(&v6).unwrap();
        match decode_setup_any(&v6_bytes).unwrap() {
            AnySetup::V6(s) => assert_eq!(s, v6),
            other => panic!("expected V6, got {other:?}"),
        }

        let v7 = SetupV7::primary_single(0, [0x11; DEVICE_ID_LEN], vec![a_token(0xAB)]);
        let v7_bytes = encode_setup_v7(&v7).unwrap();
        match decode_setup_any(&v7_bytes).unwrap() {
            AnySetup::V7(s) => assert_eq!(s, v7),
            other => panic!("expected V7, got {other:?}"),
        }
    }

    #[test]
    fn dual_accept_rejects_an_unknown_version() {
        let err = decode_setup_any(&[0x63, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::VersionMismatch { got: 0x63, .. }
        ));
        // Empty buffer is a clean codec error, not a panic.
        assert!(matches!(
            decode_setup_any(&[]),
            Err(ProtocolError::Codec(_))
        ));
    }
}
