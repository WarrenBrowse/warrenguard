//! Wire-level stable exit identifier.
//!
//! [`ExitId`] is a 16-byte (UUID-shaped) opaque identifier minted once
//! per exit deployment. Unlike the Ed25519 pubkey, which IS the exit's
//! cryptographic identity and therefore changes whenever the operator
//! rotates the key, an `ExitId` is operator-assigned and persisted
//! through pubkey rotations. Clients pin observed pubkeys against an
//! [`ExitId`] (TOFU model): a mismatch detection only
//! makes sense relative to a stable identity that survives legitimate
//! key rotations.
//!
//! The byte layout is 16 raw bytes with no length prefix, so that the
//! multihop HPKE AAD identifier and the relay-list identifier are
//! byte-equal for the same exit.

use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Length in bytes of an [`ExitId`].
pub const EXIT_ID_LEN: usize = 16;

/// 16-byte opaque exit identifier (UUID-shaped).
///
/// Serialization is format-aware:
/// - JSON / TOML / any `is_human_readable` codec: 32-char lowercase
///   hex string. Matches `WarrenPubkey`'s human-readable shape so an
///   operator inspecting `warren-relays.json` sees uniform hex fields.
/// - postcard / bincode / any binary codec: 16 raw bytes, no length
///   prefix. Keeps wire size minimal on QUIC datagrams.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct ExitId([u8; EXIT_ID_LEN]);

/// Failure modes for [`ExitId::from_hex`].
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitIdError {
    /// Hex input length is not exactly 32 characters (2 chars per byte).
    #[error("expected 32 hex chars for a 16-byte exit_id, got {got}")]
    WrongHexLength {
        /// Length of the offending input.
        got: usize,
    },
    /// Hex input contains a character outside `[0-9a-fA-F]`.
    #[error("invalid hex character in exit_id")]
    InvalidHex,
}

impl ExitId {
    /// All-zero sentinel value. Reserved on the wire to mean "no
    /// stable identifier assigned yet"; clients MUST treat a zero
    /// [`ExitId`] as a fatal protocol error during pin lookups (a
    /// pinning entry keyed on zero would collide every newly deployed
    /// exit). Used only in tests and as a `Default` placeholder.
    pub const ZERO: Self = Self([0u8; EXIT_ID_LEN]);

    /// Wraps a raw 16-byte buffer.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EXIT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EXIT_ID_LEN] {
        &self.0
    }

    /// Returns the lower-case hex encoding (exactly 32 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a 32-character hex string (lower- or upper-case mixed).
    ///
    /// # Errors
    ///
    /// - [`ExitIdError::WrongHexLength`] if `s.len() != 32`.
    /// - [`ExitIdError::InvalidHex`] if any character is not a valid
    ///   hex digit.
    pub fn from_hex(s: &str) -> Result<Self, ExitIdError> {
        if s.len() != 32 {
            return Err(ExitIdError::WrongHexLength { got: s.len() });
        }
        let mut out = [0u8; EXIT_ID_LEN];
        hex::decode_to_slice(s, &mut out).map_err(|_| ExitIdError::InvalidHex)?;
        Ok(Self(out))
    }

    /// `true` when every byte is zero. Convenience predicate so call
    /// sites do not need to spell out the comparison against
    /// [`Self::ZERO`].
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < EXIT_ID_LEN {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl Default for ExitId {
    /// Defaults to [`Self::ZERO`]. Code paths that observe a default
    /// [`ExitId`] flowing through production are bugs.
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Display for ExitId {
    /// Full lower-case 32-character hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ExitId {
    /// Same as [`Display`]: an `ExitId` is non-secret operator metadata
    /// so we do not redact in debug output (unlike `WarrenPubkey`,
    /// which carries a cryptographic identity).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExitId({self})")
    }
}

impl TryFrom<&str> for ExitId {
    type Error = ExitIdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_hex(s)
    }
}

impl Serialize for ExitId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for ExitId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; EXIT_ID_LEN]>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_then_as_bytes_roundtrips() {
        let raw = [42u8; EXIT_ID_LEN];
        let id = ExitId::from_bytes(raw);
        assert_eq!(id.as_bytes(), &raw);
    }

    #[test]
    fn hex_roundtrip_against_known_vector() {
        let raw = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let id = ExitId::from_bytes(raw);
        let hex = id.to_hex();
        assert_eq!(
            hex, "123456789abcdef01122334455667788",
            "hex encoding must be lowercase pair-of-nibbles per byte"
        );
        let parsed = ExitId::from_hex(&hex).expect("self-produced hex must parse");
        assert_eq!(parsed, id);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let too_short = "ab".repeat(15);
        assert_eq!(
            ExitId::from_hex(&too_short),
            Err(ExitIdError::WrongHexLength { got: 30 })
        );
        let too_long = "ab".repeat(17);
        assert_eq!(
            ExitId::from_hex(&too_long),
            Err(ExitIdError::WrongHexLength { got: 34 })
        );
        assert_eq!(
            ExitId::from_hex(""),
            Err(ExitIdError::WrongHexLength { got: 0 })
        );
    }

    #[test]
    fn from_hex_rejects_non_hex_chars() {
        let bad = "z".repeat(32);
        assert_eq!(ExitId::from_hex(&bad), Err(ExitIdError::InvalidHex));
    }

    #[test]
    fn from_hex_accepts_uppercase_and_mixed_case() {
        let lo = ExitId::from_hex(&"ab".repeat(16)).expect("lowercase parses");
        let up = ExitId::from_hex(&"AB".repeat(16)).expect("uppercase parses");
        let mx = ExitId::from_hex(&"aB".repeat(16)).expect("mixed case parses");
        assert_eq!(lo, up);
        assert_eq!(lo, mx);
    }

    #[test]
    fn display_is_full_32_lowercase_hex_chars() {
        let id = ExitId::from_bytes([0xab; EXIT_ID_LEN]);
        let s = format!("{id}");
        assert_eq!(s.len(), 32, "Display must always be exactly 32 chars");
        assert_eq!(s, "ab".repeat(16));
    }

    #[test]
    fn debug_includes_full_hex_no_redaction() {
        // ExitId is non-secret operator metadata: unlike WarrenPubkey,
        // we do not redact in Debug. Lock the format to detect a
        // regression that would accidentally elide bytes.
        let id = ExitId::from_bytes([0xde; EXIT_ID_LEN]);
        let s = format!("{id:?}");
        assert_eq!(s, "ExitId(dededededededededededededededede)");
    }

    #[test]
    fn zero_constant_matches_is_zero_predicate() {
        assert!(ExitId::ZERO.is_zero());
        assert!(!ExitId::from_bytes([1u8; EXIT_ID_LEN]).is_zero());
    }

    #[test]
    fn default_is_zero() {
        assert_eq!(ExitId::default(), ExitId::ZERO);
    }

    // ---------------- serde: JSON (human-readable) ---------------- //

    #[test]
    fn json_serializes_to_32_char_lowercase_hex_string() {
        let id = ExitId::from_bytes([0xab; EXIT_ID_LEN]);
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, format!("\"{}\"", "ab".repeat(16)));
        assert_eq!(json.len(), 34, "32 hex chars + 2 quotes");
    }

    #[test]
    fn json_roundtrips_for_arbitrary_bytes() {
        let bytes = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c,
        ];
        let id = ExitId::from_bytes(bytes);
        let json = serde_json::to_string(&id).expect("serialize");
        let parsed: ExitId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, id);
    }

    #[test]
    fn json_deserialize_rejects_wrong_length_hex() {
        let err = serde_json::from_str::<ExitId>("\"abcd\"")
            .expect_err("4-char hex must be rejected at deserialize");
        assert!(
            err.to_string().contains("32"),
            "error should mention expected length 32, got: {err}"
        );
    }

    #[test]
    fn json_deserialize_rejects_non_hex_characters() {
        let s = format!("\"{}\"", "z".repeat(32));
        let err = serde_json::from_str::<ExitId>(&s)
            .expect_err("non-hex chars must be rejected at deserialize");
        assert!(
            err.to_string().contains("hex"),
            "error should mention hex, got: {err}"
        );
    }

    // ---------------- serde: postcard (binary, byte-equal compat) ---------------- //

    #[test]
    fn postcard_serializes_to_16_raw_bytes_byte_equal_with_naked_array() {
        let bytes = [
            0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xa0, 0xb0,
        ];
        let id = ExitId::from_bytes(bytes);
        let id_wire = postcard::to_allocvec(&id).expect("postcard exit_id");
        let arr_wire = postcard::to_allocvec(&bytes).expect("postcard array");
        assert_eq!(
            id_wire, arr_wire,
            "ExitId postcard bytes must equal naked [u8; 16] for wire-compat with multihop AAD"
        );
        assert_eq!(
            id_wire.len(),
            16,
            "postcard must emit exactly 16 bytes, no length prefix"
        );
        assert_eq!(id_wire, bytes.to_vec(), "raw bytes in order");
    }

    #[test]
    fn postcard_roundtrips_for_arbitrary_bytes() {
        let id = ExitId::from_bytes([0x77u8; EXIT_ID_LEN]);
        let wire = postcard::to_allocvec(&id).expect("serialize");
        let parsed: ExitId = postcard::from_bytes(&wire).expect("deserialize");
        assert_eq!(parsed, id);
    }

    #[test]
    fn postcard_deserialize_rejects_truncated_buffer() {
        let id = ExitId::from_bytes([0xaa; EXIT_ID_LEN]);
        let mut wire = postcard::to_allocvec(&id).expect("serialize");
        wire.pop();
        let err = postcard::from_bytes::<ExitId>(&wire);
        assert!(err.is_err(), "truncated 15-byte buffer must fail");
    }
}
