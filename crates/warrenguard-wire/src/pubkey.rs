//! Wire-level Ed25519 public key newtype.
//!
//! [`WarrenPubkey`] is the byte-only carrier for a 32-byte Ed25519 public
//! key identifying a Warren peer (client or exit). It does not validate
//! Ed25519 point compression: that check belongs to higher layers that
//! convert to `ed25519_dalek::VerifyingKey`. Keeping this type free of a
//! crypto dependency lets `warrenguard-wire` stay as a low-level wire crate.

use core::fmt;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Length in bytes of an Ed25519 public key.
pub const PUBKEY_LEN: usize = 32;

/// 32-byte Ed25519 public key identifying a Warren peer.
///
/// Used as the on-the-wire identity of a client or exit in the tunnel setup
/// reply, TLS raw-public-key certificates, exit allowlists and signed
/// `relays.json` blobs. Equality and hashing are byte-wise, which is
/// sufficient for protocol identifier comparison; cryptographic
/// equality (rejecting non-canonical encodings of the same Ed25519
/// curve point) requires converting to `VerifyingKey` first.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct WarrenPubkey([u8; PUBKEY_LEN]);

/// Failure modes for [`WarrenPubkey::from_hex`].
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WarrenPubkeyError {
    /// Hex input length is not exactly 64 characters (one byte per pair).
    #[error("expected 64 hex chars for a 32-byte pubkey, got {got}")]
    WrongHexLength {
        /// Length of the offending input.
        got: usize,
    },
    /// Hex input contains a character outside `[0-9a-fA-F]`.
    #[error("invalid hex character in pubkey")]
    InvalidHex,
}

impl WarrenPubkey {
    /// Wraps a raw 32-byte buffer.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PUBKEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBKEY_LEN] {
        &self.0
    }

    /// Constant-time comparison for security-critical paths (allowlist
    /// gate, TLS verifier). Use standard `==` for non-security HashMap
    /// lookups where timing is irrelevant.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }

    /// Returns the lower-case hex encoding (exactly 64 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a 64-character hex string (lower- or upper-case mixed).
    ///
    /// # Errors
    ///
    /// - [`WarrenPubkeyError::WrongHexLength`] if `s.len() != 64`.
    /// - [`WarrenPubkeyError::InvalidHex`] if any character is not a
    ///   valid hex digit.
    pub fn from_hex(s: &str) -> Result<Self, WarrenPubkeyError> {
        if s.len() != 64 {
            return Err(WarrenPubkeyError::WrongHexLength { got: s.len() });
        }
        let mut out = [0u8; PUBKEY_LEN];
        hex::decode_to_slice(s, &mut out).map_err(|_| WarrenPubkeyError::InvalidHex)?;
        Ok(Self(out))
    }
}

impl fmt::Display for WarrenPubkey {
    /// Full lower-case 64-character hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl TryFrom<&str> for WarrenPubkey {
    type Error = WarrenPubkeyError;

    /// Same parsing rules as [`WarrenPubkey::from_hex`].
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_hex(s)
    }
}

impl fmt::Debug for WarrenPubkey {
    /// Truncated `WarrenPubkey(xxxxxxxx..yyyyyyyy)` form. Prevents
    /// accidental full-pubkey leaks via `tracing` debug formatting in
    /// no-log production paths. Callers that genuinely want the full
    /// pubkey must opt-in with `{}` (Display) or `to_hex()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WarrenPubkey(")?;
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..")?;
        for b in &self.0[28..] {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl Serialize for WarrenPubkey {
    /// Dispatches on `is_human_readable` to keep two wire formats:
    ///
    /// - JSON (and other human-readable codecs): 64-character lower-case
    ///   hex string. Matches what `warren-relays.json` v1/v2 already
    ///   expects, so signed relay blobs and the exit descriptor
    ///   (`--info-out`) JSON stay parseable end-to-end.
    /// - postcard / bincode / any binary codec: 32 raw bytes with no
    ///   length prefix. Matches the existing `SetupAck.exit_pubkey:
    ///   [u8; 32]` postcard layout exactly, so swapping that field to
    ///   `WarrenPubkey` later is a byte-identical wire change.
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

impl<'de> Deserialize<'de> for WarrenPubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; PUBKEY_LEN]>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn from_bytes_then_as_bytes_roundtrips() {
        let raw = [42u8; PUBKEY_LEN];
        let pk = WarrenPubkey::from_bytes(raw);
        assert_eq!(pk.as_bytes(), &raw);
    }

    #[test]
    fn hex_roundtrip_against_warrenguard_identity_seed_ab_vector() {
        // Lock against the existing test vector in warrenguard-identity
        // (`seed_ab_produces_known_pubkey`) so any drift between the
        // identity layer's hex format and warrenguard-wire's would
        // break here. Cross-component invariant.
        let raw = [
            0x21, 0xe9, 0x27, 0x6d, 0xa8, 0x39, 0x5d, 0x56, 0xaf, 0x5c, 0x83, 0xc0, 0x0f, 0xfb,
            0x4a, 0xfb, 0xa7, 0xeb, 0xd3, 0x37, 0x18, 0x9a, 0xee, 0xa9, 0x13, 0x6b, 0xfc, 0x9d,
            0x3f, 0xd4, 0x4f, 0x6b,
        ];
        let pk = WarrenPubkey::from_bytes(raw);
        let hex = pk.to_hex();
        assert_eq!(
            hex, "21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b",
            "hex encoding must match warrenguard-identity seed_ab vector"
        );
        let parsed = WarrenPubkey::from_hex(&hex).expect("self-produced hex must parse");
        assert_eq!(parsed, pk);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let too_short = "ab".repeat(31); // 62 chars
        assert_eq!(
            WarrenPubkey::from_hex(&too_short),
            Err(WarrenPubkeyError::WrongHexLength { got: 62 })
        );
        let too_long = "ab".repeat(33); // 66 chars
        assert_eq!(
            WarrenPubkey::from_hex(&too_long),
            Err(WarrenPubkeyError::WrongHexLength { got: 66 })
        );
        assert_eq!(
            WarrenPubkey::from_hex(""),
            Err(WarrenPubkeyError::WrongHexLength { got: 0 })
        );
    }

    #[test]
    fn from_hex_rejects_non_hex_chars() {
        let bad = "z".repeat(64);
        assert_eq!(
            WarrenPubkey::from_hex(&bad),
            Err(WarrenPubkeyError::InvalidHex)
        );
    }

    #[test]
    fn from_hex_accepts_uppercase_and_mixed_case() {
        let pk_lo = WarrenPubkey::from_hex(&"ab".repeat(32)).expect("lowercase parses");
        let pk_up = WarrenPubkey::from_hex(&"AB".repeat(32)).expect("uppercase parses");
        let pk_mx = WarrenPubkey::from_hex(&"aB".repeat(32)).expect("mixed case parses");
        assert_eq!(pk_lo, pk_up);
        assert_eq!(pk_lo, pk_mx);
    }

    #[test]
    fn display_is_full_64_lowercase_hex_chars() {
        let pk = WarrenPubkey::from_bytes([0xab; PUBKEY_LEN]);
        let s = format!("{pk}");
        assert_eq!(s.len(), 64, "Display must always be exactly 64 chars");
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn debug_is_truncated_safe_for_logs() {
        let pk = WarrenPubkey::from_bytes([
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xca, 0xfe, 0xba, 0xbe,
        ]);
        let s = format!("{pk:?}");
        assert_eq!(
            s, "WarrenPubkey(deadbeef..cafebabe)",
            "Debug must elide the middle 24 bytes so unintentional logging stays redacted"
        );
    }

    #[test]
    fn pubkey_works_as_hashset_key() {
        let pk_a = WarrenPubkey::from_bytes([0u8; PUBKEY_LEN]);
        let pk_b = WarrenPubkey::from_bytes([1u8; PUBKEY_LEN]);
        let pk_a_clone = WarrenPubkey::from_bytes([0u8; PUBKEY_LEN]);
        let mut set = HashSet::new();
        set.insert(pk_a);
        set.insert(pk_b);
        assert!(set.contains(&pk_a_clone), "byte-equal keys must hash equal");
        assert!(!set.contains(&WarrenPubkey::from_bytes([2u8; PUBKEY_LEN])));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn copy_semantics_holds() {
        // Compile-time check: WarrenPubkey: Copy so it can pass through
        // an allowlist match without an explicit clone.
        let pk = WarrenPubkey::from_bytes([7u8; PUBKEY_LEN]);
        let copy = pk;
        assert_eq!(pk, copy);
        assert_eq!(pk.as_bytes(), copy.as_bytes());
    }

    // ---------------- serde: JSON (human-readable) ---------------- //

    #[test]
    fn json_serializes_to_64_char_lowercase_hex_string() {
        let pk = WarrenPubkey::from_bytes([0xabu8; PUBKEY_LEN]);
        let json = serde_json::to_string(&pk).expect("json serialize");
        // Wrapped in double quotes by serde_json string serializer.
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        assert_eq!(json.len(), 66, "64 hex chars + 2 quotes");
    }

    #[test]
    fn json_deserializes_lowercase_and_uppercase_hex() {
        let original = WarrenPubkey::from_bytes([
            0x21, 0xe9, 0x27, 0x6d, 0xa8, 0x39, 0x5d, 0x56, 0xaf, 0x5c, 0x83, 0xc0, 0x0f, 0xfb,
            0x4a, 0xfb, 0xa7, 0xeb, 0xd3, 0x37, 0x18, 0x9a, 0xee, 0xa9, 0x13, 0x6b, 0xfc, 0x9d,
            0x3f, 0xd4, 0x4f, 0x6b,
        ]);
        let parsed_lower: WarrenPubkey = serde_json::from_str(
            "\"21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b\"",
        )
        .expect("lowercase hex must deserialize");
        let parsed_upper: WarrenPubkey = serde_json::from_str(
            "\"21E9276DA8395D56AF5C83C00FFB4AFBA7EBD337189AEEA9136BFC9D3FD44F6B\"",
        )
        .expect("uppercase hex must deserialize");
        assert_eq!(parsed_lower, original);
        assert_eq!(parsed_upper, original);
    }

    #[test]
    fn json_roundtrips_for_arbitrary_bytes() {
        let pk = WarrenPubkey::from_bytes([
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c,
        ]);
        let json = serde_json::to_string(&pk).expect("serialize");
        let parsed: WarrenPubkey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, pk);
    }

    #[test]
    fn json_deserialize_rejects_wrong_length_hex() {
        let err = serde_json::from_str::<WarrenPubkey>("\"abcd\"")
            .expect_err("4-char hex must be rejected");
        assert!(
            err.to_string().contains("64"),
            "error should mention expected length 64, got: {err}"
        );
    }

    #[test]
    fn json_deserialize_rejects_non_hex_characters() {
        let s = format!("\"{}\"", "z".repeat(64));
        let err =
            serde_json::from_str::<WarrenPubkey>(&s).expect_err("non-hex chars must be rejected");
        assert!(
            err.to_string().contains("hex"),
            "error should mention hex, got: {err}"
        );
    }

    // ---------------- serde: postcard (binary, byte-equal compat) ---------------- //

    #[test]
    fn postcard_serializes_to_32_raw_bytes_byte_equal_with_naked_array() {
        // Cross-pin: WarrenPubkey postcard wire format must be
        // bit-identical to `[u8; 32]` postcard wire format. This is
        // what makes the `SetupAck.exit_pubkey: WarrenPubkey` typing a
        // no-op on the wire.
        let bytes = [
            0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c,
        ];
        let pk = WarrenPubkey::from_bytes(bytes);
        let pk_wire = postcard::to_allocvec(&pk).expect("postcard pubkey");
        let arr_wire = postcard::to_allocvec(&bytes).expect("postcard array");
        assert_eq!(
            pk_wire, arr_wire,
            "WarrenPubkey postcard bytes must equal naked [u8; 32] for SetupAck wire compat"
        );
        assert_eq!(
            pk_wire.len(),
            32,
            "postcard must emit exactly 32 bytes, no length prefix"
        );
        assert_eq!(pk_wire, bytes.to_vec(), "raw bytes in order");
    }

    #[test]
    fn postcard_roundtrips_for_arbitrary_bytes() {
        let bytes = [0x77u8; PUBKEY_LEN];
        let pk = WarrenPubkey::from_bytes(bytes);
        let wire = postcard::to_allocvec(&pk).expect("serialize");
        let parsed: WarrenPubkey = postcard::from_bytes(&wire).expect("deserialize");
        assert_eq!(parsed, pk);
    }

    #[test]
    fn postcard_deserialize_rejects_truncated_buffer() {
        let pk = WarrenPubkey::from_bytes([0xaa; PUBKEY_LEN]);
        let mut wire = postcard::to_allocvec(&pk).expect("serialize");
        wire.pop(); // 31 bytes, not 32
        let err = postcard::from_bytes::<WarrenPubkey>(&wire);
        assert!(
            err.is_err(),
            "truncated 31-byte buffer must fail to deserialize"
        );
    }
}
