//! Wire format for the Warren multihop `/v2` datagram: the post-quantum hybrid
//! seal (X-Wing: X25519 + ML-KEM-768).
//!
//! The `/v2` frame is a strict, versioned SIBLING of the `/v1`
//! [`crate::WarrenMultihopFrame`]: a distinct postcard struct with its own
//! version byte [`WARREN_HPKE_VERSION_V2`] (`0x02`). The `/v1` frame is never
//! mutated (its golden bytes are frozen), and the two never cross-decode: a
//! `/v1` decoder rejects `0x02` and this decoder rejects `0x01`.
//!
//! Relative to `/v1`, `/v2` keeps the 32-byte `encapsulated_key` field in the
//! same position and role (it carries the X25519 ephemeral public `ct_X`, so
//! that portion of the wire is byte-shaped identically to `/v1`) and adds ONE
//! field, `pq_ct`, carrying the ML-KEM-768 ciphertext `ct_M` (1088 bytes). The
//! full X-Wing ciphertext is `pq_ct || encapsulated_key`.
//!
//! # Frame-size note (no new steady-state tell)
//!
//! `pq_ct` is large (1088 bytes). It is required on the frame that ESTABLISHES
//! or REKEYS an epoch (the setup frame). On steady-state data frames, once the
//! receiver holds the epoch's established [`crate::PqExitSession`] /
//! [`crate::PqClientSession`], `pq_ct` MAY be empty: the ML-KEM ciphertext is
//! not re-sent per datagram, so the data-plane frame size matches `/v1` plus
//! only the postcard length prefix. The `encapsulated_key` (`ct_X`, 32 B) is
//! still carried every frame exactly as `/v1` carries it, so no NEW per-packet
//! tell is introduced by the hybrid seal.

use serde::{Deserialize, Serialize};

use crate::errors::MultihopError;
use crate::session::ExitId;

/// Wire version byte for the `/v2` post-quantum multihop frame. Distinct from
/// [`crate::WARREN_HPKE_VERSION_V1`] (`0x01`); frozen for `/v2`.
pub const WARREN_HPKE_VERSION_V2: u8 = 0x02;

/// Maximum bytes the `/v2` frame header adds around the inner ciphertext when
/// `pq_ct` carries the full ML-KEM-768 ciphertext (setup / rekey frame):
/// version, exit-id, epoch, seq, `encapsulated_key`, the 1088-byte `pq_ct`, the
/// AEAD tag, and postcard length prefixes.
pub const MULTIHOP_FRAME_V2_MAX_OVERHEAD: usize = 83 + 1088 + 3;

/// Maximum bytes the `/v2` frame header adds around the inner ciphertext on a
/// STEADY-STATE data frame, where `pq_ct` is empty because the epoch session is
/// already established (the 1088-byte ML-KEM ciphertext is carried only by the
/// dedicated setup / bootstrap frame, never by a data frame). Sizing the tunnel
/// MTU from this, rather than from the ~1 KB larger
/// [`MULTIHOP_FRAME_V2_MAX_OVERHEAD`], gives a `/v2` session the same usable
/// inner payload as `/v1`. The `- 1088` keeps one byte of slack for the
/// empty-versus-full `pq_ct` postcard length prefix, so it never under-counts.
pub const MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD: usize = MULTIHOP_FRAME_V2_MAX_OVERHEAD - 1088;

/// `WarrenMultihopFrameV2` is the `/v2` C1 wire datagram carrying the X-Wing
/// hybrid seal. Postcard-encoded, like `/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarrenMultihopFrameV2 {
    /// Wire version byte. MUST equal [`WARREN_HPKE_VERSION_V2`] (`0x02`).
    pub version: u8,

    /// 16-byte exit identifier, bound into the PQ AAD.
    pub exit_id: ExitId,

    /// Rekey epoch counter (same semantics as `/v1`).
    pub epoch: u32,

    /// Per-session monotonic sequence number (same semantics as `/v1`).
    pub seq: u64,

    /// X25519 ephemeral public (`ct_X`), the X25519 half of the X-Wing
    /// ciphertext. Same field position and role as the `/v1`
    /// `encapsulated_key`, so this 32-byte portion of the wire is
    /// byte-indistinguishable from a `/v1` frame.
    pub encapsulated_key: [u8; 32],

    /// ML-KEM-768 ciphertext (`ct_M`, 1088 bytes) on a setup / rekey frame;
    /// MAY be empty on a steady-state data frame whose epoch session is already
    /// established. The full X-Wing ciphertext is `pq_ct || encapsulated_key`.
    pub pq_ct: Vec<u8>,

    /// Authenticated encryption tag (`ChaCha20Poly1305`, 16 bytes).
    pub aead_tag: [u8; 16],

    /// AEAD ciphertext. Length equals the original payload length.
    pub ciphertext: Vec<u8>,
}

impl WarrenMultihopFrameV2 {
    /// Serialize the `/v2` frame to postcard bytes.
    ///
    /// # Errors
    ///
    /// [`MultihopError::Decode`] if the postcard encoder fails.
    pub fn encode(&self) -> Result<Vec<u8>, MultihopError> {
        postcard::to_stdvec(self).map_err(MultihopError::from)
    }

    /// Decode a postcard-encoded `/v2` frame, rejecting a mismatched version or
    /// trailing bytes.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::Decode`] on malformed postcard input.
    /// - [`MultihopError::TrailingBytes`] if a valid frame is followed by extra
    ///   bytes.
    /// - [`MultihopError::UnsupportedVersion`] if the `version` byte is not
    ///   [`WARREN_HPKE_VERSION_V2`].
    pub fn decode(bytes: &[u8]) -> Result<Self, MultihopError> {
        const MAX_FRAME_SIZE: usize = 65536;
        if bytes.len() > MAX_FRAME_SIZE {
            return Err(MultihopError::Decode(
                postcard::Error::DeserializeUnexpectedEnd,
            ));
        }
        let (frame, rest): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(MultihopError::from)?;
        if !rest.is_empty() {
            return Err(MultihopError::TrailingBytes);
        }
        if frame.version != WARREN_HPKE_VERSION_V2 {
            return Err(MultihopError::UnsupportedVersion {
                got: frame.version,
                expected: WARREN_HPKE_VERSION_V2,
            });
        }
        Ok(frame)
    }
}

/// Free-function wrapper around [`WarrenMultihopFrameV2::encode`].
///
/// # Errors
///
/// Propagates the postcard encoder error via [`MultihopError::Decode`].
pub fn encode_frame_v2(frame: &WarrenMultihopFrameV2) -> Result<Vec<u8>, MultihopError> {
    frame.encode()
}

/// Free-function wrapper around [`WarrenMultihopFrameV2::decode`].
///
/// # Errors
///
/// Propagates [`MultihopError::Decode`] / [`MultihopError::TrailingBytes`] /
/// [`MultihopError::UnsupportedVersion`].
pub fn decode_frame_v2(bytes: &[u8]) -> Result<WarrenMultihopFrameV2, MultihopError> {
    WarrenMultihopFrameV2::decode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WARREN_HPKE_VERSION_V1;

    #[test]
    fn v2_frame_round_trips() {
        let frame = WarrenMultihopFrameV2 {
            version: WARREN_HPKE_VERSION_V2,
            exit_id: ExitId::from_bytes([0xa1; 16]),
            epoch: 7,
            seq: 42,
            encapsulated_key: [0x02; 32],
            pq_ct: vec![0x05; 1088],
            aead_tag: [0x03; 16],
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let bytes = frame.encode().expect("encode");
        assert_eq!(
            WarrenMultihopFrameV2::decode(&bytes).expect("decode"),
            frame
        );
    }

    /// A `/v2` decoder must reject a `/v1` version byte and vice-versa, so the
    /// two frozen wire formats can never be confused.
    #[test]
    fn v2_decoder_rejects_v1_version_byte() {
        let mut frame = WarrenMultihopFrameV2 {
            version: WARREN_HPKE_VERSION_V1,
            exit_id: ExitId::from_bytes([0; 16]),
            epoch: 0,
            seq: 0,
            encapsulated_key: [0; 32],
            pq_ct: vec![],
            aead_tag: [0; 16],
            ciphertext: vec![],
        };
        frame.version = WARREN_HPKE_VERSION_V1;
        let bytes = frame.encode().expect("encode");
        let err = WarrenMultihopFrameV2::decode(&bytes).expect_err("must reject v1 version");
        assert!(matches!(
            err,
            MultihopError::UnsupportedVersion {
                got: WARREN_HPKE_VERSION_V1,
                expected: WARREN_HPKE_VERSION_V2
            }
        ));
    }

    #[test]
    fn v2_decoder_rejects_trailing_bytes() {
        let frame = WarrenMultihopFrameV2 {
            version: WARREN_HPKE_VERSION_V2,
            exit_id: ExitId::from_bytes([0; 16]),
            epoch: 0,
            seq: 0,
            encapsulated_key: [0; 32],
            pq_ct: vec![],
            aead_tag: [0; 16],
            ciphertext: vec![1, 2, 3],
        };
        let mut bytes = frame.encode().expect("encode");
        bytes.push(0xff);
        assert!(matches!(
            WarrenMultihopFrameV2::decode(&bytes),
            Err(MultihopError::TrailingBytes)
        ));
    }
}
