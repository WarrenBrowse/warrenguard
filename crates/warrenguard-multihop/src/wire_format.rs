//! Wire format for the Warren multihop datagram (C1: client -> relay leg).
//!
//! The frame is postcard-encoded so the layout is self-describing across
//! Warren versions while remaining compact. Field semantics are pinned to
//! the `/v1` constants in [`crate`].

use serde::{Deserialize, Serialize};

use crate::errors::MultihopError;
use crate::{WARREN_HPKE_VERSION_V1, session::ExitId};

/// Wire version byte exposed at module scope for `pub use` re-export from
/// [`crate`]. Equal to [`crate::WARREN_HPKE_VERSION_V1`].
pub const WARREN_HPKE_VERSION: u8 = WARREN_HPKE_VERSION_V1;

/// X25519 encapsulated key (RFC 9180 KEM output). 32-byte serialized form
/// of the ephemeral sender public key.
pub type EncapsulatedKeyBytes = [u8; 32];

/// Maximum bytes the multihop frame header (version, exit-id, epoch, seq,
/// encapsulated key, AEAD tag, and the postcard length prefixes) adds around the
/// inner ciphertext. Callers size the inner plaintext budget as
/// `path_mtu - MULTIHOP_FRAME_MAX_OVERHEAD`.
pub const MULTIHOP_FRAME_MAX_OVERHEAD: usize = 83;

/// `WarrenMultihopFrame` is the C1 wire datagram carried by QUIC unreliable
/// datagrams from the client to the relay. The relay forwards the bytes
/// unchanged to the exit, which decrypts the ciphertext using its long-lived
/// X25519 private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarrenMultihopFrame {
    /// Wire version byte. MUST equal [`WARREN_HPKE_VERSION`] for `/v1`
    /// consumers.
    pub version: u8,

    /// 16-byte exit identifier (UUID-shaped). Bound into the HPKE AAD so a
    /// frame addressed to one exit cannot be replayed against another.
    pub exit_id: ExitId,

    /// `epoch` counter from the AAD. Incremented every time the client
    /// rekeys the HPKE context. Combined with `seq` to feed the AEAD AAD
    /// and the exit-side replay window.
    pub epoch: u32,

    /// Per-session monotonic sequence number assigned by the client. Lives
    /// in the AAD and feeds the exit-side replay window.
    pub seq: u64,

    /// Serialized ephemeral X25519 public key produced by the HPKE KEM
    /// encap step. The recipient (exit) combines it with its static X25519
    /// private key to recover the per-message symmetric key. 32 bytes.
    pub encapsulated_key: EncapsulatedKeyBytes,

    /// Authenticated encryption tag (`ChaCha20Poly1305` -> 16 bytes).
    pub aead_tag: [u8; 16],

    /// AEAD ciphertext. Length equals the original payload length (RFC
    /// 9180 ChaCha20Poly1305 is detached-tag in the wire format used
    /// here).
    pub ciphertext: Vec<u8>,
}

impl WarrenMultihopFrame {
    /// Serialize the frame to postcard bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MultihopError::Decode`] if the underlying postcard encoder
    /// fails (out-of-memory only in practice; the frame fields are bounded
    /// at construction time).
    pub fn encode(&self) -> Result<Vec<u8>, MultihopError> {
        postcard::to_stdvec(self).map_err(MultihopError::from)
    }

    /// Decode a postcard-encoded frame and reject mismatched versions.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::Decode`] on malformed postcard input.
    /// - [`MultihopError::TrailingBytes`] if a valid frame is followed by extra
    ///   bytes (postcard would otherwise ignore the remainder).
    /// - [`MultihopError::UnsupportedVersion`] if the `version` byte is not
    ///   [`WARREN_HPKE_VERSION`].
    pub fn decode(bytes: &[u8]) -> Result<Self, MultihopError> {
        const MAX_FRAME_SIZE: usize = 65536;
        if bytes.len() > MAX_FRAME_SIZE {
            return Err(MultihopError::Decode(
                postcard::Error::DeserializeUnexpectedEnd,
            ));
        }
        // `take_from_bytes` (not `from_bytes`) so trailing bytes after a valid
        // frame are rejected rather than silently ignored (frame malleability).
        let (frame, rest): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(MultihopError::from)?;
        if !rest.is_empty() {
            return Err(MultihopError::TrailingBytes);
        }
        if frame.version != WARREN_HPKE_VERSION {
            return Err(MultihopError::UnsupportedVersion {
                got: frame.version,
                expected: WARREN_HPKE_VERSION,
            });
        }
        Ok(frame)
    }
}

/// Free-function wrapper around [`WarrenMultihopFrame::encode`] for the
/// public re-export path documented in [`crate`].
///
/// # Errors
///
/// Propagates the underlying postcard encoder error via
/// [`MultihopError::Decode`].
pub fn encode_frame(frame: &WarrenMultihopFrame) -> Result<Vec<u8>, MultihopError> {
    frame.encode()
}

/// Free-function wrapper around [`WarrenMultihopFrame::decode`].
///
/// # Errors
///
/// Propagates [`MultihopError::Decode`] for malformed postcard, or
/// [`MultihopError::UnsupportedVersion`] for an unexpected wire version.
pub fn decode_frame(bytes: &[u8]) -> Result<WarrenMultihopFrame, MultihopError> {
    WarrenMultihopFrame::decode(bytes)
}
