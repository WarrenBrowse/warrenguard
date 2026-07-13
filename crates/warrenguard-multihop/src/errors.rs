//! Error type for the Warren multihop wire format and HPKE sessions.
//!
//! Distinguishes between protocol-level rejections (version mismatch,
//! tampered AAD, replayed sequence) and crypto-layer failures (the wrapped
//! `hpke::HpkeError`). On the exit side these errors should be surfaced to
//! tracing without leaking ciphertext, AAD bytes, or peer identifiers.

use thiserror::Error;

/// Errors emitted by the `warren-multihop` wire format and HPKE sessions.
///
/// Each variant maps to a distinct rejection path.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MultihopError {
    /// Frame `version` byte did not match [`crate::WARREN_HPKE_VERSION_V1`].
    /// All `/v1` consumers MUST reject any value other than `0x01`.
    #[error("unsupported multihop wire version: got 0x{got:02x}, expected 0x{expected:02x}")]
    UnsupportedVersion {
        /// Version byte read from the frame.
        got: u8,
        /// Version byte required by this build of the crate.
        expected: u8,
    },

    /// Postcard decoding failed: the frame is truncated or has a field that
    /// overflows postcard's limits.
    #[error("postcard decode failed: {0}")]
    Decode(#[from] postcard::Error),

    /// A valid frame was followed by unexpected trailing bytes. Rejected so a
    /// peer cannot append data to (or confuse two of) a single frame: postcard
    /// deserializes the prefix and would otherwise ignore the remainder.
    #[error("trailing bytes after a valid multihop frame")]
    TrailingBytes,

    /// HPKE setup, seal, or open returned an error. Includes AEAD tag
    /// mismatch, KEM deserialization failure, and the
    /// `MessageLimitReached` overflow that triggers rekey.
    #[error("hpke error: {0:?}")]
    Hpke(hpke::HpkeError),

    /// Replay window rejected the sequence number for the active
    /// `(exit_id, epoch)`. Either the seq has already been observed or it
    /// is too old (more than the window size below the current high
    /// watermark).
    #[error("anti-replay window rejected seq {seq} (epoch {epoch})")]
    Replay {
        /// Sequence number that was rejected.
        seq: u64,
        /// Epoch in which the rejection occurred.
        epoch: u32,
    },

    /// Datagram targeted an `exit_id` that does not match the active
    /// session. This is a tampering or misroute indicator.
    #[error("exit_id mismatch on the active session")]
    ExitIdMismatch,

    /// Rotation has been requested but the new HPKE context could not be
    /// established (e.g. KEM encap failure).
    #[error("rekey failed: {0}")]
    RekeyFailed(&'static str),

    /// The exit's per-second cap on NEW HPKE session derivations was hit.
    /// Each session build runs an X25519 KEM decap, so an unauthenticated
    /// peer can otherwise drive one decap per frame by rotating
    /// `encapsulated_key`. The triggering frame is dropped; established
    /// sessions (cache hits) are unaffected.
    #[error("session-create rate limit exceeded")]
    SessionCreateRateLimited,

    /// A post-quantum (`/v2`) key or ciphertext field had the wrong length
    /// (e.g. an ML-KEM-768 encapsulation key that is not 1184 bytes, or a
    /// ciphertext that is not 1088 bytes). No secret bytes are included, only
    /// the field name and the length mismatch.
    #[error("pq field length mismatch: {field} got {got}, expected {expected}")]
    PqKeyLength {
        /// Which field was malformed (`"mlkem768_ek"`, `"mlkem768_ct"`).
        field: &'static str,
        /// Observed byte length.
        got: usize,
        /// Byte length the field must have.
        expected: usize,
    },

    /// The X-Wing hybrid AEAD seal or open failed (per-packet key export or
    /// the ChaCha20-Poly1305 tag did not verify on the `/v2` datapath). The
    /// opaque analogue of [`Self::Hpke`] for the post-quantum session, kept
    /// off the `hpke` error type since the PQ path does not use `hpke`.
    #[error("pq hybrid seal/open failed")]
    PqAead,

    /// Anti-downgrade rejection: the client requested the post-quantum hybrid
    /// seal, but the exit's operationally SIGNED descriptor carries no
    /// ML-KEM-768 recipient key. Falling back to the classical seal here
    /// would let a middlebox strip PQ, so the dial is refused instead.
    #[error(
        "pq requested but the signed exit descriptor advertises no ML-KEM key (downgrade refused)"
    )]
    PqDowngrade,

    /// A post-quantum operation was requested but this build was compiled
    /// without the `pq-hpke` feature, so the X-Wing crypto is not present.
    /// The `/v2` wire structs still decode (a classical build must recognize
    /// and cleanly refuse a PQ frame rather than misparse it).
    #[error("pq-hpke feature not compiled into this build")]
    PqDisabled,
}

impl From<hpke::HpkeError> for MultihopError {
    fn from(e: hpke::HpkeError) -> Self {
        Self::Hpke(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hpke_error_wraps_into_multihop_error() {
        // Anchors the `From<hpke::HpkeError>` impl so the conversion stays
        // available to call sites using `?` over hpke results. The
        // specific variant doesn't matter; we only need a concrete
        // value to exercise the From path.
        let underlying = hpke::HpkeError::OpenError;
        let wrapped: MultihopError = underlying.into();
        assert!(
            matches!(wrapped, MultihopError::Hpke(hpke::HpkeError::OpenError)),
            "From<HpkeError> did not preserve the inner variant"
        );
    }

    #[test]
    fn unsupported_version_display_includes_both_bytes() {
        let err = MultihopError::UnsupportedVersion {
            got: 0x02,
            expected: 0x01,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("0x02"));
        assert!(rendered.contains("0x01"));
    }

    #[test]
    fn replay_display_includes_seq_and_epoch() {
        let err = MultihopError::Replay { seq: 42, epoch: 7 };
        let rendered = err.to_string();
        assert!(rendered.contains("42"));
        assert!(rendered.contains('7'));
    }
}
