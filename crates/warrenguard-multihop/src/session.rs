//! Warren multihop HPKE sessions and helpers.
//!
//! # Multi-message session design
//!
//! The "multi-message session" design runs the HPKE setup (KEM ECDH +
//! key schedule) once per `(client, exit)` pair and reuses it for every
//! sealed datagram. The naive interpretation is to call
//! `AeadCtxS::seal_in_place_detached` repeatedly so the crate's internal
//! sequence counter advances automatically. That naive interpretation does
//! NOT survive an unreliable transport: the QUIC datagram extension
//! (RFC 9221) can drop or reorder packets, and the moment that happens the
//! receiver's auto-incremented seq desyncs and every subsequent packet
//! fails to decrypt.
//!
//! The pattern below is the unreliable-transport-friendly variant used
//! internally by QUIC (per-packet keys via HKDF-Expand-Label):
//!
//! 1. `setup_sender` once per session, produces an `AeadCtxS` plus an
//!    `encapsulated_key`. We never call `seal_in_place_detached`; the
//!    `AeadCtxS` is held only for its `export()` API.
//! 2. For each datagram, `ctx.export(info = WARREN_HPKE_AAD_V1 || epoch_be
//!    || seq_be, 32 bytes)` derives a one-time symmetric key.
//! 3. `ChaCha20Poly1305::new(per_packet_key).encrypt_in_place_detached(
//!    nonce = [0; 12], aad = compose_aad(...), plaintext)` encrypts.
//!    The nonce can be all-zero because the key is unique per
//!    `(epoch, seq)` (nonce reuse is only dangerous with the same key).
//! 4. The exit side mirrors the same `export()` call with the same `info`
//!    and decrypts.
//!
//! This design preserves:
//! - Multi-message session (one KEM ECDH per session, amortized).
//! - Forward secrecy via the HPKE setup (ephemeral KEM keypair).
//! - Packet-loss tolerance (per-packet keys are independent).
//! - Anti-replay sliding window over `seq`.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, setup_receiver, setup_sender,
};
use rand_core::{CryptoRng, RngCore};

use crate::errors::MultihopError;
use crate::wire_format::{EncapsulatedKeyBytes, WarrenMultihopFrame};
use crate::{WARREN_HPKE_AAD_V1, WARREN_HPKE_INFO_V1, WARREN_HPKE_VERSION_V1};

/// Warren multihop AEAD: ChaCha20-Poly1305 wired through the `hpke` crate.
pub type WarrenAead = HpkeChaCha20Poly1305;

/// Warren multihop KDF: HKDF-SHA256, RFC 9180 ID 0x0001.
pub type WarrenKdf = HkdfSha256;

/// Warren multihop KEM: DHKEM(X25519, HKDF-SHA256), RFC 9180 ID 0x0020.
pub type WarrenKem = X25519HkdfSha256;

type Aes = <WarrenKem as KemTrait>::PublicKey;
type Sks = <WarrenKem as KemTrait>::PrivateKey;
type Eks = <WarrenKem as KemTrait>::EncappedKey;

/// All-zero 12-byte ChaCha20Poly1305 nonce. Safe because every datagram
/// uses a unique key derived via [`hpke::aead::AeadCtxS::export`] with
/// `(epoch, seq)` baked into the `info` slice.
const NONCE_ZERO_12: [u8; 12] = [0u8; 12];

/// Per-packet symmetric key length (ChaCha20Poly1305 key = 32 bytes).
const PER_PACKET_KEY_LEN: usize = 32;

/// Length of the composed AAD bound into every datagram:
/// `WARREN_HPKE_AAD_V1 (22) || exit_id (16) || epoch_u32_be (4) || seq_u64_be (8)`.
pub const WARREN_AAD_TOTAL_LEN: usize = 22 + 16 + 4 + 8;

const _AAD_PREFIX_LEN_CHECK: () = assert!(WARREN_HPKE_AAD_V1.len() == 22);

/// 16-byte exit identifier (UUID-shaped). Bound into every HPKE AAD and
/// into the [`crate::WarrenMultihopFrame::exit_id`] field so a datagram
/// addressed to one exit cannot be diverted to another without breaking
/// authentication.
///
/// Re-export of the canonical `warrenguard_wire::ExitId` so the multi-hop
/// AAD identifier and the single-hop relay-list identifier are the SAME
/// Rust type, not parallel duplicates that happen to share the wire
/// shape. Wire-compat is preserved: postcard emits exactly 16 raw bytes
/// from either path.
pub use warrenguard_wire::ExitId;

/// Compose the AAD bound into every datagram.
///
/// Layout: `WARREN_HPKE_AAD_V1 || exit_id (16 B) || epoch_u32_be || seq_u64_be`.
///
/// `#[inline]`: called once per outbound and once per inbound multi-hop
/// packet, hot path. The body is a tight series of `copy_from_slice`
/// on a fixed-size stack array - perfect for inlining (the caller
/// usually owns the resulting buffer locally).
#[must_use]
#[inline]
pub fn compose_aad(exit_id: &ExitId, epoch: u32, seq: u64) -> [u8; WARREN_AAD_TOTAL_LEN] {
    let mut aad = [0u8; WARREN_AAD_TOTAL_LEN];
    let mut cursor = 0usize;
    aad[cursor..cursor + 22].copy_from_slice(WARREN_HPKE_AAD_V1);
    cursor += 22;
    aad[cursor..cursor + 16].copy_from_slice(exit_id.as_bytes());
    cursor += 16;
    aad[cursor..cursor + 4].copy_from_slice(&epoch.to_be_bytes());
    cursor += 4;
    aad[cursor..cursor + 8].copy_from_slice(&seq.to_be_bytes());
    aad
}

/// `info` slice passed to [`hpke::aead::AeadCtxS::export`] /
/// `AeadCtxR::export` to derive a per-packet symmetric key for the
/// forward (client -> exit) direction. Includes the versioned AAD prefix
/// as a domain-separation tag, then epoch + seq big-endian. Frozen for
/// `/v1`: changing the byte layout of this function shifts every
/// per-packet key and breaks the `hpke_vectors_v1` regression suite.
fn compose_export_info(epoch: u32, seq: u64) -> [u8; 22 + 4 + 8] {
    let mut info = [0u8; 22 + 4 + 8];
    info[..22].copy_from_slice(WARREN_HPKE_AAD_V1);
    info[22..26].copy_from_slice(&epoch.to_be_bytes());
    info[26..34].copy_from_slice(&seq.to_be_bytes());
    info
}

/// Direction-tag byte appended to the export info for the reverse
/// (exit -> client) direction. The forward direction keeps the original
/// 34-byte layout (no tag) so the frozen `/v1` vector tests still pass.
/// The reverse direction extends the layout by one byte, producing
/// per-packet keys that never collide with the forward direction even
/// when `(epoch, seq)` repeat across directions.
const DIRECTION_TAG_REVERSE: u8 = 0x02;

/// `info` slice for the reverse (exit -> client) direction. Differs from
/// [`compose_export_info`] only by a trailing [`DIRECTION_TAG_REVERSE`]
/// byte; this is sufficient to make `AeadCtxR::export` (exit side) and
/// `AeadCtxS::export` (client side) produce a distinct per-packet key
/// from the forward direction. See the security note in the
/// module-level docs.
fn compose_export_info_reverse(epoch: u32, seq: u64) -> [u8; 22 + 4 + 8 + 1] {
    let mut info = [0u8; 22 + 4 + 8 + 1];
    info[..22].copy_from_slice(WARREN_HPKE_AAD_V1);
    info[22..26].copy_from_slice(&epoch.to_be_bytes());
    info[26..34].copy_from_slice(&seq.to_be_bytes());
    info[34] = DIRECTION_TAG_REVERSE;
    info
}

/// HPKE sender context retained for the doctrine 2-5 s overlap window
/// after a rekey. Holds just enough state to decode reverse-direction
/// frames sealed by the exit under the previous epoch while they finish
/// arriving at the client.
struct PendingOldEpoch {
    ctx: hpke::aead::AeadCtxS<WarrenAead, WarrenKdf, WarrenKem>,
    epoch: u32,
}

/// Sender (client) side of an HPKE multi-message Warren session.
///
/// Constructed by [`ClientSession::new`], reused to seal every datagram in
/// the session. Hold-then-export pattern: the internal AEAD context is
/// never used to call `seal_in_place_detached`; only `export()` is invoked
/// to derive per-packet keys.
///
/// # Rotation
///
/// A context rotation (rekey) is mandated within 8 hours of session
/// lifetime to bound the nonce-overflow exposure of the underlying AEAD
/// context. [`ClientSession::rekey`] swaps the internal
/// HPKE context for a freshly derived one against the same exit public
/// key, bumps `epoch`, and emits a brand-new `encapsulated_key` that
/// callers must send to the exit at the start of the new epoch.
///
/// # Overlap window
///
/// On every successful [`ClientSession::rekey`], the previous
/// `AeadCtxS` is moved into an internal "pending old epoch" slot so
/// [`ClientSession::open_response`] can still decode reverse-direction
/// frames sealed under the previous epoch while they finish arriving
/// at the client. The caller is responsible for ending the overlap
/// window via [`ClientSession::prune_pending_old_epoch`] once the
/// doctrine deadline (5 s by default in the client's multi-hop
/// session) has elapsed.
pub struct ClientSession {
    ctx: hpke::aead::AeadCtxS<WarrenAead, WarrenKdf, WarrenKem>,
    exit_id: ExitId,
    encapsulated_key: EncapsulatedKeyBytes,
    epoch: u32,
    pending_old_epoch: Option<PendingOldEpoch>,
}

impl ClientSession {
    /// Set up a new sender session against the given exit X25519 public
    /// key. The HPKE KEM ECDH runs here (single per-session cost); the
    /// returned `encapsulated_key` MUST be included in every sealed frame
    /// so the exit can decapsulate.
    ///
    /// # Errors
    ///
    /// Returns [`MultihopError::Hpke`] if the underlying `setup_sender`
    /// fails (e.g. KEM serialization error).
    pub fn new<R: CryptoRng + RngCore>(
        exit_pubkey: &Aes,
        exit_id: ExitId,
        rng: &mut R,
    ) -> Result<Self, MultihopError> {
        let (encapped, ctx) = setup_sender::<WarrenAead, WarrenKdf, WarrenKem, R>(
            &OpModeS::Base,
            exit_pubkey,
            WARREN_HPKE_INFO_V1,
            rng,
        )?;
        let mut encapped_bytes = [0u8; 32];
        encapped_bytes.copy_from_slice(&encapped.to_bytes());
        Ok(Self {
            ctx,
            exit_id,
            encapsulated_key: encapped_bytes,
            epoch: 0,
            pending_old_epoch: None,
        })
    }

    /// Expose the encapsulated key produced at setup time. The wire format
    /// frame carries this exact 32-byte ephemeral X25519 pubkey on every
    /// datagram of the session, including across rekeys (the value
    /// changes after each [`Self::rekey`] call).
    #[must_use]
    pub fn encapsulated_key(&self) -> EncapsulatedKeyBytes {
        self.encapsulated_key
    }

    /// Borrow the exit identifier bound into the session.
    #[must_use]
    pub fn exit_id(&self) -> ExitId {
        self.exit_id
    }

    /// Current epoch counter. Starts at `0` for a fresh session and is
    /// incremented by 1 on every successful [`Self::rekey`].
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Rotate the HPKE context.
    ///
    /// Re-runs `setup_sender` against the same exit X25519 public key
    /// with a fresh ephemeral KEM keypair (provided by `rng`). On
    /// success, the internal AEAD context, the encapsulated key, and the
    /// `epoch` counter are atomically replaced. The seq counter is owned
    /// by the caller, who MUST restart seq at `0` for the new epoch.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::Hpke`] if `setup_sender` fails.
    /// - [`MultihopError::RekeyFailed`] if the epoch would overflow
    ///   `u32::MAX`. In practice this never triggers (one rekey every
    ///   8 h gives `2^32 * 8 h ≈ 3.9 million years`).
    pub fn rekey<R: CryptoRng + RngCore>(
        &mut self,
        exit_pubkey: &Aes,
        rng: &mut R,
    ) -> Result<EncapsulatedKeyBytes, MultihopError> {
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(MultihopError::RekeyFailed("epoch counter overflowed u32"))?;
        let (encapped, new_ctx) = setup_sender::<WarrenAead, WarrenKdf, WarrenKem, R>(
            &OpModeS::Base,
            exit_pubkey,
            WARREN_HPKE_INFO_V1,
            rng,
        )?;
        let mut encapped_bytes = [0u8; 32];
        encapped_bytes.copy_from_slice(&encapped.to_bytes());

        // Move the soon-to-be-old AeadCtxS into the pending-old-epoch
        // slot so open_response can still decode reverse-direction
        // frames sealed by the exit under the previous epoch. The
        // caller closes the overlap window by invoking
        // prune_pending_old_epoch once the doctrine deadline elapses.
        // If a previous overlap window is still pending (back-to-back
        // rekeys faster than the prune cadence), it is dropped here:
        // the deeper old epoch is unrecoverable at the receiver
        // anyway because the wire format does not negotiate a
        // multi-epoch overlap.
        let old_ctx = std::mem::replace(&mut self.ctx, new_ctx);
        let old_epoch = self.epoch;
        self.pending_old_epoch = Some(PendingOldEpoch {
            ctx: old_ctx,
            epoch: old_epoch,
        });

        self.encapsulated_key = encapped_bytes;
        self.epoch = next_epoch;
        Ok(encapped_bytes)
    }

    /// End the overlap window left over from the previous
    /// [`Self::rekey`] call. After this returns, in-flight
    /// reverse-direction frames from the old epoch can no longer
    /// decode and [`Self::open_response`] will reject them with a
    /// regular AEAD failure. Idempotent; calling on a session with no
    /// pending old epoch is a no-op.
    pub fn prune_pending_old_epoch(&mut self) {
        self.pending_old_epoch = None;
    }

    /// `true` if [`Self::rekey`] has been called recently and the
    /// overlap window is still open (no [`Self::prune_pending_old_epoch`]
    /// has elapsed). Observability hook for the timer-driven prune
    /// loop in [`crate`]'s consumer.
    #[must_use]
    pub fn has_pending_old_epoch(&self) -> bool {
        self.pending_old_epoch.is_some()
    }

    /// Epoch number of the pending old-epoch slot, if one is held.
    /// Useful for the consumer's anti-replay window to look up the
    /// matching old-epoch tracker without exposing the AEAD context
    /// itself.
    #[must_use]
    pub fn pending_old_epoch_value(&self) -> Option<u32> {
        self.pending_old_epoch.as_ref().map(|p| p.epoch)
    }

    /// Seal a single payload into a [`WarrenMultihopFrame`] for the
    /// **client -> exit** direction.
    ///
    /// The caller controls `epoch` and `seq` so the same session can carry
    /// the anti-replay window and the rekey logic without depending on the
    /// crate's internal seq counter. See the module-level rationale.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::Hpke`] if `export` fails.
    /// - [`MultihopError::Hpke`] (with `SealError`) if the AEAD encryption
    ///   fails.
    pub fn seal(
        &self,
        payload: &[u8],
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrame, MultihopError> {
        let mut per_packet_key = [0u8; PER_PACKET_KEY_LEN];
        let info = compose_export_info(epoch, seq);
        self.ctx.export(&info, &mut per_packet_key)?;

        let aad = compose_aad(&self.exit_id, epoch, seq);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&per_packet_key));
        let nonce = Nonce::from_slice(&NONCE_ZERO_12);
        let mut buf = payload.to_vec();
        let sealed = cipher.encrypt_in_place_detached(nonce, &aad, &mut buf);
        // Zeroize the derived key on every path, including a seal failure, so a
        // failed frame never leaves the per-packet key on the stack.
        zero_key_array(&mut per_packet_key);
        let tag = sealed.map_err(|_| MultihopError::Hpke(hpke::HpkeError::SealError))?;

        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag.as_slice());

        Ok(WarrenMultihopFrame {
            version: WARREN_HPKE_VERSION_V1,
            exit_id: self.exit_id,
            epoch,
            seq,
            encapsulated_key: self.encapsulated_key,
            aead_tag: tag_arr,
            ciphertext: buf,
        })
    }

    /// Open a [`WarrenMultihopFrame`] sealed by [`ExitSession::seal_response`]
    /// in the **exit -> client** direction.
    ///
    /// The reverse direction shares the HPKE setup with the forward
    /// direction (same KEM ECDH, same `AeadCtxS` exporter) but uses a
    /// distinct `info` slice including a direction tag byte, so the
    /// resulting per-packet key never collides with the forward key
    /// for the same `(epoch, seq)`. A forward-direction frame fed into
    /// this method will fail AEAD verification.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::ExitIdMismatch`] if the frame targets a
    ///   different exit.
    /// - [`MultihopError::UnsupportedVersion`] if the frame `version`
    ///   does not match [`WARREN_HPKE_VERSION_V1`].
    /// - [`MultihopError::Hpke`] if `export` fails.
    /// - [`MultihopError::Hpke`] (`OpenError`) if the AEAD tag does not
    ///   verify (tampered ciphertext, AAD, tag, or cross-direction
    ///   frame).
    pub fn open_response(&self, frame: &WarrenMultihopFrame) -> Result<Vec<u8>, MultihopError> {
        // Borrowing variant: clones the frame so a caller that must retain it
        // (the once-per-session setup path) can reuse it. Hot datapath callers
        // that own the decoded frame should call [`Self::open_response_owned`]
        // to skip the per-packet ciphertext copy.
        self.open_response_owned(frame.clone())
    }

    /// Owned variant of [`Self::open_response`]: takes the decoded frame by
    /// value and decrypts in place into its own `ciphertext` buffer (the one
    /// allocated by `decode_frame`), so the reverse-direction datapath opens a
    /// frame with zero per-packet copies. Produces byte-identical plaintext to
    /// [`Self::open_response`]; see it for the reverse-direction and
    /// cross-direction-rejection semantics.
    ///
    /// # Errors
    ///
    /// Same as [`Self::open_response`].
    pub fn open_response_owned(
        &self,
        frame: WarrenMultihopFrame,
    ) -> Result<Vec<u8>, MultihopError> {
        if frame.exit_id != self.exit_id {
            return Err(MultihopError::ExitIdMismatch);
        }
        if frame.version != WARREN_HPKE_VERSION_V1 {
            return Err(MultihopError::UnsupportedVersion {
                got: frame.version,
                expected: WARREN_HPKE_VERSION_V1,
            });
        }

        // Pick the AeadCtxS whose KEM ephemeral matches the frame's
        // epoch. The current ctx covers the active epoch; the pending
        // ctx (if any) covers the previous epoch during the overlap
        // window after a rekey. A frame from any other epoch cannot
        // decode and surfaces as a clean AEAD open error.
        let ctx = if frame.epoch == self.epoch {
            &self.ctx
        } else if let Some(pending) = &self.pending_old_epoch {
            if pending.epoch == frame.epoch {
                &pending.ctx
            } else {
                return Err(MultihopError::Hpke(hpke::HpkeError::OpenError));
            }
        } else {
            return Err(MultihopError::Hpke(hpke::HpkeError::OpenError));
        };

        let mut per_packet_key = [0u8; PER_PACKET_KEY_LEN];
        let info = compose_export_info_reverse(frame.epoch, frame.seq);
        ctx.export(&info, &mut per_packet_key)?;

        let aad = compose_aad(&self.exit_id, frame.epoch, frame.seq);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&per_packet_key));
        let nonce = Nonce::from_slice(&NONCE_ZERO_12);
        // Copy the 16-byte tag out before the partial move of `ciphertext`.
        let aead_tag = frame.aead_tag;
        let tag = Tag::from_slice(&aead_tag);
        // Reuse the frame's own ciphertext buffer (allocated by `decode_frame`)
        // as the in-place decryption target: no per-packet copy on the hot path.
        let mut buf = frame.ciphertext;
        let opened = cipher.decrypt_in_place_detached(nonce, &aad, &mut buf, tag);
        // Zeroize the derived key on every path, including an AEAD-open failure,
        // so a rejected frame never leaves the per-packet key on the stack.
        zero_key_array(&mut per_packet_key);
        opened.map_err(|_| MultihopError::Hpke(hpke::HpkeError::OpenError))?;

        Ok(buf)
    }
}

/// Receiver (exit) side of an HPKE multi-message Warren session.
///
/// Constructed by [`ExitSession::new`] after parsing the first datagram of
/// a `(client, exit_id, epoch)` triple. Reused to open every datagram in
/// the session via [`ExitSession::open`].
pub struct ExitSession {
    ctx: hpke::aead::AeadCtxR<WarrenAead, WarrenKdf, WarrenKem>,
    exit_id: ExitId,
    encapsulated_key: EncapsulatedKeyBytes,
}

impl ExitSession {
    /// Set up a new receiver session by decapsulating the client-provided
    /// `encapsulated_key` with the exit's long-lived X25519 private key.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::Hpke`] if the KEM decap fails (malformed
    ///   `encapsulated_key`).
    pub fn new(
        exit_privkey: &Sks,
        encapsulated_key: &EncapsulatedKeyBytes,
        exit_id: ExitId,
    ) -> Result<Self, MultihopError> {
        let encapped = Eks::from_bytes(encapsulated_key)?;
        let ctx = setup_receiver::<WarrenAead, WarrenKdf, WarrenKem>(
            &OpModeR::Base,
            exit_privkey,
            &encapped,
            WARREN_HPKE_INFO_V1,
        )?;
        Ok(Self {
            ctx,
            exit_id,
            encapsulated_key: *encapsulated_key,
        })
    }

    /// Borrow the exit identifier bound into the session.
    #[must_use]
    pub fn exit_id(&self) -> ExitId {
        self.exit_id
    }

    /// Expose the encapsulated key the session was set up with. Reused
    /// when emitting reverse-direction frames so the wire stays
    /// indistinguishable from a forward-direction frame.
    #[must_use]
    pub fn encapsulated_key(&self) -> EncapsulatedKeyBytes {
        self.encapsulated_key
    }

    /// Open a single sealed frame and return the recovered plaintext.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::ExitIdMismatch`] if the frame targets a
    ///   different exit.
    /// - [`MultihopError::Hpke`] if `export` fails.
    /// - [`MultihopError::Hpke`] (`OpenError`) if the AEAD tag does not
    ///   verify (tampered ciphertext, AAD, or tag).
    pub fn open(&self, frame: &WarrenMultihopFrame) -> Result<Vec<u8>, MultihopError> {
        // Borrowing variant: clones the frame so a caller that must retain it
        // can reuse it. Hot datapath callers that own the decoded frame should
        // call [`Self::open_owned`] to skip the per-packet ciphertext copy.
        self.open_owned(frame.clone())
    }

    /// Owned variant of [`Self::open`]: consumes the decoded forward-direction
    /// frame and decrypts in place into its own `ciphertext` buffer, so the exit
    /// datapath opens a frame with zero per-packet copies. Byte-identical result
    /// to [`Self::open`]; see it for the direction semantics.
    ///
    /// # Errors
    ///
    /// Same as [`Self::open`].
    pub fn open_owned(&self, frame: WarrenMultihopFrame) -> Result<Vec<u8>, MultihopError> {
        if frame.exit_id != self.exit_id {
            return Err(MultihopError::ExitIdMismatch);
        }
        if frame.version != WARREN_HPKE_VERSION_V1 {
            return Err(MultihopError::UnsupportedVersion {
                got: frame.version,
                expected: WARREN_HPKE_VERSION_V1,
            });
        }

        let mut per_packet_key = [0u8; PER_PACKET_KEY_LEN];
        let info = compose_export_info(frame.epoch, frame.seq);
        self.ctx.export(&info, &mut per_packet_key)?;

        let aad = compose_aad(&self.exit_id, frame.epoch, frame.seq);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&per_packet_key));
        let nonce = Nonce::from_slice(&NONCE_ZERO_12);
        // Copy the 16-byte tag out before the partial move of `ciphertext`.
        let aead_tag = frame.aead_tag;
        let tag = Tag::from_slice(&aead_tag);
        // Reuse the frame's own ciphertext buffer as the in-place decryption
        // target: no per-packet copy on the hot path.
        let mut buf = frame.ciphertext;
        let opened = cipher.decrypt_in_place_detached(nonce, &aad, &mut buf, tag);
        // Zeroize the derived key on every path, including an AEAD-open failure,
        // so a rejected frame never leaves the per-packet key on the stack.
        zero_key_array(&mut per_packet_key);
        opened.map_err(|_| MultihopError::Hpke(hpke::HpkeError::OpenError))?;

        Ok(buf)
    }

    /// Seal a single payload into a [`WarrenMultihopFrame`] for the
    /// **exit -> client** direction.
    ///
    /// Mirrors [`ClientSession::seal`] but uses a distinct per-packet
    /// key (cf. [`compose_export_info_reverse`]) so a frame produced
    /// here cannot be opened by [`ExitSession::open`] (which uses the
    /// forward info). The emitted frame carries the same
    /// `encapsulated_key` the session was set up with, keeping the wire
    /// shape symmetric with forward-direction frames.
    ///
    /// `seq` is owned by the caller, allowing the exit binary to track
    /// its own monotonic counter independently from the client's send
    /// counter. The client's reverse-direction anti-replay window
    /// observes the exit's seq, not the client's.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::Hpke`] if `export` fails.
    /// - [`MultihopError::Hpke`] (`SealError`) if the AEAD seal fails.
    pub fn seal_response(
        &self,
        payload: &[u8],
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrame, MultihopError> {
        // Borrowing variant: copies the payload into an owned buffer. Hot
        // datapath callers that own the plaintext should call
        // [`Self::seal_response_owned`] to seal in place with no per-packet copy.
        self.seal_response_owned(payload.to_vec(), epoch, seq)
    }

    /// Owned variant of [`Self::seal_response`]: seals the caller's plaintext
    /// buffer in place and moves it into the returned frame, so the reverse-
    /// direction exit datapath emits a frame with zero per-packet copies.
    /// Byte-identical wire output to [`Self::seal_response`].
    ///
    /// # Errors
    ///
    /// Same as [`Self::seal_response`].
    pub fn seal_response_owned(
        &self,
        mut buf: Vec<u8>,
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrame, MultihopError> {
        let mut per_packet_key = [0u8; PER_PACKET_KEY_LEN];
        let info = compose_export_info_reverse(epoch, seq);
        self.ctx.export(&info, &mut per_packet_key)?;

        let aad = compose_aad(&self.exit_id, epoch, seq);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&per_packet_key));
        let nonce = Nonce::from_slice(&NONCE_ZERO_12);
        let sealed = cipher.encrypt_in_place_detached(nonce, &aad, &mut buf);
        // Zeroize the derived key on every path, including a seal failure, so a
        // failed frame never leaves the per-packet key on the stack.
        zero_key_array(&mut per_packet_key);
        let tag = sealed.map_err(|_| MultihopError::Hpke(hpke::HpkeError::SealError))?;

        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag.as_slice());

        Ok(WarrenMultihopFrame {
            version: WARREN_HPKE_VERSION_V1,
            exit_id: self.exit_id,
            epoch,
            seq,
            encapsulated_key: self.encapsulated_key,
            aead_tag: tag_arr,
            ciphertext: buf,
        })
    }
}

fn zero_key_array(buf: &mut [u8; PER_PACKET_KEY_LEN]) {
    zeroize::Zeroize::zeroize(buf.as_mut_slice());
}

// `ReplayWindow` moved to `crate::replay`; consumers re-import via the
// crate root. The receive path in [`ExitSession::open`] intentionally
// does NOT consult the window: it only performs cryptographic
// authentication. Anti-replay is a separate concern with its own
// concurrency / per-`(exit_id, epoch)` lifecycle, owned by the binary
// (the relay / exit) that wraps an `ExitSession`.

// =============================================================================
// Test-only helpers re-exported by the integration tests / vectors / examples.
// =============================================================================

/// Derive a deterministic X25519 keypair from a 32-byte input keying
/// material (`ikm`). Wraps the `hpke` KEM's `derive_keypair`, exposed for
/// test vector generation only.
#[doc(hidden)]
#[must_use]
pub fn derive_exit_keypair(ikm: &[u8]) -> (Sks, Aes) {
    <WarrenKem as KemTrait>::derive_keypair(ikm)
}

/// Serialize an X25519 public key to its raw 32-byte form.
#[doc(hidden)]
#[must_use]
pub fn pubkey_to_bytes(pk: &Aes) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.to_bytes());
    out
}

/// Parse a raw 32-byte X25519 public key.
///
/// # Errors
///
/// Returns [`MultihopError::Hpke`] if the bytes are not a valid X25519
/// pubkey (top-bit clamping / curve check).
#[doc(hidden)]
pub fn pubkey_from_bytes(bytes: &[u8; 32]) -> Result<Aes, MultihopError> {
    Ok(Aes::from_bytes(bytes)?)
}

/// Public-facing alias of [`pubkey_from_bytes`] used by the client
/// to materialize an exit's HPKE recipient pubkey from the 32-byte form
/// shipped in a signed exit descriptor.
///
/// # Errors
///
/// Returns [`MultihopError::Hpke`] if the bytes are not a valid X25519
/// pubkey (top-bit clamping / curve check).
pub fn parse_exit_x25519_pubkey(bytes: &[u8; 32]) -> Result<Aes, MultihopError> {
    pubkey_from_bytes(bytes)
}
