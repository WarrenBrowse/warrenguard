//! Warren multihop `/v2` post-quantum HPKE session (X-Wing hybrid seal).
//!
//! The PQ session mirrors the classical [`crate::ClientSession`] /
//! [`crate::ExitSession`] one-for-one, but swaps the KEM and key schedule:
//!
//! - KEM: X-Wing (X25519 + ML-KEM-768) instead of DHKEM(X25519). The hybrid
//!   shared secret is produced once per session (per epoch) by the X-Wing
//!   combiner (see [`crate::xwing`]).
//! - Exporter: HKDF-SHA256 over the X-Wing shared secret instead of the `hpke`
//!   crate's `AeadCtxS::export`. Per-packet keys use the same `(epoch, seq)`
//!   domain-separated info as `/v1`, but under a `/v2`-distinct label
//!   ([`crate::WARREN_PQ_HPKE_AAD_V2`]) so the two datapaths never collide.
//!
//! Everything else is IDENTICAL to `/v1`: per-packet key -> ChaCha20-Poly1305
//! with an all-zero nonce (safe because each `(epoch, seq)` yields a unique
//! key), forward/reverse direction tags, the rekey overlap window, and the
//! anti-replay seq owned by the caller. This keeps the packet-loss tolerance
//! and forward-secrecy-per-epoch properties of the classical path.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::errors::MultihopError;
use crate::session::ExitId;
use crate::wire_format_v2::WarrenMultihopFrameV2;
use crate::xwing::{
    XWingCiphertext, XWingRecipientPublicKey, XWingRecipientSecretKey, XWingSharedSecret,
    xwing_decapsulate, xwing_encapsulate,
};
use crate::{WARREN_HPKE_VERSION_V2, WARREN_PQ_HPKE_AAD_V2, WARREN_PQ_HPKE_SALT_V2};

const NONCE_ZERO_12: [u8; 12] = [0u8; 12];
const PER_PACKET_KEY_LEN: usize = 32;

/// Length of the `/v2` AAD prefix ([`WARREN_PQ_HPKE_AAD_V2`]).
const PQ_AAD_PREFIX_LEN: usize = 25;
const _PQ_AAD_PREFIX_LEN_CHECK: () = assert!(WARREN_PQ_HPKE_AAD_V2.len() == PQ_AAD_PREFIX_LEN);

/// Total `/v2` AAD length: prefix (25) || exit_id (16) || epoch_be (4) || seq_be (8).
const PQ_AAD_TOTAL_LEN: usize = PQ_AAD_PREFIX_LEN + 16 + 4 + 8;

/// Reverse-direction (exit -> client) tag byte, appended to the exporter info
/// so a reverse per-packet key never collides with the forward key for the same
/// `(epoch, seq)`. Same value and role as the classical `/v1` reverse tag.
const DIRECTION_TAG_REVERSE: u8 = 0x02;

fn pq_compose_aad(exit_id: &ExitId, epoch: u32, seq: u64) -> [u8; PQ_AAD_TOTAL_LEN] {
    let mut aad = [0u8; PQ_AAD_TOTAL_LEN];
    let mut cursor = 0usize;
    aad[cursor..cursor + PQ_AAD_PREFIX_LEN].copy_from_slice(WARREN_PQ_HPKE_AAD_V2);
    cursor += PQ_AAD_PREFIX_LEN;
    aad[cursor..cursor + 16].copy_from_slice(exit_id.as_bytes());
    cursor += 16;
    aad[cursor..cursor + 4].copy_from_slice(&epoch.to_be_bytes());
    cursor += 4;
    aad[cursor..cursor + 8].copy_from_slice(&seq.to_be_bytes());
    aad
}

fn pq_export_info(epoch: u32, seq: u64) -> [u8; PQ_AAD_PREFIX_LEN + 4 + 8] {
    let mut info = [0u8; PQ_AAD_PREFIX_LEN + 4 + 8];
    info[..PQ_AAD_PREFIX_LEN].copy_from_slice(WARREN_PQ_HPKE_AAD_V2);
    info[PQ_AAD_PREFIX_LEN..PQ_AAD_PREFIX_LEN + 4].copy_from_slice(&epoch.to_be_bytes());
    info[PQ_AAD_PREFIX_LEN + 4..].copy_from_slice(&seq.to_be_bytes());
    info
}

fn pq_export_info_reverse(epoch: u32, seq: u64) -> [u8; PQ_AAD_PREFIX_LEN + 4 + 8 + 1] {
    let mut info = [0u8; PQ_AAD_PREFIX_LEN + 4 + 8 + 1];
    info[..PQ_AAD_PREFIX_LEN + 4 + 8].copy_from_slice(&pq_export_info(epoch, seq));
    info[PQ_AAD_PREFIX_LEN + 4 + 8] = DIRECTION_TAG_REVERSE;
    info
}

/// Derive a per-packet key from the X-Wing shared secret via HKDF-SHA256.
///
/// PRK = HKDF-Extract(salt = [`WARREN_PQ_HPKE_SALT_V2`], ikm = ss); the
/// per-packet key is HKDF-Expand(PRK, info). The derived key is written into
/// `out`; the caller zeroizes it after use.
fn derive_per_packet_key(ss: &XWingSharedSecret, info: &[u8], out: &mut [u8; PER_PACKET_KEY_LEN]) {
    let hk = Hkdf::<Sha256>::new(Some(WARREN_PQ_HPKE_SALT_V2), ss.as_bytes());
    // `expand` only errors on an absurd output length (> 255*32); 32 is fine.
    hk.expand(info, out)
        .expect("32-byte HKDF-SHA256 expand is always within the output-length bound");
}

fn zero_key_array(buf: &mut [u8; PER_PACKET_KEY_LEN]) {
    buf.zeroize();
}

/// Retained previous-epoch X-Wing secret for the rekey overlap window (mirror
/// of the classical `PendingOldEpoch`). Keeps `encapsulated_key` alongside
/// `ss` so [`PqClientSession::seal_pending_old_epoch`] can stamp a DATA frame
/// with the OLD epoch's `ct_X`: the exit's session cache is keyed by
/// `encapsulated_key`, so a frame sealed under the new epoch's key would miss
/// the old, already-established cache entry even if the AAD/key derivation
/// used the right shared secret.
struct PqPendingOldEpoch {
    ss: XWingSharedSecret,
    encapsulated_key: [u8; 32],
    epoch: u32,
}

/// Sender (client) side of a `/v2` post-quantum multihop session.
pub struct PqClientSession {
    ss: XWingSharedSecret,
    exit_id: ExitId,
    encapsulated_key: [u8; 32],
    pq_ct: Vec<u8>,
    epoch: u32,
    pending_old_epoch: Option<PqPendingOldEpoch>,
}

impl PqClientSession {
    /// Set up a new PQ sender session against the exit's X-Wing recipient
    /// public key (its ML-KEM-768 key + static X25519 key from the signed
    /// descriptor). Runs the X-Wing encapsulation once; the resulting
    /// `encapsulated_key` (`ct_X`) and `pq_ct` (`ct_M`) are placed on the setup
    /// frame so the exit can decapsulate.
    ///
    /// # Errors
    ///
    /// [`MultihopError::PqAead`] / [`MultihopError::PqKeyLength`] if the X-Wing
    /// encapsulation fails.
    pub fn new<R: CryptoRng + RngCore>(
        recipient: &XWingRecipientPublicKey,
        exit_id: ExitId,
        rng: &mut R,
    ) -> Result<Self, MultihopError> {
        let (ct, ss) = encaps_from_rng(recipient, rng)?;
        Ok(Self::from_ciphertext(&ct, ss, exit_id, 0))
    }

    /// Deterministic constructor for golden-vector generation: encapsulate with
    /// the exact `m_seed` (ML-KEM message) and `eph_x_seed` (X25519 ephemeral)
    /// instead of drawing them from an RNG, so the emitted frame bytes are
    /// reproducible across every SDK. Never used in production (a real session
    /// MUST draw fresh CSPRNG randomness via [`Self::new`]).
    ///
    /// # Errors
    ///
    /// [`MultihopError::PqAead`] / [`MultihopError::PqKeyLength`] on encaps
    /// failure.
    #[doc(hidden)]
    pub fn new_deterministic(
        recipient: &XWingRecipientPublicKey,
        exit_id: ExitId,
        m_seed: &[u8; 32],
        eph_x_seed: &[u8; 32],
    ) -> Result<Self, MultihopError> {
        let (ct, ss) = xwing_encapsulate(recipient, m_seed, eph_x_seed)?;
        Ok(Self::from_ciphertext(&ct, ss, exit_id, 0))
    }

    fn from_ciphertext(
        ct: &XWingCiphertext,
        ss: XWingSharedSecret,
        exit_id: ExitId,
        epoch: u32,
    ) -> Self {
        Self {
            ss,
            exit_id,
            encapsulated_key: *ct.x25519_ct(),
            pq_ct: ct.mlkem_ct().to_vec(),
            epoch,
            pending_old_epoch: None,
        }
    }

    /// The X25519 ephemeral public (`ct_X`) carried in the classical
    /// `encapsulated_key` field of every `/v2` frame of this epoch.
    #[must_use]
    pub fn encapsulated_key(&self) -> [u8; 32] {
        self.encapsulated_key
    }

    /// The ML-KEM-768 ciphertext (`ct_M`) carried in `pq_ct` on the setup /
    /// rekey frame of this epoch.
    #[must_use]
    pub fn pq_ct(&self) -> &[u8] {
        &self.pq_ct
    }

    /// Borrow the exit identifier bound into the session.
    #[must_use]
    pub fn exit_id(&self) -> ExitId {
        self.exit_id
    }

    /// Current epoch counter (starts at 0, +1 per [`Self::rekey`]).
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Rotate the X-Wing session: fresh encapsulation against the same
    /// recipient, `epoch += 1`, and the previous shared secret is moved into
    /// the overlap slot so [`Self::open_response`] can still decode in-flight
    /// old-epoch reverse frames. Returns the new `(encapsulated_key, pq_ct)` to
    /// place on the new epoch's setup frame.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::RekeyFailed`] if the epoch would overflow `u32`.
    /// - [`MultihopError::PqAead`] if the X-Wing encapsulation fails.
    pub fn rekey<R: CryptoRng + RngCore>(
        &mut self,
        recipient: &XWingRecipientPublicKey,
        rng: &mut R,
    ) -> Result<([u8; 32], Vec<u8>), MultihopError> {
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(MultihopError::RekeyFailed("epoch counter overflowed u32"))?;
        let (ct, ss) = encaps_from_rng(recipient, rng)?;
        let new_encapsulated_key = *ct.x25519_ct();
        let new_pq_ct = ct.mlkem_ct().to_vec();

        let old_ss = std::mem::replace(&mut self.ss, ss);
        let old_encapsulated_key =
            std::mem::replace(&mut self.encapsulated_key, new_encapsulated_key);
        self.pending_old_epoch = Some(PqPendingOldEpoch {
            ss: old_ss,
            encapsulated_key: old_encapsulated_key,
            epoch: self.epoch,
        });
        self.pq_ct = new_pq_ct.clone();
        self.epoch = next_epoch;
        Ok((new_encapsulated_key, new_pq_ct))
    }

    /// End the rekey overlap window (mirror of the classical prune).
    pub fn prune_pending_old_epoch(&mut self) {
        self.pending_old_epoch = None;
    }

    /// `true` while a rekey overlap window is still open.
    #[must_use]
    pub fn has_pending_old_epoch(&self) -> bool {
        self.pending_old_epoch.is_some()
    }

    /// Epoch number of the pending old-epoch slot, if held.
    #[must_use]
    pub fn pending_old_epoch_value(&self) -> Option<u32> {
        self.pending_old_epoch.as_ref().map(|p| p.epoch)
    }

    /// Seal a payload into a `/v2` SETUP / rekey frame (`pq_ct` carries the
    /// ML-KEM ciphertext so the exit can establish the epoch session).
    ///
    /// # Errors
    ///
    /// [`MultihopError::PqAead`] if the AEAD seal fails.
    pub fn seal_setup(
        &self,
        payload: &[u8],
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrameV2, MultihopError> {
        self.seal_inner(payload, epoch, seq, self.pq_ct.clone())
    }

    /// Seal a payload into a `/v2` steady-state DATA frame (empty `pq_ct`: the
    /// exit already holds this epoch's established session, so the 1088-byte
    /// ML-KEM ciphertext is not re-sent per datagram).
    ///
    /// # Errors
    ///
    /// [`MultihopError::PqAead`] if the AEAD seal fails.
    pub fn seal(
        &self,
        payload: &[u8],
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrameV2, MultihopError> {
        self.seal_inner(payload, epoch, seq, Vec::new())
    }

    fn seal_inner(
        &self,
        payload: &[u8],
        epoch: u32,
        seq: u64,
        pq_ct: Vec<u8>,
    ) -> Result<WarrenMultihopFrameV2, MultihopError> {
        Self::seal_with(
            &self.ss,
            self.encapsulated_key,
            &self.exit_id,
            payload,
            epoch,
            seq,
            pq_ct,
        )
    }

    /// Seal a DATA frame under the RETAINED previous epoch while a rekey's new
    /// epoch is still unacked at the exit. The exit already established this
    /// old epoch (it is what accepted the pre-rekey traffic), so a full-size
    /// uplink packet keeps flowing there during the rekey overlap window
    /// instead of being oversized with `pq_ct`: the new epoch bootstraps on
    /// its own dedicated small setup frame instead (see
    /// [`Self::seal_setup`]). Mirrors [`Self::seal`] (no `pq_ct`), but under
    /// the pending epoch's shared secret and `encapsulated_key` rather than
    /// the current one, so the frame lands in the exit's cache entry for the
    /// OLD epoch rather than missing (or worse, colliding with) the NEW one.
    ///
    /// # Errors
    ///
    /// [`MultihopError::RekeyFailed`] if there is no pending old epoch. The
    /// caller must check [`Self::has_pending_old_epoch`] first (under the
    /// same session lock as the seal, so this should never fire in practice).
    /// [`MultihopError::PqAead`] if the AEAD seal fails.
    pub fn seal_pending_old_epoch(
        &self,
        payload: &[u8],
        seq: u64,
    ) -> Result<WarrenMultihopFrameV2, MultihopError> {
        let pending = self
            .pending_old_epoch
            .as_ref()
            .ok_or(MultihopError::RekeyFailed(
                "no pending old epoch to seal a DATA frame under",
            ))?;
        Self::seal_with(
            &pending.ss,
            pending.encapsulated_key,
            &self.exit_id,
            payload,
            pending.epoch,
            seq,
            Vec::new(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_with(
        ss: &XWingSharedSecret,
        encapsulated_key: [u8; 32],
        exit_id: &ExitId,
        payload: &[u8],
        epoch: u32,
        seq: u64,
        pq_ct: Vec<u8>,
    ) -> Result<WarrenMultihopFrameV2, MultihopError> {
        let mut key = [0u8; PER_PACKET_KEY_LEN];
        derive_per_packet_key(ss, &pq_export_info(epoch, seq), &mut key);
        let aad = pq_compose_aad(exit_id, epoch, seq);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&NONCE_ZERO_12);
        let mut buf = payload.to_vec();
        let sealed = cipher.encrypt_in_place_detached(nonce, &aad, &mut buf);
        zero_key_array(&mut key);
        let tag = sealed.map_err(|_| MultihopError::PqAead)?;

        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag.as_slice());
        Ok(WarrenMultihopFrameV2 {
            version: WARREN_HPKE_VERSION_V2,
            exit_id: *exit_id,
            epoch,
            seq,
            encapsulated_key,
            pq_ct,
            aead_tag: tag_arr,
            ciphertext: buf,
        })
    }

    /// Open a reverse-direction (exit -> client) `/v2` frame.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::ExitIdMismatch`] if the frame targets another exit.
    /// - [`MultihopError::UnsupportedVersion`] if the version is not `0x02`.
    /// - [`MultihopError::PqAead`] if the AEAD tag does not verify (tamper,
    ///   cross-direction, or unknown epoch).
    pub fn open_response(&self, frame: &WarrenMultihopFrameV2) -> Result<Vec<u8>, MultihopError> {
        if frame.exit_id != self.exit_id {
            return Err(MultihopError::ExitIdMismatch);
        }
        if frame.version != WARREN_HPKE_VERSION_V2 {
            return Err(MultihopError::UnsupportedVersion {
                got: frame.version,
                expected: WARREN_HPKE_VERSION_V2,
            });
        }
        let ss = if frame.epoch == self.epoch {
            &self.ss
        } else if let Some(pending) = &self.pending_old_epoch {
            if pending.epoch == frame.epoch {
                &pending.ss
            } else {
                return Err(MultihopError::PqAead);
            }
        } else {
            return Err(MultihopError::PqAead);
        };
        open_with_ss(ss, &self.exit_id, frame, true)
    }
}

/// Receiver (exit) side of a `/v2` post-quantum multihop session.
pub struct PqExitSession {
    ss: XWingSharedSecret,
    exit_id: ExitId,
    encapsulated_key: [u8; 32],
}

impl PqExitSession {
    /// Set up a new PQ receiver session by X-Wing-decapsulating the client's
    /// setup frame material (`encapsulated_key` = `ct_X`, `pq_ct` = `ct_M`)
    /// with the exit's X-Wing recipient secret key.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::PqKeyLength`] if `pq_ct` is not a valid ML-KEM
    ///   ciphertext length.
    /// - [`MultihopError::PqAead`] if X-Wing decapsulation fails.
    pub fn new(
        secret: &XWingRecipientSecretKey,
        encapsulated_key: &[u8; 32],
        pq_ct: &[u8],
        exit_id: ExitId,
    ) -> Result<Self, MultihopError> {
        let ct = XWingCiphertext::from_wire_parts(pq_ct, *encapsulated_key)?;
        let ss = xwing_decapsulate(secret, &ct)?;
        Ok(Self {
            ss,
            exit_id,
            encapsulated_key: *encapsulated_key,
        })
    }

    /// Borrow the exit identifier bound into the session.
    #[must_use]
    pub fn exit_id(&self) -> ExitId {
        self.exit_id
    }

    /// Open a forward-direction (client -> exit) `/v2` frame.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::ExitIdMismatch`] if the frame targets another exit.
    /// - [`MultihopError::UnsupportedVersion`] if the version is not `0x02`.
    /// - [`MultihopError::PqAead`] if the AEAD tag does not verify.
    pub fn open(&self, frame: &WarrenMultihopFrameV2) -> Result<Vec<u8>, MultihopError> {
        if frame.exit_id != self.exit_id {
            return Err(MultihopError::ExitIdMismatch);
        }
        if frame.version != WARREN_HPKE_VERSION_V2 {
            return Err(MultihopError::UnsupportedVersion {
                got: frame.version,
                expected: WARREN_HPKE_VERSION_V2,
            });
        }
        open_with_ss(&self.ss, &self.exit_id, frame, false)
    }

    /// Seal a reverse-direction (exit -> client) `/v2` frame. Steady-state:
    /// `pq_ct` is empty (the client already holds this epoch's session) and the
    /// `encapsulated_key` (`ct_X`) is echoed so the reverse wire shape matches
    /// the forward one.
    ///
    /// # Errors
    ///
    /// [`MultihopError::PqAead`] if the AEAD seal fails.
    pub fn seal_response(
        &self,
        payload: &[u8],
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrameV2, MultihopError> {
        let mut key = [0u8; PER_PACKET_KEY_LEN];
        derive_per_packet_key(&self.ss, &pq_export_info_reverse(epoch, seq), &mut key);
        let aad = pq_compose_aad(&self.exit_id, epoch, seq);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&NONCE_ZERO_12);
        let mut buf = payload.to_vec();
        let sealed = cipher.encrypt_in_place_detached(nonce, &aad, &mut buf);
        zero_key_array(&mut key);
        let tag = sealed.map_err(|_| MultihopError::PqAead)?;

        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag.as_slice());
        Ok(WarrenMultihopFrameV2 {
            version: WARREN_HPKE_VERSION_V2,
            exit_id: self.exit_id,
            epoch,
            seq,
            encapsulated_key: self.encapsulated_key,
            pq_ct: Vec::new(),
            aead_tag: tag_arr,
            ciphertext: buf,
        })
    }
}

/// Shared open path. `reverse = true` uses the reverse direction tag (a client
/// opening an exit reply); `reverse = false` the forward info (an exit opening a
/// client frame). Decrypts into an owned buffer.
fn open_with_ss(
    ss: &XWingSharedSecret,
    exit_id: &ExitId,
    frame: &WarrenMultihopFrameV2,
    reverse: bool,
) -> Result<Vec<u8>, MultihopError> {
    let info = if reverse {
        pq_export_info_reverse(frame.epoch, frame.seq).to_vec()
    } else {
        pq_export_info(frame.epoch, frame.seq).to_vec()
    };
    let mut key = [0u8; PER_PACKET_KEY_LEN];
    derive_per_packet_key(ss, &info, &mut key);
    let aad = pq_compose_aad(exit_id, frame.epoch, frame.seq);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&NONCE_ZERO_12);
    let tag = Tag::from_slice(&frame.aead_tag);
    let mut buf = frame.ciphertext.clone();
    let opened = cipher.decrypt_in_place_detached(nonce, &aad, &mut buf, tag);
    zero_key_array(&mut key);
    opened.map_err(|_| MultihopError::PqAead)?;
    Ok(buf)
}

/// Draw fresh X-Wing encapsulation randomness (ML-KEM message + X25519
/// ephemeral) from the session RNG and encapsulate. The two 32-byte seeds are
/// zeroized after the call.
fn encaps_from_rng<R: CryptoRng + RngCore>(
    recipient: &XWingRecipientPublicKey,
    rng: &mut R,
) -> Result<(XWingCiphertext, XWingSharedSecret), MultihopError> {
    let mut m_seed = [0u8; 32];
    let mut eph_x_seed = [0u8; 32];
    rng.fill_bytes(&mut m_seed);
    rng.fill_bytes(&mut eph_x_seed);
    let out = xwing_encapsulate(recipient, &m_seed, &eph_x_seed);
    m_seed.zeroize();
    eph_x_seed.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    fn pair() -> (PqClientSession, PqExitSession) {
        let (sk, pk) =
            XWingRecipientSecretKey::derive_deterministic(&[7u8; 32], &[9u8; 32], &[11u8; 32]);
        let exit_id = ExitId::from_bytes([0x3c; 16]);
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let client = PqClientSession::new(&pk, exit_id, &mut rng).expect("client");
        let exit = PqExitSession::new(&sk, &client.encapsulated_key(), client.pq_ct(), exit_id)
            .expect("exit");
        (client, exit)
    }

    #[test]
    fn forward_setup_round_trips() {
        let (client, exit) = pair();
        let frame = client.seal_setup(b"hello pq world", 0, 0).expect("seal");
        assert_eq!(frame.pq_ct.len(), 1088, "setup frame carries the ML-KEM ct");
        let opened = exit.open(&frame).expect("open");
        assert_eq!(opened, b"hello pq world");
    }

    #[test]
    fn steady_state_data_frame_omits_pq_ct_and_still_opens() {
        let (client, exit) = pair();
        // Establish the session with the setup frame, then a data frame with no
        // ML-KEM ciphertext re-sent.
        let _ = client.seal_setup(b"setup", 0, 0).expect("seal");
        let data = client.seal(b"steady payload", 0, 1).expect("seal data");
        assert!(data.pq_ct.is_empty(), "data frame must not re-carry ct_M");
        assert_eq!(exit.open(&data).expect("open"), b"steady payload");
    }

    #[test]
    fn reverse_round_trips_and_forward_key_is_distinct() {
        let (client, exit) = pair();
        let reply = exit.seal_response(b"exit reply", 0, 0).expect("seal reply");
        assert_eq!(client.open_response(&reply).expect("open"), b"exit reply");
        // A reverse frame fed into the forward opener must fail (direction tag).
        assert!(matches!(exit.open(&reply), Err(MultihopError::PqAead)));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (client, exit) = pair();
        let mut frame = client.seal_setup(b"authentic", 0, 0).expect("seal");
        frame.ciphertext[0] ^= 0x01;
        assert!(matches!(exit.open(&frame), Err(MultihopError::PqAead)));
    }

    #[test]
    fn wrong_exit_id_is_rejected() {
        let (client, exit) = pair();
        let mut frame = client.seal_setup(b"payload", 0, 0).expect("seal");
        frame.exit_id = ExitId::from_bytes([0xff; 16]);
        assert!(matches!(
            exit.open(&frame),
            Err(MultihopError::ExitIdMismatch)
        ));
    }

    #[test]
    fn rekey_bumps_epoch_and_overlap_opens_old_reverse() {
        let (sk, pk) =
            XWingRecipientSecretKey::derive_deterministic(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let exit_id = ExitId::from_bytes([0x5a; 16]);
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let mut client = PqClientSession::new(&pk, exit_id, &mut rng).expect("client");

        // Exit session for the OLD epoch (epoch 0).
        let exit0 = PqExitSession::new(&sk, &client.encapsulated_key(), client.pq_ct(), exit_id)
            .expect("exit0");
        let old_reply = exit0.seal_response(b"old epoch reply", 0, 5).expect("seal");

        // Rekey to epoch 1.
        let (_ek1, _ct1) = client.rekey(&pk, &mut rng).expect("rekey");
        assert_eq!(client.epoch(), 1);
        assert!(client.has_pending_old_epoch());
        assert_eq!(client.pending_old_epoch_value(), Some(0));

        // The overlap window still decodes the old-epoch reverse frame.
        assert_eq!(
            client.open_response(&old_reply).expect("overlap open"),
            b"old epoch reply"
        );

        // After pruning, the old-epoch frame no longer decodes.
        client.prune_pending_old_epoch();
        assert!(matches!(
            client.open_response(&old_reply),
            Err(MultihopError::PqAead)
        ));
    }

    #[test]
    fn seal_pending_old_epoch_before_any_rekey_errors() {
        let (client, _exit) = pair();
        assert!(matches!(
            client.seal_pending_old_epoch(b"data", 0),
            Err(MultihopError::RekeyFailed(_))
        ));
    }

    #[test]
    fn seal_pending_old_epoch_opens_at_the_still_established_old_exit_session() {
        let (sk, pk) =
            XWingRecipientSecretKey::derive_deterministic(&[4u8; 32], &[5u8; 32], &[6u8; 32]);
        let exit_id = ExitId::from_bytes([0x5b; 16]);
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let mut client = PqClientSession::new(&pk, exit_id, &mut rng).expect("client");

        // The exit-side session for the OLD (epoch 0) session, exactly as a
        // real exit would have cached it from the initial setup frame.
        let old_exit = PqExitSession::new(&sk, &client.encapsulated_key(), client.pq_ct(), exit_id)
            .expect("old exit session");

        client.rekey(&pk, &mut rng).expect("rekey");
        assert_eq!(client.epoch(), 1);

        // A DATA frame sealed under the pending old epoch must carry no
        // pq_ct (never oversized) and must still open at the OLD exit
        // session: the new epoch has not been bootstrapped at the exit yet,
        // but the old one is still live for the doctrine overlap window.
        let frame = client
            .seal_pending_old_epoch(b"full-size uplink", 7)
            .expect("seal under pending old epoch");
        assert_eq!(frame.epoch, 0, "must stamp the OLD epoch, not the new one");
        assert!(
            frame.pq_ct.is_empty(),
            "a DATA frame must never carry pq_ct, old epoch or new"
        );
        assert_eq!(
            old_exit.open(&frame).expect("old exit session opens it"),
            b"full-size uplink"
        );
    }
}
