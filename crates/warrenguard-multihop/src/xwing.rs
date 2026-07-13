//! X-Wing hybrid KEM: X25519 + ML-KEM-768 (draft-connolly-cfrg-xwing-kem).
//!
//! This is the security-critical combiner for the `/v2` post-quantum multihop
//! seal. It is deliberately the exact X-Wing construction, NOT a naive XOR of
//! the two component shared secrets: the hybrid secret is
//!
//! ```text
//! ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
//! ```
//!
//! where `ss_M` is the ML-KEM-768 shared secret, `ss_X` the X25519 raw DH
//! output, `ct_X` the X25519 ephemeral public (the "X25519 ciphertext"), `pk_X`
//! the recipient's static X25519 public, and `XWingLabel` the 6-byte tag
//! `\.//^\`. The label comes LAST. The X-Wing ciphertext is `ct_M || ct_X`
//! (ML-KEM ciphertext then X25519 ephemeral public).
//!
//! # Deployment note (independent component keys)
//!
//! X-Wing's native key generation derives both component keys from one 32-byte
//! seed via `expandDecapsulationKey`. Warren instead uses INDEPENDENTLY
//! generated component keys: the exit's existing long-lived
//! `exit_x25519_multihop_pubkey` (already signed in the descriptor) as `pk_X`,
//! and a separately generated ML-KEM-768 key as `ek_M`. Only the SECURITY-
//! critical combiner and the KEM operations are shared with X-Wing; the
//! single-seed keygen is a storage convenience the protocol does not need. The
//! X-Wing security argument reduces to the combiner given secure ML-KEM and
//! X25519, and holds for independently generated component keys. The
//! `tests/xwing_kat.rs` KAT still replays the official single-seed vectors
//! end-to-end to prove the combiner + ML-KEM + X25519 integration is exact.

use kem::Decapsulate;
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::{
    B32, Ciphertext, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768,
    MlKem768Params,
};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::MultihopError;

/// The 6-byte X-Wing domain-separation label, `\.//^\`, hashed LAST in the
/// combiner (draft-connolly-cfrg-xwing-kem). Frozen.
pub const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// ML-KEM-768 encapsulation-key (recipient public key) length in bytes.
pub const XWING_MLKEM_EK_LEN: usize = 1184;

/// ML-KEM-768 ciphertext length in bytes.
pub const XWING_MLKEM_CT_LEN: usize = 1088;

/// X25519 public-key / ciphertext / shared-secret length in bytes.
pub const XWING_X25519_LEN: usize = 32;

/// Full X-Wing ciphertext length: `ct_M (1088) || ct_X (32)`.
pub const XWING_CT_LEN: usize = XWING_MLKEM_CT_LEN + XWING_X25519_LEN;

/// Domain-separation prefix for expanding an exit's ML-KEM-768 keygen
/// randomness `(d, z)` from its identity-derived input keying material. Frozen:
/// an exit derives the SAME published ML-KEM key on every boot from its
/// long-lived identity, so changing this string rotates every exit's key (old
/// signed descriptors and in-flight PQ sessions would break).
const MLKEM_IKM_DOMAIN: &[u8] = b"warren-xwing-mlkem768-ikm-v1";

/// The 32-byte hybrid shared secret produced by the X-Wing combiner. Zeroized
/// on drop; no `Debug` so it never renders in a log or panic message.
///
/// `PartialEq`/`Eq` are only derived for `#[cfg(test)]` builds: a
/// non-constant-time array comparison on secret key material has no place in
/// the public API (production code compares via [`Self::as_bytes`] into a
/// constant-time AEAD/KDF primitive instead), but tests still want a plain
/// `assert_eq!` between two derived secrets.
#[derive(Clone, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct XWingSharedSecret([u8; 32]);

impl XWingSharedSecret {
    /// Borrow the raw 32 bytes. Callers feed this into the `/v2` HKDF key
    /// schedule; it must never be logged.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The X-Wing hybrid combiner: `SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)`.
///
/// This is the ONLY correct way to combine the two component secrets. A XOR or
/// a plain concatenation-without-the-transcript would silently drop the binding
/// to `ct_X` / `pk_X` and break the hybrid IND-CCA argument. The label is
/// hashed last, matching draft-connolly-cfrg-xwing-kem and the deployed
/// RustCrypto `x-wing` crate.
#[must_use]
pub fn xwing_combiner(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> XWingSharedSecret {
    let mut hasher = Sha3_256::new();
    hasher.update(ss_m);
    hasher.update(ss_x);
    hasher.update(ct_x);
    hasher.update(pk_x);
    hasher.update(XWING_LABEL);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    XWingSharedSecret(out)
}

/// The X-Wing hybrid ciphertext: the ML-KEM-768 ciphertext (`ct_M`, 1088 B)
/// followed by the X25519 ephemeral public (`ct_X`, 32 B). On the Warren wire
/// the two halves travel in separate `/v2` frame fields (`ct_M` in `pq_ct`,
/// `ct_X` in the classical `encapsulated_key`), so this type exposes both.
#[derive(Clone, PartialEq, Eq)]
pub struct XWingCiphertext {
    ct_m: Vec<u8>,
    ct_x: [u8; 32],
}

impl XWingCiphertext {
    /// The ML-KEM-768 ciphertext half (`ct_M`, 1088 bytes).
    #[must_use]
    pub fn mlkem_ct(&self) -> &[u8] {
        &self.ct_m
    }

    /// The X25519 ephemeral public half (`ct_X`, 32 bytes). Carried in the
    /// classical `encapsulated_key` frame field so the wire shape of that
    /// field is identical to a `/v1` frame.
    #[must_use]
    pub fn x25519_ct(&self) -> &[u8; 32] {
        &self.ct_x
    }

    /// Reassemble a ciphertext from its two wire halves, validating lengths.
    ///
    /// # Errors
    ///
    /// [`MultihopError::PqKeyLength`] if `ct_m` is not [`XWING_MLKEM_CT_LEN`].
    pub fn from_wire_parts(ct_m: &[u8], ct_x: [u8; 32]) -> Result<Self, MultihopError> {
        if ct_m.len() != XWING_MLKEM_CT_LEN {
            return Err(MultihopError::PqKeyLength {
                field: "mlkem768_ct",
                got: ct_m.len(),
                expected: XWING_MLKEM_CT_LEN,
            });
        }
        Ok(Self {
            ct_m: ct_m.to_vec(),
            ct_x,
        })
    }
}

/// The recipient (exit) X-Wing public key: an ML-KEM-768 encapsulation key plus
/// the static X25519 public key. Built by the client from the exit's SIGNED
/// descriptor before sealing.
#[derive(Clone)]
pub struct XWingRecipientPublicKey {
    ek_m: EncapsulationKey<MlKem768Params>,
    pk_x: [u8; 32],
}

impl XWingRecipientPublicKey {
    /// Parse a recipient public key from the exit's descriptor material: the
    /// raw ML-KEM-768 encapsulation key (1184 bytes) and the static X25519
    /// public (32 bytes).
    ///
    /// # Errors
    ///
    /// [`MultihopError::PqKeyLength`] if the ML-KEM key is not
    /// [`XWING_MLKEM_EK_LEN`] bytes.
    pub fn from_descriptor_bytes(
        mlkem768_ek: &[u8],
        x25519_pubkey: &[u8; 32],
    ) -> Result<Self, MultihopError> {
        let enc =
            Encoded::<EncapsulationKey<MlKem768Params>>::try_from(mlkem768_ek).map_err(|_| {
                MultihopError::PqKeyLength {
                    field: "mlkem768_ek",
                    got: mlkem768_ek.len(),
                    expected: XWING_MLKEM_EK_LEN,
                }
            })?;
        Ok(Self {
            ek_m: EncapsulationKey::<MlKem768Params>::from_bytes(&enc),
            pk_x: *x25519_pubkey,
        })
    }

    /// The static X25519 recipient public (`pk_X`), bound into the combiner.
    #[must_use]
    pub fn x25519_pubkey(&self) -> &[u8; 32] {
        &self.pk_x
    }

    /// The ML-KEM-768 encapsulation key bytes (1184) to publish in the
    /// descriptor `exit_mlkem768_pubkey` field.
    #[must_use]
    pub fn mlkem768_ek_bytes(&self) -> Vec<u8> {
        self.ek_m.as_bytes().to_vec()
    }

    /// The X-Wing public key encoding `ek_M || pk_X` (1216 bytes). Test/vector
    /// use only (the wire carries the two halves in separate fields).
    #[doc(hidden)]
    #[must_use]
    pub fn to_xwing_public_bytes(&self) -> Vec<u8> {
        let mut out = self.ek_m.as_bytes().to_vec();
        out.extend_from_slice(&self.pk_x);
        out
    }
}

/// The recipient (exit) X-Wing secret key: an ML-KEM-768 decapsulation key plus
/// the static X25519 secret. Both halves are zeroized on drop.
pub struct XWingRecipientSecretKey {
    dk_m: DecapsulationKey<MlKem768Params>,
    sk_x: [u8; 32],
    pk_x: [u8; 32],
}

impl Drop for XWingRecipientSecretKey {
    fn drop(&mut self) {
        // `dk_m` is `ZeroizeOnDrop` in ml-kem; scrub the X25519 scalar here.
        self.sk_x.zeroize();
    }
}

impl XWingRecipientSecretKey {
    /// Assemble a recipient secret key from an ML-KEM-768 decapsulation key and
    /// a raw X25519 secret scalar. The X25519 public is recomputed from the
    /// scalar so the combiner always binds a `pk_X` consistent with `sk_X`.
    #[must_use]
    pub fn from_parts(dk_m: DecapsulationKey<MlKem768Params>, sk_x: [u8; 32]) -> Self {
        let pk_x = x25519(sk_x, X25519_BASEPOINT_BYTES);
        Self { dk_m, sk_x, pk_x }
    }

    /// Deterministically derive a recipient keypair from test seeds. ML-KEM
    /// keygen uses `(d, z)`; the X25519 scalar is `sk_x_seed`. Test/vector use
    /// only.
    #[doc(hidden)]
    #[must_use]
    pub fn derive_deterministic(
        d: &[u8; 32],
        z: &[u8; 32],
        sk_x_seed: &[u8; 32],
    ) -> (Self, XWingRecipientPublicKey) {
        let (dk_m, ek_m) = MlKem768::generate_deterministic(&B32::from(*d), &B32::from(*z));
        let sk = Self::from_parts(dk_m, *sk_x_seed);
        let pk = XWingRecipientPublicKey {
            ek_m,
            pk_x: sk.pk_x,
        };
        (sk, pk)
    }

    /// Deterministically derive a recipient keypair from an ML-KEM input keying
    /// material and the exit's EXISTING X25519 secret scalar. The ML-KEM keygen
    /// randomness `(d, z)` is SHAKE256-expanded from `mlkem_ikm` under a fixed
    /// domain prefix, so an exit reconstructs the SAME ML-KEM key on every boot
    /// from its long-lived identity with no separately persisted secret; `sk_x`
    /// is the exit's already-derived X25519 multihop scalar (recomputed into
    /// `pk_X` and bound in the combiner). Returns the secret key (holds the
    /// decapsulation key for the datapath) and the public key (whose
    /// [`XWingRecipientPublicKey::mlkem768_ek_bytes`] is signed and published in
    /// the descriptor).
    #[must_use]
    pub fn from_ikm(mlkem_ikm: &[u8], sk_x: &[u8; 32]) -> (Self, XWingRecipientPublicKey) {
        let mut expanded = [0u8; 64];
        let mut xof = Shake256::default();
        sha3::digest::Update::update(&mut xof, MLKEM_IKM_DOMAIN);
        sha3::digest::Update::update(&mut xof, mlkem_ikm);
        xof.finalize_xof().read(&mut expanded);
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&expanded[0..32]);
        z.copy_from_slice(&expanded[32..64]);
        expanded.zeroize();
        let out = Self::derive_deterministic(&d, &z, sk_x);
        d.zeroize();
        z.zeroize();
        out
    }

    /// The ML-KEM-768 encapsulation key bytes to publish in the descriptor.
    #[doc(hidden)]
    #[must_use]
    pub fn mlkem768_ek_bytes(&self) -> Vec<u8> {
        self.dk_m.encapsulation_key().as_bytes().to_vec()
    }

    /// The static X25519 public key bytes to publish in the descriptor.
    #[doc(hidden)]
    #[must_use]
    pub fn x25519_pubkey(&self) -> [u8; 32] {
        self.pk_x
    }

    /// Derive a recipient keypair from an X-Wing native 32-byte seed via
    /// `expandDecapsulationKey` (draft-connolly-cfrg-xwing-kem): SHAKE256(seed,
    /// 96) splits into the ML-KEM `(d, z)` and the X25519 scalar. Used ONLY by
    /// the KAT to replay the official single-seed vectors through the exact same
    /// combiner and KEM code the protocol uses; Warren itself uses independent
    /// component keys ([`Self::from_parts`]).
    #[doc(hidden)]
    #[must_use]
    pub fn derive_from_xwing_seed(seed: &[u8; 32]) -> (Self, XWingRecipientPublicKey) {
        let mut expanded = [0u8; 96];
        let mut xof = Shake256::default();
        sha3::digest::Update::update(&mut xof, seed);
        xof.finalize_xof().read(&mut expanded);
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        let mut sk_x = [0u8; 32];
        d.copy_from_slice(&expanded[0..32]);
        z.copy_from_slice(&expanded[32..64]);
        sk_x.copy_from_slice(&expanded[64..96]);
        expanded.zeroize();
        let out = Self::derive_deterministic(&d, &z, &sk_x);
        d.zeroize();
        z.zeroize();
        sk_x.zeroize();
        out
    }
}

/// Intermediate + final values of an end-to-end X-Wing flow, produced by
/// [`xwing_reference_flow`] for the KAT.
#[doc(hidden)]
pub struct XWingReferenceOutput {
    /// X-Wing public key `ek_M || pk_X` (1216 bytes).
    pub public_key: Vec<u8>,
    /// X-Wing ciphertext `ct_M || ct_X` (1120 bytes).
    pub ciphertext: Vec<u8>,
    /// Shared secret computed by encapsulation.
    pub shared_secret_encaps: [u8; 32],
    /// Shared secret recovered by decapsulation (must equal the encaps one).
    pub shared_secret_decaps: [u8; 32],
}

/// Run the full X-Wing native flow (single-seed keygen -> derandomized encaps ->
/// decaps) through Warren's PRODUCTION combiner and KEM code, so a KAT can
/// assert against the official draft vectors. `seed` is the 32-byte X-Wing
/// secret seed; `eseed` is the 64-byte encapsulation randomness (`eseed[0..32]`
/// is the ML-KEM message, `eseed[32..64]` the X25519 ephemeral scalar).
///
/// # Errors
///
/// Propagates any [`MultihopError`] from encaps/decaps (not reachable for
/// well-formed vectors).
#[doc(hidden)]
pub fn xwing_reference_flow(
    seed: &[u8; 32],
    eseed: &[u8; 64],
) -> Result<XWingReferenceOutput, MultihopError> {
    let (sk, pk) = XWingRecipientSecretKey::derive_from_xwing_seed(seed);
    let mut m_seed = [0u8; 32];
    let mut eph_x_seed = [0u8; 32];
    m_seed.copy_from_slice(&eseed[0..32]);
    eph_x_seed.copy_from_slice(&eseed[32..64]);

    let (ct, ss_enc) = xwing_encapsulate(&pk, &m_seed, &eph_x_seed)?;
    m_seed.zeroize();
    eph_x_seed.zeroize();

    let mut ciphertext = ct.mlkem_ct().to_vec();
    ciphertext.extend_from_slice(ct.x25519_ct());

    let ss_dec = xwing_decapsulate(&sk, &ct)?;
    Ok(XWingReferenceOutput {
        public_key: pk.to_xwing_public_bytes(),
        ciphertext,
        shared_secret_encaps: *ss_enc.as_bytes(),
        shared_secret_decaps: *ss_dec.as_bytes(),
    })
}

/// X-Wing encapsulation against a recipient public key.
///
/// `m_seed` is the 32-byte ML-KEM message randomness; `eph_x_seed` is the
/// 32-byte X25519 ephemeral scalar. Both MUST be freshly drawn from a CSPRNG by
/// the caller (the session layer draws them). Returns the hybrid ciphertext and
/// the sender's copy of the shared secret.
///
/// # Errors
///
/// [`MultihopError::PqAead`] if the underlying ML-KEM encapsulation fails
/// (an internal encoding error; not reachable with valid inputs).
pub(crate) fn xwing_encapsulate(
    recipient: &XWingRecipientPublicKey,
    m_seed: &[u8; 32],
    eph_x_seed: &[u8; 32],
) -> Result<(XWingCiphertext, XWingSharedSecret), MultihopError> {
    let (ct_m, ss_m) = recipient
        .ek_m
        .encapsulate_deterministic(&B32::from(*m_seed))
        .map_err(|_| MultihopError::PqAead)?;

    let ct_x = x25519(*eph_x_seed, X25519_BASEPOINT_BYTES);
    let mut ss_x = x25519(*eph_x_seed, recipient.pk_x);

    let mut ss_m_arr = to_array32(ss_m.as_slice());
    let ss = xwing_combiner(&ss_m_arr, &ss_x, &ct_x, &recipient.pk_x);
    ss_m_arr.zeroize();
    ss_x.zeroize();

    let ct = XWingCiphertext {
        ct_m: ct_m.as_slice().to_vec(),
        ct_x,
    };
    Ok((ct, ss))
}

/// X-Wing decapsulation with a recipient secret key. Recovers the same hybrid
/// shared secret the sender derived.
///
/// # Errors
///
/// [`MultihopError::PqKeyLength`] if the ML-KEM ciphertext half is malformed;
/// [`MultihopError::PqAead`] if ML-KEM decapsulation fails.
pub(crate) fn xwing_decapsulate(
    secret: &XWingRecipientSecretKey,
    ct: &XWingCiphertext,
) -> Result<XWingSharedSecret, MultihopError> {
    let ct_m = Ciphertext::<MlKem768>::try_from(ct.ct_m.as_slice()).map_err(|_| {
        MultihopError::PqKeyLength {
            field: "mlkem768_ct",
            got: ct.ct_m.len(),
            expected: XWING_MLKEM_CT_LEN,
        }
    })?;
    let ss_m = secret
        .dk_m
        .decapsulate(&ct_m)
        .map_err(|_| MultihopError::PqAead)?;

    let mut ss_x = x25519(secret.sk_x, ct.ct_x);
    let mut ss_m_arr = to_array32(ss_m.as_slice());
    let ss = xwing_combiner(&ss_m_arr, &ss_x, &ct.ct_x, &secret.pk_x);
    ss_m_arr.zeroize();
    ss_x.zeroize();
    Ok(ss)
}

/// Assemble the exit's X-Wing recipient keypair from its EXISTING HPKE X25519
/// private key (whose public is the signed descriptor `exit_x25519_multihop_pubkey`)
/// and an ML-KEM input keying material.
///
/// The X25519 half is REUSED, not regenerated, so the combiner's `pk_X` equals
/// the published descriptor key; only the ML-KEM half is derived (from
/// `mlkem_ikm`, via [`XWingRecipientSecretKey::from_ikm`]). This lets an exit
/// reconstruct the same recipient keypair on every boot from its long-lived
/// identity with no separately persisted secret. Returns the secret (holds the
/// decapsulation key for the datapath) and the public (whose
/// [`XWingRecipientPublicKey::mlkem768_ek_bytes`] is signed and published).
#[must_use]
pub fn derive_exit_xwing_recipient(
    x25519_privkey: &crate::WarrenKemPrivateKey,
    mlkem_ikm: &[u8],
) -> (XWingRecipientSecretKey, XWingRecipientPublicKey) {
    use hpke::Serializable;
    let mut sk_x = [0u8; 32];
    sk_x.copy_from_slice(&x25519_privkey.to_bytes());
    let out = XWingRecipientSecretKey::from_ikm(mlkem_ikm, &sk_x);
    sk_x.zeroize();
    out
}

/// Copy a 32-byte slice into a fixed array. The ML-KEM shared key and X25519
/// output are both exactly 32 bytes by construction, so this never truncates.
fn to_array32(s: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(s);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent SHA3-256 cross-check of the combiner byte layout, computed
    /// with Python `hashlib.sha3_256` over `ss_M || ss_X || ct_X || pk_X ||
    /// label`. If the code XOR'd the secrets, reordered the transcript, or put
    /// the label first, this fails.
    #[test]
    fn combiner_matches_independent_sha3_256() {
        let ss_m = [0x01u8; 32];
        let ss_x = [0x02u8; 32];
        let ct_x = [0x03u8; 32];
        let pk_x = [0x04u8; 32];
        let got = xwing_combiner(&ss_m, &ss_x, &ct_x, &pk_x);
        let expected = hex_lit("5c6bfaf8c3ec48ab3cee7c12129b39913b8a7fa1234115da7e1c55608ad19fb6");
        assert_eq!(got.as_bytes(), &expected);
    }

    #[test]
    fn encapsulate_decapsulate_round_trip_independent_keys() {
        let (sk, pk) =
            XWingRecipientSecretKey::derive_deterministic(&[7u8; 32], &[9u8; 32], &[11u8; 32]);
        let (ct, ss_sender) = xwing_encapsulate(&pk, &[0x21; 32], &[0x22; 32]).expect("encaps");
        assert_eq!(ct.mlkem_ct().len(), XWING_MLKEM_CT_LEN);
        let ss_recv = xwing_decapsulate(&sk, &ct).expect("decaps");
        assert_eq!(
            ss_sender.as_bytes(),
            ss_recv.as_bytes(),
            "sender and recipient must derive the same hybrid secret"
        );
    }

    #[test]
    fn tampered_mlkem_ct_changes_the_secret() {
        let (sk, pk) =
            XWingRecipientSecretKey::derive_deterministic(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let (mut ct, ss_sender) = xwing_encapsulate(&pk, &[0x41; 32], &[0x42; 32]).expect("encaps");
        ct.ct_m[0] ^= 0x01;
        let ss_recv = xwing_decapsulate(&sk, &ct).expect("decaps still returns (implicit reject)");
        assert_ne!(
            ss_sender.as_bytes(),
            ss_recv.as_bytes(),
            "a flipped ML-KEM ciphertext bit must not decapsulate to the sender secret"
        );
    }

    #[test]
    fn from_ikm_is_deterministic() {
        let ikm = b"exit-identity-derived-mlkem-ikm";
        let sk_x = [0x33u8; 32];
        let (sk_a, pk_a) = XWingRecipientSecretKey::from_ikm(ikm, &sk_x);
        let (_sk_b, pk_b) = XWingRecipientSecretKey::from_ikm(ikm, &sk_x);
        assert_eq!(
            pk_a.mlkem768_ek_bytes(),
            pk_b.mlkem768_ek_bytes(),
            "same IKM must yield the same published ML-KEM key across boots"
        );
        assert_eq!(pk_a.x25519_pubkey(), pk_b.x25519_pubkey());
        assert_eq!(
            &sk_a.x25519_pubkey(),
            pk_a.x25519_pubkey(),
            "secret and public halves must agree on pk_X"
        );
        assert_eq!(pk_a.mlkem768_ek_bytes().len(), XWING_MLKEM_EK_LEN);
    }

    #[test]
    fn from_ikm_round_trips() {
        let (sk, pk) = XWingRecipientSecretKey::from_ikm(b"round-trip-ikm", &[0x55u8; 32]);
        let (ct, ss_sender) = xwing_encapsulate(&pk, &[0x61; 32], &[0x62; 32]).expect("encaps");
        let ss_recv = xwing_decapsulate(&sk, &ct).expect("decaps");
        assert_eq!(
            ss_sender.as_bytes(),
            ss_recv.as_bytes(),
            "a key derived from IKM must encapsulate/decapsulate to the same secret"
        );
    }

    #[test]
    fn from_ikm_distinct_ikm_distinct_key() {
        let sk_x = [0x77u8; 32];
        let (_a, pk_a) = XWingRecipientSecretKey::from_ikm(b"ikm-one", &sk_x);
        let (_b, pk_b) = XWingRecipientSecretKey::from_ikm(b"ikm-two", &sk_x);
        assert_ne!(
            pk_a.mlkem768_ek_bytes(),
            pk_b.mlkem768_ek_bytes(),
            "distinct IKM must derive distinct ML-KEM keys"
        );
    }

    #[test]
    fn exit_xwing_recipient_reuses_descriptor_x25519_and_round_trips() {
        // Derive the exit's HPKE X25519 keypair exactly as the descriptor does.
        let (x_priv, x_pub) = crate::test_support::derive_exit_keypair(&[0x5b; 32]);
        let x_pub_bytes = crate::test_support::pubkey_to_bytes(&x_pub);

        // Assemble the X-Wing recipient reusing that X25519 key + an ML-KEM IKM.
        let (secret, public) = derive_exit_xwing_recipient(&x_priv, b"exit-mlkem-ikm");

        // pk_X of the X-Wing recipient MUST equal the exit's PUBLISHED descriptor
        // x25519 key: a client seals against the descriptor key and the exit
        // decapsulates with this secret, so a mismatch would bind different pk_X
        // in the combiner and the two secrets would never agree.
        assert_eq!(
            secret.x25519_pubkey(),
            x_pub_bytes,
            "X-Wing pk_X must equal the exit's published descriptor x25519 pubkey"
        );
        assert_eq!(public.x25519_pubkey(), &x_pub_bytes);
        assert_eq!(public.mlkem768_ek_bytes().len(), XWING_MLKEM_EK_LEN);

        // A client sealing to the PUBLISHED (ek, x25519) bytes round-trips with
        // the exit's derived secret.
        let recipient = XWingRecipientPublicKey::from_descriptor_bytes(
            &public.mlkem768_ek_bytes(),
            &x_pub_bytes,
        )
        .expect("recipient from published bytes");
        let (ct, ss_client) =
            xwing_encapsulate(&recipient, &[0x71; 32], &[0x72; 32]).expect("encaps");
        let ss_exit = xwing_decapsulate(&secret, &ct).expect("decaps");
        assert_eq!(
            ss_client.as_bytes(),
            ss_exit.as_bytes(),
            "client (published key) and exit (derived secret) must agree on the hybrid secret"
        );
    }

    fn hex_lit(s: &str) -> [u8; 32] {
        let v = hex::decode(s).expect("hex");
        v.try_into().expect("32 bytes")
    }
}
