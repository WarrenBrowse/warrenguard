//! Route admission by anchor: the frozen `v1` seals and derived identifiers.
//!
//! A route session is admitted against the device's live main session instead
//! of a token of its own. The client holds a 32-byte **anchor secret** in
//! memory for its logical main session and never sends it in clear: it seals
//! it to the control plane's route KEM key, once bound to the token serial the
//! main session was admitted on (the anchor registration, carried by the main
//! exit) and once per route dial bound to the route exit's id (the route
//! locator, carried by the route exit). Only the control plane opens either
//! blob, so no exit ever learns the secret and two blobs of one anchor share
//! no byte an exit could match.
//!
//! Suite: HPKE RFC 9180 base mode, single shot, DHKEM(X25519, HKDF-SHA256),
//! HKDF-SHA256, ChaCha20Poly1305 (the suite of the multihop seal). Every byte
//! here is pinned by `vectors/route_admission_v1.json`; a change is a new
//! `v2`, never an edit.
//!
//! No-log: every type that carries the secret, a blob or an identifier derived
//! from them has a `Debug` that prints none of it.

use hkdf::Hkdf;
use hpke::kem::Kem as KemTrait;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::session::{ExitId, WarrenAead, WarrenKdf, WarrenKem};

/// Length of the anchor secret, in bytes.
pub const ROUTE_ANCHOR_SECRET_LEN: usize = 32;

/// Length of the token serial an anchor registration is bound to (SHA-256 of
/// the token input).
pub const ROUTE_TOKEN_SERIAL_LEN: usize = 32;

/// Length of a [`SealedToApi`] on the wire: key id, `enc`, ciphertext and tag.
pub const SEALED_TO_API_LEN: usize = 1 + SEALED_TO_API_ENC_LEN + SEALED_TO_API_CT_LEN;

/// Length of the HPKE encapsulated key inside a [`SealedToApi`].
pub const SEALED_TO_API_ENC_LEN: usize = 32;

/// Length of the ciphertext inside a [`SealedToApi`]: the 32-byte secret plus
/// the 16-byte AEAD tag.
pub const SEALED_TO_API_CT_LEN: usize = ROUTE_ANCHOR_SECRET_LEN + 16;

/// HKDF info prefix of the route KEM key derivation; the key id byte follows.
pub const ROUTE_KEM_INFO: &[u8] = b"warren/route-kem/v1";

/// HPKE info, and associated-data prefix, of the anchor registration seal.
pub const ROUTE_ANCHOR_INFO: &[u8] = b"warren/route-anchor/v1";

/// HPKE info, and associated-data prefix, of the route locator seal.
pub const ROUTE_LOCATOR_INFO: &[u8] = b"warren/route-locator/v1";

const ANCHOR_REF_DOMAIN: &[u8] = b"warren/route-anchor-ref/v1";
const ROUTE_SERIAL_DOMAIN: &[u8] = b"warren/route-serial/v1";

type RouteKemPk = <WarrenKem as KemTrait>::PublicKey;
type RouteKemSk = <WarrenKem as KemTrait>::PrivateKey;
type RouteKemEnc = <WarrenKem as KemTrait>::EncappedKey;

/// Why a route seal could not be built or opened. Carries no key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteSealError {
    /// Key id `0` is reserved; published key ids start at `1`.
    #[error("route KEM key id 0 is reserved")]
    ReservedKeyId,
    /// The published route KEM public key is not a usable X25519 point.
    #[error("route KEM public key is not a usable X25519 point")]
    InvalidPublicKey,
    /// The blob names a key id this opener does not hold.
    #[error("sealed blob names a key id this opener does not hold")]
    UnknownKeyId,
    /// The blob does not open under this key with this associated data.
    #[error("sealed blob does not open")]
    Open,
    /// HPKE refused to seal (unusable recipient key).
    #[error("route seal failed")]
    Seal,
}

/// A 32-byte anchor secret sealed to the control plane: `key_id`, the HPKE
/// `enc` and the ciphertext with its tag, 81 bytes serialized as a fixed tuple
/// with no length prefix. Carries no secret in clear, but each blob is unique
/// to one seal, so its `Debug` names the key id only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SealedToApi {
    key_id: u8,
    enc: [u8; SEALED_TO_API_ENC_LEN],
    ct: [u8; SEALED_TO_API_CT_LEN],
}

impl SealedToApi {
    /// Parse the 81 wire bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SEALED_TO_API_LEN]) -> Self {
        let mut enc = [0u8; SEALED_TO_API_ENC_LEN];
        let mut ct = [0u8; SEALED_TO_API_CT_LEN];
        enc.copy_from_slice(&bytes[1..=SEALED_TO_API_ENC_LEN]);
        ct.copy_from_slice(&bytes[1 + SEALED_TO_API_ENC_LEN..]);
        Self {
            key_id: bytes[0],
            enc,
            ct,
        }
    }

    /// Parse from a slice that must be exactly [`SEALED_TO_API_LEN`] bytes.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let fixed: &[u8; SEALED_TO_API_LEN] = bytes.try_into().ok()?;
        Some(Self::from_bytes(fixed))
    }

    /// The 81 wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SEALED_TO_API_LEN] {
        let mut out = [0u8; SEALED_TO_API_LEN];
        out[0] = self.key_id;
        out[1..=SEALED_TO_API_ENC_LEN].copy_from_slice(&self.enc);
        out[1 + SEALED_TO_API_ENC_LEN..].copy_from_slice(&self.ct);
        out
    }

    /// The route KEM key id the blob was sealed to.
    #[must_use]
    pub fn key_id(&self) -> u8 {
        self.key_id
    }
}

impl core::fmt::Debug for SealedToApi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedToApi")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl Serialize for SealedToApi {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(SEALED_TO_API_LEN)?;
        for byte in &self.to_bytes() {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for SealedToApi {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BlobVisitor;
        impl<'de> serde::de::Visitor<'de> for BlobVisitor {
            type Value = SealedToApi;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("81 raw sealed-to-api bytes")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; SEALED_TO_API_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(SealedToApi::from_bytes(&out))
            }
        }
        deserializer.deserialize_tuple(SEALED_TO_API_LEN, BlobVisitor)
    }
}

/// The client's anchor secret `s`: 32 random bytes held for one logical main
/// session, zeroized on drop. There is deliberately no accessor for the bytes:
/// the secret leaves this type only sealed, or as its one-way
/// [`RouteAnchorRef`].
pub struct RouteAnchorSecret(Zeroizing<[u8; ROUTE_ANCHOR_SECRET_LEN]>);

impl RouteAnchorSecret {
    /// Draw a fresh secret from the operating system's CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; ROUTE_ANCHOR_SECRET_LEN]);
        rand_core::UnwrapErr(rand_core::OsRng).fill_bytes(&mut bytes[..]);
        Self(bytes)
    }

    /// Wrap known bytes: an opened blob on the control plane, or a vector.
    #[must_use]
    pub fn from_bytes(bytes: [u8; ROUTE_ANCHOR_SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// `a = SHA-256("warren/route-anchor-ref/v1" || s)`, the control plane's
    /// key for the anchor.
    #[must_use]
    pub fn anchor_ref(&self) -> RouteAnchorRef {
        let mut h = Sha256::new();
        h.update(ANCHOR_REF_DOMAIN);
        h.update(&self.0[..]);
        RouteAnchorRef(h.finalize().into())
    }
}

impl core::fmt::Debug for RouteAnchorSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RouteAnchorSecret(<redacted>)")
    }
}

/// `a`, the one-way reference of an anchor secret. An identifier that joins a
/// device's routes on the control plane, so it never reaches a log.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteAnchorRef([u8; 32]);

impl RouteAnchorRef {
    /// Wrap known bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `r = SHA-256("warren/route-serial/v1" || a || exit_id)`: the stable
    /// identifier of this anchor's route at `exit_id`.
    #[must_use]
    pub fn route_serial(&self, exit_id: &ExitId) -> RouteSerial {
        let mut h = Sha256::new();
        h.update(ROUTE_SERIAL_DOMAIN);
        h.update(self.0);
        h.update(exit_id.as_bytes());
        RouteSerial(h.finalize().into())
    }
}

impl core::fmt::Debug for RouteAnchorRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RouteAnchorRef(<redacted>)")
    }
}

/// `r`, the per (anchor, exit) route serial the control plane hands the route
/// exit. The route exit keys its session on it, so it never reaches a log.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteSerial([u8; 32]);

impl RouteSerial {
    /// Wrap known bytes (the control plane's answer to a route open).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for RouteSerial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RouteSerial(<redacted>)")
    }
}

/// The control plane's published route KEM public key, with its key id.
#[derive(Clone, PartialEq, Eq)]
pub struct RouteKemPublicKey {
    key_id: u8,
    pk: RouteKemPk,
}

impl RouteKemPublicKey {
    /// Validate a published key: a non-reserved key id and an X25519 point a
    /// seal can actually use (a small-order point yields no shared secret).
    ///
    /// # Errors
    ///
    /// [`RouteSealError::ReservedKeyId`] for key id `0`,
    /// [`RouteSealError::InvalidPublicKey`] for an unusable point.
    pub fn new(key_id: u8, bytes: [u8; 32]) -> Result<Self, RouteSealError> {
        if key_id == 0 {
            return Err(RouteSealError::ReservedKeyId);
        }
        let pk = RouteKemPk::from_bytes(&bytes).map_err(|_| RouteSealError::InvalidPublicKey)?;
        let key = Self { key_id, pk };
        // One trial encapsulation: the only portable check that the point is
        // not of small order, done once per published key.
        seal_with(
            &key,
            ROUTE_LOCATOR_INFO,
            ROUTE_LOCATOR_INFO,
            &RouteAnchorSecret::from_bytes([0u8; ROUTE_ANCHOR_SECRET_LEN]),
            &mut rand_core::UnwrapErr(rand_core::OsRng),
        )
        .map_err(|_| RouteSealError::InvalidPublicKey)?;
        Ok(key)
    }

    /// The key id blobs sealed to this key carry.
    #[must_use]
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// The 32 X25519 public-key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.pk.to_bytes().into()
    }
}

impl core::fmt::Debug for RouteKemPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RouteKemPublicKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// The control plane's route KEM secret key, derived in process from its
/// signing key and never stored.
pub struct RouteKemSecretKey {
    key_id: u8,
    sk: RouteKemSk,
    public: RouteKemPublicKey,
}

impl RouteKemSecretKey {
    /// `DeriveKeyPair(HKDF-SHA256(salt = "", ikm = signing_secret,
    /// info = "warren/route-kem/v1" || key_id, 32))`.
    ///
    /// # Errors
    ///
    /// [`RouteSealError::ReservedKeyId`] for key id `0`.
    pub fn derive(signing_secret: &[u8; 32], key_id: u8) -> Result<Self, RouteSealError> {
        if key_id == 0 {
            return Err(RouteSealError::ReservedKeyId);
        }
        let mut info = Vec::with_capacity(ROUTE_KEM_INFO.len() + 1);
        info.extend_from_slice(ROUTE_KEM_INFO);
        info.push(key_id);
        let mut ikm = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(&[]), signing_secret)
            .expand(&info, &mut ikm[..])
            .map_err(|_| RouteSealError::Seal)?;
        let (sk, pk) = WarrenKem::derive_keypair(&ikm[..]);
        Ok(Self {
            key_id,
            sk,
            public: RouteKemPublicKey { key_id, pk },
        })
    }

    /// The public half to publish.
    #[must_use]
    pub fn public_key(&self) -> &RouteKemPublicKey {
        &self.public
    }

    /// Open an anchor registration sealed for the main session admitted on
    /// `serial`.
    ///
    /// # Errors
    ///
    /// [`RouteSealError::UnknownKeyId`] or [`RouteSealError::Open`].
    pub fn open_anchor(
        &self,
        blob: &SealedToApi,
        serial: &[u8; ROUTE_TOKEN_SERIAL_LEN],
    ) -> Result<RouteAnchorSecret, RouteSealError> {
        self.open(blob, ROUTE_ANCHOR_INFO, serial)
    }

    /// Open a route locator presented by the exit whose id is `exit_id`. The
    /// caller takes `exit_id` from the presenting exit's authenticated
    /// identity, never from the request.
    ///
    /// # Errors
    ///
    /// [`RouteSealError::UnknownKeyId`] or [`RouteSealError::Open`].
    pub fn open_locator(
        &self,
        blob: &SealedToApi,
        exit_id: &ExitId,
    ) -> Result<RouteAnchorSecret, RouteSealError> {
        self.open(blob, ROUTE_LOCATOR_INFO, exit_id.as_bytes())
    }

    fn open(
        &self,
        blob: &SealedToApi,
        info: &[u8],
        bound: &[u8],
    ) -> Result<RouteAnchorSecret, RouteSealError> {
        if blob.key_id != self.key_id {
            return Err(RouteSealError::UnknownKeyId);
        }
        let enc = RouteKemEnc::from_bytes(&blob.enc).map_err(|_| RouteSealError::Open)?;
        let plaintext = Zeroizing::new(
            hpke::single_shot_open::<WarrenAead, WarrenKdf, WarrenKem>(
                &OpModeR::Base,
                &self.sk,
                &enc,
                info,
                &blob.ct,
                &aad(info, bound),
            )
            .map_err(|_| RouteSealError::Open)?,
        );
        let secret: [u8; ROUTE_ANCHOR_SECRET_LEN] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| RouteSealError::Open)?;
        Ok(RouteAnchorSecret::from_bytes(secret))
    }
}

impl core::fmt::Debug for RouteKemSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RouteKemSecretKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Seal `secret` as the anchor registration of the main session admitted on
/// the token whose serial is `serial`.
///
/// # Errors
///
/// [`RouteSealError::Seal`] when HPKE refuses the recipient key.
pub fn seal_route_anchor(
    kem: &RouteKemPublicKey,
    secret: &RouteAnchorSecret,
    serial: &[u8; ROUTE_TOKEN_SERIAL_LEN],
) -> Result<SealedToApi, RouteSealError> {
    seal_with(
        kem,
        ROUTE_ANCHOR_INFO,
        serial,
        secret,
        &mut rand_core::UnwrapErr(rand_core::OsRng),
    )
}

/// Seal `secret` as a route locator for the exit whose id is `exit_id`. A
/// fresh ephemeral key per call, so two locators share no byte.
///
/// # Errors
///
/// [`RouteSealError::Seal`] when HPKE refuses the recipient key.
pub fn seal_route_locator(
    kem: &RouteKemPublicKey,
    secret: &RouteAnchorSecret,
    exit_id: &ExitId,
) -> Result<SealedToApi, RouteSealError> {
    seal_with(
        kem,
        ROUTE_LOCATOR_INFO,
        exit_id.as_bytes(),
        secret,
        &mut rand_core::UnwrapErr(rand_core::OsRng),
    )
}

fn aad(info: &[u8], bound: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(info.len() + bound.len());
    out.extend_from_slice(info);
    out.extend_from_slice(bound);
    out
}

fn seal_with<R: CryptoRng + RngCore>(
    kem: &RouteKemPublicKey,
    info: &[u8],
    bound: &[u8],
    secret: &RouteAnchorSecret,
    rng: &mut R,
) -> Result<SealedToApi, RouteSealError> {
    let (enc, ct) = hpke::single_shot_seal::<WarrenAead, WarrenKdf, WarrenKem, R>(
        &OpModeS::Base,
        &kem.pk,
        info,
        &secret.0[..],
        &aad(info, bound),
        rng,
    )
    .map_err(|_| RouteSealError::Seal)?;
    let enc: [u8; SEALED_TO_API_ENC_LEN] = enc.to_bytes().into();
    let ct: [u8; SEALED_TO_API_CT_LEN] =
        ct.as_slice().try_into().map_err(|_| RouteSealError::Seal)?;
    Ok(SealedToApi {
        key_id: kem.key_id,
        enc,
        ct,
    })
}

/// Length of the signed pre-image at the head of a session token
/// (`token_type || nonce || challenge_digest || token_key_id`).
const TOKEN_INPUT_LEN: usize = 98;

/// The serial of a session token, `SHA-256(token_input)`: the serial the exit
/// admits a v7 setup on, and so the one an anchor registration is sealed to.
/// Computed here so a client can seal to it without the issuer's RSA stack.
#[must_use]
pub fn session_token_serial(
    token: &warrenguard_wire::SessionToken,
) -> [u8; ROUTE_TOKEN_SERIAL_LEN] {
    Sha256::digest(&token.0[..TOKEN_INPUT_LEN]).into()
}

/// An RNG that yields one fixed HPKE ephemeral `ikm`, so a seal is
/// reproducible for the golden vectors. HPKE draws exactly one private-key
/// length from it per encapsulation.
struct FixedIkm([u8; 32]);

impl RngCore for FixedIkm {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for (slot, byte) in dst.iter_mut().zip(self.0.iter().cycle()) {
            *slot = *byte;
        }
    }
}

impl CryptoRng for FixedIkm {}

/// Seal with a fixed ephemeral `ikm` (HPKE `DeriveKeyPair`), for the golden
/// vectors only: a production seal draws a fresh ephemeral key.
#[doc(hidden)]
pub fn seal_route_anchor_with_ephemeral_ikm(
    kem: &RouteKemPublicKey,
    secret: &RouteAnchorSecret,
    serial: &[u8; ROUTE_TOKEN_SERIAL_LEN],
    ephemeral_ikm: [u8; 32],
) -> Result<SealedToApi, RouteSealError> {
    seal_with(
        kem,
        ROUTE_ANCHOR_INFO,
        serial,
        secret,
        &mut FixedIkm(ephemeral_ikm),
    )
}

/// Locator counterpart of [`seal_route_anchor_with_ephemeral_ikm`], for the
/// golden vectors only.
#[doc(hidden)]
pub fn seal_route_locator_with_ephemeral_ikm(
    kem: &RouteKemPublicKey,
    secret: &RouteAnchorSecret,
    exit_id: &ExitId,
    ephemeral_ikm: [u8; 32],
) -> Result<SealedToApi, RouteSealError> {
    seal_with(
        kem,
        ROUTE_LOCATOR_INFO,
        exit_id.as_bytes(),
        secret,
        &mut FixedIkm(ephemeral_ikm),
    )
}

/// Refusal code of a [`crate::WarrenControlMessage::RouteRejected`]. The wire
/// carries a plain `u8` so a code a peer does not know still decodes, as
/// [`Self::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RouteRejectCode {
    /// `0`: no specific cause.
    Unspecified,
    /// `1`: the control plane knows no live anchor for this locator.
    AnchorUnknown,
    /// `2`: the anchor already holds its maximum number of routes.
    RouteLimit,
    /// `3`: this exit does not offer route admission.
    NotOffered,
    /// `4`: the control plane could not be asked (unreachable or rate limited).
    Unavailable,
    /// A code this build does not know.
    Other(u8),
}

impl RouteRejectCode {
    /// Decode a wire code.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Unspecified,
            1 => Self::AnchorUnknown,
            2 => Self::RouteLimit,
            3 => Self::NotOffered,
            4 => Self::Unavailable,
            other => Self::Other(other),
        }
    }

    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::AnchorUnknown => 1,
            Self::RouteLimit => 2,
            Self::NotOffered => 3,
            Self::Unavailable => 4,
            Self::Other(code) => code,
        }
    }

    /// A stable label for metrics and logs (no identifier).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::AnchorUnknown => "anchor_unknown",
            Self::RouteLimit => "route_limit",
            Self::NotOffered => "not_offered",
            Self::Unavailable => "unavailable",
            Self::Other(_) => "other",
        }
    }
}

impl core::fmt::Display for RouteRejectCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Status of a [`crate::WarrenControlMessage::RouteAnchorAck`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RouteAnchorStatus {
    /// `0`: the anchor is attached to this main session.
    Bound,
    /// `1`: the session holds no live token lease; resend with a token.
    NeedsToken,
    /// `2`: this session cannot anchor (wallet session, or the exit has route
    /// admission off).
    NotEligible,
    /// `3`: the blob or the presented token was refused.
    Refused,
    /// `4`: the control plane could not be asked; retry later.
    Unavailable,
    /// `5`: the exit's renewal found no anchor; resend the request.
    Lost,
    /// A status this build does not know.
    Other(u8),
}

impl RouteAnchorStatus {
    /// Decode a wire status.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Bound,
            1 => Self::NeedsToken,
            2 => Self::NotEligible,
            3 => Self::Refused,
            4 => Self::Unavailable,
            5 => Self::Lost,
            other => Self::Other(other),
        }
    }

    /// The wire status.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Bound => 0,
            Self::NeedsToken => 1,
            Self::NotEligible => 2,
            Self::Refused => 3,
            Self::Unavailable => 4,
            Self::Lost => 5,
            Self::Other(code) => code,
        }
    }

    /// A stable label for metrics and logs (no identifier).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::NeedsToken => "needs_token",
            Self::NotEligible => "not_eligible",
            Self::Refused => "refused",
            Self::Unavailable => "unavailable",
            Self::Lost => "lost",
            Self::Other(_) => "other",
        }
    }
}

/// Reason of a [`crate::WarrenControlMessage::RouteEnded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RouteEndReason {
    /// `0`: no specific cause.
    Unspecified,
    /// `1`: the anchor this route hung on is gone.
    AnchorGone,
    /// `2`: the exit's policy closed the route.
    ClosedByPolicy,
    /// A code this build does not know.
    Other(u8),
}

impl RouteEndReason {
    /// Decode a wire code.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Unspecified,
            1 => Self::AnchorGone,
            2 => Self::ClosedByPolicy,
            other => Self::Other(other),
        }
    }

    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::AnchorGone => 1,
            Self::ClosedByPolicy => 2,
            Self::Other(code) => code,
        }
    }

    /// A stable label for metrics and logs (no identifier).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::AnchorGone => "anchor_gone",
            Self::ClosedByPolicy => "closed_by_policy",
            Self::Other(_) => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERIAL: [u8; 32] = [0x5E; 32];

    fn api_key() -> RouteKemSecretKey {
        RouteKemSecretKey::derive(&[0x71; 32], 1).expect("key id 1 is valid")
    }

    fn exit(byte: u8) -> ExitId {
        ExitId::from_bytes([byte; 16])
    }

    #[test]
    fn anchor_opens_only_for_the_serial_it_was_sealed_to() {
        let key = api_key();
        let secret = RouteAnchorSecret::from_bytes([0x3C; 32]);
        let blob = seal_route_anchor(key.public_key(), &secret, &SERIAL).expect("seal");
        let opened = key
            .open_anchor(&blob, &SERIAL)
            .expect("the right serial opens");
        assert_eq!(opened.anchor_ref(), secret.anchor_ref());
        assert_eq!(
            key.open_anchor(&blob, &[0x5F; 32]).err(),
            Some(RouteSealError::Open),
            "an anchor blob must not attach to another main session"
        );
    }

    #[test]
    fn locator_opens_only_for_the_exit_it_was_sealed_to() {
        let key = api_key();
        let secret = RouteAnchorSecret::from_bytes([0x3C; 32]);
        let blob = seal_route_locator(key.public_key(), &secret, &exit(0xA2)).expect("seal");
        let opened = key
            .open_locator(&blob, &exit(0xA2))
            .expect("the right exit opens");
        assert_eq!(opened.anchor_ref(), secret.anchor_ref());
        assert_eq!(
            key.open_locator(&blob, &exit(0xA3)).err(),
            Some(RouteSealError::Open),
            "a locator sealed for one exit must not open for another (confused deputy)"
        );
    }

    #[test]
    fn an_anchor_blob_is_never_a_locator() {
        let key = api_key();
        let secret = RouteAnchorSecret::from_bytes([0x3C; 32]);
        // Same 32-byte binding on both sides: only the info separates them.
        let serial_as_exit = [0xA2; 32];
        let blob = seal_route_anchor(key.public_key(), &secret, &serial_as_exit).expect("seal");
        assert_eq!(
            key.open(&blob, ROUTE_LOCATOR_INFO, &serial_as_exit).err(),
            Some(RouteSealError::Open)
        );
    }

    #[test]
    fn a_blob_under_another_key_id_is_refused_before_any_hpke_work() {
        let key = api_key();
        let other = RouteKemSecretKey::derive(&[0x71; 32], 2).expect("key id 2");
        let secret = RouteAnchorSecret::from_bytes([0x3C; 32]);
        let blob = seal_route_anchor(other.public_key(), &secret, &SERIAL).expect("seal");
        assert_eq!(blob.key_id(), 2);
        assert_eq!(
            key.open_anchor(&blob, &SERIAL).err(),
            Some(RouteSealError::UnknownKeyId)
        );
        assert_ne!(
            key.public_key().to_bytes(),
            other.public_key().to_bytes(),
            "each key id derives its own key pair"
        );
    }

    #[test]
    fn every_flipped_or_truncated_byte_fails_to_open() {
        let key = api_key();
        let secret = RouteAnchorSecret::from_bytes([0x3C; 32]);
        let bytes = seal_route_locator(key.public_key(), &secret, &exit(0xA2))
            .expect("seal")
            .to_bytes();
        for i in 1..SEALED_TO_API_LEN {
            let mut tampered = bytes;
            tampered[i] ^= 0x01;
            assert!(
                key.open_locator(&SealedToApi::from_bytes(&tampered), &exit(0xA2))
                    .is_err(),
                "flipping byte {i} must fail the open"
            );
        }
        assert!(SealedToApi::from_slice(&bytes[..SEALED_TO_API_LEN - 1]).is_none());
        assert!(SealedToApi::from_slice(&[bytes.as_slice(), &[0]].concat()).is_none());
    }

    #[test]
    fn two_seals_of_one_secret_share_no_byte_an_exit_could_match() {
        let key = api_key();
        let secret = RouteAnchorSecret::from_bytes([0x3C; 32]);
        let a = seal_route_locator(key.public_key(), &secret, &exit(0xA2))
            .expect("seal")
            .to_bytes();
        let b = seal_route_locator(key.public_key(), &secret, &exit(0xA2))
            .expect("seal")
            .to_bytes();
        assert_eq!(a[0], b[0], "the key id is the only shared byte by design");
        assert_ne!(a[1..33], b[1..33], "a fresh ephemeral key per seal");
        assert_ne!(a[33..], b[33..]);
    }

    #[test]
    fn reserved_key_id_and_small_order_points_are_refused() {
        assert_eq!(
            RouteKemSecretKey::derive(&[0x71; 32], 0).err(),
            Some(RouteSealError::ReservedKeyId)
        );
        let good = api_key().public_key().to_bytes();
        assert_eq!(
            RouteKemPublicKey::new(0, good).err(),
            Some(RouteSealError::ReservedKeyId)
        );
        assert!(RouteKemPublicKey::new(1, good).is_ok());
        // The all-zero u-coordinate is of small order: no shared secret.
        assert_eq!(
            RouteKemPublicKey::new(1, [0u8; 32]).err(),
            Some(RouteSealError::InvalidPublicKey)
        );
    }

    #[test]
    fn route_serial_is_bound_to_the_anchor_and_the_exit() {
        let a = RouteAnchorSecret::from_bytes([0x3C; 32]).anchor_ref();
        let b = RouteAnchorSecret::from_bytes([0x3D; 32]).anchor_ref();
        assert_ne!(a, b);
        assert_ne!(a.route_serial(&exit(0xA2)), a.route_serial(&exit(0xA3)));
        assert_ne!(a.route_serial(&exit(0xA2)), b.route_serial(&exit(0xA2)));
        assert_eq!(a.route_serial(&exit(0xA2)), a.route_serial(&exit(0xA2)));
    }

    /// Both renderings a derived `Debug` or a hex dump would produce.
    fn renderings(bytes: &[u8]) -> [String; 2] {
        [
            format!("{}, {}, {}", bytes[0], bytes[1], bytes[2]),
            hex::encode(&bytes[..3]),
        ]
    }

    #[test]
    fn no_debug_output_carries_the_secret_or_an_identifier() {
        let key = api_key();
        let secret = RouteAnchorSecret::from_bytes([0x3C; 32]);
        let blob = seal_route_anchor(key.public_key(), &secret, &SERIAL).expect("seal");
        let a = secret.anchor_ref();
        let r = a.route_serial(&exit(0xA2));
        let rendered = format!("{secret:?} {blob:?} {a:?} {r:?} {key:?}");
        let blob_bytes = blob.to_bytes();
        for (what, bytes) in [
            ("secret", &[0x3Cu8; 32][..]),
            ("anchor ref", a.as_bytes()),
            ("route serial", r.as_bytes()),
            ("blob", &blob_bytes[1..]),
        ] {
            for needle in renderings(bytes) {
                assert!(
                    !rendered.contains(&needle),
                    "Debug output leaked the {what}: {rendered}"
                );
            }
        }
    }

    #[test]
    fn the_token_serial_is_the_issuer_crate_serial() {
        use rand_v10::SeedableRng;
        let mut rng = rand_v10::rngs::StdRng::seed_from_u64(0x005E_41A1);
        let sk = warrenguard_token::IssuerSecretKey::generate(&mut rng).expect("issuer key");
        let pk = sk.public_key();
        let challenge =
            warrenguard_token::TokenChallenge::for_epoch("issuer.test", "warren/token/epoch", 3)
                .expect("challenge");
        let (req, state) = pk.blind_token(&mut rng, &challenge).expect("blind");
        let token = pk
            .finalize_token(state, &sk.blind_sign(&req).expect("sign"))
            .expect("finalize");
        assert_eq!(
            session_token_serial(&warrenguard_wire::SessionToken(token.serialize())),
            *token.serial().as_bytes(),
            "the client must seal to the serial the exit admits on"
        );
    }

    #[test]
    fn wire_codes_round_trip_and_unknown_codes_survive() {
        for code in 0..=u8::MAX {
            assert_eq!(RouteRejectCode::from_code(code).code(), code);
            assert_eq!(RouteAnchorStatus::from_code(code).code(), code);
            assert_eq!(RouteEndReason::from_code(code).code(), code);
        }
        assert_eq!(
            RouteRejectCode::from_code(1),
            RouteRejectCode::AnchorUnknown
        );
        assert_eq!(RouteRejectCode::from_code(9), RouteRejectCode::Other(9));
        assert_eq!(RouteAnchorStatus::from_code(5), RouteAnchorStatus::Lost);
        assert_eq!(RouteEndReason::from_code(1), RouteEndReason::AnchorGone);
    }
}
