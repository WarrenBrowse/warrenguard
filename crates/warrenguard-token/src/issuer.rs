//! Issuer key material and public verification.

use blind_rsa_signatures::{
    BlindSignature, KeyPairSha384PSSDeterministic, PublicKeySha384PSSDeterministic,
    SecretKeySha384PSSDeterministic, Signature,
};
use rand::CryptoRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::TokenError;
use crate::token::{AUTHENTICATOR_LEN, TOKEN_KEY_ID_LEN, Token};

/// Fixed RSA modulus for token type `0x0002`: 2048 bits (256-byte
/// authenticator). The whole crate's fixed token length depends on this, so
/// keys of any other size are rejected on load.
const MODULUS_BITS: usize = 2048;

/// The issuer key id: `SHA-256(SubjectPublicKeyInfo)` with the RSASSA-PSS
/// algorithm identifier (RFC 9578 SS8.2.1). Every token carries it so a
/// verifier can select the right key and reject tokens minted under another.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IssuerKeyId([u8; TOKEN_KEY_ID_LEN]);

impl IssuerKeyId {
    /// The raw 32-byte key id.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; TOKEN_KEY_ID_LEN] {
        &self.0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(TOKEN_KEY_ID_LEN * 2);
        use core::fmt::Write;
        for b in &self.0 {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl core::fmt::Debug for IssuerKeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IssuerKeyId({}..)", &self.to_hex()[..8])
    }
}

/// An issuer public key: everything a verifier or a client needs, and nothing
/// secret. Cheap to clone and safe to distribute (it is published in the
/// issuer directory).
#[derive(Clone)]
pub struct IssuerPublicKey {
    pub(crate) inner: PublicKeySha384PSSDeterministic,
    key_id: IssuerKeyId,
    spki: Vec<u8>,
}

impl core::fmt::Debug for IssuerPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IssuerPublicKey({:?})", self.key_id)
    }
}

impl IssuerPublicKey {
    fn from_inner(inner: PublicKeySha384PSSDeterministic) -> Result<Self, TokenError> {
        // Enforce the 2048-bit invariant the fixed token length rests on.
        if inner.components().n().len() != AUTHENTICATOR_LEN {
            return Err(TokenError::InvalidKey);
        }
        let spki = inner.to_spki().map_err(|_| TokenError::InvalidKey)?;
        let key_id = IssuerKeyId(Sha256::digest(&spki).into());
        Ok(Self {
            inner,
            key_id,
            spki,
        })
    }

    /// Parses a public key from its RSASSA-PSS `SubjectPublicKeyInfo` DER (the
    /// form published in the issuer directory).
    ///
    /// # Errors
    /// [`TokenError::InvalidKey`] on malformed DER or a non-2048-bit modulus.
    pub fn from_spki(spki: &[u8]) -> Result<Self, TokenError> {
        let inner =
            PublicKeySha384PSSDeterministic::from_spki(spki).map_err(|_| TokenError::InvalidKey)?;
        Self::from_inner(inner)
    }

    /// The RSASSA-PSS `SubjectPublicKeyInfo` DER for this key.
    #[must_use]
    pub fn to_spki(&self) -> Vec<u8> {
        self.spki.clone()
    }

    /// This key's [`IssuerKeyId`].
    #[must_use]
    pub fn key_id(&self) -> IssuerKeyId {
        self.key_id
    }

    /// Verifies a token: its `token_key_id` must match this key (constant
    /// time) and its authenticator must be a valid blind-RSA signature over
    /// the token's `token_input`.
    ///
    /// This is fully offline (public key only). It does **not** check the
    /// epoch/redemption-context or double-spend: those are the deployer's
    /// policy, keyed on [`Token::serial`](crate::Token::serial) and the
    /// challenge digest.
    ///
    /// # Errors
    /// [`TokenError::VerificationFailed`] if the key id mismatches or the
    /// signature does not verify.
    pub fn verify_token(&self, token: &Token) -> Result<(), TokenError> {
        if !token.key_id_matches(self.key_id.as_bytes()) {
            return Err(TokenError::VerificationFailed);
        }
        let sig = Signature(token.authenticator().to_vec());
        self.inner
            .verify(&sig, None, token.token_input())
            .map_err(|_| TokenError::VerificationFailed)
    }
}

/// An issuer secret key. Holds the RSA private key; never derives `Debug` on
/// the secret and zeroizes its DER exports.
pub struct IssuerSecretKey {
    inner: SecretKeySha384PSSDeterministic,
    public: IssuerPublicKey,
}

impl core::fmt::Debug for IssuerSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Render only the public handle, never the secret.
        write!(f, "IssuerSecretKey({:?})", self.public.key_id)
    }
}

impl IssuerSecretKey {
    fn from_inner(inner: SecretKeySha384PSSDeterministic) -> Result<Self, TokenError> {
        let pk = inner.public_key().map_err(|_| TokenError::InvalidKey)?;
        let public = IssuerPublicKey::from_inner(pk)?;
        Ok(Self { inner, public })
    }

    /// Generates a fresh 2048-bit issuer key.
    ///
    /// RSA keygen is expensive; do it once at issuer provisioning, persist the
    /// DER ([`IssuerSecretKey::to_der`]) and reload it.
    ///
    /// # Errors
    /// [`TokenError::InvalidKey`] if keygen fails.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self, TokenError> {
        let kp = KeyPairSha384PSSDeterministic::generate(rng, MODULUS_BITS)
            .map_err(|_| TokenError::InvalidKey)?;
        Self::from_inner(kp.sk)
    }

    /// Loads a secret key from PKCS#8 DER.
    ///
    /// # Errors
    /// [`TokenError::InvalidKey`] on malformed DER or a non-2048-bit modulus.
    pub fn from_der(der: &[u8]) -> Result<Self, TokenError> {
        let inner =
            SecretKeySha384PSSDeterministic::from_der(der).map_err(|_| TokenError::InvalidKey)?;
        Self::from_inner(inner)
    }

    /// Exports the secret key as PKCS#8 DER, in a zeroizing buffer.
    ///
    /// # Errors
    /// [`TokenError::InvalidKey`] if encoding fails.
    pub fn to_der(&self) -> Result<Zeroizing<Vec<u8>>, TokenError> {
        self.inner
            .to_der()
            .map(Zeroizing::new)
            .map_err(|_| TokenError::InvalidKey)
    }

    /// The matching [`IssuerPublicKey`].
    #[must_use]
    pub fn public_key(&self) -> IssuerPublicKey {
        self.public.clone()
    }

    /// Blind-signs a client's blinded token request.
    ///
    /// The issuer learns nothing about the token this signature will become:
    /// that is the blindness guarantee. Enforcing epoch, quota and
    /// subscription is the caller's job, done *before* calling this.
    ///
    /// # Errors
    /// [`TokenError::BlindOperation`] if the request is the wrong size or the
    /// blind-RSA operation fails.
    pub fn blind_sign(&self, blinded_request: &[u8]) -> Result<Vec<u8>, TokenError> {
        if blinded_request.len() != AUTHENTICATOR_LEN {
            return Err(TokenError::BlindOperation);
        }
        let sig: BlindSignature = self
            .inner
            .blind_sign(blinded_request)
            .map_err(|_| TokenError::BlindOperation)?;
        Ok(sig.0)
    }

    /// Constant-time equality of the underlying key id (test/ops helper).
    #[must_use]
    pub fn key_id_eq(&self, other: &IssuerKeyId) -> bool {
        self.public.key_id.as_bytes().ct_eq(other.as_bytes()).into()
    }
}
