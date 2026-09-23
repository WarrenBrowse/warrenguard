//! Issuer key material and public verification.

use blind_rsa_signatures::{
    BlindSignature, KeyPairSha384PSSDeterministic, PublicKeySha384PSSDeterministic,
    SecretKeySha384PSSDeterministic, Signature,
};
use rand::rngs::SysRng;
use rand::{CryptoRng, TryCryptoRng};
use rsa::hazmat::rsa_encrypt;
use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, RsaPublicKey};
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

    /// `true` when `blind_sig` is the canonical RSA signature of
    /// `blinded_request` under this key: `blind_sig < n` and
    /// `blind_sig^e mod n == blinded_request`. Both inputs are public (the
    /// request comes from the client, the signature goes back to it), so the
    /// check needs no constant-time care.
    fn blind_signature_matches(&self, blinded_request: &[u8], blind_sig: &[u8]) -> bool {
        let key: &RsaPublicKey = self.inner.as_ref();
        let bits = key.n_bits_precision();
        let (Ok(request), Ok(sig)) = (
            BoxedUint::from_be_slice(blinded_request, bits),
            BoxedUint::from_be_slice(blind_sig, bits),
        ) else {
            return false;
        };
        if sig >= *key.n().as_ref() {
            return false;
        }
        rsa_encrypt(key, &sig).is_ok_and(|recovered| recovered == request)
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
    /// The blinding factor comes from the operating system RNG on every call,
    /// and a signature is returned only after it verifies against the request.
    ///
    /// # Errors
    /// [`TokenError::BlindOperation`] if the request is the wrong size, the
    /// blind-RSA operation fails (an OS RNG failure included), or its result
    /// does not verify.
    pub fn blind_sign(&self, blinded_request: &[u8]) -> Result<Vec<u8>, TokenError> {
        self.blind_sign_with_rng(&mut SysRng, blinded_request)
    }

    /// [`Self::blind_sign`] with the RNG that draws the RSA blinding factor.
    ///
    /// The client chooses the value this private-key operation runs on. The
    /// library multiplies it by `r^e` for a uniform `r` drawn here on every
    /// call, so the modular arithmetic runs on a value the client cannot
    /// predict, and unblinds the result.
    fn blind_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        blinded_request: &[u8],
    ) -> Result<Vec<u8>, TokenError> {
        if blinded_request.len() != AUTHENTICATOR_LEN {
            return Err(TokenError::BlindOperation);
        }
        let sig: BlindSignature = self
            .inner
            .blind_sign_with_rng(rng, blinded_request)
            .map_err(|_| TokenError::BlindOperation)?;
        self.release_if_valid(blinded_request, sig.0)
    }

    /// Releases `blind_sig` only if it verifies against `blinded_request`.
    ///
    /// A CRT signature computed with a fault in one of its two halves hands
    /// its receiver a prime factor of the modulus (`gcd(s^e - m, n)`, the
    /// Bellcore attack). The RSA library checks its own output today; this
    /// gate keeps that property in the issuer, independent of the library
    /// version.
    fn release_if_valid(
        &self,
        blinded_request: &[u8],
        blind_sig: Vec<u8>,
    ) -> Result<Vec<u8>, TokenError> {
        if self
            .public
            .blind_signature_matches(blinded_request, &blind_sig)
        {
            Ok(blind_sig)
        } else {
            Err(TokenError::BlindOperation)
        }
    }

    /// Constant-time equality of the underlying key id (test/ops helper).
    #[must_use]
    pub fn key_id_eq(&self, other: &IssuerKeyId) -> bool {
        self.public.key_id.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenChallenge;
    use rand::rngs::StdRng;
    use rand::{SeedableRng, TryRng};

    /// Counts the bytes drawn through it, so a test can see whether (and how
    /// much) randomness a signature consumed.
    struct CountingRng {
        inner: StdRng,
        drawn: usize,
    }

    impl TryRng for CountingRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.drawn += 4;
            self.inner.try_next_u32()
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.drawn += 8;
            self.inner.try_next_u64()
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.drawn += dst.len();
            self.inner.try_fill_bytes(dst)
        }
    }

    impl TryCryptoRng for CountingRng {}

    fn issuer_and_request() -> (IssuerSecretKey, Vec<u8>) {
        let sk =
            IssuerSecretKey::generate(&mut StdRng::seed_from_u64(0x005E_C2E7)).expect("keygen");
        let challenge =
            TokenChallenge::for_context("issuer.example", [0x44; 32]).expect("challenge");
        let (request, _state) = sk
            .public_key()
            .blind_token(&mut StdRng::seed_from_u64(0x0B11_17D5), &challenge)
            .expect("blind");
        (sk, request)
    }

    #[test]
    fn every_signature_draws_a_fresh_modulus_sized_blinding_factor() {
        let (sk, request) = issuer_and_request();
        let mut rng = CountingRng {
            inner: StdRng::seed_from_u64(7),
            drawn: 0,
        };

        let first = sk.blind_sign_with_rng(&mut rng, &request).expect("sign");
        let after_first = rng.drawn;
        let second = sk.blind_sign_with_rng(&mut rng, &request).expect("sign");

        assert!(
            after_first >= AUTHENTICATOR_LEN,
            "the first signature must draw its blinding factor from the given RNG \
             (drew {after_first} bytes)"
        );
        assert!(
            rng.drawn - after_first >= AUTHENTICATOR_LEN,
            "the second signature must draw a fresh blinding factor"
        );
        assert_eq!(first, second, "blinding never changes the signature");
    }

    #[test]
    fn a_blind_signature_that_does_not_verify_is_never_released() {
        let (sk, request) = issuer_and_request();
        let genuine = sk.blind_sign(&request).expect("sign");
        assert_eq!(
            sk.release_if_valid(&request, genuine.clone())
                .expect("a genuine signature is released"),
            genuine
        );

        let mut faulty = genuine;
        faulty[AUTHENTICATOR_LEN / 2] ^= 0x01;
        assert!(matches!(
            sk.release_if_valid(&request, faulty),
            Err(TokenError::BlindOperation)
        ));
    }

    #[test]
    fn a_non_canonical_blind_signature_is_never_released() {
        let (sk, request) = issuer_and_request();
        // Above the modulus: not the canonical representative of any residue.
        assert!(matches!(
            sk.release_if_valid(&request, vec![0xFF; AUTHENTICATOR_LEN]),
            Err(TokenError::BlindOperation)
        ));
    }
}
