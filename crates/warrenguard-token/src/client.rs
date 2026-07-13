//! Client-side blinding and finalization.

use blind_rsa_signatures::{BlindSignature, BlindingResult};
use rand::CryptoRng;

use crate::TokenError;
use crate::challenge::TokenChallenge;
use crate::issuer::IssuerPublicKey;
use crate::token::{AUTHENTICATOR_LEN, CHALLENGE_DIGEST_LEN, NONCE_LEN, TOKEN_KEY_ID_LEN, Token};

/// The secret client state that bridges a blinded request and its
/// finalization. It must be kept until the issuer's blind signature comes
/// back, then consumed by [`IssuerPublicKey::finalize_token`]. It holds the
/// unblinding secret and the token fields chosen at blinding time.
///
/// Not `Clone` and not `Debug`-verbose: it carries the blinding secret, whose
/// disclosure alongside the blinded request would let the issuer link the
/// token. Dropping it without finalizing simply wastes the request.
pub struct ClientState {
    blinding: BlindingResult,
    nonce: [u8; NONCE_LEN],
    challenge_digest: [u8; CHALLENGE_DIGEST_LEN],
    token_key_id: [u8; TOKEN_KEY_ID_LEN],
}

impl core::fmt::Debug for ClientState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the blinding secret or the nonce.
        f.write_str("ClientState(..)")
    }
}

impl IssuerPublicKey {
    /// Builds a blinded token request for `challenge`.
    ///
    /// Draws a fresh 32-byte nonce and a PSS salt from `rng` (the RNG is the
    /// only system boundary here), computes the token pre-image, and blinds
    /// it. Returns the blinded request to POST to the issuer, plus the
    /// [`ClientState`] needed to finalize the resulting signature.
    ///
    /// # Errors
    /// [`TokenError::BlindOperation`] if the blind-RSA operation fails.
    pub fn blind_token<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        challenge: &TokenChallenge,
    ) -> Result<(Vec<u8>, ClientState), TokenError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let challenge_digest = challenge.digest();
        let token_key_id = *self.key_id().as_bytes();

        // token_input = token_type || nonce || challenge_digest || token_key_id
        let token_input = build_token_input(&nonce, &challenge_digest, &token_key_id);

        let blinding = self
            .inner
            .blind(rng, token_input)
            .map_err(|_| TokenError::BlindOperation)?;
        // Deterministic profile: no message randomizer must be produced.
        debug_assert!(blinding.msg_randomizer.is_none());

        let request = blinding.blind_message.0.clone();
        Ok((
            request,
            ClientState {
                blinding,
                nonce,
                challenge_digest,
                token_key_id,
            },
        ))
    }

    /// Turns the issuer's blind signature into a verified [`Token`].
    ///
    /// Unblinds, then verifies the resulting signature against this key (so a
    /// wrong or malicious blind signature is caught here, not at redemption),
    /// and assembles the token. Consumes the [`ClientState`].
    ///
    /// # Errors
    /// [`TokenError::BlindOperation`] if the blind signature is the wrong size
    /// or unblinding/verification fails.
    // Takes `state` by value on purpose: finalization is consume-once, so a
    // used blinding secret cannot be replayed into a second finalization.
    #[allow(clippy::needless_pass_by_value)]
    pub fn finalize_token(
        &self,
        state: ClientState,
        blind_signature: &[u8],
    ) -> Result<Token, TokenError> {
        if blind_signature.len() != AUTHENTICATOR_LEN {
            return Err(TokenError::BlindOperation);
        }
        let token_input =
            build_token_input(&state.nonce, &state.challenge_digest, &state.token_key_id);
        let blind_sig = BlindSignature(blind_signature.to_vec());
        let sig = self
            .inner
            .finalize(&blind_sig, &state.blinding, token_input)
            .map_err(|_| TokenError::BlindOperation)?;
        if sig.0.len() != AUTHENTICATOR_LEN {
            return Err(TokenError::BlindOperation);
        }
        let mut authenticator = [0u8; AUTHENTICATOR_LEN];
        authenticator.copy_from_slice(&sig.0);
        Ok(Token::from_parts(
            state.nonce,
            state.challenge_digest,
            state.token_key_id,
            authenticator,
        ))
    }
}

fn build_token_input(
    nonce: &[u8; NONCE_LEN],
    challenge_digest: &[u8; CHALLENGE_DIGEST_LEN],
    token_key_id: &[u8; TOKEN_KEY_ID_LEN],
) -> Vec<u8> {
    let mut ti = Vec::with_capacity(2 + NONCE_LEN + CHALLENGE_DIGEST_LEN + TOKEN_KEY_ID_LEN);
    ti.extend_from_slice(&crate::challenge::TOKEN_TYPE_BLIND_RSA.to_be_bytes());
    ti.extend_from_slice(nonce);
    ti.extend_from_slice(challenge_digest);
    ti.extend_from_slice(token_key_id);
    ti
}
