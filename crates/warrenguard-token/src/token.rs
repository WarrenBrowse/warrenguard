//! The `Token` structure (RFC 9578 SS2.2) and its redemption serial.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{TokenError, challenge::TOKEN_TYPE_BLIND_RSA};

/// Length of the client-chosen token nonce.
pub const NONCE_LEN: usize = 32;
/// Length of the embedded challenge digest (SHA-256).
pub const CHALLENGE_DIGEST_LEN: usize = 32;
/// Length of the issuer key id (SHA-256 of the SPKI).
pub const TOKEN_KEY_ID_LEN: usize = 32;
/// Length of the blind-RSA authenticator (2048-bit modulus = 256 bytes).
pub const AUTHENTICATOR_LEN: usize = 256;
/// Length of the signed pre-image: `token_type || nonce || challenge_digest ||
/// token_key_id`. This is the message the issuer blind-signs.
pub const TOKEN_INPUT_LEN: usize = 2 + NONCE_LEN + CHALLENGE_DIGEST_LEN + TOKEN_KEY_ID_LEN;
/// Length of a fully serialized token (`token_input || authenticator`).
pub const TOKEN_LEN: usize = TOKEN_INPUT_LEN + AUTHENTICATOR_LEN;

/// A redemption serial: `SHA-256(token_input)`.
///
/// It identifies a token independently of its signature: RSABSSA-PSS uses a
/// random salt, so two finalizations of the *same* token bytes differ in the
/// authenticator, yet share this serial. The anti-double-spend ledger keys on
/// it. Because it covers the whole `token_input` (nonce, challenge digest and
/// key id), a nonce reused across two different epochs yields two *distinct*
/// serials (correct: they are different-epoch tokens), while a nonce reused
/// within one epoch collapses to one serial (correct: one usable slot).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenSerial([u8; 32]);

impl TokenSerial {
    /// The raw 32-byte serial.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, suitable as a ledger key.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }
}

// A token serial is derived from a public value but printing it verbatim in a
// log invites accidental correlation records; render only a short prefix.
impl core::fmt::Debug for TokenSerial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TokenSerial({}..)", &hex_encode(&self.0[..4]))
    }
}

/// A Privacy Pass token (RFC 9578 SS2.2), type `0x0002`.
///
/// ```text
/// struct {
///     uint16_t token_type;              // 0x0002
///     uint8_t nonce[32];
///     uint8_t challenge_digest[32];
///     uint8_t token_key_id[32];
///     uint8_t authenticator[256];
/// } Token;
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    pub(crate) nonce: [u8; NONCE_LEN],
    pub(crate) challenge_digest: [u8; CHALLENGE_DIGEST_LEN],
    pub(crate) token_key_id: [u8; TOKEN_KEY_ID_LEN],
    pub(crate) authenticator: [u8; AUTHENTICATOR_LEN],
}

// Manual Debug: never render the authenticator or the full nonce (both are
// bearer material until spent). A short nonce prefix aids debugging without
// making a log a redemption oracle.
impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Token(0x0002, nonce={}..)",
            &hex_encode(&self.nonce[..4])
        )
    }
}

impl Token {
    /// Assembles a token from its finalized parts (used by the client after
    /// unblinding). Not public: a token only ever comes from finalization or
    /// [`Token::parse`], never hand-built.
    pub(crate) fn from_parts(
        nonce: [u8; NONCE_LEN],
        challenge_digest: [u8; CHALLENGE_DIGEST_LEN],
        token_key_id: [u8; TOKEN_KEY_ID_LEN],
        authenticator: [u8; AUTHENTICATOR_LEN],
    ) -> Self {
        Self {
            nonce,
            challenge_digest,
            token_key_id,
            authenticator,
        }
    }

    /// The token type (always [`TOKEN_TYPE_BLIND_RSA`]).
    #[must_use]
    pub fn token_type(&self) -> u16 {
        TOKEN_TYPE_BLIND_RSA
    }

    /// The embedded challenge digest.
    #[must_use]
    pub fn challenge_digest(&self) -> &[u8; CHALLENGE_DIGEST_LEN] {
        &self.challenge_digest
    }

    /// The issuer key id this token was minted under.
    #[must_use]
    pub fn token_key_id(&self) -> &[u8; TOKEN_KEY_ID_LEN] {
        &self.token_key_id
    }

    /// The signed pre-image `token_type || nonce || challenge_digest ||
    /// token_key_id` (98 bytes). This is what the issuer blind-signs and what
    /// the verifier checks the authenticator against.
    #[must_use]
    pub fn token_input(&self) -> [u8; TOKEN_INPUT_LEN] {
        let mut out = [0u8; TOKEN_INPUT_LEN];
        out[0..2].copy_from_slice(&TOKEN_TYPE_BLIND_RSA.to_be_bytes());
        out[2..34].copy_from_slice(&self.nonce);
        out[34..66].copy_from_slice(&self.challenge_digest);
        out[66..98].copy_from_slice(&self.token_key_id);
        out
    }

    /// The redemption serial `SHA-256(token_input)`; see [`TokenSerial`].
    #[must_use]
    pub fn serial(&self) -> TokenSerial {
        TokenSerial(Sha256::digest(self.token_input()).into())
    }

    /// The full wire serialization (`token_input || authenticator`, 354 bytes).
    #[must_use]
    pub fn serialize(&self) -> [u8; TOKEN_LEN] {
        let mut out = [0u8; TOKEN_LEN];
        out[0..TOKEN_INPUT_LEN].copy_from_slice(&self.token_input());
        out[TOKEN_INPUT_LEN..].copy_from_slice(&self.authenticator);
        out
    }

    /// Parses a token from its wire encoding.
    ///
    /// Validates the exact fixed length and the `0x0002` token type, and
    /// rejects any trailing bytes. Parsing does **not** verify the
    /// authenticator; call [`IssuerPublicKey::verify_token`](crate::IssuerPublicKey::verify_token).
    ///
    /// # Errors
    /// [`TokenError::MalformedToken`] on any length or token-type mismatch.
    pub fn parse(bytes: &[u8]) -> Result<Self, TokenError> {
        if bytes.len() != TOKEN_LEN {
            return Err(TokenError::MalformedToken);
        }
        let token_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        // Constant-time compare on the type is unnecessary (it is public), but
        // keep the rejection strict.
        if token_type != TOKEN_TYPE_BLIND_RSA {
            return Err(TokenError::MalformedToken);
        }
        let mut nonce = [0u8; NONCE_LEN];
        let mut challenge_digest = [0u8; CHALLENGE_DIGEST_LEN];
        let mut token_key_id = [0u8; TOKEN_KEY_ID_LEN];
        let mut authenticator = [0u8; AUTHENTICATOR_LEN];
        nonce.copy_from_slice(&bytes[2..34]);
        challenge_digest.copy_from_slice(&bytes[34..66]);
        token_key_id.copy_from_slice(&bytes[66..98]);
        authenticator.copy_from_slice(&bytes[98..TOKEN_LEN]);
        Ok(Self {
            nonce,
            challenge_digest,
            token_key_id,
            authenticator,
        })
    }

    /// Constant-time check that this token's key id equals `key_id`.
    pub(crate) fn key_id_matches(&self, key_id: &[u8; TOKEN_KEY_ID_LEN]) -> bool {
        self.token_key_id.ct_eq(key_id).into()
    }

    /// The raw authenticator bytes (for the verifier).
    pub(crate) fn authenticator(&self) -> &[u8; AUTHENTICATOR_LEN] {
        &self.authenticator
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
