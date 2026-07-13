//! The `TokenChallenge` structure (RFC 9577 SS2.1) and its digest.

use sha2::{Digest, Sha256};

use crate::TokenError;

/// Privacy Pass token type for publicly-verifiable blind-RSA tokens
/// (RFC 9578 SS8.2.1). This crate implements only this type.
pub const TOKEN_TYPE_BLIND_RSA: u16 = 0x0002;

/// A `TokenChallenge` (RFC 9577 SS2.1). It names the issuer and the redemption
/// context that a token is bound to; its SHA-256 digest is embedded in every
/// [`Token`](crate::Token) so a verifier can confirm the token answers the
/// challenge it expected (in Warren, the epoch lives in `redemption_context`).
///
/// ```text
/// struct {
///     uint16_t token_type;
///     opaque issuer_name<0..2^16-1>;
///     opaque redemption_context<0..32>;
///     opaque origin_info<0..2^16-1>;
/// } TokenChallenge;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenChallenge {
    token_type: u16,
    issuer_name: Vec<u8>,
    redemption_context: Vec<u8>,
    origin_info: Vec<u8>,
}

impl TokenChallenge {
    /// Builds a challenge for [`TOKEN_TYPE_BLIND_RSA`].
    ///
    /// `redemption_context` MUST be empty or exactly 32 bytes (RFC 9577);
    /// `issuer_name` and `origin_info` MUST each fit in a `u16` length prefix.
    /// A caller that binds an epoch passes it as a 32-byte context (see
    /// [`TokenChallenge::for_context`]).
    ///
    /// # Errors
    /// [`TokenError::InvalidChallengeField`] if any length rule is violated.
    pub fn new(
        issuer_name: &str,
        redemption_context: &[u8],
        origin_info: &[u8],
    ) -> Result<Self, TokenError> {
        if !redemption_context.is_empty() && redemption_context.len() != 32 {
            return Err(TokenError::InvalidChallengeField);
        }
        if issuer_name.len() > u16::MAX as usize || origin_info.len() > u16::MAX as usize {
            return Err(TokenError::InvalidChallengeField);
        }
        Ok(Self {
            token_type: TOKEN_TYPE_BLIND_RSA,
            issuer_name: issuer_name.as_bytes().to_vec(),
            redemption_context: redemption_context.to_vec(),
            origin_info: origin_info.to_vec(),
        })
    }

    /// Convenience constructor for the common Warren shape: a named issuer, a
    /// 32-byte redemption context (the domain-separated epoch), and no
    /// `origin_info` (tokens are not origin-scoped).
    ///
    /// # Errors
    /// [`TokenError::InvalidChallengeField`] if `issuer_name` overflows a
    /// `u16` length.
    pub fn for_context(
        issuer_name: &str,
        redemption_context: [u8; 32],
    ) -> Result<Self, TokenError> {
        Self::new(issuer_name, &redemption_context, &[])
    }

    /// The epoch-bound Warren challenge: `redemption_context =
    /// SHA-256(context_label || epoch_be64)`, no `origin_info`.
    ///
    /// This derivation is part of the frozen protocol: the issuer, the
    /// verifier, and every SDK client MUST build the identical challenge for
    /// an epoch or tokens will not verify, so it lives here in the engine
    /// rather than being re-derived per consumer.
    ///
    /// # Errors
    /// [`TokenError::InvalidChallengeField`] if `issuer_name` overflows a
    /// `u16` length.
    pub fn for_epoch(
        issuer_name: &str,
        context_label: &str,
        epoch: u64,
    ) -> Result<Self, TokenError> {
        let mut h = Sha256::new();
        h.update(context_label.as_bytes());
        h.update(epoch.to_be_bytes());
        Self::for_context(issuer_name, h.finalize().into())
    }

    /// The token type (always [`TOKEN_TYPE_BLIND_RSA`]).
    #[must_use]
    pub fn token_type(&self) -> u16 {
        self.token_type
    }

    /// The exact wire serialization (RFC 9577 SS2.1). This is the byte string
    /// that gets hashed to produce [`TokenChallenge::digest`]; it is frozen and
    /// pinned by golden vectors.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        // token_type(2) + name_len(2) + name + rc_len(1) + rc + oi_len(2) + oi
        let mut out = Vec::with_capacity(
            2 + 2
                + self.issuer_name.len()
                + 1
                + self.redemption_context.len()
                + 2
                + self.origin_info.len(),
        );
        out.extend_from_slice(&self.token_type.to_be_bytes());
        // `new`/`for_context` guarantee these casts cannot truncate.
        out.extend_from_slice(&(self.issuer_name.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.issuer_name);
        out.push(self.redemption_context.len() as u8);
        out.extend_from_slice(&self.redemption_context);
        out.extend_from_slice(&(self.origin_info.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.origin_info);
        out
    }

    /// `challenge_digest = SHA-256(serialize())` (RFC 9577 SS2.2). This 32-byte
    /// value is what a [`Token`](crate::Token) carries, not the full challenge.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.serialize()).into()
    }
}
