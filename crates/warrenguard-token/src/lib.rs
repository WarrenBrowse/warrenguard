//! Privacy Pass publicly-verifiable anonymous credentials (WarrenGuard engine).
//!
//! This crate implements the generic Privacy Pass token machinery for
//! **token type `0x0002`** (publicly verifiable, RFC 9578), whose issuance
//! uses **RSABSSA-SHA384-PSS-Deterministic** blind RSA signatures (RFC 9474).
//! It carries no Warren-specific policy: epochs, per-account quotas and
//! subscription checks are the deployer's business (the deployer's own
//! issuer and verifier services). The point of the split is that the
//! wire format and the cryptographic verification live here, once, and are
//! reused byte-for-byte by every consumer (the deployer's issuer service, its
//! verifier, and each language SDK through FFI or a replayed golden vector).
//!
//! # Why this design
//!
//! - **Publicly verifiable** (blind RSA, not a VOPRF): a verifier needs only
//!   the issuer's public key, so a verifier checks a token entirely offline. A
//!   compromised verifier cannot mint tokens (it has no secret), and
//!   verification never calls home, so the availability/fail-open properties
//!   of the data plane are preserved.
//! - **Blindness**: the issuer signs a blinded message and cannot correlate
//!   the token it later sees at redemption with the issuance request. That is
//!   the whole anonymity guarantee, and it rests on the audited blind-RSA core
//!   ([`blind_rsa_signatures`]); this crate only frames the Privacy Pass token
//!   around it.
//!
//! # Roles
//!
//! - Issuer holds an [`IssuerSecretKey`] and answers a blinded request with
//!   [`IssuerSecretKey::blind_sign`].
//! - Client holds only the [`IssuerPublicKey`]; it builds a blinded request
//!   with [`IssuerPublicKey::blind_token`], sends it to the issuer, and turns
//!   the blind signature into a [`Token`] with
//!   [`IssuerPublicKey::finalize_token`].
//! - Verifier holds the [`IssuerPublicKey`] and calls
//!   [`IssuerPublicKey::verify_token`]; the anti-double-spend ledger keys on
//!   [`Token::serial`].

#![forbid(unsafe_code)]

mod challenge;
mod client;
mod issuer;
mod token;

pub use challenge::{TOKEN_TYPE_BLIND_RSA, TokenChallenge};
pub use client::ClientState;
pub use issuer::{IssuerKeyId, IssuerPublicKey, IssuerSecretKey};
pub use token::{
    AUTHENTICATOR_LEN, CHALLENGE_DIGEST_LEN, NONCE_LEN, TOKEN_INPUT_LEN, TOKEN_KEY_ID_LEN,
    TOKEN_LEN, Token, TokenSerial,
};

/// Errors returned by the Privacy Pass token machinery.
///
/// Deliberately coarse and value-free: no secret or identifying material is
/// ever placed in an error (no nonce, no key bytes), so an error is safe to
/// log or surface across an FFI boundary.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// A `redemption_context` was neither empty nor exactly 32 bytes, or an
    /// `issuer_name` / `origin_info` exceeded the `u16` length limit.
    #[error("token challenge field has an invalid length")]
    InvalidChallengeField,
    /// A serialized token did not match the fixed `0x0002` layout (wrong total
    /// length, wrong token type, or trailing bytes).
    #[error("token wire encoding is malformed")]
    MalformedToken,
    /// An issuer key could not be parsed or serialized (bad DER/SPKI, or a
    /// modulus outside the supported 2048..=4096-bit range).
    #[error("issuer key is invalid")]
    InvalidKey,
    /// A blinded request or blind signature had the wrong size for the issuer
    /// modulus, or the blind-RSA operation failed.
    #[error("blind signature operation failed")]
    BlindOperation,
    /// The token's authenticator did not verify against the issuer public key,
    /// or the token's `token_key_id` did not match the verifying key.
    #[error("token verification failed")]
    VerificationFailed,
}
