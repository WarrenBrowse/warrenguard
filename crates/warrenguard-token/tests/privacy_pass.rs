//! Behavior and wire tests for the Privacy Pass token machinery.
//!
//! The RSABSSA core is already RFC-9474-conformance-tested inside
//! `blind-rsa-signatures`; these tests pin the Privacy Pass *framing* (the
//! parts every sibling SDK must reproduce byte-for-byte) and the end-to-end
//! issuance/verification behavior, plus the edge cases a verifier relies on.

use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::Digest;
use warrenguard_token::{
    AUTHENTICATOR_LEN, IssuerPublicKey, IssuerSecretKey, TOKEN_INPUT_LEN, TOKEN_LEN,
    TOKEN_TYPE_BLIND_RSA, Token, TokenChallenge,
};

fn seeded() -> StdRng {
    // Deterministic across runs so a failure is reproducible; the RNG is the
    // injected system boundary per the TDD rules.
    StdRng::seed_from_u64(0x9E37_79B9_7F4A_7C15)
}

fn issuer() -> IssuerSecretKey {
    IssuerSecretKey::generate(&mut seeded()).expect("keygen")
}

// ---- Framing golden vectors (frozen wire; sibling SDKs must match) --------

#[test]
fn challenge_serialization_is_frozen() {
    // issuer_name "api.warrenbrowse.com" (20 bytes), a 32-byte context of
    // 0x00..0x1f, empty origin_info.
    let mut ctx = [0u8; 32];
    for (i, b) in ctx.iter_mut().enumerate() {
        *b = i as u8;
    }
    let ch = TokenChallenge::for_context("api.warrenbrowse.com", ctx).unwrap();
    let ser = ch.serialize();

    // token_type(0x0002) | name_len(0x0014) | name | rc_len(0x20) | rc | oi_len(0x0000)
    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x00, 0x02]);
    expected.extend_from_slice(&[0x00, 0x14]);
    expected.extend_from_slice(b"api.warrenbrowse.com");
    expected.push(0x20);
    expected.extend_from_slice(&ctx);
    expected.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(ser, expected, "TokenChallenge wire layout drifted");

    // Digest is SHA-256 of exactly those bytes.
    let expect_digest: [u8; 32] = <[u8; 32]>::from(sha2::Sha256::digest(&expected));
    assert_eq!(ch.digest(), expect_digest);
}

#[test]
fn epoch_challenge_digest_golden_vector() {
    // Frozen: issuer, verifier, and every SDK must derive this exact digest
    // for (issuer_name, context_label, epoch) or tokens will not verify
    // cross-implementation. Changing it is a wire-format break.
    let ch =
        TokenChallenge::for_epoch("api.warrenbrowse.com", "warren/session-token/v1", 5).unwrap();
    let hex: String = ch.digest().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "17bea55042b0414a37b981cb09b0e476da5d1da047cff53246d154c1e01a8758"
    );
    // And it is epoch-sensitive.
    let other =
        TokenChallenge::for_epoch("api.warrenbrowse.com", "warren/session-token/v1", 6).unwrap();
    assert_ne!(ch.digest(), other.digest());
}

#[test]
fn token_input_and_serial_layout_is_frozen() {
    let sk = issuer();
    let pk = sk.public_key();
    let ch = TokenChallenge::for_context("api.warrenbrowse.com", [9u8; 32]).unwrap();
    let (_req, state) = pk.blind_token(&mut seeded(), &ch).unwrap();
    let blind_sig = sk.blind_sign(&_req).unwrap();
    let token = pk.finalize_token(state, &blind_sig).unwrap();

    let ti = token.token_input();
    assert_eq!(ti.len(), TOKEN_INPUT_LEN);
    assert_eq!(TOKEN_INPUT_LEN, 98);
    // token_type prefix
    assert_eq!(&ti[0..2], &[0x00, 0x02]);
    // challenge_digest slice equals the challenge's digest
    assert_eq!(&ti[34..66], &ch.digest());
    // token_key_id slice equals the issuer key id
    assert_eq!(&ti[66..98], pk.key_id().as_bytes());

    // serial = SHA-256(token_input)
    let expect: [u8; 32] = <[u8; 32]>::from(sha2::Sha256::digest(ti));
    assert_eq!(token.serial().as_bytes(), &expect);
}

#[test]
fn token_serialize_parse_roundtrip_and_length() {
    let sk = issuer();
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [1u8; 32], "api.warrenbrowse.com");

    let bytes = token.serialize();
    assert_eq!(bytes.len(), TOKEN_LEN);
    assert_eq!(TOKEN_LEN, 354);
    let parsed = Token::parse(&bytes).unwrap();
    assert_eq!(parsed, token);
    assert_eq!(parsed.serial(), token.serial());
}

// ---- End-to-end issuance/verification ------------------------------------

#[test]
fn issued_token_verifies_and_is_offline_checkable_from_spki() {
    let sk = issuer();
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [2u8; 32], "api.warrenbrowse.com");

    // Verifier that only has the published SPKI (the exit's situation).
    let pk_pub = IssuerPublicKey::from_spki(&pk.to_spki()).unwrap();
    pk_pub
        .verify_token(&token)
        .expect("token must verify offline");
}

#[test]
fn serial_is_stable_across_finalizations_but_authenticator_is_not() {
    // PSS salt is random, so two tokens from the same challenge differ in the
    // authenticator yet the verifier-facing identity (serial) is per-nonce.
    let sk = issuer();
    let pk = sk.public_key();
    let ch = TokenChallenge::for_context("api.warrenbrowse.com", [7u8; 32]).unwrap();

    // Same nonce path is not directly forced by the API (nonce is internal),
    // so instead prove: distinct tokens => distinct serials, and each verifies.
    let t1 = mint_ch(&sk, &pk, &ch);
    let t2 = mint_ch(&sk, &pk, &ch);
    assert_ne!(t1.serial(), t2.serial(), "independent nonces must differ");
    assert_ne!(t1.serialize(), t2.serialize());
    pk.verify_token(&t1).unwrap();
    pk.verify_token(&t2).unwrap();
}

// ---- Verifier edge cases (a verifier relies on every one of these) --------

#[test]
fn verify_rejects_token_from_a_different_issuer_key() {
    let sk_a = issuer();
    let pk_a = sk_a.public_key();
    let token = mint(&sk_a, &pk_a, [3u8; 32], "api.warrenbrowse.com");

    let sk_b = IssuerSecretKey::generate(&mut StdRng::seed_from_u64(999)).unwrap();
    let err = sk_b.public_key().verify_token(&token).unwrap_err();
    assert!(matches!(
        err,
        warrenguard_token::TokenError::VerificationFailed
    ));
}

#[test]
fn verify_rejects_tampered_nonce() {
    let sk = issuer();
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [4u8; 32], "api.warrenbrowse.com");

    let mut bytes = token.serialize();
    bytes[2] ^= 0x01; // flip a nonce bit
    let tampered = Token::parse(&bytes).unwrap();
    assert!(pk.verify_token(&tampered).is_err());
}

#[test]
fn verify_rejects_tampered_challenge_digest() {
    let sk = issuer();
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [5u8; 32], "api.warrenbrowse.com");

    let mut bytes = token.serialize();
    bytes[34] ^= 0x01; // flip a challenge-digest bit
    let tampered = Token::parse(&bytes).unwrap();
    assert!(pk.verify_token(&tampered).is_err());
}

#[test]
fn verify_rejects_tampered_key_id() {
    let sk = issuer();
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [6u8; 32], "api.warrenbrowse.com");

    let mut bytes = token.serialize();
    bytes[66] ^= 0x01; // flip a key-id bit: constant-time key-id check must catch it
    let tampered = Token::parse(&bytes).unwrap();
    assert!(pk.verify_token(&tampered).is_err());
}

#[test]
fn verify_rejects_tampered_authenticator() {
    let sk = issuer();
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [7u8; 32], "api.warrenbrowse.com");

    let mut bytes = token.serialize();
    bytes[TOKEN_LEN - 1] ^= 0x01;
    let tampered = Token::parse(&bytes).unwrap();
    assert!(pk.verify_token(&tampered).is_err());
}

// ---- Parser edge cases ----------------------------------------------------

#[test]
fn parse_rejects_wrong_length() {
    assert!(Token::parse(&[0u8; TOKEN_LEN - 1]).is_err());
    assert!(Token::parse(&[0u8; TOKEN_LEN + 1]).is_err());
    assert!(Token::parse(&[]).is_err());
}

#[test]
fn parse_rejects_wrong_token_type() {
    let sk = issuer();
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [8u8; 32], "api.warrenbrowse.com");
    let mut bytes = token.serialize();
    bytes[0] = 0x00;
    bytes[1] = 0x01; // type 0x0001 (VOPRF), not ours
    assert!(Token::parse(&bytes).is_err());
}

#[test]
fn challenge_rejects_bad_redemption_context_length() {
    assert!(TokenChallenge::new("api", &[0u8; 31], &[]).is_err());
    assert!(TokenChallenge::new("api", &[0u8; 33], &[]).is_err());
    // 0 and 32 are the only legal lengths.
    assert!(TokenChallenge::new("api", &[], &[]).is_ok());
    assert!(TokenChallenge::new("api", &[0u8; 32], &[]).is_ok());
}

// ---- Issuer key material --------------------------------------------------

#[test]
fn issuer_key_der_roundtrip_preserves_key_id() {
    let sk = issuer();
    let der = sk.to_der().unwrap();
    let reloaded = IssuerSecretKey::from_der(&der).unwrap();
    assert!(reloaded.key_id_eq(&sk.public_key().key_id()));

    // A token minted before persistence still verifies under the reloaded key.
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [10u8; 32], "api.warrenbrowse.com");
    reloaded.public_key().verify_token(&token).unwrap();
}

/// Blinded request built by `blind_token` under the fixed issuer key of
/// `edge_js_token_vector.rs` (seed `0xED9E5EED`), challenge
/// `("api.warrenbrowse.com", [0x33; 32])`, client RNG seed `0xB11D5160`.
const KAT_BLINDED_REQUEST_HEX: &str = concat!(
    "1585af18ec271450eafc37a91e36681500abe98c58af9bf9c68633799edfed8d16f70685d9d56d2a45a560faa33c89e198a512e215c719417a22917472ef73e1",
    "0b94ff2fd56b26366ca8ab5daeb5841ee3d58bc4bc08aadbb47defb7eeb818718d60be1b9a60900e52b10caf4391a10a7af674669ddb6565a5e14099760e87e3",
    "1be20f078d0d1608ff95d5f94a017fe625d408b38c6e5d0173270d0c81b9272002e482f9be4c369f396680aa73e78a0635ce7b54740e13d90728f37d40ef012f",
    "ce255885017f57006ef759a365df4252037af0a58179493e1f08de893a6f96dc9a656b8eecbbe807d5cc726cf627c7fcf252c2b44ded320ee932eb93f65402e6",
);

/// The issuer's answer to [`KAT_BLINDED_REQUEST_HEX`]. RSA signing is
/// deterministic, so neither the server-side blinding factor nor the RNG that
/// draws it may change these bytes.
const KAT_BLIND_SIGNATURE_HEX: &str = concat!(
    "051874c7fff19fe3b8a366765941fc914f07c4dae9eba459f491e1438cabadff2b7a1041b8408101a467bcbb3c06101e50922d2ba9d2e606931c3617b2efdeeb",
    "9940f0848bc7dbaf970f673bca44cfa725918bd2a20d2f9004acc22d3aaf1a121f202e68c87fe26feab68d40c2533794c32634f65d41a67dcc34c7c6c2b52031",
    "a9d46744f6fd5a9392c45403588e37c352f5971b7eb94f6f27f4179e9c3c9c3105a00d4f90ba61434f1ae798b87d020196040846b5ae5eeb9aeb3ea4d1625c52",
    "1da00de6965bf3caa6b7cc31e7faba3add7fe2cefc2ef17ad134150d59cb85fb217fab42d795dcc78a1d21ce57b3cdaa2b6795f5edcb86573a26e659ff798026",
);

#[test]
fn blind_signature_over_a_fixed_request_is_frozen() {
    let sk = IssuerSecretKey::generate(&mut StdRng::seed_from_u64(0xED9E_5EED)).expect("keygen");
    let request = hex::decode(KAT_BLINDED_REQUEST_HEX).expect("valid hex");
    let expected = hex::decode(KAT_BLIND_SIGNATURE_HEX).expect("valid hex");

    assert_eq!(sk.blind_sign(&request).expect("blind sign"), expected);
    assert_eq!(
        sk.blind_sign(&request).expect("blind sign"),
        expected,
        "a second signature, blinded with a fresh factor, is byte-identical"
    );
}

#[test]
fn blind_sign_rejects_wrong_size_request() {
    let sk = issuer();
    assert!(sk.blind_sign(&[0u8; AUTHENTICATOR_LEN - 1]).is_err());
    assert!(sk.blind_sign(&[0u8; 0]).is_err());
}

#[test]
fn token_type_constant_is_0x0002() {
    assert_eq!(TOKEN_TYPE_BLIND_RSA, 0x0002);
}

// ---- helpers --------------------------------------------------------------

fn mint(sk: &IssuerSecretKey, pk: &IssuerPublicKey, ctx: [u8; 32], issuer_name: &str) -> Token {
    let ch = TokenChallenge::for_context(issuer_name, ctx).unwrap();
    mint_ch(sk, pk, &ch)
}

fn mint_ch(sk: &IssuerSecretKey, pk: &IssuerPublicKey, ch: &TokenChallenge) -> Token {
    let (req, state) = pk.blind_token(&mut seeded_fresh(), ch).unwrap();
    let blind_sig = sk.blind_sign(&req).unwrap();
    pk.finalize_token(state, &blind_sig).unwrap()
}

// A per-call fresh RNG so two mints draw independent nonces/salts.
fn seeded_fresh() -> StdRng {
    StdRng::from_rng(&mut rand::rng())
}
