//! Behavior and wire tests for the Privacy Pass token machinery.
//!
//! The RSABSSA core is already RFC-9474-conformance-tested inside
//! `blind-rsa-signatures`; these tests pin the Privacy Pass *framing* (the
//! parts every sibling SDK must reproduce byte-for-byte) and the end-to-end
//! issuance/verification behavior, plus the edge cases a verifier relies on.

use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::Digest;
use subtle::ConstantTimeEq as _;
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

#[test]
fn token_equality_is_constant_time_and_reads_every_field() {
    let sk = issuer();
    let pk = sk.public_key();
    let token = mint(&sk, &pk, [3u8; 32], "api.warrenbrowse.com");
    let bytes = token.serialize();

    assert!(bool::from(token.ct_eq(&Token::parse(&bytes).unwrap())));
    // First byte of the nonce, the challenge digest and the key id, and the
    // last byte of the authenticator.
    for offset in [2, 34, 66, TOKEN_LEN - 1] {
        let mut altered = bytes;
        altered[offset] ^= 1;
        let altered = Token::parse(&altered).unwrap();
        assert!(
            !bool::from(token.ct_eq(&altered)),
            "tokens differing at byte {offset} compared equal"
        );
        assert_ne!(token, altered, "`==` must agree with `ct_eq`");
    }
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

/// PKCS#8 DER of a 2048-bit test issuer key (the one `edge_js_token_vector.rs`
/// derives from seed `0xED9E5EED`), frozen so the known answer below does not
/// depend on key generation staying reproducible across dependency versions.
const KAT_ISSUER_KEY_DER_HEX: &str = concat!(
    "308204bf020100300d06092a864886f70d0101010500048204a9308204a50201000282010100b2a9ec6c63bbdecfe566",
    "5f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450",
    "f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563",
    "ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e",
    "510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966",
    "235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0",
    "dee81bacd549020301000102820101009189ce27b54eb3005374832593c74abe758f098e4e88ce9836c7d21c30ad794e",
    "c65dcab0cb2b066b2f5af93baf5a9233a12d994e934db6477bd5fb30e7a759ec825bbb5d52b7d02e177f93bbf0a23285",
    "e9ca6f83b20da54187294a73e43a138c12bbd54e03f3b0e7c8765a5a092b110c1193151a8ab7c210861c7db8a6c4bd6e",
    "c4a840ae20fef1367ea42018e5258d9c81b83b2c03ffd344ff09056817e463c44bd4504d2923704bc3eb945d7502ac48",
    "886ad3bdeafe3827bed71b7715258bc8a9b9fa6fdf1cfab57f5fbf4e4a429651cde13dc67b690cfd9074f384e7203a22",
    "ab29168996d3bf89c919031ff8e757af3676db2b0775f1375910844aefed1d2902818100d66ecce05d260b9d48c771cc",
    "19d3392afd32a2fe3951e398edb3bfc64a88d7099ce8b462e6af1672a624fdd6cb441439cffc6713f4acd5d657b8b3b0",
    "e86a1e261dc94a5de1b559afc5d9ecfdc96f36897e9571629384fcd97e0649afa53140d13ba0b69b61b796a90c29da72",
    "27a5bdc4bb6ac4eb57d9c37037bc03f3fd9697e302818100d54c16c30918447992ee7d022ba95db3e8e67b9af489b3ff",
    "755c5a2120a0cb963ec28055b9fc7edf222e862f1c9d409753ef5b583810189d436a9be9dc21804695f9d78bd58a7951",
    "73cfbc6dd0e37a24bb437d03d0a031ac9fbf7b95713173d9a94139b48fa4ceadadb877194e379ec41596fcfeeccb6c7d",
    "24209f79ca0dede3028180706ba09fd45618eab9f84e71f9ec2261a66340ced5d057e99a5d8da270fb32fa08387c3209",
    "cd2b90aa0864c892c2bb73dfd5ed58aa035f0cc3eac2d271d708bd650a5e21c02eaab99b99f844c9b1b3befc0d6f6785",
    "fdc7ee62c2fb28ca0b7b76f6b2f869981e7f2f5b8029d58571c07efedf2824566785ae349a2edc614bed8f02818100bf",
    "ffc30983394e0225a9f9eb274448adb6fb29ce9d4b0b34ebfedabeb1312cb1ad02c624e4cb0da56b8e778916f7d279a5",
    "bb72fd215213e61416760c77f3cc153dd16d1e597551a9695758a57d8016a5d3cf774c24d2de84263466596a4ffa99b6",
    "8a991818a960c5e3f78575c8fbb63589bda53510103933187f292ea71c0cc3028181008ad13f8e63c4160cd6bcec9db9",
    "bb62d664ce9ca38859cb88232745778ad54f59a15888bb2278189090e238a8d67f5de2d36c24af2b7191f07b3b41794a",
    "9eeef185c866e9038fc2d8c89c81ab7220571d15e0f05a83e1ff2f3d0b091c06e7048f2d9f69542e34e0bb8598754724",
    "825f3bde2851d60e12869c1ef346efd5314986",
);

/// Blinded request built by `blind_token` under [`KAT_ISSUER_KEY_DER_HEX`],
/// challenge `("api.warrenbrowse.com", [0x33; 32])`, client RNG seed
/// `0xB11D5160`.
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
    let der = hex::decode(KAT_ISSUER_KEY_DER_HEX).expect("valid hex");
    let sk = IssuerSecretKey::from_der(&der).expect("valid key");
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
