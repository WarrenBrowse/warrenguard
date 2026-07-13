//! Cross-implementation proof that a TypeScript blind-RSA token client mints a
//! Privacy Pass token this engine's exit accepts.
//!
//! The frozen `EDGE_JS_TOKEN_HEX` below is emitted by the TS test
//! `packages/core/test/edge.token.test.ts`, minted against the FIXED issuer key
//! `IssuerSecretKey::generate(seed 0xED9E5EED)` (its n/e/d were exported to the
//! TS test once). This test rebuilds that issuer's public key and asserts
//! `verify_token` accepts the token: the TS RSABSSA-SHA384-PSS-Deterministic
//! blind+finalize path is byte-for-byte compatible with the Rust
//! `blind_rsa_signatures` verifier. Any drift (PSS salt, hash, token_input
//! layout, key id) flips the signature and fails verification.

use rand::SeedableRng;
use warrenguard_token::IssuerSecretKey;

/// Emitted by the TS token test: a token over token_type 0x0002, nonce 0x11*32,
/// challenge_digest 0x22*32, and this issuer's key id.
const EDGE_JS_TOKEN_HEX: &str = "000211111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222ad4229a4eea9ada97d55c227b90f95c33b021890b8a7c2a52312062f12d558099ff7115e1a0cf3b83bf39d5fcf666b1f5e90cf578ff219b2b7c4a689282bbac5f855ccd5e34cdddaa586a7aa89ac68112d279ff57350ac30e0ff2c4279a5715c5f745b556813357c0be6c1470f21f9b2e7cbb5accc9ed3fe63a5cb9728827c5380b40571cb4f462c48fa9697d6dd5ede530dbab8a829cebcfe28227d0ff96eb4a4ae8a16258aee285bdd924d6c63080175c32ecdd988586434789902871da04aabde21d851015ca9c10b2231931d5bfc97f40b4c8a8d3c54814ca279c1c4202806f254e94faaa67e4325097d3817029631c0364ee3a19576f7c8c238b90e9fb21b6c308292564a471e97c1db709d731a5ed8cdc577f0782c45692abce6542c9c";

#[test]
fn exit_verifies_a_token_minted_by_the_typescript_client() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xED9E_5EED);
    let sk = IssuerSecretKey::generate(&mut rng).expect("fixed issuer keygen");
    let pk = sk.public_key();

    let token_bytes = hex::decode(EDGE_JS_TOKEN_HEX).expect("valid hex");
    let token = warrenguard_token::Token::parse(&token_bytes).expect("TS token parses");

    pk.verify_token(&token)
        .expect("the exit must verify the token minted by the TS blind-RSA client");
}
