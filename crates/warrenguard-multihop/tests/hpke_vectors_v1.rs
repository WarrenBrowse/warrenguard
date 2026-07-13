//! Frozen HPKE Warren `/v1` test vectors.
//!
//! These vectors pin the *exact* byte output of:
//! - the X25519 derive-keypair stage,
//! - the HPKE setup_sender with a deterministically seeded `ChaCha20Rng`,
//! - the per-packet AEAD key derivation via `AeadCtxS::export`,
//! - and the `ChaCha20Poly1305` seal under the v1 AAD layout.
//!
//! Any change to any of those stages (suite, info string, AAD prefix,
//! AAD field ordering, per-packet export info layout, nonce, padding
//! semantics, ...) MUST flip at least one expected byte and therefore
//! fail at least one assertion below. That is the wire-format
//! regression detector for `/v1`: golden vectors are the wire contract,
//! so no wire-format change lands without a vector test that catches it.
//!
//! Regenerate with:
//!
//! ```sh
//! ./scripts/dev/cargo-test-nofw.sh run -p warrenguard-multihop --example gen_hpke_vectors_v1
//! ```
//!
//! and paste the new bytes into the consts below. Doing so is an
//! intentional `/v1` -> `/v2` bump and MUST be reviewed by a human.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{ClientSession, ExitId, ExitSession, WarrenMultihopFrame};

// =============================================================================
// Vector ZERO
// exit_ikm = [0u8; 32], rng_seed = [1u8; 32], exit_id = [0; 16]
// epoch = 0, seq = 0, payload = [0xAA; 64]
// =============================================================================

const ZERO_EXIT_IKM: [u8; 32] = [0u8; 32];
const ZERO_RNG_SEED: [u8; 32] = [1u8; 32];
const ZERO_EXIT_ID: [u8; 16] = [0u8; 16];
const ZERO_EPOCH: u32 = 0;
const ZERO_SEQ: u64 = 0;
const ZERO_PAYLOAD: [u8; 64] = [0xAA; 64];

const EXPECTED_ZERO_ENCAPPED_KEY: [u8; 32] = [
    0xe9, 0xc8, 0x3d, 0x33, 0xc3, 0xe2, 0xb9, 0x36, 0x52, 0x02, 0x71, 0x6a, 0x80, 0x44, 0x33, 0xe1,
    0x31, 0xdb, 0xff, 0x85, 0x50, 0x41, 0x66, 0xa8, 0x6e, 0xfb, 0x9c, 0x8e, 0x22, 0xfb, 0xf4, 0x74,
];
const EXPECTED_ZERO_AEAD_TAG: [u8; 16] = [
    0x24, 0x12, 0x41, 0x63, 0x19, 0xcc, 0x8c, 0x1c, 0x6e, 0x5e, 0xf8, 0xcb, 0x5e, 0x86, 0xeb, 0x94,
];
const EXPECTED_ZERO_CIPHERTEXT: [u8; 64] = [
    0x5d, 0xf4, 0xea, 0xd0, 0xe3, 0x01, 0x16, 0x15, 0xdb, 0x19, 0xcd, 0xcc, 0xcf, 0x1b, 0x7a, 0x48,
    0xd3, 0x85, 0x1b, 0xb7, 0x1c, 0xea, 0x04, 0xb9, 0x46, 0x36, 0x04, 0x58, 0xe8, 0x8b, 0xe3, 0xa8,
    0x13, 0x4f, 0x2d, 0xf6, 0xb2, 0xff, 0xa0, 0xf4, 0xc9, 0x40, 0x11, 0x58, 0x9f, 0x05, 0xfe, 0xdb,
    0xab, 0x8c, 0x1a, 0xf9, 0x11, 0xce, 0x3c, 0xf3, 0x7a, 0x35, 0x04, 0x17, 0x44, 0x49, 0xa1, 0xc8,
];

// =============================================================================
// Vector AB
// exit_ikm = [0xAB; 32], rng_seed = [0xCD; 32], exit_id = 0xE0..0xEF
// epoch = 7, seq = 12345, payload = [0x42 + i mod 256; 128]
// =============================================================================

const AB_EXIT_IKM: [u8; 32] = [0xABu8; 32];
const AB_RNG_SEED: [u8; 32] = [0xCDu8; 32];
const AB_EXIT_ID: [u8; 16] = [
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
];
const AB_EPOCH: u32 = 7;
const AB_SEQ: u64 = 12_345;

fn ab_payload() -> [u8; 128] {
    let mut p = [0u8; 128];
    for (i, b) in p.iter_mut().enumerate() {
        *b = (0x42u8).wrapping_add(i as u8);
    }
    p
}

const EXPECTED_AB_ENCAPPED_KEY: [u8; 32] = [
    0xb2, 0x76, 0x86, 0x2d, 0x78, 0x91, 0xd2, 0xde, 0xc9, 0xf9, 0xb4, 0x8d, 0x6b, 0xdb, 0x3e, 0x28,
    0x8e, 0xde, 0xb2, 0xb7, 0xff, 0x5e, 0xbd, 0x3a, 0x04, 0x47, 0x22, 0x7f, 0x81, 0x2d, 0xce, 0x3f,
];
const EXPECTED_AB_AEAD_TAG: [u8; 16] = [
    0x1f, 0xd6, 0x28, 0xbd, 0x29, 0x21, 0x72, 0x35, 0x6c, 0xf1, 0x79, 0x4e, 0x16, 0x2b, 0x3c, 0x33,
];
const EXPECTED_AB_CIPHERTEXT: [u8; 128] = [
    0x5f, 0xcf, 0x61, 0x17, 0x4f, 0xb3, 0x3a, 0x97, 0xc5, 0x32, 0x38, 0xad, 0x4d, 0x2e, 0xb5, 0x7b,
    0xa5, 0x7b, 0xe4, 0x43, 0xef, 0x4a, 0xa2, 0xa7, 0xac, 0x9f, 0x3d, 0x0d, 0xe4, 0x1c, 0xd7, 0xfb,
    0x64, 0x93, 0x57, 0x05, 0xfb, 0xb4, 0x5a, 0xe7, 0x3d, 0x88, 0xb8, 0x74, 0xc8, 0x2e, 0x13, 0x51,
    0x27, 0xd6, 0x42, 0x38, 0x25, 0x8d, 0xcc, 0x87, 0x8c, 0x8a, 0x36, 0xe0, 0x5a, 0x38, 0xaf, 0x10,
    0xeb, 0xd2, 0x1a, 0xfc, 0xc3, 0xb1, 0x0f, 0x16, 0xa0, 0xd7, 0xd0, 0x2a, 0x2e, 0x36, 0x5d, 0x0b,
    0xe1, 0xc8, 0xc1, 0x90, 0xa3, 0xd5, 0x56, 0x40, 0xa5, 0x01, 0xb1, 0xde, 0x51, 0x22, 0x32, 0xa8,
    0x54, 0x10, 0x69, 0x2b, 0xaa, 0xcf, 0x19, 0x85, 0x90, 0x81, 0x9c, 0xfc, 0x94, 0x9d, 0x4d, 0x92,
    0x47, 0x90, 0xb7, 0x26, 0x1c, 0xb4, 0xca, 0xbe, 0x20, 0x61, 0x16, 0xd9, 0x51, 0x9e, 0xaf, 0xde,
];

// =============================================================================
// Vector MAX
// exit_ikm = [0x37; 32], rng_seed = [0x5C; 32], exit_id = [0xDE; 16]
// epoch = u32::MAX - 1, seq = u64::MAX - 1, payload = [0xCC; 1232]
// (1232 = max useful RFC 9221 datagram payload at MTU 1280)
// =============================================================================

const MAX_EXIT_IKM: [u8; 32] = [0x37u8; 32];
const MAX_RNG_SEED: [u8; 32] = [0x5Cu8; 32];
const MAX_EXIT_ID: [u8; 16] = [0xDE; 16];
const MAX_EPOCH: u32 = u32::MAX - 1;
const MAX_SEQ: u64 = u64::MAX - 1;
const MAX_PAYLOAD: [u8; 1232] = [0xCC; 1232];

const EXPECTED_MAX_ENCAPPED_KEY: [u8; 32] = [
    0xa6, 0x9f, 0x82, 0x06, 0x94, 0xe5, 0x30, 0x8d, 0x6a, 0x9e, 0x88, 0x8f, 0xfa, 0x74, 0x45, 0x89,
    0x13, 0xba, 0x3b, 0xf0, 0xf3, 0x1f, 0x14, 0x91, 0xfe, 0x91, 0xd9, 0x58, 0xba, 0x90, 0x0b, 0x28,
];
const EXPECTED_MAX_AEAD_TAG: [u8; 16] = [
    0x66, 0xd5, 0x79, 0x50, 0xd3, 0xf4, 0x2c, 0x4c, 0xde, 0x4f, 0x0c, 0x1b, 0x73, 0x36, 0xe9, 0xaf,
];
const EXPECTED_MAX_CIPHERTEXT: &[u8; 1232] = include_bytes!("hpke_vector_max_ciphertext.bin");

// =============================================================================
// Helpers
// =============================================================================

fn seal_one(
    exit_ikm: &[u8],
    rng_seed: [u8; 32],
    exit_id_bytes: [u8; 16],
    epoch: u32,
    seq: u64,
    payload: &[u8],
) -> (WarrenMultihopFrame, ExitSession) {
    let (exit_priv, exit_pub) = derive_exit_keypair(exit_ikm);
    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    let exit_id = ExitId::from_bytes(exit_id_bytes);
    let client = ClientSession::new(&exit_pub, exit_id, &mut rng).expect("client setup_sender");
    let frame = client.seal(payload, epoch, seq).expect("seal");
    let exit = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
        .expect("exit setup_receiver");
    (frame, exit)
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn seed_zero_v1_encrypt_matches_frozen_bytes() {
    let (frame, _exit) = seal_one(
        &ZERO_EXIT_IKM,
        ZERO_RNG_SEED,
        ZERO_EXIT_ID,
        ZERO_EPOCH,
        ZERO_SEQ,
        &ZERO_PAYLOAD,
    );
    assert_eq!(
        frame.encapsulated_key, EXPECTED_ZERO_ENCAPPED_KEY,
        "encapsulated_key drifted from v1 vector ZERO"
    );
    assert_eq!(
        frame.aead_tag, EXPECTED_ZERO_AEAD_TAG,
        "aead_tag drifted from v1 vector ZERO"
    );
    assert_eq!(
        frame.ciphertext, EXPECTED_ZERO_CIPHERTEXT,
        "ciphertext drifted from v1 vector ZERO"
    );
}

#[test]
fn seed_zero_v1_decrypt_matches_payload() {
    let (frame, exit) = seal_one(
        &ZERO_EXIT_IKM,
        ZERO_RNG_SEED,
        ZERO_EXIT_ID,
        ZERO_EPOCH,
        ZERO_SEQ,
        &ZERO_PAYLOAD,
    );
    let recovered = exit.open(&frame).expect("open");
    assert_eq!(recovered, ZERO_PAYLOAD);
}

#[test]
fn seed_ab_v1_encrypt_matches_frozen_bytes() {
    let payload = ab_payload();
    let (frame, _exit) = seal_one(
        &AB_EXIT_IKM,
        AB_RNG_SEED,
        AB_EXIT_ID,
        AB_EPOCH,
        AB_SEQ,
        &payload,
    );
    assert_eq!(frame.encapsulated_key, EXPECTED_AB_ENCAPPED_KEY);
    assert_eq!(frame.aead_tag, EXPECTED_AB_AEAD_TAG);
    assert_eq!(frame.ciphertext, EXPECTED_AB_CIPHERTEXT);
}

#[test]
fn seed_ab_v1_decrypt_matches_payload() {
    let payload = ab_payload();
    let (frame, exit) = seal_one(
        &AB_EXIT_IKM,
        AB_RNG_SEED,
        AB_EXIT_ID,
        AB_EPOCH,
        AB_SEQ,
        &payload,
    );
    let recovered = exit.open(&frame).expect("open");
    assert_eq!(recovered, payload);
}

#[test]
fn seed_max_payload_v1_encrypt_matches_frozen_bytes() {
    let (frame, _exit) = seal_one(
        &MAX_EXIT_IKM,
        MAX_RNG_SEED,
        MAX_EXIT_ID,
        MAX_EPOCH,
        MAX_SEQ,
        &MAX_PAYLOAD,
    );
    assert_eq!(frame.encapsulated_key, EXPECTED_MAX_ENCAPPED_KEY);
    assert_eq!(frame.aead_tag, EXPECTED_MAX_AEAD_TAG);
    assert_eq!(
        &frame.ciphertext[..],
        &EXPECTED_MAX_CIPHERTEXT[..],
        "max-size ciphertext drifted from v1 vector"
    );
    assert_eq!(frame.ciphertext.len(), 1232);
}

#[test]
fn seed_max_payload_v1_decrypt_matches_payload() {
    let (frame, exit) = seal_one(
        &MAX_EXIT_IKM,
        MAX_RNG_SEED,
        MAX_EXIT_ID,
        MAX_EPOCH,
        MAX_SEQ,
        &MAX_PAYLOAD,
    );
    let recovered = exit.open(&frame).expect("open");
    assert_eq!(recovered.len(), 1232);
    assert_eq!(recovered, &MAX_PAYLOAD[..]);
}
