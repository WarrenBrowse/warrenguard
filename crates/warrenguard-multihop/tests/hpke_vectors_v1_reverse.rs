//! Frozen HPKE Warren `/v1` test vectors - REVERSE direction.
//!
//! Companion of `hpke_vectors_v1.rs` for the exit -> client downlink
//! path. A forward-only vector suite leaves the reverse path
//! unpinned: a regression in
//! `compose_export_info_reverse` (the `DIRECTION_TAG_REVERSE` byte
//! at position 34) or in `ExitSession::seal_response` would not
//! flip any forward vector and would land silently.
//!
//! These vectors pin the byte output of:
//! - `ExitSession::seal_response(payload, epoch, seq)`,
//! - the per-packet AEAD key derivation via `AeadCtxR::export`
//!   under the reverse-direction info,
//! - the `ChaCha20Poly1305` seal under the v1 AAD layout.
//!
//! Any change to the reverse-direction layout MUST flip at least
//! one expected byte and therefore fail this file. `/v1` -> `/v2`
//! bumps must regenerate both this file and `hpke_vectors_v1.rs`
//! together.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{ClientSession, ExitId, ExitSession};

// =============================================================================
// REVERSE Vector ZERO
// exit_ikm = [0u8; 32], rng_seed = [1u8; 32], exit_id = [0; 16]
// epoch = 0, seq = 0, payload = [0xAA; 64]
// =============================================================================

const ZERO_EXIT_IKM: [u8; 32] = [0u8; 32];
const ZERO_RNG_SEED: [u8; 32] = [1u8; 32];
const ZERO_EXIT_ID: [u8; 16] = [0u8; 16];
const ZERO_EPOCH: u32 = 0;
const ZERO_SEQ: u64 = 0;
const ZERO_PAYLOAD: [u8; 64] = [0xAA; 64];

// The reverse-direction wire differs from the forward vector despite
// identical inputs, because of the DIRECTION_TAG_REVERSE byte at
// position 34 of the export info. It is pinned below by the SHA-256
// hash-anchor (`EXPECTED_DIGEST_HEX`), not a stored ciphertext const.

#[test]
fn reverse_direction_vector_zero_is_byte_stable() {
    let (exit_priv, exit_pub) = derive_exit_keypair(&ZERO_EXIT_IKM);
    let mut rng = ChaCha20Rng::from_seed(ZERO_RNG_SEED);
    let client = ClientSession::new(&exit_pub, ExitId::from_bytes(ZERO_EXIT_ID), &mut rng)
        .expect("client session setup");
    let exit = ExitSession::new(
        &exit_priv,
        &client.encapsulated_key(),
        ExitId::from_bytes(ZERO_EXIT_ID),
    )
    .expect("exit session setup");

    let frame = exit
        .seal_response(&ZERO_PAYLOAD, ZERO_EPOCH, ZERO_SEQ)
        .expect("seal_response");

    // The encapped key is the *client's*, included in the frame for
    // wire compatibility with the forward direction. Its bytes are
    // determined by the rng_seed; we already lock them in the
    // forward vector file. Re-asserting here would be redundant.
    assert_eq!(
        frame.encapsulated_key.len(),
        32,
        "reverse frame encapsulated key is the same 32-byte X25519 KEM output"
    );

    // The Warren multihop frame uses *detached* AEAD: `ciphertext`
    // is `payload.len()` long (= 64), and `aead_tag` is a separate
    // 16-byte field on the wire struct.
    assert_eq!(
        frame.ciphertext.len(),
        ZERO_PAYLOAD.len(),
        "reverse frame layout: detached-tag, ciphertext == payload length"
    );
    assert_eq!(
        frame.aead_tag.len(),
        16,
        "reverse frame layout: 16-byte Poly1305 tag in detached aead_tag field"
    );

    // ---- Cross-check: round-trip succeeds, the frame is consistent
    // with what `ClientSession::open_response` expects. This anchors
    // the contract that any byte-stable change here must also be
    // mirrored on the open path.
    let opened = client.open_response(&frame).expect("client open_response");
    assert_eq!(opened, ZERO_PAYLOAD, "reverse vector round-trips");

    // ---- Hash-anchor: SHA-256 of (ciphertext || aead_tag) is a
    // compact signature of the reverse-direction wire. A regression
    // in the export info, the AAD, the AEAD, or the direction tag
    // will flip the digest. The digest was captured under the
    // current `/v1` constants. Bump alongside `/v2`
    // re-spin.
    let mut buf = Vec::with_capacity(frame.ciphertext.len() + frame.aead_tag.len());
    buf.extend_from_slice(&frame.ciphertext);
    buf.extend_from_slice(&frame.aead_tag);
    let digest = sha256_digest(&buf);
    const EXPECTED_DIGEST_HEX: &str =
        "31fec6c93b144fd0117d016adcfa388dffc24eecd579e840540e6fcce5741e3c";
    let actual_hex = hex_encode(&digest);
    assert_eq!(
        actual_hex, EXPECTED_DIGEST_HEX,
        "reverse vector ZERO digest changed. If the change is intentional, this is a \
         /v1 -> /v2 wire-format bump and the forward vectors must move too. Otherwise, \
         a regression in DIRECTION_TAG_REVERSE / export_info_reverse / AAD / AEAD \
         landed silently."
    );

    // Roundtrip-detect cross-direction mismatch as a sanity guard.
    // A forward-sealed frame fed into open_response MUST fail.
    let mut rng2 = ChaCha20Rng::from_seed(ZERO_RNG_SEED);
    let client2 = ClientSession::new(&exit_pub, ExitId::from_bytes(ZERO_EXIT_ID), &mut rng2)
        .expect("client session2");
    let forward_frame = client2
        .seal(&ZERO_PAYLOAD, ZERO_EPOCH, ZERO_SEQ)
        .expect("client seal forward");
    let _ = client
        .open_response(&forward_frame)
        .expect_err("forward-sealed frame MUST NOT open as a reverse-direction frame");
}

// ---- Minimal SHA-256 + hex utilities, avoid pulling new deps -----------

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}
