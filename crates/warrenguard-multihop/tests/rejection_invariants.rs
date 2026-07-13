//! Negative-path invariants for [`warrenguard_multihop::ExitSession::open`] and
//! a `proptest` bijection over random payloads.
//!
//! Each test below tampers with exactly one piece of the wire-format
//! state (version byte, epoch, seq, exit_id, ciphertext, tag) and
//! verifies that the receive path rejects the frame. These invariants
//! map to the threat-model rejections.

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{
    ClientSession, ExitId, ExitSession, MultihopError, WARREN_HPKE_VERSION, WarrenMultihopFrame,
};

const EXIT_IKM: [u8; 32] = [0x42; 32];
const RNG_SEED: [u8; 32] = [0x11; 32];
const EXIT_ID: [u8; 16] = [0xA5; 16];

fn fresh_pair() -> (ClientSession, ExitSession) {
    let (exit_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED);
    let exit_id = ExitId::from_bytes(EXIT_ID);
    let client = ClientSession::new(&exit_pub, exit_id, &mut rng).expect("client setup");
    let exit =
        ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id).expect("exit setup");
    (client, exit)
}

// =============================================================================
// Property test: bijection seal/open over random payloads
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// For any payload of length in `1..=1232`, sealing with a fresh
    /// session and opening on the matching exit recovers the plaintext
    /// unchanged. 1232 is the RFC 9221 max useful datagram payload at
    /// MTU 1280; below that bound is the entire data-plane domain.
    #[test]
    fn seal_open_bijection_random_payloads(payload in proptest::collection::vec(any::<u8>(), 1..=1232)) {
        let (client, exit) = fresh_pair();
        let frame = client.seal(&payload, 0, 0).expect("seal");
        let recovered = exit.open(&frame).expect("open");
        prop_assert_eq!(recovered, payload);
    }

    /// Same bijection across a random `(epoch, seq)` pair. Confirms
    /// per-packet key derivation is consistent on both sides for any
    /// AAD input.
    #[test]
    fn seal_open_bijection_random_epoch_seq(
        epoch in any::<u32>(),
        seq in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 1..=512),
    ) {
        let (client, exit) = fresh_pair();
        let frame = client.seal(&payload, epoch, seq).expect("seal");
        let recovered = exit.open(&frame).expect("open");
        prop_assert_eq!(recovered, payload);
    }
}

// =============================================================================
// Negative-path invariants
// =============================================================================

fn tampered_frame_with<F: FnOnce(&mut WarrenMultihopFrame)>(
    mutator: F,
) -> (WarrenMultihopFrame, ExitSession) {
    let (client, exit) = fresh_pair();
    let mut frame = client
        .seal(b"warren multihop tamper victim", 3, 1234)
        .expect("seal");
    mutator(&mut frame);
    (frame, exit)
}

#[test]
fn version_mismatch_rejected_on_open() {
    let (frame, exit) = tampered_frame_with(|f| f.version = 0x02);
    match exit.open(&frame) {
        Err(MultihopError::UnsupportedVersion { got, expected }) => {
            assert_eq!(got, 0x02);
            assert_eq!(expected, WARREN_HPKE_VERSION);
        }
        Ok(_) => panic!("open accepted a frame with bogus version 0x02"),
        Err(other) => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn exit_id_mismatch_rejected_on_open() {
    // The frame's exit_id is flipped to a different UUID. The exit-side
    // identity check must reject before reaching the AEAD layer.
    let (frame, exit) = tampered_frame_with(|f| f.exit_id = ExitId::from_bytes([0x77; 16]));
    match exit.open(&frame) {
        Err(MultihopError::ExitIdMismatch) => {}
        Ok(_) => panic!("open accepted a frame addressed to a different exit"),
        Err(other) => panic!("expected ExitIdMismatch, got {other:?}"),
    }
}

#[test]
fn epoch_modified_in_aad_rejected_on_open() {
    // The frame carries epoch=3 in the AAD that was used to seal. We
    // overwrite to 0xFFFF_FFFE. The exit recomputes the AAD with the new
    // epoch and the AEAD tag check must fail.
    let (frame, exit) = tampered_frame_with(|f| f.epoch = 0xFFFF_FFFE);
    let err = exit.open(&frame).expect_err("flipped epoch must fail open");
    assert!(matches!(err, MultihopError::Hpke(_)));
}

#[test]
fn seq_modified_in_aad_rejected_on_open() {
    // Same logic for the seq field. This is the wire-level pillar of
    // the anti-replay design: any replay attempt that forwards an old
    // frame with a fresh seq breaks AAD authentication.
    let (frame, exit) = tampered_frame_with(|f| f.seq = 0xDEAD_BEEF_CAFE_BABE);
    let err = exit.open(&frame).expect_err("flipped seq must fail open");
    assert!(matches!(err, MultihopError::Hpke(_)));
}

#[test]
fn ciphertext_byte_flip_fails_auth() {
    let (frame, exit) = tampered_frame_with(|f| {
        let last = f.ciphertext.len() - 1;
        f.ciphertext[last] ^= 0x01;
    });
    let err = exit
        .open(&frame)
        .expect_err("ciphertext flip must fail AEAD verification");
    assert!(matches!(err, MultihopError::Hpke(_)));
}

#[test]
fn aead_tag_byte_flip_fails_auth() {
    let (frame, exit) = tampered_frame_with(|f| f.aead_tag[0] ^= 0xFF);
    let err = exit.open(&frame).expect_err("tag flip must fail open");
    assert!(matches!(err, MultihopError::Hpke(_)));
}

#[test]
fn truncated_ciphertext_in_frame_rejected_on_open() {
    let (frame, exit) = tampered_frame_with(|f| {
        f.ciphertext.truncate(f.ciphertext.len() / 2);
    });
    let err = exit
        .open(&frame)
        .expect_err("truncated ciphertext must fail AEAD verification");
    assert!(matches!(err, MultihopError::Hpke(_)));
}

#[test]
fn encapsulated_key_tampered_rejected_on_open() {
    // If the encapsulated_key is replaced with garbage, the receiver
    // can't decap. Since `ExitSession::new` runs once at session start
    // with the *original* encapped_key, the per-packet path only sees
    // the AAD/tag mismatch when the wire-level encapped_key field is
    // overwritten. This test reconstructs an exit from a fresh tampered
    // encapped_key to exercise the decap path explicitly.
    let (exit_priv, _exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let bogus_encapped = [0xFFu8; 32]; // Not a valid X25519 ephemeral pubkey: contains the high bit pattern that fails on-curve check.
    let exit_id = ExitId::from_bytes(EXIT_ID);
    let result = ExitSession::new(&exit_priv, &bogus_encapped, exit_id);
    if let Ok(exit) = result {
        // Some bogus byte patterns happen to land on the curve. In that
        // case, the AAD/tag of any real frame would still mismatch, so
        // we sanity-check that the resulting session refuses a sealed
        // frame from a genuine sender.
        let (client, _) = fresh_pair();
        let frame = client.seal(b"x", 0, 0).expect("seal");
        let err = exit
            .open(&frame)
            .expect_err("bogus encapped_key cannot decrypt genuine frames");
        assert!(matches!(err, MultihopError::Hpke(_)));
    }
    // If `ExitSession::new` already returned an Err, the contract is also
    // satisfied: a bogus encapped_key was rejected at the decap step.
}
