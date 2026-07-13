//! Multi-message session contract for [`warrenguard_multihop::ClientSession`] /
//! [`warrenguard_multihop::ExitSession`].
//!
//! Anchors the design decision: one HPKE setup per `(client, exit)`
//! session, then every
//! datagram is sealed by deriving a per-packet symmetric key from the
//! shared AEAD context's `export()` API. The same context is reused for
//! N seals, the same `AeadCtxR` is reused for N opens, and packets can
//! arrive out of order without breaking decryption (the per-packet key
//! depends only on `(epoch, seq)`, not on the underlying HPKE seq
//! counter).

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{ClientSession, ExitId, ExitSession};

const SESSION_SEED: [u8; 32] = [0x73; 32];
const EXIT_IKM: [u8; 32] = [0x91; 32];
const EXIT_ID: [u8; 16] = [0x55; 16];

fn setup_pair() -> (ClientSession, ExitSession) {
    let (exit_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let mut rng = ChaCha20Rng::from_seed(SESSION_SEED);
    let exit_id = ExitId::from_bytes(EXIT_ID);
    let client = ClientSession::new(&exit_pub, exit_id, &mut rng).expect("client setup");
    let exit =
        ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id).expect("exit setup");
    (client, exit)
}

#[test]
fn seal_open_one_thousand_packets_roundtrip_in_order() {
    let (client, exit) = setup_pair();
    let epoch = 0u32;

    for seq in 0..1_000u64 {
        let mut payload = vec![0u8; 256];
        // Embed `seq` into the payload so a misordering bug would show up
        // as a content mismatch (not just a length mismatch).
        payload[..8].copy_from_slice(&seq.to_be_bytes());
        let frame = client.seal(&payload, epoch, seq).expect("seal");
        let recovered = exit.open(&frame).expect("open");
        assert_eq!(recovered, payload, "payload mismatch at seq {seq}");
    }
}

#[test]
fn seal_open_one_thousand_packets_roundtrip_reverse_order() {
    // Per-packet keys are independent: the exit must accept frames
    // arriving in any order. We seal in order 0..1000, then open in
    // reverse 999..=0. This is the test that fails the moment someone
    // swaps the implementation for one that depends on an
    // auto-incrementing AEAD seq counter (cf. session.rs module doc).
    let (client, exit) = setup_pair();
    let epoch = 1u32;

    let mut frames = Vec::with_capacity(1_000);
    let mut payloads = Vec::with_capacity(1_000);
    for seq in 0..1_000u64 {
        let mut payload = vec![0u8; 128];
        payload[..8].copy_from_slice(&seq.to_be_bytes());
        payloads.push(payload.clone());
        frames.push(client.seal(&payload, epoch, seq).expect("seal"));
    }

    for seq in (0..1_000u64).rev() {
        let idx = seq as usize;
        let recovered = exit.open(&frames[idx]).expect("open out of order");
        assert_eq!(
            recovered, payloads[idx],
            "reverse-order open mismatch at seq {seq}"
        );
    }
}

#[test]
fn encapsulated_key_is_stable_across_session() {
    // The KEM encap runs once at session setup; every sealed frame
    // carries the same 32-byte ephemeral pubkey. The wire layout amortizes
    // the X25519 ECDH cost across the entire session, which is the
    // performance pillar of the multi-message session design.
    let (client, _exit) = setup_pair();
    let expected = client.encapsulated_key();

    for seq in 0..16u64 {
        let frame = client.seal(&[0u8; 32], 0, seq).expect("seal");
        assert_eq!(
            frame.encapsulated_key, expected,
            "encapsulated_key drifted within a session at seq {seq}; \
             multi-message contract broken"
        );
    }
}

#[test]
fn seal_is_deterministic_for_fixed_seq() {
    // Given a fixed `(epoch, seq, payload)` and the same session, two
    // seal() calls must produce identical ciphertext and tag. This is
    // the property that lets the wire format pin frozen vectors; it
    // would silently fail if `seal` ever introduced a fresh nonce or
    // salt per call.
    let (client, _exit) = setup_pair();
    let payload = b"warren multihop deterministic check";
    let f1 = client.seal(payload, 42, 7).expect("first seal");
    let f2 = client.seal(payload, 42, 7).expect("second seal");
    assert_eq!(f1.encapsulated_key, f2.encapsulated_key);
    assert_eq!(f1.aead_tag, f2.aead_tag);
    assert_eq!(f1.ciphertext, f2.ciphertext);
    assert_eq!(f1.epoch, f2.epoch);
    assert_eq!(f1.seq, f2.seq);
}
