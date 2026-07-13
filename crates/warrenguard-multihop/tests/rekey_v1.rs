//! HPKE context rotation (rekey) contract.
//!
//! A periodic HPKE context rotation (within 8 h) bounds the AEAD
//! nonce-overflow exposure. The wire-level mechanic is:
//!
//! 1. Client calls [`ClientSession::rekey`] → new ephemeral KEM
//!    keypair, new `encapsulated_key`, internal `epoch += 1`.
//! 2. Client sends the new `encapsulated_key` to the exit at the start
//!    of the new epoch (it travels on every sealed frame in this
//!    crate's wire format, so the relay+exit "first frame of the new
//!    epoch carries the new ephemeral pubkey" semantic falls out for
//!    free).
//! 3. Exit holds the old session active for ~2-5 s of overlap to
//!    process in-flight frames from the previous epoch, then purges
//!    it.
//!
//! These tests pin four properties:
//! - `rotation_after_n_messages_produces_new_epoch_decryptable`
//! - `old_epoch_accepted_during_overlap_period`
//! - `old_epoch_rejected_after_overlap_purge`
//! - `seq_resets_to_zero_on_rekey` (caller-side invariant; the crate
//!   provides the `epoch()` accessor and the documentation pins the
//!   convention).

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{ClientSession, ExitId, ExitSession, MultihopError};

const EXIT_IKM: [u8; 32] = [0x71; 32];
const RNG_SEED_INITIAL: [u8; 32] = [0x33; 32];
const RNG_SEED_REKEY: [u8; 32] = [0x55; 32];
const EXIT_ID: [u8; 16] = [0xBE; 16];

#[test]
fn rekey_advances_epoch_counter_by_one() {
    let (_priv, pub_k) = derive_exit_keypair(&EXIT_IKM);
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client =
        ClientSession::new(&pub_k, ExitId::from_bytes(EXIT_ID), &mut rng).expect("setup");

    assert_eq!(client.epoch(), 0, "fresh session must start at epoch 0");

    let mut rng_rekey = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    client.rekey(&pub_k, &mut rng_rekey).expect("rekey");
    assert_eq!(client.epoch(), 1, "rekey must bump epoch to 1");

    let mut rng_rekey2 = ChaCha20Rng::from_seed([0x77; 32]);
    client.rekey(&pub_k, &mut rng_rekey2).expect("rekey2");
    assert_eq!(client.epoch(), 2, "second rekey must bump epoch to 2");
}

#[test]
fn rekey_changes_encapsulated_key() {
    let (_priv, pub_k) = derive_exit_keypair(&EXIT_IKM);
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client =
        ClientSession::new(&pub_k, ExitId::from_bytes(EXIT_ID), &mut rng).expect("setup");
    let before = client.encapsulated_key();

    let mut rng_rekey = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    let after = client.rekey(&pub_k, &mut rng_rekey).expect("rekey");

    assert_ne!(
        before, after,
        "rekey must produce a fresh ephemeral X25519 pubkey"
    );
    assert_eq!(
        client.encapsulated_key(),
        after,
        "rekey return value must match the new internal encapped_key"
    );
}

#[test]
fn rotation_after_n_messages_produces_new_epoch_decryptable() {
    // Seal 200 frames in epoch 0, then rekey and seal 200 more in
    // epoch 1. Confirm that a fresh exit session bound to each
    // (encapped_key, epoch) pair decrypts every frame in its own
    // epoch, and that the per-packet key derivation never crosses
    // sessions.
    let (priv_k, pub_k) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);

    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client = ClientSession::new(&pub_k, exit_id, &mut rng).expect("setup");

    // Epoch 0.
    let exit_e0 =
        ExitSession::new(&priv_k, &client.encapsulated_key(), exit_id).expect("exit_e0 setup");

    for seq in 0..200u64 {
        let frame = client
            .seal(b"epoch-0 traffic", client.epoch(), seq)
            .expect("seal e0");
        let pt = exit_e0.open(&frame).expect("open e0");
        assert_eq!(pt, b"epoch-0 traffic", "epoch 0 decrypt mismatch at {seq}");
    }

    // Rekey.
    let mut rng_rekey = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    client.rekey(&pub_k, &mut rng_rekey).expect("rekey");
    assert_eq!(client.epoch(), 1);

    // Epoch 1 with a brand-new exit session.
    let exit_e1 =
        ExitSession::new(&priv_k, &client.encapsulated_key(), exit_id).expect("exit_e1 setup");

    for seq in 0..200u64 {
        let frame = client
            .seal(b"epoch-1 traffic", client.epoch(), seq)
            .expect("seal e1");
        let pt = exit_e1.open(&frame).expect("open e1");
        assert_eq!(pt, b"epoch-1 traffic", "epoch 1 decrypt mismatch at {seq}");
    }
}

#[test]
fn old_epoch_accepted_during_overlap_period() {
    // Simulate the 2-5 s overlap where the relay still forwards a
    // straggler frame from epoch=0 after the client started emitting
    // epoch=1 frames. As long as the exit holds onto `exit_e0`, that
    // straggler must decrypt.
    let (priv_k, pub_k) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);

    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client = ClientSession::new(&pub_k, exit_id, &mut rng).expect("setup");

    // Stash a few epoch-0 frames "in flight".
    let mut inflight_e0 = Vec::new();
    for seq in 0..5u64 {
        inflight_e0.push(
            client
                .seal(b"in-flight", client.epoch(), seq)
                .expect("seal pre-rekey"),
        );
    }
    let exit_e0 =
        ExitSession::new(&priv_k, &client.encapsulated_key(), exit_id).expect("exit_e0 setup");

    // Client rekeys.
    let mut rng_rekey = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    client.rekey(&pub_k, &mut rng_rekey).expect("rekey");
    let exit_e1 =
        ExitSession::new(&priv_k, &client.encapsulated_key(), exit_id).expect("exit_e1 setup");

    // Interleave epoch-1 fresh frames with delivery of the in-flight
    // epoch-0 frames. Both must decrypt while the overlap is active.
    let fresh = client.seal(b"new", client.epoch(), 0).expect("fresh seal");
    exit_e1.open(&fresh).expect("new epoch frame opens");

    for frame in &inflight_e0 {
        let pt = exit_e0
            .open(frame)
            .expect("inflight epoch-0 must still open");
        assert_eq!(pt, b"in-flight");
    }
}

#[test]
fn old_epoch_rejected_after_overlap_purge() {
    // After the relay/exit "purges" the old session (drops `exit_e0`),
    // a straggler epoch-0 frame routed to the surviving session must
    // be rejected. The remaining session was set up with the new
    // `encapsulated_key`, so its `AeadCtxR::export` produces keys that
    // never match the epoch-0 wire-level frames.
    let (priv_k, pub_k) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);

    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client = ClientSession::new(&pub_k, exit_id, &mut rng).expect("setup");

    let epoch_0_frame = client.seal(b"old", 0, 0).expect("seal epoch-0");

    let mut rng_rekey = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    client.rekey(&pub_k, &mut rng_rekey).expect("rekey");
    let exit_e1 =
        ExitSession::new(&priv_k, &client.encapsulated_key(), exit_id).expect("exit_e1 setup");

    // The post-purge surviving session refuses the epoch-0 frame.
    let err = exit_e1
        .open(&epoch_0_frame)
        .expect_err("epoch-0 frame must not open on the epoch-1 session");
    assert!(matches!(err, MultihopError::Hpke(_)));
}

#[test]
fn seq_resets_to_zero_convention_after_rekey() {
    // The crate does not track the seq counter internally; the caller
    // does. The seq resets to 0 at rekey. This test pins the contract
    // behaviorally: the caller restarting at
    // seq=0 in the new epoch must decrypt on a freshly-set-up exit
    // session - i.e. there is no hidden cross-epoch state in the
    // crate.
    let (priv_k, pub_k) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client = ClientSession::new(&pub_k, exit_id, &mut rng).expect("setup");

    // Burn through some seqs in epoch 0.
    for seq in 0..50u64 {
        let _ = client.seal(b"warmup", 0, seq).expect("seal");
    }

    let mut rng_rekey = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    client.rekey(&pub_k, &mut rng_rekey).expect("rekey");
    let exit_e1 =
        ExitSession::new(&priv_k, &client.encapsulated_key(), exit_id).expect("exit_e1 setup");

    // Restart seq from 0 in the new epoch.
    for seq in 0..50u64 {
        let frame = client
            .seal(b"post-rekey", client.epoch(), seq)
            .expect("seal post-rekey");
        let pt = exit_e1.open(&frame).expect("open post-rekey");
        assert_eq!(pt, b"post-rekey");
    }
}
