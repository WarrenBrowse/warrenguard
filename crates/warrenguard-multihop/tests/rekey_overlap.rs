//! Client-side rekey overlap window.
//!
//! A sustained-traffic bench discovered that the client-side rekey
//! transition drops in-flight reverse-direction frames sealed under the
//! old HPKE epoch. The doctrine specifies a 2-5 s overlap
//! window during which the client must still be able to decrypt
//! reverse frames sealed under the previous `AeadCtxS` / epoch.
//!
//! This test pins that contract from the **receiver side** of
//! [`ClientSession`]: seal a few reverse frames under epoch 0,
//! rekey the client, then ask the client to open the in-flight
//! epoch-0 frames. Without the fix this fails with
//! `MultihopError::Hpke(OpenError)` because
//! [`ClientSession::open_response`] re-derives the per-packet key
//! from the post-rekey `AeadCtxS`. The fix introduces a
//! pending-old-epoch slot inside `ClientSession` that holds the
//! previous `AeadCtxS` until the caller explicitly prunes it.
//!
//! A companion test below covers the purge half of the contract via
//! the supporting API (`ClientSession::prune_pending_old_epoch`).

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{ClientSession, ExitId, ExitSession, MultihopError};

const EXIT_IKM: [u8; 32] = [0xA1; 32];
const RNG_SEED_INITIAL: [u8; 32] = [0xB2; 32];
const RNG_SEED_REKEY: [u8; 32] = [0xC3; 32];
const EXIT_ID: [u8; 16] = [0xD4; 16];

#[test]
fn client_decodes_inflight_reverse_frames_from_old_epoch_after_rekey() {
    // ARRANGE.
    // Set up a fresh client + exit pair in epoch 0. The exit produces
    // a few reverse-direction frames that represent the in-flight
    // traffic still travelling exit -> relay -> client when the client
    // decides to rekey (the stall mechanic from the bench).
    let (exit_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);
    let mut rng_initial = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client =
        ClientSession::new(&exit_pub, exit_id, &mut rng_initial).expect("client epoch 0 setup");
    let exit_e0 = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
        .expect("exit epoch 0 setup");

    // Five in-flight reverse frames sealed under epoch 0, seq 0..5.
    let in_flight_payloads: Vec<Vec<u8>> = (0..5u64)
        .map(|seq| format!("inflight-reverse-e0-seq{seq}").into_bytes())
        .collect();
    let in_flight_frames: Vec<_> = in_flight_payloads
        .iter()
        .enumerate()
        .map(|(i, pt)| {
            exit_e0
                .seal_response(pt, 0, i as u64)
                .expect("exit seal_response epoch 0")
        })
        .collect();

    // ACT.
    // Client rekeys (atomic swap inside ClientSession). The reverse
    // frames above were sealed BEFORE the swap and are now equivalent
    // to in-flight stragglers from the previous epoch.
    let mut rng_rekey = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    client
        .rekey(&exit_pub, &mut rng_rekey)
        .expect("client rekey to epoch 1");
    assert_eq!(client.epoch(), 1, "client epoch must advance to 1");

    // Sanity: the exit observes the rekey and would set up an epoch-1
    // session for any new forward frame. That part is exit-cache
    // territory and is already covered by the rekey_v1.rs vector
    // tests; here we only care about the client receive path.
    let _exit_e1 = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
        .expect("exit epoch 1 setup (sanity)");

    // ASSERT.
    // Every in-flight epoch-0 reverse frame must still decrypt on the
    // client side during the overlap window. This is the new contract
    // the fix introduces; it must fail without the fix.
    for (i, frame) in in_flight_frames.iter().enumerate() {
        let opened = client.open_response(frame).unwrap_or_else(|e| {
            panic!(
                "in-flight reverse frame from old epoch must decrypt during overlap; \
                 seq={i} failed with {e:?} -- this is the rekey deadlock signature"
            )
        });
        assert_eq!(
            opened, in_flight_payloads[i],
            "decrypted payload mismatch at seq {i}: overlap path used wrong AeadCtxS"
        );
    }
    assert!(
        client.has_pending_old_epoch(),
        "overlap window must remain open until the caller invokes prune"
    );
    assert_eq!(client.pending_old_epoch_value(), Some(0));
}

#[test]
fn old_epoch_reverse_frame_rejected_after_overlap_window_pruned() {
    // ARRANGE.
    // Same setup as the GREEN test above, but with an explicit prune
    // call simulating the caller noticing the doctrine 5 s deadline
    // has elapsed.
    let (exit_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);
    let mut rng_initial = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client =
        ClientSession::new(&exit_pub, exit_id, &mut rng_initial).expect("client epoch 0 setup");
    let exit_e0 = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
        .expect("exit epoch 0 setup");

    let stale_frame = exit_e0
        .seal_response(b"stale-after-purge", 0, 0)
        .expect("exit seal_response epoch 0");

    let mut rng_rekey = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    client
        .rekey(&exit_pub, &mut rng_rekey)
        .expect("client rekey to epoch 1");

    // ACT.
    client.prune_pending_old_epoch();

    // ASSERT.
    assert!(
        !client.has_pending_old_epoch(),
        "prune must clear the pending old-epoch slot"
    );
    let err = client
        .open_response(&stale_frame)
        .expect_err("post-purge stale frame must not decrypt");
    assert!(
        matches!(err, MultihopError::Hpke(_)),
        "expected MultihopError::Hpke after overlap purge, got {err:?}"
    );
}

#[test]
fn prune_is_idempotent_no_pending_epoch_no_op() {
    let (_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client = ClientSession::new(&exit_pub, exit_id, &mut rng).expect("setup");
    assert!(!client.has_pending_old_epoch());
    client.prune_pending_old_epoch();
    client.prune_pending_old_epoch();
    assert!(!client.has_pending_old_epoch());
}

#[test]
fn rekey_replaces_pending_old_epoch_with_most_recent_previous_epoch() {
    // Two back-to-back rekeys with no prune in between: the second
    // rekey must overwrite the pending slot with the immediately
    // previous epoch (1), not preserve the deepest old (0). This is
    // the explicit behaviour documented on ClientSession::rekey.
    let (exit_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let mut client = ClientSession::new(&exit_pub, exit_id, &mut rng).expect("setup");

    let exit_e0 = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
        .expect("exit epoch 0 setup");
    let stale_e0 = exit_e0
        .seal_response(b"stale-e0", 0, 0)
        .expect("seal e0 stale");

    let mut rng_r1 = ChaCha20Rng::from_seed(RNG_SEED_REKEY);
    client.rekey(&exit_pub, &mut rng_r1).expect("rekey 1");

    let exit_e1 = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
        .expect("exit epoch 1 setup");
    let stale_e1 = exit_e1
        .seal_response(b"stale-e1", 1, 0)
        .expect("seal e1 stale");

    let mut rng_r2 = ChaCha20Rng::from_seed([0xEE; 32]);
    client.rekey(&exit_pub, &mut rng_r2).expect("rekey 2");
    assert_eq!(client.epoch(), 2);
    assert_eq!(
        client.pending_old_epoch_value(),
        Some(1),
        "pending slot must hold epoch 1 after rekey 0->1->2"
    );

    // Epoch-1 stragglers still decode against the pending slot.
    let opened_e1 = client
        .open_response(&stale_e1)
        .expect("epoch-1 frame must decode through pending slot after rekey 2");
    assert_eq!(opened_e1, b"stale-e1");

    // Epoch-0 stragglers cannot decode anymore: the pending slot now
    // belongs to epoch 1.
    let err_e0 = client
        .open_response(&stale_e0)
        .expect_err("epoch-0 frame must not decode two rekeys later");
    assert!(matches!(err_e0, MultihopError::Hpke(_)));
}

#[test]
fn fresh_session_starts_with_no_pending_old_epoch() {
    let (_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED_INITIAL);
    let client = ClientSession::new(&exit_pub, ExitId::from_bytes(EXIT_ID), &mut rng)
        .expect("fresh session");
    assert!(!client.has_pending_old_epoch());
    assert_eq!(client.pending_old_epoch_value(), None);
}
