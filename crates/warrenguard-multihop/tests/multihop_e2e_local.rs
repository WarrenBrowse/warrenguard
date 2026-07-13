//! End-to-end loopback test of the full warren-multihop receive path.
//!
//! Stitches together:
//! - [`ClientSession::seal`] / [`ClientSession::rekey`]
//! - [`ExitSession::open`]
//! - [`ReplayWindow::check_and_record`]
//! - [`encode_frame`] / [`decode_frame`]
//!
//! Simulates 10 000 datagrams with a rekey at the half-way mark and
//! verifies:
//! - Every frame round-trips losslessly through the wire format.
//! - The exit-side anti-replay window accepts the fresh seqs and
//!   rejects a deliberate replay attempt.
//! - The rekey at seq 5000 produces a new epoch whose frames are
//!   decryptable by a brand-new exit session.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{
    ClientSession, ExitId, ExitSession, MultihopError, ReplayWindow, decode_frame, encode_frame,
};

const EXIT_IKM: [u8; 32] = [0x9D; 32];
const SESSION_RNG_SEED: [u8; 32] = [0x3C; 32];
const REKEY_RNG_SEED: [u8; 32] = [0xA7; 32];
const EXIT_ID: [u8; 16] = [0x5E; 16];

const FRAMES_PER_EPOCH: u64 = 5_000;
const REKEY_AT_SEQ: u64 = FRAMES_PER_EPOCH;
const TOTAL_FRAMES: u64 = 2 * FRAMES_PER_EPOCH;

fn build_payload(epoch: u32, seq: u64) -> Vec<u8> {
    let mut p = vec![0u8; 256];
    p[..4].copy_from_slice(&epoch.to_be_bytes());
    p[4..12].copy_from_slice(&seq.to_be_bytes());
    // Pseudo-random tail seeded from (epoch, seq).
    let mut acc = (epoch as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ seq;
    for b in &mut p[12..] {
        acc = acc
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (acc >> 32) as u8;
    }
    p
}

#[test]
fn full_session_with_rekey_at_seq_5000_decrypts_ten_thousand_frames() {
    let (exit_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let exit_id = ExitId::from_bytes(EXIT_ID);

    let mut rng = ChaCha20Rng::from_seed(SESSION_RNG_SEED);
    let mut client = ClientSession::new(&exit_pub, exit_id, &mut rng).expect("client setup");

    let mut exit = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
        .expect("exit initial setup");
    let mut replay = ReplayWindow::new();
    let mut last_frame_for_replay_test: Option<warrenguard_multihop::WarrenMultihopFrame> = None;

    for seq in 0..TOTAL_FRAMES {
        if seq == REKEY_AT_SEQ {
            // Rekey: drop the epoch-0 session immediately (no overlap
            // in this scenario), bring up a fresh exit + replay window
            // for epoch 1.
            let mut rng_rekey = ChaCha20Rng::from_seed(REKEY_RNG_SEED);
            client.rekey(&exit_pub, &mut rng_rekey).expect("rekey");
            exit = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
                .expect("exit post-rekey setup");
            replay = ReplayWindow::new();
            last_frame_for_replay_test = None;
        }

        let epoch = client.epoch();
        // Reset seq within the new epoch so AAD matches the per-epoch
        // seq convention.
        let in_epoch_seq = if seq < REKEY_AT_SEQ {
            seq
        } else {
            seq - REKEY_AT_SEQ
        };

        let payload = build_payload(epoch, in_epoch_seq);
        let frame = client.seal(&payload, epoch, in_epoch_seq).expect("seal");

        // Encode -> wire -> decode -> open: exercises the entire stack.
        let wire = encode_frame(&frame).expect("encode");
        let decoded = decode_frame(&wire).expect("decode");
        assert_eq!(decoded, frame, "wire format bijection broken at seq {seq}");

        let recovered = exit.open(&decoded).expect("open");
        assert_eq!(recovered, payload, "payload mismatch at seq {seq}");

        // Exit-side anti-replay accepts every fresh seq.
        replay
            .check_and_record(in_epoch_seq, epoch)
            .unwrap_or_else(|e| panic!("anti-replay rejected fresh seq {in_epoch_seq}: {e:?}"));

        // Stash one frame per epoch to verify the replay protection
        // catches a deliberate retransmission.
        if in_epoch_seq == 17 {
            last_frame_for_replay_test = Some(decoded);
        }
    }

    // The last stored frame from epoch 1 must be rejected by the
    // replay window when the relay attempts to replay it.
    let replay_target = last_frame_for_replay_test.expect("a frame was stashed in epoch 1");
    let recovered_again = exit
        .open(&replay_target)
        .expect("cryptographic re-open is fine");
    assert_eq!(recovered_again.len(), 256);
    match replay.check_and_record(replay_target.seq, replay_target.epoch) {
        Err(MultihopError::Replay { seq, epoch }) => {
            assert_eq!(seq, replay_target.seq);
            assert_eq!(epoch, replay_target.epoch);
        }
        Ok(()) => panic!("replay window must reject a deliberate retransmission"),
        Err(other) => panic!("expected Replay rejection, got {other:?}"),
    }
}
