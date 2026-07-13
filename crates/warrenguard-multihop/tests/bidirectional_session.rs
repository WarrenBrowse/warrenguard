//! Bidirectional HPKE session round-trip.
//!
//! Anchors the contract for the exit -> client direction: a
//! [`ExitSession::seal_response`] frame must decrypt under
//! [`ClientSession::open_response`] and produce the original payload,
//! and a forward-direction frame fed to `open_response` (or vice versa)
//! must fail AEAD verification. The cross-direction rejection is the
//! security boundary that defeats a key-reuse attack across the two
//! directions.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{ClientSession, ExitId, ExitSession};

const EXIT_IKM: [u8; 32] = [0x11; 32];
const RNG_SEED: [u8; 32] = [0x22; 32];
const EXIT_ID: [u8; 16] = [0x33; 16];

fn session_pair() -> (ClientSession, ExitSession) {
    let (exit_priv, exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let mut rng = ChaCha20Rng::from_seed(RNG_SEED);
    let client = ClientSession::new(&exit_pub, ExitId::from_bytes(EXIT_ID), &mut rng)
        .expect("client session setup");
    let exit = ExitSession::new(
        &exit_priv,
        &client.encapsulated_key(),
        ExitId::from_bytes(EXIT_ID),
    )
    .expect("exit session setup");
    (client, exit)
}

#[test]
fn exit_seals_response_and_client_opens_it() {
    let (client, exit) = session_pair();
    let payload = b"hello from the exit, this is the return path".to_vec();
    let frame = exit
        .seal_response(&payload, 0, 1)
        .expect("exit seal_response");
    let opened = client.open_response(&frame).expect("client open_response");
    assert_eq!(opened, payload, "reverse direction must round-trip");
}

#[test]
fn forward_direction_frame_is_rejected_by_client_open_response() {
    // Anchors the cross-direction rejection security boundary: a frame
    // sealed by the CLIENT (forward direction) must not decrypt as a
    // RESPONSE (reverse direction). Without the direction tag in the
    // export info, both directions would derive the same per-packet
    // key from a colliding (epoch, seq) and the attack surface would
    // include trivial cross-direction confusion.
    let (client, _exit) = session_pair();
    let payload = b"forward payload from client";
    let forward_frame = client.seal(payload, 0, 1).expect("client seal forward");
    let err = client
        .open_response(&forward_frame)
        .expect_err("forward frame must not decrypt as a reverse-direction frame");
    assert!(
        matches!(err, warrenguard_multihop::MultihopError::Hpke(_)),
        "expected an HPKE OpenError; got {err:?}"
    );
}

#[test]
fn reverse_direction_frame_is_rejected_by_exit_open() {
    // Mirror of the cross-direction rejection from the exit side: a
    // frame sealed in the REVERSE direction must not decrypt under the
    // exit's `ExitSession::open`, which uses the forward export info.
    let (_client, exit) = session_pair();
    let payload = b"response payload from exit";
    let reverse_frame = exit
        .seal_response(payload, 0, 1)
        .expect("exit seal_response");
    let err = exit
        .open(&reverse_frame)
        .expect_err("reverse frame must not decrypt as a forward-direction frame");
    assert!(
        matches!(err, warrenguard_multihop::MultihopError::Hpke(_)),
        "expected an HPKE OpenError; got {err:?}"
    );
}

#[test]
fn open_response_owned_recovers_the_payload() {
    // Directly exercise the zero-copy datapath entry point the reverse-direction
    // recv path uses: consuming the decoded frame and decrypting in place must
    // recover the original payload. (`open_response` delegates to this, so the
    // borrowing tests cover it transitively; this pins the direct call.)
    let (client, exit) = session_pair();
    let payload = b"reverse payload opened via the zero-copy owned path".to_vec();
    let frame = exit
        .seal_response(&payload, 0, 7)
        .expect("exit seal_response");

    let opened = client
        .open_response_owned(frame)
        .expect("owned open must succeed");
    assert_eq!(opened, payload, "owned open must recover the payload");
}

#[test]
fn open_owned_recovers_the_forward_payload() {
    // ExitSession::open_owned consumes a client-sealed forward frame and
    // decrypts it in place; it must recover the original payload.
    let (client, exit) = session_pair();
    let payload = b"forward payload consumed by the exit open_owned path".to_vec();
    let frame = client.seal(&payload, 0, 3).expect("client seal");

    let opened = exit.open_owned(frame).expect("exit open_owned");
    assert_eq!(opened, payload, "open_owned must recover the payload");
}

#[test]
fn seal_response_owned_produces_the_same_frame_as_seal_response() {
    // The zero-copy exit-downlink seal must emit a byte-identical frame to the
    // borrowing seal_response (same key + payload => same ciphertext + tag),
    // otherwise the copy elimination would be a silent wire regression.
    let (_client, exit) = session_pair();
    let payload = b"exit downlink payload sealed via the owned zero-copy path".to_vec();

    let borrow = exit.seal_response(&payload, 0, 9).expect("seal_response");
    let owned = exit
        .seal_response_owned(payload.clone(), 0, 9)
        .expect("seal_response_owned");

    assert_eq!(owned.ciphertext, borrow.ciphertext, "ciphertext must match");
    assert_eq!(owned.aead_tag, borrow.aead_tag, "aead tag must match");
    assert_eq!(owned.epoch, borrow.epoch);
    assert_eq!(owned.seq, borrow.seq);
}

#[test]
fn many_reverse_frames_round_trip_with_distinct_seq() {
    // Soak: 256 reverse frames with distinct seq values to catch any
    // hidden state-machine assumption that would break after a few
    // sealings (e.g. the AEAD context being implicitly consumed).
    let (client, exit) = session_pair();
    for seq in 0u64..256 {
        let payload = vec![(seq as u8).wrapping_mul(7); 64];
        let frame = exit.seal_response(&payload, 0, seq).expect("seal_response");
        let opened = client.open_response(&frame).expect("open_response");
        assert_eq!(opened, payload, "round-trip seq {seq}");
    }
}
