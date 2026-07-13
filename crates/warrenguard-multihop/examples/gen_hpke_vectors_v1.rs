//! Helper binary to (re-)generate the frozen HPKE Warren v1 test vectors.
//!
//! Run via:
//! ```sh
//! ./scripts/dev/cargo-test-nofw.sh run -p warren-multihop --example gen_hpke_vectors_v1
//! ```
//!
//! Output goes to stdout in a copy-paste-friendly hex form. The captured
//! bytes live in `crates/warren-multihop/tests/hpke_vectors_v1.rs` as
//! `EXPECTED_*` consts, MUST never change once frozen for `/v1`, and the
//! seed pairs below are themselves part of the contract: regenerating from
//! a different seed would invalidate every published consumer of the wire
//! format.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{ClientSession, ExitId};

fn print_hex_array(name: &str, bytes: &[u8]) {
    print!("{name}: [");
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n    ");
        }
        print!("0x{b:02x}, ");
    }
    println!("\n];");
}

fn run_one(
    label: &str,
    exit_seed: &[u8],
    rng_seed: [u8; 32],
    exit_id_bytes: [u8; 16],
    epoch: u32,
    seq: u64,
    payload: &[u8],
) {
    println!("// ===== Vector {label} =====");
    println!("// exit_ikm = 32 bytes (used for HPKE derive_keypair).");
    println!("// rng_seed = 32 bytes (used to seed ChaCha20Rng for ephemeral KEM keypair).");
    println!("// epoch = {epoch}, seq = {seq}, exit_id = {exit_id_bytes:02x?}");
    println!("// payload size = {} bytes", payload.len());
    println!();

    let (exit_priv, exit_pub) = derive_exit_keypair(exit_seed);
    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    let exit_id = ExitId::from_bytes(exit_id_bytes);
    let client = ClientSession::new(&exit_pub, exit_id, &mut rng).expect("setup_sender");
    let frame = client.seal(payload, epoch, seq).expect("seal");

    // Roundtrip sanity: decrypt with the exit privkey.
    let exit =
        warrenguard_multihop::ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
            .expect("setup_receiver");
    let recovered = exit.open(&frame).expect("open");
    assert_eq!(recovered, payload, "roundtrip mismatch for vector {label}");

    print_hex_array(
        &format!("EXPECTED_{label}_ENCAPPED_KEY"),
        &client.encapsulated_key(),
    );
    print_hex_array(&format!("EXPECTED_{label}_AEAD_TAG"), &frame.aead_tag);
    print_hex_array(&format!("EXPECTED_{label}_CIPHERTEXT"), &frame.ciphertext);
    println!();
}

fn main() {
    // Vector ZERO: exit_seed [0u8; 32], rng_seed [1u8; 32], exit_id zeros,
    // payload [0xAA; 64], epoch 0 seq 0.
    run_one("ZERO", &[0u8; 32], [1u8; 32], [0u8; 16], 0, 0, &[0xAA; 64]);

    // Vector AB: exit_seed [0xAB; 32], rng_seed [0xCD; 32], exit_id 0xEE pattern,
    // payload [0x42, 0x43, ..., wrapping], epoch 7 seq 12345.
    let mut payload_ab = [0u8; 128];
    for (i, b) in payload_ab.iter_mut().enumerate() {
        *b = (0x42u8).wrapping_add(i as u8);
    }
    let mut exit_id_ab = [0u8; 16];
    for (i, b) in exit_id_ab.iter_mut().enumerate() {
        *b = 0xE0 | (i as u8 & 0x0F);
    }
    run_one(
        "AB",
        &[0xABu8; 32],
        [0xCDu8; 32],
        exit_id_ab,
        7,
        12_345,
        &payload_ab,
    );

    // Vector MAX: exit_seed [0x37; 32], rng_seed [0x5C; 32], exit_id repeats 0xDE,
    // payload 1232 bytes (RFC 9221 max useful at MTU 1280), epoch 0xFFFF_FFFE seq u64::MAX-1.
    let payload_max = vec![0xCCu8; 1232];
    run_one(
        "MAX",
        &[0x37u8; 32],
        [0x5Cu8; 32],
        [0xDE; 16],
        u32::MAX - 1,
        u64::MAX - 1,
        &payload_max,
    );
}
