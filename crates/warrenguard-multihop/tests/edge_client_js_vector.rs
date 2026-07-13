//! Cross-implementation proof that a TypeScript EdgeConnect client seals a
//! `WarrenMultihopFrame` this engine's exit can HPKE-open, byte-for-byte.
//!
//! The frozen `SEALED_FRAME_HEX` below is emitted by the TS test
//! `packages/core/test/edge.seal.test.ts` (fixed exit key + fixed ephemeral, so
//! it is deterministic). This test rebuilds the exit's receiver session from the
//! same `[0x11; 32]` IKM and asserts `ExitSession::open` recovers the exact
//! plaintext. If either side's HPKE (suite, info string, AAD/export-info layout,
//! nonce, AEAD) drifts, the open fails, so this is the wire-format regression
//! detector across the language boundary.

use warrenguard_multihop::test_support::derive_exit_keypair;
use warrenguard_multihop::{ExitId, ExitSession, WarrenMultihopFrame};

/// Emitted by the TS seal test (exit key from `derive_exit_keypair([0x11;32])`,
/// ephemeral `[0x22;32]`, exit_id `[0xa1;16]`, epoch 7, seq 42).
const SEALED_FRAME_HEX: &str = "01a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1072a0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20c57666dcab30e6081656b3808a8af4e41934bb4770df10f3753092221b3e5ac2a3de86eaf0dc180c47c0";
const EXIT_IKM: [u8; 32] = [0x11u8; 32];
const EXPECTED_PLAINTEXT: &[u8] = b"warren-edge-connect-hello";

#[test]
fn exit_opens_a_frame_sealed_by_the_typescript_edge_client() {
    let frame_bytes = hex::decode(SEALED_FRAME_HEX).expect("valid hex");
    let frame = WarrenMultihopFrame::decode(&frame_bytes).expect("TS frame decodes as postcard");

    // The exit's long-lived X25519 keypair (its private half decapsulates).
    let (exit_priv, _exit_pub) = derive_exit_keypair(&EXIT_IKM);
    let session = ExitSession::new(
        &exit_priv,
        &frame.encapsulated_key,
        ExitId::from_bytes([0xa1; 16]),
    )
    .expect("exit sets up the receiver session from the TS-provided encapsulated key");

    let plaintext = session
        .open(&frame)
        .expect("the exit HPKE-opens the TS-sealed frame");
    assert_eq!(
        plaintext, EXPECTED_PLAINTEXT,
        "the recovered plaintext must match what the TS client sealed"
    );
}
