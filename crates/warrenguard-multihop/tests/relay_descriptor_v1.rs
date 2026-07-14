//! Tests for `RelayDescriptorSigned`.
//!
//! These tests anchor the `/v1` PKI contract for relay descriptors: the
//! signing payload layout, the Ed25519 verification path, the rejection of
//! tampered signatures, and the rejection of descriptors signed by an
//! unexpected operational key.
//!
//! Wire-distribution format (TOML round-trip) is covered separately so a
//! future schema audit can cross-check the serde representation without
//! pulling in crypto primitives.

use ed25519_dalek::{Signer, SigningKey};
use warrenguard_multihop::{
    RelayDescriptorSigned, RelayPkiError, WARREN_PKI_OPERATIONAL_RELAY_V1,
    relay_descriptor_signing_payload, verify_relay_descriptor,
};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn signed_descriptor(
    op: &SigningKey,
    relay_id: [u8; 16],
    relay_pubkey: [u8; 32],
    endpoint: &str,
) -> RelayDescriptorSigned {
    let payload = relay_descriptor_signing_payload(&relay_id, &relay_pubkey);
    let sig = op.sign(&payload);
    RelayDescriptorSigned {
        relay_id,
        relay_ed25519_pubkey: relay_pubkey,
        endpoint: endpoint.parse().expect("static addr parses"),
        cover_domain: None,
        tcp_fallback: false,
        signature: sig.to_bytes(),
    }
}

#[test]
fn signing_payload_is_context_then_relay_id_then_pubkey() {
    let relay_id = [0xAB; 16];
    let pubkey = [0xCD; 32];
    let payload = relay_descriptor_signing_payload(&relay_id, &pubkey);
    assert_eq!(
        payload.len(),
        WARREN_PKI_OPERATIONAL_RELAY_V1.len() + 16 + 32,
        "relay signing payload must be context || relay_id (16) || pubkey (32)"
    );
    assert!(
        payload.starts_with(WARREN_PKI_OPERATIONAL_RELAY_V1),
        "payload must lead with the /v1 PKI context for domain separation"
    );
    let ctx_len = WARREN_PKI_OPERATIONAL_RELAY_V1.len();
    assert_eq!(&payload[ctx_len..ctx_len + 16], &relay_id);
    assert_eq!(&payload[ctx_len + 16..], &pubkey);
}

#[test]
fn verifies_a_freshly_signed_descriptor() {
    let op = det_signing_key(0x42);
    let descriptor = signed_descriptor(&op, [0x11; 16], [0x22; 32], "10.0.0.7:443");
    verify_relay_descriptor(&op.verifying_key(), &descriptor)
        .expect("freshly signed relay descriptor must verify");
}

#[test]
fn rejects_signature_tampered_by_one_byte() {
    let op = det_signing_key(0x42);
    let mut descriptor = signed_descriptor(&op, [0x11; 16], [0x22; 32], "10.0.0.7:443");
    descriptor.signature[3] ^= 0x01;
    let err = verify_relay_descriptor(&op.verifying_key(), &descriptor)
        .expect_err("flipping a signature byte must reject");
    assert!(matches!(err, RelayPkiError::BadSignature));
}

#[test]
fn rejects_descriptor_signed_by_a_different_operational_key() {
    let signer = det_signing_key(0x42);
    let other = det_signing_key(0x99);
    let descriptor = signed_descriptor(&signer, [0x11; 16], [0x22; 32], "10.0.0.7:443");
    let err = verify_relay_descriptor(&other.verifying_key(), &descriptor)
        .expect_err("descriptor must not verify under a different operational pubkey");
    assert!(matches!(err, RelayPkiError::BadSignature));
}

#[test]
fn rejects_descriptor_with_tampered_relay_pubkey_field() {
    // The signature covers (relay_id, relay_ed25519_pubkey). If an
    // operator (or an attacker) swaps the pubkey field while keeping
    // the original signature, the descriptor must reject. This anchors
    // the security property that the PKI binds the pubkey, not just the
    // relay id.
    let op = det_signing_key(0x42);
    let mut descriptor = signed_descriptor(&op, [0x11; 16], [0x22; 32], "10.0.0.7:443");
    descriptor.relay_ed25519_pubkey[0] ^= 0xFF;
    let err = verify_relay_descriptor(&op.verifying_key(), &descriptor)
        .expect_err("tampering the pubkey field must reject");
    assert!(matches!(err, RelayPkiError::BadSignature));
}

#[test]
fn toml_round_trip_preserves_descriptor() {
    // The relay descriptor must round-trip through TOML so a consumer
    // can ship the file format on disk.
    let op = det_signing_key(0x42);
    let descriptor = signed_descriptor(&op, [0x77; 16], [0xAA; 32], "192.0.2.10:443");
    let text = toml::to_string(&descriptor).expect("relay descriptor serializes to TOML");
    let decoded: RelayDescriptorSigned =
        toml::from_str(&text).expect("relay descriptor deserializes from TOML");
    assert_eq!(decoded.relay_id, descriptor.relay_id);
    assert_eq!(
        decoded.relay_ed25519_pubkey,
        descriptor.relay_ed25519_pubkey
    );
    assert_eq!(decoded.endpoint, descriptor.endpoint);
    assert_eq!(decoded.signature, descriptor.signature);
    verify_relay_descriptor(&op.verifying_key(), &decoded)
        .expect("TOML round-tripped descriptor must still verify");
}
