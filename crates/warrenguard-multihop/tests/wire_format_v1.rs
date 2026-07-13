//! Wire format invariants for the Warren multihop `/v1` frame.
//!
//! Bijection (`decode(encode(frame)) == frame`) and rejection of malformed
//! / mismatched-version inputs. These tests pin the postcard byte layout
//! produced by [`WarrenMultihopFrame`] and the version gating inside
//! [`WarrenMultihopFrame::decode`]: removing either path causes the suite
//! to fail loudly.

use warrenguard_multihop::{
    EncapsulatedKeyBytes, ExitId, MultihopError, WARREN_HPKE_VERSION, WarrenMultihopFrame,
    decode_frame, encode_frame,
};

fn sample_frame() -> WarrenMultihopFrame {
    WarrenMultihopFrame {
        version: WARREN_HPKE_VERSION,
        exit_id: ExitId::from_bytes([0xAA; 16]),
        epoch: 0x0000_0042,
        seq: 0x0000_0000_0000_1234,
        encapsulated_key: {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = i as u8;
            }
            k
        },
        aead_tag: {
            let mut t = [0u8; 16];
            for (i, b) in t.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(0x40);
            }
            t
        },
        ciphertext: b"warren multihop sample payload".to_vec(),
    }
}

#[test]
fn encode_then_decode_is_identity() {
    let frame = sample_frame();
    let encoded = encode_frame(&frame).expect("encode succeeds");
    let decoded = decode_frame(&encoded).expect("decode succeeds");
    assert_eq!(decoded, frame, "wire format bijection broken");
}

#[test]
fn encoded_frame_starts_with_version_byte_v1() {
    // Postcard serializes fields in declaration order. `version: u8` is the
    // first field, so the very first byte on the wire MUST be the v1
    // version byte. This anchors the byte layout: anyone reordering the
    // struct fields will see this test fail.
    let frame = sample_frame();
    let encoded = encode_frame(&frame).expect("encode succeeds");
    assert!(!encoded.is_empty(), "encoded frame must not be empty");
    assert_eq!(
        encoded[0], WARREN_HPKE_VERSION,
        "wire version byte must be the first byte on the wire"
    );
}

#[test]
fn decode_rejects_version_byte_zero_two() {
    // Build a v1 frame, encode it, then flip the first byte to 0x02 and
    // verify the decoder rejects it. This is the "version mismatch"
    // invariant (line `if frame.version != WARREN_HPKE_VERSION { return Err(VersionMismatch); }`).
    let frame = sample_frame();
    let mut encoded = encode_frame(&frame).expect("encode succeeds");
    encoded[0] = 0x02;
    let err = decode_frame(&encoded).expect_err("decode must reject v0x02");
    match err {
        MultihopError::UnsupportedVersion { got, expected } => {
            assert_eq!(got, 0x02);
            assert_eq!(expected, WARREN_HPKE_VERSION);
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn decode_rejects_truncated_bytes() {
    // Truncating the encoded buffer past the postcard header bytes must
    // surface as a `Decode` error, never silently fall through. Use a
    // length that lies inside the postcard varint-encoded `ciphertext`
    // body so the inner deserializer hits a short read.
    let frame = sample_frame();
    let encoded = encode_frame(&frame).expect("encode succeeds");
    let truncated = &encoded[..encoded.len() / 2];
    let err = decode_frame(truncated).expect_err("decode must reject truncated input");
    assert!(
        matches!(err, MultihopError::Decode(_)),
        "expected Decode error, got {err:?}"
    );
}

#[test]
fn encapsulated_key_has_x25519_size_thirty_two() {
    // RFC 9180 KEM(X25519) public keys are 32 bytes. The encapsulated key
    // type alias is `[u8; 32]`; this test pins the public-API guarantee.
    let _: EncapsulatedKeyBytes = [0u8; 32];
    let frame = sample_frame();
    assert_eq!(frame.encapsulated_key.len(), 32);
}

#[test]
fn aead_tag_has_chacha20poly1305_size_sixteen() {
    // ChaCha20Poly1305 produces a 128-bit tag. The wire format pins it.
    let frame = sample_frame();
    assert_eq!(frame.aead_tag.len(), 16);
}

#[test]
fn exit_id_is_sixteen_bytes() {
    // 16-byte UUID-shaped identifier.
    let exit = ExitId::from_bytes([0; 16]);
    assert_eq!(exit.as_bytes().len(), 16);
}

#[test]
fn decode_rejects_trailing_bytes_after_a_valid_frame() {
    // Frame-malleability guard: a valid postcard frame followed by extra bytes
    // must be REJECTED, not silently accepted. `postcard::from_bytes` ignores the
    // trailing portion, so an attacker could append data without detection. The
    // SDK already rejected this; the engine must too (its `Decode` doc already
    // claims trailing bytes are caught).
    let frame = sample_frame();
    let mut bytes = frame.encode().expect("encode");
    bytes.push(0xff);
    let err = WarrenMultihopFrame::decode(&bytes).expect_err("trailing bytes must be rejected");
    assert!(
        matches!(err, MultihopError::TrailingBytes),
        "expected TrailingBytes, got {err:?}"
    );
}
