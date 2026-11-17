//! Replays `vectors/session_binding_v1.json` (the shared `warren-vectors`
//! submodule): the dated proof of possession, the control messages of the
//! session binding and setup freshness wire, and one rekey announcement sealed
//! under a deterministic `/v2` session. Every implementation must reproduce
//! these bytes; a failure means the wire moved.

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use warrenguard_multihop::{
    ExitId, POP_CONTEXT_V3, PopSignature, RECENT_SETUP_RETENTION_SECS, SEALED_TO_API_LEN,
    SETUP_CLOCK_SKEW_SECS, SealedToApi, SetupRefusalCode, WarrenControlMessage, encode_control,
    pop_signing_message_v3, sign_pop_v3, try_decode_control, verify_pop_v3,
};
use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken};

#[derive(Deserialize)]
struct File {
    schema: String,
    freshness: Freshness,
    pop_v3: PopV3,
    control: Control,
    #[cfg_attr(not(feature = "pq-hpke"), allow(dead_code))]
    rekey_frame_v2: RekeyFrameV2,
}

#[derive(Deserialize)]
struct Freshness {
    skew_secs: u64,
    retention_secs: u64,
}

#[derive(Deserialize)]
struct PopV3 {
    context_hex: String,
    exit_id_hex: String,
    encapsulated_key_hex: String,
    client_unix_secs: u64,
    preimage_hex: String,
    signing_key_seed_hex: String,
    signature_hex: String,
}

#[derive(Deserialize)]
struct Control {
    vectors: Vec<ControlVector>,
}

#[derive(Deserialize)]
struct ControlVector {
    name: String,
    discriminant: u8,
    bytes_hex: String,
}

#[derive(Deserialize)]
#[cfg_attr(not(feature = "pq-hpke"), allow(dead_code))]
struct RekeyFrameV2 {
    exit_id_hex: String,
    epoch0_mlkem768_m_seed_hex: String,
    epoch0_x25519_ephemeral_seed_hex: String,
    epoch0_encapsulated_key_hex: String,
    epoch1_mlkem768_m_seed_hex: String,
    epoch1_x25519_ephemeral_seed_hex: String,
    epoch1_encapsulated_key_hex: String,
    epoch: u32,
    seq: u64,
    plaintext_hex: String,
    frame_bytes_hex: String,
}

fn load() -> File {
    let path = format!(
        "{}/../../vectors/session_binding_v1.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("read vectors/session_binding_v1.json: {e}; run `git submodule update --init`")
    });
    serde_json::from_str(&raw).expect("parse session_binding_v1.json")
}

fn arr<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str)
        .expect("hex")
        .try_into()
        .unwrap_or_else(|_| panic!("{N} bytes"))
}

#[test]
fn the_freshness_constants_match_the_corpus() {
    let file = load();
    assert_eq!(file.schema, "session_binding/v1");
    assert_eq!(file.freshness.skew_secs, SETUP_CLOCK_SKEW_SECS);
    assert_eq!(file.freshness.retention_secs, RECENT_SETUP_RETENTION_SECS);
}

#[test]
fn the_dated_proof_of_possession_matches_the_corpus() {
    let v = load().pop_v3;
    assert_eq!(hex::decode(&v.context_hex).unwrap(), POP_CONTEXT_V3);
    let exit_id = ExitId::from_bytes(arr(&v.exit_id_hex));
    let encap: [u8; 32] = arr(&v.encapsulated_key_hex);
    let key = SigningKey::from_bytes(&arr(&v.signing_key_seed_hex));
    assert_eq!(
        hex::encode(pop_signing_message_v3(&exit_id, &encap, v.client_unix_secs)),
        v.preimage_hex,
        "the /v3 preimage drifted from the corpus"
    );
    let sig = sign_pop_v3(&key, &exit_id, &encap, v.client_unix_secs);
    assert_eq!(hex::encode(sig.0), v.signature_hex);
    assert!(verify_pop_v3(
        &key.verifying_key().to_bytes(),
        &exit_id,
        &encap,
        v.client_unix_secs,
        &PopSignature(arr(&v.signature_hex)),
    ));
}

/// The message each named control vector freezes, rebuilt from the values
/// its comment states.
fn expected_message(name: &str, file: &File) -> WarrenControlMessage {
    let t = file.pop_v3.client_unix_secs;
    match name {
        "ip_request_dated" => {
            let key = SigningKey::from_bytes(&arr(&file.pop_v3.signing_key_seed_hex));
            WarrenControlMessage::IpRequestDated {
                prefer_ipv4: Some([10, 66, 0, 42]),
                client_pubkey: Some(key.verifying_key().to_bytes()),
                wants_ipv6: true,
                pop_sig: Some(PopSignature(arr(&file.pop_v3.signature_hex))),
                wants_daita: true,
                client_unix_secs: t,
            }
        }
        "ip_request_v7_dated" => WarrenControlMessage::IpRequestV7Dated {
            prefer_ipv4: Some([0, 0, 0, 0]),
            wants_ipv6: false,
            session_tokens: vec![SessionToken([0xcd; SESSION_TOKEN_LEN])],
            wants_daita: false,
            client_unix_secs: t,
        },
        "ip_request_route_dated" => WarrenControlMessage::IpRequestRouteDated {
            prefer_ipv4: None,
            wants_ipv6: true,
            route_locator: SealedToApi::from_bytes(&[0x3c; SEALED_TO_API_LEN]),
            wants_daita: false,
            client_unix_secs: t,
        },
        "setup_refused_unspecified" => WarrenControlMessage::SetupRefused {
            reason_code: SetupRefusalCode::Unspecified.code(),
        },
        "setup_refused_clock_skew" => WarrenControlMessage::SetupRefused {
            reason_code: SetupRefusalCode::ClockSkew.code(),
        },
        "setup_refused_replayed" => WarrenControlMessage::SetupRefused {
            reason_code: SetupRefusalCode::Replayed.code(),
        },
        "setup_refused_busy" => WarrenControlMessage::SetupRefused {
            reason_code: SetupRefusalCode::Busy.code(),
        },
        "session_rekey" => WarrenControlMessage::SessionRekey {
            new_encapsulated_key: arr(&file.rekey_frame_v2.epoch1_encapsulated_key_hex),
            new_epoch: 1,
        },
        other => panic!("unknown session binding control vector name {other}"),
    }
}

#[test]
fn every_control_vector_encodes_and_decodes_byte_for_byte() {
    let file = load();
    assert_eq!(file.control.vectors.len(), 8);
    for v in &file.control.vectors {
        let msg = expected_message(&v.name, &file);
        let bytes = encode_control(&msg).expect("encode");
        assert_eq!(hex::encode(&bytes), v.bytes_hex, "{} drifted", v.name);
        assert_eq!(bytes[2], v.discriminant, "{} discriminant", v.name);
        assert_eq!(
            try_decode_control(&hex::decode(&v.bytes_hex).unwrap())
                .expect("decode")
                .expect("a control message"),
            msg,
            "{} decodes to the message it freezes",
            v.name
        );
    }
}

#[cfg(feature = "pq-hpke")]
#[test]
fn the_rekey_announcement_seals_under_the_previous_epoch_byte_for_byte() {
    use warrenguard_multihop::{
        PqClientSession, PqExitSession, XWingRecipientSecretKey, decode_frame_v2,
    };
    let v = load().rekey_frame_v2;
    let (exit_sk, exit_pk) =
        XWingRecipientSecretKey::derive_deterministic(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
    let exit_id = ExitId::from_bytes(arr(&v.exit_id_hex));
    let epoch0 = PqClientSession::new_deterministic(
        &exit_pk,
        exit_id,
        &arr(&v.epoch0_mlkem768_m_seed_hex),
        &arr(&v.epoch0_x25519_ephemeral_seed_hex),
    )
    .expect("epoch 0");
    let epoch1 = PqClientSession::new_deterministic(
        &exit_pk,
        exit_id,
        &arr(&v.epoch1_mlkem768_m_seed_hex),
        &arr(&v.epoch1_x25519_ephemeral_seed_hex),
    )
    .expect("epoch 1");
    assert_eq!(
        hex::encode(epoch0.encapsulated_key()),
        v.epoch0_encapsulated_key_hex
    );
    assert_eq!(
        hex::encode(epoch1.encapsulated_key()),
        v.epoch1_encapsulated_key_hex
    );
    let plaintext = encode_control(&WarrenControlMessage::SessionRekey {
        new_encapsulated_key: epoch1.encapsulated_key(),
        new_epoch: v.epoch + 1,
    })
    .expect("encode");
    assert_eq!(hex::encode(&plaintext), v.plaintext_hex);
    let frame = epoch0.seal(&plaintext, v.epoch, v.seq).expect("seal");
    assert_eq!(
        hex::encode(frame.encode().expect("encode frame")),
        v.frame_bytes_hex,
        "the sealed announcement drifted"
    );

    let exit = PqExitSession::new(
        &exit_sk,
        &epoch0.encapsulated_key(),
        epoch0.pq_ct(),
        exit_id,
    )
    .expect("exit epoch 0");
    let wire = decode_frame_v2(&hex::decode(&v.frame_bytes_hex).unwrap()).expect("decode");
    assert_eq!(
        exit.open(&wire).expect("the epoch 0 session opens it"),
        plaintext
    );
}
