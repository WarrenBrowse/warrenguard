//! (Re-)generate the frozen session binding and setup freshness vectors
//! (`vectors/session_binding_v1.json`): the dated proof of possession, the
//! control messages that carry the setup time, its refusal and the rekey
//! announcement, and one announcement sealed under a deterministic `/v2`
//! session.
//!
//! Run:
//! ```sh
//! ./scripts/dev/cargo-test-nofw.sh run -p warrenguard-multihop \
//!   --features pq-hpke --example gen_session_binding_vectors_v1
//! ```
//!
//! Emits a single JSON object to stdout. The seeds are part of the frozen
//! contract; the recipient and the epoch 0 session are those of
//! `vectors/pq_hpke_seal_v2.json`, so an SDK that replays that file already
//! has every primitive this one needs.

#[cfg(not(feature = "pq-hpke"))]
fn main() {
    eprintln!("re-run with --features pq-hpke");
}

#[cfg(feature = "pq-hpke")]
fn main() {
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use warrenguard_multihop::{
        ExitId, POP_CONTEXT_V3, PqClientSession, PqExitSession, RECENT_SETUP_RETENTION_SECS,
        SEALED_TO_API_LEN, SETUP_CLOCK_SKEW_SECS, SealedToApi, SetupRefusalCode,
        WarrenControlMessage, XWingRecipientSecretKey, encode_control, pop_signing_message_v3,
        sign_pop_v3,
    };
    use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken};

    fn h(bytes: impl AsRef<[u8]>) -> String {
        hex::encode(bytes)
    }
    let t: u64 = 1_800_000_000;

    // Dated proof of possession: the /v2 vector's exit id, key and seed.
    let pop_exit_id = ExitId::from_bytes([0xaa; 16]);
    let pop_encap = [0x5c; 32];
    let seed = [0x11u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let preimage = pop_signing_message_v3(&pop_exit_id, &pop_encap, t);
    let sig = sign_pop_v3(&key, &pop_exit_id, &pop_encap, t);

    let control = |name: &str, comment: &str, msg: &WarrenControlMessage| {
        let bytes = encode_control(msg).expect("encode");
        json!({
            "name": name,
            "_comment": comment,
            "discriminant": bytes[2],
            "bytes_hex": h(&bytes),
        })
    };
    let wallet = WarrenControlMessage::IpRequestDated {
        prefer_ipv4: Some([10, 66, 0, 42]),
        client_pubkey: Some(key.verifying_key().to_bytes()),
        wants_ipv6: true,
        pop_sig: Some(sig),
        wants_daita: true,
        client_unix_secs: t,
    };
    let tokens = WarrenControlMessage::IpRequestV7Dated {
        prefer_ipv4: Some([0, 0, 0, 0]),
        wants_ipv6: false,
        session_tokens: vec![SessionToken([0xcd; SESSION_TOKEN_LEN])],
        wants_daita: false,
        client_unix_secs: t,
    };
    let route = WarrenControlMessage::IpRequestRouteDated {
        prefer_ipv4: None,
        wants_ipv6: true,
        route_locator: SealedToApi::from_bytes(&[0x3c; SEALED_TO_API_LEN]),
        wants_daita: false,
        client_unix_secs: t,
    };
    let refused = |code: SetupRefusalCode| WarrenControlMessage::SetupRefused {
        reason_code: code.code(),
    };

    // The /v2 rekey announcement: epoch 0 is the session of
    // pq_hpke_seal_v2.json, the new key comes from a second deterministic
    // session, and the announcement is sealed under epoch 0.
    let (exit_sk, exit_pk) =
        XWingRecipientSecretKey::derive_deterministic(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
    let rekey_exit_id = ExitId::from_bytes([0xa2; 16]);
    let epoch0 =
        PqClientSession::new_deterministic(&exit_pk, rekey_exit_id, &[0x44; 32], &[0x55; 32])
            .expect("epoch 0");
    let epoch1 =
        PqClientSession::new_deterministic(&exit_pk, rekey_exit_id, &[0x46; 32], &[0x57; 32])
            .expect("epoch 1");
    let announce = WarrenControlMessage::SessionRekey {
        new_encapsulated_key: epoch1.encapsulated_key(),
        new_epoch: 1,
    };
    let announce_plaintext = encode_control(&announce).expect("encode announce");
    let seq = 1_000_003u64;
    let frame = epoch0
        .seal(&announce_plaintext, 0, seq)
        .expect("seal under epoch 0");
    let frame_bytes = frame.encode().expect("encode frame");
    let exit = PqExitSession::new(
        &exit_sk,
        &epoch0.encapsulated_key(),
        epoch0.pq_ct(),
        rekey_exit_id,
    )
    .expect("exit epoch 0");
    assert_eq!(
        exit.open(&frame).expect("the exit opens it under epoch 0"),
        announce_plaintext
    );

    let doc = json!({
        "_comment": "Session binding and setup freshness on the multi-hop wire (warren-core doc 116). A dated setup request carries the client's wall clock (Unix seconds) after the fields of its legacy request; the exit refuses a time further than skew_secs from its own clock and a setup key it saw within retention_secs. The wallet request's proof of possession is /v3: context || exit_id (16) || encapsulated_key (32) || client_unix_secs (u64 big-endian). SessionRekey travels on the data plane sealed under the PREVIOUS epoch and authorizes the next epoch's key on the connection. control.json and pop.json are unchanged.",
        "schema": "session_binding/v1",
        "freshness": {
            "skew_secs": SETUP_CLOCK_SKEW_SECS,
            "retention_secs": RECENT_SETUP_RETENTION_SECS,
        },
        "pop_v3": {
            "_comment": "Ed25519 (RFC 8032) over the preimage. Same exit id, key and seed as pop.json, plus the time.",
            "context_utf8": std::str::from_utf8(POP_CONTEXT_V3).expect("ascii"),
            "context_hex": h(POP_CONTEXT_V3),
            "exit_id_hex": h(pop_exit_id.as_bytes()),
            "encapsulated_key_hex": h(pop_encap),
            "client_unix_secs": t,
            "preimage_hex": h(&preimage),
            "signing_key_seed_hex": h(seed),
            "signature_hex": h(sig.0),
        },
        "control": {
            "_comment": "marker 0xC0, version 0x03, postcard payload. Tags 17 to 21 are appended after TokenRejected 16.",
            "vectors": [
                control("ip_request_dated", "tag 17: the IpRequest fields (prefer_ipv4 Some(10.66.0.42), client_pubkey = the pop_v3 key, wants_ipv6 true, pop_sig = the pop_v3 signature, wants_daita true), then client_unix_secs as a varint", &wallet),
                control("ip_request_v7_dated", "tag 18: the IpRequestV7Detailed fields (prefer_ipv4 Some(0.0.0.0), wants_ipv6 false, one token of 0xcd, wants_daita false), then client_unix_secs", &tokens),
                control("ip_request_route_dated", "tag 19: the IpRequestRoute fields (prefer_ipv4 None, wants_ipv6 true, an 81-byte locator of 0x3c, wants_daita false), then client_unix_secs", &route),
                control("setup_refused_unspecified", "tag 20, code 0: not authorized", &refused(SetupRefusalCode::Unspecified)),
                control("setup_refused_clock_skew", "tag 20, code 1: the time is too far from the exit's clock", &refused(SetupRefusalCode::ClockSkew)),
                control("setup_refused_replayed", "tag 20, code 2: the exit already saw this setup key", &refused(SetupRefusalCode::Replayed)),
                control("setup_refused_busy", "tag 20, code 3: the exit cannot vouch for the setup's freshness now (its recent-key set is full, or it restarted within the retention window); another exit", &refused(SetupRefusalCode::Busy)),
                control("session_rekey", "tag 21: the new epoch's raw 32-byte key (that of rekey_frame_v2), then new_epoch 1 as a varint", &announce),
            ],
        },
        "rekey_frame_v2": {
            "_comment": "A SessionRekey sealed under epoch 0 of the deterministic /v2 session of pq_hpke_seal_v2.json (same recipient seeds, exit id 0xa2, m_seed 0x44, x25519 ephemeral seed 0x55). The new key is the ct_X of a second deterministic session (m_seed 0x46, x25519 ephemeral seed 0x57). A DATA frame: empty pq_ct. The sequence number is not reset at a rekey, hence a large one.",
            "exit_id_hex": h(rekey_exit_id.as_bytes()),
            "epoch0_mlkem768_m_seed_hex": h([0x44u8; 32]),
            "epoch0_x25519_ephemeral_seed_hex": h([0x55u8; 32]),
            "epoch0_encapsulated_key_hex": h(epoch0.encapsulated_key()),
            "epoch1_mlkem768_m_seed_hex": h([0x46u8; 32]),
            "epoch1_x25519_ephemeral_seed_hex": h([0x57u8; 32]),
            "epoch1_encapsulated_key_hex": h(epoch1.encapsulated_key()),
            "epoch": 0,
            "seq": seq,
            "plaintext_hex": h(&announce_plaintext),
            "frame_bytes_hex": h(&frame_bytes),
        },
    });
    println!("{}", serde_json::to_string_pretty(&doc).expect("json"));
}
