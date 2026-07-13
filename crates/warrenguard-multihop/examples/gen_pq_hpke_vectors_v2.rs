//! (Re-)generate the frozen `/v2` post-quantum golden vectors (X-Wing hybrid
//! seal frame + signed PQ exit descriptor).
//!
//! Run:
//! ```sh
//! ./scripts/dev/cargo-test-nofw.sh run -p warrenguard-multihop \
//!   --features pq-hpke --example gen_pq_hpke_vectors_v2
//! ```
//!
//! Emits a single JSON object to stdout. The seeds below are part of the frozen
//! contract: regenerating from different seeds invalidates every published
//! consumer. The output feeds the shared `warren-vectors` file
//! (`vectors/pq_hpke_seal_v2.json`), the single source of truth: the engine
//! test (`tests/pq_hpke_vectors_v2.rs`) and the six SDKs all replay that same
//! file directly.

#[cfg(not(feature = "pq-hpke"))]
fn main() {
    eprintln!("re-run with --features pq-hpke");
}

#[cfg(feature = "pq-hpke")]
fn main() {
    use ed25519_dalek::{Signer, SigningKey};
    use warrenguard_multihop::{
        ExitDescriptorSigned, ExitId, PqClientSession, PqExitSession, XWingRecipientSecretKey,
        exit_descriptor_signing_payload_pq,
    };

    // Deterministic exit recipient key from independent component seeds.
    let (exit_sk, exit_pk) =
        XWingRecipientSecretKey::derive_deterministic(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
    let mlkem768_ek = exit_sk.mlkem768_ek_bytes();
    let x25519_pubkey = exit_sk.x25519_pubkey();

    let exit_id = ExitId::from_bytes([0xa2; 16]);
    let m_seed = [0x44u8; 32];
    let eph_x_seed = [0x55u8; 32];
    let payload = b"warren pq /v2 golden setup payload";

    let client = PqClientSession::new_deterministic(&exit_pk, exit_id, &m_seed, &eph_x_seed)
        .expect("client");
    let setup = client.seal_setup(payload, 0, 0).expect("seal_setup");
    let setup_bytes = setup.encode().expect("encode setup");

    // Exit reconstructs the session from the setup frame and opens it, then
    // seals a reverse-direction reply.
    let exit = PqExitSession::new(&exit_sk, &setup.encapsulated_key, &setup.pq_ct, exit_id)
        .expect("exit session");
    let opened = exit.open(&setup).expect("exit open");
    assert_eq!(opened, payload, "round-trip must recover the payload");

    let reply_payload = b"warren pq /v2 reverse reply";
    let reply = exit
        .seal_response(reply_payload, 0, 0)
        .expect("seal_response");
    let reply_bytes = reply.encode().expect("encode reply");
    assert_eq!(
        client.open_response(&reply).expect("client open"),
        reply_payload
    );

    // Signed PQ descriptor over the same exit key material.
    let op = SigningKey::from_bytes(&[0x66; 32]);
    let dns_disabled = true;
    let signing_payload =
        exit_descriptor_signing_payload_pq(exit_id, &x25519_pubkey, dns_disabled, &mlkem768_ek);
    let signature = op.sign(&signing_payload).to_bytes();
    let descriptor = ExitDescriptorSigned {
        exit_id,
        exit_ed25519_pubkey: [0x77; 32],
        exit_x25519_multihop_pubkey: x25519_pubkey,
        endpoint: None,
        cover_domain: None,
        signature,
        dns_disabled,
        exit_mlkem768_pubkey: Some(mlkem768_ek.clone()),
    };
    let descriptor_json = serde_json::to_string(&descriptor).expect("descriptor json");

    let out = serde_json::json!({
        "_comment": "Frozen cross-implementation golden vectors for the Warren /v2 post-quantum multihop seal (X-Wing: X25519 + ML-KEM-768). Every SDK must reproduce these bytes. Any change is a wire break and requires a new version. See warrenguard docs 49/PQ.",
        "wire_version": 2,
        "recipient": {
            "_comment": "Exit recipient key derived from independent component seeds. mlkem768 keygen uses (d,z); x25519 scalar is sk_x_seed.",
            "mlkem768_d_seed_hex": hex::encode([0x11u8; 32]),
            "mlkem768_z_seed_hex": hex::encode([0x22u8; 32]),
            "x25519_sk_seed_hex": hex::encode([0x33u8; 32]),
            "mlkem768_ek_hex": hex::encode(&mlkem768_ek),
            "x25519_pubkey_hex": hex::encode(x25519_pubkey)
        },
        "encaps": {
            "mlkem768_m_seed_hex": hex::encode(m_seed),
            "x25519_ephemeral_seed_hex": hex::encode(eph_x_seed)
        },
        "forward_setup": {
            "_comment": "Client -> exit setup frame: encapsulated_key = ct_X (32), pq_ct = ct_M (1088), then the sealed payload.",
            "exit_id_hex": hex::encode(exit_id.as_bytes()),
            "epoch": 0,
            "seq": 0,
            "payload_hex": hex::encode(payload),
            "encapsulated_key_hex": hex::encode(setup.encapsulated_key),
            "pq_ct_hex": hex::encode(&setup.pq_ct),
            "aead_tag_hex": hex::encode(setup.aead_tag),
            "ciphertext_hex": hex::encode(&setup.ciphertext),
            "frame_bytes_hex": hex::encode(&setup_bytes)
        },
        "reverse_reply": {
            "_comment": "Exit -> client reply frame: reverse-direction key, empty pq_ct.",
            "epoch": 0,
            "seq": 0,
            "payload_hex": hex::encode(reply_payload),
            "encapsulated_key_hex": hex::encode(reply.encapsulated_key),
            "aead_tag_hex": hex::encode(reply.aead_tag),
            "ciphertext_hex": hex::encode(&reply.ciphertext),
            "frame_bytes_hex": hex::encode(&reply_bytes)
        },
        "exit_descriptor_pq": {
            "_comment": "Signed PQ descriptor. signing_payload = context || exit_id(16) || x25519(32) || dns_disabled_byte(1) || mlkem768_ek(1184). operational key seed = 0x66*32.",
            "operational_signing_key_seed_hex": hex::encode([0x66u8; 32]),
            "operational_pubkey_hex": hex::encode(op.verifying_key().to_bytes()),
            "dns_disabled": dns_disabled,
            "signing_payload_hex": hex::encode(&signing_payload),
            "signature_hex": hex::encode(signature),
            "descriptor_json": descriptor_json
        }
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("json"));
}
