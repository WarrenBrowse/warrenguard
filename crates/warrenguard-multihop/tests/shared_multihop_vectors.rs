//! Replays the shared multihop golden vectors in `vectors/multihop_frame.json`,
//! `vectors/multihop_frame_v2.json`, and `vectors/control.json` (the cross-repo
//! warren-vectors anchor, a git submodule at the repo root). These pin the
//! cross-language wire bytes for the HPKE dispatch frame (`/v1` and `/v2`) and
//! the `/v2` control messages: every consumer must reproduce them
//! byte-for-byte. A failure means the wire layout moved.

use serde::Deserialize;
use warrenguard_multihop::{
    PopSignature, WarrenControlMessage, WarrenMultihopFrame, WarrenMultihopFrameV2, encode_control,
};
use warrenguard_wire::ExitId;

fn read(rel: &str) -> String {
    let path = format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {rel}: {e}; run `git submodule update --init`"))
}

fn bytes16(s: &str) -> [u8; 16] {
    hex::decode(s).expect("hex").try_into().expect("16 bytes")
}

fn bytes32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

// ---- multihop frame ----

#[derive(Deserialize)]
struct FrameFile {
    version: u8,
    vectors: Vec<FrameVec>,
}

#[derive(Deserialize)]
struct FrameVec {
    exit_id_hex: String,
    epoch: u32,
    seq: u64,
    encapsulated_key_hex: String,
    aead_tag_hex: String,
    ciphertext_hex: String,
    bytes_hex: String,
}

#[test]
fn multihop_frame_vectors_match() {
    let f: FrameFile = serde_json::from_str(&read("vectors/multihop_frame.json")).expect("parse");
    assert!(
        !f.vectors.is_empty(),
        "vector file must carry at least one case"
    );
    for v in &f.vectors {
        let frame = WarrenMultihopFrame {
            version: f.version,
            exit_id: ExitId::from_bytes(bytes16(&v.exit_id_hex)),
            epoch: v.epoch,
            seq: v.seq,
            encapsulated_key: bytes32(&v.encapsulated_key_hex),
            aead_tag: bytes16(&v.aead_tag_hex),
            ciphertext: hex::decode(&v.ciphertext_hex).expect("hex"),
        };
        assert_eq!(
            hex::encode(frame.encode().expect("encode")),
            v.bytes_hex,
            "multihop frame encode bytes drifted from the frozen vector"
        );
        let decoded =
            WarrenMultihopFrame::decode(&hex::decode(&v.bytes_hex).expect("hex")).expect("decode");
        assert_eq!(decoded, frame, "multihop frame decode drifted");
    }
}

// ---- multihop frame /v2 (post-quantum X-Wing seal) ----

#[derive(Deserialize)]
struct FrameV2File {
    version: u8,
    vectors: Vec<FrameV2Vec>,
}

#[derive(Deserialize)]
struct FrameV2Vec {
    exit_id_hex: String,
    epoch: u32,
    seq: u64,
    encapsulated_key_hex: String,
    pq_ct_hex: String,
    aead_tag_hex: String,
    ciphertext_hex: String,
    bytes_hex: String,
}

#[test]
fn multihop_frame_v2_vectors_match() {
    let f: FrameV2File =
        serde_json::from_str(&read("vectors/multihop_frame_v2.json")).expect("parse");
    assert!(
        f.vectors.len() >= 2,
        "expected both the setup (non-empty pq_ct) and steady-state (empty pq_ct) /v2 cases"
    );
    for v in &f.vectors {
        let frame = WarrenMultihopFrameV2 {
            version: f.version,
            exit_id: ExitId::from_bytes(bytes16(&v.exit_id_hex)),
            epoch: v.epoch,
            seq: v.seq,
            encapsulated_key: bytes32(&v.encapsulated_key_hex),
            pq_ct: hex::decode(&v.pq_ct_hex).expect("hex"),
            aead_tag: bytes16(&v.aead_tag_hex),
            ciphertext: hex::decode(&v.ciphertext_hex).expect("hex"),
        };
        assert_eq!(
            hex::encode(frame.encode().expect("encode")),
            v.bytes_hex,
            "/v2 multihop frame encode bytes drifted from the frozen vector"
        );
        let decoded = WarrenMultihopFrameV2::decode(&hex::decode(&v.bytes_hex).expect("hex"))
            .expect("decode");
        assert_eq!(decoded, frame, "/v2 multihop frame decode drifted");
    }
}

// ---- control messages (/v2) ----

#[derive(Deserialize)]
struct ControlFile {
    vectors: Vec<ControlVec>,
}

#[derive(Deserialize)]
struct ControlVec {
    name: String,
    bytes_hex: String,
    prefer_ipv4: Option<[u8; 4]>,
    client_pubkey_hex: Option<String>,
    #[serde(default)]
    wants_ipv6: bool,
    pop_sig_hex: Option<String>,
    ipv4: Option<[u8; 4]>,
    prefix_len: Option<u8>,
    gateway_ipv4: Option<[u8; 4]>,
    deadline_unix_secs: Option<u64>,
    reason_code: Option<u8>,
    #[serde(default)]
    wants_daita: bool,
    daita_spec: Option<DaitaSpecVec>,
}

/// The granted maybenot machine, mirrored from the vector so the replay drives
/// the real `DaitaConfig` rather than a hand-rolled stand-in.
#[derive(serde::Deserialize)]
struct DaitaSpecVec {
    machine_specs: Vec<String>,
    max_padding_frac: f64,
    max_blocking_frac: f64,
}

fn message_for(v: &ControlVec) -> WarrenControlMessage {
    match v.name.as_str() {
        "ip_request_minimal" | "ip_request_full" => WarrenControlMessage::IpRequest {
            prefer_ipv4: v.prefer_ipv4,
            client_pubkey: v.client_pubkey_hex.as_ref().map(|h| bytes32(h)),
            wants_ipv6: v.wants_ipv6,
            pop_sig: v
                .pop_sig_hex
                .as_ref()
                .map(|h| PopSignature(hex::decode(h).expect("hex").try_into().expect("64 bytes"))),
            wants_daita: v.wants_daita,
        },
        "ip_assign" | "ip_assign_with_daita" => WarrenControlMessage::IpAssign {
            ipv4: v.ipv4.expect("ipv4"),
            prefix_len: v.prefix_len.expect("prefix_len"),
            gateway_ipv4: v.gateway_ipv4.expect("gateway_ipv4"),
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: v
                .daita_spec
                .as_ref()
                .map(|d| warrenguard_wire::DaitaConfig {
                    machine_specs: d.machine_specs.clone(),
                    max_padding_frac: d.max_padding_frac,
                    max_blocking_frac: d.max_blocking_frac,
                }),
        },
        "ip_exhausted" => WarrenControlMessage::IpExhausted,
        "rejected" => WarrenControlMessage::Rejected,
        "exit_draining" => WarrenControlMessage::ExitDraining {
            deadline_unix_secs: v.deadline_unix_secs.expect("deadline_unix_secs"),
            reason_code: v.reason_code.expect("reason_code"),
        },
        other => panic!("unknown control vector name: {other}"),
    }
}

#[test]
fn control_vectors_match() {
    let f: ControlFile = serde_json::from_str(&read("vectors/control.json")).expect("parse");
    assert!(
        f.vectors.len() >= 5,
        "expected the full /v3 control message set"
    );
    for v in &f.vectors {
        let msg = message_for(v);
        assert_eq!(
            hex::encode(encode_control(&msg).expect("encode")),
            v.bytes_hex,
            "control message `{}` encode bytes drifted from the frozen vector",
            v.name
        );
    }
}
