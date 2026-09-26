//! Replays the shared multihop golden vectors in `vectors/multihop_frame.json`,
//! `vectors/multihop_frame_v2.json`, and `vectors/control.json` (the cross-repo
//! warren-vectors anchor, a git submodule at the repo root). These pin the
//! cross-language wire bytes for the HPKE dispatch frame (`/v1` and `/v2`) and
//! the `/v2` control messages: every consumer must reproduce them
//! byte-for-byte. A failure means the wire layout moved.

use serde::Deserialize;
use warrenguard_multihop::route_admission::{
    seal_route_anchor_with_ephemeral_ikm, seal_route_locator_with_ephemeral_ikm,
};
use warrenguard_multihop::{
    PopSignature, RouteAnchorSecret, RouteKemSecretKey, RouteSealError, SealedToApi,
    WarrenControlMessage, WarrenMultihopFrame, WarrenMultihopFrameV2, encode_control,
    try_decode_control,
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
    discriminant: Option<u8>,
    route_locator_hex: Option<String>,
    sealed_anchor_hex: Option<String>,
    session_token_hex: Option<String>,
    status: Option<u8>,
    max_routes: Option<u16>,
}

fn sealed(hex_str: &str) -> SealedToApi {
    SealedToApi::from_slice(&hex::decode(hex_str).expect("hex")).expect("81 bytes")
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
        // Both vectors share the variant and differ only by the trailing
        // product code, so the code comes from the file rather than the arm.
        "rejected_banned_unspecified" | "rejected_banned_port_forwarding" => {
            WarrenControlMessage::RejectedBanned {
                reason_code: v.reason_code.expect("reason_code"),
            }
        }
        "exit_draining" => WarrenControlMessage::ExitDraining {
            deadline_unix_secs: v.deadline_unix_secs.expect("deadline_unix_secs"),
            reason_code: v.reason_code.expect("reason_code"),
        },
        "ip_request_route_minimal" | "ip_request_route_full" => {
            WarrenControlMessage::IpRequestRoute {
                prefer_ipv4: v.prefer_ipv4,
                wants_ipv6: v.wants_ipv6,
                route_locator: sealed(v.route_locator_hex.as_ref().expect("route_locator_hex")),
                wants_daita: v.wants_daita,
            }
        }
        "route_rejected_anchor_unknown" | "route_rejected_route_limit" => {
            WarrenControlMessage::RouteRejected {
                reason_code: v.reason_code.expect("reason_code"),
            }
        }
        "route_anchor_request" | "route_anchor_request_with_token" => {
            WarrenControlMessage::RouteAnchorRequest {
                sealed_anchor: sealed(v.sealed_anchor_hex.as_ref().expect("sealed_anchor_hex")),
                session_token: v.session_token_hex.as_ref().map(|h| {
                    Box::new(warrenguard_wire::SessionToken(
                        hex::decode(h).expect("hex").try_into().expect("354 bytes"),
                    ))
                }),
            }
        }
        "route_anchor_ack_bound" | "route_anchor_ack_lost" => {
            WarrenControlMessage::RouteAnchorAck {
                status: v.status.expect("status"),
                max_routes: v.max_routes.expect("max_routes"),
            }
        }
        "route_ended_anchor_gone" => WarrenControlMessage::RouteEnded {
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
        let bytes = hex::decode(&v.bytes_hex).expect("hex");
        if let Some(discriminant) = v.discriminant {
            assert_eq!(bytes[2], discriminant, "`{}` discriminant moved", v.name);
        }
        assert_eq!(
            try_decode_control(&bytes).expect("decode").as_ref(),
            Some(&msg),
            "control message `{}` decode drifted from the frozen vector",
            v.name
        );
    }
}

// ---- route admission v1 (doc 107 section 6) ----

#[derive(Deserialize)]
struct RouteFile {
    version: u8,
    sealed_len: usize,
    kem_key: RouteKem,
    anchor_secret_hex: String,
    anchor_seal: RouteSeal,
    locator_seal: RouteSeal,
    derived: RouteDerived,
    invalid_opens: Vec<RouteInvalid>,
}

#[derive(Deserialize)]
struct RouteKem {
    signing_seed_hex: String,
    key_id: u8,
    pk_hex: String,
}

#[derive(Deserialize)]
struct RouteSeal {
    serial_hex: Option<String>,
    exit_id_hex: Option<String>,
    eph_ikm_hex: String,
    sealed_hex: String,
}

#[derive(Deserialize)]
struct RouteDerived {
    anchor_ref_hex: String,
    exit_id_hex: String,
    route_serial_hex: String,
}

#[derive(Deserialize)]
struct RouteInvalid {
    name: String,
    sealed_hex: String,
    open_as: String,
    serial_hex: Option<String>,
    exit_id_hex: Option<String>,
}

fn route_file() -> RouteFile {
    serde_json::from_str(&read("vectors/route_admission_v1.json")).expect("parse")
}

#[test]
fn route_admission_kem_key_and_seals_match() {
    let f = route_file();
    assert_eq!(
        (f.version, f.sealed_len),
        (1, warrenguard_multihop::SEALED_TO_API_LEN)
    );
    let key = RouteKemSecretKey::derive(&bytes32(&f.kem_key.signing_seed_hex), f.kem_key.key_id)
        .expect("derive");
    assert_eq!(
        hex::encode(key.public_key().to_bytes()),
        f.kem_key.pk_hex,
        "route KEM key derivation drifted"
    );
    let secret = || RouteAnchorSecret::from_bytes(bytes32(&f.anchor_secret_hex));
    let serial = bytes32(f.anchor_seal.serial_hex.as_ref().expect("serial_hex"));
    let exit_id = warrenguard_wire::ExitId::from_bytes(bytes16(
        f.locator_seal.exit_id_hex.as_ref().expect("exit_id_hex"),
    ));

    let anchor = seal_route_anchor_with_ephemeral_ikm(
        key.public_key(),
        &secret(),
        &serial,
        bytes32(&f.anchor_seal.eph_ikm_hex),
    )
    .expect("seal anchor");
    assert_eq!(
        hex::encode(anchor.to_bytes()),
        f.anchor_seal.sealed_hex,
        "anchor seal drifted"
    );
    let locator = seal_route_locator_with_ephemeral_ikm(
        key.public_key(),
        &secret(),
        &exit_id,
        bytes32(&f.locator_seal.eph_ikm_hex),
    )
    .expect("seal locator");
    assert_eq!(
        hex::encode(locator.to_bytes()),
        f.locator_seal.sealed_hex,
        "locator seal drifted"
    );

    let expected_ref = secret().anchor_ref();
    let opened = key
        .open_anchor(&sealed(&f.anchor_seal.sealed_hex), &serial)
        .expect("the vector anchor opens");
    assert_eq!(opened.anchor_ref(), expected_ref);
    let opened = key
        .open_locator(&sealed(&f.locator_seal.sealed_hex), &exit_id)
        .expect("the vector locator opens");
    assert_eq!(opened.anchor_ref(), expected_ref);

    assert_eq!(
        hex::encode(expected_ref.as_bytes()),
        f.derived.anchor_ref_hex
    );
    let route_exit = warrenguard_wire::ExitId::from_bytes(bytes16(&f.derived.exit_id_hex));
    assert_eq!(
        hex::encode(expected_ref.route_serial(&route_exit).as_bytes()),
        f.derived.route_serial_hex
    );
}

#[test]
fn route_admission_invalid_opens_are_refused() {
    let f = route_file();
    let key = RouteKemSecretKey::derive(&bytes32(&f.kem_key.signing_seed_hex), f.kem_key.key_id)
        .expect("derive");
    assert!(!f.invalid_opens.is_empty());
    for case in &f.invalid_opens {
        let blob = sealed(&case.sealed_hex);
        let result: Result<RouteAnchorSecret, RouteSealError> = match case.open_as.as_str() {
            "anchor" => key.open_anchor(&blob, &bytes32(case.serial_hex.as_ref().expect("serial"))),
            "locator" => key.open_locator(
                &blob,
                &warrenguard_wire::ExitId::from_bytes(bytes16(
                    case.exit_id_hex.as_ref().expect("exit id"),
                )),
            ),
            other => panic!("unknown open_as {other}"),
        };
        assert!(result.is_err(), "`{}` must be refused", case.name);
    }
}
