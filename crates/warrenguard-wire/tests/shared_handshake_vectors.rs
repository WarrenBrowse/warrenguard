//! Replays the shared handshake golden vectors in `vectors/handshake.json`
//! (the cross-repo warren-vectors anchor, a git submodule at the repo root).
//! These pin the byte-exact Setup/SetupAck wire layout that every consumer
//! (SDKs, backend) must reproduce; a failure means the engine codec drifted
//! from the frozen cross-language contract.

use serde::Deserialize;
use warrenguard_wire::{
    AUTH_SIG_LEN, AuthSig, DEVICE_ID_LEN, DaitaConfig, Setup, SetupAck, decode_setup,
    decode_setup_ack, encode_setup, encode_setup_ack,
};

#[derive(Deserialize)]
struct Vectors {
    protocol_version: u8,
    setup: SetupSection,
    setup_ack: SetupAckSection,
}

#[derive(Deserialize)]
struct SetupSection {
    vectors: Vec<SetupVec>,
}

#[derive(Deserialize)]
struct SetupVec {
    protocol_version: u8,
    features: u32,
    connection_index: u8,
    total_connections: u8,
    daita_support: bool,
    device_id_hex: String,
    client_pubkey_hex: String,
    auth_sig_hex: String,
    bytes_hex: String,
}

#[derive(Deserialize)]
struct SetupAckSection {
    vectors: Vec<SetupAckVec>,
}

#[derive(Deserialize)]
struct SetupAckVec {
    protocol_version: u8,
    tunnel_ipv4: [u8; 4],
    tunnel_ipv6_hex: Option<String>,
    exit_pubkey_hex: String,
    max_mtu: u16,
    multiconn_attached: bool,
    #[serde(default)]
    daita_spec: Option<DaitaSpecVec>,
    exit_auth_sig_hex: String,
    bytes_hex: String,
}

#[derive(Deserialize)]
struct DaitaSpecVec {
    machine_specs: Vec<String>,
    max_padding_frac: f64,
    max_blocking_frac: f64,
}

fn load() -> Vectors {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/handshake.json");
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("read vectors/handshake.json: {e}; run `git submodule update --init`")
    });
    serde_json::from_str(&raw).expect("parse vectors/handshake.json")
}

fn device_id(s: &str) -> [u8; DEVICE_ID_LEN] {
    hex::decode(s).expect("hex").try_into().expect("16 bytes")
}

#[test]
fn setup_vectors_match() {
    let v = load();
    assert_eq!(
        v.protocol_version,
        warrenguard_wire::PROTOCOL_VERSION,
        "vector file pins a different PROTOCOL_VERSION than the crate"
    );
    for vec in &v.setup.vectors {
        let s = Setup {
            protocol_version: vec.protocol_version,
            features: vec.features,
            connection_index: vec.connection_index,
            total_connections: vec.total_connections,
            daita_support: vec.daita_support,
            device_id: device_id(&vec.device_id_hex),
            client_pubkey: hex::decode(&vec.client_pubkey_hex)
                .expect("client_pubkey hex")
                .try_into()
                .expect("client_pubkey is 32 bytes"),
            auth_sig: AuthSig(
                hex::decode(&vec.auth_sig_hex)
                    .expect("auth_sig hex")
                    .try_into()
                    .expect("auth_sig is 64 bytes"),
            ),
        };
        assert_eq!(
            hex::encode(encode_setup(&s).expect("encode")),
            vec.bytes_hex,
            "Setup encode bytes drifted"
        );
        let decoded = decode_setup(&hex::decode(&vec.bytes_hex).expect("hex")).expect("decode");
        assert_eq!(decoded, s, "Setup decode drifted");
    }
}

#[test]
fn setup_ack_vectors_match() {
    let v = load();
    for vec in &v.setup_ack.vectors {
        let exit_pubkey: [u8; 32] = hex::decode(&vec.exit_pubkey_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let tunnel_ipv6 = vec
            .tunnel_ipv6_hex
            .as_ref()
            .map(|h| hex::decode(h).expect("hex").try_into().expect("16 bytes"));
        let daita_spec = vec.daita_spec.as_ref().map(|d| DaitaConfig {
            machine_specs: d.machine_specs.clone(),
            max_padding_frac: d.max_padding_frac,
            max_blocking_frac: d.max_blocking_frac,
        });
        let exit_auth_sig: [u8; AUTH_SIG_LEN] = hex::decode(&vec.exit_auth_sig_hex)
            .expect("hex")
            .try_into()
            .expect("auth sig is AUTH_SIG_LEN bytes");
        let a = SetupAck {
            protocol_version: vec.protocol_version,
            tunnel_ipv4: vec.tunnel_ipv4,
            tunnel_ipv6,
            exit_pubkey,
            max_mtu: vec.max_mtu,
            multiconn_attached: vec.multiconn_attached,
            daita_spec,
            exit_auth_sig: AuthSig(exit_auth_sig),
        };
        assert_eq!(
            hex::encode(encode_setup_ack(&a).expect("encode")),
            vec.bytes_hex,
            "SetupAck encode bytes drifted"
        );
        let decoded = decode_setup_ack(&hex::decode(&vec.bytes_hex).expect("hex")).expect("decode");
        assert_eq!(decoded, a, "SetupAck decode drifted");
    }
}
