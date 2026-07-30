//! Replays the shared NAT-PMP golden vectors in `vectors/natpmp.json` (the
//! cross-repo warren-vectors anchor, a git submodule at the repo root).
//!
//! These pin the port-forwarding wire: the RFC 6886 frames, the two Warren
//! result codes RFC 6886 has no equivalent for, the rate-limit response
//! trailer, and the credential trailer that buys one forwarded port. An exit
//! reads these bytes from clients it did not ship with, and a sibling-language
//! SDK has nothing else to check itself against, so a diff here is a wire
//! break rather than a test nuisance.

use std::net::Ipv4Addr;

use serde::Deserialize;
use warrenguard_natpmp_protocol::{
    CREDENTIAL_TRAILER_MAGIC, MAP_REQUEST_LEN, MAX_CREDENTIAL_LEN, MapProto, NATPMP_VERSION,
    RESPONSE_BIT, RateLimitInfo, Request, Response, ResultCode, append_credential_trailer,
    credential_trailer, parse_request, parse_response, serialize_request, serialize_response,
};

fn read() -> String {
    let path = format!("{}/../../vectors/natpmp.json", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("read vectors/natpmp.json: {e}; run `git submodule update --init`")
    })
}

#[derive(Deserialize)]
struct File {
    version: u8,
    response_bit: u8,
    map_request_len: usize,
    credential_trailer_magic: u16,
    max_credential_len: usize,
    requests: Vec<RequestVec>,
    credential_requests: Vec<CredentialVec>,
    malformed_credential_trailers: Vec<MalformedVec>,
    responses: Vec<ResponseVec>,
}

#[derive(Deserialize)]
struct RequestVec {
    name: String,
    kind: String,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    internal_port: u16,
    #[serde(default)]
    suggested_external_port: u16,
    #[serde(default)]
    lifetime_secs: u32,
    bytes_hex: String,
}

#[derive(Deserialize)]
struct CredentialVec {
    name: String,
    request: String,
    credential_hex: String,
    bytes_hex: String,
}

#[derive(Deserialize)]
struct MalformedVec {
    name: String,
    bytes_hex: String,
}

#[derive(Deserialize)]
struct RateLimitVec {
    attempts_remaining: u8,
    window_reset_secs: u16,
}

#[derive(Deserialize)]
struct ResponseVec {
    name: String,
    kind: String,
    #[serde(default)]
    proto: Option<String>,
    result_code: u16,
    epoch_secs: u32,
    #[serde(default)]
    internal_port: u16,
    #[serde(default)]
    external_port: u16,
    #[serde(default)]
    lifetime_secs: u32,
    #[serde(default)]
    external_ip: Option<String>,
    #[serde(default)]
    rate_limit: Option<RateLimitVec>,
    bytes_hex: String,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn proto_of(name: Option<&str>) -> MapProto {
    match name {
        Some("udp") => MapProto::Udp,
        Some("tcp") => MapProto::Tcp,
        other => panic!("unknown proto {other:?}"),
    }
}

fn result_of(code: u16) -> ResultCode {
    match code {
        0 => ResultCode::Success,
        1 => ResultCode::UnsupportedVersion,
        2 => ResultCode::NotAuthorized,
        3 => ResultCode::NetworkFailure,
        4 => ResultCode::OutOfResources,
        5 => ResultCode::UnsupportedOpcode,
        6 => ResultCode::SuggestedPortUnavailable,
        7 => ResultCode::RateLimited,
        other => panic!("unknown result code {other}"),
    }
}

fn load() -> File {
    serde_json::from_str(&read()).expect("parse vectors/natpmp.json")
}

#[test]
fn the_vector_file_pins_the_constants_the_frames_are_built_from() {
    let f = load();
    assert_eq!(f.version, NATPMP_VERSION);
    assert_eq!(f.response_bit, RESPONSE_BIT);
    assert_eq!(f.map_request_len, MAP_REQUEST_LEN);
    assert_eq!(f.credential_trailer_magic, CREDENTIAL_TRAILER_MAGIC);
    assert_eq!(f.max_credential_len, MAX_CREDENTIAL_LEN);
}

#[test]
fn request_vectors_round_trip() {
    let f = load();
    assert!(!f.requests.is_empty(), "vector file carries no request");
    for v in &f.requests {
        let req = match v.kind.as_str() {
            "external_address" => Request::ExternalAddress,
            "map" => Request::Map {
                proto: proto_of(v.proto.as_deref()),
                internal_port: v.internal_port,
                suggested_external_port: v.suggested_external_port,
                lifetime_secs: v.lifetime_secs,
            },
            other => panic!("unknown request kind {other}"),
        };
        let expected = unhex(&v.bytes_hex);
        assert_eq!(serialize_request(&req), expected, "serialize {}", v.name);
        assert_eq!(
            parse_request(&expected).expect("parse"),
            req,
            "parse {}",
            v.name
        );
    }
}

#[test]
fn response_vectors_round_trip() {
    let f = load();
    assert!(!f.responses.is_empty(), "vector file carries no response");
    for v in &f.responses {
        let resp = match v.kind.as_str() {
            "external_address" => Response::ExternalAddress {
                result_code: result_of(v.result_code),
                epoch_secs: v.epoch_secs,
                external_ip: v
                    .external_ip
                    .as_deref()
                    .expect("external_address vector needs external_ip")
                    .parse::<Ipv4Addr>()
                    .expect("ipv4"),
            },
            "map" => Response::Map {
                proto: proto_of(v.proto.as_deref()),
                result_code: result_of(v.result_code),
                epoch_secs: v.epoch_secs,
                internal_port: v.internal_port,
                external_port: v.external_port,
                lifetime_secs: v.lifetime_secs,
                rate_limit: v.rate_limit.as_ref().map(|r| RateLimitInfo {
                    attempts_remaining: r.attempts_remaining,
                    window_reset_secs: r.window_reset_secs,
                }),
            },
            other => panic!("unknown response kind {other}"),
        };
        let expected = unhex(&v.bytes_hex);
        assert_eq!(serialize_response(&resp), expected, "serialize {}", v.name);
        assert_eq!(
            parse_response(&expected).expect("parse"),
            resp,
            "parse {}",
            v.name
        );
    }
}

#[test]
fn credential_trailer_vectors_round_trip() {
    let f = load();
    assert!(
        !f.credential_requests.is_empty(),
        "vector file carries no credential request"
    );
    for v in &f.credential_requests {
        let base = f
            .requests
            .iter()
            .find(|r| r.name == v.request)
            .unwrap_or_else(|| panic!("{} names an unknown request {}", v.name, v.request));
        let mut frame = serialize_request(&Request::Map {
            proto: proto_of(base.proto.as_deref()),
            internal_port: base.internal_port,
            suggested_external_port: base.suggested_external_port,
            lifetime_secs: base.lifetime_secs,
        });
        let credential = unhex(&v.credential_hex);
        append_credential_trailer(&mut frame, &credential).expect("credential fits");
        assert_eq!(frame, unhex(&v.bytes_hex), "serialize {}", v.name);
        assert_eq!(
            credential_trailer(&frame),
            Some(credential.as_slice()),
            "read back {}",
            v.name
        );
        // The RFC frame in front must still parse the same, trailer or not:
        // that is what lets an exit predating the trailer serve the request.
        assert_eq!(
            parse_request(&frame).expect("parse"),
            parse_request(&frame[..MAP_REQUEST_LEN]).expect("parse"),
            "the trailer changed how {} reads",
            v.name
        );
    }
}

#[test]
fn a_malformed_trailer_reads_as_no_credential_and_never_as_a_refusal() {
    let f = load();
    assert!(
        !f.malformed_credential_trailers.is_empty(),
        "vector file carries no malformed trailer"
    );
    for v in &f.malformed_credential_trailers {
        let frame = unhex(&v.bytes_hex);
        assert_eq!(
            credential_trailer(&frame),
            None,
            "{} read as a credential",
            v.name
        );
        parse_request(&frame)
            .unwrap_or_else(|e| panic!("{} must still parse as a request: {e}", v.name));
    }
}
