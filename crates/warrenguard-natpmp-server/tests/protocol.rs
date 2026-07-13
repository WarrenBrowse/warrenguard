//! RFC 6886 wire format tests - vector tests + parse errors.
//!
//! The wire format is locked by the RFC; any accidental mutation of
//! byte order, endianness, or opcodes breaks these tests. This is
//! our main regression net on the protocol layer.

use std::net::Ipv4Addr;
use warrenguard_natpmp_server::protocol::Response;
use warrenguard_natpmp_server::protocol::{
    MapProto, ParseError, Request, ResultCode, parse_request, serialize_response,
};

// ---------------------------------------------------------------------------
// parse_request: 3 RFC 6886 variants + errors
// ---------------------------------------------------------------------------

#[test]
fn parses_external_address_request() {
    // RFC §3.2: version=0, opcode=0, total 2 bytes.
    let frame = [0x00, 0x00];
    let req = parse_request(&frame).expect("valid frame must parse");
    assert_eq!(req, Request::ExternalAddress);
}

#[test]
fn parses_udp_mapping_request() {
    // RFC §3.3: version=0, opcode=1 (UDP), reserved=0,
    // internal=0xC000 (49152), suggested_external=0 (let server
    // choose), lifetime=3600 (0x00000E10).
    let frame = [
        0x00, 0x01, // version=0, opcode=1 UDP
        0x00, 0x00, // reserved
        0xC0, 0x00, // internal port 49152 BE
        0x00, 0x00, // suggested external 0
        0x00, 0x00, 0x0E, 0x10, // lifetime 3600 BE
    ];
    let req = parse_request(&frame).expect("valid UDP map frame");
    assert_eq!(
        req,
        Request::Map {
            proto: MapProto::Udp,
            internal_port: 49152,
            suggested_external_port: 0,
            lifetime_secs: 3600,
        }
    );
}

#[test]
fn parses_tcp_mapping_request_with_suggested_port() {
    // opcode=2 (TCP), suggested_external=49200 (0xC030), lifetime=600.
    let frame = [
        0x00, 0x02, // version=0, opcode=2 TCP
        0x00, 0x00, // reserved
        0xC0, 0x30, // internal 49200
        0xC0, 0x30, // suggested external 49200 (typical qBittorrent)
        0x00, 0x00, 0x02, 0x58, // lifetime 600
    ];
    let req = parse_request(&frame).expect("valid TCP map frame");
    assert_eq!(
        req,
        Request::Map {
            proto: MapProto::Tcp,
            internal_port: 49200,
            suggested_external_port: 49200,
            lifetime_secs: 600,
        }
    );
}

#[test]
fn parses_lifetime_zero_as_delete_request() {
    // RFC §3.3.2: lifetime=0 = mapping deletion request. The parser
    // does not encode the semantic distinction (the allocator does);
    // it just returns lifetime_secs=0.
    let frame = [
        0x00, 0x01, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let req = parse_request(&frame).expect("valid delete request");
    if let Request::Map { lifetime_secs, .. } = req {
        assert_eq!(lifetime_secs, 0, "lifetime=0 must be preserved as-is");
    } else {
        panic!("expected Request::Map, got {req:?}");
    }
}

#[test]
fn rejects_frame_too_short_for_header() {
    // 1 byte < minimum 2 (version + opcode).
    let frame = [0x00];
    let err = parse_request(&frame).expect_err("must reject short frame");
    assert_eq!(err, ParseError::TooShort { got: 1, need: 2 });
}

#[test]
fn rejects_mapping_frame_too_short_for_payload() {
    // opcode=1 but only 6 bytes total (need 12).
    let frame = [0x00, 0x01, 0x00, 0x00, 0xC0, 0x00];
    let err = parse_request(&frame).expect_err("truncated payload must be rejected");
    assert_eq!(err, ParseError::TooShort { got: 6, need: 12 });
}

#[test]
fn rejects_unsupported_version() {
    // RFC §3: only version=0 is defined. Anything else =
    // UnsupportedVersion.
    let frame = [0x01, 0x00];
    let err = parse_request(&frame).expect_err("unknown version");
    assert_eq!(err, ParseError::UnsupportedVersion(1));
}

#[test]
fn rejects_unsupported_opcode() {
    // Defined opcodes: 0, 1, 2. Anything else = UnsupportedOpcode.
    let frame = [0x00, 0x07];
    let err = parse_request(&frame).expect_err("unknown opcode");
    assert_eq!(err, ParseError::UnsupportedOpcode(7));
}

// ---------------------------------------------------------------------------
// serialize_response: 12-byte external_addr + 16-byte map
// ---------------------------------------------------------------------------

#[test]
fn serializes_external_address_success_response() {
    // RFC §3.2.1: 12 bytes total, version + opcode|0x80 +
    // result_code + epoch (4B) + IPv4 (4B).
    let resp = Response::ExternalAddress {
        result_code: ResultCode::Success,
        epoch_secs: 0x12345678,
        external_ip: Ipv4Addr::new(203, 0, 113, 42),
    };
    let bytes = serialize_response(&resp);
    assert_eq!(
        bytes,
        vec![
            0x00, // version
            0x80, // opcode 0 | 0x80 (response)
            0x00, 0x00, // result code 0 = success
            0x12, 0x34, 0x56, 0x78, // epoch BE
            203, 0, 113, 42, // external IP
        ]
    );
}

#[test]
fn serializes_map_udp_response() {
    // RFC §3.3.1: 16 bytes, opcode UDP+0x80 = 0x81,
    // internal/external/lifetime.
    let resp = Response::Map {
        proto: MapProto::Udp,
        result_code: ResultCode::Success,
        epoch_secs: 100,
        internal_port: 49152,
        external_port: 49180,
        lifetime_secs: 3600,
        rate_limit: None,
    };
    let bytes = serialize_response(&resp);
    assert_eq!(
        bytes,
        vec![
            0x00, // version
            0x81, // opcode 1 UDP | 0x80
            0x00, 0x00, // success
            0x00, 0x00, 0x00, 0x64, // epoch 100
            0xC0, 0x00, // internal 49152
            0xC0, 0x1C, // external 49180
            0x00, 0x00, 0x0E, 0x10, // lifetime 3600
        ]
    );
}

#[test]
fn serializes_map_tcp_error_response() {
    // OutOfResources error with TCP opcode. Same format: still fill
    // every field, just with result_code != 0.
    let resp = Response::Map {
        proto: MapProto::Tcp,
        result_code: ResultCode::OutOfResources,
        epoch_secs: 0,
        internal_port: 8080,
        external_port: 0,
        lifetime_secs: 0,
        rate_limit: None,
    };
    let bytes = serialize_response(&resp);
    assert_eq!(bytes[0], 0x00, "version");
    assert_eq!(bytes[1], 0x82, "opcode 2 TCP | 0x80");
    assert_eq!(
        u16::from_be_bytes([bytes[2], bytes[3]]),
        ResultCode::OutOfResources as u16
    );
    assert_eq!(bytes.len(), 16, "map response = 16 bytes per RFC §3.3.1");
}

#[test]
fn serializes_response_uses_big_endian_for_all_integers() {
    // Global sanity: if someone replaces `to_be_bytes` with
    // `to_le_bytes` by mistake, this test breaks because we read in
    // BE explicitly.
    let resp = Response::Map {
        proto: MapProto::Udp,
        result_code: ResultCode::Success,
        epoch_secs: 0x01020304,
        internal_port: 0x0506,
        external_port: 0x0708,
        lifetime_secs: 0x090A0B0C,
        rate_limit: None,
    };
    let bytes = serialize_response(&resp);
    // bytes 4-7 = epoch big-endian
    assert_eq!(&bytes[4..8], &[0x01, 0x02, 0x03, 0x04]);
    // bytes 8-9 = internal port big-endian
    assert_eq!(&bytes[8..10], &[0x05, 0x06]);
    // bytes 10-11 = external port big-endian
    assert_eq!(&bytes[10..12], &[0x07, 0x08]);
    // bytes 12-15 = lifetime big-endian
    assert_eq!(&bytes[12..16], &[0x09, 0x0A, 0x0B, 0x0C]);
}

// ---------------------------------------------------------------------------
// Field-exposure sanity: every RFC field is reachable from outside
// the crate.
// ---------------------------------------------------------------------------

#[test]
fn parsed_map_request_exposes_all_fields() {
    // Regression guard: if someone hides a field (e.g. proto
    // private), this test breaks. All RFC fields must remain
    // reachable from outside the crate.
    let frame = [
        0x00, 0x02, 0x00, 0x00, 0xC0, 0x10, 0xC0, 0x10, 0x00, 0x00, 0x0E, 0x10,
    ];
    let req = parse_request(&frame).expect("frame ok");
    if let Request::Map {
        proto,
        internal_port,
        suggested_external_port,
        lifetime_secs,
    } = req
    {
        assert_eq!(proto, MapProto::Tcp);
        assert_eq!(internal_port, 49168);
        assert_eq!(suggested_external_port, 49168);
        assert_eq!(lifetime_secs, 3600);
    } else {
        panic!("expected Request::Map, got {req:?}");
    }
}
