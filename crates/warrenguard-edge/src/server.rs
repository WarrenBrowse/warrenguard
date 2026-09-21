//! Server-side HTTP/3 bytes the edge writes: the control-stream SETTINGS that
//! open a connection, and the response HEADERS that answer a request.
//!
//! All pure and golden-byte testable (the async plumbing that writes them onto
//! `quinn` streams lives in the crates that consume this one):
//!
//! 1. [`control_stream_prelude`] / [`masque_control_stream_prelude`]: the
//!    server's control uni-stream contents (its stream type then a SETTINGS
//!    frame). Both pin `QPACK_MAX_TABLE_CAPACITY = 0`, which forbids the
//!    browser from using the QPACK dynamic table so every request it sends is
//!    decodable by the static-only [`crate::qpack`] decoder. The first also
//!    advertises WebTransport (extended CONNECT, HTTP datagrams, one WT
//!    session); the second advertises what a MASQUE proxy needs and nothing a
//!    proxy would not (extended CONNECT and HTTP datagrams).
//! 2. [`webtransport_accept_response`]: the `:status 200` HEADERS frame written
//!    on the CONNECT request stream, which establishes the WebTransport session
//!    (RFC 9220).
//! 3. [`encode_response_headers`] and the proxy responses built on it: the
//!    `407` challenge, the `200` that opens a TCP tunnel, the `200` with
//!    `capsule-protocol` that opens a UDP tunnel, and a bare status.

use crate::http3::{
    FRAME_HEADERS, FRAME_SETTINGS, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_ENABLE_WEBTRANSPORT,
    SETTINGS_H3_DATAGRAM, SETTINGS_QPACK_BLOCKED_STREAMS, SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    SETTINGS_WT_MAX_SESSIONS, STREAM_CONTROL, encode_frame,
};
use crate::qpack::encode_field_section;
use crate::varint;

/// The number of concurrent WebTransport sessions the edge admits per HTTP/3
/// connection. One is enough: a browser opens a single WebTransport session to
/// the edge and tunnels the Warren circuit inside it.
const EDGE_MAX_WT_SESSIONS: u64 = 1;

/// The `Proxy-Authenticate` challenge a proxy ingress answers a CONNECT with.
/// The realm is deliberately generic: it is plaintext to any peer that sends a
/// CONNECT, so a deployer's name there would identify the service to an
/// unauthenticated prober. Same string as the HTTP/1.1 ingress.
const PROXY_CHALLENGE: &[u8] = b"Basic realm=\"proxy\"";

/// Builds a SETTINGS frame payload from identifier/value pairs (RFC 9114
/// section 7.2.4).
fn settings_payload(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(id, value) in pairs {
        out.extend_from_slice(&varint::encode(id));
        out.extend_from_slice(&varint::encode(value));
    }
    out
}

/// The control stream-type varint (RFC 9114 section 6.2.1) then a SETTINGS
/// frame carrying `pairs`.
fn control_prelude(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut out = varint::encode(STREAM_CONTROL);
    out.extend_from_slice(&encode_frame(FRAME_SETTINGS, &settings_payload(pairs)));
    out
}

/// Builds the edge's SETTINGS frame payload: the identifier/value varint pairs
/// (RFC 9114 section 7.2.4) that make the browser treat this endpoint as a
/// WebTransport server using only the QPACK static table.
fn server_settings_payload() -> Vec<u8> {
    settings_payload(&[
        // Static-only QPACK: the browser must not use the dynamic table.
        (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        // WebTransport-over-HTTP/3 prerequisites.
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
        (SETTINGS_WT_MAX_SESSIONS, EDGE_MAX_WT_SESSIONS),
        // Advertise the legacy ENABLE_WEBTRANSPORT boolean too: some browser
        // WebTransport drafts gate the session on the server sending it in
        // addition to WT_MAX_SESSIONS.
        (SETTINGS_ENABLE_WEBTRANSPORT, 1),
    ])
}

/// The full contents the edge writes on its server-initiated control uni-stream:
/// the control stream-type varint (RFC 9114 section 6.2.1) followed by the
/// SETTINGS frame. A conformant browser reads this before it will send its
/// extended CONNECT.
#[must_use]
pub fn control_stream_prelude() -> Vec<u8> {
    let mut out = varint::encode(STREAM_CONTROL);
    out.extend_from_slice(&encode_frame(FRAME_SETTINGS, &server_settings_payload()));
    out
}

/// The control-stream contents a MASQUE proxy ingress writes: static-only
/// QPACK, extended CONNECT (RFC 9220, which `connect-udp` rides on) and HTTP
/// datagrams (RFC 9297). A browser sends no `connect-udp` request until it has
/// read the first of those two, so the ingress writes this before it answers
/// anything.
#[must_use]
pub fn masque_control_stream_prelude() -> Vec<u8> {
    control_prelude(&[
        (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
    ])
}

/// The QPACK-encoded field section for a bare `:status: 200` response.
///
/// Encoded field section prefix is Required Insert Count (0) and Delta Base (0),
/// i.e. two zero bytes, then an Indexed Field Line against the static table.
/// `:status 200` is static index 25; an indexed static line is `1` (indexed)
/// `1` (T = static) then the 6-bit index: `0xC0 | 25 = 0xD9`. Identical to the
/// decoy's status encoding, since a WebTransport accept is an ordinary HTTP/3
/// `200` at the framing layer.
fn qpack_status_200() -> Vec<u8> {
    vec![0x00, 0x00, 0xC0 | 25]
}

/// The HEADERS frame the edge writes on the CONNECT request stream to accept the
/// WebTransport session: a `:status 200` (RFC 9220 section 3.3). After this the
/// stream carries the WebTransport session's data.
#[must_use]
pub fn webtransport_accept_response() -> Vec<u8> {
    encode_frame(FRAME_HEADERS, &qpack_status_200())
}

/// A response HEADERS frame: `:status` then `fields`, statically QPACK-encoded.
#[must_use]
pub fn encode_response_headers(status: u16, fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let status = status.to_string();
    let mut lines: Vec<(&[u8], &[u8])> = Vec::with_capacity(fields.len() + 1);
    lines.push((b":status", status.as_bytes()));
    lines.extend_from_slice(fields);
    encode_frame(FRAME_HEADERS, &encode_field_section(&lines))
}

/// The `407` that asks a proxy client for a credential.
#[must_use]
pub fn proxy_challenge_response() -> Vec<u8> {
    encode_response_headers(407, &[(b"proxy-authenticate", PROXY_CHALLENGE)])
}

/// The `200` that opens a TCP tunnel on a CONNECT request stream (RFC 9114
/// section 4.4): from here the stream's DATA frames carry the tunnel bytes.
#[must_use]
pub fn connect_established_response() -> Vec<u8> {
    encode_response_headers(200, &[])
}

/// The `200` that opens a UDP tunnel on a CONNECT-UDP request stream (RFC 9298
/// section 3.1): it confirms the capsule protocol, and from here HTTP Datagrams
/// for the stream carry the UDP payloads.
#[must_use]
pub fn connect_udp_established_response() -> Vec<u8> {
    encode_response_headers(200, &[(b"capsule-protocol", b"?1")])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http3::{parse_settings, read_frame, read_uni_stream_type};
    use crate::qpack::decode_field_section;

    #[test]
    fn control_prelude_opens_the_control_stream_then_settings() {
        let bytes = control_stream_prelude();
        let (ty, rest) = read_uni_stream_type(&bytes).expect("stream type");
        assert_eq!(ty, STREAM_CONTROL);
        let (frame, used) = read_frame(rest).expect("settings frame");
        assert_eq!(frame.ty, FRAME_SETTINGS);
        assert_eq!(used, rest.len(), "the prelude is exactly type + one frame");
    }

    #[test]
    fn our_settings_advertise_webtransport_support() {
        // Re-parse our own SETTINGS through the peer-facing parser: the browser
        // must see a WebTransport-capable server.
        let bytes = control_stream_prelude();
        let (_ty, rest) = read_uni_stream_type(&bytes).expect("stream type");
        let (frame, _) = read_frame(rest).expect("settings frame");
        let settings = parse_settings(frame.payload);
        assert!(
            settings.supports_webtransport(),
            "the edge must advertise extended CONNECT + H3 datagram + WT sessions"
        );
    }

    #[test]
    fn our_settings_pin_qpack_dynamic_table_to_zero() {
        // The static-only qpack decoder is only safe if the browser never uses
        // the dynamic table, which QPACK_MAX_TABLE_CAPACITY=0 enforces. Assert
        // the exact pair is present in the payload.
        let payload = server_settings_payload();
        let mut rest = payload.as_slice();
        let mut found_cap = None;
        while !rest.is_empty() {
            let (id, n1) = varint::decode(rest).expect("id");
            let (val, n2) = varint::decode(&rest[n1..]).expect("value");
            if id == SETTINGS_QPACK_MAX_TABLE_CAPACITY {
                found_cap = Some(val);
            }
            rest = &rest[n1 + n2..];
        }
        assert_eq!(found_cap, Some(0), "QPACK_MAX_TABLE_CAPACITY must be 0");
    }

    #[test]
    fn accept_response_is_a_headers_frame_with_status_200() {
        let bytes = webtransport_accept_response();
        let (frame, used) = read_frame(&bytes).expect("frame");
        assert_eq!(frame.ty, FRAME_HEADERS);
        assert_eq!(used, bytes.len());
        // The status field section is server->client, so it uses static index 25
        // which our request-side decoder does not carry; assert the golden bytes
        // (matching the decoy's proven `:status 200` encoding) directly.
        assert_eq!(frame.payload, &[0x00, 0x00, 0xD9]);
    }

    #[test]
    fn accept_response_status_field_section_is_a_valid_indexed_line() {
        // Sanity on the prefix: RIC=0, Base=0, then a single indexed static line.
        // We add `:status 200` to a throwaway static-table view to confirm the
        // representation parses as one indexed field (not a literal), guarding
        // against a stray dynamic-table bit.
        let payload = qpack_status_200();
        // Index 25 (`:status 200`) is outside the request-side decoder subset, so
        // it decodes to a single placeholder field (skip-tolerant), proving the
        // byte is one indexed static line and not a literal or dynamic ref.
        let fields = decode_field_section(&payload).expect("one indexed static line");
        assert_eq!(fields.len(), 1, "exactly one field line");
        // And the last byte is unambiguously an indexed static line (top two bits
        // 1 then 1), never a literal or dynamic reference.
        let last = *payload.last().unwrap();
        assert_eq!(last & 0xC0, 0xC0, "indexed static field line");
    }
    #[test]
    fn masque_prelude_advertises_extended_connect_and_datagrams_only() {
        let bytes = masque_control_stream_prelude();
        let (ty, rest) = read_uni_stream_type(&bytes).expect("stream type");
        assert_eq!(ty, STREAM_CONTROL);
        let (frame, used) = read_frame(rest).expect("settings frame");
        assert_eq!(frame.ty, FRAME_SETTINGS);
        assert_eq!(used, rest.len());
        let settings = parse_settings(frame.payload);
        assert!(settings.enable_connect_protocol && settings.h3_datagram);
        assert!(
            !settings.webtransport,
            "a proxy ingress must not advertise WebTransport sessions"
        );
        // And the static-only QPACK pin, without which the decoder is unsafe.
        let mut rest = frame.payload;
        let mut cap = None;
        while !rest.is_empty() {
            let (id, n1) = varint::decode(rest).expect("id");
            let (val, n2) = varint::decode(&rest[n1..]).expect("value");
            if id == SETTINGS_QPACK_MAX_TABLE_CAPACITY {
                cap = Some(val);
            }
            rest = &rest[n1 + n2..];
        }
        assert_eq!(cap, Some(0));
    }

    #[test]
    fn proxy_challenge_is_a_407_with_the_generic_realm() {
        let bytes = proxy_challenge_response();
        let (frame, used) = read_frame(&bytes).expect("frame");
        assert_eq!((frame.ty, used), (FRAME_HEADERS, bytes.len()));
        let fields = decode_field_section(frame.payload).expect("decodes");
        assert_eq!(
            (&fields[0].name[..], &fields[0].value[..]),
            (&b":status"[..], &b"407"[..])
        );
        assert_eq!(fields[1].name, b"proxy-authenticate");
        let challenge = String::from_utf8_lossy(&fields[1].value).to_lowercase();
        assert!(challenge.contains("basic realm=\"proxy\""));
        assert!(
            !challenge.contains("warren"),
            "the realm is plaintext to anyone who sends a CONNECT"
        );
    }

    #[test]
    fn tunnel_responses_are_a_200_with_and_without_the_capsule_header() {
        let tcp = connect_established_response();
        let (frame, _) = read_frame(&tcp).expect("frame");
        assert_eq!(frame.payload, &[0x00, 0x00, 0xD9], "bare :status 200");
        let udp = connect_udp_established_response();
        let (frame, _) = read_frame(&udp).expect("frame");
        let fields = decode_field_section(frame.payload).expect("decodes");
        assert_eq!(fields[0].value, b"200");
        assert_eq!(
            (&fields[1].name[..], &fields[1].value[..]),
            (&b"capsule-protocol"[..], &b"?1"[..])
        );
    }

    #[test]
    fn a_bare_status_response_carries_only_the_status() {
        let bare = encode_response_headers(502, &[]);
        let (frame, _) = read_frame(&bare).expect("frame");
        let fields = decode_field_section(frame.payload).expect("decodes");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].value, b"502");
    }
}
