//! WebTransport-over-HTTP/3 stream and datagram framing
//! (draft-ietf-webtrans-http3-02, the wire Chrome speaks).
//!
//! Once the edge has accepted the extended-CONNECT session (see
//! [`crate::webtransport_accept_response`]), the browser tunnels the Warren
//! circuit inside the WebTransport session. WebTransport does not hand the raw
//! QUIC streams and datagrams straight through: each is prefixed so the peer can
//! demultiplex it back to its owning session.
//!
//! - A **bidirectional** WebTransport stream is a client-initiated HTTP/3 bidi
//!   stream whose first bytes are the signal value
//!   [`WEBTRANSPORT_STREAM_BIDI`] (`0x41`) then the Session ID varint (the
//!   stream ID of the CONNECT request stream). The remaining bytes are the WT
//!   stream body.
//! - A **unidirectional** WebTransport stream is an HTTP/3 uni stream whose
//!   stream-type varint is [`WEBTRANSPORT_STREAM_UNI`] (`0x54`) then the Session
//!   ID varint, then the body.
//! - A WebTransport **datagram** is an HTTP Datagram (RFC 9297) whose payload is
//!   the Quarter Stream ID varint (Session ID `>> 2`) then the WT datagram bytes.
//!
//! Everything here is pure and golden-byte testable: the async code that reads
//! these off `quinn` streams and the connection's datagram channel lives in the
//! node crate that drives the multi-hop entry pump.

use crate::varint;

/// Signal value that opens a bidirectional WebTransport stream on a
/// client-initiated HTTP/3 bidi stream (draft-ietf-webtrans-http3 section 4.2).
pub const WEBTRANSPORT_STREAM_BIDI: u64 = 0x41;

/// Stream type that opens a unidirectional WebTransport stream on an HTTP/3 uni
/// stream (draft-ietf-webtrans-http3 section 4.1).
pub const WEBTRANSPORT_STREAM_UNI: u64 = 0x54;

/// Encodes the header that opens a bidirectional WebTransport stream for
/// `session_id`: the [`WEBTRANSPORT_STREAM_BIDI`] signal varint then the Session
/// ID varint. The WT stream body follows verbatim.
#[must_use]
pub fn encode_bidi_stream_header(session_id: u64) -> Vec<u8> {
    let mut out = varint::encode(WEBTRANSPORT_STREAM_BIDI);
    out.extend_from_slice(&varint::encode(session_id));
    out
}

/// Encodes the header that opens a unidirectional WebTransport stream for
/// `session_id`: the [`WEBTRANSPORT_STREAM_UNI`] stream-type varint then the
/// Session ID varint.
#[must_use]
pub fn encode_uni_stream_header(session_id: u64) -> Vec<u8> {
    let mut out = varint::encode(WEBTRANSPORT_STREAM_UNI);
    out.extend_from_slice(&varint::encode(session_id));
    out
}

/// Reads a bidirectional WebTransport stream header off the front of `input`,
/// returning the Session ID and the remaining (body) bytes.
///
/// Returns `None` if the leading signal is not [`WEBTRANSPORT_STREAM_BIDI`] or
/// either varint is truncated: the caller treats that as a non-WebTransport
/// stream (an HTTP/3 request or a protocol violation) rather than a WT stream.
#[must_use]
pub fn read_bidi_stream_header(input: &[u8]) -> Option<(u64, &[u8])> {
    let (signal, n) = varint::decode(input)?;
    if signal != WEBTRANSPORT_STREAM_BIDI {
        return None;
    }
    let (session_id, m) = varint::decode(&input[n..])?;
    Some((session_id, &input[n + m..]))
}

/// Reads a unidirectional WebTransport stream header off the front of `input`
/// (its stream-type varint has already been confirmed to be
/// [`WEBTRANSPORT_STREAM_UNI`] by the uni-stream demux), returning the Session
/// ID and the remaining bytes. `input` starts at the Session ID varint.
#[must_use]
pub fn read_uni_stream_session_id(input: &[u8]) -> Option<(u64, &[u8])> {
    varint::decode(input).map(|(session_id, n)| (session_id, &input[n..]))
}

/// The Quarter Stream ID of a WebTransport session: the CONNECT stream ID
/// divided by four (draft-ietf-webtrans-http3 section 5, RFC 9297). It is the
/// context ID that prefixes every WebTransport datagram for the session.
#[must_use]
pub fn quarter_stream_id(session_id: u64) -> u64 {
    session_id >> 2
}

/// Encodes a WebTransport datagram payload for `session_id`: the Quarter Stream
/// ID varint then the datagram `payload`. This is the HTTP Datagram payload the
/// node hands to `Connection::send_datagram`.
#[must_use]
pub fn encode_datagram(session_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = varint::encode(quarter_stream_id(session_id));
    out.extend_from_slice(payload);
    out
}

/// Reads a WebTransport datagram off `input`, returning the Quarter Stream ID
/// and the datagram payload (the remaining bytes). Returns `None` only if the
/// leading Quarter Stream ID varint is truncated.
#[must_use]
pub fn read_datagram(input: &[u8]) -> Option<(u64, &[u8])> {
    varint::decode(input).map(|(qsid, n)| (qsid, &input[n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bidi_stream_header_is_the_signal_then_session_id() {
        // The signal 0x41 is a QUIC varint: 0x41 == 65 >= 64 so it is the
        // two-byte form 0x40 0x41, then the single-byte session id 0x04. Pins
        // the exact draft-02 wire (the value is 0x41, its varint encoding is
        // two bytes).
        let header = encode_bidi_stream_header(4);
        assert_eq!(header, vec![0x40, 0x41, 0x04]);
    }

    #[test]
    fn bidi_stream_header_round_trips_and_returns_the_body() {
        let mut stream = encode_bidi_stream_header(0x3fff);
        stream.extend_from_slice(b"warren-setup-frame");
        let (session_id, body) = read_bidi_stream_header(&stream).expect("valid WT bidi header");
        assert_eq!(session_id, 0x3fff);
        assert_eq!(body, b"warren-setup-frame");
    }

    #[test]
    fn read_bidi_rejects_a_non_webtransport_signal() {
        // An HTTP/3 HEADERS frame (type 0x01) is not a WT bidi stream: the demux
        // must refuse it so a request stream is never mistaken for a WT stream.
        let not_wt = [0x01, 0x00, 0x00];
        assert_eq!(read_bidi_stream_header(&not_wt), None);
    }

    #[test]
    fn read_bidi_is_none_on_a_truncated_session_id() {
        // Signal present, but the session-id varint announces 2 bytes and only
        // one follows: incomplete header, not a protocol error yet.
        let truncated = [0x41, 0x40];
        assert_eq!(read_bidi_stream_header(&truncated), None);
    }

    #[test]
    fn uni_stream_header_is_the_type_then_session_id() {
        // Type 0x54 == 84 >= 64, so its varint is the two-byte 0x40 0x54, then
        // the single-byte session id 0x08.
        let header = encode_uni_stream_header(8);
        assert_eq!(header, vec![0x40, 0x54, 0x08]);
        // And reading past the already-consumed 2-byte type varint yields the
        // id + body.
        let (session_id, rest) = read_uni_stream_session_id(&header[2..]).expect("session id");
        assert_eq!(session_id, 8);
        assert!(rest.is_empty());
    }

    #[test]
    fn quarter_stream_id_divides_the_session_id_by_four() {
        // RFC 9297 / draft-02: the datagram context id is the CONNECT stream id
        // divided by four. Client-initiated bidi stream ids are 0,4,8,12,...
        assert_eq!(quarter_stream_id(0), 0);
        assert_eq!(quarter_stream_id(4), 1);
        assert_eq!(quarter_stream_id(8), 2);
        assert_eq!(quarter_stream_id(0xffff_fffc), 0x3fff_ffff);
    }

    #[test]
    fn datagram_is_the_quarter_stream_id_then_payload() {
        // Session id 4 -> quarter-stream-id 1 -> single byte 0x01 prefix.
        let dgram = encode_datagram(4, b"DATA");
        assert_eq!(dgram, vec![0x01, b'D', b'A', b'T', b'A']);
    }

    #[test]
    fn datagram_round_trips_the_quarter_stream_id_and_payload() {
        let dgram = encode_datagram(0x400, b"\x00\x01\x02payload");
        let (qsid, payload) = read_datagram(&dgram).expect("valid datagram");
        assert_eq!(qsid, quarter_stream_id(0x400));
        assert_eq!(payload, b"\x00\x01\x02payload");
    }

    #[test]
    fn read_datagram_of_an_empty_payload_yields_the_qsid_and_empty_bytes() {
        let dgram = encode_datagram(8, b"");
        let (qsid, payload) = read_datagram(&dgram).expect("qsid-only datagram");
        assert_eq!(qsid, 2);
        assert!(payload.is_empty());
    }
}
