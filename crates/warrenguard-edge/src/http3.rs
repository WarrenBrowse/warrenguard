//! Minimal HTTP/3 (RFC 9114) framing and SETTINGS parsing, request-side only:
//! just enough to read a peer's control-stream SETTINGS and the HEADERS frame
//! that carries its request. No response encoding lives here (the decoy owns
//! that), and no dynamic state: a browser is told, via our own SETTINGS, that
//! the QPACK dynamic table is disabled, so every request it sends is
//! statically decodable.

use crate::varint;

/// HTTP/3 frame type: DATA (RFC 9114 section 7.2.1).
pub const FRAME_DATA: u64 = 0x00;
/// HTTP/3 frame type: HEADERS (RFC 9114 section 7.2.2).
pub const FRAME_HEADERS: u64 = 0x01;
/// HTTP/3 frame type: SETTINGS (RFC 9114 section 7.2.4).
pub const FRAME_SETTINGS: u64 = 0x04;

/// HTTP/3 unidirectional stream type: control (RFC 9114 section 6.2.1).
pub const STREAM_CONTROL: u64 = 0x00;

/// SETTINGS identifier: SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204 section 5).
/// The edge advertises this as 0, which forbids the peer from using the QPACK
/// dynamic table: every request field line is then decodable from the static
/// table plus literals, which is exactly what [`crate::qpack`] supports.
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// SETTINGS identifier: SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 section 5).
/// Advertised as 0 (no blocked streams) for the same static-only reason.
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// SETTINGS identifier: SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 / RFC 8441).
/// A peer that sets this to 1 permits the extended-CONNECT method that
/// WebTransport is built on.
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// SETTINGS identifier: SETTINGS_H3_DATAGRAM (RFC 9297). WebTransport needs it.
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;
/// SETTINGS identifier: SETTINGS_WT_MAX_SESSIONS (draft-ietf-webtrans-http3).
/// Its presence (value >= 1) is a browser advertising WebTransport-over-HTTP/3.
pub const SETTINGS_WT_MAX_SESSIONS: u64 = 0xc671_706a;
/// SETTINGS identifier: SETTINGS_ENABLE_WEBTRANSPORT (older
/// draft-ietf-webtrans-http3 drafts). Some browsers still advertise WebTransport
/// with this boolean instead of (or alongside) `WT_MAX_SESSIONS`, so it is
/// treated as the same signal.
pub const SETTINGS_ENABLE_WEBTRANSPORT: u64 = 0x2b60_3742;

/// Encodes one HTTP/3 frame: `type` (varint) then `length` (varint) then the
/// payload (RFC 9114 section 7.1). The inverse of [`read_frame`].
pub fn encode_frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = varint::encode(ty);
    out.extend_from_slice(&varint::encode(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// One HTTP/3 frame parsed off a stream: its type and payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The frame type varint.
    pub ty: u64,
    /// The frame payload (already length-delimited).
    pub payload: &'a [u8],
}

/// Reads one HTTP/3 frame from the front of `input`, returning the frame and
/// the number of bytes consumed. Returns `None` if `input` does not yet hold a
/// complete frame (truncated type, length, or payload).
pub fn read_frame(input: &[u8]) -> Option<(Frame<'_>, usize)> {
    let (ty, n1) = varint::decode(input)?;
    let (len, n2) = varint::decode(&input[n1..])?;
    let header = n1 + n2;
    let end = header.checked_add(len as usize)?;
    if input.len() < end {
        return None;
    }
    Some((
        Frame {
            ty,
            payload: &input[header..end],
        },
        end,
    ))
}

/// The subset of a peer's SETTINGS relevant to admitting a browser
/// WebTransport session.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL was sent with a non-zero value.
    pub enable_connect_protocol: bool,
    /// SETTINGS_H3_DATAGRAM was sent with a non-zero value.
    pub h3_datagram: bool,
    /// SETTINGS_WT_MAX_SESSIONS was sent with a non-zero value.
    pub webtransport: bool,
}

impl Settings {
    /// True when the peer advertised everything a fully WebTransport-capable
    /// HTTP/3 endpoint sends: extended CONNECT, HTTP datagrams, and at least one
    /// WebTransport session. This is the check for a SERVER's own SETTINGS (the
    /// edge advertises all three).
    pub fn supports_webtransport(&self) -> bool {
        self.enable_connect_protocol && self.h3_datagram && self.webtransport
    }

    /// True when a CLIENT's SETTINGS advertise WebTransport. A browser client
    /// does NOT send `SETTINGS_ENABLE_CONNECT_PROTOCOL` (that is a server-only
    /// setting permitting extended CONNECT, RFC 9220), so the client signal is
    /// just HTTP datagrams plus a WebTransport-sessions advertisement. Requiring
    /// `enable_connect_protocol` here would wrongly reject every real browser.
    pub fn client_advertises_webtransport(&self) -> bool {
        self.h3_datagram && self.webtransport
    }
}

/// Parses a SETTINGS frame payload (a sequence of identifier/value varint
/// pairs, RFC 9114 section 7.2.4) into the WebTransport-relevant flags.
///
/// Unknown identifiers are ignored (as a conformant peer must), and a
/// truncated pair ends parsing at the last complete pair rather than erroring:
/// the flags reflect what was unambiguously present.
pub fn parse_settings(payload: &[u8]) -> Settings {
    let mut out = Settings::default();
    let mut rest = payload;
    while !rest.is_empty() {
        let Some((id, n1)) = varint::decode(rest) else {
            break;
        };
        let Some((value, n2)) = varint::decode(&rest[n1..]) else {
            break;
        };
        match id {
            SETTINGS_ENABLE_CONNECT_PROTOCOL => out.enable_connect_protocol = value != 0,
            SETTINGS_H3_DATAGRAM => out.h3_datagram = value != 0,
            SETTINGS_WT_MAX_SESSIONS | SETTINGS_ENABLE_WEBTRANSPORT => {
                // Either the current `WT_MAX_SESSIONS` (a count) or the legacy
                // `ENABLE_WEBTRANSPORT` boolean advertises WebTransport.
                out.webtransport = out.webtransport || value != 0;
            }
            _ => {}
        }
        rest = &rest[n1 + n2..];
    }
    out
}

/// Reads the leading uni-stream type varint (RFC 9114 section 6.2), returning
/// the type and the remaining bytes. `None` on a truncated type.
pub fn read_uni_stream_type(input: &[u8]) -> Option<(u64, &[u8])> {
    let (ty, n) = varint::decode(input)?;
    Some((ty, &input[n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_bytes(ty: u64, payload: &[u8]) -> Vec<u8> {
        encode_frame(ty, payload)
    }

    #[test]
    fn encode_frame_round_trips_through_read_frame() {
        let bytes = encode_frame(FRAME_SETTINGS, &[0x01, 0x00, 0x08, 0x01]);
        let (frame, used) = read_frame(&bytes).expect("frame");
        assert_eq!(frame.ty, FRAME_SETTINGS);
        assert_eq!(frame.payload, &[0x01, 0x00, 0x08, 0x01]);
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn reads_a_headers_frame_and_reports_consumption() {
        let bytes = frame_bytes(FRAME_HEADERS, &[0xaa, 0xbb, 0xcc]);
        let extra = [0xde, 0xad];
        let mut buf = bytes.clone();
        buf.extend_from_slice(&extra);
        let (frame, used) = read_frame(&buf).expect("frame");
        assert_eq!(frame.ty, FRAME_HEADERS);
        assert_eq!(frame.payload, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(used, bytes.len(), "does not consume the trailing bytes");
    }

    #[test]
    fn read_frame_is_none_on_a_truncated_payload() {
        let mut bytes = varint::encode(FRAME_DATA);
        bytes.extend_from_slice(&varint::encode(4));
        bytes.extend_from_slice(&[0x01, 0x02]); // only 2 of 4 payload bytes
        assert_eq!(read_frame(&bytes), None);
    }

    #[test]
    fn parses_a_webtransport_capable_settings_frame() {
        let mut payload = Vec::new();
        for (id, val) in [
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1u64),
            (SETTINGS_H3_DATAGRAM, 1),
            (SETTINGS_WT_MAX_SESSIONS, 1),
            (0x06, 0x1000), // SETTINGS_MAX_FIELD_SECTION_SIZE, ignored
        ] {
            payload.extend_from_slice(&varint::encode(id));
            payload.extend_from_slice(&varint::encode(val));
        }
        let settings = parse_settings(&payload);
        assert!(settings.supports_webtransport());
    }

    #[test]
    fn settings_without_wt_max_sessions_does_not_support_webtransport() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&varint::encode(SETTINGS_ENABLE_CONNECT_PROTOCOL));
        payload.extend_from_slice(&varint::encode(1));
        payload.extend_from_slice(&varint::encode(SETTINGS_H3_DATAGRAM));
        payload.extend_from_slice(&varint::encode(1));
        let settings = parse_settings(&payload);
        assert!(!settings.supports_webtransport());
        assert!(settings.enable_connect_protocol && settings.h3_datagram);
    }

    #[test]
    fn a_browser_client_advertises_webtransport_without_enable_connect_protocol() {
        // A real browser's control-stream SETTINGS carry H3_DATAGRAM and a
        // WebTransport-sessions count but NOT ENABLE_CONNECT_PROTOCOL (that is a
        // server-only setting). The client-side check must still recognise it.
        let mut payload = Vec::new();
        for (id, val) in [(SETTINGS_H3_DATAGRAM, 1u64), (SETTINGS_WT_MAX_SESSIONS, 1)] {
            payload.extend_from_slice(&varint::encode(id));
            payload.extend_from_slice(&varint::encode(val));
        }
        let settings = parse_settings(&payload);
        assert!(!settings.enable_connect_protocol);
        assert!(
            settings.client_advertises_webtransport(),
            "a browser must be recognised as a WebTransport client"
        );
        assert!(
            !settings.supports_webtransport(),
            "the strict server-capability check still requires enable_connect_protocol"
        );
    }

    #[test]
    fn the_legacy_enable_webtransport_setting_is_recognised() {
        let mut payload = Vec::new();
        for (id, val) in [
            (SETTINGS_H3_DATAGRAM, 1u64),
            (SETTINGS_ENABLE_WEBTRANSPORT, 1),
        ] {
            payload.extend_from_slice(&varint::encode(id));
            payload.extend_from_slice(&varint::encode(val));
        }
        assert!(parse_settings(&payload).client_advertises_webtransport());
    }

    #[test]
    fn settings_flag_off_when_value_is_zero() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&varint::encode(SETTINGS_ENABLE_CONNECT_PROTOCOL));
        payload.extend_from_slice(&varint::encode(0));
        assert!(!parse_settings(&payload).enable_connect_protocol);
    }

    #[test]
    fn reads_the_control_uni_stream_type() {
        let mut bytes = varint::encode(STREAM_CONTROL);
        bytes.extend_from_slice(&[0x04, 0x00]);
        let (ty, rest) = read_uni_stream_type(&bytes).expect("type");
        assert_eq!(ty, STREAM_CONTROL);
        assert_eq!(rest, &[0x04, 0x00]);
    }
}
