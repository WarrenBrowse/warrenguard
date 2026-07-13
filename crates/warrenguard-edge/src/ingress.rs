//! Classifies a decoded HTTP/3 request as a browser WebTransport
//! extended-CONNECT (RFC 9220) or an ordinary request, and pulls the Privacy
//! Pass token the browser presents in its `Authorization: PrivateToken` header
//! (RFC 9577 section 2.2).

use crate::EdgeError;
use crate::http3::{FRAME_HEADERS, read_frame};
use crate::qpack::{self, Field};
use warrenguard_token::{TOKEN_LEN, Token};

/// A recognised browser WebTransport CONNECT reaching the edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTransportConnect {
    /// The `:authority` pseudo-header (the cover host the browser dialed).
    pub authority: String,
    /// The `:path` pseudo-header (the WebTransport endpoint path). A Warren
    /// edge advertises a fixed path; a mismatch is rejected upstream.
    pub path: String,
    /// The Privacy Pass token from the `Authorization: PrivateToken` header, if
    /// present and well-formed. `None` means the browser presented no usable
    /// token: the edge answers with a `WWW-Authenticate` challenge rather than
    /// admitting the session.
    pub token: Option<Token>,
}

/// The classification of a peer's first request stream once its HEADERS frame
/// has been QPACK-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeRequest {
    /// A browser WebTransport extended-CONNECT: admit as a multi-hop entry
    /// after verifying and spending the token. Boxed because it is far larger
    /// than the other variant (it carries a 354-byte token and two strings).
    WebTransport(Box<WebTransportConnect>),
    /// A well-formed HTTP/3 request that is not a WebTransport CONNECT (a plain
    /// GET from a browser or an active prober): serve the decoy.
    OtherHttp3,
}

fn header<'a>(fields: &'a [Field], name: &[u8]) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.value.as_slice())
}

/// Classifies a QPACK-encoded HEADERS field section (the payload of the request
/// stream's HEADERS frame) as a WebTransport CONNECT or an ordinary request.
///
/// The decisive test is RFC 9220 extended CONNECT: `:method = CONNECT` and
/// `:protocol = webtransport`. Everything else, including a malformed-but-not-
/// WebTransport request, classifies as [`EdgeRequest::OtherHttp3`] so the caller
/// serves the decoy and never reveals Warren behaviour.
///
/// # Errors
/// [`EdgeError`] only when the QPACK field section itself cannot be decoded
/// (truncation, an unsupported representation, or a Huffman literal). A decode
/// failure is a transport-level fault, distinct from "a valid non-WebTransport
/// request".
pub fn classify_request(field_section: &[u8]) -> Result<EdgeRequest, EdgeError> {
    let fields = qpack::decode_field_section(field_section)?;

    let is_connect = header(&fields, b":method") == Some(b"CONNECT");
    let is_webtransport = header(&fields, b":protocol") == Some(b"webtransport");
    if !(is_connect && is_webtransport) {
        return Ok(EdgeRequest::OtherHttp3);
    }

    let authority = header(&fields, b":authority")
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let path = header(&fields, b":path")
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let token = header(&fields, b"authorization").and_then(parse_private_token_header);

    Ok(EdgeRequest::WebTransport(Box::new(WebTransportConnect {
        authority,
        path,
        token,
    })))
}

/// Classifies the raw bytes of a peer's HTTP/3 request stream (the async
/// dispatcher's `accept_bi` read) rather than a bare QPACK field section.
///
/// A request stream begins with a HEADERS frame (RFC 9114 section 4.1). This
/// reads the first frame: if it is HEADERS, its payload is handed to
/// [`classify_request`]; any other leading frame is not a valid request opener,
/// so it classifies as [`EdgeRequest::OtherHttp3`] (the caller serves the decoy)
/// rather than erroring, keeping a malformed peer indistinguishable from an
/// ordinary non-WebTransport client.
///
/// # Errors
/// [`EdgeError::MalformedFrame`] if the bytes do not yet hold a complete leading
/// frame, or the QPACK decode error surfaced by [`classify_request`].
pub fn classify_request_stream(stream: &[u8]) -> Result<EdgeRequest, EdgeError> {
    let (frame, _used) = read_frame(stream).ok_or(EdgeError::MalformedFrame)?;
    if frame.ty != FRAME_HEADERS {
        return Ok(EdgeRequest::OtherHttp3);
    }
    classify_request(frame.payload)
}

/// Parses a Privacy Pass token out of an `Authorization: PrivateToken token="..."`
/// header value (RFC 9577 section 2.2). Returns the parsed [`Token`], or `None`
/// if the header is not a `PrivateToken` credential, the base64url is invalid,
/// or the decoded bytes are not a well-formed token. Only the first `token`
/// parameter is used.
pub fn parse_private_token_header(value: &[u8]) -> Option<Token> {
    let text = core::str::from_utf8(value).ok()?;
    // Scheme must be PrivateToken (case-insensitive per RFC 9110 credentials).
    let rest = text.trim_start();
    let (scheme, params) = rest.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("PrivateToken") {
        return None;
    }
    // Find token="..." among the auth params.
    let key = params.split(',').find_map(|p| {
        let p = p.trim();
        let (k, v) = p.split_once('=')?;
        (k.trim().eq_ignore_ascii_case("token")).then(|| v.trim().trim_matches('"'))
    })?;
    let bytes = base64url_decode(key)?;
    if bytes.len() != TOKEN_LEN {
        return None;
    }
    Token::parse(&bytes).ok()
}

/// Decodes unpadded base64url (RFC 4648 section 5), the encoding RFC 9577 uses
/// for the token parameter. Returns `None` on any invalid character or an
/// impossible length.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let input = input.trim_end_matches('='); // tolerate optional padding
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        acc = (acc << 6) | u32::from(val(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Any leftover bits must be zero padding, not data.
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix() -> Vec<u8> {
        vec![0x00, 0x00]
    }
    /// QPACK string literal with a 7-bit length prefix and the Huffman bit
    /// clear, correct for any length (including the ~472-char base64 token).
    fn lit_str(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = bytes.len();
        if len < 0x7f {
            out.push(len as u8); // bit7 (Huffman) stays 0
        } else {
            out.push(0x7f); // prefix all-ones, Huffman bit 0
            let mut rem = len - 0x7f;
            while rem >= 0x80 {
                out.push((rem as u8 & 0x7f) | 0x80);
                rem >>= 7;
            }
            out.push(rem as u8);
        }
        out.extend_from_slice(bytes);
        out
    }
    /// Literal field line with literal name (no Huffman) for an arbitrary
    /// header, so tests can build requests with names outside the static table.
    fn lit_name(name: &[u8], value: &[u8]) -> Vec<u8> {
        // 001 N=0 H=0 namelen(3+).
        let mut out = Vec::new();
        if name.len() < 7 {
            out.push(0x20 | name.len() as u8);
        } else {
            out.push(0x20 | 0x07);
            out.push((name.len() - 7) as u8);
        }
        out.extend_from_slice(name);
        out.extend_from_slice(&lit_str(value));
        out
    }

    fn webtransport_headers(with_auth: Option<&[u8]>) -> Vec<u8> {
        let mut buf = prefix();
        buf.push(0xc0 | 15); // indexed :method CONNECT
        buf.push(0xc0 | 23); // indexed :scheme https
        // :authority via name ref index 0
        buf.push(0x50);
        buf.extend_from_slice(&lit_str(b"nl1.edge.example.net"));
        // :path via name ref index 1
        buf.push(0x51);
        buf.extend_from_slice(&lit_str(b"/warren"));
        buf.extend_from_slice(&lit_name(b":protocol", b"webtransport"));
        if let Some(auth) = with_auth {
            buf.extend_from_slice(&lit_name(b"authorization", auth));
        }
        buf
    }

    #[test]
    fn classifies_a_webtransport_connect_without_token() {
        let req = classify_request(&webtransport_headers(None)).expect("classifies");
        match req {
            EdgeRequest::WebTransport(wt) => {
                assert_eq!(wt.authority, "nl1.edge.example.net");
                assert_eq!(wt.path, "/warren");
                assert!(wt.token.is_none());
            }
            other => panic!("expected WebTransport, got {other:?}"),
        }
    }

    #[test]
    fn a_plain_get_is_other_http3() {
        // :method GET (index 17), no :protocol.
        let mut buf = prefix();
        buf.push(0xc0 | 17);
        buf.push(0x51);
        buf.extend_from_slice(&lit_str(b"/"));
        assert_eq!(
            classify_request(&buf).expect("classifies"),
            EdgeRequest::OtherHttp3
        );
    }

    #[test]
    fn connect_without_webtransport_protocol_is_other_http3() {
        // :method CONNECT but no :protocol pseudo-header (an ordinary CONNECT).
        let mut buf = prefix();
        buf.push(0xc0 | 15);
        assert_eq!(
            classify_request(&buf).expect("classifies"),
            EdgeRequest::OtherHttp3
        );
    }

    #[test]
    fn base64url_round_trips_and_rejects_bad_input() {
        // "Man" -> "TWFu" in base64; base64url same for this input.
        assert_eq!(base64url_decode("TWFu").as_deref(), Some(&b"Man"[..]));
        // url-safe alphabet: 0xfb 0xff -> "-_8" ... just assert invalid char fails.
        assert_eq!(base64url_decode("bad*char"), None);
    }

    #[test]
    fn parse_private_token_rejects_a_non_privatetoken_scheme() {
        assert!(parse_private_token_header(b"Bearer abc").is_none());
    }

    #[test]
    fn parse_private_token_rejects_wrong_length() {
        // A valid PrivateToken header shape but a token that is not TOKEN_LEN.
        assert!(parse_private_token_header(br#"PrivateToken token="TWFu""#).is_none());
    }

    #[test]
    fn classify_request_stream_reads_the_headers_frame_then_classifies() {
        use crate::http3::{FRAME_DATA, encode_frame};
        // A real request stream: a HEADERS frame wrapping the field section.
        let stream = encode_frame(FRAME_HEADERS, &webtransport_headers(None));
        match classify_request_stream(&stream).expect("classifies") {
            EdgeRequest::WebTransport(wt) => assert_eq!(wt.path, "/warren"),
            other => panic!("expected WebTransport, got {other:?}"),
        }
        // A stream whose first frame is not HEADERS is not a valid request
        // opener: decoy, not a WebTransport admit.
        let data_first = encode_frame(FRAME_DATA, b"junk");
        assert_eq!(
            classify_request_stream(&data_first).expect("classifies"),
            EdgeRequest::OtherHttp3
        );
    }

    #[test]
    fn classify_request_stream_errors_on_a_truncated_frame() {
        // A HEADERS frame claiming 8 payload bytes but carrying only 2.
        use crate::varint;
        let mut buf = varint::encode(FRAME_HEADERS);
        buf.extend_from_slice(&varint::encode(8));
        buf.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            classify_request_stream(&buf),
            Err(EdgeError::MalformedFrame)
        );
    }

    #[test]
    fn classifies_webtransport_and_extracts_a_valid_token() {
        // Build a real token via the token crate, base64url it into the header,
        // and confirm the classifier round-trips it to an equal Token.
        let token_bytes = sample_token_bytes();
        let b64 = base64url_encode(&token_bytes);
        let header = format!("PrivateToken token=\"{b64}\"");
        let req =
            classify_request(&webtransport_headers(Some(header.as_bytes()))).expect("classifies");
        match req {
            EdgeRequest::WebTransport(wt) => {
                let token = wt.token.expect("token parsed");
                assert_eq!(token.serialize().as_slice(), token_bytes.as_slice());
            }
            other => panic!("expected WebTransport, got {other:?}"),
        }
    }

    // --- helpers that mint a real token for the extraction test ---

    fn base64url_encode(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            let take = chunk.len() + 1;
            for i in 0..take {
                out.push(A[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            }
        }
        out
    }

    fn sample_token_bytes() -> Vec<u8> {
        // A syntactically well-formed token: type 0x0002 then fixed-size fields.
        // Token::parse validates only the layout, not the signature, so this is
        // enough to exercise header extraction + parse round-trip.
        let mut t = Vec::with_capacity(TOKEN_LEN);
        t.extend_from_slice(&0x0002u16.to_be_bytes());
        t.extend_from_slice(&[0x11; 32]); // nonce
        t.extend_from_slice(&[0x22; 32]); // challenge digest
        t.extend_from_slice(&[0x33; 32]); // token key id
        t.extend_from_slice(&[0x44; 256]); // authenticator
        assert_eq!(t.len(), TOKEN_LEN);
        t
    }
}
