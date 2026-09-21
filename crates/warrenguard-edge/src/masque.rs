//! The pure half of a MASQUE proxy ingress (RFC 9298 CONNECT-UDP and plain
//! HTTP/3 CONNECT): classifying a request, reading the CONNECT-UDP target out
//! of its well-known path template, and the HTTP Datagram framing (RFC 9297)
//! that carries the tunnelled UDP payloads.
//!
//! Everything here is synchronous and allocation-light so it is testable
//! against golden bytes; the async proxy that drives it over `quinn` lives in
//! the `warrenguard-masque` crate.
//!
//! No-log discipline: the request carries the client's destination and its
//! proxy credential. Neither appears in an error value here, and the credential
//! is held in a type that zeroizes on drop and never renders.

use zeroize::Zeroize;

use crate::EdgeError;
use crate::ingress::header;
use crate::qpack;
use crate::varint;

/// The path prefix of the RFC 9298 well-known CONNECT-UDP template
/// (`/.well-known/masque/udp/{target_host}/{target_port}/`). The ingress
/// serves exactly this template on the bare cover host, which is what a
/// browser's `masqueTemplate` names.
pub const CONNECT_UDP_PATH_PREFIX: &str = "/.well-known/masque/udp/";

/// The query parameter of the CONNECT-UDP template that may carry the proxy
/// credential (the password half of the Basic credential, base64url). Firefox
/// sends no `proxy-authorization` on CONNECT-UDP and opens a dedicated HTTP/3
/// connection for those requests, so a credential can only reach the ingress
/// inside the template the browser expands; RFC 9298 leaves the rest of the
/// template to the deployer, and RFC 6570 expansion keeps a literal query.
pub const CONNECT_UDP_CREDENTIAL_PARAM: &str = "credential";

/// The HTTP Datagram context ID that carries a UDP payload on a CONNECT-UDP
/// stream (RFC 9298 section 5). Other context IDs are reserved for extensions
/// the ingress does not negotiate, so their datagrams are dropped.
pub const CONNECT_UDP_CONTEXT_ID: u64 = 0;

/// The capsule type carrying an HTTP Datagram on the request stream (RFC 9297
/// section 3.5), for a peer that cannot use QUIC datagrams.
pub const CAPSULE_DATAGRAM: u64 = 0x00;

/// The raw `proxy-authorization` header value a request carried. Bearer
/// material: zeroized on drop and never printable.
pub struct ProxyAuthorization(Vec<u8>);

impl ProxyAuthorization {
    /// The header value, for the credential parser that knows its scheme.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ProxyAuthorization {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Never derived: a credential must not be printable by accident.
impl core::fmt::Debug for ProxyAuthorization {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProxyAuthorization(<redacted>)")
    }
}

/// A plain HTTP/3 `CONNECT`: a TCP tunnel to `authority`.
#[derive(Debug)]
pub struct ProxyConnect {
    /// The `:authority` pseudo-header, the `host:port` to tunnel to.
    pub authority: String,
    /// The credential presented, when one was.
    pub proxy_authorization: Option<ProxyAuthorization>,
}

/// An extended `CONNECT` with `:protocol connect-udp` (RFC 9298): a UDP tunnel
/// to the target named by the path.
#[derive(Debug)]
pub struct ProxyConnectUdp {
    /// The `:path` pseudo-header, to be read with [`parse_connect_udp_target`].
    pub path: String,
    /// The credential presented, when one was.
    pub proxy_authorization: Option<ProxyAuthorization>,
    /// Whether the request carried `capsule-protocol: ?1`, which the RFC
    /// requires of a CONNECT-UDP client.
    pub capsule_protocol: bool,
}

/// What a request stream's HEADERS asked of a proxy ingress.
#[derive(Debug)]
pub enum ProxyRequest {
    /// A TCP tunnel request.
    Connect(ProxyConnect),
    /// A UDP tunnel request.
    ConnectUdp(ProxyConnectUdp),
    /// Anything else: a GET, a WebTransport CONNECT, an unknown `:protocol`.
    /// The caller answers it as an ordinary web server would.
    Other,
}

/// Classifies a QPACK-encoded request field section as a proxy request.
///
/// `:method CONNECT` without `:protocol` is a TCP tunnel (RFC 9114 section
/// 4.4); with `:protocol connect-udp` it is a UDP tunnel (RFC 9298). A CONNECT
/// carrying any other `:protocol` is not a proxy request, so a WebTransport
/// session request classifies as [`ProxyRequest::Other`].
///
/// # Errors
/// [`EdgeError`] only when the field section itself cannot be decoded.
pub fn classify_proxy_request(field_section: &[u8]) -> Result<ProxyRequest, EdgeError> {
    let fields = qpack::decode_field_section(field_section)?;
    if header(&fields, b":method") != Some(b"CONNECT") {
        return Ok(ProxyRequest::Other);
    }
    let proxy_authorization = header(&fields, b"proxy-authorization")
        .filter(|v| !v.is_empty())
        .map(|v| ProxyAuthorization(v.to_vec()));
    match header(&fields, b":protocol") {
        None => Ok(ProxyRequest::Connect(ProxyConnect {
            authority: header(&fields, b":authority")
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default(),
            proxy_authorization,
        })),
        Some(b"connect-udp") => Ok(ProxyRequest::ConnectUdp(ProxyConnectUdp {
            path: header(&fields, b":path")
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default(),
            proxy_authorization,
            capsule_protocol: header(&fields, b"capsule-protocol") == Some(b"?1"),
        })),
        Some(_) => Ok(ProxyRequest::Other),
    }
}

/// What a CONNECT-UDP `:path` names.
pub struct ConnectUdpTarget {
    /// The percent-decoded target host.
    pub host: String,
    /// The target port, never zero.
    pub port: u16,
    /// The credential the template carried in its query
    /// ([`CONNECT_UDP_CREDENTIAL_PARAM`]), when it did. Bearer material:
    /// zeroized on drop and never rendered.
    pub credential: Option<ProxyAuthorization>,
}

impl core::fmt::Debug for ConnectUdpTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectUdpTarget")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("credential", &self.credential.is_some())
            .finish()
    }
}

/// Reads the target out of a CONNECT-UDP `:path` written against the
/// well-known template: `/.well-known/masque/udp/{target_host}/{target_port}/`,
/// optionally followed by a query whose [`CONNECT_UDP_CREDENTIAL_PARAM`]
/// carries the proxy credential.
///
/// The host segment is percent-decoded (an IPv6 literal arrives with its
/// colons encoded, `2001%3Adb8%3A%3A1`). Returns `None` for any path that is
/// not exactly the template with a non-empty host and a non-zero port, so the
/// caller answers `400` rather than guessing. Query parameters other than the
/// credential are ignored.
#[must_use]
pub fn parse_connect_udp_target(path: &str) -> Option<ConnectUdpTarget> {
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path, None),
    };
    let rest = path.strip_prefix(CONNECT_UDP_PATH_PREFIX)?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = rest.split_once('/')?;
    if host.is_empty() || port.is_empty() || port.contains('/') {
        return None;
    }
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    let host = percent_decode(host)?;
    if host.is_empty()
        || host.len() > 255
        || host
            .bytes()
            .any(|b| b <= b' ' || b == b'/' || b == b'@' || b == b'\\' || b == 0x7f)
    {
        return None;
    }
    let credential = query
        .into_iter()
        .flat_map(|q| q.split('&'))
        .find_map(|pair| {
            pair.strip_prefix(CONNECT_UDP_CREDENTIAL_PARAM)?
                .strip_prefix('=')
        })
        .filter(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
        })
        .map(|v| ProxyAuthorization(v.as_bytes().to_vec()));
    Some(ConnectUdpTarget {
        host,
        port,
        credential,
    })
}

/// Decodes `%XX` escapes. Returns `None` on a malformed escape or a result that
/// is not UTF-8.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let text = core::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(text, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Encodes a UDP payload as the HTTP Datagram the proxy sends on the
/// connection for the CONNECT-UDP stream `session_id`: the Quarter Stream ID
/// varint, the context ID varint ([`CONNECT_UDP_CONTEXT_ID`]), then the
/// payload (RFC 9297 section 2.1, RFC 9298 section 5).
#[must_use]
pub fn encode_datagram(session_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = varint::encode(session_id >> 2);
    out.extend_from_slice(&varint::encode(CONNECT_UDP_CONTEXT_ID));
    out.extend_from_slice(payload);
    out
}

/// Reads an HTTP Datagram off a QUIC datagram: the Quarter Stream ID, the
/// context ID and the payload. `None` only if either varint is truncated.
#[must_use]
pub fn read_datagram(input: &[u8]) -> Option<(u64, u64, &[u8])> {
    let (quarter_stream_id, n) = varint::decode(input)?;
    let (context_id, m) = varint::decode(&input[n..])?;
    Some((quarter_stream_id, context_id, &input[n + m..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::encode_field_section;

    fn field<'a>(name: &'a [u8], value: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        (name, value)
    }

    fn connect(authority: &str, credential: Option<&str>) -> Vec<u8> {
        let mut fields = vec![
            field(b":method", b"CONNECT"),
            field(b":authority", authority.as_bytes()),
        ];
        if let Some(c) = credential {
            fields.push(field(b"proxy-authorization", c.as_bytes()));
        }
        encode_field_section(&fields)
    }

    fn connect_udp(path: &str, credential: Option<&str>, capsule: bool) -> Vec<u8> {
        let mut fields = vec![
            field(b":method", b"CONNECT"),
            field(b":protocol", b"connect-udp"),
            field(b":scheme", b"https"),
            field(b":authority", b"nl1.edge.example.net"),
            field(b":path", path.as_bytes()),
        ];
        if capsule {
            fields.push(field(b"capsule-protocol", b"?1"));
        }
        if let Some(c) = credential {
            fields.push(field(b"proxy-authorization", c.as_bytes()));
        }
        encode_field_section(&fields)
    }

    #[test]
    fn a_plain_connect_is_a_tcp_tunnel_with_its_credential() {
        let req = classify_proxy_request(&connect("example.com:443", Some("Basic abc")))
            .expect("classifies");
        match req {
            ProxyRequest::Connect(c) => {
                assert_eq!(c.authority, "example.com:443");
                assert_eq!(
                    c.proxy_authorization.expect("credential").as_bytes(),
                    b"Basic abc"
                );
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[test]
    fn a_connect_without_a_credential_reports_none() {
        match classify_proxy_request(&connect("example.com:443", None)).expect("classifies") {
            ProxyRequest::Connect(c) => assert!(c.proxy_authorization.is_none()),
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    #[test]
    fn connect_udp_is_a_udp_tunnel_carrying_path_and_capsule_flag() {
        let path = "/.well-known/masque/udp/example.com/443/";
        match classify_proxy_request(&connect_udp(path, None, true)).expect("classifies") {
            ProxyRequest::ConnectUdp(u) => {
                assert_eq!(u.path, path);
                assert!(u.capsule_protocol);
                assert!(u.proxy_authorization.is_none());
            }
            other => panic!("expected ConnectUdp, got {other:?}"),
        }
        match classify_proxy_request(&connect_udp(path, Some("Basic x"), false))
            .expect("classifies")
        {
            ProxyRequest::ConnectUdp(u) => {
                assert!(!u.capsule_protocol);
                assert!(u.proxy_authorization.is_some());
            }
            other => panic!("expected ConnectUdp, got {other:?}"),
        }
    }

    #[test]
    fn a_get_and_a_webtransport_connect_are_not_proxy_requests() {
        let get = encode_field_section(&[field(b":method", b"GET"), field(b":path", b"/")]);
        assert!(matches!(
            classify_proxy_request(&get).expect("classifies"),
            ProxyRequest::Other
        ));
        let wt = encode_field_section(&[
            field(b":method", b"CONNECT"),
            field(b":protocol", b"webtransport"),
            field(b":path", b"/warren"),
        ]);
        assert!(matches!(
            classify_proxy_request(&wt).expect("classifies"),
            ProxyRequest::Other
        ));
    }

    #[test]
    fn a_malformed_field_section_is_a_transport_fault() {
        assert_eq!(
            classify_proxy_request(&[0x05, 0x00]).expect_err("rejects"),
            EdgeError::MalformedFieldSection
        );
    }

    #[test]
    fn never_renders_the_credential() {
        let req = classify_proxy_request(&connect("a:1", Some("Basic super-secret")))
            .expect("classifies");
        let rendered = format!("{req:?}");
        assert!(
            !rendered.contains("super-secret"),
            "a credential must never reach a debug rendering"
        );
    }

    fn target(path: &str) -> Option<(String, u16)> {
        parse_connect_udp_target(path).map(|t| (t.host, t.port))
    }

    #[test]
    fn parses_the_well_known_template_with_and_without_the_trailing_slash() {
        assert_eq!(
            target("/.well-known/masque/udp/example.com/443/"),
            Some(("example.com".to_owned(), 443))
        );
        assert_eq!(
            target("/.well-known/masque/udp/example.com/443"),
            Some(("example.com".to_owned(), 443))
        );
        assert!(
            parse_connect_udp_target("/.well-known/masque/udp/example.com/443/")
                .expect("valid")
                .credential
                .is_none()
        );
    }

    #[test]
    fn percent_decodes_an_ipv6_literal_host() {
        assert_eq!(
            target("/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/"),
            Some(("2001:db8::1".to_owned(), 53))
        );
    }

    #[test]
    fn reads_the_credential_out_of_the_query_and_ignores_other_parameters() {
        let parsed = parse_connect_udp_target(
            "/.well-known/masque/udp/example.com/443/?x=1&credential=AbC-_9=&y=2",
        )
        .expect("valid");
        assert_eq!((parsed.host.as_str(), parsed.port), ("example.com", 443));
        assert_eq!(
            parsed.credential.expect("credential").as_bytes(),
            b"AbC-_9="
        );
        // An empty or malformed value is no credential, and never rendered.
        for path in [
            "/.well-known/masque/udp/example.com/443/?credential=",
            "/.well-known/masque/udp/example.com/443/?credential=a%20b",
            "/.well-known/masque/udp/example.com/443/?other=abc",
        ] {
            assert!(
                parse_connect_udp_target(path)
                    .expect("valid")
                    .credential
                    .is_none()
            );
        }
        let rendered = format!(
            "{:?}",
            parse_connect_udp_target("/.well-known/masque/udp/a/1/?credential=supersecret")
                .expect("valid")
        );
        assert!(!rendered.contains("supersecret"));
    }

    #[test]
    fn refuses_paths_that_are_not_exactly_the_template() {
        for path in [
            "/",
            "/.well-known/masque/udp/",
            "/.well-known/masque/udp/example.com/",
            "/.well-known/masque/udp//443/",
            "/.well-known/masque/udp/example.com/0/",
            "/.well-known/masque/udp/example.com/70000/",
            "/.well-known/masque/udp/example.com/443/extra",
            "/.well-known/masque/udp/exa%2Fmple.com/443/",
            "/.well-known/masque/udp/user@host/443/",
            "/.well-known/masque/udp/bad%zz/443/",
            "/other/example.com/443/",
        ] {
            assert!(
                parse_connect_udp_target(path).is_none(),
                "{path} must be refused"
            );
        }
    }

    #[test]
    fn datagram_is_quarter_stream_id_then_context_id_zero_then_payload() {
        // CONNECT-UDP stream id 8 -> quarter stream id 2, context id 0.
        assert_eq!(
            encode_datagram(8, b"UDP"),
            vec![0x02, 0x00, b'U', b'D', b'P']
        );
    }

    #[test]
    fn datagram_round_trips_and_exposes_a_foreign_context_id() {
        let encoded = encode_datagram(4, b"x");
        let (qsid, ctx, payload) = read_datagram(&encoded).expect("valid");
        assert_eq!((qsid, ctx, payload), (1, CONNECT_UDP_CONTEXT_ID, &b"x"[..]));
        // A datagram on a context the ingress never negotiated is reported as
        // such, so the caller drops it instead of forwarding it as UDP.
        let (_, ctx, _) = read_datagram(&[0x01, 0x07, 0xaa]).expect("valid");
        assert_eq!(ctx, 7);
        assert_eq!(read_datagram(&[0x40]), None, "truncated varint");
    }
}
