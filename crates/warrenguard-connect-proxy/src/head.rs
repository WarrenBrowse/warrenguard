//! Parsing of an HTTP/1.1 CONNECT request head, and the responses to it.
//!
//! Deliberately a hand-written parser over a byte slice rather than a general
//! HTTP stack: this ingress accepts exactly one request shape, so a parser that
//! understands only that shape has the smallest attack surface and needs no
//! dependency. Everything here is pure, so the whole admission surface is
//! unit-testable without a socket.

use data_encoding::BASE64;
use zeroize::Zeroize;

/// Upper bound on the request head we buffer before refusing. A browser's
/// CONNECT head is a few hundred bytes; this bounds what a peer can make the
/// ingress hold before it has proved anything.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;

/// The fixed username the credential rides under. Only the password carries the
/// anonymous token, so nothing account-shaped is ever on the wire.
pub const CREDENTIAL_USERNAME: &str = "warren";

/// Why a request head could not be accepted. Every variant is value-free: a
/// request head carries the client's destination and its credential, and
/// neither may reach an error string or a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HeadError {
    /// The head passed [`MAX_HEAD_BYTES`] before it was complete.
    #[error("request head exceeds the size bound")]
    TooLarge,
    /// The request line does not hold exactly a method, a target and a version.
    #[error("request line is malformed")]
    MalformedRequestLine,
    /// The method is something else, typically the absolute-form request a
    /// browser sends for a plain-http URL.
    #[error("method is not CONNECT")]
    NotConnect,
    /// The version is not `HTTP/1.1`.
    #[error("HTTP version is not 1.1")]
    UnsupportedVersion,
    /// The target is not a usable `host:port`.
    #[error("authority form is malformed")]
    MalformedAuthority,
    /// A header line carries no colon.
    #[error("header line is malformed")]
    MalformedHeader,
    /// Two credentials were offered, so which one the peer meant is undefined.
    #[error("more than one Proxy-Authorization header")]
    DuplicateCredential,
    /// The authentication scheme is not `Basic`.
    #[error("proxy authentication scheme is not Basic")]
    UnsupportedAuthScheme,
    /// The credential does not decode, or holds no password.
    #[error("proxy credential is malformed")]
    MalformedCredential,
}

/// A validated `host:port` authority, the only target form CONNECT carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    host: String,
    port: u16,
}

impl Authority {
    /// Parses the authority form of a CONNECT target (`example.com:443`,
    /// `[2001:db8::1]:443`).
    ///
    /// # Errors
    /// [`HeadError::MalformedAuthority`] when the host or the port is missing,
    /// empty, or out of range.
    pub fn parse(raw: &str) -> Result<Self, HeadError> {
        let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
            // IPv6 literal: the colons inside the brackets are part of the host.
            let (inside, after) = rest.split_once(']').ok_or(HeadError::MalformedAuthority)?;
            let port = after
                .strip_prefix(':')
                .ok_or(HeadError::MalformedAuthority)?;
            (inside, port)
        } else {
            raw.rsplit_once(':').ok_or(HeadError::MalformedAuthority)?
        };
        if host.is_empty() || host.len() > 255 {
            return Err(HeadError::MalformedAuthority);
        }
        // A host with a slash, a space or a control byte is not a host: refuse
        // rather than hand it to a resolver.
        if host
            .bytes()
            .any(|b| b <= b' ' || b == b'/' || b == b'@' || b == b'\\' || b == 0x7f)
        {
            return Err(HeadError::MalformedAuthority);
        }
        let port: u16 = port.parse().map_err(|_| HeadError::MalformedAuthority)?;
        if port == 0 {
            return Err(HeadError::MalformedAuthority);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The host half, with the brackets of an IPv6 literal removed.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port half, always non-zero.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// The decoded password half of a `Proxy-Authorization: Basic` header: the
/// client's anonymous bearer credential. Zeroized on drop and never rendered.
pub struct ProxyCredential(Vec<u8>);

impl ProxyCredential {
    /// The credential bytes, for the admitter that knows how to read them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ProxyCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Never derived: a credential must not be printable by accident.
impl core::fmt::Debug for ProxyCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProxyCredential(<redacted>)")
    }
}

/// A parsed CONNECT request head.
#[derive(Debug)]
pub struct ConnectHead {
    /// Where the client asked to be connected.
    pub target: Authority,
    /// The credential it presented, when it presented one.
    pub credential: Option<ProxyCredential>,
    /// Bytes of `buf` the head occupied, so the caller can keep the remainder.
    pub head_len: usize,
}

/// Parses a CONNECT request head out of `buf`.
///
/// Returns `Ok(None)` when `buf` holds no complete head yet and is still under
/// the size bound, so the caller reads more.
///
/// # Errors
/// [`HeadError`] for any head that is complete and unacceptable, and
/// [`HeadError::TooLarge`] for an incomplete one past [`MAX_HEAD_BYTES`].
pub fn parse_connect_head(buf: &[u8]) -> Result<Option<ConnectHead>, HeadError> {
    let Some(end) = find_head_end(buf) else {
        if buf.len() > MAX_HEAD_BYTES {
            return Err(HeadError::TooLarge);
        }
        return Ok(None);
    };
    if end > MAX_HEAD_BYTES {
        return Err(HeadError::TooLarge);
    }
    // A head that reached us is ASCII by construction of HTTP/1.1; anything else
    // is not a request we serve.
    let head = core::str::from_utf8(&buf[..end]).map_err(|_| HeadError::MalformedHeader)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(HeadError::MalformedRequestLine)?;

    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(HeadError::MalformedRequestLine)?;
    let target = parts.next().ok_or(HeadError::MalformedRequestLine)?;
    let version = parts.next().ok_or(HeadError::MalformedRequestLine)?;
    if parts.next().is_some() {
        return Err(HeadError::MalformedRequestLine);
    }
    if method != "CONNECT" {
        return Err(HeadError::NotConnect);
    }
    if version != "HTTP/1.1" {
        return Err(HeadError::UnsupportedVersion);
    }

    let mut credential = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(HeadError::MalformedHeader)?;
        if !name.eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        if credential.is_some() {
            return Err(HeadError::DuplicateCredential);
        }
        credential = Some(parse_basic_credential(value.trim())?);
    }

    Ok(Some(ConnectHead {
        target: Authority::parse(target)?,
        credential,
        head_len: end + 4,
    }))
}

/// Offset of the CRLFCRLF that ends the head, when it has arrived.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Decodes `Basic <base64(user:pass)>` into the password half.
fn parse_basic_credential(value: &str) -> Result<ProxyCredential, HeadError> {
    let (scheme, encoded) = value
        .split_once(' ')
        .ok_or(HeadError::UnsupportedAuthScheme)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(HeadError::UnsupportedAuthScheme);
    }
    let mut decoded = BASE64
        .decode(encoded.trim().as_bytes())
        .map_err(|_| HeadError::MalformedCredential)?;
    let colon = decoded
        .iter()
        .position(|&b| b == b':')
        .ok_or(HeadError::MalformedCredential)?;
    let password = decoded[colon + 1..].to_vec();
    decoded.zeroize();
    if password.is_empty() {
        return Err(HeadError::MalformedCredential);
    }
    Ok(ProxyCredential(password))
}

/// The `407` that asks the client for a credential. A browser answers it by
/// asking its extension, then retries the CONNECT with the credential.
#[must_use]
pub fn challenge_response() -> &'static [u8] {
    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
      Proxy-Authenticate: Basic realm=\"warren\"\r\n\
      Content-Length: 0\r\n\
      Connection: keep-alive\r\n\r\n"
}

/// The `200` that opens the tunnel.
#[must_use]
pub fn established_response() -> &'static [u8] {
    b"HTTP/1.1 200 Connection Established\r\n\r\n"
}

/// A refusal that carries no reason a prober could learn from.
#[must_use]
pub fn refused_response() -> &'static [u8] {
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
}

/// The refusal for a request that is HTTP but not a CONNECT this ingress serves.
#[must_use]
pub fn method_not_allowed_response() -> &'static [u8] {
    b"HTTP/1.1 405 Method Not Allowed\r\n\
      Allow: CONNECT\r\n\
      Content-Length: 0\r\n\
      Connection: close\r\n\r\n"
}

/// Whether `first` could open an HTTP request line. Used by a shared listener to
/// route a connection to this ingress rather than to a binary protocol: every
/// HTTP method starts with an ASCII uppercase letter, and the framings this
/// ingress shares a port with start with a small length prefix.
#[must_use]
pub fn looks_like_http_request(first: &[u8]) -> bool {
    matches!(first.first(), Some(b) if b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(raw: &str) -> Result<Option<ConnectHead>, HeadError> {
        parse_connect_head(raw.as_bytes())
    }

    /// The refusal a head produced. Asserting on the error alone keeps
    /// `ConnectHead` free of a `PartialEq` that would compare credentials.
    fn head_err(raw: &str) -> HeadError {
        head(raw).expect_err("this head must be refused")
    }

    fn basic(user: &str, pass: &str) -> String {
        BASE64.encode(format!("{user}:{pass}").as_bytes())
    }

    #[test]
    fn parses_a_browser_connect_with_a_credential() {
        let raw = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("warren", "token-bytes")
        );

        let parsed = head(&raw).expect("accepted").expect("complete");

        assert_eq!(parsed.target.host(), "example.com");
        assert_eq!(parsed.target.port(), 443);
        assert_eq!(
            parsed.credential.expect("credential").as_bytes(),
            b"token-bytes"
        );
        assert_eq!(parsed.head_len, raw.len());
    }

    #[test]
    fn reports_incomplete_while_the_head_is_still_arriving() {
        assert!(
            head("CONNECT example.com:443 HTTP/1.1\r\nHost: example")
                .expect("not an error")
                .is_none()
        );
    }

    #[test]
    fn accepts_a_connect_without_a_credential_so_the_caller_can_challenge() {
        let parsed = head("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .expect("accepted")
            .expect("complete");

        assert!(parsed.credential.is_none());
    }

    #[test]
    fn keeps_the_offset_of_bytes_that_follow_the_head() {
        let raw = "CONNECT a.example:443 HTTP/1.1\r\n\r\nextra";

        let parsed = head(raw).expect("accepted").expect("complete");

        assert_eq!(&raw.as_bytes()[parsed.head_len..], b"extra");
    }

    #[test]
    fn refuses_an_absolute_form_request() {
        // What a browser sends for a plain-http URL through a proxy. This
        // ingress serves CONNECT only, so it is refused rather than forwarded
        // as cleartext.
        assert_eq!(
            head_err("GET http://example.com/ HTTP/1.1\r\n\r\n"),
            HeadError::NotConnect
        );
    }

    #[test]
    fn refuses_http_1_0() {
        assert_eq!(
            head_err("CONNECT example.com:443 HTTP/1.0\r\n\r\n"),
            HeadError::UnsupportedVersion
        );
    }

    #[test]
    fn refuses_a_request_line_with_a_stray_field() {
        assert_eq!(
            head_err("CONNECT example.com:443 HTTP/1.1 junk\r\n\r\n"),
            HeadError::MalformedRequestLine
        );
    }

    #[test]
    fn refuses_two_credentials_rather_than_picking_one() {
        let raw = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("warren", "one"),
            basic("warren", "two")
        );

        assert_eq!(head_err(&raw), HeadError::DuplicateCredential);
    }

    #[test]
    fn refuses_a_non_basic_scheme() {
        assert_eq!(
            head_err("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer abc\r\n\r\n"),
            HeadError::UnsupportedAuthScheme
        );
    }

    #[test]
    fn refuses_a_credential_that_is_not_base64() {
        assert_eq!(
            head_err("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic !!!\r\n\r\n"),
            HeadError::MalformedCredential
        );
    }

    #[test]
    fn refuses_a_credential_with_an_empty_password() {
        let raw = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("warren", "")
        );

        assert_eq!(head_err(&raw), HeadError::MalformedCredential);
    }

    #[test]
    fn matches_the_header_name_case_insensitively() {
        let raw = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nproxy-authorization: BASIC {}\r\n\r\n",
            basic("warren", "tok")
        );

        let parsed = head(&raw).expect("accepted").expect("complete");

        assert_eq!(parsed.credential.expect("credential").as_bytes(), b"tok");
    }

    #[test]
    fn refuses_an_incomplete_head_past_the_size_bound() {
        let raw = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nX: {}",
            "a".repeat(9000)
        );

        assert_eq!(
            parse_connect_head(raw.as_bytes()).expect_err("must be refused"),
            HeadError::TooLarge
        );
    }

    #[test]
    fn parses_an_ipv6_authority() {
        let parsed = head("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n")
            .expect("accepted")
            .expect("complete");

        assert_eq!(parsed.target.host(), "2001:db8::1");
        assert_eq!(parsed.target.port(), 8443);
    }

    #[test]
    fn refuses_an_authority_without_a_port() {
        assert_eq!(
            head_err("CONNECT example.com HTTP/1.1\r\n\r\n"),
            HeadError::MalformedAuthority
        );
    }

    #[test]
    fn refuses_port_zero() {
        assert_eq!(
            head_err("CONNECT example.com:0 HTTP/1.1\r\n\r\n"),
            HeadError::MalformedAuthority
        );
    }

    #[test]
    fn refuses_a_host_carrying_a_path_or_userinfo() {
        assert_eq!(
            head_err("CONNECT evil@example.com:443 HTTP/1.1\r\n\r\n"),
            HeadError::MalformedAuthority
        );
        assert_eq!(
            head_err("CONNECT example.com/x:443 HTTP/1.1\r\n\r\n"),
            HeadError::MalformedAuthority
        );
    }

    #[test]
    fn never_renders_the_credential() {
        let parsed = head(&format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("warren", "super-secret")
        ))
        .expect("accepted")
        .expect("complete");

        let rendered = format!("{:?}", parsed.credential.expect("credential"));

        assert!(
            !rendered.contains("super-secret"),
            "a credential must never reach a debug rendering"
        );
    }

    #[test]
    fn routes_an_http_method_to_this_ingress_and_a_length_prefix_away_from_it() {
        assert!(looks_like_http_request(b"CONNECT "));
        assert!(looks_like_http_request(b"GET /"));
        // A carrier frame opens with the high byte of a length prefix.
        assert!(!looks_like_http_request(&[0x04, 0xb0]));
        assert!(!looks_like_http_request(&[]));
    }
}
