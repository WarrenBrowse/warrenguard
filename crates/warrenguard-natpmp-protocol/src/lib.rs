//! NAT-PMP wire format (RFC 6886) - pure parse/serialize, no I/O.
//!
//! ## Essential spec (RFC 6886)
//!
//! Requests: Version (1B) + Opcode (1B) + opcode-specific payload.
//! - Opcode 0 (external addr): 2 bytes total.
//! - Opcode 1 (map UDP) / 2 (map TCP): 12 bytes total = Reserved (2B)
//!   + Internal port (2B) + Suggested external port (2B) + Lifetime (4B).
//!
//! Responses: Version (1B) + Opcode|0x80 (1B) + Result code (2B) +
//! Seconds-since-epoch (4B) + opcode-specific payload. All integers
//! are big-endian.
//!
//! Lifetime = 0 → delete-mapping (RFC §3.3.2).
//!
//! ## Non-RFC extensions
//!
//! This crate is otherwise a pure RFC 6886 wire format, but it also
//! carries a small set of deployer-specific (Warren) extensions. A
//! reimplementer targeting plain RFC 6886 interop must NOT rely on
//! any of these; a spec-only peer that ignores them still round-trips
//! cleanly (they are additive, never a required field):
//!
//! - [`ResultCode::SuggestedPortUnavailable`] (result code 6): no RFC
//!   6886 equivalent. Signals that a client's requested external port
//!   (`suggested_external_port != 0`) is unavailable, under a policy
//!   that rejects instead of silently substituting another port.
//! - [`ResultCode::RateLimited`] (result code 7): no RFC 6886
//!   equivalent. Signals a per-source allocation rate limit.
//! - [`RateLimitInfo`]: an optional 4-byte trailer appended after the
//!   16-byte RFC `Map` response, carrying the per-source rate-limit
//!   budget. Length-gated on parse so an RFC-only peer, or a server
//!   that never emits it, degrades to `rate_limit: None` cleanly.
//! - The credential trailer ([`append_credential_trailer`],
//!   [`credential_trailer`]): an optional opaque blob appended after the
//!   12-byte RFC `Map` request, for a deployer that gates its port budget
//!   on a credential the client presents. Magic-gated and length-gated on
//!   parse, and the RFC frame in front is untouched, so a server that
//!   ignores it reads exactly the request the client sent.

use std::net::Ipv4Addr;

/// NAT-PMP protocol version. Must be `0`; any other value triggers
/// `ResultCode::UnsupportedVersion`.
pub const NATPMP_VERSION: u8 = 0;

/// "Response" indicator bit on the opcode (RFC §3).
pub const RESPONSE_BIT: u8 = 0x80;

/// RFC 6886 opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// External address request (§3.2).
    ExternalAddress = 0,
    /// Map UDP port (§3.3).
    MapUdp = 1,
    /// Map TCP port (§3.3).
    MapTcp = 2,
}

/// RFC 6886 §3.5 result codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ResultCode {
    /// Operation succeeded.
    Success = 0,
    /// Unsupported version.
    UnsupportedVersion = 1,
    /// Refused by the server (port-forwarding disabled, source not
    /// allowed, ...).
    NotAuthorized = 2,
    /// Network failure (rare in POC).
    NetworkFailure = 3,
    /// No free port / rate-limit exceeded.
    OutOfResources = 4,
    /// Unknown opcode.
    UnsupportedOpcode = 5,
    /// Warren extension (non-RFC): the client requested a specific
    /// external port (`suggested != 0`) that is currently unavailable
    /// to it. Distinct from `OutOfResources` so the client/UI can show
    /// a precise "this port is already in use, pick another" message
    /// instead of a generic out-of-resources error. RFC 6886 has no
    /// code for this because it lets the server substitute a port; under
    /// Warren's strict honour-or-error policy we reject instead.
    SuggestedPortUnavailable = 6,
    /// Warren extension (non-RFC): the client exceeded the per-source
    /// allocation rate limit (sliding window). Distinct from
    /// `OutOfResources` (pool exhausted / per-client quota) so the UI
    /// can show an actionable "too many port changes, retry in N s"
    /// countdown instead of a generic out-of-resources error. The
    /// retry-after delay travels in the optional [`RateLimitInfo`]
    /// trailer (`window_reset_secs`).
    RateLimited = 7,
}

/// Optional Warren trailer appended to a `Map` response, carrying the
/// per-source rate-limit budget so the client/UI can warn before a ban
/// and show a retry countdown after one.
///
/// Wire layout (4 bytes, appended after the 16-byte RFC Map response):
/// `attempts_remaining (1B) | reserved (1B) | window_reset_secs (2B BE)`.
/// The trailer is length-gated on parse - an RFC-only peer that ignores
/// the extra bytes, or an older Warren server that never emits them,
/// degrades to `None` cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitInfo {
    /// Allocation slots still available to this source within the
    /// current sliding window, *after* accounting for the request that
    /// produced this response. `0` on a `RateLimited` rejection.
    pub attempts_remaining: u8,
    /// Seconds until the oldest in-window allocation falls out of the
    /// window (i.e. until `attempts_remaining` grows by one). On a
    /// `RateLimited` rejection this is the retry-after delay; on a
    /// success with `attempts_remaining == 0` it tells the UI how long
    /// to block the next port change.
    pub window_reset_secs: u16,
}

/// Deserialized NAT-PMP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// `GET PUBLIC ADDRESS` (§3.2). Empty payload.
    ExternalAddress,
    /// `MAP <UDP|TCP>` (§3.3). `lifetime_secs == 0` = delete-mapping.
    Map {
        /// TCP or UDP.
        proto: MapProto,
        /// Internal client port (tunnel side).
        internal_port: u16,
        /// Suggested external port (`0` = server picks).
        suggested_external_port: u16,
        /// Requested lifetime in seconds (`0` = delete).
        lifetime_secs: u32,
    },
}

/// Mapping transport protocol (TCP/UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapProto {
    /// UDP (RFC opcode 1).
    Udp,
    /// TCP (RFC opcode 2).
    Tcp,
}

/// Wire parsing errors (frame too short, unknown version, unknown
/// opcode, ...). Distinct from `NatPmpError` (business logic).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// Frame shorter than the minimum required by the opcode.
    #[error("frame too short: got {got}, need at least {need}")]
    TooShort {
        /// Received size.
        got: usize,
        /// Minimum required size.
        need: usize,
    },
    /// Header version != 0 (NATPMP_VERSION).
    #[error("unsupported NAT-PMP version: {0}")]
    UnsupportedVersion(u8),
    /// Unknown opcode (not 0/1/2).
    #[error("unsupported opcode: {0}")]
    UnsupportedOpcode(u8),
}

/// Wire size of an RFC 6886 Map request, and the offset any Warren trailer
/// starts at.
pub const MAP_REQUEST_LEN: usize = 12;

/// Opens the Warren credential trailer on a Map request, so trailing bytes
/// that are padding, a probe or a future extension are never read as a
/// credential.
pub const CREDENTIAL_TRAILER_MAGIC: u16 = 0x5747;

/// Largest credential the trailer carries, in bytes. Bounds what a peer can
/// make a server hold from one datagram, and keeps the request well inside
/// any path MTU. The engine treats the bytes as opaque; a deployer decides
/// what they mean.
pub const MAX_CREDENTIAL_LEN: usize = 512;

/// Header of the credential trailer: magic (2 B) + length (2 B, big endian).
const CREDENTIAL_TRAILER_HEADER_LEN: usize = 4;

/// Refusals from [`append_credential_trailer`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrailerError {
    /// Credential longer than [`MAX_CREDENTIAL_LEN`].
    #[error("credential too long: {len} bytes, max {max}")]
    CredentialTooLong {
        /// Length offered by the caller.
        len: usize,
        /// Accepted maximum.
        max: usize,
    },
}

/// Appends an opaque credential to a serialized Map request.
///
/// The RFC 6886 frame in front is left untouched, and a server that predates
/// this trailer ignores the extra bytes (its parser bounds the frame by a
/// minimum length, not an exact one), so presenting a credential never
/// changes how an older exit reads the request.
///
/// # Errors
///
/// [`TrailerError::CredentialTooLong`] past [`MAX_CREDENTIAL_LEN`]; `frame`
/// is then left as it was.
pub fn append_credential_trailer(
    frame: &mut Vec<u8>,
    credential: &[u8],
) -> Result<(), TrailerError> {
    let len = credential.len();
    if len > MAX_CREDENTIAL_LEN {
        return Err(TrailerError::CredentialTooLong {
            len,
            max: MAX_CREDENTIAL_LEN,
        });
    }
    frame.reserve(CREDENTIAL_TRAILER_HEADER_LEN + len);
    frame.extend_from_slice(&CREDENTIAL_TRAILER_MAGIC.to_be_bytes());
    // Truncation-safe: `len` was just bounded by MAX_CREDENTIAL_LEN.
    frame.extend_from_slice(&(len as u16).to_be_bytes());
    frame.extend_from_slice(credential);
    Ok(())
}

/// Borrows the credential a request carries, or `None` when it carries none.
///
/// Anything malformed reads as `None`: a wrong magic, a truncated body, or a
/// length past [`MAX_CREDENTIAL_LEN`]. A credential is an optional extra, so
/// a peer must never be able to turn a bad trailer into a refused request.
#[must_use]
pub fn credential_trailer(buf: &[u8]) -> Option<&[u8]> {
    let trailer = buf.get(MAP_REQUEST_LEN..)?;
    let (header, body) = trailer.split_at_checked(CREDENTIAL_TRAILER_HEADER_LEN)?;
    if u16::from_be_bytes([header[0], header[1]]) != CREDENTIAL_TRAILER_MAGIC {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if len > MAX_CREDENTIAL_LEN {
        return None;
    }
    body.get(..len)
}

/// Parses a server-side incoming Request frame.
///
/// # Errors
///
/// - [`ParseError::TooShort`] if the frame is shorter than what the
///   opcode requires.
/// - [`ParseError::UnsupportedVersion`] if byte 0 != 0.
/// - [`ParseError::UnsupportedOpcode`] if byte 1 is not in {0, 1, 2}.
pub fn parse_request(buf: &[u8]) -> Result<Request, ParseError> {
    if buf.len() < 2 {
        return Err(ParseError::TooShort {
            got: buf.len(),
            need: 2,
        });
    }
    if buf[0] != NATPMP_VERSION {
        return Err(ParseError::UnsupportedVersion(buf[0]));
    }
    let opcode = buf[1];
    match opcode {
        0 => Ok(Request::ExternalAddress),
        1 | 2 => {
            if buf.len() < 12 {
                return Err(ParseError::TooShort {
                    got: buf.len(),
                    need: 12,
                });
            }
            // bytes 2-3 = reserved (RFC §3.3 "MUST be zero on
            // transmission and MUST be ignored on reception").
            let internal_port = u16::from_be_bytes([buf[4], buf[5]]);
            let suggested_external_port = u16::from_be_bytes([buf[6], buf[7]]);
            let lifetime_secs = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
            let proto = if opcode == 1 {
                MapProto::Udp
            } else {
                MapProto::Tcp
            };
            Ok(Request::Map {
                proto,
                internal_port,
                suggested_external_port,
                lifetime_secs,
            })
        }
        other => Err(ParseError::UnsupportedOpcode(other)),
    }
}

/// NAT-PMP response, serializable to the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// `ExternalAddress` response (§3.2.1).
    ExternalAddress {
        /// RFC §3.5 result code.
        result_code: ResultCode,
        /// Seconds since the daemon epoch.
        epoch_secs: u32,
        /// Public IPv4 of the gateway. Set to `0.0.0.0` on error.
        external_ip: Ipv4Addr,
    },
    /// Mapping response (§3.3.1). Identical for TCP/UDP, different
    /// opcode.
    Map {
        /// TCP or UDP.
        proto: MapProto,
        /// Result code.
        result_code: ResultCode,
        /// Seconds since the daemon epoch.
        epoch_secs: u32,
        /// Internal port (echoed).
        internal_port: u16,
        /// Allocated external port.
        external_port: u16,
        /// Granted lifetime (may differ from the requested one).
        lifetime_secs: u32,
        /// Optional Warren rate-limit trailer. `Some` when the server
        /// reports the per-source budget (every Warren exit does, on
        /// both success and `RateLimited` responses); `None` when the
        /// frame carried no trailer (RFC-only or pre-trailer server).
        rate_limit: Option<RateLimitInfo>,
    },
}

/// Serializes a `Request` to the RFC 6886 wire format. Symmetric to
/// [`parse_request`]. Used by the client (`warrenguard-natpmp-client`)
/// to build its requests; kept here so the wire format is shared with
/// the server.
#[must_use]
pub fn serialize_request(req: &Request) -> Vec<u8> {
    match *req {
        Request::ExternalAddress => {
            vec![NATPMP_VERSION, Opcode::ExternalAddress as u8]
        }
        Request::Map {
            proto,
            internal_port,
            suggested_external_port,
            lifetime_secs,
        } => {
            let opcode = match proto {
                MapProto::Udp => Opcode::MapUdp,
                MapProto::Tcp => Opcode::MapTcp,
            };
            let mut buf = Vec::with_capacity(12);
            buf.push(NATPMP_VERSION);
            buf.push(opcode as u8);
            // Reserved (RFC §3.3 "MUST be zero on transmission").
            buf.extend_from_slice(&[0u8, 0u8]);
            buf.extend_from_slice(&internal_port.to_be_bytes());
            buf.extend_from_slice(&suggested_external_port.to_be_bytes());
            buf.extend_from_slice(&lifetime_secs.to_be_bytes());
            buf
        }
    }
}

/// Parses a client-side incoming Response frame. Symmetric to
/// [`serialize_response`].
///
/// # Errors
///
/// - [`ParseError::TooShort`] if the frame is shorter than what the
///   opcode requires (12B for ExternalAddress, 16B for Map).
/// - [`ParseError::UnsupportedVersion`] if byte 0 != 0.
/// - [`ParseError::UnsupportedOpcode`] if byte 1 (without the response
///   bit) is not in {0, 1, 2}.
pub fn parse_response(buf: &[u8]) -> Result<Response, ParseError> {
    if buf.len() < 8 {
        // Minimum response header = version (1) + opcode|0x80 (1) +
        // result_code (2) + epoch_secs (4) = 8 bytes.
        return Err(ParseError::TooShort {
            got: buf.len(),
            need: 8,
        });
    }
    if buf[0] != NATPMP_VERSION {
        return Err(ParseError::UnsupportedVersion(buf[0]));
    }
    let opcode_raw = buf[1];
    if opcode_raw & RESPONSE_BIT == 0 {
        // No response bit set → not a valid response frame. Treat as
        // an unsupported opcode client-side.
        return Err(ParseError::UnsupportedOpcode(opcode_raw));
    }
    let opcode = opcode_raw & !RESPONSE_BIT;
    let result_code_raw = u16::from_be_bytes([buf[2], buf[3]]);
    let result_code = parse_result_code(result_code_raw);
    let epoch_secs = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    match opcode {
        0 => {
            if buf.len() < 12 {
                return Err(ParseError::TooShort {
                    got: buf.len(),
                    need: 12,
                });
            }
            let external_ip = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
            Ok(Response::ExternalAddress {
                result_code,
                epoch_secs,
                external_ip,
            })
        }
        1 | 2 => {
            if buf.len() < 16 {
                return Err(ParseError::TooShort {
                    got: buf.len(),
                    need: 16,
                });
            }
            let internal_port = u16::from_be_bytes([buf[8], buf[9]]);
            let external_port = u16::from_be_bytes([buf[10], buf[11]]);
            let lifetime_secs = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
            let proto = if opcode == 1 {
                MapProto::Udp
            } else {
                MapProto::Tcp
            };
            // Optional Warren trailer (length-gated): bytes 16-19 =
            // attempts_remaining (1B) + reserved (1B) + window_reset_secs
            // (2B BE). Absent on RFC-only / pre-trailer servers → None.
            let rate_limit = if buf.len() >= 20 {
                Some(RateLimitInfo {
                    attempts_remaining: buf[16],
                    window_reset_secs: u16::from_be_bytes([buf[18], buf[19]]),
                })
            } else {
                None
            };
            Ok(Response::Map {
                proto,
                result_code,
                epoch_secs,
                internal_port,
                external_port,
                lifetime_secs,
                rate_limit,
            })
        }
        other => Err(ParseError::UnsupportedOpcode(other)),
    }
}

/// Converts a raw `result_code` into a `ResultCode` variant. Unknown
/// codes (future RFCs) are mapped to `NetworkFailure` for lack of a
/// better option.
fn parse_result_code(raw: u16) -> ResultCode {
    match raw {
        0 => ResultCode::Success,
        1 => ResultCode::UnsupportedVersion,
        2 => ResultCode::NotAuthorized,
        3 => ResultCode::NetworkFailure,
        4 => ResultCode::OutOfResources,
        5 => ResultCode::UnsupportedOpcode,
        6 => ResultCode::SuggestedPortUnavailable,
        7 => ResultCode::RateLimited,
        _ => ResultCode::NetworkFailure,
    }
}

/// Serializes a `Response` to the RFC 6886 wire format.
#[must_use]
pub fn serialize_response(resp: &Response) -> Vec<u8> {
    match *resp {
        Response::ExternalAddress {
            result_code,
            epoch_secs,
            external_ip,
        } => {
            let mut buf = Vec::with_capacity(12);
            buf.push(NATPMP_VERSION);
            buf.push(Opcode::ExternalAddress as u8 | RESPONSE_BIT);
            buf.extend_from_slice(&(result_code as u16).to_be_bytes());
            buf.extend_from_slice(&epoch_secs.to_be_bytes());
            buf.extend_from_slice(&external_ip.octets());
            buf
        }
        Response::Map {
            proto,
            result_code,
            epoch_secs,
            internal_port,
            external_port,
            lifetime_secs,
            rate_limit,
        } => {
            let opcode = match proto {
                MapProto::Udp => Opcode::MapUdp,
                MapProto::Tcp => Opcode::MapTcp,
            };
            let mut buf = Vec::with_capacity(if rate_limit.is_some() { 20 } else { 16 });
            buf.push(NATPMP_VERSION);
            buf.push(opcode as u8 | RESPONSE_BIT);
            buf.extend_from_slice(&(result_code as u16).to_be_bytes());
            buf.extend_from_slice(&epoch_secs.to_be_bytes());
            buf.extend_from_slice(&internal_port.to_be_bytes());
            buf.extend_from_slice(&external_port.to_be_bytes());
            buf.extend_from_slice(&lifetime_secs.to_be_bytes());
            // Optional Warren rate-limit trailer (see `RateLimitInfo`).
            if let Some(info) = rate_limit {
                buf.push(info.attempts_remaining);
                buf.push(0); // reserved
                buf.extend_from_slice(&info.window_reset_secs.to_be_bytes());
            }
            buf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- credential trailer -------------------------------------------------

    #[test]
    fn a_plain_request_carries_no_credential() {
        let frame = serialize_request(&Request::Map {
            proto: MapProto::Udp,
            internal_port: 8080,
            suggested_external_port: 0,
            lifetime_secs: 600,
        });
        assert_eq!(credential_trailer(&frame), None);
    }

    #[test]
    fn a_credential_survives_the_trailer_round_trip() {
        let credential = vec![0xA5; 354];
        let mut frame = serialize_request(&Request::Map {
            proto: MapProto::Tcp,
            internal_port: 8080,
            suggested_external_port: 50000,
            lifetime_secs: 600,
        });
        append_credential_trailer(&mut frame, &credential).expect("credential fits");

        assert_eq!(credential_trailer(&frame), Some(credential.as_slice()));
        // The RFC frame in front of it must be untouched, or an exit that
        // ignores the trailer would read a different request than the one the
        // client sent.
        assert!(matches!(
            parse_request(&frame),
            Ok(Request::Map {
                proto: MapProto::Tcp,
                internal_port: 8080,
                suggested_external_port: 50000,
                lifetime_secs: 600,
            })
        ));
    }

    #[test]
    fn trailing_bytes_that_are_not_a_credential_are_ignored() {
        // Padding, a probe, or a future extension must degrade to "no
        // credential" rather than be read as one or refuse the request.
        let mut frame = serialize_request(&Request::Map {
            proto: MapProto::Udp,
            internal_port: 8080,
            suggested_external_port: 0,
            lifetime_secs: 600,
        });
        frame.extend_from_slice(&[0xDE, 0xAD, 0x00, 0x02, 0x01, 0x02]);

        assert_eq!(credential_trailer(&frame), None);
        assert!(parse_request(&frame).is_ok());
    }

    #[test]
    fn a_truncated_credential_is_ignored_rather_than_half_read() {
        let mut frame = serialize_request(&Request::Map {
            proto: MapProto::Udp,
            internal_port: 8080,
            suggested_external_port: 0,
            lifetime_secs: 600,
        });
        frame.extend_from_slice(&CREDENTIAL_TRAILER_MAGIC.to_be_bytes());
        frame.extend_from_slice(&8u16.to_be_bytes());
        frame.extend_from_slice(&[0x01, 0x02, 0x03]); // 3 bytes, not 8

        assert_eq!(credential_trailer(&frame), None);
    }

    #[test]
    fn a_credential_past_the_cap_is_refused_at_append_time() {
        let mut frame = serialize_request(&Request::Map {
            proto: MapProto::Udp,
            internal_port: 8080,
            suggested_external_port: 0,
            lifetime_secs: 600,
        });
        let oversized = vec![0u8; MAX_CREDENTIAL_LEN + 1];

        let refused = append_credential_trailer(&mut frame, &oversized);

        assert!(matches!(
            refused,
            Err(TrailerError::CredentialTooLong { len, max })
                if len == MAX_CREDENTIAL_LEN + 1 && max == MAX_CREDENTIAL_LEN
        ));
        assert_eq!(frame.len(), 12, "a refused append must not touch the frame");
    }

    #[test]
    fn a_credential_announcing_more_than_the_cap_is_ignored_on_parse() {
        // The cap is a receive-side bound too: a peer that ignores it must not
        // be able to make the parser hand out an oversized slice.
        let mut frame = serialize_request(&Request::Map {
            proto: MapProto::Udp,
            internal_port: 8080,
            suggested_external_port: 0,
            lifetime_secs: 600,
        });
        let oversized = vec![0u8; MAX_CREDENTIAL_LEN + 1];
        frame.extend_from_slice(&CREDENTIAL_TRAILER_MAGIC.to_be_bytes());
        frame.extend_from_slice(
            &u16::try_from(oversized.len())
                .expect("fits in u16")
                .to_be_bytes(),
        );
        frame.extend_from_slice(&oversized);

        assert_eq!(credential_trailer(&frame), None);
    }

    // --- serialize_request --------------------------------------------------

    #[test]
    fn serialize_request_external_address_is_2_bytes() {
        let buf = serialize_request(&Request::ExternalAddress);
        assert_eq!(buf, vec![0x00, 0x00], "RFC: version=0 opcode=0");
    }

    #[test]
    fn serialize_request_map_udp_layout_is_12_bytes_be() {
        let req = Request::Map {
            proto: MapProto::Udp,
            internal_port: 0x1234,
            suggested_external_port: 0x5678,
            lifetime_secs: 0x0000_0E10, // 3600s
        };
        let buf = serialize_request(&req);
        assert_eq!(
            buf,
            vec![
                0x00, // version
                0x01, // opcode UDP
                0x00, 0x00, // reserved
                0x12, 0x34, // internal_port
                0x56, 0x78, // suggested external
                0x00, 0x00, 0x0E, 0x10, // lifetime
            ]
        );
    }

    #[test]
    fn serialize_request_map_tcp_uses_opcode_2() {
        let req = Request::Map {
            proto: MapProto::Tcp,
            internal_port: 80,
            suggested_external_port: 0,
            lifetime_secs: 60,
        };
        let buf = serialize_request(&req);
        assert_eq!(buf[1], 0x02, "TCP opcode = 2 RFC 6886");
        assert_eq!(buf.len(), 12);
    }

    #[test]
    fn serialize_request_map_lifetime_zero_means_delete() {
        // Wire-format-wise, lifetime=0 = delete-mapping (RFC §3.3.2).
        // This is a valid case to serialize.
        let req = Request::Map {
            proto: MapProto::Udp,
            internal_port: 12345,
            suggested_external_port: 0,
            lifetime_secs: 0,
        };
        let buf = serialize_request(&req);
        assert_eq!(&buf[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn serialize_request_then_parse_request_roundtrip() {
        // Property: any Request, serialized then re-parsed, yields the
        // same Request. Verifies the protocol's bidi invariant.
        for req in [
            Request::ExternalAddress,
            Request::Map {
                proto: MapProto::Udp,
                internal_port: 12345,
                suggested_external_port: 49152,
                lifetime_secs: 3600,
            },
            Request::Map {
                proto: MapProto::Tcp,
                internal_port: 0,
                suggested_external_port: 0,
                lifetime_secs: 0,
            },
        ] {
            let buf = serialize_request(&req);
            let parsed = parse_request(&buf).expect("roundtrip");
            assert_eq!(parsed, req, "roundtrip for {req:?}");
        }
    }

    // --- parse_response -----------------------------------------------------

    #[test]
    fn parse_response_external_address_layout() {
        // RFC example: v0, opcode 0|0x80=0x80, result=0, epoch=42, IP 8.8.4.4.
        let buf = vec![
            0x00, // version
            0x80, // opcode 0 + RESPONSE_BIT
            0x00, 0x00, // result_code = Success
            0x00, 0x00, 0x00, 0x2A, // epoch = 42
            8, 8, 4, 4, // external_ip
        ];
        let resp = parse_response(&buf).expect("parse OK");
        assert_eq!(
            resp,
            Response::ExternalAddress {
                result_code: ResultCode::Success,
                epoch_secs: 42,
                external_ip: Ipv4Addr::new(8, 8, 4, 4),
            }
        );
    }

    #[test]
    fn parse_response_map_udp_layout() {
        let buf = vec![
            0x00, // version
            0x81, // opcode 1 + RESPONSE_BIT
            0x00, 0x00, // result_code = Success
            0x12, 0x34, 0x56, 0x78, // epoch
            0x30, 0x39, // internal_port = 12345
            0xC0, 0x00, // external_port = 49152
            0x00, 0x00, 0x0E, 0x10, // lifetime = 3600
        ];
        let resp = parse_response(&buf).expect("parse OK");
        assert_eq!(
            resp,
            Response::Map {
                proto: MapProto::Udp,
                result_code: ResultCode::Success,
                epoch_secs: 0x1234_5678,
                internal_port: 12345,
                external_port: 49152,
                lifetime_secs: 3600,
                rate_limit: None,
            }
        );
    }

    #[test]
    fn parse_response_map_tcp_distinguished_from_udp_by_opcode() {
        let buf = vec![
            0x00, // version
            0x82, // opcode 2 + RESPONSE_BIT (TCP)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // result + epoch
            0x00, 0x50, 0xC0, 0x00, 0x00, 0x00, 0x0E, 0x10,
        ];
        let resp = parse_response(&buf).expect("parse OK");
        match resp {
            Response::Map {
                proto: MapProto::Tcp,
                ..
            } => {}
            other => panic!("expected MapProto::Tcp, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_map_propagates_error_codes() {
        // Wire `result_code = 4 = OutOfResources`.
        let buf = vec![
            0x00, 0x81, 0x00, 0x04, // result = 4
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let resp = parse_response(&buf).expect("parse OK");
        match resp {
            Response::Map {
                result_code: ResultCode::OutOfResources,
                ..
            } => {}
            other => panic!("expected OutOfResources, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_rejects_request_frames() {
        // A Map request frame (opcode without RESPONSE_BIT) must NOT
        // be parsed as a response - otherwise an attacker or buggy
        // peer could trick us into interpreting a request as an OK
        // response.
        let request_bytes = serialize_request(&Request::Map {
            proto: MapProto::Udp,
            internal_port: 80,
            suggested_external_port: 0,
            lifetime_secs: 60,
        });
        let err = parse_response(&request_bytes).unwrap_err();
        assert!(matches!(err, ParseError::UnsupportedOpcode(_)));
    }

    #[test]
    fn parse_response_rejects_short_frames() {
        // 4-byte frame: minimum response header = 8.
        let buf = vec![0x00, 0x80, 0x00, 0x00];
        let err = parse_response(&buf).unwrap_err();
        assert!(matches!(err, ParseError::TooShort { .. }));
    }

    #[test]
    fn parse_response_rejects_unsupported_version() {
        let buf = vec![0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = parse_response(&buf).unwrap_err();
        assert!(matches!(err, ParseError::UnsupportedVersion(0xFF)));
    }

    #[test]
    fn serialize_response_then_parse_response_roundtrip() {
        let cases = [
            Response::ExternalAddress {
                result_code: ResultCode::Success,
                epoch_secs: 1234,
                external_ip: Ipv4Addr::new(203, 0, 113, 7),
            },
            Response::Map {
                proto: MapProto::Udp,
                result_code: ResultCode::Success,
                epoch_secs: 0xDEAD_BEEF,
                internal_port: 22,
                external_port: 51234,
                lifetime_secs: 3600,
                rate_limit: None,
            },
            Response::Map {
                proto: MapProto::Tcp,
                result_code: ResultCode::OutOfResources,
                epoch_secs: 0,
                internal_port: 80,
                external_port: 0, // 0 on error
                lifetime_secs: 0,
                rate_limit: None,
            },
            Response::Map {
                proto: MapProto::Udp,
                result_code: ResultCode::RateLimited,
                epoch_secs: 7,
                internal_port: 22,
                external_port: 0,
                lifetime_secs: 0,
                // Trailer present: roundtrips through the 20-byte form.
                rate_limit: Some(RateLimitInfo {
                    attempts_remaining: 0,
                    window_reset_secs: 47,
                }),
            },
            Response::Map {
                proto: MapProto::Tcp,
                result_code: ResultCode::Success,
                epoch_secs: 99,
                internal_port: 443,
                external_port: 50000,
                lifetime_secs: 3600,
                rate_limit: Some(RateLimitInfo {
                    attempts_remaining: 3,
                    window_reset_secs: 12,
                }),
            },
        ];
        for orig in cases {
            let buf = serialize_response(&orig);
            let parsed = parse_response(&buf).expect("roundtrip");
            assert_eq!(parsed, orig);
        }
    }

    #[test]
    fn serialize_map_without_trailer_is_16_bytes() {
        // Backward compatibility: a Map response with no rate-limit
        // trailer must stay the canonical 16-byte RFC frame.
        let buf = serialize_response(&Response::Map {
            proto: MapProto::Udp,
            result_code: ResultCode::Success,
            epoch_secs: 1,
            internal_port: 22,
            external_port: 49152,
            lifetime_secs: 3600,
            rate_limit: None,
        });
        assert_eq!(buf.len(), 16, "no trailer → 16-byte RFC frame");
    }

    #[test]
    fn serialize_map_with_trailer_is_20_bytes_and_parses_back() {
        let info = RateLimitInfo {
            attempts_remaining: 2,
            window_reset_secs: 0x0102,
        };
        let buf = serialize_response(&Response::Map {
            proto: MapProto::Tcp,
            result_code: ResultCode::RateLimited,
            epoch_secs: 0,
            internal_port: 80,
            external_port: 0,
            lifetime_secs: 0,
            rate_limit: Some(info),
        });
        assert_eq!(buf.len(), 20, "trailer → 16 + 4 bytes");
        // Trailer layout: attempts_remaining, reserved=0, window hi, lo.
        assert_eq!(&buf[16..20], &[2, 0, 0x01, 0x02]);
        match parse_response(&buf).expect("parse") {
            Response::Map {
                result_code: ResultCode::RateLimited,
                rate_limit: Some(parsed),
                ..
            } => assert_eq!(parsed, info),
            other => panic!("expected RateLimited Map with trailer, got {other:?}"),
        }
    }

    #[test]
    fn parse_16_byte_map_yields_no_rate_limit() {
        // A legacy 16-byte Map response (no trailer) must parse with
        // `rate_limit: None` rather than failing.
        let buf = vec![
            0x00, 0x81, 0x00, 0x00, 0, 0, 0, 0, 0x00, 0x16, 0xC0, 0x00, 0x00, 0x00, 0x0E, 0x10,
        ];
        match parse_response(&buf).expect("parse") {
            Response::Map { rate_limit, .. } => assert_eq!(rate_limit, None),
            other => panic!("expected Map, got {other:?}"),
        }
    }

    #[test]
    fn parse_result_code_maps_rate_limited() {
        assert_eq!(parse_result_code(7), ResultCode::RateLimited);
    }

    #[test]
    fn parse_result_code_unknown_falls_back_to_network_failure() {
        // Future RFCs may add codes; the conservative
        // "NetworkFailure" mapping avoids confusing them with Success.
        assert_eq!(parse_result_code(0xFFFF), ResultCode::NetworkFailure);
        assert_eq!(parse_result_code(99), ResultCode::NetworkFailure);
    }
}
