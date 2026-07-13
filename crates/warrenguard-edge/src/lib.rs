//! Browser-facing edge ingress for the WarrenGuard multi-hop entry.
//!
//! A Warren exit already presents a real X.509 cover certificate on `:443` with
//! ALPN `h3` and demultiplexes native Warren clients from active probers
//! (which it answers with a plausible HTTP/3 decoy). This crate adds the third
//! case: a real browser opening a **WebTransport-over-HTTP/3** session, so a
//! user can reach a Warren entry with zero install, straight from an extension.
//!
//! Scope here is deliberately narrow and pure: parse enough real HTTP/3
//! (RFC 9114) and QPACK (RFC 9204) to
//!
//! 1. recognise a browser's control-stream SETTINGS as WebTransport-capable
//!    ([`http3::parse_settings`]), and
//! 2. classify the request-stream HEADERS as a WebTransport extended-CONNECT
//!    (RFC 9220) and extract the Privacy Pass token it presents
//!    ([`classify_request`]).
//!
//! The async plumbing (accepting the streams off a `quinn::Connection`, wiring
//! the accepted session as a multi-hop entry, spending the token) lives in the
//! node that consumes this crate; keeping this layer synchronous and
//! allocation-light makes it exhaustively testable against golden HTTP/3 bytes.
//!
//! No-log discipline: errors are value-free (they never carry token bytes,
//! header values, or peer data), so they are safe to log or cross an FFI
//! boundary.

mod http3;
mod huffman;
mod ingress;
mod qpack;
mod server;
mod varint;
mod webtransport;

pub use http3::{
    FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS, Frame, SETTINGS_ENABLE_CONNECT_PROTOCOL,
    SETTINGS_ENABLE_WEBTRANSPORT, SETTINGS_H3_DATAGRAM, SETTINGS_QPACK_BLOCKED_STREAMS,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY, SETTINGS_WT_MAX_SESSIONS, STREAM_CONTROL, Settings,
    encode_frame, parse_settings, read_frame, read_uni_stream_type,
};
pub use ingress::{
    EdgeRequest, WebTransportConnect, classify_request, classify_request_stream,
    parse_private_token_header,
};
pub use server::{control_stream_prelude, webtransport_accept_response};
pub use varint::{decode as decode_varint, encode as encode_varint};
pub use webtransport::{
    WEBTRANSPORT_STREAM_BIDI, WEBTRANSPORT_STREAM_UNI, encode_bidi_stream_header,
    encode_datagram as encode_wt_datagram, encode_uni_stream_header, quarter_stream_id,
    read_bidi_stream_header, read_datagram as read_wt_datagram, read_uni_stream_session_id,
};

/// Errors from parsing or classifying an HTTP/3 edge request. Coarse and
/// value-free by design (see the crate no-log note).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EdgeError {
    /// The bytes are not a well-formed HTTP/3 frame (truncated or malformed
    /// type/length framing).
    #[error("malformed HTTP/3 framing")]
    MalformedFrame,
    /// A QPACK field section could not be decoded (bad prefix, an instruction
    /// this static-only decoder does not implement, a dynamic-table reference,
    /// or a truncated field line).
    #[error("malformed QPACK field section")]
    MalformedFieldSection,
    /// A QPACK literal used HTTP/1-style Huffman coding that failed to decode
    /// (an invalid code or a code that ran past the input).
    #[error("invalid Huffman-coded literal")]
    InvalidHuffman,
}
