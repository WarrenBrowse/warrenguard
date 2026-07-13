//! Error type for JA4 fingerprinting.

use thiserror::Error;

use crate::varint::VarIntError;

/// Failure decoding a QUIC Initial or fingerprinting its ClientHello.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ja4Error {
    /// The datagram ended before the full Initial packet was read.
    #[error("datagram truncated before the full Initial packet")]
    Truncated,
    /// The first byte does not have the QUIC long-header form bit set.
    #[error("not a QUIC long-header packet")]
    NotLongHeader,
    /// The long-header packet type is not Initial.
    #[error("not a QUIC Initial packet")]
    NotInitial,
    /// The QUIC version is not v1 (the only version handled here).
    #[error("unsupported QUIC version {0:#010x}")]
    UnsupportedVersion(u32),
    /// A variable-length integer failed to decode.
    #[error("varint: {0}")]
    VarInt(#[from] VarIntError),
    /// AEAD authentication failed (wrong keys or a tampered packet).
    #[error("AEAD open failed")]
    AeadOpen,
    /// The decrypted payload carried no reassemblable TLS ClientHello.
    #[error("no ClientHello in the Initial CRYPTO stream")]
    NoClientHello,
    /// The TLS ClientHello was malformed.
    #[error("malformed ClientHello")]
    MalformedClientHello,
}
