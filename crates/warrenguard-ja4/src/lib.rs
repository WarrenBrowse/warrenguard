//! JA4 QUIC-client fingerprint (FoxIO JA4+) computed from a QUIC Initial
//! packet.
//!
//! Purpose: audit the WarrenGuard client's QUIC/TLS fingerprint against a
//! browser target. A QUIC Initial packet is protected with
//! keys derived from the connection's Destination Connection ID via a fixed
//! salt (RFC 9001 s5.2), so ANY on-path observer (this crate, or a censor's
//! DPI) can decrypt it, reassemble the TLS ClientHello, and fingerprint it.
//! This crate does exactly that and derives the JA4 string, so the engine's
//! fingerprint can be pinned as a regression guard and diffed against a
//! reference browser JA4 to quantify the parity gap.
//!
//! Not part of the datapath: measurement and CI tooling only.

mod clienthello;
mod error;
mod frames;
mod ja4;
mod keys;
mod packet;
mod varint;

pub use clienthello::{ClientHelloInfo, parse_client_hello};
pub use error::Ja4Error;
pub use frames::reassemble_client_hello;
pub use ja4::ja4;
pub use keys::{ClientInitialKeys, derive_client_initial_keys};
pub use packet::decrypt_client_initial;
pub use varint::{VarIntError, decode_varint};

/// Computes the JA4 QUIC-client fingerprint from the client's first-flight
/// Initial datagram(s).
///
/// Pass every Initial datagram of the first flight; the engine splits its
/// ClientHello across two Initial packets (an obfuscation knob), so both are
/// needed to recover the full ClientHello. Order does not matter.
///
/// # Errors
///
/// [`Ja4Error`] if a datagram is not a decryptable QUIC v1 Initial or the
/// flight carries no reassemblable ClientHello.
pub fn ja4_from_initials(datagrams: &[&[u8]]) -> Result<String, Ja4Error> {
    let mut payloads = Vec::with_capacity(datagrams.len());
    for dg in datagrams {
        payloads.push(decrypt_client_initial(dg)?);
    }
    let handshake = reassemble_client_hello(&payloads)?;
    Ok(ja4(&parse_client_hello(&handshake)?))
}
