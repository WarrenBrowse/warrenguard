//! TCP-over-TLS fallback datapath for the Warren QUIC engine.
//!
//! When outbound UDP/443 is blocked or throttled, a QUIC/UDP-only tunnel does
//! not connect. This crate carries the exact same QUIC datagrams the engine
//! already produces inside ONE real TLS 1.3 stream to the exit's cover domain
//! on `:443/tcp`, using the length-delimited framing of
//! [`warrenguard_tcp_carrier`]. To an on-path observer this is an ordinary
//! HTTPS connection to a real, CT-logged domain: it reuses the same cover the
//! exit already serves for QUIC, so there is no second wire profile to hide.
//!
//! Three pieces, all off the [`warrenguard_tcp_carrier`] codec:
//!
//! - [`TcpCarrierSocket`] (client): a quinn [`quinn::AsyncUdpSocket`] shim that
//!   frames every outbound QUIC datagram into the stream and deframes inbound
//!   datagrams back to quinn. Plugged into a quinn endpoint via
//!   [`build_carrier_client_endpoint`], it is the only seam the engine touches:
//!   the QUIC state machine, HPKE and obfuscation are unchanged.
//! - [`terminate_carrier`] / [`serve_carrier`] (exit): de-encapsulate the
//!   stream and shuttle datagrams to the exit's local QUIC dispatcher over a
//!   fresh loopback UDP socket per connection, so the dispatcher sees each
//!   fallback client as a distinct 5-tuple. [`serve_carrier`] adds the decoy
//!   hand-off for a connection that is not a Warren carrier.
//! - [`FallbackPolicy`] / [`connect_with_fallback`] (client): retry over TCP
//!   after the UDP handshake times out. OFF by default (opt-in): with the
//!   policy disabled, a UDP failure is surfaced and TCP is never attempted.
//!
//! The obfuscation guarantee is load-bearing: the wrap is a real WebPKI TLS 1.3
//! handshake to the cover domain (see [`tls`]), not a bespoke tunnel. The ALPN
//! and cover roots are caller-provided (no product policy in the engine); the
//! Warren deployer passes the same ALPN its QUIC cover uses, so the TCP path is
//! not a distinct, fingerprintable profile.
//!
//! # Live validation (run by an operator, not in CI)
//!
//! The unit and integration tests exercise the framing, the 5-tuple isolation,
//! the auto-activation policy and the decoy over in-memory streams and loopback
//! UDP (the network boundary is mocked). The anti-censorship behaviour itself is
//! validated against a real blocked-UDP network:
//!
//! 1. On the client host, block ALL outbound UDP (keep TCP), e.g. Linux
//!    `iptables -A OUTPUT -p udp -j DROP` in a netns, or macOS `pf`
//!    `block drop out proto udp`. Confirm a direct QUIC/UDP dial to the exit
//!    now FAILS (handshake times out).
//! 2. Enable the fallback ([`FallbackPolicy::tcp_fallback_enabled`] = true) and
//!    reconnect. The client must dial the exit's `:443/tcp`, complete the WebPKI
//!    TLS handshake to the cover domain, tunnel QUIC inside it, and egress
//!    normally (curl through the tunnel succeeds).
//! 3. `tcpdump -n 'tcp port 443'` on the client link must show a plain TLS 1.3
//!    ClientHello to the cover domain (SNI = the cover host, cert chains to a
//!    public CA) and no cleartext Warren marker: identical to any HTTPS/443 flow.
//! 4. From a third host, actively probe the exit's `:443/tcp`: complete TLS,
//!    then send a non-QUIC request. The exit must serve the decoy (a plausible
//!    response), never a Warren-specific error or a hang.
//! 5. Tear the UDP block down and confirm the client returns to the UDP path.

#![forbid(unsafe_code)]

mod activation;
mod client;
mod policy;
mod terminator;
pub mod tls;

pub use activation::{
    DEFAULT_UDP_HANDSHAKE_TIMEOUT, FallbackError, FallbackPolicy, connect_with_fallback,
};
pub use client::{TcpCarrierSocket, build_carrier_client_endpoint};
pub use policy::{COVER_TCP_ALPN, COVER_TCP_PORT, CoverTls, resolve_fallback_policy};
pub use terminator::{TerminatorConfig, serve_carrier, terminate_carrier};

use thiserror::Error;

/// Read buffer for draining a carrier stream. Sized to hold several path-MTU
/// datagrams per syscall; it bounds syscall batching only, never the wire.
pub(crate) const READ_BUF: usize = 16 * 1024;

/// Errors raised while building the client side of the carrier.
///
/// The raw TCP dial to the exit's `:443/tcp` is the caller's responsibility
/// (this crate wraps an already-established [`tokio::net::TcpStream`] in
/// [`tls::connect_cover_tls`]), so there is deliberately no `Io` variant for a
/// connect failure: that error belongs to, and is typed by, whatever the
/// caller used to dial.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CarrierError {
    /// The WebPKI TLS 1.3 handshake to the cover domain failed (bad cert chain,
    /// wrong SNI, or a network reset). Surfaced without the peer address.
    #[error("TLS handshake to the cover domain failed")]
    Tls(#[source] std::io::Error),
    /// The supplied cover-domain string is not a valid TLS server name.
    #[error("invalid cover-domain name for the TLS SNI")]
    InvalidCoverDomain,
    /// The quinn endpoint over the carrier socket could not be built.
    #[error("building the QUIC endpoint over the carrier failed")]
    Endpoint(#[source] std::io::Error),
    /// No async runtime was available to drive the carrier endpoint.
    #[error("no async runtime available for the carrier endpoint")]
    NoRuntime,
}
