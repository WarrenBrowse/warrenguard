//! Single home for the fallback-carrier dial policy and its cover-domain
//! fingerprint constants.
//!
//! The carrier itself (framing, the UDP-vs-TCP race primitive
//! [`crate::connect_with_fallback`], the terminator) lives in the sibling
//! modules. This module owns the pieces every client datapath re-derived
//! independently: WHEN the carrier is armed ([`resolve_fallback_policy`]), the
//! exit's `:443/tcp` port, the ALPN a client offers on the cover-domain TLS
//! handshake, and the per-dial cover target descriptor ([`CoverTls`]). Both the
//! privileged system-VPN transport and the userland SDK transport consume these
//! from here, so the policy and the on-wire fingerprint cannot skew between
//! datapaths.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::activation::FallbackPolicy;

/// The exit's public TCP port for the fallback carrier. The cover-domain TLS
/// handshake mimics ordinary HTTPS, which always lives on `:443`.
pub const COVER_TCP_PORT: u16 = 443;

/// ALPN a client offers on the cover-domain TLS handshake of the fallback
/// carrier. Over TCP a real cover host negotiates HTTP (`h2` then `http/1.1`),
/// never `h3`, which is QUIC-only: offering `h3` on a TCP `:443` handshake would
/// be an anomalous, fingerprintable tell that no ordinary browser produces. The
/// carrier payload after the handshake is framed QUIC datagrams regardless of
/// the negotiated protocol, so this list is purely the on-wire fingerprint,
/// matched here to what a browser offers a plain HTTPS server.
///
/// This is the CLIENT offer. The exit-side decoy deliberately advertises a
/// different, narrower list (only `http/1.1`): a real HTTPS server picking one
/// protocol from the client's two is ordinary TLS negotiation, so the asymmetry
/// is intended, not a skew. The two homes are pinned separately (this constant
/// here, the exit's in its own crate) precisely so a conformance test on each
/// side catches an accidental change to its own value.
pub const COVER_TCP_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// The cover-domain TLS target of the fallback carrier for one dial: the exit's
/// `:443/tcp` address, the cover-domain SNI to present, and the WebPKI client
/// config that validates the cover certificate.
pub struct CoverTls<'a> {
    /// The exit's `:443/tcp` endpoint the carrier connects to.
    pub addr: SocketAddr,
    /// The cover-domain hostname: the TLS SNI and the name validated against the
    /// presented certificate. Sourced from the exit's signed descriptor.
    pub domain: &'a str,
    /// WebPKI client config (roots + [`COVER_TCP_ALPN`]) for the cover handshake.
    pub client_config: Arc<rustls::ClientConfig>,
}

/// Resolves the fallback policy for one dial. Enabled ONLY when all three hold:
/// the client prefers the fallback (`opt_in`), the selected exit advertises the
/// carrier (`exit_tcp_fallback`, from its signed descriptor), and it carries a
/// cover domain to present as the TLS SNI. Any missing precondition yields the
/// default OFF policy, so a UDP failure is surfaced and no `:443/tcp` connection
/// is attempted: a non-capable exit would only refuse the TCP connection, so
/// probing it is pointless.
#[must_use]
pub fn resolve_fallback_policy(
    opt_in: bool,
    exit_tcp_fallback: bool,
    cover_domain: Option<&str>,
) -> FallbackPolicy {
    if opt_in && exit_tcp_fallback && cover_domain.is_some() {
        FallbackPolicy::enabled()
    } else {
        FallbackPolicy::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_enabled_only_when_opt_in_and_advertised_and_cover_present() {
        assert!(
            resolve_fallback_policy(true, true, Some("cover.example")).tcp_fallback_enabled,
            "client prefers fallback + exit advertises + cover present must arm the carrier"
        );
    }

    #[test]
    fn policy_off_when_the_client_disabled_the_preference() {
        assert!(
            !resolve_fallback_policy(false, true, Some("cover.example")).tcp_fallback_enabled,
            "an explicit client opt-out must keep the carrier off even for a capable exit"
        );
    }

    #[test]
    fn policy_off_when_the_exit_does_not_advertise_the_carrier() {
        assert!(
            !resolve_fallback_policy(true, false, Some("cover.example")).tcp_fallback_enabled,
            "an exit that does not advertise tcp_fallback must not be dialled over TCP"
        );
    }

    #[test]
    fn policy_off_without_a_cover_domain() {
        assert!(
            !resolve_fallback_policy(true, true, None).tcp_fallback_enabled,
            "no cover domain means no TLS SNI to present, so the carrier stays off"
        );
    }

    #[test]
    fn client_cover_alpn_is_the_browser_https_offer_and_never_h3() {
        // Pin the client cover fingerprint: exactly the ordered pair a browser
        // offers a plain HTTPS server. h3 is QUIC-only and would be an anomalous
        // tell on a TCP :443 handshake, so it must never appear here. The
        // exit-side decoy pins its own (narrower) list separately; the client
        // offering two and the exit selecting one is ordinary negotiation.
        assert_eq!(
            COVER_TCP_ALPN,
            &[b"h2".as_slice(), b"http/1.1".as_slice()],
            "client cover ALPN must stay the browser HTTPS offer, h2 then http/1.1"
        );
        assert!(
            !COVER_TCP_ALPN.contains(&b"h3".as_slice()),
            "h3 is QUIC-only: offering it on a TCP :443 handshake is a fingerprintable tell"
        );
        assert_eq!(
            COVER_TCP_PORT, 443,
            "the cover carrier mimics HTTPS on :443"
        );
    }
}
