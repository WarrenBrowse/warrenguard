//! Client orchestration for the TLS-over-TCP fallback carrier.
//!
//! When outbound UDP/443 is blocked or throttled, a QUIC/UDP-only dial does not
//! connect. This module decides WHEN the [`crate::ClientTunnel`] retries the
//! same QUIC session inside one real TLS 1.3 stream to the exit's cover domain
//! on `:443/tcp` (the [`warrenguard_tcp_fallback`] carrier). It plugs in at the
//! quinn abstract-socket seam only: the QUIC state machine, HPKE and obfuscation
//! are unchanged, so the fallback path is byte-for-byte the UDP dial's session
//! carried over a different socket.
//!
//! The decision is [`resolve_fallback_policy`]. The carrier is armed ONLY when
//! all three hold: the client prefers it (on by default, see
//! [`crate::ClientTunnel::with_tcp_fallback`]), the selected exit advertises the
//! capability in its signed descriptor (`WarrenExitAddr::tcp_fallback`), and it
//! carries a cover domain to present as the SNI. A non-capable exit is never
//! dialled over TCP: it would only refuse the connection, so probing it is
//! pointless. This mirrors the SDK reference (`warren-transport::tcp_fallback`)
//! and is the engine home both the app and the SDK inherit.

use std::net::SocketAddr;
use std::sync::Arc;

use warrenguard_tcp_fallback::FallbackPolicy;
use warrenguard_transport_core::error::{Result, TunnelError};

/// The exit's public TCP port for the fallback carrier. The cover-domain TLS
/// handshake mimics ordinary HTTPS, which always lives on `:443`.
pub(crate) const COVER_TCP_PORT: u16 = 443;

/// ALPN offered on the cover-domain TLS handshake of the fallback carrier. Over
/// TCP a real cover host negotiates HTTP (`h2` then `http/1.1`), never `h3`,
/// which is QUIC-only: offering `h3` on a TCP `:443` handshake would be an
/// anomalous, fingerprintable tell that no ordinary browser produces. The
/// carrier payload after the handshake is framed QUIC datagrams regardless of
/// the negotiated protocol, so this list is purely the on-wire fingerprint,
/// matched here to what a browser offers a plain HTTPS server.
pub(crate) const COVER_TCP_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// The cover-domain TLS target of the fallback carrier for one dial: the exit's
/// `:443/tcp` address, the cover-domain SNI to present, and the WebPKI client
/// config that validates the cover certificate.
pub(crate) struct CoverTls<'a> {
    /// The exit's `:443/tcp` endpoint the carrier connects to.
    pub addr: SocketAddr,
    /// The cover-domain hostname: the TLS SNI and the name validated against the
    /// presented certificate. Sourced from the exit's signed descriptor.
    pub domain: &'a str,
    /// WebPKI client config (roots + [`COVER_TCP_ALPN`]) for the cover handshake.
    pub client_config: Arc<rustls::ClientConfig>,
}

/// Resolves the fallback policy for one dial. Enabled ONLY when all three hold:
/// the client prefers the fallback (`opt_in`, on by default), the selected exit
/// advertises the carrier (`exit_tcp_fallback`, from its signed descriptor), and
/// it carries a cover domain to present as the TLS SNI. Any missing precondition
/// yields the default OFF policy, so a UDP failure is surfaced and no `:443/tcp`
/// connection is attempted.
#[must_use]
pub(crate) fn resolve_fallback_policy(
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

/// Builds the WebPKI client config for the OUTER cover-domain TLS handshake of
/// the carrier. `der_roots` = explicit DER trust anchors (a self-hosted CA or a
/// test fixture); `None` uses the bundled Mozilla program (the production path,
/// where the exit presents a public-ACME cover certificate). The cover trust
/// store matches the QUIC dial's, so the TCP path is not a distinct profile.
///
/// # Errors
/// [`TunnelError::Internal`] if the resulting trust store is empty (fail closed:
/// an empty store would build a config that trusts nothing and silently fails
/// every handshake), or if rustls rejects the config.
pub(crate) fn build_cover_client_config(
    der_roots: Option<&[Vec<u8>]>,
) -> Result<Arc<rustls::ClientConfig>> {
    let store = match der_roots {
        Some(ders) => {
            let (store, added) = warrenguard_tls::root_store_from_der(ders);
            if added == 0 {
                return Err(TunnelError::Internal(
                    "tcp fallback: no valid cover root certificate in the supplied anchors".into(),
                ));
            }
            store
        }
        None => {
            let store = warrenguard_tls::mozilla_root_store();
            if store.is_empty() {
                return Err(TunnelError::Internal(
                    "tcp fallback: bundled Mozilla root store is empty".into(),
                ));
            }
            store
        }
    };
    let cfg = warrenguard_tls::build_client_rustls_config_webpki(
        store,
        warrenguard_tls::default_crypto_provider(),
        COVER_TCP_ALPN,
    )
    .map_err(|e| TunnelError::Internal(format!("build cover TLS client config failed: {e}")))?;
    Ok(Arc::new(cfg))
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
    fn cover_config_with_no_valid_der_root_fails_closed() {
        let err = build_cover_client_config(Some(&[vec![0u8, 1, 2, 3]]))
            .expect_err("garbage DER anchors must fail closed, not build a trust-nothing config");
        assert!(matches!(err, TunnelError::Internal(_)));
    }
}
