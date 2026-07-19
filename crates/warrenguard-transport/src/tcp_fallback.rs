//! Client orchestration for the TLS-over-TCP fallback carrier.
//!
//! When outbound UDP/443 is blocked or throttled, a QUIC/UDP-only dial does not
//! connect. This module lets the multihop client retry the same QUIC session
//! inside one real TLS 1.3 stream to the exit's cover domain on `:443/tcp` (the
//! [`warrenguard_tcp_fallback`] carrier). It plugs in at the quinn
//! abstract-socket seam only: the QUIC state machine, HPKE and obfuscation are
//! unchanged, so the fallback path is byte-for-byte the UDP dial's session
//! carried over a different socket.
//!
//! The carrier is armed ONLY when all three hold: the client prefers it (on by
//! default), the selected exit advertises the capability in its signed
//! descriptor (`WarrenExitAddr::tcp_fallback`), and it carries a cover domain to
//! present as the SNI. A non-capable exit is never dialled over TCP: it would
//! only refuse the connection, so probing it is pointless.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use warrenguard_socket_bypass::SocketBypass;
use warrenguard_transport_core::error::{Result, TunnelError};

// The cover-domain fingerprint constants are single-homed in
// `warrenguard-tcp-fallback` (next to the carrier and the UDP-vs-TCP race
// primitive), so the privileged transport here and the userland SDK transport
// cannot skew them. Re-exported under the same names for the internal multihop
// carrier dial.
pub(crate) use warrenguard_tcp_fallback::{COVER_TCP_ALPN, COVER_TCP_PORT};

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

/// Opens the TLS-over-TCP carrier's underlying TCP connection to `addr`, used by
/// the multi-hop ([`crate::multihop`]) carrier dial.
///
/// With no `socket_bypass` (userland proxy, mobile, or no system VPN) this is
/// exactly `TcpStream::connect(addr)`: behaviour-neutral. With a bypass the
/// socket MUST be pinned to the physical link BEFORE connect, or under a
/// full-tunnel system VPN it takes the default route (the TUN) and loops into
/// the very tunnel it is meant to bypass. `std::net`/`tokio` expose no
/// pre-connect sockopt seam, so the socket is built with `socket2`, scoped via
/// [`warrenguard_socket_bypass::apply_pre_connect`], then connected on the tokio
/// reactor.
///
/// Fail-closed: a bypass that cannot be installed aborts the dial; it never
/// falls back to an un-scoped socket that would loop into the tunnel.
///
/// # Errors
/// The socket build, the bypass, or the connect failed. The error carries no
/// address (no-log): a bypass failure is the raw `setsockopt` errno.
pub(crate) async fn connect_tcp_carrier(
    addr: SocketAddr,
    socket_bypass: Option<SocketBypass>,
) -> io::Result<TcpStream> {
    let Some(bypass) = socket_bypass else {
        return TcpStream::connect(addr).await;
    };

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // The tokio reactor drives the connect, so the socket must be non-blocking
    // before the connect syscall is issued.
    sock.set_nonblocking(true)?;
    // Pin the socket to the physical link before connect. Propagate the failure
    // (no address rendered) instead of connecting an un-scoped socket: an
    // un-scoped carrier under a system VPN loops into the tunnel.
    warrenguard_socket_bypass::apply_pre_connect(&sock, addr.is_ipv6(), bypass)?;
    // A non-blocking connect returns before completion: EINPROGRESS on unix,
    // WouldBlock (WSAEWOULDBLOCK) on windows. Anything else is a real, immediate
    // failure; the reactor reports completion via writability below.
    match sock.connect(&SockAddr::from(addr)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }
    let stream = TcpStream::from_std(std::net::TcpStream::from(sock))?;
    // Connect completes when the socket becomes writable; take_error surfaces a
    // failed connect (e.g. refused) that writability alone would hide.
    stream.writable().await?;
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The dial-policy resolution and cover-fingerprint constants are tested in
    // their single home (`warrenguard_tcp_fallback::policy`); the tests below
    // cover the transport-owned cover-config builder and carrier dial.

    #[test]
    fn cover_config_with_no_valid_der_root_fails_closed() {
        let err = build_cover_client_config(Some(&[vec![0u8, 1, 2, 3]]))
            .expect_err("garbage DER anchors must fail closed, not build a trust-nothing config");
        assert!(matches!(err, TunnelError::Internal(_)));
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn carrier_dial_with_a_bypass_binds_to_loopback_and_connects() {
        use warrenguard_socket_bypass::SocketBypass;
        // IP_BOUND_IF(lo0) is unprivileged and consistent with a 127.0.0.1
        // target, so the bypassed dial must complete: this drives the full
        // socket2 build -> apply_pre_connect -> non-blocking connect -> tokio
        // conversion path, not just the bare `TcpStream::connect`.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let idx = nix::net::if_::if_nametoindex("lo0").expect("lo0 index");
        let stream = connect_tcp_carrier(addr, Some(SocketBypass::BoundIf(idx)))
            .await
            .expect("bypassed carrier dial to loopback must connect");
        assert_eq!(
            stream.peer_addr().expect("peer addr").ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "the bypassed carrier must reach the loopback listener"
        );
        let _ = accept.await;
    }

    #[cfg(target_vendor = "apple")]
    #[tokio::test]
    async fn carrier_dial_fails_closed_when_the_bypass_cannot_be_applied() {
        use warrenguard_socket_bypass::SocketBypass;
        // A wrong-OS bypass variant (Fwmark on macOS) must abort the dial: proof
        // the bypass is genuinely on the path and not silently ignored. An
        // ignored bypass would connect to the listener and, under a system VPN,
        // loop into the tunnel it must escape.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let err = connect_tcp_carrier(addr, Some(SocketBypass::Fwmark(0x1234)))
            .await
            .expect_err("a bypass this OS cannot honour must fail closed");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn carrier_dial_without_a_bypass_is_the_plain_connect() {
        // The userland-proxy / no-system-VPN path is behaviour-neutral: a plain
        // `TcpStream::connect` to a loopback listener, no socket2, no bypass.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = connect_tcp_carrier(addr, None)
            .await
            .expect("unbypassed carrier dial must connect");
        assert_eq!(stream.peer_addr().expect("peer addr").ip(), addr.ip());
        let _ = accept.await;
    }
}
