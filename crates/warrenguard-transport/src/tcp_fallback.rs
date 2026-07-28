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

/// `true` when this process holds a `VpnService.protect` hook whose escape the
/// carrier socket depends on. Windows has no such hook, so the answer there is
/// a constant `false`.
#[cfg(unix)]
fn protection_armed() -> bool {
    crate::socket_protect::is_armed()
}

#[cfg(not(unix))]
fn protection_armed() -> bool {
    false
}

/// Routes the fresh carrier socket onto the underlying physical network before
/// it can connect. The call is NOT gated on Android: the hook is inert on a
/// host with no registered protector, and keeping one uncfg'd call site is what
/// makes this fail-closed contract provable off-device.
///
/// # Errors
/// The registered protector refused the socket. Failing is the only safe
/// answer: an unprotected carrier takes the VPN routes and nests the tunnel
/// inside itself.
#[cfg(unix)]
fn protect_before_connect(sock: &socket2::Socket) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if crate::socket_protect::protect(sock.as_raw_fd()) {
        return Ok(());
    }
    Err(io::Error::other(
        "the tunnel-socket protector refused the carrier socket",
    ))
}

#[cfg(not(unix))]
fn protect_before_connect(_sock: &socket2::Socket) -> io::Result<()> {
    Ok(())
}

/// Opens the TLS-over-TCP carrier's underlying TCP connection to `addr`, used by
/// the multi-hop ([`crate::multihop`]) carrier dial.
///
/// The carrier's escape comes in two shapes and both must be installed BEFORE
/// connect, or under a full-tunnel VPN the socket takes the default route (the
/// TUN) and loops into the very tunnel it is meant to bypass: a per-socket
/// `socket_bypass` on desktop, and `VpnService.protect` on the fd on Android.
/// `std::net`/`tokio` expose no pre-connect seam, so whenever either applies the
/// socket is built with `socket2`, scoped via
/// [`warrenguard_socket_bypass::apply_pre_connect`] and by the process-wide
/// socket protector, then connected on the tokio reactor. With neither
/// (userland proxy, no system VPN) this is exactly `TcpStream::connect(addr)`:
/// behaviour-neutral.
///
/// Fail-closed: an escape that cannot be installed aborts the dial; it never
/// falls back to an un-scoped socket that would loop into the tunnel.
///
/// # Errors
/// The socket build, the bypass, the protection, or the connect failed. The
/// error carries no address (no-log): a bypass failure is the raw `setsockopt`
/// errno.
pub(crate) async fn connect_tcp_carrier(
    addr: SocketAddr,
    socket_bypass: Option<SocketBypass>,
) -> io::Result<TcpStream> {
    if socket_bypass.is_none() && !protection_armed() {
        return TcpStream::connect(addr).await;
    }

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // The tokio reactor drives the connect, so the socket must be non-blocking
    // before the connect syscall is issued.
    sock.set_nonblocking(true)?;
    // Pin the socket to the physical link before connect. Propagate the failure
    // (no address rendered) instead of connecting an un-scoped socket: an
    // un-scoped carrier under a system VPN loops into the tunnel.
    if let Some(bypass) = socket_bypass {
        warrenguard_socket_bypass::apply_pre_connect(&sock, addr.is_ipv6(), bypass)?;
    }
    protect_before_connect(&sock)?;
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

    /// The socket protector is process-wide with no uninstall, and it decides
    /// whether a dial succeeds, so every carrier-dial test below serializes on
    /// it: one running concurrently with the protector test would otherwise
    /// inherit that test's verdict. An async mutex because the guard is held
    /// across the dial's awaits.
    #[cfg(unix)]
    static PROTECT_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

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
        let _serial = PROTECT_LOCK.lock().await;
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
        let _serial = PROTECT_LOCK.lock().await;
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
        #[cfg(unix)]
        let _serial = PROTECT_LOCK.lock().await;
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

    #[cfg(unix)]
    #[tokio::test]
    async fn carrier_dial_protects_the_socket_and_fails_closed_when_protection_is_refused() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicI32, Ordering};

        // Both phases share one test because the protector is process-wide and
        // cannot be uninstalled: splitting them would let the refusing one
        // decide the accepting one's dial.
        let _serial = PROTECT_LOCK.lock().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let addr = listener.local_addr().expect("listener addr");

        // A protector that refuses must abort the dial. On Android an
        // unprotected carrier socket takes the VPN routes and loops into the
        // TUN it is meant to escape, so failing is the only safe answer.
        crate::socket_protect::set_protector(Arc::new(|_fd| false));
        let err = connect_tcp_carrier(addr, None)
            .await
            .expect_err("a refused protection must fail the dial closed");
        assert!(
            !err.to_string().contains(&addr.ip().to_string()),
            "the carrier dial error must render no address"
        );

        // An accepting protector must have seen a real fd of the very socket the
        // dial then connects: proof the hook is on the path, not decoration.
        let seen_fd = Arc::new(AtomicI32::new(-1));
        let sink = Arc::clone(&seen_fd);
        crate::socket_protect::set_protector(Arc::new(move |fd| {
            sink.store(fd, Ordering::SeqCst);
            true
        }));
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = connect_tcp_carrier(addr, None)
            .await
            .expect("a protected carrier dial must connect");
        assert_eq!(stream.peer_addr().expect("peer addr").ip(), addr.ip());
        assert_eq!(
            seen_fd.load(Ordering::SeqCst),
            std::os::fd::AsRawFd::as_raw_fd(&stream),
            "the protector must have been handed the very socket that connected"
        );
        let _ = accept.await;

        // Restore the inert state: with no protector registered `protect`
        // answers `true`, so a permissive one is the same thing to every later
        // test in this process.
        crate::socket_protect::set_protector(Arc::new(|_fd| true));
    }
}
