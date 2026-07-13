//! Auto-activation policy: retry over the TCP carrier after the UDP handshake
//! times out.
//!
//! This is a thin orchestration layer, not a change to the QUIC engine. It
//! races the UDP handshake against a deadline; only if UDP fails (times out or
//! errors) AND the fallback is explicitly enabled does it run the caller's TCP
//! path. It is OFF by default: with [`FallbackPolicy::tcp_fallback_enabled`]
//! false, a UDP failure is surfaced verbatim and the TCP closure is never even
//! constructed, so no `:443/tcp` connection is ever attempted unless the
//! deployer opts in.

use std::future::Future;
use std::io;
use std::time::Duration;

use thiserror::Error;

/// Default UDP-handshake deadline before the fallback is considered. Kept well
/// under a full QUIC handshake timeout so a blocked-UDP network fails fast to
/// TCP instead of stalling the user for tens of seconds. A plain default the
/// deployer overrides, not baked policy.
pub const DEFAULT_UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether, and how eagerly, to fall back to the TCP carrier.
#[derive(Debug, Clone)]
pub struct FallbackPolicy {
    /// Master switch. `false` (the default) means the UDP path is used alone and
    /// a UDP failure is never retried over TCP.
    pub tcp_fallback_enabled: bool,
    /// How long to wait for the UDP handshake before falling back (when
    /// enabled).
    pub udp_handshake_timeout: Duration,
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            tcp_fallback_enabled: false,
            udp_handshake_timeout: DEFAULT_UDP_HANDSHAKE_TIMEOUT,
        }
    }
}

impl FallbackPolicy {
    /// A policy with the TCP fallback enabled and the default UDP timeout.
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            tcp_fallback_enabled: true,
            ..Self::default()
        }
    }
}

/// Outcome of [`connect_with_fallback`] when no connection could be established.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FallbackError {
    /// The UDP handshake errored and the TCP fallback is disabled.
    #[error("UDP handshake failed and the TCP fallback is disabled")]
    UdpFailedFallbackDisabled(#[source] io::Error),
    /// The UDP handshake did not complete within the deadline and the TCP
    /// fallback is disabled.
    #[error("UDP handshake timed out and the TCP fallback is disabled")]
    UdpTimedOutFallbackDisabled,
    /// UDP failed, the fallback was enabled, and the TCP path also failed.
    #[error("UDP failed and the TCP fallback also failed")]
    TcpFallbackFailed(#[source] io::Error),
}

/// Connects over UDP, falling back to TCP only on a UDP failure when the policy
/// allows it.
///
/// `udp` is the in-flight UDP handshake future. `tcp` is a closure building the
/// TCP-carrier handshake future; it is called ONLY when UDP has failed and
/// [`FallbackPolicy::tcp_fallback_enabled`] is true, so a disabled policy never
/// constructs, let alone dials, the TCP path. On a UDP success within the
/// deadline the connection is returned and `tcp` is never touched.
///
/// # Errors
/// [`FallbackError`], distinguishing UDP-timeout vs UDP-error and whether the
/// fallback was disabled or itself failed.
pub async fn connect_with_fallback<C, U, T, TFut>(
    policy: &FallbackPolicy,
    udp: U,
    tcp: T,
) -> Result<C, FallbackError>
where
    U: Future<Output = io::Result<C>>,
    T: FnOnce() -> TFut,
    TFut: Future<Output = io::Result<C>>,
{
    match tokio::time::timeout(policy.udp_handshake_timeout, udp).await {
        Ok(Ok(connection)) => Ok(connection),
        Ok(Err(udp_error)) => {
            if policy.tcp_fallback_enabled {
                tcp().await.map_err(FallbackError::TcpFallbackFailed)
            } else {
                Err(FallbackError::UdpFailedFallbackDisabled(udp_error))
            }
        }
        Err(_elapsed) => {
            if policy.tcp_fallback_enabled {
                tcp().await.map_err(FallbackError::TcpFallbackFailed)
            } else {
                Err(FallbackError::UdpTimedOutFallbackDisabled)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// A never-completing UDP handshake future.
    fn udp_never() -> impl Future<Output = io::Result<u8>> {
        pending::<io::Result<u8>>()
    }

    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    /// OFF by default: a UDP timeout must NOT construct or run the TCP path.
    #[tokio::test(start_paused = true)]
    async fn off_by_default_udp_timeout_never_calls_tcp() {
        let called = flag();
        let c = Arc::clone(&called);
        let result = connect_with_fallback(&FallbackPolicy::default(), udp_never(), || {
            c.store(true, Ordering::SeqCst);
            async { Ok(0u8) }
        })
        .await;
        assert!(matches!(
            result,
            Err(FallbackError::UdpTimedOutFallbackDisabled)
        ));
        assert!(
            !called.load(Ordering::SeqCst),
            "the TCP closure must never be called when the fallback is disabled"
        );
    }

    /// OFF by default: a UDP error surfaces verbatim, TCP untouched.
    #[tokio::test(start_paused = true)]
    async fn off_by_default_udp_error_surfaces_and_never_calls_tcp() {
        let called = flag();
        let c = Arc::clone(&called);
        let udp = async { Err::<u8, _>(io::Error::from(io::ErrorKind::ConnectionRefused)) };
        let result = connect_with_fallback(&FallbackPolicy::default(), udp, || {
            c.store(true, Ordering::SeqCst);
            async { Ok(0u8) }
        })
        .await;
        assert!(matches!(
            result,
            Err(FallbackError::UdpFailedFallbackDisabled(_))
        ));
        assert!(!called.load(Ordering::SeqCst));
    }

    /// Enabled: a UDP timeout falls back to TCP and returns its connection.
    #[tokio::test(start_paused = true)]
    async fn enabled_udp_timeout_falls_back_to_tcp() {
        let called = flag();
        let c = Arc::clone(&called);
        let result = connect_with_fallback(&FallbackPolicy::enabled(), udp_never(), || {
            c.store(true, Ordering::SeqCst);
            async { Ok(42u8) }
        })
        .await;
        assert_eq!(result.expect("tcp fallback succeeds"), 42);
        assert!(called.load(Ordering::SeqCst), "the TCP path must run");
    }

    /// Enabled: a UDP error also falls back to TCP.
    #[tokio::test(start_paused = true)]
    async fn enabled_udp_error_falls_back_to_tcp() {
        let udp = async { Err::<u8, _>(io::Error::from(io::ErrorKind::ConnectionReset)) };
        let result =
            connect_with_fallback(&FallbackPolicy::enabled(), udp, || async { Ok(7u8) }).await;
        assert_eq!(result.expect("tcp fallback succeeds"), 7);
    }

    /// A UDP success is returned as-is and the TCP path is never touched, even
    /// when the fallback is enabled.
    #[tokio::test(start_paused = true)]
    async fn udp_success_never_calls_tcp() {
        let called = flag();
        let c = Arc::clone(&called);
        let result = connect_with_fallback(&FallbackPolicy::enabled(), async { Ok(9u8) }, || {
            c.store(true, Ordering::SeqCst);
            async { Ok(0u8) }
        })
        .await;
        assert_eq!(result.expect("udp succeeds"), 9);
        assert!(
            !called.load(Ordering::SeqCst),
            "UDP won, TCP must be skipped"
        );
    }

    /// Enabled but the TCP fallback itself fails: the TCP error is surfaced.
    #[tokio::test(start_paused = true)]
    async fn enabled_both_fail_surfaces_tcp_error() {
        let result = connect_with_fallback(&FallbackPolicy::enabled(), udp_never(), || async {
            Err::<u8, _>(io::Error::from(io::ErrorKind::TimedOut))
        })
        .await;
        assert!(matches!(result, Err(FallbackError::TcpFallbackFailed(_))));
    }
}
