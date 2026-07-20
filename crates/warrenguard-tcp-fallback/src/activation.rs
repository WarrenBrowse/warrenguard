//! Auto-activation policy: race the UDP handshake against the TLS-over-TCP
//! carrier.
//!
//! This is a thin orchestration layer, not a change to the QUIC engine. The UDP
//! handshake gets a head start; if it neither succeeds nor fails within
//! [`FallbackPolicy::tcp_race_delay`], the TCP carrier is dialled IN PARALLEL and
//! the first successful handshake wins (the loser's dial is dropped, cancelling
//! it). It is armed by default, but strictly fail-closed: with
//! [`FallbackPolicy::tcp_fallback_enabled`] false, a UDP failure is surfaced
//! verbatim and the TCP closure is never even constructed, so no `:443/tcp`
//! connection is ever attempted unless the carrier is armed.

use std::future::Future;
use std::io;
use std::time::Duration;

use thiserror::Error;

/// Overall UDP-handshake deadline. Kept well under a full QUIC handshake timeout
/// so a blocked-UDP network fails fast to TCP instead of stalling the user for
/// tens of seconds. It bounds the UDP arm even while the TCP carrier races
/// alongside it. A plain default the deployer overrides, not baked policy.
pub const DEFAULT_UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default head start the UDP handshake gets before the armed TCP carrier is
/// dialled in parallel. Long enough that a healthy sub-400 ms-RTT UDP handshake
/// wins without the TCP dial ever being constructed; short enough that a
/// UDP-hostile network starts the carrier well before the overall deadline.
/// A plain default the deployer overrides via `WARREN_TCP_FALLBACK_RACE_MS`.
pub const DEFAULT_TCP_FALLBACK_RACE: Duration = Duration::from_millis(400);

/// Whether, and how eagerly, to race the TCP carrier.
#[derive(Debug, Clone)]
pub struct FallbackPolicy {
    /// Master switch. `true` (the default) arms the carrier: a UDP handshake that
    /// stalls past [`Self::tcp_race_delay`] is raced against the TCP carrier.
    /// `false` keeps the UDP path alone (fail-closed): a UDP failure is never
    /// retried over TCP and the TCP dial is never constructed.
    pub tcp_fallback_enabled: bool,
    /// Overall deadline for the UDP handshake before it is abandoned (when
    /// armed, the TCP carrier may already be racing alongside it).
    pub udp_handshake_timeout: Duration,
    /// Head start the UDP handshake gets before the armed TCP carrier is dialled
    /// in parallel. A UDP success or failure inside this window is handled
    /// without ever touching the TCP path.
    pub tcp_race_delay: Duration,
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            tcp_fallback_enabled: true,
            udp_handshake_timeout: DEFAULT_UDP_HANDSHAKE_TIMEOUT,
            tcp_race_delay: DEFAULT_TCP_FALLBACK_RACE,
        }
    }
}

impl FallbackPolicy {
    /// A policy with the TCP carrier armed and the default timeouts (identical to
    /// [`Default`]; kept as an explicit-intent constructor at the arming sites).
    #[must_use]
    pub fn enabled() -> Self {
        Self {
            tcp_fallback_enabled: true,
            ..Self::default()
        }
    }

    /// A policy with the TCP carrier disarmed: fail-closed. The disarmed dial
    /// paths ([`crate::resolve_fallback_policy`] when a precondition is missing)
    /// use this so the master switch defaulting to armed can never flip a
    /// no-cover / non-advertised / env-disabled dial open.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            tcp_fallback_enabled: false,
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
    /// The carrier was armed, UDP failed, and the TCP path also failed.
    #[error("UDP failed and the TCP fallback also failed")]
    TcpFallbackFailed(#[source] io::Error),
}

/// Connects over UDP, racing the TCP carrier in parallel once the UDP handshake
/// stalls past [`FallbackPolicy::tcp_race_delay`].
///
/// `udp` is the in-flight UDP handshake future. `tcp` is a closure building the
/// TCP-carrier handshake future; it is called ONLY when the carrier is armed AND
/// the UDP handshake has either failed or not completed within the race delay, so
/// a disarmed policy never constructs, let alone dials, the TCP path. When both
/// race, the first successful handshake is returned and the loser's future is
/// dropped, cancelling its in-flight dial. A UDP success at any point wins over a
/// still-pending TCP dial. The UDP arm keeps the overall
/// [`FallbackPolicy::udp_handshake_timeout`] deadline.
///
/// # Errors
/// [`FallbackError`], distinguishing UDP-timeout vs UDP-error when disarmed, and
/// [`FallbackError::TcpFallbackFailed`] when the armed carrier (and any UDP
/// attempt) failed.
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
    // Fail-closed: a disarmed policy never constructs the TCP path.
    if !policy.tcp_fallback_enabled {
        return match tokio::time::timeout(policy.udp_handshake_timeout, udp).await {
            Ok(Ok(connection)) => Ok(connection),
            Ok(Err(udp_error)) => Err(FallbackError::UdpFailedFallbackDisabled(udp_error)),
            Err(_elapsed) => Err(FallbackError::UdpTimedOutFallbackDisabled),
        };
    }

    let udp = tokio::time::timeout(policy.udp_handshake_timeout, udp);
    tokio::pin!(udp);

    // Phase 1: give UDP a head start; the TCP path is not even constructed yet.
    // A UDP success returns immediately; a UDP failure inside the window starts
    // the TCP carrier at once (no point waiting out the rest of the delay).
    tokio::select! {
        biased;
        udp_result = &mut udp => {
            return match udp_result {
                Ok(Ok(connection)) => Ok(connection),
                Ok(Err(_)) | Err(_) => tcp().await.map_err(FallbackError::TcpFallbackFailed),
            };
        }
        () = tokio::time::sleep(policy.tcp_race_delay) => {}
    }

    // Phase 2: the UDP handshake stalled past the delay. Dial the TCP carrier and
    // race it against the still-pending UDP arm; the first success wins and the
    // loser is dropped. A UDP arm that keeps failing does not abandon a TCP dial
    // still in flight, and a failed TCP dial does not abandon a UDP arm that may
    // yet complete within its deadline.
    let tcp_fut = tcp();
    tokio::pin!(tcp_fut);
    let mut udp_done = false;
    let mut tcp_error: Option<io::Error> = None;
    loop {
        tokio::select! {
            biased;
            udp_result = &mut udp, if !udp_done => match udp_result {
                Ok(Ok(connection)) => return Ok(connection),
                Ok(Err(_)) | Err(_) => {
                    // UDP lost. If TCP already failed, surface that error;
                    // otherwise wait for the TCP dial still in flight.
                    if let Some(tcp_error) = tcp_error.take() {
                        return Err(FallbackError::TcpFallbackFailed(tcp_error));
                    }
                    udp_done = true;
                }
            },
            tcp_result = &mut tcp_fut, if tcp_error.is_none() => match tcp_result {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    // TCP lost. If UDP already finished, surface the TCP error;
                    // otherwise keep the UDP arm running to its deadline.
                    if udp_done {
                        return Err(FallbackError::TcpFallbackFailed(error));
                    }
                    tcp_error = Some(error);
                }
            },
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

    /// Sets its flag when dropped: proof that a racing arm was cancelled (its
    /// future dropped) rather than run to completion.
    struct CancelGuard(Arc<AtomicBool>);
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A handshake that never completes on its own but records, via its
    /// [`CancelGuard`], that it was dropped (cancelled) by the race.
    async fn pending_until_cancelled(cancelled: Arc<AtomicBool>) -> io::Result<u8> {
        let _guard = CancelGuard(cancelled);
        pending::<io::Result<u8>>().await
    }

    #[test]
    fn default_policy_arms_the_carrier() {
        assert!(
            FallbackPolicy::default().tcp_fallback_enabled,
            "the carrier must be armed by default (the anti-censorship path is on unless disabled)"
        );
        assert_eq!(
            FallbackPolicy::default().tcp_race_delay,
            DEFAULT_TCP_FALLBACK_RACE
        );
        assert!(
            !FallbackPolicy::disabled().tcp_fallback_enabled,
            "the disarmed policy must be fail-closed"
        );
    }

    /// Disarmed: a UDP timeout must NOT construct or run the TCP path.
    #[tokio::test(start_paused = true)]
    async fn disabled_udp_timeout_never_calls_tcp() {
        let called = flag();
        let c = Arc::clone(&called);
        let result = connect_with_fallback(&FallbackPolicy::disabled(), udp_never(), || {
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
            "the TCP closure must never be called when the carrier is disarmed"
        );
    }

    /// Disarmed: a UDP error surfaces verbatim, TCP untouched.
    #[tokio::test(start_paused = true)]
    async fn disabled_udp_error_surfaces_and_never_calls_tcp() {
        let called = flag();
        let c = Arc::clone(&called);
        let udp = async { Err::<u8, _>(io::Error::from(io::ErrorKind::ConnectionRefused)) };
        let result = connect_with_fallback(&FallbackPolicy::disabled(), udp, || {
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

    /// Armed: a UDP handshake that stalls past the race delay dials the TCP
    /// carrier, and it wins in a fraction of the overall UDP deadline (proof the
    /// dial is raced after the ~delay, not deferred to the 5s timeout).
    #[tokio::test(start_paused = true)]
    async fn armed_races_tcp_after_the_delay_when_udp_stalls() {
        let called = flag();
        let c = Arc::clone(&called);
        let start = tokio::time::Instant::now();
        let result = connect_with_fallback(&FallbackPolicy::enabled(), udp_never(), || {
            c.store(true, Ordering::SeqCst);
            async { Ok(42u8) }
        })
        .await;
        let elapsed = start.elapsed();
        assert_eq!(result.expect("tcp carrier wins the race"), 42);
        assert!(
            called.load(Ordering::SeqCst),
            "the TCP path must be dialled"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "TCP must be raced right after the ~400ms delay, not deferred to the 5s deadline (got {elapsed:?})"
        );
    }

    /// Armed: a UDP error before the race delay dials the TCP carrier at once,
    /// without waiting out the rest of the head start.
    #[tokio::test(start_paused = true)]
    async fn armed_udp_error_before_delay_dials_tcp_immediately() {
        let udp = async { Err::<u8, _>(io::Error::from(io::ErrorKind::ConnectionReset)) };
        let start = tokio::time::Instant::now();
        let result =
            connect_with_fallback(&FallbackPolicy::enabled(), udp, || async { Ok(7u8) }).await;
        assert_eq!(result.expect("tcp carrier succeeds"), 7);
        assert!(
            start.elapsed() < FallbackPolicy::enabled().tcp_race_delay,
            "an early UDP error must not wait out the head start before dialling TCP"
        );
    }

    /// Armed: a UDP success inside the head start returns immediately and the
    /// TCP path is never constructed.
    #[tokio::test(start_paused = true)]
    async fn armed_udp_success_before_delay_never_calls_tcp() {
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
            "UDP won inside the head start, TCP must never be constructed"
        );
    }

    /// Armed: with both racing, a UDP success wins and cancels the in-flight TCP
    /// dial (the TCP future is dropped before it completes).
    #[tokio::test(start_paused = true)]
    async fn armed_udp_wins_the_race_and_cancels_the_tcp_dial() {
        let tcp_called = flag();
        let tcp_cancelled = flag();
        let called = Arc::clone(&tcp_called);
        let cancelled = Arc::clone(&tcp_cancelled);
        // UDP stalls past the 400ms delay, then succeeds at 500ms; TCP starts at
        // 400ms but never completes on its own, so UDP wins and TCP is cancelled.
        let udp = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok::<u8, io::Error>(1)
        };
        let result = connect_with_fallback(&FallbackPolicy::enabled(), udp, move || {
            called.store(true, Ordering::SeqCst);
            pending_until_cancelled(cancelled)
        })
        .await;
        assert_eq!(result.expect("udp wins the race"), 1);
        assert!(
            tcp_called.load(Ordering::SeqCst),
            "the race must have started the TCP dial"
        );
        assert!(
            tcp_cancelled.load(Ordering::SeqCst),
            "UDP winning must cancel (drop) the in-flight TCP dial"
        );
    }

    /// Armed: with both racing, a TCP success wins and cancels the still-pending
    /// UDP arm (its future is dropped before the deadline).
    #[tokio::test(start_paused = true)]
    async fn armed_tcp_wins_the_race_and_cancels_the_udp_dial() {
        let udp_cancelled = flag();
        let cancelled = Arc::clone(&udp_cancelled);
        let start = tokio::time::Instant::now();
        // UDP never completes; after the 400ms delay TCP starts and completes at
        // +50ms, so TCP wins and the UDP arm is cancelled well before its 5s
        // deadline.
        let result = connect_with_fallback(
            &FallbackPolicy::enabled(),
            pending_until_cancelled(cancelled),
            || async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<u8, io::Error>(42)
            },
        )
        .await;
        assert_eq!(result.expect("tcp wins the race"), 42);
        assert!(
            udp_cancelled.load(Ordering::SeqCst),
            "TCP winning must cancel (drop) the still-pending UDP arm"
        );
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "TCP winning must not wait out the UDP deadline"
        );
    }

    /// Armed: TCP loses (fails) but the UDP arm is still pending, so the race
    /// keeps waiting and a later UDP success still wins.
    #[tokio::test(start_paused = true)]
    async fn armed_tcp_failure_does_not_abandon_a_pending_udp() {
        // TCP fails at +50ms after the delay; UDP succeeds at 700ms. The failed
        // TCP dial must NOT short-circuit the still-viable UDP handshake.
        let udp = async {
            tokio::time::sleep(Duration::from_millis(700)).await;
            Ok::<u8, io::Error>(5)
        };
        let result = connect_with_fallback(&FallbackPolicy::enabled(), udp, || async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Err::<u8, _>(io::Error::from(io::ErrorKind::ConnectionRefused))
        })
        .await;
        assert_eq!(
            result.expect("udp still completes after TCP failed"),
            5,
            "a failed TCP dial must not abandon a UDP handshake that can still succeed"
        );
    }

    /// Armed but both arms fail: the TCP error is surfaced.
    #[tokio::test(start_paused = true)]
    async fn armed_both_fail_surfaces_tcp_error() {
        let result = connect_with_fallback(&FallbackPolicy::enabled(), udp_never(), || async {
            Err::<u8, _>(io::Error::from(io::ErrorKind::TimedOut))
        })
        .await;
        assert!(matches!(result, Err(FallbackError::TcpFallbackFailed(_))));
    }
}
