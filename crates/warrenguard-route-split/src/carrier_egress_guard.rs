//! Bootstrap egress guard for the carrier socket bypass, with a self-healing
//! revert to the destination-route escape.
//!
//! This is the single home of the post-incident carrier policy that pairs with
//! [`socket_bypass::tunnel_socket_bypass`](crate::socket_bypass::tunnel_socket_bypass):
//! the per-OS bind is PREFERRED, not mandatory, and only kept while egress is
//! proven. The decision logic is pure over [`EgressGuardIo`], so every
//! consumer (the privileged system-VPN app, the SDK's experimental TUN
//! datapath) drives the same proven policy with its own thin I/O seam rather
//! than re-deriving it.
//!
//! # Why (2026-07-13 carrier-blackhole incident)
//!
//! On a multi-interface host an `IP_BOUND_IF`-bound carrier socket loses ALL
//! egress the instant the routing layer swaps the default onto the TUN (the
//! physical default becomes ifscoped): every `sendmsg` returns Ok, zero packets
//! reach the wire, and quinn's own `udp_tx` counter still climbs, so nothing in
//! the transport notices. The tunnel sits "Connected" over a dead datapath
//! because there is no signal that distinguishes "the datagram left the NIC"
//! from "the send syscall returned Ok but the packet went nowhere".
//!
//! The socket bind is the leak-free escape (Port Fail / TunnelCrack ServerIP
//! fix): unlike the `<carrier_ip>/32` host route it does not let any OTHER app
//! reach the exit IP off-tunnel. So the bind is PREFERRED, but only while egress
//! is proven. This guard is the missing signal plus its remedy: right after the
//! route swap it runs a short bootstrap window and watches for proof that our
//! own post-swap sends reach the peer. If proven, the bind is good and stays.
//! If sends were issued but nothing was acknowledged within the window, the
//! bound carrier is black-holing, so the guard reverts to the proven-safe
//! `<carrier_ip>/32` DefaultNode route AND unbinds the socket. The revert is the
//! fail-safe net; the bind is kept only when confirmed working, never
//! fail-closed (fail-closed is what took egress down).
//!
//! # Why ACK progress, not received bytes (2026-07-15 incident)
//!
//! The original evidence was `udp_rx.bytes` ("a reply cannot arrive unless our
//! request left the wire"). That axiom died when the fleet armed exit-side
//! DAITA and idle cover: the exit now sends UNSOLICITED dummies downlink, so
//! rx climbs on a client whose uplink is fully black-holed, and every
//! reconnect false-confirmed the dead bind (VPN "Connected", no internet,
//! NAT-PMP timeouts). ACK frames are different: the peer only emits them in
//! response to receiving OUR ack-eliciting packets, so `frame_rx.acks`
//! advancing proves client egress even under a rain of dummies. The baseline
//! is additionally taken one probe interval AFTER the guard starts, so ACKs
//! for pre-swap sends (handshake, setup stream: they land within one
//! RTT + max_ack_delay, far below the interval) can never masquerade as
//! post-swap proof.
//!
//! The decision logic is pure over [`EgressGuardIo`] so every transition is
//! unit-testable with paused time, without touching a real socket or route
//! table. The socket/route I/O is a thin seam each consumer implements.

use std::time::Duration;

/// Upper bound on the whole guard: past this the guard stops probing and
/// returns [`GuardOutcome::Inconclusive`] (and it caps the adaptive dead
/// window on very-high-RTT paths).
const BOOTSTRAP_WINDOW: Duration = Duration::from_secs(3);

/// Floor of the adaptive dead window: never declare a blackhole faster than
/// this, whatever the measured RTT claims.
const MIN_DEAD_WINDOW: Duration = Duration::from_secs(1);

/// Adaptive dead window = `DEAD_WINDOW_RTTS` x the path's smoothed RTT,
/// clamped to `[MIN_DEAD_WINDOW, BOOTSTRAP_WINDOW]`. 20 round trips of
/// probe-and-silence is decisive on any real path, and on a ~25 ms RTT this
/// cuts the connect-time cost of a black-holed bind from 3 s to ~1 s.
const DEAD_WINDOW_RTTS: u32 = 20;

/// Interval between egress probes inside the bootstrap window.
const PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// Minimum carrier sends that must have been ISSUED (post-baseline) before an
/// ack-silent window counts as a blackhole. The guard actively probes every
/// [`PROBE_INTERVAL`], so a live carrier clears this within the first probes;
/// the threshold only stops a genuinely idle window (no session, relay
/// unreachable) from being mislabelled dead and paying the `/32` leak for a
/// failure the `/32` cannot fix.
const MIN_SENDS_FOR_DEAD: u64 = 3;

/// Snapshot of the live carrier session's egress-relevant counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EgressReading {
    /// Identity of the currently published session (`0` = none published). A
    /// change to a new non-zero id proves a full QUIC handshake completed AFTER
    /// the route swap, which is impossible unless the carrier egressed.
    pub session_id: u64,
    /// quinn `udp_tx.datagrams`: sends the transport ISSUED. Climbs even when
    /// the packet never left the NIC (the blackhole artifact), so it proves
    /// intent to send, never egress.
    pub tx_datagrams: u64,
    /// quinn `frame_rx.acks`: ACK frames received from the peer. The peer only
    /// generates an ACK in response to receiving our ack-eliciting packets, so
    /// progress here (past the post-swap baseline) is client-side proof of
    /// egress that unsolicited downlink traffic (DAITA dummies, idle cover)
    /// cannot fake.
    pub acks_rx: u64,
    /// Smoothed path RTT, for the adaptive dead window. `Duration::ZERO` when
    /// no session is published.
    pub rtt: Duration,
}

/// Verdict of one [`assess_egress`] evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressVerdict {
    /// Post-baseline ACK progress (or a fresh session handshook post-swap):
    /// the bound carrier egresses. Keep the bind.
    Confirmed,
    /// No egress proof yet and the dead window has not elapsed: keep probing.
    Pending,
    /// Sends were issued, the adaptive window elapsed, and not one of them was
    /// acknowledged: the bound carrier is black-holing. Revert to the
    /// destination-route escape.
    Dead,
}

/// Adaptive blackhole deadline for the measured `rtt`: [`DEAD_WINDOW_RTTS`]
/// round trips, clamped to `[MIN_DEAD_WINDOW, BOOTSTRAP_WINDOW]` (an
/// unpublished session reads RTT zero and gets the floor).
pub(crate) fn dead_window(rtt: Duration) -> Duration {
    (rtt * DEAD_WINDOW_RTTS).clamp(MIN_DEAD_WINDOW, BOOTSTRAP_WINDOW)
}

/// Pure decision: given the `baseline` reading (captured one probe interval
/// after the route swap, so pre-swap ACKs are already drained) and the
/// `current` reading `elapsed` later, decide whether the bound carrier is
/// confirmed working, still pending, or dead.
pub(crate) fn assess_egress(
    baseline: EgressReading,
    current: EgressReading,
    elapsed: Duration,
) -> EgressVerdict {
    // A different live session id means a full handshake completed AFTER the
    // route swap; a handshake exchanges bytes both ways, so it cannot complete
    // unless the carrier egressed. Proof of a working bind.
    if current.session_id != 0 && current.session_id != baseline.session_id {
        return EgressVerdict::Confirmed;
    }
    // Same session acknowledging more of our packets than at baseline: a
    // post-baseline send left the NIC and reached the peer.
    if current.session_id == baseline.session_id && current.acks_rx > baseline.acks_rx {
        return EgressVerdict::Confirmed;
    }
    // Nothing acknowledged. Only call it dead on POSITIVE blackhole evidence:
    // sends were actually issued and the adaptive window elapsed. Absent that
    // (e.g. no session published, relay unreachable) leave it to the connect
    // timeout / dead-path escalation; reverting there would add the `/32` leak
    // for a failure the `/32` cannot heal.
    let sends = current.tx_datagrams.saturating_sub(baseline.tx_datagrams);
    if elapsed >= dead_window(current.rtt) && sends >= MIN_SENDS_FOR_DEAD {
        return EgressVerdict::Dead;
    }
    EgressVerdict::Pending
}

/// What the guard did, for logging and the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Egress confirmed within the window: the bind stayed and no `/32` route
    /// was added (leak-free, the goal).
    BypassConfirmed,
    /// The bound carrier looked dead: reverted to the `<carrier_ip>/32`
    /// DefaultNode escape and unbound the socket.
    RevertedToRoute,
    /// The window elapsed without confirmation but also without positive
    /// blackhole evidence (no session / no sends): left the bind untouched and
    /// deferred to the connect timeout / dead-path escalation.
    Inconclusive,
}

/// I/O seam consumed by [`run_bootstrap_guard`]. Each consumer implements it
/// over its own session channel and route/socket layer; the tests drive it with
/// a scripted mock and paused time.
//
// `async fn` in a trait: the guard is always driven with a single concrete
// consumer type (never a `dyn EgressGuardIo`), so the missing `Send` bound the
// lint warns about is not reachable here. The house pattern (killswitch-os,
// pump) is the documented allow rather than an `impl Future` desugaring.
#[allow(async_fn_in_trait)]
pub trait EgressGuardIo {
    /// Sample the live carrier session's egress counters.
    fn read_egress(&mut self) -> EgressReading;

    /// Emit one in-tunnel probe so the carrier issues a send even on an idle
    /// bootstrap. This is what makes `tx_datagrams` climb, which is what lets
    /// [`assess_egress`] distinguish a blackhole (tx climbs, acks frozen) from
    /// a merely idle socket, and what elicits the ACKs that prove egress.
    async fn send_probe(&mut self);

    /// Revert to the proven-safe escape: install the `<carrier_ip>/32`
    /// DefaultNode route AND unbind the carrier socket (fresh wildcard rebind),
    /// reproducing the pre-bind config. Best-effort; logs its own failures.
    async fn revert_to_route(&mut self);
}

/// Run the bootstrap egress guard: burn one probe interval (so ACKs of
/// pre-swap sends drain), take the decision baseline, then probe the freshly
/// bound carrier until it is confirmed, declared dead (revert), or the window
/// closes inconclusively.
pub async fn run_bootstrap_guard<I: EgressGuardIo>(io: &mut I) -> GuardOutcome {
    io.send_probe().await;
    tokio::time::sleep(PROBE_INTERVAL).await;
    let baseline = io.read_egress();
    let start = tokio::time::Instant::now();
    loop {
        io.send_probe().await;
        tokio::time::sleep(PROBE_INTERVAL).await;
        let elapsed = tokio::time::Instant::now().saturating_duration_since(start);
        match assess_egress(baseline, io.read_egress(), elapsed) {
            EgressVerdict::Confirmed => return GuardOutcome::BypassConfirmed,
            EgressVerdict::Dead => {
                io.revert_to_route().await;
                return GuardOutcome::RevertedToRoute;
            }
            EgressVerdict::Pending => {
                if elapsed >= BOOTSTRAP_WINDOW {
                    // Window elapsed with no confirmation and no blackhole
                    // evidence: leave the bind, defer to other machinery.
                    return GuardOutcome::Inconclusive;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(session_id: u64, tx_datagrams: u64, acks_rx: u64) -> EgressReading {
        EgressReading {
            session_id,
            tx_datagrams,
            acks_rx,
            rtt: Duration::from_millis(25),
        }
    }

    #[test]
    fn confirmed_when_acks_advance_on_the_same_session() {
        // The peer acknowledged a post-baseline send: it must have egressed.
        let base = reading(1, 10, 5);
        let cur = reading(1, 14, 7);
        assert_eq!(
            assess_egress(base, cur, Duration::from_millis(250)),
            EgressVerdict::Confirmed
        );
    }

    #[test]
    fn confirmed_when_a_fresh_session_handshakes_after_the_swap() {
        // A different non-zero session id can only exist if a full handshake
        // completed post-swap, which requires egress. Confirmed even though the
        // fresh session's ack counter is BELOW the old baseline.
        let base = reading(1, 500, 90);
        let cur = reading(2, 3, 1);
        assert_eq!(
            assess_egress(base, cur, Duration::from_millis(250)),
            EgressVerdict::Confirmed
        );
        // Also confirmed when there was no session at baseline and one is up now.
        assert_eq!(
            assess_egress(
                reading(0, 0, 0),
                reading(7, 1, 1),
                Duration::from_millis(250)
            ),
            EgressVerdict::Confirmed
        );
    }

    #[test]
    fn dead_when_sends_issued_but_none_acknowledged_after_the_window() {
        // The exact incident shape: tx climbs (sends issued), acks frozen,
        // window elapsed. This is the signal that was missing.
        let base = reading(1, 10, 5);
        let cur = reading(1, 273, 5);
        assert_eq!(
            assess_egress(base, cur, dead_window(cur.rtt)),
            EgressVerdict::Dead
        );
    }

    #[test]
    fn unsolicited_downlink_traffic_never_confirms_a_dead_uplink() {
        // 2026-07-15 regression: an armed exit rains DAITA dummies on the
        // downlink, so RECEIVED traffic is not proof of egress. Nothing in the
        // reading but ACK progress may confirm; a frozen ack counter with
        // climbing sends past the window must read Dead, whatever arrived.
        let base = reading(1, 10, 5);
        let cur = reading(1, 400, 5);
        assert_eq!(
            assess_egress(base, cur, dead_window(cur.rtt)),
            EgressVerdict::Dead
        );
    }

    #[test]
    fn dead_window_scales_with_rtt_between_floor_and_cap() {
        assert_eq!(dead_window(Duration::from_millis(25)), MIN_DEAD_WINDOW);
        assert_eq!(
            dead_window(Duration::from_millis(100)),
            Duration::from_secs(2)
        );
        assert_eq!(dead_window(Duration::from_millis(600)), BOOTSTRAP_WINDOW);
        assert_eq!(dead_window(Duration::ZERO), MIN_DEAD_WINDOW);
    }

    #[test]
    fn pending_before_the_adaptive_window_even_with_sends_and_ack_silence() {
        // Same blackhole shape but the window has not elapsed yet: keep probing,
        // never revert early (a slow first RTT must not be mislabelled dead).
        let base = reading(1, 10, 5);
        let cur = reading(1, 100, 5);
        assert_eq!(
            assess_egress(base, cur, dead_window(cur.rtt) - Duration::from_millis(1)),
            EgressVerdict::Pending
        );
    }

    #[test]
    fn pending_when_window_elapsed_but_too_few_sends_were_issued() {
        // Window elapsed but fewer than MIN_SENDS_FOR_DEAD sends issued: not a
        // blackhole, an idle/absent carrier. Do NOT revert (the /32 would not
        // help and only adds the leak).
        let base = reading(1, 10, 5);
        let cur = reading(1, 10 + MIN_SENDS_FOR_DEAD - 1, 5);
        assert_eq!(
            assess_egress(base, cur, BOOTSTRAP_WINDOW),
            EgressVerdict::Pending
        );
    }

    #[test]
    fn not_confirmed_when_the_session_drops_to_none() {
        // Session went to None mid-window (supervisor redialing): the id is 0,
        // which must NOT read as a fresh-session confirmation.
        let base = reading(1, 10, 5);
        let cur = EgressReading::default();
        assert_eq!(
            assess_egress(base, cur, Duration::from_millis(250)),
            EgressVerdict::Pending
        );
    }

    // Driver tests over a scripted mock with paused time.

    struct MockIo {
        /// Reading returned while the pre-baseline interval burns (leftover
        /// ACKs of pre-swap sends may already be counted here).
        baseline: EgressReading,
        /// The reading returned on every sample AFTER the baseline sample.
        post: EgressReading,
        first_read_taken: bool,
        probes_sent: u32,
        reverts: u32,
    }

    impl MockIo {
        fn new(baseline: EgressReading, post: EgressReading) -> Self {
            Self {
                baseline,
                post,
                first_read_taken: false,
                probes_sent: 0,
                reverts: 0,
            }
        }
    }

    impl EgressGuardIo for MockIo {
        fn read_egress(&mut self) -> EgressReading {
            // The driver reads once for the (post-burn) baseline, then again
            // each probe iteration; the mock returns the post-swap reading for
            // all reads after the first.
            if self.first_read_taken {
                self.post
            } else {
                self.first_read_taken = true;
                self.baseline
            }
        }
        async fn send_probe(&mut self) {
            self.probes_sent += 1;
        }
        async fn revert_to_route(&mut self) {
            self.reverts += 1;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn guard_keeps_the_bind_when_egress_is_confirmed() {
        // Post-baseline acks advance on the same session: confirmed on the
        // first probe, no revert, the /32 leak is never added.
        let mut io = MockIo::new(reading(1, 10, 5), reading(1, 12, 6));
        let outcome = run_bootstrap_guard(&mut io).await;
        assert_eq!(outcome, GuardOutcome::BypassConfirmed);
        assert_eq!(io.reverts, 0, "confirmed egress must never revert");
        assert!(io.probes_sent >= 2, "one burn probe plus decision probes");
    }

    #[tokio::test(start_paused = true)]
    async fn guard_reverts_to_the_route_when_the_carrier_blackholes() {
        // Post-baseline tx climbs but not one send is acknowledged for the
        // whole adaptive window: the incident shape. Revert exactly once.
        let mut io = MockIo::new(reading(1, 10, 5), reading(1, 400, 5));
        let outcome = run_bootstrap_guard(&mut io).await;
        assert_eq!(outcome, GuardOutcome::RevertedToRoute);
        assert_eq!(io.reverts, 1, "a detected blackhole reverts exactly once");
        assert!(
            io.probes_sent >= 2,
            "the guard must actively probe so tx can climb"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn guard_ignores_acks_that_landed_during_the_burn_interval() {
        // 2026-07-15 regression: on a reconnect, ACKs of the pre-swap
        // handshake land milliseconds after the swap. They arrive during the
        // burn interval, so they are already inside the baseline and must not
        // confirm; with the ack counter frozen after the baseline and sends
        // climbing, the guard must still detect the blackhole and revert.
        let mut io = MockIo::new(reading(1, 10, 9), reading(1, 400, 9));
        let outcome = run_bootstrap_guard(&mut io).await;
        assert_eq!(outcome, GuardOutcome::RevertedToRoute);
        assert_eq!(io.reverts, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn guard_is_inconclusive_without_a_session_or_sends() {
        // No session the whole window (relay unreachable): no acks, no sends.
        // Do not revert, defer to the connect timeout / dead-path escalation.
        let mut io = MockIo::new(EgressReading::default(), EgressReading::default());
        let outcome = run_bootstrap_guard(&mut io).await;
        assert_eq!(outcome, GuardOutcome::Inconclusive);
        assert_eq!(io.reverts, 0, "no blackhole evidence must not revert");
    }
}
