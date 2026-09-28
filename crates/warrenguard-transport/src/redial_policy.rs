//! Single home of the client redial (reconnect) schedule.
//!
//! Every client tier that rebuilds a dead tunnel (the engine multi-hop
//! supervisor's cold dial, the SDK userland proxy supervisor, any future
//! client loop) draws its schedule from here: the shared
//! [`Backoff::HANDSHAKE`] preset plus the healthy-vs-flapping session
//! verdict. Clients keep their own loop plumbing (watch channels, listeners,
//! netstack epochs); the schedule values and the flap rule live here only,
//! so they cannot drift apart again.

use std::time::{Duration, Instant};

use warrenguard_backoff::{Backoff, JitterBackoff};

/// The client redial schedule: the shared QUIC handshake preset
/// ([`Backoff::HANDSHAKE`], 500 ms base, 15 s ceiling). The first draw after
/// a reset is immediate, so a healthy session's death redials at once and
/// only repeated failures escalate.
pub const REDIAL_BACKOFF: Backoff = Backoff::HANDSHAKE;

/// A session that stayed up at least this long is healthy, so its death
/// redials immediately (schedule reset). A shorter one is flapping (the
/// exit accepts the handshake then drops right away): the schedule keeps
/// escalating so clients do not tight-loop full cryptographic handshakes
/// against a flapping exit.
pub const MIN_HEALTHY_UPTIME: Duration = Duration::from_secs(5);

/// The healthy-vs-flapping verdict on a session that just ended: `true` when
/// it stayed up for at least [`MIN_HEALTHY_UPTIME`].
#[must_use]
pub fn is_healthy_uptime(uptime: Duration) -> bool {
    uptime >= MIN_HEALTHY_UPTIME
}

/// Applies the post-session verdict to `backoff` and returns the delay to
/// wait before the next redial: a healthy uptime resets the schedule and
/// redials immediately; a flap draws the next escalating delay.
#[must_use]
pub fn delay_after_session(uptime: Duration, backoff: &mut JitterBackoff) -> Duration {
    if is_healthy_uptime(uptime) {
        backoff.reset();
        Duration::ZERO
    } else {
        backoff.next_delay()
    }
}

/// Application close code a server closes a client with when it is going away
/// rather than refusing it: a stopping exit closing its clients before it
/// exits, and a relay that lost the exit leg. QUIC also closes with code 0
/// implicitly when a peer drops its last handle, so a code 0 close is not
/// always a restart; the fast schedule it starts is bounded
/// ([`OPERATIONAL_REDIAL_WINDOW`]), which is all a misreading costs.
pub const OPERATIONAL_CLOSE_CODE: u32 = 0;

/// Spacing of the dial attempts that follow an operational close. A dial
/// whose QUIC Initial reaches a port nothing has bound yet is dropped, and
/// QUIC resends it only after a probe timeout of about a second (three times
/// the 333 ms initial RTT, RFC 9002 section 6.2.2), then two, then four. On
/// a restarting server the ordinary schedule's second attempt, drawn 250 to
/// 500 ms after the close, lands in exactly the gap before the successor
/// binds, and the client came back a whole retransmission after the server
/// listened again. Fresh attempts on this cadence bound that wait instead.
pub const OPERATIONAL_REDIAL_CADENCE: Duration = Duration::from_millis(150);

/// How long after an operational close the cadence lasts. It covers a server
/// restart (a successor bound its port 1.3 to 1.4 s after the stop in the
/// measurement this schedule answers) with room to spare; past it the
/// ordinary schedule takes over, so a peer that closed and never came back is
/// not redialled at this rate.
pub const OPERATIONAL_REDIAL_WINDOW: Duration = Duration::from_secs(3);

/// Round trips of the closed session's path a single fast attempt is given
/// before it is abandoned: a handshake needs one or two (two when the
/// server's certificate flight exceeds the anti-amplification limit), so a
/// far server that is up is never cut short by the cadence.
pub const OPERATIONAL_ATTEMPT_ROUND_TRIPS: u32 = 4;

/// [`OPERATIONAL_ATTEMPT_ROUND_TRIPS`] for a session that rode the
/// TLS-over-TCP carrier, whose dial adds the TCP and TLS handshakes to the
/// QUIC one.
pub const OPERATIONAL_CARRIER_ATTEMPT_ROUND_TRIPS: u32 = 6;

/// `true` when the peer closed the connection with [`OPERATIONAL_CLOSE_CODE`].
/// A close by this side, a reset, a timeout or any other code is not one.
#[must_use]
pub fn is_operational_close(error: &quinn::ConnectionError) -> bool {
    matches!(
        error,
        quinn::ConnectionError::ApplicationClosed(close)
            if close.error_code == quinn::VarInt::from_u32(OPERATIONAL_CLOSE_CODE)
    )
}

/// One dial of the fast schedule: when to start it and how long its dial may
/// run before it is abandoned for the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationalAttempt {
    /// When the attempt starts.
    pub start_at: Instant,
    /// How long the dial (the handshake, never the setup that follows it)
    /// may run before it is abandoned.
    pub dial_bound: Duration,
}

/// The bounded fast schedule a client redials on after a healthy session was
/// closed with [`OPERATIONAL_CLOSE_CODE`]: an attempt at once, then one every
/// [`OPERATIONAL_REDIAL_CADENCE`], each abandoned after its dial bound, until
/// [`OPERATIONAL_REDIAL_WINDOW`] after the close. The ordinary schedule
/// ([`REDIAL_BACKOFF`]) resumes when it is spent.
///
/// Every client of a server learns of its stop at the same moment, so the
/// slots after the first are shifted by a random phase under one cadence:
/// the clients reach the successor spread over a cadence instead of in one
/// burst, and each is still back within a cadence of it listening.
#[derive(Debug, Clone)]
pub struct OperationalRedial {
    closed_at: Instant,
    dial_bound: Duration,
    phase: Duration,
    next_slot: u32,
}

impl OperationalRedial {
    /// The fast schedule after a session that lived `uptime` and ended with
    /// `close` at `closed_at`, or `None` when the ordinary schedule applies:
    /// any close other than the operational one, and a session shorter than
    /// [`MIN_HEALTHY_UPTIME`], so a peer that closes every session with the
    /// operational code right after admitting it is not answered in bursts.
    /// `path_rtt` is the closed session's smoothed round trip, which sizes
    /// each attempt's dial bound. `carrier_head_start` is `Some` with the
    /// fallback race delay when the session rode the TLS-over-TCP carrier,
    /// whose dial only starts once the UDP handshake has had that long.
    #[must_use]
    pub fn after_session(
        uptime: Duration,
        close: &quinn::ConnectionError,
        closed_at: Instant,
        path_rtt: Duration,
        carrier_head_start: Option<Duration>,
    ) -> Option<Self> {
        if !is_healthy_uptime(uptime) || !is_operational_close(close) {
            return None;
        }
        let (round_trips, head_start) = match carrier_head_start {
            Some(head_start) => (OPERATIONAL_CARRIER_ATTEMPT_ROUND_TRIPS, head_start),
            None => (OPERATIONAL_ATTEMPT_ROUND_TRIPS, Duration::ZERO),
        };
        let dial_bound = OPERATIONAL_REDIAL_CADENCE
            .max(path_rtt.saturating_mul(round_trips))
            .saturating_add(head_start);
        Some(Self {
            closed_at,
            dial_bound,
            phase: OPERATIONAL_REDIAL_CADENCE.mul_f64(rand::random::<f64>()),
            next_slot: 0,
        })
    }

    /// Offset from the close of slot `slot`: the first at once, the others on
    /// the cadence after the phase.
    fn slot_offset(&self, slot: u32) -> Duration {
        if slot == 0 {
            return Duration::ZERO;
        }
        OPERATIONAL_REDIAL_CADENCE
            .saturating_mul(slot)
            .saturating_add(self.phase)
    }

    /// The next attempt, given that the previous one ended at `now`: at the
    /// next slot, or at once when the previous attempt overran it. `None`
    /// once the window is spent, and from then on.
    pub fn next_attempt(&mut self, now: Instant) -> Option<OperationalAttempt> {
        let offset = self
            .slot_offset(self.next_slot)
            .max(now.saturating_duration_since(self.closed_at));
        if offset >= OPERATIONAL_REDIAL_WINDOW {
            self.next_slot = u32::MAX;
            return None;
        }
        let since_first_slot = offset.saturating_sub(self.phase).as_nanos();
        self.next_slot = u32::try_from(since_first_slot / OPERATIONAL_REDIAL_CADENCE.as_nanos())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        Some(OperationalAttempt {
            start_at: self.closed_at + offset,
            dial_bound: self.dial_bound,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_the_shared_handshake_preset() {
        // Vector-style anchor: the redial schedule is the HANDSHAKE preset,
        // literal values pinned so a silent repoint (or a preset retune that
        // should be a deliberate policy change) fails here.
        assert_eq!(
            REDIAL_BACKOFF.base,
            Duration::from_millis(500),
            "client redial base must be the shared HANDSHAKE preset's 500 ms"
        );
        assert_eq!(
            REDIAL_BACKOFF.max,
            Duration::from_secs(15),
            "client redial ceiling must be the shared HANDSHAKE preset's 15 s"
        );
    }

    #[test]
    fn the_healthy_verdict_starts_at_the_minimum_uptime() {
        assert!(
            is_healthy_uptime(MIN_HEALTHY_UPTIME),
            "a session that lasted exactly the minimum uptime is healthy"
        );
        assert!(
            !is_healthy_uptime(MIN_HEALTHY_UPTIME - Duration::from_millis(1)),
            "a session that died a millisecond sooner is a flap"
        );
    }

    #[test]
    fn healthy_session_resets_the_schedule_and_redials_immediately() {
        let mut b = REDIAL_BACKOFF.forever();
        let _ = b.next_delay();
        let _ = b.next_delay();
        assert_eq!(
            delay_after_session(MIN_HEALTHY_UPTIME, &mut b),
            Duration::ZERO,
            "a healthy session's death must redial at once"
        );
        assert_eq!(
            b.next_delay(),
            Duration::ZERO,
            "the schedule must be reset so the first failed attempt retries immediately"
        );
    }

    #[test]
    fn flapping_session_keeps_escalating() {
        let mut b = REDIAL_BACKOFF.forever();
        let _ = b.next_delay();
        let d = delay_after_session(Duration::from_millis(200), &mut b);
        assert!(
            d > Duration::ZERO,
            "a flap must back off, never tight-loop full handshakes"
        );
        assert!(
            d <= REDIAL_BACKOFF.max,
            "no jittered delay may exceed the schedule ceiling"
        );
    }

    fn closed_by_peer(code: u32) -> quinn::ConnectionError {
        quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(code),
            reason: bytes::Bytes::new(),
        })
    }

    #[test]
    fn only_a_peer_close_with_the_operational_code_is_operational() {
        assert!(
            is_operational_close(&closed_by_peer(OPERATIONAL_CLOSE_CODE)),
            "a stopping exit closes its clients with code 0"
        );
        assert!(
            !is_operational_close(&closed_by_peer(1)),
            "any other application code is a refusal, never a restart"
        );
        assert!(
            !is_operational_close(&quinn::ConnectionError::LocallyClosed),
            "a close by this side says nothing about the peer coming back"
        );
        assert!(
            !is_operational_close(&quinn::ConnectionError::TimedOut),
            "a timeout is a dead path, not an announced restart"
        );
    }

    #[test]
    fn the_fast_schedule_follows_only_a_healthy_session_closed_with_the_operational_code() {
        let now = Instant::now();
        let rtt = Duration::from_millis(20);
        assert!(
            OperationalRedial::after_session(
                MIN_HEALTHY_UPTIME,
                &closed_by_peer(OPERATIONAL_CLOSE_CODE),
                now,
                rtt,
                None,
            )
            .is_some(),
            "a healthy session closed for a restart gets the fast schedule"
        );
        assert!(
            OperationalRedial::after_session(
                MIN_HEALTHY_UPTIME,
                &closed_by_peer(7),
                now,
                rtt,
                None,
            )
            .is_none(),
            "another close code keeps the ordinary schedule"
        );
        assert!(
            OperationalRedial::after_session(
                MIN_HEALTHY_UPTIME - Duration::from_millis(1),
                &closed_by_peer(OPERATIONAL_CLOSE_CODE),
                now,
                rtt,
                None,
            )
            .is_none(),
            "a peer closing every session right after admitting it is not answered in bursts"
        );
    }

    #[test]
    fn fast_attempts_start_on_the_cadence_from_the_close_until_the_window_is_spent() {
        let closed_at = Instant::now();
        let mut fast = OperationalRedial::after_session(
            MIN_HEALTHY_UPTIME,
            &closed_by_peer(OPERATIONAL_CLOSE_CODE),
            closed_at,
            Duration::from_millis(1),
            None,
        )
        .expect("an operational close");
        let first = fast.next_attempt(closed_at).expect("a first attempt");
        assert_eq!(first.start_at, closed_at, "the first redial is immediate");
        let second = fast
            .next_attempt(closed_at + Duration::from_millis(2))
            .expect("a second attempt")
            .start_at;
        assert!(
            second >= closed_at + OPERATIONAL_REDIAL_CADENCE
                && second < closed_at + OPERATIONAL_REDIAL_CADENCE * 2,
            "an attempt refused at once is followed within the next cadence, phase included"
        );
        let third = fast
            .next_attempt(second + Duration::from_millis(2))
            .expect("a third attempt")
            .start_at;
        assert_eq!(
            third,
            second + OPERATIONAL_REDIAL_CADENCE,
            "the slots after the first are one cadence apart"
        );
        let overran = third + OPERATIONAL_REDIAL_CADENCE + Duration::from_millis(40);
        assert_eq!(
            fast.next_attempt(overran)
                .expect("a fourth attempt")
                .start_at,
            overran,
            "an attempt that overran its slot is followed at once"
        );
        let mut starts = 4;
        let mut last = overran;
        while let Some(attempt) = fast.next_attempt(last) {
            starts += 1;
            last = attempt.start_at;
        }
        assert_eq!(
            starts, 20,
            "an attempt at once, then one per cadence until the window ends"
        );
        assert!(
            last < closed_at + OPERATIONAL_REDIAL_WINDOW
                && last >= closed_at + OPERATIONAL_REDIAL_WINDOW - OPERATIONAL_REDIAL_CADENCE,
            "the last attempt starts in the window's last cadence"
        );
        assert!(
            fast.next_attempt(closed_at).is_none(),
            "a spent window stays spent"
        );
    }

    #[test]
    fn a_fast_dial_is_given_the_cadence_or_its_round_trips_plus_the_carrier_head_start() {
        let fast = |rtt: Duration, carrier_head_start: Option<Duration>| {
            OperationalRedial::after_session(
                MIN_HEALTHY_UPTIME,
                &closed_by_peer(OPERATIONAL_CLOSE_CODE),
                Instant::now(),
                rtt,
                carrier_head_start,
            )
            .expect("an operational close")
            .next_attempt(Instant::now())
            .expect("a first attempt")
            .dial_bound
        };
        assert_eq!(
            fast(Duration::from_millis(5), None),
            OPERATIONAL_REDIAL_CADENCE,
            "a near server is dialled on the cadence"
        );
        assert_eq!(
            fast(Duration::from_millis(250), None),
            Duration::from_millis(1000),
            "a far server that is up must have time to finish its handshake"
        );
        assert_eq!(
            fast(Duration::from_millis(100), Some(Duration::from_millis(400))),
            Duration::from_millis(1000),
            "a session that rode the carrier must reach the carrier dial and its handshakes"
        );
    }
}
