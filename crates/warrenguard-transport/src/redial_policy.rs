//! Single home of the client redial (reconnect) schedule.
//!
//! Every client tier that rebuilds a dead tunnel (the engine multi-hop
//! supervisor's cold dial, the SDK userland proxy supervisor, any future
//! client loop) draws its schedule from here: the shared
//! [`Backoff::HANDSHAKE`] preset plus the healthy-vs-flapping session
//! verdict. Clients keep their own loop plumbing (watch channels, listeners,
//! netstack epochs); the schedule values and the flap rule live here only,
//! so they cannot drift apart again.

use std::time::Duration;

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

/// Applies the post-session verdict to `backoff` and returns the delay to
/// wait before the next redial: a healthy uptime resets the schedule and
/// redials immediately; a flap draws the next escalating delay.
#[must_use]
pub fn delay_after_session(uptime: Duration, backoff: &mut JitterBackoff) -> Duration {
    if uptime >= MIN_HEALTHY_UPTIME {
        backoff.reset();
        Duration::ZERO
    } else {
        backoff.next_delay()
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
}
