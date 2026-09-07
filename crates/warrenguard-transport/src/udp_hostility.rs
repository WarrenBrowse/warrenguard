//! Process-wide memory behind the carrier-first dial.
//!
//! The pure logic is [`UdpHostilityTracker`] in `warrenguard-tcp-fallback`.
//! This module owns the one instance a client process needs: the supervisor
//! records how each session ended, and every relay dial asks which transport to
//! try first. It is public so a deployer with its own supervisor and dial (the
//! userland SDK datapath) feeds and reads the SAME memory as the engine's
//! supervisor in the same process. It is process-wide on purpose. A client app tears its supervisor
//! down and builds a new one on every reconnect, and the pattern this exists to
//! catch (a censor that passes the QUIC handshake and kills the flow seconds
//! later) only shows across several of those sessions.
//!
//! Nothing here logs an address or an identity: the tracker sees durations and
//! booleans only.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use warrenguard_tcp_fallback::{Carrier, DialPreference, SessionEnd, UdpHostilityTracker};

static TRACKER: Mutex<UdpHostilityTracker> = Mutex::new(UdpHostilityTracker::new());

fn with_tracker<R>(f: impl FnOnce(&mut UdpHostilityTracker, Instant) -> R) -> R {
    let mut tracker = TRACKER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut tracker, Instant::now())
}

/// Record a closed session: which socket carried it, how long it lived after
/// establishment, and whether a dead-path watch forced the close. Logs the
/// verdict only when it changes, so a stable network stays silent.
pub fn record_session_end(over_carrier: bool, lifetime: Duration, watchdog_forced: bool) {
    let carrier = if over_carrier {
        Carrier::Tcp
    } else {
        Carrier::Udp
    };
    let (before, after) = with_tracker(|tracker, now| {
        let before = tracker.preference(now);
        tracker.record_session_end(
            SessionEnd {
                carrier,
                lifetime,
                watchdog_forced,
            },
            now,
        );
        (before, tracker.preference(now))
    });
    if before != after {
        tracing::info!(
            ?after,
            lifetime_secs = lifetime.as_secs(),
            watchdog_forced,
            over_carrier,
            "dial preference changed: sessions die shortly after the handshake"
        );
    }
}

/// A carrier-first dial that did not produce a session.
pub fn record_carrier_dial_failed() {
    with_tracker(|tracker, now| tracker.record_carrier_dial_failed(now));
}

/// A carrier-first dial that produced a live session.
pub fn record_carrier_dial_succeeded() {
    with_tracker(|tracker, _now| tracker.record_carrier_dial_succeeded());
}

/// Which transport the next relay dial tries first. The deployer's
/// `WARREN_TCP_FALLBACK_PREFER` knob forces carrier-first regardless of what
/// the tracker has seen (a UDP-hostile network known in advance, or a real
/// network validation of the carrier path).
#[must_use]
pub fn preference() -> DialPreference {
    #[cfg(test)]
    if let Some(forced) = tests::forced_preference() {
        return forced;
    }
    if warrenguard_config::knobs::tcp_fallback_prefer() {
        return DialPreference::CarrierFirst;
    }
    with_tracker(|tracker, now| tracker.preference(now))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::Cell;

    use super::*;

    // Thread-local so a test that forces the verdict cannot leak it into
    // another test running in parallel; production never reads it.
    thread_local! {
        static FORCED: Cell<Option<DialPreference>> = const { Cell::new(None) };
    }

    pub(crate) fn forced_preference() -> Option<DialPreference> {
        FORCED.with(Cell::get)
    }

    pub(crate) fn force_preference(preference: Option<DialPreference>) {
        FORCED.with(|f| f.set(preference));
    }

    #[test]
    fn the_forced_verdict_wins_over_the_tracker() {
        force_preference(Some(DialPreference::CarrierFirst));
        assert_eq!(preference(), DialPreference::CarrierFirst);
        force_preference(None);
    }
}
