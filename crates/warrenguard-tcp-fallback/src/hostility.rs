//! UDP-hostility memory: when to dial the TCP carrier FIRST.
//!
//! [`connect_with_fallback`](crate::connect_with_fallback) races the carrier
//! against the UDP HANDSHAKE, so a network that lets the handshake through and
//! kills the flow a few seconds later never triggers it: every redial completes
//! the UDP handshake in under the race delay, the session dies again on the
//! dead-path watch, and the carrier is never dialled. Observed live on a Russian
//! mobile operator on 2026-09-07: ten UDP sessions in 1 h 45, each dead at 18 to
//! 32 s, and not one TCP dial.
//!
//! This tracker turns that pattern into a dial preference. A UDP session that a
//! dead-path watch had to kill inside [`POST_HANDSHAKE_KILL_WINDOW`] of its
//! establishment is one post-handshake kill; [`KILLS_BEFORE_CARRIER_FIRST`] of
//! them in a row arm carrier-first dialling for [`CARRIER_FIRST_TTL`]. A UDP
//! session that outlives the window proves the network sane and clears the
//! streak. A carrier that itself keeps failing enters a cooldown so a network
//! hostile to both never pays an extra TCP dial on every redial.
//!
//! Pure logic with an injected clock; the deployer owns the instance. One per
//! process is the natural scope: the memory must outlive a single supervisor
//! run, since a client app rebuilds its supervisor on every reconnect.

use std::time::{Duration, Instant};

/// A session killed by a dead-path watch within this long of its establishment
/// is a post-handshake kill, the signature of a censor that passes the handshake
/// and drops the flow. A session that lives longer proves the UDP path usable.
pub const POST_HANDSHAKE_KILL_WINDOW: Duration = Duration::from_secs(60);

/// Consecutive post-handshake kills over UDP before the next dial tries the
/// carrier first. Two, so one unlucky radio drop never flips the transport.
pub const KILLS_BEFORE_CARRIER_FIRST: u32 = 2;

/// How long carrier-first stays armed after it was earned. Once it lapses the
/// UDP race gets one more chance; a single further kill re-arms it, since the
/// streak is kept.
pub const CARRIER_FIRST_TTL: Duration = Duration::from_secs(15 * 60);

/// Consecutive carrier dial failures (or carrier sessions killed young) before
/// carrier-first is suspended for [`CARRIER_COOLDOWN`].
pub const CARRIER_FAILURES_BEFORE_COOLDOWN: u32 = 3;

/// Suspension of carrier-first after the carrier proved dead too.
pub const CARRIER_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// Which socket carried a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// The native UDP QUIC dial.
    Udp,
    /// The TLS-over-TCP carrier.
    Tcp,
}

/// How one session ended, as the supervisor observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionEnd {
    /// The socket the session ran on.
    pub carrier: Carrier,
    /// Time from establishment (handshake done, session published) to close.
    pub lifetime: Duration,
    /// `true` when a dead-path watch (RX silence, one-way app traffic, uplink
    /// loss) forced the close. A clean close, a rejection or a teardown is
    /// `false` and says nothing about the network.
    pub watchdog_forced: bool,
}

/// The dial-time verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialPreference {
    /// Race as usual: UDP first, the carrier only if the handshake stalls.
    Race,
    /// Dial the TCP carrier first; fall back to the race if it fails.
    CarrierFirst,
}

/// The memory behind [`DialPreference`]. See the module docs.
#[derive(Debug, Default)]
pub struct UdpHostilityTracker {
    young_udp_kills: u32,
    carrier_first_until: Option<Instant>,
    carrier_failures: u32,
    cooldown_until: Option<Instant>,
}

impl UdpHostilityTracker {
    /// A tracker that has seen nothing: it races, like [`Default`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            young_udp_kills: 0,
            carrier_first_until: None,
            carrier_failures: 0,
            cooldown_until: None,
        }
    }

    /// Record how a session ended. `now` is the close instant.
    pub fn record_session_end(&mut self, end: SessionEnd, now: Instant) {
        let young = end.lifetime < POST_HANDSHAKE_KILL_WINDOW;
        match end.carrier {
            Carrier::Udp => {
                if !young {
                    self.young_udp_kills = 0;
                    self.carrier_first_until = None;
                } else if end.watchdog_forced {
                    self.young_udp_kills = self.young_udp_kills.saturating_add(1);
                    if self.young_udp_kills >= KILLS_BEFORE_CARRIER_FIRST {
                        self.carrier_first_until = Some(now + CARRIER_FIRST_TTL);
                    }
                }
            }
            Carrier::Tcp => {
                if !young {
                    self.carrier_failures = 0;
                    if self.carrier_first_until.is_some() {
                        self.carrier_first_until = Some(now + CARRIER_FIRST_TTL);
                    }
                } else if end.watchdog_forced {
                    self.note_carrier_failure(now);
                }
            }
        }
    }

    /// Record a setup round-trip that timed out on a connection whose handshake
    /// had already completed.
    ///
    /// One is enough to arm carrier-first, where a session death needs
    /// [`KILLS_BEFORE_CARRIER_FIRST`]: that threshold exists so a single radio
    /// drop cannot flip the transport, and this is not a radio drop. The setup
    /// request rides a reliable stream that retransmits, on a connection the
    /// peer has just answered, so seconds of total silence in that window means
    /// the flow was cut rather than a packet lost. Observed on a Russian mobile
    /// operator on 2026-09-10: 60 dials in 51 minutes, every one abandoned with
    /// no `IpAssign`, while HTTPS to the same operator's uplink kept working.
    pub fn record_setup_timeout(&mut self, carrier: Carrier, now: Instant) {
        match carrier {
            Carrier::Udp => {
                self.young_udp_kills = self.young_udp_kills.saturating_add(1);
                self.carrier_first_until = Some(now + CARRIER_FIRST_TTL);
            }
            Carrier::Tcp => self.note_carrier_failure(now),
        }
    }

    /// Record a carrier-first dial that failed (TCP connect, cover TLS or the
    /// inner QUIC handshake). The caller then runs the ordinary race.
    pub fn record_carrier_dial_failed(&mut self, now: Instant) {
        self.note_carrier_failure(now);
    }

    /// Record a carrier-first dial that produced a live session.
    pub fn record_carrier_dial_succeeded(&mut self) {
        self.carrier_failures = 0;
    }

    /// The verdict for the next dial at `now`.
    #[must_use]
    pub fn preference(&self, now: Instant) -> DialPreference {
        if self.cooldown_until.is_some_and(|until| now < until) {
            return DialPreference::Race;
        }
        if self.carrier_first_until.is_some_and(|until| now < until) {
            DialPreference::CarrierFirst
        } else {
            DialPreference::Race
        }
    }

    fn note_carrier_failure(&mut self, now: Instant) {
        self.carrier_failures = self.carrier_failures.saturating_add(1);
        if self.carrier_failures >= CARRIER_FAILURES_BEFORE_COOLDOWN {
            self.carrier_failures = 0;
            self.cooldown_until = Some(now + CARRIER_COOLDOWN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn young_udp_kill() -> SessionEnd {
        SessionEnd {
            carrier: Carrier::Udp,
            lifetime: Duration::from_secs(25),
            watchdog_forced: true,
        }
    }

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn a_fresh_tracker_races() {
        let tracker = UdpHostilityTracker::default();
        assert_eq!(tracker.preference(t0()), DialPreference::Race);
    }

    #[test]
    fn one_post_handshake_kill_is_tolerated() {
        let mut tracker = UdpHostilityTracker::default();
        tracker.record_session_end(young_udp_kill(), t0());
        assert_eq!(
            tracker.preference(t0()),
            DialPreference::Race,
            "a single radio drop must not flip the transport"
        );
    }

    #[test]
    fn two_consecutive_post_handshake_kills_arm_carrier_first() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(young_udp_kill(), now + Duration::from_secs(40));
        assert_eq!(
            tracker.preference(now + Duration::from_secs(41)),
            DialPreference::CarrierFirst
        );
    }

    #[test]
    fn a_udp_session_that_outlives_the_window_clears_the_streak() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(
            SessionEnd {
                carrier: Carrier::Udp,
                lifetime: POST_HANDSHAKE_KILL_WINDOW,
                watchdog_forced: true,
            },
            now,
        );
        tracker.record_session_end(young_udp_kill(), now);
        assert_eq!(
            tracker.preference(now),
            DialPreference::Race,
            "a healthy UDP session resets the count, so one more kill is not two in a row"
        );
    }

    #[test]
    fn a_long_udp_session_disarms_an_armed_preference() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(young_udp_kill(), now);
        assert_eq!(tracker.preference(now), DialPreference::CarrierFirst);
        tracker.record_session_end(
            SessionEnd {
                carrier: Carrier::Udp,
                lifetime: Duration::from_secs(600),
                watchdog_forced: false,
            },
            now,
        );
        assert_eq!(tracker.preference(now), DialPreference::Race);
    }

    #[test]
    fn a_short_clean_close_over_udp_says_nothing() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(
            SessionEnd {
                carrier: Carrier::Udp,
                lifetime: Duration::from_secs(3),
                watchdog_forced: false,
            },
            now,
        );
        tracker.record_session_end(young_udp_kill(), now);
        assert_eq!(
            tracker.preference(now),
            DialPreference::CarrierFirst,
            "an overlap swap or a teardown between two kills neither counts nor resets"
        );
    }

    #[test]
    fn carrier_first_lapses_after_its_ttl_and_one_more_kill_rearms_it() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(young_udp_kill(), now);
        let later = now + CARRIER_FIRST_TTL;
        assert_eq!(tracker.preference(later), DialPreference::Race);
        tracker.record_session_end(young_udp_kill(), later);
        assert_eq!(tracker.preference(later), DialPreference::CarrierFirst);
    }

    #[test]
    fn a_surviving_carrier_session_extends_the_preference() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(young_udp_kill(), now);
        let near_expiry = now + CARRIER_FIRST_TTL - Duration::from_secs(1);
        tracker.record_session_end(
            SessionEnd {
                carrier: Carrier::Tcp,
                lifetime: Duration::from_secs(900),
                watchdog_forced: false,
            },
            near_expiry,
        );
        assert_eq!(
            tracker.preference(now + CARRIER_FIRST_TTL + Duration::from_secs(60)),
            DialPreference::CarrierFirst,
            "a carrier that carries traffic keeps the preference alive"
        );
    }

    #[test]
    fn three_carrier_failures_suspend_carrier_first_for_the_cooldown() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_carrier_dial_failed(now);
        tracker.record_carrier_dial_failed(now);
        assert_eq!(tracker.preference(now), DialPreference::CarrierFirst);
        tracker.record_carrier_dial_failed(now);
        assert_eq!(
            tracker.preference(now),
            DialPreference::Race,
            "a carrier that is dead too must not cost a TCP dial on every redial"
        );
        assert_eq!(
            tracker.preference(now + CARRIER_COOLDOWN),
            DialPreference::CarrierFirst,
            "the cooldown lifts and the earned preference is still there"
        );
    }

    #[test]
    fn a_carrier_session_killed_young_counts_as_a_carrier_failure() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(young_udp_kill(), now);
        for _ in 0..CARRIER_FAILURES_BEFORE_COOLDOWN {
            tracker.record_session_end(
                SessionEnd {
                    carrier: Carrier::Tcp,
                    lifetime: Duration::from_secs(20),
                    watchdog_forced: true,
                },
                now,
            );
        }
        assert_eq!(tracker.preference(now), DialPreference::Race);
    }

    #[test]
    fn one_setup_timeout_over_udp_arms_carrier_first_on_its_own() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_setup_timeout(Carrier::Udp, now);
        assert_eq!(
            tracker.preference(now + Duration::from_secs(1)),
            DialPreference::CarrierFirst,
            "a handshake that completes and then answers nothing on its setup \
             stream is the censor signature, not an unlucky radio drop"
        );
    }

    #[test]
    fn a_udp_session_that_outlives_the_window_clears_a_setup_timeout_streak() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_setup_timeout(Carrier::Udp, now);
        tracker.record_session_end(
            SessionEnd {
                carrier: Carrier::Udp,
                lifetime: Duration::from_secs(120),
                watchdog_forced: true,
            },
            now + Duration::from_secs(200),
        );
        assert_eq!(
            tracker.preference(now + Duration::from_secs(201)),
            DialPreference::Race,
            "one healthy session proves the UDP path usable again"
        );
    }

    #[test]
    fn a_setup_timeout_over_the_carrier_counts_as_a_carrier_failure() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_setup_timeout(Carrier::Udp, now);
        for i in 0..CARRIER_FAILURES_BEFORE_COOLDOWN {
            tracker.record_setup_timeout(Carrier::Tcp, now + Duration::from_secs(u64::from(i)));
        }
        assert_eq!(
            tracker.preference(now + Duration::from_secs(10)),
            DialPreference::Race,
            "a network that swallows the setup over both transports must not \
             pay an extra TCP dial on every redial"
        );
    }

    #[test]
    fn a_successful_carrier_dial_resets_the_failure_count() {
        let mut tracker = UdpHostilityTracker::default();
        let now = t0();
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_session_end(young_udp_kill(), now);
        tracker.record_carrier_dial_failed(now);
        tracker.record_carrier_dial_failed(now);
        tracker.record_carrier_dial_succeeded();
        tracker.record_carrier_dial_failed(now);
        tracker.record_carrier_dial_failed(now);
        assert_eq!(
            tracker.preference(now),
            DialPreference::CarrierFirst,
            "two failures after a success are not three in a row"
        );
    }
}
