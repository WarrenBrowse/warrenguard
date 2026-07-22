//! Goodput-aware path-health detection for the multi-hop client.
//!
//! The three dead-path watches in [`crate::supervisor`] catch a fully
//! dead tunnel (RX silence, one-way app traffic, unacked uplink) but are
//! structurally blind to the degradation class where a TRICKLE keeps
//! every counter advancing while bulk traffic is dead: a last-mile
//! brownout that drops large frames, an in-path queue collapse, or a
//! middlebox that starves everything above keep-alive size. A user
//! experiences "no internet" for minutes while the tunnel looks
//! Connected and no watchdog fires.
//!
//! This module closes that gap with an ACTIVE measurement: paired
//! ICMPv4 echo probes (one minimum-size, one at the live inner budget)
//! sent from the session's assigned tunnel IP to the tunnel gateway,
//! whose kernel echoes them back through the full downlink datapath.
//! Large probe dead while the small one survives = size-selective
//! blackhole; both dead while transport ACKs still flow = wedged
//! datapath. Either way the prober requests ONE make-before-break
//! overlap migration per episode (it fixes session-state wedges and is
//! gap-free), then publishes the degraded verdict on a watch channel so
//! an embedder can tell the user the PATH is sick instead of looking
//! healthy-but-dead.
//!
//! Complementary to [`crate::egress_probe`], which asks the gateway
//! resolver a SMALL DNS question and therefore keeps reporting a
//! healthy egress across exactly this class (the 2026-07-22 last-mile
//! brownout passed every small packet while bulk was dead for 4
//! minutes); the paired sizes here are the point.
//!
//! No-log discipline: probes carry an all-zero payload between
//! tunnel-internal addresses; the transitions are logged with aggregate
//! loss counts only.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, mpsc, watch};
use warrenguard_transport_core::icmp_probe::{build_echo_request, parse_echo_reply};

/// Published health verdict of the tunnel datapath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathHealth {
    /// Paired probes deliver at both size classes.
    #[default]
    Healthy,
    /// Large probes are (almost) all lost while small probes survive:
    /// a size-selective blackhole between the client and the exit
    /// gateway (brownout radio, shrunk-path middlebox, queue shedding
    /// large frames). Bulk TCP/QUIC is dead for the user.
    DegradedLarge,
    /// Both probe sizes are (almost) all lost while the session itself
    /// stays up: a wedged datapath (the "QUIC alive, egress dead"
    /// class).
    DegradedBoth,
}

/// Transition events surfaced by [`HealthTracker::record_pair`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthEvent {
    /// The tracker entered (or re-classified into) a degraded state.
    Entered(PathHealth),
    /// The tracker returned to [`PathHealth::Healthy`].
    Recovered,
    /// First degradation of an episode: the caller should request ONE
    /// gap-free overlap migration (it cures session-state wedges; it is
    /// harmless when the underlay itself is sick).
    RequestMigration,
}

/// Probe outcomes evaluated per paired round.
const WINDOW: usize = 5;
/// Losses within [`WINDOW`] at which a size class counts as dead.
const DEGRADE_MIN_LOST: usize = 4;
/// Small-probe losses within [`WINDOW`] still compatible with the
/// "small survives" half of [`PathHealth::DegradedLarge`].
const SMALL_SURVIVES_MAX_LOST: usize = 1;
/// Consecutive fully-clean pairs required to declare recovery.
const RECOVER_STREAK: usize = 3;

/// Fixed-size ring of the last [`WINDOW`] boolean outcomes.
#[derive(Debug, Default, Clone)]
struct OutcomeRing {
    slots: [bool; WINDOW],
    len: usize,
    next: usize,
}

impl OutcomeRing {
    fn push(&mut self, ok: bool) {
        self.slots[self.next] = ok;
        self.next = (self.next + 1) % WINDOW;
        self.len = (self.len + 1).min(WINDOW);
    }

    fn full(&self) -> bool {
        self.len == WINDOW
    }

    fn lost(&self) -> usize {
        self.slots[..self.len].iter().filter(|ok| !**ok).count()
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Pure state machine behind the prober: feed one paired-probe outcome
/// per round, get the transitions to act on. No clocks, no I/O, so the
/// detection policy is exhaustively unit-testable.
#[derive(Debug, Default)]
pub struct HealthTracker {
    small: OutcomeRing,
    large: OutcomeRing,
    state: PathHealth,
    recover_streak: usize,
    migration_requested: bool,
}

impl HealthTracker {
    /// Current verdict.
    #[must_use]
    pub fn state(&self) -> PathHealth {
        self.state
    }

    /// `true` while the prober should probe at the burst cadence
    /// (degradation suspected or confirmed) instead of the steady one.
    #[must_use]
    pub fn wants_fast(&self) -> bool {
        if self.state != PathHealth::Healthy {
            return true;
        }
        // A fresh large loss escalates immediately so a real blackhole
        // is confirmed within ~WINDOW * FAST_CADENCE instead of minutes.
        self.large.len > 0 && !self.large.slots[(self.large.next + WINDOW - 1) % WINDOW]
    }

    /// Records one paired-probe round and returns the transitions it
    /// produced (empty on no change).
    pub fn record_pair(&mut self, small_ok: bool, large_ok: bool) -> Vec<HealthEvent> {
        self.small.push(small_ok);
        self.large.push(large_ok);
        let mut events = Vec::new();

        if self.state != PathHealth::Healthy {
            if small_ok && large_ok {
                self.recover_streak += 1;
                if self.recover_streak >= RECOVER_STREAK {
                    self.state = PathHealth::Healthy;
                    self.recover_streak = 0;
                    self.migration_requested = false;
                    self.small.clear();
                    self.large.clear();
                    events.push(HealthEvent::Recovered);
                    return events;
                }
            } else {
                self.recover_streak = 0;
            }
        }

        let Some(verdict) = self.classify() else {
            return events;
        };
        if verdict != self.state {
            self.state = verdict;
            self.recover_streak = 0;
            events.push(HealthEvent::Entered(verdict));
            if !self.migration_requested {
                self.migration_requested = true;
                events.push(HealthEvent::RequestMigration);
            }
        }
        events
    }

    /// Degraded classification over the full window, `None` while the
    /// window has too few samples or the losses stay below the bar.
    fn classify(&self) -> Option<PathHealth> {
        if !self.large.full() {
            return None;
        }
        if self.large.lost() < DEGRADE_MIN_LOST {
            return None;
        }
        if self.small.lost() <= SMALL_SURVIVES_MAX_LOST {
            Some(PathHealth::DegradedLarge)
        } else {
            Some(PathHealth::DegradedBoth)
        }
    }
}

/// Shared reply intercept between the prober and the downlink pumps.
///
/// The pumps call [`Self::try_intercept`] on every decoded downlink
/// packet; a matching echo reply is consumed (never written to the TUN)
/// and its sequence number handed to the prober. The id is random per
/// supervisor so replies of a previous process instance never alias.
#[derive(Debug)]
pub struct ProbeTap {
    id: u16,
    tx: mpsc::UnboundedSender<u16>,
}

impl ProbeTap {
    /// Creates the tap plus the reply stream consumed by the prober.
    #[must_use]
    pub fn new(id: u16) -> (Arc<Self>, mpsc::UnboundedReceiver<u16>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Arc::new(Self { id, tx }), rx)
    }

    /// Probe id carried by every echo this tap owns.
    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Consumes `pkt` when it is an echo reply of this tap; `true`
    /// means the caller must NOT forward the packet to the TUN.
    #[must_use]
    pub fn try_intercept(&self, pkt: &[u8]) -> bool {
        match parse_echo_reply(pkt, self.id) {
            Some((seq, _len)) => {
                let _ = self.tx.send(seq);
                true
            }
            None => false,
        }
    }
}

/// Prober state OWNED BY THE SUPERVISOR and shared across the
/// per-session prober tasks it spawns: the tracker (episode memory
/// survives an overlap swap, so a persistent degradation does not
/// re-request a migration after every swap), the reply stream, and the
/// latest assigned endpoints. The prober task itself is per-bundle
/// (spawned on publish, exits with the bundle) because holding a
/// supervisor watch receiver here would block the supervisor's
/// no-receivers shutdown.
pub struct ProberShared {
    tracker: parking_lot::Mutex<HealthTracker>,
    replies: tokio::sync::Mutex<mpsc::UnboundedReceiver<u16>>,
    tap: Arc<ProbeTap>,
    endpoints: parking_lot::Mutex<Option<(Ipv4Addr, Ipv4Addr)>>,
    health_tx: watch::Sender<PathHealth>,
    seq: std::sync::atomic::AtomicU16,
}

impl ProberShared {
    /// Builds the shared prober state around a fresh tap.
    #[must_use]
    pub fn new(probe_id: u16) -> Arc<Self> {
        let (tap, replies) = ProbeTap::new(probe_id);
        let (health_tx, _) = watch::channel(PathHealth::Healthy);
        Arc::new(Self {
            tracker: parking_lot::Mutex::new(HealthTracker::default()),
            replies: tokio::sync::Mutex::new(replies),
            tap,
            endpoints: parking_lot::Mutex::new(None),
            health_tx,
            seq: std::sync::atomic::AtomicU16::new(0),
        })
    }

    /// The tap the supervisor installs on every bundle it publishes.
    #[must_use]
    pub fn tap(&self) -> Arc<ProbeTap> {
        self.tap.clone()
    }

    /// Publishes the session's `(assigned v4, gateway v4)`; called by
    /// the supervisor on every IP assignment.
    pub fn set_endpoints(&self, assigned: Ipv4Addr, gateway: Ipv4Addr) {
        *self.endpoints.lock() = Some((assigned, gateway));
    }

    /// Verdict watch for embedders (UI surfacing, tests).
    #[must_use]
    pub fn health_watch(&self) -> watch::Receiver<PathHealth> {
        self.health_tx.subscribe()
    }
}

/// Steady cadence between paired probes (env `WARREN_PATH_HEALTH_SECS`).
fn steady_cadence() -> Option<Duration> {
    match warrenguard_config::knobs::path_health_secs() {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    }
}

/// Burst cadence while a degradation is suspected or confirmed.
const FAST_CADENCE: Duration = Duration::from_secs(2);
/// How long a probe pair may take before its missing replies count as
/// lost. Covers RTT spikes by two orders of magnitude over a healthy
/// path.
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);
/// Total IP length of the small probe (the classic 56-byte ping).
const SMALL_PROBE_LEN: usize = 84;

/// Spawns the prober for one published bundle. The task holds only a
/// `Weak` on the bundle (a strong reference here would keep the session
/// alive past the supervisor's teardown) and exits when the bundle dies
/// or is dropped; the supervisor spawns a fresh prober on the next
/// publish. A no-op task when `WARREN_PATH_HEALTH_SECS=0`.
pub fn spawn_path_health(
    bundle: std::sync::Weak<crate::bundle::MultiHopBundle>,
    shared: Arc<ProberShared>,
    overlap: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(steady) = steady_cadence() else {
            return;
        };
        loop {
            let Some(strong) = bundle.upgrade() else {
                return;
            };
            let done = tokio::select! {
                _ = strong.closed() => true,
                () = probe_round(&strong, &shared, &overlap, steady) => false,
            };
            drop(strong);
            if done {
                return;
            }
        }
    })
}

/// One paced probe round against a live bundle: sleep the cadence, send
/// the pair, collect replies, feed the tracker, act on transitions.
async fn probe_round(
    bundle: &Arc<crate::bundle::MultiHopBundle>,
    shared: &Arc<ProberShared>,
    overlap: &Arc<Notify>,
    steady: Duration,
) {
    {
        // Single round; the caller's loop re-upgrades the bundle
        // between rounds so this task never pins the session alive.
        let cadence = if shared.tracker.lock().wants_fast() {
            FAST_CADENCE
        } else {
            steady
        };
        tokio::time::sleep(cadence).await;
        let Some((src, gw)) = *shared.endpoints.lock() else {
            return;
        };

        let small_seq = shared
            .seq
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        let large_seq = small_seq.wrapping_add(1);
        let large_len = bundle.max_inner_payload().max(SMALL_PROBE_LEN);
        let small = build_echo_request(src, gw, shared.tap.id(), small_seq, SMALL_PROBE_LEN);
        let large = build_echo_request(src, gw, shared.tap.id(), large_seq, large_len);
        let (Some(small), Some(large)) = (small, large) else {
            return;
        };

        let (small_ok, large_ok) = {
            let mut replies = shared.replies.lock().await;
            // Stale replies of older rounds must not credit this one.
            while replies.try_recv().is_ok() {}
            if bundle.send_probe(&small).await.is_err() || bundle.send_probe(&large).await.is_err()
            {
                // Dying connection: the supervisor is already on it; a
                // send failure is not path evidence.
                return;
            }
            let mut small_ok = false;
            let mut large_ok = false;
            let deadline = tokio::time::Instant::now() + REPLY_TIMEOUT;
            while !(small_ok && large_ok) {
                let reply = tokio::select! {
                    reply = replies.recv() => reply,
                    () = tokio::time::sleep_until(deadline) => break,
                };
                match reply {
                    Some(s) if s == small_seq => small_ok = true,
                    Some(s) if s == large_seq => large_ok = true,
                    Some(_) => {}
                    None => return,
                }
            }
            (small_ok, large_ok)
        };

        let (events, small_lost, large_lost) = {
            let mut tracker = shared.tracker.lock();
            let events = tracker.record_pair(small_ok, large_ok);
            (events, tracker.small.lost(), tracker.large.lost())
        };
        for event in events {
            match event {
                HealthEvent::Entered(kind) => {
                    tracing::warn!(
                        verdict = ?kind,
                        small_lost,
                        large_lost,
                        window = WINDOW,
                        "path health degraded: in-tunnel goodput probes failing \
                         (physical path or datapath wedge suspected)"
                    );
                    let _ = shared.health_tx.send(kind);
                }
                HealthEvent::Recovered => {
                    tracing::info!("path health recovered: goodput probes delivering again");
                    let _ = shared.health_tx.send(PathHealth::Healthy);
                }
                HealthEvent::RequestMigration => {
                    tracing::info!(
                        "path health: requesting one gap-free overlap migration for this episode"
                    );
                    overlap.notify_one();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warrenguard_transport_core::icmp_probe::build_echo_request;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 177);
    const GW: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

    fn reply_packet(id: u16, seq: u16, len: usize) -> Vec<u8> {
        // The gateway mirrors the request with type flipped to reply;
        // for the tap only the type/id/seq fields matter.
        let mut pkt = build_echo_request(GW, SRC, id, seq, len).expect("builds");
        pkt[20] = 0;
        pkt
    }

    #[test]
    fn healthy_stream_stays_healthy_and_slow() {
        let mut t = HealthTracker::default();
        for _ in 0..10 {
            assert!(t.record_pair(true, true).is_empty());
        }
        assert_eq!(t.state(), PathHealth::Healthy);
        assert!(!t.wants_fast());
    }

    #[test]
    fn one_lost_large_is_noise_but_escalates_cadence() {
        let mut t = HealthTracker::default();
        for _ in 0..4 {
            assert!(t.record_pair(true, true).is_empty());
        }
        assert!(t.record_pair(true, false).is_empty());
        assert!(t.wants_fast(), "a fresh large loss must probe faster");
        for _ in 0..4 {
            assert!(t.record_pair(true, true).is_empty());
        }
        assert_eq!(t.state(), PathHealth::Healthy);
        assert!(!t.wants_fast(), "clean again: back to steady cadence");
    }

    #[test]
    fn large_blackhole_enters_degraded_large_with_one_migration() {
        let mut t = HealthTracker::default();
        for _ in 0..4 {
            assert!(t.record_pair(true, false).is_empty(), "window not full yet");
        }
        let events = t.record_pair(true, false);
        assert_eq!(
            events,
            vec![
                HealthEvent::Entered(PathHealth::DegradedLarge),
                HealthEvent::RequestMigration
            ]
        );
        assert_eq!(t.state(), PathHealth::DegradedLarge);
        assert!(t.wants_fast());
        // Staying degraded emits nothing new, and never a second
        // migration for the same episode.
        assert!(t.record_pair(true, false).is_empty());
    }

    #[test]
    fn total_blackhole_enters_degraded_both() {
        let mut t = HealthTracker::default();
        for _ in 0..4 {
            assert!(t.record_pair(false, false).is_empty());
        }
        let events = t.record_pair(false, false);
        assert_eq!(
            events,
            vec![
                HealthEvent::Entered(PathHealth::DegradedBoth),
                HealthEvent::RequestMigration
            ]
        );
    }

    #[test]
    fn large_degradation_reclassifies_to_both_without_second_migration() {
        let mut t = HealthTracker::default();
        for _ in 0..5 {
            t.record_pair(true, false);
        }
        assert_eq!(t.state(), PathHealth::DegradedLarge);
        // Small probes start dying too.
        let mut saw_both = false;
        for _ in 0..5 {
            for e in t.record_pair(false, false) {
                assert_ne!(
                    e,
                    HealthEvent::RequestMigration,
                    "one migration per episode"
                );
                if e == HealthEvent::Entered(PathHealth::DegradedBoth) {
                    saw_both = true;
                }
            }
        }
        assert!(saw_both);
        assert_eq!(t.state(), PathHealth::DegradedBoth);
    }

    #[test]
    fn recovery_needs_three_clean_pairs_then_new_episode_can_migrate_again() {
        let mut t = HealthTracker::default();
        for _ in 0..5 {
            t.record_pair(true, false);
        }
        assert_eq!(t.state(), PathHealth::DegradedLarge);
        assert!(t.record_pair(true, true).is_empty());
        assert!(t.record_pair(true, true).is_empty());
        assert_eq!(t.record_pair(true, true), vec![HealthEvent::Recovered]);
        assert_eq!(t.state(), PathHealth::Healthy);
        assert!(!t.wants_fast());
        // A relapse is a NEW episode: it may request migration again.
        for _ in 0..4 {
            assert!(t.record_pair(true, false).is_empty());
        }
        assert!(
            t.record_pair(true, false)
                .contains(&HealthEvent::RequestMigration)
        );
    }

    #[test]
    fn interrupted_recovery_streak_stays_degraded() {
        let mut t = HealthTracker::default();
        for _ in 0..5 {
            t.record_pair(true, false);
        }
        t.record_pair(true, true);
        t.record_pair(true, true);
        assert!(t.record_pair(true, false).is_empty(), "streak broken");
        assert_eq!(t.state(), PathHealth::DegradedLarge);
    }

    #[test]
    fn tap_intercepts_own_reply_and_feeds_seq() {
        let (tap, mut rx) = ProbeTap::new(0xC0DE);
        let reply = reply_packet(0xC0DE, 9, 84);
        assert!(tap.try_intercept(&reply));
        assert_eq!(rx.try_recv().ok(), Some(9));
    }

    #[test]
    fn tap_ignores_foreign_and_non_probe_packets() {
        let (tap, mut rx) = ProbeTap::new(0xC0DE);
        assert!(
            !tap.try_intercept(&reply_packet(0xBEEF, 9, 84)),
            "foreign id"
        );
        let mut tcp = reply_packet(0xC0DE, 9, 84);
        tcp[9] = 6;
        assert!(!tap.try_intercept(&tcp), "not icmp");
        let request = build_echo_request(SRC, GW, 0xC0DE, 9, 84).expect("builds");
        assert!(!tap.try_intercept(&request), "request, not reply");
        assert!(rx.try_recv().is_err(), "nothing was fed");
    }
}
