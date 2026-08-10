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
//! blackhole (last-mile shrink / brownout); both dead while transport
//! ACKs still flow = wedged datapath. Only the wedge (`DegradedBoth`)
//! requests an overlap migration, retried while it persists and capped
//! per episode: a fresh session can cure
//! a session-state wedge, whereas a same-exit re-dial cannot fix a
//! last-mile shrink and (with sticky-IP preservation unmerged) would
//! force an IP-change tunnel rebuild. Both verdicts publish on a watch
//! channel so an embedder can tell the user the PATH is sick instead of
//! looking healthy-but-dead.
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
    /// The episode reached a state a fresh session can plausibly cure (a
    /// [`PathHealth::DegradedBoth`] datapath wedge): request an overlap
    /// migration. Re-emitted while the wedge persists, spaced by
    /// [`MIGRATION_RETRY_COOLDOWN`] and capped at
    /// [`MAX_MIGRATIONS_PER_EPISODE`] per episode, because the first
    /// migration can land straight back on the wedged path.
    ///
    /// NOT emitted for [`PathHealth::DegradedLarge`]: that is the
    /// large-frame-selective signature of a last-mile brownout / shrunk
    /// path MTU, which a same-exit re-dial over the SAME first hop cannot
    /// fix, and which (while the sticky-IP-preservation fix is unmerged)
    /// a re-dial actively harms by forcing an inner-IP change and a full
    /// tunnel rebuild, converting a self-healing degradation into a
    /// guaranteed gap. A DegradedLarge episode is surfaced and left to
    /// the MSS-clamp / PMTU machinery and last-mile recovery.
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
/// Probe rounds to wait before asking for another overlap migration while a
/// [`PathHealth::DegradedBoth`] wedge persists. A degraded tracker probes at
/// [`FAST_CADENCE`], so one full window spaces the retries by ~10s: long
/// enough to judge the fresh session on its own evidence, short enough that a
/// user is not left on a dead tunnel.
const MIGRATION_RETRY_COOLDOWN: usize = WINDOW;
/// Overlap migrations allowed per degraded episode. Bounded because a wedge a
/// re-dial cannot cure must not turn into an endless re-dial storm; once the
/// budget is spent the episode stays degraded and the consumer surfaces it.
const MAX_MIGRATIONS_PER_EPISODE: usize = 3;

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
    migrations_requested: usize,
    migration_cooldown: usize,
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
                    self.migrations_requested = 0;
                    self.migration_cooldown = 0;
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
        }

        // Only a DegradedBoth wedge is worth a re-dial: a fresh session can
        // cure a session-state datapath wedge, but a same-exit re-dial cannot
        // fix the last-mile shrink that DegradedLarge signals (and, with
        // sticky-IP preservation unmerged, would force an IP-change tunnel
        // rebuild).
        //
        // Deliberately evaluated on every round rather than only on the state
        // transition: a wedge that the first migration does not cure keeps
        // classifying as DegradedBoth, so a transition-only request fired once
        // and never again, leaving the tunnel dead with the uplink still
        // sending into the void. Retries are spaced and capped below.
        if verdict == PathHealth::DegradedBoth {
            if self.migration_cooldown > 0 {
                self.migration_cooldown -= 1;
            } else if self.migrations_requested < MAX_MIGRATIONS_PER_EPISODE {
                self.migrations_requested += 1;
                self.migration_cooldown = MIGRATION_RETRY_COOLDOWN;
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
    /// Whether the last sweep found the bond's published inner budget under
    /// [`warrenguard_transport_core::QUIC_SAFE_INNER_MTU`]. Kept so the
    /// condition is logged on its transitions instead of on every round.
    under_quic_floor: std::sync::atomic::AtomicBool,
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
            under_quic_floor: std::sync::atomic::AtomicBool::new(false),
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
///
/// Under Quinn's `min_mtu`, which is load-bearing beyond the measurement:
/// its black-hole detector only refuses to call a loss burst "suspicious"
/// when the burst held a packet smaller than `min_mtu`, and a tunnel
/// otherwise emits almost nothing but max-size datagrams. Sweeping every leg
/// with this probe is what keeps ordinary congestion loss from reading to
/// Quinn as an MTU black hole and collapsing a healthy leg to its base MTU.
const SMALL_PROBE_LEN: usize = 84;

/// Sequence number of one probe in a round: legs are laid out in pairs from
/// `base`, small first. Wraps with `base`, which is why the round is decoded
/// with [`decode_probe_seq`] rather than compared.
fn probe_seq(base: u16, leg: usize, large: bool) -> u16 {
    base.wrapping_add(2 * leg as u16 + u16::from(large))
}

/// Inverse of [`probe_seq`], rejecting anything outside this round's
/// `2 * legs` window so a straggler from an earlier round cannot credit a
/// leg it never crossed.
fn decode_probe_seq(base: u16, seq: u16, legs: usize) -> Option<(usize, bool)> {
    let offset = usize::from(seq.wrapping_sub(base));
    (offset < 2 * legs).then_some((offset / 2, offset % 2 == 1))
}

/// Per-leg outcome of one sweep.
///
/// The comparison that matters is small-versus-large **on the same leg**:
/// that is what separates a size-selective blackhole from congestion, and
/// what the previous round-robin routing made impossible to observe.
struct Sweep {
    small_ok: Vec<bool>,
    large_ok: Vec<bool>,
}

impl Sweep {
    fn new(legs: usize) -> Self {
        Self {
            small_ok: vec![false; legs],
            large_ok: vec![false; legs],
        }
    }

    fn record(&mut self, leg: usize, large: bool) {
        let row = if large {
            &mut self.large_ok
        } else {
            &mut self.small_ok
        };
        if let Some(slot) = row.get_mut(leg) {
            *slot = true;
        }
    }

    fn complete(&self) -> bool {
        self.small_ok.iter().all(|ok| *ok) && self.large_ok.iter().all(|ok| *ok)
    }

    /// Bond-level pair fed to [`HealthTracker::record_pair`]: a size class is
    /// deliverable when ANY leg delivered it.
    ///
    /// `any`, not `all`, because the tracker drives user-visible verdicts and
    /// migrations, and a single leg out of eight failing is invisible to the
    /// user once that leg is quarantined out of the routing plan. Every leg
    /// failing is a real bond-wide shrink and still classifies as it always
    /// did. The per-leg detail is not lost: it goes to
    /// [`Self::size_blackholed_legs`].
    fn aggregate(&self) -> (bool, bool) {
        (
            self.small_ok.iter().any(|ok| *ok),
            self.large_ok.iter().any(|ok| *ok),
        )
    }

    /// Legs that returned their small probe and lost their large one: the
    /// size-selective signature, named leg by leg.
    fn size_blackholed_legs(&self) -> Vec<usize> {
        self.small_ok
            .iter()
            .zip(&self.large_ok)
            .enumerate()
            .filter(|&(_, (&small, &large))| small && !large)
            .map(|(leg, _)| leg)
            .collect()
    }
}

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

        // Every leg is probed, and each leg's pair is sized against ITS OWN
        // budget: a leg that has quietly stopped carrying full-size frames
        // is only visible when the packet it is asked to carry is the one it
        // claims to support.
        let budgets = bundle.leg_inner_payloads();
        let legs = budgets.len();
        if legs == 0 {
            return;
        }
        let base = shared
            .seq
            .fetch_add(2 * legs as u16, std::sync::atomic::Ordering::Relaxed);

        let sweep = {
            let mut replies = shared.replies.lock().await;
            // Stale replies of older rounds must not credit this one.
            while replies.try_recv().is_ok() {}
            for (leg, budget) in budgets.iter().enumerate() {
                let large_len = (*budget).max(SMALL_PROBE_LEN);
                let (Some(small), Some(large)) = (
                    build_echo_request(
                        src,
                        gw,
                        shared.tap.id(),
                        probe_seq(base, leg, false),
                        SMALL_PROBE_LEN,
                    ),
                    build_echo_request(
                        src,
                        gw,
                        shared.tap.id(),
                        probe_seq(base, leg, true),
                        large_len,
                    ),
                ) else {
                    return;
                };
                if bundle.send_probe_on(leg, &small).await.is_err()
                    || bundle.send_probe_on(leg, &large).await.is_err()
                {
                    // Dying connection: the supervisor is already on it; a
                    // send failure is not path evidence.
                    return;
                }
            }
            let mut sweep = Sweep::new(legs);
            let deadline = tokio::time::Instant::now() + REPLY_TIMEOUT;
            while !sweep.complete() {
                let reply = tokio::select! {
                    reply = replies.recv() => reply,
                    () = tokio::time::sleep_until(deadline) => break,
                };
                match reply {
                    Some(seq) => {
                        if let Some((leg, large)) = decode_probe_seq(base, seq, legs) {
                            sweep.record(leg, large);
                        }
                    }
                    None => return,
                }
            }
            sweep
        };

        // The bond has run out of legs above the inner-QUIC floor: quarantine
        // cannot route around it, PTB reflection has no legal answer (RFC 9000
        // forbids shrinking an Initial below 1200 bytes), and the MSS clamp
        // keeps TCP flowing, so the user sees "some sites work, HTTP/3 sites
        // hang" on a tunnel that reports Connected. Logged on the transitions
        // only, in both directions, so it dates the episode instead of
        // repeating every round.
        let published = bundle.max_inner_payload();
        let under_floor = published < warrenguard_transport_core::QUIC_SAFE_INNER_MTU;
        if under_floor
            != shared
                .under_quic_floor
                .swap(under_floor, std::sync::atomic::Ordering::Relaxed)
        {
            if under_floor {
                tracing::warn!(
                    inner_mtu = published,
                    floor = warrenguard_transport_core::QUIC_SAFE_INNER_MTU,
                    legs,
                    uplink_too_large_drops = warrenguard_pump::uplink_too_large_drop_total(),
                    "path health: no bonded leg reaches the inner-QUIC floor, so inner QUIC \
                     (HTTP/3, DNS-over-QUIC) cannot be ESTABLISHED on this path at all while \
                     MSS-clamped TCP keeps flowing"
                );
            } else {
                tracing::info!(
                    inner_mtu = published,
                    "path health: inner budget back above the inner-QUIC floor"
                );
            }
        }

        // The sentence that names a collapsed leg. Logged before the
        // aggregate verdict because a single leg failing is deliberately
        // invisible to the bond-level tracker.
        for leg in sweep.size_blackholed_legs() {
            tracing::warn!(
                leg,
                leg_inner_mtu = budgets[leg],
                legs,
                "path health: leg passes small probes and loses large ones (size-selective \
                 blackhole on this leg alone); it is quarantined out of the routing plan while \
                 it stays under the inner-QUIC floor"
            );
        }

        let (small_ok, large_ok) = sweep.aggregate();
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
                        max_per_episode = MAX_MIGRATIONS_PER_EPISODE,
                        "path health: datapath wedge (both probe sizes dead), requesting an overlap migration"
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

    #[test]
    fn a_probe_sequence_number_round_trips_to_its_leg_and_size() {
        // Correlating a reply back to (leg, size class) is the whole
        // instrument: get it wrong and the sweep reports noise.
        for base in [0u16, 1, 40_000, u16::MAX - 3] {
            for leg in 0..8 {
                for large in [false, true] {
                    let seq = probe_seq(base, leg, large);
                    assert_eq!(
                        decode_probe_seq(base, seq, 8),
                        Some((leg, large)),
                        "base {base} leg {leg} large {large} must round trip across u16 wrap"
                    );
                }
            }
        }
    }

    #[test]
    fn a_sequence_number_outside_this_round_is_rejected() {
        let base = 100u16;
        assert_eq!(decode_probe_seq(base, base.wrapping_sub(1), 4), None);
        assert_eq!(
            decode_probe_seq(base, base.wrapping_add(8), 4),
            None,
            "8 is the first seq past a 4-leg round"
        );
        assert_eq!(
            decode_probe_seq(base, base.wrapping_add(7), 4),
            Some((3, true))
        );
    }

    #[test]
    fn a_size_class_counts_as_deliverable_when_any_leg_delivered_it() {
        // One collapsed leg out of four must NOT read as a bond-wide
        // large-frame blackhole: after quarantine it carries no user
        // traffic, so declaring DegradedLarge here would be a false alarm.
        let mut sweep = Sweep::new(4);
        for leg in 0..4 {
            sweep.record(leg, false);
        }
        for leg in [0, 1, 3] {
            sweep.record(leg, true);
        }
        assert_eq!(sweep.aggregate(), (true, true));
    }

    #[test]
    fn a_size_class_counts_as_dead_only_when_every_leg_lost_it() {
        let mut sweep = Sweep::new(3);
        for leg in 0..3 {
            sweep.record(leg, false);
        }
        assert_eq!(
            sweep.aggregate(),
            (true, false),
            "no leg returned a large probe: that is a real bond-wide shrink"
        );

        let dead = Sweep::new(3);
        assert_eq!(dead.aggregate(), (false, false));
    }

    #[test]
    fn only_the_leg_whose_large_probe_died_is_named() {
        let mut sweep = Sweep::new(3);
        for leg in 0..3 {
            sweep.record(leg, false);
        }
        sweep.record(0, true);
        sweep.record(2, true);
        assert_eq!(
            sweep.size_blackholed_legs(),
            vec![1],
            "small alive and large dead on leg 1 is the size-selective signature"
        );

        let mut both_dead = Sweep::new(2);
        both_dead.record(0, false);
        both_dead.record(0, true);
        assert!(
            both_dead.size_blackholed_legs().is_empty(),
            "a leg that lost BOTH sizes is congestion or a dead leg, not a size blackhole"
        );
    }

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
    fn large_blackhole_enters_degraded_large_without_migration() {
        let mut t = HealthTracker::default();
        for _ in 0..4 {
            assert!(t.record_pair(true, false).is_empty(), "window not full yet");
        }
        // DegradedLarge is the last-mile signature: surface it, but do
        // NOT request a migration (a same-exit re-dial cannot fix the
        // radio and would force an IP-change rebuild).
        let events = t.record_pair(true, false);
        assert_eq!(
            events,
            vec![HealthEvent::Entered(PathHealth::DegradedLarge)]
        );
        assert_eq!(t.state(), PathHealth::DegradedLarge);
        assert!(t.wants_fast());
        assert!(t.record_pair(true, false).is_empty());
    }

    #[test]
    fn total_blackhole_enters_degraded_both_with_one_migration() {
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
        // The next round is inside the retry cooldown, so it stays quiet;
        // the spacing and the cap are pinned by the retry tests below.
        assert!(t.record_pair(false, false).is_empty());
    }

    #[test]
    fn large_reclassifies_to_both_and_migrates_once_then_not_again() {
        let mut t = HealthTracker::default();
        for _ in 0..5 {
            t.record_pair(true, false);
        }
        assert_eq!(t.state(), PathHealth::DegradedLarge);
        // Small probes start dying too: NOW a fresh session can help, so
        // the reclassification to Both is the first migration of the
        // episode.
        let mut migrations = 0;
        let mut saw_both = false;
        for _ in 0..5 {
            for e in t.record_pair(false, false) {
                if e == HealthEvent::RequestMigration {
                    migrations += 1;
                }
                if e == HealthEvent::Entered(PathHealth::DegradedBoth) {
                    saw_both = true;
                }
            }
        }
        assert!(saw_both);
        assert_eq!(
            migrations, 1,
            "exactly one migration when Large escalates to Both"
        );
        assert_eq!(t.state(), PathHealth::DegradedBoth);
    }

    #[test]
    fn recovery_needs_three_clean_pairs_then_a_both_episode_can_migrate_again() {
        let mut t = HealthTracker::default();
        for _ in 0..5 {
            t.record_pair(false, false);
        }
        assert_eq!(t.state(), PathHealth::DegradedBoth);
        assert!(t.record_pair(true, true).is_empty());
        assert!(t.record_pair(true, true).is_empty());
        assert_eq!(t.record_pair(true, true), vec![HealthEvent::Recovered]);
        assert_eq!(t.state(), PathHealth::Healthy);
        assert!(!t.wants_fast());
        // A relapse into a Both wedge is a NEW episode: it may migrate again.
        for _ in 0..4 {
            assert!(t.record_pair(false, false).is_empty());
        }
        assert!(
            t.record_pair(false, false)
                .contains(&HealthEvent::RequestMigration)
        );
    }

    #[test]
    fn a_persisting_wedge_retries_the_migration_up_to_the_cap() {
        // One migration that lands back on the same wedged path leaves the
        // tunnel dead with no further attempt: observed on Android after an
        // in-place exit switch, where the uplink kept sending while zero
        // bytes ever came back, for as long as the tunnel stayed up.
        let mut t = HealthTracker::default();
        let mut migrations = 0;
        let rounds = (MIGRATION_RETRY_COOLDOWN + 1) * (MAX_MIGRATIONS_PER_EPISODE + 3);
        for _ in 0..rounds {
            for e in t.record_pair(false, false) {
                if e == HealthEvent::RequestMigration {
                    migrations += 1;
                }
            }
        }
        assert_eq!(t.state(), PathHealth::DegradedBoth);
        assert_eq!(
            migrations, MAX_MIGRATIONS_PER_EPISODE,
            "a wedge the first migration does not cure must be retried, and bounded"
        );
    }

    #[test]
    fn a_wedge_retry_waits_a_full_probe_window_between_attempts() {
        let mut t = HealthTracker::default();
        let mut events = Vec::new();
        for _ in 0..5 {
            events = t.record_pair(false, false);
        }
        assert!(events.contains(&HealthEvent::RequestMigration));
        // The cooldown holds the next attempt back so each retry is judged on
        // a fresh window of evidence instead of firing on every probe round.
        for _ in 0..MIGRATION_RETRY_COOLDOWN {
            assert!(
                !t.record_pair(false, false)
                    .contains(&HealthEvent::RequestMigration),
                "retry fired before the cooldown elapsed"
            );
        }
        assert!(
            t.record_pair(false, false)
                .contains(&HealthEvent::RequestMigration),
            "retry never fired after the cooldown elapsed"
        );
    }

    #[test]
    fn degraded_large_never_requests_migration_across_a_long_episode() {
        let mut t = HealthTracker::default();
        let mut sent = 0;
        for _ in 0..20 {
            for e in t.record_pair(true, false) {
                if e == HealthEvent::RequestMigration {
                    sent += 1;
                }
            }
        }
        assert_eq!(t.state(), PathHealth::DegradedLarge);
        assert_eq!(
            sent, 0,
            "a pure last-mile episode must never force a re-dial"
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
