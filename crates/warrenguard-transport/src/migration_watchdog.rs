//! Migration watchdog: keeps the multi-hop QUIC path alive across
//! network changes, with a layered fallback.
//!
//! Primary path (zero work here): the QUIC socket is wildcard-bound
//! and the relay accepts migration, so after a default-route change
//! the very next packet leaves through the new interface and the
//! relay revalidates the path in ~1 RTT. This module only VERIFIES
//! that this happened, nudges the carrier bypass, and falls back when
//! it did not:
//!
//! 1. On a default-route change, establish the carrier escape the fresh
//!    socket will need ([`MigrationIo::ensure_route_escape`]), then rebind
//!    ([`MigrationIo::rebind_endpoint`]) and probe the tunnel with DAITA
//!    padding datagrams for [`MIGRATION_TIMEOUT`]. No escape, no rebind:
//!    the cycle redials rather than hand quinn a socket that self-nests
//!    into the tunnel it carries.
//! 2. No response (relay without migration support, broken NAT):
//!    [`MigrationIo::force_reconnect`], which redials from a fresh
//!    socket under the consumer's supervisor backoff (see
//!    [`crate::supervisor::SupervisorHandle::force_reconnect`]). TUN,
//!    routes, firewall and the consumer's state machine are untouched.
//! 3. Still no live session after [`ESCALATE_TIMEOUT`] (captive
//!    portal, IPv6-only network with a v4-only relay):
//!    [`MigrationIo::escalate`] hands the failure to the consumer's
//!    fail-closed reconnect machinery.
//!
//! The decision loop is pure over [`MigrationIo`] so every branch is
//! unit-testable with paused time; each consumer supplies its own
//! platform bindings (route-event source, session watch, escape and
//! rebind policy, escalation channel).

use std::future::Future;
use std::time::Duration;

/// Coalescing window for bursts of route events (an interface flap
/// emits several within milliseconds). This is event coalescing, not
/// a state debounce: the probe starts at most 250 ms after the FIRST
/// event of a burst.
pub const ROUTE_SETTLE: Duration = Duration::from_millis(250);
/// Interval between liveness probes while waiting for the migrated
/// path to answer.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// How long passive migration gets before the watchdog forces a
/// supervisor re-handshake. Several probe RTTs plus link-settle time,
/// far above the relay's ~1 RTT path validation.
pub const MIGRATION_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a forced reconnect gets to republish a live session
/// before the watchdog escalates to the state machine.
pub const ESCALATE_TIMEOUT: Duration = Duration::from_secs(30);

/// Identity + rx-counter sample of the currently published session.
/// The `id` combines the `Arc` pointer of the published client with
/// its local UDP port: rx counters are only comparable between samples
/// of the SAME session (a fresh session restarts its counters near
/// zero). The pointer alone is NOT a safe identity: the allocator can
/// reuse a freed `Arc` address for the very next session (ABA), which
/// once made the watchdog kill a freshly re-established session
/// because its low rx counter read as "no progress" on the old
/// baseline. The wildcard bind gives every session a fresh ephemeral
/// port, which disambiguates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxSample {
    /// Session identity: published-client `Arc` pointer XOR local port.
    pub id: usize,
    /// The session's cumulative received-datagram counter at sample time.
    pub rx_datagrams: u64,
}

/// Platform/IO surface consumed by [`run_watchdog`]. Each consumer
/// implements it over its own route-event source, session watch and
/// reconnect machinery; the unit tests script it with a mock.
///
/// The async methods are declared with an explicit `impl Future` return (not
/// `async fn`) so this public trait is free of the `async_fn_in_trait`
/// caveat; an implementor may still write `async fn` for each.
pub trait MigrationIo {
    /// Resolves on the next default-route change event. Returns
    /// `false` when the event source is gone (teardown): the watchdog
    /// loop exits.
    fn next_route_event(&mut self) -> impl Future<Output = bool> + Send;

    /// `true` when a usable IPv4 default route is currently present
    /// (the relay is dialed over v4).
    fn has_v4_default_route(&mut self) -> impl Future<Output = bool> + Send;

    /// Nudge the carrier bypass so it tracks the current default
    /// gateway. Best-effort; a no-op for consumers whose escape
    /// follows the routing table on its own.
    fn nudge_bypass(&mut self) -> impl Future<Output = ()> + Send;

    /// `false` when the live session cannot migrate because it rides the
    /// TLS-over-TCP fallback carrier, which has no UDP socket to swap. The
    /// cycle then skips the rebind and the probe window and goes straight to
    /// the redial.
    fn session_can_migrate(&mut self) -> bool;

    /// Ensure a destination-keyed escape exists before the socket loses its
    /// per-socket bypass (e.g. a `<carrier_ip>/32` host route on a platform
    /// whose bypass cannot survive the socket swap); a no-op elsewhere.
    /// Returns `false` when no escape could be established: the caller must
    /// then skip the rebind and redial instead of egressing unprotected.
    fn ensure_route_escape(&mut self) -> impl Future<Output = bool> + Send;

    /// Actively rebind the live session's QUIC endpoint onto a fresh
    /// wildcard UDP socket (see
    /// [`crate::multihop::MultiHopClient::rebind_wildcard`]). On macOS a
    /// wildcard socket does NOT reliably follow an interface change on
    /// its own (the kernel keeps the old flow's source state), so
    /// passive migration stalls; a fresh socket forces the next packet
    /// out the current default route, giving the relay a new 4-tuple to
    /// validate. Best-effort and a no-op when no session is published.
    /// Async because a consumer may re-resolve the current physical
    /// interface here (to follow a genuine Wi-Fi -> Ethernet hand-off,
    /// not just a same-interface flap).
    fn rebind_endpoint(&mut self) -> impl Future<Output = ()> + Send;

    /// Send one in-tunnel liveness probe (DAITA padding datagram) on
    /// the current session, if any. Any answer bumps the rx counters
    /// observed by [`Self::rx_sample`].
    fn send_probe(&mut self) -> impl Future<Output = ()> + Send;

    /// Sample the live session's identity + rx counter. `None` when
    /// no session is published (supervisor redialing).
    fn rx_sample(&mut self) -> Option<RxSample>;

    /// Close the current session so the supervisor redials from a
    /// fresh socket. Returns `false` when no session was published.
    fn force_reconnect(&mut self) -> bool;

    /// Report an unrecoverable path to the consumer's tunnel monitor
    /// (the desktop surfaces it as a transient backend error through
    /// its pump-error channel).
    fn escalate(&mut self, msg: String);
}

/// Outcome of one verification cycle, for logging and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The path answered probes (or a fresh session was published)
    /// without a forced reconnect.
    Migrated,
    /// The forced re-handshake brought a live session back.
    Reconnected,
    /// Nothing recovered within [`ESCALATE_TIMEOUT`]; escalated.
    Escalated,
    /// No usable v4 default route: parked until the next event, with
    /// the escalation backstop armed for online-but-broken networks.
    Parked,
}

/// `true` when `cur` proves the tunnel is receiving again relative to
/// `base`. A session swap (different id) counts as alive: a fresh
/// session only exists because a full handshake just succeeded.
fn rx_advanced(base: Option<RxSample>, cur: Option<RxSample>) -> bool {
    match (base, cur) {
        // Same id: any change in the counter proves liveness. Forward
        // movement is normal RX progress; a backward move can only be an
        // ABA id collision against a fresh session (counters are monotonic
        // within one session), which means a handshake just succeeded. Both
        // count as alive, hence `!=` rather than `>`.
        (Some(b), Some(c)) if b.id == c.id => c.rx_datagrams != b.rx_datagrams,
        (Some(b), Some(c)) => b.id != c.id,
        // No baseline session but one is published now: it was just
        // dialed on the new network, which is proof of liveness.
        (None, Some(_)) => true,
        (_, None) => false,
    }
}

/// Probe the current session until it answers or `window` elapses.
async fn probe_until<I: MigrationIo>(io: &mut I, window: Duration) -> bool {
    let base = io.rx_sample();
    let deadline = tokio::time::Instant::now() + window;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        io.send_probe().await;
        tokio::time::sleep(PROBE_INTERVAL).await;
        if rx_advanced(base, io.rx_sample()) {
            return true;
        }
    }
}

/// One full verification cycle following a (coalesced) route event.
pub async fn run_cycle<I: MigrationIo>(io: &mut I) -> CycleOutcome {
    if !io.has_v4_default_route().await {
        // Truly offline windows are owned by the consumer's state machine
        // (offline grace then a fail-closed block). The backstop below
        // only matters on networks that count as online without a v4
        // route (IPv6-only): no offline edge ever fires there, so
        // without it the consumer would sit "Connected" on a dead tunnel
        // forever.
        let woke_by_event = {
            let parked = tokio::time::sleep(ESCALATE_TIMEOUT);
            tokio::pin!(parked);
            tokio::select! {
                () = &mut parked => false,
                _alive = io.next_route_event() => true,
            }
        };
        if woke_by_event {
            // New event (or source closed): restart from the top; a
            // closed source makes the caller's next recv exit the loop.
            return CycleOutcome::Parked;
        }
        if io.has_v4_default_route().await {
            return CycleOutcome::Parked;
        }
        if probe_until(io, MIGRATION_TIMEOUT).await {
            return CycleOutcome::Migrated;
        }
        io.escalate(
            "no IPv4 default route and tunnel unresponsive after network change".to_string(),
        );
        return CycleOutcome::Escalated;
    }

    io.nudge_bypass().await;
    let started = tokio::time::Instant::now();

    if io.session_can_migrate() {
        if !io.ensure_route_escape().await {
            // The fresh socket of a rebind carries no per-socket bypass, so the
            // destination-keyed escape is the only thing left keeping the
            // carrier off the tunnel it carries. Without it the rebind would
            // self-nest the session (the macOS carrier-blackhole failure mode),
            // so redial instead and let the connect path rebuild the escape.
            let had_session = io.force_reconnect();
            tracing::warn!(
                "Warren migration watchdog: no carrier escape could be established; skipped the \
                 rebind and forced a supervisor reconnect (had_session={had_session})"
            );
        } else {
            // Active migration: rebind onto a fresh socket BEFORE probing.
            // Passive migration on the existing socket is unreliable on macOS
            // (kernel keeps the old interface's flow state), so the probes
            // below would otherwise keep leaving the dead interface and the
            // path would never revalidate. A fresh socket (with the carrier
            // bypass reapplied to it, see `rebind_endpoint`) is what actually
            // moves traffic to the new interface; the relay (migration enabled)
            // then validates it.
            io.rebind_endpoint().await;

            tracing::info!(
                "Warren migration watchdog: default-route change; rebound socket, probing the \
                 path (baseline {:?})",
                io.rx_sample()
            );
            if probe_until(io, MIGRATION_TIMEOUT).await {
                tracing::info!(
                    "Warren migration watchdog: QUIC path revalidated in {} ms after \
                     default-route change",
                    started.elapsed().as_millis()
                );
                return CycleOutcome::Migrated;
            }

            let last_sample = io.rx_sample();
            let had_session = io.force_reconnect();
            tracing::warn!(
                "Warren migration watchdog: path not revalidated within {MIGRATION_TIMEOUT:?} \
                 (last sample {last_sample:?}); forced supervisor reconnect \
                 (had_session={had_session})"
            );
        }
    } else {
        // The session rides the TLS-over-TCP carrier: there is no UDP socket to
        // swap, so a rebind would tear the TLS stream out from under a working
        // connection and the probe window could prove nothing about it.
        let had_session = io.force_reconnect();
        tracing::info!(
            "Warren migration watchdog: session carried over TCP cannot migrate; forced \
             supervisor reconnect straight away (had_session={had_session})"
        );
    }

    let escalate_deadline = tokio::time::Instant::now() + ESCALATE_TIMEOUT;
    loop {
        if tokio::time::Instant::now() >= escalate_deadline {
            io.escalate(format!(
                "tunnel path not recovered within {ESCALATE_TIMEOUT:?} after network change"
            ));
            return CycleOutcome::Escalated;
        }
        if probe_until(io, MIGRATION_TIMEOUT).await {
            tracing::info!(
                "Warren migration watchdog: session recovered via forced re-handshake \
                 {} ms after the default-route change",
                started.elapsed().as_millis()
            );
            return CycleOutcome::Reconnected;
        }
    }
}

/// Watchdog main loop: coalesce route-event bursts, then run one
/// verification cycle per burst. Exits when the event source closes
/// (route manager torn down) or after an escalation (the monitor is
/// about to tear the tunnel down anyway).
pub async fn run_watchdog<I: MigrationIo>(io: &mut I) {
    loop {
        if !io.next_route_event().await {
            return;
        }
        // Coalesce the burst: flaps emit several events back-to-back.
        let mut source_closed = false;
        {
            let settle = tokio::time::sleep(ROUTE_SETTLE);
            tokio::pin!(settle);
            loop {
                tokio::select! {
                    () = &mut settle => break,
                    alive = io.next_route_event() => {
                        if !alive {
                            source_closed = true;
                            break;
                        }
                    }
                }
            }
        }
        if source_closed {
            return;
        }
        if run_cycle(io).await == CycleOutcome::Escalated {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Scripted mock: every IO answer is pre-loaded; calls are recorded.
    struct MockIo {
        route_events: tokio::sync::mpsc::UnboundedReceiver<()>,
        has_route: bool,
        /// Successive samples returned by `rx_sample`, then the last
        /// one repeats forever.
        samples: VecDeque<Option<RxSample>>,
        last_sample: Option<RxSample>,
        can_migrate: bool,
        escape_ok: bool,
        probes_sent: u32,
        nudges: u32,
        rebinds: u32,
        force_reconnects: u32,
        escalations: Vec<String>,
        /// Ordered trace of the escape/rebind pair, so a test can pin that the
        /// escape is installed BEFORE the socket loses its per-socket bypass.
        calls: Vec<&'static str>,
    }

    impl MockIo {
        fn new(
            has_route: bool,
            samples: Vec<Option<RxSample>>,
        ) -> (Self, tokio::sync::mpsc::UnboundedSender<()>) {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let mut samples: VecDeque<_> = samples.into();
            let last = samples.pop_back().flatten();
            (
                Self {
                    route_events: rx,
                    has_route,
                    samples,
                    last_sample: last,
                    can_migrate: true,
                    escape_ok: true,
                    probes_sent: 0,
                    nudges: 0,
                    rebinds: 0,
                    force_reconnects: 0,
                    escalations: Vec::new(),
                    calls: Vec::new(),
                },
                tx,
            )
        }
    }

    impl MigrationIo for MockIo {
        async fn next_route_event(&mut self) -> bool {
            self.route_events.recv().await.is_some()
        }
        async fn has_v4_default_route(&mut self) -> bool {
            self.has_route
        }
        async fn nudge_bypass(&mut self) {
            self.nudges += 1;
        }
        fn session_can_migrate(&mut self) -> bool {
            self.can_migrate
        }
        async fn ensure_route_escape(&mut self) -> bool {
            self.calls.push("ensure_route_escape");
            self.escape_ok
        }
        async fn rebind_endpoint(&mut self) {
            self.calls.push("rebind_endpoint");
            self.rebinds += 1;
        }
        async fn send_probe(&mut self) {
            self.probes_sent += 1;
        }
        fn rx_sample(&mut self) -> Option<RxSample> {
            match self.samples.pop_front() {
                Some(s) => s,
                None => self.last_sample,
            }
        }
        fn force_reconnect(&mut self) -> bool {
            self.force_reconnects += 1;
            true
        }
        fn escalate(&mut self, msg: String) {
            self.escalations.push(msg);
        }
    }

    fn sample(id: usize, rx: u64) -> Option<RxSample> {
        Some(RxSample {
            id,
            rx_datagrams: rx,
        })
    }

    #[test]
    fn rx_advanced_same_session_requires_counter_movement() {
        assert!(rx_advanced(sample(1, 10), sample(1, 11)));
        assert!(!rx_advanced(sample(1, 10), sample(1, 10)));
        // Counter going BACKWARDS on the same id = ABA address reuse by
        // a fresh session (monotonic within a session) = alive.
        assert!(rx_advanced(sample(1, 10), sample(1, 9)));
    }

    #[test]
    fn rx_advanced_session_swap_counts_as_alive() {
        // A fresh session only exists because a handshake succeeded on
        // the new network; its counters are NOT comparable.
        assert!(rx_advanced(sample(1, 500), sample(2, 3)));
        assert!(rx_advanced(None, sample(2, 0)));
        assert!(!rx_advanced(sample(1, 500), None));
        assert!(!rx_advanced(None, None));
    }

    #[tokio::test(start_paused = true)]
    async fn cycle_confirms_migration_when_rx_advances() {
        // Baseline 10, first post-probe sample 11: confirmed on the
        // first probe, no force_reconnect, exactly one nudge.
        let (mut io, _tx) = MockIo::new(true, vec![sample(7, 10), sample(7, 11)]);
        let outcome = run_cycle(&mut io).await;
        assert_eq!(outcome, CycleOutcome::Migrated);
        assert_eq!(io.nudges, 1);
        assert_eq!(io.rebinds, 1, "active rebind must run before probing");
        assert_eq!(io.force_reconnects, 0);
        assert!(io.escalations.is_empty());
        assert!(io.probes_sent >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn carrier_session_skips_the_rebind_and_redials_immediately() {
        // A TLS-over-TCP carrier has no UDP socket to swap, so rebinding would
        // kill a working session and the 3 s probe window could prove nothing.
        // The cycle must drop straight to the redial.
        let (mut io, _tx) = MockIo::new(true, vec![sample(7, 10), sample(8, 1)]);
        io.can_migrate = false;
        let started = tokio::time::Instant::now();
        let outcome = run_cycle(&mut io).await;
        assert_eq!(outcome, CycleOutcome::Reconnected);
        assert_eq!(io.rebinds, 0, "a carrier session must never be rebound");
        assert_eq!(io.force_reconnects, 1, "exactly one forced reconnect");
        assert!(
            started.elapsed() < MIGRATION_TIMEOUT,
            "the redial must not wait out the probe window, took {:?}",
            started.elapsed()
        );
        assert!(io.escalations.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn rebind_is_skipped_when_no_escape_can_be_established() {
        // The fresh migration socket carries no per-socket bypass on macOS, so
        // the destination-keyed `/32` escape is the only thing keeping the
        // carrier out of the tunnel it carries. With no escape the rebind would
        // hand the session a socket that self-nests: redial instead.
        let (mut io, _tx) = MockIo::new(true, vec![sample(7, 10), sample(8, 1)]);
        io.escape_ok = false;
        let outcome = run_cycle(&mut io).await;
        assert_eq!(outcome, CycleOutcome::Reconnected);
        assert_eq!(io.rebinds, 0, "never rebind without a live escape");
        assert_eq!(io.force_reconnects, 1, "exactly one forced reconnect");
        assert!(io.escalations.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn escape_is_established_before_every_rebind() {
        // Order is the whole safety property: the rebind is what drops the
        // per-socket bypass, so an escape installed after it leaves a window
        // where the carrier has neither. Swapping the two calls must fail here.
        let (mut io, _tx) = MockIo::new(true, vec![sample(7, 10), sample(7, 11)]);
        let outcome = run_cycle(&mut io).await;
        assert_eq!(outcome, CycleOutcome::Migrated);
        assert!(io.rebinds >= 1, "the migratable branch must rebind at all");
        let mut escaped = false;
        for call in &io.calls {
            match *call {
                "ensure_route_escape" => escaped = true,
                "rebind_endpoint" => assert!(
                    escaped,
                    "rebound before establishing the escape, call order {:?}",
                    io.calls
                ),
                other => panic!("unexpected recorded call {other}"),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cycle_forces_reconnect_after_migration_timeout_then_recovers() {
        // Counter never advances on session 7 (stuck path); after the
        // forced reconnect a NEW session id appears => Reconnected.
        let stuck: Vec<Option<RxSample>> = std::iter::repeat_n(sample(7, 10), 16).collect();
        let mut script = stuck;
        // Post-reconnect: a fresh session publishes (different id).
        script.push(sample(8, 1));
        script.push(sample(8, 2));
        let (mut io, _tx) = MockIo::new(true, script);
        let outcome = run_cycle(&mut io).await;
        assert_eq!(outcome, CycleOutcome::Reconnected);
        assert_eq!(io.force_reconnects, 1, "exactly one forced reconnect");
        assert!(io.escalations.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn cycle_escalates_when_nothing_recovers() {
        // Session never answers and never swaps: Migrated window fails,
        // forced reconnect fails, escalation fires with a message.
        let (mut io, _tx) = MockIo::new(true, vec![sample(7, 10)]);
        let outcome = run_cycle(&mut io).await;
        assert_eq!(outcome, CycleOutcome::Escalated);
        assert_eq!(io.force_reconnects, 1);
        assert_eq!(io.escalations.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cycle_parks_without_v4_route_until_next_event() {
        // No v4 route: no probes, no forced reconnect. A new route
        // event within the backstop window re-parks (fresh cycle).
        let (mut io, tx) = MockIo::new(false, vec![sample(7, 10)]);
        tx.send(()).expect("inject route event");
        let outcome = run_cycle(&mut io).await;
        assert_eq!(outcome, CycleOutcome::Parked);
        assert_eq!(io.force_reconnects, 0);
        assert_eq!(io.probes_sent, 0);
        assert!(io.escalations.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn cycle_escalates_from_park_when_network_stays_v4_less_and_tunnel_dead() {
        // IPv6-only backstop: no v4 route for the whole ESCALATE
        // window, no recovery on the final probe => escalate (the
        // offline grace never fires on an online-v6 network, so the
        // watchdog is the only honest exit).
        let (mut io, _tx) = MockIo::new(false, vec![sample(7, 10)]);
        let outcome = run_cycle(&mut io).await;
        assert_eq!(outcome, CycleOutcome::Escalated);
        assert_eq!(io.escalations.len(), 1);
        assert_eq!(io.force_reconnects, 0, "park path never force-reconnects");
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_coalesces_event_bursts_into_one_cycle() {
        // 5 events in a burst => exactly one nudge (one cycle), since
        // the settle window swallows the follow-ups. Dropping the
        // sender afterwards makes the main loop exit cleanly.
        let (mut io, tx) = MockIo::new(true, vec![sample(7, 10), sample(7, 11)]);
        for _ in 0..5 {
            tx.send(()).expect("inject");
        }
        // Close the source long after the cycle completes (paused time
        // advances instantly); dropping it earlier would end the settle
        // window before the cycle ever runs.
        let dropper = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(tx);
        });
        run_watchdog(&mut io).await;
        dropper.await.expect("dropper task");
        assert_eq!(io.nudges, 1, "burst must collapse into one cycle");
        assert_eq!(io.force_reconnects, 0);
    }
}
