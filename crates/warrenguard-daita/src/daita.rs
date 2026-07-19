//! DAITA v2 wrapper around the [`maybenot`] traffic-analysis-defense
//! framework.
//!
//! Defense Against AI-guided Traffic Analysis - a server-negotiated set of
//! probabilistic state machines that schedule padding ("dummy") packets
//! and traffic blocking actions to obscure the packet-timing /
//! packet-size fingerprint exposed by encrypted communication.
//!
//! Warren's DAITA layer is functionally equivalent to Mullvad's DAITA v2
//! (Tobias Pulls et al., Karlstad U, sponsored by Mullvad) but tied to
//! the Quinn QUIC datagram pump rather than wireguard-go. Mullvad's v2
//! implementation specifics (e.g. their thousands-of-defenses generation
//! pipeline) are not fully published yet (PETS 2026 paper in flight),
//! so Warren ships with an initial pool of hand-selected machines from
//! [`maybenot_machines`] (NoOp, SimpleNetFlow, RegulaTor, Tamaraw,
//! FRONT, Interspace, BreakPad, Scrambler) and expands the pool over
//! time.
//!
//! ## Lifecycle
//!
//! 1. Exit-side: pick one machine from the pool at the start of each
//!    new session (uniform random, optionally weighted in the future).
//! 2. Send [`DaitaConfig`] to the client in the handshake `IpAssign`
//!    control message (`daita_spec` field).
//! 3. Both sides instantiate a [`DaitaFramework`] from the same config.
//! 4. The Quinn pump feeds packet events ([`DaitaEvent::NormalSent`] /
//!    [`DaitaEvent::NormalRecv`]) into the framework and applies the
//!    emitted [`DaitaAction`]s (send padding, schedule timer, block
//!    outgoing).
//!
//! This module exposes the framework wrapper only. Pump integration is
//! done in the pump.

use std::str::FromStr;
use std::time::{Duration, Instant};

use maybenot::{Framework, Machine, TriggerAction, TriggerEvent};
// `maybenot` 2.2.2 is built against rand 0.9. The engine uses rand
// 0.10 everywhere else, so we import rand 0.9 here under the
// `rand_v9` alias to feed the framework's RNG bound without polluting
// the rest of the crate. `StdRng` (vs `ThreadRng`) is `Send`, which
// the pump integration needs so the `DaitaState` can cross an `.await`
// boundary inside `tokio::spawn`.
pub use maybenot::MachineId;
use rand_v9::SeedableRng;
use rand_v9::rngs::StdRng;
pub use warrenguard_wire::DaitaConfig;

/// Failure building a [`DaitaState`] / [`DaitaFramework`] from a [`DaitaConfig`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DaitaError {
    /// A machine spec string failed to parse via `maybenot::Machine::from_str`.
    /// The cause is rendered as text (it describes the malformed encoding, not
    /// any identity, so it is not redaction-sensitive).
    #[error("invalid DAITA machine spec")]
    InvalidMachine(String),
    /// The fractional caps were not within `[0.0, 1.0]`.
    #[error("invalid DAITA fractions (padding/blocking must be in 0.0..=1.0)")]
    InvalidFraction,
    /// The maybenot framework refused the configuration. Defensive: unreachable
    /// from `from_config` with the current maybenot (the fraction caps and
    /// per-machine validation are rejected earlier), kept so a future framework
    /// check surfaces here rather than panicking.
    #[error("DAITA framework rejected the configuration")]
    Framework(String),
}

/// Placeholder sleep when no DAITA action timer is armed. The pump always
/// keeps one sleep arm so the `select!`/timer task has a uniform shape; the
/// next uplink/downlink event (plus the per-pump `Notify`) re-arms whatever
/// is actually due, so this only bounds the idle wake-up cadence. Far longer
/// than any real machine's first `SendPadding` after a `TunnelSent`.
/// See [`DaitaState::sleep_deadline`].
pub const DAITA_PLACEHOLDER_SLEEP: Duration = Duration::from_secs(3600);

/// Extension helpers on the wire-level [`DaitaConfig`] (defined in
/// `warren-protocol`) that depend on `maybenot` types and therefore
/// cannot live in the protocol crate (which has no runtime dep on
/// maybenot).
pub trait DaitaConfigExt {
    /// Builds a config with DAITA disabled (no machines, no caps).
    /// Convenience constructor for sites that need an explicit
    /// "off" config (vs `daita_spec: None` in `IpAssign`).
    fn disabled() -> Self;

    /// Builds a config from already-built [`Machine`]s.
    fn from_machines(machines: &[Machine], max_padding_frac: f64, max_blocking_frac: f64) -> Self;
}

impl DaitaConfigExt for DaitaConfig {
    fn disabled() -> Self {
        Self {
            machine_specs: Vec::new(),
            max_padding_frac: 0.0,
            max_blocking_frac: 0.0,
        }
    }

    fn from_machines(machines: &[Machine], max_padding_frac: f64, max_blocking_frac: f64) -> Self {
        Self {
            machine_specs: machines.iter().map(Machine::serialize).collect(),
            max_padding_frac,
            max_blocking_frac,
        }
    }
}

/// Warren-side mirror of [`TriggerEvent`], kept as a separate enum so
/// the public Warren API does not leak the `maybenot` types and stays
/// stable across upstream version bumps.
///
/// Only the subset relevant for the Quinn pump integration is exposed.
///
/// **Pairing convention**: for every outgoing application packet the
/// pump must fire `NormalSent` then `TunnelSent`; for every outgoing
/// padding packet, `PaddingSent` then `TunnelSent`. Symmetrically on
/// receive. Many published machines (e.g. SimpleNetFlow) listen on the
/// tunnel-level events to capture the "any packet activity" signal
/// rather than the kind-tagged events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaitaEvent {
    /// One application ("normal") packet was sent on the tunnel.
    NormalSent,
    /// One application ("normal") packet was received on the tunnel.
    NormalRecv,
    /// One padding ("dummy") packet was sent on the tunnel, in response
    /// to a previous [`DaitaAction::SendPadding`].
    PaddingSent {
        /// Identifier of the machine that requested the padding.
        machine: MachineId,
    },
    /// One padding ("dummy") packet was received on the tunnel.
    PaddingRecv,
    /// A packet of any type was actually written to the network.
    /// Fired after the kind-specific Normal/Padding-Sent event.
    TunnelSent,
    /// A packet of any type was received from the network. Fired
    /// before the kind-specific Normal/Padding-Recv event.
    TunnelRecv,
    /// Outgoing-blocking is now active for `machine` (= the
    /// [`DaitaAction::BlockOutgoing`] timer just fired). Required by
    /// Tamaraw / Scrambler state machines whose blocking state only
    /// advances on this event. `DaitaState` fires this internally from
    /// [`Self::drain_expired`] right after
    /// the BlockOutgoing action timer expires; pump callers normally
    /// don't need to fire it themselves.
    BlockingBegin {
        /// Identifier of the machine whose blocking interval has just
        /// started.
        machine: MachineId,
    },
    /// Outgoing-blocking has just ended after its `duration` interval
    /// elapsed. Counterpart to [`Self::BlockingBegin`]. Fired
    /// internally by [`Self::drain_expired`] when the per-machine
    /// `block_end_at` instant is reached.
    BlockingEnd,
}

/// Which timer is targeted by a [`TriggerAction::Cancel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaitaTimer {
    /// The per-machine action timer (drives `SendPadding` /
    /// `BlockOutgoing` expiration).
    Action,
    /// The per-machine internal timer (state-machine logic).
    Internal,
    /// Both timers at once.
    Both,
}

/// Warren-side mirror of [`TriggerAction`]. Kept as a separate enum for
/// the same stability reason as [`DaitaEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaitaAction {
    /// Set an action timer with `timeout`; on expiry, send one padding
    /// packet and trigger [`DaitaEvent::PaddingSent`] with the same
    /// `machine`. See [`TriggerAction::SendPadding`] for the precise
    /// semantics of `bypass` / `replace`.
    SendPadding {
        /// Identifier of the machine requesting the padding.
        machine: MachineId,
        /// Time until the padding must be emitted (relative to "now").
        timeout: Duration,
        /// If `true`, the padding may still be sent while outgoing
        /// blocking is active and was started with bypass also set.
        bypass: bool,
        /// If `true`, the padding may be replaced by an already-queued
        /// normal packet, avoiding extra wire bytes when possible.
        replace: bool,
    },
    /// Set an action timer with `timeout`; on expiry, block outgoing
    /// traffic for `duration`. See [`TriggerAction::BlockOutgoing`].
    BlockOutgoing {
        /// Identifier of the machine requesting the blocking.
        machine: MachineId,
        /// Time until blocking should start (relative to "now").
        timeout: Duration,
        /// How long outgoing traffic must remain blocked once started.
        duration: Duration,
        /// If `true`, padding marked `bypass` is still allowed during
        /// the blocking interval.
        bypass: bool,
        /// If `true`, an existing blocking duration is replaced rather
        /// than extended (`max(remaining, duration)`).
        replace: bool,
    },
    /// Cancel the specified timer(s) for the machine.
    Cancel {
        /// Identifier of the machine whose timer(s) are cancelled.
        machine: MachineId,
        /// Which timer is targeted (action, internal, or both).
        timer: DaitaTimer,
    },
    /// Update the per-machine internal timer.
    UpdateTimer {
        /// Identifier of the machine whose internal timer is updated.
        machine: MachineId,
        /// New duration for the internal timer.
        duration: Duration,
        /// If `true`, overwrite the existing internal timer; if
        /// `false`, take `max(existing_remaining, duration)`.
        replace: bool,
    },
}

/// Runtime container that drives a [`maybenot::Framework`] from
/// Warren-side events and emits Warren-side actions.
///
/// Stateful: the framework keeps internal counters, RNG state and
/// pending timers. One [`DaitaFramework`] per Quinn session per peer
/// (so 1 on the client + 1 on the exit). Both must be built from the
/// same [`DaitaConfig`] to ensure they speak the same defense.
///
/// `#[derive(Debug)]` is intentionally **not** delegated to
/// `maybenot::Framework` (no upstream `Debug` impl); we expose a
/// manual minimal Debug that prints only the machine count, never the
/// machine internals which are sensitive (the deployed defense
/// fingerprint).
pub struct DaitaFramework {
    /// `None` when [`DaitaConfig::disabled`] was used. All methods
    /// short-circuit to no-op behaviour in that case. `maybenot::Framework`
    /// is generic over `M: AsRef<[Machine]>`, so `Vec<Machine>` lets the
    /// framework own its machines directly: no `'static` borrow, no leak.
    inner: Option<Framework<Vec<Machine>, StdRng>>,
    /// Machine count, cached so [`Self::machines_count`] does not need to
    /// reach into `inner` (and stays available when `inner` is `None`).
    machine_count: usize,
}

impl std::fmt::Debug for DaitaFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaitaFramework")
            .field("enabled", &self.inner.is_some())
            .field("machines_count", &self.machine_count)
            .finish()
    }
}

impl DaitaFramework {
    /// Builds a framework from a wire-transmissible [`DaitaConfig`].
    ///
    /// # Errors
    ///
    /// - `DaitaInvalidMachine` if any of the machine_specs strings fails
    ///   to parse via [`Machine::from_str`].
    /// - `DaitaInvalidFraction` if the fractional caps are not in
    ///   `0.0..=1.0`.
    pub fn from_config(cfg: &DaitaConfig, start_time: Instant) -> Result<Self, DaitaError> {
        if !cfg.is_enabled() {
            return Ok(Self {
                inner: None,
                machine_count: 0,
            });
        }
        if !cfg.fractions_valid() {
            return Err(DaitaError::InvalidFraction);
        }

        let parsed: Vec<Machine> = cfg
            .machine_specs
            .iter()
            .map(|s| Machine::from_str(s).map_err(|e| DaitaError::InvalidMachine(e.to_string())))
            .collect::<Result<_, DaitaError>>()?;
        let machine_count = parsed.len();

        let inner = Framework::new(
            parsed,
            cfg.max_padding_frac,
            cfg.max_blocking_frac,
            start_time,
            // StdRng::from_os_rng seeds from the OS entropy pool every
            // call; on Linux this maps to getrandom(2), on macOS to
            // SecRandomCopyBytes. Acceptable cost for a once-per-session
            // operation; the framework then uses StdRng's deterministic
            // ChaCha core for per-event sampling.
            StdRng::from_os_rng(),
        )
        .map_err(|e| DaitaError::Framework(e.to_string()))?;

        Ok(Self {
            inner: Some(inner),
            machine_count,
        })
    }

    /// Convenience constructor for tests: starts a no-op framework
    /// (empty machine list). [`Self::trigger`] always returns an empty
    /// action vector.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            inner: None,
            machine_count: 0,
        }
    }

    /// True if the framework actually drives any machine. False after
    /// [`Self::disabled`] or when the config was empty.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Number of machines driven by the framework.
    #[must_use]
    pub fn machines_count(&self) -> usize {
        self.machine_count
    }

    /// Feeds zero or more events into the framework and returns the
    /// resulting actions. The caller (Quinn pump) is responsible for
    /// scheduling timers and applying [`DaitaAction::SendPadding`] etc.
    pub fn trigger(&mut self, events: &[DaitaEvent], now: Instant) -> Vec<DaitaAction> {
        let Some(fw) = self.inner.as_mut() else {
            return Vec::new();
        };

        let mb_events: Vec<TriggerEvent> = events.iter().map(daita_event_to_maybenot).collect();

        // `Framework::trigger_events` yields `&TriggerAction` (borrowed
        // for the framework's lifetime). `TriggerAction` is not `Copy`
        // (some variants own a `Box`), so we destructure each one by
        // reference and copy out the primitive fields (MachineId,
        // Duration, bool, Timer are all `Copy`).
        fw.trigger_events(&mb_events, now)
            .map(daita_action_from_maybenot)
            .collect()
    }
}

/// Per-machine timer slot maintained by [`DaitaState`].
///
/// Two timers per machine, per the `maybenot` contract:
/// - `action`: when set, the machine wants to send padding (or start
///   blocking) at that instant.
/// - `internal`: state-machine timer used by some machines (e.g. FRONT)
///   that re-trigger via [`maybenot::TriggerEvent::TimerEnd`] when
///   they expire.
#[derive(Debug, Default, Clone, Copy)]
struct MachineTimers {
    action: Option<Instant>,
    /// Track which kind of action the scheduled timer represents, so
    /// [`DaitaState::drain_expired`] can fire the
    /// matching follow-up event (`BlockingBegin` for `BlockOutgoing`).
    /// Without this, machines that use `BlockOutgoing` (Tamaraw,
    /// Scrambler) never advance past the blocking state because the
    /// pump only ever fires `PaddingSent` after a drain.
    action_kind: Option<TimerKind>,
    /// When a `BlockOutgoing` action fired, this is the instant at
    /// which the corresponding `BlockingEnd` event must be raised
    /// (= drain_at + duration). Some machines (Scrambler) use the
    /// `BlockingEnd` event to transition out of the blocking state.
    block_end_at: Option<Instant>,
    internal: Option<Instant>,
}

/// Disambiguates the two action-timer kinds so `drain_expired` can
/// fire the correct follow-up event into the framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerKind {
    /// Sourced from a [`DaitaAction::SendPadding`]. Pump callers emit
    /// one padding packet and fire `PaddingSent + TunnelSent`.
    Padding,
    /// Sourced from a [`DaitaAction::BlockOutgoing`]. `drain_expired`
    /// fires `BlockingBegin` internally and arms `block_end_at`. The
    /// pump caller still emits one padding packet (allowed via
    /// `bypass: true`) so the cadence stays observable on-wire.
    Block {
        /// Duration to wait before firing `BlockingEnd`. Carried over
        /// from the originating `BlockOutgoing` action.
        duration: Duration,
    },
}

/// Stateful driver around [`DaitaFramework`] that maintains the
/// per-machine action / internal timers. Designed to be polled
/// synchronously from a pump loop via `tokio::select!`:
///
/// 1. Pump receives a packet, calls [`Self::fire_events`] with the
///    matching [`DaitaEvent`]s (typically `NormalSent`+`TunnelSent`
///    on send, or `TunnelRecv`+`NormalRecv` on recv).
/// 2. Pump checks [`Self::next_timer`] to know whether to use
///    `tokio::time::sleep_until` for the next iteration.
/// 3. When the timer fires, pump calls [`Self::drain_expired`] to
///    collect the machine IDs that want padding emission. The pump
///    then sends one dummy datagram per machine and reports back
///    [`DaitaEvent::PaddingSent`] + [`DaitaEvent::TunnelSent`].
///
/// `DaitaState` itself does no I/O and is fully synchronous. The
/// async orchestration lives in the pump.
pub struct DaitaState {
    framework: DaitaFramework,
    /// One slot per machine, in the same index order as the framework
    /// initialisation. `MachineId` is opaque so we keep a side map.
    timers: std::collections::HashMap<MachineId, MachineTimers>,
    /// Per-session counters for production observability (logged on
    /// session close + queryable from in-process tests). Not on the
    /// wire; not part of the DAITA protocol surface.
    metrics: DaitaMetrics,
}

/// Counters surfaced by [`DaitaState::metrics`].
///
/// Snapshot semantics : the returned `DaitaMetrics` is a `Copy` of the
/// internal counters at call time. Tests and production loggers don't
/// share mutable state with the live `DaitaState`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DaitaMetrics {
    /// Total `SendPadding`-kind action timers that fired (and were
    /// surfaced to the pump caller as a "emit a dummy" signal).
    pub padding_fired: u64,
    /// Total `BlockOutgoing`-kind action timers that fired (each
    /// fires one internal `BlockingBegin` event into the framework
    /// and arms a `block_end_at` timer; the pump caller still emits
    /// one dummy per drain because `bypass: true`).
    pub blocking_begins: u64,
    /// Total `block_end_at` instants that elapsed, each firing a
    /// `BlockingEnd` event back into the framework.
    pub blocking_ends: u64,
}

impl std::fmt::Debug for DaitaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaitaState")
            .field("enabled", &self.framework.is_enabled())
            .field("machines", &self.framework.machines_count())
            .field("pending_action_timers", &self.count_pending_action_timers())
            .finish()
    }
}

impl DaitaState {
    /// Builds a driver from a wire-level [`DaitaConfig`]. Returns a
    /// driver that is `is_enabled() == false` when the config carries
    /// no machines.
    ///
    /// # Errors
    ///
    /// See [`DaitaFramework::from_config`].
    pub fn from_config(cfg: &DaitaConfig, start_time: Instant) -> Result<Self, DaitaError> {
        Ok(Self {
            framework: DaitaFramework::from_config(cfg, start_time)?,
            timers: std::collections::HashMap::new(),
            metrics: DaitaMetrics::default(),
        })
    }

    /// Convenience: a disabled driver (no machines, no timers). Used
    /// when DAITA is opted out for the session.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            framework: DaitaFramework::disabled(),
            timers: std::collections::HashMap::new(),
            metrics: DaitaMetrics::default(),
        }
    }

    /// Returns a snapshot of the per-session metric counters.
    /// Production loggers call this on session close to surface the
    /// DAITA defense's actual emission profile, and in-process
    /// regression tests use it to assert specific machines fire the
    /// expected counter mix without needing to drain timers
    /// step-by-step.
    #[must_use]
    pub fn metrics(&self) -> DaitaMetrics {
        self.metrics
    }

    /// True if the underlying framework drives any machine.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.framework.is_enabled()
    }

    /// Number of machines the framework drives. Used by the per-conn
    /// close-log on the exit side to surface whether
    /// DAITA was active without the caller needing to track the spec.
    #[must_use]
    pub fn machines_count(&self) -> usize {
        self.framework.machines_count()
    }

    /// Pushes `events` into the framework and updates the local timer
    /// slots according to the emitted actions. Returns the list of
    /// [`DaitaAction`]s for caller inspection (mostly observability;
    /// the timer logic is already applied internally).
    pub fn fire_events(&mut self, events: &[DaitaEvent], now: Instant) -> Vec<DaitaAction> {
        let actions = self.framework.trigger(events, now);
        for action in &actions {
            self.apply_action(*action, now);
        }
        actions
    }

    /// Deadline the pump should `sleep_until` before re-checking timers.
    ///
    /// Single source of the "always have a sleep arm" placeholder: when no
    /// action timer is armed, park for [`DAITA_PLACEHOLDER_SLEEP`] (the next
    /// uplink/downlink event re-arms whatever is due). Every pump variant
    /// must use this so the magic interval lives in one place; a too-short
    /// value would busy-wake, a too-long one would (without the per-pump
    /// `Notify`) delay the first dummy.
    #[must_use]
    pub fn sleep_deadline(&self, now: Instant) -> Instant {
        self.next_timer().unwrap_or(now + DAITA_PLACEHOLDER_SLEEP)
    }

    /// Fire the event sequence for ONE real (non-dummy) packet sent uplink.
    ///
    /// Centralizes the maybenot choreography so it cannot drift between the
    /// 5 pump variants (single-hop, multi-conn, multi-hop client, supervised
    /// uplink, exit). `NormalSent` then `TunnelSent`, in that order.
    pub fn on_real_uplink_sent(&mut self, now: Instant) {
        self.fire_events(&[DaitaEvent::NormalSent, DaitaEvent::TunnelSent], now);
    }

    /// Fire the event sequence for ONE dummy (padding) packet sent on the
    /// wire for `machine`: `PaddingSent { machine }` then `TunnelSent`. Call
    /// once per machine returned by [`Self::drain_expired`] AFTER the dummy
    /// was actually placed on the wire.
    pub fn on_dummy_sent(&mut self, machine: MachineId, now: Instant) {
        self.fire_events(
            &[DaitaEvent::PaddingSent { machine }, DaitaEvent::TunnelSent],
            now,
        );
    }

    /// Fire the event sequence for ONE datagram received on the wire.
    /// `TunnelRecv` MUST precede the kind-specific event per the maybenot
    /// spec; the kind is `PaddingRecv` for a dummy (caller drops it) or
    /// `NormalRecv` for a real packet (caller writes it to the TUN).
    pub fn on_downlink_received(&mut self, is_dummy: bool, now: Instant) {
        let kind = if is_dummy {
            DaitaEvent::PaddingRecv
        } else {
            DaitaEvent::NormalRecv
        };
        self.fire_events(&[DaitaEvent::TunnelRecv, kind], now);
    }

    /// Returns the earliest pending action-timer instant across all
    /// machines, or `None` if no action timer is armed. The pump
    /// uses this with `tokio::time::sleep_until` to wake up exactly
    /// when the next padding action is due.
    ///
    /// `block_end_at` instants are also surfaced so the pump wakes up
    /// to fire `BlockingEnd` events. The pump caller
    /// won't see those machines in the [`Self::drain_expired`]
    /// return (block-end fires internally without emitting a dummy);
    /// surfacing the timer just keeps the wake-up cadence accurate.
    #[must_use]
    pub fn next_timer(&self) -> Option<Instant> {
        self.timers
            .values()
            .flat_map(|t| t.action.into_iter().chain(t.block_end_at))
            .min()
    }

    /// Drains the action timers that have expired at or before `now`,
    /// returning the corresponding machine IDs (one per expired
    /// timer). The caller is expected to emit one padding packet per
    /// returned id and then call [`Self::fire_events`] with
    /// `DaitaEvent::PaddingSent { machine }` for each, so the
    /// framework can keep its accounting straight.
    pub fn drain_expired(&mut self, now: Instant) -> Vec<MachineId> {
        // Phase 1: drain expired action timers + identify which were
        // BlockOutgoing (need a follow-up BlockingBegin) vs SendPadding
        // (caller emits dummy + fires PaddingSent itself).
        let mut fired = Vec::new();
        let mut blocking_begins: Vec<MachineId> = Vec::new();
        let mut blocking_ends: Vec<MachineId> = Vec::new();
        for (id, t) in &mut self.timers {
            if let Some(at) = t.action
                && at <= now
            {
                t.action = None;
                let kind = t.action_kind.take();
                fired.push(*id);
                match kind {
                    Some(TimerKind::Block { duration }) => {
                        t.block_end_at = Some(now + duration);
                        blocking_begins.push(*id);
                        self.metrics.blocking_begins =
                            self.metrics.blocking_begins.saturating_add(1);
                    }
                    Some(TimerKind::Padding) | None => {
                        self.metrics.padding_fired = self.metrics.padding_fired.saturating_add(1);
                    }
                }
            }
            if let Some(end_at) = t.block_end_at
                && end_at <= now
            {
                t.block_end_at = None;
                blocking_ends.push(*id);
                self.metrics.blocking_ends = self.metrics.blocking_ends.saturating_add(1);
            }
        }
        // Phase 2: feed BlockingBegin / BlockingEnd back into the
        // framework so the machine state machine advances. These
        // events are NOT exposed to the pump caller - they are an
        // internal coupling between the action-timer expiry and the
        // maybenot framework's `BlockingBegin` / `BlockingEnd` inputs.
        for machine in blocking_begins {
            self.fire_events(&[DaitaEvent::BlockingBegin { machine }], now);
        }
        if !blocking_ends.is_empty() {
            // `TriggerEvent::BlockingEnd` has no payload (no MachineId)
            // - a single event covers any subset of unblocking
            // machines.
            self.fire_events(&[DaitaEvent::BlockingEnd], now);
        }
        fired
    }

    fn count_pending_action_timers(&self) -> usize {
        self.timers.values().filter(|t| t.action.is_some()).count()
    }

    fn apply_action(&mut self, action: DaitaAction, now: Instant) {
        match action {
            DaitaAction::SendPadding {
                machine, timeout, ..
            } => {
                let at = now + timeout;
                let entry = self.timers.entry(machine).or_default();
                entry.action = Some(at);
                entry.action_kind = Some(TimerKind::Padding);
            }
            DaitaAction::BlockOutgoing {
                machine,
                timeout,
                duration,
                ..
            } => {
                // Store the action-timer alongside its
                // kind so [`Self::drain_expired`] can fire
                // `BlockingBegin` after the timeout elapses (rather
                // than the prior simplification of treating Block as
                // Padding, which left Tamaraw / Scrambler state
                // machines stuck in their block state).
                let at = now + timeout;
                let entry = self.timers.entry(machine).or_default();
                entry.action = Some(at);
                entry.action_kind = Some(TimerKind::Block { duration });
            }
            DaitaAction::Cancel { machine, timer } => {
                let entry = self.timers.entry(machine).or_default();
                match timer {
                    DaitaTimer::Action => {
                        entry.action = None;
                        entry.action_kind = None;
                    }
                    DaitaTimer::Internal => entry.internal = None,
                    DaitaTimer::Both => {
                        entry.action = None;
                        entry.action_kind = None;
                        entry.internal = None;
                    }
                }
            }
            DaitaAction::UpdateTimer {
                machine,
                duration,
                replace,
            } => {
                let at = now + duration;
                let entry = self.timers.entry(machine).or_default();
                entry.internal = match (entry.internal, replace) {
                    (None, _) => Some(at),
                    (Some(_), true) => Some(at),
                    (Some(prev), false) => Some(prev.max(at)),
                };
            }
        }
    }
}

fn daita_event_to_maybenot(event: &DaitaEvent) -> TriggerEvent {
    match *event {
        DaitaEvent::NormalSent => TriggerEvent::NormalSent,
        DaitaEvent::NormalRecv => TriggerEvent::NormalRecv,
        DaitaEvent::PaddingSent { machine } => TriggerEvent::PaddingSent { machine },
        DaitaEvent::PaddingRecv => TriggerEvent::PaddingRecv,
        DaitaEvent::TunnelSent => TriggerEvent::TunnelSent,
        DaitaEvent::TunnelRecv => TriggerEvent::TunnelRecv,
        DaitaEvent::BlockingBegin { machine } => TriggerEvent::BlockingBegin { machine },
        DaitaEvent::BlockingEnd => TriggerEvent::BlockingEnd,
    }
}

fn daita_action_from_maybenot(action: &TriggerAction) -> DaitaAction {
    match *action {
        TriggerAction::SendPadding {
            machine,
            timeout,
            bypass,
            replace,
        } => DaitaAction::SendPadding {
            machine,
            timeout,
            bypass,
            replace,
        },
        TriggerAction::BlockOutgoing {
            machine,
            timeout,
            duration,
            bypass,
            replace,
        } => DaitaAction::BlockOutgoing {
            machine,
            timeout,
            duration,
            bypass,
            replace,
        },
        TriggerAction::Cancel { machine, timer } => DaitaAction::Cancel {
            machine,
            timer: daita_timer_from_maybenot(timer),
        },
        TriggerAction::UpdateTimer {
            machine,
            duration,
            replace,
        } => DaitaAction::UpdateTimer {
            machine,
            duration,
            replace,
        },
    }
}

fn daita_timer_from_maybenot(timer: maybenot::Timer) -> DaitaTimer {
    match timer {
        maybenot::Timer::Action => DaitaTimer::Action,
        maybenot::Timer::Internal => DaitaTimer::Internal,
        maybenot::Timer::All => DaitaTimer::Both,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical no-op machine published in the `maybenot` 2.2.2 example.
    /// Validates that we are wire-compatible with upstream serialization.
    const NO_OP_MACHINE_V2: &str = "02eNpjYEAHjOgCAAA0AAI=";

    #[test]
    fn disabled_config_carries_no_machines() {
        let cfg = DaitaConfig::disabled();
        assert!(cfg.machine_specs.is_empty(), "no machines on disabled");
        assert_eq!(cfg.max_padding_frac, 0.0);
        assert_eq!(cfg.max_blocking_frac, 0.0);
        assert!(
            !cfg.is_enabled(),
            "disabled config is_enabled() must be false"
        );
    }

    #[test]
    fn config_default_is_disabled() {
        let cfg = DaitaConfig::default();
        assert!(
            !cfg.is_enabled(),
            "Default::default() must equal disabled()"
        );
    }

    #[test]
    fn from_config_disabled_yields_disabled_framework() {
        let cfg = DaitaConfig::disabled();
        let fw = DaitaFramework::from_config(&cfg, Instant::now())
            .expect("disabled config must always build");
        assert!(!fw.is_enabled(), "framework must report disabled");
        assert_eq!(fw.machines_count(), 0);
    }

    #[test]
    fn sleep_deadline_uses_placeholder_when_no_timer_armed() {
        // A disabled state never arms an action timer, so the deadline is
        // exactly the placeholder horizon from `now`.
        let state = DaitaState::disabled();
        let now = Instant::now();
        assert_eq!(state.sleep_deadline(now), now + DAITA_PLACEHOLDER_SLEEP);
    }

    #[test]
    fn shared_event_helpers_are_inert_on_disabled_state() {
        // The centralized pump-event helpers must be safe to call on a
        // disabled DaitaState (the non-DAITA fast path never reaches them,
        // but a misconfigured machine degrades to `disabled()`).
        let mut state = DaitaState::disabled();
        let now = Instant::now();
        state.on_real_uplink_sent(now);
        state.on_downlink_received(true, now);
        state.on_downlink_received(false, now);
        // No machine ids exist on a disabled state; drain is empty.
        assert!(state.drain_expired(now).is_empty());
    }

    #[test]
    fn disabled_framework_returns_no_actions_on_any_event() {
        let mut fw = DaitaFramework::disabled();
        let now = Instant::now();
        let actions = fw.trigger(
            &[
                DaitaEvent::NormalSent,
                DaitaEvent::NormalSent,
                DaitaEvent::NormalRecv,
                DaitaEvent::NormalRecv,
            ],
            now,
        );
        assert!(
            actions.is_empty(),
            "disabled framework MUST NOT emit actions, got {actions:?}"
        );
    }

    #[test]
    fn from_config_with_noop_machine_builds_enabled_framework() {
        let cfg = DaitaConfig {
            machine_specs: vec![NO_OP_MACHINE_V2.to_owned()],
            max_padding_frac: 0.0,
            max_blocking_frac: 0.0,
        };
        let fw = DaitaFramework::from_config(&cfg, Instant::now())
            .expect("valid no-op machine must parse");
        assert!(fw.is_enabled(), "1 machine must enable the framework");
        assert_eq!(fw.machines_count(), 1);
    }

    #[test]
    fn from_config_with_invalid_machine_string_errors() {
        let cfg = DaitaConfig {
            machine_specs: vec!["not-a-real-machine-spec".to_owned()],
            max_padding_frac: 0.0,
            max_blocking_frac: 0.0,
        };
        let err = DaitaFramework::from_config(&cfg, Instant::now())
            .expect_err("invalid machine MUST fail parsing");
        match err {
            DaitaError::InvalidMachine(_) => {}
            other => panic!("expected InvalidMachine, got {other:?}"),
        }
    }

    #[test]
    fn from_config_rejects_invalid_padding_fraction() {
        let cfg = DaitaConfig {
            machine_specs: vec![NO_OP_MACHINE_V2.to_owned()],
            max_padding_frac: 1.5,
            max_blocking_frac: 0.0,
        };
        let err = DaitaFramework::from_config(&cfg, Instant::now())
            .expect_err("padding fraction > 1.0 MUST be rejected");
        match err {
            DaitaError::InvalidFraction => {}
            other => panic!("expected InvalidFraction error, got {other:?}"),
        }
    }

    #[test]
    fn noop_machine_emits_no_padding_on_normal_events() {
        // Cycle 100 NormalSent through a no-op machine, expect zero
        // SendPadding. The no-op machine has a single zero-action state,
        // by construction it MUST NOT emit any TriggerAction.
        let cfg = DaitaConfig {
            machine_specs: vec![NO_OP_MACHINE_V2.to_owned()],
            max_padding_frac: 1.0,
            max_blocking_frac: 1.0,
        };
        let mut fw =
            DaitaFramework::from_config(&cfg, Instant::now()).expect("no-op machine builds");

        let mut total_actions = 0usize;
        for _ in 0..100 {
            let now = Instant::now();
            let actions = fw.trigger(&[DaitaEvent::NormalSent], now);
            total_actions += actions.len();
        }
        assert_eq!(
            total_actions, 0,
            "no-op machine MUST NOT emit any action over 100 NormalSent events"
        );
    }

    #[test]
    fn simple_netflow_machine_schedules_padding_on_tunnel_sent() {
        // SimpleNetFlow listens on `TunnelSent` / `TunnelRecv` (the
        // wire-level "any-packet" events, post-encryption) and schedules
        // a `SendPadding` with a 1.5-9.5s random timeout (per
        // `maybenot_machines::netflow::simple_netflow`). Driving one
        // `TunnelSent` must surface a `SendPadding` action.
        use maybenot_machines::{StaticMachine, get_machine};

        let mut rng: StdRng = StdRng::from_os_rng();
        let machines = get_machine(&[StaticMachine::SimpleNetFlow], &mut rng);
        assert!(
            !machines.is_empty(),
            "SimpleNetFlow must produce at least one machine"
        );
        let cfg = DaitaConfig::from_machines(&machines, 1.0, 1.0);

        let mut fw =
            DaitaFramework::from_config(&cfg, Instant::now()).expect("SimpleNetFlow config builds");
        assert!(fw.is_enabled());

        // First `TunnelSent` moves the machine from the start state to
        // the padding state, which sets `action = SendPadding`.
        let actions = fw.trigger(&[DaitaEvent::TunnelSent], Instant::now());

        let has_send_padding = actions
            .iter()
            .any(|a| matches!(a, DaitaAction::SendPadding { .. }));
        assert!(
            has_send_padding,
            "SimpleNetFlow MUST schedule SendPadding on TunnelSent, got {actions:?}"
        );
    }

    // ---------- DaitaState tests ----------

    #[test]
    fn daita_state_disabled_reports_no_pending_timer() {
        let state = DaitaState::disabled();
        assert!(!state.is_enabled());
        assert_eq!(state.next_timer(), None);
    }

    #[test]
    fn daita_state_disabled_drain_returns_empty() {
        let mut state = DaitaState::disabled();
        let fired = state.drain_expired(Instant::now());
        assert!(fired.is_empty());
    }

    #[test]
    fn daita_state_from_disabled_config_is_disabled() {
        let cfg = DaitaConfig::disabled();
        let state = DaitaState::from_config(&cfg, Instant::now()).unwrap();
        assert!(!state.is_enabled());
        assert_eq!(state.next_timer(), None);
    }

    #[test]
    fn daita_state_arms_action_timer_on_send_padding_action() {
        // SimpleNetFlow schedules SendPadding on TunnelSent. The state
        // driver must record an action timer Instant exactly
        // `timeout` ahead of the firing `now`.
        use maybenot_machines::{StaticMachine, get_machine};
        let mut rng: StdRng = StdRng::from_os_rng();
        let machines = get_machine(&[StaticMachine::SimpleNetFlow], &mut rng);
        let cfg = DaitaConfig::from_machines(&machines, 1.0, 0.0);
        let start = Instant::now();
        let mut state = DaitaState::from_config(&cfg, start).unwrap();

        // Pre-condition: nothing scheduled.
        assert_eq!(state.next_timer(), None, "no timer before any event");

        // Fire a TunnelSent: SimpleNetFlow returns SendPadding with a
        // timeout in [1.5s, 9.5s]. The driver must record it.
        let now = Instant::now();
        let actions = state.fire_events(&[DaitaEvent::TunnelSent], now);
        let send_padding_count = actions
            .iter()
            .filter(|a| matches!(a, DaitaAction::SendPadding { .. }))
            .count();
        assert!(
            send_padding_count >= 1,
            "SimpleNetFlow MUST schedule SendPadding on TunnelSent"
        );

        let next = state
            .next_timer()
            .expect("driver MUST arm an action timer after SendPadding");
        // Bounded by the documented SimpleNetFlow window: timeout is
        // sampled uniformly in [1.5s, 9.5s], so `next` must be in
        // `(now, now+10s]`.
        assert!(
            next > now && next <= now + Duration::from_secs(10),
            "armed action timer must land in (now, now+10s], got {:?}",
            next.duration_since(now)
        );
    }

    #[test]
    fn daita_state_drain_expired_returns_machine_after_timer_elapses() {
        // We can't time-travel, but `drain_expired(now + 1h)` is a
        // legitimate way to assert "any armed timer would have fired
        // by then".
        use maybenot_machines::{StaticMachine, get_machine};
        let mut rng: StdRng = StdRng::from_os_rng();
        let machines = get_machine(&[StaticMachine::SimpleNetFlow], &mut rng);
        let cfg = DaitaConfig::from_machines(&machines, 1.0, 0.0);
        let start = Instant::now();
        let mut state = DaitaState::from_config(&cfg, start).unwrap();
        state.fire_events(&[DaitaEvent::TunnelSent], Instant::now());

        // Before "future" probe: drain at `now` returns nothing
        // (timer is > now).
        let immediate = state.drain_expired(Instant::now());
        assert!(
            immediate.is_empty(),
            "no timer can have expired at the instant after firing"
        );

        // Probe a far-future instant: every armed timer must have fired.
        let later = Instant::now() + Duration::from_secs(60 * 60);
        let fired = state.drain_expired(later);
        assert!(
            !fired.is_empty(),
            "drain_expired at +1h MUST surface the SimpleNetFlow timer"
        );

        // And the timer slot is now cleared.
        assert_eq!(
            state.next_timer(),
            None,
            "drained timer must be cleared from the slot"
        );
    }

    #[test]
    fn daita_state_disabled_fire_events_is_a_no_op() {
        // Sanity: feeding events to a disabled driver MUST never arm
        // timers (no machines = no actions = no schedule).
        let mut state = DaitaState::disabled();
        let actions = state.fire_events(
            &[
                DaitaEvent::TunnelSent,
                DaitaEvent::TunnelRecv,
                DaitaEvent::NormalSent,
                DaitaEvent::NormalRecv,
            ],
            Instant::now(),
        );
        assert!(actions.is_empty(), "disabled driver emits no action");
        assert_eq!(
            state.next_timer(),
            None,
            "disabled driver MUST stay timer-empty"
        );
    }

    #[test]
    fn from_config_repeated_sessions_do_not_leak_machines() {
        // Regression guard: `DaitaFramework` must never
        // `Box::leak` its machine allocation to satisfy a `'static` bound
        // on `Framework` (that leaks once per DAITA session, unbounded
        // growth on a long-running exit). `Framework<Vec<Machine>, _>`
        // owns its machines directly, so each `DaitaFramework` frees them
        // on drop like any other owned value; a `Box::leak` regression
        // here would be reported by a leak checker (e.g. `cargo miri
        // test`) at process/test exit. Build and drop a large number of
        // independent sessions to exercise this path.
        use maybenot_machines::{StaticMachine, get_machine};

        let mut rng: StdRng = StdRng::from_os_rng();
        let machines = get_machine(&[StaticMachine::SimpleNetFlow], &mut rng);
        let cfg = DaitaConfig::from_machines(&machines, 0.5, 0.5);

        for _ in 0..10_000 {
            let fw = DaitaFramework::from_config(&cfg, Instant::now()).expect("config builds");
            assert!(fw.is_enabled());
            assert_eq!(fw.machines_count(), machines.len());
            drop(fw);
        }
    }

    #[test]
    fn from_machines_round_trip_preserves_count() {
        // Serializing then reparsing must preserve the machine count.
        use maybenot_machines::{StaticMachine, get_machine};

        let mut rng: StdRng = StdRng::from_os_rng();
        let original = get_machine(&[StaticMachine::SimpleNetFlow], &mut rng);
        let count = original.len();
        assert!(count >= 1);

        let cfg = DaitaConfig::from_machines(&original, 0.5, 0.5);
        assert_eq!(cfg.machine_specs.len(), count);

        let fw =
            DaitaFramework::from_config(&cfg, Instant::now()).expect("round-trip config parses");
        assert_eq!(fw.machines_count(), count);
    }
}
