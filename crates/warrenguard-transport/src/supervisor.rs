//! Transparent mid-session auto-reconnect for the multi-hop client.
//!
//! The [`MultiHopSupervisor`] owns the lifecycle of a [`MultiHopClient`]
//! across disconnects. It dials the relay on start, publishes the live
//! client through a [`tokio::sync::watch`] channel, then awaits
//! [`MultiHopClient::closed`]. As soon as the QUIC connection drops
//! (idle timeout, peer reset, transient network blip beyond the 180 s
//! `max_idle_timeout` window), the supervisor:
//!
//! 1. Publishes `None` so pumps can drop in-flight packets cleanly,
//! 2. Retries the dial via [`MultiHopClient::connect_with_retry`]-style
//!    semantics, recycling the [`warrenguard_backoff::Backoff`] iterator so
//!    a long-lived disconnect (router restart, WiFi <-> 4G handover) is
//!    survivable,
//! 3. Publishes the freshly-dialed `Some(Arc<MultiHopClient>)` so the
//!    pump resumes.
//!
//! Throughout the reconnect window, **the supervisor does not touch the
//! killswitch, the TUN device, or any routing guard**. Those handles
//! live in the binary's `run()` frame and stay installed for the
//! entire process lifetime, so a packet emitted by an application
//! during the reconnect window either:
//! - hits the TUN (which the pump now drops because the published
//!   client is `None`),
//! - or is blocked by the killswitch / routing split.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::sync::{Notify, watch};
use warrenguard_backoff::Backoff;
use warrenguard_multihop::{ExitId, RejectionReason, RelayDescriptorSigned, WarrenControlMessage};
use warrenguard_socket_bypass::SocketBypass;
use warrenguard_wire::SessionToken;

use crate::bundle::{MAX_BONDED_CONNECTIONS, MultiHopBundle};
use crate::ip_assign::{IpAssignChannel, IpAssignSpec};
use warrenguard_transport_core::{
    warren_transport_config_client_multihop_with_idle_cover,
    warren_transport_config_client_with_idle_cover,
};

use crate::multihop::{self, MultiHopClient, MultiHopError};

/// Observer invoked whenever the supervisor successfully publishes a
/// fresh session that follows a previous disconnect (i.e. the initial
/// connect does NOT fire the callback). A consuming daemon typically
/// wires this to a counter that drives its UI's reconnect display.
/// Cloneable so the supervisor can move
/// it into the spawned task without taking ownership of the caller's
/// handle.
pub type ReconnectObserver = Arc<dyn Fn() + Send + Sync + 'static>;

/// Async gate the supervisor runs right before COMMITTING an overlap
/// swap, generic so the verdict logic is unit-testable without a live
/// bundle. Returning `false` aborts the swap: the fresh session is
/// closed and the current one kept (the safe side for state that must
/// not be lost across an exit change, e.g. reserved forwarded ports).
pub type PreSwapCheckFn<T> = Arc<
    dyn Fn(T) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync,
>;

/// Production instantiation of [`PreSwapCheckFn`]: the check receives
/// the FULLY established new session (Setup done, inner IP assigned,
/// secondaries bonded, not yet published) while the current session
/// keeps serving, so it can run an end-to-end exchange against the new
/// exit (e.g. a NAT-PMP port reservation) before the pump ever moves.
pub type PreSwapCheck = PreSwapCheckFn<Arc<MultiHopBundle>>;

/// Observer fired right AFTER an overlap swap is committed (the watch
/// now publishes the new session), with the circuit target it landed
/// on. Distinguishes a completed migration from a mere request, which
/// [`SupervisorHandle::migrate_to`] cannot: consumers that must act on
/// the NEW exit (re-map forwarded ports) would otherwise race the dial.
pub type OverlapSwapObserver = Arc<dyn Fn(&CircuitTarget) + Send + Sync>;

/// Observer fired when a dial attempt is deliberately refused by the
/// target circuit (see [`MultiHopError::dial_refusal`]). Arguments:
/// the refused hop, the entry `relay_id`, the exit id bytes of the
/// circuit whose dial was refused.
pub type DialRefusedObserver =
    Arc<dyn Fn(multihop::DialRefusedHop, [u8; 16], [u8; 16]) + Send + Sync>;

/// Source of anonymous v7 session tokens (Privacy Pass). Called ONCE
/// per session establishment to obtain the token stack the primary and all its
/// bonded secondaries present; because they share one stack they resolve to the
/// same anonymous serial and thus the same sticky tunnel IP. Returning an empty
/// vec (or configuring no provider) keeps the v6 wallet-signed `IpRequest` path.
///
/// The app wires this to a closure that pops a token from its `TokenStore` for
/// the current epoch (plus an optional next-epoch lookahead for clock skew) and
/// converts it to the wire [`SessionToken`]. The supervisor is deliberately
/// ignorant of epochs and the store: it only asks for a per-session stack.
pub type SessionTokenProvider = Arc<dyn Fn() -> Vec<SessionToken> + Send + Sync>;

/// Upper bound on a pre-swap check. Past it the swap is ABORTED (fail
/// closed), because during the check the serve loop polls nothing else:
/// an unbounded check would wedge liveness handling.
const PRE_SWAP_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Applies the optional pre-swap gate: no check = allow, a verdict is
/// honoured, a timeout aborts. Free function so the timeout semantics
/// are testable without a supervisor.
async fn pre_swap_allows<T>(check: Option<&PreSwapCheckFn<T>>, subject: T) -> bool {
    let Some(check) = check else {
        return true;
    };
    match tokio::time::timeout(PRE_SWAP_CHECK_TIMEOUT, check(subject)).await {
        Ok(verdict) => verdict,
        Err(_) => {
            tracing::warn!("pre-swap check timed out; overlap swap aborted");
            false
        }
    }
}

/// Inputs required to build and re-dial a multi-hop session.
///
/// Cloned eagerly into the supervisor task; the supervisor takes
/// ownership of its copy so the caller may drop the original after
/// spawning.
#[derive(Clone)]
pub struct SupervisorConfig {
    /// Signed relay descriptor for the first hop.
    pub relay: Arc<RelayDescriptorSigned>,
    /// Destination exit identifier (must match the exit descriptor).
    pub exit_id: ExitId,
    /// Long-lived X25519 HPKE recipient pubkey of the exit.
    pub exit_x25519_multihop_pubkey: [u8; 32],
    /// Operational pubkey used to verify signed descriptors.
    pub operational_pubkey: VerifyingKey,
    /// Local Ed25519 signing key (TLS raw public key authentication).
    pub client_signing: SigningKey,
    /// Local UDP bind address (`0.0.0.0:0` for kernel-picked port).
    pub bind_addr: std::net::SocketAddr,
    /// `true` enables UDP segmentation offload (GSO) on the QUIC
    /// transport. Disable on virtio NICs without HW support.
    pub enable_gso: bool,
    /// `true` opts into the Warren wire-mimicry profile (Initial
    /// padding + split ClientHello). Required on production relays.
    pub use_warren_obfuscation: bool,
    /// Keeps the dial's QUIC socket on the physical link, out of the
    /// full-tunnel capture a system-VPN datapath installs (`SO_MARK` on Linux,
    /// `IP_BOUND_IF` on macOS, `IP_UNICAST_IF` on Windows). Set by a privileged
    /// TUN datapath so it can drop the `<exit_ip>/32` host route: the escape is
    /// keyed on the socket, not the exit destination, closing Port Fail /
    /// TunnelCrack ServerIP. `None` for the userland proxy (no OS tunnel to
    /// bypass) and mobile (handled by `VpnService.protect`).
    pub socket_bypass: Option<SocketBypass>,
    /// `true` ⇒ ask every circuit for the traffic-analysis defense (DAITA).
    /// The exit answers per session; a granted machine reaches the caller via
    /// [`MultiHopClient::daita_spec`], and its absence means the defense is NOT
    /// running, which the caller must surface rather than pump undefended.
    pub enable_daita: bool,
    /// `true` => dial with the fixed keep-alive PING disabled and let the
    /// caller drive idle cover
    /// ([`crate::supervised_pump::run_idle_cover`]) for liveness + NAT refresh
    /// instead (ADR-0006). The two MUST be set together: this only changes the
    /// dial's transport config; the caller still spawns the cover emitter, so
    /// keep-alive-off without a cover pump leaves the session with only the
    /// 25s idle timeout. Resolve it from
    /// [`warrenguard_config::knobs::cover_defenses`] so the DAITA/idle-cover
    /// mutual exclusion holds (DAITA already emits its own cover, so idle cover
    /// is off whenever `enable_daita` is on). `false` keeps the fixed keep-alive
    /// beacon, byte-identical to the pre-ADR-0006 dial.
    pub idle_cover: bool,
    /// Exponential backoff schedule for retries. `Backoff::HANDSHAKE`
    /// (base 500 ms, max 15 s) is the default and matches the
    /// cold-start retry profile of [`MultiHopClient::connect_with_retry`].
    pub backoff: Backoff,
    /// Optional observer invoked once per successful reconnect (NOT on
    /// the initial connect). `None` is the test-only default; a
    /// consuming daemon wires this to a closure that bumps its live
    /// status counter so the UI reconnect display advances.
    pub on_reconnect: Option<ReconnectObserver>,
    /// Optional channel onto which the supervisor publishes the
    /// `IpAssign` obtained from the reliable setup-stream round-trip on
    /// each (re)connect. The orchestrator's reassign task subscribes and
    /// reassigns the TUN. `None` ⇒ IP-nego is not wired (the client
    /// keeps its bootstrap IP); used by tests and by deployments without
    /// `--multihop-subnet`.
    pub ip_assign_channel: Option<IpAssignChannel>,
    /// Multi-hop dual-stack: `true` sets `wants_ipv6` on the setup-stream
    /// `IpRequest`. The exit answers with an `IpAssign` whose `ipv6` is
    /// `Some` only when it actually granted v6; if it could not, the client
    /// stays IPv4-only AND the gap is surfaced (logged here) rather than
    /// silently degrading. The firewall keeps native v6 blocked throughout,
    /// so a non-grant is leak-safe.
    pub wants_ipv6: bool,
    /// Number of bonded QUIC connections per session (clamped to
    /// `1..=MAX_BONDED_CONNECTIONS`). One QUIC connection is capped at
    /// the per-flow bandwidth share of the client↔relay path; bonding N
    /// connections under the same identity (the exit's sticky allocator
    /// assigns them one inner IP) multiplies the available share.
    /// Secondary dials are best-effort: the session runs with however
    /// many came up (always >= 1). Bonding silently degrades to 1 when
    /// the exit does not run ip-nego (no `IpAssign`): without an
    /// allocator the exit cannot fan its TUN downlink across
    /// connections.
    pub n_connections: usize,
    /// Optional gate run against the fresh session before an overlap
    /// swap is committed; `false` (or a [`PRE_SWAP_CHECK_TIMEOUT`]
    /// overrun) aborts the swap and keeps the current session. `None`
    /// commits unconditionally (the pre-docs-59 behavior).
    pub pre_swap_check: Option<PreSwapCheck>,
    /// Optional observer fired after each committed overlap swap with
    /// the circuit target it landed on (completion signal, see
    /// [`OverlapSwapObserver`]). `None` = not observed.
    pub on_overlap_swapped: Option<OverlapSwapObserver>,
    /// Optional observer fired on each deliberately refused dial
    /// attempt (drained entry or exit, see
    /// [`MultiHopError::dial_refusal`]), with the refused circuit's
    /// identity. A deployer excludes the refusing node from its own
    /// selection and retargets via [`SupervisorHandle::migrate_to`];
    /// the retry loop keeps running either way and picks a retarget up
    /// on its next attempt. `None` = refusals retry like any other
    /// transient error.
    pub on_dial_refused: Option<DialRefusedObserver>,
    /// Optional source of anonymous v7 session tokens
    /// ([`SessionTokenProvider`]). When set and it yields a non-empty stack,
    /// each session presents `IpRequestV7` (the exit admits on the token and
    /// never learns the account pubkey); the whole bonded session shares one
    /// stack so every connection maps to the same anonymous serial and sticky
    /// IP. `None` keeps the v6 wallet-signed `IpRequest` + PoP path.
    pub session_token_provider: Option<SessionTokenProvider>,
}

/// The exit-defining half of a circuit: which relay (first hop) to dial
/// and which exit (second hop) to terminate at. The supervisor holds the
/// CURRENT target behind a mutex so [`SupervisorHandle::migrate_to`] can
/// retarget it at runtime; the dial path reads it on every (re)dial.
///
/// Everything else needed to dial (operational pubkey, the client's own
/// signing key, bind address, GSO/obfuscation flags) lives in
/// [`SupervisorConfig`] and does NOT change on a migration - a cross-exit
/// migration stays within one fleet, under one operational key.
#[derive(Clone)]
pub struct CircuitTarget {
    /// Signed relay descriptor for the first hop.
    pub relay: Arc<RelayDescriptorSigned>,
    /// Destination exit identifier (must match the exit descriptor).
    pub exit_id: ExitId,
    /// Long-lived X25519 HPKE recipient pubkey of the exit.
    pub exit_x25519_multihop_pubkey: [u8; 32],
}

impl CircuitTarget {
    fn from_config(config: &SupervisorConfig) -> Self {
        Self {
            relay: config.relay.clone(),
            exit_id: config.exit_id,
            exit_x25519_multihop_pubkey: config.exit_x25519_multihop_pubkey,
        }
    }
}

/// Counters scraped through [`MultiHopSupervisor::snapshot`].
///
/// All `Relaxed` ordering: advisory observability data, not control
/// flow.
#[derive(Debug, Default)]
pub struct SupervisorMetrics {
    reconnect_count: AtomicU64,
    last_reconnect_duration_ms: AtomicU64,
}

/// Point-in-time view of [`SupervisorMetrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SupervisorMetricsSnapshot {
    /// Number of completed reconnect cycles (initial connect does NOT
    /// count). A non-zero value means the session survived at least
    /// one mid-session disconnect. Includes both cold (break-before-make)
    /// reconnects AND make-before-break overlap swaps.
    pub reconnect_count: u64,
    /// Wall-clock duration, in milliseconds, of the most recent COLD
    /// reconnect window (from session loss detection to a fresh
    /// session being published on the watch channel). `0` before the
    /// first reconnect completes. Overlap swaps are gapless, so they do
    /// NOT update this (only [`reconnect_count`](Self::reconnect_count)).
    pub last_reconnect_duration_ms: u64,
}

impl SupervisorMetrics {
    /// Allocate a fresh snapshot of the current counters.
    #[must_use]
    pub fn snapshot(&self) -> SupervisorMetricsSnapshot {
        SupervisorMetricsSnapshot {
            reconnect_count: self.reconnect_count.load(Ordering::Relaxed),
            last_reconnect_duration_ms: self.last_reconnect_duration_ms.load(Ordering::Relaxed),
        }
    }
}

/// Watcher receiver alias for the type the pump consumes. `Some` means
/// the supervisor has a live session; `None` means a reconnect is in
/// flight and packets should be dropped (uplink) or the receiver should
/// park on [`watch::Receiver::changed`] (downlink). The published value
/// is a [`MultiHopBundle`]: 1..=N bonded connections behind the API
/// surface of a single session.
pub type ClientWatch = watch::Receiver<Option<Arc<MultiHopBundle>>>;

/// Cloneable control handle over a running supervisor, obtained via
/// [`MultiHopSupervisor::handle`] before `run()` consumes the
/// supervisor. Lets an external component (e.g. a caller's migration
/// watchdog) force a re-dial without tearing anything else
/// down.
#[derive(Clone)]
pub struct SupervisorHandle {
    rx: ClientWatch,
    /// Trigger for a make-before-break overlap reconnect. Shared with
    /// the supervisor's `run` loop, which parks on `notified()` in its serve
    /// select.
    overlap: Arc<Notify>,
    /// The supervisor's live circuit target (shared `Arc<Mutex<_>>`).
    /// [`Self::migrate_to`] swaps it before notifying the overlap, so the
    /// make-before-break dial lands on a DIFFERENT exit (cross-exit
    /// migration) instead of re-dialing the same one.
    target: Arc<Mutex<CircuitTarget>>,
}

impl SupervisorHandle {
    /// Force the supervisor through a reconnect cycle: closes the
    /// currently published session with the dedicated
    /// `WARREN_MH_FORCED_RECONNECT` code, which the supervisor's
    /// `closed()` race observes as a transient loss (`LocallyClosed`,
    /// never a [`RejectionReason`]) and answers with a fresh-socket
    /// redial under the configured backoff. TUN, routes and killswitch
    /// are untouched; the pumps park on the watch channel meanwhile.
    ///
    /// Returns `true` if a live session was closed, `false` if no
    /// session was published (a redial is already in flight; the call
    /// is a no-op).
    #[must_use]
    pub fn force_reconnect(&self) -> bool {
        let bundle = self.rx.borrow().clone();
        match bundle {
            Some(bundle) => {
                bundle.force_close_for_reconnect();
                true
            }
            None => false,
        }
    }

    /// `true` while the supervisor has a live published session.
    #[must_use]
    pub fn has_session(&self) -> bool {
        self.rx.borrow().is_some()
    }

    /// Request a make-before-break overlap reconnect: the supervisor
    /// dials a FRESH session while the current one keeps serving, atomically
    /// swaps the published session onto the new one (the watch transition is
    /// live -> live, never None, so the data plane sees no gap), then closes
    /// the old session after [`OVERLAP_DEFERRED_CLOSE_GRACE`]. Unlike
    /// [`force_reconnect`](Self::force_reconnect) (break-before-make, for a DEAD
    /// path), this keeps the tunnel's live session throughout a planned
    /// re-dial. A no-op when the supervisor is between sessions (the cold dial
    /// covers it) or when the overlap dial fails (the current session is kept).
    ///
    /// ## NOT a cross-exit migration primitive
    ///
    /// The overlap re-dials the exit/relay in THIS supervisor's
    /// [`SupervisorConfig`] (one fixed circuit). It does NOT re-select a
    /// different exit, so it must NOT be wired onto an exit-drain path: a drain
    /// migration must land on a DIFFERENT exit (the daemon's directory
    /// avoid-set), and calling this would just re-dial the SAME
    /// draining exit, gaplessly, back into the drain. Use it only for a
    /// same-circuit re-dial (e.g. a scheduled key/path refresh on a healthy
    /// exit).
    ///
    /// ## Coalescing
    ///
    /// Backed by a [`tokio::sync::Notify`]: a burst of calls collapses to a
    /// single pending overlap, and a call landing while an overlap dial is
    /// already in flight schedules at most ONE more. Do not assume strict 1:1
    /// call-to-overlap.
    pub fn overlap_reconnect(&self) {
        self.overlap.notify_one();
    }

    /// Gap-free **cross-exit** migration: retarget the supervisor at a
    /// DIFFERENT circuit (`new_target`), then trigger the same
    /// make-before-break overlap. The supervisor dials the new exit while
    /// the old one keeps serving, atomically swaps the published session
    /// onto it (the watch transition is live -> live, never `None`), and
    /// defer-closes the old. Subsequent cold reconnects also use the new
    /// target.
    ///
    /// Used to migrate OFF a draining exit without a connectivity gap (the
    /// caller - the daemon's selector - supplies a non-drained exit). Note
    /// that the public egress IP changes with the exit, so established
    /// flows pinned to the old exit's egress will reset; the *tunnel*
    /// itself never drops, so new flows route through the new exit
    /// immediately.
    ///
    /// Like [`Self::overlap_reconnect`], backed by a coalescing
    /// [`tokio::sync::Notify`]: rapid calls collapse, and the LAST
    /// `migrate_to` before the overlap fires wins the target. Same-fleet
    /// only: `operational_pubkey` and the client identity are unchanged.
    pub fn migrate_to(&self, new_target: CircuitTarget) {
        // Set the target BEFORE notifying so the overlap dial that the
        // notify wakes reads the new exit. A lock poisoned by a panicked
        // holder still yields the guard (into_inner): the target is plain
        // data, never left half-written across an await.
        match self.target.lock() {
            Ok(mut guard) => *guard = new_target,
            Err(poisoned) => *poisoned.into_inner() = new_target,
        }
        self.overlap.notify_one();
    }

    /// Derive a [`MigrateHandle`]: a migrate-only handle that does NOT hold a
    /// watch receiver, so it can be stored by an external owner (the daemon's
    /// `ParametersGenerator`) across tunnel lifetimes WITHOUT keeping a torn
    /// down supervisor alive. A [`SupervisorHandle`] holds `rx`, so storing a
    /// full handle would block `run()`'s "no remaining receivers" shutdown and
    /// leak the supervisor on teardown.
    #[must_use]
    pub fn migrate_handle(&self) -> MigrateHandle {
        MigrateHandle {
            overlap: self.overlap.clone(),
            target: self.target.clone(),
        }
    }
}

/// Migrate-only control handle: triggers a gap-free cross-exit migration
/// without holding a watch receiver. Obtained via
/// [`SupervisorHandle::migrate_handle`] or [`MultiHopSupervisor::migrate_handle`].
///
/// Safe to store across tunnel lifetimes: unlike [`SupervisorHandle`] it
/// carries no `rx`, so a stale handle never blocks the supervisor's
/// no-receivers shutdown. A `migrate_to` on a handle whose supervisor has
/// already terminated is a harmless no-op (the overlap arm never runs).
#[derive(Clone)]
pub struct MigrateHandle {
    overlap: Arc<Notify>,
    target: Arc<Mutex<CircuitTarget>>,
}

impl MigrateHandle {
    /// Gap-free cross-exit migration: retarget the supervisor at `new_target`
    /// then trigger the make-before-break overlap. Identical semantics to
    /// [`SupervisorHandle::migrate_to`].
    pub fn migrate_to(&self, new_target: CircuitTarget) {
        match self.target.lock() {
            Ok(mut guard) => *guard = new_target,
            Err(poisoned) => *poisoned.into_inner() = new_target,
        }
        self.overlap.notify_one();
    }
}

/// Long-lived task that keeps a [`MultiHopClient`] alive across
/// mid-session disconnects.
///
/// Construct with [`MultiHopSupervisor::new`], spawn the returned
/// [`MultiHopSupervisor::run`] future, and let the binary's pump
/// consume the watch channel returned by `new`.
pub struct MultiHopSupervisor {
    config: SupervisorConfig,
    tx: watch::Sender<Option<Arc<MultiHopBundle>>>,
    /// Published once when the exit definitively rejects the session
    /// (e.g. pubkey not allowlisted). Consumers (the tunnel monitor)
    /// subscribe via [`MultiHopSupervisor::fatal_rx`] and convert it to
    /// a clean tunnel error state, so a rejection never looks like a
    /// transient reconnect.
    fatal_tx: watch::Sender<Option<RejectionReason>>,
    /// Published (latched true) when [`DATAPATH_DEAD_FATAL_REDIALS`]
    /// consecutive watchdog-forced redials each carried zero application
    /// downlink: the tunnel establishes but nothing flows back. Signal-only,
    /// the supervisor keeps redialing (a late recovery still heals), but
    /// subscribers must stop presenting the tunnel as healthy.
    datapath_dead_tx: watch::Sender<bool>,
    metrics: Arc<SupervisorMetrics>,
    /// Make-before-break overlap trigger. `SupervisorHandle`s share a
    /// clone and `notify_one()` it; the serve select parks on `notified()`.
    overlap: Arc<Notify>,
    /// The live circuit target the dial path reads on every (re)dial.
    /// Initialized from `config`; [`SupervisorHandle::migrate_to`] swaps it
    /// to retarget a fresh dial at a DIFFERENT exit, which the existing
    /// make-before-break overlap then swaps in gap-free (cross-exit
    /// migration). `SupervisorHandle`s share the same `Arc<Mutex<_>>`.
    target: Arc<Mutex<CircuitTarget>>,
    /// Inner IPv4 the exit assigned to the LAST established session.
    /// Redials send it as the `prefer_ipv4` session-placement hint so the
    /// exit keeps the session on its address (overlap and fast reconnects
    /// join the predecessor instead of minting a new IP); a first session
    /// sends the 0.0.0.0 session-fresh sentinel instead, which is what
    /// stops two independent same-wallet sessions from sharing one inner
    /// IP and stealing each other's downlink.
    last_assigned_v4: Mutex<Option<std::net::Ipv4Addr>>,
}

/// Consecutive watchdog-forced redials, each of a session whose ENTIRE life
/// carried zero application downlink, before the supervisor escalates the
/// dead datapath as fatal instead of redialing silently forever. Three
/// windows (~45 s at the default 15 s watches) tolerate a slow one-off
/// recovery while bounding how long a dead tunnel may masquerade as
/// Connected (2026-07-13 carrier-blackhole incident: the UI said Connected
/// for hours over a datapath that egressed nothing).
const DATAPATH_DEAD_FATAL_REDIALS: u32 = 3;

/// Escalation counter behind [`MultiHopSupervisor::datapath_dead_rx`].
#[derive(Default)]
struct DeadPathEscalation {
    consecutive: u32,
}

/// Downlink volume a closing session is judged on by the dead-datapath
/// escalation. Sampled from the bundle's real-traffic accounting, NEVER from
/// quinn frame counters: an armed exit's DAITA dummies advance
/// `frame_rx.datagram` on a fully dead tunnel, which would reset the
/// escalation on every close and permanently suppress the fatal.
pub(crate) fn session_escalation_downlink(bundle: &MultiHopBundle) -> u64 {
    bundle.real_traffic_totals().1
}

impl DeadPathEscalation {
    /// Record a session close. `watchdog_forced` is true when a dead-path
    /// watch (RX silence, one-way app traffic, uplink loss) forced the
    /// close; `downlink_frames` is the application datagrams the session
    /// received over its whole life. Returns true when the dead-datapath
    /// pattern has repeated [`DATAPATH_DEAD_FATAL_REDIALS`] times in a row.
    fn record_close(&mut self, watchdog_forced: bool, downlink_frames: u64) -> bool {
        if watchdog_forced && downlink_frames == 0 {
            self.consecutive += 1;
        } else {
            self.consecutive = 0;
        }
        self.consecutive >= DATAPATH_DEAD_FATAL_REDIALS
    }
}

/// Outcome of [`MultiHopSupervisor::establish_session`]: a live (un-published)
/// session ready to publish, or a definitive policy rejection from the exit.
enum Established {
    Session {
        bundle: Arc<MultiHopBundle>,
        primary: Arc<MultiHopClient>,
    },
    Rejected(RejectionReason),
}

impl MultiHopSupervisor {
    /// Build a supervisor pre-loaded with the dial config. Returns the
    /// supervisor itself plus a [`ClientWatch`] the binary hands to the
    /// pump tasks. Call [`MultiHopSupervisor::metrics`] before
    /// [`MultiHopSupervisor::run`] consumes `self` if observability is
    /// needed.
    #[must_use]
    pub fn new(config: SupervisorConfig) -> (Self, ClientWatch) {
        let (tx, rx) = watch::channel(None);
        let (fatal_tx, _fatal_rx) = watch::channel(None);
        let (datapath_dead_tx, _datapath_dead_rx) = watch::channel(false);
        let target = Arc::new(Mutex::new(CircuitTarget::from_config(&config)));
        let supervisor = Self {
            config,
            tx,
            fatal_tx,
            datapath_dead_tx,
            metrics: Arc::new(SupervisorMetrics::default()),
            overlap: Arc::new(Notify::new()),
            target,
            last_assigned_v4: Mutex::new(None),
        };
        (supervisor, rx)
    }

    /// Subscribe to the supervisor's terminal-rejection signal. The
    /// receiver observes `Some(reason)` exactly once if the exit
    /// definitively refuses the session (e.g. the client pubkey is not
    /// on the subscription allowlist), after which [`Self::run`] returns
    /// `Err(MultiHopError::Rejected)`. Call this BEFORE [`Self::run`]
    /// consumes `self`. The tunnel monitor races this against the
    /// initial-session wait so a rejection surfaces promptly as a clean,
    /// cancelable error state instead of a fake "Connected".
    #[must_use]
    pub fn fatal_rx(&self) -> watch::Receiver<Option<RejectionReason>> {
        self.fatal_tx.subscribe()
    }

    /// Subscribe to the dead-datapath escalation signal. The receiver
    /// observes `true` once [`DATAPATH_DEAD_FATAL_REDIALS`] consecutive
    /// watchdog-forced redials each carried ZERO application downlink over
    /// the session's whole life: the tunnel keeps establishing (handshake,
    /// setup, keep-alives) while the user's traffic goes nowhere. Consumers
    /// (the tunnel monitor) must convert it to a visible error state instead
    /// of letting the tunnel masquerade as Connected; the supervisor itself
    /// keeps redialing so a late network recovery still heals the session.
    /// Call BEFORE [`Self::run`] consumes `self`.
    #[must_use]
    pub fn datapath_dead_rx(&self) -> watch::Receiver<bool> {
        self.datapath_dead_tx.subscribe()
    }

    /// Borrow the metrics handle so the caller can scrape counters
    /// while [`MultiHopSupervisor::run`] is executing on a separate
    /// task.
    #[must_use]
    pub fn metrics(&self) -> Arc<SupervisorMetrics> {
        self.metrics.clone()
    }

    /// Build a [`SupervisorHandle`] for external reconnect control.
    /// Call BEFORE [`Self::run`] consumes `self`. The handle holds a
    /// watch receiver: it does NOT keep the supervisor alive, and a
    /// handle kept after teardown simply observes `None` forever.
    ///
    /// NOTE: because the handle holds a receiver, `run()`'s
    /// "no remaining receivers" shutdown check only fires once every
    /// handle AND every pump receiver is dropped. Owners must drop the
    /// handle (abort the watchdog task) during teardown, before or
    /// alongside the pumps.
    #[must_use]
    pub fn handle(&self) -> SupervisorHandle {
        SupervisorHandle {
            rx: self.tx.subscribe(),
            overlap: self.overlap.clone(),
            target: self.target.clone(),
        }
    }

    /// Build a migrate-only [`MigrateHandle`] WITHOUT subscribing a watch
    /// receiver, so the owner can store it across tunnel lifetimes without
    /// pinning a torn down supervisor alive (cf. [`MigrateHandle`]). Call
    /// before [`Self::run`] consumes `self`.
    #[must_use]
    pub fn migrate_handle(&self) -> MigrateHandle {
        MigrateHandle {
            overlap: self.overlap.clone(),
            target: self.target.clone(),
        }
    }

    /// Run the supervise-and-reconnect loop forever.
    ///
    /// Returns:
    /// - `Ok(())` if the watch channel has no remaining receivers
    ///   (binary shut down or pump dropped the receiver).
    /// - `Err(MultiHopError)` if a non-retriable error surfaces on a
    ///   dial (PKI mismatch, TLS provider failure, decoder rejection).
    ///   Retriable errors (bind, connect, handshake) are absorbed by
    ///   the backoff and never escape this function.
    ///
    /// # Errors
    ///
    /// See [`MultiHopError`]. The supervisor only surfaces
    /// non-retriable variants; the cold-start backoff handles the
    /// transient network failures.
    pub async fn run(self) -> Result<(), MultiHopError> {
        let mut first_session = true;
        let mut dead_path_escalation = DeadPathEscalation::default();
        loop {
            // Non-racy shutdown check: if every pump receiver is already
            // gone (the tunnel monitor tore down and aborted the pumps),
            // do not start another dial - `connect_with_unbounded_retry`
            // would otherwise spin through the backoff against a relay
            // nobody is listening for until the next `tx.send` finally
            // fails. Cheap, exact, and avoids burning the radio during a
            // teardown window.
            if self.tx.is_closed() {
                tracing::info!("supervisor watch has no receivers, terminating before dial");
                return Ok(());
            }

            let reconnect_start = Instant::now();
            // Race the dial against the receivers disappearing: a teardown
            // landing while the retry loop is spinning would otherwise never
            // be observed (the loop-top check runs only between sessions,
            // and a dial that never succeeds re-enters neither).
            let client = tokio::select! {
                biased;
                () = self.tx.closed() => {
                    tracing::info!(
                        "supervisor watch receivers dropped during dial, terminating"
                    );
                    return Ok(());
                }
                result = self.connect_with_unbounded_retry() => result?,
            };
            let primary = Arc::new(client);

            if !first_session {
                let duration_ms =
                    u64::try_from(reconnect_start.elapsed().as_millis()).unwrap_or(u64::MAX);
                self.metrics
                    .last_reconnect_duration_ms
                    .store(duration_ms, Ordering::Relaxed);
                tracing::info!(duration_ms, "multi-hop session re-established");
            } else {
                tracing::info!("multi-hop session initially established");
            }

            // Run the primary's setup round-trip, then publish the
            // PRIMARY-ONLY bundle immediately: the datapath is correct
            // with one session (the secondaries only add throughput),
            // so gating the publish on the full bond would serialize
            // `n_connections - 1` handshakes + setup RTTs into the
            // user-visible connect path. The secondaries bond in the
            // background onto the same published bundle
            // (`spawn_background_bond`).
            let mut primary = primary;
            // One token stack per session: the primary and every bonded
            // secondary present it, so they share one anonymous serial + IP.
            let session_tokens = self.select_session_tokens();
            let assign = match self
                .setup_primary(&primary, session_tokens.as_deref())
                .await
            {
                Ok(assign) => assign,
                Err(reason) => {
                    let _ = self.fatal_tx.send(Some(reason));
                    tracing::warn!(%reason, "multi-hop session rejected by exit at setup; surfacing fatal");
                    return Err(MultiHopError::Rejected(reason));
                }
            };
            let mut bundle = MultiHopBundle::new_unsealed(vec![primary.clone()]);

            // Publish the live session. If the receiver side dropped,
            // shut down cleanly (sealing first so the unsealed bundle's
            // MUST-seal contract holds on this exit path too; Drop
            // still closes the primary regardless).
            if self.tx.send(Some(bundle.clone())).is_err() {
                bundle.seal();
                tracing::info!("supervisor watch has no receivers, terminating cleanly");
                return Ok(());
            }
            // Per-session QUIC path probe (cwnd/rtt/loss/datagram buffer
            // headroom, 5s cadence); the background bond spawns another
            // probe over the secondaries it attaches.
            drop(warrenguard_transport_core::spawn_path_probe(
                "client-mh",
                bundle.clone_connections(),
                None,
            ));
            self.spawn_background_bond(&bundle, assign, session_tokens);
            self.notify_on_reconnect(first_session);
            first_session = false;

            // Inner serve loop. The current session serves until it dies (cold
            // path -> break to the outer cold dial with a brief gap) OR a
            // make-before-break overlap swaps in a fresh session with NO
            // data-plane gap. The race covers: the connection closing, all
            // receivers dropping (teardown), RX-silence / uplink-dead dead-path
            // detection (avoids quinn's ~40s idle timeout), and the overlap
            // trigger.
            loop {
                let mut watchdog_forced = false;
                let close_err = tokio::select! {
                    err = bundle.closed() => err,
                    () = self.tx.closed() => {
                        tracing::info!(
                            "supervisor watch receivers dropped while session alive, terminating"
                        );
                        return Ok(());
                    }
                    () = dead_path_watch({
                        let sample = bundle.clone();
                        move || {
                            sample
                                .clients()
                                .iter()
                                .map(|c| c.quinn_stats().udp_rx.datagrams)
                                .sum()
                        }
                    }) => {
                        tracing::warn!(
                            silent_secs = dead_path_secs(),
                            "no datagram received on any bonded session; forcing redial"
                        );
                        watchdog_forced = true;
                        bundle.force_close_for_reconnect();
                        bundle.closed().await
                    }
                    () = app_downlink_dead_watch({
                        let sample = bundle.clone();
                        // Real-packet counters, NOT Quinn's datagram frames:
                        // an armed exit rains 0xFF dummies on the downlink
                        // and a DAITA client pads its uplink, so frame
                        // counters keep a dead tunnel looking alive (and an
                        // idle DAITA session would look one-way and be
                        // spuriously redialed).
                        move || sample.real_traffic_totals()
                    }) => {
                        tracing::warn!(
                            window_secs = app_downlink_dead_secs(),
                            "app datagrams flowing up with zero coming back; forcing redial"
                        );
                        watchdog_forced = true;
                        bundle.force_close_for_reconnect();
                        bundle.closed().await
                    }
                    () = uplink_dead_watch({
                        let sample = bundle.clone();
                        move || {
                            let mut sent = 0u64;
                            let mut lost = 0u64;
                            for c in sample.clients() {
                                let p = c.quinn_stats().path;
                                sent += p.sent_packets;
                                lost += p.lost_packets;
                            }
                            (sent, lost)
                        }
                    }) => {
                        tracing::warn!(
                            "uplink dead (sends not being acked) across the bundle; forcing redial"
                        );
                        watchdog_forced = true;
                        bundle.force_close_for_reconnect();
                        bundle.closed().await
                    }
                    () = self.overlap.notified() => {
                        // Make-before-break: dial a FRESH session while
                        // the current one keeps serving, then atomically swap
                        // the published session onto it (the watch transition is
                        // live -> live, never None, so the data plane sees no
                        // gap) and defer-close the old one. A failed overlap
                        // dial keeps the current session (the cold path still
                        // covers a real death).
                        match self.try_overlap().await {
                            Some((new_bundle, new_primary)) => {
                                if !pre_swap_allows(
                                    self.config.pre_swap_check.as_ref(),
                                    new_bundle.clone(),
                                )
                                .await
                                {
                                    // Abort path: same as a failed overlap
                                    // dial, the current session keeps
                                    // serving untouched.
                                    new_bundle.force_close_for_reconnect();
                                    drop(new_primary);
                                    tracing::info!(
                                        "overlap swap aborted by pre-swap check; keeping current session"
                                    );
                                    continue;
                                }
                                if self.tx.send(Some(new_bundle.clone())).is_err() {
                                    return Ok(());
                                }
                                if let Some(observer) = self.config.on_overlap_swapped.as_ref() {
                                    observer(&self.current_target());
                                }
                                drop(warrenguard_transport_core::spawn_path_probe(
                                    "client-mh",
                                    new_bundle.clone_connections(),
                                    None,
                                ));
                                self.notify_on_reconnect(false);
                                self.metrics.reconnect_count.fetch_add(1, Ordering::Relaxed);
                                Self::spawn_deferred_close(bundle.clone(), primary.clone());
                                tracing::info!(
                                    "multi-hop overlap migration: swapped to a fresh session, old draining"
                                );
                                bundle = new_bundle;
                                primary = new_primary;
                                continue;
                            }
                            None => continue,
                        }
                    }
                };

                // The current session closed (cold path).
                //
                // A definitive policy rejection (the exit closed with a known
                // rejection code) is not a transient loss: redialing hits the
                // same refusal, so surface it as a clean error state instead of
                // a reconnect storm.
                if let Some(reason) = multihop::rejection_from_conn_error(&close_err) {
                    let _ = self.fatal_tx.send(Some(reason));
                    tracing::warn!(%reason, "multi-hop session rejected by exit; surfacing fatal");
                    bundle.force_close_for_reconnect();
                    let _ = self.tx.send(None);
                    return Err(MultiHopError::Rejected(reason));
                }

                // Dead-datapath escalation: a session whose whole life carried
                // zero application downlink AND that a watchdog had to kill is
                // one dead window; enough of them in a row must become visible
                // to the user instead of an endless silent redial loop.
                let session_downlink = session_escalation_downlink(&bundle);
                if dead_path_escalation.record_close(watchdog_forced, session_downlink) {
                    let _ = self.datapath_dead_tx.send(true);
                    tracing::error!(
                        consecutive = DATAPATH_DEAD_FATAL_REDIALS,
                        "datapath dead: sessions establish but carry zero downlink; \
                         surfacing the fatal signal while redials continue"
                    );
                }

                // Increment BEFORE publishing None so a reader that observes
                // None always sees a coherent reconnect_count >= 1.
                self.metrics.reconnect_count.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    reason = %close_err,
                    "multi-hop session lost, scheduling reconnect"
                );
                // One dead connection condemns the whole bundle: close the
                // surviving siblings so the exit releases their slots.
                bundle.force_close_for_reconnect();
                // Publish None so uplink drops packets and downlink parks; drop
                // the supervisor's strong refs so the watch holds the last one.
                drop(bundle);
                drop(primary);
                if self.tx.send(None).is_err() {
                    return Ok(());
                }
                break;
            }
        }
    }

    /// Dial ONE fresh QUIC + handshake session to the relay -> exit, no retry.
    /// The cold-dial retry loop ([`connect_with_unbounded_retry`]) and the warm
    /// make-before-break overlap dial ([`try_overlap`], a best-effort single
    /// attempt) both build on this.
    /// Snapshot the live circuit target (relay + exit), cloning out of the
    /// mutex so no lock is held across the dial's awaits.
    fn current_target(&self) -> CircuitTarget {
        match self.target.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The Quinn transport config for a (re)dial, resolved from the same
    /// obfuscation and idle-cover switches for the primary and every bonded
    /// secondary. `idle_cover` disables the fixed keep-alive PING on the
    /// obfuscation or multihop profile; when it is `false` this is
    /// byte-identical to the pre-ADR-0006 dial (`_with_gso`), because
    /// `_with_idle_cover(gso, false)` is defined as the `_with_gso` config.
    fn dial_transport_config(config: &SupervisorConfig) -> Arc<quinn::TransportConfig> {
        if config.use_warren_obfuscation {
            warren_transport_config_client_with_idle_cover(config.enable_gso, config.idle_cover)
        } else {
            warren_transport_config_client_multihop_with_idle_cover(
                config.enable_gso,
                config.idle_cover,
            )
        }
    }

    async fn connect_once(&self) -> Result<MultiHopClient, MultiHopError> {
        // Read the LIVE target (not config): a `migrate_to` retargets this
        // so the next dial lands on a different exit (cross-exit migration).
        let target = self.current_target();
        MultiHopClient::connect_with_transport_config(
            &target.relay,
            target.exit_id,
            &target.exit_x25519_multihop_pubkey,
            &self.config.operational_pubkey,
            &self.config.client_signing,
            self.config.bind_addr,
            Self::dial_transport_config(&self.config),
            self.config.socket_bypass,
        )
        .await
    }

    /// Run the primary's reliable setup-stream round-trip and detect a
    /// definitive policy rejection. Returns the decoded `IpAssign`
    /// (already published on the [`IpAssignChannel`]) or `None` when
    /// the exit stayed on its legacy first-frame path.
    ///
    /// # Errors
    ///
    /// The exit's rejection reason: a definitive policy refusal must
    /// NOT become a live session (it would be a fake "Connected" + a
    /// reconnect storm). It surfaces as the sealed detail on the setup
    /// stream (specific cause) or the opaque close code.
    /// The anonymous v7 token stack for ONE session, or `None` when no
    /// provider is wired (v6) or the provider yielded an empty stack (no token
    /// available this epoch, so fall back to v6 rather than fail closed). Called
    /// once per session establishment; the same stack feeds the primary and
    /// every bonded secondary so they share one serial and one sticky IP.
    fn select_session_tokens(&self) -> Option<Vec<SessionToken>> {
        let provider = self.config.session_token_provider.as_ref()?;
        let tokens = provider();
        (!tokens.is_empty()).then_some(tokens)
    }

    async fn setup_primary(
        &self,
        primary: &Arc<MultiHopClient>,
        session_tokens: Option<&[SessionToken]>,
    ) -> Result<Option<IpAssignSpec>, RejectionReason> {
        // The first multi-hop frame carries the HPKE `encapsulated_key`; on a
        // warming path the first datagram is frequently lost, so the SETUP
        // round-trip rides a reliable bidi stream (converges in one call). The
        // exit's `IpAssign` reply drives the reassign flow. With v7 tokens the
        // request is an anonymous `IpRequestV7` (no wallet pubkey); otherwise
        // the v6 wallet-signed `IpRequest` + PoP.
        // Session-placement hint: a redial names its session's current
        // address so the exit keeps it there (joining, then stale-evicting,
        // the predecessor); a first session sends the session-fresh
        // sentinel so it can never be co-housed with another live session
        // of the same identity. Exits predating the hint ignore it.
        let placement = Some(
            self.last_assigned_v4
                .lock()
                .expect("last_assigned_v4 lock poisoned")
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        );
        let setup_result = primary
            .setup_over_stream_with_options(
                Some(&self.config.client_signing),
                self.config.wants_ipv6,
                self.config.enable_daita,
                session_tokens,
                placement,
            )
            .await;

        let sealed_detail = setup_result
            .as_ref()
            .ok()
            .and_then(|reply| Self::decode_sealed_rejection(reply));
        if let Some(reason) = sealed_detail.or_else(|| primary.rejection_reason()) {
            return Err(reason);
        }
        Ok(match setup_result {
            Ok(reply) => {
                let spec = Self::decode_ip_assign(&reply);
                if let Some(spec) = &spec {
                    self.publish_setup_ip_assign(spec);
                    *self
                        .last_assigned_v4
                        .lock()
                        .expect("last_assigned_v4 lock poisoned") = Some(spec.assigned);
                }
                spec
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "multi-hop setup-stream round-trip failed; session falls back to its bootstrap IP"
                );
                None
            }
        })
    }

    /// Dial the `want - 1` bonded secondaries in parallel and return
    /// the ones that came up with the primary's sticky IP, in index
    /// order. Best-effort: bonding failures only reduce capacity.
    ///
    /// Bond secondaries to the SAME circuit the primary just dialed. A
    /// migration racing in here would change the snapshot, but a
    /// secondary on a different exit fails `dial_secondary`'s sticky
    /// IpAssign check and is skipped (safe).
    async fn bond_secondaries(
        config: &SupervisorConfig,
        target: &CircuitTarget,
        primary_spec: IpAssignSpec,
        want: usize,
        session_tokens: Option<Vec<SessionToken>>,
    ) -> Vec<Arc<MultiHopClient>> {
        let mut dials = tokio::task::JoinSet::new();
        for index in 1..want {
            let config = config.clone();
            let target = target.clone();
            // Every bonded connection presents the SAME token stack as the
            // primary so it resolves to the same anonymous serial and the exit
            // hands it the same sticky IP.
            let tokens = session_tokens.clone();
            dials.spawn(async move {
                let secondary =
                    Self::dial_secondary(&config, &target, index, primary_spec, tokens.as_deref())
                        .await;
                (index, secondary)
            });
        }
        let mut secondaries: Vec<(usize, Arc<MultiHopClient>)> = Vec::new();
        while let Some(joined) = dials.join_next().await {
            if let Ok((index, Some(secondary))) = joined {
                secondaries.push((index, secondary));
            }
        }
        secondaries.sort_by_key(|(index, _)| *index);
        secondaries.into_iter().map(|(_, c)| c).collect()
    }

    /// Bond the configured secondaries onto an already-published
    /// unsealed `bundle` from a detached task, then seal it.
    ///
    /// Each secondary is attached to the bundle THE MOMENT its own dial
    /// completes, not after the slowest sibling joins. This matters:
    /// the exit registers a secondary's downlink sender and begins
    /// fanning live flows to it as soon as ITS setup finishes, so a
    /// batch-attach would leave downlink queuing in quinn's datagram
    /// buffer (readerless) until the whole JoinSet drained, a
    /// seconds-scale stall for the affected flows in the exact connect
    /// window this feature optimizes. Incremental attach shrinks that
    /// gap to ~0.
    ///
    /// The task holds only a `Weak`: if the session dies or is torn
    /// down mid-bond, `upgrade()` fails and the late secondary is
    /// closed instead of leaking as a zombie exit slot (and a secondary
    /// attached in the race between `force_close_for_reconnect` and the
    /// final drop is closed by the bundle's `Drop`).
    fn spawn_background_bond(
        &self,
        bundle: &Arc<MultiHopBundle>,
        primary_assign: Option<IpAssignSpec>,
        session_tokens: Option<Vec<SessionToken>>,
    ) {
        let want = self.config.n_connections.clamp(1, MAX_BONDED_CONNECTIONS);
        let Some(primary_spec) = primary_assign else {
            if want > 1 {
                tracing::warn!(
                    requested = want,
                    "bonding requested but the exit returned no IpAssign; \
                     staying on a single connection"
                );
            }
            bundle.seal();
            return;
        };
        if want <= 1 {
            bundle.seal();
            return;
        }
        let weak = Arc::downgrade(bundle);
        let config = self.config.clone();
        let target = self.current_target();
        tokio::spawn(async move {
            let mut dials = tokio::task::JoinSet::new();
            for index in 1..want {
                let config = config.clone();
                let target = target.clone();
                // Same token stack as the primary (shared serial -> same IP).
                let tokens = session_tokens.clone();
                dials.spawn(async move {
                    Self::dial_secondary(&config, &target, index, primary_spec, tokens.as_deref())
                        .await
                });
            }
            let mut bonded = 1usize;
            while let Some(joined) = dials.join_next().await {
                let Ok(Some(secondary)) = joined else {
                    continue;
                };
                // Attach on arrival so this secondary's reader is live
                // before the exit's downlink fan-out reaches it.
                match weak.upgrade() {
                    Some(bundle) if bundle.add_client(secondary.clone()) => {
                        bonded += 1;
                        drop(warrenguard_transport_core::spawn_path_probe(
                            "client-mh",
                            vec![secondary.clone_conn()],
                            None,
                        ));
                    }
                    _ => secondary.force_close_for_reconnect(),
                }
            }
            if let Some(bundle) = weak.upgrade() {
                bundle.seal();
                tracing::info!(
                    bonded,
                    requested = want,
                    "multi-hop bonded session assembled"
                );
            }
        });
    }

    /// Run the setup round-trip, then bond the secondaries INLINE and
    /// assemble a sealed [`MultiHopBundle`]. Only the make-before-break
    /// overlap dial uses this: the current session keeps serving during
    /// an overlap, so there is no user-visible latency to shave, and
    /// swapping in a full-width bundle avoids a throughput dip.
    async fn establish_session(&self, primary: Arc<MultiHopClient>) -> Established {
        // One token stack for this whole session (primary + secondaries).
        let session_tokens = self.select_session_tokens();
        let primary_assign = match self
            .setup_primary(&primary, session_tokens.as_deref())
            .await
        {
            Ok(assign) => assign,
            Err(reason) => return Established::Rejected(reason),
        };

        // Bonded secondaries: best-effort extra connections under the same
        // identity (the exit's sticky allocator gives them ONE inner IP).
        // Requires the primary's `IpAssign` as the stickiness witness.
        let mut clients = vec![primary.clone()];
        let want = self.config.n_connections.clamp(1, MAX_BONDED_CONNECTIONS);
        if want > 1 {
            match primary_assign {
                Some(primary_spec) => {
                    let target = self.current_target();
                    clients.extend(
                        Self::bond_secondaries(
                            &self.config,
                            &target,
                            primary_spec,
                            want,
                            session_tokens.clone(),
                        )
                        .await,
                    );
                    tracing::info!(
                        bonded = clients.len(),
                        requested = want,
                        "multi-hop bonded session assembled"
                    );
                }
                None => tracing::warn!(
                    requested = want,
                    "bonding requested but the exit returned no IpAssign; \
                     staying on a single connection"
                ),
            }
        }
        Established::Session {
            bundle: MultiHopBundle::new(clients),
            primary,
        }
    }

    /// Make-before-break warm dial: a best-effort SINGLE connect +
    /// establish while the CURRENT session keeps serving. Returns the new
    /// `(bundle, primary)` on success, or `None` to keep the current session
    /// (a failed or rejected overlap dial must never tear down the still
    /// healthy current session - the natural cold path covers a real death).
    async fn try_overlap(&self) -> Option<(Arc<MultiHopBundle>, Arc<MultiHopClient>)> {
        let primary = match self.connect_once().await {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::warn!(error = %e, "overlap dial failed; keeping the current session");
                return None;
            }
        };
        match self.establish_session(primary).await {
            Established::Session { bundle, primary } => Some((bundle, primary)),
            Established::Rejected(reason) => {
                tracing::warn!(%reason, "overlap dial rejected by exit; keeping the current session");
                None
            }
        }
    }

    /// Close an OLD bundle after a grace once a make-before-break overlap has
    /// swapped to a new one, so in-flight downlink packets on the old session
    /// finish draining before its connections go away.
    fn spawn_deferred_close(old: Arc<MultiHopBundle>, old_primary: Arc<MultiHopClient>) {
        tokio::spawn(async move {
            tokio::time::sleep(OVERLAP_DEFERRED_CLOSE_GRACE).await;
            old.force_close_for_reconnect();
            drop(old_primary);
        });
    }

    /// Fire the [`SupervisorConfig::on_reconnect`] observer when a
    /// reconnect (not the initial connect) just completed. Extracted as
    /// a helper so the dispatch logic is testable without a real QUIC
    /// connection: tests can drive this directly with a counter-bumping
    /// observer and assert the gate (first_session vs subsequent
    /// publication).
    /// Decode the setup-stream reply plaintext as an HPKE-sealed
    /// rejection detail (`Rejected` -> not authorized, `IpExhausted` ->
    /// pool exhausted), or `None` for a normal (or undecodable) reply.
    /// This is how the client learns the rejection cause: the
    /// relay-facing close code is deliberately opaque.
    fn decode_sealed_rejection(reply: &[u8]) -> Option<RejectionReason> {
        let msg = warrenguard_multihop::try_decode_control(reply)
            .ok()
            .flatten()?;
        RejectionReason::from_sealed_detail(&msg)
    }

    /// Decode the setup-stream reply plaintext into an [`IpAssignSpec`].
    /// `None` for a non-`IpAssign` reply (the session keeps its
    /// bootstrap IP) or a decode failure (logged).
    fn decode_ip_assign(reply: &[u8]) -> Option<IpAssignSpec> {
        match warrenguard_multihop::try_decode_control(reply) {
            Ok(Some(msg)) => {
                let spec = IpAssignSpec::from_control(&msg);
                if spec.is_none() {
                    // No-log: print only the variant discriminant, never the
                    // message body via `Debug` - a hostile relay/exit could
                    // otherwise smuggle a variant carrying a client pubkey
                    // (`IpRequest`/`IpRequestV7`) into a debug log by
                    // replying with an unexpected control message. Mirrors
                    // `supervised_pump::dispatch_control_message`'s no-log
                    // policy for exactly the same reason.
                    tracing::debug!(
                        variant = control_message_variant_name(&msg),
                        "setup-stream reply is not an IpAssign; ignoring"
                    );
                }
                spec
            }
            Ok(None) => {
                tracing::debug!("setup-stream reply is not a control message; ignoring");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "setup-stream reply control decode failed");
                None
            }
        }
    }

    /// Surface the primary session's `IpAssign`: capability-echo warning
    /// for a denied v6 request, then publication on the configured
    /// [`IpAssignChannel`] so the orchestrator's reassign task installs
    /// the exit-allocated addressing. No channel ⇒ log-only.
    fn publish_setup_ip_assign(&self, spec: &IpAssignSpec) {
        // Capability echo: if we asked for v6 but the exit did not grant
        // one (`ipv6: None` in the reply), surface it LOUDLY rather than
        // silently going v4-only. The presence of `assigned_v6` is the
        // exit's authoritative answer.
        if self.config.wants_ipv6 && spec.assigned_v6.is_none() {
            tracing::warn!(
                "IPv6 was requested but this exit did NOT grant it; \
                 staying IPv4-only - IPv6 is unavailable on this exit \
                 (surfaced, NOT a silent fallback)"
            );
        }
        let Some(channel) = self.config.ip_assign_channel.as_ref() else {
            return;
        };
        // No-log policy (matches `run_reassign_loop`'s INV-3 in
        // supervised_pump.rs): the v4 tunnel address is a shared /24-scale
        // subnet allocation, low sensitivity even logged in full, so it is
        // printed at INFO for operability; the v6 allocation is a
        // globally-routable, effectively per-session client identifier, so
        // only its PRESENCE (`dual_stack`) is logged here, never the value.
        tracing::info!(
            assigned = %spec.assigned,
            gateway = %spec.gateway,
            prefix_len = spec.prefix_len,
            dual_stack = spec.assigned_v6.is_some(),
            "setup-stream returned IpAssign; publishing on the IpAssignChannel"
        );
        channel.publish(*spec);
    }

    /// Dial one bonded secondary connection: same identity, same relay,
    /// same exit. Best-effort with two quick attempts (a secondary is
    /// optional capacity; the session runs regardless). The secondary's
    /// own setup-stream `IpAssign` must match the primary's sticky
    /// allocation: a mismatch means the exit cannot fan its downlink to
    /// this connection, so it is closed and skipped.
    async fn dial_secondary(
        config: &SupervisorConfig,
        target: &CircuitTarget,
        index: usize,
        primary_spec: IpAssignSpec,
        session_tokens: Option<&[SessionToken]>,
    ) -> Option<Arc<MultiHopClient>> {
        let bind_addr = secondary_bind_addr(config.bind_addr);
        for attempt in 0..2u8 {
            let result = MultiHopClient::connect_with_transport_config(
                &target.relay,
                target.exit_id,
                &target.exit_x25519_multihop_pubkey,
                &config.operational_pubkey,
                &config.client_signing,
                bind_addr,
                Self::dial_transport_config(config),
                config.socket_bypass,
            )
            .await;
            let client = match result {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    tracing::warn!(index, attempt, error = %e, "bonded secondary dial failed");
                    // A deliberate refusal (drained node) is deterministic:
                    // the second attempt would hit the same answer, so stop
                    // here. The primary dial path owns the retarget signal
                    // (`on_dial_refused`); a secondary is optional capacity.
                    if e.dial_refusal().is_some() {
                        return None;
                    }
                    continue;
                }
            };
            // Join hint: a bonded secondary names its session's address so
            // a per-session exit lands it on the primary's IP even when
            // another live session of the same identity holds the sticky
            // binding.
            let setup = client
                .setup_over_stream_with_options(
                    Some(&config.client_signing),
                    config.wants_ipv6,
                    config.enable_daita,
                    session_tokens,
                    Some(primary_spec.assigned),
                )
                .await;
            if let Some(reason) = client.rejection_reason() {
                tracing::warn!(index, %reason, "bonded secondary rejected at setup; skipping");
                return None;
            }
            let spec = match setup {
                Ok(reply) => Self::decode_ip_assign(&reply),
                Err(e) => {
                    tracing::warn!(index, attempt, error = %e, "bonded secondary setup failed");
                    continue;
                }
            };
            match spec {
                Some(spec)
                    if spec.assigned == primary_spec.assigned
                        && spec.assigned_v6 == primary_spec.assigned_v6 =>
                {
                    tracing::debug!(index, assigned = %spec.assigned, "bonded secondary up");
                    return Some(client);
                }
                Some(spec) => {
                    // Allocator did not honor stickiness (pool churn,
                    // exit restart mid-bond): this connection would
                    // receive downlink for the WRONG address. Close it.
                    tracing::warn!(
                        index,
                        primary = %primary_spec.assigned,
                        secondary = %spec.assigned,
                        "bonded secondary got a different sticky IP; closing it"
                    );
                    client.force_close_for_reconnect();
                    return None;
                }
                None => {
                    tracing::warn!(index, "bonded secondary returned no IpAssign; closing it");
                    client.force_close_for_reconnect();
                    return None;
                }
            }
        }
        None
    }

    fn notify_on_reconnect(&self, first_session: bool) {
        if first_session {
            return;
        }
        if let Some(observer) = self.config.on_reconnect.as_ref() {
            observer();
        }
    }

    /// Fire the [`SupervisorConfig::on_dial_refused`] observer when a
    /// dial attempt failed with a deliberate refusal, carrying the
    /// CURRENT target's identity (the circuit whose dial was refused;
    /// a concurrent `migrate_to` would retarget the NEXT attempt, not
    /// the one that just failed, but the report then points at a node
    /// the deployer already moved off, which is harmless). Extracted so
    /// the dispatch gate (refusal vs plain transient) is testable
    /// without a real QUIC dial.
    fn notify_dial_refused(&self, error: &MultiHopError) {
        let Some(hop) = error.dial_refusal() else {
            return;
        };
        let Some(observer) = self.config.on_dial_refused.as_ref() else {
            return;
        };
        let target = self.current_target();
        observer(hop, target.relay.relay_id, *target.exit_id.as_bytes());
    }

    /// Drive [`MultiHopClient::connect`] /
    /// [`MultiHopClient::connect_with_warren_obfuscation`] with the
    /// configured backoff, recycling the iterator after each exhaustion
    /// so a long network outage stays survivable.
    ///
    /// Non-retriable errors propagate after the first occurrence so an
    /// operator misconfiguration (rotated operational pubkey, broken
    /// TLS provider) is visible instead of burning the user's battery
    /// in a retry loop.
    async fn connect_with_unbounded_retry(&self) -> Result<MultiHopClient, MultiHopError> {
        loop {
            let mut attempt_count = 0u64;
            for delay in self.config.backoff.take(usize::MAX) {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                attempt_count += 1;
                let result = self.connect_once().await;
                match result {
                    Ok(c) => return Ok(c),
                    Err(e) if e.is_retriable() => {
                        self.notify_dial_refused(&e);
                        tracing::warn!(
                            error = %e,
                            attempt = attempt_count,
                            "supervisor reconnect attempt failed, retrying after backoff"
                        );
                    }
                    Err(e) => return Err(e),
                }
                // Safety belt: the outer `loop` recycles the iterator
                // if Backoff::take(usize::MAX) ever yields finite
                // results (it does not in the current impl, but pinning
                // this guards against silent semantic drift).
                if attempt_count == u64::MAX {
                    break;
                }
            }
        }
    }
}

/// No-log helper: the discriminant name only, never the message body. A
/// `WarrenControlMessage::IpRequest`/`IpRequestV7` carries a client pubkey
/// (and, for the v7 path, anonymous session tokens); logging the full
/// `Debug` of an unexpected control message would let a hostile relay/exit
/// smuggle that identity material into a debug log just by replying with
/// the "wrong" variant. Mirrors
/// `supervised_pump::dispatch_control_message`'s identical policy.
fn control_message_variant_name(msg: &WarrenControlMessage) -> &'static str {
    match msg {
        WarrenControlMessage::IpRequest { .. } => "IpRequest",
        WarrenControlMessage::IpRequestV7 { .. } => "IpRequestV7",
        WarrenControlMessage::IpAssign { .. } => "IpAssign",
        WarrenControlMessage::IpExhausted => "IpExhausted",
        WarrenControlMessage::Rejected => "Rejected",
        WarrenControlMessage::ExitDraining { .. } => "ExitDraining",
    }
}

/// Bind address for a bonded secondary dial: the primary's IP with the
/// port forced to 0 (kernel-picked). Every bonded connection needs its
/// own UDP socket; reusing a caller-pinned non-zero `bind_addr` port
/// for the secondaries would `EADDRINUSE` against the primary's live
/// socket and silently degrade the bundle to a single connection (the
/// secondary dials are best-effort and only warn-log).
fn secondary_bind_addr(primary: std::net::SocketAddr) -> std::net::SocketAddr {
    let mut addr = primary;
    addr.set_port(0);
    addr
}

/// Sampling cadence of the dead-path watch.
/// Grace before a make-before-break overlap closes the OLD bundle after
/// the published session is swapped to the new one. This is a SHORT settle
/// delay so the old connection's teardown does not race the new session's first
/// scheduler tick; it does NOT deliver in-flight downlink to the application
/// (the supervised pump reads only the PUBLISHED bundle, which is already the
/// new one after the swap). Kept brief on purpose: a longer grace would hold the
/// old exit slot during exactly the drain scenario this targets.
const OVERLAP_DEFERRED_CLOSE_GRACE: Duration = Duration::from_secs(1);

const DEAD_PATH_POLL: Duration = Duration::from_secs(3);

/// `WARREN_DEAD_PATH_SECS` env override (ops escape hatch; `0` disables
/// the watch entirely). The read, parse, clamp and read-once cache all
/// live in the central knob registry (default 15 s).
///
/// Rationale for the 15 s default: the client keep-alives fire every 5 s
/// (`CLIENT_KEEP_ALIVE_INTERVAL_SECS`), so a healthy session receives at
/// least an ACK datagram on every bonded connection every few seconds;
/// 15 s of silence across ALL of them is three missed keep-alive cycles
/// on eight independent connections. A false positive only costs a
/// ~30 ms redial (the exit's pubkey-sticky allocator preserves the inner
/// IP), while a missed dead exit costs the user a ~40 s blackout.
fn dead_path_secs() -> u64 {
    warrenguard_config::knobs::dead_path_secs()
}

/// Uplink-dead detection window (seconds of sustained "everything we send is
/// lost"). Companion of the RX-silence watch: that one cannot see a
/// pure-uplink failure (client->exit dead, exit->client alive) because the
/// exit's keep-alive PINGs keep `udp_rx` advancing. This arm watches the
/// path's sent/lost counters instead.
const UPLINK_DEAD_SECS: u64 = 15;

/// Minimum sent-packet delta per sample below which the ratio is NOT evaluated
/// (keep-alives alone must not qualify as "actively sending").
const UPLINK_MIN_SENT_DELTA: u64 = 8;

/// Loss ratio over a sample window above which the uplink is considered dead
/// (essentially every packet we send is declared lost = no ACKs returning).
const UPLINK_LOSS_RATIO: f64 = 0.9;

/// Whether the uplink-dead watch is enabled. DEFAULT OFF: a too-eager ratio
/// turns a genuinely lossy mobile link into a redial storm, so this ships
/// inert and is enabled with `WARREN_UPLINK_DEADPATH=1` once the `tc netem`
/// lossy-link bench has
/// validated the no-false-positive criterion. The RX-silence watch already
/// covers the dominant failures (exit death, full path blackhole).
fn uplink_dead_enabled() -> bool {
    warrenguard_config::knobs::uplink_deadpath_enabled()
}

/// Resolves once the bundle has spent [`UPLINK_DEAD_SECS`] continuously in a
/// state where we keep sending (`sent_delta >= UPLINK_MIN_SENT_DELTA`) but at
/// least [`UPLINK_LOSS_RATIO`] of those sends are declared lost. Pends forever
/// when disabled (the default) so it never affects the select.
///
/// `sample` returns cumulative `(sent_packets, lost_packets)` across the
/// bundle. Uses `tokio::time::Instant` for `start_paused` testability.
async fn uplink_dead_watch(mut sample: impl FnMut() -> (u64, u64)) {
    if !uplink_dead_enabled() {
        return std::future::pending().await;
    }
    let dead_after = Duration::from_secs(UPLINK_DEAD_SECS);
    let (mut last_sent, mut last_lost) = sample();
    let mut bad_since: Option<tokio::time::Instant> = None;
    loop {
        tokio::time::sleep(DEAD_PATH_POLL).await;
        let (sent, lost) = sample();
        let sent_delta = sent.saturating_sub(last_sent);
        let lost_delta = lost.saturating_sub(last_lost);
        last_sent = sent;
        last_lost = lost;

        let bad = sent_delta >= UPLINK_MIN_SENT_DELTA
            && (lost_delta as f64) >= (sent_delta as f64) * UPLINK_LOSS_RATIO;
        match (bad, bad_since) {
            (true, None) => bad_since = Some(tokio::time::Instant::now()),
            (true, Some(t)) if t.elapsed() >= dead_after => return,
            (false, _) => bad_since = None,
            _ => {}
        }
    }
}

/// `WARREN_APP_DOWNLINK_DEAD_SECS` (default 15 s, `0` disables): window of
/// sustained one-way application traffic before the session is declared dead.
fn app_downlink_dead_secs() -> u64 {
    warrenguard_config::knobs::app_downlink_dead_secs()
}

/// Minimum application datagrams sent since the last downlink progress before
/// the one-way window may fire: an idle tunnel (nothing sent, nothing
/// received) is healthy and must never trip this watch.
const APP_DOWNLINK_MIN_TX: u64 = 8;

/// Resolves once the bundle has kept SENDING application datagrams (>=
/// [`APP_DOWNLINK_MIN_TX`] since the last downlink progress) while not one
/// application datagram frame arrived, for [`app_downlink_dead_secs`] seconds.
///
/// This is the watch the other two cannot replace: transport ACKs keep
/// `udp_rx` advancing (RX-silence watch blind) and mark every send delivered
/// (uplink-loss watch blind), yet the tunnel carries nothing. Observed for
/// real on 2026-07-12: a relay ACKed 90 uplink datagrams and forwarded none;
/// the client sat "connected" for ~39 s with zero traffic until quinn's idle
/// timeout. A false positive only costs a ~30 ms redial (the exit's
/// pubkey-sticky allocator preserves the inner IP); 15 s of genuinely one-way
/// app traffic (no DNS reply, no TCP ACK, nothing) is a dead tunnel.
///
/// `sample` returns cumulative (app datagram frames sent, received) across
/// the bundle. Uses `tokio::time::Instant` for `start_paused` testability.
async fn app_downlink_dead_watch(mut sample: impl FnMut() -> (u64, u64)) {
    let dead_after = match app_downlink_dead_secs() {
        0 => return std::future::pending().await,
        secs => Duration::from_secs(secs),
    };
    let (mut last_tx, mut last_rx) = sample();
    let mut tx_since_progress: u64 = 0;
    let mut last_progress = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(DEAD_PATH_POLL).await;
        let (tx, rx) = sample();
        let tx_delta = tx.saturating_sub(last_tx);
        last_tx = tx;
        if rx != last_rx {
            last_rx = rx;
            tx_since_progress = 0;
            last_progress = tokio::time::Instant::now();
        } else {
            // Accumulate rather than gate per-sample: real uplink is bursty
            // (retries back off), and a quiet 3 s sample must not reset the
            // evidence that traffic is flowing one-way.
            tx_since_progress = tx_since_progress.saturating_add(tx_delta);
            if tx_since_progress >= APP_DOWNLINK_MIN_TX && last_progress.elapsed() >= dead_after {
                return;
            }
        }
    }
}

/// Resolves once `sample_rx_datagrams` has not advanced for
/// [`dead_path_secs`] seconds (total RX silence across the whole bundle).
/// Pends forever when the watch is disabled (`WARREN_DEAD_PATH_SECS=0`).
///
/// Uses `tokio::time::Instant` so the watch follows tokio's clock
/// (testable under `start_paused`; identical to the monotonic clock in
/// production). Monotonic clocks pause across a laptop suspend, so after
/// wake-up a dead session is detected within a fresh `dead_path_secs`
/// window, not instantly; that is fine (the redial is what matters).
async fn dead_path_watch(mut sample_rx_datagrams: impl FnMut() -> u64) {
    let dead_after = match dead_path_secs() {
        0 => return std::future::pending().await,
        secs => Duration::from_secs(secs),
    };
    let mut last_total = sample_rx_datagrams();
    let mut last_progress = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(DEAD_PATH_POLL).await;
        let total = sample_rx_datagrams();
        if total != last_total {
            last_total = total;
            last_progress = tokio::time::Instant::now();
        } else if last_progress.elapsed() >= dead_after {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use warrenguard_multihop::RelayDescriptorSigned;

    /// Mirror of the registry default for `WARREN_DEAD_PATH_SECS`, used to
    /// bound the watch-timing assertions below.
    const DEAD_PATH_SECS_DEFAULT: u64 = 15;

    /// Mirror of the registry default for `WARREN_APP_DOWNLINK_DEAD_SECS`.
    const APP_DOWNLINK_DEAD_SECS_DEFAULT: u64 = 15;

    fn dummy_config() -> SupervisorConfig {
        SupervisorConfig {
            relay: Arc::new(RelayDescriptorSigned {
                relay_id: [0u8; 16],
                relay_ed25519_pubkey: [0u8; 32],
                endpoint: "127.0.0.1:1".parse().expect("static addr parses"),
                cover_domain: None,
                tcp_fallback: false,
                signature: [0u8; 64],
            }),
            exit_id: ExitId::from_bytes([0u8; 16]),
            exit_x25519_multihop_pubkey: [0u8; 32],
            operational_pubkey: SigningKey::from_bytes(&[0x42; 32]).verifying_key(),
            client_signing: SigningKey::from_bytes(&[0x88; 32]),
            bind_addr: "0.0.0.0:0".parse().expect("static addr parses"),
            enable_gso: false,
            use_warren_obfuscation: false,
            socket_bypass: None,
            enable_daita: false,
            idle_cover: false,
            backoff: Backoff::HANDSHAKE,
            on_reconnect: None,
            ip_assign_channel: None,
            wants_ipv6: false,
            n_connections: 1,
            pre_swap_check: None,
            on_overlap_swapped: None,
            on_dial_refused: None,
            session_token_provider: None,
        }
    }

    #[tokio::test]
    async fn pre_swap_allows_when_no_check_is_wired() {
        assert!(pre_swap_allows::<()>(None, ()).await);
    }

    #[tokio::test]
    async fn pre_swap_honours_the_check_verdict() {
        let allow: PreSwapCheckFn<()> = Arc::new(|()| Box::pin(async { true }));
        assert!(pre_swap_allows(Some(&allow), ()).await);
        let deny: PreSwapCheckFn<()> = Arc::new(|()| Box::pin(async { false }));
        assert!(!pre_swap_allows(Some(&deny), ()).await);
    }

    #[tokio::test(start_paused = true)]
    async fn pre_swap_fails_closed_on_a_hung_check() {
        // A check that never resolves must NOT wedge the serve loop nor
        // commit the swap: past the timeout the migration is aborted and
        // the current session kept (the safe side for port preservation).
        let hung: PreSwapCheckFn<()> =
            Arc::new(|()| Box::pin(async { std::future::pending::<bool>().await }));
        assert!(!pre_swap_allows(Some(&hung), ()).await);
    }

    #[test]
    fn secondary_bind_addr_forces_a_kernel_picked_port() {
        // A user pinning `--bind-addr 192.0.2.7:51000` must not make
        // every bonded secondary EADDRINUSE against the primary's
        // socket: same IP (interface pinning intent preserved), port 0.
        let pinned: std::net::SocketAddr = "192.0.2.7:51000".parse().expect("addr parses");
        let secondary = secondary_bind_addr(pinned);
        assert_eq!(secondary.ip(), pinned.ip(), "interface pin preserved");
        assert_eq!(secondary.port(), 0, "port must be kernel-picked");
    }

    #[test]
    fn secondary_bind_addr_keeps_an_already_ephemeral_bind_unchanged() {
        let default_bind: std::net::SocketAddr = "0.0.0.0:0".parse().expect("addr parses");
        assert_eq!(
            secondary_bind_addr(default_bind),
            default_bind,
            "the common port-0 case is a no-op"
        );
    }

    /// Three consecutive watchdog-forced closes with zero session-lifetime
    /// downlink must escalate; fewer must not. Guards the bound on how long
    /// a dead datapath may masquerade as Connected.
    #[test]
    fn dead_path_escalation_fires_after_three_consecutive_zero_downlink_closes() {
        let mut esc = DeadPathEscalation::default();
        assert!(!esc.record_close(true, 0), "first dead window is tolerated");
        assert!(
            !esc.record_close(true, 0),
            "second dead window is tolerated"
        );
        assert!(
            esc.record_close(true, 0),
            "third consecutive dead window escalates"
        );
    }

    /// Any sign of life resets the streak: downlink flowed during the
    /// session, or the close was not watchdog-forced (a normal reconnect).
    #[test]
    fn dead_path_escalation_resets_on_downlink_or_non_watchdog_close() {
        let mut esc = DeadPathEscalation::default();
        assert!(!esc.record_close(true, 0));
        assert!(!esc.record_close(true, 0));
        assert!(
            !esc.record_close(true, 512),
            "session had downlink: healthy"
        );
        assert!(!esc.record_close(true, 0));
        assert!(!esc.record_close(false, 0), "non-watchdog close: resets");
        assert!(!esc.record_close(true, 0));
        assert!(!esc.record_close(true, 0));
        assert!(esc.record_close(true, 0), "streak rebuilt after resets");
    }

    /// Total RX silence across the bundle must resolve the dead-path
    /// watch at ~`DEAD_PATH_SECS_DEFAULT`, NOT wait for quinn's idle
    /// timeout (which the RFC 9000 3xPTO floor inflates to ~40 s once
    /// the keep-alive probes back off; live measurement).
    #[tokio::test(start_paused = true)]
    async fn dead_path_watch_fires_on_total_rx_silence() {
        let started = tokio::time::Instant::now();
        dead_path_watch(|| 42).await;
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(DEAD_PATH_SECS_DEFAULT),
            "must not fire before the silence bound, fired at {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_secs(DEAD_PATH_SECS_DEFAULT + 4),
            "must fire within one poll period of the bound, fired at {elapsed:?}"
        );
    }

    /// A bundle that keeps receiving (keep-alive ACKs count) must never
    /// trip the watch, no matter how long the session runs.
    #[tokio::test(start_paused = true)]
    async fn dead_path_watch_stays_pending_while_rx_advances() {
        let counter = Arc::new(AtomicU64::new(0));
        let sampled = counter.clone();
        let ticker = counter.clone();
        // Simulated keep-alive ACK every 4s (cadence of a healthy conn).
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(4)).await;
                ticker.fetch_add(1, Ordering::Relaxed);
            }
        });
        let watch = dead_path_watch(move || sampled.load(Ordering::Relaxed));
        tokio::select! {
            () = watch => panic!("watch fired despite continuous RX progress"),
            () = tokio::time::sleep(Duration::from_secs(300)) => {}
        }
    }

    /// The 2026-07-12 incident shape: app datagrams keep going up, transport
    /// ACKs keep the RX-silence watch blind, yet not one application datagram
    /// ever comes back. The watch must fire within its window instead of
    /// leaving the session "connected" until quinn's ~40 s idle timeout.
    #[tokio::test(start_paused = true)]
    async fn app_downlink_dead_watch_fires_when_uplink_flows_and_downlink_stays_flat() {
        let started = tokio::time::Instant::now();
        let tx = Arc::new(AtomicU64::new(0));
        let tx_sampled = tx.clone();
        app_downlink_dead_watch(move || {
            // ~5 app datagrams sent per sample, zero ever received.
            (tx_sampled.fetch_add(5, Ordering::Relaxed) + 5, 0)
        })
        .await;
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(APP_DOWNLINK_DEAD_SECS_DEFAULT),
            "must not fire before the window, fired at {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_secs(APP_DOWNLINK_DEAD_SECS_DEFAULT + 4),
            "must fire within one poll period of the window, fired at {elapsed:?}"
        );
    }

    /// An idle tunnel (nothing sent, nothing received) is healthy: the watch
    /// must never fire on it, no matter how long it runs.
    #[tokio::test(start_paused = true)]
    async fn app_downlink_dead_watch_stays_pending_when_idle() {
        tokio::select! {
            () = app_downlink_dead_watch(|| (3, 0)) => {
                panic!("watch fired on an idle session")
            }
            () = tokio::time::sleep(Duration::from_secs(300)) => {}
        }
    }

    /// A working tunnel (downlink app datagrams keep arriving) must never trip
    /// the watch, however much uplink it also carries.
    #[tokio::test(start_paused = true)]
    async fn app_downlink_dead_watch_stays_pending_while_downlink_advances() {
        let rx = Arc::new(AtomicU64::new(0));
        let rx_sampled = rx.clone();
        let ticker = rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(4)).await;
                ticker.fetch_add(1, Ordering::Relaxed);
            }
        });
        let tx = Arc::new(AtomicU64::new(0));
        let tx_sampled = tx.clone();
        let watch = app_downlink_dead_watch(move || {
            (
                tx_sampled.fetch_add(20, Ordering::Relaxed) + 20,
                rx_sampled.load(Ordering::Relaxed),
            )
        });
        tokio::select! {
            () = watch => panic!("watch fired despite continuous downlink progress"),
            () = tokio::time::sleep(Duration::from_secs(300)) => {}
        }
    }

    /// Disabled by default: the watch must pend forever unless
    /// `WARREN_UPLINK_DEADPATH=1`, so it never affects the select in prod.
    #[tokio::test(start_paused = true)]
    async fn uplink_dead_watch_pends_when_disabled() {
        // Env unset in the test process -> disabled. Even with a
        // permanently-"bad" sampler it must never resolve.
        tokio::select! {
            () = uplink_dead_watch(|| (1_000, 1_000)) => panic!("must pend when disabled"),
            () = tokio::time::sleep(Duration::from_secs(120)) => {}
        }
    }

    /// The ratio/floor/window logic, exercised directly (clock-free) so the
    /// test does not depend on the process-wide env gate. Mirrors
    /// `uplink_dead_watch`'s decision.
    #[test]
    fn uplink_dead_decision_matches_criteria() {
        let decide = |sent_delta: u64, lost_delta: u64| {
            sent_delta >= UPLINK_MIN_SENT_DELTA
                && (lost_delta as f64) >= (sent_delta as f64) * UPLINK_LOSS_RATIO
        };
        // Healthy idle: keep-alives only -> below the send floor -> not bad.
        assert!(!decide(2, 2), "idle keep-alives must not qualify");
        // Lossy-but-alive link (15% loss, actively sending): not bad.
        assert!(!decide(100, 15), "15% loss on a live link must not trip");
        // Uplink dead: actively sending, ~all lost.
        assert!(decide(40, 40), "all-sends-lost must trip");
        assert!(decide(20, 19), "95% loss above floor must trip");
        // Above ratio but below the send floor (a single straggler): not bad.
        assert!(!decide(4, 4), "below the send floor must not trip");
    }

    #[test]
    fn notify_on_reconnect_skips_first_session() {
        // Anti-regression: the initial connect must NOT fire the
        // observer. A fresh session is not a reconnect, and bumping a
        // daemon-side reconnect counter here would surface
        // `Reconnects: 1` immediately on every boot in a consuming UI.
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = calls.clone();
        let observer: ReconnectObserver = Arc::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        let mut cfg = dummy_config();
        cfg.on_reconnect = Some(observer);
        let (supervisor, _rx) = MultiHopSupervisor::new(cfg);
        supervisor.notify_on_reconnect(true);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "on_reconnect must NOT fire on the initial connect"
        );
        drop(supervisor);
    }

    #[test]
    fn notify_on_reconnect_fires_on_subsequent_publication() {
        // The reverse anti-regression: a publication that follows a
        // disconnect MUST fire the observer once. The daemon-side
        // WarrenStatusCache::record_reconnect call is the only path
        // that advances the live `reconnect_count` shown in the UI
        // connection-details rows.
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = calls.clone();
        let observer: ReconnectObserver = Arc::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        let mut cfg = dummy_config();
        cfg.on_reconnect = Some(observer);
        let (supervisor, _rx) = MultiHopSupervisor::new(cfg);
        supervisor.notify_on_reconnect(false);
        supervisor.notify_on_reconnect(false);
        supervisor.notify_on_reconnect(false);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            3,
            "on_reconnect must fire once per non-initial publication"
        );
        drop(supervisor);
    }

    #[test]
    fn metrics_snapshot_observes_each_atomic_independently() {
        // Mutate each counter and verify the snapshot reflects them
        // individually. Anchors the field <-> snapshot mapping so a
        // typo (swapping reconnect_count and last_reconnect_duration_ms)
        // is caught before the metrics ship.
        let m = SupervisorMetrics::default();
        m.reconnect_count.fetch_add(3, Ordering::Relaxed);
        m.last_reconnect_duration_ms
            .fetch_add(1500, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.reconnect_count, 3);
        assert_eq!(s.last_reconnect_duration_ms, 1500);
    }

    #[test]
    fn notify_dial_refused_reports_the_refused_circuit_identity() {
        // The observer must fire on a deliberate refusal with the hop
        // and the CURRENT target's identity, and must stay silent on a
        // plain transient error: firing on every blip would make the
        // deployer exclude healthy nodes on ordinary packet loss.
        type SeenRefusals = Vec<(multihop::DialRefusedHop, [u8; 16], [u8; 16])>;
        let seen: Arc<std::sync::Mutex<SeenRefusals>> = Default::default();
        let mut config = dummy_config();
        config.relay = Arc::new(RelayDescriptorSigned {
            relay_id: [0xAB; 16],
            relay_ed25519_pubkey: [0u8; 32],
            endpoint: "127.0.0.1:1".parse().expect("static addr parses"),
            cover_domain: None,
            tcp_fallback: false,
            signature: [0u8; 64],
        });
        config.exit_id = ExitId::from_bytes([0xCD; 16]);
        let sink = seen.clone();
        config.on_dial_refused = Some(Arc::new(move |hop, relay_id, exit_id| {
            sink.lock()
                .expect("sink lock")
                .push((hop, relay_id, exit_id));
        }));
        let (supervisor, _rx) = MultiHopSupervisor::new(config);

        let refused = MultiHopError::Handshake(quinn::ConnectionError::ConnectionClosed(
            quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::CONNECTION_REFUSED,
                frame_type: None,
                reason: bytes::Bytes::from_static(b""),
            },
        ));
        supervisor.notify_dial_refused(&refused);
        supervisor.notify_dial_refused(&MultiHopError::Handshake(quinn::ConnectionError::TimedOut));

        assert_eq!(
            *seen.lock().expect("seen lock"),
            vec![(multihop::DialRefusedHop::Entry, [0xAB; 16], [0xCD; 16])],
            "exactly one report, for the refusal only, with the target identity"
        );
        drop(supervisor);
    }

    #[test]
    fn notify_dial_refused_without_observer_is_a_noop() {
        // No observer wired (tests, deployments without a directory):
        // a refusal must not panic or change behavior.
        let (supervisor, _rx) = MultiHopSupervisor::new(dummy_config());
        supervisor.notify_dial_refused(&MultiHopError::Handshake(
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(warrenguard_multihop::WARREN_MH_DRAINING),
                reason: bytes::Bytes::from_static(b""),
            }),
        ));
        drop(supervisor);
    }

    #[test]
    fn handle_force_reconnect_without_session_is_a_noop() {
        // The watchdog can race a redial window: forcing a reconnect
        // while the supervisor has published `None` must do nothing
        // (the redial in flight already serves the purpose).
        let (supervisor, _rx) = MultiHopSupervisor::new(dummy_config());
        let handle = supervisor.handle();
        assert!(!handle.has_session());
        assert!(!handle.force_reconnect(), "no session => must be a no-op");
        drop(supervisor);
    }

    #[test]
    fn handle_is_cloneable_and_survives_supervisor_drop() {
        // The handle must not keep the supervisor alive nor panic once
        // the supervisor is gone; it just observes None forever.
        let (supervisor, _rx) = MultiHopSupervisor::new(dummy_config());
        let handle = supervisor.handle();
        let clone = handle.clone();
        drop(supervisor);
        assert!(!clone.force_reconnect());
    }

    #[tokio::test]
    async fn new_publishes_none_before_any_connect() {
        // The watch channel must start in the disconnected state so a
        // pump task that polls the receiver before the supervisor has
        // dialed sees `None` and drops the packet rather than dialing
        // an uninitialized client.
        let (supervisor, rx) = MultiHopSupervisor::new(dummy_config());
        assert!(
            rx.borrow().is_none(),
            "watch must initialize to None so pumps observe disconnected state"
        );
        // Don't spawn run() - dummy_config can't actually dial. The
        // supervisor handle is dropped here which closes the channel
        // and would cause a real run() to terminate cleanly.
        drop(supervisor);
    }

    #[tokio::test]
    async fn metrics_handle_can_be_cloned_for_scraping() {
        // The metrics handle is intended to be cloned to a metrics
        // scraper task that lives alongside the supervisor. Verify the
        // handle Arc is exposed before run() consumes self.
        let (supervisor, _rx) = MultiHopSupervisor::new(dummy_config());
        let scraper = supervisor.metrics();
        let snap = scraper.snapshot();
        assert_eq!(snap.reconnect_count, 0);
        // Holding a second clone must not affect the original handle.
        let clone = supervisor.metrics();
        assert!(Arc::ptr_eq(&scraper, &clone));
        drop(supervisor);
    }
}

/// Live loopback tests for [`MultiHopSupervisor::run`] against
/// [`crate::test_support::spawn_fake_multihop_exit`] (a real relay descriptor
/// pinned by a real TLS RPK dial, driving the real HPKE setup-over-stream
/// exchange, not a "cannot actually dial" stub). Covers what `dummy_config`
/// structurally cannot: the fatal publish on a setup rejection, a forced
/// redial actually reaching the exit again, and the watch-closed shutdown
/// path.
#[cfg(test)]
mod run_tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::test_support::{FakeMultihopExit, spawn_fake_multihop_exit};

    fn config_with_fake_exit(
        exit: &FakeMultihopExit,
        operational_key: &SigningKey,
    ) -> SupervisorConfig {
        SupervisorConfig {
            relay: exit.relay.clone(),
            exit_id: exit.exit_id,
            exit_x25519_multihop_pubkey: exit.exit_x25519_pubkey,
            operational_pubkey: operational_key.verifying_key(),
            client_signing: SigningKey::from_bytes(&[0x24; 32]),
            bind_addr: "127.0.0.1:0".parse().expect("static addr parses"),
            enable_gso: false,
            use_warren_obfuscation: false,
            socket_bypass: None,
            enable_daita: false,
            idle_cover: false,
            backoff: Backoff::HANDSHAKE,
            on_reconnect: None,
            ip_assign_channel: None,
            wants_ipv6: false,
            n_connections: 1,
            pre_swap_check: None,
            on_overlap_swapped: None,
            on_dial_refused: None,
            session_token_provider: None,
        }
    }

    #[tokio::test]
    async fn run_dials_the_fake_exit_and_terminates_once_every_receiver_drops() {
        let operational_key = SigningKey::from_bytes(&[0x42; 32]);
        let exit_id = ExitId::from_bytes([0x51; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        let config = config_with_fake_exit(&exit, &operational_key);
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let metrics = supervisor.metrics();

        let task = tokio::spawn(supervisor.run());

        let bundle = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(b) = rx.borrow_and_update().clone() {
                    return b;
                }
                if rx.changed().await.is_err() {
                    panic!("watch closed before a session was ever published");
                }
            }
        })
        .await
        .expect("the fake exit must accept the dial within 5s");
        assert!(bundle.num_connections() >= 1);
        assert_eq!(
            exit.accepted.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "exactly one connection for the initial (non-reconnect) dial"
        );
        assert_eq!(
            metrics.snapshot().reconnect_count,
            0,
            "the initial connect must not count as a reconnect"
        );

        // Dropping every receiver (the pumps + this test's own handle) must
        // make `run()` observe `tx.is_closed()` (or the inner loop's
        // `self.tx.closed()` arm) and return `Ok(())` promptly, never hang
        // waiting on a dial nobody is listening for.
        drop(bundle);
        drop(rx);
        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("run() must terminate promptly once every receiver drops")
            .expect("run() task must not panic");
        assert!(
            result.is_ok(),
            "no receivers left must be a clean Ok(()), not an error"
        );
    }

    #[tokio::test]
    async fn run_forced_reconnect_redials_the_exit_and_bumps_the_metrics() {
        let operational_key = SigningKey::from_bytes(&[0x43; 32]);
        let exit_id = ExitId::from_bytes([0x52; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        let config = config_with_fake_exit(&exit, &operational_key);
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let metrics = supervisor.metrics();
        let handle = supervisor.handle();

        let task = tokio::spawn(supervisor.run());

        // Wait for the first (non-reconnect) session.
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("must not time out")
            .expect("watch sender alive");
        let first = rx
            .borrow_and_update()
            .clone()
            .expect("first session published");

        // Force a break-before-make reconnect: the current session closes,
        // the watch republishes `None`, then a fresh dial against the SAME
        // fake exit republishes `Some` with a NEW bundle.
        assert!(
            handle.force_reconnect(),
            "a live session must be present to force-close"
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                rx.changed().await.expect("watch sender alive");
                if rx.borrow().is_none() {
                    continue;
                }
                return;
            }
        })
        .await
        .expect("must observe the republished session within 5s");
        let second = rx
            .borrow_and_update()
            .clone()
            .expect("session republished after redial");

        assert!(
            !Arc::ptr_eq(&first, &second),
            "the forced reconnect must publish a NEW bundle, not the old one"
        );
        assert_eq!(
            exit.accepted.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "the fake exit must have accepted exactly two connections: initial + one redial"
        );
        assert_eq!(
            metrics.snapshot().reconnect_count,
            1,
            "one completed reconnect cycle must be recorded"
        );

        drop(first);
        drop(second);
        drop(rx);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test]
    async fn run_terminates_when_receivers_drop_during_the_cold_dial_retry_loop() {
        // A teardown landing while the supervisor is INSIDE its cold-dial
        // retry loop must stop the retries: the loop-top receiver check
        // cannot see it, and a dial that never succeeds means the loop is
        // never left. Observed live on Windows as a supervisor still
        // redialing at attempt=948 long after the daemon reported
        // Disconnected. The TEST-NET bind address makes every attempt fail
        // instantly with the same retriable Bind error as the field case.
        let operational_key = SigningKey::from_bytes(&[0x46; 32]);
        let exit_id = ExitId::from_bytes([0x55; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.bind_addr = "192.0.2.1:0".parse().expect("static addr parses");

        let (supervisor, rx) = MultiHopSupervisor::new(config);
        let task = tokio::spawn(supervisor.run());

        // Let run() pass its loop-top no-receivers check and enter the
        // retry loop before the teardown drops the last receiver.
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(rx);

        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("run() must terminate promptly when every receiver drops mid-dial")
            .expect("run() task must not panic");
        assert!(
            result.is_ok(),
            "a receiverless teardown must terminate run() cleanly, got {result:?}"
        );
    }

    #[tokio::test]
    async fn run_surfaces_a_setup_rejection_as_fatal_and_returns_err() {
        let operational_key = SigningKey::from_bytes(&[0x44; 32]);
        let exit_id = ExitId::from_bytes([0x53; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        exit.reject
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let config = config_with_fake_exit(&exit, &operational_key);
        let (supervisor, _rx) = MultiHopSupervisor::new(config);
        let mut fatal_rx = supervisor.fatal_rx();

        let result = tokio::time::timeout(Duration::from_secs(5), supervisor.run())
            .await
            .expect("run() must not hang retrying a definitive rejection");

        match result {
            Err(MultiHopError::Rejected(reason)) => {
                assert_eq!(reason, RejectionReason::NotAllowlisted);
            }
            other => panic!("expected Err(MultiHopError::Rejected(_)), got {other:?}"),
        }

        let published = *fatal_rx.borrow_and_update();
        assert_eq!(
            published,
            Some(RejectionReason::NotAllowlisted),
            "fatal_rx must observe the same rejection reason run() returned"
        );
    }

    /// M14 wiring: `dead_path_watch` (RX silence) is blind here - quinn's own
    /// ACK/keep-alive traffic keeps `udp_rx.datagrams` advancing even though
    /// no application data ever flows - so this exercises the OTHER arm,
    /// `app_downlink_dead_watch`: a background task keeps sending real
    /// uplink application datagrams on every published session while the
    /// fake exit never emits a single downlink QUIC datagram back (only the
    /// setup-stream `IpAssign` reply, which rides a reliable STREAM and
    /// never touches `frame_rx.datagram`). Every resulting watchdog-forced
    /// redial therefore carries zero application downlink over its whole
    /// life - the exact [`DeadPathEscalation::record_close`] trigger.
    #[tokio::test(start_paused = true)]
    async fn run_datapath_dead_latch_fires_after_three_consecutive_zero_downlink_redials() {
        let operational_key = SigningKey::from_bytes(&[0x45; 32]);
        let exit_id = ExitId::from_bytes([0x54; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        let config = config_with_fake_exit(&exit, &operational_key);
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let mut datapath_dead_rx = supervisor.datapath_dead_rx();
        let metrics = supervisor.metrics();

        let task = tokio::spawn(supervisor.run());

        // Keep the uplink "flowing" on every (re)published session so
        // `app_downlink_dead_watch`'s one-way condition can actually
        // evaluate; an idle tunnel is deliberately never flagged.
        let mut burst_rx = rx.clone();
        tokio::spawn(async move {
            loop {
                if burst_rx.changed().await.is_err() {
                    return;
                }
                let Some(bundle) = burst_rx.borrow().clone() else {
                    continue;
                };
                for _ in 0..16 {
                    let _ = bundle.send(&[0x45, 0, 0, 20, 1, 2, 3, 4]).await;
                }
            }
        });

        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                rx.changed().await.expect("watch sender alive");
                if rx.borrow().is_some() {
                    return;
                }
            }
        })
        .await
        .expect("initial session must publish");

        assert!(
            !*datapath_dead_rx.borrow_and_update(),
            "must not be latched before any watchdog-forced redial"
        );

        tokio::time::timeout(Duration::from_secs(120), datapath_dead_rx.changed())
            .await
            .expect("the latch must fire well within three redial cycles")
            .expect("datapath_dead_tx sender alive");
        assert!(
            *datapath_dead_rx.borrow_and_update(),
            "the latch must publish true, never any other value"
        );
        assert!(
            metrics.snapshot().reconnect_count >= 3,
            "the latch must not fire before at least three redial cycles completed, got {}",
            metrics.snapshot().reconnect_count
        );

        // Once latched it must never un-latch: a late recovery does not
        // retroactively undo the fact the tunnel WAS observed dead, and the
        // supervisor keeps silently redialing regardless.
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert!(
            *datapath_dead_rx.borrow_and_update(),
            "the latch must stay true, never reset to false"
        );

        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }
}
