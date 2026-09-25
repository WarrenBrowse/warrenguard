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
//! 2. Retries the dial under one unbounded [`warrenguard_backoff::Backoff`]
//!    schedule that survives across reconnect cycles, so a long-lived
//!    disconnect (router restart, WiFi <-> 4G handover) is survivable and
//!    an exit that refuses or drops every session is not hammered: only a
//!    session that served for the healthy uptime
//!    ([`crate::redial_policy::MIN_HEALTHY_UPTIME`]) resets it,
//! 3. Publishes the freshly-dialed `Some(Arc<MultiHopClient>)` so the
//!    pump resumes, and only once the exit assigned the session its inner
//!    address: a setup that ends without an `IpAssign` is a failed dial.
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
use warrenguard_backoff::{Backoff, JitterBackoff};
use warrenguard_multihop::{ExitId, RejectionReason, RelayDescriptorSigned};
use warrenguard_socket_bypass::SocketBypass;
use warrenguard_wire::SessionToken;

use crate::bundle::{MAX_BONDED_CONNECTIONS, MultiHopBundle};
use crate::ip_assign::{IpAssignChannel, IpAssignSpec};
use warrenguard_transport_core::{
    warren_transport_config_client_multihop_with_idle_cover,
    warren_transport_config_client_with_idle_cover,
};

use crate::multihop::{self, MultiHopClient, MultiHopError, NoSessionTokenCause};

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

/// Observer of the measured client->entry QUIC path RTT, fired at
/// connection lifecycle points (session publish post-handshake, and once
/// more when the serving session ends) with
/// `(relay_ed25519_pubkey, rtt_ms)` of the DIALED first hop (captured at
/// dial time, so a concurrent retarget can never mis-key a sample). The
/// engine stays store-agnostic: an embedder feeds its own RTT store (the
/// client-measured half of the shared path-aware selection signal).
pub type PathRttObserver = Arc<dyn Fn([u8; 32], u32) + Send + Sync>;

/// Source of anonymous v7 session tokens (Privacy Pass). Called ONCE
/// per session establishment to obtain the token stack the primary and all its
/// bonded secondaries present; because they share one stack they resolve to the
/// same anonymous serial and thus the same sticky tunnel IP. Returning an empty
/// vec (or configuring no provider) keeps the v6 wallet-signed `IpRequest` path,
/// unless the supervisor runs under [`SessionAdmission::TokensOnly`].
///
/// The exit spends the first token of the stack that verifies and stops there.
/// When it refuses the session, the supervisor redials leading with the next
/// token (see [`SessionAdmission`]), so a stack of several current-epoch tokens
/// lets a session get past a serial another device already holds.
///
/// The app wires this to a closure that pops a token from its `TokenStore` for
/// the current epoch (plus an optional next-epoch lookahead for clock skew) and
/// converts it to the wire [`SessionToken`]. The supervisor is deliberately
/// ignorant of epochs and the store: it only asks for a per-session stack.
pub type SessionTokenProvider = Arc<dyn Fn() -> Vec<SessionToken> + Send + Sync>;

/// How the supervisor's sessions are admitted at the exit. Set with
/// [`MultiHopSupervisor::with_session_admission`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SessionAdmission {
    /// Present v7 anonymous tokens when the [`SessionTokenProvider`] yields
    /// any, and the v6 wallet-signed `IpRequest` otherwise.
    #[default]
    TokensOrWallet,
    /// Present v7 anonymous tokens only. A session with no token, or whose
    /// every token the exit refuses, is never set up:
    /// [`MultiHopSupervisor::run`] returns
    /// [`MultiHopError::NoSessionToken`], and no request naming the wallet is
    /// ever built, for the primary or any bonded secondary. For a session that
    /// must not be linkable to the account at the exit it lands on.
    TokensOnly,
}

impl SessionAdmission {
    /// The wallet key a setup request may prove possession of: none at all
    /// under [`Self::TokensOnly`], so even a request built without tokens
    /// could not carry the account pubkey.
    fn wallet_identity(self, key: &SigningKey) -> Option<&SigningKey> {
        match self {
            Self::TokensOrWallet => Some(key),
            Self::TokensOnly => None,
        }
    }
}

/// Whether a setup rejection can be the exit refusing the presented token. The
/// exit answers every v7 refusal (no token verified, or the token's serial is
/// already leased to a live session elsewhere, `SerialInUse`) with the same
/// sealed `Rejected` detail, or with the bare opaque close when the detail is
/// lost, so the client cannot tell an in-use serial from an invalid token.
fn is_token_refusal(reason: RejectionReason) -> bool {
    matches!(
        reason,
        RejectionReason::NotAllowlisted | RejectionReason::PolicyRefused
    )
}

/// One session's v7 token stack, as the provider handed it out, plus how many
/// of its tokens the exit has refused so far.
///
/// The exit spends the FIRST token of a stack that verifies and stops there, a
/// refusal included, so the next token is only ever tried by a fresh setup
/// that leads with it. A refused token is moved to the back rather than
/// dropped: a refusal spends nothing, and the session holding its serial may
/// release it. Retries are bounded by the stack: each token leads at most one
/// attempt.
#[derive(Clone)]
struct TokenStack {
    tokens: Vec<SessionToken>,
    refused: usize,
}

impl TokenStack {
    /// `None` for an empty stack (no token to present).
    fn new(tokens: Vec<SessionToken>) -> Option<Self> {
        (!tokens.is_empty()).then_some(Self { tokens, refused: 0 })
    }

    fn as_slice(&self) -> &[SessionToken] {
        &self.tokens
    }

    /// Record that the exit refused the lead token and move it to the back.
    /// `false` once every token has led an attempt: nothing untried remains.
    fn rotate(&mut self) -> bool {
        self.refused += 1;
        if self.refused >= self.tokens.len() {
            return false;
        }
        self.tokens.rotate_left(1);
        true
    }

    /// Whether this stack is part-way through its refusal retries, so an
    /// attempt that fails for another reason must re-present it rather than
    /// pop a fresh one.
    fn is_retrying(&self) -> bool {
        self.refused > 0
    }

    fn into_tokens(self) -> Vec<SessionToken> {
        self.tokens
    }
}

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
    /// Raw ML-KEM-768 encapsulation key of the exit (`MLKEM768_ENCAPS_KEY_LEN`
    /// bytes) from its PQ-signed descriptor, or `None`/empty when the exit
    /// advertises no PQ key. When present the supervisor dials the `/v2` X-Wing
    /// hybrid seal with `require_pq = false`, so an exit publishing no PQ
    /// descriptor still falls back to the byte-identical classical `/v1` session
    /// over `exit_x25519_multihop_pubkey`.
    pub exit_mlkem768_pubkey: Option<Vec<u8>>,
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
    /// Exponential backoff schedule for redials. `Backoff::HANDSHAKE`
    /// (base 500 ms, max 15 s) is the default and matches the
    /// cold-start retry profile of [`MultiHopClient::connect_with_retry`].
    /// One schedule runs for the supervisor's whole life: failed dials,
    /// refused setups and sessions that die before the healthy uptime all
    /// escalate it, and only a healthy session resets it.
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
    /// Optional observer of the measured client->entry path RTT
    /// ([`PathRttObserver`]): fired on each session publish and once
    /// more when the serving session ends. `None` = not observed.
    pub on_path_rtt: Option<PathRttObserver>,
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
    /// Raw ML-KEM-768 encapsulation key of the exit, or `None` when it
    /// advertises no PQ descriptor (classical seal). Carried per-target so a
    /// cross-exit `migrate_to` retargets the PQ key together with the exit.
    pub exit_mlkem768_pubkey: Option<Vec<u8>>,
}

impl CircuitTarget {
    fn from_config(config: &SupervisorConfig) -> Self {
        Self {
            relay: config.relay.clone(),
            exit_id: config.exit_id,
            exit_x25519_multihop_pubkey: config.exit_x25519_multihop_pubkey,
            exit_mlkem768_pubkey: config.exit_mlkem768_pubkey.clone(),
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
    /// Inner IPv4 the exit assigned to the LAST established session, with
    /// the exit that assigned it. Redials to that exit send it as the
    /// `prefer_ipv4` session-placement hint so the exit keeps the session on
    /// its address (overlap and fast reconnects join the predecessor instead
    /// of minting a new IP, and a restarted exit hands it back); a first
    /// session, or a dial to any other exit, sends the 0.0.0.0 session-fresh
    /// sentinel instead. The sentinel is what stops two independent
    /// same-wallet sessions from sharing one inner IP and stealing each
    /// other's downlink, and it keeps one exit's allocation from being
    /// disclosed to, or reproduced by, another. A watch so a deployer can
    /// follow it ([`Self::placement_rx`]).
    placement: watch::Sender<Option<(ExitId, std::net::Ipv4Addr)>>,
    /// Shared state of the goodput prober ([`crate::path_health`]):
    /// tracker episode memory, reply stream and probe tap. The tap is
    /// installed on every published bundle; one prober task runs per
    /// published bundle and exits with it.
    prober: Arc<crate::path_health::ProberShared>,
    /// How sessions are admitted; see [`SessionAdmission`].
    admission: SessionAdmission,
}

/// Consecutive watchdog-forced redials, each of a session whose ENTIRE life
/// carried zero application downlink, before the supervisor escalates the
/// dead datapath as fatal instead of redialing silently forever. Three
/// windows (~45 s at the default 15 s watches) tolerate a slow one-off
/// recovery while bounding how long a dead tunnel may masquerade as
/// Connected (without the bound, a UI can say Connected
/// for hours over a datapath that egresses nothing).
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
    /// The setup round-trip got nothing back before
    /// [`SETUP_ROUND_TRIP_TIMEOUT`].
    SetupTimedOut,
    /// The setup round-trip ended without an `IpAssign` (see
    /// [`SetupOutcome::Failed`]), already reported.
    SetupFailed,
}

/// Ceiling on the setup round-trip, measured from a completed handshake.
///
/// Every other leg of the connect path is bounded (the UDP handshake at
/// `DEFAULT_UDP_HANDSHAKE_TIMEOUT`, the relay-auth proof at
/// `RELAY_PROOF_TIMEOUT`), and this one was not: `read_to_end` on the setup
/// stream waited for QUIC's own idle timeout. On a network that passes the
/// handshake and then cuts the flow, that turned every dial into a single
/// multi-second stall, and a client whose deployer bounds a connect attempt
/// (Android gives it 20 s) never got a second try inside its own window.
/// Sized so three dials fit in that window.
const SETUP_ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(6);

/// What one setup round-trip produced.
enum SetupOutcome {
    /// The exit assigned the session its inner address.
    Assigned(IpAssignSpec),
    /// The exit refused the session. A redial hits the same refusal.
    Rejected(RejectionReason),
    /// Nothing came back within [`SETUP_ROUND_TRIP_TIMEOUT`].
    TimedOut,
    /// The round-trip ended without an `IpAssign`: the connection closed or
    /// the stream failed (`Some`, a drained exit refuses this way), or the
    /// exit answered something else (`None`). The session has no address
    /// the exit routes to, so it is never published.
    Failed(Option<MultiHopError>),
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
            placement: watch::channel(None).0,
            prober: crate::path_health::ProberShared::new(rand::random()),
            admission: SessionAdmission::default(),
        };
        (supervisor, rx)
    }

    /// Admit this supervisor's sessions under `admission` instead of the
    /// default [`SessionAdmission::TokensOrWallet`]. Call before
    /// [`Self::run`].
    #[must_use]
    pub fn with_session_admission(mut self, admission: SessionAdmission) -> Self {
        self.admission = admission;
        self
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

    /// Continue the session that `assigned_v4` belongs to instead of starting
    /// an independent one, for a supervisor built to REPLACE a previous one
    /// (a deployer that rebuilds its whole tunnel rather than redialing).
    /// `assigning_exit` is the exit that assigned `assigned_v4`: the address
    /// is named to that exit only, so a tunnel rebuilt onto another exit
    /// starts a fresh session there. Call before [`Self::run`].
    ///
    /// A supervisor learns its session's address from the exit and names it on
    /// every redial, which is what keeps a reconnect on one inner IP. That
    /// memory dies with the supervisor, so a rebuilt tunnel would introduce
    /// itself as a brand-new session and the exit, which never co-houses an
    /// independent session with a live one of the same identity, would place
    /// it elsewhere. Anything the exit keys on the inner address then looks
    /// like it belongs to a stranger: NAT-PMP port ownership above all, where
    /// the rebuilt tunnel finds its own forwarded ports taken by its
    /// predecessor. Naming the address makes the exit hand it back and evict
    /// the stale predecessor. A stale or foreign address costs nothing: the
    /// exit degrades it to an independent session start.
    pub fn resume_session_placement(
        &self,
        assigning_exit: ExitId,
        assigned_v4: std::net::Ipv4Addr,
    ) {
        self.placement
            .send_replace(Some((assigning_exit, assigned_v4)));
    }

    /// Subscribe to the session's placement: the inner IPv4 the exit last
    /// assigned, with the exit that assigned it, which after a migration is
    /// not the exit the supervisor was built for. It is updated before the
    /// matching `IpAssign` reaches [`SupervisorConfig::ip_assign_channel`],
    /// so a deployer reacting to that publication reads the right exit
    /// here. What a deployer keeps across tunnel rebuilds and hands back
    /// through [`Self::resume_session_placement`]. Holding the receiver does
    /// not keep the supervisor alive.
    #[must_use]
    pub fn placement_rx(&self) -> watch::Receiver<Option<(ExitId, std::net::Ipv4Addr)>> {
        self.placement.subscribe()
    }

    /// Session-placement hint for the next setup request to `exit_id`: the
    /// address this session already holds there, or the all-zero
    /// session-fresh sentinel when there is no predecessor on that exit to
    /// continue.
    fn session_placement_hint(&self, exit_id: ExitId) -> Option<std::net::Ipv4Addr> {
        let last = *self.placement.borrow();
        Some(match last {
            Some((assigning_exit, addr)) if assigning_exit == exit_id => addr,
            _ => std::net::Ipv4Addr::UNSPECIFIED,
        })
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

    /// Subscribe to the goodput-prober's verdict
    /// ([`crate::path_health::PathHealth`]). Observes the degraded
    /// states the dead-path watches cannot see (bulk traffic dead
    /// behind a live trickle) so an embedder can surface "the PATH is
    /// degraded" instead of a healthy-looking dead tunnel. Call BEFORE
    /// [`Self::run`] consumes `self`.
    #[must_use]
    pub fn path_health_rx(&self) -> watch::Receiver<crate::path_health::PathHealth> {
        self.prober.health_watch()
    }

    /// Subscribe to the per-leg reading of the live bond's latest
    /// path-health sweep ([`crate::path_health::LegHealth`]): which legs
    /// deliver a probe end to end and which do not. It is the only per-leg
    /// delivery signal a leg's QUIC counters cannot fake. Call BEFORE
    /// [`Self::run`] consumes `self`.
    #[must_use]
    pub fn leg_health_rx(&self) -> watch::Receiver<crate::path_health::LegHealth> {
        self.prober.leg_health_watch()
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
        let mut redial = self.config.backoff.forever();
        // A token stack part-way through its refusal retries, re-presented by
        // the next dial instead of a fresh stack from the provider.
        let mut retrying_tokens: Option<TokenStack> = None;
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
            let (client, mut session_target) = tokio::select! {
                biased;
                () = self.tx.closed() => {
                    tracing::info!(
                        "supervisor watch receivers dropped during dial, terminating"
                    );
                    return Ok(());
                }
                result = self.connect_with_unbounded_retry(&mut redial) => result?,
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
            let session_tokens = match retrying_tokens.take() {
                Some(stack) => Some(stack),
                None => match self.select_session_tokens() {
                    Ok(stack) => stack,
                    Err(error) => {
                        tracing::warn!(%error, "tokens-only session has no token; not setting it up");
                        drop(primary);
                        return Err(error);
                    }
                },
            };
            let assign = match self
                .setup_primary(&primary, session_tokens.as_ref().map(TokenStack::as_slice))
                .await
            {
                SetupOutcome::Assigned(assign) => assign,
                SetupOutcome::Rejected(reason) => {
                    if is_token_refusal(reason)
                        && let Some(mut stack) = session_tokens
                    {
                        if stack.rotate() {
                            // No-log: counts only, never a token or its serial.
                            tracing::info!(
                                refused = stack.refused,
                                stack = stack.tokens.len(),
                                "exit refused the session token; redialling with the next token"
                            );
                            drop(primary);
                            retrying_tokens = Some(stack);
                            continue;
                        }
                        if self.admission == SessionAdmission::TokensOnly {
                            tracing::warn!(
                                stack = stack.tokens.len(),
                                "exit refused every token of a tokens-only session"
                            );
                            drop(primary);
                            return Err(MultiHopError::NoSessionToken(
                                NoSessionTokenCause::AllRefused,
                            ));
                        }
                    }
                    let _ = self.fatal_tx.send(Some(reason));
                    tracing::warn!(%reason, "multi-hop session rejected by exit at setup; surfacing fatal");
                    return Err(MultiHopError::Rejected(reason));
                }
                SetupOutcome::TimedOut => {
                    retrying_tokens = session_tokens.filter(TokenStack::is_retrying);
                    // The censor shape: the handshake passed, the request went
                    // out, nothing came back. No session is born, so the
                    // session-death path below never runs and this is the only
                    // place the carrier-first memory can learn about it.
                    crate::udp_hostility::record_setup_timeout(primary.is_over_carrier());
                    tracing::warn!(
                        timeout_secs = SETUP_ROUND_TRIP_TIMEOUT.as_secs(),
                        "multi-hop setup round-trip answered nothing; redialling"
                    );
                    drop(primary);
                    continue;
                }
                SetupOutcome::Failed(error) => {
                    // Never published: the redial draws the next backoff
                    // delay, since nothing reset the schedule.
                    retrying_tokens = session_tokens.filter(TokenStack::is_retrying);
                    self.report_setup_failure(&primary, &session_target, error.as_ref());
                    drop(primary);
                    continue;
                }
            };
            let mut bundle = MultiHopBundle::new_unsealed(vec![primary.clone()]);
            bundle.set_source_addresses(assign.assigned, assign.assigned_v6);
            bundle.set_probe_tap(self.prober.tap());

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
            drop(crate::path_health::spawn_path_health(
                Arc::downgrade(&bundle),
                self.prober.clone(),
                self.overlap.clone(),
            ));
            self.spawn_background_bond(
                &bundle,
                &session_target,
                assign,
                session_tokens.map(TokenStack::into_tokens),
            );
            self.notify_on_reconnect(first_session);
            self.notify_path_rtt(
                session_target.relay.relay_ed25519_pubkey,
                bundle.quinn_stats().path.rtt,
            );
            first_session = false;
            // Establishment instant of the session currently served: its
            // lifetime at close is what tells a post-handshake kill (a censor
            // passing the handshake and dropping the flow) from an ordinary
            // loss, and feeds the carrier-first dial verdict.
            let mut session_established = Instant::now();

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
                        // spuriously redialed). The uplink half counts only
                        // what the exit can answer.
                        move || {
                            (
                                sample.answerable_uplink_total(),
                                sample.real_traffic_totals().1,
                            )
                        }
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
                            Some((new_bundle, new_primary, new_target)) => {
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
                                new_bundle.set_probe_tap(self.prober.tap());
                                if self.tx.send(Some(new_bundle.clone())).is_err() {
                                    return Ok(());
                                }
                                if let Some(observer) = self.config.on_overlap_swapped.as_ref() {
                                    observer(&new_target);
                                }
                                drop(warrenguard_transport_core::spawn_path_probe(
                                    "client-mh",
                                    new_bundle.clone_connections(),
                                    None,
                                ));
                                drop(crate::path_health::spawn_path_health(
                                    Arc::downgrade(&new_bundle),
                                    self.prober.clone(),
                                    self.overlap.clone(),
                                ));
                                self.notify_on_reconnect(false);
                                self.metrics.reconnect_count.fetch_add(1, Ordering::Relaxed);
                                // Last sample of the OLD session before its
                                // deferred close, then the fresh session's
                                // post-handshake sample under ITS dialed key.
                                self.notify_path_rtt(
                                    session_target.relay.relay_ed25519_pubkey,
                                    bundle.quinn_stats().path.rtt,
                                );
                                Self::spawn_deferred_close(bundle.clone(), primary.clone());
                                tracing::info!(
                                    "multi-hop overlap migration: swapped to a fresh session, old draining"
                                );
                                // The outgoing session is judged like one that
                                // died: a healthy one clears the escalation,
                                // so its successor's early death is not
                                // charged the waits of older failures.
                                if crate::redial_policy::is_healthy_uptime(
                                    session_established.elapsed(),
                                ) {
                                    redial.reset();
                                }
                                bundle = new_bundle;
                                primary = new_primary;
                                session_target = new_target;
                                session_established = Instant::now();
                                self.notify_path_rtt(
                                    session_target.relay.relay_ed25519_pubkey,
                                    bundle.quinn_stats().path.rtt,
                                );
                                continue;
                            }
                            None => continue,
                        }
                    }
                };

                // The current session closed (cold path). Its last smoothed
                // RTT is still readable on the closed connection handle and
                // is the session's parting sample (a degraded path records
                // high, correctly biasing later selection away).
                self.notify_path_rtt(
                    session_target.relay.relay_ed25519_pubkey,
                    bundle.quinn_stats().path.rtt,
                );
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

                // Only a session that served for the healthy uptime earns an
                // immediate redial; one that died sooner leaves the schedule
                // escalating, so an exit that drops every session right after
                // setup is not answered with back-to-back handshakes.
                if crate::redial_policy::is_healthy_uptime(session_established.elapsed()) {
                    redial.reset();
                }

                // Feed the carrier-first verdict: a UDP session that a watchdog
                // killed within a minute of establishing is one post-handshake
                // kill, and enough of them in a row make the next dial try the
                // TLS-over-TCP carrier before racing it.
                crate::udp_hostility::record_session_end(
                    bundle.is_over_carrier(),
                    session_established.elapsed(),
                    watchdog_forced,
                );

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

    /// Dial ONE fresh QUIC + handshake session to `target`, no retry. The
    /// cold-dial retry loop ([`Self::connect_with_unbounded_retry`]) and the
    /// warm make-before-break overlap dial ([`Self::try_overlap`], a
    /// best-effort single attempt) both build on this, each with one
    /// [`Self::current_target`] snapshot per attempt that the attempt keeps:
    /// a `migrate_to` landing mid-dial redirects the NEXT attempt, and every
    /// report about this one (a refusal, the RTT samples, the circuit an
    /// overlap swap landed on) names the circuit it actually dialled.
    async fn connect_once(&self, target: &CircuitTarget) -> Result<MultiHopClient, MultiHopError> {
        Self::dial_target(&self.config, target, self.config.bind_addr).await
    }

    /// Dial one fresh session to `target`, preferring the post-quantum X-Wing
    /// (`/v2`) seal when the target carries an ML-KEM key and falling back to
    /// the classical X25519 (`/v1`) seal otherwise. `require_pq = false`: an
    /// exit advertising no PQ key stays on the byte-identical classical session,
    /// so this is inert on the wire until exits publish PQ descriptors. Shared
    /// by the primary dial ([`Self::connect_once`], itself the overlap re-dial
    /// and cold-retry path) and each bonded secondary ([`Self::dial_secondary`])
    /// so a make-before-break swap never downgrades a live PQ circuit.
    async fn dial_target(
        config: &SupervisorConfig,
        target: &CircuitTarget,
        bind_addr: std::net::SocketAddr,
    ) -> Result<MultiHopClient, MultiHopError> {
        #[cfg(feature = "pq-hpke")]
        if let Some(mlkem768_ek) = pq_dial_key(target) {
            return MultiHopClient::connect_with_transport_config_pq(
                &target.relay,
                target.exit_id,
                &target.exit_x25519_multihop_pubkey,
                mlkem768_ek,
                false,
                &config.operational_pubkey,
                &config.client_signing,
                bind_addr,
                Self::dial_transport_config(config),
                config.socket_bypass,
            )
            .await;
        }
        MultiHopClient::connect_with_transport_config(
            &target.relay,
            target.exit_id,
            &target.exit_x25519_multihop_pubkey,
            &config.operational_pubkey,
            &config.client_signing,
            bind_addr,
            Self::dial_transport_config(config),
            config.socket_bypass,
        )
        .await
    }

    /// The anonymous v7 token stack for ONE session. With no provider wired,
    /// or an empty stack from it (no token available this epoch), the default
    /// admission falls back to v6 (`Ok(None)`) rather than fail closed, and
    /// [`SessionAdmission::TokensOnly`] fails with
    /// [`NoSessionTokenCause::Empty`]. Called once per session establishment;
    /// the same stack feeds the primary and every bonded secondary so they
    /// share one serial and one sticky IP.
    fn select_session_tokens(&self) -> Result<Option<TokenStack>, MultiHopError> {
        let stack = self
            .config
            .session_token_provider
            .as_ref()
            .and_then(|provider| TokenStack::new(provider()));
        match (stack, self.admission) {
            (None, SessionAdmission::TokensOnly) => {
                Err(MultiHopError::NoSessionToken(NoSessionTokenCause::Empty))
            }
            (stack, _) => Ok(stack),
        }
    }

    /// Run the primary's reliable setup-stream round-trip, bounded by
    /// [`SETUP_ROUND_TRIP_TIMEOUT`], and say what it produced. An assigned
    /// address is already published on the [`IpAssignChannel`] when this
    /// returns. A definitive policy refusal must NOT become a live session
    /// (it would be a fake "Connected" plus a reconnect storm): it comes back
    /// as [`SetupOutcome::Rejected`], read from the sealed detail on the setup
    /// stream (specific cause) or from the opaque close code.
    async fn setup_primary(
        &self,
        primary: &Arc<MultiHopClient>,
        session_tokens: Option<&[SessionToken]>,
    ) -> SetupOutcome {
        tokio::time::timeout(
            SETUP_ROUND_TRIP_TIMEOUT,
            self.setup_primary_unbounded(primary, session_tokens),
        )
        .await
        .unwrap_or(SetupOutcome::TimedOut)
    }

    /// [`Self::setup_primary`] without the deadline. Split out so the timeout
    /// is stated once and cannot be forgotten at a call site.
    async fn setup_primary_unbounded(
        &self,
        primary: &Arc<MultiHopClient>,
        session_tokens: Option<&[SessionToken]>,
    ) -> SetupOutcome {
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
        let placement = self.session_placement_hint(primary.exit_id());
        let setup_result = primary
            .setup_over_stream_with_options(
                self.admission.wallet_identity(&self.config.client_signing),
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
            return SetupOutcome::Rejected(reason);
        }
        let reply = match setup_result {
            Ok(reply) => reply,
            Err(e) => return SetupOutcome::Failed(Some(e)),
        };
        let Some(spec) = Self::decode_ip_assign(&reply) else {
            return SetupOutcome::Failed(None);
        };
        // Whether the exit kept the IPv4 this session named: `moved` is a
        // tunnel rebuild on the client, and after an exit restart `kept` is
        // the exit handing the session back its address. The address itself
        // never reaches a log.
        let named = placement.filter(|named| !named.is_unspecified());
        tracing::info!(
            placement = match named {
                Some(named) if named == spec.assigned => "kept",
                Some(_) => "moved",
                None => "new",
            },
            "multi-hop setup assigned the session its inner IPv4"
        );
        self.placement
            .send_replace(Some((primary.exit_id(), spec.assigned)));
        self.publish_setup_ip_assign(&spec);
        prime_leg(primary);
        SetupOutcome::Assigned(spec)
    }

    /// Account for a setup round-trip that ended without an `IpAssign`: close
    /// the connection so the exit frees whatever it holds for it, report a
    /// deliberate refusal to [`SupervisorConfig::on_dial_refused`] like one
    /// met at the handshake (so the deployer reselects instead of waiting the
    /// drain out), and say which of the three it was. The close code, when
    /// there is one, rides in the error; no address or identity does.
    fn report_setup_failure(
        &self,
        primary: &MultiHopClient,
        dialled: &CircuitTarget,
        error: Option<&MultiHopError>,
    ) {
        primary.force_close_for_reconnect();
        match error {
            Some(e) => match e.dial_refusal() {
                Some(hop) => {
                    tracing::warn!(
                        error = %e,
                        refused_by = hop.as_str(),
                        "multi-hop setup refused after the handshake by a drained node; \
                         session not published, refusal reported, redialling after backoff"
                    );
                    self.notify_dial_refused(e, dialled);
                }
                None => tracing::warn!(
                    error = %e,
                    "multi-hop setup round-trip failed; session not published, \
                     redialling after backoff"
                ),
            },
            None => tracing::warn!(
                "multi-hop setup reply carried no IpAssign; session not published, \
                 redialling after backoff"
            ),
        }
    }

    /// Dial the `want - 1` bonded secondaries in parallel and return
    /// the ones that came up with the primary's sticky IP, in index
    /// order. Best-effort: bonding failures only reduce capacity.
    ///
    /// `target` is the circuit the primary dialled, never a fresh read of
    /// the live target: a secondary names the primary's address as its join
    /// hint, which another exit may hand out as well, so a secondary sent to
    /// a target that moved during the primary's setup can pass the sticky
    /// check and leave one bond spanning two exits.
    async fn bond_secondaries(
        config: &SupervisorConfig,
        admission: SessionAdmission,
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
                let secondary = Self::dial_secondary(
                    &config,
                    admission,
                    &target,
                    index,
                    primary_spec,
                    tokens.as_deref(),
                )
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
    ///
    /// `dialled` is the circuit the primary dialled, for the reason given on
    /// [`Self::bond_secondaries`].
    fn spawn_background_bond(
        &self,
        bundle: &Arc<MultiHopBundle>,
        dialled: &CircuitTarget,
        primary_spec: IpAssignSpec,
        session_tokens: Option<Vec<SessionToken>>,
    ) {
        let want = resolve_bonded_want(
            self.config.n_connections,
            warrenguard_config::knobs::multihop_conns_override(),
        );
        if want <= 1 {
            bundle.seal();
            return;
        }
        let weak = Arc::downgrade(bundle);
        let config = self.config.clone();
        let admission = self.admission;
        let target = dialled.clone();
        tokio::spawn(async move {
            let mut dials = tokio::task::JoinSet::new();
            for index in 1..want {
                let config = config.clone();
                let target = target.clone();
                // Same token stack as the primary (shared serial -> same IP).
                let tokens = session_tokens.clone();
                dials.spawn(async move {
                    Self::dial_secondary(
                        &config,
                        admission,
                        &target,
                        index,
                        primary_spec,
                        tokens.as_deref(),
                    )
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
    async fn establish_session(
        &self,
        primary: Arc<MultiHopClient>,
        dialled: &CircuitTarget,
        session_tokens: Option<&TokenStack>,
    ) -> Established {
        let primary_spec = match self
            .setup_primary(&primary, session_tokens.map(TokenStack::as_slice))
            .await
        {
            SetupOutcome::Assigned(spec) => spec,
            SetupOutcome::Rejected(reason) => return Established::Rejected(reason),
            SetupOutcome::TimedOut => return Established::SetupTimedOut,
            SetupOutcome::Failed(error) => {
                self.report_setup_failure(&primary, dialled, error.as_ref());
                return Established::SetupFailed;
            }
        };

        // Bonded secondaries: best-effort extra connections under the same
        // identity (the exit's sticky allocator gives them ONE inner IP).
        // The primary's `IpAssign` is the stickiness witness.
        let mut clients = vec![primary.clone()];
        let want = resolve_bonded_want(
            self.config.n_connections,
            warrenguard_config::knobs::multihop_conns_override(),
        );
        if want > 1 {
            clients.extend(
                Self::bond_secondaries(
                    &self.config,
                    self.admission,
                    dialled,
                    primary_spec,
                    want,
                    session_tokens.map(|stack| stack.as_slice().to_vec()),
                )
                .await,
            );
            tracing::info!(
                bonded = clients.len(),
                requested = want,
                "multi-hop bonded session assembled"
            );
        }
        let bundle = MultiHopBundle::new(clients);
        bundle.set_source_addresses(primary_spec.assigned, primary_spec.assigned_v6);
        Established::Session { bundle, primary }
    }

    /// Make-before-break warm dial: a best-effort SINGLE connect +
    /// establish while the CURRENT session keeps serving. Returns the new
    /// `(bundle, primary)` on success, or `None` to keep the current session
    /// (a failed or rejected overlap dial must never tear down the still
    /// healthy current session - the natural cold path covers a real death).
    async fn try_overlap(
        &self,
    ) -> Option<(Arc<MultiHopBundle>, Arc<MultiHopClient>, CircuitTarget)> {
        let target = self.current_target();
        // Set once the exit refused a token: the next dial leads with the
        // stack's next token instead of popping a fresh stack.
        let mut retrying_tokens: Option<TokenStack> = None;
        loop {
            let primary = match self.connect_once(&target).await {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    // A refusal is reported like one met on a cold dial, so the
                    // deployer reselects while the current session still serves.
                    self.notify_dial_refused(&e, &target);
                    tracing::warn!(error = %e, "overlap dial failed; keeping the current session");
                    return None;
                }
            };
            // One token stack for this whole session (primary + secondaries).
            let session_tokens = match retrying_tokens.take() {
                Some(stack) => Some(stack),
                None => match self.select_session_tokens() {
                    Ok(stack) => stack,
                    Err(error) => {
                        tracing::warn!(%error, "overlap dial has no session token; keeping the current session");
                        return None;
                    }
                },
            };
            match self
                .establish_session(primary, &target, session_tokens.as_ref())
                .await
            {
                Established::Session { bundle, primary } => return Some((bundle, primary, target)),
                Established::Rejected(reason) => {
                    if is_token_refusal(reason)
                        && let Some(mut stack) = session_tokens
                        && stack.rotate()
                    {
                        tracing::info!(
                            refused = stack.refused,
                            stack = stack.tokens.len(),
                            "overlap dial's session token refused; redialling with the next token"
                        );
                        retrying_tokens = Some(stack);
                        continue;
                    }
                    tracing::warn!(%reason, "overlap dial rejected by exit; keeping the current session");
                    return None;
                }
                // Deliberately NOT recorded as a censor signature: an overlap runs
                // while a session is serving fine, so the network is demonstrably
                // carrying traffic and a stalled warm dial says much less than the
                // same stall on a cold one.
                Established::SetupTimedOut => {
                    tracing::warn!(
                        "overlap dial setup answered nothing; keeping the current session"
                    );
                    return None;
                }
                // Already logged and reported by `establish_session`.
                Established::SetupFailed => return None,
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

    /// Fire the [`SupervisorConfig::on_path_rtt`] observer with a
    /// measured path RTT for the session dialed to `relay_pubkey`.
    /// Extracted as a helper so the millisecond conversion and dispatch
    /// are testable without a real QUIC connection.
    fn notify_path_rtt(&self, relay_pubkey: [u8; 32], rtt: std::time::Duration) {
        if let Some(observer) = self.config.on_path_rtt.as_ref() {
            observer(
                relay_pubkey,
                u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX),
            );
        }
    }

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
    /// `None` for a non-`IpAssign` reply or a decode failure (logged): a
    /// connection that gets no address from the exit never carries traffic.
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
                        variant = msg.variant_name(),
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
        // The goodput prober sources its echoes from the CURRENT
        // assignment (a stale source is dropped by the exit's spoof
        // guard), so the endpoints follow every assignment, channel or
        // not.
        self.prober.set_endpoints(spec.assigned, spec.gateway);
        let Some(channel) = self.config.ip_assign_channel.as_ref() else {
            return;
        };
        // No-log policy (matches `run_reassign_loop`'s INV-3 in
        // supervised_pump.rs): a per-session tunnel address is a correlation
        // handle across log lines whichever family it belongs to, so NEITHER
        // value is logged here. Only the prefix length and the PRESENCE of a
        // v6 allocation (`dual_stack`) are emitted.
        tracing::info!(
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
        admission: SessionAdmission,
        target: &CircuitTarget,
        index: usize,
        primary_spec: IpAssignSpec,
        session_tokens: Option<&[SessionToken]>,
    ) -> Option<Arc<MultiHopClient>> {
        // A tokens-only primary never sets up without tokens, so this only
        // guards a future caller against building a wallet request here.
        if admission == SessionAdmission::TokensOnly && session_tokens.is_none_or(<[_]>::is_empty) {
            return None;
        }
        let bind_addr = secondary_bind_addr(config.bind_addr);
        for attempt in 0..2u8 {
            let result = Self::dial_target(config, target, bind_addr).await;
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
                    admission.wallet_identity(&config.client_signing),
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
                    // Same verdict as a refused dial: the next attempt would
                    // be refused too.
                    if e.dial_refusal().is_some() {
                        return None;
                    }
                    continue;
                }
            };
            match spec {
                Some(spec)
                    if spec.assigned == primary_spec.assigned
                        && spec.assigned_v6 == primary_spec.assigned_v6 =>
                {
                    // No-log (INV-3): the sticky per-session address is not an
                    // event field; `index` identifies the connection.
                    tracing::debug!(index, "bonded secondary up");
                    prime_leg(&client);
                    return Some(client);
                }
                Some(_) => {
                    // Allocator did not honor stickiness (pool churn,
                    // exit restart mid-bond): this connection would
                    // receive downlink for the WRONG address. Close it.
                    // No-log (INV-3): neither the primary's nor the
                    // secondary's sticky address is logged; the mismatch
                    // itself is the actionable signal.
                    tracing::warn!(
                        index,
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

    /// Fire the [`SupervisorConfig::on_reconnect`] observer when a
    /// reconnect (not the initial connect) just completed. Extracted as
    /// a helper so the dispatch logic is testable without a real QUIC
    /// connection: tests can drive this directly with a counter-bumping
    /// observer and assert the gate (first_session vs subsequent
    /// publication).
    fn notify_on_reconnect(&self, first_session: bool) {
        if first_session {
            return;
        }
        if let Some(observer) = self.config.on_reconnect.as_ref() {
            observer();
        }
    }

    /// Fire the [`SupervisorConfig::on_dial_refused`] observer when a
    /// dial attempt failed with a deliberate refusal, naming `dialled`, the
    /// circuit that attempt dialled. Never a fresh read of the live target:
    /// a `migrate_to` that lands while the attempt is in flight redirects
    /// the next attempt, and reading the target here would charge this
    /// refusal to the node the deployer has just moved to. Extracted so
    /// the dispatch gate (refusal vs plain transient) is testable
    /// without a real QUIC dial.
    fn notify_dial_refused(&self, error: &MultiHopError, dialled: &CircuitTarget) {
        let Some(hop) = error.dial_refusal() else {
            return;
        };
        let Some(observer) = self.config.on_dial_refused.as_ref() else {
            return;
        };
        observer(hop, dialled.relay.relay_id, *dialled.exit_id.as_bytes());
    }

    /// Drive [`MultiHopClient::connect`] /
    /// [`MultiHopClient::connect_with_warren_obfuscation`] until a dial
    /// succeeds, waiting `redial`'s next delay before every attempt. The
    /// schedule is the supervisor's, not this call's: it arrives escalated
    /// after a refused setup or a session that died young, and reset after
    /// a healthy one, so the first attempt of a cycle is immediate only when
    /// the previous session earned it.
    ///
    /// Non-retriable errors propagate after the first occurrence so an
    /// operator misconfiguration (rotated operational pubkey, broken
    /// TLS provider) is visible instead of burning the user's battery
    /// in a retry loop.
    async fn connect_with_unbounded_retry(
        &self,
        redial: &mut JitterBackoff,
    ) -> Result<(MultiHopClient, CircuitTarget), MultiHopError> {
        let mut attempt_count = 0u64;
        loop {
            let delay = redial.next_delay();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            attempt_count = attempt_count.saturating_add(1);
            let target = self.current_target();
            match self.connect_once(&target).await {
                Ok(client) => return Ok((client, target)),
                Err(e) if e.is_retriable() => {
                    self.notify_dial_refused(&e, &target);
                    tracing::warn!(
                        error = %e,
                        attempt = attempt_count,
                        "supervisor reconnect attempt failed, retrying after backoff"
                    );
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Puts one cover datagram on a leg the moment its setup completes.
///
/// An exit that refreshes a `/v2` leg's session only from the leg's own
/// traffic forgets a leg that stays silent for five seconds after its setup,
/// and drops every later frame of it until the client's next rekey, thirty
/// minutes on. Such exits are deployed, a bonded secondary carries nothing
/// until a flow hashes onto it, and a quiet host sends nothing at all, so
/// every leg speaks first. The datagram is idle cover, dropped by the exit
/// before its TUN and sized from the same distribution as every other cover
/// datagram, so it adds no shape of its own to the wire.
fn prime_leg(client: &MultiHopClient) {
    let budget = client.max_inner_payload();
    let now = Instant::now();
    let size = warrenguard_pump::idle_cover::IdleCover::new(rand::random(), now, Some(budget))
        .fire_size(now);
    let padding_len = size.saturating_sub(1).min(budget.saturating_sub(1));
    if let Err(e) = client.send_cover_traffic(padding_len) {
        tracing::debug!(error = %e, "could not put a first frame on a fresh multi-hop leg");
    }
}

/// Bonded width for a session: the `WARREN_MULTIHOP_CONNS` env override
/// when set, else the deployer-configured `n_connections`, clamped to
/// the bundle's hard cap. Pure so the resolution is unit-testable
/// without touching the process environment.
fn resolve_bonded_want(configured: usize, env_override: Option<usize>) -> usize {
    env_override
        .unwrap_or(configured)
        .clamp(1, MAX_BONDED_CONNECTIONS)
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

/// The exit ML-KEM key to seal a dial with, or `None` for the classical seal.
/// Empty key material counts as absent so an exit that publishes no PQ
/// descriptor keeps the classical `/v1` session (inert on the wire until a
/// fleet PQ flip).
#[cfg(feature = "pq-hpke")]
fn pq_dial_key(target: &CircuitTarget) -> Option<&[u8]> {
    target
        .exit_mlkem768_pubkey
        .as_deref()
        .filter(|key| !key.is_empty())
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
/// (uplink-loss watch blind), yet the tunnel carries nothing. A relay that
/// ACKs uplink datagrams and forwards none leaves the client sitting
/// "connected" with zero traffic until quinn's idle
/// timeout. A false positive only costs a ~30 ms redial (the exit's
/// pubkey-sticky allocator preserves the inner IP); 15 s of genuinely one-way
/// app traffic (no DNS reply, no TCP ACK, nothing) is a dead tunnel.
///
/// `sample` returns cumulative (app datagrams sent that the exit can answer,
/// app datagrams received) across the bundle. Uses `tokio::time::Instant` for
/// `start_paused` testability.
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
                endpoint_v6: None,
                cover_domain: None,
                tcp_fallback: false,
                signature: [0u8; 64],
            }),
            exit_id: ExitId::from_bytes([0u8; 16]),
            exit_x25519_multihop_pubkey: [0u8; 32],
            exit_mlkem768_pubkey: None,
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
            on_path_rtt: None,
            session_token_provider: None,
        }
    }

    #[test]
    fn bonded_want_keeps_the_configured_width_without_an_override() {
        assert_eq!(resolve_bonded_want(1, None), 1);
        assert_eq!(resolve_bonded_want(4, None), 4);
        assert_eq!(
            resolve_bonded_want(0, None),
            1,
            "a zero config still dials the mandatory primary"
        );
        assert_eq!(resolve_bonded_want(99, None), MAX_BONDED_CONNECTIONS);
    }

    #[test]
    fn bonded_want_env_override_wins_over_the_configured_width() {
        assert_eq!(
            resolve_bonded_want(1, Some(4)),
            4,
            "the A/B env override must widen a deployer stuck on the default width"
        );
        assert_eq!(
            resolve_bonded_want(8, Some(1)),
            1,
            "the override must also narrow, as the rollback lever"
        );
        assert_eq!(resolve_bonded_want(1, Some(99)), MAX_BONDED_CONNECTIONS);
        assert_eq!(
            resolve_bonded_want(4, Some(0)),
            1,
            "a zero override is clamped to the mandatory primary, never zero sessions"
        );
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

    #[cfg(feature = "pq-hpke")]
    #[test]
    fn supervisor_prefers_pq_seal_only_with_a_non_empty_exit_mlkem_key() {
        use warrenguard_multihop::MLKEM768_ENCAPS_KEY_LEN;

        // No PQ descriptor: the target carries no key and the dial stays
        // classical, byte-identical to today (the de-risk property).
        let classical = CircuitTarget::from_config(&dummy_config());
        assert!(classical.exit_mlkem768_pubkey.is_none());
        assert!(pq_dial_key(&classical).is_none());

        // An advertised-but-empty key must NOT force the PQ seal.
        let mut empty = classical.clone();
        empty.exit_mlkem768_pubkey = Some(Vec::new());
        assert!(pq_dial_key(&empty).is_none());

        // A real ML-KEM key threads through `from_config` and selects PQ.
        let mut cfg = dummy_config();
        let key = vec![7u8; MLKEM768_ENCAPS_KEY_LEN];
        cfg.exit_mlkem768_pubkey = Some(key.clone());
        let pq = CircuitTarget::from_config(&cfg);
        assert_eq!(pq.exit_mlkem768_pubkey.as_deref(), Some(key.as_slice()));
        assert_eq!(pq_dial_key(&pq), Some(key.as_slice()));
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

    /// The silent-relay shape: app datagrams keep going up, transport
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
    fn notify_path_rtt_reports_millis_keyed_by_the_dialed_relay() {
        // The observer must receive the DIALED relay pubkey unchanged and
        // the RTT converted to whole milliseconds: this pair is the exact
        // record an embedder feeds its client-side RTT store, so a key or
        // unit slip here silently poisons path-aware selection downstream.
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let observer: PathRttObserver = Arc::new(move |pubkey, rtt_ms| {
            sink.lock()
                .expect("observer sink lock")
                .push((pubkey, rtt_ms));
        });
        let mut cfg = dummy_config();
        cfg.on_path_rtt = Some(observer);
        let (supervisor, _rx) = MultiHopSupervisor::new(cfg);
        supervisor.notify_path_rtt([7u8; 32], Duration::from_micros(23_400));
        assert_eq!(
            seen.lock().expect("observer sink lock").as_slice(),
            &[([7u8; 32], 23)]
        );
        drop(supervisor);
    }

    #[test]
    fn a_fresh_supervisor_asks_the_exit_for_a_session_of_its_own() {
        let config = dummy_config();
        let exit_id = config.exit_id;
        let (supervisor, _rx) = MultiHopSupervisor::new(config);
        assert_eq!(
            supervisor.session_placement_hint(exit_id),
            Some(std::net::Ipv4Addr::UNSPECIFIED),
            "with no predecessor to name, the hint must be the session-fresh sentinel"
        );
    }

    #[test]
    fn a_resumed_supervisor_names_its_predecessors_address() {
        let config = dummy_config();
        let exit_id = config.exit_id;
        let (supervisor, _rx) = MultiHopSupervisor::new(config);
        supervisor.resume_session_placement(exit_id, std::net::Ipv4Addr::new(10, 66, 0, 7));
        assert_eq!(
            supervisor.session_placement_hint(exit_id),
            Some(std::net::Ipv4Addr::new(10, 66, 0, 7)),
            "a rebuilt tunnel must keep its session on the address it already holds"
        );
    }

    fn token(fill: u8) -> SessionToken {
        SessionToken([fill; warrenguard_wire::SESSION_TOKEN_LEN])
    }

    fn leads(stack: &TokenStack) -> Vec<u8> {
        stack.as_slice().iter().map(|t| t.0[0]).collect()
    }

    #[test]
    fn a_refused_lead_token_moves_to_the_back_of_the_stack_until_each_was_presented() {
        // The refused token stays in the stack (another session may release its
        // serial), and the redials stop once every token led one attempt.
        let mut stack = TokenStack::new(vec![token(1), token(2), token(3)]).expect("non-empty");
        assert!(stack.rotate());
        assert_eq!(leads(&stack), [2, 3, 1]);
        assert!(stack.rotate());
        assert_eq!(leads(&stack), [3, 1, 2]);
        assert!(!stack.rotate(), "a third refusal has no untried token left");
        assert_eq!(
            leads(&stack),
            [3, 1, 2],
            "an exhausted stack keeps its tokens"
        );
    }

    #[test]
    fn a_single_token_stack_has_no_next_token() {
        let mut stack = TokenStack::new(vec![token(1)]).expect("non-empty");
        assert!(!stack.rotate());
    }

    #[test]
    fn an_empty_provider_stack_is_no_stack() {
        assert!(TokenStack::new(Vec::new()).is_none());
    }

    #[test]
    fn only_the_refusals_a_token_can_cause_move_to_the_next_token() {
        // A v7 refusal of any cause reaches the client as the sealed `Rejected`
        // detail (or, detail lost, the opaque close). Pool exhaustion and a ban
        // are not about the token: another token cannot change them.
        assert!(is_token_refusal(RejectionReason::NotAllowlisted));
        assert!(is_token_refusal(RejectionReason::PolicyRefused));
        assert!(!is_token_refusal(RejectionReason::IpExhausted));
        assert!(!is_token_refusal(RejectionReason::Banned(0)));
    }

    #[test]
    fn tokens_only_admission_never_hands_the_wallet_key_to_a_setup() {
        let key = SigningKey::from_bytes(&[0x07; 32]);
        assert!(SessionAdmission::TokensOnly.wallet_identity(&key).is_none());
        assert!(
            SessionAdmission::TokensOrWallet
                .wallet_identity(&key)
                .is_some()
        );
    }

    #[test]
    fn a_supervisor_names_an_address_only_to_the_exit_that_assigned_it() {
        // An address is one exit's allocation. Naming it to another exit
        // tells that exit something about the session elsewhere, and a
        // freshly restarted exit would even hand it over, carrying one inner
        // address across exits. A tunnel rebuilt onto another exit than the
        // one its predecessor used is the everyday case.
        let config = dummy_config();
        let configured_exit = config.exit_id;
        let assigning_exit = ExitId::from_bytes([0x7E; 16]);
        let (supervisor, _rx) = MultiHopSupervisor::new(config);
        supervisor.resume_session_placement(assigning_exit, std::net::Ipv4Addr::new(10, 66, 0, 7));
        assert_eq!(
            supervisor.session_placement_hint(configured_exit),
            Some(std::net::Ipv4Addr::UNSPECIFIED),
            "a dial to another exit must start a fresh session"
        );
        assert_eq!(
            supervisor.session_placement_hint(assigning_exit),
            Some(std::net::Ipv4Addr::new(10, 66, 0, 7)),
            "the assigning exit is still named its address"
        );
    }

    #[test]
    fn notify_path_rtt_is_a_noop_when_unwired() {
        let cfg = dummy_config();
        let (supervisor, _rx) = MultiHopSupervisor::new(cfg);
        supervisor.notify_path_rtt([7u8; 32], Duration::from_millis(10));
        drop(supervisor);
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
        // and the dialled circuit's identity, and must stay silent on a
        // plain transient error: firing on every blip would make the
        // deployer exclude healthy nodes on ordinary packet loss.
        type SeenRefusals = Vec<(multihop::DialRefusedHop, [u8; 16], [u8; 16])>;
        let seen: Arc<std::sync::Mutex<SeenRefusals>> = Default::default();
        let mut config = dummy_config();
        config.relay = Arc::new(RelayDescriptorSigned {
            relay_id: [0xAB; 16],
            relay_ed25519_pubkey: [0u8; 32],
            endpoint: "127.0.0.1:1".parse().expect("static addr parses"),
            endpoint_v6: None,
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
        let dialled = supervisor.current_target();

        let refused = MultiHopError::Handshake(quinn::ConnectionError::ConnectionClosed(
            quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::CONNECTION_REFUSED,
                frame_type: None,
                reason: bytes::Bytes::from_static(b""),
            },
        ));
        supervisor.notify_dial_refused(&refused, &dialled);
        supervisor.notify_dial_refused(
            &MultiHopError::Handshake(quinn::ConnectionError::TimedOut),
            &dialled,
        );

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
        supervisor.notify_dial_refused(
            &MultiHopError::Handshake(quinn::ConnectionError::ApplicationClosed(
                quinn::ApplicationClose {
                    error_code: quinn::VarInt::from_u32(warrenguard_multihop::WARREN_MH_DRAINING),
                    reason: bytes::Bytes::from_static(b""),
                },
            )),
            &supervisor.current_target(),
        );
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
    use crate::test_support::{FakeMultihopExit, SeenSetupRequest, spawn_fake_multihop_exit};

    fn config_with_fake_exit(
        exit: &FakeMultihopExit,
        operational_key: &SigningKey,
    ) -> SupervisorConfig {
        SupervisorConfig {
            relay: exit.relay.clone(),
            exit_id: exit.exit_id,
            exit_x25519_multihop_pubkey: exit.exit_x25519_pubkey,
            exit_mlkem768_pubkey: None,
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
            on_path_rtt: None,
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

    /// A UDP relay in the middle of the loopback path that can be told to
    /// swallow every packet, both ways. This is what a censor does to a flow it
    /// has classified: the handshake went through, then nothing does.
    struct UdpBlackhole {
        addr: std::net::SocketAddr,
        drop_all: Arc<std::sync::atomic::AtomicBool>,
        task: tokio::task::JoinHandle<()>,
    }

    async fn spawn_udp_blackhole(upstream: std::net::SocketAddr) -> UdpBlackhole {
        use std::sync::atomic::{AtomicBool, Ordering};

        let socket = Arc::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("blackhole relay binds"),
        );
        let addr = socket.local_addr().expect("blackhole addr");
        let drop_all = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let socket = socket.clone();
            let drop_all = drop_all.clone();
            async move {
                let mut buf = vec![0u8; 65_535];
                let mut client: Option<std::net::SocketAddr> = None;
                loop {
                    let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                        return;
                    };
                    if drop_all.load(Ordering::Relaxed) {
                        continue;
                    }
                    if from == upstream {
                        if let Some(client) = client {
                            let _ = socket.send_to(&buf[..n], client).await;
                        }
                    } else {
                        client = Some(from);
                        let _ = socket.send_to(&buf[..n], upstream).await;
                    }
                }
            }
        });
        UdpBlackhole {
            addr,
            drop_all,
            task,
        }
    }

    /// A relay reachable only over IPv6, dialed by a client that asks for the
    /// IPv4 wildcard bind every Warren client passes today. The whole family
    /// decision runs for real here: the route probe, the bind moving to
    /// `[::]:0`, and the genuine QUIC handshake plus HPKE setup against the
    /// fake exit. Before the bind followed the endpoint, this could only ever
    /// answer `ENETUNREACH`, which is the incident of 2026-09-20 in miniature.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dials_a_v6_only_relay_from_the_v4_wildcard_bind() {
        let operational_key = SigningKey::from_bytes(&[0x45; 32]);
        let exit_id = ExitId::from_bytes([0x54; 16]);
        let Some(exit) = crate::test_support::spawn_fake_multihop_exit_on(
            &operational_key,
            exit_id,
            "[::1]:0".parse().expect("static addr parses"),
        ) else {
            eprintln!("skipped: this host has no IPv6 loopback to put the fake relay on");
            return;
        };
        let mut config = config_with_fake_exit(&exit, &operational_key);
        // What every client passes: quinn's historical v4 wildcard.
        config.bind_addr = "0.0.0.0:0".parse().expect("static addr parses");
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
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
        .expect("the v6 relay must accept the dial within 5s");
        assert!(bundle.num_connections() >= 1);
        assert_eq!(
            exit.accepted.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the dial must have reached the relay over IPv6"
        );
        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// The 2026-09-07 Kaliningrad pattern seen from the supervisor: the QUIC
    /// handshake passes, the session is published, and seconds later the
    /// network swallows the flow, so the dead-path watch has to kill it. Two of
    /// those in a row must arm the carrier-first dial verdict for the whole
    /// process. Real time, on purpose: the dead-path window is what the field
    /// failure runs on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_sessions_killed_by_the_dead_path_watch_arm_carrier_first() {
        use std::sync::atomic::Ordering;

        use warrenguard_tcp_fallback::DialPreference;

        let operational_key = SigningKey::from_bytes(&[0x44; 32]);
        let exit_id = ExitId::from_bytes([0x53; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        let blackhole = spawn_udp_blackhole(exit.relay.endpoint).await;
        let mut config = config_with_fake_exit(&exit, &operational_key);
        // The descriptor signature covers the relay id and key, never the
        // endpoint, so the dial can be routed through the blackhole verbatim.
        config.relay = Arc::new(RelayDescriptorSigned {
            endpoint: blackhole.addr,
            endpoint_v6: None,
            ..(*exit.relay).clone()
        });
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        // The tracker is process-wide and other tests in this binary end
        // sessions too: a long healthy UDP session is the documented reset, so
        // the streak counted below starts from zero whatever ran before.
        crate::udp_hostility::record_session_end(false, Duration::from_secs(3600), false);
        let task = tokio::spawn(supervisor.run());

        async fn wait_for(
            rx: &mut watch::Receiver<Option<Arc<MultiHopBundle>>>,
            want_session: bool,
            budget: Duration,
        ) {
            tokio::time::timeout(budget, async {
                loop {
                    if rx.borrow_and_update().is_some() == want_session {
                        return;
                    }
                    rx.changed().await.expect("watch alive");
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!("session state never became published={want_session} within {budget:?}")
            });
        }

        // Two kills: the single-kill tolerance is pinned at the tracker's own
        // unit tests, and a concurrent test ending a session of its own could
        // add a kill here, so only the arming after two is asserted.
        for _kill in 0..2 {
            wait_for(&mut rx, true, Duration::from_secs(10)).await;
            // Let the session live a moment, then swallow the flow: the RX
            // silence watch (15 s at the default) must kill it.
            tokio::time::sleep(Duration::from_millis(500)).await;
            blackhole.drop_all.store(true, Ordering::Relaxed);
            wait_for(&mut rx, false, Duration::from_secs(40)).await;
            blackhole.drop_all.store(false, Ordering::Relaxed);
        }

        assert_eq!(
            crate::udp_hostility::preference(),
            DialPreference::CarrierFirst,
            "two UDP sessions killed within a minute of establishing must make the next dial try the carrier first"
        );

        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        blackhole.task.abort();
    }

    /// The 2026-09-10 Kaliningrad pattern, one layer deeper than the test
    /// above: the handshake passes, the exit RECEIVES the setup request, and
    /// the reply never travels. The client used to park in an untimed
    /// `read_to_end` for the whole of the app's 20 s grace, so it made ONE
    /// attempt per window, never redialled inside it, and taught the
    /// carrier-first memory nothing (that memory is fed by session DEATHS, and
    /// no session is ever born here). Real time, on purpose.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_setup_that_never_answers_is_abandoned_and_arms_carrier_first() {
        use std::sync::atomic::Ordering;

        use warrenguard_tcp_fallback::DialPreference;

        let operational_key = SigningKey::from_bytes(&[0x47; 32]);
        let exit_id = ExitId::from_bytes([0x57; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        exit.swallow_setup.store(true, Ordering::Relaxed);
        let config = config_with_fake_exit(&exit, &operational_key);
        let (supervisor, rx) = MultiHopSupervisor::new(config);
        // The tracker is process-wide and other tests in this binary feed it:
        // a long healthy UDP session is the documented reset, so what is
        // asserted below is this test's own doing.
        crate::udp_hostility::record_session_end(false, Duration::from_secs(3600), false);
        let task = tokio::spawn(supervisor.run());

        // Absolute on purpose, not derived from the constant under test: a
        // budget that tracks the ceiling would stretch with it and this test
        // could never go red by raising it. Generous because the whole crate's
        // suite runs in this process and the dials here are real ones.
        let budget = Duration::from_secs(60);
        tokio::time::timeout(budget, async {
            while exit.accepted.load(Ordering::Relaxed) < 2 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "a setup that never answers must be abandoned and redialled within {budget:?}; \
                 the exit accepted {} connection(s)",
                exit.accepted.load(Ordering::Relaxed)
            )
        });

        assert_eq!(
            crate::udp_hostility::preference(),
            DialPreference::CarrierFirst,
            "a handshake that passes and a setup that answers nothing must send \
             the next dial over the TLS-over-TCP carrier"
        );

        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
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

    /// A deployer that keeps the session's address across tunnel rebuilds
    /// must record it with the exit that assigned it, which after a
    /// migration is not the exit the tunnel was built for. The placement
    /// watch carries both, and it is already current when the `IpAssign`
    /// that triggers a rebuild is published.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_placement_watch_names_the_assigning_exit_before_the_ip_assign_is_published() {
        let operational_key = SigningKey::from_bytes(&[0x4C; 32]);
        let exit_id = ExitId::from_bytes([0x5C; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        let channel = IpAssignChannel::new();
        let mut assigns = channel.subscribe();
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.ip_assign_channel = Some(channel);
        let (supervisor, rx) = MultiHopSupervisor::new(config);
        let placement = supervisor.placement_rx();
        let task = tokio::spawn(supervisor.run());

        tokio::time::timeout(Duration::from_secs(5), assigns.changed())
            .await
            .expect("the setup publishes an IpAssign")
            .expect("channel alive");
        let spec = assigns
            .borrow_and_update()
            .expect("an IpAssign was published");
        assert_eq!(
            *placement.borrow(),
            Some((exit_id, spec.assigned)),
            "the placement names the assigning exit and address by the time the IpAssign is out"
        );

        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A fixed-width redial schedule for the timing tests below: every draw
    /// after the first immediate one lands in 100 to 200 ms, far above what a
    /// loopback handshake takes, so an un-backed-off redial is unmistakable.
    const TEST_BACKOFF: Backoff = Backoff {
        base: Duration::from_millis(200),
        max: Duration::from_millis(200),
    };

    /// Floor of every [`TEST_BACKOFF`] draw, less a margin for the handshake
    /// time that separates a dial from the exit's accept.
    const TEST_BACKOFF_FLOOR: Duration = Duration::from_millis(95);

    /// Waits until the fake exit has accepted `n` connections.
    async fn wait_for_accepts(exit: &FakeMultihopExit, n: usize, within: Duration) {
        tokio::time::timeout(within, async {
            while exit.accepted_at.lock().len() < n {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the fake exit must accept {n} connections within {within:?}"));
    }

    /// Spacing between consecutive connections the fake exit accepted.
    fn redial_gaps(exit: &FakeMultihopExit) -> Vec<Duration> {
        exit.accepted_at
            .lock()
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect()
    }

    /// Every `on_dial_refused` report a test observed, in order.
    type RefusalReports = Arc<Mutex<Vec<(multihop::DialRefusedHop, [u8; 16], [u8; 16])>>>;

    /// An `on_dial_refused` observer that records every report into `reports`.
    fn record_refusals(reports: &RefusalReports) -> DialRefusedObserver {
        let reports = reports.clone();
        Arc::new(move |hop, relay_id, exit_id| {
            reports
                .lock()
                .expect("reports lock")
                .push((hop, relay_id, exit_id));
        })
    }

    /// A setup the exit refuses after the QUIC handshake (here the drain close
    /// a draining one-hop node answers every new session with) is a failed
    /// dial: nothing is published, the refusal reaches `on_dial_refused`
    /// naming the node the connection terminates at, and the redials wait for
    /// the backoff instead of hammering it. Once the exit admits again, the
    /// session is published.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_setup_refused_by_a_draining_exit_is_reported_backed_off_and_never_published() {
        let operational_key = SigningKey::from_bytes(&[0x47; 32]);
        let exit_id = ExitId::from_bytes([0x57; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        exit.refuse_setup.store(
            warrenguard_multihop::WARREN_MH_DRAINING,
            std::sync::atomic::Ordering::Relaxed,
        );
        let reports = RefusalReports::default();
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.backoff = TEST_BACKOFF;
        config.on_dial_refused = Some(record_refusals(&reports));
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let task = tokio::spawn(supervisor.run());

        let published = tokio::time::timeout(Duration::from_millis(1500), rx.changed()).await;
        assert!(
            published.is_err(),
            "a refused setup must never be published as a session"
        );
        let gaps = redial_gaps(&exit);
        assert!(
            gaps.len() >= 2,
            "the supervisor keeps redialling a refusing exit, got {} dials",
            gaps.len() + 1
        );
        assert!(
            gaps.iter().all(|gap| *gap >= TEST_BACKOFF_FLOOR),
            "every redial after a refusal must wait for the backoff, got {gaps:?}"
        );
        let reports = reports.lock().expect("reports lock").clone();
        assert!(
            !reports.is_empty(),
            "a refusal at setup must reach on_dial_refused"
        );
        assert!(
            reports.iter().all(|report| *report
                == (
                    multihop::DialRefusedHop::Entry,
                    exit.relay.relay_id,
                    *exit_id.as_bytes()
                )),
            "each report must name the node that closed the setup, the entry of the dialed \
             circuit, got {reports:?}"
        );

        exit.refuse_setup
            .store(0, std::sync::atomic::Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("once the exit admits again, a session must be published")
            .expect("watch sender alive");
        assert!(
            rx.borrow_and_update().is_some(),
            "the first publication is the admitted session"
        );

        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A circuit to `exit` entered through a relay named `relay_id`, signed by
    /// `operational_key` so the dial verifies it. Every fake exit presents the
    /// same relay key, so the relay id is what tells two entries apart.
    fn circuit_to(
        exit: &FakeMultihopExit,
        relay_id: [u8; 16],
        operational_key: &SigningKey,
    ) -> CircuitTarget {
        use ed25519_dalek::Signer;

        let signature = operational_key
            .sign(&warrenguard_multihop::relay_descriptor_signing_payload(
                &relay_id,
                &exit.relay.relay_ed25519_pubkey,
            ))
            .to_bytes();
        CircuitTarget {
            relay: Arc::new(RelayDescriptorSigned {
                relay_id,
                signature,
                ..(*exit.relay).clone()
            }),
            exit_id: exit.exit_id,
            exit_x25519_multihop_pubkey: exit.exit_x25519_pubkey,
            exit_mlkem768_pubkey: None,
        }
    }

    /// The dial path a refusal is met on.
    #[derive(Clone, Copy)]
    enum DialPath {
        /// The cold dial that brings a session up.
        Cold,
        /// A make-before-break overlap dial while a session serves.
        Overlap,
    }

    fn refuse_handshakes(exit: &FakeMultihopExit) {
        exit.refuse_handshake
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn refuse_setups(exit: &FakeMultihopExit) {
        exit.refuse_setup.store(
            warrenguard_multihop::WARREN_MH_DRAINING,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Dials, on `path`, an exit that refuses the way `refuse` configures it,
    /// while a retarget onto an admitting exit lands during that very dial,
    /// and asserts the one refusal report names the circuit the refused
    /// attempt dialled. The retarget redirects the next attempt only: a
    /// refusal charged to it would make the deployer avoid the node it has
    /// just moved to.
    async fn assert_a_mid_dial_retarget_leaves_the_refusal_on_the_dialled_circuit(
        path: DialPath,
        refuse: impl FnOnce(&FakeMultihopExit),
    ) {
        let operational_key = SigningKey::from_bytes(&[0x4D; 32]);
        let serving = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x5C; 16]));
        let refusing = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x5D; 16]));
        let admitting = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x5E; 16]));
        refuse(&refusing);
        let dialled = circuit_to(&refusing, [0xD1; 16], &operational_key);
        let moved_to = circuit_to(&admitting, [0xD2; 16], &operational_key);
        let reports = RefusalReports::default();
        let mut config = match path {
            DialPath::Cold => SupervisorConfig {
                relay: dialled.relay.clone(),
                ..config_with_fake_exit(&refusing, &operational_key)
            },
            DialPath::Overlap => config_with_fake_exit(&serving, &operational_key),
        };
        config.backoff = TEST_BACKOFF;
        config.on_dial_refused = Some(record_refusals(&reports));
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let handle = supervisor.handle();
        let migrate = supervisor.migrate_handle();
        refusing.on_next_dial(move || migrate.migrate_to(moved_to));
        let task = tokio::spawn(supervisor.run());

        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("a session comes up")
            .expect("watch sender alive");
        if let DialPath::Overlap = path {
            handle.migrate_to(dialled.clone());
            tokio::time::timeout(Duration::from_secs(5), async {
                while reports.lock().expect("reports lock").is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the overlap dial's refusal is reported");
        }
        assert_eq!(
            *reports.lock().expect("reports lock"),
            vec![(
                multihop::DialRefusedHop::Entry,
                dialled.relay.relay_id,
                *dialled.exit_id.as_bytes()
            )],
            "the refusal is charged to the circuit the refused attempt dialled"
        );

        drop(rx);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_handshake_refusal_names_the_dialled_node_when_a_retarget_lands_mid_dial() {
        assert_a_mid_dial_retarget_leaves_the_refusal_on_the_dialled_circuit(
            DialPath::Cold,
            refuse_handshakes,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_setup_refusal_names_the_dialled_node_when_a_retarget_lands_mid_dial() {
        assert_a_mid_dial_retarget_leaves_the_refusal_on_the_dialled_circuit(
            DialPath::Cold,
            refuse_setups,
        )
        .await;
    }

    /// An overlap dial refused at the handshake is reported like a cold one,
    /// so a deployer that migrated onto a refusing node reselects while the
    /// current session still serves, instead of learning it on the cold
    /// redial after that session dies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_overlap_handshake_refusal_names_the_dialled_node_when_a_retarget_lands_mid_dial() {
        assert_a_mid_dial_retarget_leaves_the_refusal_on_the_dialled_circuit(
            DialPath::Overlap,
            refuse_handshakes,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_overlap_setup_refusal_names_the_dialled_node_when_a_retarget_lands_mid_dial() {
        assert_a_mid_dial_retarget_leaves_the_refusal_on_the_dialled_circuit(
            DialPath::Overlap,
            refuse_setups,
        )
        .await;
    }

    /// The exit each connection of `bundle` terminates at, primary first.
    fn exits_of(bundle: &MultiHopBundle) -> Vec<ExitId> {
        bundle.clients().iter().map(|c| c.exit_id()).collect()
    }

    /// Whether `WARREN_MULTIHOP_CONNS` pins the bond to a single connection in
    /// this process, which leaves a bonding test no secondary to observe.
    fn bond_pinned_to_one_connection_by_env() -> bool {
        warrenguard_config::knobs::multihop_conns_override().is_some_and(|width| width < 2)
    }

    /// Every connection of a bonded session terminates at the exit its primary
    /// dialled, even when the target moves while that primary is being set up.
    /// A secondary dialled to the new target would name the primary's address
    /// to another exit, and one bond would then span two exits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cold_dial_bonds_its_secondaries_to_the_exit_its_primary_dialled() {
        if bond_pinned_to_one_connection_by_env() {
            eprintln!("skipped: WARREN_MULTIHOP_CONNS pins the bond to one connection");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x4E; 32]);
        let dialled = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x60; 16]));
        let elsewhere = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x61; 16]));
        let mut config = config_with_fake_exit(&dialled, &operational_key);
        config.n_connections = 2;
        // Every overlap is refused, so the cold session stays the published
        // one while the retarget below queues an overlap behind it.
        config.pre_swap_check = Some(Arc::new(|_| Box::pin(async { false })));
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let migrate = supervisor.migrate_handle();
        let moved_to = circuit_to(&elsewhere, elsewhere.relay.relay_id, &operational_key);
        dialled.on_next_dial(move || migrate.migrate_to(moved_to));
        let task = tokio::spawn(supervisor.run());

        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the cold dial publishes a session")
            .expect("watch sender alive");
        let bundle = rx
            .borrow_and_update()
            .clone()
            .expect("a session was published");
        tokio::time::timeout(Duration::from_secs(5), async {
            while bundle.num_connections() < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the secondary bonds onto the published session");
        assert_eq!(
            exits_of(&bundle),
            vec![dialled.exit_id; 2],
            "the secondary is dialled to the exit of its primary"
        );

        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// Every leg of a bond carries a frame the moment its setup completes,
    /// on a silent host, with one sibling slow to join. An exit keeps a
    /// `/v2` leg's session alive only once the leg has sent something, and
    /// every exit deployed before that was fixed drops a leg that stays
    /// silent for five seconds after its setup, with all its flows, until
    /// the client's next rekey.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_bonded_leg_carries_a_frame_within_a_second_of_its_setup() {
        if bond_pinned_to_one_connection_by_env() {
            eprintln!("skipped: WARREN_MULTIHOP_CONNS pins the bond to one connection");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x51; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x68; 16]));
        let want = resolve_bonded_want(4, warrenguard_config::knobs::multihop_conns_override());
        *exit.hold_setup_reply.lock() = Some((want, Duration::from_secs(3)));
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.n_connections = 4;
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let task = tokio::spawn(supervisor.run());

        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the cold dial publishes a session")
            .expect("watch sender alive");
        let bundle = rx
            .borrow_and_update()
            .clone()
            .expect("a session was published");
        tokio::time::timeout(Duration::from_secs(10), async {
            while bundle.num_connections() < want {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("every secondary bonds onto the published session");
        tokio::time::sleep(Duration::from_millis(1_200)).await;

        let delays = exit.first_datagram_delays();
        assert_eq!(delays.len(), want, "the exit answered every leg's setup");
        for (leg, delay) in delays.iter().enumerate() {
            assert!(
                delay.is_some_and(|d| d <= Duration::from_secs(1)),
                "leg {leg} carried its first frame {delay:?} after its setup"
            );
        }

        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// Whether `WARREN_PATH_HEALTH_SECS` leaves no steady cadence long enough
    /// for a test to tell a sweep at the seal from a scheduled one.
    fn path_health_cadence_too_short_by_env() -> bool {
        warrenguard_config::knobs::path_health_secs() < 10
    }

    /// A quiet host still sends: router solicitations from its link-local
    /// address, and the last packets of connections it opened before the
    /// tunnel, from its own LAN address. The exit refuses both by design, so
    /// nothing ever answers them, and they must not read as a return path
    /// that died: a redial about 18 s into every quiet connect was the cost.
    #[tokio::test(start_paused = true)]
    async fn uplink_the_exit_refuses_by_design_never_trips_the_one_way_watch() {
        let operational_key = SigningKey::from_bytes(&[0x46; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x55; 16]));
        let config = config_with_fake_exit(&exit, &operational_key);
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let metrics = supervisor.metrics();
        let task = tokio::spawn(supervisor.run());
        let session = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                rx.changed().await.expect("watch sender alive");
                if let Some(session) = rx.borrow_and_update().clone() {
                    return session;
                }
            }
        })
        .await
        .expect("the cold dial publishes a session");
        // Stands in for the downlink pump, which hands the prober its
        // replies: without it the bond-level verdict would ask for a
        // migration of its own.
        let reader = tokio::spawn({
            let session = session.clone();
            async move { while session.recv().await.is_ok() {} }
        });
        let mut router_solicitation = vec![0u8; 48];
        router_solicitation[0] = 0x60;
        router_solicitation[4..6].copy_from_slice(&8u16.to_be_bytes());
        router_solicitation[6] = 58;
        router_solicitation[7] = 255;
        router_solicitation[8..10].copy_from_slice(&[0xfe, 0x80]);
        router_solicitation[23] = 1;
        router_solicitation[24..26].copy_from_slice(&[0xff, 0x02]);
        router_solicitation[39] = 2;
        router_solicitation[40] = 133;
        let mut from_the_lan = udp_packet(40_000);
        from_the_lan[12..16].copy_from_slice(&[172, 17, 0, 2]);

        for _ in 0..20 {
            for pkt in [&router_solicitation, &from_the_lan] {
                // A redial closes this session under the sender, which is
                // what the assertion below reports.
                let _ = session.send(pkt).await;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }

        let redials = metrics.snapshot().reconnect_count;
        reader.abort();
        drop(session);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert_eq!(
            redials, 0,
            "a minute of uplink the exit refuses by design must not redial the session"
        );
    }

    /// A minimal IPv4/UDP packet from the fake exit's assigned address, one
    /// flow per source port.
    fn udp_packet(src_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 77, 0, 2]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes());
        pkt
    }

    /// Waits for the first leg-health report that covers `legs` legs.
    async fn leg_health_covering(
        rx: &mut watch::Receiver<crate::path_health::LegHealth>,
        legs: usize,
        within: Duration,
    ) -> Option<crate::path_health::LegHealth> {
        tokio::time::timeout(within, async {
            loop {
                let report = rx.borrow_and_update().clone();
                if report.legs == legs {
                    return report;
                }
                rx.changed()
                    .await
                    .expect("the prober's watch outlives the test");
            }
        })
        .await
        .ok()
    }

    /// A fresh bond is swept the moment it is sealed rather than a steady
    /// cadence later, so a leg that does not deliver is found, and routed
    /// around, while the connect is still in progress.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_fresh_bond_is_swept_as_soon_as_it_is_sealed() {
        if bond_pinned_to_one_connection_by_env() || path_health_cadence_too_short_by_env() {
            eprintln!("skipped: the environment pins the bond width or the prober cadence");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x52; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x69; 16]));
        let want = resolve_bonded_want(4, warrenguard_config::knobs::multihop_conns_override());
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.n_connections = 4;
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let mut leg_health = supervisor.leg_health_rx();
        let task = tokio::spawn(supervisor.run());
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the cold dial publishes a session")
            .expect("watch sender alive");
        let bundle = rx
            .borrow_and_update()
            .clone()
            .expect("a session was published");
        // Stands in for the downlink pump, which is where probe replies are
        // taken off the receive path.
        let reader = tokio::spawn({
            let bundle = bundle.clone();
            async move { while bundle.recv().await.is_ok() {} }
        });
        tokio::time::timeout(Duration::from_secs(10), bundle.sealed())
            .await
            .expect("the bond seals");

        // Well under the 15 s steady cadence, and room for a sweep that
        // waits out its whole reply timeout.
        let report = leg_health_covering(&mut leg_health, want, Duration::from_secs(8)).await;

        reader.abort();
        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        let report = report.expect("the sealed bond is swept within seconds, not a cadence later");
        assert!(
            report.unresponsive.is_empty(),
            "every leg of this bond answers its probes: {report:?}"
        );
    }

    /// Runs a four-leg bond against `exit` for `window` and returns its width
    /// with every leg-health report the prober published for the full bond.
    async fn leg_health_of_a_fresh_bond(
        exit: &FakeMultihopExit,
        operational_key: &SigningKey,
        window: Duration,
    ) -> (usize, Vec<crate::path_health::LegHealth>) {
        let want = resolve_bonded_want(4, warrenguard_config::knobs::multihop_conns_override());
        let mut config = config_with_fake_exit(exit, operational_key);
        config.n_connections = 4;
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let mut leg_health = supervisor.leg_health_rx();
        let task = tokio::spawn(supervisor.run());
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the cold dial publishes a session")
            .expect("watch sender alive");
        let bundle = rx
            .borrow_and_update()
            .clone()
            .expect("a session was published");
        let reader = tokio::spawn({
            let bundle = bundle.clone();
            async move { while bundle.recv().await.is_ok() {} }
        });
        let mut reports = Vec::new();
        let _ = tokio::time::timeout(window, async {
            loop {
                leg_health
                    .changed()
                    .await
                    .expect("the prober's watch outlives the test");
                let report = leg_health.borrow_and_update().clone();
                if report.legs == want {
                    reports.push(report);
                }
            }
        })
        .await;

        reader.abort();
        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        (want, reports)
    }

    /// Total IP length of the prober's small probe: anything longer is its
    /// large one.
    const SMALL_PROBE_LEN: usize = 84;

    /// When a bond is sealed, the exit's side of its fresh legs is still
    /// searching the path MTU, and a large echo reply it sends back on one of
    /// them does not fit and is dropped. That loss is the exit's, on the leg it
    /// chose for the reply, and it is over a round later: no leg is named a
    /// size-selective blackhole for it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_large_reply_the_exit_loses_once_at_the_seal_names_no_leg() {
        if bond_pinned_to_one_connection_by_env() || path_health_cadence_too_short_by_env() {
            eprintln!("skipped: the environment pins the bond width or the prober cadence");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x59; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x6B; 16]));
        let lost = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *exit.lose_reply.lock() = Some(Box::new({
            let lost = lost.clone();
            move |_leg, len| {
                len > SMALL_PROBE_LEN
                    && lost
                        .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
            }
        }));

        let (_, reports) =
            leg_health_of_a_fresh_bond(&exit, &operational_key, Duration::from_secs(10)).await;

        assert_eq!(
            lost.load(Ordering::Relaxed),
            1,
            "the exit lost one large reply"
        );
        assert!(
            reports
                .iter()
                .all(|report| report.size_blackholed.is_empty()),
            "a reply lost once is no size-selective blackhole: {reports:?}"
        );
        assert!(
            reports.len() >= 2,
            "a second round ran within seconds of the seal: {reports:?}"
        );
    }

    /// A leg whose large frames never get through is still named, once a
    /// second round has seen it too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_leg_that_keeps_losing_its_large_probes_is_named_a_size_blackhole() {
        if bond_pinned_to_one_connection_by_env() || path_health_cadence_too_short_by_env() {
            eprintln!("skipped: the environment pins the bond width or the prober cadence");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x5A; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x6C; 16]));
        // The primary: the first leg the exit answers and the bond's leg 0.
        *exit.lose_reply.lock() = Some(Box::new(|leg, len| leg == 0 && len > SMALL_PROBE_LEN));

        let (_, reports) =
            leg_health_of_a_fresh_bond(&exit, &operational_key, Duration::from_secs(10)).await;

        assert!(
            reports
                .iter()
                .any(|report| report.size_blackholed == vec![0]),
            "the leg that never returns a large probe is named: {reports:?}"
        );
        assert!(
            reports.iter().all(|report| report.unresponsive.is_empty()),
            "a leg that returns its small probe delivers: {reports:?}"
        );
    }

    /// Replies the exit loses for a few seconds, the way it loses those it
    /// sends to a dead sender of the client's previous bond until it evicts
    /// it, take no leg out of the routing plan: the leg delivered, the reply
    /// was lost on its way back, and the next round hears the leg.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn replies_lost_for_one_round_take_no_leg_out_of_the_routing_plan() {
        if bond_pinned_to_one_connection_by_env() || path_health_cadence_too_short_by_env() {
            eprintln!("skipped: the environment pins the bond width or the prober cadence");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x5B; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x6D; 16]));
        let lost = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *exit.lose_reply.lock() = Some(Box::new({
            let lost = lost.clone();
            move |leg, _len| leg == 0 && lost.fetch_add(1, Ordering::Relaxed) < 2
        }));

        let (_, reports) =
            leg_health_of_a_fresh_bond(&exit, &operational_key, Duration::from_secs(10)).await;

        assert!(
            reports.iter().all(|report| report.unresponsive.is_empty()),
            "a leg silent for one round only is never taken out: {reports:?}"
        );
        assert!(
            reports.len() >= 2,
            "a second round ran within seconds of the seal: {reports:?}"
        );
    }

    /// A leg whose large probe comes back while its small one does not has
    /// delivered both: the small one was lost on its way back. While the exit
    /// is seen losing replies like that, a leg that returned nothing proves
    /// nothing about its own path either, and is not taken out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_leg_is_taken_out_while_the_exit_is_seen_losing_replies() {
        if bond_pinned_to_one_connection_by_env() || path_health_cadence_too_short_by_env() {
            eprintln!("skipped: the environment pins the bond width or the prober cadence");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x5C; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x6E; 16]));
        *exit.lose_reply.lock() = Some(Box::new(|leg, len| {
            leg == 0 || (leg == 1 && len <= SMALL_PROBE_LEN)
        }));

        let (_, reports) =
            leg_health_of_a_fresh_bond(&exit, &operational_key, Duration::from_secs(10)).await;

        assert!(
            !reports.is_empty(),
            "the bond was swept within seconds of the seal"
        );
        assert!(
            reports.iter().all(|report| report.unresponsive.is_empty()),
            "no leg is convicted on replies the exit is seen losing: {reports:?}"
        );
    }

    /// A leg whose frames the exit takes and never answers, while its QUIC
    /// layer acknowledges every one of them, is named in the leg health and
    /// carries no user flow: its flows go to the legs that deliver.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_leg_whose_probes_never_come_back_is_named_and_carries_no_flow() {
        if bond_pinned_to_one_connection_by_env() || path_health_cadence_too_short_by_env() {
            eprintln!("skipped: the environment pins the bond width or the prober cadence");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x53; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x6A; 16]));
        // The primary: the first leg the exit answers and the bond's leg 0.
        *exit.mute_leg.lock() = Some(0);
        let want = resolve_bonded_want(4, warrenguard_config::knobs::multihop_conns_override());
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.n_connections = 4;
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let mut leg_health = supervisor.leg_health_rx();
        let task = tokio::spawn(supervisor.run());
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the cold dial publishes a session")
            .expect("watch sender alive");
        let bundle = rx
            .borrow_and_update()
            .clone()
            .expect("a session was published");
        let reader = tokio::spawn({
            let bundle = bundle.clone();
            async move { while bundle.recv().await.is_ok() {} }
        });

        let report = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let report = leg_health.borrow_and_update().clone();
                if report.legs == want && !report.unresponsive.is_empty() {
                    return report;
                }
                leg_health
                    .changed()
                    .await
                    .expect("the prober's watch outlives the test");
            }
        })
        .await
        .expect("a leg that never answers is named within seconds of the seal");
        for port in 0..64u16 {
            bundle
                .send(&udp_packet(40_000 + port))
                .await
                .expect("the bond takes the packet");
        }
        let carried = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let carried = exit.user_packets();
                if carried.iter().sum::<usize>() >= 64 {
                    return carried;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| exit.user_packets());

        reader.abort();
        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert_eq!(
            report.unresponsive,
            vec![0],
            "only the leg the exit never answers is named"
        );
        assert_eq!(
            carried[0], 0,
            "no flow may be pinned to a leg whose frames do not get through"
        );
        assert_eq!(
            carried.iter().sum::<usize>(),
            64,
            "every flow leaves on a leg that delivers: {carried:?}"
        );
    }

    /// The overlap dial assembles its full bond before the swap: every
    /// secondary goes to the exit the overlap's primary dialled, whatever
    /// retarget lands during that primary's setup.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_overlap_bonds_its_secondaries_to_the_exit_its_primary_dialled() {
        if bond_pinned_to_one_connection_by_env() {
            eprintln!("skipped: WARREN_MULTIHOP_CONNS pins the bond to one connection");
            return;
        }
        let operational_key = SigningKey::from_bytes(&[0x4F; 32]);
        let serving = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x62; 16]));
        let next = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x63; 16]));
        let elsewhere = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x64; 16]));
        let presented: Arc<Mutex<Vec<Vec<ExitId>>>> = Arc::default();
        let mut config = config_with_fake_exit(&serving, &operational_key);
        config.n_connections = 2;
        config.pre_swap_check = Some(Arc::new({
            let presented = presented.clone();
            move |bundle: Arc<MultiHopBundle>| {
                presented
                    .lock()
                    .expect("presented lock")
                    .push(exits_of(&bundle));
                Box::pin(async { false })
            }
        }));
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let handle = supervisor.handle();
        let migrate = supervisor.migrate_handle();
        let task = tokio::spawn(supervisor.run());
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the cold dial publishes a session")
            .expect("watch sender alive");

        let moved_to = circuit_to(&elsewhere, elsewhere.relay.relay_id, &operational_key);
        next.on_next_dial(move || migrate.migrate_to(moved_to));
        handle.migrate_to(circuit_to(&next, next.relay.relay_id, &operational_key));
        tokio::time::timeout(Duration::from_secs(5), async {
            while presented.lock().expect("presented lock").is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the overlap presents its session to the pre-swap check");
        assert_eq!(
            presented.lock().expect("presented lock")[0],
            vec![next.exit_id; 2],
            "every connection of the overlap's bond goes to the exit its primary dialled"
        );

        drop(rx);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// The swap observer is told the circuit the session landed on. A retarget
    /// that lands during the overlap only queues the next move: reporting it
    /// here would have a deployer act on an exit the session is not on (the
    /// forwarded ports it re-maps after a swap, above all).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_overlap_swap_reports_the_circuit_the_session_landed_on() {
        let operational_key = SigningKey::from_bytes(&[0x50; 32]);
        let serving = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x65; 16]));
        let next = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x66; 16]));
        let elsewhere = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x67; 16]));
        let swapped: Arc<Mutex<Vec<ExitId>>> = Arc::default();
        let mut config = config_with_fake_exit(&serving, &operational_key);
        config.on_overlap_swapped = Some(Arc::new({
            let swapped = swapped.clone();
            move |target: &CircuitTarget| {
                swapped.lock().expect("swapped lock").push(target.exit_id);
            }
        }));
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let handle = supervisor.handle();
        let migrate = supervisor.migrate_handle();
        let task = tokio::spawn(supervisor.run());
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the cold dial publishes a session")
            .expect("watch sender alive");

        let moved_to = circuit_to(&elsewhere, elsewhere.relay.relay_id, &operational_key);
        next.on_next_dial(move || migrate.migrate_to(moved_to));
        handle.migrate_to(circuit_to(&next, next.relay.relay_id, &operational_key));
        tokio::time::timeout(Duration::from_secs(5), async {
            while swapped.lock().expect("swapped lock").is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the overlap swaps the session");
        assert_eq!(
            swapped.lock().expect("swapped lock")[0],
            next.exit_id,
            "the first swap landed on the exit its overlap dialled"
        );

        drop(rx);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A session an overlap swaps in is judged by the one-way watch like a
    /// cold-dialled one: only what the exit can answer counts as uplink.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_an_overlap_swaps_in_counts_only_what_the_exit_admits() {
        let operational_key = SigningKey::from_bytes(&[0x47; 32]);
        let serving = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x56; 16]));
        let next = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x57; 16]));
        let config = config_with_fake_exit(&serving, &operational_key);
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let handle = supervisor.handle();
        let task = tokio::spawn(supervisor.run());
        tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .expect("the cold dial publishes a session")
            .expect("watch sender alive");

        handle.migrate_to(circuit_to(&next, next.relay.relay_id, &operational_key));
        let swapped_in = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                rx.changed().await.expect("watch sender alive");
                let published = rx.borrow_and_update().clone();
                if let Some(session) = published
                    && session.exit_id() == next.exit_id
                {
                    return session;
                }
            }
        })
        .await
        .expect("the overlap swaps the session");
        let mut from_the_lan = udp_packet(40_000);
        from_the_lan[12..16].copy_from_slice(&[172, 17, 0, 2]);
        for pkt in [udp_packet(40_001), from_the_lan] {
            swapped_in
                .send(&pkt)
                .await
                .expect("the session takes the packet");
        }
        let answerable = swapped_in.answerable_uplink_total();

        drop(swapped_in);
        drop(rx);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert_eq!(
            answerable, 1,
            "the packet from another source can never be answered"
        );
    }

    /// A session that dies right after it was established is a flap: the
    /// redial waits for the backoff instead of running full handshakes back to
    /// back against an exit that keeps dropping it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_that_dies_right_after_setup_backs_off_before_the_redial() {
        let operational_key = SigningKey::from_bytes(&[0x48; 32]);
        let exit_id = ExitId::from_bytes([0x58; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        exit.close_after_setup
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.backoff = TEST_BACKOFF;
        let (supervisor, rx) = MultiHopSupervisor::new(config);
        let task = tokio::spawn(supervisor.run());

        wait_for_accepts(&exit, 4, Duration::from_secs(5)).await;
        let gaps = redial_gaps(&exit);
        assert!(
            gaps.iter().all(|gap| *gap >= TEST_BACKOFF_FLOOR),
            "a flapping session must be redialled after the backoff, got {gaps:?}"
        );

        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A session that served for the healthy uptime clears the escalation its
    /// predecessors built up: its death is redialled at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_that_served_long_enough_is_redialled_at_once_after_flaps() {
        // Every escalated draw of this schedule waits at least a second, so a
        // redial that skipped the reset cannot pass for an immediate one even
        // on a loaded machine.
        const SLOW_BACKOFF: Backoff = Backoff {
            base: Duration::from_secs(2),
            max: Duration::from_secs(2),
        };
        let operational_key = SigningKey::from_bytes(&[0x49; 32]);
        let exit_id = ExitId::from_bytes([0x59; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        exit.close_after_setup
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.backoff = SLOW_BACKOFF;
        let (supervisor, rx) = MultiHopSupervisor::new(config);
        let handle = supervisor.handle();
        let task = tokio::spawn(supervisor.run());

        wait_for_accepts(&exit, 2, Duration::from_secs(5)).await;
        // From here on the exit keeps every session; the one it keeps is up
        // within one escalated draw and must then serve the healthy uptime.
        exit.close_after_setup
            .store(false, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(
            SLOW_BACKOFF.max + crate::redial_policy::MIN_HEALTHY_UPTIME + Duration::from_secs(1),
        )
        .await;
        let accepted_before = exit.accepted_at.lock().len();
        let killed_at = Instant::now();
        assert!(handle.force_reconnect(), "the healthy session is live");
        wait_for_accepts(&exit, accepted_before + 1, Duration::from_secs(5)).await;
        let redial_at = *exit
            .accepted_at
            .lock()
            .last()
            .expect("the redial was accepted");
        assert!(
            redial_at - killed_at < Duration::from_millis(500),
            "a healthy session's death must be redialled without waiting, took {:?}",
            redial_at - killed_at
        );

        drop(rx);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A make-before-break swap judges the outgoing session like one that
    /// ended: a healthy one clears the escalation, so a successor that dies
    /// young is redialled at once instead of after the waits of failures that
    /// predate the healthy session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_overlap_swap_off_a_healthy_session_clears_the_escalation() {
        const SLOW_BACKOFF: Backoff = Backoff {
            base: Duration::from_secs(2),
            max: Duration::from_secs(2),
        };
        let operational_key = SigningKey::from_bytes(&[0x4A; 32]);
        let exit_id = ExitId::from_bytes([0x5A; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        exit.close_after_setup
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.backoff = SLOW_BACKOFF;
        let (supervisor, rx) = MultiHopSupervisor::new(config);
        let handle = supervisor.handle();
        let task = tokio::spawn(supervisor.run());

        wait_for_accepts(&exit, 2, Duration::from_secs(5)).await;
        exit.close_after_setup
            .store(false, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(
            SLOW_BACKOFF.max + crate::redial_policy::MIN_HEALTHY_UPTIME + Duration::from_secs(1),
        )
        .await;
        // The successor the overlap dials dies right after its setup.
        exit.close_after_setup
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let before = exit.accepted_at.lock().len();
        handle.overlap_reconnect();
        wait_for_accepts(&exit, before + 2, Duration::from_secs(10)).await;
        let accepted = exit.accepted_at.lock().clone();
        let redial_gap = accepted[before + 1] - accepted[before];
        assert!(
            redial_gap < Duration::from_millis(500),
            "the young successor of a healthy session must be redialled without waiting, \
             took {redial_gap:?}"
        );

        drop(rx);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    /// A setup that fails while the connection stays up (here a reply that is
    /// no sealed frame) is never published, and the supervisor closes that
    /// connection itself before it redials.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_setup_that_fails_on_a_live_connection_is_closed_and_never_published() {
        let operational_key = SigningKey::from_bytes(&[0x4B; 32]);
        let exit_id = ExitId::from_bytes([0x5B; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        exit.garbage_reply
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.backoff = TEST_BACKOFF;
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let task = tokio::spawn(supervisor.run());

        let published = tokio::time::timeout(Duration::from_millis(1500), rx.changed()).await;
        assert!(
            published.is_err(),
            "a setup that got no IpAssign must never be published as a session"
        );
        assert!(
            exit.accepted_at.lock().len() >= 2,
            "the supervisor must give up the failed connection and redial"
        );

        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test]
    async fn run_terminates_when_receivers_drop_during_the_cold_dial_retry_loop() {
        // A teardown landing while the supervisor is INSIDE its cold-dial
        // retry loop must stop the retries: the loop-top receiver check
        // cannot see it, and a dial that never succeeds means the loop is
        // never left, so the supervisor would keep redialing for hundreds
        // of attempts after the daemon reported
        // Disconnected. The TEST-NET bind address makes every attempt fail
        // instantly with the same retriable Bind error a real host hits.
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

    #[tokio::test]
    async fn run_surfaces_a_banned_rejection_distinctly_and_fatally() {
        // A sealed RejectedBanned detail must surface as the distinct Banned
        // reason (not the generic NotAllowlisted), so the app can show a
        // suspension message; it is fatal like any rejection. The sealed
        // product reason code must reach the client-side reason intact so the
        // message can be specialized (here a non-zero code end-to-end).
        let operational_key = SigningKey::from_bytes(&[0x47; 32]);
        let exit_id = ExitId::from_bytes([0x56; 16]);
        let exit = spawn_fake_multihop_exit(&operational_key, exit_id);
        exit.reject_banned
            .store(true, std::sync::atomic::Ordering::Relaxed);
        exit.ban_reason_code
            .store(1, std::sync::atomic::Ordering::Relaxed);
        let config = config_with_fake_exit(&exit, &operational_key);
        let (supervisor, _rx) = MultiHopSupervisor::new(config);
        let mut fatal_rx = supervisor.fatal_rx();

        let result = tokio::time::timeout(Duration::from_secs(5), supervisor.run())
            .await
            .expect("run() must not hang retrying a definitive ban");

        match result {
            Err(MultiHopError::Rejected(reason)) => {
                assert_eq!(
                    reason,
                    RejectionReason::Banned(1),
                    "a sealed RejectedBanned must decode to the distinct Banned reason carrying \
                     the exit's product reason code"
                );
                assert_eq!(
                    reason.retryability(),
                    warrenguard_wire::Retryability::Fatal(warrenguard_wire::FatalCause::Banned),
                    "a ban must be fatal and carry the Banned cause"
                );
            }
            other => panic!("expected Err(MultiHopError::Rejected(Banned)), got {other:?}"),
        }

        let published = *fatal_rx.borrow_and_update();
        assert_eq!(
            published,
            Some(RejectionReason::Banned(1)),
            "fatal_rx must observe the ban reason (and code) run() returned"
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
                for port in 0..16 {
                    let _ = bundle.send(&udp_packet(40_000 + port)).await;
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

    /// A provider that hands out `stacks` in order (then empty stacks) and
    /// counts its calls, so a test can see that no token was popped twice.
    fn provider_of(
        stacks: Vec<Vec<SessionToken>>,
    ) -> (SessionTokenProvider, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let queue = Arc::new(Mutex::new(std::collections::VecDeque::from(stacks)));
        let provider: SessionTokenProvider = Arc::new({
            let calls = calls.clone();
            move || {
                calls.fetch_add(1, Ordering::Relaxed);
                queue
                    .lock()
                    .expect("provider lock")
                    .pop_front()
                    .unwrap_or_default()
            }
        });
        (provider, calls)
    }

    fn v7_token(fill: u8) -> SessionToken {
        SessionToken([fill; warrenguard_wire::SESSION_TOKEN_LEN])
    }

    fn presented(fills: &[u8]) -> SeenSetupRequest {
        SeenSetupRequest::Tokens(
            fills
                .iter()
                .map(|f| [*f; warrenguard_wire::SESSION_TOKEN_LEN])
                .collect(),
        )
    }

    async fn first_session(rx: &mut ClientWatch) -> Arc<MultiHopBundle> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(b) = rx.borrow_and_update().clone() {
                    return b;
                }
                rx.changed().await.expect("watch sender alive");
            }
        })
        .await
        .expect("a session is published")
    }

    #[tokio::test]
    async fn tokens_only_with_no_token_fails_typed_and_never_sends_a_setup_request() {
        let operational_key = SigningKey::from_bytes(&[0x61; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x71; 16]));
        let mut config = config_with_fake_exit(&exit, &operational_key);
        let (provider, calls) = provider_of(Vec::new());
        config.session_token_provider = Some(provider);
        let (supervisor, _rx) = MultiHopSupervisor::new(config);
        let supervisor = supervisor.with_session_admission(SessionAdmission::TokensOnly);
        let mut fatal_rx = supervisor.fatal_rx();

        let result = tokio::time::timeout(Duration::from_secs(5), supervisor.run())
            .await
            .expect("run() must stop, not redial, when no token is available");

        assert!(
            matches!(
                result,
                Err(MultiHopError::NoSessionToken(NoSessionTokenCause::Empty))
            ),
            "got {result:?}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(
            exit.setup_requests.lock().is_empty(),
            "no setup request of any kind may leave: {:?}",
            exit.setup_requests.lock()
        );
        assert_eq!(
            *fatal_rx.borrow_and_update(),
            None,
            "a missing token is not an exit rejection"
        );
    }

    #[tokio::test]
    async fn without_the_policy_an_empty_token_stack_keeps_the_wallet_signed_request() {
        let operational_key = SigningKey::from_bytes(&[0x62; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x72; 16]));
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.session_token_provider = Some(provider_of(Vec::new()).0);
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let task = tokio::spawn(supervisor.run());

        let bundle = first_session(&mut rx).await;

        assert_eq!(
            *exit.setup_requests.lock(),
            vec![SeenSetupRequest::Wallet { names_pubkey: true }]
        );
        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test]
    async fn a_token_refused_as_in_use_is_followed_by_the_next_token_of_the_stack() {
        let operational_key = SigningKey::from_bytes(&[0x63; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x73; 16]));
        exit.tokens_in_use
            .lock()
            .push([1; warrenguard_wire::SESSION_TOKEN_LEN]);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        let (provider, calls) = provider_of(vec![vec![v7_token(1), v7_token(2), v7_token(3)]]);
        config.session_token_provider = Some(provider);
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let supervisor = supervisor.with_session_admission(SessionAdmission::TokensOnly);
        let task = tokio::spawn(supervisor.run());

        let bundle = first_session(&mut rx).await;

        assert_eq!(
            *exit.setup_requests.lock(),
            vec![presented(&[1, 2, 3]), presented(&[2, 3, 1])],
            "the redial leads with the next token and keeps the refused one"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "the retry reuses the stack instead of popping new tokens"
        );
        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test]
    async fn every_token_refused_ends_after_one_attempt_per_token_and_stays_fatal_by_default() {
        let operational_key = SigningKey::from_bytes(&[0x64; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x74; 16]));
        exit.tokens_in_use.lock().extend([
            [1; warrenguard_wire::SESSION_TOKEN_LEN],
            [2; warrenguard_wire::SESSION_TOKEN_LEN],
        ]);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.session_token_provider = Some(provider_of(vec![vec![v7_token(1), v7_token(2)]]).0);
        let (supervisor, _rx) = MultiHopSupervisor::new(config);
        let mut fatal_rx = supervisor.fatal_rx();

        let result = tokio::time::timeout(Duration::from_secs(10), supervisor.run())
            .await
            .expect("the retries are bounded by the stack");

        assert!(
            matches!(
                result,
                Err(MultiHopError::Rejected(RejectionReason::NotAllowlisted))
            ),
            "got {result:?}"
        );
        assert_eq!(
            *fatal_rx.borrow_and_update(),
            Some(RejectionReason::NotAllowlisted)
        );
        assert_eq!(
            *exit.setup_requests.lock(),
            vec![presented(&[1, 2]), presented(&[2, 1])]
        );
    }

    #[tokio::test]
    async fn tokens_only_with_every_token_refused_fails_typed_without_a_wallet_request() {
        let operational_key = SigningKey::from_bytes(&[0x65; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x75; 16]));
        exit.tokens_in_use.lock().extend([
            [1; warrenguard_wire::SESSION_TOKEN_LEN],
            [2; warrenguard_wire::SESSION_TOKEN_LEN],
        ]);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.session_token_provider = Some(provider_of(vec![vec![v7_token(1), v7_token(2)]]).0);
        let (supervisor, _rx) = MultiHopSupervisor::new(config);
        let supervisor = supervisor.with_session_admission(SessionAdmission::TokensOnly);
        let mut fatal_rx = supervisor.fatal_rx();

        let result = tokio::time::timeout(Duration::from_secs(10), supervisor.run())
            .await
            .expect("the retries are bounded by the stack");

        assert!(
            matches!(
                result,
                Err(MultiHopError::NoSessionToken(
                    NoSessionTokenCause::AllRefused
                ))
            ),
            "got {result:?}"
        );
        assert_eq!(
            *exit.setup_requests.lock(),
            vec![presented(&[1, 2]), presented(&[2, 1])],
            "only token requests, one per token"
        );
        assert_eq!(*fatal_rx.borrow_and_update(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_overlap_whose_token_is_in_use_swaps_in_on_the_next_token() {
        let operational_key = SigningKey::from_bytes(&[0x66; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x76; 16]));
        let mut config = config_with_fake_exit(&exit, &operational_key);
        config.session_token_provider =
            Some(provider_of(vec![vec![v7_token(1)], vec![v7_token(2), v7_token(3)]]).0);
        let swaps = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        config.on_overlap_swapped = Some(Arc::new({
            let swaps = swaps.clone();
            move |_: &CircuitTarget| {
                swaps.fetch_add(1, Ordering::Relaxed);
            }
        }));
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let supervisor = supervisor.with_session_admission(SessionAdmission::TokensOnly);
        let handle = supervisor.handle();
        let task = tokio::spawn(supervisor.run());
        drop(first_session(&mut rx).await);
        exit.tokens_in_use
            .lock()
            .push([2; warrenguard_wire::SESSION_TOKEN_LEN]);

        handle.overlap_reconnect();
        tokio::time::timeout(Duration::from_secs(10), async {
            while swaps.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the overlap swaps in on the next token");

        assert_eq!(
            *exit.setup_requests.lock(),
            vec![presented(&[1]), presented(&[2, 3]), presented(&[3, 2])]
        );
        drop(rx);
        drop(handle);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test]
    async fn a_retrying_stack_survives_a_failed_setup_and_is_presented_again() {
        // The first token is refused, then the setup leading with the second
        // fails for an unrelated reason: the redial re-presents the rotated
        // stack rather than popping a fresh one and losing the refused token.
        let operational_key = SigningKey::from_bytes(&[0x67; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x77; 16]));
        exit.tokens_in_use
            .lock()
            .push([1; warrenguard_wire::SESSION_TOKEN_LEN]);
        *exit.garbage_reply_on.lock() = Some(2);
        let mut config = config_with_fake_exit(&exit, &operational_key);
        let (provider, calls) = provider_of(vec![vec![v7_token(1), v7_token(2)]]);
        config.session_token_provider = Some(provider);
        let (supervisor, mut rx) = MultiHopSupervisor::new(config);
        let task = tokio::spawn(supervisor.run());

        let bundle = first_session(&mut rx).await;

        assert_eq!(
            *exit.setup_requests.lock(),
            vec![presented(&[1, 2]), presented(&[2, 1])],
            "the garbage-answered attempt is not recorded; the admitted one re-presents the stack"
        );
        assert_eq!(exit.accepted.load(Ordering::Relaxed), 3);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        drop(bundle);
        drop(rx);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test]
    async fn a_tokens_only_secondary_without_tokens_is_never_dialled() {
        let operational_key = SigningKey::from_bytes(&[0x68; 32]);
        let exit = spawn_fake_multihop_exit(&operational_key, ExitId::from_bytes([0x78; 16]));
        let config = config_with_fake_exit(&exit, &operational_key);
        let spec = IpAssignSpec {
            assigned: std::net::Ipv4Addr::new(10, 77, 0, 2),
            prefix_len: 24,
            gateway: std::net::Ipv4Addr::new(10, 77, 0, 1),
            assigned_v6: None,
            prefix_len_v6: 0,
            gateway_v6: None,
        };

        let secondary = MultiHopSupervisor::dial_secondary(
            &config,
            SessionAdmission::TokensOnly,
            &CircuitTarget::from_config(&config),
            1,
            spec,
            None,
        )
        .await;

        assert!(secondary.is_none());
        assert_eq!(exit.accepted.load(Ordering::Relaxed), 0);
        assert!(exit.setup_requests.lock().is_empty());
    }
}
