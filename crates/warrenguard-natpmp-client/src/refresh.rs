//! Automatic NAT-PMP mapping refresh loop.
//!
//! The bare [`request_map`](crate::request_map) helper is one-shot: a
//! caller wishing to keep its allocation alive past `lifetime_secs`
//! must re-issue the request itself. [`spawn_refresh_loop`] turns this
//! into a long-running tokio task: an initial `request_map` is sent,
//! the granted lifetime is observed, and renewals are emitted at
//! `lifetime / 2` (RFC 6886 §3.7 recommendation), until the caller
//! cancels via [`RefreshLoopHandle::cancel`].
//!
//! Events are emitted on an `mpsc::UnboundedSender<NatPmpEvent>`
//! supplied by the caller. This channel-based observer keeps the API
//! free of trait bounds and lets the daemon-side `NatPmpManager` forward
//! events into its `WarrenStatusCache` without intermediate adapters.
//!
//! ## Lifecycle
//!
//! 1. `spawn_refresh_loop(...)` -> task spawned.
//! 2. Initial `request_map` -> `NatPmpEvent::Mapped` (or `Failed`).
//! 3. Sleep `lifetime_secs / 2` (clamped to >= 1s).
//! 4. Re-`request_map` -> `NatPmpEvent::Renewed` (or `Failed`).
//! 5. Repeat 3-4 until cancellation.
//! 6. On `RefreshLoopHandle::cancel` -> `NatPmpEvent::Cancelled` and the
//!    task exits.
//!
//! ## Error handling
//!
//! Failures are split by whether retrying the *same* request could fix
//! them:
//! - **Transient** (`Io`, `Timeout`, `Parse` - classified as
//!   [`NatPmpFailureReason::Other`]): handling depends on whether a
//!   mapping has ever succeeded.
//!   - *After* the first `Mapped`: the loop keeps the mapping alive by
//!     retrying with capped exponential backoff
//!     ([`INITIAL_BACKOFF_SECS`]..=[`MAX_BACKOFF_SECS`]) instead of
//!     tearing it down. No `Failed` event is emitted (the exit-side
//!     mapping survives until its lease expires, so the UI keeps showing
//!     the last good state rather than flapping). A short network blip
//!     during a renewal therefore no longer kills a working port forward.
//!   - *Before* the first `Mapped`: the retries are bounded
//!     ([`MAX_INITIAL_MAP_ATTEMPTS`]). An exit that never answers (NAT-PMP
//!     disabled exit-side, packets not traversing the tunnel) must not
//!     leave the UI stuck in its "requesting…" state forever, so once the
//!     bound is hit the loop emits `Failed { reason: Other }` and stops.
//!   - In both regimes the retry is also bounded by cancellation - the
//!     tunnel going down cancels the loop.
//! - **Permanent** (`Server(SuggestedPortUnavailable | NotAuthorized |
//!   OutOfResources)`): retrying the identical request cannot help (the
//!   port is held by another client, port forwarding is not authorised,
//!   or the pool/quota is exhausted). The loop emits
//!   `NatPmpEvent::Failed { reason, .. }` and terminates so the daemon
//!   can surface an actionable message and the user can react (pick
//!   another port, disable, retry later). Exception: a
//!   [`SuggestionKind::Sticky`] suggestion downgrades to a server pick
//!   (`suggested = 0`) on `SuggestedPortUnavailable` instead of failing,
//!   because a carried-over port is a best-effort preference, not a
//!   contract (the pinned honour-or-error contract is
//!   [`SuggestionKind::Pinned`]).
//! - **Rate-limited** (`RateLimited { retry_after_secs }`): the exit's
//!   per-source rate limit fired (usually too many port changes in a
//!   row). This is recoverable once the sliding window clears, so the
//!   loop emits `NatPmpEvent::RateLimited { retry_after_secs }` (the UI
//!   blocks the port control and shows a countdown) and retries after
//!   the retry-after instead of terminating.

use std::net::SocketAddr;
use std::time::Duration;

/// How a non-zero `suggested_external_port` was chosen, deciding the
/// loop's reaction to the exit's strict `SuggestedPortUnavailable`
/// rejection.
///
/// - `Pinned`: the user chose the port. Honour-or-error: a conflict is
///   surfaced as `Failed(SuggestedPortInUse)` and the loop stops.
/// - `Sticky`: the port is a previously-granted value carried over so
///   the public port follows the client (reconnect, exit maintenance
///   migration). Best-effort: on conflict the loop downgrades to a
///   server-picked port (`suggested = 0`) and keeps the rule alive.
///
/// Irrelevant when `suggested_external_port == 0` (nothing to honour).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestionKind {
    /// User-chosen port: strict honour-or-error.
    Pinned,
    /// Carried-over preference: downgrade to a server pick on conflict.
    Sticky,
}

/// Protocol scope of one forward rule: a single transport, or the
/// atomic TCP+UDP pair on ONE external port.
///
/// `Both` drives both legs from a single refresh loop: the UDP leg maps
/// first (with the configured suggestion), then the TCP leg pins the
/// exact port the UDP leg was granted. The pair is atomic: a permanent
/// refusal of either leg releases the already-granted leg and fails the
/// whole rule, so the user never ends up with a half-forwarded port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardProtos {
    /// UDP only (RFC 6886 opcode 1).
    Udp,
    /// TCP only (RFC 6886 opcode 2).
    Tcp,
    /// TCP + UDP together on the same external port.
    Both,
}

impl ForwardProtos {
    /// The wire protocols this scope maps, in request order. The UDP
    /// leg leads for `Both` so the server-picked port exists before the
    /// TCP leg pins it.
    #[must_use]
    pub fn legs(self) -> &'static [MapProto] {
        match self {
            Self::Udp => &[MapProto::Udp],
            Self::Tcp => &[MapProto::Tcp],
            Self::Both => &[MapProto::Udp, MapProto::Tcp],
        }
    }
}

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use warrenguard_natpmp_protocol::{MapProto, ResultCode};

use crate::NatPmpClientError;

/// Minimum lifetime (in seconds) used to derive the refresh interval.
/// Even when the server grants `lifetime_secs = 0` (unexpected for a
/// successful mapping), we sleep at least `MIN_LIFETIME_FOR_REFRESH /
/// 2` to avoid a busy-loop.
const MIN_LIFETIME_FOR_REFRESH: u32 = 2;

/// Initial backoff (seconds) before retrying after a *transient*
/// failure (timeout / I/O). `request_map` already retried ~7.75 s
/// internally, so this only kicks in for longer outages.
const INITIAL_BACKOFF_SECS: u32 = 5;

/// Cap (seconds) for the exponential retry backoff on transient
/// failures, so a long exit/network outage settles into a steady ~1/min
/// retry rather than spinning.
const MAX_BACKOFF_SECS: u32 = 60;

/// Maximum number of consecutive transient failures tolerated *before
/// the first successful mapping*. Past this, the loop emits
/// `Failed { reason: Other }` and terminates so the UI leaves its
/// "requesting…" state instead of spinning forever.
///
/// Rationale: the infinite-retry policy for transient failures exists to
/// keep an *already working* mapping alive across network blips without
/// flapping the UI. But until the very first `Mapped`, there is nothing
/// to keep alive and nothing to flap - an exit that never answers (NAT-PMP
/// disabled exit-side, packets not traversing the tunnel, wrong gateway)
/// would otherwise leave the user staring at "mapping request in
/// progress…" indefinitely with zero feedback. Bounding only the initial
/// attempt surfaces an actionable failure while leaving renewal
/// resilience untouched. With `request_map`'s internal ~7.75 s RFC
/// backoff plus the 5 s/10 s inter-attempt backoff, three attempts span
/// roughly 35-40 s before giving up - long enough to ride out a slow
/// first handshake, short enough that a dead exit is reported promptly.
const MAX_INITIAL_MAP_ATTEMPTS: u32 = 3;

/// RFC 6886 §3.6: the gateway's Seconds-Since-Start-of-Epoch increases
/// monotonically while it preserves its mappings. If a renewal observes the
/// value jump backwards, the gateway rebooted and lost every mapping, so the
/// freshly-granted mapping must be surfaced as a new `Mapped` (not `Renewed`)
/// event - the daemon re-applies its side (e.g. re-installs the DNAT rule)
/// instead of assuming the prior mapping still holds.
fn epoch_indicates_restart(prev_epoch_secs: u32, new_epoch_secs: u32) -> bool {
    new_epoch_secs < prev_epoch_secs
}

/// Event emitted by [`spawn_refresh_loop`] on the caller's channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatPmpEvent {
    /// Initial mapping obtained from the server.
    Mapped {
        /// External (public) port allocated by the server.
        external_port: u16,
        /// Granted lifetime, in seconds (may be < the requested one).
        lifetime_secs: u32,
        /// Per-source rate-limit slots still available after this
        /// request (Warren trailer). `None` if the exit sent no trailer
        /// (RFC-only / pre-trailer). The UI warns when this hits 0/1.
        attempts_remaining: Option<u8>,
        /// Seconds until the rate-limit budget grows by one. `0` when
        /// unknown or when the window is empty. Lets the UI block the
        /// port control with a countdown when `attempts_remaining == 0`.
        window_reset_secs: u16,
    },
    /// Mapping renewed at `lifetime / 2`. Conceptually distinct from
    /// `Mapped` so the UI can show "Mapped" once and silently "Renewed"
    /// on subsequent ticks if it wants to.
    Renewed {
        /// External (public) port (typically unchanged across renewals
        /// but the server may rotate ports in theory).
        external_port: u16,
        /// Lifetime granted on this renewal.
        lifetime_secs: u32,
        /// Per-source rate-limit slots still available after this
        /// renewal (see [`NatPmpEvent::Mapped`]).
        attempts_remaining: Option<u8>,
        /// Seconds until the rate-limit budget grows by one.
        window_reset_secs: u16,
    },
    /// The exit rate-limited a (re)mapping request. The loop does NOT
    /// terminate on this: it emits the event (so the UI can block the
    /// port control and show a countdown) then waits `retry_after_secs`
    /// before retrying, so a burst of rapid port changes self-heals once
    /// the sliding window clears.
    RateLimited {
        /// Seconds to wait before a rate-limit slot frees for this
        /// client.
        retry_after_secs: u16,
    },
    /// Last `request_map` failed; the loop has stopped.
    Failed {
        /// `NatPmpClientError::to_string()` of the failure. Kept for
        /// logs/diagnostics - UI code should switch on `reason`.
        error: String,
        /// Stable, translatable category of the failure so the UI can
        /// show a localised message rather than the raw error string.
        reason: NatPmpFailureReason,
    },
    /// Caller invoked [`RefreshLoopHandle::cancel`]; the loop has
    /// stopped cleanly.
    Cancelled,
}

/// Stable, translatable discriminant for why a NAT-PMP map request
/// failed. The companion `error` string on [`NatPmpEvent::Failed`] stays
/// for logs/diagnostics; UI code switches on this enum to pick a
/// localised message instead of surfacing a raw English string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatPmpFailureReason {
    /// The exit refused the explicitly requested external port because
    /// it is already in use / reserved for a *different* client
    /// (Warren's strict honour-or-error policy). UI: "this port is
    /// already in use, choose another one".
    SuggestedPortInUse,
    /// Generic out-of-resources: the port pool is exhausted, the
    /// per-client quota was hit, or the per-source rate limit fired.
    OutOfResources,
    /// Port forwarding is not authorised (disabled exit-side, or the
    /// client's source address is not allowed).
    NotAuthorized,
    /// Any other failure (timeout, I/O, protocol parse, network).
    Other,
}

impl NatPmpFailureReason {
    /// Classifies a [`NatPmpClientError`] into a UI-facing reason.
    #[must_use]
    pub fn from_client_error(err: &NatPmpClientError) -> Self {
        match err {
            NatPmpClientError::Server(ResultCode::SuggestedPortUnavailable) => {
                Self::SuggestedPortInUse
            }
            NatPmpClientError::Server(ResultCode::OutOfResources) => Self::OutOfResources,
            NatPmpClientError::Server(ResultCode::NotAuthorized) => Self::NotAuthorized,
            _ => Self::Other,
        }
    }
}

/// Handle returned by [`spawn_refresh_loop`]. Drop it without calling
/// `cancel` is OK: the loop keeps running until the event receiver is
/// dropped (the channel close detection terminates the loop on the next
/// send). For deterministic shutdown, call `cancel` then `join`.
///
/// The struct also remembers the request shape so [`release`] can
/// issue a final `lifetime = 0` Map (RFC 6886 §3.3.2) without
/// re-asking the caller for parameters.
pub struct RefreshLoopHandle {
    cancel_tx: Option<oneshot::Sender<()>>,
    join_handle: JoinHandle<()>,
    /// Request shape captured at spawn time. Reused by [`release`] to
    /// issue a final `lifetime = 0` Map per leg directed at the same
    /// `(client_ip, internal_port, proto)` tuple - the exit allocator
    /// keys its lookup on those three values, so a fresh socket with
    /// the same `bind_addr` finds and frees the mapping.
    server: SocketAddr,
    protos: ForwardProtos,
    internal_port: u16,
    bind_addr: Option<std::net::IpAddr>,
}

impl RefreshLoopHandle {
    /// Signals the loop to stop at the next checkpoint (either between
    /// requests during the sleep, or while awaiting a `request_map`
    /// response). Idempotent: a second call is a no-op.
    pub fn cancel(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            // Failure to send means the loop already terminated (Failed
            // or receiver dropped). Either way, nothing to do.
            let _ = tx.send(());
        }
    }

    /// Graceful shutdown that also asks the NAT-PMP server to release
    /// the active mapping (RFC 6886 §3.3.2: a Map request with
    /// `lifetime = 0` deletes the existing mapping for the given
    /// `(client_ip, internal_port, proto)` tuple).
    ///
    /// Order of operations:
    /// 1. [`cancel`] the refresh loop so its own next request does not
    ///    race against ours.
    /// 2. Brief best-effort attempt (single try, ~250 ms timeout) to
    ///    send the `lifetime = 0` Map. Failure is silenced: a release
    ///    is fire-and-forget by RFC convention, and the exit will
    ///    naturally GC the mapping at its lease expiry if our packet
    ///    is lost.
    /// 3. Return - the caller can spawn a fresh loop immediately
    ///    without contending against the freshly-released slot.
    ///
    /// This is the path used by daemon-side live reconfig (toggle
    /// off, protocol change, suggested-port change) where the
    /// upstream `NatPmpManager` needs to release the current mapping
    /// before allocating a new one - without this, the exit's
    /// per-client quota (default 1) refuses the new allocation until
    /// the old lease expires (~1 h).
    pub async fn release(&mut self) {
        // Step 1: stop the loop. Any in-flight `request_map` aborts
        // because the cancel channel races against the request future
        // inside the loop (see `tokio::select! { biased; ... }`).
        self.cancel();
        // Step 2: issue the lifetime=0 Map, once per leg (a dual-proto
        // pair frees both its slots).
        for &proto in self.protos.legs() {
            send_release(self.server, proto, self.internal_port, self.bind_addr).await;
        }
    }

    /// Waits for the loop task to exit. Useful for tests; in production
    /// the daemon typically drops the handle without joining.
    ///
    /// # Errors
    ///
    /// Propagates a tokio `JoinError` if the task panicked.
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.join_handle.await
    }

    /// Returns `true` once the loop task has finished. Non-blocking.
    /// Useful in tests to assert that `Failed` indeed terminated the
    /// task.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.join_handle.is_finished()
    }
}

/// Best-effort `lifetime = 0` Map (RFC 6886 §3.3.2) for one leg. Single
/// attempt, ~750 ms bound: a stuck server is not worth holding the
/// caller for the full RFC §3.1 exponential backoff (~7.75 s), and the
/// exit GCs the mapping at its lease expiry anyway if the packet is
/// lost. Shared by [`RefreshLoopHandle::release`] and the dual-pair
/// atomic-abort path inside the refresh loop.
async fn send_release(
    server: SocketAddr,
    proto: MapProto,
    internal_port: u16,
    bind_addr: Option<std::net::IpAddr>,
) {
    let outcome = tokio::time::timeout(
        Duration::from_millis(750),
        crate::request_map_with_retries_from_addr(
            server,
            proto,
            internal_port,
            0, // suggested_external_port irrelevant for a release
            0, // lifetime = 0 = delete this mapping
            1, // single attempt, no retry
            bind_addr,
        ),
    )
    .await;
    match outcome {
        Ok(Ok(_)) => {
            // Server confirmed the release.
        }
        Ok(Err(e)) => {
            // Anything other than Success is acceptable here: a
            // release for a mapping we don't own (mid-rotation race,
            // server already GC'd it, …) still does its job. We log so
            // an operator can correlate if needed.
            tracing::debug!("NAT-PMP release: server reply {e}; ignoring");
        }
        Err(_elapsed) => {
            // The mapping will GC on its own at lease expiry. Not
            // strictly safe (the slot is held until then), but the
            // caller's reconfig path is best-effort by design.
            tracing::debug!(
                "NAT-PMP release: timed out after 750 ms; mapping will GC at lease expiry"
            );
        }
    }
}

/// Spawns the auto-renewing NAT-PMP loop. Returns a handle the caller
/// uses to stop the loop.
///
/// `event_tx` receives a sequence of [`NatPmpEvent`]s. The loop
/// terminates after emitting either `Failed` (on `request_map` error)
/// or `Cancelled` (on explicit cancel). The caller is free to drop the
/// receiver: the next `send` will silently fail and the loop exits.
///
/// # Arguments
///
/// - `server`: NAT-PMP server address (typically
///   `default_server_addr()` = tunnel gateway:5351).
/// - `proto`: TCP or UDP.
/// - `internal_port`: client-side port (the one bound on the client's
///   socket).
/// - `suggested_external_port`: 0 = server picks.
/// - `lifetime_secs`: requested lifetime; the server may grant less,
///   in which case renewals follow the granted value.
/// - `event_tx`: where mapping events are delivered.
#[must_use = "the returned handle owns the spawned task; drop discards control"]
pub fn spawn_refresh_loop(
    server: SocketAddr,
    proto: MapProto,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    event_tx: mpsc::UnboundedSender<NatPmpEvent>,
) -> RefreshLoopHandle {
    spawn_refresh_loop_from_addr(
        server,
        proto,
        internal_port,
        suggested_external_port,
        lifetime_secs,
        SuggestionKind::Pinned,
        event_tx,
        None,
    )
}

/// Variant of [`spawn_refresh_loop`] that binds the client UDP socket
/// to an explicit local IP. See
/// [`crate::request_map_from_addr`] for the rationale - needed on
/// Android VPN clients to force egress through the tunnel inner IPv4.
///
/// # Arguments
///
/// - `server`, `proto`, `internal_port`, `suggested_external_port`,
///   `lifetime_secs`, `event_tx`: see [`spawn_refresh_loop`].
/// - `suggestion`: policy applied when the exit rejects
///   `suggested_external_port` as unavailable. [`SuggestionKind::Pinned`]
///   (used by [`spawn_refresh_loop`]) fails the loop; [`SuggestionKind::Sticky`]
///   instead downgrades to a server-picked port (`suggested = 0`) and
///   retries, treating a carried-over port as a best-effort preference
///   rather than a contract.
/// - `bind_addr`: `None` lets the OS route via the default interface;
///   `Some(ip)` forces the egress interface by binding the client UDP
///   socket to `ip` (needed on Android VPN clients, see
///   [`crate::request_map_from_addr`]).
#[must_use = "the returned handle owns the spawned task; drop discards control"]
// Mirrors the one-shot request_map_with_retries_from_addr surface plus the
// suggestion policy; a param struct would hide that 1:1 mapping.
#[expect(clippy::too_many_arguments)]
pub fn spawn_refresh_loop_from_addr(
    server: SocketAddr,
    proto: MapProto,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    suggestion: SuggestionKind,
    event_tx: mpsc::UnboundedSender<NatPmpEvent>,
    bind_addr: Option<std::net::IpAddr>,
) -> RefreshLoopHandle {
    let protos = match proto {
        MapProto::Udp => ForwardProtos::Udp,
        MapProto::Tcp => ForwardProtos::Tcp,
    };
    spawn_refresh_loop_protos_from_addr(
        server,
        protos,
        internal_port,
        suggested_external_port,
        lifetime_secs,
        suggestion,
        event_tx,
        bind_addr,
    )
}

/// Generalisation of [`spawn_refresh_loop_from_addr`] over a
/// [`ForwardProtos`] scope. With a single-proto scope the behaviour is
/// identical to the historical loop. With [`ForwardProtos::Both`], each
/// cycle maps the UDP leg first (with the configured suggestion), then
/// the TCP leg pinned to the exact port the UDP leg was granted, and
/// emits ONE `Mapped`/`Renewed` event for the pair (lifetime = the
/// smaller grant). The pair is atomic: a permanent refusal of either
/// leg releases the leg(s) already granted in that cycle and emits a
/// single `Failed`. Recoverable situations (rate limit, transient
/// network errors) retry the whole cycle; a leg already granted stays
/// alive through its lease meanwhile, which also keeps the pair's port
/// reserved for the retry.
#[must_use = "the returned handle owns the spawned task; drop discards control"]
#[expect(clippy::too_many_arguments)]
pub fn spawn_refresh_loop_protos_from_addr(
    server: SocketAddr,
    protos: ForwardProtos,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    suggestion: SuggestionKind,
    event_tx: mpsc::UnboundedSender<NatPmpEvent>,
    bind_addr: Option<std::net::IpAddr>,
) -> RefreshLoopHandle {
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let join_handle = tokio::spawn(async move {
        let mut suggested_external_port = suggested_external_port;
        let legs = protos.legs();
        let mut is_first = true;
        // Counts consecutive transient failures while no mapping has ever
        // succeeded. Bounds the initial attempt (see
        // `MAX_INITIAL_MAP_ATTEMPTS`); reset is unnecessary because it is
        // only consulted while `is_first` is still true.
        let mut initial_transient_failures = 0u32;
        // Exponential backoff for transient-failure retries; reset to
        // the initial value after every successful (re)mapping.
        let mut backoff_secs = INITIAL_BACKOFF_SECS;
        let mut last_epoch_secs: Option<u32> = None;
        'cycle: loop {
            // One cycle = one Map per leg. `granted_this_cycle` tracks
            // the legs granted so far so a permanent refusal of a later
            // leg can release them (atomic pair). `pair_port` is the
            // port granted to the first leg; later legs pin it.
            let mut granted_this_cycle: Vec<MapProto> = Vec::new();
            let mut pair_port = suggested_external_port;
            let mut min_lifetime = u32::MAX;
            let mut external_port = 0u16;
            let mut rate_limit = None;
            let mut epoch_secs = 0u32;
            for (leg_index, &proto) in legs.iter().enumerate() {
                let leg_suggested = if leg_index == 0 {
                    suggested_external_port
                } else {
                    pair_port
                };
                // Race the request_map call against cancellation so a
                // cancel during a slow / unreachable server does not wait
                // for the RFC §3.1 retry exhaustion (~7.75s).
                let req_fut = crate::request_map_with_retries_from_addr(
                    server,
                    proto,
                    internal_port,
                    leg_suggested,
                    lifetime_secs,
                    crate::DEFAULT_MAX_ATTEMPTS,
                    bind_addr,
                );
                let result = tokio::select! {
                    biased;
                    _ = &mut cancel_rx => {
                        let _ = event_tx.send(NatPmpEvent::Cancelled);
                        return;
                    }
                    r = req_fut => r,
                };

                match result {
                    Ok(m) => {
                        backoff_secs = INITIAL_BACKOFF_SECS; // recovered
                        pair_port = m.external_port;
                        external_port = m.external_port;
                        min_lifetime = min_lifetime.min(m.lifetime_secs);
                        if m.rate_limit.is_some() {
                            rate_limit = m.rate_limit;
                        }
                        epoch_secs = m.epoch_secs;
                        granted_this_cycle.push(proto);
                    }
                    Err(NatPmpClientError::RateLimited { retry_after_secs }) => {
                        // Recoverable-after-delay: the exit's per-source rate
                        // limit fired (typically the user changed ports too
                        // many times in a row). Surface it so the UI can block
                        // the port control and show a countdown, then wait the
                        // retry-after and retry the whole cycle - the loop
                        // self-heals once the sliding window clears, without
                        // tearing the feature down. A leg already granted
                        // this cycle stays alive (its lease reserves the
                        // pair's port for the retry). We do NOT reset the
                        // transient backoff here.
                        let _ = event_tx.send(NatPmpEvent::RateLimited { retry_after_secs });
                        // Clamp: never busy-spin (>= 1s), and never sleep
                        // longer than ~2 min even if the server reports a
                        // larger window, so a stale value cannot wedge the
                        // loop.
                        let wait = Duration::from_secs(u64::from(retry_after_secs.clamp(1, 120)));
                        tokio::select! {
                            biased;
                            _ = &mut cancel_rx => {
                                let _ = event_tx.send(NatPmpEvent::Cancelled);
                                return;
                            }
                            () = tokio::time::sleep(wait) => {}
                        }
                        continue 'cycle;
                    }
                    Err(NatPmpClientError::Server(ResultCode::SuggestedPortUnavailable))
                        if leg_index == 0
                            && suggestion == SuggestionKind::Sticky
                            && suggested_external_port != 0 =>
                    {
                        // A sticky preference lost its port to another client
                        // (typically on the destination exit of a maintenance
                        // migration). Downgrade to a server pick and re-request
                        // immediately: keeping the rule alive on a new port
                        // beats failing it over a port the user never chose.
                        // First leg only: a later leg's suggestion is the
                        // pair port, a contract rather than a preference.
                        tracing::debug!("sticky suggested port taken; retrying with a server pick");
                        suggested_external_port = 0;
                        continue 'cycle;
                    }
                    Err(err) => {
                        let reason = NatPmpFailureReason::from_client_error(&err);
                        if reason != NatPmpFailureReason::Other {
                            // Permanent / not-self-recoverable: the exit
                            // refused for a reason retrying the same request
                            // cannot fix (port taken by another client,
                            // not authorised, out of resources/quota/rate
                            // limit). Atomic pair: free the leg(s) granted
                            // this cycle so the rule never survives
                            // half-mapped, then surface and stop - the
                            // daemon/UI decides (the user picks another
                            // port, etc.).
                            for &granted in &granted_this_cycle {
                                send_release(server, granted, internal_port, bind_addr).await;
                            }
                            let _ = event_tx.send(NatPmpEvent::Failed {
                                reason,
                                error: err.to_string(),
                            });
                            return;
                        }
                        // Transient (timeout / I/O / parse). Two regimes:
                        //
                        // - Before the first successful cycle: bound the
                        //   retries. An exit that never answers must not strand
                        //   the UI in "requesting…" forever - after
                        //   `MAX_INITIAL_MAP_ATTEMPTS` we surface `Failed` so
                        //   the user gets actionable feedback and can retry.
                        // - After at least one `Mapped`: keep the mapping alive
                        //   by retrying with capped exponential backoff instead
                        //   of tearing it down. The exit-side mapping survives
                        //   until its lease expires, so we do NOT emit `Failed`
                        //   (which would flap the UI from Mapped to error and
                        //   back); we retry until success or cancellation. The
                        //   tunnel going down cancels the loop, bounding the
                        //   retries.
                        if is_first {
                            initial_transient_failures += 1;
                            if initial_transient_failures >= MAX_INITIAL_MAP_ATTEMPTS {
                                for &granted in &granted_this_cycle {
                                    send_release(server, granted, internal_port, bind_addr).await;
                                }
                                let _ = event_tx.send(NatPmpEvent::Failed {
                                    reason: NatPmpFailureReason::Other,
                                    error: err.to_string(),
                                });
                                return;
                            }
                        }
                        let wait = Duration::from_secs(u64::from(backoff_secs));
                        backoff_secs = backoff_secs.saturating_mul(2).min(MAX_BACKOFF_SECS);
                        tokio::select! {
                            biased;
                            _ = &mut cancel_rx => {
                                let _ = event_tx.send(NatPmpEvent::Cancelled);
                                return;
                            }
                            () = tokio::time::sleep(wait) => {}
                        }
                        continue 'cycle;
                    }
                }
            }

            let attempts_remaining = rate_limit.map(|r| r.attempts_remaining);
            let window_reset_secs = rate_limit.map_or(0, |r| r.window_reset_secs);
            // RFC 6886 §3.6 gateway-restart detection: a backwards epoch jump
            // means the gateway rebooted and dropped our mapping. The Map above
            // already re-created it, so surface it as a fresh Mapped (not
            // Renewed) so the daemon re-applies its side (DNAT, etc.).
            let restart =
                last_epoch_secs.is_some_and(|prev| epoch_indicates_restart(prev, epoch_secs));
            last_epoch_secs = Some(epoch_secs);
            let event = if is_first || restart {
                NatPmpEvent::Mapped {
                    external_port,
                    lifetime_secs: min_lifetime,
                    attempts_remaining,
                    window_reset_secs,
                }
            } else {
                NatPmpEvent::Renewed {
                    external_port,
                    lifetime_secs: min_lifetime,
                    attempts_remaining,
                    window_reset_secs,
                }
            };
            if event_tx.send(event).is_err() {
                // Receiver dropped: nothing observes the mapping
                // anymore, exit silently. No Cancelled because the
                // caller did not request it; their channel drop is
                // their "implicit cancel".
                return;
            }
            is_first = false;

            // RFC 6886 §3.7: refresh at half the granted lifetime to
            // tolerate clock skew and packet loss. The pair follows the
            // SMALLER grant so neither leg ever lapses.
            let granted = min_lifetime.max(MIN_LIFETIME_FOR_REFRESH);
            let refresh_in = Duration::from_secs(u64::from(granted) / 2);

            tokio::select! {
                biased;
                _ = &mut cancel_rx => {
                    let _ = event_tx.send(NatPmpEvent::Cancelled);
                    return;
                }
                () = tokio::time::sleep(refresh_in) => {}
            }
        }
    });

    RefreshLoopHandle {
        cancel_tx: Some(cancel_tx),
        join_handle,
        server,
        protos,
        internal_port,
        bind_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_backwards_jump_signals_gateway_restart() {
        // Steady or increasing epoch: the gateway kept its mappings.
        assert!(!epoch_indicates_restart(100, 100));
        assert!(!epoch_indicates_restart(100, 200));
        // Backwards jump: the gateway rebooted and lost all mappings
        // (RFC 6886 §3.6), so the renewed mapping is actually fresh.
        assert!(epoch_indicates_restart(100, 50));
        assert!(epoch_indicates_restart(1, 0));
    }
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::net::UdpSocket;
    use warrenguard_natpmp_protocol::{
        MapProto, Response as ServerResponse, ResultCode, serialize_response,
    };

    /// Spawns a UDP stub that replies to every received datagram with a
    /// fixed `Response::Map`. Lets us test renewals (the loop sends
    /// repeated requests; the stub serves them all).
    async fn spawn_repeated_stub(lifetime_secs: u32, external_port: u16) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = sock.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (_, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let resp = serialize_response(&ServerResponse::Map {
                    proto: MapProto::Udp,
                    result_code: ResultCode::Success,
                    epoch_secs: 0,
                    internal_port: 22,
                    external_port,
                    lifetime_secs,
                    rate_limit: None,
                });
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    /// Stub that replies to every datagram with malformed bytes, which
    /// the client parses as a transient `Parse` error (classified
    /// `NatPmpFailureReason::Other`). Used to assert the loop retries
    /// (backs off) instead of terminating with `Failed`.
    async fn spawn_repeated_garbage_stub() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = sock.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (_, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                // version byte 0xFF != 0 → ParseError::UnsupportedVersion.
                let _ = sock.send_to(&[0xFF, 0xFF, 0xFF, 0xFF], peer).await;
            }
        });
        addr
    }

    /// Stub that replies once with the provided response then stops
    /// answering. Subsequent client requests time out.
    async fn spawn_one_shot_stub(reply: ServerResponse) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = sock.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if let Ok((_, peer)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&serialize_response(&reply), peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn refresh_loop_emits_mapped_on_first_success() {
        let stub = spawn_repeated_stub(2, 49152).await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("event arrived")
            .expect("channel open");
        match event {
            NatPmpEvent::Mapped {
                external_port,
                lifetime_secs,
                ..
            } => {
                assert_eq!(external_port, 49152);
                assert_eq!(lifetime_secs, 2);
            }
            other => panic!("expected Mapped, got {other:?}"),
        }

        handle.cancel();
        let _ = handle.join().await;
    }

    #[tokio::test]
    async fn refresh_loop_emits_renewed_after_half_lifetime() {
        // Lifetime = 2s -> renew at 1s. The stub answers both the
        // initial request and the renewal.
        let stub = spawn_repeated_stub(2, 51000).await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        // First event: Mapped (within ~250ms).
        let first = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("first event")
            .expect("open");
        assert!(matches!(first, NatPmpEvent::Mapped { .. }));

        // Second event: Renewed (within ~1s + slack).
        let second = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("renewal event")
            .expect("open");
        match second {
            NatPmpEvent::Renewed {
                external_port,
                lifetime_secs,
                ..
            } => {
                assert_eq!(external_port, 51000);
                assert_eq!(lifetime_secs, 2);
            }
            other => panic!("expected Renewed, got {other:?}"),
        }

        handle.cancel();
        let _ = handle.join().await;
    }

    #[tokio::test]
    async fn refresh_loop_emits_failed_on_server_error_and_stops() {
        let stub = spawn_one_shot_stub(ServerResponse::Map {
            proto: MapProto::Udp,
            result_code: ResultCode::OutOfResources,
            epoch_secs: 0,
            internal_port: 22,
            external_port: 0,
            lifetime_secs: 0,
            rate_limit: None,
        })
        .await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("event arrived")
            .expect("open");
        match event {
            NatPmpEvent::Failed { error, reason } => {
                assert!(
                    error.contains("OutOfResources"),
                    "expected OutOfResources error, got: {error}"
                );
                assert_eq!(
                    reason,
                    NatPmpFailureReason::OutOfResources,
                    "OutOfResources ResultCode must classify as the OutOfResources reason"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        // The loop must have exited after Failed: join completes
        // quickly.
        let _ = tokio::time::timeout(Duration::from_secs(2), handle.join())
            .await
            .expect("loop terminated after Failed");
    }

    #[tokio::test]
    async fn refresh_loop_emits_rate_limited_and_keeps_running() {
        // A stub that always rate-limits. The loop must emit
        // `RateLimited` (carrying the retry-after from the trailer) and
        // must NOT terminate - it waits the retry-after and retries, so
        // the feature self-heals once the window clears.
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (_, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let resp = serialize_response(&ServerResponse::Map {
                    proto: MapProto::Udp,
                    result_code: ResultCode::RateLimited,
                    epoch_secs: 0,
                    internal_port: 22,
                    external_port: 0,
                    lifetime_secs: 0,
                    rate_limit: Some(warrenguard_natpmp_protocol::RateLimitInfo {
                        attempts_remaining: 0,
                        window_reset_secs: 1,
                    }),
                });
                let _ = sock.send_to(&resp, peer).await;
            }
        });

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handle = spawn_refresh_loop(addr, MapProto::Udp, 22, 0, 60, tx);

        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("event arrived")
            .expect("channel open");
        match event {
            NatPmpEvent::RateLimited { retry_after_secs } => assert_eq!(retry_after_secs, 1),
            other => panic!("expected RateLimited, got {other:?}"),
        }
        // The loop must still be alive: rate-limit is recoverable.
        assert!(
            !handle.is_finished(),
            "rate-limit must not terminate the refresh loop"
        );

        handle.cancel();
        let _ = handle.join().await;
    }

    #[tokio::test]
    async fn refresh_loop_retries_transient_error_without_emitting_failed() {
        // Regression: a transient failure (here a parse error from a
        // garbage reply) must NOT terminate the loop with `Failed` - it
        // must back off and retry, keeping the mapping alive. The
        // garbage reply guarantees the loop received + processed a
        // response and reached its retry decision, so the absence of any
        // event within the window proves it entered backoff rather than
        // emitting `Failed` (the pre-fix behaviour emitted `Failed`
        // immediately and stopped).
        let stub = spawn_repeated_garbage_stub().await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        let res = tokio::time::timeout(Duration::from_millis(800), rx.recv()).await;
        assert!(
            res.is_err(),
            "a transient error must not produce an immediate event (no Failed); got {res:?}"
        );

        handle.cancel();
        let _ = handle.join().await;
    }

    #[tokio::test]
    async fn refresh_loop_emits_failed_after_bounded_initial_transient_attempts() {
        // Regression (UI hang): BEFORE the first successful mapping, an
        // exit that never produces a valid response must NOT leave the
        // loop retrying forever - that strands the UI in its "requesting…"
        // state indefinitely (the exact symptom reported when NAT-PMP is
        // unreachable over the tunnel). After `MAX_INITIAL_MAP_ATTEMPTS`
        // transient failures the loop must emit `Failed { Other }` and
        // terminate so the user gets actionable feedback.
        //
        // The garbage stub yields an instant `Parse` error on every
        // request (transient, and `request_map_with_retries` does NOT retry
        // on parse), so each attempt itself is ~free; the only wall-clock
        // cost is the two inter-attempt backoff sleeps (5 s + 10 s) before
        // the third attempt trips the bound. A non-responding server would
        // instead pay the full ~7.75 s RFC timeout per attempt.
        let stub = spawn_repeated_garbage_stub().await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        let event = tokio::time::timeout(Duration::from_secs(30), rx.recv())
            .await
            .expect("a Failed event must arrive after the bounded initial attempts")
            .expect("channel open");
        match event {
            NatPmpEvent::Failed { reason, .. } => assert_eq!(
                reason,
                NatPmpFailureReason::Other,
                "an unresponsive exit classifies as the Other reason"
            ),
            other => panic!("expected Failed after bounded initial attempts, got {other:?}"),
        }

        // Failed must have terminated the loop.
        let _ = tokio::time::timeout(Duration::from_secs(5), handle.join())
            .await
            .expect("loop terminated after the initial Failed");
    }

    #[tokio::test]
    async fn refresh_loop_cancel_emits_cancelled_and_stops() {
        // Lifetime = 60 -> first renewal in 30s; we cancel well
        // before, expect Mapped then Cancelled.
        let stub = spawn_repeated_stub(60, 52000).await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Mapped event")
            .expect("open");
        assert!(matches!(first, NatPmpEvent::Mapped { .. }));

        handle.cancel();

        let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Cancelled event")
            .expect("open");
        assert!(matches!(second, NatPmpEvent::Cancelled));

        let _ = tokio::time::timeout(Duration::from_secs(2), handle.join())
            .await
            .expect("loop terminated after Cancelled");
    }

    #[tokio::test]
    async fn refresh_loop_cancel_during_request_short_circuits() {
        // Aim a never-responding server. With max_attempts=5 the
        // request_map keeps retrying for ~7.75s. Cancel must abort
        // the in-flight request and emit Cancelled within ~100ms.
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = server_sock.local_addr().expect("addr");
        std::mem::forget(server_sock);

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handle = spawn_refresh_loop(server_addr, MapProto::Udp, 22, 0, 60, tx);

        // Give the loop a moment to issue its first request.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let cancel_start = std::time::Instant::now();
        handle.cancel();

        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Cancelled event")
            .expect("open");
        assert!(matches!(event, NatPmpEvent::Cancelled));
        let elapsed = cancel_start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "cancel should short-circuit the in-flight request, took {elapsed:?}"
        );

        let _ = handle.join().await;
    }

    #[tokio::test]
    async fn refresh_loop_terminates_if_receiver_dropped() {
        let stub = spawn_repeated_stub(2, 53000).await;
        let (tx, rx) = mpsc::unbounded_channel();

        let handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);
        drop(rx);

        // The loop sends Mapped, the send fails because rx is dropped,
        // and the loop exits. join completes quickly.
        let _ = tokio::time::timeout(Duration::from_secs(3), handle.join())
            .await
            .expect("loop terminated after receiver drop");
    }

    #[tokio::test]
    async fn refresh_loop_cancel_is_idempotent() {
        let stub = spawn_repeated_stub(60, 54000).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        // Wait for Mapped.
        let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Mapped");

        // First cancel -> Cancelled event.
        handle.cancel();
        // Second cancel -> no panic, no extra event.
        handle.cancel();
        handle.cancel();

        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Cancelled")
            .expect("open");
        assert!(matches!(event, NatPmpEvent::Cancelled));

        let _ = handle.join().await;
    }

    /// Spawns a stub that records the `lifetime_secs` of every received
    /// Map request and replies with success (using `external_port` and
    /// the request's lifetime). Lets us assert that `release()` sends a
    /// `lifetime = 0` Map.
    async fn spawn_lifetime_recording_stub(
        external_port: u16,
    ) -> (SocketAddr, Arc<std::sync::Mutex<Vec<u32>>>) {
        use std::sync::Mutex;
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = sock.local_addr().expect("local_addr");
        let log: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let log_for_stub = log.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let lifetime = match warrenguard_natpmp_protocol::parse_request(&buf[..n]) {
                    Ok(warrenguard_natpmp_protocol::Request::Map { lifetime_secs, .. }) => {
                        lifetime_secs
                    }
                    _ => continue,
                };
                log_for_stub
                    .lock()
                    .expect("stub lock poisoned")
                    .push(lifetime);
                // Echo back a Success with the granted lifetime. For
                // a release (lifetime=0) the RFC says the server
                // responds with lifetime=0 too - mirror it so the
                // refresh loop's response parser is happy if the
                // packet ever reaches it (which won't happen here
                // because we call release() AFTER cancel()).
                let resp = serialize_response(&ServerResponse::Map {
                    proto: MapProto::Udp,
                    result_code: ResultCode::Success,
                    epoch_secs: 0,
                    internal_port: 22,
                    external_port,
                    lifetime_secs: lifetime,
                    rate_limit: None,
                });
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        (addr, log)
    }

    #[tokio::test]
    async fn release_sends_lifetime_zero_map_to_server() {
        // Wire-contract: `release()` must issue a Map with
        // `lifetime = 0` so the exit's allocator frees the slot
        // immediately. Without this, the per-client quota (=1)
        // would refuse a subsequent allocation until the lease
        // expires (~1 h).
        let (stub, log) = spawn_lifetime_recording_stub(56000).await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        // Wait for the initial Mapped so we know the first request
        // (lifetime != 0) reached the stub.
        let mapped = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Mapped event")
            .expect("open");
        assert!(matches!(mapped, NatPmpEvent::Mapped { .. }));

        // Pre-condition: stub saw the initial map request with
        // lifetime = 60.
        {
            let snapshot = log.lock().unwrap().clone();
            assert_eq!(snapshot, vec![60], "initial Map should carry lifetime=60");
        }

        handle.release().await;

        // Post-condition: a second request with lifetime = 0 was
        // sent to the stub. The exact count is at least 2 (the
        // release adds one). The release timeout is 750 ms so we
        // give the assertion a small slack window for the stub
        // socket to drain.
        for _ in 0..50 {
            let snapshot = log.lock().unwrap().clone();
            if snapshot.len() >= 2 && snapshot.contains(&0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let snapshot = log.lock().unwrap().clone();
        assert!(
            snapshot.len() >= 2,
            "stub should have recorded at least 2 requests (initial + release), got: {snapshot:?}"
        );
        assert!(
            snapshot.contains(&0),
            "stub should have recorded a lifetime=0 request, got: {snapshot:?}"
        );
    }

    #[tokio::test]
    async fn release_short_circuits_when_server_unresponsive() {
        // If the exit drops the release packet (network blip, server
        // overloaded), release() MUST still return within its
        // internal timeout - the caller (typically a daemon-side
        // reconfig path) cannot afford to block. We never want a
        // user toggling the feature off to hang the UI for 7+ s.
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = server_sock.local_addr().expect("addr");
        std::mem::forget(server_sock); // leak so the port stays bound; UDP receive never replies

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handle = spawn_refresh_loop(server_addr, MapProto::Udp, 22, 0, 60, tx);

        // Drain the eventual Failed event so the channel does not
        // back-pressure the loop on shutdown (the refresh loop hits
        // the retry limit and emits Failed).
        let _ = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;

        let start = std::time::Instant::now();
        handle.release().await;
        let elapsed = start.elapsed();
        // 750 ms internal timeout + ~250 ms cancel propagation slack.
        assert!(
            elapsed < Duration::from_millis(1500),
            "release() must short-circuit a stuck server, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn release_is_safe_to_call_after_cancel() {
        // Idempotence: calling release() on a handle that was
        // already cancelled must not panic. It also must not
        // re-send a request (the loop is already gone, but the
        // out-of-band release path uses its own socket).
        // Acceptable: the lifetime=0 request still goes out - it
        // is a no-op on the server side (mapping already absent or
        // expired) and the function returns cleanly.
        let stub = spawn_repeated_stub(60, 57000).await;
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut handle = spawn_refresh_loop(stub, MapProto::Udp, 22, 0, 60, tx);

        let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Mapped");

        handle.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await; // Cancelled

        // Calling release() after cancel must complete without
        // panicking. Internally `cancel()` is a no-op (already
        // cancelled), then the lifetime=0 Map fires and returns.
        let start = std::time::Instant::now();
        handle.release().await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "release() after cancel must remain bounded, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn refresh_loop_multiple_renewals_in_burst() {
        // Lifetime = 2 -> renew every 1s. We collect 3 events in <5s.
        let counter = Arc::new(AtomicU32::new(0));
        let counter_for_stub = counter.clone();
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (_, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                counter_for_stub.fetch_add(1, Ordering::SeqCst);
                let resp = serialize_response(&ServerResponse::Map {
                    proto: MapProto::Udp,
                    result_code: ResultCode::Success,
                    epoch_secs: 0,
                    internal_port: 22,
                    external_port: 55000,
                    lifetime_secs: 2,
                    rate_limit: None,
                });
                let _ = sock.send_to(&resp, peer).await;
            }
        });

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handle = spawn_refresh_loop(addr, MapProto::Udp, 22, 0, 60, tx);

        let mut events = Vec::new();
        for _ in 0..3 {
            let ev = tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .expect("event")
                .expect("open");
            events.push(ev);
        }

        assert!(matches!(events[0], NatPmpEvent::Mapped { .. }));
        assert!(matches!(events[1], NatPmpEvent::Renewed { .. }));
        assert!(matches!(events[2], NatPmpEvent::Renewed { .. }));
        assert!(
            counter.load(Ordering::SeqCst) >= 3,
            "stub should have served at least 3 requests"
        );

        handle.cancel();
        let _ = handle.join().await;
    }

    /// Records every Map request `(proto, suggested_external_port,
    /// lifetime_secs)` and replies per proto: UDP always succeeds with
    /// external port 58000; TCP replies `tcp_result` (Success echoes the
    /// suggested port, mirroring the exit's strict honour-or-error
    /// grant). Releases (lifetime=0) are recorded and acked.
    async fn spawn_pair_recording_stub(
        tcp_result: ResultCode,
    ) -> (SocketAddr, Arc<std::sync::Mutex<Vec<(MapProto, u16, u32)>>>) {
        use std::sync::Mutex;
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = sock.local_addr().expect("local_addr");
        let log: Arc<Mutex<Vec<(MapProto, u16, u32)>>> = Arc::new(Mutex::new(Vec::new()));
        let log_for_stub = log.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let (proto, suggested, lifetime) =
                    match warrenguard_natpmp_protocol::parse_request(&buf[..n]) {
                        Ok(warrenguard_natpmp_protocol::Request::Map {
                            proto,
                            suggested_external_port,
                            lifetime_secs,
                            ..
                        }) => (proto, suggested_external_port, lifetime_secs),
                        _ => continue,
                    };
                log_for_stub
                    .lock()
                    .expect("stub lock poisoned")
                    .push((proto, suggested, lifetime));
                let (result_code, external_port) = if lifetime == 0 {
                    (ResultCode::Success, 0)
                } else {
                    match proto {
                        MapProto::Udp => (ResultCode::Success, 58000),
                        MapProto::Tcp => match tcp_result {
                            ResultCode::Success => (ResultCode::Success, suggested),
                            other => (other, 0),
                        },
                    }
                };
                let resp = serialize_response(&ServerResponse::Map {
                    proto,
                    result_code,
                    epoch_secs: 0,
                    internal_port: 22,
                    external_port,
                    lifetime_secs: if result_code == ResultCode::Success {
                        lifetime
                    } else {
                        0
                    },
                    rate_limit: None,
                });
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        (addr, log)
    }

    #[tokio::test]
    async fn dual_refresh_loop_maps_both_protos_on_the_same_port() {
        let (stub, log) = spawn_pair_recording_stub(ResultCode::Success).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handle = spawn_refresh_loop_protos_from_addr(
            stub,
            ForwardProtos::Both,
            22,
            0,
            60,
            SuggestionKind::Pinned,
            tx,
            None,
        );

        let ev = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("event within timeout")
            .expect("channel open");
        assert!(
            matches!(
                ev,
                NatPmpEvent::Mapped {
                    external_port: 58000,
                    ..
                }
            ),
            "one Mapped for the whole pair with the UDP-granted port, got {ev:?}"
        );

        let reqs = log.lock().unwrap().clone();
        assert_eq!(reqs.len(), 2, "one Map per leg: {reqs:?}");
        assert_eq!(reqs[0].0, MapProto::Udp, "UDP leg goes first");
        assert_eq!(
            reqs[1],
            (MapProto::Tcp, 58000, 60),
            "TCP leg must pin the port granted to the UDP leg"
        );

        handle.cancel();
        let _ = handle.join().await;
    }

    #[tokio::test]
    async fn dual_refresh_loop_atomic_failure_releases_first_leg() {
        // The exit refuses the TCP leg permanently: the whole rule must
        // fail AND the already-granted UDP leg must be released, never
        // left half-mapped.
        let (stub, log) = spawn_pair_recording_stub(ResultCode::OutOfResources).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let handle = spawn_refresh_loop_protos_from_addr(
            stub,
            ForwardProtos::Both,
            22,
            0,
            60,
            SuggestionKind::Pinned,
            tx,
            None,
        );

        let ev = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("event within timeout")
            .expect("channel open");
        assert!(
            matches!(
                ev,
                NatPmpEvent::Failed {
                    reason: NatPmpFailureReason::OutOfResources,
                    ..
                }
            ),
            "the pair must fail as a unit, got {ev:?}"
        );

        // Give the in-task release a moment to hit the stub.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let reqs = log.lock().unwrap().clone();
        assert!(
            reqs.contains(&(MapProto::Udp, 0, 0)),
            "the granted UDP leg must be released (lifetime=0): {reqs:?}"
        );
        assert!(
            !matches!(
                tokio::time::timeout(Duration::from_millis(100), rx.recv()).await,
                Ok(Some(NatPmpEvent::Mapped { .. }))
            ),
            "no Mapped may be emitted for a half-granted pair"
        );

        let _ = handle.join().await;
    }

    #[tokio::test]
    async fn dual_release_sends_lifetime_zero_for_both_protos() {
        let (stub, log) = spawn_pair_recording_stub(ResultCode::Success).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handle = spawn_refresh_loop_protos_from_addr(
            stub,
            ForwardProtos::Both,
            22,
            0,
            60,
            SuggestionKind::Pinned,
            tx,
            None,
        );
        let _ = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("Mapped");

        handle.release().await;

        let reqs = log.lock().unwrap().clone();
        assert!(
            reqs.contains(&(MapProto::Udp, 0, 0)),
            "release must free the UDP leg: {reqs:?}"
        );
        assert!(
            reqs.contains(&(MapProto::Tcp, 0, 0)),
            "release must free the TCP leg: {reqs:?}"
        );
    }

    #[tokio::test]
    async fn dual_refresh_loop_renews_both_legs() {
        // Granted lifetime 2 -> renewal after ~1s re-Maps BOTH legs,
        // the TCP leg still pinned to the pair port.
        let (stub, log) = spawn_pair_recording_stub(ResultCode::Success).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut handle = spawn_refresh_loop_protos_from_addr(
            stub,
            ForwardProtos::Both,
            22,
            0,
            2,
            SuggestionKind::Pinned,
            tx,
            None,
        );

        let first = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("first event")
            .expect("open");
        assert!(matches!(first, NatPmpEvent::Mapped { .. }));
        let second = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("second event")
            .expect("open");
        assert!(
            matches!(
                second,
                NatPmpEvent::Renewed {
                    external_port: 58000,
                    ..
                }
            ),
            "renewal covers the pair as one event, got {second:?}"
        );

        let reqs = log.lock().unwrap().clone();
        let tcp_maps: Vec<_> = reqs
            .iter()
            .filter(|(p, _, l)| *p == MapProto::Tcp && *l > 0)
            .collect();
        assert!(
            tcp_maps.len() >= 2 && tcp_maps.iter().all(|(_, s, _)| *s == 58000),
            "every TCP renewal must stay pinned to the pair port: {reqs:?}"
        );

        handle.cancel();
        let _ = handle.join().await;
    }
}
