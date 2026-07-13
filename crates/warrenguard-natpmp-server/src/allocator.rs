//! In-RAM port-forwarding allocation pool with abuse mitigations
//! (cooldown, anti-predictable-rotation, rate-limit).
//!
//! **No disk persistence**: reboot = full reset, by design no-log.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::RngExt;
use warrenguard_config::{
    NATPMP_EXTERNAL_PORT_MAX, NATPMP_EXTERNAL_PORT_MIN, NATPMP_LIFETIME_MAX_SECS,
    NATPMP_LIFETIME_MIN_SECS, NATPMP_PORT_COOLDOWN_SECS, NATPMP_QUOTA_PER_CLIENT_IP,
    NATPMP_RATE_LIMIT_MAX_PER_WINDOW, NATPMP_RATE_LIMIT_WINDOW_SECS,
};

use crate::protocol::RateLimitInfo;
use crate::{Allocation, NatPmpError, Proto};

/// Tunable configuration for the [`Allocator`]. Use [`Allocator::new`]
/// for the Warren defaults; reach for `with_config` when a test needs
/// to shrink limits or a future subscription tier needs to widen the
/// per-client quota.
#[derive(Debug, Clone, Copy)]
pub struct AllocatorConfig {
    /// Inclusive `(low, high)` port range.
    pub range: (u16, u16),
    /// Cooldown applied to a freed port before it can be reused.
    pub cooldown: Duration,
    /// Max allocations per sliding `rate_limit_window` for one
    /// source IP.
    pub rate_limit_max: usize,
    /// Sliding window for the per-source rate limit.
    pub rate_limit_window: Duration,
    /// Max simultaneous active allocations per source IP. With the
    /// one-IP-per-pubkey tunnel model, this caps the per-pubkey
    /// port-forward budget at the same value.
    pub quota_per_client: usize,
}

impl AllocatorConfig {
    /// Build the Warren defaults (range 49152-65535, 5 min cooldown,
    /// `NATPMP_RATE_LIMIT_MAX_PER_WINDOW` new-allocations / window,
    /// `NATPMP_QUOTA_PER_CLIENT_IP` ports/client).
    #[must_use]
    pub fn warren_default() -> Self {
        Self {
            range: (NATPMP_EXTERNAL_PORT_MIN, NATPMP_EXTERNAL_PORT_MAX),
            cooldown: Duration::from_secs(NATPMP_PORT_COOLDOWN_SECS),
            rate_limit_max: NATPMP_RATE_LIMIT_MAX_PER_WINDOW,
            rate_limit_window: Duration::from_secs(NATPMP_RATE_LIMIT_WINDOW_SECS),
            quota_per_client: NATPMP_QUOTA_PER_CLIENT_IP,
        }
    }
}

impl Default for AllocatorConfig {
    fn default() -> Self {
        Self::warren_default()
    }
}

/// Outcome of an [`Allocator::allocate_collecting`] call: the allocation
/// result **plus** every previously-active mapping the same call removed
/// as a side effect.
///
/// The two fields are independent on purpose. `evicted` carries the
/// entries dropped from the `active` map while serving this request -
/// expired mappings reaped by the lazy sweep, and a stale same-tuple
/// mapping reclaimed on a refresh - and the caller **must** tear down
/// the backend rule (nftables `delete element`) for every entry in it,
/// **on every path, including when `result` is `Err`**. The entries are
/// already gone from `active`, so skipping teardown leaks their DNAT
/// rule past its in-memory lifetime (the allocator↔nftables desync this
/// type exists to prevent). An earlier version returned
/// `Result<AllocateOutcome, _>` and dropped `evicted` whenever the
/// allocation itself failed (rate-limit / quota / exhaustion): the
/// swept entries' kernel rules leaked on exactly those error paths.
/// Folding the result into the struct guarantees the caller always sees
/// what to undo. No backend call is made under the allocator lock.
#[derive(Debug, Clone)]
pub struct AllocateOutcome {
    /// The allocation result: `Ok(allocation)` on success, or `Err` on a
    /// strict suggested-port rejection, rate-limit, quota, or
    /// exhaustion. Independent of `evicted` - tear that down regardless.
    pub result: Result<Allocation, NatPmpError>,
    /// Mappings removed from `active` as a side effect of this call,
    /// each requiring a matching backend teardown on every path.
    pub evicted: Vec<Allocation>,
}

/// External port allocator for `warrenguard-natpmp-server`.
///
/// Internal state (RAM only):
/// - `active`: `external_port → Allocation`. Current source of truth.
/// - `cooldown`: recently released ports (FIFO ordered by release
///   instant + cooldown). A port in cooldown cannot be reallocated.
/// - `last_user_per_port`: `external_port → (last_client, expiry)`.
///   Prevents a port `N` from coming back to the same client on two
///   consecutive sessions (anti-predictable-rotation mitigation).
/// - `rate_limit_log`: `client_ip → sliding window of request
///   instants`. Rejects if > 5 allocations in the last 60 seconds.
pub struct Allocator {
    inner: Mutex<Inner>,
    range: (u16, u16),
    cooldown: Duration,
    rate_limit_max: usize,
    rate_limit_window: Duration,
    quota_per_client: usize,
    counters: AllocatorCounters,
}

/// Monotonic event tally exposed via [`Allocator::metrics`]. Each
/// counter only ever increments so a future `/metrics` exporter can
/// scrape it without an exclusive lock. The values are snapshotted
/// with `Relaxed` ordering: the counts may briefly drift across
/// concurrent threads, which is acceptable for ops dashboards.
#[derive(Default, Debug)]
struct AllocatorCounters {
    allocations: AtomicU64,
    releases: AtomicU64,
    evictions: AtomicU64,
    quota_exceeded: AtomicU64,
    rate_limited: AtomicU64,
    exhausted: AtomicU64,
    suggested_in_use: AtomicU64,
}

/// Snapshot of [`Allocator`] counters. Cheap to copy and stable
/// across versions: a future Prometheus exporter or admin JSON view
/// can read it and never trip on the internal mutex.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocatorMetrics {
    /// Successful allocations since boot.
    pub allocations_total: u64,
    /// Successful releases triggered by the client through a
    /// Map(lifetime=0) RFC §3.3.2 request or by an out-of-band
    /// eviction. Does NOT include the passive lazy expiry sweep:
    /// expired mappings are dropped from `active` and torn down at the
    /// backend, but they are not an explicit release event, so the
    /// `nftables` delete count is `releases_total` plus the number of
    /// expiry/refresh-reclaim teardowns.
    pub releases_total: u64,
    /// Forced releases triggered by an allowlist eviction
    /// (sub expired, admin revoke, etc.). Subset of
    /// `releases_total`; lets the admin separate organic churn
    /// from policy enforcement.
    pub evictions_total: u64,
    /// `allocate` attempts that hit the per-client quota.
    pub quota_exceeded_total: u64,
    /// `allocate` attempts that hit the per-source rate limit.
    pub rate_limited_total: u64,
    /// `allocate` attempts that failed because the port pool is
    /// full.
    pub exhausted_total: u64,
    /// `allocate` attempts that requested a specific external port
    /// (`suggested != 0`) that was unavailable to the client (held or
    /// cooled-down by a different client, or out of range). Under
    /// Warren's strict honour-or-error policy these are rejected with
    /// `SuggestedPortInUse` rather than silently reassigned.
    pub suggested_in_use_total: u64,
}

struct Inner {
    active: HashMap<u16, Allocation>,
    cooldown_until: HashMap<u16, Instant>,
    last_user_per_port: HashMap<u16, (Ipv4Addr, Instant)>,
    rate_limit_log: HashMap<Ipv4Addr, VecDeque<Instant>>,
}

impl Allocator {
    /// Creates an allocator with the Warren defaults (range
    /// 49152-65535, 5 min cooldown, 5/min/source rate limit, 1
    /// port/client quota).
    #[must_use]
    pub fn new() -> Self {
        Self::from_config(AllocatorConfig::warren_default())
    }

    /// Builds the allocator with the legacy four-argument shape.
    /// Kept for the pre-quota test fleet that calls into it with a
    /// tight pool range or aggressive rate limit; new callers
    /// should prefer [`Self::from_config`] which accepts the full
    /// [`AllocatorConfig`] (including the per-client quota).
    ///
    /// The quota defaults to `usize::MAX` here so the legacy tests
    /// keep observing their original semantics: only the explicit
    /// quota tests exercise the new cap.
    #[must_use]
    pub fn with_config(
        range: (u16, u16),
        cooldown: Duration,
        rate_limit_max: usize,
        rate_limit_window: Duration,
    ) -> Self {
        Self::from_config(AllocatorConfig {
            range,
            cooldown,
            rate_limit_max,
            rate_limit_window,
            quota_per_client: usize::MAX,
        })
    }

    /// Builds the allocator from a full [`AllocatorConfig`]. Use
    /// this for the quota-aware setup; the legacy `with_config`
    /// stays for backward compatibility with the pre-quota tests.
    #[must_use]
    pub fn from_config(config: AllocatorConfig) -> Self {
        assert!(
            config.range.0 <= config.range.1,
            "port range must be non-empty"
        );
        Self {
            inner: Mutex::new(Inner {
                active: HashMap::new(),
                cooldown_until: HashMap::new(),
                last_user_per_port: HashMap::new(),
                rate_limit_log: HashMap::new(),
            }),
            range: config.range,
            cooldown: config.cooldown,
            rate_limit_max: config.rate_limit_max,
            rate_limit_window: config.rate_limit_window,
            quota_per_client: config.quota_per_client,
            counters: AllocatorCounters::default(),
        }
    }

    /// Snapshot of the monotonic event counters. Useful for ops
    /// dashboards (Prometheus exporter, admin JSON view) and tests
    /// that assert on behavior end-to-end without prying into the
    /// allocator's private state.
    #[must_use]
    pub fn metrics(&self) -> AllocatorMetrics {
        AllocatorMetrics {
            allocations_total: self.counters.allocations.load(Ordering::Relaxed),
            releases_total: self.counters.releases.load(Ordering::Relaxed),
            evictions_total: self.counters.evictions.load(Ordering::Relaxed),
            quota_exceeded_total: self.counters.quota_exceeded.load(Ordering::Relaxed),
            rate_limited_total: self.counters.rate_limited.load(Ordering::Relaxed),
            exhausted_total: self.counters.exhausted.load(Ordering::Relaxed),
            suggested_in_use_total: self.counters.suggested_in_use.load(Ordering::Relaxed),
        }
    }

    /// Allocates an external port for `client_ip`, protocol `proto`,
    /// with the given lifetime. `suggested` != 0 → try that port
    /// first; otherwise random pick in the range.
    ///
    /// Lifetime is clamped to `[NATPMP_LIFETIME_MIN_SECS,
    /// NATPMP_LIFETIME_MAX_SECS]` (RFC 6886 §3.3).
    ///
    /// # Errors
    ///
    /// - [`NatPmpError::RateLimited`]: `client_ip` exceeded
    ///   `5 alloc/min`.
    /// - [`NatPmpError::Exhausted`]: no free port in the range.
    pub fn allocate(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested: u16,
        lifetime_secs: u32,
    ) -> Result<Allocation, NatPmpError> {
        self.allocate_at(
            client_ip,
            proto,
            internal_port,
            suggested,
            lifetime_secs,
            Instant::now(),
        )
    }

    /// Variant of [`Self::allocate`] with an injectable `now`. Used
    /// by tests to simulate cooldown / rate-limit expiry without a
    /// real clock.
    ///
    /// `internal_port` is propagated through to the `Allocation`
    /// (using it instead of the external port is required so the
    /// nftables DNAT works correctly when the client uses
    /// internal != external).
    ///
    /// # Errors
    ///
    /// See [`Self::allocate`].
    pub fn allocate_at(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested: u16,
        lifetime_secs: u32,
        now: Instant,
    ) -> Result<Allocation, NatPmpError> {
        // The plain (non-collecting) entry point discards `evicted`: it
        // is for the pure-RAM stub backend and tests that do not mirror
        // into kernel state, so there is nothing to tear down.
        self.allocate_at_collecting(
            client_ip,
            proto,
            internal_port,
            suggested,
            lifetime_secs,
            now,
        )
        .result
    }

    /// Variant of [`Self::allocate`] that also returns the entries this
    /// call removed from the active map (see [`AllocateOutcome`]).
    ///
    /// Backends that mirror the allocation into kernel state (the
    /// nftables DNAT map) **must** use this and tear down the matching
    /// rule for every `evicted` entry - even when
    /// [`AllocateOutcome::result`] is `Err` - otherwise expired or
    /// port-changed mappings leak their DNAT rule. The plain
    /// [`Self::allocate`] is kept for the pure-RAM stub and for tests
    /// that do not care about backend teardown.
    ///
    /// The allocation outcome (success or the specific failure) is in
    /// [`AllocateOutcome::result`]; this method itself never returns
    /// `Err` because the caller must inspect `evicted` regardless.
    pub fn allocate_collecting(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested: u16,
        lifetime_secs: u32,
    ) -> AllocateOutcome {
        self.allocate_at_collecting(
            client_ip,
            proto,
            internal_port,
            suggested,
            lifetime_secs,
            Instant::now(),
        )
    }

    /// Variant of [`Self::allocate_collecting`] with an injectable
    /// `now`. The allocation outcome is in [`AllocateOutcome::result`];
    /// `evicted` must be torn down by the caller on every path.
    pub fn allocate_at_collecting(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested: u16,
        lifetime_secs: u32,
        now: Instant,
    ) -> AllocateOutcome {
        let lifetime = clamp_lifetime(lifetime_secs);
        let mut g = self.inner.lock();

        // Entries this call removes from `active` (expiry sweep +
        // refresh-reclaim), collected up-front so EVERY return path -
        // including the error returns below - hands them back for
        // backend teardown. The strict pre-check returns before any
        // mutation, so `evicted` is simply empty there.
        let mut evicted: Vec<Allocation> = Vec::new();

        // Strict honouring of an explicit suggestion. RFC 6886 §3.3
        // permits the server to grant a different port, but Warren's UX
        // pins the requested port: the user typed a specific public
        // port, so we either grant exactly that port or fail with
        // `SuggestedPortInUse` - we never silently substitute a random
        // port, which the UI cannot distinguish from success and which
        // confused users who pinned a port (it appeared to "work" on a
        // different port, then "fix itself" on the next renewal).
        //
        // Checked up-front, BEFORE the lazy sweep / refresh-reclaim
        // mutate `active`, so a rejection leaves the client's current
        // mapping (and its backend DNAT rule) untouched: a live
        // port-change to an unavailable port fails cleanly and the
        // existing mapping keeps working. The rejection path mutates only
        // the probing client's rate-limit log, never `active`, so
        // there is still no `evicted` teardown to leak.
        if suggested != 0 {
            let grantable = port_in_range(suggested, self.range)
                && match g.active.get(&suggested) {
                    // Occupied - but a self-owned same-tuple entry (a
                    // refresh of the very same port) or an already
                    // expired entry (which the sweep below would free)
                    // does not block this client.
                    Some(a) => {
                        (a.internal_ip == client_ip
                            && a.internal_port == internal_port
                            && a.proto == proto)
                            || a.expires_at <= now
                    }
                    // Free in `active`: grantable iff eligible for this
                    // client, allowing the owner to reclaim its OWN
                    // pinned port (the cooldown only guards against a
                    // *different* client inheriting residual traffic).
                    None => port_eligible(&g, suggested, client_ip, now, true),
                };
            if !grantable {
                // Throttle the suggested-port occupancy oracle: a rejected
                // suggestion from a NON-owner (the owner's own refresh hits
                // grantable=true above and never reaches here) is a probe of
                // another client's port; charge it against the per-source rate
                // limit so an attacker cannot enumerate the live allocation
                // table at line rate for free and target other tenants' ports.
                let log = g.rate_limit_log.entry(client_ip).or_default();
                while log
                    .front()
                    .is_some_and(|t| now.duration_since(*t) > self.rate_limit_window)
                {
                    log.pop_front();
                }
                if log.len() >= self.rate_limit_max {
                    self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
                    let retry_after_secs = log
                        .front()
                        .map(|t| window_reset_secs(self.rate_limit_window, now.duration_since(*t)))
                        .unwrap_or(0);
                    return AllocateOutcome {
                        result: Err(NatPmpError::RateLimited {
                            client: client_ip,
                            retry_after_secs,
                        }),
                        evicted,
                    };
                }
                log.push_back(now);
                self.counters
                    .suggested_in_use
                    .fetch_add(1, Ordering::Relaxed);
                return AllocateOutcome {
                    result: Err(NatPmpError::SuggestedPortInUse(suggested)),
                    evicted,
                };
            }
        }

        // Lazy sweep of expired allocations before allocating. Without
        // this, ports stay RAM-occupied past their lifetime and the
        // pool ends in guaranteed exhaustion (clients that crash
        // without sending a delete-mapping).
        // Collect lazily-expired `(port, owner_ip, expires_at)` so their
        // anti-inheritance cooldown can be armed after the retain (the other
        // side maps cannot be touched while `active` is mutably borrowed here).
        let mut expired_ports: Vec<(u16, Ipv4Addr, Instant)> = Vec::new();
        g.active.retain(|ext, alloc| {
            let keep = alloc.expires_at > now;
            if !keep {
                expired_ports.push((*ext, alloc.internal_ip, alloc.expires_at));
                evicted.push(alloc.clone());
            }
            keep
        });
        // A lazily-expired lease (client crashed without sending delete) must
        // arm the SAME cooldown as an explicit release, or a DIFFERENT client
        // could grab the exact port the instant it lapses and inherit residual
        // inbound traffic. The cooldown is measured from the lease's EXPIRY,
        // not from `now` (the sweep time) - otherwise a client that simply
        // asks long after the lease lapsed would restart the cooldown clock and
        // be wrongly blocked. A long-dead entry whose cooldown already elapsed
        // adds nothing, so skip it. The owner can still reclaim its own port
        // via an explicit suggestion (`port_eligible(allow_owner_reclaim=true)`),
        // which is exactly the case the cooldown is NOT meant to block.
        for (ext, ip, expires_at) in expired_ports {
            let deadline = expires_at + self.cooldown;
            if deadline > now {
                g.cooldown_until.insert(ext, deadline);
                g.last_user_per_port.insert(ext, (ip, deadline));
            }
        }

        // The three side maps used to grow without bound
        // (cooldown_until, last_user_per_port, rate_limit_log). In
        // particular `rate_limit_log` kept empty entries forever for
        // any client that made a request then disappeared - unbounded
        // leak under ephemeral-client churn. The two port maps are
        // bounded by `range_size` but their entries used to remain
        // permanent past expiry.
        g.cooldown_until.retain(|_, expiry| *expiry > now);
        g.last_user_per_port.retain(|_, (_, expiry)| *expiry > now);
        let rate_window = self.rate_limit_window;
        g.rate_limit_log.retain(|_, log| {
            while log
                .front()
                .is_some_and(|t| now.duration_since(*t) > rate_window)
            {
                log.pop_front();
            }
            !log.is_empty()
        });

        // A refresh = a still-live mapping for the SAME
        // (client_ip, internal_port, proto) tuple (the expiry sweep above
        // already dropped dead ones). Renewals and re-applying an
        // unchanged port are refreshes; they neither count against nor
        // are blocked by the per-source rate limit. Without this, a
        // client holding N ports (multi-port) would spend its whole
        // rate-limit budget just keeping them alive - the limit is meant
        // to throttle NEW allocations / port changes, not steady-state
        // renewals.
        let is_refresh = g.active.values().any(|a| {
            a.internal_ip == client_ip && a.internal_port == internal_port && a.proto == proto
        });

        // Rate limit (NEW allocations only): trim the window then check
        // (do not increment yet). Incrementing before `pick_port` would
        // consume a slot on `Exhausted` failure, and a client racing
        // against a full pool would end up permanently `RateLimited`
        // (self-reinforcing DoS).
        if !is_refresh {
            let log = g.rate_limit_log.entry(client_ip).or_default();
            while log
                .front()
                .is_some_and(|t| now.duration_since(*t) > self.rate_limit_window)
            {
                log.pop_front();
            }
            if log.len() >= self.rate_limit_max {
                self.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
                // Retry-after = time until the oldest in-window entry
                // falls out of the window, freeing one slot. The log is
                // non-empty here (len >= max >= 1), so `front()` exists.
                let retry_after_secs = log
                    .front()
                    .map(|t| window_reset_secs(self.rate_limit_window, now.duration_since(*t)))
                    .unwrap_or(0);
                return AllocateOutcome {
                    result: Err(NatPmpError::RateLimited {
                        client: client_ip,
                        retry_after_secs,
                    }),
                    evicted,
                };
            }
        }

        // RFC 6886 §3.3 refresh semantics + orphan self-heal: a MAP
        // request for a `(client_ip, internal_port, proto)` tuple that
        // is ALREADY mapped is a REFRESH, not a brand-new allocation.
        // Drop the existing entry (entries - defensive against any
        // historical duplicate) BEFORE the quota check so that:
        //
        //  (a) the refresh does not count against the per-client quota
        //      (otherwise a quota-saturated client could never renew its
        //      own mappings - it would always see QuotaExceeded);
        //  (b) the client may change the suggested external port
        //      across refreshes (we re-run pick_port below);
        //  (c) a stale mapping left by a client that crashed /
        //      reconnected without releasing (orphan) is reclaimed by
        //      the same client's next MAP, instead of the client being
        //      locked out with OutOfResources until the old lease
        //      expires (~1 h). This is the path that unblocks a user
        //      whose tunnel dropped mid-mapping and reconnected with
        //      the same deterministic tunnel IP.
        //
        // We deliberately do NOT register a cooldown / anti-rotation
        // entry for the reclaimed port: the same client is the one
        // re-requesting, so penalising it would defeat the refresh.
        let stale_same_tuple: Vec<u16> = g
            .active
            .iter()
            .filter(|(_, a)| {
                a.internal_ip == client_ip && a.internal_port == internal_port && a.proto == proto
            })
            .map(|(ext, _)| *ext)
            .collect();
        // Remember the port this client most recently held for the
        // tuple, so a refresh that carries no explicit suggestion can
        // reuse it (port stability across renewals - see below).
        let mut previously_held: Option<u16> = None;
        for ext in stale_same_tuple {
            if let Some(removed) = g.active.remove(&ext) {
                previously_held = Some(ext);
                // Refresh that moves to a different external port: the
                // old port's DNAT element must be deleted by the
                // backend, or it lingers forwarding to the client
                // forever. When the refresh keeps the same port it is
                // re-granted below and re-added; deleting then re-adding
                // the same element keeps the kernel map authoritative.
                evicted.push(removed);
            }
        }

        // Per-client quota. Counted on *active* allocations only
        // (after the refresh-reclaim above). Releasing a port restores
        // a slot immediately so a legitimate client can rotate ports
        // without waiting on the global cooldown. Once a source IP holds
        // `NATPMP_QUOTA_PER_CLIENT_IP` (currently 5) simultaneous mappings,
        // a further mapping on a different internal_port is refused here
        // before we touch the port pool.
        let already_held = g
            .active
            .values()
            .filter(|alloc| alloc.internal_ip == client_ip)
            .count();
        if already_held >= self.quota_per_client {
            self.counters.quota_exceeded.fetch_add(1, Ordering::Relaxed);
            return AllocateOutcome {
                result: Err(NatPmpError::QuotaExceeded(client_ip)),
                evicted,
            };
        }

        // Port choice.
        // - An explicit suggestion was already validated as grantable
        //   by the strict pre-check at the top of this function, and the
        //   sweep / refresh-reclaim since then only ever FREED ports
        //   (never made it ineligible), so we grant it verbatim. No
        //   random fallback: strict honour-or-error.
        // - With no suggestion, reuse the port the client just held on a
        //   refresh so the public mapping stays stable across the
        //   ~30 min renewal cycle (RFC 6886 refresh semantics), else
        //   pick a random free port.
        let port = if suggested != 0 {
            suggested
        } else {
            match pick_port(&g, self.range, previously_held.unwrap_or(0), client_ip, now) {
                Some(p) => p,
                None => {
                    self.counters.exhausted.fetch_add(1, Ordering::Relaxed);
                    return AllocateOutcome {
                        result: Err(NatPmpError::Exhausted),
                        evicted,
                    };
                }
            }
        };

        // Allocation succeeded: register a rate-limit slot ONLY for a
        // genuinely-new allocation (a refresh of an existing mapping is
        // exempt - see `is_refresh` above - so steady-state renewals of
        // many held ports never erode the budget).
        if !is_refresh {
            g.rate_limit_log
                .entry(client_ip)
                .or_default()
                .push_back(now);
        }

        let alloc = Allocation {
            external_port: port,
            internal_ip: client_ip,
            internal_port,
            proto,
            expires_at: now + lifetime,
        };
        g.active.insert(port, alloc.clone());
        self.counters.allocations.fetch_add(1, Ordering::Relaxed);
        AllocateOutcome {
            result: Ok(alloc),
            evicted,
        }
    }

    /// Releases an allocation. Starts the port cooldown and records
    /// `last_user_per_port` to block immediate return to the same
    /// client.
    ///
    /// # Errors
    ///
    /// No visible error; release is best-effort (an unknown port is
    /// silently ignored, conforming to RFC §3.3.2).
    ///
    /// # Warning
    ///
    /// Releases whatever currently holds `alloc.external_port` with NO
    /// `internal_ip` owner check. This is safe today only because the single
    /// client-reachable release path is `release_by_client` (owner-scoped, RFC
    /// `lifetime=0`). NEVER call this with an attacker-influenced port, or one
    /// client could tear down another client's mapping (cross-tenant).
    pub fn release(&self, alloc: &Allocation) {
        self.release_at(alloc, Instant::now());
    }

    /// Variant with an injectable `now`.
    pub fn release_at(&self, alloc: &Allocation, now: Instant) {
        let mut g = self.inner.lock();
        if g.active.remove(&alloc.external_port).is_some() {
            g.cooldown_until
                .insert(alloc.external_port, now + self.cooldown);
            // Anti-rotation expires with the cooldown: past that, the
            // same client may re-request the same port (no permanent
            // penalty).
            g.last_user_per_port.insert(
                alloc.external_port,
                (alloc.internal_ip, now + self.cooldown),
            );
            self.counters.releases.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Releases a mapping identified by `(client_ip, internal_port,
    /// proto)`. Conforms to RFC 6886 §3.3.2: a Map request with
    /// `lifetime=0` carries the client's `internal_port` (the port it
    /// bound on its socket) - the server does the internal lookup to
    /// find the associated `external_port`, then releases the
    /// mapping.
    ///
    /// Lookup must be by `internal_port`: looking up by
    /// `external_port` would only work by accident when
    /// internal == external (when the client passes `suggested ==
    /// bind`). The RFC semantics is internal-port lookup.
    ///
    /// Returns `Some(alloc)` iff a matching mapping was found AND
    /// belonged to the client requesting deletion. Otherwise `None`
    /// (silent no-op so we do not leak the existence of a mapping
    /// owned by another client). The `Allocation` is useful for the
    /// caller (e.g. nftables backend) to recover the `external_port`
    /// to pass to `delete element`.
    pub fn release_by_client(
        &self,
        client_ip: Ipv4Addr,
        internal_port: u16,
        proto: Proto,
    ) -> Option<Allocation> {
        self.release_by_client_at(client_ip, internal_port, proto, Instant::now())
    }

    /// Variant of [`Self::release_by_client`] with an injectable
    /// `now`.
    pub fn release_by_client_at(
        &self,
        client_ip: Ipv4Addr,
        internal_port: u16,
        proto: Proto,
        now: Instant,
    ) -> Option<Allocation> {
        let mut g = self.inner.lock();
        // Find the external_port for (client_ip, internal_port,
        // proto). Linear in N=active mappings; OK for N < a few
        // thousand, otherwise add a reverse index later.
        let external_port = g.active.iter().find_map(|(ext, a)| {
            (a.internal_ip == client_ip && a.internal_port == internal_port && a.proto == proto)
                .then_some(*ext)
        })?;
        let alloc = g.active.remove(&external_port).expect("checked above");
        g.cooldown_until.insert(external_port, now + self.cooldown);
        g.last_user_per_port
            .insert(external_port, (alloc.internal_ip, now + self.cooldown));
        self.counters.releases.fetch_add(1, Ordering::Relaxed);
        Some(alloc)
    }

    /// Current number of active mappings (useful for metrics and
    /// tests).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.inner.lock().active.len()
    }

    /// Reinstates mappings saved by a previous process of this same
    /// allocator (exit hot-swap persistence). Each entry goes back into
    /// the active table unless it has expired or its external port is
    /// already held (first-wins). No quota or rate-limit charge: these
    /// grants were already paid for before the restart. The previous
    /// owner is re-armed in the anti-rotation map so owner-reclaim
    /// semantics survive the restart. Returns the entries actually
    /// reinstated so a backend can mirror exactly those into the
    /// kernel. No range validation: entries come from a prior run of
    /// this allocator (the consumer's snapshot version gate is the
    /// compatibility boundary), never from clients.
    pub fn restore(&self, entries: Vec<Allocation>) -> Vec<Allocation> {
        self.restore_at(entries, Instant::now())
    }

    /// [`Self::restore`] with an injectable `now` (tests).
    pub fn restore_at(&self, entries: Vec<Allocation>, now: Instant) -> Vec<Allocation> {
        let mut g = self.inner.lock();
        let mut kept = Vec::new();
        for entry in entries {
            if entry.expires_at <= now || g.active.contains_key(&entry.external_port) {
                continue;
            }
            g.last_user_per_port
                .insert(entry.external_port, (entry.internal_ip, now));
            g.active.insert(entry.external_port, entry.clone());
            kept.push(entry);
        }
        kept
    }

    /// Pure read of every currently active mapping. Consumed by the
    /// Exit -> API sync push that mirrors allocations into the admin
    /// view. Does NOT lazy-sweep expired entries; that happens on the
    /// next `allocate_at`. Callers that need a fresh-only view must
    /// either drive a periodic allocate or filter on `expires_at`.
    #[must_use]
    pub fn snapshot_active(&self) -> Vec<Allocation> {
        self.inner.lock().active.values().cloned().collect()
    }

    /// Remove every active mapping owned by `client_ip` and return
    /// them so the caller can tear down the matching backend rules
    /// (typically nftables DNAT). Each freed port enters the same
    /// cooldown as a regular release: an evicted client cannot
    /// race-recover its port by reconnecting.
    ///
    /// Called by the exit binary's revocation handler whenever the
    /// allowlist drops a pubkey: the tunnel IP becomes unreachable
    /// the moment the QUIC session closes, but without this step
    /// the NAT-PMP allocator would keep the port pinned to the
    /// gone IP and the API admin mirror would stay stale.
    pub fn take_active_for_ip(&self, client_ip: Ipv4Addr) -> Vec<Allocation> {
        self.take_active_for_ip_at(client_ip, Instant::now())
    }

    /// Remove the single active mapping at `external_port` and
    /// return it so the caller can tear down the matching backend
    /// rule. Used by the admin revoke path: the control plane pushes the
    /// pending port list back to the exit through the sync
    /// response, and the exit drains each entry through this
    /// method before feeding the cleanup worker.
    ///
    /// Returns `None` if no allocation currently holds that port
    /// (already expired, never allocated, or freed by a concurrent
    /// path). The cooldown bookkeeping mirrors the regular release
    /// path so an admin revoke does not let the same port come
    /// back to the same client immediately.
    ///
    /// # Warning
    ///
    /// Removes whatever holds `port` with NO `internal_ip` owner check (it is
    /// the admin-revoke-by-port primitive). NEVER expose it on a
    /// client-reachable path with a client-supplied port, or one client could
    /// evict another's mapping. Client releases go through `release_by_client`.
    pub fn take_active_for_port(&self, port: u16) -> Option<Allocation> {
        self.take_active_for_port_at(port, Instant::now())
    }

    /// Variant of [`Self::take_active_for_port`] with an injectable
    /// `now` for tests.
    pub fn take_active_for_port_at(&self, port: u16, now: Instant) -> Option<Allocation> {
        let mut g = self.inner.lock();
        let alloc = g.active.remove(&port)?;
        g.cooldown_until.insert(port, now + self.cooldown);
        g.last_user_per_port
            .insert(port, (alloc.internal_ip, now + self.cooldown));
        self.counters.releases.fetch_add(1, Ordering::Relaxed);
        self.counters.evictions.fetch_add(1, Ordering::Relaxed);
        Some(alloc)
    }

    /// Variant of [`Self::take_active_for_ip`] with an injectable
    /// `now`; used by tests that need to observe the cooldown
    /// bookkeeping deterministically.
    pub fn take_active_for_ip_at(&self, client_ip: Ipv4Addr, now: Instant) -> Vec<Allocation> {
        let mut g = self.inner.lock();
        let ports: Vec<u16> = g
            .active
            .iter()
            .filter_map(|(port, alloc)| (alloc.internal_ip == client_ip).then_some(*port))
            .collect();
        let mut removed = Vec::with_capacity(ports.len());
        for port in ports {
            if let Some(alloc) = g.active.remove(&port) {
                g.cooldown_until.insert(port, now + self.cooldown);
                g.last_user_per_port
                    .insert(port, (alloc.internal_ip, now + self.cooldown));
                removed.push(alloc);
            }
        }
        if !removed.is_empty() {
            let n = removed.len() as u64;
            self.counters.releases.fetch_add(n, Ordering::Relaxed);
            self.counters.evictions.fetch_add(n, Ordering::Relaxed);
        }
        removed
    }

    /// Number of ports currently in cooldown (useful for metrics and
    /// memory-purge invariant tests).
    #[must_use]
    pub fn cooldown_count(&self) -> usize {
        self.inner.lock().cooldown_until.len()
    }

    /// Number of `(port → last_user)` entries in the anti-rotation
    /// map (useful for metrics and memory-purge invariant tests).
    #[must_use]
    pub fn last_user_count(&self) -> usize {
        self.inner.lock().last_user_per_port.len()
    }

    /// Number of clients currently tracked in the rate-limit window
    /// (useful for metrics and memory-purge invariant tests).
    #[must_use]
    pub fn rate_limit_clients_tracked(&self) -> usize {
        self.inner.lock().rate_limit_log.len()
    }

    /// Current per-source rate-limit budget for `client_ip`, without
    /// consuming a slot. Attached by the server to every Map response so
    /// the client/UI can warn before a ban and show a retry countdown
    /// after one.
    #[must_use]
    pub fn rate_limit_status(&self, client_ip: Ipv4Addr) -> RateLimitInfo {
        self.rate_limit_status_at(client_ip, Instant::now())
    }

    /// Variant of [`Self::rate_limit_status`] with an injectable `now`
    /// for tests. Trims the client's sliding window (so the reported
    /// budget reflects the current instant) but never inserts an empty
    /// entry for an unknown client - keeping the read leak-free.
    #[must_use]
    pub fn rate_limit_status_at(&self, client_ip: Ipv4Addr, now: Instant) -> RateLimitInfo {
        let window = self.rate_limit_window;
        let mut g = self.inner.lock();
        let (used, oldest) = match g.rate_limit_log.get_mut(&client_ip) {
            Some(log) => {
                while log.front().is_some_and(|t| now.duration_since(*t) > window) {
                    log.pop_front();
                }
                (log.len(), log.front().copied())
            }
            None => (0, None),
        };
        let attempts_remaining =
            u8::try_from(self.rate_limit_max.saturating_sub(used)).unwrap_or(u8::MAX);
        let window_reset_secs =
            oldest.map_or(0, |t| window_reset_secs(window, now.duration_since(t)));
        RateLimitInfo {
            attempts_remaining,
            window_reset_secs,
        }
    }
}

/// Seconds until a sliding-window entry that is `elapsed_since_oldest`
/// old falls out of `window`. Rounds up to whole seconds (so a partial
/// second still reads as "wait 1s" rather than "0s, retry now" which
/// would just bounce off the limit again). Saturates at `u16::MAX`.
fn window_reset_secs(window: Duration, elapsed_since_oldest: Duration) -> u16 {
    let remaining = window.saturating_sub(elapsed_since_oldest);
    let secs = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
    u16::try_from(secs).unwrap_or(u16::MAX)
}

impl Default for Allocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Clamps `requested_secs` to `[NATPMP_LIFETIME_MIN_SECS,
/// NATPMP_LIFETIME_MAX_SECS]`. Returns a `Duration` >= min.
///
/// RFC §3.3 note: if the client asks for 0, it's a delete - the
/// caller must have intercepted that earlier. Clamp to min as a
/// safety net so we never create a 0s mapping.
fn clamp_lifetime(requested_secs: u32) -> Duration {
    let s = requested_secs.clamp(NATPMP_LIFETIME_MIN_SECS, NATPMP_LIFETIME_MAX_SECS);
    Duration::from_secs(u64::from(s))
}

/// Whether external port `p` falls within the allocator's range.
fn port_in_range(p: u16, range: (u16, u16)) -> bool {
    p >= range.0 && p <= range.1
}

/// Whether external port `p` may be granted to `client_ip`.
///
/// A port is eligible when it is not actively mapped and not within the
/// post-release cooldown. The cooldown exists to stop a *different*
/// client from inheriting a port whose previous tenant may still receive
/// residual inbound traffic.
///
/// `allow_owner_reclaim` distinguishes the two call paths:
/// - `false` (no-preference random pick / refresh reuse): the port's own
///   previous owner is ALSO steered away from its just-released port -
///   anti-predictable-rotation when the client expressed no preference.
/// - `true` (EXPLICIT suggestion): the previous owner may reclaim its
///   OWN port immediately, bypassing only its own cooldown (a different
///   client is still blocked). Routing an explicit suggestion through
///   the `false` path was the bug behind "I pin port X but get a random
///   port until the next renewal".
fn port_eligible(
    g: &Inner,
    p: u16,
    client_ip: Ipv4Addr,
    now: Instant,
    allow_owner_reclaim: bool,
) -> bool {
    if g.active.contains_key(&p) {
        return false;
    }
    // Owner reclaiming its own recently-released port (explicit
    // suggestion only): bypass its own cooldown.
    if allow_owner_reclaim
        && g.last_user_per_port
            .get(&p)
            .is_some_and(|(prev_ip, expiry)| *prev_ip == client_ip && *expiry > now)
    {
        return true;
    }
    g.cooldown_until.get(&p).is_none_or(|t| *t <= now)
        && g.last_user_per_port
            .get(&p)
            .is_none_or(|(prev_ip, expiry)| *prev_ip != client_ip || *expiry <= now)
}

/// Maximum random attempts before falling back to the linear path of
/// `pick_port`. On a lightly loaded pool (<99%), 256 uniform draws
/// statistically cover almost all cases with
/// `(1 - p_free) ** 256 ≈ 0` for p_free >= 1%. On a near-full pool the
/// linear fallback (O(range_size)) takes over, but that case is
/// already in the exhaustion regime where we return `Exhausted`.
const PICK_PORT_RANDOM_TRIES: usize = 256;

/// Picks a free port in `range`:
/// 1. if `suggested != 0` and it is free + not in cooldown + not the
///    same user as `last_user_per_port`, return it.
/// 2. otherwise, draw randomly up to [`PICK_PORT_RANDOM_TRIES`]
///    indices from the range. Hot case: lightly loaded pool → finds
///    one in O(1).
/// 3. linear fallback in `O(range_size)` only when the pool is nearly
///    full (< 1% free) - acceptable since we are at the edge of
///    `Exhausted`.
/// 4. otherwise `None` (= [`NatPmpError::Exhausted`]).
///
/// Earlier versions collected the whole range into a `Vec<u16>`
/// (32 KB for 16384 ports) and Fisher-Yates shuffled the entire vec
/// on *every* NAT-PMP allocation, holding the global allocator lock.
/// This was a measured bottleneck under sustained load.
fn pick_port(
    g: &Inner,
    range: (u16, u16),
    suggested: u16,
    client_ip: Ipv4Addr,
    now: Instant,
) -> Option<u16> {
    // `allow_owner_reclaim = false`: this is the no-preference path
    // (random pick / refresh reuse), where anti-rotation steers a client
    // away from its own recently-released port. Explicit suggestions are
    // handled by the strict pre-check, not here.
    if suggested != 0
        && port_in_range(suggested, range)
        && port_eligible(g, suggested, client_ip, now, false)
    {
        return Some(suggested);
    }

    let range_size = u32::from(range.1 - range.0) + 1;
    let mut rng = rand::rng();

    // Hot path: uniform draw without alloc. Covers the overwhelming
    // majority of real cases where the pool is not saturated.
    let tries = (range_size as usize).min(PICK_PORT_RANDOM_TRIES);
    for _ in 0..tries {
        let offset = rng.random_range(0..range_size);
        // Cast safe: range_size <= 65536, offset < range_size, so
        // range.0 + offset <= u16::MAX (the addition fits in u32 and
        // the result fits in u16 since it is <= range.1).
        let p = range.0 + u16::try_from(offset).expect("offset < range_size <= 65536");
        if port_eligible(g, p, client_ip, now, false) {
            return Some(p);
        }
    }

    // Linear fallback. Only reached when the pool is full enough that
    // 256 uniform draws hit no free port.
    (range.0..=range.1).find(|&p| port_eligible(g, p, client_ip, now, false))
}
