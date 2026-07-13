//! Session management types for the exit side: multi-conn state,
//! session handles, revocation, and IP attribution logic.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex as AsyncMutex;
use warrenguard_wire::{DEVICE_ID_LEN, Setup, WarrenPubkey};

use super::{
    DEFAULT_MAX_MTU, DaitaPool, IpAllocator, IpAllocatorV6, select_daita_spec_with_existing,
};
use crate::exit_state::StatePersister;
use warrenguard_transport_core::constants::WARREN_AUTH_FAILED;

/// Session map key (v2 device cap): the wallet pubkey **plus** the
/// per-run `device_id`. Re-keying by `(pubkey, device_id)` means that
/// multi-conn connections of ONE device (same id) still collapse onto a
/// single session/IP, while DISTINCT devices of the same account (same
/// pubkey, different id) get DISTINCT sessions and DISTINCT tunnel IPs
/// instead of colliding on one IP.
pub(crate) type SessionKey = (WarrenPubkey, [u8; DEVICE_ID_LEN]);

/// Multi-conn session state on the exit side: all parameters shared by
/// the N connections of a single Ed25519 client identity.
///
/// The `HashMap<WarrenPubkey, MultiSessionState>` of [`super::ExitListener`]
/// aggregates the assigned IP, no need to recount per conn. When a
/// secondary arrives (idx > 0), the exit looks up this state and returns
/// the same IP as the primary.
#[derive(Debug, Clone)]
pub(crate) struct MultiSessionState {
    /// IPv4 assigned to the primary, shared by all secondaries of the
    /// session.
    pub(crate) ipv4: Ipv4Addr,
    /// Optional tunnel IPv6 in `fdcc:f:1::/64`. `Some` if the primary
    /// announced `features::IPV6` in its `Setup`. Secondaries inherit
    /// the same value automatically.
    pub(crate) ipv6: Option<Ipv6Addr>,
    /// MTU negotiated with the primary, also shared.
    pub(crate) max_mtu: u16,
    /// Connection count declared by the client in the primary Setup's
    /// `total_connections` field. Allows validating that secondaries
    /// have the same `total` and that `connection_index < total`.
    pub(crate) total: u8,
    /// DAITA spec negotiated with the primary. Shared with
    /// every secondary so every connection of a multi-conn session
    /// runs the same maybenot machines; otherwise the per-connection
    /// signal an attacker observes could be re-distinguished after
    /// the per-connection defenses collapse. `None` when the client
    /// did not opt into DAITA or the exit has no configured pool.
    pub(crate) daita_spec: Option<warrenguard_wire::DaitaConfig>,
    /// v7 only: the Privacy Pass token serial the PRIMARY spent to open
    /// this session. `Some` for a v7 session (its lease is re-asserted by
    /// serial), `None` for a v6 session (its lease is re-asserted by
    /// `(pubkey, device_id)` through the device-cap enforcer). Never
    /// persisted: a v7 session is a RAM-only bearer credential, recovered by
    /// a re-handshake after an exit restart.
    pub(crate) token_serial: Option<[u8; 32]>,
}

/// Cloneable read-only view over the live session map of an
/// [`super::ExitListener`]. Other components (notably an exit binary's
/// NAT-PMP -> API sync push) need to know which client pubkey currently owns
/// each tunnel-pool IPv4, without taking the same async mutex as the
/// handshake hot path. The `snapshot_*` accessors take the lock for
/// the duration of one O(N) copy and release it immediately.
#[derive(Clone)]
pub struct ExitSessionsHandle {
    pub(super) sessions: Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
}

impl ExitSessionsHandle {
    /// Build a handle from explicit pairs, for use in tests that
    /// need a populated map without spawning a real exit + tunnel.
    /// In production the handle is obtained via
    /// [`super::ExitListener::sessions_handle`].
    ///
    /// The supplied pubkeys are keyed with the all-zero `device_id`
    /// sentinel; tests that only exercise the `IPv4 -> pubkey_hex`
    /// snapshot do not care about the device dimension.
    #[must_use]
    pub fn from_pairs(pairs: impl IntoIterator<Item = (WarrenPubkey, Ipv4Addr)>) -> Self {
        let mut map: HashMap<SessionKey, MultiSessionState> = HashMap::new();
        for (pk, ipv4) in pairs {
            map.insert(
                (pk, [0u8; DEVICE_ID_LEN]),
                MultiSessionState {
                    ipv4,
                    ipv6: None,
                    max_mtu: 0,
                    total: 1,
                    daita_spec: None,
                    token_serial: None,
                },
            );
        }
        Self {
            sessions: Arc::new(AsyncMutex::new(map)),
        }
    }

    /// Snapshot the live `(IPv4 -> pubkey hex)` map. Used by the
    /// port-forward sync loop to attribute every NAT-PMP allocation
    /// to a client pubkey. The cost is O(N_sessions) under one lock
    /// acquisition; cheap enough to drive once per sync interval.
    ///
    /// Keyed by `(pubkey, device_id)` internally: if two devices of one
    /// account own two distinct IPs, the snapshot correctly emits both
    /// `IPv4 -> pubkey_hex` entries (same pubkey, different IPv4).
    pub async fn snapshot_ipv4_to_pubkey_hex(&self) -> HashMap<Ipv4Addr, String> {
        let map = self.sessions.lock().await;
        let mut out = HashMap::with_capacity(map.len());
        for ((pk, _device_id), state) in map.iter() {
            out.insert(state.ipv4, pk.to_hex());
        }
        out
    }

    /// Snapshot the live set of `(pubkey, device_id)` sessions. Consumed
    /// by the exit binary's lease-renewal task, which re-asserts each
    /// live device against the global device-session ledger every
    /// `SESSION_LEASE_RENEW_SECS` so a lease never expires under an
    /// active device.
    pub async fn snapshot_live_devices(&self) -> Vec<(WarrenPubkey, [u8; DEVICE_ID_LEN])> {
        let map = self.sessions.lock().await;
        map.keys().copied().collect()
    }

    /// Snapshot the live v7 token serials (one per anonymous session that a
    /// PRIMARY opened by spending a token). Consumed by the exit binary's
    /// lease-renewal task, which passes them to
    /// [`SessionTokenAdmitter::renew_live`](super::session_token::SessionTokenAdmitter::renew_live)
    /// every `SESSION_LEASE_RENEW_SECS` so a v7 lease never expires under a
    /// live session, and any serial that dropped out is forgotten.
    pub async fn snapshot_live_token_serials(&self) -> Vec<[u8; 32]> {
        let map = self.sessions.lock().await;
        map.values().filter_map(|s| s.token_serial).collect()
    }
}

/// Extract the IPv4 source of a QUIC peer address for the Port Fail guard
/// set, unmapping a v4-mapped-v6 address. Returns `None` for a genuine IPv6
/// peer: the guard set is v4-only, so a native-v6 client's real address
/// cannot be added (a documented coverage gap, not a fabricated entry).
///
/// Kept pure (no `quinn::Connection`) so it is unit-tested directly; the
/// handle below only maps every live connection's `remote_address()` through
/// it.
pub(crate) fn ipv4_source_of(addr: std::net::SocketAddr) -> Option<Ipv4Addr> {
    match addr {
        std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
        std::net::SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped(),
    }
}

/// Cloneable read-only view over the REAL (outer, 5-tuple) source IPv4s of the
/// exit's currently-connected subscribers. Consumed by an exit binary's Port
/// Fail defense-in-depth maintainer, which mirrors this set into an nftables
/// set so a packet from a connected subscriber's real IP to another's
/// forwarded port is dropped on the exit (closing the Port Fail leak for old
/// clients whose route-split is not yet narrowed).
///
/// Reads the live connection map only; never a data-plane hot path.
#[derive(Clone)]
pub struct ExitPeerSourcesHandle {
    pub(super) active_conns: Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
}

impl ExitPeerSourcesHandle {
    /// Snapshot the set of connected subscribers' real source IPv4s. Native
    /// IPv6-only peers are absent (the v4 guard cannot cover them). Sorted
    /// (BTreeSet) so the rendered nft sync is deterministic.
    #[must_use]
    pub fn snapshot_ipv4_sources(&self) -> std::collections::BTreeSet<Ipv4Addr> {
        let map = self.active_conns.lock();
        map.values()
            .flatten()
            .filter_map(|conn| ipv4_source_of(conn.remote_address()))
            .collect()
    }
}

/// Cheap, clonable handle that lets a task running independently of
/// the consuming [`super::ExitListener::accept_forever_with_tun`] tear down
/// connections whose pubkey was revoked.
///
/// Holds clones of the two internal `Arc`s; dropping the handle does
/// not affect the listener itself.
#[derive(Clone)]
pub struct ExitRevocationHandle {
    pub(super) active_conns: Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
    pub(super) sessions: Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
    pub(super) allocator: Arc<IpAllocator>,
    pub(super) allocator_v6: Arc<IpAllocatorV6>,
}

impl ExitRevocationHandle {
    /// Same contract as [`super::ExitListener::close_connections_for`].
    pub async fn close_connections_for(&self, removed: &HashSet<WarrenPubkey>) -> usize {
        close_connections_for_impl(
            &self.active_conns,
            &self.sessions,
            &self.allocator,
            &self.allocator_v6,
            removed,
        )
        .await
    }
}

/// Carries the per-handshake decisions made by [`attribute_session`]
/// while it holds the [`MultiSessionState`] mutex. Replaces the older
/// 4-tuple return so `daita_spec` (multi-conn sharing) can be
/// computed against the same lock as the IP allocation, avoiding a
/// race where a secondary reads a stale (empty) spec between two
/// independent lock acquisitions.
#[derive(Debug, Clone)]
pub(super) struct AttributedSession {
    pub(super) ipv4: Ipv4Addr,
    pub(super) ipv6: Option<Ipv6Addr>,
    pub(super) max_mtu: u16,
    pub(super) attached: bool,
    pub(super) daita_spec: Option<warrenguard_wire::DaitaConfig>,
}

/// Free-function implementation shared by [`super::ExitListener::close_connections_for`]
/// and [`ExitRevocationHandle::close_connections_for`]. Documented on
/// the public method.
pub(super) async fn close_connections_for_impl(
    active_conns: &Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
    sessions: &Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
    allocator: &IpAllocator,
    allocator_v6: &IpAllocatorV6,
    removed: &HashSet<WarrenPubkey>,
) -> usize {
    // Revocation is by `WarrenPubkey`, but the maps are keyed by
    // `(pubkey, device_id)`. Tearing down a revoked account must close
    // EVERY device of that account, so we drain every `(pubkey, *)`
    // entry whose pubkey is in `removed`, not a single exact-key match.
    //
    // Drain entries under the lock to keep the critical section brief;
    // the actual `.close()` calls happen after the lock is dropped.
    let to_close: Vec<quinn::Connection> = {
        let mut map = active_conns.lock();
        let mut drained = Vec::new();
        map.retain(|(pubkey, _device_id), conns| {
            if removed.contains(pubkey) {
                drained.append(conns);
                false
            } else {
                true
            }
        });
        drained
    };
    let n = to_close.len();
    for conn in to_close {
        conn.close(WARREN_AUTH_FAILED, b"subscription revoked");
    }
    if !removed.is_empty() {
        let mut sessions = sessions.lock().await;
        sessions.retain(|key, state| {
            if removed.contains(&key.0) {
                // Recycle the revoked session's tunnel IPs; without
                // this, every revocation would permanently leak one
                // pool address.
                allocator.release(state.ipv4, key);
                if let Some(v6) = state.ipv6 {
                    allocator_v6.release(v6, key);
                }
                false
            } else {
                true
            }
        });
    }
    n
}

/// Removes `conn` from the session's active set and, when it was the
/// LAST live connection of `(pubkey, device_id)`, evicts the session:
/// the entry leaves the map and its tunnel IPs return to the allocators
/// with a sticky hint, so an immediate reconnect of the same device
/// prefers the same addresses while the pool never exhausts under
/// connect/disconnect churn.
///
/// Lock order: `sessions` (async) first, then `active_conns`
/// (parking_lot, never held across an await). `attribute_session`
/// registers the connection under the same `sessions` lock, so a
/// concurrent reconnect can never observe a half-evicted session and
/// keep an address the allocator just recycled.
pub(super) async fn release_connection_and_maybe_session(
    sessions: &Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
    active_conns: &Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
    allocator: &IpAllocator,
    allocator_v6: &IpAllocatorV6,
    persister: &Option<Arc<StatePersister>>,
    key: SessionKey,
    conn: &quinn::Connection,
) {
    let mut map = sessions.lock().await;
    let idle = {
        let mut ac = active_conns.lock();
        match ac.get_mut(&key) {
            Some(conns) => {
                conns.retain(|c| c.stable_id() != conn.stable_id() && c.close_reason().is_none());
                if conns.is_empty() {
                    ac.remove(&key);
                    true
                } else {
                    false
                }
            }
            None => true,
        }
    };
    if !idle {
        return;
    }
    let Some(state) = map.remove(&key) else {
        return;
    };
    allocator.release(state.ipv4, &key);
    if let Some(v6) = state.ipv6 {
        allocator_v6.release(v6, &key);
    }
    tracing::info!(
        client = ?key.0,
        // no-log (INV-3): never log the recycled tunnel IPs.
        "last connection closed - session evicted, tunnel IPs recycled"
    );
    drop(map);
    if let Some(p) = persister.as_ref() {
        p.request_save();
    }
}

/// How long a session may sit without any live connection before the
/// GC tick evicts it. Safety net for crash paths where the pump-end
/// release never ran (task panic, abrupt process-internal teardown);
/// the nominal path is [`release_connection_and_maybe_session`].
pub(super) const SESSION_IDLE_TTL: Duration = Duration::from_secs(120);

/// GC-tick sweep: evicts sessions that have had no live connection for
/// at least `ttl`, recycling their tunnel IPs. `idle_since` carries the
/// first-seen-idle timestamps between ticks and self-cleans. Returns
/// the number of evicted sessions.
///
/// The caller holds the `sessions` lock and the `active_conns` lock
/// (in that order) for the duration of the call.
pub(super) fn sweep_idle_sessions(
    sessions: &mut HashMap<SessionKey, MultiSessionState>,
    active_conns: &HashMap<SessionKey, Vec<quinn::Connection>>,
    idle_since: &mut HashMap<SessionKey, Instant>,
    allocator: &IpAllocator,
    allocator_v6: &IpAllocatorV6,
    now: Instant,
    ttl: Duration,
) -> usize {
    // Drop idle marks for sessions that got a connection back or left
    // the map through the nominal release path.
    idle_since.retain(|key, _| sessions.contains_key(key) && !active_conns.contains_key(key));
    let mut evicted = 0;
    sessions.retain(|key, state| {
        if active_conns.contains_key(key) {
            return true;
        }
        let first_idle = *idle_since.entry(*key).or_insert(now);
        if now.duration_since(first_idle) < ttl {
            return true;
        }
        allocator.release(state.ipv4, key);
        if let Some(v6) = state.ipv6 {
            allocator_v6.release(v6, key);
        }
        idle_since.remove(key);
        evicted += 1;
        false
    });
    evicted
}

/// Multi-conn aggregation logic on the exit side: from the received
/// `Setup` and the remote Ed25519 identity (`remote_id`), decides which
/// IP to allocate (or reuse) and whether the conn attaches correctly to
/// the session.
///
/// Cases handled:
///
/// - **idx=0, total=N** *(primary)*: creates a new entry in the
///   `sessions` map and allocates a fresh IP. If the identity already
///   has an active session (rare: immediate reconnect), we replace it -
///   the previous session was dying client-side anyway.
/// - **idx>0, total=N** *(secondary)*: lookup by identity; if present
///   and `total` matches, return the existing IP. If absent or
///   inconsistent total, return `attached=false` and IP `0.0.0.0` (the
///   client must close this conn and retry).
/// - **idx >= total**: protocol invariant violated (the client should
///   catch this via `Setup::multi_conn`), but defense-in-depth refuses
///   the attachment.
/// - **total > MAX_CONNECTIONS_PER_SESSION**: DoS refusal, a malicious
///   client could otherwise multiply RAM/CPU/fd by 255 (max u8).
///
/// On every `attached = true` outcome the connection is registered in
/// `active_conns` **under the same `sessions` lock** that creates or
/// reuses the session entry. This atomicity is what makes the
/// last-connection eviction in [`release_connection_and_maybe_session`]
/// race-free: an evictor that takes the `sessions` lock either sees the
/// new connection already registered (no eviction) or runs before the
/// attribution (the reconnect then re-allocates, sticky hint first).
/// Unattached connections are never registered - the client closes
/// them, nothing to track or evict.
#[allow(clippy::too_many_arguments)] // handshake plumbing, mirrors handshake_from_incoming
pub(super) async fn attribute_session(
    sessions: &Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
    allocator: &IpAllocator,
    allocator_v6: &IpAllocatorV6,
    persister: &Option<Arc<StatePersister>>,
    active_conns: &Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
    conn: &quinn::Connection,
    remote_id: WarrenPubkey,
    setup: &Setup,
    daita_pool: Option<&DaitaPool>,
) -> warrenguard_transport_core::Result<AttributedSession> {
    let register_conn = || {
        active_conns
            .lock()
            .entry((remote_id, setup.device_id))
            .or_default()
            .push(conn.clone());
    };
    use warrenguard_config::MAX_CONNECTIONS_PER_SESSION;
    use warrenguard_wire::features;

    // v2 device cap: key the session by `(pubkey, device_id)` so a
    // second device of the same account does not collapse onto the
    // first device's session/IP. Multi-conn secondaries of one device
    // carry the same `device_id`, so they still attach to one session.
    let session_key: SessionKey = (remote_id, setup.device_id);

    if setup.connection_index >= setup.total_connections || setup.total_connections == 0 {
        // Invariant violated: refuse the attachment. Throwaway IP.
        return Ok(AttributedSession {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: None,
            max_mtu: DEFAULT_MAX_MTU,
            attached: false,
            daita_spec: None,
        });
    }
    if setup.total_connections > MAX_CONNECTIONS_PER_SESSION {
        tracing::warn!(
            requested = setup.total_connections,
            max = MAX_CONNECTIONS_PER_SESSION,
            "rejecting multi-conn session: total > MAX (DoS guard)"
        );
        return Ok(AttributedSession {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: None,
            max_mtu: DEFAULT_MAX_MTU,
            attached: false,
            daita_spec: None,
        });
    }

    let wants_v6 = (setup.features & features::IPV6) != 0;
    let mut map = sessions.lock().await;

    if setup.connection_index == 0 {
        // Primary: if a session already exists for this `WarrenPubkey`,
        // we **reuse** its IPs instead of allocating new ones.
        //
        // Reuse is *unconditional* on reconnect, regardless of whether
        // `total_connections` has changed. Before this fix, a `total`
        // mismatch triggered an `allocator.next_ipv4()` that didn't
        // free the old IP (`IpAllocator` is a monotonic counter),
        // producing guaranteed exhaustion of the `10.66.0.0/16` pool
        // under churn from clients changing their config.
        if let Some(existing) = map.get(&session_key) {
            let ipv4 = existing.ipv4;
            let ipv6 = existing.ipv6;
            let max_mtu = existing.max_mtu;
            let total_changed = existing.total != setup.total_connections;
            // Primary reconnect inherits the existing DAITA
            // spec verbatim (never re-picks). Otherwise a reconnect
            // storm rotating machines every iteration would dilute
            // the fingerprint defense.
            let daita_spec = select_daita_spec_with_existing(
                setup,
                existing.daita_spec.as_ref(),
                daita_pool,
                &mut rand_v9::rng(),
            );
            register_conn();

            if total_changed {
                tracing::info!(
                    remote_id = ?remote_id,
                    old_total = existing.total,
                    new_total = setup.total_connections,
                    // no-log (INV-3): never log the per-session client
                    // tunnel IPs - they correlate sessions across log lines.
                    ipv6_assigned = ipv6.is_some(),
                    "primary reconnect with new total_connections - reusing IP, updating total"
                );
                let state = MultiSessionState {
                    ipv4,
                    ipv6,
                    max_mtu,
                    total: setup.total_connections,
                    daita_spec: daita_spec.clone(),
                    token_serial: None,
                };
                map.insert(session_key, state);

                drop(map);
                if let Some(p) = persister.as_ref() {
                    p.request_save();
                }
            } else {
                tracing::info!(
                    remote_id = ?remote_id,
                    // no-log (INV-3): never log the per-session client
                    // tunnel IPs - they correlate sessions across log lines.
                    ipv6_assigned = ipv6.is_some(),
                    "primary reconnect: reusing existing session IPs"
                );
            }

            return Ok(AttributedSession {
                ipv4,
                ipv6,
                max_mtu,
                attached: true,
                daita_spec,
            });
        }

        // Fresh primary: allocate from the recycling pool (sticky hint
        // first, so a reconnect after eviction lands on its previous
        // address when still free).
        let ipv4 = allocator.allocate(&session_key)?;
        let ipv6 = if wants_v6 {
            match allocator_v6.allocate(&session_key) {
                Ok(v6) => Some(v6),
                Err(e) => {
                    // Do not leak the v4 address on a partial failure.
                    allocator.release(ipv4, &session_key);
                    return Err(e);
                }
            }
        } else {
            None
        };
        // Fresh primary picks a DAITA spec from the pool and
        // stores it on the session so every secondary inherits the
        // same machines.
        let daita_spec =
            select_daita_spec_with_existing(setup, None, daita_pool, &mut rand_v9::rng());
        let state = MultiSessionState {
            ipv4,
            ipv6,
            max_mtu: DEFAULT_MAX_MTU,
            total: setup.total_connections,
            daita_spec: daita_spec.clone(),
            token_serial: None,
        };
        map.insert(session_key, state);
        register_conn();
        drop(map);

        // Persistence is debounced and runs off-thread: the handshake
        // path never clones the map nor blocks on an fsync (the saver
        // snapshots the live map at write time).
        if let Some(p) = persister.as_ref() {
            p.request_save();
        }

        return Ok(AttributedSession {
            ipv4,
            ipv6,
            max_mtu: DEFAULT_MAX_MTU,
            attached: true,
            daita_spec,
        });
    }

    // Secondary: must find an existing session with the matching `total`.
    // Secondaries inherit the primary's (ipv4, ipv6) couple AND the
    // primary's DAITA spec (cross-connection machine sharing).
    match map.get(&session_key) {
        Some(state) if state.total == setup.total_connections => {
            let daita_spec = select_daita_spec_with_existing(
                setup,
                state.daita_spec.as_ref(),
                daita_pool,
                &mut rand_v9::rng(),
            );
            register_conn();
            Ok(AttributedSession {
                ipv4: state.ipv4,
                ipv6: state.ipv6,
                max_mtu: state.max_mtu,
                attached: true,
                daita_spec,
            })
        }
        _ => Ok(AttributedSession {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: None,
            max_mtu: DEFAULT_MAX_MTU,
            attached: false,
            daita_spec: None,
        }),
    }
}

/// v7 counterpart of [`attribute_session`]: multi-conn aggregation for an
/// anonymous session keyed by `session_pubkey` (the value derived from the
/// attach capability by
/// [`session_key_value`](super::session_token::session_key_value)) plus the
/// per-run `device_id`.
///
/// The shape mirrors [`attribute_session`] but there is no `Setup` and no
/// wallet identity: a PRIMARY (`connection_index == 0`) allocates or reuses an
/// IP and records `serial` on the session so the lease can be renewed by
/// serial; a SECONDARY looks up the session by the same derived key and
/// attaches (inheriting the primary's IP + DAITA spec) only when `total`
/// matches. `serial` is `Some` for a primary and `None` for a secondary.
#[allow(clippy::too_many_arguments)]
pub(super) async fn attribute_session_v7(
    sessions: &Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
    allocator: &IpAllocator,
    allocator_v6: &IpAllocatorV6,
    persister: &Option<Arc<StatePersister>>,
    active_conns: &Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
    conn: &quinn::Connection,
    session_pubkey: WarrenPubkey,
    device_id: [u8; DEVICE_ID_LEN],
    serial: Option<[u8; 32]>,
    connection_index: u8,
    total_connections: u8,
    features: u32,
    daita_support: bool,
    daita_pool: Option<&DaitaPool>,
) -> warrenguard_transport_core::Result<AttributedSession> {
    use super::select_daita_spec_raw;
    use warrenguard_config::MAX_CONNECTIONS_PER_SESSION;
    use warrenguard_wire::features as feat;

    let session_key: SessionKey = (session_pubkey, device_id);
    let register_conn = || {
        active_conns
            .lock()
            .entry(session_key)
            .or_default()
            .push(conn.clone());
    };

    // Invariants are already enforced by `decode_setup_v7`, but keep the
    // defense-in-depth refusals so a hand-crafted call cannot slip through.
    if connection_index >= total_connections || total_connections == 0 {
        return Ok(AttributedSession {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: None,
            max_mtu: DEFAULT_MAX_MTU,
            attached: false,
            daita_spec: None,
        });
    }
    if total_connections > MAX_CONNECTIONS_PER_SESSION {
        tracing::warn!(
            requested = total_connections,
            max = MAX_CONNECTIONS_PER_SESSION,
            "rejecting v7 multi-conn session: total > MAX (DoS guard)"
        );
        return Ok(AttributedSession {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: None,
            max_mtu: DEFAULT_MAX_MTU,
            attached: false,
            daita_spec: None,
        });
    }

    let wants_v6 = (features & feat::IPV6) != 0;
    let mut map = sessions.lock().await;

    if connection_index == 0 {
        // Primary. Reuse an existing session's IPs on reconnect (same derived
        // key = same spent serial re-presented), exactly like v6.
        if let Some(existing) = map.get(&session_key) {
            let ipv4 = existing.ipv4;
            let ipv6 = existing.ipv6;
            let max_mtu = existing.max_mtu;
            let daita_spec = select_daita_spec_raw(
                daita_support,
                connection_index,
                existing.daita_spec.as_ref(),
                daita_pool,
                &mut rand_v9::rng(),
            );
            register_conn();
            return Ok(AttributedSession {
                ipv4,
                ipv6,
                max_mtu,
                attached: true,
                daita_spec,
            });
        }

        let ipv4 = allocator.allocate(&session_key)?;
        let ipv6 = if wants_v6 {
            match allocator_v6.allocate(&session_key) {
                Ok(v6) => Some(v6),
                Err(e) => {
                    allocator.release(ipv4, &session_key);
                    return Err(e);
                }
            }
        } else {
            None
        };
        let daita_spec =
            select_daita_spec_raw(daita_support, 0, None, daita_pool, &mut rand_v9::rng());
        let state = MultiSessionState {
            ipv4,
            ipv6,
            max_mtu: DEFAULT_MAX_MTU,
            total: total_connections,
            daita_spec: daita_spec.clone(),
            token_serial: serial,
        };
        map.insert(session_key, state);
        register_conn();
        drop(map);
        if let Some(p) = persister.as_ref() {
            p.request_save();
        }
        return Ok(AttributedSession {
            ipv4,
            ipv6,
            max_mtu: DEFAULT_MAX_MTU,
            attached: true,
            daita_spec,
        });
    }

    // Secondary: attach only to a matching primary session.
    match map.get(&session_key) {
        Some(state) if state.total == total_connections => {
            let daita_spec = select_daita_spec_raw(
                daita_support,
                connection_index,
                state.daita_spec.as_ref(),
                daita_pool,
                &mut rand_v9::rng(),
            );
            register_conn();
            Ok(AttributedSession {
                ipv4: state.ipv4,
                ipv6: state.ipv6,
                max_mtu: state.max_mtu,
                attached: true,
                daita_spec,
            })
        }
        _ => Ok(AttributedSession {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: None,
            max_mtu: DEFAULT_MAX_MTU,
            attached: false,
            daita_spec: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skey(pk: u8, dev: u8) -> SessionKey {
        (WarrenPubkey::from_bytes([pk; 32]), [dev; DEVICE_ID_LEN])
    }

    #[test]
    fn ipv4_source_of_extracts_the_v4_peer_address() {
        use std::net::SocketAddr;
        let addr: SocketAddr = "203.0.113.9:51234".parse().unwrap();
        assert_eq!(
            super::ipv4_source_of(addr),
            Some(Ipv4Addr::new(203, 0, 113, 9)),
            "a v4 QUIC peer must yield its v4 source for the Port Fail guard set"
        );
    }

    #[test]
    fn ipv4_source_of_unmaps_a_v4_mapped_v6_peer() {
        use std::net::SocketAddr;
        // A dual-stack socket sees a v4 client as ::ffff:a.b.c.d; the guard
        // set is v4, so we must recover the embedded v4 address.
        let addr: SocketAddr = "[::ffff:198.51.100.7]:443".parse().unwrap();
        assert_eq!(
            super::ipv4_source_of(addr),
            Some(Ipv4Addr::new(198, 51, 100, 7)),
            "a v4-mapped-v6 peer must be unmapped to its v4 source"
        );
    }

    #[test]
    fn ipv4_source_of_skips_a_genuine_v6_peer() {
        use std::net::SocketAddr;
        // A native v6 client has no v4 source; the v4-only guard cannot cover
        // it (documented limitation), so the helper returns None rather than
        // fabricate an address.
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(super::ipv4_source_of(addr), None);
    }

    fn state_for(ipv4: Ipv4Addr, ipv6: Option<Ipv6Addr>) -> MultiSessionState {
        MultiSessionState {
            ipv4,
            ipv6,
            max_mtu: 1350,
            total: 1,
            daita_spec: None,
            token_serial: None,
        }
    }

    #[test]
    fn sweep_evicts_connless_session_only_after_ttl_and_recycles_its_ips() {
        // Crash-path net: a session whose pump-end release never ran
        // (task panic) sits with no live connection. The first sweep
        // must only MARK it idle (grace period: a handshake may be
        // mid-flight); a sweep past the TTL must evict it and return
        // the IPs to the allocators.
        let allocator = IpAllocator::with_capacity(2);
        let allocator_v6 = IpAllocatorV6::new();
        let key = skey(1, 1);
        let ipv4 = allocator.allocate(&key).expect("capacity 2");
        let ipv6 = allocator_v6.allocate(&key).expect("v6 mint");

        let mut sessions = HashMap::new();
        sessions.insert(key, state_for(ipv4, Some(ipv6)));
        let active_conns: HashMap<SessionKey, Vec<quinn::Connection>> = HashMap::new();
        let mut idle_since = HashMap::new();

        let t0 = Instant::now();
        let ttl = Duration::from_secs(120);
        let evicted = sweep_idle_sessions(
            &mut sessions,
            &active_conns,
            &mut idle_since,
            &allocator,
            &allocator_v6,
            t0,
            ttl,
        );
        assert_eq!(evicted, 0, "first idle sighting must not evict (grace)");
        assert!(
            sessions.contains_key(&key),
            "session survives the grace tick"
        );

        let evicted = sweep_idle_sessions(
            &mut sessions,
            &active_conns,
            &mut idle_since,
            &allocator,
            &allocator_v6,
            t0 + ttl,
            ttl,
        );
        assert_eq!(evicted, 1, "past the TTL the conn-less session is evicted");
        assert!(sessions.is_empty());
        assert!(idle_since.is_empty(), "idle marks must self-clean");

        // The recycled IPv4 must be allocatable again (and sticky to
        // the evicted key first).
        let again = allocator.allocate(&key).expect("recycled slot");
        assert_eq!(
            again, ipv4,
            "evicted session's IP must be recycled with a sticky hint"
        );
    }

    #[test]
    fn sweep_resets_idle_mark_when_a_connection_comes_back() {
        // A session marked idle at tick N whose device reconnects
        // before N+TTL must NOT be evicted later on the stale mark.
        let allocator = IpAllocator::with_capacity(2);
        let allocator_v6 = IpAllocatorV6::new();
        let key = skey(2, 2);
        let ipv4 = allocator.allocate(&key).expect("capacity 2");

        let mut sessions = HashMap::new();
        sessions.insert(key, state_for(ipv4, None));
        let mut idle_since = HashMap::new();

        let t0 = Instant::now();
        let ttl = Duration::from_secs(120);
        let no_conns: HashMap<SessionKey, Vec<quinn::Connection>> = HashMap::new();
        sweep_idle_sessions(
            &mut sessions,
            &no_conns,
            &mut idle_since,
            &allocator,
            &allocator_v6,
            t0,
            ttl,
        );
        assert!(idle_since.contains_key(&key), "idle mark recorded");

        // The device reconnected: active_conns has an entry again
        // (vec content does not matter for the sweep, presence does).
        let mut with_conns: HashMap<SessionKey, Vec<quinn::Connection>> = HashMap::new();
        with_conns.insert(key, Vec::new());
        let evicted = sweep_idle_sessions(
            &mut sessions,
            &with_conns,
            &mut idle_since,
            &allocator,
            &allocator_v6,
            t0 + ttl + Duration::from_secs(1),
            ttl,
        );
        assert_eq!(evicted, 0, "session with live conns must never be evicted");
        assert!(
            !idle_since.contains_key(&key),
            "stale idle mark must be dropped once a connection is back"
        );
    }
}
