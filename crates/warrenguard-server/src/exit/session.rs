//! Session management types for the exit side: multi-conn state, the read-only
//! session handles (sessions map, peer sources, revocation), and the shared
//! revocation teardown.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::Mutex as AsyncMutex;
use warrenguard_wire::{DEVICE_ID_LEN, WarrenPubkey};

use warrenguard_transport_core::constants::WARREN_AUTH_FAILED;

/// Session map key (v2 device cap): the wallet pubkey **plus** the
/// per-run `device_id`. Re-keying by `(pubkey, device_id)` means that
/// multi-conn connections of ONE device (same id) still collapse onto a
/// single session/IP, while DISTINCT devices of the same account (same
/// pubkey, different id) get DISTINCT sessions and DISTINCT tunnel IPs
/// instead of colliding on one IP.
pub(crate) type SessionKey = (WarrenPubkey, [u8; DEVICE_ID_LEN]);

/// Per-identity session state the exit's read-only handles expose: the tunnel
/// IPv4 assigned to a `(pubkey, device_id)` and the Privacy Pass token serial it
/// was opened with. Keyed in the exit's `HashMap<SessionKey, MultiSessionState>`.
#[derive(Debug, Clone)]
pub(crate) struct MultiSessionState {
    /// Tunnel IPv4 assigned to this session.
    pub(crate) ipv4: Ipv4Addr,
    /// The Privacy Pass token serial the session was opened with, if any. `Some`
    /// for an anonymous (token) session (its lease is re-asserted by serial),
    /// `None` otherwise. Never persisted: a token session is a RAM-only bearer
    /// credential, recovered by a re-handshake after an exit restart.
    pub(crate) token_serial: Option<[u8; 32]>,
}

/// Cloneable read-only view over the exit's live session map. Other components
/// (notably an exit binary's NAT-PMP -> API sync push) need to know which client
/// pubkey currently owns each tunnel-pool IPv4, without taking the same async
/// mutex as the handshake hot path. The `snapshot_*` accessors take the lock for
/// the duration of one O(N) copy and release it immediately.
#[derive(Clone)]
pub struct ExitSessionsHandle {
    pub(super) sessions: Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
}

impl ExitSessionsHandle {
    /// Build a handle from explicit pairs, for use in tests that
    /// need a populated map without spawning a real exit + tunnel.
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

/// Cheap, clonable handle that lets a task running independently of the exit's
/// accept loop tear down connections whose pubkey was revoked.
///
/// Holds clones of the internal `Arc`s; dropping the handle does not affect the
/// exit itself.
#[derive(Clone)]
pub struct ExitRevocationHandle {
    pub(super) active_conns: Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
    pub(super) sessions: Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
}

impl ExitRevocationHandle {
    /// Closes every live connection whose account pubkey is in `removed` and
    /// drops the revoked sessions from the session map. Returns the number of
    /// connections closed.
    pub async fn close_connections_for(&self, removed: &HashSet<WarrenPubkey>) -> usize {
        close_connections_for_impl(&self.active_conns, &self.sessions, removed).await
    }
}

/// Free-function implementation behind [`ExitRevocationHandle::close_connections_for`].
/// Documented on the public method.
pub(super) async fn close_connections_for_impl(
    active_conns: &Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
    sessions: &Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
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
        sessions.retain(|key, _state| !removed.contains(&key.0));
    }
    n
}
