//! Dynamic allowlist handle for the exit-side handshake gate.
//!
//! Wraps a `HashSet<WarrenPubkey>` in a `RwLock` so the exit's admission set can
//! be refreshed by a polling task without restarting the exit.
//!
//! Security invariants enforced here:
//!
//! - **Cold-start fail-closed**: a fresh [`AllowlistHandle::new`]
//!   admits no pubkey. Until `apply_snapshot` or `apply_delta` lands
//!   a populated snapshot, every handshake is refused. The exit
//!   binary boots an empty handle deliberately: if the control-plane API is
//!   unreachable AND the on-disk cache is missing, we MUST NOT
//!   regress to "allow all".
//! - **Generation gate**: snapshots arrive over a network that may
//!   reorder retries. We accept a snapshot only if its `generation`
//!   is strictly greater than the last applied one (or the very
//!   first snapshot). An out-of-order older snapshot is dropped
//!   silently.
//! - **Revocation diff**: a transition `(old \ new)` is broadcast
//!   over the constructor-paired `mpsc::UnboundedSender` so the
//!   listener can tear down live sessions whose pubkey just lost its
//!   subscription. Pure-addition snapshots do NOT emit on the
//!   channel; that lets the listener keep its `recv().await` quiet
//!   on the no-revocation path. The channel is deliberately
//!   unbounded: entries are removed from `entries` (this handle's own
//!   admission state) *before* the corresponding batch is queued, so
//!   a bounded channel that fills up would silently drop a teardown
//!   notification while the map already refuses the pubkey - the
//!   revoked session would then keep tunneling until the listener's
//!   next, unrelated wake-up. Unbounded memory growth in practice
//!   tracks the allowlist's own churn (each pubkey is queued for
//!   teardown at most once per revocation, and a healthy listener
//!   drains the channel promptly); it grows without bound only if the
//!   listener task itself is stuck, which is already a standalone
//!   failure (no live session is being torn down at all) independent
//!   of this channel's capacity.
//! - **Per-entry TTL**: each entry carries an `expires_at`
//!   (unix secs) honoured by [`AllowlistHandle::is_allowed_at`] so a
//!   fail-open exit (backend silent) still refuses a pubkey whose
//!   subscription has lapsed. Legacy wire payloads without per-entry
//!   expiry use `u64::MAX` (no local TTL).
//! - **Fail-open last-known**: when the control-plane API becomes
//!   unreachable, the handle keeps serving the last-known allowlist
//!   indefinitely  -  per-entry TTL + the CRL handle the bounded
//!   fraud window. The legacy `clear_if_stale` method survives for
//!   tests but is no longer called by the refresh loop.
//! - **CRL precedence**: pubkeys in the
//!   [`AllowlistHandle::apply_crl_revocations`] set are refused at
//!   the gate even when the allowlist still admits them, so urgent
//!   revocations propagate even during a control-plane outage.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use tokio::sync::mpsc;
use warrenguard_wire::WarrenPubkey;

/// One snapshot of the active-subscribers list received from
/// the control-plane API. Carries the bookkeeping needed to drive the
/// generation gate and the staleness fallback.
#[derive(Debug, Clone)]
pub struct AllowlistSnapshot {
    /// Server-side monotonic counter (`SubscriptionStore::generation`).
    pub generation: u64,
    /// Pubkeys allowed to handshake mapped to their `expires_at`
    /// (unix secs). The expiry is enforced locally by
    /// [`AllowlistHandle::is_allowed_at`]: a fail-open
    /// exit still refuses a pubkey whose subscription has lapsed
    /// even when the backend is unreachable. Wire payloads that
    /// pre-date the per-entry expiry contract use `u64::MAX` (no
    /// local TTL  -  trust the server's `expires_at > now` filter at
    /// fetch time); cf. [`AllowlistSnapshot::from_legacy_set`].
    pub pubkeys: HashMap<WarrenPubkey, u64>,
    /// Local time when this snapshot was successfully fetched. Drives
    /// the staleness fallback in [`AllowlistHandle::clear_if_stale`].
    pub fetched_at_unix_secs: u64,
}

impl AllowlistSnapshot {
    /// Build a snapshot from a bare set of pubkeys (legacy wire
    /// payload without per-entry expiry). Every entry is tagged with
    /// `u64::MAX`, which disables the local TTL check  -  the
    /// server's `expires_at > now` filter at fetch time is the only
    /// freshness guarantee in this mode. The delta-polling path
    /// carries real expiries instead.
    #[must_use]
    pub fn from_legacy_set(
        generation: u64,
        pubkeys: HashSet<WarrenPubkey>,
        fetched_at_unix_secs: u64,
    ) -> Self {
        Self {
            generation,
            pubkeys: pubkeys.into_iter().map(|pk| (pk, u64::MAX)).collect(),
            fetched_at_unix_secs,
        }
    }
}

/// Shared, thread-safe handle to the current exit allowlist. Cheap to
/// clone (single `Arc`); each clone reads the same state.
#[derive(Clone)]
pub struct AllowlistHandle {
    inner: Arc<Inner>,
}

struct Inner {
    /// Current allowed pubkeys mapped to their `expires_at` (unix
    /// secs). `RwLock` because reads (the per-handshake gate)
    /// dominate writes (one apply per polling tick). The `u64::MAX`
    /// value disables the local TTL check for entries that arrived
    /// via a legacy wire payload (no per-entry expiry).
    entries: RwLock<HashMap<WarrenPubkey, u64>>,
    /// Last applied `generation`. Read on every `apply_snapshot` to
    /// drop stale retries; `AtomicU64` avoids reaching into `set`'s
    /// lock just to test the gate.
    last_generation: AtomicU64,
    /// Local unix timestamp of the last successful poll, regardless
    /// of whether the payload was applied or dropped by the
    /// generation gate. Tracks control-plane reachability, not
    /// mutation lineage: the legacy `clear_if_stale` (no longer
    /// called by the refresh loop but still exposed for
    /// tests) reads this to decide whether the backend has gone
    /// dark. `0` means "never polled yet"; the fallback explicitly
    /// short-circuits on that value to avoid clearing an already
    /// empty boot-time handle. Updates use `fetch_max` so an
    /// out-of-order retry whose `fetched_at` is older than the
    /// freshest poll cannot regress the clock.
    last_success_unix_secs: AtomicU64,
    /// Broadcaster for revocation diffs. Always present  -  the
    /// constructor [`AllowlistHandle::new`] pairs the handle with a
    /// receiver in a single tuple so a caller cannot accidentally
    /// build a handle without wiring teardown. If the listener is
    /// uninterested (test fixture, single-tenant POC), it can drop
    /// the receiver; the sender then logs and skips, never panics.
    /// Unbounded on purpose: see the module doc's "Revocation diff"
    /// entry for why a bounded channel would silently fail open.
    revocation_tx: mpsc::UnboundedSender<HashSet<WarrenPubkey>>,
    /// Pubkeys explicitly revoked by an admin-signed CRL.
    /// Checked BEFORE the entries lookup in `is_allowed*` so a CRL
    /// entry blocks even when the allowlist still admits the pubkey
    /// (e.g. fail-open last-known where the backend has not yet
    /// pushed the corresponding allowlist removal).
    crl_revocations: RwLock<HashSet<WarrenPubkey>>,
}

impl AllowlistHandle {
    /// Build an empty, fail-closed handle paired with the receiver
    /// side of its revocation channel. No pubkey is admitted until a
    /// snapshot is applied; once one is, the diff `(old \ new)` is
    /// broadcast on the receiver on every subsequent retiring snapshot
    /// (see [`AllowlistHandle::apply_snapshot`]).
    ///
    /// The tuple return is intentional: making the receiver inseparable
    /// from construction forces every caller to make an explicit
    /// decision about live-session teardown. A previous "optional
    /// channel" API silently dropped revocations when the caller forgot
    /// to wire the channel; the tuple shape removes that footgun at
    /// compile time. Callers who genuinely do not need teardown
    /// (unit tests, dev permissive mode) write `let (handle, _rx) =
    /// AllowlistHandle::new();` and the unused `_rx` documents intent.
    #[must_use]
    pub fn new() -> (Self, mpsc::UnboundedReceiver<HashSet<WarrenPubkey>>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = Self {
            inner: Arc::new(Inner {
                entries: RwLock::new(HashMap::new()),
                last_generation: AtomicU64::new(0),
                last_success_unix_secs: AtomicU64::new(0),
                revocation_tx: tx,
                crl_revocations: RwLock::new(HashSet::new()),
            }),
        };
        (handle, rx)
    }

    /// Builds a handle pre-seeded with a fixed, never-expiring roster.
    ///
    /// This is the static-allowlist admission a generic WarrenGuard deployer
    /// wants: a closed set of peer pubkeys, no subscription backend, no TTL, no
    /// live revocation. It admits exactly `keys` and refuses everything else,
    /// driving the same trait-based gate the multi-tenant path uses (so the
    /// engine has one admission code path, not two). The revocation receiver is
    /// dropped on purpose: a static roster never retires a key, so there is no
    /// teardown stream to consume.
    ///
    /// For the subscription-driven, revocable Warren path use [`Self::new`]
    /// plus [`Self::apply_snapshot`] instead.
    #[must_use]
    pub fn from_static_keys(keys: impl IntoIterator<Item = WarrenPubkey>) -> Self {
        let (handle, _rx) = Self::new();
        let set: HashSet<WarrenPubkey> = keys.into_iter().collect();
        // generation 1 (> the initial 0) so the seed passes the gate;
        // `from_legacy_set` tags each entry `u64::MAX` = no local TTL.
        handle.apply_snapshot(AllowlistSnapshot::from_legacy_set(
            1,
            set,
            warrenguard_config::unix_now(),
        ));
        handle
    }

    /// Replace the CRL revocations set. Any pubkey in this set is
    /// refused at the gate regardless of its presence in the
    /// allowlist. Called by the exit-side CRL poller after it has
    /// validated the admin Ed25519 signature on the wire payload.
    /// Returns the count of newly-revoked pubkeys that were also in
    /// the allowlist (= live sessions that the listener should now
    /// tear down).
    pub fn apply_crl_revocations(&self, revocations: HashSet<WarrenPubkey>) -> usize {
        let to_tear_down: HashSet<WarrenPubkey> = {
            let entries = self.inner.entries.read();
            revocations
                .iter()
                .filter(|pk| entries.contains_key(pk))
                .copied()
                .collect()
        };
        *self.inner.crl_revocations.write() = revocations;
        let n = to_tear_down.len();
        if n > 0
            && let Err(e) = self.inner.revocation_tx.send(to_tear_down)
        {
            // Unbounded channel: this only fails when the receiver was
            // dropped (clean shutdown, or a test that ignored `_rx`).
            tracing::warn!(
                dropped = e.0.len(),
                "CRL revocation channel closed; pubkeys not signalled"
            );
        }
        n
    }

    /// Return `true` if `id` is currently allowed by presence alone.
    /// Does NOT honour the per-entry `expires_at`  -  use
    /// [`AllowlistHandle::is_allowed_at`] when local TTL enforcement
    /// matters (fail-open path).
    ///
    /// Kept for back-compat with callers that observed the older
    /// contract ("server already filtered expired entries"). New
    /// production callers should prefer `is_allowed_at`.
    #[must_use]
    pub fn is_allowed(&self, id: &WarrenPubkey) -> bool {
        if self.inner.crl_revocations.read().contains(id) {
            return false;
        }
        self.inner.entries.read().contains_key(id)
    }

    /// Return `true` if `id` is currently allowed AND its
    /// `expires_at > now_unix_secs`. This is the authoritative gate
    /// for production handshakes: it lets a
    /// fail-open exit (backend unreachable, last-known allowlist
    /// still cached) refuse a pubkey whose subscription has lapsed
    /// without re-checking the backend.
    ///
    /// Entries that arrived via the legacy full-snapshot wire (no
    /// per-entry expiry) are stored with `u64::MAX` and therefore
    /// always pass the check  -  the server's `expires_at > now`
    /// filter at fetch time is the only freshness guarantee in that
    /// mode. Use the delta polling path to obtain real per-entry
    /// expiries.
    #[must_use]
    pub fn is_allowed_at(&self, id: &WarrenPubkey, now_unix_secs: u64) -> bool {
        if self.inner.crl_revocations.read().contains(id) {
            return false;
        }
        self.inner
            .entries
            .read()
            .get(id)
            .is_some_and(|expires_at| *expires_at > now_unix_secs)
    }

    /// Snapshot the current state into a new [`AllowlistSnapshot`].
    /// Used by the refresh loop after `apply_delta` so the on-disk
    /// cache can be re-written without having to re-fetch a full
    /// payload from the control-plane API.
    #[must_use]
    pub fn current_snapshot(&self, fetched_at_unix_secs: u64) -> AllowlistSnapshot {
        let entries = self.inner.entries.read().clone();
        AllowlistSnapshot {
            generation: self.last_generation(),
            pubkeys: entries,
            fetched_at_unix_secs,
        }
    }

    /// Last applied server `generation`. `0` until the first snapshot
    /// is applied.
    #[must_use]
    pub fn last_generation(&self) -> u64 {
        self.inner.last_generation.load(Ordering::Acquire)
    }

    /// Last successful poll time (unix secs), regardless of whether
    /// the payload was applied or dropped as a no-op. `0` if no
    /// snapshot has been polled yet. See `apply_snapshot` for the
    /// reachability ack contract.
    #[must_use]
    pub fn last_success_unix_secs(&self) -> u64 {
        self.inner.last_success_unix_secs.load(Ordering::Acquire)
    }

    /// Resolve once the FIRST successful allowlist poll has landed, or
    /// after `timeout`, whichever comes first. Returns `true` if a sync
    /// has happened (the gate can now be trusted), `false` on timeout.
    ///
    /// This is the cold-start grace for the gate: right after a process
    /// restart (deploy/update) or a fresh/immutable deploy with no disk
    /// cache, the in-memory allowlist is empty until the refresh loop's
    /// first poll completes. Evaluating the gate in that window would
    /// reject every legitimate client (`not-allowlisted`) for a few
    /// seconds and trigger client reconnect churn. A setup handler can
    /// instead `wait_for_first_sync` to hold briefly until the allowlist
    /// is populated, then evaluate the gate normally. Once synced this
    /// returns immediately forever after (`last_success` never regresses
    /// to 0), so steady-state handshakes pay nothing.
    ///
    /// Implemented as a cheap poll (the window is rare and bounded, and a
    /// poll naturally serves many concurrent waiters without the
    /// missed-notification hazards of a single shared `Notify`).
    pub async fn wait_for_first_sync(&self, timeout: std::time::Duration) -> bool {
        if self.last_success_unix_secs() != 0 {
            return true;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if self.last_success_unix_secs() != 0 {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
        }
    }

    /// Number of currently allowed pubkeys. Convenience getter used
    /// by tests + tracing.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.entries.read().len()
    }

    /// `true` when no pubkey is admitted right now.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.entries.read().is_empty()
    }

    /// Land a snapshot. Returns the number of pubkeys retired
    /// (`old \ new`).
    ///
    /// Behavior matrix (payload, i.e. the set + `last_generation`):
    /// - `snapshot.generation <= self.last_generation()` AND
    ///   `last_generation > 0` → payload ignored. Returns 0. Defends
    ///   against out-of-order retries and steady-state polls (server
    ///   has not mutated since last apply).
    /// - First-ever snapshot (`last_success_unix_secs == 0`) → applied,
    ///   no revocation emitted (everything is an addition).
    /// - Strictly newer snapshot → applied, revocation diff
    ///   `(old \ new)` is broadcast on `revocation_tx` when non-empty.
    ///
    /// Reachability ack (`last_success_unix_secs`): updated on EVERY
    /// call via `fetch_max` regardless of the generation gate. A
    /// successful poll proves the control-plane API answered, so the staleness
    /// clock advances even when the payload is a no-op duplicate. This
    /// is what stops `clear_if_stale` from fail-closing a healthy exit
    /// whose backend never mutates between polls.
    /// Apply an incremental delta from the delta-polling endpoint.
    /// `added` are inserted (or overwritten with the new `expires_at`)
    /// and `removed` are retired; the diff `removed` is broadcast on
    /// the revocation channel so the listener tears down live
    /// sessions for revoked pubkeys.
    ///
    /// `to_generation` is the new known server generation (the
    /// `to_generation` field of `SubscribersDeltaResponse`) and is
    /// installed atomically with the entries swap so a concurrent
    /// `is_allowed*` reader either sees the new state and the new
    /// generation, or neither.
    ///
    /// Returns the number of pubkeys actually retired (may be less
    /// than `removed.len()` if some keys were already absent locally,
    /// which is harmless and expected after a stale snapshot reset).
    ///
    /// Reachability ack: `fetched_at_unix_secs` advances
    /// `last_success_unix_secs` via `fetch_max` so the staleness
    /// fallback knows the backend answered. This matches
    /// [`AllowlistHandle::apply_snapshot`] semantics.
    ///
    /// Out-of-order safety: if `to_generation <= last_generation` AND
    /// a previous apply has already happened (`last_success != 0`),
    /// the delta is dropped silently (caller's view of the world is
    /// older than ours). The reachability ack still advances.
    pub fn apply_delta(
        &self,
        added: Vec<(WarrenPubkey, u64)>,
        removed: Vec<WarrenPubkey>,
        to_generation: u64,
        fetched_at_unix_secs: u64,
    ) -> usize {
        let prev_generation = self.inner.last_generation.load(Ordering::Acquire);
        let first_apply = self.inner.last_success_unix_secs.load(Ordering::Acquire) == 0;
        self.inner
            .last_success_unix_secs
            .fetch_max(fetched_at_unix_secs, Ordering::AcqRel);
        if !first_apply && to_generation <= prev_generation {
            return 0;
        }

        let mut guard = self.inner.entries.write();
        for (pk, expires_at) in added {
            guard.insert(pk, expires_at);
        }
        let mut actually_removed: HashSet<WarrenPubkey> = HashSet::new();
        for pk in removed {
            if guard.remove(&pk).is_some() {
                actually_removed.insert(pk);
            }
        }
        drop(guard);

        self.inner
            .last_generation
            .store(to_generation, Ordering::Release);

        let removed_count = actually_removed.len();
        if removed_count > 0
            && let Err(e) = self.inner.revocation_tx.send(actually_removed)
        {
            // Unbounded channel: this only fails when the receiver was
            // dropped (clean shutdown, or a test that ignored `_rx`).
            tracing::warn!(
                dropped = e.0.len(),
                "revocation channel closed; pubkeys not signalled"
            );
        }
        removed_count
    }

    /// Replace the live allowlist with the supplied full snapshot.
    ///
    /// Returns the number of entries removed (i.e. present in the
    /// previous state but absent from `snapshot`). New entries are
    /// inserted as a side effect. The generation in `snapshot` is
    /// honoured: a snapshot with a `generation` strictly lower than
    /// the currently-applied one is silently ignored (out-of-order
    /// retry), except on the very first apply (`last_success_unix_secs
    /// == 0`) where any generation value is accepted to bootstrap.
    ///
    /// Also bumps `last_success_unix_secs` to mark the control-plane
    /// reachability ack, even on a no-op apply.
    pub fn apply_snapshot(&self, snapshot: AllowlistSnapshot) -> usize {
        let prev_generation = self.inner.last_generation.load(Ordering::Acquire);
        // Capture first-apply BEFORE the reachability ack below, so the
        // very first poll still passes the generation gate even when
        // the server legitimately reports `generation == 0`. We tell
        // "first-ever" from "out-of-order retry" by inspecting
        // `last_success_unix_secs`, which only becomes non-zero on a
        // successful poll.
        let first_apply = self.inner.last_success_unix_secs.load(Ordering::Acquire) == 0;

        // Ack control-plane reachability up front, before the generation
        // gate may early-return. Any successful fetch that produced a
        // snapshot proves the backend answered, so the staleness clock
        // must advance even when the payload is a no-op (steady-state
        // polls with no server mutations). `fetch_max` guards against
        // an out-of-order retry whose `fetched_at` is older than the
        // freshest poll: that case must not regress the reachability
        // timestamp.
        self.inner
            .last_success_unix_secs
            .fetch_max(snapshot.fetched_at_unix_secs, Ordering::AcqRel);

        if !first_apply && snapshot.generation <= prev_generation {
            return 0;
        }

        // Compute the diff under the write lock to make the swap +
        // notification atomic w.r.t. concurrent `is_allowed` readers.
        let mut guard = self.inner.entries.write();
        let new_keys: HashSet<WarrenPubkey> = snapshot.pubkeys.keys().copied().collect();
        let removed: HashSet<WarrenPubkey> = guard
            .keys()
            .copied()
            .filter(|pk| !new_keys.contains(pk))
            .collect();
        *guard = snapshot.pubkeys;
        drop(guard);

        // Bump the generation AFTER the set is updated. Order matters
        // under `is_allowed` racing with `apply_snapshot`: a reader
        // that observes the new generation MUST also observe the new
        // set (Release on the atomic chains with the implicit RwLock
        // release). The reachability ack was bumped above; no need to
        // re-store it here.
        self.inner
            .last_generation
            .store(snapshot.generation, Ordering::Release);

        let removed_count = removed.len();
        if removed_count > 0 {
            // `send` on `UnboundedSender` only fails if the
            // receiver is gone. That happens during clean shutdown
            // or in a test that dropped its `_rx`; a revocation lost
            // to a closed channel cannot be recovered, but in
            // shutdown the listener is tearing down anyway, and in
            // tests the absence of a receiver is intentional. Log +
            // carry on.
            if let Err(e) = self.inner.revocation_tx.send(removed) {
                tracing::warn!(
                    dropped = e.0.len(),
                    "revocation channel closed; pubkeys not signalled"
                );
            }
        }
        removed_count
    }

    /// Legacy fail-closed staleness sweep. If the last successful
    /// poll was older than `grace_secs` before `now_unix_secs`,
    /// clear the allowlist and broadcast the cleared set on the
    /// revocation channel so the listener tears down live sessions.
    ///
    /// **Not called by the refresh loop**: production
    /// honours the fail-open last-known contract (extended outage
    /// preserves the allowlist; per-entry TTL + the CRL handle the
    /// bounded fraud window). This method survives for tests and
    /// for callers that explicitly opt back into the legacy
    /// behaviour.
    ///
    /// "Successful poll" here means any `apply_snapshot` /
    /// `apply_delta` call that produced a snapshot, including
    /// duplicate-generation no-ops, see the `apply_snapshot` doc for
    /// the reachability ack contract.
    ///
    /// Returns the number of pubkeys evicted (`0` if the handle was
    /// already empty, or if the snapshot is still fresh, or if
    /// `last_success_unix_secs == 0` = never applied; there is
    /// nothing to stale-clear in that case, the handle is already
    /// cold-start fail-closed on its own).
    #[must_use = "clear_if_stale returns the count of evicted pubkeys; ignoring it loses observability for the staleness sweep"]
    pub fn clear_if_stale(&self, now_unix_secs: u64, grace_secs: u64) -> usize {
        let last = self.inner.last_success_unix_secs.load(Ordering::Acquire);
        if last == 0 {
            return 0;
        }
        let age = now_unix_secs.saturating_sub(last);
        if age <= grace_secs {
            return 0;
        }

        let mut guard = self.inner.entries.write();
        if guard.is_empty() {
            return 0;
        }
        let evicted: HashSet<WarrenPubkey> = std::mem::take(&mut *guard).into_keys().collect();
        drop(guard);

        let n = evicted.len();
        // Best-effort: a closed receiver means the listener is gone
        // (shutdown) or never subscribed (test); either way no live
        // session needs tearing down on our side. Ignore.
        let _ = self.inner.revocation_tx.send(evicted);
        n
    }
}

impl std::fmt::Debug for AllowlistHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Warren no-log: the pubkey set IS user-identifying. Only
        // surface counts + generation.
        f.debug_struct("AllowlistHandle")
            .field("len", &self.len())
            .field("last_generation", &self.last_generation())
            .field("last_success_unix_secs", &self.last_success_unix_secs())
            .finish()
    }
}

impl crate::authorizer::Authorizer for AllowlistHandle {
    fn is_allowed(&self, remote_id: &WarrenPubkey, now_unix_secs: u64) -> bool {
        self.is_allowed_at(remote_id, now_unix_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WarrenPubkey is a byte-only newtype (no curve validation), so
    /// we can fabricate one straight from a seed: the allowlist only
    /// hashes them.
    fn pk(seed: u8) -> WarrenPubkey {
        WarrenPubkey::from_bytes([seed; 32])
    }

    fn set_of(seeds: &[u8]) -> HashSet<WarrenPubkey> {
        seeds.iter().copied().map(pk).collect()
    }

    fn snapshot(generation: u64, seeds: &[u8], fetched_at: u64) -> AllowlistSnapshot {
        AllowlistSnapshot::from_legacy_set(generation, set_of(seeds), fetched_at)
    }

    fn collect_revocations(
        rx: &mut mpsc::UnboundedReceiver<HashSet<WarrenPubkey>>,
    ) -> Vec<HashSet<WarrenPubkey>> {
        let mut out = Vec::new();
        while let Ok(v) = rx.try_recv() {
            out.push(v);
        }
        out
    }

    // ----- Static roster (generic deployer) -----

    #[test]
    fn from_static_keys_admits_listed_refuses_unlisted_and_never_expires() {
        use crate::authorizer::Authorizer;
        let handle = AllowlistHandle::from_static_keys([pk(1), pk(2)]);

        // Listed keys are admitted, an unlisted one is refused.
        assert!(handle.is_allowed_at(&pk(1), 1_000), "listed key admitted");
        assert!(handle.is_allowed_at(&pk(2), 1_000), "listed key admitted");
        assert!(
            !handle.is_allowed_at(&pk(3), 1_000),
            "unlisted key must be refused (closed roster)"
        );

        // No local TTL: still admitted arbitrarily far in the future.
        assert!(
            handle.is_allowed_at(&pk(1), u64::MAX - 1),
            "static roster entry must never expire locally"
        );

        // The same decision flows through the `Authorizer` trait the accept
        // loop uses, so the CLI path and the prod path share one gate.
        assert!(Authorizer::is_allowed(&handle, &pk(1), 1_000));
        assert!(!Authorizer::is_allowed(&handle, &pk(9), 1_000));
    }

    #[test]
    fn from_static_keys_empty_roster_is_deny_all() {
        let handle = AllowlistHandle::from_static_keys([]);
        assert!(
            !handle.is_allowed_at(&pk(1), 1_000),
            "an empty static roster must admit nobody"
        );
    }

    // ----- Fail-closed bootstrap -----

    #[test]
    fn is_allowed_at_refuses_entries_past_their_expires_at() {
        // Fail-open contract: when the exit has lost contact
        // with the control plane and is serving the last-known allowlist,
        // the per-entry `expires_at` is the only local guard against
        // lapsed subscriptions. A pubkey whose `expires_at` is in the
        // past MUST be refused even though it is present in the map.
        let (handle, _rx) = AllowlistHandle::new();
        let mut entries: HashMap<WarrenPubkey, u64> = HashMap::new();
        entries.insert(pk(1), 1_500); // expires at t=1500
        handle.apply_snapshot(AllowlistSnapshot {
            generation: 1,
            pubkeys: entries,
            fetched_at_unix_secs: 1_000,
        });

        // Before expiry: allowed.
        assert!(handle.is_allowed_at(&pk(1), 1_499));
        // At the boundary: refused (contract is `> now`, strict).
        assert!(!handle.is_allowed_at(&pk(1), 1_500));
        // After expiry: refused.
        assert!(!handle.is_allowed_at(&pk(1), 2_000));
        // Legacy presence check still says present  -  matches
        // older callers that did not honour local TTL.
        assert!(handle.is_allowed(&pk(1)));
    }

    #[test]
    fn is_allowed_at_legacy_snapshot_always_passes_ttl_check() {
        // `from_legacy_set` tags every entry with `u64::MAX`, which
        // disables the local TTL check. Regression: if we accidentally
        // wrote a smaller default, every legacy snapshot would refuse
        // its own pubkeys after 1970 + small offset = essentially
        // refuse everything in production.
        let (handle, _rx) = AllowlistHandle::new();
        let mut set = HashSet::new();
        set.insert(pk(1));
        handle.apply_snapshot(AllowlistSnapshot::from_legacy_set(1, set, 1_000));
        assert!(handle.is_allowed_at(&pk(1), u64::MAX - 1));
    }

    // ----- apply_delta -----

    #[test]
    fn apply_delta_inserts_added_with_expires_at_and_advances_generation() {
        // Baseline: the delta path must carry per-entry expiries
        // through. Otherwise the fail-open contract would
        // observe entries with `u64::MAX` (legacy default) and never
        // refuse a lapsed subscription.
        let (handle, _rx) = AllowlistHandle::new();
        let added = vec![(pk(1), 1_500), (pk(2), 2_500)];
        let removed = handle.apply_delta(added, vec![], 7, 1_000);

        assert_eq!(removed, 0, "first delta has no removals");
        assert_eq!(handle.last_generation(), 7);
        assert_eq!(handle.last_success_unix_secs(), 1_000);
        // Per-entry expiry is honoured.
        assert!(handle.is_allowed_at(&pk(1), 1_499));
        assert!(!handle.is_allowed_at(&pk(1), 1_500));
        assert!(handle.is_allowed_at(&pk(2), 2_499));
    }

    #[test]
    fn apply_delta_removes_and_broadcasts_revocation() {
        // Seed via apply_snapshot, then retire a pubkey via delta.
        // The revocation diff MUST reach the receiver so the listener
        // closes the live session for the retired pubkey.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1, 2, 3], 500));
        rx.try_recv().ok();

        let n = handle.apply_delta(vec![], vec![pk(2)], 2, 600);

        assert_eq!(n, 1);
        assert!(handle.is_allowed(&pk(1)));
        assert!(!handle.is_allowed(&pk(2)), "retired key must be gone");
        assert!(handle.is_allowed(&pk(3)));
        let evicted = rx.try_recv().expect("revocation must be broadcast");
        assert!(evicted.contains(&pk(2)));
        assert!(!evicted.contains(&pk(1)));
    }

    #[test]
    fn apply_delta_removal_of_absent_key_is_silent_noop() {
        // Idempotency: a delta that asks to retire a pubkey we never
        // saw locally MUST succeed silently. Otherwise a stale
        // resync after a local reset would double-broadcast or
        // panic.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1], 500));
        rx.try_recv().ok();

        let n = handle.apply_delta(vec![], vec![pk(99)], 2, 600);
        assert_eq!(n, 0, "absent key removal must count as 0");
        assert!(
            rx.try_recv().is_err(),
            "no revocation broadcast for absent key"
        );
    }

    #[test]
    fn apply_delta_drops_payload_when_to_generation_is_stale() {
        // Out-of-order: a delta whose `to_generation` is older than
        // what we already applied MUST be ignored (a retry that lost
        // a race against a freshly applied delta). Otherwise the
        // local state would regress to a stale view.
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(5, &[1, 2, 3], 500));

        let n = handle.apply_delta(vec![], vec![pk(1), pk(2)], 3, 600);
        assert_eq!(n, 0, "stale delta must be ignored");
        assert!(handle.is_allowed(&pk(1)), "stale delta did not retire pk1");
        assert!(handle.is_allowed(&pk(2)), "stale delta did not retire pk2");
        // last_success still advances (reachability ack).
        assert_eq!(handle.last_success_unix_secs(), 600);
        assert_eq!(
            handle.last_generation(),
            5,
            "stale delta did not regress gen"
        );
    }

    // ----- CRL -----

    #[test]
    fn crl_revocation_refuses_pubkey_even_when_in_allowlist() {
        // CRL contract: a pubkey listed in the CRL MUST be refused
        // at the gate even when the regular allowlist still admits
        // it. Otherwise an admin revoke in fail-open mode would not
        // propagate until the backend pushes a corresponding
        // allowlist removal  -  defeating the whole CRL design.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1, 2], 100));

        // Sanity: both pubkeys initially admitted.
        assert!(handle.is_allowed(&pk(1)));
        assert!(handle.is_allowed_at(&pk(1), 50));
        assert!(handle.is_allowed(&pk(2)));

        let mut crl: HashSet<WarrenPubkey> = HashSet::new();
        crl.insert(pk(1));
        let tear_down_count = handle.apply_crl_revocations(crl);

        assert_eq!(tear_down_count, 1, "pk(1) was in allowlist + now revoked");
        assert!(!handle.is_allowed(&pk(1)), "CRL must refuse the pubkey");
        assert!(
            !handle.is_allowed_at(&pk(1), 50),
            "CRL must refuse via is_allowed_at too"
        );
        assert!(
            handle.is_allowed(&pk(2)),
            "non-revoked pubkey still admitted"
        );

        // Tear-down notification broadcast on the revocation channel
        // so the listener can close the live session.
        let evicted = rx.try_recv().expect("CRL apply must broadcast");
        assert!(evicted.contains(&pk(1)));
        assert!(!evicted.contains(&pk(2)));
    }

    #[test]
    fn crl_apply_for_pubkey_not_in_allowlist_does_not_broadcast() {
        // Idempotency: revoking a pubkey we never admitted is a no-op
        // on the listener side (no live session to tear down). Avoid
        // spurious wake-ups on the revocation channel for these.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1], 100));
        rx.try_recv().ok();

        let mut crl: HashSet<WarrenPubkey> = HashSet::new();
        crl.insert(pk(99));
        let n = handle.apply_crl_revocations(crl);

        assert_eq!(n, 0, "revoking an absent pubkey is a no-op");
        assert!(
            rx.try_recv().is_err(),
            "no broadcast for an absent-pubkey CRL apply"
        );
    }

    #[test]
    fn end_to_end_fail_open_with_crl_revocation_after_backend_outage() {
        // Acceptance test combining per-entry expiry, fail-open
        // last-known, and CRL override. Scenario:
        //
        // 1. Apply an initial snapshot with two paying subscribers
        //    (one expires soon, one far in the future).
        // 2. Simulate the control-plane API going dark indefinitely. No
        //    further apply_snapshot calls happen.
        // 3. Time advances PAST the legacy stale_grace + past the
        //    near-term subscriber's `expires_at`.
        // 4. An admin issues an out-of-band CRL revoking the
        //    far-future subscriber (compromised pubkey). We apply
        //    the CRL on the handle.
        //
        // Expected end state:
        // - The lapsed subscriber is refused locally via `expires_at`
        //   (TTL).
        // - The far-future subscriber is refused via the CRL
        //   even though its `expires_at` is far away and the backend
        //   has been silent forever (fail-open).
        // - No other pubkey is admitted (cold-start guard for any
        //   bystander).
        let (handle, mut rx) = AllowlistHandle::new();
        let mut entries: HashMap<WarrenPubkey, u64> = HashMap::new();
        entries.insert(pk(1), 1_500); // expires soon
        entries.insert(pk(2), u64::MAX / 2); // far future
        handle.apply_snapshot(AllowlistSnapshot {
            generation: 1,
            pubkeys: entries,
            fetched_at_unix_secs: 1_000,
        });
        rx.try_recv().ok();

        // T+ many hours; backend silent the whole time (no more
        // apply_snapshot calls). Fail-open keeps both pubkeys in the
        // map; per-entry expiry handles pk(1).
        let now_after_outage = 86_400_u64; // ~1 day
        assert!(
            !handle.is_allowed_at(&pk(1), now_after_outage),
            "lapsed subscriber refused via local TTL"
        );
        assert!(
            handle.is_allowed_at(&pk(2), now_after_outage),
            "far-future subscriber still admitted (fail-open)"
        );

        // Admin issues an out-of-band CRL revocation (e.g. via a
        // signed payload distributed through the redundant control
        // plane). The exit applies the CRL on the handle.
        let mut crl: HashSet<WarrenPubkey> = HashSet::new();
        crl.insert(pk(2));
        let n = handle.apply_crl_revocations(crl);
        assert_eq!(
            n, 1,
            "pk(2) was in allowlist + now revoked => tear-down required"
        );

        // pk(2) refused even though `expires_at` is far away and
        // backend is still silent.
        assert!(
            !handle.is_allowed_at(&pk(2), now_after_outage),
            "CRL revocation must apply even in fail-open"
        );
        // Bystander never admitted.
        assert!(!handle.is_allowed_at(&pk(99), now_after_outage));

        // Tear-down notification reaches the listener.
        let evicted = rx
            .try_recv()
            .expect("CRL must broadcast on revocation channel");
        assert!(evicted.contains(&pk(2)));
    }

    #[test]
    fn crl_set_swap_clears_previously_revoked_pubkey() {
        // The CRL is replaced wholesale on each apply (matching the
        // wire contract: a CrlResponse carries the full current
        // list). A pubkey that disappears from the CRL between two
        // applies MUST become eligible again.
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1], 100));

        let mut crl: HashSet<WarrenPubkey> = HashSet::new();
        crl.insert(pk(1));
        handle.apply_crl_revocations(crl);
        assert!(!handle.is_allowed(&pk(1)));

        // Empty CRL -> back to allowed.
        handle.apply_crl_revocations(HashSet::new());
        assert!(handle.is_allowed(&pk(1)));
    }

    #[test]
    fn fresh_empty_handle_refuses_every_pubkey() {
        // Critical security property: an exit that has not yet
        // received a snapshot from the control plane MUST refuse all clients.
        // If `is_allowed` returned `true` on the empty set, the boot
        // window between binary start and first successful fetch would
        // be permissive, exactly the regression we're closing.
        let (handle, _rx) = AllowlistHandle::new();
        assert!(!handle.is_allowed(&pk(1)));
        assert!(!handle.is_allowed(&pk(99)));
        assert_eq!(handle.last_generation(), 0);
        assert_eq!(handle.last_success_unix_secs(), 0);
    }

    #[tokio::test]
    async fn new_constructor_pairs_handle_with_a_live_revocation_receiver() {
        // The whole point of the tuple return is that no caller can
        // forget the channel. Prove the receiver is genuinely wired
        // by causing a revocation and observing it on `rx`. If a
        // future refactor swaps the constructor back to a footgun
        // "optional channel" shape, this test will fail or stop
        // compiling.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1, 2], 100));
        // First snapshot is pure addition  -  no revocation expected.
        assert!(rx.try_recv().is_err(), "first-apply must not broadcast");

        // Retire pk(1) by applying a snapshot that omits it.
        handle.apply_snapshot(snapshot(2, &[2], 101));
        let dropped = rx
            .try_recv()
            .expect("revocation must reach the paired receiver");
        assert!(dropped.contains(&pk(1)));
        assert!(!dropped.contains(&pk(2)));
    }

    // ----- Snapshot application -----

    #[test]
    fn first_snapshot_populates_set_and_emits_no_revocation() {
        // First-apply lifecycle: every pubkey is an addition, the
        // revocation channel must stay silent. If we erroneously sent
        // the empty `old \ new = empty` as a revocation, the listener
        // would receive a useless wake-up at every reboot.
        let (handle, mut rx) = AllowlistHandle::new();

        let removed = handle.apply_snapshot(snapshot(7, &[1, 2, 3], 1_000));

        assert_eq!(removed, 0, "first snapshot must not revoke anything");
        assert!(handle.is_allowed(&pk(1)));
        assert!(handle.is_allowed(&pk(2)));
        assert!(handle.is_allowed(&pk(3)));
        assert!(!handle.is_allowed(&pk(4)));
        assert_eq!(handle.last_generation(), 7);
        assert_eq!(handle.last_success_unix_secs(), 1_000);
        assert!(
            collect_revocations(&mut rx).is_empty(),
            "no revocation event on first apply"
        );
    }

    #[test]
    fn snapshot_with_strictly_greater_generation_replaces_set() {
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(5, &[1, 2], 1_000));
        let removed = handle.apply_snapshot(snapshot(6, &[2, 3], 1_010));

        assert_eq!(removed, 1, "pubkey 1 removed; only one revocation expected");
        assert!(!handle.is_allowed(&pk(1)), "revoked pubkey gone");
        assert!(handle.is_allowed(&pk(2)));
        assert!(handle.is_allowed(&pk(3)));
        assert_eq!(handle.last_generation(), 6);
        assert_eq!(handle.last_success_unix_secs(), 1_010);
    }

    #[test]
    fn revocation_diff_is_broadcast_on_channel() {
        // The exit consumes this broadcast to close live sessions
        // mid-flight. A revocation that doesn't reach it
        // = a paid-then-cancelled user keeps tunneling.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1, 2, 3], 100));

        let removed = handle.apply_snapshot(snapshot(2, &[1], 200));

        assert_eq!(removed, 2);
        let events = collect_revocations(&mut rx);
        assert_eq!(events.len(), 1, "exactly one batch revocation event");
        assert_eq!(events[0], set_of(&[2, 3]));
    }

    #[test]
    fn revocation_is_never_lost_when_receiver_lags_behind_bursty_teardowns() {
        // Regression for the fail-open channel bug: entries are removed
        // from `entries` BEFORE the revocation batch is queued (see
        // `apply_snapshot`), so a dropped batch leaves the map already
        // refusing the pubkey while the listener never learns to close
        // its live QUIC session. A bounded channel drops a batch outright
        // once more un-drained batches pile up than its capacity (e.g. a
        // listener briefly stalled during a mass revocation / large CRL).
        // Every batch must reach the receiver no matter how many pile up
        // unread.
        let (handle, mut rx) = AllowlistHandle::new();

        // Seed with one pubkey, then retire exactly one pubkey per
        // subsequent apply_snapshot: each call produces exactly one
        // revocation batch. `rx` is never drained during the loop, so
        // batches pile up exactly as they would under a stalled listener.
        handle.apply_snapshot(snapshot(1, &[0], 0));
        let batches: u64 = 100; // comfortably more than any bounded channel's capacity
        for generation in 2..=batches {
            #[allow(clippy::cast_possible_truncation)]
            let seed = generation as u8;
            let removed = handle.apply_snapshot(snapshot(generation, &[seed], generation * 100));
            assert_eq!(
                removed, 1,
                "each snapshot retires exactly the previous pubkey"
            );
        }

        let mut received = 0u64;
        while rx.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(
            received,
            batches - 1,
            "every revocation batch must reach the listener; none may be \
             silently dropped because the channel filled up"
        );
    }

    #[test]
    fn pure_addition_snapshot_does_not_emit_revocation() {
        // Adding a new subscriber MUST NOT wake the listener up: the
        // listener only cares about teardown. False revocations would
        // waste CPU on every poll where a new user signs up.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1, 2], 100));

        let removed = handle.apply_snapshot(snapshot(2, &[1, 2, 3], 200));

        assert_eq!(removed, 0);
        assert!(collect_revocations(&mut rx).is_empty());
    }

    #[test]
    fn snapshot_with_equal_generation_skips_payload_but_acks_reachability() {
        // Two-part contract:
        //   (a) Defense against duplicate replies (retry storms): the
        //       same generation arriving twice must not re-apply the
        //       payload. Otherwise a slow duplicate carrying old state
        //       could clobber a newer set, or a server returning
        //       generation == previous (steady state) would let a
        //       client-side mock alter the live set.
        //   (b) Reachability ack: the poll itself succeeded, so the
        //       staleness clock MUST advance. This is the fix for the
        //       empirical bug where a healthy backend
        //       returning a stable generation caused `clear_if_stale`
        //       to fail-close at T0 + grace because last_success was
        //       frozen on the boot-from-cache timestamp.
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(5, &[1, 2], 1_000));

        let removed = handle.apply_snapshot(snapshot(5, &[9], 2_000));

        assert_eq!(removed, 0);
        assert!(handle.is_allowed(&pk(1)));
        assert!(handle.is_allowed(&pk(2)));
        assert!(
            !handle.is_allowed(&pk(9)),
            "duplicate gen must NOT apply payload"
        );
        assert_eq!(
            handle.last_generation(),
            5,
            "last_generation must not advance on a rejected payload",
        );
        assert_eq!(
            handle.last_success_unix_secs(),
            2_000,
            "successful poll updates last_success regardless of generation gate",
        );
    }

    #[test]
    fn steady_state_polls_advance_last_success_without_mutating_payload() {
        // Regression guard. An exit
        // restored from on-disk cache (gen=G, fetched_at=T_OLD) polls
        // a healthy control plane that has not mutated since. The server
        // returns the SAME generation on every tick, so the payload
        // gate early-returns. If last_success stayed frozen at T_OLD,
        // the staleness sweep would evict the entire allowlist at
        // T_OLD + grace, treating a healthy backend as a 5-minute
        // outage. last_success must therefore advance on every
        // successful poll regardless of the gate, so the sweep
        // never fires while the backend is reachable.
        let (handle, _rx) = AllowlistHandle::new();
        let cache_seed_time = 1_000;
        handle.apply_snapshot(snapshot(5, &[1, 2], cache_seed_time));

        for tick in 1..=10 {
            let poll_time = cache_seed_time + 30 * tick;
            let removed = handle.apply_snapshot(snapshot(5, &[1, 2], poll_time));
            assert_eq!(removed, 0, "stable-gen snapshot is a no-op payload");
            assert_eq!(
                handle.last_success_unix_secs(),
                poll_time,
                "tick {tick} must advance reachability clock",
            );
        }
        // 300 s past the cache seed, 0 s past the last poll: still
        // alive. A frozen last_success would evict here.
        let evicted = handle.clear_if_stale(cache_seed_time + 300, 60);
        assert_eq!(
            evicted, 0,
            "fresh successive polls must reset the staleness clock",
        );
        assert!(handle.is_allowed(&pk(1)));
        assert!(handle.is_allowed(&pk(2)));
    }

    #[test]
    fn out_of_order_snapshot_with_stale_fetched_at_does_not_regress_last_success() {
        // An out-of-order retry whose `fetched_at_unix_secs` is older
        // than the freshest poll observed so far must NOT roll back
        // the staleness clock. The fix uses `fetch_max`, so a stale
        // timestamp is dropped.
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(10, &[1], 2_000));

        let removed = handle.apply_snapshot(snapshot(9, &[1, 2, 3], 1_500));

        assert_eq!(removed, 0);
        assert!(
            !handle.is_allowed(&pk(2)),
            "older gen must not apply payload"
        );
        assert_eq!(
            handle.last_success_unix_secs(),
            2_000,
            "stale fetched_at must not regress the reachability clock",
        );
        assert_eq!(handle.last_generation(), 10);
    }

    #[test]
    fn rejected_payload_with_strictly_newer_fetched_at_advances_last_success() {
        // A later poll that the generation gate still rejects (e.g.
        // server replays the same generation but the client clock has
        // advanced) must move the reachability clock forward.
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(7, &[1, 2], 1_000));

        let removed = handle.apply_snapshot(snapshot(7, &[], 1_999));

        assert_eq!(removed, 0, "gate drops payload at equal generation");
        assert!(handle.is_allowed(&pk(1)));
        assert_eq!(handle.last_success_unix_secs(), 1_999);
        assert_eq!(handle.last_generation(), 7);
    }

    #[test]
    fn snapshot_with_older_generation_is_ignored_after_first_apply() {
        // Out-of-order arrival: snapshot A (gen 10) lands first, then
        // a delayed reply for snapshot B (gen 9) arrives. Accepting B
        // would roll back a revocation and re-admit a user the admin
        // just cancelled.
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(10, &[1], 1_000));

        let removed = handle.apply_snapshot(snapshot(9, &[1, 2, 3], 999));

        assert_eq!(removed, 0);
        assert!(!handle.is_allowed(&pk(2)));
        assert_eq!(handle.last_generation(), 10);
    }

    #[test]
    fn first_snapshot_with_generation_zero_is_accepted() {
        // Edge: the server has never seen any mutation; `generation`
        // is legitimately 0. Treating this as "duplicate" would leave
        // a fresh exit fail-closed forever even with a healthy backend.
        let (handle, _rx) = AllowlistHandle::new();
        let removed = handle.apply_snapshot(snapshot(0, &[1, 2], 1_000));

        assert_eq!(removed, 0);
        assert!(handle.is_allowed(&pk(1)));
        assert_eq!(handle.last_success_unix_secs(), 1_000);
    }

    // ----- Staleness fallback -----

    #[test]
    fn clear_if_stale_does_nothing_before_first_apply() {
        // Boot-time invariant: a never-applied handle is already
        // empty (fail-closed). Calling `clear_if_stale` must not
        // emit a phantom revocation just because real-world time
        // is far ahead of zero.
        let (handle, mut rx) = AllowlistHandle::new();

        let evicted = handle.clear_if_stale(10_000, 60);

        assert_eq!(evicted, 0);
        assert!(collect_revocations(&mut rx).is_empty());
    }

    #[test]
    fn clear_if_stale_within_grace_is_noop() {
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1, 2], 1_000));

        let evicted = handle.clear_if_stale(1_059, 60);

        assert_eq!(evicted, 0);
        assert!(handle.is_allowed(&pk(1)));
        assert!(handle.is_allowed(&pk(2)));
    }

    #[test]
    fn clear_if_stale_past_grace_empties_and_broadcasts_eviction() {
        // The full security contract: when the control plane is unreachable
        // for longer than grace, the exit MUST degrade to "deny all".
        // A subscription that just lapsed and that the exit never
        // saw the revocation for is the exact case this guards
        // against. Eviction must hit the listener's revocation
        // channel so live sessions are torn down too.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1, 2], 1_000));

        let evicted = handle.clear_if_stale(1_061, 60);

        assert_eq!(evicted, 2);
        assert!(handle.is_empty());
        assert!(!handle.is_allowed(&pk(1)));
        let events = collect_revocations(&mut rx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], set_of(&[1, 2]));
    }

    #[test]
    fn clear_if_stale_on_already_empty_handle_does_not_re_broadcast() {
        // Idempotency: the refresh task calls `clear_if_stale` on
        // every tick. Once the eviction has fired, subsequent ticks
        // must NOT keep flooding the channel with empty-set events.
        let (handle, mut rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1], 1_000));
        let _ = handle.clear_if_stale(2_000, 60);
        let _ = collect_revocations(&mut rx);

        let evicted = handle.clear_if_stale(3_000, 60);

        assert_eq!(evicted, 0);
        assert!(collect_revocations(&mut rx).is_empty());
    }

    // ----- Concurrency invariants -----

    #[test]
    fn is_allowed_and_apply_snapshot_are_safe_under_thread_contention() {
        // Stress test: thousands of `is_allowed` reads racing with
        // `apply_snapshot` writes. The test asserts the structural
        // invariant by simply completing without aborting. A bug here
        // would manifest as a torn read (impossible with
        // RwLock<HashSet>) or, more subtly, as a generation advancing
        // without its companion set being visible.
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::thread;

        let (handle, _rx) = AllowlistHandle::new();
        let handle = Arc::new(handle);
        handle.apply_snapshot(snapshot(1, &[1, 2, 3, 4, 5], 1_000));
        let stop = Arc::new(AtomicBool::new(false));

        let reader_count = 4;
        let mut readers = Vec::with_capacity(reader_count);
        for _ in 0..reader_count {
            let h = Arc::clone(&handle);
            let s = Arc::clone(&stop);
            readers.push(thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    // Every observed generation MUST come with a
                    // non-empty set (we only apply non-empty snapshots).
                    let observed_gen = h.last_generation();
                    assert!(
                        !(observed_gen > 0 && h.is_empty()),
                        "torn observation: generation {observed_gen} visible but set empty"
                    );
                    std::hint::spin_loop();
                }
            }));
        }

        for g in 2u64..200 {
            #[allow(clippy::cast_possible_truncation)]
            let seeds: Vec<u8> = (g as u8..g as u8 + 5).collect();
            handle.apply_snapshot(snapshot(g, &seeds, 1_000 + g));
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread panic-free");
        }
    }

    // ----- Cold-start first-sync grace -----

    #[tokio::test(start_paused = true)]
    async fn wait_for_first_sync_returns_immediately_once_synced() {
        let (handle, _rx) = AllowlistHandle::new();
        handle.apply_snapshot(snapshot(1, &[1], 1_000));
        // Already synced: resolves true without consuming the grace.
        let start = tokio::time::Instant::now();
        assert!(
            handle
                .wait_for_first_sync(std::time::Duration::from_secs(5))
                .await
        );
        assert!(start.elapsed() < std::time::Duration::from_millis(50));
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_first_sync_times_out_when_never_synced() {
        let (handle, _rx) = AllowlistHandle::new();
        // Never polled (last_success == 0): falls back to false after grace.
        assert!(
            !handle
                .wait_for_first_sync(std::time::Duration::from_secs(5))
                .await
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_first_sync_wakes_when_sync_lands_within_grace() {
        let (handle, _rx) = AllowlistHandle::new();
        let waiter = {
            let h = handle.clone();
            tokio::spawn(async move {
                h.wait_for_first_sync(std::time::Duration::from_secs(30))
                    .await
            })
        };
        // Let the waiter park on its poll loop, then land the first sync.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        handle.apply_snapshot(snapshot(1, &[1], 1_000));
        assert!(waiter.await.expect("waiter task panic-free"));
    }
}
