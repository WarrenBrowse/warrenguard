//! Registry of buckets indexed by identity (typical key = `WarrenPubkey`).
//!
//! The caller picks the key type via the `K: Eq + Hash + Clone` generic.
//! `IdentityLimiter` lazy-inits a bucket for any unknown key with the
//! same `(capacity, rate)` as the registry config, up to a hard cap on the
//! number of tracked keys.
//!
//! ## Admission cap
//!
//! A key the registry has never seen is admitted only while fewer than
//! `max_tracked` keys are tracked. The capacity check and the insertion run
//! under ONE write-lock acquisition, so concurrent first packets from distinct
//! keys can never push the map past the cap. Beyond the cap a new key is
//! refused ([`Admission::AtCapacity`]) and nothing is evicted: an admitted
//! key keeps its bucket (and its drained budget) until the caller's sweep
//! ([`IdentityLimiter::retain_active`], [`IdentityLimiter::retain`]) drops it,
//! which is what frees capacity. The refusal itself is O(1); the O(n) sweep
//! stays on the caller's cadence so a flood of new keys at the cap cannot turn
//! every attempt into a full-map scan under the write lock.

use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::TokenBucket;

/// Hard cap applied by [`IdentityLimiter::new`]: a memory backstop, so a
/// registry keyed by attacker-influenced identities (source IPs) stays bounded
/// even when its owner never picks a tighter cap. Same order as the
/// connection limiter's backstop; a deployer who knows its population sets a
/// tighter one with [`IdentityLimiter::with_max_tracked`].
pub const DEFAULT_MAX_TRACKED_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000_000).unwrap();

/// Verdict of [`IdentityLimiter::try_admit`] for one consume attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Admission {
    /// The key is tracked and its bucket held the tokens, now deducted.
    Allowed,
    /// The key is tracked but its bucket is short of tokens; nothing was
    /// deducted. The caller drops.
    RateLimited,
    /// The key is new and the registry already tracks its cap of keys. The
    /// key was refused WITHOUT being tracked and without evicting anyone; the
    /// caller drops, fail-closed.
    AtCapacity,
}

/// Per-identity registry of buckets. Uses an `RwLock<HashMap>` to let
/// reads (the `try_consume` hot path) proceed without blocking other
/// clients when fetching an existing bucket. Insertion upgrades to the
/// write lock, where the admission cap is checked atomically.
#[derive(Debug)]
pub struct IdentityLimiter<K: Eq + Hash + Clone> {
    capacity_bytes: u64,
    rate_bps: u64,
    max_tracked: usize,
    buckets: RwLock<HashMap<K, Arc<TokenBucket>>>,
    /// Running count of [`Admission::AtCapacity`] verdicts: the only trace a
    /// full registry leaves, since its refusals look like drops to a caller.
    at_capacity_refusals: AtomicU64,
}

impl<K: Eq + Hash + Clone> IdentityLimiter<K> {
    /// Creates an empty registry capped at [`DEFAULT_MAX_TRACKED_IDENTITIES`] keys.
    /// Buckets are created on demand on the first consume of each key.
    ///
    /// # Panics
    ///
    /// See [`TokenBucket::new`] (panics if `rate_bps == 0`).
    #[must_use]
    pub fn new(capacity_bytes: u64, rate_bps: u64) -> Self {
        Self::with_max_tracked(capacity_bytes, rate_bps, DEFAULT_MAX_TRACKED_IDENTITIES)
    }

    /// Creates an empty registry that tracks at most `max_tracked` keys; a
    /// new key beyond that is refused (see the module docs).
    ///
    /// # Panics
    ///
    /// See [`TokenBucket::new`] (panics if `rate_bps == 0`).
    #[must_use]
    pub fn with_max_tracked(capacity_bytes: u64, rate_bps: u64, max_tracked: NonZeroUsize) -> Self {
        // Sanity-check the rate here too so we fail fast at construction
        // (otherwise the panic would only fire on the first try_consume).
        assert!(rate_bps > 0, "IdentityLimiter rate_bps must be > 0");
        Self {
            capacity_bytes,
            rate_bps,
            max_tracked: max_tracked.get(),
            buckets: RwLock::new(HashMap::new()),
            at_capacity_refusals: AtomicU64::new(0),
        }
    }

    /// Tries to consume `bytes` on behalf of `key`, admitting `key` first if
    /// it is new and the cap allows it. Uses the system clock.
    pub fn try_admit(&self, key: &K, bytes: u64) -> Admission {
        self.try_admit_at(key, bytes, Instant::now())
    }

    /// Same as [`Self::try_admit`] with an explicit `now`, so tests can drive
    /// a deterministic clock without sleeping.
    pub fn try_admit_at(&self, key: &K, bytes: u64, now: Instant) -> Admission {
        let Some(bucket) = self.bucket_or_admit(key) else {
            self.at_capacity_refusals.fetch_add(1, Ordering::Relaxed);
            return Admission::AtCapacity;
        };
        if bucket.try_consume_at(bytes, now) {
            Admission::Allowed
        } else {
            Admission::RateLimited
        }
    }

    /// Tries to consume `bytes` on behalf of `key`: `true` admits, `false`
    /// means drop (rate-limited, or a new key refused at the cap). Uses the
    /// system clock.
    pub fn try_consume(&self, key: &K, bytes: u64) -> bool {
        self.try_admit(key, bytes) == Admission::Allowed
    }

    /// Same as [`Self::try_consume`] but with an explicit `now`. Used
    /// by tests to drive a deterministic clock without sleeping.
    pub fn try_consume_at(&self, key: &K, bytes: u64, now: Instant) -> bool {
        self.try_admit_at(key, bytes, now) == Admission::Allowed
    }

    /// The bucket of `key`, inserting a full one if `key` is new and the cap
    /// allows it; `None` when `key` is new and the registry is full.
    fn bucket_or_admit(&self, key: &K) -> Option<Arc<TokenBucket>> {
        if let Some(b) = self.buckets.read().get(key).cloned() {
            return Some(b);
        }
        // Re-check presence and capacity under the SAME write guard as the
        // insert: another thread may have admitted this key, or filled the
        // last slot, between the read above and this point.
        let mut w = self.buckets.write();
        if let Some(b) = w.get(key) {
            return Some(Arc::clone(b));
        }
        if w.len() >= self.max_tracked {
            return None;
        }
        let bucket = Arc::new(TokenBucket::new(self.capacity_bytes, self.rate_bps));
        w.insert(key.clone(), Arc::clone(&bucket));
        Some(bucket)
    }

    /// How many consume attempts were refused because the key was new and the
    /// registry full ([`Admission::AtCapacity`]), since construction.
    #[must_use]
    pub fn at_capacity_refusals(&self) -> u64 {
        self.at_capacity_refusals.load(Ordering::Relaxed)
    }

    /// Number of registered buckets (= distinct clients seen). Useful
    /// for metrics or tests.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.buckets.read().len()
    }

    /// Drops buckets whose key is no longer accepted by `predicate`.
    /// Called periodically by a cleanup task to avoid a memory leak when
    /// many ephemeral clients connect.
    pub fn retain<F>(&self, mut predicate: F)
    where
        F: FnMut(&K) -> bool,
    {
        let mut w = self.buckets.write();
        w.retain(|k, _| predicate(k));
        crate::shrink_if_sparse(&mut w);
    }

    /// Drops buckets whose `last_refill` is older than `idle` before
    /// `now`. Convenience wrapper over [`Self::retain`] that captures
    /// the typical idle-GC pattern.
    pub fn retain_active(&self, idle: Duration, now: Instant) {
        let mut w = self.buckets.write();
        w.retain(|_, bucket| now.saturating_duration_since(bucket.last_refill()) < idle);
        crate::shrink_if_sparse(&mut w);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    fn cap(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("non-zero cap")
    }

    #[test]
    fn lazy_init_per_key() {
        let lim: IdentityLimiter<&str> = IdentityLimiter::new(100, 10);
        assert_eq!(lim.tracked_count(), 0);
        assert!(lim.try_consume(&"alice", 50));
        assert_eq!(lim.tracked_count(), 1);
        assert!(lim.try_consume(&"bob", 100));
        assert_eq!(lim.tracked_count(), 2);
    }

    #[test]
    fn buckets_are_independent_per_key() {
        let lim: IdentityLimiter<&str> = IdentityLimiter::new(100, 1);
        // Alice consumes everything.
        assert!(lim.try_consume(&"alice", 100));
        assert!(!lim.try_consume(&"alice", 1));
        // Bob is independent: his bucket is full.
        assert!(lim.try_consume(&"bob", 100));
    }

    #[test]
    fn retain_removes_unwanted_keys() {
        let lim: IdentityLimiter<u32> = IdentityLimiter::new(100, 1);
        lim.try_consume(&1, 1);
        lim.try_consume(&2, 1);
        lim.try_consume(&3, 1);
        assert_eq!(lim.tracked_count(), 3);
        lim.retain(|k| *k != 2);
        assert_eq!(lim.tracked_count(), 2);
    }

    #[test]
    #[should_panic(expected = "rate_bps must be > 0")]
    fn rate_zero_panics() {
        let _: IdentityLimiter<u32> = IdentityLimiter::new(100, 0);
    }

    #[test]
    #[should_panic(expected = "rate_bps must be > 0")]
    fn capped_rate_zero_panics() {
        let _: IdentityLimiter<u32> = IdentityLimiter::with_max_tracked(100, 0, cap(4));
    }

    #[test]
    fn try_admit_reports_allowed_then_rate_limited_for_a_tracked_key() {
        let lim: IdentityLimiter<&str> = IdentityLimiter::with_max_tracked(100, 1, cap(4));
        let now = Instant::now();
        assert_eq!(lim.try_admit_at(&"alice", 100, now), Admission::Allowed);
        assert_eq!(lim.try_admit_at(&"alice", 1, now), Admission::RateLimited);
        assert_eq!(lim.tracked_count(), 1);
    }

    #[test]
    fn new_key_beyond_the_cap_is_refused_without_evicting_admitted_keys() {
        let lim: IdentityLimiter<&str> = IdentityLimiter::with_max_tracked(100, 1, cap(2));
        let now = Instant::now();
        assert_eq!(lim.try_admit_at(&"alice", 100, now), Admission::Allowed);
        assert_eq!(lim.try_admit_at(&"bob", 10, now), Admission::Allowed);

        assert_eq!(lim.try_admit_at(&"carol", 1, now), Admission::AtCapacity);
        assert!(!lim.try_consume_at(&"carol", 1, now));
        assert_eq!(lim.tracked_count(), 2, "a refused key is never tracked");

        // Alice drained her budget before the refusals: had she been evicted
        // (and re-admitted with a fresh bucket) she would pass again.
        assert_eq!(lim.try_admit_at(&"alice", 1, now), Admission::RateLimited);
        // Admitted keys keep being served at the cap.
        assert_eq!(lim.try_admit_at(&"bob", 90, now), Admission::Allowed);
    }

    #[test]
    fn idle_sweep_frees_capacity_for_a_new_key() {
        let lim: IdentityLimiter<&str> = IdentityLimiter::with_max_tracked(100, 1, cap(2));
        let t0 = Instant::now();
        assert!(lim.try_consume_at(&"alice", 1, t0));
        assert!(lim.try_consume_at(&"bob", 1, t0 + Duration::from_secs(8)));
        let t1 = t0 + Duration::from_secs(10);
        assert_eq!(lim.try_admit_at(&"carol", 1, t1), Admission::AtCapacity);

        // Alice idle 10s, Bob 2s: a 5s idle sweep drops Alice only.
        lim.retain_active(Duration::from_secs(5), t1);
        assert_eq!(lim.tracked_count(), 1);
        assert_eq!(lim.try_admit_at(&"carol", 1, t1), Admission::Allowed);
        assert_eq!(lim.try_admit_at(&"dave", 1, t1), Admission::AtCapacity);
    }

    #[test]
    fn explicit_retain_frees_capacity_for_a_new_key() {
        let lim: IdentityLimiter<u32> = IdentityLimiter::with_max_tracked(100, 1, cap(1));
        assert!(lim.try_consume(&1, 1));
        assert_eq!(lim.try_admit(&2, 1), Admission::AtCapacity);
        lim.retain(|k| *k != 1);
        assert_eq!(lim.try_admit(&2, 1), Admission::Allowed);
    }

    #[test]
    fn a_sweep_that_empties_the_registry_returns_its_memory() {
        let lim: IdentityLimiter<u32> = IdentityLimiter::new(100, 1);
        let t0 = Instant::now();
        for key in 0..20_000u32 {
            assert!(lim.try_consume_at(&key, 1, t0));
        }
        let peak = lim.buckets.read().capacity();
        lim.retain_active(Duration::from_secs(1), t0 + Duration::from_secs(5));
        assert_eq!(lim.tracked_count(), 0);
        assert!(
            lim.buckets.read().capacity() < peak / 4,
            "a flood's peak allocation must not outlive the sweep"
        );

        for key in 0..20_000u32 {
            assert!(lim.try_consume_at(&key, 1, t0));
        }
        lim.retain(|_| false);
        assert!(lim.buckets.read().capacity() < peak / 4);
    }

    #[test]
    fn refusals_at_capacity_are_counted() {
        let lim: IdentityLimiter<&str> = IdentityLimiter::with_max_tracked(100, 1, cap(1));
        let now = Instant::now();
        assert_eq!(lim.try_admit_at(&"alice", 100, now), Admission::Allowed);
        assert_eq!(lim.try_admit_at(&"alice", 1, now), Admission::RateLimited);
        assert_eq!(
            lim.at_capacity_refusals(),
            0,
            "a rate-limit drop is not one"
        );
        assert_eq!(lim.try_admit_at(&"bob", 1, now), Admission::AtCapacity);
        assert!(!lim.try_consume_at(&"carol", 1, now));
        assert_eq!(lim.at_capacity_refusals(), 2);
    }

    #[test]
    fn new_applies_the_default_cap() {
        let lim: IdentityLimiter<usize> = IdentityLimiter::new(100, 1);
        let limit = DEFAULT_MAX_TRACKED_IDENTITIES.get();
        let now = Instant::now();
        // Seed all but one slot directly: a million admissions through the
        // public path cost seconds in an unoptimized test build. Sharing one
        // bucket is fine, only the key count matters to the limit.
        let shared = Arc::new(TokenBucket::new(100, 1));
        lim.buckets
            .write()
            .extend((0..limit - 1).map(|k| (k, Arc::clone(&shared))));
        let last = limit - 1;
        assert_eq!(lim.try_admit_at(&last, 1, now), Admission::Allowed);
        assert_eq!(lim.try_admit_at(&limit, 1, now), Admission::AtCapacity);
        assert_eq!(lim.tracked_count(), limit);
    }

    /// Many threads race their FIRST packet on distinct keys against a small
    /// cap. A check-then-insert (capacity read under one lock acquisition,
    /// insertion under another) lets several racers pass the check before any
    /// of them inserts, so the map ends above the cap; the atomic
    /// insert-or-refuse admits exactly `CAP` keys every round.
    #[test]
    fn concurrent_new_keys_never_exceed_the_cap() {
        const CAP: usize = 4;
        const RACERS: usize = 32;
        const ROUNDS: usize = 100;
        for round in 0..ROUNDS {
            let lim: IdentityLimiter<usize> = IdentityLimiter::with_max_tracked(1_000, 1, cap(CAP));
            let barrier = Barrier::new(RACERS);
            let verdicts: Vec<Admission> = std::thread::scope(|s| {
                let handles: Vec<_> = (0..RACERS)
                    .map(|key| {
                        let (lim, barrier) = (&lim, &barrier);
                        s.spawn(move || {
                            barrier.wait();
                            lim.try_admit(&key, 1)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("racer thread panicked"))
                    .collect()
            });
            let allowed = verdicts
                .iter()
                .filter(|v| **v == Admission::Allowed)
                .count();
            let refused = verdicts
                .iter()
                .filter(|v| **v == Admission::AtCapacity)
                .count();
            assert_eq!(
                lim.tracked_count(),
                CAP,
                "round {round}: the map must hold exactly the cap"
            );
            assert_eq!(allowed, CAP, "round {round}: exactly CAP keys admitted");
            assert_eq!(refused, RACERS - CAP, "round {round}: the rest refused");
        }
    }
}
