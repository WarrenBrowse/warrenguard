//! Registry of buckets indexed by identity (typical key = `WarrenPubkey`).
//!
//! The caller picks the key type via the `K: Eq + Hash + Clone` generic.
//! `IdentityLimiter` lazy-inits a bucket for any unknown key with the
//! same `(capacity, rate)` as the registry config.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::TokenBucket;

/// Per-identity registry of buckets. Uses an `RwLock<HashMap>` to let
/// reads (the `try_consume` hot path) proceed without blocking other
/// clients when fetching an existing bucket. Insertion upgrades to the
/// write lock.
#[derive(Debug)]
pub struct IdentityLimiter<K: Eq + Hash + Clone> {
    capacity_bytes: u64,
    rate_bps: u64,
    buckets: RwLock<HashMap<K, Arc<TokenBucket>>>,
}

impl<K: Eq + Hash + Clone> IdentityLimiter<K> {
    /// Creates an empty registry. Buckets are created on demand on the
    /// first `try_consume(key, _)`.
    ///
    /// # Panics
    ///
    /// See [`TokenBucket::new`] (panics if `rate_bps == 0`).
    #[must_use]
    pub fn new(capacity_bytes: u64, rate_bps: u64) -> Self {
        // Sanity-check the rate here too so we fail fast at construction
        // (otherwise the panic would only fire on the first try_consume).
        assert!(rate_bps > 0, "IdentityLimiter rate_bps must be > 0");
        Self {
            capacity_bytes,
            rate_bps,
            buckets: RwLock::new(HashMap::new()),
        }
    }

    /// Tries to consume `bytes` on behalf of `key`. Creates the bucket
    /// on the fly if absent. Uses the system clock.
    pub fn try_consume(&self, key: &K, bytes: u64) -> bool {
        if let Some(b) = self.buckets.read().get(key).cloned() {
            return b.try_consume(bytes);
        }
        let mut w = self.buckets.write();
        let bucket = w
            .entry(key.clone())
            .or_insert_with(|| Arc::new(TokenBucket::new(self.capacity_bytes, self.rate_bps)))
            .clone();
        drop(w);
        bucket.try_consume(bytes)
    }

    /// Same as [`Self::try_consume`] but with an explicit `now`. Used
    /// by tests to drive a deterministic clock without sleeping.
    pub fn try_consume_at(&self, key: &K, bytes: u64, now: Instant) -> bool {
        if let Some(b) = self.buckets.read().get(key).cloned() {
            return b.try_consume_at(bytes, now);
        }
        let mut w = self.buckets.write();
        let bucket = w
            .entry(key.clone())
            .or_insert_with(|| Arc::new(TokenBucket::new(self.capacity_bytes, self.rate_bps)))
            .clone();
        drop(w);
        bucket.try_consume_at(bytes, now)
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
    }

    /// Drops buckets whose `last_refill` is older than `idle` before
    /// `now`. Convenience wrapper over [`Self::retain`] that captures
    /// the typical idle-GC pattern.
    pub fn retain_active(&self, idle: Duration, now: Instant) {
        let mut w = self.buckets.write();
        w.retain(|_, bucket| now.saturating_duration_since(bucket.last_refill()) < idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
