//! Runtime-updatable per-key rate policy.
//!
//! [`IdentityLimiter`](crate::IdentityLimiter) gives every key the same fixed
//! `(capacity, rate)` for the lifetime of the registry. [`RatePolicyHandle`]
//! is the policy-driven variant a deployer's refresh loop can feed at runtime:
//! a network-wide default plus per-key overrides (a different cap, or a full
//! exemption), applied to live keys without any reconnect.
//!
//! ## Update semantics
//!
//! [`RatePolicyHandle::set_policy`] swaps the whole policy and CLEARS the live
//! buckets: every key re-resolves against the new policy on its next consume
//! and restarts with a full burst budget. Resetting in-flight budgets on a
//! policy change is deliberate: it keeps the hot path a single map lookup
//! (no per-packet policy comparison) and a refresh loop updates rarely.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::TokenBucket;

/// One bandwidth cap: burst capacity plus sustained refill rate, both in
/// BYTES (`rate_bps` is bytes/second, the same convention as the rest of
/// this crate; a product-level bits-per-second figure must be divided by 8
/// by the caller).
///
/// A `RateSpec` always refills (`rate_bps >= 1` by construction), so it can
/// never build the panicking zero-rate [`TokenBucket`]; "no cap" is
/// represented by the ABSENCE of a spec (`None`), never by a sentinel value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateSpec {
    capacity_bytes: u64,
    rate_bps: u64,
}

impl RateSpec {
    /// Builds a spec, or `None` when `rate_bps == 0` (an unrefillable bucket
    /// is a caller bug; map an admin-side "0 = unlimited" convention to no
    /// spec instead of passing the zero through).
    #[must_use]
    pub fn new(capacity_bytes: u64, rate_bps: u64) -> Option<Self> {
        if rate_bps == 0 {
            return None;
        }
        Some(Self {
            capacity_bytes,
            rate_bps,
        })
    }

    /// Spec whose burst capacity is one second of traffic at `rate_bps`,
    /// the shape a plain "N bytes/second" cap wants: brief bursts absorb,
    /// sustained throughput converges on the rate.
    #[must_use]
    pub fn one_second_burst(rate_bps: u64) -> Option<Self> {
        Self::new(rate_bps, rate_bps)
    }

    /// Max burst size in bytes.
    #[must_use]
    pub fn capacity_bytes(self) -> u64 {
        self.capacity_bytes
    }

    /// Sustained refill rate in bytes/second.
    #[must_use]
    pub fn rate_bps(self) -> u64 {
        self.rate_bps
    }
}

/// Per-key exception to the policy default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateOverride {
    /// This key is exempt: no cap, whatever the default says.
    Unlimited,
    /// This key runs its own spec instead of the default (raise or lower).
    Limit(RateSpec),
}

/// The resolvable policy: a network default plus per-key exceptions.
struct Policy<K> {
    default: Option<RateSpec>,
    overrides: HashMap<K, RateOverride>,
}

struct PolicyInner<K> {
    policy: RwLock<Policy<K>>,
    /// Lazily-built buckets, one per key that resolved to a spec. A key that
    /// resolves to unlimited stores nothing, so an all-exempt population
    /// costs no memory and no per-key state.
    buckets: RwLock<HashMap<K, Arc<TokenBucket>>>,
}

/// Shared, runtime-updatable per-key limiter. `Clone` is a handle clone:
/// every clone reads and feeds the SAME policy and bucket state, which is
/// what lets a refresh loop update the policy while the datapath consumes.
///
/// A fresh handle carries an empty policy (no default, no overrides), so it
/// admits everything until first fed via [`Self::set_policy`].
pub struct RatePolicyHandle<K: Eq + Hash + Clone> {
    inner: Arc<PolicyInner<K>>,
}

impl<K: Eq + Hash + Clone> Clone for RatePolicyHandle<K> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<K: Eq + Hash + Clone> Default for RatePolicyHandle<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash + Clone> RatePolicyHandle<K> {
    /// An empty policy: no default, no overrides, everything admitted.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(PolicyInner {
                policy: RwLock::new(Policy {
                    default: None,
                    overrides: HashMap::new(),
                }),
                buckets: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Atomically replaces the whole policy (default + overrides) and resets
    /// the live buckets, so the change reaches every key on its next consume
    /// without any reconnect (see the module docs for the reset semantics).
    pub fn set_policy(&self, default: Option<RateSpec>, overrides: HashMap<K, RateOverride>) {
        {
            let mut p = self.inner.policy.write();
            p.default = default;
            p.overrides = overrides;
        }
        self.inner.buckets.write().clear();
    }

    /// The current network default, `None` when uncapped.
    #[must_use]
    pub fn default_spec(&self) -> Option<RateSpec> {
        self.inner.policy.read().default
    }

    /// The spec `key` runs under the current policy, `None` when unlimited
    /// (exempt override, or no override and no default).
    #[must_use]
    pub fn resolve(&self, key: &K) -> Option<RateSpec> {
        let p = self.inner.policy.read();
        match p.overrides.get(key) {
            Some(RateOverride::Unlimited) => None,
            Some(RateOverride::Limit(spec)) => Some(*spec),
            None => p.default,
        }
    }

    /// Tries to consume `bytes` on behalf of `key` against its resolved
    /// spec. `true` admits (an unlimited key always admits); `false` means
    /// the caller must drop. Builds the key's bucket on first use.
    pub fn try_consume(&self, key: &K, bytes: u64) -> bool {
        self.try_consume_at(key, bytes, Instant::now())
    }

    /// Same as [`Self::try_consume`] with an explicit `now`, so tests can
    /// drive a deterministic clock without sleeping.
    pub fn try_consume_at(&self, key: &K, bytes: u64, now: Instant) -> bool {
        if let Some(b) = self.inner.buckets.read().get(key).cloned() {
            return b.try_consume_at(bytes, now);
        }
        let Some(spec) = self.resolve(key) else {
            return true;
        };
        let mut w = self.inner.buckets.write();
        let bucket = w
            .entry(key.clone())
            .or_insert_with(|| Arc::new(TokenBucket::new(spec.capacity_bytes, spec.rate_bps)))
            .clone();
        drop(w);
        bucket.try_consume_at(bytes, now)
    }

    /// Number of live buckets (= capped keys seen since the last policy
    /// update or sweep). Metrics/tests only.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.inner.buckets.read().len()
    }

    /// Drops `key`'s bucket, if any. Teardown hook for a caller that knows
    /// the key left; the key simply re-builds a full bucket if it returns.
    pub fn remove(&self, key: &K) {
        self.inner.buckets.write().remove(key);
    }

    /// Drops buckets idle (no consume attempt) for at least `idle` before
    /// `now`. A key idle that long has fully refilled anyway, so dropping
    /// its bucket changes nothing for it and bounds memory across churn.
    pub fn retain_active(&self, idle: Duration, now: Instant) {
        let mut w = self.inner.buckets.write();
        w.retain(|_, bucket| now.saturating_duration_since(bucket.last_refill()) < idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(capacity: u64, rate: u64) -> RateSpec {
        RateSpec::new(capacity, rate).expect("non-zero rate")
    }

    #[test]
    fn rate_spec_refuses_a_zero_rate() {
        assert_eq!(RateSpec::new(100, 0), None);
        assert_eq!(RateSpec::one_second_burst(0), None);
        assert_eq!(
            RateSpec::one_second_burst(500).map(RateSpec::capacity_bytes),
            Some(500)
        );
    }

    #[test]
    fn empty_policy_admits_everything_and_tracks_nothing() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        assert!(h.try_consume(&"alice", u64::MAX));
        assert!(h.try_consume(&"alice", u64::MAX));
        assert_eq!(
            h.tracked_count(),
            0,
            "an unlimited key must not allocate a bucket"
        );
    }

    #[test]
    fn default_caps_any_key() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        h.set_policy(Some(spec(100, 1)), HashMap::new());
        let now = Instant::now();
        assert!(h.try_consume_at(&"alice", 100, now));
        assert!(!h.try_consume_at(&"alice", 1, now), "budget exhausted");
        // Another key gets its own independent full bucket.
        assert!(h.try_consume_at(&"bob", 100, now));
    }

    #[test]
    fn override_replaces_the_default_for_its_key_only() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        let mut overrides = HashMap::new();
        overrides.insert("vip", RateOverride::Limit(spec(1_000, 1)));
        h.set_policy(Some(spec(100, 1)), overrides);
        let now = Instant::now();
        assert!(h.try_consume_at(&"vip", 500, now), "raised cap applies");
        assert!(
            !h.try_consume_at(&"alice", 500, now),
            "other keys keep the default"
        );
    }

    #[test]
    fn exempt_key_is_never_limited_and_stores_no_bucket() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        let mut overrides = HashMap::new();
        overrides.insert("team", RateOverride::Unlimited);
        h.set_policy(Some(spec(100, 1)), overrides);
        assert!(h.try_consume(&"team", u64::MAX));
        assert!(h.try_consume(&"team", u64::MAX));
        assert_eq!(h.tracked_count(), 0);
    }

    #[test]
    fn live_update_takes_effect_without_a_new_handle() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        h.set_policy(Some(spec(100, 1)), HashMap::new());
        let now = Instant::now();
        assert!(h.try_consume_at(&"alice", 100, now));
        assert!(
            !h.try_consume_at(&"alice", 50, now),
            "capped under policy 1"
        );

        // Uncap: the previously exhausted key must admit immediately.
        h.set_policy(None, HashMap::new());
        assert!(h.try_consume_at(&"alice", 1_000_000, now));

        // Re-cap: takes effect again, with a fresh full bucket.
        h.set_policy(Some(spec(200, 1)), HashMap::new());
        assert!(h.try_consume_at(&"alice", 200, now));
        assert!(!h.try_consume_at(&"alice", 1, now));
    }

    #[test]
    fn policy_change_resets_burst_budgets() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        h.set_policy(Some(spec(100, 1)), HashMap::new());
        let now = Instant::now();
        assert!(h.try_consume_at(&"alice", 100, now));
        // Same default re-applied: the documented semantics restart every
        // key with a full bucket.
        h.set_policy(Some(spec(100, 1)), HashMap::new());
        assert!(h.try_consume_at(&"alice", 100, now));
    }

    #[test]
    fn clones_share_policy_and_buckets() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        let feeder = h.clone();
        feeder.set_policy(Some(spec(100, 1)), HashMap::new());
        let now = Instant::now();
        assert!(h.try_consume_at(&"alice", 100, now));
        assert!(
            !feeder.try_consume_at(&"alice", 1, now),
            "clones must consume from the same bucket"
        );
    }

    #[test]
    fn capped_bucket_refills_at_its_rate() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        h.set_policy(Some(spec(100, 1_000)), HashMap::new());
        let now = Instant::now();
        assert!(h.try_consume_at(&"alice", 100, now));
        assert!(!h.try_consume_at(&"alice", 100, now));
        let later = now + Duration::from_millis(200);
        assert!(
            h.try_consume_at(&"alice", 100, later),
            "200ms at 1000 B/s must refill the 100 B capacity"
        );
    }

    #[test]
    fn remove_and_retain_active_gc_buckets() {
        let h: RatePolicyHandle<u32> = RatePolicyHandle::new();
        h.set_policy(Some(spec(100, 1)), HashMap::new());
        let now = Instant::now();
        assert!(h.try_consume_at(&1, 1, now));
        assert!(h.try_consume_at(&2, 1, now));
        assert_eq!(h.tracked_count(), 2);
        h.remove(&1);
        assert_eq!(h.tracked_count(), 1);
        // Key 2's bucket last consumed at `now`; an idle sweep 10s later
        // with a 5s TTL drops it.
        h.retain_active(Duration::from_secs(5), now + Duration::from_secs(10));
        assert_eq!(h.tracked_count(), 0);
        // The key is not banned, only forgotten: it returns with a full
        // bucket.
        assert!(h.try_consume_at(&2, 100, now + Duration::from_secs(10)));
    }

    #[test]
    fn resolve_reports_the_effective_spec() {
        let h: RatePolicyHandle<&str> = RatePolicyHandle::new();
        let mut overrides = HashMap::new();
        overrides.insert("vip", RateOverride::Limit(spec(1_000, 500)));
        overrides.insert("team", RateOverride::Unlimited);
        h.set_policy(Some(spec(100, 50)), overrides);
        assert_eq!(h.resolve(&"vip"), Some(spec(1_000, 500)));
        assert_eq!(h.resolve(&"team"), None);
        assert_eq!(h.resolve(&"alice"), Some(spec(100, 50)));
        assert_eq!(h.default_spec(), Some(spec(100, 50)));
    }
}
