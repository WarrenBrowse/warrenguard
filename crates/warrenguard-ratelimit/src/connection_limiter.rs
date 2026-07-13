//! Per-key connection-attempt rate limiter (events-based, not bytes).
//!
//! Used by the Warren exit accept loop to protect against a single subscriber
//! spamming connect/disconnect cycles, which would otherwise tie up handshake
//! CPU + allowlist lookups even when the subscription is valid.
//!
//! ## Model
//!
//! Simple token bucket where one token = one connection attempt:
//! - `burst`: max attempts allowed in a single burst (lazy init to full bucket).
//! - `refill_interval`: how often one token is regenerated.
//!
//! A subscriber that bursts up to `burst` connects, then is throttled to one
//! attempt per `refill_interval` until idle. Bursting back to full requires
//! `burst * refill_interval` of idle time.
//!
//! Distinct from the bytes-based [`crate::IdentityLimiter`], which controls
//! bandwidth once the tunnel is up. The connection limiter fires earlier, at
//! the handshake authentication boundary, before per-tunnel resources are
//! committed.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Hard cap on tracked keys, a memory backstop so an IP-spoofing / pubkey
/// flood cannot grow the map unbounded even if the caller forgets to schedule
/// [`ConnectionRateLimiter::retain_active`]. Mirrors the nonce-store hard cap
/// elsewhere. When the map is full of genuinely-active keys, a brand-new key
/// is refused (fail-closed) rather than admitted at the cost of unbounded RAM.
const MAX_TRACKED_KEYS: usize = 1_000_000;

#[derive(Debug)]
struct State {
    tokens: u32,
    last_refill: Instant,
}

/// Per-key connection-attempt rate limiter.
///
/// The key type is generic so the caller can use `WarrenPubkey`, `IpAddr`, or
/// any other identity. The exit binary keys per pubkey (subscriber-stable);
/// `IpAddr` would be useful for an anti-DDoS layer that runs before pubkey
/// authentication.
#[derive(Debug)]
pub struct ConnectionRateLimiter<K: Eq + Hash + Clone> {
    burst: u32,
    refill_interval: Duration,
    state: RwLock<HashMap<K, State>>,
}

impl<K: Eq + Hash + Clone> ConnectionRateLimiter<K> {
    /// Builds a new limiter with the given burst (1..=u32::MAX) and refill
    /// interval (must be non-zero).
    ///
    /// # Panics
    ///
    /// Panics if `burst == 0` or if `refill_interval.is_zero()` because both
    /// produce nonsensical limits.
    #[must_use]
    pub fn new(burst: u32, refill_interval: Duration) -> Self {
        assert!(burst > 0, "ConnectionRateLimiter burst must be > 0");
        assert!(
            !refill_interval.is_zero(),
            "ConnectionRateLimiter refill_interval must be > 0"
        );
        Self {
            burst,
            refill_interval,
            state: RwLock::new(HashMap::new()),
        }
    }

    /// Tries to acquire one connection token for `key`. Returns true if the
    /// attempt is granted (counter decremented), false if the bucket is empty.
    pub fn try_acquire(&self, key: &K) -> bool {
        self.try_acquire_at(key, Instant::now())
    }

    /// Same as [`Self::try_acquire`] but with an explicit `now`, for
    /// deterministic tests that drive the clock manually.
    pub fn try_acquire_at(&self, key: &K, now: Instant) -> bool {
        let mut w = self.state.write();
        // Memory backstop: only relevant when inserting a brand-new key at the
        // cap. First drop entries idle long enough to have fully refilled to
        // baseline (lossless: a forgotten key re-inits to a full bucket). If
        // the map is still saturated by actively-limited keys, refuse the new
        // key rather than grow unbounded.
        if !w.contains_key(key) && w.len() >= MAX_TRACKED_KEYS {
            let full_recovery = self.refill_interval.saturating_mul(self.burst);
            w.retain(|_, st| now.saturating_duration_since(st.last_refill) < full_recovery);
            if w.len() >= MAX_TRACKED_KEYS {
                return false;
            }
        }
        let entry = w.entry(key.clone()).or_insert(State {
            tokens: self.burst,
            last_refill: now,
        });
        // Refill based on time elapsed since the last refill instant.
        let elapsed = now.saturating_duration_since(entry.last_refill);
        let refill_nanos = self.refill_interval.as_nanos();
        // `checked_div` yields None when the interval is zero (disabled
        // refill) -> 0 refills. Saturating to u32::MAX is safe: u32 can
        // express up to ~4.2B refills which exceeds anything reasonable.
        let refills = elapsed
            .as_nanos()
            .checked_div(refill_nanos)
            .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX));
        if refills > 0 {
            entry.tokens = entry.tokens.saturating_add(refills).min(self.burst);
            // Advance last_refill by the exact number of consumed intervals
            // rather than to `now`, to preserve sub-interval fractional time.
            entry.last_refill = entry
                .last_refill
                .checked_add(self.refill_interval.saturating_mul(refills))
                .unwrap_or(now);
        }
        if entry.tokens > 0 {
            entry.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Number of tracked keys. Useful for metrics + tests.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.state.read().len()
    }

    /// Garbage-collects state entries whose `last_refill` is older than `idle`
    /// before `now`. Call periodically (e.g. every 5 minutes) to avoid an
    /// unbounded map for ephemeral subscribers.
    pub fn retain_active(&self, idle: Duration, now: Instant) {
        let mut w = self.state.write();
        w.retain(|_, st| now.saturating_duration_since(st.last_refill) < idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_consumed_then_rate_limited() {
        let lim: ConnectionRateLimiter<&str> =
            ConnectionRateLimiter::new(5, Duration::from_secs(60));
        let now = Instant::now();
        for _ in 0..5 {
            assert!(lim.try_acquire_at(&"alice", now), "burst should pass");
        }
        assert!(
            !lim.try_acquire_at(&"alice", now),
            "6th attempt should be rate-limited"
        );
    }

    #[test]
    fn refill_after_interval_grants_one_token() {
        let lim: ConnectionRateLimiter<&str> =
            ConnectionRateLimiter::new(5, Duration::from_secs(60));
        let now = Instant::now();
        for _ in 0..5 {
            assert!(lim.try_acquire_at(&"alice", now));
        }
        let later = now + Duration::from_secs(60);
        assert!(
            lim.try_acquire_at(&"alice", later),
            "after one interval, 1 token should be available"
        );
        assert!(
            !lim.try_acquire_at(&"alice", later),
            "after consuming the refilled token, next attempt should fail"
        );
    }

    #[test]
    fn refill_caps_at_burst() {
        let lim: ConnectionRateLimiter<&str> =
            ConnectionRateLimiter::new(3, Duration::from_secs(60));
        let now = Instant::now();
        // Drain the bucket.
        for _ in 0..3 {
            assert!(lim.try_acquire_at(&"alice", now));
        }
        // Idle 10 intervals: refill should cap at burst, not exceed it.
        let later = now + Duration::from_secs(600);
        for _ in 0..3 {
            assert!(lim.try_acquire_at(&"alice", later));
        }
        assert!(
            !lim.try_acquire_at(&"alice", later),
            "burst is the ceiling regardless of idle time"
        );
    }

    #[test]
    fn independent_keys() {
        let lim: ConnectionRateLimiter<&str> =
            ConnectionRateLimiter::new(2, Duration::from_secs(60));
        let now = Instant::now();
        assert!(lim.try_acquire_at(&"alice", now));
        assert!(lim.try_acquire_at(&"alice", now));
        assert!(!lim.try_acquire_at(&"alice", now));
        assert!(lim.try_acquire_at(&"bob", now), "bob has his own bucket");
        assert!(lim.try_acquire_at(&"bob", now));
        assert!(!lim.try_acquire_at(&"bob", now));
    }

    #[test]
    fn retain_active_drops_idle_keys() {
        let lim: ConnectionRateLimiter<&str> =
            ConnectionRateLimiter::new(5, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(lim.try_acquire_at(&"alice", t0));
        assert!(lim.try_acquire_at(&"bob", t0 + Duration::from_secs(30)));
        assert_eq!(lim.tracked_count(), 2);
        // GC entries idle more than 45s before t0 + 60s (= alice only).
        lim.retain_active(Duration::from_secs(45), t0 + Duration::from_secs(60));
        assert_eq!(lim.tracked_count(), 1);
    }

    #[test]
    #[should_panic(expected = "burst must be > 0")]
    fn burst_zero_panics() {
        let _: ConnectionRateLimiter<u32> = ConnectionRateLimiter::new(0, Duration::from_secs(1));
    }

    #[test]
    #[should_panic(expected = "refill_interval must be > 0")]
    fn refill_zero_panics() {
        let _: ConnectionRateLimiter<u32> = ConnectionRateLimiter::new(5, Duration::ZERO);
    }
}
