//! Warren rate limiter - pure token bucket to throttle bandwidth per
//! identity (`WarrenPubkey`) or per-tunnel.
//!
//! ## Model
//!
//! Classic token bucket. An instance carries:
//! - `capacity_bytes`: max burst size (typically 1 MTU × N to absorb
//!   a small burst without drop).
//! - `rate_bps`: refill rate in bytes/second.
//!
//! On every `try_consume(n)`, we compute how many tokens were
//! replenished since the previous call (`(now - last_refill) * rate`),
//! add them (capped at `capacity`), then consume `n` if possible.
//!
//! ## Typical usage on the Warren exit
//!
//! One bucket per client `WarrenPubkey` -> prevents a single client
//! from saturating the exit's outbound link. Re-checked on every
//! downlink pump before writing to the TUN.

#![warn(missing_docs)]

use std::time::Instant;

use parking_lot::Mutex;

mod connection_limiter;
mod policy;
mod registry;

pub use connection_limiter::ConnectionRateLimiter;
pub use policy::{RateOverride, RatePolicyHandle, RateSpec};
pub use registry::IdentityLimiter;

/// Pure token bucket. Thread-safe via internal `Mutex`; we assume the
/// hot path is fast readers/writers (Mutex overhead << network I/O
/// overhead).
///
/// `pub(crate)` because the public surface of this crate is
/// [`IdentityLimiter`]; the bucket lives behind it.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    capacity_bytes: u64,
    rate_bps: u64,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Current tokens (may be fractional for sub-byte precision).
    tokens: f64,
    /// Last refill timestamp.
    last_refill: Instant,
}

impl TokenBucket {
    /// Creates a full bucket (= `capacity_bytes` tokens available
    /// immediately).
    ///
    /// # Panics
    ///
    /// Panics if `rate_bps == 0` - a bucket without refill is useless
    /// and signals a caller bug (use `u64::MAX` for an effectively
    /// unlimited bucket).
    #[must_use]
    pub(crate) fn new(capacity_bytes: u64, rate_bps: u64) -> Self {
        assert!(
            rate_bps > 0,
            "TokenBucket rate_bps must be > 0 - use u64::MAX to disable"
        );
        Self {
            capacity_bytes,
            rate_bps,
            state: Mutex::new(State {
                #[allow(clippy::cast_precision_loss)]
                tokens: capacity_bytes as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Tries to consume `bytes` tokens. Returns `true` if allowed
    /// (and deducts the tokens), `false` otherwise (state unchanged).
    ///
    /// Refill side-effect: before the decision, we add the tokens
    /// produced since the last call (capped at `capacity_bytes`).
    pub(crate) fn try_consume(&self, bytes: u64) -> bool {
        self.try_consume_at(bytes, Instant::now())
    }

    /// Same as [`Self::try_consume`] but with an explicit `now`. Used
    /// by tests and by `IdentityLimiter::try_consume_at` to drive a
    /// deterministic clock without sleeping.
    pub(crate) fn try_consume_at(&self, bytes: u64, now: Instant) -> bool {
        let mut state = self.state.lock();
        let elapsed = now.saturating_duration_since(state.last_refill);
        let added = elapsed.as_secs_f64() * (self.rate_bps as f64);
        state.tokens = (state.tokens + added).min(self.capacity_bytes as f64);
        state.last_refill = now;

        let need = bytes as f64;
        if state.tokens >= need {
            state.tokens -= need;
            true
        } else {
            false
        }
    }

    /// Returns the last-refill instant of the underlying state.
    /// Used by `IdentityLimiter` to expire idle entries.
    pub(crate) fn last_refill(&self) -> Instant {
        self.state.lock().last_refill
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn new_bucket_starts_full() {
        let b = TokenBucket::new(1_000, 100);
        assert!(b.try_consume(1_000), "fresh bucket should allow capacity");
    }

    #[test]
    fn consume_more_than_capacity_fails() {
        let b = TokenBucket::new(100, 100);
        assert!(
            !b.try_consume(101),
            "must refuse beyond capacity even on a fresh bucket"
        );
        // State is unchanged: we can still consume the full capacity.
        assert!(b.try_consume(100));
    }

    #[test]
    fn empty_bucket_refuses_until_refill() {
        let b = TokenBucket::new(100, 100);
        assert!(b.try_consume(100));
        assert!(!b.try_consume(1), "no tokens left = refuse");
    }

    #[test]
    fn refills_at_rate_over_time() {
        // 1000 B capacity, 1000 B/s refill. Empty → wait 100ms → ~100 B
        // refilled → 100 B should pass, 200 B should fail.
        let b = TokenBucket::new(1_000, 1_000);
        assert!(b.try_consume(1_000));
        assert!(!b.try_consume(50));
        thread::sleep(Duration::from_millis(120));
        // Conservative: 100ms × 1000 B/s = 100 B; we ask 90 B to allow
        // some slack on sleep precision.
        assert!(
            b.try_consume(90),
            "should have refilled enough after ~120ms"
        );
    }

    #[test]
    fn refill_caps_at_capacity() {
        // 100 B cap, 10000 B/s rate (fast). Empty → wait 1s → refill
        // would add 10000 B, but must cap at 100.
        let b = TokenBucket::new(100, 10_000);
        assert!(b.try_consume(100));
        thread::sleep(Duration::from_millis(50));
        // Refill would add 500 B (50ms × 10kB/s); capped at 100.
        assert!(b.try_consume(100), "after refill, full again");
        assert!(!b.try_consume(1), "must not exceed cap");
    }

    #[test]
    fn concurrent_consume_thread_safe() {
        // 1000 tokens, 1 thread × 100 try_consume(10) = 1000 requested.
        // With a very slow rate (1 B/s) only the ~1000 initial pass.
        let b = std::sync::Arc::new(TokenBucket::new(1_000, 1));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let b = b.clone();
                thread::spawn(move || {
                    let mut ok = 0;
                    for _ in 0..100 {
                        if b.try_consume(10) {
                            ok += 1;
                        }
                    }
                    ok
                })
            })
            .collect();
        let total: i32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // 4 threads × 100 = 400 attempts = 4000 B requested; we have
        // 1000 B initial so max 100 successes, plus a handful of very
        // slow refills (negligible as total runtime is on the ms scale).
        assert!(
            (90..=110).contains(&total),
            "total successful consumes outside expected range: {total}"
        );
    }

    #[test]
    #[should_panic(expected = "rate_bps must be > 0")]
    fn rate_zero_panics() {
        let _ = TokenBucket::new(100, 0);
    }
}
