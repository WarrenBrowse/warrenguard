//! Generic exponential backoff with full jitter.
//!
//! Pattern from the AWS Architecture Blog (Marc Brooker,
//! "Exponential Backoff and Jitter", 2015): the first attempt fires
//! immediately, then each subsequent delay is uniformly sampled in
//! `[current / 2, current]` where `current` doubles up to a hard cap.
//! Full jitter avoids thundering-herd retries when many callers race
//! against the same backend.
//!
//! Three pre-built schedules cover the Warren retry call sites:
//!
//! - [`Backoff::HANDSHAKE`]: 500 ms base, 15 s ceiling, used for QUIC
//!   connect retries. Ceiling tuned down from 30 s to bring the
//!   multi-hop worst-case reconnect window below 15 s instead of the
//!   31 s observed on the bench.
//! - [`Backoff::BACKGROUND`]: 1 s base, 60 s ceiling, used for
//!   long-running heartbeat loops.
//! - [`Backoff::SHORT`]: 200 ms base, 5 s ceiling, used for snappy
//!   calls like DNS resolution or a short REST request.
//!
//! Callers iterate the schedule with [`Backoff::take`] and `sleep`
//! between attempts. A typical retry loop:
//!
//! ```no_run
//! use warrenguard_backoff::Backoff;
//! # fn try_connect() -> Result<(), ()> { Ok(()) }
//! for delay in Backoff::HANDSHAKE.take(5) {
//!     std::thread::sleep(delay);
//!     if try_connect().is_ok() {
//!         break;
//!     }
//! }
//! ```
//!
//! Inside an async runtime, swap `std::thread::sleep` for the
//! runtime's `sleep` (`tokio::time::sleep(delay).await` etc.).
//!
//! # Not for NAT-PMP
//!
//! `warren-natpmp-client` carries its own RFC 6886 §3.1 backoff
//! (initial 250 ms, doubled, 5 retries, ~7.75 s total). That schedule
//! is protocol-mandated and stays exactly as it is: this crate only
//! targets generic retry call sites.

#![forbid(unsafe_code)]

use std::iter::FusedIterator;
use std::time::Duration;

use rand::RngExt;

/// Exponential backoff schedule (base + ceiling).
///
/// The schedule is purely descriptive: nothing happens until
/// [`Backoff::take`] turns it into a [`BackoffIter`].
///
/// `base` should be `<=` `max`; if the caller violates this, the
/// iterator silently clamps the effective base to `max` so the
/// `delay <= max` invariant always holds.
#[derive(Clone, Copy, Debug)]
#[must_use = "a Backoff schedule does nothing until you call `.take(n)`"]
pub struct Backoff {
    /// Initial non-zero delay (used as the first jitter upper bound).
    ///
    /// A `base` of [`Duration::ZERO`] is not rejected (both fields are
    /// public and trivially constructed by a deployer), but `jitter_step`
    /// clamps the effective seed to a minimal positive floor: without the
    /// clamp, a zero base collapses the `next.is_zero()` first-call
    /// sentinel forever, so every subsequent delay stays zero too and the
    /// schedule becomes an infinite zero-delay retry loop hammering the
    /// backend. See [`jitter_step`].
    pub base: Duration,
    /// Hard ceiling: no individual delay ever exceeds this value.
    pub max: Duration,
}

/// Floor applied to a zero `Backoff::base` so the schedule always makes
/// forward progress instead of getting stuck re-arming the same zero
/// seed on every call (see the `base` field doc and `jitter_step`).
const MIN_EFFECTIVE_BASE: Duration = Duration::from_nanos(1);

impl Backoff {
    /// QUIC handshake / connect retry profile.
    ///
    /// Base 500 ms, ceiling 15 s. Typical use: 5 attempts. The 15 s
    /// ceiling caps the worst-case multi-hop reconnect window
    /// (supervisor + downstream consumers) at one ceiling hit, vs. the
    /// 31 s observed on the original 30 s ceiling.
    pub const HANDSHAKE: Self = Self {
        base: Duration::from_millis(500),
        max: Duration::from_secs(15),
    };

    /// Long-running background loop profile.
    ///
    /// Base 1 s, ceiling 60 s. Typical use: heartbeat loops that
    /// retry forever via a very large `attempts` count.
    pub const BACKGROUND: Self = Self {
        base: Duration::from_secs(1),
        max: Duration::from_secs(60),
    };

    /// Fast-call retry profile.
    ///
    /// Base 200 ms, ceiling 5 s. Typical use: DNS lookup or a short
    /// REST API call where 3 attempts is enough.
    pub const SHORT: Self = Self {
        base: Duration::from_millis(200),
        max: Duration::from_secs(5),
    };

    /// Build a finite iterator yielding `attempts` successive delays.
    ///
    /// The first yielded delay is always [`Duration::ZERO`] so the
    /// caller can retry immediately; subsequent delays are drawn
    /// from `[current / 2, current]` with `current` doubling up to
    /// [`Backoff::max`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use warrenguard_backoff::Backoff;
    ///
    /// let delays: Vec<Duration> = Backoff::HANDSHAKE.take(3).collect();
    /// assert_eq!(delays.len(), 3);
    /// assert_eq!(delays[0], Duration::ZERO);
    /// for d in &delays {
    ///     assert!(*d <= Backoff::HANDSHAKE.max);
    /// }
    /// ```
    #[must_use = "iterators are lazy and do nothing unless consumed"]
    pub fn take(self, attempts: usize) -> BackoffIter {
        BackoffIter {
            backoff: self,
            remaining: attempts,
            next: Duration::ZERO,
        }
    }

    /// Build an unbounded [`JitterBackoff`] for a supervisor that retries
    /// indefinitely, where the finite [`BackoffIter`] attempt count does not
    /// fit. The first delay is still [`Duration::ZERO`].
    #[must_use]
    pub fn forever(self) -> JitterBackoff {
        JitterBackoff {
            backoff: self,
            next: Duration::ZERO,
        }
    }
}

/// Advances `next` per the full-jitter law and returns this attempt's delay:
/// the first call (when `next` is zero) fires immediately and seeds `next` at
/// `base`; each later call draws from `[current / 2, current]` and doubles up
/// to `max`. Shared by the finite [`BackoffIter`] and the unbounded
/// [`JitterBackoff`] so the two can never drift.
fn jitter_step(backoff: &Backoff, next: &mut Duration) -> Duration {
    if next.is_zero() {
        // Clamp the seed to at least `MIN_EFFECTIVE_BASE` (still capped by
        // `max`): if `base` were zero, an unclamped seed would leave `next`
        // at zero, so every later call would take this same branch and the
        // schedule would return `Duration::ZERO` forever instead of
        // escalating towards `max`.
        let floor = MIN_EFFECTIVE_BASE.min(backoff.max);
        *next = backoff.base.min(backoff.max).max(floor);
        return Duration::ZERO;
    }
    let current = (*next).min(backoff.max);
    *next = current.saturating_mul(2).min(backoff.max);
    let half = current / 2;
    let half_nanos = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
    let jitter_nanos = rand::rng().random_range(0..=half_nanos);
    half + Duration::from_nanos(jitter_nanos)
}

/// Iterator yielding successive backoff delays from a [`Backoff`].
///
/// Created by [`Backoff::take`]. Implements [`ExactSizeIterator`] so
/// the remaining attempt count is observable, and [`FusedIterator`]
/// because the iterator stays at `None` once exhausted.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct BackoffIter {
    backoff: Backoff,
    remaining: usize,
    next: Duration,
}

impl Iterator for BackoffIter {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(jitter_step(&self.backoff, &mut self.next))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for BackoffIter {
    fn len(&self) -> usize {
        self.remaining
    }
}

impl FusedIterator for BackoffIter {}

/// Unbounded full-jitter backoff for supervisors that retry indefinitely,
/// where the finite [`BackoffIter`] attempt count does not fit. Same jitter
/// law: the first [`next_delay`](Self::next_delay) is zero, then each is drawn
/// from `[current / 2, current]` doubling up to the ceiling.
/// [`reset`](Self::reset) returns to the immediate-retry state, e.g. after a
/// session that stayed healthy long enough to clear the backoff.
#[derive(Clone, Copy, Debug)]
pub struct JitterBackoff {
    backoff: Backoff,
    next: Duration,
}

impl JitterBackoff {
    /// Returns the next delay and advances the schedule.
    #[must_use]
    pub fn next_delay(&mut self) -> Duration {
        jitter_step(&self.backoff, &mut self.next)
    }

    /// Resets to the immediate-retry state (the next delay is zero again).
    pub fn reset(&mut self) {
        self.next = Duration::ZERO;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forever_first_delay_is_immediate_then_bounded_and_unbounded() {
        let mut b = Backoff::HANDSHAKE.forever();
        assert_eq!(
            b.next_delay(),
            Duration::ZERO,
            "the first retry must be immediate, like the finite BackoffIter"
        );
        // Unlike take(n), forever() never exhausts; every delay stays capped.
        for _ in 0..100 {
            assert!(
                b.next_delay() <= Backoff::HANDSHAKE.max,
                "no jittered delay may exceed the ceiling"
            );
        }
    }

    #[test]
    fn reset_restores_immediate_retry() {
        let mut b = Backoff::SHORT.forever();
        assert_eq!(b.next_delay(), Duration::ZERO);
        let _ = b.next_delay();
        assert!(
            b.next_delay() > Duration::ZERO,
            "the schedule advanced past the immediate first delay"
        );
        b.reset();
        assert_eq!(
            b.next_delay(),
            Duration::ZERO,
            "reset must return the schedule to the immediate-retry state"
        );
    }

    #[test]
    fn finite_and_unbounded_share_the_immediate_first_step() {
        assert_eq!(Backoff::BACKGROUND.take(1).next(), Some(Duration::ZERO));
        assert_eq!(Backoff::BACKGROUND.forever().next_delay(), Duration::ZERO);
    }
}
