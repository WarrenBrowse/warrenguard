//! Tests for `warren-backoff`. The expectations encoded here pin the
//! exponential + full-jitter schedule from the AWS Architecture Blog.
//!
//! `handshake_ceiling_is_15_seconds` locks the reduced 15 s ceiling
//! chosen to keep the multi-hop worst-case reconnect under one window.
//! Bumping the ceiling back to 30 s without a deliberate decision will
//! fail this test.

use std::time::Duration;

use proptest::prelude::*;
use warrenguard_backoff::Backoff;

#[test]
fn handshake_ceiling_is_15_seconds() {
    // Anti-regression lock: the tune dropped the ceiling from 30 s to
    // 15 s so a saturated retry window stays under 15 s. The
    // MultiHopSupervisor + `cli_multihop_tun_client_retry` tests
    // transitively rely on this value when sizing the bounded wait.
    // Bump deliberately if a future profile genuinely needs a longer
    // ceiling, but update those consumers too.
    assert_eq!(
        Backoff::HANDSHAKE.max,
        Duration::from_secs(15),
        "Backoff::HANDSHAKE ceiling must stay at 15 s",
    );
    assert_eq!(
        Backoff::HANDSHAKE.base,
        Duration::from_millis(500),
        "Backoff::HANDSHAKE base should remain 500 ms",
    );
}

#[test]
fn background_and_short_profiles_are_locked() {
    // Same anti-regression lock as `handshake_ceiling_is_15_seconds`, for
    // the other two pre-built profiles: their doc comments (`lib.rs`)
    // state the base/ceiling values are load-bearing for the call sites
    // that use them (long-running heartbeat loops for BACKGROUND, snappy
    // DNS/REST retries for SHORT), yet only HANDSHAKE was actually pinned
    // by a test. A silent retune of either would change retry cadence
    // for every consumer without any test noticing.
    assert_eq!(
        Backoff::BACKGROUND.base,
        Duration::from_secs(1),
        "Backoff::BACKGROUND base should remain 1 s",
    );
    assert_eq!(
        Backoff::BACKGROUND.max,
        Duration::from_secs(60),
        "Backoff::BACKGROUND ceiling must stay at 60 s",
    );
    assert_eq!(
        Backoff::SHORT.base,
        Duration::from_millis(200),
        "Backoff::SHORT base should remain 200 ms",
    );
    assert_eq!(
        Backoff::SHORT.max,
        Duration::from_secs(5),
        "Backoff::SHORT ceiling must stay at 5 s",
    );
}

#[test]
fn handshake_first_attempt_is_zero() {
    let mut it = Backoff::HANDSHAKE.take(5);
    assert_eq!(
        it.next(),
        Some(Duration::ZERO),
        "first attempt must be immediate (no delay) so the caller retries right away"
    );
}

#[test]
fn handshake_attempts_count() {
    assert_eq!(Backoff::HANDSHAKE.take(5).count(), 5);
    assert_eq!(Backoff::HANDSHAKE.take(0).count(), 0);
    assert_eq!(Backoff::BACKGROUND.take(128).count(), 128);
}

#[test]
fn len_tracks_remaining_attempts() {
    let mut it = Backoff::HANDSHAKE.take(4);
    assert_eq!(it.len(), 4);
    let _ = it.next();
    assert_eq!(it.len(), 3);
    while it.next().is_some() {}
    assert_eq!(it.len(), 0);
}

#[test]
fn base_zero_does_not_loop_forever_at_zero_delay() {
    // M17 regression: `Backoff { base: Duration::ZERO, .. }` used to
    // collapse `jitter_step`'s `next.is_zero()` first-call sentinel
    // forever, since the seeded `next` (`base.min(max)`) was itself zero:
    // every following call re-entered the "first call" branch and
    // returned `Duration::ZERO` again, producing an infinite zero-delay
    // retry loop that would hammer the backend nonstop despite a sane,
    // non-zero `max`. The internal floor (`MIN_EFFECTIVE_BASE`) guarantees
    // forward progress: the delay strictly escalates and stops being zero
    // within a handful of attempts.
    let mut b = Backoff {
        base: Duration::ZERO,
        max: Duration::from_secs(1),
    }
    .forever();
    assert_eq!(
        b.next_delay(),
        Duration::ZERO,
        "the first attempt is still immediate, matching every other profile"
    );
    let escalated = (0..16).any(|_| b.next_delay() > Duration::ZERO);
    assert!(
        escalated,
        "a zero base must not loop forever at zero delay: the schedule must \
         escalate to a non-zero delay within a bounded number of attempts"
    );
}

#[test]
fn base_greater_than_max_is_clamped() {
    // Defensive clamp: a pathological Backoff with `base > max` must
    // still respect `delay <= max` on every attempt.
    let weird = Backoff {
        base: Duration::from_secs(120),
        max: Duration::from_secs(10),
    };
    for d in weird.take(8) {
        assert!(
            d <= weird.max,
            "clamp violated: delay {d:?} exceeds max {:?}",
            weird.max,
        );
    }
}

#[test]
fn delay_grows_then_caps() {
    // HANDSHAKE: base 500ms, max 15s. After ~5 doublings the schedule
    // saturates, so the tail of a 20-attempt run must sit in
    // `[max/2, max]`.
    let b = Backoff::HANDSHAKE;
    let delays: Vec<Duration> = b.take(20).collect();
    let tail = &delays[delays.len() - 5..];
    for &d in tail {
        assert!(
            d >= b.max / 2 && d <= b.max,
            "saturated delay {d:?} should lie in [max/2, max] = [{:?}, {:?}]",
            b.max / 2,
            b.max,
        );
    }
}

proptest! {
    #[test]
    fn delay_never_exceeds_max(attempts in 0usize..20) {
        let backoff = Backoff::HANDSHAKE;
        for d in backoff.take(attempts) {
            prop_assert!(
                d <= backoff.max,
                "delay {d:?} exceeds max {:?}",
                backoff.max,
            );
        }
    }

    #[test]
    fn jitter_distributes_in_half_range(attempts in 2usize..12) {
        // For every attempt i >= 2 (1-indexed), the delay must fall in
        // `[current_i / 2, current_i]` where
        // `current_i = min(base * 2^(i-2), max)`.
        let b = Backoff::HANDSHAKE;
        let delays: Vec<Duration> = b.take(attempts).collect();
        for (idx, &d) in delays.iter().enumerate().skip(1) {
            let mut current = b.base;
            for _ in 0..(idx - 1) {
                current = current.saturating_mul(2).min(b.max);
            }
            let half = current / 2;
            prop_assert!(
                d >= half,
                "attempt {idx}: delay {d:?} below jitter floor {half:?} (current={current:?})",
            );
            prop_assert!(
                d <= current,
                "attempt {idx}: delay {d:?} above jitter ceiling {current:?}",
            );
        }
    }
}
