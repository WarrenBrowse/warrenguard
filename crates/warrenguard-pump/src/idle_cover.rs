//! Idle cover-traffic scheduler.
//!
//! The QUIC keep-alive emits a fixed 30-byte PING every ~5s while the
//! tunnel is idle, a metronome that no browser produces and that betrays
//! the obfuscation on both the timing and the size axis. This
//! scheduler replaces that beacon: while the link is idle it emits a
//! dummy datagram at a JITTERED interval and a VARIED size, so the idle
//! wire footprint is neither periodic nor fixed-size. The dummy reuses
//! the existing DAITA discriminator (first byte [`crate::DAITA_DUMMY_FIRST_BYTE`]),
//! so the peer drops it before the TUN via [`crate::is_daita_dummy`] with
//! no new wire format. Sending it also refreshes the NAT mapping and
//! resets the idle timeout, which is why the client keep-alive can be
//! disabled when this is active (see
//! `warren_transport_config_client_with_idle_cover`).
//!
//! The scheduler is a pure, deterministic state machine: it owns a small
//! splitmix64 PRNG (the jitter is de-regularization, not a security
//! primitive; the payload is encrypted by QUIC), so it needs no external
//! RNG dependency and its behavior is fully reproducible in tests. The
//! pump calls [`IdleCover::note_activity`] on every real packet (which
//! pushes the deadline out, so cover is silent whenever there is real
//! traffic) and [`IdleCover::fire`] when the deadline elapses.

use std::time::{Duration, Instant};

use crate::DAITA_DUMMY_FIRST_BYTE;

/// Lower bound of the jittered idle interval before a cover datagram is
/// emitted.
pub const IDLE_COVER_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// Upper bound of the jittered idle interval. Kept below the ~30s
/// NAT/CGNAT UDP mapping expiry (so cover refreshes the mapping) and
/// below the 25s client idle timeout (so cover keeps the connection
/// alive), with margin. A dead exit is still detected by the 25s idle
/// timeout once cover datagrams stop being acknowledged.
pub const IDLE_COVER_MAX_INTERVAL: Duration = Duration::from_secs(20);

/// Lower bound of the varied cover datagram size, in bytes. The upper
/// bound is `min(max_datagram_size, 1280)`.
pub const IDLE_COVER_MIN_SIZE: usize = 64;

/// Hard cap on the cover datagram size (full path-MTU floor). The actual
/// max is the connection's negotiated `max_datagram_size` clamped to this.
const IDLE_COVER_MAX_SIZE_CAP: usize = 1280;

// Compile-time guards on the constants this scheduler relies on. The
// interval ceiling must stay strictly under both the NAT mapping expiry
// and the client idle timeout, or cover would stop refreshing the path.
const _: () = assert!(
    IDLE_COVER_MIN_INTERVAL.as_secs() < IDLE_COVER_MAX_INTERVAL.as_secs(),
    "idle cover min interval must be below the max"
);
const _: () = assert!(
    IDLE_COVER_MAX_INTERVAL.as_secs() < 25,
    "idle cover max interval must stay below the 25s client idle timeout"
);
const _: () = assert!(
    IDLE_COVER_MIN_SIZE < IDLE_COVER_MAX_SIZE_CAP,
    "idle cover min size must be below the size cap"
);

/// Jittered idle cover-traffic scheduler. See the module docs.
pub struct IdleCover {
    rng: u64,
    min_interval_us: u64,
    span_interval_us: u64,
    min_size: usize,
    span_size: usize,
    next: Instant,
}

impl IdleCover {
    /// Builds a scheduler seeded by `seed` (the call site uses the QUIC
    /// connection's stable id, which varies per connection), arming the
    /// first deadline relative to `now`. `max_datagram_size` is the
    /// connection's negotiated datagram limit; cover sizes are capped to
    /// `min(it, 1280)` so a dummy never exceeds the path MTU.
    ///
    /// Uses the production [`IDLE_COVER_MIN_INTERVAL`] /
    /// [`IDLE_COVER_MAX_INTERVAL`] bounds; see [`Self::with_interval`] for
    /// the test/tuning seam that injects a different range.
    #[must_use]
    pub fn new(seed: u64, now: Instant, max_datagram_size: Option<usize>) -> Self {
        Self::with_interval(
            seed,
            now,
            max_datagram_size,
            IDLE_COVER_MIN_INTERVAL,
            IDLE_COVER_MAX_INTERVAL,
        )
    }

    /// Same as [`Self::new`] but with an explicit jittered interval range
    /// instead of the fixed production [`IDLE_COVER_MIN_INTERVAL`]..
    /// [`IDLE_COVER_MAX_INTERVAL`] (10-20s). Exists so integration tests can
    /// drive the REAL pump wiring
    /// ([`crate::pump_bidirectional_with_idle_cover_interval`]) with a
    /// short interval instead of waiting ~35s for the production bound to
    /// elapse; the long-running `#[ignore]`d suite still validates the
    /// production interval end to end.
    ///
    /// # Panics
    ///
    /// Panics (debug assertion) if `min_interval > max_interval`: an
    /// inverted range is a caller bug, not a runtime condition.
    #[must_use]
    pub fn with_interval(
        seed: u64,
        now: Instant,
        max_datagram_size: Option<usize>,
        min_interval: Duration,
        max_interval: Duration,
    ) -> Self {
        debug_assert!(
            min_interval <= max_interval,
            "IdleCover::with_interval: min_interval must not exceed max_interval"
        );
        let max_size = max_datagram_size
            .unwrap_or(IDLE_COVER_MAX_SIZE_CAP)
            .clamp(IDLE_COVER_MIN_SIZE, IDLE_COVER_MAX_SIZE_CAP);
        let min_us = min_interval.as_micros() as u64;
        let max_us = max_interval.as_micros() as u64;
        let mut cover = Self {
            // Mix the seed so a small/sequential stable id still yields a
            // well-distributed first interval.
            rng: seed ^ 0x9E37_79B9_7F4A_7C15,
            min_interval_us: min_us,
            span_interval_us: max_us - min_us,
            min_size: IDLE_COVER_MIN_SIZE,
            span_size: max_size - IDLE_COVER_MIN_SIZE,
            next: now,
        };
        cover.arm(now);
        cover
    }

    /// splitmix64: a fast, well-distributed non-cryptographic PRNG. The
    /// jitter only needs to break periodicity, and the cover payload is
    /// encrypted by QUIC, so a CSPRNG would be overkill here.
    fn next_u64(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// (Re)arm the next deadline at `now + jittered interval`.
    fn arm(&mut self, now: Instant) {
        let jitter = self.next_u64() % (self.span_interval_us + 1);
        self.next = now + Duration::from_micros(self.min_interval_us + jitter);
    }

    /// Reset the deadline because real traffic occurred at `now`. While
    /// there is real traffic the deadline keeps moving out, so no cover
    /// datagram is ever emitted during active use (zero overhead).
    pub fn note_activity(&mut self, now: Instant) {
        self.arm(now);
    }

    /// The instant the pump should sleep until before emitting cover.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.next
    }

    /// Produce one cover datagram (idle elapsed) and re-arm the next
    /// deadline relative to `now`. The datagram has a varied size in
    /// `[IDLE_COVER_MIN_SIZE, max]` and first byte
    /// [`DAITA_DUMMY_FIRST_BYTE`], so the peer drops it via
    /// [`crate::is_daita_dummy`].
    #[must_use]
    pub fn fire(&mut self, now: Instant) -> Vec<u8> {
        let size = self.min_size + (self.next_u64() as usize % (self.span_size + 1));
        self.arm(now);
        // Constant 0xFF fill: the marker is the first byte; the rest is
        // non-secret padding (QUIC encrypts the whole datagram).
        vec![DAITA_DUMMY_FIRST_BYTE; size]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_daita_dummy;

    #[test]
    fn new_arms_first_deadline_within_interval_bounds() {
        let now = Instant::now();
        let cover = IdleCover::new(1, now, Some(1280));
        let dl = cover.deadline();
        assert!(
            dl >= now + IDLE_COVER_MIN_INTERVAL && dl <= now + IDLE_COVER_MAX_INTERVAL,
            "first deadline must fall inside [min, max] interval"
        );
    }

    #[test]
    fn with_interval_honours_a_custom_short_range() {
        // The test/tuning seam must actually change the bounds, not just
        // accept the parameters and fall back to the production constants.
        let now = Instant::now();
        let short_min = Duration::from_millis(50);
        let short_max = Duration::from_millis(100);
        let cover = IdleCover::with_interval(3, now, Some(1280), short_min, short_max);
        let dl = cover.deadline();
        assert!(
            dl >= now + short_min && dl <= now + short_max,
            "with_interval must arm the first deadline inside the injected [min, max], \
             not the production [{IDLE_COVER_MIN_INTERVAL:?}, {IDLE_COVER_MAX_INTERVAL:?}]"
        );
    }

    #[test]
    fn new_delegates_to_with_interval_using_the_production_bounds() {
        // `new` must be byte-identical to `with_interval` given the production
        // constants: same seed, same `now` must produce the same first
        // deadline, proving `new` did not diverge into separate logic.
        let now = Instant::now();
        let a = IdleCover::new(9, now, Some(1280)).deadline();
        let b = IdleCover::with_interval(
            9,
            now,
            Some(1280),
            IDLE_COVER_MIN_INTERVAL,
            IDLE_COVER_MAX_INTERVAL,
        )
        .deadline();
        assert_eq!(
            a, b,
            "new() must delegate to with_interval with the production bounds"
        );
    }

    #[test]
    fn note_activity_rearms_relative_to_now() {
        let t0 = Instant::now();
        let mut cover = IdleCover::new(7, t0, Some(1280));
        let later = t0 + Duration::from_secs(100);
        cover.note_activity(later);
        let dl = cover.deadline();
        assert!(
            dl >= later + IDLE_COVER_MIN_INTERVAL && dl <= later + IDLE_COVER_MAX_INTERVAL,
            "note_activity must push the deadline to now+[min,max], silencing cover under traffic"
        );
    }

    #[test]
    fn fire_returns_marked_dummy_within_size_bounds() {
        let now = Instant::now();
        let mut cover = IdleCover::new(42, now, Some(1280));
        for _ in 0..200 {
            let dummy = cover.fire(now);
            assert_eq!(
                dummy.first().copied(),
                Some(DAITA_DUMMY_FIRST_BYTE),
                "cover dummy must carry the DAITA discriminator as its first byte"
            );
            assert!(
                is_daita_dummy(&dummy),
                "cover dummy must classify as a dummy so the peer drops it"
            );
            assert!(
                (IDLE_COVER_MIN_SIZE..=1280).contains(&dummy.len()),
                "cover dummy size {} must be within [min, cap]",
                dummy.len()
            );
        }
    }

    #[test]
    fn fire_varies_both_size_and_interval() {
        let mut now = Instant::now();
        let mut cover = IdleCover::new(0xC0FFEE, now, Some(1280));
        let mut sizes = std::collections::BTreeSet::new();
        let mut intervals = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let before = cover.deadline();
            let gap = before.duration_since(now);
            intervals.insert(gap.as_micros());
            // every interval stays within bounds
            assert!(
                gap >= IDLE_COVER_MIN_INTERVAL && gap <= IDLE_COVER_MAX_INTERVAL,
                "every jittered interval must stay within [min, max]"
            );
            now = before;
            let dummy = cover.fire(now);
            sizes.insert(dummy.len());
        }
        assert!(
            sizes.len() > 1,
            "cover must vary the datagram SIZE, got a single value: defeats the size tell only if varied"
        );
        assert!(
            intervals.len() > 1,
            "cover must vary the INTERVAL, got a single value: a fixed cadence is the very tell we remove"
        );
    }

    #[test]
    fn small_max_datagram_size_clamps_without_panicking() {
        let now = Instant::now();
        // max_datagram_size below the min cover size: size collapses to a
        // single valid value, never panics on the modulo.
        let mut cover = IdleCover::new(5, now, Some(10));
        let dummy = cover.fire(now);
        assert_eq!(
            dummy.len(),
            IDLE_COVER_MIN_SIZE,
            "when the path MTU is below the min cover size, clamp to the min, do not panic"
        );
        assert!(is_daita_dummy(&dummy));
    }
}
