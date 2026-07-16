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

    /// Pick the varied datagram size for one cover emission (idle elapsed)
    /// and re-arm the next deadline relative to `now`. The size is in
    /// `[IDLE_COVER_MIN_SIZE, max]`.
    ///
    /// This is the emission primitive both cover consumers share: the
    /// mono-conn pump wraps it in [`Self::fire`] to build the raw datagram,
    /// while [`IdleCoverDriver`] (the session-agnostic driver behind the
    /// multi-hop / SDK datapaths) turns it into a padding length. Keeping
    /// the size distribution in one method is what makes the idle footprint
    /// byte-identical across every datapath rather than re-derived per home.
    pub fn fire_size(&mut self, now: Instant) -> usize {
        let size = self.min_size + (self.next_u64() as usize % (self.span_size + 1));
        self.arm(now);
        size
    }

    /// Produce one cover datagram (idle elapsed) and re-arm the next
    /// deadline relative to `now`. The datagram has a varied size in
    /// `[IDLE_COVER_MIN_SIZE, max]` and first byte
    /// [`DAITA_DUMMY_FIRST_BYTE`], so the peer drops it via
    /// [`crate::is_daita_dummy`].
    #[must_use]
    pub fn fire(&mut self, now: Instant) -> Vec<u8> {
        // Constant 0xFF fill: the marker is the first byte; the rest is
        // non-secret padding (QUIC encrypts the whole datagram).
        vec![DAITA_DUMMY_FIRST_BYTE; self.fire_size(now)]
    }
}

/// A live tunnel session cover traffic can be driven over. The engine's
/// mono-conn pump emits cover inline; the split-task datapaths (the
/// multi-hop supervised pump, and the SDK's userland proxy sessions) drive
/// it through this seam instead, so the jitter/size scheduler
/// ([`IdleCover`]) has a single home rather than a re-implementation per
/// consumer.
pub trait CoverSink: Send + Sync + 'static {
    /// Sends one cover (dummy) datagram carrying `padding_len` padding bytes
    /// after the discriminator. Returns `false` if the tunnel is gone (the
    /// driver then stops). A `bool` keeps the trait free of each session's
    /// distinct error type.
    fn send_cover(&self, padding_len: usize) -> bool;
    /// The largest inner payload a cover datagram can carry on the current
    /// path. Seeds the scheduler's size cap so a dummy never exceeds the MTU.
    fn max_inner_payload(&self) -> usize;
    /// A stable, connection-local id used only to seed the jitter PRNG (never
    /// on the wire), so two concurrent tunnels do not share a cover schedule.
    fn cover_seed(&self) -> u64;
}

/// Drives idle cover traffic for a [`CoverSink`] session. Construct with
/// [`new`](Self::new), spawn [`run`](Self::run), and report real traffic
/// through a [`handle`](Self::handle) so cover stays silent under load.
///
/// This is the session-scoped driver: it owns one session for that session's
/// lifetime (the SDK re-creates it per dial). The multi-hop supervised pump,
/// whose session is swapped on reconnect behind a watch channel, drives the
/// same [`IdleCover`] scheduler directly instead of holding a fixed session.
pub struct IdleCoverDriver<S: CoverSink> {
    session: std::sync::Arc<S>,
    cover: std::sync::Mutex<IdleCover>,
    wake: tokio::sync::Notify,
    covers_sent: std::sync::atomic::AtomicU64,
}

impl<S: CoverSink> IdleCoverDriver<S> {
    /// Builds a driver for `session`, arming the first cover deadline now.
    #[must_use]
    pub fn new(session: std::sync::Arc<S>) -> std::sync::Arc<Self> {
        let cover = IdleCover::new(
            session.cover_seed(),
            Instant::now(),
            Some(session.max_inner_payload()),
        );
        std::sync::Arc::new(Self {
            session,
            cover: std::sync::Mutex::new(cover),
            wake: tokio::sync::Notify::new(),
            covers_sent: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// A cheap, cloneable handle the datapath uses to report real traffic.
    #[must_use]
    pub fn handle(self: &std::sync::Arc<Self>) -> IdleCoverDriverHandle<S> {
        IdleCoverDriverHandle(std::sync::Arc::clone(self))
    }

    /// Number of cover datagrams emitted so far (observability / tests).
    #[must_use]
    pub fn covers_sent(&self) -> u64 {
        self.covers_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Runs the cover loop until `stop` is notified or the tunnel closes (a
    /// cover send then errors). The loop never holds the lock across an
    /// `.await`, and the cover send is synchronous, so it cannot stall the
    /// runtime.
    pub async fn run(self: std::sync::Arc<Self>, stop: std::sync::Arc<tokio::sync::Notify>) {
        loop {
            // Arm the wake waiter BEFORE reading the deadline so an activity
            // report that lands between the two cannot be missed for a cycle.
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();

            let deadline = self.lock().deadline();
            let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
            tokio::pin!(sleep);
            tokio::select! {
                () = &mut sleep => {}
                () = &mut wake => continue,
                () = stop.notified() => return,
            }

            // A cover dummy is one discriminator byte plus `padding_len`
            // padding bytes, so the on-wire plaintext size equals the
            // scheduler's chosen datagram size.
            let padding_len = self.lock().fire_size(Instant::now()).saturating_sub(1);
            if !self.session.send_cover(padding_len) {
                // The tunnel is gone; stop (the session is finished).
                return;
            }
            self.covers_sent
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, IdleCover> {
        self.cover.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A cloneable handle the datapath uses to report real traffic, silencing
/// cover for the next interval. Optional: if the datapath never reports, the
/// driver still emits on every jittered interval (correct, just not
/// load-optimized).
#[derive(Clone)]
pub struct IdleCoverDriverHandle<S: CoverSink>(std::sync::Arc<IdleCoverDriver<S>>);

impl<S: CoverSink> IdleCoverDriverHandle<S> {
    /// Reports real application traffic (uplink or downlink) at this instant,
    /// pushing the next cover emission out by a fresh jittered interval.
    pub fn note_activity(&self) {
        self.0.lock().note_activity(Instant::now());
        self.0.wake.notify_one();
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

    #[test]
    fn fire_datagram_length_equals_fire_size_for_the_same_rng_stream() {
        // `fire` must be exactly `fire_size` wrapped in a 0xFF fill: same seed,
        // same `now` must produce a datagram whose length equals the size the
        // size-only primitive returns, proving the two did not diverge (the
        // reason a single scheduler can back both the raw-datagram pump and the
        // padding-length driver).
        let now = Instant::now();
        let mut a = IdleCover::new(77, now, Some(1280));
        let mut b = IdleCover::new(77, now, Some(1280));
        for _ in 0..64 {
            let size = a.fire_size(now);
            let dummy = b.fire(now);
            assert_eq!(
                dummy.len(),
                size,
                "fire() length must equal fire_size() on an identical RNG stream"
            );
        }
    }

    /// A fake [`CoverSink`] recording the padding lengths it was asked to send.
    struct RecordingSink {
        sent: std::sync::Mutex<Vec<usize>>,
        alive: std::sync::atomic::AtomicBool,
    }
    impl CoverSink for RecordingSink {
        fn send_cover(&self, padding_len: usize) -> bool {
            if !self.alive.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            self.sent.lock().unwrap().push(padding_len);
            true
        }
        fn max_inner_payload(&self) -> usize {
            1280
        }
        fn cover_seed(&self) -> u64 {
            0xABCD
        }
    }

    #[tokio::test(start_paused = true)]
    async fn driver_emits_padded_dummies_on_the_jittered_schedule() {
        let sink = std::sync::Arc::new(RecordingSink {
            sent: std::sync::Mutex::new(Vec::new()),
            alive: std::sync::atomic::AtomicBool::new(true),
        });
        let driver = IdleCoverDriver::new(std::sync::Arc::clone(&sink));
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        let run = tokio::spawn(driver.clone().run(stop.clone()));

        // With time paused, advance past several max intervals so the loop must
        // fire multiple covers; every emitted padding must be within the
        // scheduler's size bounds (minus the one discriminator byte).
        tokio::time::advance(IDLE_COVER_MAX_INTERVAL * 5).await;
        tokio::task::yield_now().await;
        stop.notify_one();
        let _ = run.await;

        let sent = sink.sent.lock().unwrap().clone();
        assert!(
            !sent.is_empty(),
            "driver must emit at least one cover over five idle intervals"
        );
        assert_eq!(
            sent.len() as u64,
            driver.covers_sent(),
            "covers_sent counter must match the sends the sink observed"
        );
        for pad in sent {
            assert!(
                (IDLE_COVER_MIN_SIZE - 1..=IDLE_COVER_MAX_SIZE_CAP - 1).contains(&pad),
                "padding {pad} out of [min-1, cap-1] (one discriminator byte precedes it)"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn driver_stops_when_the_sink_reports_the_tunnel_gone() {
        let sink = std::sync::Arc::new(RecordingSink {
            sent: std::sync::Mutex::new(Vec::new()),
            alive: std::sync::atomic::AtomicBool::new(false),
        });
        let driver = IdleCoverDriver::new(std::sync::Arc::clone(&sink));
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        let run = tokio::spawn(driver.clone().run(stop));
        tokio::time::advance(IDLE_COVER_MAX_INTERVAL * 2).await;
        // The first send returns false (tunnel gone), so run must return on its
        // own without the stop signal ever firing.
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("run must return once the sink reports the tunnel gone")
            .expect("run task must not panic");
        assert_eq!(driver.covers_sent(), 0, "a failed send emits no cover");
    }
}
