//! RFC 6479-style sliding window anti-replay tracker.
//!
//! The exit side maintains
//! a sliding window of size `1024` (one per `(exit_id, epoch)`). For each
//! decrypted frame's `seq` field, [`ReplayWindow::check_and_record`]
//! decides whether to accept or reject:
//!
//! - `seq` strictly greater than the high-water mark → accept, advance
//!   the window.
//! - `seq` within the window and not yet seen → accept, mark as seen.
//! - `seq` within the window and already seen → reject (replay).
//! - `seq` more than `WINDOW_SIZE` below the high-water mark → reject
//!   (too old).
//!
//! The implementation mirrors the well-tested WireGuard
//! `drivers/net/wireguard/replay.c` algorithm: a `[u64; 16]` bitmap of
//! 1024 bits, where bit at offset `i` (relative to the high-water mark)
//! is `1` iff a frame with `seq = high - i` has already been recorded.
//! Advancing the high-water mark by `d` shifts the bitmap left by `d`
//! bits and zeroes the freshly exposed low bits.

use crate::errors::MultihopError;

/// Sliding-window size in bits. The design specifies 1024.
pub const REPLAY_WINDOW_SIZE: u64 = 1024;

/// Internal alias kept short for the bit-manipulation code below.
const WINDOW_SIZE: u64 = REPLAY_WINDOW_SIZE;

/// Number of `u64` words backing the bitmap (1024 / 64 = 16).
const BITMAP_WORDS: usize = 16;

/// RFC 6479-style sliding window for the receiver-side anti-replay
/// check. One instance per `(exit_id, epoch)`.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest `seq` accepted so far. `None` means "no seq seen yet"
    /// and the next call to [`Self::check_and_record`] is unconditionally
    /// accepted.
    highest: Option<u64>,

    /// Bitmap of seen offsets. `bitmap[0]` bit 0 (LSB) corresponds to
    /// `seq == highest`; bit 1 corresponds to `seq == highest - 1`; and
    /// so on through bit `WINDOW_SIZE - 1`.
    bitmap: [u64; BITMAP_WORDS],
}

impl ReplayWindow {
    /// Construct an empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: None,
            bitmap: [0u64; BITMAP_WORDS],
        }
    }

    /// Return the current high-water mark, or `None` if no seq has been
    /// recorded yet.
    #[must_use]
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Check that `seq` is not a replay and not too old, and record it
    /// as seen.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::Replay`] with the offending `seq` if it has
    ///   already been seen *or* if it falls below the active window.
    ///
    /// `#[inline]`: hot path - called once per inbound multi-hop frame
    /// at the exit. The body short-circuits on the common case (`seq >
    /// highest` straight-line, no bit-test loop) so inlining puts the
    /// straight-line code right at the call site.
    #[inline]
    pub fn check_and_record(&mut self, seq: u64, epoch: u32) -> Result<(), MultihopError> {
        let highest = match self.highest {
            None => {
                self.set_bit(0);
                self.highest = Some(seq);
                return Ok(());
            }
            Some(h) => h,
        };

        if seq > highest {
            let shift = seq - highest;
            self.shift_left(shift);
            self.set_bit(0);
            self.highest = Some(seq);
            Ok(())
        } else {
            let offset = highest - seq;
            if offset >= WINDOW_SIZE {
                return Err(MultihopError::Replay { seq, epoch });
            }
            let offset = offset as usize;
            if self.get_bit(offset) {
                Err(MultihopError::Replay { seq, epoch })
            } else {
                self.set_bit(offset);
                Ok(())
            }
        }
    }

    /// Check whether `seq` would be accepted, WITHOUT recording it.
    ///
    /// First phase of the verify-then-record pattern: callers probe the
    /// window before paying for (and trusting) the AEAD open, then call
    /// [`Self::check_and_record`] only once the frame authenticated.
    /// Recording before verification would let an unauthenticated
    /// attacker (e.g. a hostile relay forging an arbitrary far-future
    /// `seq`) slam the window past the legitimate in-flight sequence
    /// numbers.
    ///
    /// # Errors
    ///
    /// - [`MultihopError::Replay`] if `seq` has already been seen *or*
    ///   falls below the active window. Same acceptance predicate as
    ///   [`Self::check_and_record`], minus the commit.
    #[inline]
    pub fn check(&self, seq: u64, epoch: u32) -> Result<(), MultihopError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if seq > highest {
            return Ok(());
        }
        let offset = highest - seq;
        if offset >= WINDOW_SIZE {
            return Err(MultihopError::Replay { seq, epoch });
        }
        if self.get_bit(offset as usize) {
            return Err(MultihopError::Replay { seq, epoch });
        }
        Ok(())
    }

    fn set_bit(&mut self, offset: usize) {
        let word = offset / 64;
        let bit = offset % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn get_bit(&self, offset: usize) -> bool {
        let word = offset / 64;
        let bit = offset % 64;
        (self.bitmap[word] >> bit) & 1 == 1
    }

    fn shift_left(&mut self, shift: u64) {
        if shift >= WINDOW_SIZE {
            // Everything in the old window is now too old: wipe.
            self.bitmap = [0u64; BITMAP_WORDS];
            return;
        }

        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as u32;

        let mut new_bitmap = [0u64; BITMAP_WORDS];

        // Move whole words first (low offsets become higher offsets).
        for (i, dest) in new_bitmap.iter_mut().enumerate() {
            *dest = match i.checked_sub(word_shift) {
                Some(s) => self.bitmap[s],
                None => 0,
            };
        }

        // Then handle the sub-word shift.
        if bit_shift != 0 {
            let mut carry = 0u64;
            for word in &mut new_bitmap {
                let shifted = (*word << bit_shift) | carry;
                carry = *word >> (64 - bit_shift);
                *word = shifted;
            }
        }

        self.bitmap = new_bitmap;
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_replay(window: &mut ReplayWindow, seq: u64) {
        match window.check_and_record(seq, 0) {
            Err(MultihopError::Replay { .. }) => {}
            Ok(()) => panic!("expected Replay rejection for seq {seq}"),
            Err(other) => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn accepts_in_order_sequence_from_zero() {
        let mut w = ReplayWindow::new();
        for seq in 0..50 {
            w.check_and_record(seq, 0)
                .unwrap_or_else(|e| panic!("in-order accept failed at {seq}: {e:?}"));
        }
        assert_eq!(w.highest(), Some(49));
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        // Bring the window up to seq=500.
        w.check_and_record(500, 0).unwrap();
        // Then accept earlier, never-seen seq within the window.
        w.check_and_record(250, 0).unwrap();
        w.check_and_record(499, 0).unwrap();
        w.check_and_record(1, 0).unwrap();
    }

    #[test]
    fn rejects_replay_within_window() {
        let mut w = ReplayWindow::new();
        w.check_and_record(10, 0).unwrap();
        assert_replay(&mut w, 10);

        w.check_and_record(20, 0).unwrap();
        assert_replay(&mut w, 20);
        assert_replay(&mut w, 10);
    }

    #[test]
    fn rejects_too_old_below_window() {
        let mut w = ReplayWindow::new();
        w.check_and_record(2_000, 0).unwrap();
        // Window covers offsets `0..1024`, i.e. seq in `(highest - 1024
        // .. highest]` = `(976 .. 2000]`. seq 976 lands at offset
        // exactly `WINDOW_SIZE`, which is *outside* the window per RFC
        // 6479 and our `offset < WINDOW_SIZE` boundary.
        assert_replay(&mut w, 976);
        assert_replay(&mut w, 0);
        // seq 977 is the oldest still-tracked value (offset 1023).
        w.check_and_record(977, 0).unwrap();
    }

    #[test]
    fn accepts_newest_advancing_window() {
        let mut w = ReplayWindow::new();
        w.check_and_record(0, 0).unwrap();
        w.check_and_record(1024, 0).unwrap();
        // After a +1024 jump the entire prior window is wiped. seq=0
        // is now too old (offset = 1024 == WINDOW_SIZE).
        assert_replay(&mut w, 0);
        // seq=1 is also too old (offset 1023 inside the window before
        // the jump but the bitmap was wiped, so 1 is treated as
        // never-seen - accepted).
        w.check_and_record(1, 0).unwrap();
    }

    #[test]
    fn shift_by_more_than_window_clears_state() {
        let mut w = ReplayWindow::new();
        w.check_and_record(100, 0).unwrap();
        w.check_and_record(200, 0).unwrap();
        // Big jump: window wiped.
        w.check_and_record(100_000, 0).unwrap();
        // Old seqs in the bitmap are now too old.
        assert_replay(&mut w, 100);
        // But never-seen, within-the-new-window, seqs accept.
        w.check_and_record(99_999, 0).unwrap();
    }

    #[test]
    fn check_only_probe_does_not_commit_the_seq() {
        let mut w = ReplayWindow::new();
        w.check_and_record(10, 0).unwrap();
        // A fresh seq passes `check` repeatedly: the probe must be
        // commit-free or the verify-then-record pattern degenerates
        // back to record-before-verify.
        w.check(11, 0)
            .expect("first probe of an unseen seq accepts");
        w.check(11, 0).expect(
            "second probe of the same unseen seq must still accept - \
             `check` must not record",
        );
        // The window state is untouched: the seq records normally
        // afterwards, and only then becomes a replay.
        w.check_and_record(11, 0).expect("record after probe");
        assert!(
            matches!(w.check(11, 0), Err(MultihopError::Replay { .. })),
            "after check_and_record, the probe must flag the replay"
        );
    }

    #[test]
    fn check_only_probe_matches_check_and_record_predicate() {
        let mut w = ReplayWindow::new();
        w.check_and_record(2_000, 0).unwrap();
        assert!(
            matches!(w.check(2_000, 0), Err(MultihopError::Replay { .. })),
            "seen seq rejected by the probe"
        );
        assert!(
            matches!(w.check(976, 0), Err(MultihopError::Replay { .. })),
            "below-window seq rejected by the probe (offset == WINDOW_SIZE)"
        );
        w.check(977, 0)
            .expect("oldest in-window unseen seq accepted by the probe");
        w.check(3_000, 0).expect("future seq accepted by the probe");
    }

    #[test]
    fn small_in_window_accepts_then_rejects_replay() {
        let mut w = ReplayWindow::new();
        for seq in (0u64..1024).step_by(7) {
            w.check_and_record(seq, 0)
                .unwrap_or_else(|e| panic!("first pass {seq}: {e:?}"));
        }
        // Replay all of the above.
        for seq in (0u64..1024).step_by(7) {
            assert_replay(&mut w, seq);
        }
    }
}
