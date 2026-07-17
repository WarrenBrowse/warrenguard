//! Single home of the client drain-reaction anti-stampede policy (ADR 36).
//!
//! When an exit drains, EVERY client on it receives the advisory within
//! seconds. The reaction policy that keeps that from becoming a reconnect
//! stampede (jittered spread bounded by the hard-close deadline, a
//! process-wide reconnect cooldown, and a TTL'd avoid-set window) is decided
//! here, next to the advisory decode, and consumed by every tier: the app
//! drain reactor, the SDK proxy supervisor, and any future client. Clients
//! keep their own plumbing (channels, avoid-set containers, RNG); the
//! decisions and the constants live here only.
//!
//! Promoted verbatim from the production app reactor
//! (`talpid-warren-tunnel/src/drain_reactor.rs`), the implementation proven
//! against real fleet drains.

use std::time::Duration;

use warrenguard_multihop::WarrenControlMessage;

/// Floor kept between the jittered reconnect and the exit's hard-close
/// deadline, so the proactive migration finishes before the backstop close.
pub const DEADLINE_SAFETY_MARGIN: Duration = Duration::from_secs(5);

/// Upper bound on the anti-stampede spread, even when the operator sets a
/// very distant (or soft / `u64::MAX`) deadline.
pub const MAX_JITTER: Duration = Duration::from_secs(20);

/// Minimum interval between two drain-triggered reconnects, process-wide.
/// Bounds a reconnect loop when the proactive reconnect re-lands on a still
/// draining exit before the ambient relay-list refresh has excluded it.
pub const DRAIN_RECONNECT_COOLDOWN: Duration = Duration::from_secs(120);

/// How long a drained exit stays in a client's avoid-set before it may be
/// selected again (the ambient relay-list refresh is the long-term
/// authority; the TTL only bridges its propagation delay).
pub const DRAINED_EXIT_AVOID_TTL: Duration = Duration::from_secs(300);

/// Maintenance-drain advisory the exit sent mid-session
/// (`WarrenControlMessage::ExitDraining`, ADR 36). `Copy + Eq` so a
/// repeated advisory (the exit re-sends until the client leaves) is
/// dedup'd by a watch subscriber's `current != new` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitDrainAdvisory {
    /// Absolute Unix epoch seconds after which the exit hard-closes
    /// stragglers. `u64::MAX` = soft drain (no hard deadline).
    pub deadline_unix_secs: u64,
    /// Opaque reason (`0` = maintenance).
    pub reason_code: u8,
}

impl ExitDrainAdvisory {
    /// Build from a [`WarrenControlMessage::ExitDraining`]. Returns `None`
    /// for any other variant.
    #[must_use]
    pub fn from_control(msg: &WarrenControlMessage) -> Option<Self> {
        match msg {
            WarrenControlMessage::ExitDraining {
                deadline_unix_secs,
                reason_code,
            } => Some(Self {
                deadline_unix_secs: *deadline_unix_secs,
                reason_code: *reason_code,
            }),
            _ => None,
        }
    }
}

/// Anti-stampede delay before reacting to a drain advisory.
///
/// `fraction` is a uniform draw in `[0.0, 1.0)` (per-client, so the herd
/// spreads); production draws it from the RNG, tests pass it in. The window
/// is `min(MAX_JITTER, deadline - now - SAFETY_MARGIN)`, clamped at zero:
///
/// - a soft drain (`deadline == u64::MAX`, no hard deadline) caps at
///   [`MAX_JITTER`],
/// - a deadline already within the safety margin yields `ZERO` (react
///   now: the close is imminent, no time to spread).
#[must_use]
pub fn jitter_delay(deadline_unix_secs: u64, now_unix_secs: u64, fraction: f64) -> Duration {
    let budget = deadline_unix_secs.saturating_sub(now_unix_secs);
    let usable = budget.saturating_sub(DEADLINE_SAFETY_MARGIN.as_secs());
    let window = usable.min(MAX_JITTER.as_secs());
    let frac = fraction.clamp(0.0, 1.0);
    Duration::from_secs_f64(window as f64 * frac)
}

/// `true` when a drain reconnect fired less than [`DRAIN_RECONNECT_COOLDOWN`]
/// ago and a second one must be suppressed. `last_unix == 0` (never) is always
/// allowed. Robust to clock skew: a `last` in the future reads as not-elapsed
/// (suppress), erring on the safe side.
#[must_use]
pub fn within_cooldown(now_unix: u64, last_unix: u64) -> bool {
    if last_unix == 0 {
        return false;
    }
    now_unix.saturating_sub(last_unix) < DRAIN_RECONNECT_COOLDOWN.as_secs() || last_unix > now_unix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_soft_drain_caps_at_max_window() {
        // A soft drain has no hard deadline (u64::MAX): the window must still
        // be capped at MAX_JITTER, never the (astronomically large) budget.
        let d = jitter_delay(u64::MAX, 1_000, 1.0);
        assert!(
            d <= MAX_JITTER && d >= MAX_JITTER - Duration::from_secs(1),
            "soft drain must cap the jitter at MAX_JITTER, got {d:?}"
        );
    }

    #[test]
    fn jitter_imminent_deadline_is_zero() {
        // Deadline inside the safety margin (budget 3 < margin 5): no time to
        // spread, react immediately regardless of the fraction.
        assert_eq!(jitter_delay(1_003, 1_000, 0.9), Duration::ZERO);
    }

    #[test]
    fn jitter_scales_linearly_with_fraction() {
        // budget 30 => usable 25 => window min(25, 20) = 20.
        assert_eq!(jitter_delay(1_030, 1_000, 0.0), Duration::ZERO);
        assert_eq!(jitter_delay(1_030, 1_000, 0.5), Duration::from_secs(10));
    }

    #[test]
    fn cooldown_allows_first_escalation_and_suppresses_a_quick_second() {
        // Never escalated (0) => allowed.
        assert!(!within_cooldown(1_000, 0));
        // 30s after a drain reconnect (< 120s cooldown) => suppress.
        assert!(within_cooldown(1_030, 1_000));
        // 200s after (> cooldown) => allowed again.
        assert!(!within_cooldown(1_200, 1_000));
        // Clock skew (last in the future) => suppress, erring safe.
        assert!(within_cooldown(900, 1_000));
    }

    #[test]
    fn advisory_decodes_only_the_exit_draining_variant() {
        let adv = ExitDrainAdvisory::from_control(&WarrenControlMessage::ExitDraining {
            deadline_unix_secs: 1_234,
            reason_code: 7,
        })
        .expect("ExitDraining must decode into an advisory");
        assert_eq!(adv.deadline_unix_secs, 1_234);
        assert_eq!(adv.reason_code, 7);
    }

    #[test]
    fn policy_constants_are_pinned() {
        // Every client tier consumes THESE values; a drift here is a fleet
        // behavior change and must be a conscious edit of this test.
        assert_eq!(DEADLINE_SAFETY_MARGIN, Duration::from_secs(5));
        assert_eq!(MAX_JITTER, Duration::from_secs(20));
        assert_eq!(DRAIN_RECONNECT_COOLDOWN, Duration::from_secs(120));
        assert_eq!(DRAINED_EXIT_AVOID_TTL, Duration::from_secs(300));
    }
}
