//! Session binding and setup freshness on the exit (warren-core doc 116).
//!
//! HPKE runs in base mode: anyone holding the exit's published key can create
//! a session the exit opens, and on a relayed circuit the exit's QUIC peer is
//! the entry relay. Two consequences this module closes for a connection set
//! up with a dated request:
//!
//! - the data plane accepts only the keys the client itself authorized (the
//!   setup's, then each one a `SessionRekey` sealed under an authorized key
//!   announced), so a session the relay creates never becomes the one the
//!   downlink is sealed with;
//! - a dated setup is refused once it is too old or when its key was already
//!   seen, so a captured setup frame is not a reusable credential.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use warrenguard_multihop::{EncapsulatedKeyBytes, RECENT_SETUP_RETENTION_SECS};

/// What the exit does with a setup that carries no time (a client that
/// predates session binding).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionBindingPolicy {
    /// Admit legacy setups as before, unbound, and bind every dated one.
    /// The default until a client floor that speaks the dated requests is
    /// recorded.
    #[default]
    AcceptLegacy,
    /// Refuse every setup that is not dated, before admission, with the
    /// answer that client reads as a policy refusal.
    RequireBound,
}

/// Most setup keys the exit can have to remember at once: each of the two
/// session caches builds at most its burst plus its rate over the retention
/// window, and a key reaches the set only after its cache built its session.
const RECENT_SETUP_KEYS_CAP: usize = 2
    * (super::SESSION_CREATE_BURST as usize
        + super::SESSION_CREATE_RATE_PER_SEC as usize * RECENT_SETUP_RETENTION_SECS as usize);

/// How often the recent set drops its expired entries, at most. A claim never
/// walks the whole set more often than this, whatever the setup rate.
const RECENT_SETUP_SWEEP_EVERY: Duration = Duration::from_secs(RECENT_SETUP_RETENTION_SECS / 8);

/// Outcome of [`RecentSetupKeys::claim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Claim {
    /// First sighting within the retention window: recorded.
    Fresh,
    /// Already presented within the retention window.
    Seen,
    /// The set is full of live entries: refuse rather than forget one.
    Saturated,
}

struct RecentState {
    seen: HashMap<EncapsulatedKeyBytes, Instant>,
    last_sweep: Option<Instant>,
}

/// Exit-wide set of the setup keys seen in the last
/// [`RECENT_SETUP_RETENTION_SECS`]. A key stays claimed whatever the
/// admission verdict, so a refused frame cannot be replayed into a later
/// success (a device slot freed meanwhile).
pub(super) struct RecentSetupKeys {
    inner: Mutex<RecentState>,
    retention: Duration,
    cap: usize,
}

impl RecentSetupKeys {
    pub(super) fn new() -> Self {
        Self::with_limits(
            Duration::from_secs(RECENT_SETUP_RETENTION_SECS),
            RECENT_SETUP_KEYS_CAP,
        )
    }

    pub(super) fn with_limits(retention: Duration, cap: usize) -> Self {
        Self {
            inner: Mutex::new(RecentState {
                seen: HashMap::new(),
                last_sweep: None,
            }),
            retention,
            cap,
        }
    }

    pub(super) fn claim(&self, key: &EncapsulatedKeyBytes) -> Claim {
        self.claim_at(key, Instant::now())
    }

    pub(super) fn claim_at(&self, key: &EncapsulatedKeyBytes, now: Instant) -> Claim {
        let mut state = self.inner.lock();
        let retention = self.retention;
        let live = |at: &Instant| now.saturating_duration_since(*at) < retention;
        if state.seen.get(key).is_some_and(live) {
            return Claim::Seen;
        }
        let due = state
            .last_sweep
            .is_none_or(|t| now.saturating_duration_since(t) >= RECENT_SETUP_SWEEP_EVERY);
        if due || state.seen.len() >= self.cap {
            state.seen.retain(|_, at| live(at));
            state.last_sweep = Some(now);
        }
        if state.seen.len() >= self.cap {
            return Claim::Saturated;
        }
        state.seen.insert(*key, now);
        Claim::Fresh
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.inner.lock().seen.len()
    }
}

/// The exit-wide freshness state and policy every connection's setup reads.
#[derive(Clone)]
pub(crate) struct SetupFreshness {
    pub(super) recent: std::sync::Arc<RecentSetupKeys>,
    pub(super) policy: SessionBindingPolicy,
}

impl SetupFreshness {
    pub(super) fn new() -> Self {
        Self {
            recent: std::sync::Arc::new(RecentSetupKeys::new()),
            policy: SessionBindingPolicy::default(),
        }
    }
}

/// Most `(key, epoch)` pairs a bound connection keeps: the current epoch, the
/// previous one still in its overlap, and slack for an announcement that
/// arrives before the bootstrap frame of the epoch it names.
const ACCEPTED_KEYS_KEPT: usize = 4;

/// The keys a bound connection's data plane accepts, each with the one epoch
/// its frames may carry.
#[derive(Debug)]
pub(super) struct AcceptedKeys {
    keys: Vec<(EncapsulatedKeyBytes, u32)>,
}

impl AcceptedKeys {
    /// Seeded by the setup frame, the only key the client proved before the
    /// data plane started.
    pub(super) fn seeded(key: EncapsulatedKeyBytes, epoch: u32) -> Self {
        let mut keys = Vec::with_capacity(ACCEPTED_KEYS_KEPT + 1);
        keys.push((key, epoch));
        Self { keys }
    }

    /// Whether a frame under `key` at `epoch` may reach the session cache.
    pub(super) fn admits(&self, key: &EncapsulatedKeyBytes, epoch: u32) -> bool {
        self.keys.iter().any(|(k, e)| k == key && *e == epoch)
    }

    /// Record the key a `SessionRekey` announced, carried by an authenticated
    /// frame of `frame_epoch`. Only the epoch right after the frame's is
    /// accepted; a key already recorded under another epoch is refused.
    /// Returns whether the key is now accepted.
    pub(super) fn authorize(
        &mut self,
        frame_epoch: u32,
        new_key: EncapsulatedKeyBytes,
        new_epoch: u32,
    ) -> bool {
        if frame_epoch.checked_add(1) != Some(new_epoch) {
            return false;
        }
        if let Some((_, epoch)) = self.keys.iter().find(|(k, _)| *k == new_key) {
            return *epoch == new_epoch;
        }
        self.keys.push((new_key, new_epoch));
        if self.keys.len() > ACCEPTED_KEYS_KEPT
            && let Some(oldest) = self
                .keys
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, epoch))| *epoch)
                .map(|(i, _)| i)
        {
            self.keys.swap_remove(oldest);
        }
        true
    }
}

/// Whether a frame of `frame_epoch` may become the session the downlink is
/// sealed with. Unbound connections keep the historical last-frame-wins rule;
/// a bound connection's session only moves forward, so a client still sealing
/// under the previous epoch while it waits for the new one's acknowledgement
/// cannot pull the downlink back.
pub(super) const fn installs_current(bound: bool, current_epoch: u32, frame_epoch: u32) -> bool {
    !bound || frame_epoch >= current_epoch
}

/// Apply a `SessionRekey` an authenticated frame of `frame_epoch` carried:
/// on a bound connection, accept the key it names; on an unbound one, nothing
/// (a legacy client never sends one, and its exit accepts any key anyway).
pub(super) fn note_rekey(
    accepted: Option<&mut AcceptedKeys>,
    frame_epoch: u32,
    new_key: EncapsulatedKeyBytes,
    new_epoch: u32,
) {
    use crate::metrics::{SetupFreshnessResult, setup_freshness_metrics};
    let bound = accepted.is_some_and(|keys| keys.authorize(frame_epoch, new_key, new_epoch));
    setup_freshness_metrics().record(if bound {
        SetupFreshnessResult::RekeyBound
    } else {
        SetupFreshnessResult::RekeyIgnored
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const K0: EncapsulatedKeyBytes = [0x10; 32];
    const K1: EncapsulatedKeyBytes = [0x11; 32];
    const RELAY: EncapsulatedKeyBytes = [0xEE; 32];

    #[test]
    fn a_bound_connection_admits_only_the_setup_key_at_its_epoch() {
        let keys = AcceptedKeys::seeded(K0, 0);
        assert!(keys.admits(&K0, 0));
        assert!(
            !keys.admits(&RELAY, 0),
            "a key the client never authorized must not reach the session cache"
        );
        assert!(
            !keys.admits(&K0, 1),
            "the setup key carries the setup epoch only"
        );
    }

    #[test]
    fn an_announcement_authorizes_the_next_epoch_only() {
        let mut keys = AcceptedKeys::seeded(K0, 0);
        assert!(
            !keys.authorize(0, K1, 2),
            "an epoch that skips one is refused"
        );
        assert!(
            !keys.authorize(0, K1, 0),
            "an epoch that does not advance too"
        );
        assert!(!keys.admits(&K1, 2));
        assert!(keys.authorize(0, K1, 1));
        assert!(keys.admits(&K1, 1));
        assert!(
            keys.admits(&K0, 0),
            "the previous epoch stays for its overlap"
        );
        assert!(
            keys.authorize(0, K1, 1),
            "a replayed announcement is idempotent"
        );
        assert!(
            !keys.authorize(1, K1, 2),
            "a key cannot be re-announced under another epoch"
        );
        assert!(!keys.authorize(u32::MAX, RELAY, 0), "no wrap");
    }

    #[test]
    fn the_oldest_epoch_goes_once_the_set_is_full() {
        let mut keys = AcceptedKeys::seeded([0; 32], 0);
        for epoch in 1..=ACCEPTED_KEYS_KEPT as u32 {
            assert!(keys.authorize(epoch - 1, [epoch as u8; 32], epoch));
        }
        assert!(!keys.admits(&[0; 32], 0), "epoch 0 dropped");
        assert!(keys.admits(&[ACCEPTED_KEYS_KEPT as u8; 32], ACCEPTED_KEYS_KEPT as u32));
        assert_eq!(keys.keys.len(), ACCEPTED_KEYS_KEPT);
    }

    #[test]
    fn a_bound_connection_never_moves_its_downlink_back_an_epoch() {
        assert!(installs_current(true, 1, 1));
        assert!(installs_current(true, 1, 2));
        assert!(!installs_current(true, 2, 1));
        assert!(
            installs_current(false, 2, 1),
            "an unbound connection keeps last-frame-wins"
        );
    }

    #[test]
    fn a_setup_key_is_refused_while_remembered_and_forgotten_after() {
        let recent = RecentSetupKeys::with_limits(Duration::from_secs(240), 16);
        let t0 = Instant::now();
        assert_eq!(recent.claim_at(&K0, t0), Claim::Fresh);
        assert_eq!(
            recent.claim_at(&K0, t0 + Duration::from_secs(239)),
            Claim::Seen,
            "a second presentation inside the window is a replay"
        );
        assert_eq!(recent.claim_at(&K1, t0), Claim::Fresh);
        assert_eq!(
            recent.claim_at(&K0, t0 + Duration::from_secs(240)),
            Claim::Fresh,
            "past the window the clock check is what refuses an old frame"
        );
    }

    #[test]
    fn a_full_set_refuses_instead_of_forgetting_a_live_key() {
        let recent = RecentSetupKeys::with_limits(Duration::from_secs(240), 2);
        let t0 = Instant::now();
        assert_eq!(recent.claim_at(&[1; 32], t0), Claim::Fresh);
        assert_eq!(recent.claim_at(&[2; 32], t0), Claim::Fresh);
        assert_eq!(recent.claim_at(&[3; 32], t0), Claim::Saturated);
        assert_eq!(
            recent.claim_at(&[1; 32], t0),
            Claim::Seen,
            "saturation never evicts a live entry"
        );
        assert_eq!(
            recent.claim_at(&[3; 32], t0 + Duration::from_secs(241)),
            Claim::Fresh,
            "expired entries make room again"
        );
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn the_cap_covers_both_caches_over_the_whole_window() {
        assert_eq!(RECENT_SETUP_KEYS_CAP, 2 * (1000 + 500 * 240));
    }
}
