//! Process-wide uplink accounting for the exit termination datapath.
//!
//! Every investigation of a silent exit black-hole has needed the same
//! number first: how many datagrams did this node receive from clients and
//! never put on the TUN, and which gate ate them. Until now that quantity
//! existed only inside a live pump, as plain locals, surfaced by a
//! per-session log line written when the session had already ended. A
//! deployer's scrape could see `datagrams_rx` (a QUIC transport counter)
//! and nothing about what happened to those datagrams afterwards.
//!
//! These counters answer it directly and at any moment: `received` minus
//! `forwarded` is the black-holed volume, and the per-reason breakdown
//! names the gate. The reason set is closed and mirrors the gates the rx
//! pumps actually apply, in the order they apply them; nothing here is
//! inferred or merged, so a reason can never describe two different
//! failures.
//!
//! **Privacy.** Node-level totals only. Nothing here is keyed on a client,
//! a session, an address, a pubkey or a connection, and no such label may
//! ever be added: on a privacy product a metric's cardinality is an
//! identification surface before it is a performance one. A drop reason is
//! a property of the exit's own code, never of who sent the datagram.
//!
//! **Cost.** A datagram pays no atomic. Each pump keeps counting in the
//! plain `u64` locals it already had and folds its delta in here on the
//! cadence it already uses for its structured report (once per
//! [`crate::datapath::RX_REPORT_CHECK_EVERY`] datagrams, and at most once
//! per [`crate::datapath::RX_REPORT_INTERVAL`]), plus once when the pump
//! ends so a short session is never lost. A connection therefore costs one
//! batch of relaxed `fetch_add` every few seconds, whatever its packet
//! rate.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::datapath::RxCounters;

/// The process-wide block. One exit process serves one listener, so a
/// single instance is the whole node's view; [`uplink_metrics`] hands it
/// out. Construct your own only in a test that wants an isolated sink.
#[derive(Debug)]
pub struct UplinkMetrics {
    received: AtomicU64,
    forwarded: AtomicU64,
    authenticated: AtomicU64,
    dropped_decode: AtomicU64,
    dropped_exit_id: AtomicU64,
    dropped_session: AtomicU64,
    dropped_aead_open: AtomicU64,
    dropped_replay: AtomicU64,
    dropped_control_frame: AtomicU64,
    dropped_daita_dummy: AtomicU64,
    dropped_spoofed_source: AtomicU64,
    /// Refused by the inner-destination policy: addressed into the exit's
    /// own client pool. Its own reason, never merged into
    /// `spoofed_source`: one is a client claiming an address it was not
    /// given, the other a client aiming at a neighbour it must not reach,
    /// and an operator responds differently to each.
    dropped_pool_destination: AtomicU64,
    dropped_rate_limit: AtomicU64,
    dropped_tun_write: AtomicU64,
    /// Refinement of `dropped_spoofed_source`, in [`crate::datapath::SpoofTally::CLASSES`]
    /// order. Kept a separate series rather than five more `reason` values
    /// so the closed reason set, and the invariant that it sums to
    /// `received - forwarded`, both stay exactly as they are.
    spoofed_by_class: [AtomicU64; 5],
}

/// The node's block, folded into by every exit rx pump in this process.
static UPLINK: UplinkMetrics = UplinkMetrics::new();

/// The process-wide uplink block.
#[must_use]
pub fn uplink_metrics() -> &'static UplinkMetrics {
    &UPLINK
}

/// Point-in-time read of the process-wide block, for a deployer's scrape.
#[must_use]
pub fn uplink_snapshot() -> UplinkSnapshot {
    UPLINK.snapshot()
}

impl Default for UplinkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl UplinkMetrics {
    /// A zeroed block.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            received: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            authenticated: AtomicU64::new(0),
            dropped_decode: AtomicU64::new(0),
            dropped_exit_id: AtomicU64::new(0),
            dropped_session: AtomicU64::new(0),
            dropped_aead_open: AtomicU64::new(0),
            dropped_replay: AtomicU64::new(0),
            dropped_control_frame: AtomicU64::new(0),
            dropped_daita_dummy: AtomicU64::new(0),
            dropped_spoofed_source: AtomicU64::new(0),
            dropped_pool_destination: AtomicU64::new(0),
            dropped_rate_limit: AtomicU64::new(0),
            dropped_tun_write: AtomicU64::new(0),
            spoofed_by_class: [const { AtomicU64::new(0) }; 5],
        }
    }

    /// Folds what one pump has counted since it last published: `now` is
    /// its current reading, `published` the reading it already folded in.
    /// Every counter here is therefore a sum of non-negative deltas and
    /// only ever grows, so the difference between two scrapes is the
    /// traffic of that interval whatever happened to the sessions in
    /// between.
    ///
    /// `received` and `forwarded` are folded first and adjacently: a
    /// scrape racing this call can only see the two headline numbers a few
    /// nanoseconds apart, and the per-reason series catch up immediately
    /// after.
    pub(crate) fn fold(&self, now: &RxCounters, published: &RxCounters) {
        let add = |slot: &AtomicU64, new: u64, old: u64| {
            let delta = new.saturating_sub(old);
            if delta != 0 {
                slot.fetch_add(delta, Ordering::Relaxed);
            }
        };
        add(&self.received, now.datagrams, published.datagrams);
        add(&self.forwarded, now.to_tun, published.to_tun);
        add(&self.authenticated, now.opened, published.opened);
        add(&self.dropped_decode, now.decode_errs, published.decode_errs);
        add(
            &self.dropped_exit_id,
            now.exit_id_mismatches,
            published.exit_id_mismatches,
        );
        add(
            &self.dropped_session,
            now.session_errs,
            published.session_errs,
        );
        add(&self.dropped_aead_open, now.open_errs, published.open_errs);
        add(&self.dropped_replay, now.replays, published.replays);
        add(
            &self.dropped_control_frame,
            now.control_frames,
            published.control_frames,
        );
        add(&self.dropped_daita_dummy, now.dummies, published.dummies);
        // The total is derived from the classes, so the refinement can
        // never disagree with the series it refines.
        add(
            &self.dropped_spoofed_source,
            now.spoof.total(),
            published.spoof.total(),
        );
        let (now_classes, published_classes) = (now.spoof.as_array(), published.spoof.as_array());
        for (i, slot) in self.spoofed_by_class.iter().enumerate() {
            add(slot, now_classes[i], published_classes[i]);
        }
        add(
            &self.dropped_pool_destination,
            now.pool_drops,
            published.pool_drops,
        );
        add(
            &self.dropped_rate_limit,
            now.rate_drops,
            published.rate_drops,
        );
        add(
            &self.dropped_tun_write,
            now.tun_write_errs,
            published.tun_write_errs,
        );
    }

    /// Reads every counter. Relaxed loads, so the series are individually
    /// exact and mutually best-effort (no transactional view), which is
    /// what a Prometheus-style scrape wants.
    #[must_use]
    pub fn snapshot(&self) -> UplinkSnapshot {
        UplinkSnapshot {
            received: self.received.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            authenticated: self.authenticated.load(Ordering::Relaxed),
            dropped_decode: self.dropped_decode.load(Ordering::Relaxed),
            dropped_exit_id: self.dropped_exit_id.load(Ordering::Relaxed),
            dropped_session: self.dropped_session.load(Ordering::Relaxed),
            dropped_aead_open: self.dropped_aead_open.load(Ordering::Relaxed),
            dropped_replay: self.dropped_replay.load(Ordering::Relaxed),
            dropped_control_frame: self.dropped_control_frame.load(Ordering::Relaxed),
            dropped_daita_dummy: self.dropped_daita_dummy.load(Ordering::Relaxed),
            dropped_spoofed_source: self.dropped_spoofed_source.load(Ordering::Relaxed),
            dropped_pool_destination: self.dropped_pool_destination.load(Ordering::Relaxed),
            dropped_rate_limit: self.dropped_rate_limit.load(Ordering::Relaxed),
            dropped_tun_write: self.dropped_tun_write.load(Ordering::Relaxed),
            spoofed_by_class: std::array::from_fn(|i| {
                self.spoofed_by_class[i].load(Ordering::Relaxed)
            }),
        }
    }
}

/// Node-wide count of downlink packets the exit read off its TUN and could
/// not hand to a client connection, by reason. The uplink block above
/// answers "did the exit forward what the client sent"; these answer the
/// mirror question, which is the one the 2026-08-02 black-hole actually
/// turned on.
///
/// Only the drop paths are counted, and every one of them is cold on a
/// healthy node, so these are incremented directly with a relaxed
/// `fetch_add` at the drop site. There is deliberately no per-packet
/// denominator here: adding one would put an atomic on the single TUN
/// reader's hot loop, and the delivered volume is already visible as
/// `warren_exit_bytes_tx_total`.
#[derive(Debug)]
pub struct DownlinkMetrics {
    dropped_no_route: AtomicU64,
    dropped_channel_full: AtomicU64,
    dropped_unroutable: AtomicU64,
}

/// The node's downlink block.
static DOWNLINK: DownlinkMetrics = DownlinkMetrics::new();

/// The process-wide downlink block.
#[must_use]
pub fn downlink_metrics() -> &'static DownlinkMetrics {
    &DOWNLINK
}

/// Point-in-time read of the process-wide downlink block.
#[must_use]
pub fn downlink_snapshot() -> DownlinkSnapshot {
    DOWNLINK.snapshot()
}

impl Default for DownlinkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DownlinkMetrics {
    /// A zeroed block.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dropped_no_route: AtomicU64::new(0),
            dropped_channel_full: AtomicU64::new(0),
            dropped_unroutable: AtomicU64::new(0),
        }
    }

    /// A reply arrived for a tunnel address no live connection owns: the
    /// session that opened the flow is gone, or its downlink route was
    /// taken away.
    pub(crate) fn inc_no_route(&self) {
        self.dropped_no_route.fetch_add(1, Ordering::Relaxed);
    }

    /// The owning connection's downlink channel was full. One is a burst;
    /// a sustained rate means that connection's tx task is not draining
    /// and every flow pinned to it stalls silently.
    pub(crate) fn inc_channel_full(&self) {
        self.dropped_channel_full.fetch_add(1, Ordering::Relaxed);
    }

    /// The packet carried no routable inner destination (neither a valid
    /// IPv4 nor a valid IPv6 header).
    pub(crate) fn inc_unroutable(&self) {
        self.dropped_unroutable.fetch_add(1, Ordering::Relaxed);
    }

    /// Reads every counter.
    #[must_use]
    pub fn snapshot(&self) -> DownlinkSnapshot {
        DownlinkSnapshot {
            dropped_no_route: self.dropped_no_route.load(Ordering::Relaxed),
            dropped_channel_full: self.dropped_channel_full.load(Ordering::Relaxed),
            dropped_unroutable: self.dropped_unroutable.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time view of [`DownlinkMetrics`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DownlinkSnapshot {
    /// See [`DownlinkMetrics::inc_no_route`].
    pub dropped_no_route: u64,
    /// See [`DownlinkMetrics::inc_channel_full`].
    pub dropped_channel_full: u64,
    /// See [`DownlinkMetrics::inc_unroutable`].
    pub dropped_unroutable: u64,
}

impl DownlinkSnapshot {
    /// The breakdown as `(reason, count)`, same contract as
    /// [`UplinkSnapshot::dropped_by_reason`].
    #[must_use]
    pub const fn dropped_by_reason(&self) -> [(&'static str, u64); 3] {
        [
            ("no_route", self.dropped_no_route),
            ("channel_full", self.dropped_channel_full),
            ("unroutable", self.dropped_unroutable),
        ]
    }
}

/// What proved a downlink sender dead before its route was taken away.
/// Closed on a QUIC connection that reported itself closed, silent on one
/// that moved neither its application counter nor its peer's UDP receive
/// count for a whole conviction window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvictReason {
    /// The owning QUIC connection is closed for good.
    Closed,
    /// The owner went silent at BOTH the application and the QUIC level for
    /// the whole window. Application silence alone never convicts.
    Silent,
}

/// Node-wide accounting of the downlink ROUTE table itself, as opposed to
/// the packets it carries: how many senders the exit took a route away from
/// and what proved them dead, plus how many are sitting application silent
/// in a shared slot right now.
///
/// These exist because a route the exit keeps pointing at a departed owner
/// is invisible in every other series: the packets it swallows are neither
/// dropped nor unroutable, they are handed to a channel that accepts them
/// and nobody reads. An exit slot once held seven such senders out of
/// fifteen for tens of minutes, each keeping its share of the 5-tuple hash
/// and, because a learned flow is first-writer-wins, black-holing every
/// flow it owned, while the node said nothing at all.
///
/// The gauge is deliberately wider than the counters. A sender whose client
/// vanished behind a relay leg that keeps ACKing cannot be convicted (the
/// exit's QUIC peer on a multi-hop session is the relay), so it is counted
/// here and evicted nowhere.
///
/// Same privacy contract as the blocks above: node-level totals, never a
/// per-client, per-address or per-slot label.
#[derive(Debug)]
pub struct RouteMetrics {
    evicted_closed: AtomicU64,
    evicted_silent: AtomicU64,
    stale_senders: AtomicU64,
}

/// The node's route block.
static ROUTE: RouteMetrics = RouteMetrics::new();

/// The process-wide downlink-route block.
#[must_use]
pub fn route_metrics() -> &'static RouteMetrics {
    &ROUTE
}

/// Point-in-time read of the process-wide downlink-route block.
#[must_use]
pub fn route_snapshot() -> RouteSnapshot {
    ROUTE.snapshot()
}

impl Default for RouteMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteMetrics {
    /// A zeroed block.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            evicted_closed: AtomicU64::new(0),
            evicted_silent: AtomicU64::new(0),
            stale_senders: AtomicU64::new(0),
        }
    }

    /// Folds `n` evictions attributed to `reason`. Called once per pass by
    /// the task that drove it, so an eviction sweep costs one atomic per
    /// reason rather than one per victim.
    pub(crate) fn add_evicted(&self, reason: EvictReason, n: u64) {
        if n == 0 {
            return;
        }
        let slot = match reason {
            EvictReason::Closed => &self.evicted_closed,
            EvictReason::Silent => &self.evicted_silent,
        };
        slot.fetch_add(n, Ordering::Relaxed);
    }

    /// Publishes the patrol's latest reading of how many senders sit
    /// application silent in a shared slot. A gauge, republished whole every
    /// round: it goes down as those senders are evicted, start speaking
    /// again, or become the sole owner of their address.
    pub(crate) fn set_stale_senders(&self, n: u64) {
        self.stale_senders.store(n, Ordering::Relaxed);
    }

    /// Reads every counter.
    #[must_use]
    pub fn snapshot(&self) -> RouteSnapshot {
        RouteSnapshot {
            evicted_closed: self.evicted_closed.load(Ordering::Relaxed),
            evicted_silent: self.evicted_silent.load(Ordering::Relaxed),
            stale_senders: self.stale_senders.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time view of [`RouteMetrics`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteSnapshot {
    /// Senders evicted because their QUIC connection was closed.
    pub evicted_closed: u64,
    /// Senders evicted after a whole window of silence at both levels.
    pub evicted_silent: u64,
    /// Senders that have carried no application traffic for a long while and
    /// share their address with at least one other sender, as of the last
    /// patrol round. A gauge, not a counter: see [`RouteMetrics`] for why it
    /// is the wider number.
    pub stale_senders: u64,
}

impl RouteSnapshot {
    /// The eviction breakdown as `(reason, count)`, same contract as
    /// [`DownlinkSnapshot::dropped_by_reason`]: the reason strings live
    /// here so an exposition cannot drift from the verdicts that produce
    /// the counts.
    #[must_use]
    pub const fn evicted_by_reason(&self) -> [(&'static str, u64); 2] {
        [
            ("closed", self.evicted_closed),
            ("silent", self.evicted_silent),
        ]
    }
}

/// A point-in-time view of [`UplinkMetrics`]. Deliberately constructible
/// by a consumer, so a deployer can unit-test its own exposition against a
/// crafted reading instead of having to drive a live pump.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UplinkSnapshot {
    /// Datagrams read off a client connection by an exit rx pump, whatever
    /// became of them. The denominator of every ratio below.
    pub received: u64,
    /// Datagrams written to the exit's TUN device: the traffic that
    /// actually left towards the internet.
    pub forwarded: u64,
    /// Datagrams that cleared decode, exit-id, session lookup, AEAD open
    /// and anti-replay. This is the client's real uplink, as opposed to
    /// everything a public UDP endpoint receives, so
    /// `authenticated - forwarded` is the volume the exit itself refused
    /// after admitting it.
    pub authenticated: u64,
    /// Wire frame that did not decode.
    pub dropped_decode: u64,
    /// Frame addressed to another exit's id.
    pub dropped_exit_id: u64,
    /// No HPKE session for the frame's encapsulated key, and none could be
    /// established from it (a `/v2` DATA frame after a cache eviction, a
    /// stale key after an epoch rotation, a session-creation refusal).
    pub dropped_session: u64,
    /// The AEAD open failed: wrong key, corrupted frame, forged tag.
    pub dropped_aead_open: u64,
    /// Anti-replay rejected an already-accepted `(epoch, seq)`.
    pub dropped_replay: u64,
    /// A control message on the DATA path, dropped by design (the setup
    /// stream carries the real control plane).
    pub dropped_control_frame: u64,
    /// DAITA cover traffic, dropped by design before the TUN.
    pub dropped_daita_dummy: u64,
    /// The inner source address was not the one this connection was
    /// assigned: the anti-spoof gate refused it.
    pub dropped_spoofed_source: u64,
    /// Addressed into the exit's own client pool, at anything but the
    /// gateway: the inner-destination policy refused it.
    pub dropped_pool_destination: u64,
    /// Over the session's uplink budget.
    pub dropped_rate_limit: u64,
    /// The TUN write itself failed (kernel queue pressure, device gone).
    pub dropped_tun_write: u64,
    /// See [`Self::spoofed_by_class`].
    pub spoofed_by_class: [u64; 5],
}

impl UplinkSnapshot {
    /// Datagrams received and never forwarded, whatever the reason. The
    /// one number every black-hole investigation opens with; the breakdown
    /// then says which gate is responsible.
    ///
    /// Saturating because the two series are folded microseconds apart and
    /// a scrape can land between them: a racing read reports one datagram
    /// too few rather than an absurdity.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.received.saturating_sub(self.forwarded)
    }

    /// The drop breakdown as `(reason, count)`, in the order the datapath
    /// applies the gates. The reason strings live here so an exposition
    /// cannot drift from the gates that produce the counts, and the array
    /// is exhaustive: the counts sum to [`Self::dropped`].
    #[must_use]
    pub const fn dropped_by_reason(&self) -> [(&'static str, u64); 11] {
        [
            ("decode", self.dropped_decode),
            ("exit_id", self.dropped_exit_id),
            ("session", self.dropped_session),
            ("aead_open", self.dropped_aead_open),
            ("replay", self.dropped_replay),
            ("control_frame", self.dropped_control_frame),
            ("daita_dummy", self.dropped_daita_dummy),
            ("spoofed_source", self.dropped_spoofed_source),
            ("pool_destination", self.dropped_pool_destination),
            ("rate_limit", self.dropped_rate_limit),
            ("tun_write", self.dropped_tun_write),
        ]
    }

    /// What the anti-spoof gate refused, split by the class of packet that
    /// caused it, as `(class, count)`. The classes sum to
    /// [`Self::dropped_spoofed_source`], so this refines that reason rather
    /// than competing with it.
    ///
    /// It exists because `spoofed_source` merged two facts that want
    /// opposite responses: `v4_mismatch` is a tunnel client impersonating
    /// another, and `v6_link_local` is a client's own neighbour-discovery
    /// chatter on a link that does not exist. Node-level aggregates, and
    /// every class is a property of the packet's own header, never of who
    /// sent it.
    #[must_use]
    pub fn spoofed_by_class(&self) -> [(&'static str, u64); 5] {
        std::array::from_fn(|i| {
            (
                crate::datapath::SpoofTally::CLASSES[i],
                self.spoofed_by_class[i],
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pump reading with every field distinct, so a fold that crosses two
    /// counters is caught rather than averaging out.
    const fn distinct() -> RxCounters {
        RxCounters {
            datagrams: 100,
            opened: 90,
            to_tun: 60,
            decode_errs: 1,
            exit_id_mismatches: 2,
            session_errs: 3,
            open_errs: 4,
            replays: 5,
            control_frames: 6,
            dummies: 7,
            spoof: crate::datapath::SpoofTally {
                malformed: 1,
                v4_mismatch: 2,
                v6_link_local: 3,
                v6_unallocated: 1,
                v6_mismatch: 1,
            },
            pool_drops: 11,
            rate_drops: 9,
            tun_write_errs: 10,
        }
    }

    #[test]
    fn each_drop_reason_folds_into_its_own_counter() {
        let m = UplinkMetrics::new();
        m.fold(&distinct(), &RxCounters::default());
        let s = m.snapshot();

        assert_eq!(s.received, 100);
        assert_eq!(s.forwarded, 60);
        assert_eq!(s.authenticated, 90);
        assert_eq!(s.dropped_decode, 1);
        assert_eq!(s.dropped_exit_id, 2);
        assert_eq!(s.dropped_session, 3);
        assert_eq!(s.dropped_aead_open, 4);
        assert_eq!(s.dropped_replay, 5);
        assert_eq!(s.dropped_control_frame, 6);
        assert_eq!(s.dropped_daita_dummy, 7);
        assert_eq!(s.dropped_spoofed_source, 8);
        assert_eq!(s.dropped_pool_destination, 11);
        assert_eq!(s.dropped_rate_limit, 9);
        assert_eq!(s.dropped_tun_write, 10);
    }

    #[test]
    fn the_breakdown_accounts_for_every_datagram_that_was_not_forwarded() {
        // The invariant that makes the exposition self-checking: a
        // received datagram either reached the TUN or is named by exactly
        // one reason. A gate added without a counter breaks this.
        let m = UplinkMetrics::new();
        let now = RxCounters {
            datagrams: 66,
            to_tun: 0,
            ..distinct()
        };
        m.fold(&now, &RxCounters::default());
        let s = m.snapshot();

        let named: u64 = s.dropped_by_reason().iter().map(|(_, n)| n).sum();
        assert_eq!(
            named,
            s.dropped(),
            "every datagram that did not reach the TUN must be named by a reason"
        );
    }

    #[test]
    fn each_spoof_class_folds_into_its_own_series_and_they_sum_to_the_reason() {
        // The refinement must never disagree with the reason it refines: a
        // scrape that reads `spoofed_source=23` and a breakdown summing to
        // 22 tells an investigator nothing it can trust.
        let m = UplinkMetrics::new();
        m.fold(&distinct(), &RxCounters::default());
        let s = m.snapshot();

        assert_eq!(
            s.spoofed_by_class(),
            [
                ("malformed", 1),
                ("v4_mismatch", 2),
                ("v6_link_local", 3),
                ("v6_unallocated", 1),
                ("v6_mismatch", 1),
            ],
            "a stale class ordering would mislabel every series"
        );
        let named: u64 = s.spoofed_by_class().iter().map(|(_, n)| n).sum();
        assert_eq!(
            named, s.dropped_spoofed_source,
            "the classes must account for every refusal the gate counted"
        );
    }

    #[test]
    fn a_forwarded_datagram_increments_no_drop_counter() {
        let m = UplinkMetrics::new();
        m.fold(
            &RxCounters {
                datagrams: 7,
                opened: 7,
                to_tun: 7,
                ..RxCounters::default()
            },
            &RxCounters::default(),
        );
        let s = m.snapshot();

        assert_eq!(s.forwarded, 7);
        assert_eq!(s.dropped(), 0, "nothing was dropped");
        for (reason, count) in s.dropped_by_reason() {
            assert_eq!(count, 0, "a healthy uplink must not increment {reason}");
        }
    }

    #[test]
    fn folds_are_deltas_so_the_counters_only_ever_grow() {
        // A pump publishes repeatedly against its own watermark; a second
        // pump then publishes its own. Nothing may be double-counted and
        // nothing may go backwards, or a scrape difference means nothing.
        let m = UplinkMetrics::new();
        let first_half = RxCounters {
            datagrams: 10,
            opened: 10,
            to_tun: 8,
            spoof: crate::datapath::SpoofTally {
                v4_mismatch: 2,
                ..crate::datapath::SpoofTally::default()
            },
            ..RxCounters::default()
        };
        m.fold(&first_half, &RxCounters::default());
        let mid = m.snapshot();

        let whole = RxCounters {
            datagrams: 30,
            opened: 30,
            to_tun: 25,
            spoof: crate::datapath::SpoofTally {
                v4_mismatch: 5,
                ..crate::datapath::SpoofTally::default()
            },
            ..RxCounters::default()
        };
        m.fold(&whole, &first_half);
        let after_session_one = m.snapshot();

        assert_eq!(after_session_one.received, 30, "no double counting");
        assert_eq!(after_session_one.forwarded, 25);
        assert_eq!(after_session_one.dropped_spoofed_source, 5);
        assert!(after_session_one.received >= mid.received);

        // A second session starts its own counting from zero.
        let second = RxCounters {
            datagrams: 4,
            opened: 4,
            to_tun: 4,
            ..RxCounters::default()
        };
        m.fold(&second, &RxCounters::default());
        let after_session_two = m.snapshot();

        assert_eq!(
            after_session_two.received, 34,
            "counters survive across sessions"
        );
        assert_eq!(after_session_two.forwarded, 29);
        assert_eq!(
            after_session_two.dropped_spoofed_source, 5,
            "a healthy second session leaves the first one's drops alone"
        );
    }

    #[test]
    fn each_downlink_fault_increments_only_its_own_counter() {
        let m = DownlinkMetrics::new();
        m.inc_no_route();
        m.inc_no_route();
        m.inc_channel_full();
        m.inc_unroutable();
        m.inc_unroutable();
        m.inc_unroutable();
        let s = m.snapshot();

        assert_eq!(s.dropped_no_route, 2);
        assert_eq!(s.dropped_channel_full, 1);
        assert_eq!(s.dropped_unroutable, 3);
        assert_eq!(
            s.dropped_by_reason(),
            [("no_route", 2), ("channel_full", 1), ("unroutable", 3)],
            "a stale reason ordering would mislabel every series"
        );
    }

    #[test]
    fn each_route_eviction_increments_only_its_own_counter() {
        let m = RouteMetrics::new();
        m.add_evicted(EvictReason::Closed, 1);
        m.add_evicted(EvictReason::Silent, 2);
        let s = m.snapshot();

        assert_eq!(s.evicted_closed, 1);
        assert_eq!(s.evicted_silent, 2);
        assert_eq!(
            s.evicted_by_reason(),
            [("closed", 1), ("silent", 2)],
            "a stale reason ordering would mislabel every series"
        );
    }

    #[test]
    fn the_stale_sender_gauge_reports_the_latest_reading_not_a_running_total() {
        // It answers "how many are stale right now", so it has to be able to
        // go down: a patrol that published a sum would turn a slot that
        // recovered into a permanent alert.
        let m = RouteMetrics::new();
        m.set_stale_senders(7);
        assert_eq!(m.snapshot().stale_senders, 7);

        m.set_stale_senders(2);
        assert_eq!(m.snapshot().stale_senders, 2);
    }

    #[test]
    fn a_fresh_route_block_has_evicted_nothing() {
        let s = RouteMetrics::new().snapshot();
        for (reason, count) in s.evicted_by_reason() {
            assert_eq!(count, 0, "{reason} must start at zero");
        }
    }

    #[test]
    fn a_fresh_downlink_block_has_dropped_nothing() {
        let s = DownlinkMetrics::new().snapshot();
        for (reason, count) in s.dropped_by_reason() {
            assert_eq!(count, 0, "{reason} must start at zero");
        }
    }

    #[test]
    fn the_process_wide_block_is_the_same_one_every_pump_folds_into() {
        assert!(
            std::ptr::eq(uplink_metrics(), uplink_metrics()),
            "a second block would split the node's view in half"
        );
    }
}
