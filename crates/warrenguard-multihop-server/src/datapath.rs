//! Per-packet datapath helpers shared by the `/v1` and `/v2` exit pumps.
//!
//! Everything here runs once (or more) per packet on a live tunnel, so the
//! cost of each item is multiplied by the node's whole packet rate. Keeping
//! them in one module means the two pumps cannot drift apart on a security
//! gate or a drop-accounting rule, and `benches/datapath.rs` can measure the
//! chain directly (see the `bench-internals` feature).
//!
//! The module is crate-private; the items inside are `pub` only so that
//! feature-gated facade can re-export them. Nothing here reaches a deployer's
//! build.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use quinn::{Connection, DatagramClass, SendDatagramError};
use warrenguard_daita::daita::{DaitaEvent, DaitaMetrics, DaitaState};
use warrenguard_server::tun_dispatch::source_ip_matches;
use warrenguard_transport_core::PacketDevice;
use warrenguard_transport_core::{build_frag_needed, clamp_syn_mss, is_tcp_syn};

/// Bound on each connection's downlink channel. Full ⇒ the router drops
/// (TCP retransmits); sized for a burst without unbounded memory growth.
pub const DOWNLINK_CHANNEL_BOUND: usize = 1024;

/// Cap on the per-IP learned-flow table (canonical 5-tuple -> owning
/// downlink sender). Bounds memory when many short flows churn under one
/// sticky IP; at the cap one existing entry is evicted and that flow falls
/// back to the 5-tuple hash until its next uplink packet re-learns the
/// owner. A normal client holds far fewer than this.
pub const FLOW_TABLE_CAP_PER_IP: usize = 8192;

/// Give up on a connection's RX pump only after this many consecutive
/// TUN write failures. A single transient write error (kernel queue
/// pressure under a burst) used to kill the RX task, which cascaded
/// into a zombie connection: pumps dead, QUIC alive, every flow pinned
/// to it blackholed both ways (2026-06-11 incident, 8-flow collapse).
pub(crate) const MAX_CONSECUTIVE_TUN_WRITE_ERRORS: u32 = 10_000;

/// Extracts the destination IPv4 from a raw inner IP packet, or `None`
/// when the packet is too short or not IPv4.
pub(crate) fn dst_ipv4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

/// Extracts the source IPv4 from a raw inner IP packet (offset 12..16), or
/// `None` when too short or not IPv4. On the uplink the source is the
/// client's own allocated address (the anti-spoof gate has already proven
/// it), which is the slot key the downlink uses as destination.
pub(crate) fn src_ipv4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// Direction-agnostic hash of an inner packet's flow, so an uplink packet
/// (src=client, dst=peer) and its downlink reply (src=peer, dst=client)
/// map to the SAME key. It hashes `(proto, min(endpoint), max(endpoint))`
/// where an endpoint is `(ip, port)`, ordering the two endpoints so the
/// direction drops out. Returns `None` for non-TCP/UDP or malformed
/// packets (the caller then falls back to the plain 5-tuple hash).
///
/// This is the key under which the exit learns, from the uplink, which
/// bonded connection owns a flow, so the downlink returns to the same
/// session instead of being split by a blind hash across every session
/// that happens to share one sticky IP.
#[must_use]
pub fn canonical_flow_key(pkt: &[u8]) -> Option<u64> {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let first = *pkt.first()?;
    let mut h: u64 = FNV_OFFSET;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
    };
    match first >> 4 {
        4 => {
            if pkt.len() < 24 {
                return None;
            }
            let ihl = (first & 0x0f) as usize * 4;
            if ihl < 20 || pkt.len() < ihl + 4 {
                return None;
            }
            let proto = pkt[9];
            if proto != 6 && proto != 17 {
                return None;
            }
            let mut a = [0u8; 6];
            a[..4].copy_from_slice(&pkt[12..16]);
            a[4..].copy_from_slice(&pkt[ihl..ihl + 2]);
            let mut b = [0u8; 6];
            b[..4].copy_from_slice(&pkt[16..20]);
            b[4..].copy_from_slice(&pkt[ihl + 2..ihl + 4]);
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            feed(&[proto]);
            feed(&lo);
            feed(&hi);
            Some(h)
        }
        6 => {
            if pkt.len() < 44 {
                return None;
            }
            let next = pkt[6];
            if next != 6 && next != 17 {
                return None;
            }
            let mut a = [0u8; 18];
            a[..16].copy_from_slice(&pkt[8..24]);
            a[16..].copy_from_slice(&pkt[40..42]);
            let mut b = [0u8; 18];
            b[..16].copy_from_slice(&pkt[24..40]);
            b[16..].copy_from_slice(&pkt[42..44]);
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            feed(&[next]);
            feed(&lo);
            feed(&hi);
            Some(h)
        }
        _ => None,
    }
}

/// Process-wide count of downlink packets tail-dropped by the over-read
/// backpressure gate. Kept observable (rate-limited log) so the early-drop
/// volume can be A/B-compared against the fork's CoDel `dropped_overflow`
/// stat when tuning `WARREN_EXIT_OVERREAD_GATE`.
pub(crate) static OVERREAD_GATE_DROPS: AtomicU64 = AtomicU64::new(0);

/// Fallback MTU when the peer has not yet advertised a datagram frame size
/// (`max_datagram_size()` is `None`): the Warren tunnel floor.
pub(crate) const OVERREAD_GATE_FALLBACK_MTU: usize = 1280;

/// Exit downlink over-read backpressure: `true` when this packet must be
/// tail-dropped because `conn`'s datagram send buffer is within `gate_mtus`
/// MTUs of full.
///
/// With N multi-queue TUN readers feeding one client's single QUIC connection,
/// the aggregate read rate can far exceed the connection's BBR-limited drain
/// rate. The excess piles into the datagram send buffer until the fork's CoDel
/// head-drops (and `send_datagram`'s overflow drops) the OLDEST in-flight
/// datagrams, which is exactly what the inner TCP is waiting to ACK, spiking
/// its retransmits. Dropping the NEWEST packet at the reader keeps the standing
/// queue shallow, so inner-TCP RTT and loss recovery stay fast.
///
/// `datagram_send_buffer_space()` is relative to the LIVE (BDP-adaptive) buffer
/// limit, so a small MTU-multiple low-water stays correct as fork.11 shrinks
/// the buffer toward the path BDP (no fixed-16-MiB constant). `gate_mtus == 0`
/// disables the gate; when the buffer has room it is a no-op, so the gate can
/// only ever reduce occupancy.
pub(crate) fn overread_gate_should_drop(conn: &Connection, gate_mtus: usize) -> bool {
    if gate_mtus == 0 {
        return false;
    }
    let mtu = conn
        .max_datagram_size()
        .unwrap_or(OVERREAD_GATE_FALLBACK_MTU);
    if !overread_should_drop(conn.datagram_send_buffer_space(), mtu, gate_mtus) {
        return false;
    }
    let n = OVERREAD_GATE_DROPS.fetch_add(1, Ordering::Relaxed);
    if n.is_multiple_of(50_000) {
        tracing::debug!(
            total_drops = n + 1,
            "exit downlink over-read gate: tail-drop (rate-limited log)"
        );
    }
    true
}

/// Pure over-read decision: drop when fewer than `gate_mtus` MTUs of buffer
/// `space` remain. `gate_mtus == 0` disables the gate. The threshold scales
/// with `mtu` (the connection's live datagram size), so it stays relative to
/// the BDP-adaptive buffer rather than a fixed byte constant. Split out from
/// the connection read so the boundary/relative-keying logic is unit-testable
/// without a live QUIC connection.
pub(crate) fn overread_should_drop(space: usize, mtu: usize, gate_mtus: usize) -> bool {
    if gate_mtus == 0 {
        return false;
    }
    space < gate_mtus.saturating_mul(mtu)
}

/// This node's live inner-packet budget for one multihop connection: its
/// current QUIC datagram budget minus the wire overhead of the frame format
/// this session speaks ([`MULTIHOP_FRAME_MAX_OVERHEAD`] for `/v1`,
/// `MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD` for `/v2`). Saturates instead of
/// wrapping when the path MTU cannot even carry the frame overhead, and falls
/// back to `u16::MAX` (no clamp) before the connection has negotiated a size.
///
/// A `/v2` DATA frame carries an EMPTY `pq_ct` (the 1088-byte ML-KEM
/// ciphertext rides only the dedicated bootstrap frame), so its overhead is
/// the DATA bound, not the ~1 KB-larger setup bound: subtracting the latter
/// starved a 1452-byte path to a ~240-byte budget, so every real downlink
/// packet exceeded it and was reflected as frag-needed rather than sealed, a
/// silent data black-hole while the tunnel stayed Connected.
#[must_use]
pub fn inner_budget(max_datagram_size: Option<usize>, frame_overhead: usize) -> u16 {
    u16::try_from(
        max_datagram_size
            .unwrap_or(usize::from(u16::MAX))
            .saturating_sub(frame_overhead),
    )
    .unwrap_or(u16::MAX)
}

/// Rewrites the MSS option of a SYN/SYN-ACK down to `budget`, logging the
/// change. A no-op, silently, when [`clamp_syn_mss`] finds the packet
/// already fits or carries no MSS option.
pub(crate) fn clamp_mss_logged(packet: &mut [u8], budget: u16) {
    if let Some((old, new)) = clamp_syn_mss(packet, budget) {
        tracing::debug!(
            old,
            new,
            budget,
            "exit clamped inner TCP MSS to node budget"
        );
    }
}

/// Uplink SYN clamp (client -> exit -> TUN). The [`is_tcp_syn`] pre-filter
/// means the live-budget lookup (a `Connection` state read) is only paid on
/// the rare packets that could actually be rewritten, not on every uplink
/// packet. The MSS a peer announces governs the segments the OTHER side
/// will emit back through this node, so clamping it here caps what any
/// origin server ever sends down through this exit's own transmit budget,
/// healing pre-existing clients with no app update since the clamp lives
/// entirely on the exit (2026-07-15 SNCF incident: a reduced-MTU underlay
/// silently blackholed full-MSS downlink segments while the tunnel stayed
/// Connected).
pub(crate) fn clamp_uplink_syn(packet: &mut [u8], conn: &Connection, frame_overhead: usize) {
    if !is_tcp_syn(packet) {
        return;
    }
    clamp_mss_logged(
        packet,
        inner_budget(conn.max_datagram_size(), frame_overhead),
    );
}

/// Downlink adaptation (TUN -> exit -> client) of a packet about to be
/// sealed, given the live `budget` ([`inner_budget`]). Clamps an outgoing
/// SYN-ACK's MSS the same way as [`clamp_uplink_syn`] (always small enough
/// afterward on its own: a SYN carries no payload). Any other packet that
/// still exceeds `budget` cannot be sealed/sent as-is: `Some` is the RFC
/// 1191/4443 fragmentation-needed reply to reflect into the TUN so the
/// origin server's own PMTUD shrinks its segments within one RTT instead of
/// the exit dropping them silently forever; `None` means seal and send
/// unchanged.
#[must_use]
pub fn adapt_inner_for_budget(packet: &mut [u8], budget: u16) -> Option<Vec<u8>> {
    if is_tcp_syn(packet) {
        clamp_mss_logged(packet, budget);
        return None;
    }
    if packet.len() <= usize::from(budget) {
        return None;
    }
    build_frag_needed(
        packet,
        budget,
        warrenguard_config::TUNNEL_GATEWAY_IP,
        warrenguard_config::TUNNEL_GATEWAY_IPV6,
    )
}

/// Counter whose rate-limited log fires on the first hit and then every
/// `every`-th, so a pathological condition is visible immediately and then
/// stays bounded. Every drop/error class on the datapath is counted this way:
/// a per-packet log would itself become the outage under load.
pub(crate) struct RateLimited {
    count: u64,
    every: u64,
}

impl RateLimited {
    pub(crate) const fn new(every: u64) -> Self {
        Self { count: 0, every }
    }

    /// Records one hit and reports whether it should be logged.
    pub(crate) fn hit(&mut self) -> bool {
        self.count += 1;
        self.count == 1 || self.count.is_multiple_of(self.every)
    }

    pub(crate) const fn count(&self) -> u64 {
        self.count
    }
}

/// What a TUN write did, so the caller can both account for it and decide
/// whether the pump can keep going.
#[derive(PartialEq, Eq)]
pub(crate) enum TunWrite {
    /// The packet reached the device.
    Wrote,
    /// A transient error swallowed this packet; keep pumping.
    Dropped,
    /// An unbroken run of write errors hit the cap: the device is not coming
    /// back, so the pump must end and let the connection be torn down rather
    /// than black-hole every packet in silence.
    Fatal,
}

/// Uplink writer owning the consecutive-error backoff shared by every pump.
/// A single success resets the run, so an occasional transient error never
/// accumulates toward the cap.
pub(crate) struct TunWriter<T> {
    pub(crate) tun: T,
    pub(crate) consecutive_errors: u32,
    pub(crate) errors: RateLimited,
    pub(crate) label: &'static str,
}

impl<T: PacketDevice> TunWriter<T> {
    pub(crate) fn new(tun: T, label: &'static str) -> Self {
        Self {
            tun,
            consecutive_errors: 0,
            errors: RateLimited::new(1_000),
            label,
        }
    }

    pub(crate) async fn write(&mut self, packet: &[u8]) -> TunWrite {
        match self.tun.send(packet).await {
            Ok(()) => {
                self.consecutive_errors = 0;
                TunWrite::Wrote
            }
            Err(e) => {
                self.consecutive_errors += 1;
                if self.errors.hit() {
                    tracing::warn!(
                        error = %e,
                        consecutive = self.consecutive_errors,
                        pump = self.label,
                        "rx_task: transient TUN write error, dropping packet"
                    );
                }
                if self.consecutive_errors >= MAX_CONSECUTIVE_TUN_WRITE_ERRORS {
                    TunWrite::Fatal
                } else {
                    TunWrite::Dropped
                }
            }
        }
    }
}

/// Inner-source anti-spoof gate: a decrypted uplink packet may only carry the
/// address this connection was assigned. Load-bearing authorization, which is
/// why the v4 address is not optional: setup refuses any session it could not
/// assign one to, so the gate is armed for every served connection. Only the
/// drop COUNT is ever logged, never the address (no-log discipline).
pub struct SpoofGate {
    pub(crate) v4: Ipv4Addr,
    pub(crate) v6: Option<Ipv6Addr>,
    pub(crate) drops: RateLimited,
    pub(crate) label: &'static str,
}

impl SpoofGate {
    /// Arm the gate on the address this connection was assigned. `v6` is the
    /// dual-stack counterpart, absent on a v4-only session.
    #[must_use]
    pub fn new(v4: Ipv4Addr, v6: Option<Ipv6Addr>, label: &'static str) -> Self {
        Self {
            v4,
            v6,
            drops: RateLimited::new(10_000),
            label,
        }
    }

    /// `false` when the packet must be dropped, counting the rejection.
    pub fn admits(&mut self, plaintext: &[u8]) -> bool {
        if source_ip_matches(plaintext, self.v4, self.v6) {
            return true;
        }
        if self.drops.hit() {
            tracing::warn!(
                spoofed_drops = self.drops.count(),
                pump = self.label,
                "rx_task: dropped packet with spoofed inner source IP"
            );
        }
        false
    }

    pub(crate) const fn drops(&self) -> u64 {
        self.drops.count()
    }
}

/// Lock-free per-connection memo of the flows already announced to the
/// downlink router. The owner of a flow is set once (first-writer-wins), so
/// the router lock is only ever taken on a flow's FIRST uplink packet, never
/// on the bulk data that follows. Cleared coarsely at the cap.
#[derive(Default)]
pub struct FlowNoter(pub(crate) HashSet<u64>);

impl FlowNoter {
    /// An empty memo: the connection has announced no flow yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when this is the first packet of its flow, so the caller must
    /// take the router lock to record the downlink owner. `false` on the
    /// memoized steady state and on packets that carry no flow key.
    pub fn is_first_of_flow(&mut self, plaintext: &[u8]) -> bool {
        let Some(fk) = canonical_flow_key(plaintext) else {
            return false;
        };
        if self.0.len() >= FLOW_TABLE_CAP_PER_IP {
            self.0.clear();
        }
        self.0.insert(fk)
    }
}

/// How many datagrams an rx pump handles between clock reads for its periodic
/// report. Cheap enough to be invisible at line rate while still reporting
/// every few seconds on a lightly-loaded connection.
pub(crate) const RX_REPORT_CHECK_EVERY: u64 = 64;

/// Per-connection rx counters, reported every [`RX_REPORT_INTERVAL`] so a
/// silent drop class (decode, exit_id, session, open, replay, spoof) is
/// diagnosable from production logs without per-packet spam. Counters only, no
/// identity material.
pub(crate) struct RxReport {
    pub(crate) datagrams: u64,
    pub(crate) decode_errs: u64,
    pub(crate) exit_id_mismatches: u64,
    pub(crate) session_errs: u64,
    pub(crate) open_errs: u64,
    pub(crate) dummies: u64,
    pub(crate) control_frames: u64,
    pub(crate) to_tun: u64,
    pub(crate) replays: u64,
    pub(crate) rate_drops: u64,
    pub(crate) last_report: Instant,
    pub(crate) label: &'static str,
}

/// Cadence of the rx pump's structured counter report.
pub(crate) const RX_REPORT_INTERVAL: Duration = Duration::from_secs(5);

impl RxReport {
    pub(crate) fn new(label: &'static str) -> Self {
        Self {
            datagrams: 0,
            decode_errs: 0,
            exit_id_mismatches: 0,
            session_errs: 0,
            open_errs: 0,
            dummies: 0,
            control_frames: 0,
            to_tun: 0,
            replays: 0,
            rate_drops: 0,
            last_report: Instant::now(),
            label,
        }
    }

    /// Emit the report when the interval has elapsed. The clock is only read
    /// once per [`RX_REPORT_CHECK_EVERY`] datagrams so the per-packet cost is
    /// a counter test, not a `clock_gettime`.
    pub(crate) fn maybe_emit(&mut self, spoofed_drops: u64) {
        if !self.datagrams.is_multiple_of(RX_REPORT_CHECK_EVERY)
            || self.last_report.elapsed() < RX_REPORT_INTERVAL
        {
            return;
        }
        tracing::debug!(
            datagrams = self.datagrams,
            decode_errs = self.decode_errs,
            exit_id_mismatches = self.exit_id_mismatches,
            session_errs = self.session_errs,
            open_errs = self.open_errs,
            dummies = self.dummies,
            control_frames = self.control_frames,
            to_tun = self.to_tun,
            replays = self.replays,
            rate_drops = self.rate_drops,
            spoofed_drops,
            pump = self.label,
            "rx_task report"
        );
        self.last_report = Instant::now();
    }
}

/// Per-connection tx counters, same rationale as [`RxReport`].
pub(crate) struct TxReport {
    pub(crate) from_tun: u64,
    pub(crate) seal_errs: u64,
    pub(crate) encode_errs: u64,
    pub(crate) sent: u64,
    pub(crate) rate_drops: u64,
    pub(crate) last_report: Instant,
    pub(crate) label: &'static str,
}

impl TxReport {
    pub(crate) fn new(label: &'static str) -> Self {
        Self {
            from_tun: 0,
            seal_errs: 0,
            encode_errs: 0,
            sent: 0,
            rate_drops: 0,
            last_report: Instant::now(),
            label,
        }
    }

    pub(crate) fn maybe_emit(&mut self, too_large: u64, mtu_reflected: u64) {
        if !self.from_tun.is_multiple_of(RX_REPORT_CHECK_EVERY)
            || self.last_report.elapsed() < RX_REPORT_INTERVAL
        {
            return;
        }
        tracing::debug!(
            from_tun = self.from_tun,
            seal_errs = self.seal_errs,
            encode_errs = self.encode_errs,
            sent = self.sent,
            rate_drops = self.rate_drops,
            too_large,
            mtu_reflected,
            pump = self.label,
            "tx_task report"
        );
        self.last_report = Instant::now();
    }
}

/// The downlink steps every tx pump runs before the seal, which is the only
/// part that differs between `/v1` and `/v2`: read the routed packet, apply
/// over-read backpressure, and adapt it to the live inner budget.
///
/// `Break` ends the tx task (the downlink source is exhausted).
/// `Continue(None)` means the packet was consumed without producing anything
/// to seal (tail-dropped, or reflected as frag-needed).
pub(crate) async fn next_sealable<T: PacketDevice>(
    down_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    conn: &Connection,
    tun: &T,
    frame_overhead: usize,
    reflected: &mut RateLimited,
    label: &'static str,
) -> ControlFlow<(), Option<Vec<u8>>> {
    let Some(mut packet) = down_rx.recv().await else {
        return ControlFlow::Break(());
    };
    // Over-read backpressure: drop the newest packet BEFORE sealing (and
    // before any DAITA uplink-sent event, which must only fire for a packet
    // that actually egresses) when the client's connection buffer is near
    // full. See the gate helper.
    if overread_gate_should_drop(conn, warrenguard_config::knobs::exit_overread_gate_mtus()) {
        return ControlFlow::Continue(None);
    }
    // Reject/clamp before sealing: see `adapt_inner_for_budget`.
    let budget = inner_budget(conn.max_datagram_size(), frame_overhead);
    if let Some(ptb) = adapt_inner_for_budget(&mut packet, budget) {
        if reflected.hit() {
            tracing::warn!(
                mtu_reflected = reflected.count(),
                budget,
                pump = label,
                "tx_task: packet exceeds downlink budget, reflecting frag-needed instead of sealing"
            );
        }
        if let Err(e) = tun.send(&ptb).await {
            tracing::trace!(error = %e, pump = label, "tx_task: frag-needed reflection tun write failed");
        }
        return ControlFlow::Continue(None);
    }
    ControlFlow::Continue(Some(packet))
}

/// Put one already-sealed downlink frame on the wire. `Break` means the
/// connection can never carry another datagram, so the tx task must end.
pub(crate) fn send_sealed(
    conn: &Connection,
    bytes: Vec<u8>,
    class: DatagramClass,
    too_large: &mut RateLimited,
    label: &'static str,
) -> ControlFlow<()> {
    match conn.send_datagram_classified(bytes.into(), class) {
        Ok(()) => ControlFlow::Continue(()),
        // Transient: Quinn's black-hole detector can lower the path-MTU
        // estimate under a loss burst, making an already-sealed frame "too
        // large" for a moment. Drop the packet (TCP retransmits); returning
        // here used to permanently mute this connection's downlink while QUIC
        // stayed alive, collapsing every bonded flow onto the last surviving
        // sender (2026-06-11 incident).
        Err(SendDatagramError::TooLarge) => {
            if too_large.hit() {
                tracing::warn!(
                    too_large = too_large.count(),
                    pump = label,
                    "tx_task: datagram too large for current path MTU, dropped"
                );
            }
            ControlFlow::Continue(())
        }
        // Connection gone (or datagrams disabled by the peer): nothing further
        // can ever be sent on this conn.
        Err(_) => ControlFlow::Break(()),
    }
}

/// DAITA state shared by a connection's rx, tx and timer tasks.
pub(crate) struct DaitaShared {
    pub(crate) state: Mutex<DaitaState>,
    /// Woken whenever rx or tx fires events that may have scheduled a closer
    /// action timer. Without it the timer parks on the placeholder deadline it
    /// read before any event fired and the machine never produces a dummy.
    /// `Notify` consolidates wake-ups: a burst of events wakes the timer once,
    /// which then re-reads an already up-to-date state.
    pub(crate) changed: tokio::sync::Notify,
}

/// A connection's DAITA cover driver, or nothing when this connection runs no
/// machine. Keeping the un-armed case an empty `Option` means the pump has one
/// shape while a connection without cover pays neither the shared lock nor the
/// clock read the maybenot choreography needs, and spawns no timer task.
#[derive(Clone)]
pub struct DaitaSink(Option<Arc<DaitaShared>>);

impl DaitaSink {
    /// A connection running no cover machine: every hook is a null check.
    #[must_use]
    pub const fn off() -> Self {
        Self(None)
    }

    /// A connection driving `state`, with the timer wake-up channel its
    /// three tasks share.
    #[must_use]
    pub fn armed(state: DaitaState) -> Self {
        Self(Some(Arc::new(DaitaShared {
            state: Mutex::new(state),
            changed: tokio::sync::Notify::new(),
        })))
    }

    /// The shared state a connection's timer task drives, or `None` when
    /// this connection runs no cover machine and needs no timer at all.
    pub(crate) fn shared(&self) -> Option<&Arc<DaitaShared>> {
        self.0.as_ref()
    }

    /// Push `events` into the machine and wake the timer, if this connection
    /// has one.
    pub fn fire(&self, events: &[DaitaEvent]) {
        if let Some(shared) = &self.0 {
            shared.state.lock().fire_events(events, Instant::now());
            shared.changed.notify_one();
        }
    }

    /// The event sequence for one real (non-dummy) packet sent downlink,
    /// fired BEFORE the seal so the framework observes the egress timing
    /// independently of any QUIC backpressure in `send_datagram`.
    pub(crate) fn on_real_uplink_sent(&self) {
        if let Some(shared) = &self.0 {
            shared.state.lock().on_real_uplink_sent(Instant::now());
            shared.changed.notify_one();
        }
    }

    /// Live emission profile for the close log: zeroes when this connection
    /// ran no machine.
    pub(crate) fn snapshot(&self) -> (DaitaMetrics, usize) {
        match &self.0 {
            Some(shared) => {
                let st = shared.state.lock();
                (st.metrics(), st.machines_count())
            }
            None => (DaitaMetrics::default(), 0),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A peer on the public internet: the far end of every synthetic packet
    /// these tests push through the gates.
    const PEER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    /// Packet device whose writes always fail, so the rx pump's fatal
    /// consecutive-error cap is reachable without a real TUN.
    #[derive(Clone)]
    struct FailingTun;

    impl PacketDevice for FailingTun {
        async fn recv(&self) -> std::io::Result<Vec<u8>> {
            std::future::pending().await
        }

        async fn send(&self, _packet: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("tun down"))
        }

        fn try_recv(&self) -> std::io::Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }

    /// Builds a minimal IPv4 packet (20-byte header) with the given src.
    fn ipv4_packet_from(src: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.octets());
        p
    }

    /// The gate is a kill-switchable safety, not a hard-coded behaviour: with
    /// `gate_mtus == 0` it must NEVER drop, even when the send buffer is empty.
    #[test]
    fn overread_gate_disabled_never_drops() {
        assert!(
            !overread_should_drop(0, 1280, 0),
            "disabled gate must pass a full buffer"
        );
        assert!(!overread_should_drop(1_000_000, 1280, 0));
    }

    /// The gate's whole purpose: when the connection's datagram send buffer has
    /// less than `gate_mtus` MTUs of room, the NEW packet is tail-dropped before
    /// it can deepen the standing queue into the CoDel oldest-first head-drop.
    #[test]
    fn overread_gate_drops_when_buffer_near_full() {
        // 1 KiB of room left, 4-MTU (5120 B) low-water at a 1280 B MTU: drop.
        assert!(overread_should_drop(1024, 1280, 4));
        // No room at all: drop.
        assert!(overread_should_drop(0, 1280, 4));
    }

    /// Symmetric to the drop case: with plenty of room the gate is a no-op, so
    /// the datapath is unchanged whenever the connection is draining normally.
    #[test]
    fn overread_gate_passes_when_space_available() {
        assert!(!overread_should_drop(100_000, 1280, 4));
        // Exactly at the low-water is enough room (strict `<`): the boundary
        // packet passes, so the gate never fires one MTU too early.
        assert!(
            !overread_should_drop(4 * 1280, 1280, 4),
            "at the low-water, pass"
        );
        // One byte under the low-water fires.
        assert!(
            overread_should_drop(4 * 1280 - 1, 1280, 4),
            "just under the low-water, drop"
        );
    }

    /// Relative keying (the property that lets the gate survive fork.11's
    /// BDP-adaptive buffer without a fixed 16-MiB constant): the SAME `gate_mtus`
    /// yields a threshold that scales with the connection's live MTU. With the
    /// same 5000 B of room, a 1000 B MTU (threshold 4000) passes but a 2000 B
    /// MTU (threshold 8000) drops.
    #[test]
    fn overread_gate_threshold_is_relative_to_mtu() {
        assert!(!overread_should_drop(5000, 1000, 4), "5000 >= 4*1000, pass");
        assert!(overread_should_drop(5000, 2000, 4), "5000 < 4*2000, drop");
    }

    #[test]
    fn rate_limited_logs_the_first_hit_then_every_nth() {
        let mut r = RateLimited::new(4);
        let logged: Vec<bool> = (0..9).map(|_| r.hit()).collect();
        assert_eq!(
            logged,
            vec![true, false, false, true, false, false, false, true, false],
            "a rate-limited counter must surface the first occurrence immediately \
             and then only every nth"
        );
        assert_eq!(r.count(), 9, "every hit is counted, logged or not");
    }

    #[tokio::test]
    async fn tun_writer_drops_transient_errors_then_declares_the_device_fatal() {
        // A wedged TUN must end the rx pump so the connection is torn down and
        // the client redials, instead of silently black-holing every packet
        // for the rest of the session.
        let mut w = TunWriter::new(FailingTun, "test");
        for i in 1..MAX_CONSECUTIVE_TUN_WRITE_ERRORS {
            assert!(
                w.write(b"x").await == TunWrite::Dropped,
                "error {i} is below the cap and must only drop the packet"
            );
        }
        assert!(
            w.write(b"x").await == TunWrite::Fatal,
            "the cap must end the pump"
        );
    }

    #[tokio::test]
    async fn tun_writer_success_resets_the_error_run() {
        // A device that fails intermittently must never accumulate toward the
        // fatal cap: only an UNBROKEN run means the device is gone.
        let mut w = TunWriter::new(FailingTun, "test");
        for _ in 0..MAX_CONSECUTIVE_TUN_WRITE_ERRORS - 1 {
            let _ = w.write(b"x").await;
        }
        w.consecutive_errors = 0; // what one successful write does
        assert!(
            w.write(b"x").await == TunWrite::Dropped,
            "after a success the run restarts from zero"
        );
    }

    #[test]
    fn spoof_gate_admits_only_the_assigned_source_address() {
        let assigned = Ipv4Addr::new(10, 66, 0, 7);
        let mut gate = SpoofGate::new(assigned, None, "test");
        assert!(
            gate.admits(&ipv4_packet_from(assigned)),
            "the client's own assigned address must pass"
        );
        assert!(
            !gate.admits(&ipv4_packet_from(Ipv4Addr::new(10, 66, 0, 8))),
            "a neighbour's tunnel address must be dropped"
        );
        assert!(
            !gate.admits(&ipv4_packet_from(Ipv4Addr::new(93, 184, 216, 34))),
            "an arbitrary forged public source must be dropped"
        );
        assert_eq!(gate.drops(), 2, "every rejection is counted for the report");
    }

    #[test]
    fn spoof_gate_drops_v6_when_the_connection_is_v4_only() {
        // A v4-only session has no expected v6 source, so a v6 packet has
        // nothing to be gated against and must not reach the TUN.
        let mut gate = SpoofGate::new(Ipv4Addr::new(10, 66, 0, 7), None, "test");
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert!(!gate.admits(&v6));
    }

    #[test]
    fn flow_noter_announces_a_flow_once_however_many_packets_it_carries() {
        // The router lock is only taken on a `true`, so a bulk transfer must
        // answer from the memo after its first packet.
        let ip = Ipv4Addr::new(10, 66, 0, 7);
        let pkt = ipv4_tcp_full(ip, PEER, 4242, 443);
        let mut noter = FlowNoter::new();
        assert!(noter.is_first_of_flow(&pkt), "the first packet announces");
        for _ in 0..5 {
            assert!(
                !noter.is_first_of_flow(&pkt),
                "every later packet of the same flow must answer from the memo"
            );
        }
    }

    #[test]
    fn flow_noter_clears_at_the_cap_so_the_memo_stays_bounded() {
        // The memo is per-connection and must not grow with a scanner opening
        // unbounded flows.
        let ip = Ipv4Addr::new(10, 66, 0, 7);
        let mut noter = FlowNoter::new();
        for port in 0..=u16::try_from(FLOW_TABLE_CAP_PER_IP).expect("cap fits a port") {
            noter.is_first_of_flow(&ipv4_tcp_full(ip, PEER, port, 443));
        }
        assert!(
            noter.0.len() <= FLOW_TABLE_CAP_PER_IP,
            "the flow memo must stay bounded, got {}",
            noter.0.len()
        );
    }

    #[test]
    fn a_connection_without_cover_allocates_no_daita_state() {
        // The un-armed case is the common one (a client that did not negotiate
        // DAITA, or a DAITA-off exit); it must cost nothing per packet and
        // report an honest empty profile at close.
        let off = DaitaSink::off();
        off.fire(&[DaitaEvent::TunnelRecv]);
        off.on_real_uplink_sent();
        let (metrics, machines) = off.snapshot();
        assert_eq!(machines, 0);
        assert_eq!(metrics.padding_fired, 0);
    }

    #[test]
    fn an_armed_sink_reports_the_machines_it_actually_drives() {
        // The per-conn close log reads this snapshot, so ops can tell a
        // connection that really ran cover from one that only sat on a
        // DAITA-armed exit. A wrong count here would claim protection that
        // was never applied.
        let cfg = warrenguard_daita::DaitaPool::default_pool()
            .pick_named_os("tamaraw")
            .expect("curated pool carries tamaraw");
        let armed =
            DaitaSink::armed(DaitaState::from_config(&cfg, Instant::now()).expect("state builds"));
        let (_, machines) = armed.snapshot();
        assert!(
            machines > 0,
            "an armed sink must report the machines it drives"
        );
        armed.fire(&[DaitaEvent::TunnelRecv]);
        armed.on_real_uplink_sent();
        assert!(
            armed.snapshot().1 > 0,
            "firing events must not disarm the connection's machines"
        );
    }

    /// Builds a minimal IPv4 TCP packet with explicit src/dst IP and ports,
    /// so uplink and its downlink reply can be constructed as mirror images.
    pub(crate) fn ipv4_tcp_full(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45;
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src_ip.octets());
        p[16..20].copy_from_slice(&dst_ip.octets());
        p[20..22].copy_from_slice(&src_port.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    #[test]
    fn canonical_flow_key_is_direction_agnostic() {
        let client = Ipv4Addr::new(10, 66, 0, 7);
        let peer = Ipv4Addr::new(93, 184, 216, 34);
        // Uplink (client -> peer) and its downlink reply (peer -> client)
        // are mirror images; they MUST hash to the same flow key.
        let up = ipv4_tcp_full(client, peer, 51000, 443);
        let down = ipv4_tcp_full(peer, client, 443, 51000);
        assert_eq!(
            canonical_flow_key(&up),
            canonical_flow_key(&down),
            "reverse directions of one flow must share a key"
        );
        // A different flow (other client port) must differ.
        let other = ipv4_tcp_full(client, peer, 51001, 443);
        assert_ne!(canonical_flow_key(&up), canonical_flow_key(&other));
        // Non-TCP/UDP yields None (caller falls back to the plain hash).
        let mut icmp = up.clone();
        icmp[9] = 1;
        assert_eq!(canonical_flow_key(&icmp), None);
    }

    /// Minimal IPv4 TCP SYN carrying one MSS option, enough for
    /// `clamp_syn_mss` to locate and rewrite it. Checksums are irrelevant
    /// here: `adapt_inner_for_budget` never reads them, and the incremental
    /// checksum maintenance itself is already vector-tested in
    /// `warrenguard_transport_core`.
    fn syn_packet(mss: u16) -> Vec<u8> {
        let mut p = vec![0u8; 44];
        p[0] = 0x45; // version 4, IHL 20
        p[9] = 6; // proto TCP
        let t = 20;
        p[t + 12] = 6 << 4; // data offset: 24 bytes (20 base + 4-byte MSS option)
        p[t + 13] = 0x02; // SYN
        p[t + 20] = 2; // MSS option kind
        p[t + 21] = 4; // MSS option length
        p[t + 22..t + 24].copy_from_slice(&mss.to_be_bytes());
        p
    }

    #[test]
    fn adapt_inner_for_budget_clamps_a_syn_and_sends_it() {
        let mut pkt = syn_packet(1460);
        assert_eq!(
            adapt_inner_for_budget(&mut pkt, 200),
            None,
            "a clamped SYN is sent, never reflected"
        );
        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert!(
            mss < 1460,
            "MSS option must have been lowered to fit the budget"
        );
    }

    #[test]
    fn adapt_inner_for_budget_leaves_a_fitting_non_syn_packet_untouched() {
        let mut pkt = ipv4_tcp_full(
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(10, 66, 0, 7),
            443,
            51000,
        );
        let original = pkt.clone();
        assert_eq!(adapt_inner_for_budget(&mut pkt, u16::MAX), None);
        assert_eq!(
            pkt, original,
            "a fitting non-SYN packet must stay untouched"
        );
    }

    #[test]
    fn adapt_inner_for_budget_reflects_frag_needed_for_an_oversized_non_syn_packet() {
        let mut pkt = vec![0u8; 1300];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP: irrelevant to the too-large path
        pkt[12..16].copy_from_slice(&[93, 184, 216, 34]);
        let icmp =
            adapt_inner_for_budget(&mut pkt, 1200).expect("oversized packet must be reflected");
        assert_eq!(icmp[0] >> 4, 4);
        assert_eq!(icmp[9], 1, "ICMP");
        assert_eq!(icmp[20], 3, "destination unreachable");
        assert_eq!(icmp[21], 4, "fragmentation needed");
        assert_eq!(
            u16::from_be_bytes([icmp[26], icmp[27]]),
            1200,
            "next-hop MTU echoes the live budget"
        );
    }

    #[test]
    fn adapt_inner_for_budget_returns_none_when_the_packet_already_fits() {
        let mut pkt = vec![0u8; 100];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[93, 184, 216, 34]);
        assert_eq!(adapt_inner_for_budget(&mut pkt, 100), None);
    }

    #[test]
    fn inner_budget_subtracts_the_frame_overhead_from_the_live_datagram_size() {
        assert_eq!(inner_budget(Some(1300), 83), 1217);
    }

    #[test]
    fn inner_budget_saturates_instead_of_underflowing_when_overhead_exceeds_the_datagram() {
        assert_eq!(inner_budget(Some(50), 83), 0);
    }

    #[test]
    fn inner_budget_defaults_to_u16_max_before_the_connection_negotiates_a_size() {
        assert_eq!(inner_budget(None, 83), u16::MAX - 83);
    }

    #[cfg(feature = "pq-hpke")]
    #[test]
    fn pq_inner_budget_sizes_from_the_data_frame_not_the_setup_bound() {
        // A /v2 DATA frame carries an empty pq_ct, so the exit's downlink budget
        // must subtract the small data-frame overhead, not the ~1174-byte setup
        // bound (which held the 1088-byte ML-KEM ciphertext). The setup bound
        // starved a 1452-byte path to a ~240-byte budget, so every real downlink
        // packet was reflected as frag-needed instead of sealed: a silent data
        // black-hole while the tunnel stayed Connected.
        assert!(
            inner_budget(
                Some(1452),
                warrenguard_multihop::MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD,
            ) > 1000,
            "the /v2 downlink budget must not be starved by the ~1 KB setup bound"
        );
    }
}
