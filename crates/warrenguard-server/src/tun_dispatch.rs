//! Centralized TUN downlink dispatcher for multi-client exit.
//!
//! Replaces per-connection `pump_tun_to_quic` with a single TUN reader
//! that routes packets to the correct QUIC connection based on the
//! destination IP extracted from each packet's header.
//!
//! Architecture (cf. wireguard-go `RoutineReadFromTUN`):
//! - 1 task reads TUN in batch (`recv_batch`).
//! - Destination IPv4/v6 extracted from the IP header.
//! - O(1) lookup in a table indexed by IP offset within 10.66.0.0/16.
//! - `conn.send_datagram()` directly (no intermediate channel).
//! - Multi-conn same client: sticky 5-tuple hash via `flow_hash_5tuple`.
//! - Per-client downlink rate limiting via `IdentityLimiter`.
//! - DAITA `NormalSent + TunnelSent` events fired after successful dispatch.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;
use parking_lot::RwLock;
use quinn::{Connection, SendDatagramError};
use warrenguard_ratelimit::IdentityLimiter;
use warrenguard_wire::WarrenPubkey;

use warrenguard_transport_core::ip_parse::{extract_dst_ipv4, extract_dst_ipv6};
// Re-exported so the exit-side multihop termination can reach the anti-spoof
// gate from this module rather than reaching into the transport core.
pub use warrenguard_transport_core::ip_parse::source_ip_matches;

use warrenguard_daita::daita::{DaitaEvent, DaitaState};
use warrenguard_transport_core::PacketDevice;
use warrenguard_transport_core::error::{Result, TunnelError};

#[must_use]
pub(crate) fn pool_offset(ip: Ipv4Addr) -> Option<u16> {
    let octets = ip.octets();
    if octets[0] != 10 || octets[1] != 66 {
        return None;
    }
    let offset = u16::from(octets[2]) << 8 | u16::from(octets[3]);
    // 0 = network, 1 = gateway, 65535 = broadcast
    if offset < 2 || offset == 65535 {
        return None;
    }
    Some(offset)
}

/// Rate-limited log gate: [`Self::should_log`] returns `true` for the
/// first occurrence and then once every `every` occurrences, so an
/// error in a packet loop stays visible without flooding the journal.
pub(crate) struct LogEveryN {
    count: u64,
    every: u64,
}

impl LogEveryN {
    pub(crate) const fn new(every: u64) -> Self {
        Self { count: 0, every }
    }

    /// Records one occurrence; `true` when this one should be logged.
    pub(crate) fn should_log(&mut self) -> bool {
        self.count += 1;
        self.count == 1 || self.count.is_multiple_of(self.every)
    }

    /// Total occurrences recorded so far.
    pub(crate) fn count(&self) -> u64 {
        self.count
    }
}

/// Shared DAITA state for a client, accessible from the dispatcher
/// (uplink events) and the per-connection timer task.
pub struct SharedDaitaState {
    /// DAITA state machine, shared between dispatcher and per-connection timer.
    pub state: Arc<parking_lot::Mutex<DaitaState>>,
    /// Wakes the per-connection timer task when the dispatcher fires events.
    pub notify: Arc<tokio::sync::Notify>,
}

impl SharedDaitaState {
    /// Wraps a `DaitaState` in shared Arc + Mutex + Notify.
    #[must_use]
    pub fn new(daita_state: DaitaState) -> Self {
        Self {
            state: Arc::new(parking_lot::Mutex::new(daita_state)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

/// Snapshot of a dispatch slot's data, extracted under the RwLock read
/// guard to minimize lock hold time. All fields are cheap to clone
/// (Arc, Connection is Arc-backed internally).
struct DispatchTarget {
    conn: Connection,
    daita: Option<Arc<SharedDaitaState>>,
    metrics: Option<Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
}

/// Outcome of resolving a downlink packet's route, before the payload is
/// turned into a datagram (see [`TunDownlinkTable::resolve_for_send`]).
enum SendDecision {
    /// No connection owns this destination IP; caller returns `Ok(false)`.
    NoRoute,
    /// The packet was intentionally dropped (downlink rate limit); the caller
    /// returns `Ok(true)` (handled, nothing to send).
    Dropped,
    /// Send the payload to this resolved target.
    Send(DispatchTarget),
}

pub(crate) struct DispatchSlot {
    conns: Vec<Connection>,
    round_robin: AtomicUsize,
    client_id: WarrenPubkey,
    daita: Option<Arc<SharedDaitaState>>,
    metrics: Option<Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
}

impl DispatchSlot {
    pub(crate) fn new(
        conn: Connection,
        client_id: WarrenPubkey,
        daita: Option<Arc<SharedDaitaState>>,
        metrics: Option<Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
    ) -> Self {
        Self {
            conns: vec![conn],
            round_robin: AtomicUsize::new(0),
            client_id,
            daita,
            metrics,
        }
    }

    pub(crate) fn add_conn(
        &mut self,
        conn: Connection,
        client_id: WarrenPubkey,
        daita: Option<Arc<SharedDaitaState>>,
        metrics: Option<Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
    ) {
        self.conns.push(conn);
        self.client_id = client_id;
        if daita.is_some() {
            self.daita = daita;
        }
        if metrics.is_some() {
            self.metrics = metrics;
        }
    }

    pub(crate) fn remove_conn(&mut self, conn: &Connection) {
        self.conns.retain(|c| c.stable_id() != conn.stable_id());
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    pub(crate) fn conn_count(&self) -> usize {
        self.conns.len()
    }

    fn snapshot(&self, pkt: &[u8]) -> Option<DispatchTarget> {
        if self.conns.is_empty() {
            return None;
        }
        let n = self.conns.len();
        let idx = match warrenguard_transport_core::flow_hash::flow_hash_5tuple(pkt) {
            Some(h) => (h as usize) % n,
            None => self.round_robin.fetch_add(1, Ordering::Relaxed) % n,
        };
        Some(DispatchTarget {
            conn: self.conns[idx].clone(),
            daita: self.daita.clone(),
            metrics: self.metrics.clone(),
        })
    }
}

/// Downlink routing table: maps tunnel IPv4/v6 to QUIC connection(s).
///
/// IPv4: indexed by offset within 10.66.0.0/16 (O(1) array lookup).
/// IPv6: `HashMap<Ipv6Addr, u16>` mapping to the same slot offset.
///
/// Includes per-client downlink rate limiting and DAITA event firing.
pub struct TunDownlinkTable {
    slots: RwLock<Vec<Option<DispatchSlot>>>,
    ipv6_to_offset: RwLock<HashMap<Ipv6Addr, u16>>,
    downlink_limiter: Option<Arc<IdentityLimiter<WarrenPubkey>>>,
}

impl Default for TunDownlinkTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TunDownlinkTable {
    /// Creates an empty table covering the 10.66.0.0/16 pool.
    #[must_use]
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(65536);
        slots.resize_with(65536, || None);
        Self {
            slots: RwLock::new(slots),
            ipv6_to_offset: RwLock::new(HashMap::new()),
            downlink_limiter: None,
        }
    }

    /// Sets the downlink rate limiter (exit -> client bandwidth cap).
    #[must_use]
    pub fn with_downlink_limiter(
        mut self,
        limiter: Option<Arc<IdentityLimiter<WarrenPubkey>>>,
    ) -> Self {
        self.downlink_limiter = limiter;
        self
    }

    /// Registers a connection for the given tunnel IP pair. Returns the
    /// number of connections now registered on this slot (1 = this is
    /// the session's first/only connection), so callers can attach
    /// session-wide observability exactly once per session.
    pub fn register(
        &self,
        ipv4: Ipv4Addr,
        ipv6: Option<Ipv6Addr>,
        conn: Connection,
        client_id: WarrenPubkey,
        daita: Option<Arc<SharedDaitaState>>,
        metrics: Option<Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
    ) -> usize {
        let Some(offset) = pool_offset(ipv4) else {
            return 0;
        };
        let mut slots = self.slots.write();
        let count = match &mut slots[offset as usize] {
            Some(slot) => {
                slot.add_conn(conn, client_id, daita, metrics);
                slot.conn_count()
            }
            entry @ None => {
                *entry = Some(DispatchSlot::new(conn, client_id, daita, metrics));
                1
            }
        };
        drop(slots);

        if let Some(v6) = ipv6 {
            self.ipv6_to_offset.write().insert(v6, offset);
        }
        count
    }

    /// Unregisters a connection. Removes the slot if no connections remain.
    ///
    /// The shared IPv6 route of a bonded session is removed only when
    /// the LAST connection unregisters: dropping it on the first dead
    /// sibling would blackhole the v6 downlink for the survivors.
    pub fn unregister(&self, ipv4: Ipv4Addr, ipv6: Option<Ipv6Addr>, conn: &Connection) {
        let Some(offset) = pool_offset(ipv4) else {
            return;
        };
        let mut slots = self.slots.write();
        let mut slot_empty = false;
        if let Some(slot) = &mut slots[offset as usize] {
            slot.remove_conn(conn);
            if slot.is_empty() {
                slots[offset as usize] = None;
                slot_empty = true;
            }
        } else {
            // No slot at all: nothing routes through this offset, the
            // stale v6 mapping (if any) must not survive either.
            slot_empty = true;
        }
        drop(slots);

        if slot_empty && let Some(v6) = ipv6 {
            self.ipv6_to_offset.write().remove(&v6);
        }
    }

    fn resolve_offset(&self, pkt: &[u8]) -> Option<u16> {
        if pkt.is_empty() {
            return None;
        }
        match pkt[0] >> 4 {
            4 => {
                let dst = extract_dst_ipv4(pkt)?;
                pool_offset(dst)
            }
            6 => {
                let dst = extract_dst_ipv6(pkt)?;
                let map = self.ipv6_to_offset.read();
                map.get(&dst).copied()
            }
            _ => None,
        }
    }

    /// Resolves the destination connection for a downlink packet and applies
    /// the per-client downlink rate limit, reading only the packet header. The
    /// send itself is left to [`Self::finish_send`] so the caller chooses how
    /// the payload becomes a [`Bytes`]: a borrow copies, an owned `Vec` moves
    /// (zero-copy). Splitting the two is what lets the hot path avoid a
    /// per-packet allocation without duplicating the routing/limiter logic.
    fn resolve_for_send(&self, pkt: &[u8]) -> SendDecision {
        let Some(offset) = self.resolve_offset(pkt) else {
            return SendDecision::NoRoute;
        };
        // Snapshot the target under the read guard, then drop the guard before
        // any send / DAITA work.
        let slots = self.slots.read();
        let Some(slot) = &slots[offset as usize] else {
            return SendDecision::NoRoute;
        };
        if let Some(limiter) = &self.downlink_limiter
            && !limiter.try_consume(&slot.client_id, pkt.len() as u64)
        {
            tracing::trace!(bytes = pkt.len(), "dispatch: rate limit drop (downlink)");
            return SendDecision::Dropped;
        }
        match slot.snapshot(pkt) {
            Some(t) => SendDecision::Send(t),
            None => SendDecision::NoRoute,
        }
    }

    /// Sends an already-resolved downlink `payload` to `target`, firing metrics
    /// and DAITA events. `Ok(true)` = handled (sent or intentionally dropped),
    /// `Ok(false)` = the connection was lost.
    fn finish_send(&self, target: &DispatchTarget, payload: Bytes) -> Result<bool> {
        if let Some(max) = target.conn.max_datagram_size()
            && payload.len() > max
        {
            tracing::trace!(
                pkt_size = payload.len(),
                max_datagram = max,
                "dispatch: dropping oversized packet"
            );
            return Ok(true);
        }
        let len = payload.len();
        match target.conn.send_datagram(payload) {
            Ok(()) => {
                if let Some(m) = &target.metrics {
                    m.record_tx(len as u64);
                }
                if let Some(daita) = &target.daita {
                    let now = Instant::now();
                    let mut state = daita.state.lock();
                    state.fire_events(&[DaitaEvent::NormalSent], now);
                    state.fire_events(&[DaitaEvent::TunnelSent], now);
                    drop(state);
                    daita.notify.notify_one();
                }
                Ok(true)
            }
            Err(SendDatagramError::TooLarge) => {
                tracing::trace!("dispatch: PMTU race drop");
                Ok(true)
            }
            Err(SendDatagramError::ConnectionLost(_)) => Ok(false),
            Err(e) => Err(TunnelError::QuicSendDatagram {
                context: "tun_dispatch".into(),
                source: e,
            }),
        }
    }

    /// Routes a borrowed packet to the correct QUIC connection by destination
    /// IP. Copies the payload into the datagram; prefer
    /// [`Self::dispatch_packet_owned`] on the hot path to avoid that copy.
    /// Returns `Ok(true)` if handled, `Ok(false)` if no route.
    pub fn dispatch_packet(&self, pkt: &[u8]) -> Result<bool> {
        match self.resolve_for_send(pkt) {
            SendDecision::NoRoute => Ok(false),
            SendDecision::Dropped => Ok(true),
            SendDecision::Send(target) => self.finish_send(&target, Bytes::copy_from_slice(pkt)),
        }
    }

    /// Zero-copy variant of [`Self::dispatch_packet`] for the downlink hot
    /// path: takes ownership of the packet `Vec` (already allocated by the TUN
    /// batch read) and moves it into the datagram via `Bytes::from`, so no
    /// per-packet allocation or copy happens. This removes the downlink
    /// dispatcher's largest allocator hotspot at multi-Gbps line rates.
    /// Returns `Ok(true)` if handled, `Ok(false)` if no route.
    pub fn dispatch_packet_owned(&self, pkt: Vec<u8>) -> Result<bool> {
        match self.resolve_for_send(&pkt) {
            SendDecision::NoRoute => Ok(false),
            SendDecision::Dropped => Ok(true),
            SendDecision::Send(target) => self.finish_send(&target, Bytes::from(pkt)),
        }
    }

    /// Number of active slots (IPs with at least one connection).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.slots.read().iter().filter(|s| s.is_some()).count()
    }
}

/// Single TUN reader dispatcher. Reads TUN packets in batch and routes
/// each to the correct QUIC connection by destination IP.
pub async fn pump_tun_downlink<T: PacketDevice>(
    tun: T,
    table: Arc<TunDownlinkTable>,
) -> Result<()> {
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(warrenguard_pump::PUMP_UPLINK_BATCH_SIZE);
    // Survive transient TUN read errors (EINTR/ENOBUFS bursts under high
    // PPS): this single reader is the downlink for EVERY connected
    // client, so exiting on the first error silently blackholes the
    // whole exit (cf. an earlier multihop incident). Only a long
    // unbroken error streak (TUN truly gone) surfaces as Err.
    let mut tun_io = warrenguard_pump::TunIoTolerance::new("tun_dispatch recv_batch");
    // Dispatch errors are non-fatal (the per-connection pumps own the
    // connection lifecycle) but must stay visible: an exit silently
    // swallowing send errors for every client is exactly the
    // degradation an earlier incident hid. First error logged,
    // then one log every N (no client identifiers in the message).
    let mut dispatch_err_log = LogEveryN::new(10_000);
    loop {
        batch.clear();
        let n = match tun
            .recv_batch(warrenguard_pump::PUMP_UPLINK_BATCH_SIZE, &mut batch)
            .await
        {
            Ok(n) => {
                tun_io.ok();
                n
            }
            Err(e) if warrenguard_pump::is_err_too_many_segments(&e) => {
                tracing::warn!("dispatch: dropped oversized GSO packet");
                continue;
            }
            Err(e) => {
                tun_io.tolerate(&e).await?;
                continue;
            }
        };
        for pkt in batch.drain(..n) {
            if warrenguard_pump::is_daita_dummy(&pkt) {
                continue;
            }
            // Owned dispatch moves the batch's `Vec` straight into the QUIC
            // datagram (no per-packet copy or allocation on the hot path).
            if let Err(e) = table.dispatch_packet_owned(pkt)
                && dispatch_err_log.should_log()
            {
                tracing::warn!(
                    error = %e,
                    occurrences = dispatch_err_log.count(),
                    "downlink dispatch error (rate-limited log, packet dropped)"
                );
            }
        }
    }
}

/// Per-connection QUIC->TUN pump with DAITA downlink events and timer.
/// Combines `pump_quic_to_tun` + DAITA event firing + dummy timer in
/// a single task, sharing the DaitaState with the centralized dispatcher.
#[allow(clippy::too_many_arguments)]
pub async fn pump_quic_to_tun_with_daita<T: PacketDevice>(
    conn: Connection,
    tun: T,
    shared_daita: Arc<SharedDaitaState>,
    uplink_limiter: Option<Arc<IdentityLimiter<WarrenPubkey>>>,
    client_id: WarrenPubkey,
    client_ipv4: Ipv4Addr,
    client_ipv6: Option<Ipv6Addr>,
    metrics: Option<Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
) -> Result<()> {
    use std::time::Duration;
    use tokio::time::Instant as TokioInstant;

    let mut tun_io = warrenguard_pump::TunIoTolerance::new("daita dispatch tun send");
    // Rate-limited: a hostile client spoofing its source IP at line rate would
    // otherwise cost one WARN per packet here (journald flood, logging CPU,
    // disk fill). Scoped to this one connection (not a process-global static),
    // matching `LogEveryN`'s existing use for `dispatch_err_log` above.
    let mut spoof_log = LogEveryN::new(64);
    loop {
        let next_timer = {
            let state = shared_daita.state.lock();
            state
                .next_timer()
                .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(3600))
        };
        let sleep = tokio::time::sleep_until(TokioInstant::from_std(next_timer));
        tokio::pin!(sleep);

        enum Action {
            Datagram(bytes::Bytes),
            DaitaDummy,
            TimerFired,
            Notified,
        }

        let action = tokio::select! {
            biased;

            result = conn.read_datagram() => {
                let dg = result.map_err(|source| TunnelError::QuicReadDatagram {
                    context: "downlink".into(),
                    source,
                })?;
                if warrenguard_pump::is_daita_dummy(&dg) {
                    Action::DaitaDummy
                } else {
                    Action::Datagram(dg)
                }
            }

            _ = &mut sleep => Action::TimerFired,

            _ = shared_daita.notify.notified() => Action::Notified,
        };

        match action {
            Action::Datagram(dg) => {
                let now = std::time::Instant::now();
                {
                    let mut state = shared_daita.state.lock();
                    state.fire_events(&[DaitaEvent::TunnelRecv, DaitaEvent::NormalRecv], now);
                }
                shared_daita.notify.notify_one();

                if !source_ip_matches(&dg, client_ipv4, client_ipv6) {
                    if spoof_log.should_log() {
                        tracing::warn!(
                            bytes = dg.len(),
                            occurrences = spoof_log.count(),
                            "dropped packet with spoofed source IP (rate-limited log)"
                        );
                    }
                    continue;
                }
                if let Some(limiter) = &uplink_limiter
                    && !limiter.try_consume(&client_id, dg.len() as u64)
                {
                    tracing::trace!(bytes = dg.len(), "rate limit drop (uplink, DAITA path)");
                    continue;
                }
                if let Some(m) = &metrics {
                    m.record_rx(dg.len() as u64);
                }
                match tun.send(&dg).await {
                    Ok(()) => tun_io.ok(),
                    // Packet dropped (IP is lossy; TCP retransmits).
                    Err(e) => tun_io.tolerate(&e).await?,
                }
            }
            Action::DaitaDummy => {
                let now = std::time::Instant::now();
                {
                    let mut state = shared_daita.state.lock();
                    state.fire_events(&[DaitaEvent::TunnelRecv], now);
                    state.fire_events(&[DaitaEvent::PaddingRecv], now);
                }
                shared_daita.notify.notify_one();
            }
            Action::TimerFired => {
                let now = std::time::Instant::now();
                let expired = shared_daita.state.lock().drain_expired(now);
                for machine in expired {
                    let dummy = warrenguard_pump::build_daita_dummy_vec(&conn);
                    warrenguard_pump::send_datagram_drop_too_large(&conn, dummy)?;
                    // Single Instant::now() + merged fire_events for
                    // PaddingSent + TunnelSent.
                    let now = Instant::now();
                    shared_daita.state.lock().fire_events(
                        &[DaitaEvent::PaddingSent { machine }, DaitaEvent::TunnelSent],
                        now,
                    );
                }
                shared_daita.notify.notify_one();
            }
            Action::Notified => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&1234u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
        pkt
    }

    fn make_ipv6_packet(src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60;
        pkt[6] = 6;
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt[40..42].copy_from_slice(&1234u16.to_be_bytes());
        pkt[42..44].copy_from_slice(&80u16.to_be_bytes());
        pkt
    }

    #[test]
    fn pool_offset_valid() {
        assert_eq!(pool_offset(Ipv4Addr::new(10, 66, 0, 2)), Some(2));
        assert_eq!(pool_offset(Ipv4Addr::new(10, 66, 0, 255)), Some(255));
        assert_eq!(pool_offset(Ipv4Addr::new(10, 66, 1, 0)), Some(256));
    }

    #[test]
    fn pool_offset_gateway_returns_none() {
        assert_eq!(pool_offset(Ipv4Addr::new(10, 66, 0, 1)), None);
        assert_eq!(pool_offset(Ipv4Addr::new(10, 66, 0, 0)), None);
    }

    #[test]
    fn pool_offset_broadcast_returns_none() {
        assert_eq!(pool_offset(Ipv4Addr::new(10, 66, 255, 255)), None);
    }

    #[test]
    fn pool_offset_outside_pool_returns_none() {
        assert_eq!(pool_offset(Ipv4Addr::new(192, 168, 1, 1)), None);
        assert_eq!(pool_offset(Ipv4Addr::new(10, 67, 0, 2)), None);
    }

    #[test]
    fn log_every_n_fires_first_then_every_nth() {
        let mut gate = LogEveryN::new(1000);
        assert!(gate.should_log(), "first occurrence must log");
        for i in 2..1000u64 {
            assert!(!gate.should_log(), "occurrence {i} must stay silent");
        }
        assert!(gate.should_log(), "occurrence 1000 must log again");
        assert!(!gate.should_log(), "occurrence 1001 must stay silent");
        assert_eq!(gate.count(), 1001, "gate must keep the exact tally");
    }

    #[test]
    fn table_starts_empty() {
        let table = TunDownlinkTable::new();
        assert_eq!(table.active_count(), 0);
    }

    #[test]
    fn dispatch_packet_no_route_returns_false() {
        let table = TunDownlinkTable::new();
        let pkt = make_ipv4_packet([1, 2, 3, 4], [10, 66, 0, 5]);
        assert!(matches!(table.dispatch_packet(&pkt), Ok(false)));
    }

    #[test]
    fn dispatch_packet_truncated_returns_false() {
        let table = TunDownlinkTable::new();
        assert!(matches!(table.dispatch_packet(&[0x45; 10]), Ok(false)));
    }

    #[test]
    fn dispatch_packet_owned_matches_borrow_on_no_route() {
        // The zero-copy owned path must route identically to the borrow path:
        // an unrouted destination yields Ok(false) and the moved Vec is
        // dropped (no send). Parity is what lets the hot path use the owned
        // variant without changing delivery semantics.
        let table = TunDownlinkTable::new();
        let pkt = make_ipv4_packet([1, 2, 3, 4], [10, 66, 0, 5]);
        assert!(matches!(table.dispatch_packet(&pkt), Ok(false)));
        assert!(matches!(table.dispatch_packet_owned(pkt), Ok(false)));
    }

    #[test]
    fn dispatch_packet_empty_returns_false() {
        let table = TunDownlinkTable::new();
        assert!(matches!(table.dispatch_packet(&[]), Ok(false)));
    }

    #[test]
    fn dispatch_packet_outside_pool_returns_false() {
        let table = TunDownlinkTable::new();
        let pkt = make_ipv4_packet([1, 2, 3, 4], [192, 168, 1, 1]);
        assert!(matches!(table.dispatch_packet(&pkt), Ok(false)));
    }

    #[test]
    fn ipv6_resolve_without_registration_returns_none() {
        let table = TunDownlinkTable::new();
        let pkt = make_ipv6_packet(
            [0; 16],
            [0xfd, 0xcc, 0, 0xf, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
        );
        assert!(matches!(table.dispatch_packet(&pkt), Ok(false)));
    }

    #[test]
    fn dispatch_packet_broadcast_address_returns_false() {
        let table = TunDownlinkTable::new();
        let pkt = make_ipv4_packet([1, 2, 3, 4], [10, 66, 255, 255]);
        assert!(matches!(table.dispatch_packet(&pkt), Ok(false)));
    }

    #[test]
    fn dispatch_daita_dummy_returns_false() {
        let table = TunDownlinkTable::new();
        let pkt = vec![0xFFu8; 40];
        assert!(matches!(table.dispatch_packet(&pkt), Ok(false)));
    }

    // --- Source IP extraction (anti-spoofing) ---
}
