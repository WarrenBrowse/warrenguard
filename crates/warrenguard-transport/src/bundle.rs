//! Bonded multi-connection session for the multi-hop client.
//!
//! A single QUIC connection is bottlenecked by the per-flow bandwidth
//! share of the client↔relay path (cross-AS peering commonly caps one
//! flow well below line rate while N parallel flows fill the link).
//! [`MultiHopBundle`] bonds N independent [`MultiHopClient`] sessions,
//! all authenticated with the same identity so the exit's sticky
//! allocator assigns them the SAME inner tunnel IP:
//!
//! - **Uplink**: each packet is pinned to one session by 5-tuple flow
//!   hash ([`warrenguard_transport_core::flow_hash_5tuple`], the exact function the
//!   exit dispatchers use), with an atomic round-robin fallback for
//!   non-TCP/UDP packets. Per-flow ordering is preserved; N flows spread
//!   across N connections.
//! - **Downlink**: one reader task per session HPKE-opens its frames
//!   and feeds a single merged channel, so the consumer keeps the
//!   exact `recv().await` shape it had against a lone client (and the
//!   per-session decode work spreads across runtime workers).
//!
//! With `n = 1` the bundle is a transparent wrapper: same dial, same
//! errors, no extra copies on the uplink path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use parking_lot::{Mutex as PlMutex, RwLock};

use quinn::Connection;
use tokio::sync::{mpsc, watch};
use warrenguard_multihop::{MULTIHOP_FRAME_MAX_OVERHEAD, RejectionReason};

use crate::multihop::{MultiHopClient, MultiHopError, RebindError, RebindPolicy};

/// Hard cap on bonded connections per session, matching the `n_connections`
/// operating range; the exit-side router slot cap (16)
/// leaves headroom for the reconnect-overlap window on top of this.
pub const MAX_BONDED_CONNECTIONS: usize = 8;

/// Bound on the merged downlink channel, in packets (~3 MiB at the
/// 1452-byte tunnel MTU). Full ⇒ the per-session readers backpressure
/// into Quinn's own receive queue; nothing is dropped here.
const MERGED_DOWNLINK_BOUND: usize = 2048;

/// Uplink packets between two refreshes of the cached [`RoutingPlan`].
///
/// The plan reads every leg's `max_datagram_size`, which locks each Quinn
/// connection, so recomputing it per packet would put eight lock round-trips
/// on the hottest path in the engine. Quinn moves a path MTU on the scale of
/// its DPLPMTUD timers (seconds to minutes), never per packet, so a bounded
/// staleness of this many packets costs at most that many drops on a leg that
/// has just collapsed, each of which is still counted and reflected as PTB.
/// Counted in packets rather than elapsed time so an idle tunnel, which has
/// nothing to black-hole, never pays for a refresh.
const ROUTING_PLAN_REFRESH_PACKETS: u64 = 256;

/// Which legs may carry user traffic, and which one a given packet goes to.
///
/// The whole bond-level MTU policy, kept pure and free of I/O so it is
/// exhaustively unit-testable: [`MultiHopBundle`] only samples the live
/// per-leg budgets and caches the result.
///
/// Two rules, each bought by the 2026-08-10 incident where one of eight legs
/// fell to Quinn's 1200-byte base MTU under congestion loss:
///
/// - **Quarantine.** A leg strictly worse than the best one AND under
///   [`QUIC_SAFE_INNER_MTU`] carries nothing and sets nothing. Without this,
///   the bond published the `min` across its legs, so one collapsed leg
///   dictated an inner MTU below the floor for all eight and inner QUIC could
///   not be established at all. The best leg is never quarantined, so the
///   usable set is never empty and a session legitimately under the floor on
///   every leg (the TLS-over-TCP carrier) keeps all of them.
/// - **Size-aware routing.** A packet too large for its flow-pinned leg moves
///   to a leg that can carry it instead of being dropped while healthy legs
///   sit idle.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RoutingPlan {
    /// Inner budget per leg, indexed by leg, quarantined legs included.
    budgets: Vec<usize>,
    /// Legs allowed to carry user traffic, ascending.
    usable: Vec<usize>,
    /// Budget published to the MSS clamp and the PTB reflection: the
    /// smallest among the usable legs.
    published: usize,
}

impl RoutingPlan {
    fn from_budgets(budgets: Vec<usize>) -> Self {
        let Some(best) = budgets.iter().copied().max() else {
            return Self {
                budgets,
                usable: Vec::new(),
                published: usize::from(warrenguard_config::TUNNEL_MIN_MTU)
                    - MULTIHOP_FRAME_MAX_OVERHEAD,
            };
        };
        let usable: Vec<usize> = budgets
            .iter()
            .enumerate()
            .filter(|&(_, &b)| {
                // `b < best` keeps at least the best leg, so a uniformly
                // sub-floor path is never left with nothing to send on.
                !(b < best && b < warrenguard_transport_core::QUIC_SAFE_INNER_MTU)
            })
            .map(|(i, _)| i)
            .collect();
        let published = usable.iter().map(|&i| budgets[i]).min().unwrap_or(
            usize::from(warrenguard_config::TUNNEL_MIN_MTU) - MULTIHOP_FRAME_MAX_OVERHEAD,
        );
        Self {
            budgets,
            usable,
            published,
        }
    }

    /// Leg index for a `pkt_len`-byte inner packet: the flow-pinned usable
    /// leg when it fits, else the next usable leg that does, else the widest
    /// usable leg so an unavoidable drop is charged to the best path there is.
    fn route(&self, hash: Option<u64>, rr: usize, pkt_len: usize) -> usize {
        let n = self.usable.len();
        if n == 0 {
            return 0;
        }
        let start = match hash {
            Some(h) => (h as usize) % n,
            None => rr % n,
        };
        let pinned = self.usable[start];
        if self.budgets[pinned] >= pkt_len {
            return pinned;
        }
        (1..n)
            .map(|step| self.usable[(start + step) % n])
            .find(|&leg| self.budgets[leg] >= pkt_len)
            .unwrap_or_else(|| {
                self.usable
                    .iter()
                    .copied()
                    .max_by_key(|&leg| self.budgets[leg])
                    .unwrap_or(pinned)
            })
    }
}

/// N bonded multi-hop sessions behind the API surface of one.
///
/// Constructed by the supervisor once the PRIMARY session is set up;
/// consumers (the supervised pumps) only ever see this type. An
/// unsealed bundle (see [`Self::new_unsealed`]) accepts late-bonded
/// secondaries through [`Self::add_client`] so the extra throughput
/// capacity appears on the already-published handle without a watch
/// re-publish or a datapath gap.
pub struct MultiHopBundle {
    clients: RwLock<Vec<Arc<MultiHopClient>>>,
    rr: AtomicUsize,
    merged_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Held only while unsealed. Sealing (dropping this last non-reader
    /// sender clone) lets the merged channel close once every reader
    /// ends, so a `recv()` consumer sees the bundle as fully drained.
    /// The SUPERVISOR redial does NOT depend on this: it watches
    /// `closed()` (first fatal reader error), which fires independently
    /// of seal. Sealing exists so a late secondary can still be
    /// attached before it, and so the drained-bundle signal stays
    /// correct.
    merged_tx: PlMutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// First session-fatal receive error observed by any reader task.
    /// `closed()` resolves as soon as this is set: ONE dead session
    /// tears the whole bundle down (the supervisor redials all N), so
    /// a degraded bundle never lingers half-alive.
    closed_tx: watch::Sender<Option<quinn::ConnectionError>>,
    reader_tasks: PlMutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Real user packets pumped up/down, maintained by the supervised
    /// pumps (padding, dummies and control frames excluded). See
    /// [`Self::real_traffic_totals`].
    real_tx: AtomicU64,
    real_rx: AtomicU64,
    /// Path-health reply intercept, installed by the supervisor on every
    /// bundle it publishes. `recv()` consumes matching echo replies so
    /// probe traffic never reaches the TUN nor the real-traffic
    /// counters.
    probe_tap: RwLock<Option<Arc<crate::path_health::ProbeTap>>>,
    /// Cached per-leg MTU policy, refreshed every
    /// [`ROUTING_PLAN_REFRESH_PACKETS`] uplink packets and on every bundle
    /// width change. Read on the uplink hot path; never computed there.
    routing: RwLock<RoutingPlan>,
    /// Uplink packets since the last [`Self::refresh_routing_plan`].
    routing_tick: AtomicU64,
}

impl MultiHopBundle {
    /// Wraps `clients` (non-empty, truncated to
    /// [`MAX_BONDED_CONNECTIONS`]) and spawns the per-session downlink
    /// readers. The bundle is sealed: [`Self::add_client`] refuses.
    ///
    /// # Panics
    ///
    /// Panics if `clients` is empty: the supervisor only builds a
    /// bundle after at least the primary dial succeeded.
    #[must_use]
    pub fn new(clients: Vec<Arc<MultiHopClient>>) -> Arc<Self> {
        let bundle = Self::new_unsealed(clients);
        bundle.seal();
        bundle
    }

    /// Like [`Self::new`] but keeps the bundle open for late-bonded
    /// secondaries ([`Self::add_client`]). The caller MUST eventually
    /// [`Self::seal`] it, else `recv()` cannot report the all-sessions-
    /// dead condition.
    ///
    /// # Panics
    ///
    /// Panics if `clients` is empty (same invariant as [`Self::new`]).
    #[must_use]
    pub fn new_unsealed(mut clients: Vec<Arc<MultiHopClient>>) -> Arc<Self> {
        assert!(!clients.is_empty(), "bundle requires at least one session");
        clients.truncate(MAX_BONDED_CONNECTIONS);
        let (merged_tx, merged_rx) = mpsc::channel(MERGED_DOWNLINK_BOUND);
        let (closed_tx, _) = watch::channel(None);
        let reader_tasks = clients
            .iter()
            .map(|client| Self::spawn_reader(client.clone(), merged_tx.clone(), closed_tx.clone()))
            .collect();
        let plan =
            RoutingPlan::from_budgets(clients.iter().map(|c| c.max_inner_payload()).collect());
        Arc::new(Self {
            clients: RwLock::new(clients),
            rr: AtomicUsize::new(0),
            merged_rx: tokio::sync::Mutex::new(merged_rx),
            merged_tx: PlMutex::new(Some(merged_tx)),
            closed_tx,
            reader_tasks: PlMutex::new(reader_tasks),
            real_tx: AtomicU64::new(0),
            real_rx: AtomicU64::new(0),
            probe_tap: RwLock::new(None),
            routing: RwLock::new(plan),
            routing_tick: AtomicU64::new(0),
        })
    }

    /// Whether a late secondary may still be attached: only to an
    /// unsealed bundle that is below the hard connection cap. Pure so
    /// the refusal branches are unit-testable without a live QUIC
    /// session (which `add_client` otherwise requires).
    fn attach_decision(sealed: bool, current_len: usize) -> bool {
        !sealed && current_len < MAX_BONDED_CONNECTIONS
    }

    /// Attaches one late-bonded session: spawns its downlink reader and
    /// makes it eligible for uplink flow pinning. Returns `false`
    /// without touching `client` when the bundle is sealed or already
    /// at [`MAX_BONDED_CONNECTIONS`] (the caller then closes it).
    pub fn add_client(&self, client: Arc<MultiHopClient>) -> bool {
        let tx_guard = self.merged_tx.lock();
        let mut clients = self.clients.write();
        if !Self::attach_decision(tx_guard.is_none(), clients.len()) {
            return false;
        }
        let Some(merged_tx) = tx_guard.as_ref() else {
            return false;
        };
        let reader = Self::spawn_reader(client.clone(), merged_tx.clone(), self.closed_tx.clone());
        clients.push(client);
        self.reader_tasks.lock().push(reader);
        let budgets = clients.iter().map(|c| c.max_inner_payload()).collect();
        drop(clients);
        // A width change re-indexes every leg, so the cached plan is stale
        // the instant the secondary lands: refresh it here rather than let
        // the packet tick route against indices that no longer mean the
        // same thing.
        *self.routing.write() = RoutingPlan::from_budgets(budgets);
        true
    }

    /// Closes the bundle for [`Self::add_client`]. Idempotent. Must run
    /// once background bonding is done so the merged downlink channel
    /// can close when every reader terminates (the `recv()` error
    /// path the supervisor's redial relies on).
    pub fn seal(&self) {
        self.merged_tx.lock().take();
    }

    fn spawn_reader(
        client: Arc<MultiHopClient>,
        tx: mpsc::Sender<Vec<u8>>,
        closed_tx: watch::Sender<Option<quinn::ConnectionError>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match client.recv().await {
                    Ok(payload) => {
                        if tx.send(payload).await.is_err() {
                            return; // bundle consumer gone
                        }
                    }
                    Err(MultiHopError::Recv(e)) => {
                        // Session-fatal: surface the first such
                        // error as the bundle's close reason.
                        closed_tx.send_if_modified(|slot| {
                            if slot.is_none() {
                                *slot = Some(e);
                                true
                            } else {
                                false
                            }
                        });
                        return;
                    }
                    Err(e) => {
                        // Per-frame error (decode, dummy filter
                        // edge): paced by datagram arrival, never
                        // a hot loop.
                        tracing::trace!(error = %e, "bundle reader transient error");
                    }
                }
            }
        })
    }

    /// Number of currently bonded sessions (grows while background
    /// bonding attaches secondaries to an unsealed bundle).
    #[must_use]
    pub fn num_connections(&self) -> usize {
        self.clients.read().len()
    }

    /// The session whose setup-stream `IpAssign` drives the TUN
    /// addressing (index 0).
    #[must_use]
    pub fn primary(&self) -> Arc<MultiHopClient> {
        self.clients.read()[0].clone()
    }

    /// Snapshot of the bonded sessions, primary first.
    #[must_use]
    pub fn clients(&self) -> Vec<Arc<MultiHopClient>> {
        self.clients.read().clone()
    }

    /// Clones of every session's Quinn connection, for
    /// `warrenguard_transport_core::spawn_path_probe`.
    #[must_use]
    pub fn clone_connections(&self) -> Vec<Connection> {
        self.clients.read().iter().map(|c| c.clone_conn()).collect()
    }

    /// Recomputes the cached [`RoutingPlan`] from the live per-leg budgets.
    ///
    /// Deliberately samples every leg in one pass: reading a leg's budget
    /// locks its Quinn connection, so this is the only place in the engine
    /// allowed to pay that cost.
    fn refresh_routing_plan(&self) {
        let budgets: Vec<usize> = self
            .clients
            .read()
            .iter()
            .map(|c| c.max_inner_payload())
            .collect();
        *self.routing.write() = RoutingPlan::from_budgets(budgets);
    }

    /// Session that must carry `pkt`: the flow-pinned leg when it is usable
    /// and wide enough, else the nearest leg that can take the packet. See
    /// [`RoutingPlan`] for the policy and why one leg's collapse must not
    /// reach the other seven.
    ///
    /// A flow keeps its pinned session at a given usable-leg set; a width
    /// change (background bonding completing) or a leg entering or leaving
    /// quarantine may re-pin flows once, exactly like a reconnect re-pins
    /// them, which QUIC datagram delivery tolerates (no per-flow ordering
    /// promise across different sessions is ever made to the exit).
    fn pick(&self, pkt: &[u8]) -> Arc<MultiHopClient> {
        if self
            .routing_tick
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(ROUTING_PLAN_REFRESH_PACKETS)
        {
            self.refresh_routing_plan();
        }
        let hash = warrenguard_transport_core::flow_hash_5tuple(pkt);
        // The round-robin cursor only advances for packets that have no
        // 5-tuple to hash, so hashed flows never consume its sequence.
        let rr = if hash.is_none() {
            self.rr.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        };
        let idx = self.routing.read().route(hash, rr, pkt.len());
        let clients = self.clients.read();
        // The plan can lag a width change by up to one refresh, so an index
        // it produced is not guaranteed to still exist.
        clients
            .get(idx)
            .unwrap_or_else(|| &clients[clients.len() - 1])
            .clone()
    }

    /// Seals and sends one inner packet on its flow-pinned session.
    ///
    /// # Errors
    ///
    /// Propagates [`MultiHopClient::send`] errors of the picked session.
    pub async fn send(&self, payload: &[u8]) -> Result<(), MultiHopError> {
        let sent = self.pick(payload).send(payload).await;
        // Padding rides `send_daita_padding`, so everything sent here is
        // real user traffic: feed the liveness accounting directly (see
        // `real_traffic_totals`).
        if sent.is_ok() {
            self.note_real_uplink();
        }
        sent
    }

    /// Seals and sends one path-health probe on the leg at `leg`, WITHOUT
    /// feeding the real-traffic liveness counters: engine-generated probes
    /// must never satisfy (or trip) the app-traffic dead-path watches.
    ///
    /// The leg is explicit because the prober's whole value is comparing a
    /// small and a large probe **on one leg**: routed by [`Self::pick`],
    /// an ICMP probe has no 5-tuple to hash, falls into the round-robin
    /// branch, and the two halves of a pair leave on two different legs,
    /// which is how a collapsed leg went unnoticed for six minutes on
    /// 2026-08-10. Quarantined legs are probed too: the probe is how a
    /// quarantined leg proves it deserves to come back.
    ///
    /// # Errors
    ///
    /// Propagates [`MultiHopClient::send`] errors of that leg. Returns
    /// [`MultiHopError::NoSession`] when `leg` is out of range.
    pub async fn send_probe_on(&self, leg: usize, payload: &[u8]) -> Result<(), MultiHopError> {
        let client = self
            .clients
            .read()
            .get(leg)
            .cloned()
            .ok_or(MultiHopError::NoSession)?;
        client.send(payload).await
    }

    /// Per-leg inner budgets, indexed like [`Self::clients`]: what the
    /// prober sizes each leg's large probe against, and what names a leg
    /// that has fallen out of family in a log line.
    #[must_use]
    pub fn leg_inner_payloads(&self) -> Vec<usize> {
        self.clients
            .read()
            .iter()
            .map(|c| c.max_inner_payload())
            .collect()
    }

    /// Installs the path-health reply intercept consulted by
    /// [`Self::recv`]. The supervisor installs the SAME tap on every
    /// bundle it publishes so probe sequencing survives overlap swaps.
    pub fn set_probe_tap(&self, tap: Arc<crate::path_health::ProbeTap>) {
        *self.probe_tap.write() = Some(tap);
    }

    /// Sends one DAITA padding frame on the next round-robin session,
    /// so cover traffic spreads across every bonded connection.
    ///
    /// # Errors
    ///
    /// Propagates [`MultiHopClient::send_daita_padding`] errors.
    pub async fn send_daita_padding(&self) -> Result<usize, MultiHopError> {
        let client = {
            let clients = self.clients.read();
            let idx = self.rr.fetch_add(1, Ordering::Relaxed) % clients.len();
            clients[idx].clone()
        };
        client.send_daita_padding().await
    }

    /// Sends one idle-cover dummy of `padding_len` padding bytes on the next
    /// round-robin session, spreading cover across every bonded connection
    /// exactly like [`Self::send_daita_padding`]. Unlike DAITA padding (which
    /// auto-sizes to the path MTU) the caller picks the length, so the
    /// jittered, size-varied idle-cover scheduler drives the on-wire size.
    ///
    /// # Errors
    ///
    /// Propagates [`MultiHopClient::send_cover_traffic`] errors.
    pub fn send_cover_traffic(&self, padding_len: usize) -> Result<(), MultiHopError> {
        let client = {
            let clients = self.clients.read();
            let idx = self.rr.fetch_add(1, Ordering::Relaxed) % clients.len();
            clients[idx].clone()
        };
        client.send_cover_traffic(padding_len)
    }

    /// Receives the next decoded inner packet from any bonded session.
    /// Path-health echo replies are consumed here (handed to the prober
    /// through the installed tap) so probe traffic never reaches the
    /// consumer or the TUN.
    ///
    /// # Errors
    ///
    /// [`MultiHopError::Recv`] once every reader has terminated (the
    /// bundle is dead and the supervisor is about to redial).
    pub async fn recv(&self) -> Result<Vec<u8>, MultiHopError> {
        let mut rx = self.merged_rx.lock().await;
        loop {
            match rx.recv().await {
                Some(payload) => {
                    // Cheap shape pre-check before touching the tap
                    // lock: IPv4 + protocol ICMP is the only thing a
                    // probe reply can be.
                    if payload.len() >= 28
                        && payload[0] >> 4 == 4
                        && payload[9] == 1
                        && let Some(tap) = self.probe_tap.read().as_ref()
                        && tap.try_intercept(&payload)
                    {
                        continue;
                    }
                    return Ok(payload);
                }
                None => return Err(MultiHopError::Recv(self.closed().await)),
            }
        }
    }

    /// Resolves when ANY bonded session dies, with that session's close
    /// error. Mirrors `MultiHopClient::closed` for `n = 1`.
    pub async fn closed(&self) -> quinn::ConnectionError {
        let mut rx = self.closed_tx.subscribe();
        loop {
            if let Some(e) = rx.borrow().clone() {
                return e;
            }
            if rx.changed().await.is_err() {
                // Sender gone (bundle dropped mid-await): report a local
                // close, the supervisor is tearing down anyway.
                return quinn::ConnectionError::LocallyClosed;
            }
        }
    }

    /// Closes every bonded session with the forced-reconnect code; the
    /// supervisor observes the bundle close and redials all N.
    pub fn force_close_for_reconnect(&self) {
        for client in self.clients.read().iter() {
            client.force_close_for_reconnect();
        }
    }

    /// First definitive policy-rejection reason any session carries.
    #[must_use]
    pub fn rejection_reason(&self) -> Option<RejectionReason> {
        self.clients
            .read()
            .iter()
            .find_map(|c| c.rejection_reason())
    }

    /// WIDEST datagram budget any usable leg can carry, for reporting a
    /// packet the bond had to drop.
    ///
    /// A max, not a min, and only because [`Self::pick`] already routes a
    /// packet to whatever leg can take it: reaching a `TooLarge` drop means
    /// NO leg could, so the widest is both the truthful ceiling to log and
    /// the correct next-hop MTU to reflect back as PTB. Sizing anything that
    /// must FIT every leg belongs to [`Self::max_inner_payload`].
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        // Cloning the (at most eight) usable indices keeps the two locks
        // from ever nesting. This is the drop-report path, not a hot one.
        let usable = self.routing.read().usable.clone();
        let clients = self.clients.read();
        usable
            .iter()
            .filter_map(|&i| clients.get(i).and_then(|c| c.max_datagram_size()))
            .max()
    }

    /// Largest inner IP packet EVERY usable leg can currently carry in one
    /// datagram: the live "effective inner MTU" of the tunnel, which the
    /// pumps clamp TCP MSS and reflect PMTUD against on reduced-MTU
    /// underlays.
    ///
    /// Quarantined legs are excluded, so one leg collapsing to Quinn's base
    /// MTU no longer drags the whole bond under [`QUIC_SAFE_INNER_MTU`] and
    /// kills inner QUIC on the seven healthy ones. Served from the cached
    /// [`RoutingPlan`], so it lags a real change by at most
    /// [`ROUTING_PLAN_REFRESH_PACKETS`] uplink packets.
    #[must_use]
    pub fn max_inner_payload(&self) -> usize {
        self.routing.read().published
    }

    /// Primary session's Quinn stats (bench scraping; per-session stats
    /// are reachable through [`Self::clients`]).
    #[must_use]
    pub fn quinn_stats(&self) -> quinn::ConnectionStats {
        self.primary().quinn_stats()
    }

    /// Records one REAL uplink packet (from the TUN, not DAITA padding or
    /// idle cover) successfully handed to a session.
    pub fn note_real_uplink(&self) {
        self.real_tx.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one REAL downlink packet (decoded IP, not a 0xFF dummy or
    /// a control frame) successfully written to the TUN.
    pub fn note_real_downlink(&self) {
        self.real_rx.fetch_add(1, Ordering::Relaxed);
    }

    /// Cumulative (real uplink, real downlink) packet counts recorded by
    /// the supervised pumps. Liveness watches MUST sample this instead of
    /// Quinn's datagram frame counters: an armed exit pads its downlink
    /// with dummies and a DAITA client pads its uplink, so frame counters
    /// keep advancing on a tunnel that carries no user traffic at all
    /// (a dead uplink can sit "Connected" behind a rain of exit
    /// dummies).
    #[must_use]
    pub fn real_traffic_totals(&self) -> (u64, u64) {
        (
            self.real_tx.load(Ordering::Relaxed),
            self.real_rx.load(Ordering::Relaxed),
        )
    }

    /// Field-wise sum of every bonded session's metrics snapshot, so a
    /// bundle reads like one session in the CLI/bench summaries.
    #[must_use]
    pub fn metrics(&self) -> crate::multihop::MultiHopMetricsSnapshot {
        let mut total = crate::multihop::MultiHopMetricsSnapshot::default();
        for m in self.clients.read().iter().map(|c| c.metrics()) {
            total.frames_sent += m.frames_sent;
            total.frames_recv += m.frames_recv;
            total.bytes_sent += m.bytes_sent;
            total.bytes_recv += m.bytes_recv;
            total.rekey_count += m.rekey_count;
            total.replay_rejects += m.replay_rejects;
            total.decode_errors += m.decode_errors;
            total.unexpected_exit_id += m.unexpected_exit_id;
            total.decode_fallback_to_old_epoch += m.decode_fallback_to_old_epoch;
        }
        total
    }

    /// Closes every bonded session with the given application code.
    pub fn close(&self, code: u32, reason: &[u8]) {
        for client in self.clients.read().iter() {
            client.close(code, reason);
        }
    }

    /// Primary session's local UDP socket address. The migration
    /// watchdog uses it to detect a stale source interface after a
    /// route change.
    ///
    /// # Errors
    ///
    /// Propagates the underlying `Endpoint::local_addr` I/O error.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.primary().local_addr()
    }

    /// Rebinds the PRIMARY session's endpoint to `socket` (migration
    /// watchdog bypass nudge). Secondaries are left alone on purpose:
    /// if the path truly moved they all die together and the watchdog
    /// escalation redials the whole bundle; if only the primary was
    /// wedged, the nudge fixes the probe path without churning the
    /// healthy siblings.
    ///
    /// Hidden raw seam, like [`MultiHopClient::rebind`]: the caller owns the
    /// escape contract of the socket it injects. Production migration goes
    /// through [`Self::rebind_wildcard`].
    ///
    /// # Errors
    ///
    /// Propagates [`MultiHopClient::rebind`]: the primary rides the
    /// TLS-over-TCP carrier, or `Endpoint::rebind` refused the socket.
    #[doc(hidden)]
    pub fn rebind(&self, socket: std::net::UdpSocket) -> Result<(), RebindError> {
        self.primary().rebind(socket)
    }

    /// Rebinds the PRIMARY session onto a fresh wildcard socket built under
    /// `policy`, exactly as [`MultiHopClient::rebind_wildcard`] does at dial
    /// time. Secondaries are left alone on purpose, matching [`Self::rebind`].
    ///
    /// # Errors
    ///
    /// Propagates [`MultiHopClient::rebind_wildcard`]: the primary rides the
    /// TLS-over-TCP carrier, or the bind / escape policy / `Endpoint::rebind`
    /// failed (the primary then keeps its current socket).
    pub fn rebind_wildcard(&self, policy: RebindPolicy) -> Result<(), RebindError> {
        self.primary().rebind_wildcard(policy)
    }

    /// `true` when the primary session rides the TLS-over-TCP carrier, so the
    /// bundle cannot migrate and must redial instead.
    #[must_use]
    pub fn is_over_carrier(&self) -> bool {
        self.primary().is_over_carrier()
    }
}

impl Drop for MultiHopBundle {
    fn drop(&mut self) {
        for task in self.reader_tasks.lock().iter() {
            task.abort();
        }
        // Close the QUIC sessions explicitly: aborting the readers only
        // drops THIS bundle's handles, but detached observers (the
        // client-side path probe holds `Connection` clones from
        // `clone_connections`) keep the connections referenced, and the
        // 20 s transport keep-alive then sustains them forever. Without
        // this close, a torn-down tunnel leaves N zombie sessions
        // heartbeating the exit indefinitely (observed).
        // Idempotent: sessions already closed by
        // `force_close_for_reconnect` ignore the second close.
        for client in self.clients.read().iter() {
            client.close(0, b"bundle dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The attach gate is the refusal contract of `add_client`, extracted
    // pure so the branch logic itself is unit-tested without a live
    // `MultiHopClient`. The full attach/grow/Drop path (needing a real QUIC
    // session) is covered by `live_tests` below.

    #[test]
    fn attach_refused_once_sealed() {
        assert!(
            !MultiHopBundle::attach_decision(true, 1),
            "a sealed bundle must refuse late secondaries"
        );
    }

    #[test]
    fn attach_refused_at_the_hard_cap() {
        assert!(
            !MultiHopBundle::attach_decision(false, MAX_BONDED_CONNECTIONS),
            "an unsealed bundle at MAX_BONDED_CONNECTIONS must refuse more"
        );
    }

    #[test]
    fn attach_allowed_while_unsealed_and_below_cap() {
        assert!(
            MultiHopBundle::attach_decision(false, 1),
            "an unsealed sub-cap bundle must accept a secondary"
        );
        assert!(
            MultiHopBundle::attach_decision(false, MAX_BONDED_CONNECTIONS - 1),
            "the last slot below the cap is still attachable"
        );
    }

    // The routing plan is the whole bond-level MTU policy, extracted pure so
    // the quarantine and the size-aware fallback are exhaustively testable
    // without eight live QUIC sessions.

    #[test]
    fn a_leg_under_the_quic_floor_with_a_healthier_peer_is_quarantined() {
        // The 2026-08-10 shape: seven legs at 1242, one collapsed to the
        // QUIC base MTU. The collapsed leg must stop dictating the bond.
        let plan = RoutingPlan::from_budgets(vec![1242, 1242, 1242, 1076]);
        assert_eq!(plan.usable, vec![0, 1, 2]);
        assert_eq!(
            plan.published, 1242,
            "one collapsed leg must not drag the published budget under the QUIC floor"
        );
    }

    #[test]
    fn the_best_leg_is_never_quarantined() {
        // A session on the TLS-over-TCP carrier is legitimately under the
        // floor on EVERY leg (CARRIER_MAX_INNER_MTU is 1100 on purpose).
        // Quarantining them all would leave nothing to send on.
        let uniform = RoutingPlan::from_budgets(vec![1100, 1100, 1100]);
        assert_eq!(uniform.usable, vec![0, 1, 2]);
        assert_eq!(uniform.published, 1100);

        let ragged = RoutingPlan::from_budgets(vec![1076, 1100]);
        assert_eq!(ragged.usable, vec![1], "the worse sub-floor leg is dropped");
        assert_eq!(ragged.published, 1100);

        let single = RoutingPlan::from_budgets(vec![900]);
        assert_eq!(single.usable, vec![0], "a lone leg is always usable");
        assert_eq!(single.published, 900);
    }

    #[test]
    fn a_leg_at_or_above_the_quic_floor_is_kept_even_when_it_is_the_worst() {
        // Above the floor a smaller leg is merely slower, and dropping it
        // would throw away capacity for nothing.
        let plan = RoutingPlan::from_budgets(vec![1400, 1228]);
        assert_eq!(plan.usable, vec![0, 1]);
        assert_eq!(plan.published, 1228);
    }

    #[test]
    fn route_never_hands_a_packet_to_a_quarantined_leg() {
        let plan = RoutingPlan::from_budgets(vec![1242, 1242, 1076]);
        for hash in 0..24u64 {
            let leg = plan.route(Some(hash), 0, 800);
            assert_ne!(leg, 2, "hash {hash} must not land on the quarantined leg");
        }
        for rr in 0..24 {
            assert_ne!(plan.route(None, rr, 800), 2, "round-robin must skip it too");
        }
    }

    #[test]
    fn route_falls_back_to_a_leg_that_can_carry_an_oversized_packet() {
        // Every leg is above the floor so all stay usable, but only some
        // can take this packet. Dropping it while a capable leg sits idle
        // is the defect that black-holed inner QUIC.
        //
        // The widest leg is deliberately NOT the first that fits: the scan
        // takes the nearest capable leg from the pin, which spreads
        // oversized flows instead of piling them all on one leg, and it is
        // what tells this branch apart from the undeliverable fallback.
        let plan = RoutingPlan::from_budgets(vec![1240, 1300, 1400]);
        assert_eq!(plan.usable, vec![0, 1, 2]);
        assert_eq!(
            plan.route(Some(0), 0, 800),
            0,
            "a packet that fits stays on its pinned leg"
        );
        assert_eq!(
            plan.route(Some(0), 0, 1300),
            1,
            "a packet too large for the pinned leg moves to the nearest one that fits"
        );
    }

    #[test]
    fn route_attributes_an_undeliverable_packet_to_the_widest_leg() {
        // No leg can take it: the drop is unavoidable, but it must be
        // charged to the widest leg so the counter and the reflected PTB
        // carry the largest MTU actually achievable.
        let plan = RoutingPlan::from_budgets(vec![1240, 1400, 1300]);
        assert_eq!(plan.route(Some(0), 0, 1500), 1);
    }

    #[test]
    fn route_is_stable_for_a_given_flow() {
        let plan = RoutingPlan::from_budgets(vec![1242, 1242, 1242, 1076]);
        let first = plan.route(Some(0xdead_beef), 0, 900);
        for _ in 0..8 {
            assert_eq!(
                plan.route(Some(0xdead_beef), 0, 900),
                first,
                "flow pinning must be deterministic across calls"
            );
        }
    }

    #[test]
    fn an_empty_bundle_plan_is_inert_rather_than_panicking() {
        let plan = RoutingPlan::from_budgets(Vec::new());
        assert!(plan.usable.is_empty());
        assert_eq!(plan.route(Some(7), 3, 900), 0);
    }
}

/// Live loopback tests for the paths that need a real QUIC session:
/// `closed()`'s first-error-wins latch, `recv()`'s end-of-stream mapping,
/// `force_close_for_reconnect`, and the `Drop` invariant that guards the
/// observed zombie-session bug (a detached observer's `Connection` clone
/// keeping a torn-down tunnel heartbeating the exit forever).
#[cfg(test)]
mod live_tests {
    use std::time::Duration;

    use warrenguard_multihop::ExitId;

    use super::*;
    use crate::test_support::{spawn_loopback_multihop, spawn_loopback_multihop_with_transport};

    #[tokio::test]
    async fn closed_resolves_once_the_peer_closes_the_connection() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x71; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);

        pair.exit_conn
            .close(quinn::VarInt::from_u32(0x1234), b"exit closing");

        let close_err = tokio::time::timeout(Duration::from_secs(2), bundle.closed())
            .await
            .expect("closed() must resolve promptly once the peer closes");
        assert!(
            !matches!(close_err, quinn::ConnectionError::LocallyClosed),
            "a peer-initiated close must never be reported as LocallyClosed, got {close_err:?}"
        );
    }

    #[tokio::test]
    async fn carrier_primary_makes_the_bundle_refuse_a_rebind() {
        let native_pair = spawn_loopback_multihop(ExitId::from_bytes([0x78; 16])).await;
        let native = MultiHopBundle::new(vec![native_pair.client.clone()]);
        assert!(
            !native.is_over_carrier(),
            "a natively dialed bundle must report itself as migratable"
        );

        let mut carried_pair = spawn_loopback_multihop(ExitId::from_bytes([0x79; 16])).await;
        Arc::get_mut(&mut carried_pair.client)
            .expect("sole owner before the bundle clones it")
            .set_over_carrier_for_test();
        let carried = MultiHopBundle::new(vec![carried_pair.client.clone()]);
        assert!(carried.is_over_carrier());
        let fresh = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind a fresh loopback socket");
        assert!(
            matches!(carried.rebind(fresh), Err(RebindError::OverCarrier)),
            "the bundle must propagate the primary's carrier refusal"
        );
    }

    #[tokio::test]
    async fn carrier_primary_makes_the_bundle_refuse_a_wildcard_rebind() {
        let mut pair = spawn_loopback_multihop(ExitId::from_bytes([0x7b; 16])).await;
        Arc::get_mut(&mut pair.client)
            .expect("sole owner before the bundle clones it")
            .set_over_carrier_for_test();
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        assert!(
            matches!(
                bundle.rebind_wildcard(RebindPolicy::Plain),
                Err(RebindError::OverCarrier)
            ),
            "the bundle must propagate the primary's carrier refusal on the \
             policy-built rebind too"
        );
    }

    #[tokio::test]
    async fn recv_maps_end_of_stream_to_err_recv_once_every_reader_is_dead() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x72; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);

        pair.exit_conn.close(quinn::VarInt::from_u32(0), b"bye");

        let result = tokio::time::timeout(Duration::from_secs(2), bundle.recv())
            .await
            .expect("recv() must not hang once the only session has died");
        assert!(
            matches!(result, Err(MultiHopError::Recv(_))),
            "a drained bundle must map to Err(MultiHopError::Recv(_)), got {result:?}"
        );
    }

    /// Transport config pinning a session to a fixed path MTU: MTU discovery
    /// off so the loopback cannot grow it, which is how a leg is held at
    /// Quinn's base MTU the way the 2026-08-10 black-hole detector held one.
    fn transport_pinned_to_mtu(mtu: u16) -> Arc<quinn::TransportConfig> {
        let mut cfg = quinn::TransportConfig::default();
        cfg.initial_mtu(mtu).mtu_discovery_config(None);
        Arc::new(cfg)
    }

    /// The incident, replayed on real QUIC: one leg pinned under the
    /// inner-QUIC floor beside a healthy one. The bond must publish the
    /// HEALTHY leg's budget and route a large packet to it, instead of
    /// letting the collapsed leg set an inner MTU on which no inner QUIC
    /// handshake can exist.
    #[tokio::test]
    async fn a_collapsed_leg_sets_neither_the_budget_nor_the_route() {
        let healthy = spawn_loopback_multihop_with_transport(
            ExitId::from_bytes([0x81; 16]),
            Some(transport_pinned_to_mtu(1452)),
        )
        .await;
        let collapsed = spawn_loopback_multihop_with_transport(
            ExitId::from_bytes([0x82; 16]),
            Some(transport_pinned_to_mtu(warrenguard_config::TUNNEL_MIN_MTU)),
        )
        .await;

        let healthy_budget = healthy.client.max_inner_payload();
        let collapsed_budget = collapsed.client.max_inner_payload();
        assert!(
            collapsed_budget < warrenguard_transport_core::QUIC_SAFE_INNER_MTU
                && healthy_budget >= warrenguard_transport_core::QUIC_SAFE_INNER_MTU,
            "the fixture must straddle the floor: healthy {healthy_budget}, \
             collapsed {collapsed_budget}"
        );

        let bundle = MultiHopBundle::new(vec![healthy.client.clone(), collapsed.client.clone()]);
        assert_eq!(
            bundle.max_inner_payload(),
            healthy_budget,
            "a `min` across legs would publish {collapsed_budget} here and kill inner QUIC"
        );

        // Drive every flow hash: none may land on the collapsed leg.
        let plan = bundle.routing.read().clone();
        assert_eq!(plan.usable, vec![0], "leg 1 must be quarantined");
        for hash in 0..16u64 {
            assert_eq!(plan.route(Some(hash), 0, healthy_budget), 0);
        }
    }

    /// A probe addressed to a leg must leave on THAT leg. The whole
    /// small-versus-large comparison is worthless otherwise, which is how a
    /// collapsed leg stayed invisible for six minutes on 2026-08-10.
    #[tokio::test]
    async fn send_probe_on_puts_the_packet_on_the_leg_it_was_given() {
        let a = spawn_loopback_multihop(ExitId::from_bytes([0x83; 16])).await;
        let b = spawn_loopback_multihop(ExitId::from_bytes([0x84; 16])).await;
        let bundle = MultiHopBundle::new(vec![a.client.clone(), b.client.clone()]);

        // DATAGRAM frames, not UDP packets: Quinn sends ACKs and keep-alives
        // of its own on every leg, so a UDP counter cannot tell a probe from
        // the transport's own chatter.
        let before_a = a.client.quinn_stats().frame_tx.datagram;
        let before_b = b.client.quinn_stats().frame_tx.datagram;
        const PROBES: u64 = 5;
        for _ in 0..PROBES {
            bundle
                .send_probe_on(1, &[0x45; 200])
                .await
                .expect("leg 1 accepts the probe");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            a.client.quinn_stats().frame_tx.datagram,
            before_a,
            "leg 0 must not have carried a probe addressed to leg 1"
        );
        assert_eq!(
            b.client.quinn_stats().frame_tx.datagram,
            before_b + PROBES,
            "leg 1 must have carried every one of them"
        );
        assert!(
            bundle.send_probe_on(9, &[0x45; 200]).await.is_err(),
            "an out-of-range leg is an error, never a silent send elsewhere"
        );
    }

    #[tokio::test]
    async fn closed_is_first_error_wins_across_two_bonded_sessions() {
        let pair_a = spawn_loopback_multihop(ExitId::from_bytes([0x73; 16])).await;
        let pair_b = spawn_loopback_multihop(ExitId::from_bytes([0x74; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair_a.client.clone(), pair_b.client.clone()]);

        pair_a
            .exit_conn
            .close(quinn::VarInt::from_u32(0x1111), b"a closes first");
        let first = tokio::time::timeout(Duration::from_secs(2), bundle.closed())
            .await
            .expect("closed() must resolve once session A dies");

        // Session B dying afterwards must NOT overwrite the cached reason:
        // one dead session condemns the whole bundle, and the supervisor's
        // redial reads a single, stable close cause.
        pair_b
            .exit_conn
            .close(quinn::VarInt::from_u32(0x2222), b"b closes second");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let second = tokio::time::timeout(Duration::from_secs(2), bundle.closed())
            .await
            .expect("closed() must still resolve (from the cached slot)");
        assert_eq!(
            format!("{first:?}"),
            format!("{second:?}"),
            "the second observation must be the SAME cached first-error, not B's"
        );
    }

    #[tokio::test]
    async fn force_close_for_reconnect_closes_every_bonded_session() {
        let pair_a = spawn_loopback_multihop(ExitId::from_bytes([0x75; 16])).await;
        let pair_b = spawn_loopback_multihop(ExitId::from_bytes([0x76; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair_a.client.clone(), pair_b.client.clone()]);

        bundle.force_close_for_reconnect();

        let close_err = tokio::time::timeout(Duration::from_secs(2), bundle.closed())
            .await
            .expect("closed() must resolve promptly after a forced reconnect close");
        assert!(
            matches!(close_err, quinn::ConnectionError::LocallyClosed),
            "a self-initiated forced-reconnect close must surface as LocallyClosed, \
             got {close_err:?}"
        );
        // Both sessions must be closed, not just whichever the reader
        // happened to observe first.
        for exit_conn in [&pair_a.exit_conn, &pair_b.exit_conn] {
            let peer_view = tokio::time::timeout(Duration::from_secs(2), exit_conn.closed())
                .await
                .expect("the exit side of EVERY bonded session must observe the close");
            assert!(
                !matches!(peer_view, quinn::ConnectionError::TimedOut),
                "must be an explicit close, not an idle timeout"
            );
        }
    }

    #[tokio::test]
    async fn drop_explicitly_closes_every_bonded_session_even_with_outstanding_clones() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x77; 16])).await;
        // Simulate a detached observer (e.g. the client-side path probe)
        // that holds its own `Arc<MultiHopClient>` clone independent of the
        // bundle: this is exactly the shape of the observed production bug
        // (a torn-down tunnel left zombie sessions heartbeating the exit
        // indefinitely because only the bundle's OWN Arc handles were
        // dropped, and this outstanding clone kept the connection alive).
        let outstanding_clone = pair.client.clone();
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);

        drop(bundle);

        let close_err = tokio::time::timeout(Duration::from_secs(2), pair.exit_conn.closed())
            .await
            .expect("the exit side must observe the close promptly after Drop");
        assert!(
            !matches!(close_err, quinn::ConnectionError::TimedOut),
            "Drop must EXPLICITLY close the session, not merely drop Arc handles \
             (an idle timeout here means the zombie-session bug is back), got {close_err:?}"
        );
        drop(outstanding_clone);
    }
}
