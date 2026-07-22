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

use crate::multihop::{MultiHopClient, MultiHopError};

/// Hard cap on bonded connections per session, matching the `n_connections`
/// operating range; the exit-side router slot cap (16)
/// leaves headroom for the reconnect-overlap window on top of this.
pub const MAX_BONDED_CONNECTIONS: usize = 8;

/// Bound on the merged downlink channel, in packets (~3 MiB at the
/// 1452-byte tunnel MTU). Full ⇒ the per-session readers backpressure
/// into Quinn's own receive queue; nothing is dropped here.
const MERGED_DOWNLINK_BOUND: usize = 2048;

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

    /// Flow-pinned session for `pkt`: 5-tuple hash for TCP/UDP,
    /// round-robin fallback otherwise.
    ///
    /// A flow keeps its pinned session at a given bundle width; a
    /// mid-session width change (background bonding completing) may
    /// re-pin flows once, exactly like a reconnect re-pins them, which
    /// QUIC datagram delivery tolerates (no per-flow ordering promise
    /// across different sessions is ever made to the exit).
    fn pick(&self, pkt: &[u8]) -> Arc<MultiHopClient> {
        let clients = self.clients.read();
        let n = clients.len();
        let idx = match warrenguard_transport_core::flow_hash_5tuple(pkt) {
            Some(h) => (h as usize) % n,
            None => self.rr.fetch_add(1, Ordering::Relaxed) % n,
        };
        clients[idx].clone()
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

    /// Seals and sends one path-health probe packet on its flow-pinned
    /// session, WITHOUT feeding the real-traffic liveness counters:
    /// engine-generated probes must never satisfy (or trip) the
    /// app-traffic dead-path watches.
    ///
    /// # Errors
    ///
    /// Propagates [`MultiHopClient::send`] errors of the picked session.
    pub async fn send_probe(&self, payload: &[u8]) -> Result<(), MultiHopError> {
        self.pick(payload).send(payload).await
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

    /// Most conservative datagram budget across the bonded sessions
    /// (a packet may be pinned to any of them).
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.clients
            .read()
            .iter()
            .filter_map(|c| c.max_datagram_size())
            .min()
    }

    /// Most conservative inner-packet budget across the bonded sessions:
    /// the largest inner IP packet every session can currently carry in
    /// one datagram (path budget minus that session's frame overhead).
    /// This is the live "effective inner MTU" of the tunnel; when it
    /// drops below the TUN MTU the pumps clamp TCP MSS and reflect
    /// PMTUD so the datapath keeps flowing on reduced-MTU underlays.
    #[must_use]
    pub fn max_inner_payload(&self) -> usize {
        self.clients
            .read()
            .iter()
            .map(|c| c.max_inner_payload())
            .min()
            .unwrap_or(
                usize::from(warrenguard_config::TUNNEL_MIN_MTU) - MULTIHOP_FRAME_MAX_OVERHEAD,
            )
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
    /// # Errors
    ///
    /// Propagates the underlying `Endpoint::rebind` I/O error.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> std::io::Result<()> {
        self.primary().rebind(socket)
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
    use crate::test_support::spawn_loopback_multihop;

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
