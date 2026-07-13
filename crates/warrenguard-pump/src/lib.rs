//! Bidirectional TUN <-> QUIC RFC 9221 datagram pumps.
//!
//! Outbound IP packets (read from the local TUN) are encapsulated one
//! by one in QUIC datagrams. Datagrams received by the connection are
//! written to the TUN.
//!
//! No Warren header is added around the IP packet: we identify the IP
//! version by the first nibble of the payload (4 or 6).

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use quinn::{Connection, SendDatagramError};
use warrenguard_ratelimit::IdentityLimiter;
use warrenguard_wire::WarrenPubkey;

use warrenguard_config::knobs::CoverDefenses;
use warrenguard_daita::daita::DaitaState;
use warrenguard_transport_core::PacketDevice;
use warrenguard_transport_core::error::{Result, TunnelError};

pub mod idle_cover;
use idle_cover::IdleCover;

/// A client multi-connection session the multi-conn pumps dispatch over.
///
/// Kept as a trait so the pump stays client-agnostic: the concrete client
/// `MultiSession` implements it, but the pump never names that type. The two
/// methods are all the pump needs - the N connections to read downlink from, and
/// a sticky-hash uplink send.
pub trait MultiConnSession: Send + Sync + 'static {
    /// The N active connections of this session (cheap `Arc` clones).
    fn clone_connections(&self) -> Vec<Connection>;
    /// Sends one datagram, dispatching it across the N connections by sticky
    /// 5-tuple hash (or round-robin for non-IP packets).
    ///
    /// # Errors
    /// Datagram too large for the path MTU, or the selected connection closed.
    fn send_datagram(&self, payload: Vec<u8>) -> Result<()>;

    /// Zero-copy variant of [`Self::send_datagram`] that forwards a `Bytes`
    /// handle (a pooled buffer recycles on drop) instead of taking a
    /// `Vec<u8>`. Same sticky-hash dispatch. The default falls back to the
    /// `Vec` path (one copy); real impls override to forward the handle.
    ///
    /// # Errors
    /// Datagram too large for the path MTU, or the selected connection closed.
    fn send_datagram_bytes(&self, payload: Bytes) -> Result<()> {
        self.send_datagram(payload.to_vec())
    }
}

impl<S: MultiConnSession> MultiConnSession for std::sync::Arc<S> {
    fn clone_connections(&self) -> Vec<Connection> {
        (**self).clone_connections()
    }
    fn send_datagram(&self, payload: Vec<u8>) -> Result<()> {
        (**self).send_datagram(payload)
    }
    fn send_datagram_bytes(&self, payload: Bytes) -> Result<()> {
        (**self).send_datagram_bytes(payload)
    }
}

/// Returns true if `e` is the tun-rs `ErrTooManySegments` sentinel.
///
/// tun-rs (ported from wireguard-go `tun.ErrTooManySegments`) returns this
/// when the kernel pushes a GSO/GRO packet whose segment count exceeds
/// the output buffer size (128 = `IDEAL_BATCH_SIZE`). wireguard-go treats
/// it as non-fatal (`device/send.go:300`): log verbose + continue.
///
/// The raw kernel packet is already consumed by `read()` before
/// `gso_split()` fails, so we cannot retry - we drop the oversized packet
/// and let TCP retransmission recover.
#[must_use]
pub fn is_err_too_many_segments(e: &std::io::Error) -> bool {
    e.to_string().contains("ErrTooManySegments")
}

/// Upper bound on the consecutive TUN I/O failure streak tolerated by a
/// pump before it gives up. A wedged TUN (closed fd, EIO forever) still
/// exits via this bound; transient bursts (macOS utun ENOBUFS under
/// load, EINTR) never kill the pump.
const MAX_CONSECUTIVE_TUN_ERRORS: u32 = 10_000;

/// Process-wide tally of tolerated TUN I/O errors. Each increment is
/// at least one dropped packet, so a TUN that fails 95 % of the time
/// (partial degradation that never trips the consecutive-error bound)
/// is visible to ops through [`TunIoTolerance::global_error_total`]
/// instead of hiding behind 1 WARN per 1 000 errors.
static TUN_IO_ERROR_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Tracks a consecutive TUN I/O failure streak for one pump direction.
/// Packets hitting a transient error are dropped (IP is lossy; TCP/uTP
/// retransmit); only a persistent streak kills the pump.
///
/// A single transient `tun.send`/`tun.recv` error MUST NOT tear the
/// tunnel down: on macOS utun returns ENOBUFS whenever its queue fills
/// under a download burst, and a fatal-on-first-error pump silently
/// blackholes the whole session (and on the exit, the whole fleet)
/// while QUIC stays "Connected".
pub struct TunIoTolerance {
    what: &'static str,
    consecutive: u32,
}

impl TunIoTolerance {
    /// Creates a fresh tolerance tracker; `what` labels the pump
    /// direction in the rate-limited warning logs.
    #[must_use]
    pub fn new(what: &'static str) -> Self {
        Self {
            what,
            consecutive: 0,
        }
    }

    /// Resets the streak after a successful TUN operation.
    pub fn ok(&mut self) {
        self.consecutive = 0;
    }

    /// Process-wide count of TUN I/O errors tolerated by every pump
    /// since process start (monotonic). Each tolerated error dropped
    /// at least one packet; a steadily climbing counter under traffic
    /// means a partially-degraded TUN even when the tunnel stays
    /// "Connected".
    #[must_use]
    pub fn global_error_total() -> u64 {
        TUN_IO_ERROR_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Logs (rate-limited), backs off briefly, and errors out once the
    /// streak exceeds [`MAX_CONSECUTIVE_TUN_ERRORS`].
    ///
    /// # Errors
    ///
    /// Returns [`TunnelError::Tun`] once the consecutive streak exceeds
    /// the bound (the TUN is considered gone for good).
    pub async fn tolerate(&mut self, e: &std::io::Error) -> Result<()> {
        self.consecutive += 1;
        TUN_IO_ERROR_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.consecutive == 1 || self.consecutive.is_multiple_of(1_000) {
            tracing::warn!(
                error = %e,
                consecutive = self.consecutive,
                "{}: transient TUN I/O error, dropping packet and continuing",
                self.what
            );
        }
        if self.consecutive >= MAX_CONSECUTIVE_TUN_ERRORS {
            return Err(TunnelError::Tun {
                context: format!("{} persistent TUN failure", self.what).into(),
                source: std::io::Error::new(e.kind(), e.to_string()),
            });
        }
        // ENOBUFS clears as soon as the kernel drains the utun queue;
        // a short sleep avoids a hot loop without hurting goodput.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        Ok(())
    }
}

/// Maximum number of packets accumulated per `send_batch` call on the
/// downlink path (QUIC -> TUN). After reading the first datagram
/// (blocking), the pump polls for more immediately-available datagrams
/// up to this limit, then flushes the batch in a single `send_batch`.
///
/// On Linux + offload, `RealTun::send_batch` uses GRO coalescing +
/// `send_multiple` to write N packets in ~1 syscall. On macOS / Plain
/// mode the default impl loops over `send()` (no worse than before).
///
/// 64 matches wireguard-go's `IdealBatchSize / 2` for the write path.
pub(crate) const DOWNLINK_BATCH_MAX: usize = 64;

/// Non-blocking single-poll of `Connection::read_datagram`. Returns
/// `Some(Ok(bytes))` if a datagram is immediately available,
/// `Some(Err(e))` on connection error, or `None` if nothing is ready.
///
/// Uses `Waker::noop()` (Rust 1.85+) so the poll is fire-and-forget:
/// Quinn's internal state correctly services the next blocking
/// `read_datagram().await` regardless of whether this poll returned
/// Pending.
fn try_read_datagram(
    conn: &Connection,
) -> Option<std::result::Result<Bytes, quinn::ConnectionError>> {
    use std::task::{Context, Poll, Waker};
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut fut = std::pin::pin!(conn.read_datagram());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(result) => Some(result),
        Poll::Pending => None,
    }
}

/// Maximum number of packets drained via `try_recv` after an initial
/// `recv().await` - application-level batching infrastructure.
///
/// **Default 1 = batching DISABLED** per bench results
/// (32 and 128 were tested on real cloud servers):
/// - BATCH=32: uplink ~ neutral (+0.7 % within noise), downlink -7 to
///   -10 % (CPU contention with N=32 downlink tasks).
/// - BATCH=128: -12 % uplink, -23 % downlink (scheduler starvation).
///
/// **Hypotheses for the absence of gain**:
/// 1. `tun-rs::try_recv` per-call overhead ~= marginal sendmsg GSO gain.
/// 2. The kernel TUN driver does not queue packets between scheduler
///    yields - one-by-one delivery under saturated iperf3 bench.
/// 3. The Quinn driver wakes between `send_datagram` calls, defeating
///    the batch.
///
/// **Env override**: `WARREN_UPLINK_BATCH_MAX=N` re-enables the drain
/// for future experimentation (e.g. cumulating with IFF_VNET_HDR,
/// kernel 6.8 UDP-GRO, or less variable bare-metal). N=1 = no-op
/// (inner loop runs 0 iterations).
///
/// The infrastructure (`PacketDevice::try_recv` + drain loop) stays in
/// place for those future experiments - near-zero cost at BATCH=1
/// (just a OnceLock read).
/// `WARREN_UPLINK_BATCH_MAX` (default 1, clamped to `[1, 1024]`). The env
/// read, parse and clamp live in the central knob registry.
fn uplink_batch_max() -> usize {
    warrenguard_config::knobs::uplink_batch_max()
}

/// Rate-limited visibility into silent uplink too-large drops.
///
/// A datagram that exceeds the connection's `max_datagram_size` is dropped
/// rather than erroring (a transient PMTU shrink must not crash the tunnel).
/// But a SUSTAINED mismatch (the TUN MTU + HPKE overhead permanently exceeds
/// the negotiated max datagram size, e.g. behind a reduced-MTU or nested path)
/// black-holes the whole data plane while the control plane stays up: the
/// tunnel reports "connected" yet carries nothing. That failure was invisible
/// (logged at TRACE). This surfaces it at WARN, with the sizes, on the first
/// drop and every 64th after, so the cause is visible in a normal client log
/// without a packet capture.
/// Returns the running total (1-based) of uplink too-large drops tallied so
/// far. Exposed so tests can observe the counter's increment behavior via a
/// before/after delta (the counter is process-global, like
/// [`TunIoTolerance::global_error_total`], so an absolute-value assertion
/// would be racy against other tests running in the same process).
fn record_uplink_too_large_drop(pkt_size: usize, max_datagram: Option<usize>) -> u64 {
    static DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let total = n + 1;
    if n == 0 || n.is_multiple_of(64) {
        tracing::warn!(
            total_uplink_too_large_drops = total,
            pkt_size,
            max_datagram = max_datagram.unwrap_or(0),
            "uplink datagram dropped: too large for the path max datagram size. \
             Sustained drops mean a black-holed data plane despite a live tunnel."
        );
    }
    total
}

/// Wrapper around `send_datagram` that silently drops oversized packets.
///
/// Factored to share the logic between `pump_tun_to_quic` (mono-conn)
/// and `pump_multi_bidirectional` (multi-conn). Both paths must treat
/// `SendDatagramError::TooLarge` as non-fatal (would otherwise crash
/// the entire tunnel under PMTU race).
/// Pooled variant: wraps the buffer with the pool so it recycles on drop.
fn send_datagram_drop_too_large_pooled(
    conn: &Connection,
    pkt: Vec<u8>,
    pool: &warrenguard_transport_core::buffer_pool::BufferPool,
) -> Result<()> {
    if let Some(max) = conn.max_datagram_size()
        && pkt.len() > max
    {
        record_uplink_too_large_drop(pkt.len(), Some(max));
        pool.return_buf_explicit(pkt);
        return Ok(());
    }
    let pkt_len = pkt.len();
    if let Err(e) = conn.send_datagram(pool.wrap(pkt)) {
        if matches!(e, SendDatagramError::TooLarge) {
            record_uplink_too_large_drop(pkt_len, conn.max_datagram_size());
            return Ok(());
        }
        return Err(TunnelError::QuicSendDatagram {
            context: "uplink".into(),
            source: e,
        });
    }
    Ok(())
}

/// Sends a datagram, dropping it (rather than erroring) when it exceeds the
/// connection's current max datagram size: the PMTU may have shrunk since the
/// caller measured it. Other send errors propagate.
///
/// # Errors
/// Propagates a non-size send error from the connection.
pub fn send_datagram_drop_too_large(conn: &Connection, pkt: Vec<u8>) -> Result<()> {
    if let Some(max) = conn.max_datagram_size()
        && pkt.len() > max
    {
        record_uplink_too_large_drop(pkt.len(), Some(max));
        return Ok(());
    }
    let pkt_len = pkt.len();
    if let Err(e) = conn.send_datagram(Bytes::from(pkt)) {
        // Typed `SendDatagramError::TooLarge` signal instead of string
        // matching. The `max_datagram_size()` pre-check catches most
        // cases; this path is the safety net for the PMTU race (PMTU
        // may change between the check and the send under load).
        if matches!(e, SendDatagramError::TooLarge) {
            record_uplink_too_large_drop(pkt_len, conn.max_datagram_size());
            return Ok(());
        }
        return Err(TunnelError::QuicSendDatagram {
            context: "uplink".into(),
            source: e,
        });
    }
    Ok(())
}

/// Same as `send_datagram_drop_too_large` but via `MultiSession` for
/// sticky 5-tuple N-conn dispatch. Same too-large drop logic for the
/// PMTU race on the multi-conn side.
fn multi_send_drop_too_large<S: MultiConnSession>(session: &S, pkt: Vec<u8>) -> Result<()> {
    let pkt_len = pkt.len();
    if let Err(e) = session.send_datagram(pkt) {
        // Typed match on the wrapped Quinn error. `MultiSession::send_datagram`
        // boxes the source as `TunnelError::QuicSendDatagram { source, .. }`,
        // so we recover the original cause via destructuring.
        if let TunnelError::QuicSendDatagram {
            source: SendDatagramError::TooLarge,
            ..
        } = &e
        {
            record_uplink_too_large_drop(pkt_len, None);
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

/// Pooled variant of [`multi_send_drop_too_large`]: wraps the buffer with
/// the [`warrenguard_transport_core::buffer_pool::BufferPool`] (via
/// [`MultiConnSession::send_datagram_bytes`]) so it recycles on drop,
/// instead of handing over ownership of a `Vec<u8>` allocated fresh per
/// packet. Used by the multi-conn uplinks (the main throughput path) to
/// avoid a malloc + memset on every packet in Plain TUN mode, mirroring
/// [`send_datagram_drop_too_large_pooled`] on the mono-conn side.
fn multi_send_drop_too_large_pooled<S: MultiConnSession>(
    session: &S,
    pkt: Vec<u8>,
    pool: &warrenguard_transport_core::buffer_pool::BufferPool,
) -> Result<()> {
    let pkt_len = pkt.len();
    if let Err(e) = session.send_datagram_bytes(pool.wrap(pkt)) {
        // Typed match on the wrapped Quinn error, mirroring
        // `multi_send_drop_too_large`.
        if let TunnelError::QuicSendDatagram {
            source: SendDatagramError::TooLarge,
            ..
        } = &e
        {
            record_uplink_too_large_drop(pkt_len, None);
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

/// Batch size requested from `PacketDevice::recv_batch` on the uplink
/// pump side. Equals `tun-rs::IDEAL_BATCH_SIZE` (128) to match the
/// Linux + offload path.
///
/// In `RealTun` Plain mode (macOS, Linux without offload, FakeTun) the
/// default trait impl returns 1 packet per call - batching is
/// effectively a no-op on that path. Only with
/// `RealTun::create_with_ipv4_mtu_offload(true)` (Linux + IFF_VNET_HDR)
/// does the kernel coalesce N packets into 1 syscall, allowing
/// recv_batch to return up to 128 packets.
pub const PUMP_UPLINK_BATCH_SIZE: usize = 128;

/// Loop reading outbound packets from the TUN and pushing them as QUIC
/// datagrams onto the connection. Terminates when the TUN or connection
/// is closed.
///
/// # Batching
///
/// Uses `PacketDevice::recv_batch`, which can return up to
/// `PUMP_UPLINK_BATCH_SIZE` packets in 1 syscall on Linux + offload.
/// In Plain mode, recv_batch performs a single recv and returns 1
/// packet - the `try_recv` drain (gated by `WARREN_UPLINK_BATCH_MAX`)
/// then takes over.
///
/// # Errors
///
/// TUN read error (closed) or datagram send error (connection closed,
/// or packet larger than the negotiated path MTU).
pub async fn pump_tun_to_quic<T: PacketDevice>(tun: T, conn: Connection) -> Result<()> {
    let pool = warrenguard_transport_core::buffer_pool::BufferPool::new();
    let mut bufs: Vec<Vec<u8>> = (0..PUMP_UPLINK_BATCH_SIZE).map(|_| pool.take()).collect();
    let mut tun_io = TunIoTolerance::new("uplink tun recv");
    loop {
        let n = match tun.recv_batch_into(&mut bufs).await {
            Ok(n) => {
                tun_io.ok();
                n
            }
            Err(e) if is_err_too_many_segments(&e) => {
                tracing::warn!("dropped oversized GSO packet (ErrTooManySegments)");
                continue;
            }
            Err(e) => {
                tun_io.tolerate(&e).await?;
                continue;
            }
        };
        for buf in &mut bufs[..n] {
            let filled = std::mem::replace(buf, pool.take());
            send_datagram_drop_too_large_pooled(&conn, filled, &pool)?;
        }

        for _ in 0..uplink_batch_max().saturating_sub(1) {
            match tun.try_recv() {
                Ok(Some(pkt)) => send_datagram_drop_too_large_pooled(&conn, pkt, &pool)?,
                Ok(None) => break,
                Err(e) => {
                    tun_io.tolerate(&e).await?;
                    break;
                }
            }
        }
    }
}

/// Loop reading inbound datagrams from the connection and writing them
/// to the TUN. Terminates when the connection or TUN is closed.
///
/// When `tunnel_ips` is `Some`, validates that each packet's source IP
/// matches the client's allocated tunnel IP before writing to the TUN.
/// Packets with spoofed source IPs are silently dropped.
///
/// ## Batched writes
///
/// After the first blocking `read_datagram`, the pump polls for more
/// immediately-available datagrams (up to [`DOWNLINK_BATCH_MAX`]) and
/// flushes them all via [`PacketDevice::send_batch`]. On Linux +
/// offload this amortizes the TUN write to ~1 syscall for N packets
/// (via `send_multiple` + GRO coalescing). On macOS / Plain mode the
/// default `send_batch` loops over `send()` (no regression).
///
/// # Errors
///
/// Datagram read error (connection closed) or TUN write error.
pub async fn pump_quic_to_tun<T: PacketDevice>(
    conn: Connection,
    tun: T,
    tunnel_ips: Option<(std::net::Ipv4Addr, Option<std::net::Ipv6Addr>)>,
    metrics: Option<std::sync::Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
) -> Result<()> {
    // batch holds Bytes (zero-copy Arc clones) instead of Vec<u8>.
    let mut batch: Vec<Bytes> = Vec::with_capacity(DOWNLINK_BATCH_MAX);
    let mut tun_io = TunIoTolerance::new("downlink tun send");
    let mut spoof_log = SpoofDropLog::new();
    loop {
        let dg = conn
            .read_datagram()
            .await
            .map_err(|source| TunnelError::QuicReadDatagram {
                context: "downlink".into(),
                source,
            })?;
        if let Some(pkt) = accept_downlink(&dg, tunnel_ips, &metrics, &mut spoof_log) {
            batch.push(pkt);
        }

        while batch.len() < DOWNLINK_BATCH_MAX {
            match try_read_datagram(&conn) {
                Some(Ok(dg)) => {
                    if let Some(pkt) = accept_downlink(&dg, tunnel_ips, &metrics, &mut spoof_log) {
                        batch.push(pkt);
                    }
                }
                Some(Err(source)) => {
                    // Best-effort flush: the packets already validated
                    // in this batch were received before the connection
                    // died; deliver them to the TUN instead of dropping
                    // up to DOWNLINK_BATCH_MAX packets per teardown.
                    if !batch.is_empty() {
                        let _ = tun.send_batch_bytes(&mut batch).await;
                        batch.clear();
                    }
                    return Err(TunnelError::QuicReadDatagram {
                        context: "downlink batch drain".into(),
                        source,
                    });
                }
                None => break,
            }
        }

        if !batch.is_empty() {
            match tun.send_batch_bytes(&mut batch).await {
                Ok(_) => tun_io.ok(),
                // The batch is dropped (IP is lossy; TCP retransmits).
                Err(e) => tun_io.tolerate(&e).await?,
            }
            batch.clear();
        }
    }
}

/// Pure cadence decision behind [`SpoofDropLog`]: should the `n`-th
/// (1-based) occurrence be logged, given a "log every `every`" policy? True
/// for the first occurrence and every `every`-th after, so a sustained flood
/// stays visible without flooding the log. Extracted as a standalone,
/// state-free function so the cadence itself is unit-tested without needing
/// a live `tracing` subscriber.
#[must_use]
pub fn log_every_n_should_log(n: u64, every: u64) -> bool {
    n == 1 || (every > 0 && n.is_multiple_of(every))
}

/// Rate-limited visibility into anti-spoof drops on the downlink (QUIC ->
/// TUN). Without this, a hostile client spoofing its source IP at line rate
/// would cost the exit one WARN per packet: journald flood, logging CPU,
/// disk fill, on fully attacker-controlled input. Warns on the first drop
/// and every 64th after, mirroring [`record_uplink_too_large_drop`]'s
/// cadence.
///
/// Kept as a small counter owned by the pump loop (constructed once per
/// `pump_quic_to_tun` / `pump_quic_to_tun_rate_limited` call, i.e. once per
/// connection) rather than a process-global `static`: each pump instance
/// already tracks exactly one connection, so a per-instance counter both
/// keeps the cadence scoped to that one client's spoofing burst (a global
/// counter would blend every client's drops into a single shared cadence)
/// and makes it trivially unit-testable in isolation, unlike the older
/// `static`-based [`record_uplink_too_large_drop`] counter.
#[derive(Default)]
pub struct SpoofDropLog {
    total: u64,
}

impl SpoofDropLog {
    /// Log cadence: first occurrence, then every 64th.
    const LOG_EVERY: u64 = 64;

    /// Creates a fresh, zeroed counter.
    #[must_use]
    pub const fn new() -> Self {
        Self { total: 0 }
    }

    /// Records one spoofed-source-IP drop. Returns `(should_log, total)`:
    /// `total` is the running 1-based count, and `should_log` is the fixed
    /// cadence decision from [`log_every_n_should_log`].
    fn record(&mut self) -> (bool, u64) {
        self.total += 1;
        (
            log_every_n_should_log(self.total, Self::LOG_EVERY),
            self.total,
        )
    }
}

/// Filters and validates a downlink datagram for zero-copy batching.
///
/// Returns `Some(Bytes)` - a clone of the QUIC-layer `Bytes` handle
/// (Arc ref-count increment, no memcpy) - if the packet should be
/// forwarded to the TUN. Returns `None` for DAITA dummies or packets
/// with spoofed source IPs, which are silently dropped.
///
/// Compared to the previous `dg.to_vec()` approach, this eliminates a
/// ~1 280-byte heap allocation per inbound packet.
fn accept_downlink(
    dg: &Bytes,
    tunnel_ips: Option<(std::net::Ipv4Addr, Option<std::net::Ipv6Addr>)>,
    metrics: &Option<std::sync::Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
    spoof_log: &mut SpoofDropLog,
) -> Option<Bytes> {
    if is_daita_dummy(dg) {
        tracing::trace!(bytes = dg.len(), "drop DAITA dummy (defense-in-depth)");
        return None;
    }
    if let Some((v4, v6)) = tunnel_ips
        && !warrenguard_transport_core::ip_parse::source_ip_matches(dg, v4, v6)
    {
        let (should_log, total) = spoof_log.record();
        if should_log {
            tracing::warn!(
                bytes = dg.len(),
                total_spoofed_drops = total,
                "dropped packet with spoofed source IP (rate-limited log)"
            );
        }
        return None;
    }
    if let Some(m) = metrics {
        m.record_rx(dg.len() as u64);
    }
    // Zero-copy: clone() increments the Arc reference count only.
    Some(dg.clone())
}

/// First nibble of an outgoing/incoming Warren datagram that signals
/// a DAITA padding ("dummy") packet rather than a real IP packet. IPv4
/// always starts with `0x4?` and IPv6 with `0x6?`; we pick `0xF?` as
/// our padding marker so dummy bytes cannot be confused with either
/// kind by a passive observer of cleartext (they couldn't anyway with
/// QUIC, but the receiver-side filter must distinguish them locally
/// without false positives against fragmented IP or future protocol
/// extensions).
pub const DAITA_DUMMY_FIRST_BYTE: u8 = 0xFF;

/// Default size of a DAITA dummy datagram in bytes. Matches the
/// typical full-MTU packet size so the wire footprint is
/// indistinguishable from a normal data packet of the maximum size.
/// The first byte (`0xFF`) is the marker; the remaining bytes can be
/// any non-secret-looking filler (we use `0xFF` for simplicity - the
/// payload is encrypted by QUIC anyway, so a constant fill is fine).
const DAITA_DUMMY_PAYLOAD_LEN: usize = 1280;

/// Detects a DAITA dummy datagram by reading the first byte's high
/// nibble. Real IPv4 packets have first nibble = 4, IPv6 = 6.
/// Anything else is treated as a dummy and must be dropped by the
/// receiver before it reaches the TUN (a malformed IP packet would
/// otherwise generate a kernel-level rejection with extra work).
#[must_use]
pub fn is_daita_dummy(datagram: &[u8]) -> bool {
    match datagram.first() {
        Some(b) => {
            let nibble = b >> 4;
            nibble != 4 && nibble != 6
        }
        None => true,
    }
}

/// Builds a DAITA dummy datagram payload sized to the connection's
/// negotiated `max_datagram_size` (clipped to
/// `DAITA_DUMMY_PAYLOAD_LEN`). The first byte is
/// [`DAITA_DUMMY_FIRST_BYTE`] to identify the packet as padding; the
/// rest is constant filler. The QUIC layer encrypts the entire
/// datagram before transmission so a passive observer sees only
/// pseudorandom bytes.
///
/// Prefer [`DaitaDummyTemplate`] on hot paths: this function allocates
/// a fresh `Vec` on every call (used only during template initialisation
/// and in code paths where `max_datagram_size()` has just changed).
#[must_use]
pub fn build_daita_dummy_vec(conn: &Connection) -> Vec<u8> {
    let max = conn
        .max_datagram_size()
        .unwrap_or(DAITA_DUMMY_PAYLOAD_LEN)
        .min(DAITA_DUMMY_PAYLOAD_LEN);
    vec![DAITA_DUMMY_FIRST_BYTE; max]
}

/// Pre-allocated DAITA dummy template.
///
/// Created once per session/connection from the negotiated
/// `max_datagram_size()`. Each `clone()` returns a new `Bytes` handle
/// backed by the **same underlying allocation** (atomic reference-count
/// increment only, no `memcpy`). At Tamaraw's 200 pkt/s padding rate
/// this saves ~256 KB/s of heap allocations compared to the previous
/// `vec![…; max]` on every timer fire.
///
/// If `max_datagram_size()` changes between timer fires (PMTU
/// discovery), call [`Self::refresh_if_changed`] to regenerate the
/// backing buffer only when the size actually changes.
pub(crate) struct DaitaDummyTemplate {
    template: Bytes,
    /// Last known datagram size used to build the template.
    last_max: usize,
}

impl DaitaDummyTemplate {
    /// Build the template from the connection's current
    /// `max_datagram_size()`, or `DAITA_DUMMY_PAYLOAD_LEN` as fallback.
    pub(crate) fn new(conn: &Connection) -> Self {
        let max = conn
            .max_datagram_size()
            .unwrap_or(DAITA_DUMMY_PAYLOAD_LEN)
            .min(DAITA_DUMMY_PAYLOAD_LEN);
        Self {
            template: Bytes::from(vec![DAITA_DUMMY_FIRST_BYTE; max]),
            last_max: max,
        }
    }

    /// Returns a zero-copy clone of the pre-allocated dummy payload.
    ///
    /// `Bytes::clone` is an Arc reference-count increment: O(1) and
    /// no heap allocation.
    #[inline]
    pub(crate) fn get(&self) -> Bytes {
        self.template.clone()
    }

    /// Regenerates the template only if `max_datagram_size()` has
    /// changed since the last call. No-op on the common path (PMTU
    /// stable); one allocation on PMTU discovery events.
    pub(crate) fn refresh_if_changed(&mut self, conn: &Connection) {
        let max = conn
            .max_datagram_size()
            .unwrap_or(DAITA_DUMMY_PAYLOAD_LEN)
            .min(DAITA_DUMMY_PAYLOAD_LEN);
        if max != self.last_max {
            self.template = Bytes::from(vec![DAITA_DUMMY_FIRST_BYTE; max]);
            self.last_max = max;
        }
    }
}

/// Bidirectional pump variant that drives a [`DaitaState`] in addition
/// to the normal datagram pumping. Compared to [`pump_bidirectional`]:
///
/// - every outgoing real packet fires `NormalSent` + `TunnelSent`,
/// - every incoming datagram is classified by [`is_daita_dummy`]:
///   IP packets pass through to the TUN and fire `NormalRecv` +
///   `TunnelRecv`; dummies are dropped at the pump and fire
///   `PaddingRecv` + `TunnelRecv`,
/// - an additional timer branch wakes up when the next per-machine
///   action timer expires and emits one dummy datagram per machine
///   whose padding budget is due.
///
/// When the supplied state is disabled (`!state.is_enabled()`), the
/// function defers to the regular [`pump_bidirectional`] for zero
/// overhead.
///
/// # Errors
///
/// First error from any of the three branches (uplink TUN read,
/// downlink datagram read, downstream TUN write) is returned and the
/// other branches are cancelled by the `tokio::select!`.
pub async fn pump_bidirectional_with_daita<T>(
    tun: T,
    conn: Connection,
    state: DaitaState,
) -> Result<()>
where
    T: PacketDevice + Clone,
{
    if !state.is_enabled() {
        // Cheap fall-through: no DAITA configured for this session,
        // skip the extra event channels and timer overhead.
        return pump_bidirectional(tun, conn).await;
    }
    pump_bidirectional_daita_inner(tun, conn, state).await
}

async fn pump_bidirectional_daita_inner<T>(
    tun: T,
    conn: Connection,
    mut state: DaitaState,
) -> Result<()>
where
    T: PacketDevice + Clone,
{
    // Pre-allocate the dummy payload once after the handshake. On
    // each timer fire `dummy_template.get()` returns a zero-copy
    // `Bytes` clone (Arc ref-count bump) instead of a fresh
    // `vec![0xFF; 1280]` allocation.
    let mut dummy_template = DaitaDummyTemplate::new(&conn);
    let mut tun_io_up = TunIoTolerance::new("daita uplink tun recv");
    let mut tun_io_dn = TunIoTolerance::new("daita downlink tun send");
    // Buffer pool for the uplink read: `recv_batch_into` fills a pooled buffer
    // in place (no per-packet 2 KiB alloc), and `wrap` hands Quinn a `Bytes`
    // that recycles the buffer on drop. Mirrors the non-DAITA pooled uplink.
    let pool = warrenguard_transport_core::buffer_pool::BufferPool::new();
    let mut up_buf = pool.take();

    loop {
        // The pump always has *some* sleep arm so we don't have to
        // express "no timer" as a separate match: if the framework has
        // no pending action timer, sleep for an hour and let the next
        // event/recv re-arm whatever is due. The arbitrary hour is far
        // enough that we never wake up for nothing in practice (the
        // shortest DAITA machine emits a `SendPadding` within seconds
        // of the first `TunnelSent`).
        let next_timer = state.sleep_deadline(Instant::now());
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(next_timer));
        tokio::pin!(sleep);

        tokio::select! {
            // Branch 1: uplink - read one packet from the TUN, send it
            // as a QUIC datagram, fire the uplink DAITA event sequence.
            res = tun.recv_batch_into(std::slice::from_mut(&mut up_buf)) => {
                let n = match res {
                    Ok(n) => {
                        tun_io_up.ok();
                        n
                    }
                    Err(e) => {
                        tun_io_up.tolerate(&e).await?;
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }
                if let Some(max) = conn.max_datagram_size()
                    && up_buf.len() > max
                {
                    up_buf.clear();
                    continue;
                }
                // Hand the filled buffer to Quinn as a pooled datagram and take
                // a fresh scratch for the next read; the pooled `Bytes` returns
                // its buffer to the pool on drop, so steady-state uplink does
                // not allocate per packet.
                let filled = std::mem::replace(&mut up_buf, pool.take());
                match conn.send_datagram(pool.wrap(filled)) {
                    Ok(()) => state.on_real_uplink_sent(Instant::now()),
                    Err(SendDatagramError::TooLarge) => {}
                    Err(e) => return Err(TunnelError::QuicSendDatagram {
                        context: "uplink".into(), source: e,
                    }),
                }
            }

            // Branch 2: downlink - read one datagram from QUIC,
            // classify, write to TUN if real, drop if dummy.
            res = conn.read_datagram() => {
                let dg = res.map_err(|source| TunnelError::QuicReadDatagram {
                    context: "daita pump conn.read_datagram".into(),
                    source,
                })?;
                let now = Instant::now();
                let dummy = is_daita_dummy(&dg);
                if !dummy {
                    match tun.send(&dg).await {
                        Ok(()) => tun_io_dn.ok(),
                        // Packet dropped (IP is lossy; TCP retransmits).
                        Err(e) => tun_io_dn.tolerate(&e).await?,
                    }
                }
                // Dummy: dropped (not written to the TUN); the kernel would
                // discard it as a malformed IP packet anyway. The DAITA event
                // sequence (TunnelRecv before the kind-specific event) is the
                // same shared helper for real and dummy.
                state.on_downlink_received(dummy, now);
            }

            // Branch 3: padding timer - emit one dummy datagram per
            // machine whose action timer expired.
            _ = &mut sleep => {
                // Refresh the template if PMTU changed, then clone
                // (Arc increment only) on each timer fire.
                dummy_template.refresh_if_changed(&conn);
                let now = Instant::now();
                let fired_machines = state.drain_expired(now);
                for machine in fired_machines {
                    // Zero-copy: Arc ref-count increment.
                    let dummy = dummy_template.get();
                    if let Err(e) = conn.send_datagram(dummy) {
                        if !matches!(e, SendDatagramError::TooLarge) {
                            return Err(TunnelError::QuicSendDatagram {
                                context: "daita dummy uplink".into(),
                                source: e,
                            });
                        }
                    } else {
                        state.on_dummy_sent(machine, Instant::now());
                    }
                }
            }
        }
    }
}

/// Runs both pumps simultaneously via `tokio::select!`. Terminates when
/// one direction fails (returning the error), or is cancelled by the
/// caller (`abort()` on the JoinHandle).
///
/// **Optimization explored and rejected**: we tried separate
/// `tokio::spawn` for the two pumps, hoping the multi-thread scheduler
/// would place them on distinct cores. Result: client CPU 70%->150%
/// (parallelization OK) BUT throughput 469->425 Mbps (-9% regression).
/// Cause: both pumps share the same Quinn `Connection` whose
/// `send_datagram` / `read_datagram` methods serialize on an internal
/// Quinn mutex. Cross-thread spawn -> lock contention exceeds the
/// parallelization gain. To break this ceiling we'd need multiple QUIC
/// connections (multi-conn), not multi-pump on the same Connection.
///
/// # Errors
///
/// The first error from either pump is returned; the other is
/// implicitly cancelled by the `select!`.
pub async fn pump_bidirectional<T>(tun: T, conn: Connection) -> Result<()>
where
    T: PacketDevice + Clone,
{
    let tun_for_uplink = tun.clone();
    let conn_for_uplink = conn.clone();
    tokio::select! {
        res = pump_tun_to_quic(tun_for_uplink, conn_for_uplink) => res,
        res = pump_quic_to_tun(conn, tun, None, None) => res,
    }
}

/// Bidirectional pump variant with idle cover traffic.
///
/// Identical data plane to [`pump_bidirectional`], plus a third
/// [`tokio::select!`] arm: when neither direction has carried a real
/// packet for a jittered interval (10-20s), it emits one varied-size
/// [`crate::DAITA_DUMMY_FIRST_BYTE`] dummy datagram. This replaces the
/// fixed keep-alive PING beacon (a 30-byte metronome every ~5s) with a
/// non-periodic, non-fixed-size idle footprint, refreshes the NAT
/// mapping, and resets the idle timeout. The client transport config
/// MUST be built with the keep-alive disabled
/// (`warren_transport_config_client_with_idle_cover(.., true)`) so the
/// two are coordinated; otherwise the PING still fires alongside cover.
///
/// Unlike [`pump_bidirectional`] (two concurrent batched pumps), this is
/// a single-task select loop, matching the DAITA inner loop. The
/// reduced batching is irrelevant for the idle case this targets, and
/// callers that need both DAITA and cover should compose at a higher
/// layer (out of scope here).
///
/// # Errors
///
/// First error from the uplink read, the downlink read, or a non-size
/// cover send error. A `SendDatagramError::TooLarge` on cover (transient
/// PMTU shrink) is non-fatal: the dummy is skipped and the next one is
/// re-sized to the current MTU.
pub async fn pump_bidirectional_with_idle_cover<T>(tun: T, conn: Connection) -> Result<()>
where
    T: PacketDevice,
{
    pump_bidirectional_with_idle_cover_interval(
        tun,
        conn,
        idle_cover::IDLE_COVER_MIN_INTERVAL,
        idle_cover::IDLE_COVER_MAX_INTERVAL,
    )
    .await
}

/// Test/tuning seam behind [`pump_bidirectional_with_idle_cover`]: identical
/// wiring, but with an explicit jittered interval range instead of the fixed
/// production [`idle_cover::IDLE_COVER_MIN_INTERVAL`]..
/// [`idle_cover::IDLE_COVER_MAX_INTERVAL`] (10-20s). `pump_bidirectional_with_idle_cover`
/// is a thin wrapper around this function using the production bounds, so
/// exercising this with a short interval runs the exact same loop body
/// (uplink read, downlink read, cover timer, `TunIoTolerance`) as the
/// production entry point, just re-timed for a fast integration test - the
/// long-running `#[ignore]`d suite still validates the production interval
/// end to end.
///
/// # Errors
///
/// Same as [`pump_bidirectional_with_idle_cover`].
pub async fn pump_bidirectional_with_idle_cover_interval<T>(
    tun: T,
    conn: Connection,
    min_interval: std::time::Duration,
    max_interval: std::time::Duration,
) -> Result<()>
where
    T: PacketDevice,
{
    // Per-connection seed so two concurrent tunnels do not share a cover
    // schedule; the stable id is local-only (never on the wire).
    let mut cover = IdleCover::with_interval(
        conn.stable_id() as u64,
        Instant::now(),
        conn.max_datagram_size(),
        min_interval,
        max_interval,
    );
    let mut tun_io_up = TunIoTolerance::new("idle-cover uplink tun recv");
    let mut tun_io_dn = TunIoTolerance::new("idle-cover downlink tun send");
    // Pooled uplink read: no per-packet 2 KiB alloc (see the DAITA pump).
    let pool = warrenguard_transport_core::buffer_pool::BufferPool::new();
    let mut up_buf = pool.take();
    loop {
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(cover.deadline()));
        tokio::pin!(sleep);
        tokio::select! {
            // Uplink: a real packet from the TUN. Sending it is genuine
            // activity, so it silences cover for the next interval.
            res = tun.recv_batch_into(std::slice::from_mut(&mut up_buf)) => {
                let n = match res {
                    Ok(n) => { tun_io_up.ok(); n }
                    Err(e) => { tun_io_up.tolerate(&e).await?; continue; }
                };
                if n == 0 { continue; }
                let filled = std::mem::replace(&mut up_buf, pool.take());
                send_datagram_drop_too_large_pooled(&conn, filled, &pool)?;
                cover.note_activity(Instant::now());
            }

            // Downlink: a datagram from the peer. Receiving (and thus
            // acknowledging) it is also activity, so it silences cover.
            // Dummies are dropped before the TUN, exactly like the other
            // pumps.
            res = conn.read_datagram() => {
                let dg = res.map_err(|source| TunnelError::QuicReadDatagram {
                    context: "idle-cover downlink".into(),
                    source,
                })?;
                cover.note_activity(Instant::now());
                if !is_daita_dummy(&dg) {
                    match tun.send(&dg).await {
                        Ok(()) => tun_io_dn.ok(),
                        Err(e) => tun_io_dn.tolerate(&e).await?,
                    }
                }
            }

            // Idle elapsed: emit one jittered, varied-size cover dummy.
            _ = &mut sleep => {
                let dummy = cover.fire(Instant::now());
                if let Some(max) = conn.max_datagram_size()
                    && dummy.len() > max
                {
                    // Transient PMTU shrink since construction: skip this
                    // one, the next fire re-sizes to the current MTU.
                    continue;
                }
                if let Err(e) = conn.send_datagram(Bytes::from(dummy))
                    && !matches!(e, SendDatagramError::TooLarge)
                {
                    return Err(TunnelError::QuicSendDatagram {
                        context: "idle cover".into(),
                        source: e,
                    });
                }
            }
        }
    }
}

/// The cover-traffic pump a session runs, resolved once from the coupled
/// DAITA / idle-cover decision ([`warrenguard_config::knobs::CoverDefenses`]).
///
/// This is the single selection seam that threads
/// [`warrenguard_config::knobs::cover_defenses`] into the datapath. Keeping
/// the choice in one place (rather than re-deriving `if idle_cover { .. } else
/// { .. }` at every call site) is what guarantees the DAITA / idle-cover
/// mutual exclusion is honoured identically for the mono-conn, multi-conn and
/// multi-hop pumps. The three arms are mutually exclusive by construction:
/// `resolve_cover_defenses` never sets both `daita` and `idle_cover`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverPump {
    /// No cover defense: the plain datapath (`pump_bidirectional` /
    /// `pump_multi_bidirectional`), byte-identical to a build with neither
    /// knob set.
    Plain,
    /// DAITA (maybenot) padding on a `*_with_daita` pump.
    Daita,
    /// Idle-cover jittered, size-varied dummies on a `*_with_idle_cover` pump.
    IdleCover,
}

impl CoverPump {
    /// Selects the cover pump from a resolved [`CoverDefenses`].
    ///
    /// DAITA wins when requested (it emits its own `0xFF` cover substrate that
    /// already masks the idle keep-alive), then idle cover, else the plain
    /// path. `resolve_cover_defenses` already enforces `!(daita &&
    /// idle_cover)`, so the `daita`-first order only reasserts that invariant
    /// defensively at the selection layer.
    #[must_use]
    pub fn from_defenses(defenses: CoverDefenses) -> Self {
        if defenses.daita {
            Self::Daita
        } else if defenses.idle_cover {
            Self::IdleCover
        } else {
            Self::Plain
        }
    }
}

/// Runs the mono-conn bidirectional pump selected by `defenses`, threading the
/// resolved cover-defense decision into the datapath: the idle-cover pump when
/// idle cover is resolved, otherwise the DAITA pump.
///
/// The DAITA pump itself short-circuits to [`pump_bidirectional`] at zero
/// overhead when `daita` is disabled, so the `Daita` and `Plain` arms share one
/// branch and idle cover can never coexist with DAITA. The caller resolves
/// `defenses` from the knobs via [`warrenguard_config::knobs::cover_defenses`]
/// and, when DAITA is requested, passes the negotiated [`DaitaState`] (a
/// disabled state when it is not).
///
/// # Errors
///
/// The first error from the selected pump (see [`pump_bidirectional_with_daita`]
/// and [`pump_bidirectional_with_idle_cover`]).
pub async fn pump_bidirectional_cover<T>(
    tun: T,
    conn: Connection,
    defenses: CoverDefenses,
    daita: DaitaState,
) -> Result<()>
where
    T: PacketDevice + Clone,
{
    match CoverPump::from_defenses(defenses) {
        CoverPump::IdleCover => pump_bidirectional_with_idle_cover(tun, conn).await,
        CoverPump::Daita | CoverPump::Plain => {
            pump_bidirectional_with_daita(tun, conn, daita).await
        }
    }
}

/// Multi-conn counterpart of [`pump_bidirectional_cover`]: selects the
/// multi-conn idle-cover or DAITA pump from `defenses`, over a
/// [`MultiConnSession`].
///
/// Like the mono-conn dispatcher, the DAITA pump falls through to
/// [`pump_multi_bidirectional`] at zero overhead when `daita` is disabled, so
/// the `Daita` and `Plain` arms share one branch. The cover pumps run on the
/// single-queue topology (privacy features, not the throughput path); a caller
/// that wants the multi-queue plain datapath keeps its own
/// [`pump_multi_bidirectional_queues`] branch for the no-cover case.
///
/// # Errors
///
/// The first error from the selected pump (see
/// [`pump_multi_bidirectional_with_daita`] and
/// [`pump_multi_bidirectional_with_idle_cover`]).
pub async fn pump_multi_bidirectional_cover<T, S>(
    tun: T,
    session: S,
    defenses: CoverDefenses,
    daita: DaitaState,
) -> Result<()>
where
    T: PacketDevice + Clone,
    S: MultiConnSession,
{
    match CoverPump::from_defenses(defenses) {
        CoverPump::IdleCover => pump_multi_bidirectional_with_idle_cover(tun, session).await,
        CoverPump::Daita | CoverPump::Plain => {
            pump_multi_bidirectional_with_daita(tun, session, daita).await
        }
    }
}

/// Variant of [`pump_quic_to_tun`] that rate-limits the *uplink*
/// direction (QUIC -> TUN, datagrams received from the client then
/// written to the exit TUN to reach the Internet).
///
/// Silent drop if the bucket is empty - TCP will retransmit on the
/// client side.
///
/// # Errors
///
/// See [`pump_quic_to_tun`].
pub async fn pump_quic_to_tun_rate_limited<T: PacketDevice>(
    conn: Connection,
    tun: T,
    limiter: Arc<IdentityLimiter<WarrenPubkey>>,
    client_id: WarrenPubkey,
    client_ipv4: std::net::Ipv4Addr,
    client_ipv6: Option<std::net::Ipv6Addr>,
    metrics: Option<std::sync::Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
) -> Result<()> {
    let tunnel_ips = Some((client_ipv4, client_ipv6));
    // Bytes batch avoids per-packet .to_vec() allocation.
    let mut batch: Vec<Bytes> = Vec::with_capacity(DOWNLINK_BATCH_MAX);
    let mut tun_io = TunIoTolerance::new("rate-limited tun send");
    let mut spoof_log = SpoofDropLog::new();
    loop {
        let dg = conn
            .read_datagram()
            .await
            .map_err(|source| TunnelError::QuicReadDatagram {
                context: "downlink".into(),
                source,
            })?;
        if let Some(pkt) = accept_downlink_rate_limited(
            &dg,
            tunnel_ips,
            &limiter,
            &client_id,
            &metrics,
            &mut spoof_log,
        ) {
            batch.push(pkt);
        }

        while batch.len() < DOWNLINK_BATCH_MAX {
            match try_read_datagram(&conn) {
                Some(Ok(dg)) => {
                    if let Some(pkt) = accept_downlink_rate_limited(
                        &dg,
                        tunnel_ips,
                        &limiter,
                        &client_id,
                        &metrics,
                        &mut spoof_log,
                    ) {
                        batch.push(pkt);
                    }
                }
                Some(Err(source)) => {
                    // Best-effort flush; see `pump_quic_to_tun`.
                    if !batch.is_empty() {
                        let _ = tun.send_batch_bytes(&mut batch).await;
                        batch.clear();
                    }
                    return Err(TunnelError::QuicReadDatagram {
                        context: "downlink batch drain".into(),
                        source,
                    });
                }
                None => break,
            }
        }

        if !batch.is_empty() {
            match tun.send_batch_bytes(&mut batch).await {
                Ok(_) => tun_io.ok(),
                // The batch is dropped (IP is lossy; TCP retransmits).
                Err(e) => tun_io.tolerate(&e).await?,
            }
            batch.clear();
        }
    }
}

/// Zero-copy variant of the rate-limited downlink filter.
///
/// Returns `Some(Bytes)` - an Arc-refcount clone, no memcpy - when the
/// datagram passes all checks. Returns `None` for dummies, spoofed IPs,
/// and rate-limited packets.
fn accept_downlink_rate_limited(
    dg: &Bytes,
    tunnel_ips: Option<(std::net::Ipv4Addr, Option<std::net::Ipv6Addr>)>,
    limiter: &IdentityLimiter<WarrenPubkey>,
    client_id: &WarrenPubkey,
    metrics: &Option<std::sync::Arc<warrenguard_transport_core::client_metrics::ClientMetrics>>,
    spoof_log: &mut SpoofDropLog,
) -> Option<Bytes> {
    if is_daita_dummy(dg) {
        tracing::trace!(
            bytes = dg.len(),
            "drop DAITA dummy (defense-in-depth, rate-limited path)"
        );
        return None;
    }
    if let Some((v4, v6)) = tunnel_ips
        && !warrenguard_transport_core::ip_parse::source_ip_matches(dg, v4, v6)
    {
        let (should_log, total) = spoof_log.record();
        if should_log {
            tracing::warn!(
                bytes = dg.len(),
                total_spoofed_drops = total,
                "dropped packet with spoofed source IP (rate-limited log)"
            );
        }
        return None;
    }
    if !limiter.try_consume(client_id, dg.len() as u64) {
        tracing::trace!(bytes = dg.len(), "rate limit drop (uplink)");
        return None;
    }
    if let Some(m) = metrics {
        m.record_rx(dg.len() as u64);
    }
    // Zero-copy: Arc reference-count increment only.
    Some(dg.clone())
}

/// Generalized variant of [`pump_bidirectional`] that can rate-limit
/// the downlink, the uplink, both, or neither. Each direction takes an
/// independent `Option<IdentityLimiter>`: a client may e.g. be limited
/// to 100 Mbps download and 50 Mbps upload.
///
/// # Errors
///
/// The first error from either pump is returned; the other is
/// implicitly cancelled by the `tokio::select!`.
/// **Multi-connection** bidirectional pump.
///
/// Architecture: 1 uplink task (reads the TUN and dispatches in
/// round-robin onto the session's N connections) + N downlink tasks
/// (1 per connection, reads datagrams and writes to the shared TUN).
/// The underlying TUN must be thread-safe for write - `tun-rs::AsyncDevice`
/// is, write() is atomic at the syscall level.
///
/// Terminates when any of the `1 + N` tasks terminates (Ok or Err);
/// the others are then cancelled by the `JoinSet` drop.
///
/// **Why this design?** The mono-conn tunnel bottleneck is not the pump
/// CPU but the per-Connection Quinn mutex serialization. With N
/// distinct Connections, each tokio task can run on a different core,
/// and the Quinn locks are independent -> effective parallelism.
///
/// # Errors
///
/// The first error from any task is returned. If a task panics, the
/// error encapsulates the `JoinError`.
pub async fn pump_multi_bidirectional<T, S>(tun: T, session: S) -> Result<()>
where
    T: PacketDevice + Clone,
    S: MultiConnSession,
{
    let conns = session.clone_connections();
    let n = conns.len();
    if n == 0 {
        return Err(TunnelError::MultiSessionEmpty(
            "MultiSession has zero connections",
        ));
    }

    let mut tasks: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();

    // Uplink: a single reader of the TUN dispatching by sticky 5-tuple
    // hash on the `MultiSession`. Keeps the same semantics as
    // `pump_tun_to_quic` (alloc 2 KiB per packet + sync send_datagram).
    //
    // **Tested-and-rejected: parallel uplink workers.** A flamegraph
    // showed `quinn::Connection::send_datagram -> Mutex::lock_contended`
    // as hot stack #1. We tried splitting into 1 dispatcher + N workers
    // (bounded mpsc, sticky by hash) so tokio could distribute the N
    // send_datagram calls across N cores. Bench result: capacity=64 =
    // 1674 Mbps avg + 1 outlier 533 Mbps; capacity=256 = 1714 Mbps avg
    // stable. Vs single-task = 1864 Mbps. **Clear -8 % regression.**
    // Causes:
    // 1. mpsc::try_send has non-negligible overhead (mutex + atomic
    //    counter + wake) that exceeds the apparent
    //    `Mutex::lock_contended` cost in the flamegraph.
    // 2. The `quinn::Connection` mutex visible in the flamegraph is
    //    not a real parallel contention point, it's just where the
    //    single-task uplink spends its time (sending datagrams), not
    //    a cross-task serialization.
    // 3. The tokio scheduler must context-switch between dispatcher +
    //    workers, cancelling the gain from parallel cores vs simple
    //    single-task.
    //
    // Conclusion: keep the single-task uplink. The real ~2 Gbps
    // bottleneck is elsewhere (likely quinn endpoint-wide or
    // quinn-udp UDP send syscalls).
    let tun_up = tun.clone();
    let session_up = std::sync::Arc::new(session);
    tasks.spawn(async move {
        // Pooled uplink read: `recv_batch_into` fills pooled buffers in
        // place instead of `recv_batch` allocating a fresh `vec![0u8; 2048]`
        // per packet in Plain TUN mode. Mirrors the mono-conn
        // `pump_tun_to_quic` pooling.
        let pool = warrenguard_transport_core::buffer_pool::BufferPool::new();
        let mut bufs: Vec<Vec<u8>> = (0..PUMP_UPLINK_BATCH_SIZE).map(|_| pool.take()).collect();
        let mut tun_io = TunIoTolerance::new("multi uplink tun recv");
        loop {
            // recv_batch_into amortizes the syscall in Linux offload mode.
            let n = match tun_up.recv_batch_into(&mut bufs).await {
                Ok(n) => {
                    tun_io.ok();
                    n
                }
                Err(e) if is_err_too_many_segments(&e) => {
                    tracing::warn!("dropped oversized GSO packet (ErrTooManySegments)");
                    continue;
                }
                Err(e) => {
                    tun_io.tolerate(&e).await?;
                    continue;
                }
            };
            for buf in &mut bufs[..n] {
                let filled = std::mem::replace(buf, pool.take());
                multi_send_drop_too_large_pooled(&session_up, filled, &pool)?;
            }

            // Fallback drain (env override, default no-op).
            for _ in 0..uplink_batch_max().saturating_sub(1) {
                match tun_up.try_recv() {
                    Ok(Some(pkt)) => multi_send_drop_too_large_pooled(&session_up, pkt, &pool)?,
                    Ok(None) => break,
                    Err(e) => {
                        tun_io.tolerate(&e).await?;
                        break;
                    }
                }
            }
        }
    });

    // N downlinks: 1 task per connection. Each reads its datagrams and
    // writes onto the shared TUN concurrently (tun-rs::send is
    // thread-safe). Defense-in-depth: drop DAITA dummies before the
    // TUN (mirrors `pump_quic_to_tun`).
    // Bytes batch avoids per-packet .to_vec() on the downlink.
    for (idx, conn) in conns.into_iter().enumerate() {
        let tun_dn = tun.clone();
        let conn_label: std::sync::Arc<str> = std::sync::Arc::from(format!("conn[{idx}]"));
        tasks.spawn(async move {
            let mut batch: Vec<Bytes> = Vec::with_capacity(DOWNLINK_BATCH_MAX);
            let mut tun_io = TunIoTolerance::new("multi downlink tun send");
            loop {
                let dg =
                    conn.read_datagram()
                        .await
                        .map_err(|source| TunnelError::QuicReadDatagram {
                            context: conn_label.to_string().into(),
                            source,
                        })?;
                if !is_daita_dummy(&dg) {
                    // Zero-copy: Arc ref-count increment, no memcpy.
                    batch.push(dg);
                }

                while batch.len() < DOWNLINK_BATCH_MAX {
                    match try_read_datagram(&conn) {
                        Some(Ok(dg)) => {
                            if !is_daita_dummy(&dg) {
                                batch.push(dg);
                            }
                        }
                        Some(Err(source)) => {
                            // Best-effort flush; see `pump_quic_to_tun`.
                            if !batch.is_empty() {
                                let _ = tun_dn.send_batch_bytes(&mut batch).await;
                                batch.clear();
                            }
                            return Err(TunnelError::QuicReadDatagram {
                                context: format!("conn[{idx}] batch drain").into(),
                                source,
                            });
                        }
                        None => break,
                    }
                }

                if !batch.is_empty() {
                    match tun_dn.send_batch_bytes(&mut batch).await {
                        Ok(_) => tun_io.ok(),
                        // The batch is dropped (IP is lossy; TCP retransmits).
                        Err(e) => tun_io.tolerate(&e).await?,
                    }
                    batch.clear();
                }
            }
        });
    }

    // Wait for the first task to terminate. Dropping the `JoinSet`
    // afterwards = automatic abort of all remaining tasks.
    let first = tasks.join_next().await.ok_or_else(|| {
        TunnelError::Internal("join_next returned None on non-empty JoinSet".into())
    })?;
    drop(tasks);

    match first {
        Ok(inner) => inner,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(TunnelError::Internal(format!(
            "pump_multi task panicked: {e}"
        ))),
    }
}

/// **Multi-queue** variant of [`pump_multi_bidirectional`]: the client TUN is
/// opened with `Q` `IFF_MULTI_QUEUE` kernel queues (see
/// `RealTun::create_multi_queue_named`) and this pump runs **Q uplink reader
/// tasks (one per queue)** plus **N downlink writer tasks (one per connection,
/// each writing to a distinct queue fd)**.
///
/// Why: [`pump_multi_bidirectional`] has a **single** uplink task reading the
/// one TUN queue and dispatching to N connections. Real-exit benching showed
/// that single client-TUN task is the single-client throughput wall (exit-side
/// `SO_REUSEPORT` sharding and exit multi-queue TUN both left the plateau
/// unmoved). Q independent kernel queues let the kernel flow-hash uplink
/// packets across Q reader tasks that each run on their own core, with **no
/// userspace mpsc** (the mpsc dispatcher/worker split was tested-and-rejected at
/// -8 %: its channel overhead exceeded the contention it removed). Downlink
/// writers already numbered N; giving each a distinct queue fd removes their
/// shared-fd write serialization too.
///
/// `queues` must be non-empty. With a single queue this degrades to exactly
/// [`pump_multi_bidirectional`]'s topology (1 reader + N writers on one fd).
/// Terminates when any of the `Q + N` tasks terminates; the rest are cancelled.
///
/// # Errors
///
/// [`TunnelError::MultiSessionEmpty`] if the session has zero connections or
/// `queues` is empty. Otherwise the first error from any task (a `JoinError`
/// from a panicking task is wrapped as [`TunnelError::Internal`]).
pub async fn pump_multi_bidirectional_queues<T, S>(queues: Vec<T>, session: S) -> Result<()>
where
    T: PacketDevice + Clone,
    S: MultiConnSession,
{
    if queues.is_empty() {
        return Err(TunnelError::MultiSessionEmpty(
            "pump_multi_bidirectional_queues needs at least one TUN queue",
        ));
    }
    let conns = session.clone_connections();
    let n = conns.len();
    if n == 0 {
        return Err(TunnelError::MultiSessionEmpty(
            "MultiSession has zero connections",
        ));
    }

    let mut tasks: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();
    let session_up = std::sync::Arc::new(session);

    // Uplink: one reader per queue. The kernel flow-hashes outbound packets
    // across the Q queues (`tun_select_queue`), so the Q readers each drain a
    // disjoint flow subset and dispatch to the session by the same sticky
    // 5-tuple hash as the single-reader pump. No cross-task channel.
    for queue in &queues {
        let tun_up = queue.clone();
        let session_up = session_up.clone();
        tasks.spawn(async move {
            // Pooled uplink read, one pool per queue task: see
            // `pump_multi_bidirectional`'s uplink for the rationale.
            let pool = warrenguard_transport_core::buffer_pool::BufferPool::new();
            let mut bufs: Vec<Vec<u8>> = (0..PUMP_UPLINK_BATCH_SIZE).map(|_| pool.take()).collect();
            let mut tun_io = TunIoTolerance::new("multi-queue uplink tun recv");
            loop {
                let n = match tun_up.recv_batch_into(&mut bufs).await {
                    Ok(n) => {
                        tun_io.ok();
                        n
                    }
                    Err(e) if is_err_too_many_segments(&e) => {
                        tracing::warn!("dropped oversized GSO packet (ErrTooManySegments)");
                        continue;
                    }
                    Err(e) => {
                        tun_io.tolerate(&e).await?;
                        continue;
                    }
                };
                for buf in &mut bufs[..n] {
                    let filled = std::mem::replace(buf, pool.take());
                    multi_send_drop_too_large_pooled(&session_up, filled, &pool)?;
                }
                for _ in 0..uplink_batch_max().saturating_sub(1) {
                    match tun_up.try_recv() {
                        Ok(Some(pkt)) => multi_send_drop_too_large_pooled(&session_up, pkt, &pool)?,
                        Ok(None) => break,
                        Err(e) => {
                            tun_io.tolerate(&e).await?;
                            break;
                        }
                    }
                }
            }
        });
    }

    // N downlinks: one task per connection, each writing to a distinct queue
    // fd (round-robin) so the per-connection writes no longer serialize on one
    // kernel queue. tun-rs write() is atomic at the syscall level.
    let q = queues.len();
    for (idx, conn) in conns.into_iter().enumerate() {
        let tun_dn = queues[idx % q].clone();
        let conn_label: std::sync::Arc<str> = std::sync::Arc::from(format!("conn[{idx}]"));
        tasks.spawn(async move {
            let mut batch: Vec<Bytes> = Vec::with_capacity(DOWNLINK_BATCH_MAX);
            let mut tun_io = TunIoTolerance::new("multi-queue downlink tun send");
            loop {
                let dg =
                    conn.read_datagram()
                        .await
                        .map_err(|source| TunnelError::QuicReadDatagram {
                            context: conn_label.to_string().into(),
                            source,
                        })?;
                if !is_daita_dummy(&dg) {
                    batch.push(dg);
                }
                while batch.len() < DOWNLINK_BATCH_MAX {
                    match try_read_datagram(&conn) {
                        Some(Ok(dg)) => {
                            if !is_daita_dummy(&dg) {
                                batch.push(dg);
                            }
                        }
                        Some(Err(source)) => {
                            if !batch.is_empty() {
                                let _ = tun_dn.send_batch_bytes(&mut batch).await;
                                batch.clear();
                            }
                            return Err(TunnelError::QuicReadDatagram {
                                context: format!("conn[{idx}] batch drain").into(),
                                source,
                            });
                        }
                        None => break,
                    }
                }
                if !batch.is_empty() {
                    match tun_dn.send_batch_bytes(&mut batch).await {
                        Ok(_) => tun_io.ok(),
                        Err(e) => tun_io.tolerate(&e).await?,
                    }
                    batch.clear();
                }
            }
        });
    }

    let first = tasks.join_next().await.ok_or_else(|| {
        TunnelError::Internal("join_next returned None on non-empty JoinSet".into())
    })?;
    drop(tasks);

    match first {
        Ok(inner) => inner,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(TunnelError::Internal(format!(
            "pump_multi_queue task panicked: {e}"
        ))),
    }
}

/// Multi-connection variant of [`pump_bidirectional_with_idle_cover`].
///
/// Same uplink as [`pump_multi_bidirectional`] (one sticky-hash
/// dispatcher), but each of the N downlink tasks owns its OWN
/// [`IdleCover`] and emits cover on ITS connection. Each QUIC connection
/// is a distinct 5-tuple with its own NAT mapping and idle timeout, so
/// per-connection cover is required: a session-wide scheduler would let
/// an idle secondary connection's mapping expire while the primary
/// carries a sticky flow. Cover is driven off the per-conn DOWNLINK: a
/// connection that receives real traffic resets its own cover; a fully
/// idle connection fills with jittered, varied-size dummies; a
/// connection that only uploads (sticky dispatch, no downlink) may emit a
/// few unneeded dummies, which is harmless overhead, never a missed
/// keep-alive. The client transport config MUST disable the keep-alive
/// (`warren_transport_config_client_with_idle_cover(.., true)`), exactly
/// like the mono variant, so cover replaces the beacon on every
/// connection.
///
/// # Errors
///
/// First error from any task (uplink read, a downlink read, or a
/// non-size cover send). A panicked task is wrapped in
/// [`TunnelError::Internal`].
pub async fn pump_multi_bidirectional_with_idle_cover<T, S>(tun: T, session: S) -> Result<()>
where
    T: PacketDevice + Clone,
    S: MultiConnSession,
{
    let conns = session.clone_connections();
    let n = conns.len();
    if n == 0 {
        return Err(TunnelError::MultiSessionEmpty(
            "MultiSession has zero connections",
        ));
    }

    let mut tasks: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();

    // Uplink: identical single sticky-hash dispatcher as
    // `pump_multi_bidirectional` (see that function for the
    // tested-and-rejected parallel-worker rationale).
    let tun_up = tun.clone();
    let session_up = std::sync::Arc::new(session);
    tasks.spawn(async move {
        // Pooled uplink read: see `pump_multi_bidirectional`'s uplink for
        // the rationale.
        let pool = warrenguard_transport_core::buffer_pool::BufferPool::new();
        let mut bufs: Vec<Vec<u8>> = (0..PUMP_UPLINK_BATCH_SIZE).map(|_| pool.take()).collect();
        let mut tun_io = TunIoTolerance::new("multi idle-cover uplink tun recv");
        loop {
            let n = match tun_up.recv_batch_into(&mut bufs).await {
                Ok(n) => {
                    tun_io.ok();
                    n
                }
                Err(e) if is_err_too_many_segments(&e) => {
                    tracing::warn!("dropped oversized GSO packet (ErrTooManySegments)");
                    continue;
                }
                Err(e) => {
                    tun_io.tolerate(&e).await?;
                    continue;
                }
            };
            for buf in &mut bufs[..n] {
                let filled = std::mem::replace(buf, pool.take());
                multi_send_drop_too_large_pooled(&session_up, filled, &pool)?;
            }
            for _ in 0..uplink_batch_max().saturating_sub(1) {
                match tun_up.try_recv() {
                    Ok(Some(pkt)) => multi_send_drop_too_large_pooled(&session_up, pkt, &pool)?,
                    Ok(None) => break,
                    Err(e) => {
                        tun_io.tolerate(&e).await?;
                        break;
                    }
                }
            }
        }
    });

    // N downlinks: each task reads its conn, drops dummies, writes to the
    // shared TUN, AND drives a per-conn IdleCover via a select arm.
    for (idx, conn) in conns.into_iter().enumerate() {
        let tun_dn = tun.clone();
        let conn_label: std::sync::Arc<str> = std::sync::Arc::from(format!("conn[{idx}]"));
        tasks.spawn(async move {
            let mut cover = IdleCover::new(
                conn.stable_id() as u64,
                Instant::now(),
                conn.max_datagram_size(),
            );
            let mut batch: Vec<Bytes> = Vec::with_capacity(DOWNLINK_BATCH_MAX);
            let mut tun_io = TunIoTolerance::new("multi idle-cover downlink tun send");
            loop {
                let sleep =
                    tokio::time::sleep_until(tokio::time::Instant::from_std(cover.deadline()));
                tokio::pin!(sleep);
                let dg = tokio::select! {
                    res = conn.read_datagram() => {
                        res.map_err(|source| TunnelError::QuicReadDatagram {
                            context: conn_label.to_string().into(),
                            source,
                        })?
                    }
                    _ = &mut sleep => {
                        let dummy = cover.fire(Instant::now());
                        if let Some(max) = conn.max_datagram_size()
                            && dummy.len() > max
                        {
                            continue;
                        }
                        if let Err(e) = conn.send_datagram(Bytes::from(dummy))
                            && !matches!(e, SendDatagramError::TooLarge)
                        {
                            return Err(TunnelError::QuicSendDatagram {
                                context: "multi idle cover".into(),
                                source: e,
                            });
                        }
                        continue;
                    }
                };
                cover.note_activity(Instant::now());
                if !is_daita_dummy(&dg) {
                    batch.push(dg);
                }

                while batch.len() < DOWNLINK_BATCH_MAX {
                    match try_read_datagram(&conn) {
                        Some(Ok(dg)) => {
                            cover.note_activity(Instant::now());
                            if !is_daita_dummy(&dg) {
                                batch.push(dg);
                            }
                        }
                        Some(Err(source)) => {
                            if !batch.is_empty() {
                                let _ = tun_dn.send_batch_bytes(&mut batch).await;
                                batch.clear();
                            }
                            return Err(TunnelError::QuicReadDatagram {
                                context: format!("conn[{idx}] batch drain").into(),
                                source,
                            });
                        }
                        None => break,
                    }
                }

                if !batch.is_empty() {
                    match tun_dn.send_batch_bytes(&mut batch).await {
                        Ok(_) => tun_io.ok(),
                        Err(e) => tun_io.tolerate(&e).await?,
                    }
                    batch.clear();
                }
            }
        });
    }

    let first = tasks.join_next().await.ok_or_else(|| {
        TunnelError::Internal("join_next returned None on non-empty JoinSet".into())
    })?;
    drop(tasks);

    match first {
        Ok(inner) => inner,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(TunnelError::Internal(format!(
            "pump_multi idle-cover task panicked: {e}"
        ))),
    }
}

/// Multi-conn bidirectional pump variant driving a shared
/// [`DaitaState`] in addition to dispatching real traffic across N
/// connections. Companion of [`pump_bidirectional_with_daita`] (mono)
/// for sessions established via [`MultiSession`].
///
/// **Architecture (4 tokio tasks total, regardless of N)**:
///
/// 1. **Uplink** (single task): reads from the TUN, fires
///    `NormalSent` + `TunnelSent` on the shared state, then dispatches
///    the packet across the N conns via [`MultiSession::send_datagram`]
///    (sticky 5-tuple hash).
/// 2. **Downlink** (N tasks, one per conn): reads datagrams from a
///    single conn, fires `TunnelRecv` + (`NormalRecv` or
///    `PaddingRecv`) depending on [`is_daita_dummy`], writes real
///    packets to the TUN, drops dummies before the TUN.
/// 3. **Timer** (single task): sleeps until the next expired
///    machine-action timer, drains them and emits one DAITA dummy
///    datagram per expired machine via the multi-conn session. The
///    dummies' first byte (`0xFF`) makes [`MultiSession::dispatch_idx`]
///    fall back to round-robin so the padding load distributes
///    evenly across the N conns.
///
/// **Lock model**: the shared `DaitaState` is wrapped in a
/// `parking_lot::Mutex` (sync, not tokio's). Critical sections are a
/// handful of `HashMap` lookups + atomic adds; with N = 4..32 conns at
/// typical traffic rates the contention is negligible. Switching to a
/// tokio mutex would force every fire_events into an `.await`,
/// serialising the pumps unnecessarily.
///
/// When the supplied state is disabled (`!state.is_enabled()`), the
/// function defers to the regular [`pump_multi_bidirectional`] for
/// zero overhead, identical to the mono-conn fall-through.
///
/// # Errors
///
/// First error from any of the tasks is returned. The remaining tasks
/// are cancelled by dropping the [`tokio::task::JoinSet`]. A task
/// panic is wrapped into [`TunnelError::Internal`].
pub async fn pump_multi_bidirectional_with_daita<T, S>(
    tun: T,
    session: S,
    state: DaitaState,
) -> Result<()>
where
    T: PacketDevice + Clone,
    S: MultiConnSession,
{
    if !state.is_enabled() {
        return pump_multi_bidirectional(tun, session).await;
    }
    pump_multi_bidirectional_daita_inner(tun, session, state).await
}

async fn pump_multi_bidirectional_daita_inner<T, S>(
    tun: T,
    session: S,
    state: DaitaState,
) -> Result<()>
where
    T: PacketDevice + Clone,
    S: MultiConnSession,
{
    let conns = session.clone_connections();
    let n = conns.len();
    if n == 0 {
        return Err(TunnelError::MultiSessionEmpty(
            "MultiSession has zero connections",
        ));
    }

    let session_arc = std::sync::Arc::new(session);
    let daita = std::sync::Arc::new(parking_lot::Mutex::new(state));
    // Wake the timer task as soon as RX or uplink fires events that
    // may have scheduled a new action timer. Without this, the timer
    // task would park on the placeholder 3600s `next_timer` it reads
    // before any event has fired, and the maybenot machine would emit
    // zero dummies in practice (early tests only checked the pump's
    // survival, not actual dummy emission, so the bug was latent in
    // production wiring). `tokio::sync::Notify` collapses concurrent
    // notifications into a single wake.
    let state_changed = std::sync::Arc::new(tokio::sync::Notify::new());

    let mut tasks: tokio::task::JoinSet<Result<()>> = tokio::task::JoinSet::new();

    // Branch 1: uplink. Single reader, mirrors the layout of the
    // non-DAITA multi-pump but slips a `NormalSent + TunnelSent` event
    // pair before each dispatch.
    // Single lock acquisition + merged fire_events per packet.
    {
        let tun_up = tun.clone();
        let session_up = session_arc.clone();
        let daita_up = daita.clone();
        let notify_up = state_changed.clone();
        tasks.spawn(async move {
            let mut tun_io = TunIoTolerance::new("multi daita uplink tun recv");
            // Pooled uplink read: no per-packet 2 KiB alloc; the pooled `Bytes`
            // handed to `send_datagram_bytes` recycles on drop.
            let pool = warrenguard_transport_core::buffer_pool::BufferPool::new();
            let mut up_buf = pool.take();
            loop {
                let n = match tun_up
                    .recv_batch_into(std::slice::from_mut(&mut up_buf))
                    .await
                {
                    Ok(n) => {
                        tun_io.ok();
                        n
                    }
                    Err(e) => {
                        tun_io.tolerate(&e).await?;
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }
                let filled = std::mem::replace(&mut up_buf, pool.take());
                match session_up.send_datagram_bytes(pool.wrap(filled)) {
                    Ok(()) => {
                        daita_up.lock().on_real_uplink_sent(Instant::now());
                        notify_up.notify_one();
                    }
                    Err(e)
                        if matches!(
                            &e,
                            TunnelError::QuicSendDatagram {
                                source: SendDatagramError::TooLarge,
                                ..
                            }
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
        });
    }

    // Branch 2: N downlinks. Each task owns its conn and the shared
    // TUN sender (tun-rs::send is thread-safe). The dummy filter mirrors
    // the mono-conn variant.
    // Single Instant::now() + merged fire_events per datagram.
    // Single lock acquisition per datagram (was 2-3 separate locks).
    for (idx, conn) in conns.iter().cloned().enumerate() {
        let tun_dn = tun.clone();
        let daita_dn = daita.clone();
        let notify_dn = state_changed.clone();
        // cf. comment in `pump_multi_downlink` above for the
        // rationale on pre-allocating the per-conn label.
        let conn_label: std::sync::Arc<str> = std::sync::Arc::from(format!("conn[{idx}]"));
        let conn_label_for_tun = conn_label.clone();
        tasks.spawn(async move {
            let mut tun_io = TunIoTolerance::new("multi daita downlink tun send");
            loop {
                let dg =
                    conn.read_datagram()
                        .await
                        .map_err(|source| TunnelError::QuicReadDatagram {
                            context: conn_label.to_string().into(),
                            source,
                        })?;
                // TunnelRecv MUST fire before the kind-specific event,
                // per the maybenot specification.
                // Classify first (no lock needed for is_daita_dummy),
                // then acquire the Mutex exactly once and fire both events
                // (TunnelRecv + kind-specific) in a single critical section.
                let now = Instant::now();
                let dummy = is_daita_dummy(&dg);
                if !dummy {
                    match tun_dn.send(&dg).await {
                        Ok(_) => tun_io.ok(),
                        // Packet dropped (IP is lossy; TCP retransmits).
                        Err(e) => {
                            tracing::trace!(conn = %conn_label_for_tun, "tun send error");
                            tun_io.tolerate(&e).await?;
                        }
                    }
                }
                // Dummy: dropped (not written to the TUN). Same shared
                // downlink event sequence (TunnelRecv before kind-specific)
                // for real and dummy; single lock acquisition.
                daita_dn.lock().on_downlink_received(dummy, now);
                notify_dn.notify_one();
            }
        });
    }

    // Branch 3: padding timer. Wakes at `next_timer()` OR on
    // `state_changed.notified()` (so a freshly-scheduled action
    // timer is observed immediately instead of after the placeholder
    // 3600 s sleep). The dummies hash to round-robin via
    // `MultiSession::dispatch_idx` (their first byte `0xFF` makes
    // `flow_hash_5tuple` return None).
    // DaitaDummyTemplate pre-allocated once; each timer fire clones
    // the Bytes handle (Arc increment) instead of allocating a fresh Vec.
    {
        let session_t = session_arc.clone();
        let daita_t = daita.clone();
        // Build the template from the first connection's negotiated MTU.
        let dummy_template = DaitaDummyTemplate::new(&conns[0]);
        let state_changed_t = state_changed;
        tasks.spawn(async move {
            loop {
                let next_timer = daita_t.lock().sleep_deadline(Instant::now());
                let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(next_timer));
                tokio::pin!(sleep);
                tokio::select! {
                    _ = &mut sleep => {}
                    _ = state_changed_t.notified() => continue,
                }
                let now = Instant::now();
                let fired_machines = daita_t.lock().drain_expired(now);
                for machine in fired_machines {
                    // Zero-copy clone (Arc ref-count bump).
                    let dummy_bytes = dummy_template.get();
                    // `multi_send_drop_too_large` expects Vec<u8>; convert
                    // via copy only when actually needed (i.e. in the
                    // offload path). On Plain mode this is a single
                    // send_datagram call - the Bytes deref avoids an
                    // intermediate Vec on the session dispatch path.
                    // NOTE: MultiSession::send_datagram currently takes
                    // Vec<u8>. We convert once here; a future session can
                    // accept Bytes directly for full zero-copy.
                    multi_send_drop_too_large(&session_t, dummy_bytes.to_vec())?;
                    daita_t.lock().on_dummy_sent(machine, Instant::now());
                }
            }
        });
    }

    // Wait for the first task to terminate. Dropping the `JoinSet`
    // afterwards = automatic abort of all remaining tasks.
    let first = tasks.join_next().await.ok_or_else(|| {
        TunnelError::Internal("join_next returned None on non-empty JoinSet".into())
    })?;
    drop(tasks);

    match first {
        Ok(inner) => inner,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(TunnelError::Internal(format!(
            "pump_multi_daita task panicked: {e}"
        ))),
    }
}

/// Single-channel tunnel handle the multi-hop pump drives: `send`/`recv` of one
/// application payload plus a DAITA padding emit and a clean close. The
/// implementor (typically a relay-encapsulated HPKE client) owns rekey,
/// metrics and replay accounting; the pump only needs these four.
#[allow(async_fn_in_trait)]
pub trait WarrenPumpHandle: Send + Sync {
    /// Tunnel error surfaced by the implementor.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Forward one application payload through the tunnel.
    async fn pump_send(&self, payload: &[u8]) -> std::result::Result<(), Self::Error>;

    /// Read one application payload from the tunnel.
    async fn pump_recv(&self) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Emit one DAITA padding frame (first byte [`DAITA_DUMMY_FIRST_BYTE`]);
    /// returns its on-wire size for overhead accounting.
    async fn pump_send_daita_dummy(&self) -> std::result::Result<usize, Self::Error>;

    /// Close the underlying connection.
    fn pump_close(&self, code: u32, reason: &[u8]);
}

/// Failure of the multi-hop pump: either TUN I/O or the tunnel handle.
#[derive(Debug, thiserror::Error)]
pub enum MultiHopPumpError<E: std::error::Error + Send + Sync + 'static> {
    /// TUN device read/write failed.
    #[error("multi-hop pump: TUN I/O")]
    Tun(#[source] std::io::Error),
    /// The tunnel handle (send/recv/padding) failed.
    #[error("multi-hop pump: tunnel")]
    Handle(#[source] E),
}

/// Pumps a [`PacketDevice`] (TUN) against any [`WarrenPumpHandle`] (single
/// uplink + single downlink task joined by `select!`). Mirrors
/// [`pump_bidirectional`] for the relay-encapsulated single-pipe case.
///
/// # Errors
///
/// [`MultiHopPumpError`] on the first direction failure.
pub async fn pump_multi_hop_bidirectional<P, T>(
    pump: Arc<P>,
    tun: T,
) -> std::result::Result<(), MultiHopPumpError<P::Error>>
where
    P: WarrenPumpHandle + Send + Sync + 'static,
    T: PacketDevice + Clone + Send + Sync + 'static,
{
    let pump_up = pump.clone();
    let tun_up = tun.clone();
    let pump_dn = pump;
    let tun_dn = tun;

    let up = async move {
        loop {
            let pkt = tun_up.recv().await.map_err(MultiHopPumpError::Tun)?;
            pump_up
                .pump_send(&pkt)
                .await
                .map_err(MultiHopPumpError::Handle)?;
        }
    };
    let down = async move {
        loop {
            let dg = pump_dn
                .pump_recv()
                .await
                .map_err(MultiHopPumpError::Handle)?;
            // Drop wire-marker dummies before the TUN even when local DAITA is
            // off: a peer with DAITA on emits padding this side must not forward.
            if is_daita_dummy(&dg) {
                continue;
            }
            tun_dn.send(&dg).await.map_err(MultiHopPumpError::Tun)?;
        }
    };

    tokio::select! {
        res = up => res,
        res = down => res,
    }
}

/// DAITA-aware variant: when `state` is disabled, falls through to
/// [`pump_multi_hop_bidirectional`]; otherwise drives the [`DaitaState`] timer
/// and emits padding via [`WarrenPumpHandle::pump_send_daita_dummy`]. All three
/// branches share one task (a single QUIC pipe to the relay, no per-conn
/// parallelism).
///
/// # Errors
///
/// [`MultiHopPumpError`] on the first branch failure.
pub async fn pump_multi_hop_bidirectional_with_daita<P, T>(
    pump: Arc<P>,
    tun: T,
    state: DaitaState,
) -> std::result::Result<(), MultiHopPumpError<P::Error>>
where
    P: WarrenPumpHandle + Send + Sync + 'static,
    T: PacketDevice + Clone + Send + Sync + 'static,
{
    if !state.is_enabled() {
        return pump_multi_hop_bidirectional(pump, tun).await;
    }
    pump_multi_hop_daita_inner(pump, tun, state).await
}

async fn pump_multi_hop_daita_inner<P, T>(
    pump: Arc<P>,
    tun: T,
    mut state: DaitaState,
) -> std::result::Result<(), MultiHopPumpError<P::Error>>
where
    P: WarrenPumpHandle + Send + Sync + 'static,
    T: PacketDevice + Clone + Send + Sync + 'static,
{
    loop {
        let next_timer = state.sleep_deadline(Instant::now());
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(next_timer));
        tokio::pin!(sleep);

        tokio::select! {
            res = tun.recv() => {
                let pkt = res.map_err(MultiHopPumpError::Tun)?;
                state.on_real_uplink_sent(Instant::now());
                pump.pump_send(&pkt).await.map_err(MultiHopPumpError::Handle)?;
            }
            res = pump.pump_recv() => {
                let dg = res.map_err(MultiHopPumpError::Handle)?;
                let now = Instant::now();
                let dummy = is_daita_dummy(&dg);
                if !dummy {
                    tun.send(&dg).await.map_err(MultiHopPumpError::Tun)?;
                }
                state.on_downlink_received(dummy, now);
            }
            _ = &mut sleep => {
                let now = Instant::now();
                for machine in state.drain_expired(now) {
                    pump.pump_send_daita_dummy().await.map_err(MultiHopPumpError::Handle)?;
                    state.on_dummy_sent(machine, Instant::now());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tun_io_tolerance_increments_the_global_error_counter() {
        // Observability: every tolerated TUN error must be
        // countable by ops, otherwise a partially-degraded TUN hides
        // behind the rate-limited WARNs forever.
        let before = TunIoTolerance::global_error_total();
        let mut tol = TunIoTolerance::new("test pump");
        let e = std::io::Error::other("transient ENOBUFS stand-in");
        tol.tolerate(&e).await.expect("below the fatal bound");
        tol.tolerate(&e).await.expect("below the fatal bound");
        assert!(
            TunIoTolerance::global_error_total() >= before + 2,
            "two tolerated errors must add at least 2 to the global counter"
        );
    }
    use warrenguard_config::knobs::resolve_cover_defenses;
    use warrenguard_transport_core::packet_device::FakeTun;

    // The pump-selection decision is the single seam that threads the
    // resolved cover-defense choice into the datapath. These pin the four
    // corners: DAITA requested selects the DAITA pump, idle-cover-only
    // selects the idle-cover pump, neither is the plain path, and the
    // DAITA/idle-cover mutual exclusion holds at the selection layer even
    // when both knobs are set on.

    #[test]
    fn cover_pump_selects_daita_when_daita_is_requested() {
        let defenses = resolve_cover_defenses(true, false);
        assert_eq!(
            CoverPump::from_defenses(defenses),
            CoverPump::Daita,
            "a session that requested DAITA must select the DAITA pump"
        );
    }

    #[test]
    fn cover_pump_selects_idle_cover_when_only_idle_cover_is_on() {
        let defenses = resolve_cover_defenses(false, true);
        assert_eq!(
            CoverPump::from_defenses(defenses),
            CoverPump::IdleCover,
            "idle cover on with DAITA off must select the idle-cover pump"
        );
    }

    #[test]
    fn cover_pump_is_plain_when_no_defense_is_requested() {
        let defenses = resolve_cover_defenses(false, false);
        assert_eq!(
            CoverPump::from_defenses(defenses),
            CoverPump::Plain,
            "the default (no knob) must select the plain datapath, byte-identical to before"
        );
    }

    #[test]
    fn daita_supersedes_idle_cover_in_pump_selection() {
        // `resolve_cover_defenses` already suppresses idle cover when DAITA
        // is on, and the selection reasserts it: the pair can never resolve
        // to the idle-cover pump while DAITA is requested.
        let both = resolve_cover_defenses(true, true);
        assert_eq!(
            CoverPump::from_defenses(both),
            CoverPump::Daita,
            "DAITA and idle cover are mutually exclusive: DAITA wins the selection"
        );
        assert_ne!(
            CoverPump::from_defenses(both),
            CoverPump::IdleCover,
            "idle cover MUST NOT be selected while DAITA is requested"
        );
    }

    // ----------------------------------------------------------------
    // Transient TUN I/O tolerance (macOS ENOBUFS under downlink load)
    // ----------------------------------------------------------------

    /// A burst of TUN I/O errors must NOT kill a pump (macOS utun
    /// ENOBUFS under downlink load); only an uninterrupted streak of
    /// `MAX_CONSECUTIVE_TUN_ERRORS` may. A single success resets the
    /// streak.
    #[tokio::test(start_paused = true)]
    async fn tun_io_tolerance_resets_on_success_and_bounds_persistent_failures() {
        let enobufs = || std::io::Error::other("No buffer space available (os error 55)");
        let mut tol = TunIoTolerance::new("test");
        for _ in 0..5_000 {
            tol.tolerate(&enobufs())
                .await
                .expect("interrupted streak must stay transient");
        }
        tol.ok();
        for _ in 0..5_000 {
            tol.tolerate(&enobufs())
                .await
                .expect("streak must restart from zero after a success");
        }
        tol.ok();
        let mut last = Ok(());
        for _ in 0..MAX_CONSECUTIVE_TUN_ERRORS {
            last = tol.tolerate(&enobufs()).await;
        }
        assert!(
            last.is_err(),
            "an uninterrupted persistent failure streak must eventually error out"
        );
    }

    // ----------------------------------------------------------------
    // Downlink batch accepts Bytes without copying
    // ----------------------------------------------------------------

    /// Verifies that `accept_downlink` returns a `Bytes` clone whose
    /// underlying allocation is the **same object** as the input (no
    /// memcpy). We confirm this via pointer equality of the underlying
    /// slice data, which holds for `Bytes::clone()` (Arc ref-count bump).
    #[test]
    fn accept_downlink_returns_zero_copy_bytes() {
        // IPv4 packet: first nibble = 4 → not a dummy.
        let raw = vec![0x45u8, 0x00, 0x00, 0x28];
        let dg = Bytes::from(raw);
        let ptr_before = dg.as_ptr();

        let mut spoof_log = SpoofDropLog::new();
        let result = accept_downlink(&dg, None, &None, &mut spoof_log);
        let pkt = result.expect("IPv4 packet must pass the filter");

        // Both `dg` and `pkt` must point into the same Arc-owned buffer.
        assert_eq!(
            pkt.as_ptr(),
            ptr_before,
            "accept_downlink must return a zero-copy Bytes clone, not a new allocation"
        );
        assert_eq!(&pkt[..], &dg[..], "content must be identical");
    }

    /// Verifies that a DAITA dummy is dropped by `accept_downlink`.
    #[test]
    fn accept_downlink_drops_daita_dummy() {
        let dg = Bytes::from(vec![DAITA_DUMMY_FIRST_BYTE; 64]);
        let mut spoof_log = SpoofDropLog::new();
        let result = accept_downlink(&dg, None, &None, &mut spoof_log);
        assert!(
            result.is_none(),
            "DAITA dummy must be filtered by accept_downlink"
        );
    }

    // ----------------------------------------------------------------
    // M5: anti-spoof drop rate-limited logging (log-flood DoS fix)
    // ----------------------------------------------------------------

    fn ipv4_packet_bytes(src: [u8; 4], dst: [u8; 4]) -> Bytes {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        Bytes::from(pkt)
    }

    /// The anti-spoof drop branch (lines 498-503 pre-fix) was never
    /// exercised by the two tests above (both pass `tunnel_ips = None`).
    /// This pins the pass case: a packet whose source matches the client's
    /// allocated tunnel IP is forwarded.
    #[test]
    fn accept_downlink_with_matching_source_passes() {
        let client_ip = std::net::Ipv4Addr::new(10, 66, 0, 5);
        let dg = ipv4_packet_bytes([10, 66, 0, 5], [8, 8, 8, 8]);
        let mut spoof_log = SpoofDropLog::new();
        let result = accept_downlink(&dg, Some((client_ip, None)), &None, &mut spoof_log);
        assert!(
            result.is_some(),
            "a packet with a matching source IP must pass accept_downlink"
        );
        assert_eq!(
            spoof_log.total, 0,
            "a passing packet must not count as a drop"
        );
    }

    /// Companion of the above: a spoofed source IP must be dropped, and the
    /// drop must be tallied by the counter (even though it is not logged
    /// every time - see the rate-limit test below).
    #[test]
    fn accept_downlink_with_mismatching_source_is_dropped() {
        let client_ip = std::net::Ipv4Addr::new(10, 66, 0, 5);
        let dg = ipv4_packet_bytes([10, 66, 0, 99], [8, 8, 8, 8]);
        let mut spoof_log = SpoofDropLog::new();
        let result = accept_downlink(&dg, Some((client_ip, None)), &None, &mut spoof_log);
        assert!(
            result.is_none(),
            "a packet with a spoofed source IP must be dropped by accept_downlink"
        );
        assert_eq!(spoof_log.total, 1, "the drop must be tallied");
    }

    /// M5 regression: a hostile client spoofing source IPs at line rate must
    /// not cost one WARN per packet. Drains far more than the 64-cadence
    /// through `accept_downlink` and confirms the counter keeps every drop
    /// (`total`) while the log-worthy cadence stays at `first + every 64th`
    /// (verified via the pure `log_every_n_should_log`, which is what
    /// `SpoofDropLog::record` delegates to - this test exercises the
    /// integration, `log_every_n_should_log`'s own tests below exercise the
    /// cadence exhaustively).
    #[test]
    fn accept_downlink_spoof_drop_counter_survives_a_flood_without_losing_the_tally() {
        let client_ip = std::net::Ipv4Addr::new(10, 66, 0, 5);
        let dg = ipv4_packet_bytes([10, 66, 0, 99], [8, 8, 8, 8]);
        let mut spoof_log = SpoofDropLog::new();
        const FLOOD: u64 = 500;
        for _ in 0..FLOOD {
            let result = accept_downlink(&dg, Some((client_ip, None)), &None, &mut spoof_log);
            assert!(
                result.is_none(),
                "every spoofed packet in the flood must be dropped"
            );
        }
        assert_eq!(
            spoof_log.total, FLOOD,
            "the counter must keep an exact tally of every drop even though only a \
             fraction are actually logged"
        );
    }

    #[test]
    fn log_every_n_should_log_fires_first_then_every_nth() {
        assert!(log_every_n_should_log(1, 64), "first occurrence must log");
        for n in 2..64u64 {
            assert!(
                !log_every_n_should_log(n, 64),
                "occurrence {n} must stay silent"
            );
        }
        assert!(
            log_every_n_should_log(64, 64),
            "occurrence 64 must log again"
        );
        assert!(
            !log_every_n_should_log(65, 64),
            "occurrence 65 must stay silent"
        );
        assert!(
            log_every_n_should_log(128, 64),
            "occurrence 128 must log again"
        );
    }

    #[test]
    fn log_every_n_should_log_zero_every_only_fires_on_the_first() {
        // `every = 0` must not panic (division/modulo by zero) and must
        // degrade to "log only the first occurrence".
        assert!(log_every_n_should_log(1, 0));
        assert!(!log_every_n_should_log(2, 0));
        assert!(!log_every_n_should_log(1000, 0));
    }

    // ----------------------------------------------------------------
    // M22: accept_downlink_rate_limited had zero tests
    // ----------------------------------------------------------------

    fn test_limiter() -> IdentityLimiter<WarrenPubkey> {
        IdentityLimiter::new(u64::MAX, u64::MAX)
    }

    #[test]
    fn accept_downlink_rate_limited_drops_daita_dummy() {
        let dg = Bytes::from(vec![DAITA_DUMMY_FIRST_BYTE; 64]);
        let limiter = test_limiter();
        let client_id = WarrenPubkey::from_bytes([0xAB; 32]);
        let mut spoof_log = SpoofDropLog::new();
        let result =
            accept_downlink_rate_limited(&dg, None, &limiter, &client_id, &None, &mut spoof_log);
        assert!(result.is_none(), "DAITA dummy must be dropped");
    }

    #[test]
    fn accept_downlink_rate_limited_drops_spoofed_source() {
        let client_ip = std::net::Ipv4Addr::new(10, 66, 0, 7);
        let dg = ipv4_packet_bytes([10, 66, 0, 250], [1, 1, 1, 1]);
        let limiter = test_limiter();
        let client_id = WarrenPubkey::from_bytes([0xAC; 32]);
        let mut spoof_log = SpoofDropLog::new();
        let result = accept_downlink_rate_limited(
            &dg,
            Some((client_ip, None)),
            &limiter,
            &client_id,
            &None,
            &mut spoof_log,
        );
        assert!(result.is_none(), "spoofed source IP must be dropped");
        assert_eq!(spoof_log.total, 1);
    }

    #[test]
    fn accept_downlink_rate_limited_passes_matching_unlimited_traffic() {
        let client_ip = std::net::Ipv4Addr::new(10, 66, 0, 7);
        let dg = ipv4_packet_bytes([10, 66, 0, 7], [1, 1, 1, 1]);
        let limiter = test_limiter();
        let client_id = WarrenPubkey::from_bytes([0xAD; 32]);
        let mut spoof_log = SpoofDropLog::new();
        let result = accept_downlink_rate_limited(
            &dg,
            Some((client_ip, None)),
            &limiter,
            &client_id,
            &None,
            &mut spoof_log,
        );
        assert!(
            result.is_some(),
            "matching source under the bandwidth cap must pass"
        );
        assert_eq!(spoof_log.total, 0);
    }

    /// Rate-limit exhaustion: once the bucket is drained, further packets
    /// (even with a matching source) must be dropped, and the anti-spoof
    /// counter must NOT be touched (this is a distinct drop reason).
    #[test]
    fn accept_downlink_rate_limited_drops_once_bucket_is_exhausted() {
        let client_ip = std::net::Ipv4Addr::new(10, 66, 0, 7);
        let dg = ipv4_packet_bytes([10, 66, 0, 7], [1, 1, 1, 1]);
        // Capacity exactly fits one packet (20 bytes) and refills at a
        // negligible rate, so the first packet drains it and the second
        // (executed microseconds later, no real time elapsed) finds it
        // exhausted.
        let limiter: IdentityLimiter<WarrenPubkey> = IdentityLimiter::new(dg.len() as u64, 1);
        let client_id = WarrenPubkey::from_bytes([0xAE; 32]);
        let mut spoof_log = SpoofDropLog::new();

        let first = accept_downlink_rate_limited(
            &dg,
            Some((client_ip, None)),
            &limiter,
            &client_id,
            &None,
            &mut spoof_log,
        );
        assert!(
            first.is_some(),
            "the first packet fits in the initial bucket"
        );

        let second = accept_downlink_rate_limited(
            &dg,
            Some((client_ip, None)),
            &limiter,
            &client_id,
            &None,
            &mut spoof_log,
        );
        assert!(
            second.is_none(),
            "the bucket is exhausted: the second packet must be dropped"
        );
        assert_eq!(
            spoof_log.total, 0,
            "a rate-limit drop must not be counted as an anti-spoof drop"
        );
    }

    // ----------------------------------------------------------------
    // M22: record_uplink_too_large_drop / send_datagram_drop_too_large
    // ----------------------------------------------------------------

    /// The counter is process-global (like `TUN_IO_ERROR_TOTAL`), so this
    /// asserts a before/after delta rather than an absolute value to stay
    /// correct when other tests in this binary also drive the counter.
    #[test]
    fn record_uplink_too_large_drop_tallies_every_call() {
        let before = record_uplink_too_large_drop(1500, Some(1400));
        let after = record_uplink_too_large_drop(1600, Some(1400));
        assert_eq!(
            after,
            before + 1,
            "each call must increment the running total by exactly 1"
        );
    }

    /// Verifies that the `Bytes` batch path in `pump_quic_to_tun` does
    /// not require a `Vec<Vec<u8>>` - i.e., the batch can hold `Bytes`
    /// without any conversion, and the `FakeTun::send_batch_bytes`
    /// default implementation correctly forwards each packet.
    #[tokio::test]
    async fn send_batch_bytes_default_impl_writes_all_packets() {
        let tun = FakeTun::new();
        let mut batch: Vec<Bytes> = vec![
            Bytes::from(vec![0x45, 0x00, 0x00, 0x14]),
            Bytes::from(vec![0x60, 0x00, 0x00, 0x00]),
        ];
        let n = tun
            .send_batch_bytes(&mut batch)
            .await
            .expect("send_batch_bytes must succeed on FakeTun");
        assert_eq!(n, 2, "must report 2 packets written");
        let out = tun.take_outbound();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], vec![0x45, 0x00, 0x00, 0x14]);
        assert_eq!(out[1], vec![0x60, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn is_daita_dummy_classifies_ipv4_as_real() {
        // IPv4 header: first nibble = 4. Any byte 0x40..=0x4F counts.
        for first in 0x40u8..=0x4F {
            let pkt = [first, 0, 0, 0];
            assert!(
                !is_daita_dummy(&pkt),
                "IPv4 first byte 0x{first:02x} MUST classify as real, not dummy"
            );
        }
    }

    #[test]
    fn is_daita_dummy_classifies_ipv6_as_real() {
        // IPv6 header: first nibble = 6.
        for first in 0x60u8..=0x6F {
            let pkt = [first, 0, 0, 0];
            assert!(
                !is_daita_dummy(&pkt),
                "IPv6 first byte 0x{first:02x} MUST classify as real, not dummy"
            );
        }
    }

    #[test]
    fn is_daita_dummy_classifies_marker_as_dummy() {
        // DAITA dummy marker byte = 0xFF (high nibble = 0xF).
        let pkt = [DAITA_DUMMY_FIRST_BYTE, 0xFF, 0xFF, 0xFF];
        assert!(
            is_daita_dummy(&pkt),
            "0xFF first byte MUST be classified as DAITA dummy"
        );
    }

    #[test]
    fn is_daita_dummy_classifies_empty_as_dummy() {
        // Empty datagram is not a valid IP packet. Treat as dummy
        // (it'd be dropped at the TUN anyway, but explicit handling
        // is cheaper and clearer).
        assert!(
            is_daita_dummy(&[]),
            "empty buffer MUST classify as dummy / non-IP"
        );
    }

    #[test]
    fn is_daita_dummy_classifies_other_nibbles_as_dummy() {
        // Anything else than 4 (IPv4) or 6 (IPv6) is dummy. Cover the
        // boundary nibbles to lock the contract.
        for nibble in [0u8, 1, 2, 3, 5, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF] {
            let pkt = [nibble << 4, 0, 0, 0];
            assert!(
                is_daita_dummy(&pkt),
                "first nibble 0x{nibble:x} MUST classify as dummy"
            );
        }
    }

    #[tokio::test]
    async fn multi_hop_pump_forwards_both_ways_and_drops_downlink_dummies() {
        use std::sync::Arc;
        use tokio::sync::{Mutex, mpsc};

        #[derive(Debug, thiserror::Error)]
        #[error("fake pump")]
        struct FakePumpErr;

        #[derive(Clone)]
        struct FakePump {
            sent: Arc<Mutex<Vec<Vec<u8>>>>,
            downlink: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
        }
        impl WarrenPumpHandle for FakePump {
            type Error = FakePumpErr;
            async fn pump_send(&self, payload: &[u8]) -> std::result::Result<(), FakePumpErr> {
                self.sent.lock().await.push(payload.to_vec());
                Ok(())
            }
            async fn pump_recv(&self) -> std::result::Result<Vec<u8>, FakePumpErr> {
                self.downlink.lock().await.recv().await.ok_or(FakePumpErr)
            }
            async fn pump_send_daita_dummy(&self) -> std::result::Result<usize, FakePumpErr> {
                Ok(1)
            }
            fn pump_close(&self, _: u32, _: &[u8]) {}
        }

        let tun = FakeTun::new();
        let (dn_tx, dn_rx) = mpsc::unbounded_channel();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let pump = Arc::new(FakePump {
            sent: sent.clone(),
            downlink: Arc::new(Mutex::new(dn_rx)),
        });

        let task = tokio::spawn(pump_multi_hop_bidirectional(pump, tun.clone()));

        tun.inject_inbound(vec![0x45, 1, 2, 3]);
        dn_tx.send(vec![0x45, 9, 9]).unwrap();
        dn_tx.send(vec![DAITA_DUMMY_FIRST_BYTE, 0]).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;

        assert_eq!(
            sent.lock().await.as_slice(),
            &[vec![0x45, 1, 2, 3]],
            "uplink TUN packet must reach pump_send"
        );
        assert_eq!(
            tun.take_outbound(),
            vec![vec![0x45, 9, 9]],
            "real downlink forwarded, dummy dropped"
        );
        task.abort();
    }
}
