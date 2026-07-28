//! Per-connection QUIC path probe: rate-limited (5 s) transport
//! counters for diagnosing throughput limits on real WAN paths.
//!
//! A healthy path logs a heartbeat every
//! [`PATH_PROBE_HEARTBEAT_TICKS`] intervals; an interval that carries
//! a pathology (loss, congestion, a send-queue drop, ECN CE) logs
//! immediately. The old every-tick INFO line was 8 lines every 5 s on
//! a multihop session, about 1.4 MB per hour, and it crowded out
//! everything else: a real beta problem report was 98.9% path-probe
//! bytes and covered only 7 minutes of history. Set
//! `WARREN_PATH_PROBE_EVERY=1` to restore the every-tick stream for a
//! throughput bench.
//!
//! Surfaces the signals that discriminate between the possible
//! datagram-path bottlenecks:
//!
//! - `cwnd`, `rtt_ms`, `lost`, `congestion`: is the OUTER congestion
//!   controller throttling below the link, or is the path lossy?
//! - `dg_buf_free`: remaining space in the datagram send buffer; a
//!   buffer pinned near 0 means the queue is absorbing an app-vs-link
//!   rate mismatch.
//! - `dg_drop_aqm` / `dg_drop_full`: datagrams the send queue dropped
//!   this interval, split by cause (CoDel sojourn-time head-drop vs
//!   buffer-overflow oldest-first eviction). Both are silent from the
//!   sender's point of view, so these counters are the only direct
//!   evidence of send-queue pressure.
//! - `app_tx` vs `dg_tx` (exit side, where [`crate::ClientMetrics`]
//!   counts app-level sends): a sustained gap means datagrams accepted
//!   by `send_datagram` never reached the wire (buffer overflow).
//! - `udp_gso`: average datagrams per UDP I/O (GSO/sendmmsg
//!   efficiency).

use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, ConnectionStats};

use crate::client_metrics::ClientMetrics;

/// Interval between probe samples. 5 s is frequent enough to catch
/// ramp-up behavior; what used to be expensive was logging every one
/// of them, not taking them.
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Samples between two heartbeat lines for a path with nothing to
/// report. 60 x 5 s is one line per connection per 5 minutes, which
/// keeps a problem report readable for days instead of minutes while
/// still proving the path was alive and what its steady state was.
pub const PATH_PROBE_HEARTBEAT_TICKS: u32 = 60;

/// Env override for [`PATH_PROBE_HEARTBEAT_TICKS`]. `1` logs every
/// sample, which is what a throughput bench wants and what production
/// no longer pays for by default.
pub const PATH_PROBE_EVERY_ENV: &str = "WARREN_PATH_PROBE_EVERY";

/// Resolves the heartbeat cadence, clamped to at least one sample so a
/// hostile or fat-fingered value can never divide by zero or silence
/// the probe entirely.
#[must_use]
pub fn heartbeat_ticks() -> u32 {
    heartbeat_ticks_from(std::env::var(PATH_PROBE_EVERY_ENV).ok().as_deref())
}

/// The parsing half, split out because mutating the process environment
/// in a test needs `unsafe` under edition 2024 and this crate forbids it.
#[must_use]
fn heartbeat_ticks_from(raw: Option<&str>) -> u32 {
    raw.and_then(|v| v.trim().parse::<u32>().ok())
        .map_or(PATH_PROBE_HEARTBEAT_TICKS, |v| v.max(1))
}

/// Counter deltas between two consecutive [`ConnectionStats`]
/// snapshots. All fields saturate at 0 so a stats reset (path
/// migration) can never underflow.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PathProbeDelta {
    /// QUIC packets sent on the path.
    pub sent_packets: u64,
    /// QUIC packets declared lost on the path.
    pub lost_packets: u64,
    /// Congestion events (loss/ECN-triggered cwnd reductions).
    pub congestion_events: u64,
    /// DATAGRAM frames transmitted (actually emitted on the wire).
    pub dg_frames_tx: u64,
    /// DATAGRAM frames received.
    pub dg_frames_rx: u64,
    /// UDP datagrams handed to the socket.
    pub udp_tx_datagrams: u64,
    /// UDP I/O operations (< `udp_tx_datagrams` when GSO batches).
    pub udp_tx_ios: u64,
    /// Outgoing datagrams head-dropped by the CoDel AQM.
    pub dg_dropped_aqm: u64,
    /// Outgoing datagrams evicted oldest-first on send-buffer overflow.
    pub dg_dropped_overflow: u64,
    /// Enqueued inner packets classified Not-ECT.
    pub ecn_not_ect: u64,
    /// Enqueued inner packets classified ECT(0).
    pub ecn_ect0: u64,
    /// Enqueued inner packets classified ECT(1).
    pub ecn_ect1: u64,
    /// Enqueued inner packets classified CE.
    pub ecn_ce: u64,
}

impl PathProbeDelta {
    /// Computes the per-interval deltas between `prev` and `cur`.
    #[must_use]
    pub fn between(prev: &ConnectionStats, cur: &ConnectionStats) -> Self {
        Self {
            sent_packets: cur.path.sent_packets.saturating_sub(prev.path.sent_packets),
            lost_packets: cur.path.lost_packets.saturating_sub(prev.path.lost_packets),
            congestion_events: cur
                .path
                .congestion_events
                .saturating_sub(prev.path.congestion_events),
            dg_frames_tx: cur.frame_tx.datagram.saturating_sub(prev.frame_tx.datagram),
            dg_frames_rx: cur.frame_rx.datagram.saturating_sub(prev.frame_rx.datagram),
            udp_tx_datagrams: cur.udp_tx.datagrams.saturating_sub(prev.udp_tx.datagrams),
            udp_tx_ios: cur.udp_tx.ios.saturating_sub(prev.udp_tx.ios),
            dg_dropped_aqm: cur
                .datagram_tx
                .dropped_aqm
                .saturating_sub(prev.datagram_tx.dropped_aqm),
            dg_dropped_overflow: cur
                .datagram_tx
                .dropped_overflow
                .saturating_sub(prev.datagram_tx.dropped_overflow),
            ecn_not_ect: cur
                .datagram_tx
                .ecn_not_ect
                .saturating_sub(prev.datagram_tx.ecn_not_ect),
            ecn_ect0: cur
                .datagram_tx
                .ecn_ect0
                .saturating_sub(prev.datagram_tx.ecn_ect0),
            ecn_ect1: cur
                .datagram_tx
                .ecn_ect1
                .saturating_sub(prev.datagram_tx.ecn_ect1),
            ecn_ce: cur
                .datagram_tx
                .ecn_ce
                .saturating_sub(prev.datagram_tx.ecn_ce),
        }
    }

    /// True when the interval saw no traffic at all; the probe skips
    /// the log line to keep idle tunnels silent.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.sent_packets == 0 && self.dg_frames_tx == 0 && self.dg_frames_rx == 0
    }

    /// Whether this interval is worth a line on its own, without
    /// waiting for the next heartbeat.
    ///
    /// Exactly the counters the probe exists to catch: anything else is
    /// a healthy path restating itself, which is what made these lines
    /// crowd every other event out of a problem report.
    #[must_use]
    pub fn is_noteworthy(&self) -> bool {
        self.lost_packets > 0
            || self.congestion_events > 0
            || self.dg_dropped_aqm > 0
            || self.dg_dropped_overflow > 0
            || self.ecn_ce > 0
    }

    /// Average UDP datagrams per I/O operation (GSO/sendmmsg batching
    /// efficiency). 1.0 = no batching. 0.0 when no I/O happened.
    #[must_use]
    pub fn udp_gso_ratio(&self) -> f64 {
        if self.udp_tx_ios == 0 {
            return 0.0;
        }
        self.udp_tx_datagrams as f64 / self.udp_tx_ios as f64
    }
}

/// Spawns the probe task over a set of connections (one client session:
/// 1 conn mono, N conns multi). Logs one INFO line per active
/// connection per [`PATH_PROBE_INTERVAL`] while traffic flows, and
/// terminates by itself once every connection is closed, so callers
/// can fire-and-forget the handle.
///
/// `app` carries the exit-side per-client app-level counters
/// ([`ClientMetrics`]); when present, the probe logs `app_tx`/`app_rx`
/// deltas so the app-vs-wire gap (silent send-buffer drops) is visible.
/// Client side passes `None` (no app counter exists there).
#[must_use = "fire-and-forget is fine (the task self-terminates), but discard explicitly with let _"]
pub fn spawn_path_probe(
    label: &'static str,
    conns: Vec<Connection>,
    app: Option<Arc<ClientMetrics>>,
) -> tokio::task::JoinHandle<()> {
    // `WARREN_PATH_PROBE=0` opts out entirely: no timer task per
    // connection and no per-identity throughput/RTT time series in the
    // logs (defense-in-depth for operators who want quieter exits).
    // Default stays ON. The env read and
    // its read-once caching live in the central knob registry.
    if !warrenguard_config::knobs::path_probe_enabled() {
        return tokio::spawn(async {});
    }
    tokio::spawn(async move {
        let mut prev: Vec<ConnectionStats> = conns.iter().map(quinn::Connection::stats).collect();
        let mut prev_app = app.as_ref().map(|m| m.snapshot());
        let every = heartbeat_ticks();
        let mut tick: u32 = 0;
        let mut interval = tokio::time::interval(PATH_PROBE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The first tick of `tokio::time::interval` fires immediately;
        // consume it so the first delta covers a full interval.
        interval.tick().await;
        loop {
            interval.tick().await;
            // Counted per sample, not per connection, so the healthy
            // lines of a multihop session land together and stay
            // comparable side by side.
            let heartbeat = tick % every == 0;
            tick = tick.wrapping_add(1);
            // App-level deltas are session-wide (the exit counts per
            // client, not per conn): compute once per tick.
            let app_deltas = match (&app, &mut prev_app) {
                (Some(m), Some(prev_snap)) => {
                    let cur = m.snapshot();
                    let d = (
                        cur.datagrams_tx.saturating_sub(prev_snap.datagrams_tx),
                        cur.datagrams_rx.saturating_sub(prev_snap.datagrams_rx),
                    );
                    *prev_snap = cur;
                    Some(d)
                }
                _ => None,
            };
            let mut all_closed = true;
            for (idx, conn) in conns.iter().enumerate() {
                if conn.close_reason().is_some() {
                    continue;
                }
                all_closed = false;
                let cur = conn.stats();
                let delta = PathProbeDelta::between(&prev[idx], &cur);
                prev[idx] = cur;
                if delta.is_idle() {
                    continue;
                }
                // A healthy path between heartbeats has nothing to add.
                if !heartbeat && !delta.is_noteworthy() {
                    continue;
                }
                let rtt_ms = cur.path.rtt.as_secs_f64() * 1000.0;
                match app_deltas {
                    Some((app_tx, app_rx)) => tracing::info!(
                        probe = label,
                        conn = idx,
                        cwnd = cur.path.cwnd,
                        rtt_ms = format_args!("{rtt_ms:.1}"),
                        mtu = cur.path.current_mtu,
                        sent = delta.sent_packets,
                        lost = delta.lost_packets,
                        congestion = delta.congestion_events,
                        dg_tx = delta.dg_frames_tx,
                        dg_rx = delta.dg_frames_rx,
                        dg_buf_free = conn.datagram_send_buffer_space(),
                        dg_drop_aqm = delta.dg_dropped_aqm,
                        dg_drop_full = delta.dg_dropped_overflow,
                        ecn_not = delta.ecn_not_ect,
                        ecn_ect0 = delta.ecn_ect0,
                        ecn_ect1 = delta.ecn_ect1,
                        ecn_ce = delta.ecn_ce,
                        udp_gso = format_args!("{:.1}", delta.udp_gso_ratio()),
                        app_tx,
                        app_rx,
                        "path probe"
                    ),
                    None => tracing::info!(
                        probe = label,
                        conn = idx,
                        cwnd = cur.path.cwnd,
                        rtt_ms = format_args!("{rtt_ms:.1}"),
                        mtu = cur.path.current_mtu,
                        sent = delta.sent_packets,
                        lost = delta.lost_packets,
                        congestion = delta.congestion_events,
                        dg_tx = delta.dg_frames_tx,
                        dg_rx = delta.dg_frames_rx,
                        dg_buf_free = conn.datagram_send_buffer_space(),
                        dg_drop_aqm = delta.dg_dropped_aqm,
                        dg_drop_full = delta.dg_dropped_overflow,
                        ecn_not = delta.ecn_not_ect,
                        ecn_ect0 = delta.ecn_ect0,
                        ecn_ect1 = delta.ecn_ect1,
                        ecn_ce = delta.ecn_ce,
                        udp_gso = format_args!("{:.1}", delta.udp_gso_ratio()),
                        "path probe"
                    ),
                }
            }
            if all_closed {
                break;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats_with(
        sent: u64,
        lost: u64,
        congestion: u64,
        dg_tx: u64,
        dg_rx: u64,
        udp_dg: u64,
        udp_ios: u64,
    ) -> ConnectionStats {
        let mut s = ConnectionStats::default();
        s.path.sent_packets = sent;
        s.path.lost_packets = lost;
        s.path.congestion_events = congestion;
        s.frame_tx.datagram = dg_tx;
        s.frame_rx.datagram = dg_rx;
        s.udp_tx.datagrams = udp_dg;
        s.udp_tx.ios = udp_ios;
        s
    }

    #[test]
    fn between_computes_per_field_deltas() {
        let prev = stats_with(100, 2, 1, 90, 80, 95, 10);
        let cur = stats_with(250, 5, 3, 200, 180, 220, 20);
        let d = PathProbeDelta::between(&prev, &cur);
        assert_eq!(d.sent_packets, 150);
        assert_eq!(d.lost_packets, 3);
        assert_eq!(d.congestion_events, 2);
        assert_eq!(d.dg_frames_tx, 110);
        assert_eq!(d.dg_frames_rx, 100);
        assert_eq!(d.udp_tx_datagrams, 125);
        assert_eq!(d.udp_tx_ios, 10);
    }

    #[test]
    fn between_computes_datagram_drop_deltas() {
        // The AQM head-drops and the buffer-overflow evictions are the
        // only visibility into send-queue pressure; the probe must
        // surface both as per-interval deltas.
        let mut prev = stats_with(100, 0, 0, 90, 80, 95, 10);
        prev.datagram_tx.dropped_aqm = 3;
        prev.datagram_tx.dropped_overflow = 1;
        let mut cur = stats_with(200, 0, 0, 180, 160, 190, 20);
        cur.datagram_tx.dropped_aqm = 10;
        cur.datagram_tx.dropped_overflow = 6;
        let d = PathProbeDelta::between(&prev, &cur);
        assert_eq!(d.dg_dropped_aqm, 7);
        assert_eq!(d.dg_dropped_overflow, 5);
    }

    #[test]
    fn between_computes_ecn_distribution_deltas() {
        // The inner-ECN counters are the measurement basis for any future
        // mark-vs-drop decision; the probe must surface them per interval.
        let mut prev = stats_with(100, 0, 0, 90, 80, 95, 10);
        prev.datagram_tx.ecn_not_ect = 50;
        prev.datagram_tx.ecn_ect0 = 5;
        prev.datagram_tx.ecn_ect1 = 1;
        prev.datagram_tx.ecn_ce = 0;
        let mut cur = stats_with(200, 0, 0, 180, 160, 190, 20);
        cur.datagram_tx.ecn_not_ect = 130;
        cur.datagram_tx.ecn_ect0 = 12;
        cur.datagram_tx.ecn_ect1 = 4;
        cur.datagram_tx.ecn_ce = 2;
        let d = PathProbeDelta::between(&prev, &cur);
        assert_eq!(d.ecn_not_ect, 80);
        assert_eq!(d.ecn_ect0, 7);
        assert_eq!(d.ecn_ect1, 3);
        assert_eq!(d.ecn_ce, 2);
    }

    #[test]
    fn between_saturates_on_counter_regression() {
        // A stats reset (e.g. path migration rebuilding PathStats) must
        // yield 0, never an underflow panic or a giant wrapped value.
        let mut prev = stats_with(1000, 10, 5, 900, 800, 950, 100);
        prev.datagram_tx.dropped_aqm = 9;
        prev.datagram_tx.dropped_overflow = 9;
        let cur = stats_with(50, 0, 0, 40, 30, 45, 5);
        let d = PathProbeDelta::between(&prev, &cur);
        assert_eq!(d.sent_packets, 0);
        assert_eq!(d.lost_packets, 0);
        assert_eq!(d.congestion_events, 0);
        assert_eq!(d.dg_frames_tx, 0);
        assert_eq!(d.dg_frames_rx, 0);
        assert_eq!(d.udp_tx_datagrams, 0);
        assert_eq!(d.udp_tx_ios, 0);
        assert_eq!(d.dg_dropped_aqm, 0);
        assert_eq!(d.dg_dropped_overflow, 0);
    }

    #[test]
    fn only_a_pathology_earns_a_line_of_its_own() {
        // A busy but healthy path is what used to flood the logs: 456 of the
        // 480 lines in a real problem report, 98.9% of its bytes, leaving a
        // 7 minute window to debug from.
        let healthy = PathProbeDelta {
            sent_packets: 41,
            dg_frames_tx: 28,
            dg_frames_rx: 26,
            udp_tx_datagrams: 28,
            udp_tx_ios: 28,
            ecn_not_ect: 28,
            ..Default::default()
        };
        assert!(
            !healthy.is_noteworthy(),
            "healthy traffic waits for the heartbeat"
        );
        assert!(!healthy.is_idle(), "and it is still traffic");

        for (name, delta) in [
            (
                "loss",
                PathProbeDelta {
                    lost_packets: 1,
                    ..healthy
                },
            ),
            (
                "congestion",
                PathProbeDelta {
                    congestion_events: 1,
                    ..healthy
                },
            ),
            (
                "aqm drop",
                PathProbeDelta {
                    dg_dropped_aqm: 1,
                    ..healthy
                },
            ),
            (
                "overflow drop",
                PathProbeDelta {
                    dg_dropped_overflow: 1,
                    ..healthy
                },
            ),
            (
                "ecn ce",
                PathProbeDelta {
                    ecn_ce: 1,
                    ..healthy
                },
            ),
        ] {
            assert!(
                delta.is_noteworthy(),
                "{name} is exactly what this probe exists to catch"
            );
        }
    }

    #[test]
    fn an_idle_interval_is_never_noteworthy() {
        // Nothing happened: no pathology can be inferred, and the loop skips
        // it before the heartbeat is even considered.
        let idle = PathProbeDelta::default();
        assert!(idle.is_idle());
        assert!(!idle.is_noteworthy());
    }

    #[test]
    fn the_heartbeat_cadence_is_overridable_but_never_zero() {
        // Default keeps production quiet; a bench sets 1 to get every sample
        // back. A zero or garbage value must neither divide by zero in the
        // loop nor silence the probe.
        assert_eq!(heartbeat_ticks_from(None), PATH_PROBE_HEARTBEAT_TICKS);
        assert_eq!(
            heartbeat_ticks_from(Some("1")),
            1,
            "a bench gets every sample"
        );
        assert_eq!(
            heartbeat_ticks_from(Some(" 12 ")),
            12,
            "surrounding space is fine"
        );
        assert_eq!(
            heartbeat_ticks_from(Some("0")),
            1,
            "zero would divide by zero"
        );
        assert_eq!(
            heartbeat_ticks_from(Some("not a number")),
            PATH_PROBE_HEARTBEAT_TICKS,
            "garbage falls back to the default"
        );
        assert_eq!(
            heartbeat_ticks_from(Some("")),
            PATH_PROBE_HEARTBEAT_TICKS,
            "an empty override is not an override"
        );
    }

    #[test]
    fn is_idle_only_without_any_traffic() {
        assert!(PathProbeDelta::default().is_idle());

        let rx_only = PathProbeDelta {
            dg_frames_rx: 1,
            ..Default::default()
        };
        assert!(
            !rx_only.is_idle(),
            "a receive-only interval (download) must still log"
        );

        let acks_only = PathProbeDelta {
            sent_packets: 3,
            ..Default::default()
        };
        assert!(
            !acks_only.is_idle(),
            "pure-ACK intervals carry congestion info worth logging"
        );
    }

    #[test]
    fn udp_gso_ratio_handles_zero_ios() {
        assert_eq!(PathProbeDelta::default().udp_gso_ratio(), 0.0);
        let d = PathProbeDelta {
            udp_tx_datagrams: 64,
            udp_tx_ios: 4,
            ..Default::default()
        };
        assert!((d.udp_gso_ratio() - 16.0).abs() < f64::EPSILON);
    }
}
