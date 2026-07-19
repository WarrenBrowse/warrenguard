//! Multi-hop throughput bench session driver.
//!
//! Extracted from the multi-hop bench binary so the
//! sender/receiver loop is reachable from integration tests. The
//! binary stays thin (CLI parsing + Quinn endpoint construction); the
//! actual throughput-driving logic lives here.
//!
//! # Backpressure contract
//!
//! [`run_bench_session`] runs a concurrent sender + receiver against
//! the supplied [`MultiHopClient`]. The sender bounds the number of
//! outstanding datagrams via a shared atomic counter pair
//! (`sent - recv`); when the in-flight window fills, the sender
//! yields with a short sleep until the receiver drains the queue.
//! Without that window the underlying Quinn datagram queue would
//! saturate, drop bursts, and collapse the pipe to a few KB/s within
//! seconds; see `tests/bench_backpressure_regression.rs` for the
//! reproduction.
//!
//! Bench-only: this module is not wired into the production client
//! flow and touches none of the higher-level session features (TUN,
//! NAT-PMP, allowlist).
//!
//! # Exit mode requirement (echo loopback only)
//!
//! The receiver loop polls `client.recv()` for the same bytes the
//! sender enqueued via `client.send()`. The sender's in-flight window
//! is bounded by `sent - recv`. Both contracts only hold if the exit
//! runs `serve_multihop_echo` (echo loopback). If the exit instead
//! forwards payloads through a TUN bridge to the Internet
//! (`--multihop --use-tun` production mode), no echo ever comes back,
//! the in-flight window fills, and the sender stalls. For end-to-end
//! Internet traversal benches, use `iperf3` over the TUN interface
//! established by a deployer's multi-hop TUN client binary instead.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::multihop::{MultiHopClient, MultiHopError};

/// Aggregated counters and derived throughput for a single bench
/// session. All fields are reported by [`run_bench_session`] at the
/// end of the run; intermediate values are kept inside the sender /
/// receiver tasks.
#[derive(Debug, Clone, Copy)]
pub struct BenchResult {
    /// Total bytes successfully accepted by `client.send()`.
    pub sent_bytes: u64,
    /// Total datagrams successfully accepted by `client.send()`.
    pub sent_datagrams: u64,
    /// Total bytes returned by `client.recv()` after exit-side echo.
    pub recv_bytes: u64,
    /// Total datagrams returned by `client.recv()`.
    pub recv_datagrams: u64,
    /// Failures observed (send-side errors, recv-side break paths,
    /// and any sender error retries summed together).
    pub errors: u64,
    /// Elapsed wall-clock time of the bench session.
    pub elapsed: Duration,
}

impl BenchResult {
    /// Effective send-side throughput in megabits per second.
    #[must_use]
    pub fn send_mbps(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64().max(0.001);
        (self.sent_bytes as f64 * 8.0) / 1_000_000.0 / secs
    }

    /// Effective recv-side throughput in megabits per second.
    #[must_use]
    pub fn recv_mbps(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64().max(0.001);
        (self.recv_bytes as f64 * 8.0) / 1_000_000.0 / secs
    }

    /// Effective send-side packet rate.
    #[must_use]
    pub fn send_pps(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64().max(0.001);
        self.sent_datagrams as f64 / secs
    }

    /// Effective recv-side packet rate.
    #[must_use]
    pub fn recv_pps(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64().max(0.001);
        self.recv_datagrams as f64 / secs
    }
}

/// Parameters driving a single [`run_bench_session`] call.
#[derive(Debug, Clone)]
pub struct BenchParams {
    /// Payload bytes per datagram (cleartext, pre-HPKE seal).
    pub payload_bytes: usize,
    /// Wall-clock duration of the bench session.
    pub duration: Duration,
    /// Bound on the number of in-flight (sent but not yet recv) datagrams.
    /// The sender awaits the receiver to drain before exceeding this.
    pub in_flight: usize,
}

/// Drive the multi-hop pipeline at saturation for `params.duration`.
///
/// Concurrent sender + receiver task: each direction is driven
/// independently so the pipe is exercised both ways without the sender
/// blocking on the receiver. The sender's emit rate is throttled by a
/// window-based backpressure on `(sent - recv)`.
///
/// # Panics
///
/// Panics if `params.payload_bytes` is zero (a zero-length payload is
/// rejected by the multi-hop wire format and would loop forever on
/// failures).
pub async fn run_bench_session(client: Arc<MultiHopClient>, params: BenchParams) -> BenchResult {
    assert!(
        params.payload_bytes > 0,
        "BenchParams::payload_bytes must be > 0"
    );
    let payload = Arc::new(vec![0xA5u8; params.payload_bytes]);
    let stop_at = Instant::now() + params.duration;

    let sent_bytes_c = Arc::new(AtomicU64::new(0));
    let sent_datagrams_c = Arc::new(AtomicU64::new(0));
    let recv_bytes_c = Arc::new(AtomicU64::new(0));
    let recv_datagrams_c = Arc::new(AtomicU64::new(0));
    let errors_c = Arc::new(AtomicU64::new(0));

    let send_client = client.clone();
    let send_payload = payload.clone();
    let send_sent_bytes = sent_bytes_c.clone();
    let send_sent_datagrams = sent_datagrams_c.clone();
    let send_errors = errors_c.clone();
    // Window-based backpressure: the sender keeps `sent - recv` below
    // `in_flight` by reading the receiver task's atomic counter on
    // every iteration. Without this read the sender would burst
    // unbounded into Quinn's datagram queue, the queue would saturate,
    // drops would cascade, and the recv path would collapse to a
    // handful of KB/s. The behaviour was diagnosed on a cross-DC
    // cloud backbone; the regression test in
    // `tests/bench_backpressure_regression.rs` reproduces the
    // collapse locally via a slow fake exit.
    let send_recv_observed = recv_datagrams_c.clone();
    let send_sent_observed = sent_datagrams_c.clone();
    let in_flight = params.in_flight as u64;
    let sender = tokio::spawn(async move {
        while Instant::now() < stop_at {
            let sent = send_sent_observed.load(Ordering::Relaxed);
            let recv = send_recv_observed.load(Ordering::Relaxed);
            if sent.saturating_sub(recv) >= in_flight {
                // The receive task has not drained the queue enough
                // for the next datagram to fit under the window.
                // Yield briefly and re-check, rather than feeding the
                // queue past its drop threshold.
                tokio::time::sleep(Duration::from_micros(50)).await;
                continue;
            }
            match send_client.send(&send_payload).await {
                Ok(()) => {
                    send_sent_bytes.fetch_add(send_payload.len() as u64, Ordering::Relaxed);
                    send_sent_datagrams.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    send_errors.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_micros(100)).await;
                }
            }
        }
    });

    let recv_client = client.clone();
    let recv_bytes_t = recv_bytes_c.clone();
    let recv_datagrams_t = recv_datagrams_c.clone();
    let recv_errors = errors_c.clone();
    let receiver = tokio::spawn(async move {
        while Instant::now() < stop_at {
            match tokio::time::timeout(Duration::from_millis(500), recv_client.recv()).await {
                Ok(Ok(payload)) => {
                    recv_bytes_t.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    recv_datagrams_t.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Err(MultiHopError::Recv(_))) => {
                    // Terminal: the QUIC connection is gone. Continuing
                    // would tight-loop on the same error 8M times per
                    // second and inflate the counters without doing
                    // useful work.
                    recv_errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Ok(Err(_)) => {
                    // Transient: a single decrypt / replay / decode
                    // miss on one datagram. A diagnostic surfaced a
                    // catastrophic deadlock when the bench treated
                    // these as terminal: a reverse straggler from the
                    // pre-rekey epoch killed the entire receiver task
                    // and saturated the sender's in-flight window
                    // until manual termination. The rekey overlap
                    // fix makes that specific straggler decode, but
                    // other one-off errors (corrupt frame on the
                    // wire, replay reject on a duplicate datagram)
                    // must still be tolerated rather than promoted
                    // to a connection death.
                    recv_errors.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    // Timeout: not an error, just an idle window.
                }
            }
        }
    });

    let start = Instant::now();
    let _ = tokio::join!(sender, receiver);

    BenchResult {
        sent_bytes: sent_bytes_c.load(Ordering::Relaxed),
        sent_datagrams: sent_datagrams_c.load(Ordering::Relaxed),
        recv_bytes: recv_bytes_c.load(Ordering::Relaxed),
        recv_datagrams: recv_datagrams_c.load(Ordering::Relaxed),
        errors: errors_c.load(Ordering::Relaxed),
        elapsed: start.elapsed(),
    }
}
