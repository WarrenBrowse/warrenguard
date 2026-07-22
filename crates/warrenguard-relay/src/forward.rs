//! Bidirectional datagram forwarder between the client connection
//! (`C1`) and the exit connection (`C2`).
//!
//! The relay never decrypts datagrams; it pumps them across the two
//! `quinn::Connection`s as raw `Bytes` until one direction closes. The
//! setup round-trip is shuttled over reliable bidi streams BEFORE the
//! datagram pump starts (cf. [`crate::session::shuttle_setup_to_exit`]),
//! so by the time this forwarder runs both ends already share an HPKE
//! context and only DATA datagrams remain.
//!
//! This module implements the "two-relayed QUIC + HPKE" pattern.

use std::sync::Arc;

use quinn::{Connection, SendDatagramError};
use thiserror::Error;
use tokio::task::JoinSet;

/// Errors raised by [`forward_session`].
///
/// Operational outcomes (one side closing, oversize datagrams) are not
/// errors of the relay's job - they are reported as normal
/// [`ForwardSummary`] fields instead. The datagram pump itself cannot
/// fail fatally, so this enum is currently empty of variants; it is
/// retained as the function's error type for forward-compatibility.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ForwardError {}

/// Counters returned by [`forward_session`] once both directions have
/// stopped pumping. Used by the metrics layer and by the e2e test to
/// assert lossless throughput on the happy path.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ForwardSummary {
    /// Datagrams successfully sent from client to exit.
    pub client_to_exit: u64,
    /// Datagrams successfully sent from exit to client.
    pub exit_to_client: u64,
    /// Datagrams dropped on the client to exit direction because the
    /// payload exceeded `Connection::max_datagram_size()` on `C2`.
    /// These are counted but do not crash the session.
    pub dropped_client_to_exit_too_large: u64,
    /// Datagrams dropped on the exit to client direction for the same
    /// reason.
    pub dropped_exit_to_client_too_large: u64,
    /// Wall-clock lifetime of the forward session, in whole seconds.
    /// Lets a log reader tell a long-lived bonded-secondary connection
    /// (one-sided by flow-ownership design) from a short-lived blackhole.
    pub duration_secs: u64,
}

/// Pumps DATA datagrams bidirectionally between `client_conn` and
/// `exit_conn` until either side closes. Returns a
/// [`ForwardSummary`] describing what happened.
///
/// The setup round-trip has already been shuttled over reliable streams
/// (cf. [`crate::session::shuttle_setup_to_exit`]) before this runs, so
/// there is no first-frame replay: only DATA datagrams flow here.
///
/// Backpressure: Quinn's datagram queue is internally bounded. The
/// forwarder distinguishes:
/// - `SendDatagramError::TooLarge` -> drop + counter increment.
/// - `SendDatagramError::Disabled` -> stop pumping that direction.
/// - `SendDatagramError::ConnectionLost` -> stop pumping that direction.
///
/// # Errors
/// This function does not currently return an error; the
/// `Result<_, ForwardError>` shape is retained for callers and for
/// forward-compatibility.
pub async fn forward_session(
    client_conn: Connection,
    exit_conn: Arc<Connection>,
) -> Result<ForwardSummary, ForwardError> {
    let started = std::time::Instant::now();

    // Client-leg path telemetry (rtt/loss/cwnd/datagram-queue of the
    // relay->client connection). This leg is where a client's last-mile
    // pathology manifests server-side, and it had ZERO visibility during
    // the 2026-07-22 brownout forensics; the probe self-terminates when
    // the connection closes.
    drop(warrenguard_transport_core::spawn_path_probe(
        "relay-client-leg",
        vec![client_conn.clone()],
        None,
    ));

    // Live shared counters, incremented by the pumps as they forward.
    // The teardown below ABORTS whichever pump is still parked on its
    // recv when the first one finishes; counters accumulated inside the
    // task would be lost with it (every real session used to end with
    // `exit_to_client=0` this way, reading as a phantom half-dead
    // session), so the pumps write here instead of returning totals.
    let live = Arc::new(LiveCounters::default());

    // Spawn two unidirectional pumps. JoinSet lets us cancel the
    // twin task when one direction stops, mirroring the lifetime
    // of the session.
    let mut set = JoinSet::new();
    let client_for_c1 = client_conn.clone();
    let exit_for_c1 = exit_conn.clone();
    let live_for_c1 = live.clone();
    set.spawn(async move { pump_c1_to_c2(client_for_c1, exit_for_c1, live_for_c1).await });
    let client_for_c2 = client_conn.clone();
    let exit_for_c2 = exit_conn.clone();
    let live_for_c2 = live.clone();
    set.spawn(async move { pump_c2_to_c1(exit_for_c2, client_for_c2, live_for_c2).await });

    let mut teardown_started = false;
    while let Some(joined) = set.join_next().await {
        if let Err(join_err) = joined {
            if join_err.is_panic() {
                tracing::warn!("relay forward pump task panicked");
            } else if !(teardown_started && join_err.is_cancelled()) {
                // A cancellation we did not initiate is still abnormal.
                tracing::warn!(
                    cancelled = join_err.is_cancelled(),
                    "relay forward pump task ended abnormally"
                );
            }
        }
        // First task to finish triggers session shutdown; the twin's
        // cancellation right after is the NORMAL end of every session.
        client_conn.close(quinn::VarInt::from_u32(0), b"forward complete");
        exit_conn.close(quinn::VarInt::from_u32(0), b"forward complete");
        teardown_started = true;
        set.abort_all();
    }

    let mut summary = live.snapshot();
    summary.duration_secs = started.elapsed().as_secs();
    Ok(summary)
}

/// Pump counters shared between the two direction tasks and the
/// session teardown (cf. the abort note in [`forward_session`]).
#[derive(Debug, Default)]
struct LiveCounters {
    client_to_exit: std::sync::atomic::AtomicU64,
    exit_to_client: std::sync::atomic::AtomicU64,
    dropped_client_to_exit_too_large: std::sync::atomic::AtomicU64,
    dropped_exit_to_client_too_large: std::sync::atomic::AtomicU64,
}

impl LiveCounters {
    fn snapshot(&self) -> ForwardSummary {
        use std::sync::atomic::Ordering;
        ForwardSummary {
            client_to_exit: self.client_to_exit.load(Ordering::Relaxed),
            exit_to_client: self.exit_to_client.load(Ordering::Relaxed),
            dropped_client_to_exit_too_large: self
                .dropped_client_to_exit_too_large
                .load(Ordering::Relaxed),
            dropped_exit_to_client_too_large: self
                .dropped_exit_to_client_too_large
                .load(Ordering::Relaxed),
            duration_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToExit,
    ExitToClient,
}

async fn pump_c1_to_c2(client: Connection, exit: Arc<Connection>, live: Arc<LiveCounters>) {
    pump_one_direction(&client, exit.as_ref(), Direction::ClientToExit, &live).await;
}

async fn pump_c2_to_c1(exit: Arc<Connection>, client: Connection, live: Arc<LiveCounters>) {
    pump_one_direction(exit.as_ref(), &client, Direction::ExitToClient, &live).await;
}

async fn pump_one_direction(
    source: &Connection,
    sink: &Connection,
    direction: Direction,
    live: &LiveCounters,
) {
    use std::sync::atomic::Ordering;
    let (forwarded, dropped_too_large) = match direction {
        Direction::ClientToExit => (&live.client_to_exit, &live.dropped_client_to_exit_too_large),
        Direction::ExitToClient => (&live.exit_to_client, &live.dropped_exit_to_client_too_large),
    };
    loop {
        let bytes = match source.read_datagram().await {
            Ok(b) => b,
            Err(_) => return,
        };
        match sink.send_datagram(bytes) {
            Ok(()) => {
                forwarded.fetch_add(1, Ordering::Relaxed);
            }
            Err(SendDatagramError::TooLarge) => {
                dropped_too_large.fetch_add(1, Ordering::Relaxed);
            }
            Err(_other) => return,
        }
    }
}
