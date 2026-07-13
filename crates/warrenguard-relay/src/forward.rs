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
    let mut summary = ForwardSummary::default();

    // Spawn two unidirectional pumps. JoinSet lets us cancel the
    // twin task when one direction stops, mirroring the lifetime
    // of the session.
    let mut set = JoinSet::new();
    let client_for_c1 = client_conn.clone();
    let exit_for_c1 = exit_conn.clone();
    set.spawn(async move { pump_c1_to_c2(client_for_c1, exit_for_c1).await });
    let client_for_c2 = client_conn.clone();
    let exit_for_c2 = exit_conn.clone();
    set.spawn(async move { pump_c2_to_c1(exit_for_c2, client_for_c2).await });

    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(result) => match result.direction {
                Direction::ClientToExit => {
                    summary.client_to_exit += result.forwarded;
                    summary.dropped_client_to_exit_too_large += result.dropped_too_large;
                }
                Direction::ExitToClient => {
                    summary.exit_to_client += result.forwarded;
                    summary.dropped_exit_to_client_too_large += result.dropped_too_large;
                }
            },
            Err(join_err) => {
                // A pump task panicked or was aborted. We cannot reliably
                // tell which direction it carried from a JoinError, so we
                // record nothing into the summary rather than blindly
                // attributing it to ClientToExit (which would corrupt the
                // counters). Log it without any identifying data.
                tracing::warn!(
                    panicked = join_err.is_panic(),
                    cancelled = join_err.is_cancelled(),
                    "relay forward pump task ended abnormally"
                );
            }
        }
        // First task to finish triggers session shutdown.
        client_conn.close(quinn::VarInt::from_u32(0), b"forward complete");
        exit_conn.close(quinn::VarInt::from_u32(0), b"forward complete");
        set.abort_all();
    }

    Ok(summary)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToExit,
    ExitToClient,
}

struct PumpResult {
    forwarded: u64,
    dropped_too_large: u64,
    direction: Direction,
}

async fn pump_c1_to_c2(client: Connection, exit: Arc<Connection>) -> PumpResult {
    pump_one_direction(&client, exit.as_ref(), Direction::ClientToExit).await
}

async fn pump_c2_to_c1(exit: Arc<Connection>, client: Connection) -> PumpResult {
    pump_one_direction(exit.as_ref(), &client, Direction::ExitToClient).await
}

async fn pump_one_direction(
    source: &Connection,
    sink: &Connection,
    direction: Direction,
) -> PumpResult {
    let mut forwarded: u64 = 0;
    let mut dropped_too_large: u64 = 0;
    loop {
        let bytes = match source.read_datagram().await {
            Ok(b) => b,
            Err(_) => {
                return PumpResult {
                    forwarded,
                    dropped_too_large,
                    direction,
                };
            }
        };
        match sink.send_datagram(bytes) {
            Ok(()) => forwarded += 1,
            Err(SendDatagramError::TooLarge) => dropped_too_large += 1,
            Err(_other) => {
                return PumpResult {
                    forwarded,
                    dropped_too_large,
                    direction,
                };
            }
        }
    }
}
