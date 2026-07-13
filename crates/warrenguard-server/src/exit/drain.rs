//! Exit drain signalling for the single-hop datapath.
//!
//! A deployer's control-plane marks the exit as draining for planned
//! maintenance by publishing an [`ExitDrainSignal`] on the `watch` channel
//! wired through `ExitBindOpts::drain_rx`. Two effects:
//!
//! - **Admission gate** (handshake path): while the signal is active, NEW
//!   authenticated handshakes are refused with
//!   [`WARREN_EXIT_DRAINING`], so a client reconnecting to a draining exit
//!   fails fast and re-selects another exit instead of landing on a node
//!   about to go away. Established sessions are NOT touched by the gate.
//! - **Per-connection emitter** (this module): every live connection gets an
//!   in-band `WarrenControlMessage::ExitDraining` control datagram (first
//!   byte `0xC0`, never a valid IP version nibble, so a client that does not
//!   decode control frames drops it harmlessly), re-emitted every
//!   [`DRAIN_REEMIT_INTERVAL`] until the deadline because QUIC datagrams are
//!   unreliable. At the deadline the connection is hard-closed with
//!   [`WARREN_EXIT_DRAINING`] as a backstop for a client that did not
//!   migrate. Withdrawing the signal (`Some` -> `None`, a cancelled
//!   maintenance) stops the emitter WITHOUT closing.
//!
//! This is the single-hop mirror of the multi-hop drain emitter that the
//! exit-hop termination path runs (there the advisory is HPKE-sealed; here
//! the QUIC TLS session already covers it, so the control frame is sent as a
//! plain datagram).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quinn::{Connection, SendDatagramError};
use tokio::sync::watch;
use warrenguard_multihop::{WarrenControlMessage, encode_control};
use warrenguard_transport_core::constants::{WARREN_EXIT_DRAINING, WARREN_EXIT_DRAINING_REASON};

/// A drain directive broadcast to the exit's data-plane: the exit is going
/// away for maintenance, clients should migrate before
/// `deadline_unix_secs`. Published by the deployer's control-plane on the
/// watch channel in `ExitBindOpts::drain_rx`; `None` means not draining.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitDrainSignal {
    /// Unix seconds after which a still-attached connection is hard-closed
    /// with [`WARREN_EXIT_DRAINING`]. Carried verbatim to the client so it
    /// can schedule its own jittered migration before then.
    pub deadline_unix_secs: u64,
    /// Opaque reason carried verbatim to the client (0 = scheduled
    /// maintenance). Never a destination hint (anti-herding: the client
    /// re-selects only from its signed relay list).
    pub reason_code: u8,
}

/// How often each connection re-sends its `ExitDraining` advisory until the
/// deadline. QUIC datagrams are unreliable, so a single emit can be lost;
/// re-emitting every few seconds bounds the worst-case notice a client
/// loses to one interval, at a negligible bandwidth cost.
const DRAIN_REEMIT_INTERVAL: Duration = Duration::from_secs(3);

/// Current wall-clock as unix seconds, saturating to 0 before the epoch
/// (never in practice). Compared against the absolute drain deadline.
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether the exit is currently draining (admission-gate predicate).
/// `None` receiver (no drain wired: bench/standalone deployments) is never
/// draining.
pub(crate) fn is_draining(drain_rx: Option<&watch::Receiver<Option<ExitDrainSignal>>>) -> bool {
    drain_rx.is_some_and(|rx| rx.borrow().is_some())
}

/// Spawn the per-connection drain emitter (see the module docs).
///
/// Parks on `drain_rx` until a signal is published, then encodes ONE
/// `ExitDraining` control frame and sends it as a plain QUIC datagram,
/// re-emitting every [`DRAIN_REEMIT_INTERVAL`] until the deadline, at which
/// point it hard-closes the connection with [`WARREN_EXIT_DRAINING`]. A
/// republished signal with a different deadline/reason re-arms the emitter
/// (operator extends the window); a withdrawal returns without closing.
///
/// Returns `None` when no `drain_rx` is wired, so callers can skip the
/// abort bookkeeping. The caller MUST abort the returned task once the
/// connection's pump ends: the watch sender lives for the process lifetime,
/// so a parked emitter would otherwise leak per closed connection.
pub(crate) fn spawn_drain_emitter(
    drain_rx: Option<watch::Receiver<Option<ExitDrainSignal>>>,
    conn: Connection,
) -> Option<tokio::task::JoinHandle<()>> {
    let mut drain_rx = drain_rx?;
    Some(tokio::spawn(async move {
        let encode_adv = |sig: ExitDrainSignal| {
            encode_control(&WarrenControlMessage::ExitDraining {
                deadline_unix_secs: sig.deadline_unix_secs,
                reason_code: sig.reason_code,
            })
        };
        // Park until a signal is published. `borrow_and_update` marks the
        // current value seen so the next `changed()` only fires on a genuine
        // transition. A connection admitted mid-drain (never on this exit:
        // the admission gate refuses those; but a gate-less deployer may
        // admit) reads `Some` immediately and emits right away.
        let mut signal = loop {
            if let Some(sig) = *drain_rx.borrow_and_update() {
                break sig;
            }
            if drain_rx.changed().await.is_err() {
                return; // exit shutting down: sender dropped.
            }
        };
        let mut frame = match encode_adv(signal) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "drain: failed to encode ExitDraining; no soft signal");
                return;
            }
        };
        loop {
            match conn.send_datagram(frame.clone().into()) {
                // Best-effort: a transient PMTU dip can make even a tiny
                // control frame momentarily TooLarge; the next re-emit
                // retries. A hard send error means the conn is gone: stop.
                Ok(()) | Err(SendDatagramError::TooLarge) => {}
                Err(_) => return,
            }
            let now = unix_now_secs();
            if now >= signal.deadline_unix_secs {
                break;
            }
            let remaining = Duration::from_secs(signal.deadline_unix_secs - now);
            let nap = DRAIN_REEMIT_INTERVAL.min(remaining);
            tokio::select! {
                _ = tokio::time::sleep(nap) => {}
                changed = drain_rx.changed() => {
                    if changed.is_err() {
                        return; // sender dropped (exit shutdown).
                    }
                    match *drain_rx.borrow_and_update() {
                        // Undrain (cancelled maintenance): do NOT hard-close.
                        None => return,
                        // Republished with a changed deadline/reason (the
                        // operator EXTENDS the window): re-arm so the
                        // hard-close honours the latest deadline instead of
                        // firing at the stale one.
                        Some(new_sig) if new_sig != signal => {
                            signal = new_sig;
                            match encode_adv(signal) {
                                Ok(f) => frame = f,
                                Err(e) => {
                                    tracing::warn!(error = %e, "drain: re-encode failed");
                                    return;
                                }
                            }
                        }
                        // Same signal republished: keep going unchanged.
                        Some(_) => {}
                    }
                }
            }
        }
        // Deadline reached: backstop hard-close. The client should already
        // have migrated off the soft advisory; this only catches stragglers.
        conn.close(WARREN_EXIT_DRAINING, WARREN_EXIT_DRAINING_REASON);
    }))
}
