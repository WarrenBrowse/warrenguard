//! Multi-hop entry pump for an accepted browser WebTransport session.
//!
//! Once [`crate::serve_edge_session`] has written the `:status 200` accept, the
//! browser tunnels the Warren circuit inside the WebTransport session. This
//! module bridges that session onto the exit exactly as a Warren relay does,
//! with one translation layer: the browser speaks WebTransport framing
//! (draft-ietf-webtrans-http3), the exit speaks the native Warren wire (raw
//! `WarrenMultihopFrame` on a bidi setup stream, raw QUIC datagrams for DATA).
//!
//! # What the pump does
//!
//! 1. Accept the browser's WebTransport **bidi setup stream** (a fresh HTTP/3
//!    bidi stream opened after the CONNECT), strip its WebTransport stream
//!    header ([`warrenguard_edge::read_bidi_stream_header`]), and read the one
//!    finish-delimited [`WarrenMultihopFrame`] it carries. The cleartext
//!    `exit_id` in that frame selects the exit.
//! 2. Dial that exit (the caller supplies the dialer, so the node decides its
//!    own routing/pool policy) and shuttle the verbatim setup bytes to it on a
//!    fresh relay->exit bidi stream, writing the exit's reply back onto the
//!    browser's WebTransport setup stream.
//! 3. Pump DATA bidirectionally until either side closes: browser
//!    WebTransport datagrams (Quarter-Stream-ID prefixed) have the prefix
//!    stripped and the raw payload is sent to the exit as a plain QUIC
//!    datagram; the exit's plain QUIC datagrams are re-prefixed and sent to the
//!    browser as WebTransport datagrams.
//!
//! Like the relay, the edge never decrypts: the only field it reads is the
//! cleartext `exit_id`. Everything else is opaque HPKE ciphertext pumped across.
//!
//! # Validation
//!
//! This is loopback-validated over real QUIC (a synthetic WebTransport client
//! and a fake exit, see the crate integration tests): the "necessary" datapath
//! tier. Real end-to-end validation needs the browser-side Warren WebTransport
//! client (the extension edge-CONNECT tier), which does not exist yet, so the
//! pump is NOT mounted on a production exit until that closes the loop.

use std::future::Future;

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use warrenguard_edge::{encode_wt_datagram, quarter_stream_id, read_bidi_stream_header};
use warrenguard_multihop::{ExitId, WarrenMultihopFrame};

/// Upper bound on the WebTransport setup stream (its WebTransport header plus
/// one [`WarrenMultihopFrame`]). Mirrors the relay's
/// `MAX_MULTIHOP_SETUP_FRAME_BYTES`, with slack for the small WebTransport
/// stream header, and strictly bounds what a hostile peer can buffer.
const MAX_SETUP_STREAM_BYTES: usize = 64 * 1024 + 16;

/// Deadline for a pre-DATA-pump phase, tighter than the QUIC idle timeout so a
/// slowloris cannot pin a session slot. Shared (via `pub(crate)`) with
/// `lib.rs`'s `run_handshake_bounded`, which applies the SAME bound to the
/// earlier WebTransport handshake phase (control-stream SETTINGS through
/// CONNECT established): each pre-pump phase is independently bounded, and
/// the long-lived DATA pump that follows either one is deliberately
/// unbounded.
pub(crate) const SETUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Errors from running the multi-hop entry pump. Coarse and value-free (no
/// peer bytes, no `exit_id`, no ciphertext) so they are safe to log.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PumpError {
    /// A QUIC stream operation on the browser or exit connection failed.
    #[error("QUIC stream error")]
    Stream,
    /// The browser's setup stream did not carry a valid WebTransport stream
    /// header followed by a decodable `WarrenMultihopFrame`.
    #[error("malformed WebTransport setup stream")]
    MalformedSetup,
    /// The caller's dialer could not reach the exit selected by the frame.
    #[error("exit dial failed")]
    ExitDial,
    /// Shuttling the setup round-trip to the exit failed (open/write/read on
    /// the relay->exit stream, or writing the reply back to the browser).
    #[error("setup shuttle failed")]
    Shuttle,
}

/// Counters returned once both DATA directions have stopped. Used by tests to
/// assert the pump forwarded losslessly and by a future metrics layer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PumpSummary {
    /// WebTransport datagrams forwarded browser -> exit (prefix stripped).
    pub browser_to_exit: u64,
    /// QUIC datagrams forwarded exit -> browser (prefix added).
    pub exit_to_browser: u64,
}

/// Runs the multi-hop entry pump for one accepted WebTransport session.
///
/// `connect_send`/`connect_recv` are the CONNECT request stream halves: the
/// pump only holds them open (dropping them resets the stream and tears the
/// WebTransport session down), it does not read or write them. `dial_exit` is
/// invoked with the `exit_id` parsed from the browser's setup frame and must
/// return a live QUIC connection to that exit.
///
/// Returns when either the browser or the exit closes; the session's
/// connections are the caller's to close.
///
/// # Errors
/// [`PumpError`] on a stream failure, a malformed setup stream, a failed exit
/// dial, or a failed setup shuttle. A DATA-phase transport close is a normal
/// end, not an error.
pub async fn pump_multihop_entry<F, Fut>(
    browser: &Connection,
    connect_send: SendStream,
    connect_recv: RecvStream,
    dial_exit: F,
) -> Result<PumpSummary, PumpError>
where
    F: FnOnce(ExitId) -> Fut,
    Fut: Future<Output = Result<Connection, PumpError>>,
{
    // The Quarter-Stream-ID that prefixes every WebTransport datagram for this
    // session is derived from the CONNECT request stream's id.
    let session_id = u64::from(connect_recv.id());
    // Keep the CONNECT stream halves alive for the whole session: a reset here
    // is an ERR_QUIC_PROTOCOL_ERROR that tears the session down.
    let _connect = (connect_send, connect_recv);

    // Steps 1-2 (setup stream, exit dial, shuttle) under a deadline so a
    // slowloris cannot hold a session slot; step 3 (DATA) then runs unbounded.
    let exit = tokio::time::timeout(SETUP_DEADLINE, async {
        let (mut browser_setup_send, mut browser_setup_recv) =
            browser.accept_bi().await.map_err(|_| PumpError::Stream)?;
        let raw = browser_setup_recv
            .read_to_end(MAX_SETUP_STREAM_BYTES)
            .await
            .map_err(|_| PumpError::Stream)?;
        let (session_of_stream, setup_bytes) =
            read_bidi_stream_header(&raw).ok_or(PumpError::MalformedSetup)?;
        if session_of_stream != session_id {
            return Err(PumpError::MalformedSetup);
        }
        let frame =
            WarrenMultihopFrame::decode(setup_bytes).map_err(|_| PumpError::MalformedSetup)?;
        let exit = dial_exit(frame.exit_id).await?;
        shuttle_setup(&exit, setup_bytes, &mut browser_setup_send).await?;
        Ok::<Connection, PumpError>(exit)
    })
    .await
    .map_err(|_| PumpError::MalformedSetup)??;

    let summary = pump_datagrams(browser, &exit, session_id).await;
    Ok(summary)
}

/// Opens a fresh bidi stream to the exit, writes the verbatim `setup_bytes`
/// (the raw `WarrenMultihopFrame`, without the WebTransport stream header) and
/// finishes it, reads the exit's reply frame to its finish, then writes that
/// reply back onto the browser's WebTransport setup stream and finishes it.
async fn shuttle_setup(
    exit: &Connection,
    setup_bytes: &[u8],
    browser_setup_send: &mut SendStream,
) -> Result<(), PumpError> {
    let (mut exit_send, mut exit_recv) = exit.open_bi().await.map_err(|_| PumpError::Shuttle)?;
    exit_send
        .write_all(setup_bytes)
        .await
        .map_err(|_| PumpError::Shuttle)?;
    exit_send.finish().map_err(|_| PumpError::Shuttle)?;
    let reply = exit_recv
        .read_to_end(MAX_SETUP_STREAM_BYTES)
        .await
        .map_err(|_| PumpError::Shuttle)?;
    browser_setup_send
        .write_all(&reply)
        .await
        .map_err(|_| PumpError::Shuttle)?;
    browser_setup_send
        .finish()
        .map_err(|_| PumpError::Shuttle)?;
    Ok(())
}

/// Bidirectional DATA pump with the WebTransport datagram translation. Runs
/// until either connection stops delivering datagrams, then returns the
/// per-direction counts. Never fails: a transport close is a normal end.
///
/// Each direction runs on its own task (owning cheap `Connection` clones); the
/// FIRST to finish closes both connections so the twin task's blocked
/// `read_datagram` unblocks and cannot hang the session. This mirrors the
/// relay's `forward_session` shutdown discipline.
async fn pump_datagrams(browser: &Connection, exit: &Connection, session_id: u64) -> PumpSummary {
    let expected_qsid = quarter_stream_id(session_id);
    let mut set = tokio::task::JoinSet::new();

    {
        let browser = browser.clone();
        let exit = exit.clone();
        set.spawn(async move {
            let mut n = 0u64;
            loop {
                let Ok(dgram) = browser.read_datagram().await else {
                    break;
                };
                // Strip the Quarter-Stream-ID prefix; drop datagrams that do
                // not reference this session (defensive; a browser sends only
                // ours).
                let Some((qsid, payload)) = warrenguard_edge::read_wt_datagram(&dgram) else {
                    continue;
                };
                if qsid != expected_qsid {
                    continue;
                }
                // `payload` is a suffix of `dgram` (see `read_wt_datagram`):
                // `slice_ref` reconstructs the sub-`Bytes` by pointer/range
                // arithmetic, no copy, unlike `copy_from_slice`.
                if exit.send_datagram(dgram.slice_ref(payload)).is_err() {
                    break;
                }
                n += 1;
            }
            (Direction::BrowserToExit, n)
        });
    }
    {
        let browser = browser.clone();
        let exit = exit.clone();
        set.spawn(async move {
            let mut n = 0u64;
            loop {
                let Ok(dgram) = exit.read_datagram().await else {
                    break;
                };
                let wt = encode_wt_datagram(session_id, &dgram);
                if browser.send_datagram(Bytes::from(wt)).is_err() {
                    break;
                }
                n += 1;
            }
            (Direction::ExitToBrowser, n)
        });
    }

    let mut summary = PumpSummary::default();
    while let Some(joined) = set.join_next().await {
        if let Ok((dir, n)) = joined {
            match dir {
                Direction::BrowserToExit => summary.browser_to_exit = n,
                Direction::ExitToBrowser => summary.exit_to_browser = n,
            }
        }
        // The first direction to stop ends the session: close both so the twin
        // task's blocked read unblocks and the loop drains its count too.
        browser.close(VarInt::from_u32(0), b"pump complete");
        exit.close(VarInt::from_u32(0), b"pump complete");
    }
    summary
}

#[derive(Clone, Copy)]
enum Direction {
    BrowserToExit,
    ExitToBrowser,
}
