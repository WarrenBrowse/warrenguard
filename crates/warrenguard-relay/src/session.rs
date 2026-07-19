//! Client session handler: extracts the routing `exit_id` from the
//! first applicative frame and resolves it against the relay's exit
//! pool.
//!
//! The setup frame arrives on a **reliable bidi QUIC stream** (the
//! client opens it, writes one finish-delimited
//! [`WarrenMultihopFrame`], and waits for the reply on the same
//! stream). On a real network path the first QUIC datagram is
//! frequently lost, so the HPKE setup is carried on a reliable stream
//! rather than a datagram. DATA still flows over datagrams via
//! [`crate::forward::forward_session`].
//!
//! The relay never decrypts the HPKE ciphertext; the only field it
//! reads is the cleartext `exit_id`, carried at the same wire position in
//! both the postcard-encoded [`WarrenMultihopFrame`] (`/v1`) and its
//! post-quantum X-Wing sibling [`WarrenMultihopFrameV2`] (`/v2`). If decoding
//! or pool lookup fails, the connection is closed with one of the explicit
//! `WARREN_VARINT_*` application error codes documented below. The setup
//! bytes are returned to the caller alongside the matched descriptor and the
//! client-facing stream's send half: the caller shuttles those bytes to the
//! exit on a fresh relay→exit stream and writes the exit's reply back onto
//! the send half (cf. [`shuttle_setup_to_exit`]).
//!
//! The relay is version-agnostic about the setup frame: it routes both
//! `/v1` and `/v2` (post-quantum X-Wing) frames, since it only ever reads
//! the cleartext `exit_id` and never decrypts the HPKE payload (the
//! `decode_dispatch_exit_id` cascade below; see also
//! `docs/90-PQ-HPKE-XWING.md`).

use std::sync::Arc;

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use thiserror::Error;
use warrenguard_multihop::{ExitId, MultihopError, WarrenMultihopFrame, WarrenMultihopFrameV2};

use crate::config::{ExitDescriptorSigned, RelayConfig};

/// Upper bound on a single multi-hop setup-stream message
/// (`read_to_end` cap on both the client→relay and relay→exit legs).
/// The setup frame is one HPKE-sealed [`WarrenMultihopFrame`] of a few
/// hundred bytes; 64 KiB is generous but strictly bounds the memory a
/// hostile peer can force the relay to buffer on a setup stream. Mirror
/// of the client's `MAX_MULTIHOP_SETUP_FRAME_BYTES`.
pub const MAX_MULTIHOP_SETUP_FRAME_BYTES: usize = 64 * 1024;

/// QUIC application close code applied when the first datagram cannot
/// be decoded as a `/v1` [`WarrenMultihopFrame`] or `/v2`
/// [`WarrenMultihopFrameV2`] (malformed bytes, version byte rejection,
/// postcard overflow). Picked from the upper range of `VarInt` so it does
/// not collide with HTTP/3 error codes.
pub const WARREN_VARINT_INVALID_FRAME: u64 = 0x4577;

/// QUIC application close code applied when the first datagram's
/// `exit_id` does not match any descriptor in the relay's pool.
pub const WARREN_VARINT_UNKNOWN_EXIT: u64 = 0x4578;

/// QUIC application close code applied when the client never opened the
/// setup stream (or opened it but closed before sending the setup
/// frame), or the underlying connection died while waiting.
pub const WARREN_VARINT_NO_FIRST_DATAGRAM: u64 = 0x4579;

/// Errors emitted by [`extract_dispatched_exit`]. Each variant maps to
/// a dedicated close code so an external operator can correlate logs
/// with wireshark traces of the QUIC CONNECTION_CLOSE frame.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The client never opened the setup stream or never sent the setup
    /// frame, or the QUIC connection died while waiting.
    #[error("client never sent a setup frame: {0}")]
    NoFirstDatagram(quinn::ConnectionError),
    /// Reading the setup frame off the client's bidi stream failed
    /// (peer reset the stream, oversize beyond the cap, connection
    /// lost).
    #[error("reading setup stream failed: {0}")]
    SetupStreamRead(String),
    /// The setup bytes failed to decode as either a `/v1`
    /// [`WarrenMultihopFrame`] or a `/v2` [`WarrenMultihopFrameV2`].
    #[error("setup frame does not decode as a /v1 or /v2 multihop frame: {0}")]
    DecodeFailed(#[from] MultihopError),
    /// The `exit_id` carried by the setup frame does not match any
    /// signed entry in the relay's pool. The id is truncated in the
    /// rendered message so a future `tracing` site that formats this
    /// error cannot leak the full routing tag of an unrecognised peer.
    #[error("setup frame targets unknown exit_id {}", truncate_exit_id(.0))]
    UnknownExitId(ExitId),
    /// Writing the exit's reply back onto the client setup stream, or
    /// the relay→exit setup shuttle, failed.
    #[error("setup stream shuttle {context}: {detail}")]
    SetupStreamShuttle {
        /// Which shuttle step failed.
        context: &'static str,
        /// Underlying Quinn error rendered as text.
        detail: String,
    },
    /// The client kept the connection alive but did not complete the
    /// setup exchange before the deadline (slowloris guard, cf.
    /// [`extract_dispatched_exit_with_deadline`]).
    #[error("client did not complete setup within {0:?}")]
    SetupTimeout(std::time::Duration),
}

/// Renders an [`ExitId`] as its first 8 hex chars followed by an
/// ellipsis, e.g. `deadbeef...`. Used by
/// [`SessionError::UnknownExitId`]'s `Display` so an unrecognised
/// routing tag is never logged in full.
fn truncate_exit_id(exit_id: &ExitId) -> String {
    let hex = exit_id.to_hex();
    let head: String = hex.chars().take(8).collect();
    format!("{head}...")
}

/// Outcome of a successful setup-frame inspection: the matched
/// descriptor, the raw setup bytes the relay must shuttle to the exit,
/// and the send half of the client-facing stream onto which the relay
/// writes the exit's reply (cf. [`shuttle_setup_to_exit`]).
#[derive(Debug)]
pub struct DispatchedExit {
    /// Pool entry resolved from the cleartext `exit_id` field.
    pub descriptor: ExitDescriptorSigned,
    /// Verbatim setup-frame bytes. The relay shuttles these to the
    /// exit on a fresh relay→exit stream so the exit sees an intact
    /// HPKE setup frame.
    pub initial_frame_bytes: Bytes,
    /// Send half of the client-facing setup stream. The relay writes
    /// the exit's reply frame here (then finishes the stream) once the
    /// relay→exit shuttle has produced it.
    pub client_setup_send: SendStream,
}

/// Reads the routing `exit_id` from a dispatch frame, trying `/v1`
/// (`WarrenMultihopFrame`) then falling back to `/v2`
/// (`WarrenMultihopFrameV2`, the post-quantum X-Wing seal). The relay only
/// needs the cleartext `exit_id`; it never decrypts, so routing either wire
/// version is safe. The `/v1` decode error is returned if neither parses.
fn decode_dispatch_exit_id(bytes: &[u8]) -> Result<ExitId, MultihopError> {
    match WarrenMultihopFrame::decode(bytes) {
        Ok(frame) => Ok(frame.exit_id),
        Err(v1_err) => match WarrenMultihopFrameV2::decode(bytes) {
            Ok(frame) => Ok(frame.exit_id),
            Err(_v2_err) => Err(v1_err),
        },
    }
}

/// Accept the client's setup bidi stream, read the finish-delimited
/// setup frame, and decode its cleartext `exit_id` for routing. Closes
/// `conn` with the matching `WARREN_VARINT_*` code on any stream or
/// decode failure.
///
/// Returns the stream's send half (for the reply), the verbatim setup
/// bytes, and the routing `exit_id`. The caller decides what to do with
/// the tag: a pure relay forwards it to the matching pool exit (see
/// [`extract_dispatched_exit`]); a dual-role node's unified dispatcher
/// first checks whether the tag is its own `exit_id` and, if so,
/// terminates the connection locally instead of dialing (which would
/// otherwise loop back onto its own `:443` listener).
///
/// # Errors
/// - [`SessionError::NoFirstDatagram`] if the client never opens the
///   stream or the connection dies while waiting.
/// - [`SessionError::SetupStreamRead`] if reading the stream to its
///   finish fails.
/// - [`SessionError::DecodeFailed`] if the bytes are not a valid `/v1`
///   [`WarrenMultihopFrame`] or `/v2` [`WarrenMultihopFrameV2`].
pub async fn read_dispatch_frame(
    conn: &Connection,
) -> Result<(SendStream, Bytes, ExitId), SessionError> {
    let (send, mut recv) = match conn.accept_bi().await {
        Ok(pair) => pair,
        Err(source) => {
            // The connection is already dead; closing again is a no-op.
            conn.close(
                VarInt::from_u64(WARREN_VARINT_NO_FIRST_DATAGRAM).unwrap_or(VarInt::from_u32(0)),
                b"no setup stream",
            );
            return Err(SessionError::NoFirstDatagram(source));
        }
    };

    let bytes = match recv.read_to_end(MAX_MULTIHOP_SETUP_FRAME_BYTES).await {
        Ok(b) => Bytes::from(b),
        Err(e) => {
            conn.close(
                VarInt::from_u64(WARREN_VARINT_NO_FIRST_DATAGRAM).unwrap_or(VarInt::from_u32(0)),
                b"setup stream read failed",
            );
            return Err(SessionError::SetupStreamRead(e.to_string()));
        }
    };

    let exit_id = match decode_dispatch_exit_id(&bytes) {
        Ok(id) => id,
        Err(source) => {
            conn.close(
                VarInt::from_u64(WARREN_VARINT_INVALID_FRAME).unwrap_or(VarInt::from_u32(0)),
                b"malformed setup frame",
            );
            return Err(SessionError::DecodeFailed(source));
        }
    };

    Ok((send, bytes, exit_id))
}

/// Outcome of [`read_dispatch_frame_or_unauth`]: the non-closing variant of
/// [`read_dispatch_frame`] that lets the caller divert a non-Warren peer to an
/// active-probe decoy instead of revealing Warren behaviour by
/// closing the connection with a Warren-specific code.
#[derive(Debug)]
pub enum DispatchFrame {
    /// The peer opened the setup stream and sent a well-formed
    /// [`WarrenMultihopFrame`]: this is an authentic Warren client. Carries
    /// the stream's send half (for the reply), the verbatim setup bytes (to
    /// shuttle to the exit), and the routing `exit_id`.
    Routed {
        /// Send half of the client's setup stream.
        send: SendStream,
        /// Verbatim setup-frame bytes.
        bytes: Bytes,
        /// Cleartext routing tag parsed from the frame.
        exit_id: ExitId,
    },
    /// The peer completed the QUIC + TLS handshake and opened a bidi stream,
    /// but the first stream did NOT carry a decodable `WarrenMultihopFrame`
    /// (e.g. an HTTP/3 request from an active prober that reached the cover
    /// domain). The connection is left OPEN and the consumed stream's send
    /// half plus the bytes already read are handed back so the caller can
    /// serve a decoy. The caller MUST close or hand off; this function does
    /// not.
    Unauthenticated {
        /// Send half of the peer's first bidi stream.
        send: SendStream,
        /// Bytes already read off that stream (the prober's request).
        bytes: Bytes,
    },
    /// The peer never opened a usable setup stream (it stayed silent, or the
    /// connection died, or the stream broke mid-read). There is nothing to
    /// route and nothing a decoy could answer; the caller closes.
    NoStream,
}

/// Non-closing sibling of [`read_dispatch_frame`]. Accepts the peer's first
/// bidi stream and tries to decode a `/v1` or `/v2` dispatch frame (see
/// [`decode_dispatch_exit_id`]), but NEVER closes `conn` and emits no
/// Warren-specific application close code. This is the seam the unified
/// dual-role dispatcher uses so a connection that completed the WebPKI
/// handshake against the cover certificate but is not a Warren client
/// (an active prober) can be handed to a decoy that serves plausible HTTP/3,
/// instead of being abruptly closed - the tell that burns a cover domain.
///
/// The Warren-specific identity proof a node sends in X.509 cover-domain mode
/// is therefore emitted by the caller ONLY after this returns [`DispatchFrame::Routed`],
/// never to a peer that turns out to be a prober.
pub async fn read_dispatch_frame_or_unauth(conn: &Connection) -> DispatchFrame {
    let (send, mut recv) = match conn.accept_bi().await {
        Ok(pair) => pair,
        // No stream and no Warren-shaped signal sent: a bare prober or a dead
        // connection. Nothing to decoy; let the caller close.
        Err(_) => return DispatchFrame::NoStream,
    };

    let bytes = match recv.read_to_end(MAX_MULTIHOP_SETUP_FRAME_BYTES).await {
        Ok(b) => Bytes::from(b),
        Err(_) => return DispatchFrame::NoStream,
    };

    match decode_dispatch_exit_id(&bytes) {
        Ok(exit_id) => DispatchFrame::Routed {
            send,
            bytes,
            exit_id,
        },
        // Handshake completed and a stream arrived, but it is not Warren: a
        // decoy candidate. Hand the live stream + request bytes back unclosed.
        Err(_) => DispatchFrame::Unauthenticated { send, bytes },
    }
}

/// Awaits the client's setup stream on `conn` via [`read_dispatch_frame`]
/// and resolves the parsed `exit_id` against `config`. On an unknown
/// exit the connection is closed with `WARREN_VARINT_UNKNOWN_EXIT`.
///
/// Returns the matched descriptor, the verbatim setup bytes, and the
/// client stream's send half (for the reply write performed by
/// [`shuttle_setup_to_exit`]).
///
/// # Errors
/// - Any error from [`read_dispatch_frame`].
/// - [`SessionError::UnknownExitId`] if the parsed `exit_id` has no
///   matching pool entry.
pub async fn extract_dispatched_exit(
    conn: &Connection,
    config: &Arc<RelayConfig>,
) -> Result<DispatchedExit, SessionError> {
    let (send, bytes, exit_id) = read_dispatch_frame(conn).await?;

    let descriptor = match config.find_exit(&exit_id) {
        Some(d) => d.clone(),
        None => {
            conn.close(
                VarInt::from_u64(WARREN_VARINT_UNKNOWN_EXIT).unwrap_or(VarInt::from_u32(0)),
                b"unknown exit_id",
            );
            return Err(SessionError::UnknownExitId(exit_id));
        }
    };

    Ok(DispatchedExit {
        descriptor,
        initial_frame_bytes: bytes,
        client_setup_send: send,
    })
}

/// Deadline-bounded variant of [`extract_dispatched_exit`].
///
/// A hostile client can complete the QUIC handshake and then stay
/// silent forever; without a deadline, every such connection pins a
/// session slot (and, in the daemon, one of the bounded in-flight
/// permits) until the QUIC idle timeout - a cheap slowloris against
/// the relay's connection cap. On expiry the connection is closed with
/// [`WARREN_VARINT_NO_FIRST_DATAGRAM`] and the slot is released.
///
/// # Errors
/// Everything [`extract_dispatched_exit`] returns, plus
/// [`SessionError::SetupTimeout`] when `deadline` elapses first.
pub async fn extract_dispatched_exit_with_deadline(
    conn: &Connection,
    config: &Arc<RelayConfig>,
    deadline: std::time::Duration,
) -> Result<DispatchedExit, SessionError> {
    match tokio::time::timeout(deadline, extract_dispatched_exit(conn, config)).await {
        Ok(result) => result,
        Err(_elapsed) => {
            conn.close(
                VarInt::from_u64(WARREN_VARINT_NO_FIRST_DATAGRAM).unwrap_or(VarInt::from_u32(0)),
                b"setup timeout",
            );
            Err(SessionError::SetupTimeout(deadline))
        }
    }
}

/// Shuttles the setup round-trip across the relay→exit leg: opens a
/// fresh bidi stream to `exit_conn`, writes the verbatim
/// `setup_bytes` + finish, reads the exit's reply frame to its finish,
/// then writes that reply back onto `client_setup_send` + finish.
///
/// The relay forwards raw bytes in both directions; it never decrypts.
/// After this returns, both setup streams are finished and DATA flows
/// over datagrams via [`crate::forward::forward_session`].
///
/// # Errors
/// - [`SessionError::SetupStreamShuttle`] on any open/write/finish/read
///   failure on either the relay→exit stream or the client reply write, or
///   when the whole round-trip exceeds [`SETUP_SHUTTLE_TIMEOUT`].
pub async fn shuttle_setup_to_exit(
    exit_conn: &Connection,
    setup_bytes: &[u8],
    client_setup_send: SendStream,
) -> Result<(), SessionError> {
    shuttle_setup_to_exit_with_timeout(
        exit_conn,
        setup_bytes,
        client_setup_send,
        SETUP_SHUTTLE_TIMEOUT,
    )
    .await
}

/// Ceiling on the whole setup round-trip through the exit. The forward pumps
/// only start once the shuttle returns, so without a budget an exit that
/// accepts the stream but never finishes its reply holds the session in a
/// silent limbo: streams look alive, zero datagrams are ever pumped, and the
/// client sits "connected" with no traffic until its own idle timeout.
pub const SETUP_SHUTTLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// [`shuttle_setup_to_exit`] with an explicit `budget` (exposed for tests).
///
/// # Errors
/// Same as [`shuttle_setup_to_exit`], with the timeout read from `budget`.
pub async fn shuttle_setup_to_exit_with_timeout(
    exit_conn: &Connection,
    setup_bytes: &[u8],
    client_setup_send: SendStream,
    budget: std::time::Duration,
) -> Result<(), SessionError> {
    tokio::time::timeout(
        budget,
        shuttle_setup_to_exit_inner(exit_conn, setup_bytes, client_setup_send),
    )
    .await
    .map_err(|_| SessionError::SetupStreamShuttle {
        context: "setup shuttle timed out",
        detail: format!("budget {budget:?} exhausted"),
    })?
}

async fn shuttle_setup_to_exit_inner(
    exit_conn: &Connection,
    setup_bytes: &[u8],
    mut client_setup_send: SendStream,
) -> Result<(), SessionError> {
    let shuttle = |context: &'static str, detail: String| SessionError::SetupStreamShuttle {
        context,
        detail,
    };

    let (mut exit_send, mut exit_recv): (SendStream, RecvStream) = exit_conn
        .open_bi()
        .await
        .map_err(|e| shuttle("exit open_bi", e.to_string()))?;
    exit_send
        .write_all(setup_bytes)
        .await
        .map_err(|e| shuttle("exit write", e.to_string()))?;
    exit_send
        .finish()
        .map_err(|e| shuttle("exit finish", e.to_string()))?;
    let reply = exit_recv
        .read_to_end(MAX_MULTIHOP_SETUP_FRAME_BYTES)
        .await
        .map_err(|e| shuttle("exit read reply", e.to_string()))?;
    client_setup_send
        .write_all(&reply)
        .await
        .map_err(|e| shuttle("client write reply", e.to_string()))?;
    client_setup_send
        .finish()
        .map_err(|e| shuttle("client finish reply", e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_exit_id_display_is_truncated() {
        let exit_id = ExitId::from_bytes([
            0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc,
        ]);
        let rendered = SessionError::UnknownExitId(exit_id).to_string();
        assert!(
            rendered.contains("deadbeef..."),
            "Display must show the truncated head + ellipsis, got {rendered}"
        );
        assert!(
            !rendered.contains(&exit_id.to_hex()),
            "Display must NOT embed the full 32-char exit_id, got {rendered}"
        );
    }

    // ---- decode_dispatch_exit_id (/v1 and /v2 cascade) ----

    #[test]
    fn decode_dispatch_exit_id_reads_a_v1_frame() {
        use warrenguard_multihop::WARREN_HPKE_VERSION;
        let exit_id = ExitId::from_bytes([0x11; 16]);
        let frame = WarrenMultihopFrame {
            version: WARREN_HPKE_VERSION,
            exit_id,
            epoch: 0,
            seq: 0,
            encapsulated_key: [0xAA; 32],
            aead_tag: [0xBB; 16],
            ciphertext: vec![0xCC; 8],
        };
        let bytes = frame.encode().expect("encode");
        assert_eq!(decode_dispatch_exit_id(&bytes).expect("decode"), exit_id);
    }

    #[test]
    fn decode_dispatch_exit_id_reads_a_v2_setup_frame_with_full_pq_ct() {
        use warrenguard_multihop::WARREN_HPKE_VERSION_V2;
        let exit_id = ExitId::from_bytes([0x22; 16]);
        let frame = WarrenMultihopFrameV2 {
            version: WARREN_HPKE_VERSION_V2,
            exit_id,
            epoch: 0,
            seq: 0,
            encapsulated_key: [0xAA; 32],
            pq_ct: vec![0x05; 1088],
            aead_tag: [0xBB; 16],
            ciphertext: vec![0xCC; 8],
        };
        let bytes = frame.encode().expect("encode");
        assert_eq!(decode_dispatch_exit_id(&bytes).expect("decode"), exit_id);
    }

    /// A steady-state `/v2` data frame carries an empty `pq_ct` (the ML-KEM
    /// ciphertext is only re-sent on setup/rekey, cf. `wire_format_v2`'s
    /// module docs); the dispatch cascade must still resolve the `exit_id`
    /// from such a frame, since the relay routes every frame the client
    /// opens the setup stream with, not only the very first one.
    #[test]
    fn decode_dispatch_exit_id_reads_a_v2_frame_with_empty_pq_ct() {
        use warrenguard_multihop::WARREN_HPKE_VERSION_V2;
        let exit_id = ExitId::from_bytes([0x33; 16]);
        let frame = WarrenMultihopFrameV2 {
            version: WARREN_HPKE_VERSION_V2,
            exit_id,
            epoch: 1,
            seq: 42,
            encapsulated_key: [0xAA; 32],
            pq_ct: Vec::new(),
            aead_tag: [0xBB; 16],
            ciphertext: vec![0xCC; 8],
        };
        let bytes = frame.encode().expect("encode");
        assert_eq!(decode_dispatch_exit_id(&bytes).expect("decode"), exit_id);
    }

    #[test]
    fn decode_dispatch_exit_id_rejects_bytes_that_are_neither_v1_nor_v2() {
        let err = decode_dispatch_exit_id(b"not a multihop frame")
            .expect_err("garbage bytes must fail both /v1 and /v2 decode");
        // Just prove it renders (no panic) rather than pin the exact variant.
        let _ = format!("{err}");
    }
}
