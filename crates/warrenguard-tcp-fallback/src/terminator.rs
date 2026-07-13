//! Exit-side terminator: de-encapsulate a carrier stream and shuttle its QUIC
//! datagrams to the exit's local QUIC dispatcher.
//!
//! Each terminated connection gets a FRESH loopback UDP socket (an ephemeral
//! source port) connected to the dispatcher, so the dispatcher sees every
//! fallback client as a distinct 5-tuple, exactly as it would for a direct UDP
//! client. The terminator is a thin byte-shuttle: it never terminates the inner
//! QUIC TLS, so the exit's in-band auth and its QUIC-layer active-probe decoy
//! apply unchanged to anyone who reaches the dispatcher. [`serve_carrier`] adds
//! the hand-off for a peer that completes the outer TLS but is NOT a Warren
//! carrier (a plain-HTTPS prober), so it is served a decoy instead of hanging.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use warrenguard_tcp_carrier::{Deframer, LEN_PREFIX_BYTES, encode_frame};

use crate::READ_BUF;

/// Receive buffer for one QUIC datagram off the loopback dispatcher. One
/// path-MTU datagram is ~1350 bytes; sized generously so a jumbo datagram is
/// never truncated.
const DISPATCHER_RECV_BUF: usize = 2048;

/// Configuration for [`serve_carrier`].
#[derive(Debug, Clone)]
pub struct TerminatorConfig {
    /// Loopback address of the exit's QUIC dispatcher (its `:443` datapath
    /// socket) that de-encapsulated datagrams are shuttled to.
    pub dispatcher: SocketAddr,
    /// How long to wait for the first complete carrier frame before treating
    /// the connection as a non-carrier probe and handing it to the decoy.
    pub first_frame_timeout: Duration,
}

/// Terminates a carrier `stream` and shuttles its datagrams to `dispatcher`
/// over a fresh per-connection loopback UDP socket, until either side closes.
///
/// This is the pure shuttle with no decoy branch: use it when the caller has
/// already decided the peer is a carrier. It gives the 5-tuple isolation
/// property (a distinct ephemeral source port per call). For a public listener
/// that must also absorb active probes, use [`serve_carrier`].
///
/// # Errors
/// Binding or connecting the loopback UDP socket, or an I/O error on either
/// leg of the shuttle. A clean EOF on the stream returns `Ok(())`.
pub async fn terminate_carrier<S>(stream: S, dispatcher: SocketAddr) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let udp = Arc::new(bind_loopback_to(dispatcher).await?);
    let (read, write) = tokio::io::split(stream);
    run_shuttle(read, write, udp, Deframer::new(), None).await
}

/// Terminates a carrier `stream`, or hands it to `decoy` if it is not a Warren
/// carrier.
///
/// The peer completes the outer cover-domain TLS, then the terminator reads the
/// first carrier frame. If a complete frame arrives within
/// [`TerminatorConfig::first_frame_timeout`] and its first byte has the QUIC
/// long-header form (an Initial packet), the connection is shuttled to the
/// dispatcher (with the same per-connection 5-tuple isolation as
/// [`terminate_carrier`]). Otherwise (timeout, EOF, or a first frame that is not
/// a QUIC Initial), `decoy` is invoked with the stream and the raw bytes already
/// consumed, so it can serve a plausible response (or reverse-proxy them to a
/// real backend). This mirrors the exit's QUIC-layer decoy for the TCP path.
///
/// # Errors
/// I/O errors from the stream, the loopback UDP socket, or `decoy`.
pub async fn serve_carrier<S, D, F>(
    mut stream: S,
    config: &TerminatorConfig,
    decoy: D,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: FnOnce(S, Vec<u8>) -> F,
    F: Future<Output = io::Result<()>>,
{
    let mut deframer = Deframer::new();
    let mut consumed = Vec::new();
    let mut buf = vec![0u8; READ_BUF];

    let first = loop {
        match tokio::time::timeout(config.first_frame_timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break None,
            Ok(Ok(n)) => {
                consumed.extend_from_slice(&buf[..n]);
                deframer.push(&buf[..n]);
                if let Some(datagram) = deframer.next_datagram() {
                    break Some(datagram);
                }
            }
            Ok(Err(error)) => return Err(error),
            // No complete frame in time: not a carrier, serve the decoy.
            Err(_elapsed) => break None,
        }
    };

    let Some(first_datagram) = first else {
        return decoy(stream, consumed).await;
    };
    if !is_quic_long_header(&first_datagram) {
        return decoy(stream, consumed).await;
    }

    let udp = Arc::new(bind_loopback_to(config.dispatcher).await?);
    let (read, write) = tokio::io::split(stream);
    run_shuttle(read, write, udp, deframer, Some(first_datagram)).await
}

/// Whether a de-encapsulated datagram looks like a QUIC long-header packet (the
/// form of an Initial): high bit (long header) and the QUIC fixed bit both set.
///
/// This is a decoy discriminator only, not an authentication check: a Warren
/// client's first packet is always a QUIC Initial, so anything else is an active
/// probe that should get the decoy instead of a hang. Real client authentication
/// happens in-band at the QUIC layer, untouched by this heuristic.
fn is_quic_long_header(datagram: &[u8]) -> bool {
    matches!(datagram.first(), Some(byte) if byte & 0xc0 == 0xc0)
}

/// Binds a loopback UDP socket on an ephemeral port (the per-connection 5-tuple
/// isolation) and connects it to `dispatcher`.
async fn bind_loopback_to(dispatcher: SocketAddr) -> io::Result<UdpSocket> {
    let bind: SocketAddr = match dispatcher {
        SocketAddr::V4(_) => (Ipv4Addr::LOCALHOST, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::LOCALHOST, 0).into(),
    };
    let udp = UdpSocket::bind(bind).await?;
    udp.connect(dispatcher).await?;
    Ok(udp)
}

/// Runs the two shuttle legs until either finishes. `first` (if present) and any
/// datagrams already buffered in `deframer` are flushed to the dispatcher before
/// the uplink reads more from the stream.
async fn run_shuttle<R, W>(
    read: R,
    write: W,
    udp: Arc<UdpSocket>,
    deframer: Deframer,
    first: Option<Vec<u8>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::select! {
        result = pump_uplink(read, Arc::clone(&udp), deframer, first) => result,
        result = pump_downlink(write, udp) => result,
    }
}

/// Uplink leg: carrier stream -> dispatcher. Flushes `first` and any datagrams
/// already buffered in `deframer`, then reads and de-encapsulates until EOF.
async fn pump_uplink<R>(
    mut read: R,
    udp: Arc<UdpSocket>,
    mut deframer: Deframer,
    first: Option<Vec<u8>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    if let Some(datagram) = first {
        udp.send(&datagram).await?;
    }
    let mut buf = vec![0u8; READ_BUF];
    loop {
        while let Some(datagram) = deframer.next_datagram() {
            udp.send(&datagram).await?;
        }
        let n = read.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        deframer.push(&buf[..n]);
    }
}

/// Downlink leg: dispatcher -> carrier stream. Frames every datagram the
/// dispatcher sends back and writes it to the stream. Runs until a socket error
/// (including the peer closing, surfaced by the paired uplink ending the select).
async fn pump_downlink<W>(mut write: W, udp: Arc<UdpSocket>) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut datagram = vec![0u8; DISPATCHER_RECV_BUF];
    let mut framed = Vec::with_capacity(DISPATCHER_RECV_BUF + LEN_PREFIX_BYTES);
    loop {
        let n = udp.recv(&mut datagram).await?;
        framed.clear();
        encode_frame(&mut framed, &datagram[..n]).map_err(io::Error::other)?;
        write.write_all(&framed).await?;
        write.flush().await?;
    }
}
