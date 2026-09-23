//! The two tunnel pumps: a CONNECT stream to a TCP upstream, and a
//! CONNECT-UDP stream plus its HTTP Datagrams to a UDP socket.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use quinn::{RecvStream, SendStream, VarInt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use warrenguard_edge::{
    CAPSULE_DATAGRAM, CONNECT_UDP_CONTEXT_ID, decode_varint, encode_masque_datagram, read_frame,
};

use crate::connection::ConnState;
use crate::frames::{FrameError, FrameReader, MAX_CONTROL_FRAME_BYTES, data_frame_header};

/// HTTP/3 `H3_NO_ERROR` (RFC 9114 section 8.1): the code a server stops
/// reading a request with once its response is complete.
pub(crate) const H3_NO_ERROR: VarInt = VarInt::from_u32(0x100);
/// HTTP/3 `H3_INTERNAL_ERROR`.
pub(crate) const H3_INTERNAL_ERROR: VarInt = VarInt::from_u32(0x102);

/// How much upstream data is read per DATA frame written to the client.
const UPSTREAM_READ: usize = 64 * 1024;

/// Largest UDP payload the tunnel relays. A datagram the outer QUIC
/// connection cannot carry is dropped by the transport anyway.
const UDP_READ: usize = 64 * 1024;

/// Bytes of capsule stream a CONNECT-UDP peer may leave unparsed before the
/// tunnel is closed as malformed.
const MAX_CAPSULE_BUFFER: usize = MAX_CONTROL_FRAME_BYTES as usize;

/// Pipes a CONNECT stream and a TCP upstream into each other until both
/// directions have ended: the client's DATA frames become upstream bytes, and
/// upstream bytes become DATA frames. Each direction closes its own end (a
/// client finish shuts the upstream write half, an upstream EOF finishes the
/// stream), so a half-closed TCP connection keeps flowing the other way.
pub(crate) async fn pump_tcp<U>(mut send: SendStream, reader: FrameReader, upstream: U)
where
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut up_read, mut up_write) = tokio::io::split(upstream);
    let mut reader = reader;
    let client_to_upstream = async {
        loop {
            match reader.next_data().await {
                Ok(Some(chunk)) => {
                    if up_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = up_write.shutdown().await;
                    break;
                }
                Err(_) => break,
            }
        }
    };
    let upstream_to_client = async {
        let mut buf = BytesMut::with_capacity(UPSTREAM_READ);
        loop {
            buf.reserve(UPSTREAM_READ);
            match up_read.read_buf(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = send.finish();
                    break;
                }
                Ok(n) => {
                    let payload = buf.split().freeze();
                    let mut chunks = [data_frame_header(n), payload];
                    if send.write_all_chunks(&mut chunks).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    tokio::join!(client_to_upstream, upstream_to_client);
}

/// The HTTP Datagram route of one CONNECT-UDP stream: registered on
/// [`Self::open`], unregistered on drop.
///
/// It is opened before the tunnel's target is dialed. A client may send its
/// first datagrams right after the request (RFC 9298 section 5), and a
/// datagram for a stream with no route is dropped, so the route has to exist
/// before the 200 can reach the client; until the pump runs, the channel
/// holds what arrives.
pub(crate) struct UdpRoute {
    state: Arc<ConnState>,
    quarter_stream_id: u64,
    datagrams: mpsc::Receiver<Bytes>,
}

impl UdpRoute {
    pub(crate) fn open(state: &Arc<ConnState>, stream_id: u64) -> Self {
        let (tx, datagrams) = mpsc::channel::<Bytes>(256);
        let quarter_stream_id = stream_id >> 2;
        state.routes().register(quarter_stream_id, tx);
        Self {
            state: Arc::clone(state),
            quarter_stream_id,
            datagrams,
        }
    }
}

impl Drop for UdpRoute {
    fn drop(&mut self) {
        self.state.routes().unregister(self.quarter_stream_id);
    }
}

/// Relays a CONNECT-UDP tunnel: HTTP Datagrams for the request stream (and
/// DATAGRAM capsules on it) go to `socket`, and what the socket receives is
/// sent back as HTTP Datagrams, until the client ends the stream or the
/// connection is gone.
pub(crate) async fn pump_udp(
    state: Arc<ConnState>,
    stream_id: u64,
    mut send: SendStream,
    mut reader: FrameReader,
    socket: UdpSocket,
    mut route: UdpRoute,
) {
    let mut udp_buf = vec![0u8; UDP_READ];
    let mut capsules = CapsuleBuffer::default();
    loop {
        tokio::select! {
            from_client = route.datagrams.recv() => {
                let Some(payload) = from_client else { break };
                // A send failure (an ICMP unreachable surfacing) is the
                // destination's business, not a reason to end the tunnel.
                let _ = socket.send(&payload).await;
            }
            from_upstream = socket.recv(&mut udp_buf) => {
                let Ok(n) = from_upstream else { continue };
                let datagram = Bytes::from(encode_masque_datagram(stream_id, &udp_buf[..n]));
                if !state.send_datagram(datagram) {
                    break;
                }
            }
            on_stream = reader.next_data() => {
                match on_stream {
                    Ok(Some(chunk)) => {
                        if !capsules.push(&chunk, &socket).await {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
    drop(route);
    let _ = send.finish();
    let _ = reader.recv_mut().stop(H3_NO_ERROR);
}

/// Accumulates the capsule stream a CONNECT-UDP request carries in its DATA
/// frames and forwards DATAGRAM capsules on the UDP context to the socket.
#[derive(Default)]
struct CapsuleBuffer {
    buf: Vec<u8>,
}

impl CapsuleBuffer {
    /// Appends `chunk` and drains every complete capsule. Returns `false` when
    /// the peer's capsule stream is malformed or unbounded.
    async fn push(&mut self, chunk: &[u8], socket: &UdpSocket) -> bool {
        self.buf.extend_from_slice(chunk);
        loop {
            match read_frame(&self.buf) {
                Some((capsule, used)) => {
                    if capsule.ty == CAPSULE_DATAGRAM
                        && let Some((context_id, n)) = decode_varint(capsule.payload)
                        && context_id == CONNECT_UDP_CONTEXT_ID
                    {
                        let _ = socket.send(&capsule.payload[n..]).await;
                    }
                    self.buf.drain(..used);
                }
                None => return self.buf.len() <= MAX_CAPSULE_BUFFER,
            }
        }
    }
}

/// Writes a complete response on `send`, finishes it, and stops reading the
/// request: the shape of every answer that opens no tunnel.
pub(crate) async fn respond_and_close(
    send: &mut SendStream,
    recv: &mut RecvStream,
    response: &[u8],
) {
    // Value-free: the status alone, which names no destination and no peer.
    tracing::debug!(
        status = response_status(response),
        "masque: request answered without a tunnel"
    );
    let _ = send.write_all(response).await;
    let _ = send.finish();
    let _ = recv.stop(H3_NO_ERROR);
}

/// The `:status` of an encoded response, for the log line above; `0` when the
/// response is not a HEADERS frame this crate produced.
fn response_status(response: &[u8]) -> u16 {
    read_frame(response)
        .and_then(|(frame, _)| warrenguard_edge::decode_field_section(frame.payload).ok())
        .and_then(|fields| {
            fields
                .into_iter()
                .find(|f| f.name == b":status")
                .and_then(|f| core::str::from_utf8(&f.value).ok()?.parse().ok())
        })
        .unwrap_or(0)
}

/// Reports a frame-level failure on a request stream: the stream is reset so
/// the client sees an error rather than a hang.
pub(crate) fn abort(send: &mut SendStream, recv: &mut RecvStream, error: FrameError) {
    let code = match error {
        FrameError::Stream => H3_NO_ERROR,
        FrameError::Malformed => H3_INTERNAL_ERROR,
    };
    let _ = send.reset(code);
    let _ = recv.stop(code);
}
