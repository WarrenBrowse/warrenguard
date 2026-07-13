//! Client-side quinn [`AsyncUdpSocket`] over a single TLS-over-TCP stream.
//!
//! [`TcpCarrierSocket`] presents a normal abstract UDP socket to quinn while,
//! underneath, every outbound QUIC datagram is length-delimited into one byte
//! stream (the [`warrenguard_tcp_carrier`] framing) and every inbound datagram
//! is reassembled from it. quinn never learns it is not on UDP; the framing
//! lives inside the TLS session, so it adds no wire fingerprint.

use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use warrenguard_tcp_carrier::{Deframer, LEN_PREFIX_BYTES, encode_frame};

use crate::{CarrierError, READ_BUF};

/// Bound on datagrams buffered from the network before quinn drains them. It
/// caps memory under an inbound burst; the reader task awaits on a full channel,
/// which back-pressures onto the TCP read (the peer's congestion window then
/// bounds the flow).
const INBOUND_CAPACITY: usize = 4096;

/// Hard byte backstop on datagrams queued for the writer task but not yet
/// handed to the TCP write.
///
/// This is defense-in-depth, not the primary flow control: the primary
/// mechanism is QUIC's own congestion window, since an ACK only returns once
/// the peer's TCP stack has actually delivered the bytes, which already
/// throttles how fast quinn re-fills this queue (see [`try_send`]). But
/// nothing stops an inflated congestion window (e.g. a permissive or
/// misbehaving BBR exit) from growing an otherwise-unbounded queue to several
/// MB per connection. Sized generously above any realistic burst so it is
/// never hit in normal operation; a datagram enqueued past it is dropped
/// exactly as an ordinary UDP packet lost to a full send buffer would be
/// (recoverable by QUIC's own loss detection), not surfaced as a caller error.
const MAX_OUTBOUND_QUEUE_BYTES: usize = 8 * 1024 * 1024;

/// A quinn abstract UDP socket whose datagrams ride a single TLS-over-TCP
/// stream to the exit. Construct with [`TcpCarrierSocket::new`] over an
/// already-established stream (usually a [`tokio_rustls`] client TLS stream to
/// the cover domain), then hand it to [`build_carrier_client_endpoint`].
#[derive(Debug)]
pub struct TcpCarrierSocket {
    /// Synthetic peer address reported to quinn for every received datagram.
    /// It must equal the address the caller passes to `Endpoint::connect`, so
    /// quinn routes inbound packets to that connection's path.
    peer: SocketAddr,
    /// Synthetic local address (unspecified, same family as `peer`).
    local: SocketAddr,
    /// Framed outbound bytes queued for the writer task. Unbounded as a
    /// channel (quinn only enqueues as fast as QUIC congestion and flow
    /// control allow, so it self-limits in the common case), but
    /// [`MAX_OUTBOUND_QUEUE_BYTES`] caps it explicitly via `out_queued_bytes`
    /// as a backstop against an inflated congestion window.
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Running total of bytes currently sitting in `out_tx`'s channel, not yet
    /// picked up by the writer task. Checked against
    /// [`MAX_OUTBOUND_QUEUE_BYTES`] in `try_send`, decremented in
    /// `writer_loop` as soon as a batch is dequeued.
    out_queued_bytes: Arc<AtomicUsize>,
    /// Datagrams reassembled by the reader task, drained by `poll_recv`.
    in_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Reader + writer task handles, aborted on drop so a dropped socket does
    /// not leak the two background tasks (and its half of the TLS stream).
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl TcpCarrierSocket {
    /// Wraps an established bidirectional `stream` as a quinn abstract socket
    /// toward `peer` (the synthetic address reported to quinn and passed to
    /// `Endpoint::connect`). Spawns the reader and writer tasks that drive the
    /// stream; they are aborted when the returned socket is dropped.
    #[must_use]
    pub fn new<S>(stream: S, peer: SocketAddr) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CAPACITY);
        let out_queued_bytes = Arc::new(AtomicUsize::new(0));
        let writer = tokio::spawn(writer_loop(
            write_half,
            out_rx,
            Arc::clone(&out_queued_bytes),
        ));
        let reader = tokio::spawn(reader_loop(read_half, in_tx));
        Arc::new(Self {
            peer,
            local: unspecified_for(peer),
            out_tx,
            out_queued_bytes,
            in_rx: Mutex::new(in_rx),
            tasks: Mutex::new(vec![writer, reader]),
        })
    }
}

impl Drop for TcpCarrierSocket {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.tasks.lock() {
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
    }
}

impl AsyncUdpSocket for TcpCarrierSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // `try_send` never blocks and never returns `WouldBlock`: past
        // `MAX_OUTBOUND_QUEUE_BYTES` it drops the datagram and still reports
        // `Ok`, rather than making quinn spin retrying against a poller that
        // would have to track queue occupancy. The socket is therefore always
        // writable and quinn never needs to park on write-readiness.
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let mut framed = Vec::with_capacity(transmit.contents.len() + LEN_PREFIX_BYTES);
        match transmit.segment_size {
            // A GSO transmit packs several datagrams of `seg` bytes (the last
            // possibly shorter) back-to-back; frame each as its own carrier
            // datagram so the terminator re-splits them exactly.
            Some(seg) if seg > 0 => {
                for datagram in transmit.contents.chunks(seg) {
                    encode_frame(&mut framed, datagram).map_err(io::Error::other)?;
                }
            }
            _ => encode_frame(&mut framed, transmit.contents).map_err(io::Error::other)?,
        }

        let framed_len = framed.len();
        let queued_before = self
            .out_queued_bytes
            .fetch_add(framed_len, Ordering::Relaxed);
        if queued_before + framed_len > MAX_OUTBOUND_QUEUE_BYTES {
            // Over the backstop: drop this datagram instead of growing the
            // queue further. See `MAX_OUTBOUND_QUEUE_BYTES` for why `Ok(())`
            // (a silent drop) is the correct analogy here, not an error.
            self.out_queued_bytes
                .fetch_sub(framed_len, Ordering::Relaxed);
            tracing::warn!(
                queued_bytes = queued_before,
                len = framed_len,
                "dropping outbound carrier datagram: uplink queue backstop reached"
            );
            return Ok(());
        }

        self.out_tx.send(framed).map_err(|_| {
            self.out_queued_bytes
                .fetch_sub(framed_len, Ordering::Relaxed);
            io::Error::from(io::ErrorKind::BrokenPipe)
        })
    }

    /// Drains reassembled datagrams into `bufs`. A datagram larger than the
    /// caller's buffer is dropped whole (never truncated into `bufs`): see the
    /// inline comment on that branch for why a partial copy would be worse
    /// than a drop.
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self
            .in_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut count = 0;
        while count < bufs.len() {
            match rx.poll_recv(cx) {
                Poll::Ready(Some(datagram)) if datagram.len() > bufs[count].len() => {
                    // Never hand quinn a truncated datagram: a partial packet
                    // is not merely short, it is corrupt (a cut QUIC header or
                    // AEAD tag quinn would either misparse or fail to
                    // authenticate). The buffer is sized to the tunnel MTU, so
                    // an oversized datagram is out-of-contract; drop it whole
                    // and keep draining, same as a dropped UDP packet would be.
                    tracing::warn!(
                        len = datagram.len(),
                        buf_len = bufs[count].len(),
                        "dropping inbound carrier datagram larger than the receive buffer"
                    );
                }
                Poll::Ready(Some(datagram)) => {
                    let n = datagram.len();
                    bufs[count][..n].copy_from_slice(&datagram[..n]);
                    // RecvMeta is #[non_exhaustive]; fill the fields we own on a
                    // default (ecn / dst_ip / interface_index stay None).
                    let mut received = RecvMeta::default();
                    received.addr = self.peer;
                    received.len = n;
                    received.stride = n;
                    meta[count] = received;
                    count += 1;
                }
                // The stream closed (EOF or a dead task): the tunnel is gone.
                // Surface it as a reset so quinn tears the connection down
                // (fail-closed) rather than spinning on an empty socket.
                Poll::Ready(None) => {
                    if count == 0 {
                        return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
                    }
                    break;
                }
                Poll::Pending => {
                    if count == 0 {
                        return Poll::Pending;
                    }
                    break;
                }
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    // The carrier never fans a datagram across several UDP packets: TCP
    // delivers each framed datagram whole. One segment in, one datagram out.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    // Report "may fragment" so quinn keeps MTU discovery OFF (`allow_mtud =
    // !may_fragment`). The carrier has no path-MTU concept (any datagram up to
    // the u16 frame limit is delivered whole), so probing would be pointless;
    // the engine's fixed tunnel MTU governs the datagram size.
    fn may_fragment(&self) -> bool {
        true
    }
}

/// A [`UdpPoller`] that always reports writable, matching the unbounded
/// outbound queue: a send can never block, so there is nothing to wait for.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Drains framed datagrams from `out_rx` and writes them to the stream,
/// coalescing everything currently queued into one write + flush so a burst of
/// small datagrams is one syscall, not one per datagram. `queued_bytes` is
/// decremented by each batch's length as soon as it is dequeued, freeing that
/// much of [`MAX_OUTBOUND_QUEUE_BYTES`]'s budget for `try_send`.
async fn writer_loop<W>(
    mut write: W,
    mut out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    queued_bytes: Arc<AtomicUsize>,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(first) = out_rx.recv().await {
        let mut batch = first;
        while let Ok(more) = out_rx.try_recv() {
            batch.extend_from_slice(&more);
        }
        queued_bytes.fetch_sub(batch.len(), Ordering::Relaxed);
        if write.write_all(&batch).await.is_err() || write.flush().await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
}

/// Reads stream bytes, reassembles datagrams with a [`Deframer`], and forwards
/// each to `in_tx`. Ends on EOF or a read error; dropping `in_tx` closes the
/// inbound channel, which `poll_recv` surfaces as a connection reset.
async fn reader_loop<R>(mut read: R, in_tx: mpsc::Sender<Vec<u8>>)
where
    R: AsyncRead + Unpin,
{
    let mut deframer = Deframer::new();
    let mut buf = vec![0u8; READ_BUF];
    loop {
        match read.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                deframer.push(&buf[..n]);
                while let Some(datagram) = deframer.next_datagram() {
                    if in_tx.send(datagram).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// The unspecified address of `peer`'s family, used as the carrier's synthetic
/// local address (quinn reads it only for the v4/v6 discriminator).
fn unspecified_for(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    }
}

/// Builds a client quinn [`Endpoint`](quinn::Endpoint) whose datapath is the
/// TCP carrier `socket`, installing `client_config` as its default. The caller
/// then dials with `endpoint.connect(peer, inner_sni)`, where `peer` is the same
/// synthetic address the socket was constructed with and `inner_sni` is the
/// exit's QUIC server name (RPK-encoded pubkey or cover domain, per the QUIC
/// TLS mode). The outer cover-domain TLS is already terminated by `socket`.
///
/// # Errors
/// [`CarrierError::NoRuntime`] if no async runtime is active, or
/// [`CarrierError::Endpoint`] if quinn rejects the abstract socket.
pub fn build_carrier_client_endpoint(
    socket: Arc<TcpCarrierSocket>,
    client_config: quinn::ClientConfig,
) -> Result<quinn::Endpoint, CarrierError> {
    let runtime = quinn::default_runtime().ok_or(CarrierError::NoRuntime)?;
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        runtime,
    )
    .map_err(CarrierError::Endpoint)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn peer() -> SocketAddr {
        "127.0.0.1:443".parse().unwrap()
    }

    /// A single datagram is length-delimited as `u16 len || datagram` on the
    /// stream (the wire contract shared with the terminator).
    #[tokio::test]
    async fn try_send_frames_a_single_datagram() {
        let (carrier, mut observer) = tokio::io::duplex(64 * 1024);
        let socket = TcpCarrierSocket::new(carrier, peer());
        let contents = [0xAA, 0xBB, 0xCC];
        let transmit = Transmit {
            destination: peer(),
            ecn: None,
            contents: &contents,
            segment_size: None,
            src_ip: None,
        };
        socket.try_send(&transmit).expect("try_send enqueues");

        let mut got = vec![0u8; 5];
        tokio::time::timeout(Duration::from_secs(2), observer.read_exact(&mut got))
            .await
            .expect("framed bytes arrive")
            .expect("read ok");
        assert_eq!(got, vec![0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    /// A GSO transmit (several segments in one `contents`) is split into one
    /// carrier frame per segment, so the terminator re-splits them exactly.
    #[tokio::test]
    async fn try_send_frames_each_gso_segment_separately() {
        let (carrier, mut observer) = tokio::io::duplex(64 * 1024);
        let socket = TcpCarrierSocket::new(carrier, peer());
        let contents = [1u8, 2, 3, 4, 5, 6];
        let transmit = Transmit {
            destination: peer(),
            ecn: None,
            contents: &contents,
            segment_size: Some(3),
            src_ip: None,
        };
        socket.try_send(&transmit).expect("try_send enqueues");

        let mut got = vec![0u8; 10];
        tokio::time::timeout(Duration::from_secs(2), observer.read_exact(&mut got))
            .await
            .expect("framed bytes arrive")
            .expect("read ok");
        assert_eq!(
            got,
            vec![0x00, 0x03, 1, 2, 3, 0x00, 0x03, 4, 5, 6],
            "two 3-byte segments become two independent frames"
        );
    }

    #[test]
    fn synthetic_local_matches_peer_family() {
        let v4 = unspecified_for("127.0.0.1:443".parse().unwrap());
        assert!(v4.is_ipv4() && v4.ip().is_unspecified() && v4.port() == 0);
        let v6 = unspecified_for("[::1]:443".parse().unwrap());
        assert!(v6.is_ipv6() && v6.ip().is_unspecified() && v6.port() == 0);
    }

    /// A single receive buffer to drive `poll_recv` with in tests.
    fn one_buf(buf: &mut [u8]) -> ([IoSliceMut<'_>; 1], [RecvMeta; 1]) {
        ([IoSliceMut::new(buf)], [RecvMeta::default()])
    }

    /// The far end closing (EOF on the wire) must surface as a
    /// `ConnectionReset`, not a `Pending` that spins quinn forever on a dead
    /// tunnel: this is the fail-closed teardown path.
    #[tokio::test]
    async fn poll_recv_surfaces_connection_reset_when_the_far_end_closes() {
        let (carrier, observer) = tokio::io::duplex(64 * 1024);
        let socket = TcpCarrierSocket::new(carrier, peer());
        drop(observer); // the peer is gone: the reader task sees EOF

        let mut buf = [0u8; 16];
        let (mut bufs, mut meta) = one_buf(&mut buf);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("poll_recv must not hang on a closed carrier");
        let err = result.expect_err("a closed carrier must surface as a reset, not a success");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    /// An inbound datagram bigger than the caller's buffer must be dropped
    /// whole, never delivered as a truncated (corrupt) prefix.
    #[tokio::test]
    async fn poll_recv_drops_an_inbound_datagram_larger_than_the_buffer() {
        let (carrier, mut wire) = tokio::io::duplex(64 * 1024);
        let socket = TcpCarrierSocket::new(carrier, peer());

        let oversized = vec![0xEEu8; 32];
        let small = vec![0xAA, 0xBB, 0xCC];
        let mut framed = Vec::new();
        encode_frame(&mut framed, &oversized).expect("frame oversized");
        encode_frame(&mut framed, &small).expect("frame small");
        wire.write_all(&framed).await.expect("write both frames");

        let mut buf = [0u8; 8]; // smaller than `oversized`, larger than `small`
        let (mut bufs, mut meta) = one_buf(&mut buf);
        let n = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .expect("poll_recv completes")
        .expect("poll_recv ok");

        assert_eq!(n, 1, "only the small datagram is delivered");
        assert_eq!(
            &buf[..meta[0].len],
            &small[..],
            "delivered bytes are the small datagram verbatim, never a \
             truncated prefix of the oversized one"
        );
    }

    /// A stream whose writes always fail, standing in for a dead TCP/TLS
    /// connection: exercises `writer_loop`'s error branch, which must end the
    /// task (and drop its half of the queue) rather than loop forever.
    struct AlwaysErroringWriter;

    impl AsyncRead for AlwaysErroringWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for AlwaysErroringWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// After the writer task dies on a write error, the queue it owned is
    /// dropped and every subsequent `try_send` must fail closed
    /// (`BrokenPipe`), never silently swallow datagrams into a dead queue.
    #[tokio::test]
    async fn try_send_returns_broken_pipe_after_the_writer_task_dies() {
        let socket = TcpCarrierSocket::new(AlwaysErroringWriter, peer());
        let contents = [0xAAu8];
        let transmit = Transmit {
            destination: peer(),
            ecn: None,
            contents: &contents,
            segment_size: None,
            src_ip: None,
        };

        let err = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Err(err) = socket.try_send(&transmit) {
                    return err;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the writer task must die and close the queue promptly");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// If the writer task stalls forever (the wire never drains), the
    /// backstop must cap the tracked queue at `MAX_OUTBOUND_QUEUE_BYTES`
    /// rather than letting it grow without bound, and `try_send` must keep
    /// reporting `Ok` throughout (a dropped datagram is equivalent to
    /// ordinary packet loss, never a caller-visible error).
    #[tokio::test]
    async fn try_send_caps_the_uplink_queue_at_the_backstop() {
        // A tiny duplex whose far end is kept alive but never read: the
        // writer task's first write partially succeeds, then blocks forever
        // once the internal buffer fills, exactly like a stalled TCP peer.
        let (carrier, _never_drained) = tokio::io::duplex(64);
        let socket = TcpCarrierSocket::new(carrier, peer());

        let contents = vec![0xAAu8; 4096];
        let transmit = Transmit {
            destination: peer(),
            ecn: None,
            contents: &contents,
            segment_size: None,
            src_ip: None,
        };

        // Enqueue well past the backstop (total attempted bytes exceed
        // MAX_OUTBOUND_QUEUE_BYTES), so this only passes if the drop path
        // actually triggers.
        let attempts = MAX_OUTBOUND_QUEUE_BYTES / contents.len() + 8;
        for _ in 0..attempts {
            socket
                .try_send(&transmit)
                .expect("try_send never errors when the backstop is hit");
        }

        // Let the writer task run and stall on its first partial write.
        tokio::task::yield_now().await;

        assert!(
            socket.out_queued_bytes.load(Ordering::Acquire) <= MAX_OUTBOUND_QUEUE_BYTES,
            "the uplink queue must never grow past the explicit backstop"
        );
    }

    /// `build_carrier_client_endpoint` needs an active Tokio runtime to hand
    /// to quinn; called with none current, it must fail with `NoRuntime`
    /// rather than panicking or hanging.
    #[test]
    fn build_carrier_client_endpoint_without_a_runtime_returns_no_runtime() {
        // The socket must be built INSIDE a runtime (it spawns reader/writer
        // tasks); `build_carrier_client_endpoint` is then called from plain
        // synchronous test code, outside `block_on`, where no Tokio context
        // is current.
        let rt = tokio::runtime::Runtime::new().expect("build a tokio runtime");
        let socket = rt.block_on(async {
            let (carrier, _observer) = tokio::io::duplex(1024);
            TcpCarrierSocket::new(carrier, peer())
        });

        let client_config = warrenguard_tls::make_client_config(
            warrenguard_tls::default_crypto_provider(),
            &[b"h3"],
        )
        .expect("client config builds");

        let err = build_carrier_client_endpoint(socket, client_config)
            .expect_err("no Tokio runtime is current outside `block_on`");
        assert!(matches!(err, CarrierError::NoRuntime), "got {err:?}");
    }
}
