//! Exit-terminator behaviour: 5-tuple isolation, bidirectional shuttle, and the
//! decoy hand-off for non-carrier probes. The "dispatcher" is a loopback UDP
//! socket standing in for the exit's QUIC datapath; the carrier "wire" is an
//! in-memory duplex standing in for the cover-domain TLS stream.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use warrenguard_tcp_carrier::{Deframer, encode_frame};
use warrenguard_tcp_fallback::{TerminatorConfig, serve_carrier, terminate_carrier};

/// Frames one datagram the way the client carrier would.
fn frame(datagram: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_frame(&mut out, datagram).expect("frame");
    out
}

/// A loopback UDP dispatcher that reports the source address of each datagram.
async fn spawn_dispatcher() -> (SocketAddr, mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>) {
    let sock = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("dispatcher binds");
    let addr = sock.local_addr().expect("dispatcher addr");
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if tx.send((from, buf[..n].to_vec())).is_err() {
                break;
            }
        }
    });
    (addr, rx)
}

/// The core anti-abuse property: every terminated connection uses a fresh
/// ephemeral loopback source port, so the dispatcher sees each fallback client
/// as a distinct 5-tuple (never a shared one that would fan sessions together).
#[tokio::test]
async fn each_connection_uses_a_distinct_loopback_source_port() {
    let (dispatcher, mut rx) = spawn_dispatcher().await;

    let mut ports = Vec::new();
    for tag in [b"conn-one".as_slice(), b"conn-two".as_slice()] {
        let (mut client, term) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = terminate_carrier(term, dispatcher).await;
        });
        client.write_all(&frame(tag)).await.expect("client writes");
        let (from, payload) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("dispatcher receives in time")
            .expect("channel open");
        assert_eq!(
            payload, tag,
            "the de-encapsulated datagram reaches the dispatcher"
        );
        ports.push(from.port());
    }
    assert_ne!(
        ports[0], ports[1],
        "each carrier connection must use its own loopback source port (5-tuple isolation)"
    );
}

/// Datagrams flow both ways: uplink to the dispatcher, downlink framed back to
/// the carrier stream.
#[tokio::test]
async fn shuttle_forwards_datagrams_both_ways() {
    let sock = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("dispatcher binds");
    let dispatcher = sock.local_addr().unwrap();
    // Echo dispatcher: reply to the source with a transformed payload.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let (n, from) = sock.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"up");
        sock.send_to(b"down", from).await.unwrap();
    });

    let (mut client, term) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let _ = terminate_carrier(term, dispatcher).await;
    });

    client
        .write_all(&frame(b"up"))
        .await
        .expect("client writes uplink");

    // Read the framed downlink datagram back off the carrier stream.
    let mut deframer = Deframer::new();
    let mut buf = vec![0u8; 256];
    let down = loop {
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("downlink arrives")
            .expect("read ok");
        assert_ne!(n, 0, "stream must not close before the downlink");
        deframer.push(&buf[..n]);
        if let Some(dg) = deframer.next_datagram() {
            break dg;
        }
    };
    assert_eq!(
        down, b"down",
        "the dispatcher reply is framed back to the client"
    );
}

/// A complete first frame that is NOT a QUIC Initial (an active prober) is
/// handed to the decoy, never shuttled to the dispatcher.
#[tokio::test]
async fn serve_carrier_hands_non_quic_first_frame_to_decoy() {
    let (dispatcher, mut rx) = spawn_dispatcher().await;
    let cfg = TerminatorConfig {
        dispatcher,
        first_frame_timeout: Duration::from_secs(5),
    };

    let (mut client, term) = tokio::io::duplex(64 * 1024);
    let decoy_called = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&decoy_called);
    let served = tokio::spawn(async move {
        serve_carrier(term, &cfg, move |mut stream, prefix| async move {
            flag.store(true, Ordering::SeqCst);
            assert!(!prefix.is_empty(), "decoy receives the consumed bytes");
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            Ok(())
        })
        .await
    });

    // First byte 0x00 => not a QUIC long header.
    client.write_all(&frame(&[0x00, 0x11, 0x22])).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), served)
        .await
        .expect("serve_carrier returns")
        .expect("task ok")
        .expect("serve_carrier ok");

    assert!(decoy_called.load(Ordering::SeqCst), "decoy must be invoked");
    assert!(
        rx.try_recv().is_err(),
        "a non-carrier probe must never reach the dispatcher"
    );
}

/// A first frame shaped like a QUIC Initial (long-header first byte) is shuttled
/// to the dispatcher; the decoy is not invoked.
#[tokio::test]
async fn serve_carrier_shuttles_a_quic_initial_first_frame() {
    let (dispatcher, mut rx) = spawn_dispatcher().await;
    let cfg = TerminatorConfig {
        dispatcher,
        first_frame_timeout: Duration::from_secs(5),
    };

    let (mut client, term) = tokio::io::duplex(64 * 1024);
    let decoy_called = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&decoy_called);
    tokio::spawn(async move {
        let _ = serve_carrier(term, &cfg, move |_s, _p| {
            let flag = Arc::clone(&flag);
            async move {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;
    });

    // 0xc0 => QUIC long header + fixed bit set (Initial-shaped).
    let initial = [0xc0, 0xde, 0xad, 0xbe, 0xef];
    client.write_all(&frame(&initial)).await.unwrap();

    let (_from, payload) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("dispatcher receives the shuttled Initial")
        .expect("channel open");
    assert_eq!(
        payload, initial,
        "the Initial datagram is shuttled verbatim"
    );
    assert!(
        !decoy_called.load(Ordering::SeqCst),
        "a QUIC-shaped carrier must not trigger the decoy"
    );
}

/// A zero-length carrier frame (`[0x00, 0x00]`) decodes to an empty datagram,
/// which the shuttle must forward as a genuine 0-byte UDP send (a legitimate,
/// if degenerate, QUIC datagram), never silently drop.
#[tokio::test]
async fn zero_length_datagram_is_forwarded_as_a_genuine_empty_udp_send() {
    let (dispatcher, mut rx) = spawn_dispatcher().await;

    let (mut client, term) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let _ = terminate_carrier(term, dispatcher).await;
    });

    client
        .write_all(&frame(&[]))
        .await
        .expect("client writes an empty frame");

    let (_from, payload) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("dispatcher receives the empty datagram")
        .expect("channel open");
    assert!(
        payload.is_empty(),
        "a zero-length carrier frame must forward as a genuine 0-byte UDP \
         send, not be dropped"
    );
}

/// A frame truncated by a mid-frame connection close must be DROPPED, never
/// shuttled to the dispatcher as a corrupt, short datagram: this is the
/// property `pump_uplink` relies on by returning `Ok(())` on EOF without ever
/// trying to flush whatever partial bytes remain buffered in the deframer.
#[tokio::test]
async fn partial_frame_at_eof_is_dropped_not_shuttled() {
    let (dispatcher, mut rx) = spawn_dispatcher().await;

    let (mut client, term) = tokio::io::duplex(64 * 1024);
    let served = tokio::spawn(async move { terminate_carrier(term, dispatcher).await });

    let full = frame(b"this frame never fully arrives");
    let truncated = &full[..full.len() - 5]; // hold back the tail
    client
        .write_all(truncated)
        .await
        .expect("write the partial frame");
    drop(client); // the peer resets/closes mid-frame

    tokio::time::timeout(Duration::from_secs(2), served)
        .await
        .expect("terminate_carrier returns promptly on EOF")
        .expect("task did not panic")
        .expect("terminate_carrier ok");

    assert!(
        rx.try_recv().is_err(),
        "a truncated frame must never reach the dispatcher, complete or not"
    );
}

/// A peer that connects and closes immediately, without sending a single byte
/// (the classic active-probe shape: complete the outer TLS, then hang up), is
/// handed to the decoy with an EMPTY prefix, never shuttled to the dispatcher
/// and never left hanging.
#[tokio::test]
async fn serve_carrier_hands_immediate_close_to_decoy_with_empty_prefix() {
    let (dispatcher, mut rx) = spawn_dispatcher().await;
    let cfg = TerminatorConfig {
        dispatcher,
        first_frame_timeout: Duration::from_secs(5),
    };

    let (client, term) = tokio::io::duplex(64 * 1024);
    drop(client); // connect-then-close: no bytes ever cross the wire

    let decoy_called = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&decoy_called);
    let served = tokio::spawn(async move {
        serve_carrier(term, &cfg, move |_stream, prefix| {
            let flag = Arc::clone(&flag);
            async move {
                flag.store(true, Ordering::SeqCst);
                assert!(
                    prefix.is_empty(),
                    "an immediate close consumes zero bytes before EOF"
                );
                Ok(())
            }
        })
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), served)
        .await
        .expect("serve_carrier returns promptly on an immediate close")
        .expect("task ok")
        .expect("serve_carrier ok");

    assert!(
        decoy_called.load(Ordering::SeqCst),
        "a connect-then-close probe must be handed to the decoy"
    );
    assert!(
        rx.try_recv().is_err(),
        "a peer that never sent a frame must never reach the dispatcher"
    );
}

/// A stream whose very first read fails, standing in for a reset or a broken
/// TLS record: `serve_carrier` must surface the error directly rather than
/// treating it as a probe (the decoy branch is for a peer that behaves like a
/// non-carrier client, not for a hard I/O failure).
struct FailingReadStream;

impl AsyncRead for FailingReadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    }
}

impl AsyncWrite for FailingReadStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn serve_carrier_surfaces_a_read_error_instead_of_hanging_or_decoying() {
    let (dispatcher, mut rx) = spawn_dispatcher().await;
    let cfg = TerminatorConfig {
        dispatcher,
        first_frame_timeout: Duration::from_secs(5),
    };

    let decoy_called = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&decoy_called);
    let err = tokio::time::timeout(
        Duration::from_secs(2),
        serve_carrier(FailingReadStream, &cfg, move |_stream, _prefix| {
            let flag = Arc::clone(&flag);
            async move {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }
        }),
    )
    .await
    .expect("serve_carrier returns promptly on a read error")
    .expect_err("a hard read error must be surfaced, not swallowed");

    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    assert!(
        !decoy_called.load(Ordering::SeqCst),
        "a read error is not a probe shape, the decoy must not run"
    );
    assert!(
        rx.try_recv().is_err(),
        "nothing reaches the dispatcher either"
    );
}

/// No complete frame within the timeout (a slow or silent prober) triggers the
/// decoy rather than hanging.
#[tokio::test]
async fn serve_carrier_times_out_to_decoy_when_no_frame() {
    let (dispatcher, _rx) = spawn_dispatcher().await;
    let cfg = TerminatorConfig {
        dispatcher,
        first_frame_timeout: Duration::from_millis(150),
    };

    let (_client, term) = tokio::io::duplex(64 * 1024);
    let decoy_called = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&decoy_called);
    let served = tokio::spawn(async move {
        serve_carrier(term, &cfg, move |_s, _p| {
            let flag = Arc::clone(&flag);
            async move {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
    });

    // Hold `_client` open but send nothing: the timeout must fire and hand off.
    tokio::time::timeout(Duration::from_secs(2), served)
        .await
        .expect("serve_carrier returns after the first-frame timeout")
        .expect("task ok")
        .expect("serve_carrier ok");
    assert!(
        decoy_called.load(Ordering::SeqCst),
        "a silent peer past the timeout must be handed to the decoy"
    );
}
