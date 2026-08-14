//! How long a client that vanishes WITHOUT a word keeps its relay legs alive.
//!
//! A close frame is emitted once and never retransmitted, so a client whose
//! network disappears (or whose close is written to a socket the OS has already
//! detached from the route) leaves the relay with no event at all. The only
//! thing that ends `C1` then is the negotiated idle timeout, and the only thing
//! that ends `C2` is the relay closing it when a `C1` pump stops. Until both
//! happen the exit still holds a downlink sender for a client that is gone, and
//! keeps writing that client's share of the traffic into a hole.
//!
//! The client advertises `CLIENT_MAX_IDLE_TIMEOUT_SECS` (25 s) and each
//! endpoint applies the minimum of the two advertised values, so this window is
//! a property of the relay's own inbound profile, and the test pins it with the
//! production configs on both ends.
//!
//! Loopback, with a plain UDP relay in front of the relay so the client can be
//! made to vanish mid-session the way a network change makes it vanish: silently,
//! in both directions, with no close and no ICMP.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use quinn::Endpoint;
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::{ExitId, WARREN_HPKE_VERSION, WarrenMultihopFrame, encode_frame};
use warrenguard_relay::{
    ExitConnPool, ExitDescriptorSigned, RelayConfig, RelayServer, exit_descriptor_signing_payload,
    extract_dispatched_exit, forward_session, shuttle_setup_to_exit,
};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

/// Ceiling this test holds the relay to, from the moment the client stops
/// answering to the exit-side connection being gone. The negotiated idle
/// timeout is 25 s; the rest is slack for a loaded runner. A relay that only
/// reaps at 45 s (its own keep-alive PING restarting the idle timer once, per
/// RFC 9000 section 10.1) fails here, which is the regression this pins.
const REAP_BOUND: Duration = Duration::from_secs(35);

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_bytes(k: &SigningKey) -> [u8; 32] {
    *k.verifying_key().as_bytes()
}

fn signed_descriptor(
    op: &SigningKey,
    exit_id: ExitId,
    exit_ed25519_pubkey: [u8; 32],
    exit_addr: SocketAddr,
) -> ExitDescriptorSigned {
    let x25519 = [0x11; 32];
    let payload = exit_descriptor_signing_payload(exit_id, &x25519);
    let sig = op.sign(&payload);
    ExitDescriptorSigned {
        exit_id,
        exit_ed25519_pubkey,
        exit_x25519_multihop_pubkey: x25519,
        endpoint: Some(exit_addr),
        cover_domain: None,
        signature: sig.to_bytes(),
        dns_disabled: false,
        exit_mlkem768_pubkey: None,
    }
}

fn dummy_frame(exit_id: ExitId, seq: u64) -> Vec<u8> {
    let frame = WarrenMultihopFrame {
        version: WARREN_HPKE_VERSION,
        exit_id,
        epoch: 0,
        seq,
        encapsulated_key: [0xCC; 32],
        aead_tag: [0xDD; 16],
        ciphertext: {
            let mut v = vec![0u8; 64];
            v[0..8].copy_from_slice(&seq.to_be_bytes());
            v
        },
    };
    encode_frame(&frame).expect("frame encodes")
}

/// Downlink the exit keeps pushing at the client, whatever the client does.
const COVER: [u8; 64] = [0xEE; 64];

/// What the exit is doing at the moment the client vanishes. The two shapes
/// fail differently, so both are held to the same bound.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Downlink {
    /// Nothing to send: the relay's discovery rests on the idle timeout alone,
    /// which is what a periodic server-side PING silently extends.
    Silent,
    /// The exit keeps writing at a client that is already gone, the shape the
    /// black-hole comes from, and the one that catches a transport where an
    /// outgoing packet keeps restarting the idle timer.
    Flowing,
}

/// Echoing exit on the production exit transport profile. Reports how each
/// accepted connection ended, so the test observes the exit side of the
/// teardown rather than inferring it from the relay.
fn spawn_echo_exit(
    exit_key: &SigningKey,
    downlink: Downlink,
    ended: tokio::sync::mpsc::Sender<quinn::ConnectionError>,
) -> SocketAddr {
    let mut server_cfg = make_server_config(exit_key, default_crypto_provider(), &[ALPN_H3])
        .expect("exit server config");
    server_cfg
        .transport_config(warrenguard_transport_core::warren_transport_config_exit_with_gso(false));
    let endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("exit bind");
    let addr = endpoint.local_addr().expect("exit addr");
    let listen = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = listen.accept().await {
            let ended = ended.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                if let Ok((mut send, mut recv)) = conn.accept_bi().await
                    && let Ok(setup) = recv.read_to_end(64 * 1024).await
                {
                    let _ = send.write_all(&setup).await;
                    let _ = send.finish();
                }
                let echo = conn.clone();
                tokio::spawn(async move {
                    while let Ok(bytes) = echo.read_datagram().await {
                        if echo.send_datagram(bytes).is_err() {
                            break;
                        }
                    }
                });
                if downlink == Downlink::Flowing {
                    let cover = conn.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            if cover.send_datagram(Bytes::from_static(&COVER)).is_err() {
                                break;
                            }
                        }
                    });
                }
                let _ = ended.send(conn.closed().await).await;
            });
        }
    });
    Box::leak(Box::new(endpoint));
    addr
}

/// Plain UDP relay in front of `upstream`, with a switch that makes every
/// packet disappear in both directions. Simulates the client's network going
/// away: no close, no error, nothing the relay can observe except silence.
async fn spawn_blackholing_forwarder(upstream: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
    let front = Arc::new(
        tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("forwarder front bind"),
    );
    let back = Arc::new(
        tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("forwarder back bind"),
    );
    let front_addr = front.local_addr().expect("forwarder addr");
    let blackholed = Arc::new(AtomicBool::new(false));
    let peer: Arc<parking_lot::Mutex<Option<SocketAddr>>> = Arc::new(parking_lot::Mutex::new(None));

    {
        let (front, back, blackholed, peer) = (
            front.clone(),
            back.clone(),
            blackholed.clone(),
            peer.clone(),
        );
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = front.recv_from(&mut buf).await {
                *peer.lock() = Some(from);
                if blackholed.load(Ordering::Relaxed) {
                    continue;
                }
                let _ = back.send_to(&buf[..n], upstream).await;
            }
        });
    }
    {
        let (front, back, blackholed, peer) = (front, back, blackholed.clone(), peer);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, _)) = back.recv_from(&mut buf).await {
                if blackholed.load(Ordering::Relaxed) {
                    continue;
                }
                let to = *peer.lock();
                if let Some(to) = to {
                    let _ = front.send_to(&buf[..n], to).await;
                }
            }
        });
    }
    (front_addr, blackholed)
}

/// A client whose network went away mid-session, with the exit in the given
/// state at that moment. Asserts both legs are gone inside [`REAP_BOUND`].
async fn assert_reaped_after_the_client_vanishes(downlink: Downlink) {
    let op_key = det_signing_key(0x42);
    let relay_key = det_signing_key(0x77);
    let exit_key = det_signing_key(0x55);
    let exit_id = ExitId::from_bytes([0xAA; 16]);

    let (ended_tx, mut ended_rx) = tokio::sync::mpsc::channel(4);
    let exit_addr = spawn_echo_exit(&exit_key, downlink, ended_tx);

    let descriptor = signed_descriptor(&op_key, exit_id, pubkey_bytes(&exit_key), exit_addr);
    let cfg = Arc::new(RelayConfig {
        bind_addr: "127.0.0.1:0".parse().expect("static addr parses"),
        signing_key_path: PathBuf::from("/dev/null"),
        operational_pubkey: op_key.verifying_key(),
        exits: vec![descriptor],
    });
    // The constructor the dual-role production relay uses for its
    // client-facing listener.
    let server = RelayServer::new_multihop_with_gso(cfg.clone(), &relay_key, false)
        .expect("relay binds on loopback");
    let relay_addr = server.local_addr().expect("relay addr");
    let (front_addr, blackholed) = spawn_blackholing_forwarder(relay_addr).await;

    let pool =
        Arc::new(ExitConnPool::new((Ipv4Addr::LOCALHOST, 0).into()).expect("exit pool binds"));
    let endpoint = server.endpoint();
    let server_task = tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("relay handshake");
        let dispatched = extract_dispatched_exit(&conn, &cfg)
            .await
            .expect("setup dispatch");
        let exit_conn = pool
            .dial_fresh(&dispatched.descriptor)
            .await
            .map(Arc::new)
            .expect("exit dial");
        shuttle_setup_to_exit(
            &exit_conn,
            &dispatched.initial_frame_bytes,
            dispatched.client_setup_send,
        )
        .await
        .expect("setup shuttle");
        forward_session(conn, exit_conn)
            .await
            .expect("forward_session returns Ok")
    });

    let mut client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
    client_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_client_multihop_with_gso(false),
    );
    let client_endpoint =
        Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *relay_key.verifying_key().as_bytes(),
    ));
    let client_conn = client_endpoint
        .connect_with(client_cfg, front_addr, &server_name)
        .expect("client connect setup")
        .await
        .expect("client handshake");

    // Bring the session all the way to a live DATA path, so what follows is a
    // vanished client rather than a session that never started.
    let first = dummy_frame(exit_id, 0);
    {
        let (mut send, mut recv) = client_conn.open_bi().await.expect("client open_bi");
        send.write_all(&first).await.expect("client write setup");
        send.finish().expect("client finish setup");
        let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
            .await
            .expect("setup reply timely")
            .expect("setup reply bytes");
        assert_eq!(reply, first, "the echoing exit returns the setup frame");
    }
    let probe = dummy_frame(exit_id, 1);
    client_conn
        .send_datagram(Bytes::from(probe.clone()))
        .expect("send a DATA datagram");
    let echo_seen = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let Ok(bytes) = client_conn.read_datagram().await else {
                return false;
            };
            // The exit's own downlink cover shares this path; the echo is what
            // proves the client's uplink reached the exit and came back.
            if bytes.as_ref() == probe.as_slice() {
                return true;
            }
        }
    })
    .await
    .expect("the DATA path must be live before the client vanishes");
    assert!(echo_seen, "the round trip must complete on a live session");

    // Let the session settle into the state under test, so what the relay last
    // saw is a client packet rather than the DATA round trip above.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // The client vanishes: its process is still there, but nothing it sends
    // leaves and nothing the relay sends arrives. No close reaches the relay.
    blackholed.store(true, Ordering::Relaxed);
    let vanished_at = Instant::now();

    let ended = tokio::time::timeout(REAP_BOUND, ended_rx.recv())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the exit still held the session {:?} after the client vanished: the relay had not \
                 reaped C1, so the exit is still writing this client's downlink into a hole",
                vanished_at.elapsed()
            )
        })
        .expect("the exit reports how its connection ended");
    assert!(
        !matches!(ended, quinn::ConnectionError::TimedOut),
        "the exit leg must be ended by the relay's teardown, not by its own idle timeout, \
         got {ended:?}"
    );

    // The client half of the same guarantee: a client whose path is gone must
    // give up inside the same window, or its supervisor never gets to redial.
    let client_ended = tokio::time::timeout(
        REAP_BOUND.saturating_sub(vanished_at.elapsed()),
        client_conn.closed(),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the client was still holding a session with no path {:?} after it vanished",
            vanished_at.elapsed()
        )
    });
    assert!(
        matches!(client_ended, quinn::ConnectionError::TimedOut),
        "a path that stopped answering must surface as an idle timeout, got {client_ended:?}"
    );

    let summary = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("the relay's forwarder must return once C1 is reaped")
        .expect("forward task did not panic");
    assert!(
        summary.client_to_exit >= 1,
        "the session must have carried DATA before the client vanished, got {summary:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_vanishes_from_a_quiet_session_is_reaped_within_the_bound() {
    assert_reaped_after_the_client_vanishes(Downlink::Silent).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_vanishes_under_downlink_is_reaped_within_the_bound() {
    assert_reaped_after_the_client_vanishes(Downlink::Flowing).await;
}
