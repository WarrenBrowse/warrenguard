//! End-to-end tests for [`forward_session`].
//!
//! The pump is exercised by spinning up four real Quinn endpoints
//! arranged as `fake_client ↔ relay_client_side` and
//! `relay_exit_side ↔ fake_exit`. The fake exit echoes every datagram
//! it receives, so the round-trip path is
//! `fake_client → relay_client_side → relay_exit_side → fake_exit
//!  → relay_exit_side → relay_client_side → fake_client`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint, TransportConfig, VarInt};
use warrenguard_config::ALPN_H3;
use warrenguard_relay::{ForwardSummary, forward_session};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn build_handshaken_pair(server_key: &SigningKey) -> (Connection, Connection) {
    build_handshaken_pair_with_transport(server_key, None).await
}

/// [`build_handshaken_pair`] with an optional `TransportConfig` applied to
/// BOTH ends of the pair. Used by the oversize-datagram test below to give
/// one leg a larger `max_datagram_size` than the other, deterministically
/// (MTU discovery is disabled so the value never drifts mid-test).
async fn build_handshaken_pair_with_transport(
    server_key: &SigningKey,
    transport: Option<Arc<TransportConfig>>,
) -> (Connection, Connection) {
    let provider = default_crypto_provider();
    let mut server_cfg =
        make_server_config(server_key, provider.clone(), &[ALPN_H3]).expect("server config");
    let mut client_cfg = make_client_config(provider, &[ALPN_H3]).expect("client config");
    if let Some(transport) = transport {
        server_cfg.transport_config(transport.clone());
        client_cfg.transport_config(transport);
    }

    let server_endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("server bind");
    let server_addr = server_endpoint.local_addr().expect("server addr");

    let client_endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client bind");
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *server_key.verifying_key().as_bytes(),
    ));

    let accept_endpoint = server_endpoint.clone();
    let server_task = tokio::spawn(async move {
        let incoming = accept_endpoint.accept().await.expect("incoming");
        incoming.await.expect("server handshake")
    });

    let client_conn = client_endpoint
        .connect_with(client_cfg, server_addr, &server_name)
        .expect("connect setup")
        .await
        .expect("client handshake");

    let server_conn = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .expect("server task timely")
        .expect("server task did not panic");

    // Hold the endpoints alive by leaking them - dropping them mid
    // test closes the connections we just built. The test runtime
    // tears them down at process exit.
    Box::leak(Box::new(client_endpoint));
    Box::leak(Box::new(server_endpoint));

    (client_conn, server_conn)
}

/// Spawns an echo task on `conn`: every datagram it reads is sent
/// back. Returns the JoinHandle so the test can cancel it on
/// teardown.
fn spawn_echo_loop(conn: Connection) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match conn.read_datagram().await {
                Ok(bytes) => {
                    if conn.send_datagram(bytes).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwards_bytes_for_bytes_one_packet_each_direction() {
    let relay_server_key = det_signing_key(0x11);
    let exit_server_key = det_signing_key(0x22);

    // fake_client ↔ relay_client_side
    let (fake_client_conn, relay_client_side) = build_handshaken_pair(&relay_server_key).await;
    // relay_exit_side ↔ fake_exit (here the relay is the *client*; we
    // reuse the same paired helper because the connection shapes are
    // symmetric for datagram I/O).
    let (relay_exit_side, fake_exit_conn) = build_handshaken_pair(&exit_server_key).await;
    let exit_arc = Arc::new(relay_exit_side);

    let echo_handle = spawn_echo_loop(fake_exit_conn);

    let forward_handle = tokio::spawn({
        let exit_arc = exit_arc.clone();
        async move { forward_session(relay_client_side, exit_arc).await }
    });

    // Setup now travels over a reliable stream (not the datagram pump),
    // so the pump only carries DATA datagrams. Send one and observe the
    // echo on the same channel.
    fake_client_conn
        .send_datagram(Bytes::from_static(b"first-frame-as-datagram"))
        .expect("send_datagram first");
    let first = tokio::time::timeout(Duration::from_secs(3), fake_client_conn.read_datagram())
        .await
        .expect("read first echo")
        .expect("first echo bytes");
    assert_eq!(first.as_ref(), b"first-frame-as-datagram");

    // Now send one more datagram from the fake_client and observe the
    // echo on the same channel.
    fake_client_conn
        .send_datagram(Bytes::from_static(b"hello-warren"))
        .expect("send_datagram");
    let echo = tokio::time::timeout(Duration::from_secs(3), fake_client_conn.read_datagram())
        .await
        .expect("read echo")
        .expect("echo bytes");
    assert_eq!(echo.as_ref(), b"hello-warren");

    // Tear down: closing the fake_client lets the relay's client-side
    // pump exit and end the session.
    fake_client_conn.close(VarInt::from_u32(0), b"test done");

    let summary: ForwardSummary = tokio::time::timeout(Duration::from_secs(3), forward_handle)
        .await
        .expect("forward_session completes")
        .expect("forward task did not panic")
        .expect("forward_session returns Ok");
    // The pump cancels both directions as soon as either side closes,
    // so the receiver-side counter is racy under teardown. The
    // invariant we care about is "the replay path + at least one
    // application datagram made it across", which the two `read_datagram`
    // assertions above already prove on the wire. Here we just assert
    // the sender-side counter rose past the bare minimum.
    assert!(
        summary.client_to_exit >= 2,
        "expected >= 2 client_to_exit (initial + one app), got {}",
        summary.client_to_exit
    );

    echo_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwards_first_data_datagram_after_setup() {
    let relay_server_key = det_signing_key(0x11);
    let exit_server_key = det_signing_key(0x22);

    let (fake_client_conn, relay_client_side) = build_handshaken_pair(&relay_server_key).await;
    let (relay_exit_side, fake_exit_conn) = build_handshaken_pair(&exit_server_key).await;
    let exit_arc = Arc::new(relay_exit_side);

    let echo_handle = spawn_echo_loop(fake_exit_conn);

    // Setup is shuttled over a reliable stream before the pump runs; the
    // forwarder only carries DATA datagrams. The first data datagram
    // must round-trip through the echoing exit.
    let forward_handle = tokio::spawn({
        let exit_arc = exit_arc.clone();
        async move { forward_session(relay_client_side, exit_arc).await }
    });

    fake_client_conn
        .send_datagram(Bytes::from_static(b"opaque-data-datagram-bytes"))
        .expect("send data datagram");
    let echo = tokio::time::timeout(Duration::from_secs(3), fake_client_conn.read_datagram())
        .await
        .expect("read data echo")
        .expect("data echo bytes");
    assert_eq!(echo.as_ref(), b"opaque-data-datagram-bytes");

    fake_client_conn.close(VarInt::from_u32(0), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(3), forward_handle).await;
    echo_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn survives_one_thousand_concurrent_datagrams_both_directions() {
    let relay_server_key = det_signing_key(0x11);
    let exit_server_key = det_signing_key(0x22);

    let (fake_client_conn, relay_client_side) = build_handshaken_pair(&relay_server_key).await;
    let (relay_exit_side, fake_exit_conn) = build_handshaken_pair(&exit_server_key).await;
    let exit_arc = Arc::new(relay_exit_side);

    let echo_handle = spawn_echo_loop(fake_exit_conn);

    let forward_handle = tokio::spawn({
        let exit_arc = exit_arc.clone();
        async move { forward_session(relay_client_side, exit_arc).await }
    });

    // Send 1000 datagrams, each 256 bytes, and count echoes returned.
    const N: usize = 1000;
    let send_handle = tokio::spawn({
        let conn = fake_client_conn.clone();
        async move {
            for i in 0..N {
                let mut payload = vec![0u8; 256];
                payload[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                if conn.send_datagram(Bytes::from(payload)).is_err() {
                    // Quinn's datagram queue back-pressures: drop and
                    // continue; the test relies on the receiver count
                    // matching, not all 1000 being delivered.
                    continue;
                }
                // Yield occasionally so the receiver gets time to drain.
                if i % 100 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        }
    });

    // Receive at least 100 datagrams - over-asserting a precise count
    // is flaky on loopback because Quinn drops datagrams under heavy
    // bursts. The behavioural invariant is: the pump stays healthy
    // and does not crash, which we observe by completing many
    // round-trips.
    let mut received: usize = 0;
    for _ in 0..N {
        match tokio::time::timeout(Duration::from_secs(2), fake_client_conn.read_datagram()).await {
            Ok(Ok(_bytes)) => received += 1,
            _ => break,
        }
    }
    assert!(
        received >= 100,
        "expected at least 100 round-trips, got {received}"
    );

    send_handle.await.expect("send task does not panic");
    fake_client_conn.close(VarInt::from_u32(0), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(3), forward_handle).await;
    echo_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_session_cleanly_on_client_close() {
    let relay_server_key = det_signing_key(0x11);
    let exit_server_key = det_signing_key(0x22);

    let (fake_client_conn, relay_client_side) = build_handshaken_pair(&relay_server_key).await;
    let (relay_exit_side, fake_exit_conn) = build_handshaken_pair(&exit_server_key).await;
    let exit_arc = Arc::new(relay_exit_side);

    let echo_handle = spawn_echo_loop(fake_exit_conn);

    let forward_handle = tokio::spawn({
        let exit_arc = exit_arc.clone();
        async move { forward_session(relay_client_side, exit_arc).await }
    });

    // Send one data datagram and drain its echo so we know the pump is live.
    fake_client_conn
        .send_datagram(Bytes::from_static(b"hi"))
        .expect("send data datagram");
    let _ = tokio::time::timeout(Duration::from_secs(3), fake_client_conn.read_datagram()).await;

    // Force-close from the fake_client side.
    fake_client_conn.close(VarInt::from_u32(0), b"client closes");

    let summary = tokio::time::timeout(Duration::from_secs(3), forward_handle)
        .await
        .expect("forward_session finished after client close")
        .expect("forward task did not panic")
        .expect("forward_session returned Ok");
    assert!(
        summary.client_to_exit >= 1,
        "at least one data datagram should have been forwarded"
    );
    echo_handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closes_session_cleanly_on_exit_close() {
    let relay_server_key = det_signing_key(0x11);
    let exit_server_key = det_signing_key(0x22);

    let (_fake_client_conn, relay_client_side) = build_handshaken_pair(&relay_server_key).await;
    let (relay_exit_side, fake_exit_conn) = build_handshaken_pair(&exit_server_key).await;
    let exit_arc = Arc::new(relay_exit_side);

    // Close the exit side abruptly: forward_session must observe the
    // closure and return without panicking.
    fake_exit_conn.close(VarInt::from_u32(0), b"exit closes");

    let forward_handle = tokio::spawn({
        let exit_arc = exit_arc.clone();
        async move { forward_session(relay_client_side, exit_arc).await }
    });

    let result = tokio::time::timeout(Duration::from_secs(3), forward_handle)
        .await
        .expect("forward_session finished after exit close")
        .expect("forward task did not panic");
    // The pump observes the closed exit and returns Ok with an empty
    // summary; the invariant we care about is "no panic, returns within
    // timeout".
    let _ = result;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_client_to_exit_datagram_is_dropped_and_counted_not_fatal() {
    // Give the C1 (client-facing) pair a much larger MTU budget than the C2
    // (exit-facing) pair, both with MTU discovery disabled so the values
    // stay fixed for the whole test. A payload sized between the two
    // budgets is then legal to SEND on C1 but too large for the pump to
    // forward onto C2, exercising `SendDatagramError::TooLarge` /
    // `dropped_client_to_exit_too_large` without crashing the session.
    let mut big_mtu = TransportConfig::default();
    big_mtu.initial_mtu(8000).mtu_discovery_config(None);
    let mut small_mtu = TransportConfig::default();
    small_mtu.mtu_discovery_config(None);

    let relay_server_key = det_signing_key(0x11);
    let exit_server_key = det_signing_key(0x22);

    let (fake_client_conn, relay_client_side) =
        build_handshaken_pair_with_transport(&relay_server_key, Some(Arc::new(big_mtu))).await;
    let (relay_exit_side, fake_exit_conn) =
        build_handshaken_pair_with_transport(&exit_server_key, Some(Arc::new(small_mtu))).await;
    let exit_arc = Arc::new(relay_exit_side);

    let exit_max = exit_arc
        .max_datagram_size()
        .expect("datagrams enabled on the small-MTU exit-side connection");
    let client_max = fake_client_conn
        .max_datagram_size()
        .expect("datagrams enabled on the large-MTU client-side connection");
    assert!(
        client_max > exit_max,
        "test setup invariant: the C1 budget must exceed the C2 budget \
         (client_max={client_max}, exit_max={exit_max})"
    );
    let oversize_len = exit_max + 1;
    assert!(
        oversize_len <= client_max,
        "the oversize payload must still be legal to send on C1 \
         (oversize_len={oversize_len}, client_max={client_max})"
    );

    let echo_handle = spawn_echo_loop(fake_exit_conn);

    let forward_handle = tokio::spawn({
        let exit_arc = exit_arc.clone();
        async move { forward_session(relay_client_side, exit_arc).await }
    });

    // Oversize-for-the-exit-leg datagram first, then a normal one to prove
    // the pump kept running afterward.
    fake_client_conn
        .send_datagram(Bytes::from(vec![0u8; oversize_len]))
        .expect("C1 accepts a payload within its own (larger) budget");
    fake_client_conn
        .send_datagram(Bytes::from_static(b"still-alive-after-drop"))
        .expect("send a normal-size datagram after the oversize one");
    let echo = tokio::time::timeout(Duration::from_secs(3), fake_client_conn.read_datagram())
        .await
        .expect("read echo after the oversize drop")
        .expect("echo bytes");
    assert_eq!(echo.as_ref(), b"still-alive-after-drop");

    fake_client_conn.close(VarInt::from_u32(0), b"done");
    let summary = tokio::time::timeout(Duration::from_secs(3), forward_handle)
        .await
        .expect("forward_session completes")
        .expect("forward task did not panic")
        .expect("forward_session returns Ok");

    assert!(
        summary.dropped_client_to_exit_too_large >= 1,
        "expected the oversize datagram to be counted as dropped, got summary={summary:?}"
    );
    assert!(
        summary.client_to_exit >= 1,
        "the pump must keep forwarding after an oversize drop, got summary={summary:?}"
    );
    echo_handle.abort();
}
