//! Direct loopback coverage for `pump_tun_to_quic`, `pump_quic_to_tun`, and
//! `pump_quic_to_tun_rate_limited` (M22): before this file, none of the
//! three had a direct test - only their pure helper functions
//! (`accept_downlink`, `is_daita_dummy`, ...) were unit-tested. Each pump
//! loop gets a normal-round-trip case plus a connection-death case; the
//! latter is only meaningful against a REAL `quinn::Connection`, because it
//! relies on Quinn's documented ordering ("check for buffered datagrams
//! before checking `state.error`, so already-received datagrams... can be
//! drained from a closed connection", `ReadDatagram::poll`): a fake/mock
//! connection cannot reproduce that ordering, so the flush-on-death path
//! genuinely needs a loopback QUIC pair to exercise.
//!
//! Also covers `send_datagram_drop_too_large`'s drop-not-crash contract
//! (M22): a datagram exceeding the connection's negotiated
//! `max_datagram_size` must be silently dropped (`Ok(())`), never
//! propagated as an error that would tear down the whole tunnel over a
//! transient PMTU race.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint, VarInt};
use warrenguard_config::ALPN_H3;
use warrenguard_pump::{
    MultiConnSession, pump_multi_bidirectional, pump_quic_to_tun, pump_quic_to_tun_rate_limited,
    pump_tun_to_quic, send_datagram_drop_too_large,
};
use warrenguard_ratelimit::IdentityLimiter;
use warrenguard_tls::{
    WarrenPubkey as TlsPubkey, default_crypto_provider, make_client_config, make_server_config,
    name as tls_name,
};
use warrenguard_transport_core::error::TunnelError;
use warrenguard_transport_core::packet_device::FakeTun;
use warrenguard_wire::WarrenPubkey;

/// Builds a loopback (initiator, acceptor) `Connection` pair over real QUIC
/// on localhost, mirroring the harness in `idle_cover_loopback.rs` /
/// `cover_dispatch_loopback.rs`. Leaks both endpoints for the test
/// process's lifetime (test-only: avoids threading endpoint lifetimes
/// through every short-lived test).
async fn loopback_pair() -> (Connection, Connection) {
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let provider = default_crypto_provider();
    let mut server_cfg = make_server_config(&key, provider, &[ALPN_H3]).expect("server config");
    server_cfg
        .transport_config(warrenguard_transport_core::warren_transport_config_exit_with_gso(false));
    let server_endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("server bind");
    let addr = server_endpoint.local_addr().expect("server addr");
    let accept_endpoint = server_endpoint.clone();
    let accept = tokio::spawn(async move {
        let incoming = accept_endpoint.accept().await.expect("server accept");
        incoming.await.expect("server handshake")
    });

    let mut client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
    client_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_client_with_gso(false),
    );
    let client_endpoint =
        Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    let server_name = tls_name::encode(TlsPubkey::from_bytes(*key.verifying_key().as_bytes()));
    let client_conn = client_endpoint
        .connect_with(client_cfg, addr, &server_name)
        .expect("client connect setup")
        .await
        .expect("client handshake");
    let server_conn = accept.await.expect("accept task join");

    Box::leak(Box::new(server_endpoint));
    Box::leak(Box::new(client_endpoint));
    (client_conn, server_conn)
}

/// Polls `conn.stats().frame_rx.datagram` until it reaches `want`, or panics
/// after 5s. Used instead of a fixed sleep to deterministically wait for
/// real QUIC datagrams to be delivered over loopback (an actual async
/// network round trip, not an in-process no-op) before proceeding.
async fn wait_frame_rx_datagrams_at_least(conn: &Connection, want: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let got = conn.stats().frame_rx.datagram;
        if got >= want {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for frame_rx.datagram >= {want}, got {got}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Polls `probe` until it contains `want`, appending whatever `FakeTun`
/// hands back on each poll (its `take_outbound` drains the queue, so we
/// must accumulate rather than re-check a fresh snapshot each time).
async fn wait_for_outbound(tun: &FakeTun, want: &[u8]) -> Vec<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut acc: Vec<Vec<u8>> = Vec::new();
    loop {
        acc.extend(tun.take_outbound());
        if acc.iter().any(|p| p.as_slice() == want) {
            return acc;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for {want:?} on the FakeTun outbound queue, got {acc:?}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn ipv4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt
}

// ---------------------------------------------------------------------
// pump_tun_to_quic (uplink: TUN -> QUIC)
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_tun_to_quic_forwards_then_errors_on_connection_death() {
    let (client_conn, exit_conn) = loopback_pair().await;
    let tun = FakeTun::new();

    let pump = tokio::spawn(pump_tun_to_quic(tun.clone(), client_conn.clone()));

    // Normal round trip: a packet injected into the TUN must reach the peer
    // as a QUIC datagram, unmodified.
    let pkt = ipv4_packet([10, 66, 0, 5], [8, 8, 8, 8]);
    tun.inject_inbound(pkt.clone());
    let got = tokio::time::timeout(Duration::from_secs(5), exit_conn.read_datagram())
        .await
        .expect("datagram must arrive within 5s")
        .expect("read_datagram must succeed");
    assert_eq!(
        &got[..],
        &pkt[..],
        "uplink packet must reach the peer unmodified"
    );

    // Kill the SAME connection instance the pump is reading from: `close`
    // sets the local error state synchronously (no network round trip
    // needed), so the pump's next send deterministically fails.
    client_conn.close(VarInt::from_u32(0), b"kill");
    tun.inject_inbound(ipv4_packet([10, 66, 0, 5], [1, 1, 1, 1]));

    let result = tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("pump must terminate after the connection dies")
        .expect("pump task must not panic");
    assert!(
        matches!(result, Err(TunnelError::QuicSendDatagram { .. })),
        "pump_tun_to_quic must surface a QuicSendDatagram error once the connection is \
         dead, got {result:?}"
    );
}

// ---------------------------------------------------------------------
// pump_quic_to_tun (downlink: QUIC -> TUN)
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_quic_to_tun_normal_round_trip() {
    let (client_conn, exit_conn) = loopback_pair().await;
    let tun = FakeTun::new();

    let pump = tokio::spawn(pump_quic_to_tun(client_conn, tun.clone(), None, None));

    let pkt = ipv4_packet([10, 66, 0, 5], [8, 8, 8, 8]);
    exit_conn
        .send_datagram(Bytes::from(pkt.clone()))
        .expect("exit send must succeed");

    let delivered = wait_for_outbound(&tun, &pkt).await;
    assert!(
        delivered.contains(&pkt),
        "downlink datagram must reach the TUN unmodified"
    );

    pump.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_quic_to_tun_flushes_pending_batch_on_connection_death() {
    let (client_conn, exit_conn) = loopback_pair().await;

    // Two datagrams sent and confirmed DELIVERED into client_conn's local
    // receive queue before any pump reads them: this is what lets the test
    // deterministically land in the batched drain loop (lib.rs, inside
    // `while batch.len() < DOWNLINK_BATCH_MAX`) rather than the top-level
    // blocking read.
    let pkt_a = ipv4_packet([10, 66, 0, 6], [9, 9, 9, 9]);
    let pkt_b = ipv4_packet([10, 66, 0, 6], [9, 9, 9, 10]);
    exit_conn
        .send_datagram(Bytes::from(pkt_a.clone()))
        .expect("exit send pkt_a must succeed");
    exit_conn
        .send_datagram(Bytes::from(pkt_b.clone()))
        .expect("exit send pkt_b must succeed");
    wait_frame_rx_datagrams_at_least(&client_conn, 2).await;

    // Kill the SAME connection the pump will read from. Quinn drains
    // already-buffered datagrams before surfacing `state.error`, so the
    // pump below will read pkt_a, then pkt_b, THEN observe the error - with
    // both already accepted into its batch.
    client_conn.close(VarInt::from_u32(0), b"kill");

    let tun = FakeTun::new();
    let result = pump_quic_to_tun(client_conn, tun.clone(), None, None).await;

    match result {
        Err(TunnelError::QuicReadDatagram { context, .. }) => {
            assert_eq!(
                context.as_ref(),
                "downlink batch drain",
                "the error must come from the batched drain loop (proves the batch was \
                 non-empty when the connection death was observed), got context {context:?}"
            );
        }
        other => panic!("expected TunnelError::QuicReadDatagram, got {other:?}"),
    }

    assert_eq!(
        tun.take_outbound(),
        vec![pkt_a, pkt_b],
        "the pending batch must be flushed to the TUN even though the connection died \
         mid-drain (lib.rs's best-effort flush before returning the error)"
    );
}

// ---------------------------------------------------------------------
// pump_quic_to_tun_rate_limited (downlink, rate-limited + anti-spoof)
// ---------------------------------------------------------------------

fn unlimited_limiter() -> std::sync::Arc<IdentityLimiter<WarrenPubkey>> {
    std::sync::Arc::new(IdentityLimiter::new(u64::MAX, u64::MAX))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_quic_to_tun_rate_limited_normal_round_trip() {
    let (client_conn, exit_conn) = loopback_pair().await;
    let tun = FakeTun::new();
    let client_ipv4 = Ipv4Addr::new(10, 66, 0, 7);
    let client_id = WarrenPubkey::from_bytes([0xC1; 32]);

    let pump = tokio::spawn(pump_quic_to_tun_rate_limited(
        client_conn,
        tun.clone(),
        unlimited_limiter(),
        client_id,
        client_ipv4,
        None,
        None,
    ));

    // Source must match `client_ipv4` or the anti-spoof gate drops it.
    let pkt = ipv4_packet([10, 66, 0, 7], [8, 8, 8, 8]);
    exit_conn
        .send_datagram(Bytes::from(pkt.clone()))
        .expect("exit send must succeed");

    let delivered = wait_for_outbound(&tun, &pkt).await;
    assert!(
        delivered.contains(&pkt),
        "rate-limited downlink datagram must reach the TUN unmodified"
    );

    pump.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_quic_to_tun_rate_limited_flushes_pending_batch_on_connection_death() {
    let (client_conn, exit_conn) = loopback_pair().await;
    let client_ipv4 = Ipv4Addr::new(10, 66, 0, 8);
    let client_id = WarrenPubkey::from_bytes([0xC2; 32]);

    let pkt_a = ipv4_packet([10, 66, 0, 8], [9, 9, 9, 9]);
    let pkt_b = ipv4_packet([10, 66, 0, 8], [9, 9, 9, 10]);
    exit_conn
        .send_datagram(Bytes::from(pkt_a.clone()))
        .expect("exit send pkt_a must succeed");
    exit_conn
        .send_datagram(Bytes::from(pkt_b.clone()))
        .expect("exit send pkt_b must succeed");
    wait_frame_rx_datagrams_at_least(&client_conn, 2).await;

    client_conn.close(VarInt::from_u32(0), b"kill");

    let tun = FakeTun::new();
    let result = pump_quic_to_tun_rate_limited(
        client_conn,
        tun.clone(),
        unlimited_limiter(),
        client_id,
        client_ipv4,
        None,
        None,
    )
    .await;

    match result {
        Err(TunnelError::QuicReadDatagram { context, .. }) => {
            assert_eq!(context.as_ref(), "downlink batch drain");
        }
        other => panic!("expected TunnelError::QuicReadDatagram, got {other:?}"),
    }

    assert_eq!(
        tun.take_outbound(),
        vec![pkt_a, pkt_b],
        "the pending batch must be flushed to the TUN even though the connection died \
         mid-drain"
    );
}

// ---------------------------------------------------------------------
// send_datagram_drop_too_large: drop-not-crash contract (M22)
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_datagram_drop_too_large_silently_drops_an_oversized_packet() {
    let (client_conn, _exit_conn) = loopback_pair().await;

    // Deliberately far larger than any realistic negotiated
    // max_datagram_size (bounded by the path MTU), so this reliably hits
    // the too-large branch regardless of the current PMTU discovery state.
    let huge = vec![0x45u8; 100_000];
    let result = send_datagram_drop_too_large(&client_conn, huge);
    assert!(
        result.is_ok(),
        "an oversized datagram must be silently dropped, not propagated as an error \
         that would tear down the whole tunnel: got {result:?}"
    );

    // The connection must still be fully usable afterwards - the drop must
    // not have poisoned any state.
    let small = ipv4_packet([10, 66, 0, 9], [8, 8, 8, 8]);
    let result = send_datagram_drop_too_large(&client_conn, small);
    assert!(
        result.is_ok(),
        "the connection must remain usable after a too-large drop: {result:?}"
    );
}

// ---------------------------------------------------------------------
// M12: pump_multi_bidirectional's uplink switched from `recv_batch` (a
// fresh `vec![0u8; 2048]` allocated per packet in Plain TUN mode) to
// `recv_batch_into` + `BufferPool` + `send_datagram_bytes`. This proves
// the rewiring still round-trips a real payload end to end (the pooling
// change should never alter delivered content).
// ---------------------------------------------------------------------

/// Minimal round-robin multi-conn session, mirroring the `TestMultiSession`
/// helper already used by `multi_queue_client.rs` / `cover_dispatch_loopback.rs`.
struct TestMultiSession {
    conns: Vec<Connection>,
    rr: AtomicUsize,
}

impl MultiConnSession for TestMultiSession {
    fn clone_connections(&self) -> Vec<Connection> {
        self.conns.clone()
    }
    fn send_datagram(&self, payload: Vec<u8>) -> warrenguard_transport_core::error::Result<()> {
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.conns.len();
        self.conns[idx]
            .send_datagram(Bytes::from(payload))
            .map_err(|source| TunnelError::QuicSendDatagram {
                context: "test multi".into(),
                source,
            })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_multi_bidirectional_uplink_forwards_a_pooled_packet_unmodified() {
    let (client_conn, exit_conn) = loopback_pair().await;
    let session = TestMultiSession {
        conns: vec![client_conn],
        rr: AtomicUsize::new(0),
    };
    let tun = FakeTun::new();

    let pump = tokio::spawn(pump_multi_bidirectional(tun.clone(), session));

    let pkt = ipv4_packet([10, 66, 0, 10], [8, 8, 8, 8]);
    tun.inject_inbound(pkt.clone());

    let got = tokio::time::timeout(Duration::from_secs(5), exit_conn.read_datagram())
        .await
        .expect("datagram must arrive within 5s")
        .expect("read_datagram must succeed");
    assert_eq!(
        &got[..],
        &pkt[..],
        "the pooled recv_batch_into uplink must forward the packet unmodified"
    );

    pump.abort();
}
