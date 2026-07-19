//! Sustained-flood coverage for `pump_bidirectional_with_daita` driven by an
//! ACTIVE DAITA state (Tamaraw), over a real loopback QUIC pair + `FakeTun`.
//!
//! The pump's cover/idle tests run `DaitaState::disabled()` on quiet tunnels,
//! so the DAITA inner loop (`pump_bidirectional_daita_inner`: pooled uplink,
//! dummy classification on downlink, the per-machine padding timer) was never
//! exercised under a real, sustained bidirectional flood with padding actively
//! firing. A local fake cannot reproduce it: the loop mixes real datagram I/O
//! on a live `quinn::Connection` with a wall-clock padding timer, and the
//! failure modes we guard against (a select branch starving, a deadlock, a
//! `datagram too large` turning fatal, a panic) only surface against real QUIC
//! under load. This is the necessary-but-not-sufficient local counterpart to a
//! real-network DAITA bench.
//!
//! The assertion is behavioural, not structural: after the flood the pump task
//! must still be running (no panic, no fatal error), real traffic must have
//! round-tripped BOTH ways in bulk (proving the loop is pumping, not wedged),
//! and DAITA padding dummies must have actually been emitted (proving the
//! ACTIVE state drove the timer branch). Break any of the three pump branches
//! and one of these goes red.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};
use tokio::time::{Duration, Instant, sleep};
use warrenguard_config::ALPN_H3;
use warrenguard_daita::DaitaPool;
use warrenguard_daita::daita::DaitaState;
use warrenguard_pump::{DAITA_DUMMY_FIRST_BYTE, pump_bidirectional_with_daita};
use warrenguard_tls::{
    WarrenPubkey as TlsPubkey, default_crypto_provider, make_client_config, make_server_config,
    name as tls_name,
};
use warrenguard_transport_core::packet_device::FakeTun;

/// First byte of a well-formed IPv4 header (version 4, IHL 5). Distinguishes a
/// real forwarded packet from a DAITA padding dummy ([`DAITA_DUMMY_FIRST_BYTE`])
/// on the wire.
const IPV4_FIRST_BYTE: u8 = 0x45;

/// Builds a loopback (client, exit) `Connection` pair over real QUIC on
/// localhost, mirroring `pump_loopback.rs`. Leaks both endpoints for the test
/// process's lifetime (test-only).
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

fn ipv4_packet(payload_len: usize) -> Vec<u8> {
    let mut pkt = vec![0u8; payload_len.max(20)];
    pkt[0] = IPV4_FIRST_BYTE;
    pkt[9] = 6; // protocol = TCP, arbitrary but well-formed.
    pkt[12..16].copy_from_slice(&[10, 66, 0, 5]);
    pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
    pkt
}

/// An ACTIVE DAITA state forced to the curated Tamaraw machine (constant-rate
/// padding, ~200 pkt/s). The enabled assertion pins the "ACTIVE" precondition:
/// a disabled state would make `pump_bidirectional_with_daita` fall through to
/// the plain pump and never exercise the DAITA loop this test targets.
fn tamaraw_state() -> DaitaState {
    let cfg = DaitaPool::default_pool()
        .pick_named_os("tamaraw")
        .expect("default pool carries a tamaraw entry");
    let state = DaitaState::from_config(&cfg, std::time::Instant::now())
        .expect("curated tamaraw config must build a DAITA state");
    assert!(
        state.is_enabled(),
        "the tamaraw DAITA state must be ACTIVE, otherwise the pump takes the disabled fall-through"
    );
    state
}

/// Drives `pump_bidirectional_with_daita` under a `target_pps` bidirectional
/// flood for `duration`, then asserts the pump survived and actually pumped.
async fn run_sustained_flood(target_pps: u64, duration: Duration) {
    let (client_conn, exit_conn) = loopback_pair().await;
    let tun = FakeTun::new();

    // Unit under test: the client-side DAITA pump.
    let pump = tokio::spawn(pump_bidirectional_with_daita(
        tun.clone(),
        client_conn.clone(),
        tamaraw_state(),
    ));

    let uplink_real = Arc::new(AtomicU64::new(0));
    let uplink_dummy = Arc::new(AtomicU64::new(0));
    let downlink_real = Arc::new(AtomicU64::new(0));

    // Exit-side drain: reads every uplink datagram the pump forwards, splitting
    // real forwarded packets from DAITA padding dummies by their first byte.
    let exit_drain = {
        let exit_conn = exit_conn.clone();
        let uplink_real = uplink_real.clone();
        let uplink_dummy = uplink_dummy.clone();
        tokio::spawn(async move {
            while let Ok(dg) = exit_conn.read_datagram().await {
                match dg.first() {
                    Some(&IPV4_FIRST_BYTE) => uplink_real.fetch_add(1, Ordering::Relaxed),
                    Some(&DAITA_DUMMY_FIRST_BYTE) => uplink_dummy.fetch_add(1, Ordering::Relaxed),
                    _ => 0,
                };
            }
        })
    };

    // TUN-side drain: counts real downlink packets the pump wrote to the TUN,
    // freeing the queue so a multi-minute run stays bounded in memory.
    let tun_drain = {
        let tun = tun.clone();
        let downlink_real = downlink_real.clone();
        let stop = Arc::new(AtomicU64::new(0));
        let stop_signal = stop.clone();
        let handle = tokio::spawn(async move {
            while stop.load(Ordering::Relaxed) == 0 {
                for p in tun.take_outbound() {
                    if p.first() == Some(&IPV4_FIRST_BYTE) {
                        downlink_real.fetch_add(1, Ordering::Relaxed);
                    }
                }
                sleep(Duration::from_millis(2)).await;
            }
        });
        (handle, stop_signal)
    };

    let deadline = Instant::now() + duration;
    let per_tick = (target_pps / 1000).max(1);

    // Downlink feeder: the exit sends real IPv4 datagrams the pump must classify
    // as non-dummy and write to the TUN.
    let downlink_feeder = {
        let exit_conn = exit_conn.clone();
        tokio::spawn(async move {
            let mut sent = 0u64;
            while Instant::now() < deadline {
                for _ in 0..per_tick {
                    if exit_conn
                        .send_datagram(Bytes::from(ipv4_packet(40)))
                        .is_ok()
                    {
                        sent += 1;
                    }
                }
                sleep(Duration::from_millis(1)).await;
            }
            sent
        })
    };

    // Uplink feeder (inline): inject real IPv4 packets into the TUN, plus an
    // occasional oversized one to exercise the drop-not-crash too-large path in
    // the DAITA uplink branch.
    let mut uplink_sent = 0u64;
    let mut tick = 0u64;
    while Instant::now() < deadline {
        for _ in 0..per_tick {
            tick += 1;
            if tick % 500 == 0 {
                // Far above any loopback max_datagram_size: the pump must drop
                // it and keep pumping, never tear the tunnel down.
                tun.inject_inbound(ipv4_packet(4096));
            } else {
                tun.inject_inbound(ipv4_packet(40));
                uplink_sent += 1;
            }
        }
        sleep(Duration::from_millis(1)).await;
    }

    let downlink_sent = downlink_feeder.await.expect("downlink feeder join");

    // Grace window for in-flight datagrams to drain before sampling.
    sleep(Duration::from_millis(500)).await;

    let up_real = uplink_real.load(Ordering::Relaxed);
    let up_dummy = uplink_dummy.load(Ordering::Relaxed);
    let dn_real = downlink_real.load(Ordering::Relaxed);

    // Tear down the helpers before asserting so a failing assert never leaks
    // tasks holding the leaked endpoints.
    let (tun_drain_handle, tun_drain_stop) = tun_drain;
    tun_drain_stop.store(1, Ordering::Relaxed);
    let _ = tun_drain_handle.await;
    let pump_finished = pump.is_finished();
    pump.abort();
    exit_drain.abort();

    assert!(
        !pump_finished,
        "the DAITA pump must still be running after a {target_pps} pps / {duration:?} flood; \
         it finished early, meaning it panicked or returned a fatal error under load"
    );
    // A wedged/deadlocked pump forwards ~nothing. A quarter of what was sent is
    // a deliberately forgiving floor (loopback delivers nearly all of it) that
    // still separates a live pump from a dead one without flaking on jitter.
    assert!(
        up_real > 0 && up_real >= uplink_sent / 4,
        "uplink starved: pump forwarded {up_real} real packets of {uplink_sent} injected \
         (expected the pump to keep up over loopback)"
    );
    assert!(
        dn_real > 0 && dn_real >= downlink_sent / 4,
        "downlink starved: pump delivered {dn_real} real packets of {downlink_sent} sent \
         (expected the pump to keep up over loopback)"
    );
    assert!(
        up_dummy > 0,
        "no DAITA padding was emitted under sustained traffic; the ACTIVE Tamaraw state must \
         drive the pump's padding-timer branch (got {up_dummy} dummies)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daita_pump_survives_5s_flood_at_1k_pps() {
    run_sustained_flood(1_000, Duration::from_secs(5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daita_pump_survives_5s_flood_at_5k_pps() {
    run_sustained_flood(5_000, Duration::from_secs(5)).await;
}

/// Longer soak; ignored by default (run with `--ignored`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "60s soak: run explicitly with --ignored"]
async fn daita_pump_survives_60s_flood_at_10k_pps() {
    run_sustained_flood(10_000, Duration::from_secs(60)).await;
}

/// Full 5-minute soak; ignored by default (run with `--ignored`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "5min soak: run explicitly with --ignored"]
async fn daita_pump_survives_5min_flood_at_10k_pps() {
    run_sustained_flood(10_000, Duration::from_secs(300)).await;
}
