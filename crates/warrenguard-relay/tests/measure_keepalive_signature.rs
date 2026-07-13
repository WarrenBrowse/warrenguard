//! Measurement harness for the keep-alive PING as a passive
//! traffic-analysis tell. NOT a regression assertion: it quantifies
//! the idle keep-alive wire signature so measured numbers can be
//! cited instead of asserted ones.
//!
//! It brings up a single-hop client <-> exit QUIC connection over
//! loopback with the production client transport config (5s keep-alive
//! via `warren_transport_config_client`) and the production exit config,
//! then leaves the connection idle and samples `Connection::stats()`.
//! During pure idle every datagram the client sends IS a keep-alive
//! packet, so `udp_tx.bytes / udp_tx.datagrams` over an idle window is
//! the exact keep-alive packet size, and `frame_tx.ping` increments time
//! the cadence. No packet capture / privileges needed: the stats are
//! frame-level ground truth from quinn itself.
//!
//! Run: `./scripts/dev/cargo-test-nofw.sh test -p warrenguard-relay \
//!       --test measure_keepalive_signature -- --ignored --nocapture`

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use warrenguard_config::ALPN_H3;
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Spawn an exit that accepts one connection and holds it open without
/// sending application traffic, so only keep-alive packets flow.
fn spawn_idle_exit(exit_key: &SigningKey) -> SocketAddr {
    let provider = default_crypto_provider();
    let mut server_cfg =
        make_server_config(exit_key, provider, &[ALPN_H3]).expect("exit server config");
    server_cfg
        .transport_config(warrenguard_transport_core::warren_transport_config_exit_with_gso(false));
    let endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("exit bind");
    let addr = endpoint.local_addr().expect("exit addr");
    let listen = endpoint.clone();
    tokio::spawn(async move {
        while let Some(incoming) = listen.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    // Hold the connection open, send nothing. Keep-alive
                    // is the only thing on the wire from here on.
                    let _ = conn.closed().await;
                }
            });
        }
    });
    Box::leak(Box::new(endpoint));
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement (~35s idle); run with --ignored --nocapture"]
async fn measure_idle_client_keepalive_signature() {
    let exit_key = det_signing_key(0x55);
    let exit_addr = spawn_idle_exit(&exit_key);

    let mut client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
    client_cfg.transport_config(warrenguard_transport_core::warren_transport_config_client());
    let client_endpoint =
        Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *exit_key.verifying_key().as_bytes(),
    ));
    let client_conn = client_endpoint
        .connect_with(client_cfg, exit_addr, &server_name)
        .expect("client connect setup")
        .await
        .expect("client handshake");

    // Sample the moment the handshake settled; keep-alive timing is
    // measured relative to this idle baseline.
    let start = Instant::now();
    let mut last_ping = client_conn.stats().frame_tx.ping;
    let mut last_dgrams = client_conn.stats().udp_tx.datagrams;
    let mut last_bytes = client_conn.stats().udp_tx.bytes;
    let mut last_event = start;

    println!("idle client keep-alive signature (client cfg: 5s keep-alive)");
    println!("t(s)\tevent\tping_total\tdgram_size_bytes\tsince_prev(s)");

    // Steady-state idle keep-alive samples (size, gap), collected after
    // the first 2s so the handshake tail does not pollute the figures.
    let mut idle_sizes: Vec<u64> = Vec::new();
    let mut idle_gaps: Vec<f64> = Vec::new();

    let deadline = start + Duration::from_secs(35);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let s = client_conn.stats();
        if s.frame_tx.ping > last_ping {
            let now = Instant::now();
            let elapsed = now.duration_since(start).as_secs_f64();
            let gap = now.duration_since(last_event).as_secs_f64();
            let d_dgrams = s.udp_tx.datagrams.saturating_sub(last_dgrams);
            let d_bytes = s.udp_tx.bytes.saturating_sub(last_bytes);
            let size = if d_dgrams > 0 { d_bytes / d_dgrams } else { 0 };
            println!(
                "{:.2}\tPING\t{}\t{}\t{:.2}",
                elapsed, s.frame_tx.ping, size, gap,
            );
            if elapsed > 2.0 {
                idle_sizes.push(size);
                idle_gaps.push(gap);
            }
            last_ping = s.frame_tx.ping;
            last_dgrams = s.udp_tx.datagrams;
            last_bytes = s.udp_tx.bytes;
            last_event = now;
        }
    }

    let max_idle_size = idle_sizes.iter().copied().max().unwrap_or(0);
    let mean_gap = if idle_gaps.is_empty() {
        0.0
    } else {
        idle_gaps.iter().sum::<f64>() / idle_gaps.len() as f64
    };
    println!("---");
    println!(
        "summary: {} steady-state idle keep-alive packets; size <= {} B; mean inter-PING gap {:.2}s (client cfg = 5s)",
        idle_sizes.len(),
        max_idle_size,
        mean_gap,
    );

    // Loose sanity bounds (not a tight regression): at 5s cadence we
    // expect several steady-state PINGs in 35s, each a tiny unpadded
    // packet (short header + PING + AEAD tag).
    assert!(
        idle_sizes.len() >= 3,
        "expected several steady-state keep-alive PINGs, got {}",
        idle_sizes.len()
    );
    assert!(
        max_idle_size < 200,
        "idle keep-alive packets should be tiny, max was {max_idle_size} B"
    );

    client_conn.close(quinn::VarInt::from_u32(0), b"measurement done");
}
