//! End-to-end: idle cover replaces the keep-alive beacon.
//!
//! Brings up a real loopback client<->exit QUIC connection with the
//! idle-cover client config (`warren_transport_config_client_with_idle_cover(.., true)`,
//! which disables the keep-alive PING) and runs
//! `pump_bidirectional_with_idle_cover` over an empty `FakeTun` (so the
//! tunnel is idle). After ~35s it asserts, via quinn frame stats, that the
//! keep-alive beacon did NOT grow at the 5s cadence (`frame_tx.ping` stays
//! at the handshake baseline rather than reaching ~11), that cover
//! DATAGRAMs WERE emitted (`frame_tx.datagram >= 1`, the jittered idle
//! filler took over), and that the connection is still alive (the exit
//! ack'd the cover, the 25s idle timeout never fired). This is the
//! behavioral proof that config + pump are coordinated and the tell is
//! replaced, not augmented.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use warrenguard_config::ALPN_H3;
use warrenguard_pump::{
    pump_bidirectional_with_idle_cover, pump_bidirectional_with_idle_cover_interval,
};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};
use warrenguard_transport_core::packet_device::FakeTun;

/// Exit that accepts one connection and drains datagrams (discarding
/// them, like the real exit drops dummies). Sends nothing, so the only
/// wire activity is the client's cover + the exit's ACKs.
fn spawn_draining_exit(exit_key: &SigningKey) -> SocketAddr {
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
                    loop {
                        match conn.read_datagram().await {
                            Ok(_) => {} // drain & discard (cover dummies)
                            Err(_) => return,
                        }
                    }
                }
            });
        }
    });
    Box::leak(Box::new(endpoint));
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "~35s idle; run with --ignored --nocapture"]
async fn idle_cover_replaces_keepalive_beacon() {
    let exit_key = SigningKey::from_bytes(&[0x55; 32]);
    let exit_addr = spawn_draining_exit(&exit_key);

    // idle_cover = true: keep-alive PING disabled, cover provides liveness.
    let mut client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
    client_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_client_with_idle_cover(false, true),
    );
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

    // Run the cover pump over an idle (empty) FakeTun.
    let pump_conn = client_conn.clone();
    let pump = tokio::spawn(async move {
        let _ = pump_bidirectional_with_idle_cover(FakeTun::new(), pump_conn).await;
    });

    // Long enough for at least one jittered cover fire (interval 10-20s).
    tokio::time::sleep(Duration::from_secs(35)).await;

    let stats = client_conn.stats();
    println!(
        "after 35s idle: frame_tx.ping={} frame_tx.datagram={}",
        stats.frame_tx.ping, stats.frame_tx.datagram
    );

    // A handful of PINGs are emitted during the handshake/PTO regardless
    // of keep-alive (the measure_keepalive_signature harness records ~4
    // right after the handshake). The KEEP-ALIVE BEACON is the steady 5s
    // growth on top: with keep-alive on (5s) over 35s that is ~7 extra
    // PINGs (total ~11). With idle cover the keep-alive is disabled, so
    // the count must stay at the handshake baseline and NOT grow at the
    // 5s cadence. The threshold cleanly separates the two regimes.
    assert!(
        stats.frame_tx.ping <= 6,
        "idle cover must REPLACE the keep-alive beacon: PING must stay at the \
         handshake baseline (~4), not grow at the 5s cadence (~11 over 35s). \
         got {}. If high, the client config did not disable keep-alive.",
        stats.frame_tx.ping
    );
    assert!(
        stats.frame_tx.datagram >= 1,
        "idle cover must emit at least one DATAGRAM during 35s idle (got {}); \
         the jittered interval is 10-20s",
        stats.frame_tx.datagram
    );

    // The connection must still be alive: cover datagrams were ack'd and
    // the 25s idle timeout never fired. close_reason() is None while live.
    assert!(
        client_conn.close_reason().is_none(),
        "connection must stay alive on cover traffic alone (idle timeout must not fire): {:?}",
        client_conn.close_reason()
    );

    client_conn.close(quinn::VarInt::from_u32(0), b"idle cover test done");
    pump.abort();
}

/// Fast (~2s), non-ignored companion of the test above: exercises the
/// EXACT SAME `pump_bidirectional_with_idle_cover` loop body (uplink,
/// downlink, cover timer, `TunIoTolerance`) via the test/tuning seam
/// `pump_bidirectional_with_idle_cover_interval`, injecting a
/// 300-600ms jittered interval instead of the production 10-20s. This
/// keeps the real pump wiring under CI's normal (non-`--ignored`) run
/// without the ~35s wait: the long-running test above stays the
/// authority for the production interval end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_cover_interval_seam_emits_cover_datagrams_quickly() {
    let exit_key = SigningKey::from_bytes(&[0x56; 32]);
    let exit_addr = spawn_draining_exit(&exit_key);

    // Keep-alive disabled so the client stats aren't polluted by the fixed
    // PING beacon (only the transport config matters here, not the pump's
    // own interval - the pump's interval is overridden below).
    let mut client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
    client_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_client_with_idle_cover(false, true),
    );
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

    let pump_conn = client_conn.clone();
    let pump = tokio::spawn(async move {
        let _ = pump_bidirectional_with_idle_cover_interval(
            FakeTun::new(),
            pump_conn,
            Duration::from_millis(300),
            Duration::from_millis(600),
        )
        .await;
    });

    // Comfortably longer than the injected 600ms ceiling, short enough to
    // keep this test fast.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let stats = client_conn.stats();
    assert!(
        stats.frame_tx.datagram >= 1,
        "the injected short interval must have fired at least one cover DATAGRAM within 2s \
         (got {}); the production 10-20s interval could not have fired that fast, so this \
         proves the interval seam actually reaches the pump loop",
        stats.frame_tx.datagram
    );
    assert!(
        client_conn.close_reason().is_none(),
        "connection must stay alive on cover traffic alone: {:?}",
        client_conn.close_reason()
    );

    client_conn.close(
        quinn::VarInt::from_u32(0),
        b"idle cover interval seam test done",
    );
    pump.abort();
}
