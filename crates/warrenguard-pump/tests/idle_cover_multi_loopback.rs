//! Multi-connection end-to-end: per-connection idle
//! cover keeps EVERY connection covered.
//!
//! The multi-conn correctness property is that each QUIC connection (a
//! distinct 5-tuple with its own NAT mapping and idle timeout) gets its
//! own cover, so an idle secondary is not left to expire while a sticky
//! flow keeps the primary busy. This test builds a 2-connection session
//! to a draining exit, runs `pump_multi_bidirectional_with_idle_cover`
//! over an idle `FakeTun`, and after ~35s asserts that BOTH connections
//! emitted cover (`frame_tx.datagram >= 1` each) with no keep-alive
//! beacon growth, and both are still alive.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};
use warrenguard_config::ALPN_H3;
use warrenguard_pump::{MultiConnSession, pump_multi_bidirectional_with_idle_cover};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};
use warrenguard_transport_core::error::{Result as PumpResult, TunnelError};
use warrenguard_transport_core::packet_device::FakeTun;

/// Minimal test session: a fixed set of connections with round-robin
/// uplink dispatch. Enough to exercise the multi-conn cover pump without
/// pulling in the real `MultiSession` from warrenguard-transport.
struct TestMultiSession {
    conns: Vec<Connection>,
    rr: AtomicUsize,
}

impl MultiConnSession for TestMultiSession {
    fn clone_connections(&self) -> Vec<Connection> {
        self.conns.clone()
    }
    fn send_datagram(&self, payload: Vec<u8>) -> PumpResult<()> {
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.conns.len();
        self.conns[idx]
            .send_datagram(Bytes::from(payload))
            .map_err(|source| TunnelError::QuicSendDatagram {
                context: "test multi".into(),
                source,
            })
    }
}

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
                    while conn.read_datagram().await.is_ok() {} // drain & discard
                }
            });
        }
    });
    Box::leak(Box::new(endpoint));
    addr
}

async fn dial(exit_addr: SocketAddr, server_name: &str) -> Connection {
    let mut client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
    client_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_client_with_idle_cover(false, true),
    );
    let endpoint =
        Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    let conn = endpoint
        .connect_with(client_cfg, exit_addr, server_name)
        .expect("client connect setup")
        .await
        .expect("client handshake");
    // Keep the endpoint alive for the connection's lifetime.
    Box::leak(Box::new(endpoint));
    conn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "multi-conn ~35s idle; run with --ignored --nocapture"]
async fn idle_cover_covers_every_connection() {
    let exit_key = SigningKey::from_bytes(&[0x55; 32]);
    let exit_addr = spawn_draining_exit(&exit_key);
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *exit_key.verifying_key().as_bytes(),
    ));

    let c0 = dial(exit_addr, &server_name).await;
    let c1 = dial(exit_addr, &server_name).await;
    let session = TestMultiSession {
        conns: vec![c0.clone(), c1.clone()],
        rr: AtomicUsize::new(0),
    };

    let pump = tokio::spawn(async move {
        let _ = pump_multi_bidirectional_with_idle_cover(FakeTun::new(), session).await;
    });

    tokio::time::sleep(Duration::from_secs(35)).await;

    for (i, conn) in [&c0, &c1].iter().enumerate() {
        let s = conn.stats();
        println!(
            "conn[{i}] after 35s idle: frame_tx.ping={} frame_tx.datagram={}",
            s.frame_tx.ping, s.frame_tx.datagram
        );
        assert!(
            s.frame_tx.datagram >= 1,
            "conn[{i}] must receive its own idle cover (got {} datagrams); a per-conn \
             scheduler must not leave any connection's NAT mapping to expire",
            s.frame_tx.datagram
        );
        assert!(
            s.frame_tx.ping <= 6,
            "conn[{i}] keep-alive beacon must stay at the handshake baseline, not grow at \
             the 5s cadence (got {} pings)",
            s.frame_tx.ping
        );
        assert!(
            conn.close_reason().is_none(),
            "conn[{i}] must stay alive on cover alone: {:?}",
            conn.close_reason()
        );
    }

    c0.close(quinn::VarInt::from_u32(0), b"done");
    c1.close(quinn::VarInt::from_u32(0), b"done");
    pump.abort();
}
