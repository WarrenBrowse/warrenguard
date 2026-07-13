//! Client multi-queue TUN pump: `pump_multi_bidirectional_queues` runs one
//! uplink reader task per `IFF_MULTI_QUEUE` queue, removing the single
//! client-TUN-reader chokepoint that the real-exit bench localised as the
//! single-client throughput wall.
//!
//! Engine-only over loopback QUIC with in-memory `FakeTun` queues: proves the
//! uplink fan-in ORCHESTRATION (a packet injected into EACH queue reaches the
//! peer, so every queue has its own live reader). The throughput win from real
//! kernel multi-queue is validated on a real network, not here.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};
use warrenguard_config::ALPN_H3;
use warrenguard_pump::{MultiConnSession, pump_multi_bidirectional_queues};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};
use warrenguard_transport_core::error::{Result as PumpResult, TunnelError};
use warrenguard_transport_core::packet_device::FakeTun;

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

/// Exit that records every datagram payload it receives on any connection.
fn spawn_recording_exit(exit_key: &SigningKey, sink: Arc<Mutex<Vec<Vec<u8>>>>) -> SocketAddr {
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
            let sink = sink.clone();
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    while let Ok(dg) = conn.read_datagram().await {
                        sink.lock().expect("sink poisoned").push(dg.to_vec());
                    }
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
    Box::leak(Box::new(endpoint));
    conn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uplink_drains_every_queue() {
    // Three distinct TUN queues, a 2-conn session. A packet injected into EACH
    // queue must reach the exit. If only the first queue had a reader task, the
    // packets injected into queues 1 and 2 would sit unread forever and the
    // exit would receive one payload, not three: receiving all three is what
    // proves one live uplink reader per queue.
    let exit_key = SigningKey::from_bytes(&[0x71; 32]);
    let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let exit_addr = spawn_recording_exit(&exit_key, received.clone());
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *exit_key.verifying_key().as_bytes(),
    ));

    let c0 = dial(exit_addr, &server_name).await;
    let c1 = dial(exit_addr, &server_name).await;
    let session = TestMultiSession {
        conns: vec![c0.clone(), c1.clone()],
        rr: AtomicUsize::new(0),
    };

    let q0 = FakeTun::new();
    let q1 = FakeTun::new();
    let q2 = FakeTun::new();
    let queues = vec![q0.clone(), q1.clone(), q2.clone()];
    let pump = tokio::spawn(async move {
        let _ = pump_multi_bidirectional_queues(queues, session).await;
    });

    // One distinguishable packet per queue.
    let p0 = vec![0xA0u8; 32];
    let p1 = vec![0xB1u8; 32];
    let p2 = vec![0xC2u8; 32];
    q0.inject_inbound(p0.clone());
    q1.inject_inbound(p1.clone());
    q2.inject_inbound(p2.clone());

    // Poll until all three arrive (or time out).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        {
            let got = received.lock().expect("sink poisoned");
            if got.contains(&p0) && got.contains(&p1) && got.contains(&p2) {
                break;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let got = received.lock().expect("sink poisoned");
            panic!(
                "not every queue was drained to the exit: got {} payloads, missing q0={} q1={} q2={}",
                got.len(),
                !got.contains(&p0),
                !got.contains(&p1),
                !got.contains(&p2)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    c0.close(quinn::VarInt::from_u32(0), b"done");
    c1.close(quinn::VarInt::from_u32(0), b"done");
    pump.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_queue_list_is_rejected() {
    // At least one queue is required: an empty Vec is a caller bug, not a
    // silently dead uplink.
    let exit_key = SigningKey::from_bytes(&[0x72; 32]);
    let sink = Arc::new(Mutex::new(Vec::new()));
    let exit_addr = spawn_recording_exit(&exit_key, sink);
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *exit_key.verifying_key().as_bytes(),
    ));
    let c0 = dial(exit_addr, &server_name).await;
    let session = TestMultiSession {
        conns: vec![c0.clone()],
        rr: AtomicUsize::new(0),
    };
    let res = pump_multi_bidirectional_queues(Vec::<FakeTun>::new(), session).await;
    assert!(res.is_err(), "empty queue list must be rejected");
    c0.close(quinn::VarInt::from_u32(0), b"done");
}
