//! End-to-end: the cover-pump DISPATCHER routes to the real pump.
//!
//! Proves the selection seam ([`pump_bidirectional_cover`]) is wired to the
//! actual datapath, not just the pure [`CoverPump`] decision. Resolves
//! idle-cover-only defenses (`resolve_cover_defenses(false, true)`, DAITA off)
//! and runs `pump_bidirectional_cover` over a real loopback client<->exit QUIC
//! connection with an idle (empty) `FakeTun`. After the jittered idle interval
//! it asserts, via quinn frame stats, that cover DATAGRAMs WERE emitted, which
//! can only happen if the dispatcher selected the idle-cover pump (a disabled
//! DAITA state emits nothing on an idle tunnel). The keep-alive PING must also
//! stay at the handshake baseline, confirming the idle-cover transport config
//! took over from the beacon.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};
use warrenguard_config::ALPN_H3;
use warrenguard_config::knobs::resolve_cover_defenses;
use warrenguard_daita::daita::DaitaState;
use warrenguard_pump::{
    MultiConnSession, pump_bidirectional_cover, pump_multi_bidirectional_cover,
};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};
use warrenguard_transport_core::error::{Result as PumpResult, TunnelError};
use warrenguard_transport_core::packet_device::FakeTun;

/// Exit that accepts one connection and drains datagrams (discarding them,
/// like the real exit drops dummies). Sends nothing, so the only wire activity
/// is the client's cover plus the exit's ACKs.
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
                            Ok(_) => {}
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
#[ignore = "~35s idle loopback; run with --ignored --nocapture"]
async fn cover_dispatch_routes_idle_cover_defenses_to_the_cover_pump() {
    let exit_key = SigningKey::from_bytes(&[0x77; 32]);
    let exit_addr = spawn_draining_exit(&exit_key);

    // idle-cover-only defenses: DAITA off, idle cover on. The transport
    // config must disable the keep-alive PING so the cover takes over.
    let defenses = resolve_cover_defenses(false, true);
    assert!(
        defenses.idle_cover && !defenses.daita,
        "precondition: this test drives the idle-cover arm of the dispatcher"
    );

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

    // Route through the dispatcher, not the bare pump: idle-cover defenses +
    // a disabled DAITA state must land on the idle-cover pump.
    let pump_conn = client_conn.clone();
    let pump = tokio::spawn(async move {
        let _ =
            pump_bidirectional_cover(FakeTun::new(), pump_conn, defenses, DaitaState::disabled())
                .await;
    });

    // Long enough for at least one jittered cover fire (interval 10-20s).
    tokio::time::sleep(Duration::from_secs(35)).await;

    let stats = client_conn.stats();
    assert!(
        stats.frame_tx.datagram >= 1,
        "dispatcher must have selected the idle-cover pump: at least one cover DATAGRAM \
         must be emitted during 35s idle (got {}). A disabled-DAITA plain path emits none.",
        stats.frame_tx.datagram
    );
    assert!(
        stats.frame_tx.ping <= 6,
        "the idle-cover transport config must replace the keep-alive beacon: PING stays at \
         the handshake baseline (~4), not the 5s cadence (~11 over 35s). got {}",
        stats.frame_tx.ping
    );
    assert!(
        client_conn.close_reason().is_none(),
        "connection must stay alive on cover traffic alone: {:?}",
        client_conn.close_reason()
    );

    client_conn.close(quinn::VarInt::from_u32(0), b"cover dispatch test done");
    pump.abort();
}

/// Minimal multi-conn session with round-robin uplink dispatch, enough to
/// exercise the multi-conn cover dispatcher without pulling in the real
/// `MultiSession` from warrenguard-transport.
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

async fn dial_idle_cover(exit_addr: SocketAddr, server_name: &str) -> Connection {
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
#[ignore = "multi-conn ~35s idle loopback; run with --ignored --nocapture"]
async fn cover_dispatch_routes_multi_conn_idle_cover_defenses_to_the_cover_pump() {
    let exit_key = SigningKey::from_bytes(&[0x79; 32]);
    let exit_addr = spawn_draining_exit(&exit_key);
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *exit_key.verifying_key().as_bytes(),
    ));

    let defenses = resolve_cover_defenses(false, true);
    let c0 = dial_idle_cover(exit_addr, &server_name).await;
    let c1 = dial_idle_cover(exit_addr, &server_name).await;
    let session = TestMultiSession {
        conns: vec![c0.clone(), c1.clone()],
        rr: AtomicUsize::new(0),
    };

    // Route through the multi-conn dispatcher: idle-cover defenses + a disabled
    // DAITA state must land on the multi-conn idle-cover pump, covering EVERY
    // connection.
    let pump = tokio::spawn(async move {
        let _ = pump_multi_bidirectional_cover(
            FakeTun::new(),
            session,
            defenses,
            DaitaState::disabled(),
        )
        .await;
    });

    tokio::time::sleep(Duration::from_secs(35)).await;

    for (i, conn) in [&c0, &c1].iter().enumerate() {
        let s = conn.stats();
        assert!(
            s.frame_tx.datagram >= 1,
            "dispatcher must select the multi-conn idle-cover pump: conn[{i}] must emit at \
             least one cover DATAGRAM (got {})",
            s.frame_tx.datagram
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
