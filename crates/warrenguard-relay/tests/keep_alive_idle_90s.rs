//! Regression guard for the downlink-idle ~50s crash.
//!
//! When the multi-hop tunnel (client -> relay -> exit) sees no
//! application traffic, the `QUIC_KEEP_ALIVE_INTERVAL_SECS = 20`
//! configured on every Warren `TransportConfig` (cf.
//! [`warrenguard_transport_core::warren_transport_config_base`]) is supposed to
//! emit native Quinn PINGs every 20s on each of the two QUIC
//! connections (client<->relay = C1, relay<->exit = C2). With both
//! sides of each hop configured, the connection should survive
//! arbitrarily long idle periods.
//!
//! A cross-DC bench observed a tunnel crash at
//! ~50s with `multi-hop connection closed on downlink recv`.
//! If the cause is keep-alive not firing (or not surviving the
//! relay's blind datagram forwarder), this test reproduces the
//! crash in loopback in 90s. If the loopback path stays alive, the
//! cause is cross-DC-specific (path MTU / backbone
//! reordering) and the next step is a real-network bench, not a code fix.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use quinn::Endpoint;
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::{ExitId, WARREN_HPKE_VERSION, WarrenMultihopFrame, encode_frame};
use warrenguard_relay::{
    ExitConnPool, ExitDescriptorSigned, RelayConfig, RelayMetrics, RelayServer,
    exit_descriptor_signing_payload, extract_dispatched_exit, forward_session,
    record_forward_summary, shuttle_setup_to_exit,
};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

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

fn spawn_echo_exit(exit_key: &SigningKey) -> SocketAddr {
    let provider = default_crypto_provider();
    let server_cfg =
        make_server_config(exit_key, provider, &[ALPN_H3]).expect("exit server config");
    // Mirror the production exit transport config so the keep-alive
    // interval and idle timeout configured by warren_transport_config_base
    // are in force on C2 as well.
    let mut server_cfg = server_cfg;
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
                    // Setup phase: echo the relay's setup frame back on
                    // the bidi stream.
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await
                        && let Ok(setup) = recv.read_to_end(64 * 1024).await
                    {
                        let _ = send.write_all(&setup).await;
                        let _ = send.finish();
                    }
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
                }
            });
        }
    });
    Box::leak(Box::new(endpoint));
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "90s idle wait; run with --ignored to validate keep-alive locally"]
async fn multi_hop_loopback_idle_90s_keeps_connection_alive() {
    // ARRANGE: fake exit + real relay + real server accept loop +
    // real client (mirrors `relay_e2e_local.rs::end_to_end_local_loopback_round_trips_one_thousand_frames`).
    let op_key = det_signing_key(0x42);
    let relay_key = det_signing_key(0x77);
    let exit_key = det_signing_key(0x55);
    let exit_id = ExitId::from_bytes([0xAA; 16]);

    let exit_addr = spawn_echo_exit(&exit_key);

    let descriptor = signed_descriptor(&op_key, exit_id, pubkey_bytes(&exit_key), exit_addr);
    let cfg = Arc::new(RelayConfig {
        bind_addr: "127.0.0.1:0".parse().expect("static addr parses"),
        signing_key_path: PathBuf::from("/dev/null"),
        operational_pubkey: op_key.verifying_key(),
        exits: vec![descriptor.clone()],
    });
    let server = RelayServer::new(cfg.clone(), &relay_key).expect("relay bind");
    let server_addr = server.local_addr().expect("relay addr");

    let pool =
        Arc::new(ExitConnPool::new((Ipv4Addr::LOCALHOST, 0).into()).expect("exit pool binds"));
    let metrics = Arc::new(RelayMetrics::new());
    let endpoint = server.endpoint();
    let cfg_clone = cfg.clone();
    let pool_clone = pool.clone();
    let metrics_clone = metrics.clone();
    let server_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let conn = incoming.await.expect("server handshake");
        let dispatched = extract_dispatched_exit(&conn, &cfg_clone)
            .await
            .expect("first datagram dispatch");
        metrics_clone.inc_sessions_dispatched();
        let was_cached = pool_clone.is_cached(&dispatched.descriptor.exit_id);
        let exit_conn = pool_clone
            .get_or_create(&dispatched.descriptor)
            .await
            .expect("exit pool dial");
        if was_cached {
            metrics_clone.inc_exit_pool_hit();
        } else {
            metrics_clone.inc_exit_pool_miss();
        }
        shuttle_setup_to_exit(
            &exit_conn,
            &dispatched.initial_frame_bytes,
            dispatched.client_setup_send,
        )
        .await
        .expect("setup shuttle");
        let summary = forward_session(conn, exit_conn)
            .await
            .expect("forward_session returns Ok");
        record_forward_summary(&metrics_clone, &summary);
        summary
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
        .connect_with(client_cfg, server_addr, &server_name)
        .expect("client connect setup")
        .await
        .expect("client handshake");

    // Setup phase over the reliable stream to bootstrap the dispatched
    // session and the forward_session pumps on the relay.
    let first = dummy_frame(exit_id, 0);
    {
        let (mut send, mut recv) = client_conn.open_bi().await.expect("client open_bi");
        send.write_all(&first).await.expect("client write setup");
        send.finish().expect("client finish setup");
        let reply = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(64 * 1024))
            .await
            .expect("setup reply timely")
            .expect("setup reply bytes");
        assert_eq!(reply, first, "echoing exit returns the setup frame");
    }

    // ACT: idle 90s. With QUIC_KEEP_ALIVE_INTERVAL_SECS = 20 and
    // QUIC_MAX_IDLE_TIMEOUT_SECS = 180 wired on every Warren
    // TransportConfig, native Quinn PINGs should fire on C1 and C2
    // every 20s and keep both connections alive past the 180s idle
    // window. This test stays at 90s because the historical regression
    // it captures (downlink-idle crash on the relay's blind
    // forwarder) reproduces well within that budget when keep-alive is
    // broken; bumping the test duration would only add wall-clock cost.
    tokio::time::sleep(Duration::from_secs(90)).await;

    // ASSERT: the connection survives. A second datagram round-trips.
    let probe = dummy_frame(exit_id, 1);
    client_conn
        .send_datagram(Bytes::from(probe.clone()))
        .expect("send probe after 90s idle");
    let probe_echo = tokio::time::timeout(Duration::from_secs(5), client_conn.read_datagram())
        .await
        .expect(
            "probe echo must round-trip after 90s of idle: if this fails, native Quinn keep-alive \
             PINGs are not actually keeping the C1<->C2 chain alive through the relay's blind \
             datagram forwarder, and the downlink-idle crash is reproduced in loopback",
        )
        .expect("probe echo bytes after 90s idle");
    assert_eq!(probe_echo.as_ref(), probe.as_slice());

    // Tear down.
    client_conn.close(quinn::VarInt::from_u32(0), b"idle test done");
    let _summary = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task completes")
        .expect("server task did not panic");
}
