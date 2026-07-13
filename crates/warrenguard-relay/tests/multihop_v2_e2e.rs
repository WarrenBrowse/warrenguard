//! End-to-end loopback test proving the relay routes a `/v2` post-quantum
//! X-Wing setup frame exactly like a `/v1` one: same primitives as
//! `relay_e2e_local.rs` (a fake echoing exit, a real [`RelayServer`], the
//! `extract_dispatched_exit -> ExitConnPool::get_or_create -> forward_session`
//! accept loop), but the client's setup and burst frames are all
//! [`WarrenMultihopFrameV2`].
//!
//! Asserts:
//! - The relay routes the `/v2` setup frame to the matching exit (it never
//!   decrypts, so it never notices the frame is PQ-sealed rather than
//!   classical).
//! - Multiple `/v2` frames round-trip without crashing the session.
//! - The exit pool ends with a single cached entry (no leak).
//!
//! Loopback only; the corresponding real-network validation is a
//! cross-DC bench run against deployed nodes (see `docs/90-PQ-HPKE-XWING.md`).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use quinn::Endpoint;
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::{
    ExitId, WARREN_HPKE_VERSION_V2, WarrenMultihopFrameV2, encode_frame_v2,
};
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

/// Builds a `/v2` frame. `pq_ct` carries the full 1088-byte ML-KEM
/// ciphertext on `seq == 0` (the setup/rekey frame) and is empty afterwards,
/// mirroring the steady-state frame shape documented in `wire_format_v2`.
fn dummy_frame_v2(exit_id: ExitId, seq: u64) -> Vec<u8> {
    let pq_ct = if seq == 0 {
        vec![0x05; 1088]
    } else {
        Vec::new()
    };
    let frame = WarrenMultihopFrameV2 {
        version: WARREN_HPKE_VERSION_V2,
        exit_id,
        epoch: 0,
        seq,
        encapsulated_key: [0xCC; 32],
        pq_ct,
        aead_tag: [0xDD; 16],
        ciphertext: {
            let mut v = vec![0u8; 64];
            v[0..8].copy_from_slice(&seq.to_be_bytes());
            v
        },
    };
    encode_frame_v2(&frame).expect("v2 frame encodes")
}

fn spawn_echo_exit(exit_key: &SigningKey) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let provider = default_crypto_provider();
    let server_cfg =
        make_server_config(exit_key, provider, &[ALPN_H3]).expect("exit server config");
    let endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("exit bind");
    let addr = endpoint.local_addr().expect("exit addr");
    let listen = endpoint.clone();
    let handle = tokio::spawn(async move {
        let mut conn_tasks = Vec::new();
        while let Some(incoming) = listen.accept().await {
            conn_tasks.push(tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    // Setup phase: the relay opens a bidi stream and
                    // writes the finish-delimited setup frame; echo it
                    // straight back on the same stream so the client's
                    // setup round-trip completes. The exit is just as
                    // blind to `/v1` vs `/v2` here as the relay is: it
                    // echoes whatever bytes it received.
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await
                        && let Ok(setup) = recv.read_to_end(64 * 1024).await
                    {
                        let _ = send.write_all(&setup).await;
                        let _ = send.finish();
                    }
                    // DATA phase: echo every datagram.
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
            }));
        }
        for t in conn_tasks {
            let _ = t.await;
        }
    });
    // Leak the endpoint so accept loop stays alive for the whole test.
    Box::leak(Box::new(endpoint));
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end_local_loopback_routes_a_v2_pq_session() {
    let op_key = det_signing_key(0x42);
    let relay_key = det_signing_key(0x77);
    let exit_key = det_signing_key(0x55);
    let exit_id = ExitId::from_bytes([0xBB; 16]);

    // (1) Fake exit
    let (exit_addr, _exit_handle) = spawn_echo_exit(&exit_key);

    // (2) Real relay server, loaded from a plain /v1-signed descriptor: the
    // relay's version-agnostic dispatch does not require the descriptor
    // itself to be /v2-signed, only that the setup frame's exit_id decodes.
    let descriptor = signed_descriptor(&op_key, exit_id, pubkey_bytes(&exit_key), exit_addr);
    let cfg = Arc::new(RelayConfig {
        bind_addr: "127.0.0.1:0".parse().expect("static addr parses"),
        signing_key_path: PathBuf::from("/dev/null"),
        operational_pubkey: op_key.verifying_key(),
        exits: vec![descriptor.clone()],
    });
    let server = RelayServer::new(cfg.clone(), &relay_key).expect("relay bind");
    let server_addr = server.local_addr().expect("relay addr");

    // (3) Server accept loop: dispatch -> pool -> forward
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
            .expect("first /v2 setup frame dispatch");
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

    // (4) Fake client: dial relay with h3 ALPN, RPK pinned to relay_key.
    let client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
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

    // Setup phase: the client opens a bidi stream, writes the
    // finish-delimited /v2 setup frame (full ML-KEM ciphertext), and reads
    // the echoed reply. The relay extracts the exit_id from this frame's
    // cleartext header and shuttles it to the exit over a relay->exit
    // stream, exactly as it would for a /v1 frame.
    let first = dummy_frame_v2(exit_id, 0);
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

    // Burst N more /v2 datagrams (empty pq_ct, steady-state shape) and
    // count round-trips.
    const N: u64 = 200;
    let burst_send = tokio::spawn({
        let conn = client_conn.clone();
        async move {
            for seq in 1..=N {
                let bytes = dummy_frame_v2(exit_id, seq);
                if conn.send_datagram(Bytes::from(bytes)).is_err() {
                    // Quinn datagram back-pressure: accept drops.
                }
                if seq % 50 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        }
    });

    let mut received: u64 = 0;
    for _ in 0..N {
        match tokio::time::timeout(Duration::from_secs(2), client_conn.read_datagram()).await {
            Ok(Ok(_bytes)) => received += 1,
            _ => break,
        }
    }
    assert!(
        received >= 20,
        "expected >= 20 /v2 frames round-tripped, got {received}"
    );

    burst_send.await.expect("burst send completes");

    // Tear down.
    client_conn.close(quinn::VarInt::from_u32(0), b"v2 e2e done");
    let _summary = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task completes")
        .expect("server task did not panic");

    // Pool should still hold a single entry (the fake exit).
    assert_eq!(
        pool.cached_entry_count(),
        1,
        "expected single cached exit entry, got {}",
        pool.cached_entry_count()
    );

    // Metrics: dispatched exactly once, c2e at least the initial /v2 frame.
    let snap = metrics.snapshot();
    assert_eq!(snap.sessions_dispatched, 1);
    assert!(
        snap.datagrams_client_to_exit >= 1,
        "expected initial /v2 datagram counted, got snap={snap:?}"
    );
    assert_eq!(snap.exit_pool_misses, 1, "single dial on first use");
}
