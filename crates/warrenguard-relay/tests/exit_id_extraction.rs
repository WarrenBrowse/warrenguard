//! End-to-end tests for [`extract_dispatched_exit`]: feed a real Quinn
//! client a relay endpoint, send a setup frame over a bidi stream, and
//! assert the routing layer either resolves the exit, rejects a
//! malformed frame, or rejects an unknown exit_id - each with its
//! dedicated QUIC application close code.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::{
    ExitId, WARREN_HPKE_VERSION, WARREN_HPKE_VERSION_V2, WarrenMultihopFrame,
    WarrenMultihopFrameV2, encode_frame, encode_frame_v2,
};
use warrenguard_relay::{
    ExitDescriptorSigned, RelayConfig, RelayServer, SessionError, WARREN_VARINT_INVALID_FRAME,
    WARREN_VARINT_UNKNOWN_EXIT, exit_descriptor_signing_payload, extract_dispatched_exit,
};
use warrenguard_tls::{default_crypto_provider, make_client_config, name as tls_name};

const KNOWN_EXIT_ID_BYTES: [u8; 16] = [0xAA; 16];

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn dummy_frame(exit_id: ExitId) -> WarrenMultihopFrame {
    // The relay never decrypts the ciphertext; only `version` and
    // `exit_id` must be well-formed for routing. We pad the other
    // fields with non-trivial bytes to mimic a real HPKE datagram
    // shape (encapsulated_key, aead_tag, ciphertext).
    WarrenMultihopFrame {
        version: WARREN_HPKE_VERSION,
        exit_id,
        epoch: 0,
        seq: 0,
        encapsulated_key: [0xCC; 32],
        aead_tag: [0xDD; 16],
        ciphertext: vec![0xEE; 64],
    }
}

/// A `/v2` post-quantum setup frame: `pq_ct` carries the full ML-KEM-768
/// ciphertext shape (1088 bytes), as a real setup/rekey frame would.
fn dummy_frame_v2(exit_id: ExitId) -> WarrenMultihopFrameV2 {
    WarrenMultihopFrameV2 {
        version: WARREN_HPKE_VERSION_V2,
        exit_id,
        epoch: 0,
        seq: 0,
        encapsulated_key: [0xCC; 32],
        pq_ct: vec![0x05; 1088],
        aead_tag: [0xDD; 16],
        ciphertext: vec![0xEE; 64],
    }
}

fn signed_descriptor(op: &SigningKey, exit_id: ExitId, x25519: [u8; 32]) -> ExitDescriptorSigned {
    let payload = exit_descriptor_signing_payload(exit_id, &x25519);
    let sig = op.sign(&payload);
    ExitDescriptorSigned {
        exit_id,
        exit_ed25519_pubkey: [0xEE; 32],
        exit_x25519_multihop_pubkey: x25519,
        endpoint: Some("10.0.0.1:443".parse().expect("static addr parses")),
        cover_domain: None,
        signature: sig.to_bytes(),
        dns_disabled: false,
        exit_mlkem768_pubkey: None,
    }
}

fn relay_with_known_exit() -> (RelayServer, SocketAddr, SigningKey, Arc<RelayConfig>) {
    let op = det_signing_key(0x42);
    let relay_key = det_signing_key(0x77);
    let cfg = Arc::new(RelayConfig {
        bind_addr: "127.0.0.1:0".parse().expect("static addr parses"),
        signing_key_path: PathBuf::from("/dev/null"),
        operational_pubkey: op.verifying_key(),
        exits: vec![signed_descriptor(
            &op,
            ExitId::from_bytes(KNOWN_EXIT_ID_BYTES),
            [0x11; 32],
        )],
    });
    let server = RelayServer::new(cfg.clone(), &relay_key).expect("relay binds");
    let addr = server.local_addr().expect("local_addr after bind");
    (server, addr, relay_key, cfg)
}

async fn dial_relay_with_h3(
    relay_addr: SocketAddr,
    relay_pubkey: warrenguard_tls::WarrenPubkey,
) -> (quinn::Endpoint, quinn::Connection) {
    let client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config builds");
    let client_endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    let server_name = tls_name::encode(relay_pubkey);
    let conn = client_endpoint
        .connect_with(client_cfg, relay_addr, &server_name)
        .expect("client connect kicks off")
        .await
        .expect("client handshake completes");
    (client_endpoint, conn)
}

/// Open a bidi stream on `conn` and write `bytes` as the
/// finish-delimited setup frame (the transport the relay now reads the
/// first frame from). The send half is dropped after `finish`, but the
/// recv half is held by the caller so the stream stays open for the
/// relay's reply / close.
async fn send_setup_frame(conn: &quinn::Connection, bytes: Vec<u8>) -> quinn::RecvStream {
    let (mut send, recv) = conn.open_bi().await.expect("client open_bi");
    send.write_all(&bytes).await.expect("client write setup");
    send.finish().expect("client finish setup");
    recv
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_extracts_exit_id_from_first_datagram_and_routes_correctly() {
    let (server, server_addr, relay_key, cfg) = relay_with_known_exit();
    let relay_pubkey =
        warrenguard_tls::WarrenPubkey::from_bytes(*relay_key.verifying_key().as_bytes());

    let endpoint = server.endpoint();
    let cfg_for_server = cfg.clone();
    let accept_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let conn = incoming.await.expect("handshake completes");
        extract_dispatched_exit(&conn, &cfg_for_server).await
    });

    let (_client_endpoint, client_conn) = dial_relay_with_h3(server_addr, relay_pubkey).await;

    let frame = dummy_frame(ExitId::from_bytes(KNOWN_EXIT_ID_BYTES));
    let frame_bytes = encode_frame(&frame).expect("frame encodes");
    let _recv = send_setup_frame(&client_conn, frame_bytes.clone()).await;

    let dispatched = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .expect("server task completes")
        .expect("server task did not panic")
        .expect("extract_dispatched_exit succeeds for known exit_id");

    assert_eq!(
        dispatched.descriptor.exit_id.as_bytes(),
        &KNOWN_EXIT_ID_BYTES
    );
    assert_eq!(
        dispatched.initial_frame_bytes.as_ref(),
        frame_bytes.as_slice()
    );

    drop(client_conn);
    drop(server);
}

/// The relay is version-agnostic about the setup frame: a `/v2`
/// post-quantum X-Wing setup frame must route to the matching exit exactly
/// like a `/v1` frame does, since both carry `exit_id` in cleartext at the
/// same wire position and the relay never decrypts either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_extracts_exit_id_from_a_v2_pq_setup_frame_and_routes_correctly() {
    let (server, server_addr, relay_key, cfg) = relay_with_known_exit();
    let relay_pubkey =
        warrenguard_tls::WarrenPubkey::from_bytes(*relay_key.verifying_key().as_bytes());

    let endpoint = server.endpoint();
    let cfg_for_server = cfg.clone();
    let accept_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let conn = incoming.await.expect("handshake completes");
        extract_dispatched_exit(&conn, &cfg_for_server).await
    });

    let (_client_endpoint, client_conn) = dial_relay_with_h3(server_addr, relay_pubkey).await;

    let frame = dummy_frame_v2(ExitId::from_bytes(KNOWN_EXIT_ID_BYTES));
    let frame_bytes = encode_frame_v2(&frame).expect("v2 frame encodes");
    let _recv = send_setup_frame(&client_conn, frame_bytes.clone()).await;

    let dispatched = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .expect("server task completes")
        .expect("server task did not panic")
        .expect("extract_dispatched_exit succeeds for a /v2 setup frame");

    assert_eq!(
        dispatched.descriptor.exit_id.as_bytes(),
        &KNOWN_EXIT_ID_BYTES
    );
    assert_eq!(
        dispatched.initial_frame_bytes.as_ref(),
        frame_bytes.as_slice()
    );

    drop(client_conn);
    drop(server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_rejects_malformed_first_datagram_cleanly() {
    let (server, server_addr, relay_key, cfg) = relay_with_known_exit();
    let relay_pubkey =
        warrenguard_tls::WarrenPubkey::from_bytes(*relay_key.verifying_key().as_bytes());

    let endpoint = server.endpoint();
    let cfg_for_server = cfg.clone();
    let accept_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let conn = incoming.await.expect("handshake completes");
        extract_dispatched_exit(&conn, &cfg_for_server).await
    });

    let (_client_endpoint, client_conn) = dial_relay_with_h3(server_addr, relay_pubkey).await;

    // Random non-postcard bytes that fail to decode as `WarrenMultihopFrame`.
    let _recv = send_setup_frame(&client_conn, vec![0xFF; 8]).await;

    let result = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .expect("server task completes")
        .expect("server task did not panic");

    let err = result.expect_err("garbage first datagram must reject");
    assert!(
        matches!(err, SessionError::DecodeFailed(_)),
        "expected DecodeFailed, got {err:?}"
    );

    // Observe the close code on the client side: Quinn surfaces it via
    // `closed().await` once the CONNECTION_CLOSE reaches us.
    let closed = tokio::time::timeout(Duration::from_secs(2), client_conn.closed())
        .await
        .expect("connection closes within timeout");
    match closed {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code.into_inner(),
                WARREN_VARINT_INVALID_FRAME,
                "expected WARREN_VARINT_INVALID_FRAME, got close={close:?}"
            );
        }
        other => panic!("expected ApplicationClosed, got {other:?}"),
    }

    drop(server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_rejects_unknown_exit_id_with_explicit_close_code() {
    let (server, server_addr, relay_key, cfg) = relay_with_known_exit();
    let relay_pubkey =
        warrenguard_tls::WarrenPubkey::from_bytes(*relay_key.verifying_key().as_bytes());

    let endpoint = server.endpoint();
    let cfg_for_server = cfg.clone();
    let accept_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let conn = incoming.await.expect("handshake completes");
        extract_dispatched_exit(&conn, &cfg_for_server).await
    });

    let (_client_endpoint, client_conn) = dial_relay_with_h3(server_addr, relay_pubkey).await;

    // Frame is well-formed but targets an exit_id absent from the pool.
    let unknown = ExitId::from_bytes([0x99; 16]);
    let frame = dummy_frame(unknown);
    let frame_bytes = encode_frame(&frame).expect("frame encodes");
    let _recv = send_setup_frame(&client_conn, frame_bytes).await;

    let result = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .expect("server task completes")
        .expect("server task did not panic");

    let err = result.expect_err("unknown exit_id must reject");
    match err {
        SessionError::UnknownExitId(id) => {
            assert_eq!(id.as_bytes(), unknown.as_bytes());
        }
        other => panic!("expected UnknownExitId, got {other:?}"),
    }

    let closed = tokio::time::timeout(Duration::from_secs(2), client_conn.closed())
        .await
        .expect("connection closes within timeout");
    match closed {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code.into_inner(),
                WARREN_VARINT_UNKNOWN_EXIT,
                "expected WARREN_VARINT_UNKNOWN_EXIT, got close={close:?}"
            );
        }
        other => panic!("expected ApplicationClosed, got {other:?}"),
    }

    drop(server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_times_out_a_client_that_never_opens_the_setup_stream() {
    // Slowloris guard: a client that completes the QUIC handshake but
    // never opens the setup stream must not hold a relay session slot
    // (and its in-flight-session permit) forever. The deadline-bounded
    // extraction closes the connection with the NO_FIRST_DATAGRAM code.
    let (server, server_addr, relay_key, cfg) = relay_with_known_exit();
    let relay_pubkey =
        warrenguard_tls::WarrenPubkey::from_bytes(*relay_key.verifying_key().as_bytes());

    let endpoint = server.endpoint();
    let cfg_for_server = cfg.clone();
    let accept_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let conn = incoming.await.expect("handshake completes");
        warrenguard_relay::extract_dispatched_exit_with_deadline(
            &conn,
            &cfg_for_server,
            Duration::from_millis(300),
        )
        .await
    });

    // Connect, then stay silent: no bidi stream, no setup frame.
    let (_client_endpoint, client_conn) = dial_relay_with_h3(server_addr, relay_pubkey).await;

    let result = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .expect("server task completes within the deadline, not at idle timeout")
        .expect("server task did not panic");

    let err = result.expect_err("a silent client must be rejected");
    assert!(
        matches!(err, SessionError::SetupTimeout(_)),
        "expected SetupTimeout, got {err:?}"
    );

    let closed = tokio::time::timeout(Duration::from_secs(2), client_conn.closed())
        .await
        .expect("connection closes within timeout");
    match closed {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code.into_inner(),
                warrenguard_relay::WARREN_VARINT_NO_FIRST_DATAGRAM,
                "expected WARREN_VARINT_NO_FIRST_DATAGRAM, got close={close:?}"
            );
        }
        other => panic!("expected ApplicationClosed, got {other:?}"),
    }

    drop(server);
}
