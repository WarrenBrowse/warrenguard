//! Tests for [`read_dispatch_frame_or_unauth`], the non-closing dispatch read
//! the unified dual-role dispatcher uses so a connection that completes the
//! cover-certificate handshake but is NOT a Warren client (an active prober)
//! can be handed to a decoy instead of being closed with a Warren-specific
//! code. Two properties matter:
//! 1. a well-formed Warren frame still routes (`DispatchFrame::Routed`);
//! 2. a non-Warren first stream yields `DispatchFrame::Unauthenticated` AND the
//!    connection stays ALIVE - the server can still answer on the handed-back
//!    send half, which a decoy needs to serve plausible content.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::{ExitId, WARREN_HPKE_VERSION, WarrenMultihopFrame, encode_frame};
use warrenguard_relay::{DispatchFrame, read_dispatch_frame_or_unauth};
use warrenguard_tls::{
    default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

const KNOWN_EXIT_ID_BYTES: [u8; 16] = [0xAA; 16];

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn dummy_frame(exit_id: ExitId) -> WarrenMultihopFrame {
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

/// Bind a minimal RPK server endpoint on loopback and return it with its addr
/// and identity pubkey (the client encodes it as the SNI).
fn server_endpoint() -> (quinn::Endpoint, SocketAddr, warrenguard_tls::WarrenPubkey) {
    let key = det_signing_key(0x77);
    let cfg = make_server_config(&key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config builds");
    let ep = quinn::Endpoint::server(cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("server binds");
    let addr = ep.local_addr().expect("local_addr after bind");
    let pubkey = warrenguard_tls::WarrenPubkey::from_bytes(*key.verifying_key().as_bytes());
    (ep, addr, pubkey)
}

async fn dial(addr: SocketAddr, pubkey: warrenguard_tls::WarrenPubkey) -> quinn::Connection {
    let client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config builds");
    let mut ep =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    ep.set_default_client_config(client_cfg);
    let conn = ep
        .connect(addr, &tls_name::encode(pubkey))
        .expect("connect kicks off")
        .await
        .expect("handshake completes");
    // Keep the endpoint alive for the duration of the connection.
    Box::leak(Box::new(ep));
    conn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn well_formed_frame_routes() {
    let (ep, addr, pubkey) = server_endpoint();
    let server = tokio::spawn(async move {
        let conn = ep
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("server handshake");
        read_dispatch_frame_or_unauth(&conn).await
    });

    let conn = dial(addr, pubkey).await;
    let frame =
        encode_frame(&dummy_frame(ExitId::from_bytes(KNOWN_EXIT_ID_BYTES))).expect("frame encodes");
    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(&frame).await.expect("write frame");
    send.finish().expect("finish");

    let outcome = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server completes")
        .expect("server task ok");
    match outcome {
        DispatchFrame::Routed { exit_id, .. } => {
            assert_eq!(exit_id, ExitId::from_bytes(KNOWN_EXIT_ID_BYTES));
        }
        other => panic!("expected Routed, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_warren_stream_is_unauthenticated_and_connection_stays_open() {
    let (ep, addr, pubkey) = server_endpoint();
    // The decoy payload the server writes back on the handed-back send half.
    const DECOY_REPLY: &[u8] = b"HTTP/3-ish decoy body";
    let server = tokio::spawn(async move {
        let conn = ep
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("server handshake");
        let outcome = read_dispatch_frame_or_unauth(&conn).await;
        match outcome {
            DispatchFrame::Unauthenticated { mut send, bytes } => {
                // The connection must NOT have been closed: writing the decoy
                // reply and finishing must succeed and reach the client.
                send.write_all(DECOY_REPLY)
                    .await
                    .expect("decoy can still write");
                send.finish().expect("decoy can finish the stream");
                // Hold the connection open until the client has read the reply.
                tokio::time::sleep(Duration::from_millis(200)).await;
                bytes
            }
            other => panic!("expected Unauthenticated, got {other:?}"),
        }
    });

    let conn = dial(addr, pubkey).await;
    // A non-Warren request: bytes that cannot decode as a WarrenMultihopFrame.
    let probe = Arc::new(b"GET / HTTP/3 probe from a censor".to_vec());
    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(&probe).await.expect("write probe");
    send.finish().expect("finish probe");

    // The decoy must be able to answer on the same stream: proof the engine
    // left the connection alive instead of closing it.
    let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(4096))
        .await
        .expect("read does not hang")
        .expect("decoy reply arrives on the live connection");
    assert_eq!(reply, DECOY_REPLY, "client must receive the decoy reply");

    let server_bytes = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server completes")
        .expect("server task ok");
    assert_eq!(
        server_bytes,
        probe.as_slice(),
        "the prober's request bytes are handed back verbatim for the decoy"
    );
}
