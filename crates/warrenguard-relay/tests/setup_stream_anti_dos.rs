//! M21: exercises the setup-stream anti-DoS paths that `dispatch_frame_or_unauth.rs`
//! and `exit_id_extraction.rs` do not cover:
//!
//! - the 64 KiB `read_to_end` cap (`MAX_MULTIHOP_SETUP_FRAME_BYTES`) on
//!   [`read_dispatch_frame`], which strictly bounds the memory a hostile
//!   peer can force the relay to buffer on a setup stream;
//! - [`DispatchFrame::NoStream`], the third outcome of
//!   [`read_dispatch_frame_or_unauth`]: a peer that completes the handshake
//!   but never opens a usable setup stream (stays silent, or resets the
//!   stream mid-read).
//!
//! Before this file existed, `SetupStreamRead` and `NoStream` never appeared
//! in `tests/` at all.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warrenguard_config::ALPN_H3;
use warrenguard_relay::{
    DispatchFrame, MAX_MULTIHOP_SETUP_FRAME_BYTES, SessionError, read_dispatch_frame,
    read_dispatch_frame_or_unauth,
};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn server_endpoint() -> (quinn::Endpoint, SocketAddr, WarrenPubkey) {
    let key = det_signing_key(0x91);
    let cfg = make_server_config(&key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config builds");
    let ep = quinn::Endpoint::server(cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("server binds");
    let addr = ep.local_addr().expect("local_addr after bind");
    let pubkey = WarrenPubkey::from_bytes(*key.verifying_key().as_bytes());
    (ep, addr, pubkey)
}

async fn dial(addr: SocketAddr, pubkey: WarrenPubkey) -> quinn::Connection {
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
async fn oversize_setup_stream_is_rejected_with_setup_stream_read() {
    let (ep, addr, pubkey) = server_endpoint();
    let server = tokio::spawn(async move {
        let conn = ep
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("server handshake");
        read_dispatch_frame(&conn).await
    });

    let conn = dial(addr, pubkey).await;
    let oversize = vec![0u8; MAX_MULTIHOP_SETUP_FRAME_BYTES + 1];
    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    // Once the relay's read_to_end cap trips it closes the whole connection,
    // which can abort this write mid-flight; that failure is expected and not
    // what this test is about (the assertion is on the server outcome
    // below), so it is intentionally ignored here.
    let _ = send.write_all(&oversize).await;
    let _ = send.finish();

    let outcome = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server completes")
        .expect("server task did not panic");
    match outcome {
        Err(SessionError::SetupStreamRead(_)) => {}
        other => panic!("expected SetupStreamRead, got {other:?}"),
    }

    // Keep `conn` (and its implicit close-on-drop) alive until AFTER the
    // server outcome is observed: dropping the client's sole `Connection`
    // handle triggers an implicit CONNECTION_CLOSE, which otherwise races
    // the relay's `accept_bi()` / `read_to_end` and can surface as
    // `NoFirstDatagram` instead of the `SetupStreamRead` this test targets.
    drop(conn);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_peer_that_never_opens_a_stream_yields_no_stream() {
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
    // The peer completes the QUIC + TLS handshake but never opens a bidi
    // stream, then closes: there is nothing to route and no decoy target.
    conn.close(quinn::VarInt::from_u32(0), b"silent peer, no setup stream");

    let outcome = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server completes")
        .expect("server task did not panic");
    assert!(
        matches!(outcome, DispatchFrame::NoStream),
        "expected NoStream, got {outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_reset_mid_read_yields_no_stream() {
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
    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"partial setup bytes, then the sender resets")
        .await
        .expect("partial write");
    send.reset(quinn::VarInt::from_u32(0))
        .expect("reset the stream instead of finishing it");

    let outcome = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server completes")
        .expect("server task did not panic");
    assert!(
        matches!(outcome, DispatchFrame::NoStream),
        "a stream reset mid-read must surface as NoStream (there is nothing left to route or decoy), got {outcome:?}"
    );

    // Keep the connection alive until the server task above has observed the
    // reset; dropping it earlier races the assertion against teardown.
    drop(conn);
}
