//! Engine seam for an active-probe decoy.
//!
//! A connection that completes the QUIC + TLS handshake but does NOT present a
//! valid, authenticated Warren `Setup` (here: garbage on the setup stream) is
//! handed to a configured [`UnauthenticatedHandler`] instead of being closed.
//! The decoy itself (a real HTTP/3 site, a reverse proxy) lives in the
//! deployer; this test proves only the engine seam: such a connection reaches
//! the handler. Loopback only, no TUN, no secret.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warrenguard_config::ALPN_H3;
use warrenguard_server::{
    ExitBindOpts, ExitListener, UnauthenticatedHandler, UnauthenticatedProbe,
};
use warrenguard_tls::{WarrenPubkey, default_crypto_provider, make_client_config, name};

const DECOY_REPLY: &[u8] = b"decoy-http3-response";

struct RecordingHandler {
    hit: Arc<tokio::sync::Notify>,
    seen_request: Arc<parking_lot::Mutex<Vec<u8>>>,
}

impl UnauthenticatedHandler for RecordingHandler {
    fn handle(&self, conn: quinn::Connection, probe: UnauthenticatedProbe) {
        // A real deployer speaks HTTP/3 here and serves a decoy site. The test
        // proves the seam hands over BOTH the live connection and the prober's
        // request stream, and that the decoy can reply on it (the connection is
        // not closed). It records the request bytes for assertion.
        *self.seen_request.lock() = probe.request.clone();
        let hit = self.hit.clone();
        tokio::spawn(async move {
            let mut send = probe.send;
            let _ = send.write_all(DECOY_REPLY).await;
            let _ = send.finish();
            // Hold the connection briefly so the client reads the reply.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = &conn;
            hit.notify_one();
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_connection_is_handed_to_the_decoy_handler() {
    let exit_key = SigningKey::from_bytes(&[7u8; 32]);
    let exit_pubkey = WarrenPubkey::from_bytes(*exit_key.verifying_key().as_bytes());

    let notify = Arc::new(tokio::sync::Notify::new());
    let seen_request = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let handler = Arc::new(RecordingHandler {
        hit: notify.clone(),
        seen_request: seen_request.clone(),
    });

    let opts = ExitBindOpts {
        signing_key: Some(exit_key),
        unauthenticated_handler: Some(handler),
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts((Ipv4Addr::LOCALHOST, 0).into(), opts)
        .await
        .expect("exit binds");
    let endpoint_addr = exit
        .bound_addr()
        .ip_addrs()
        .next()
        .expect("exit has a bound socket addr");

    // Drive one handshake attempt on the exit (the handshake_only path).
    let exit_task = tokio::spawn(async move { exit.accept_one_handshake_for_test().await });

    // Raw, anonymous QUIC client (NOT ClientTunnel): it completes the
    // server-auth-only handshake (no client cert), opens a bidi stream and
    // writes bytes that are not a valid Warren Setup. A real censor active
    // probe looks like this from the exit's side.
    let client_cfg = make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client cfg");
    let mut client =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    client.set_default_client_config(client_cfg);
    let conn = client
        .connect(endpoint_addr, &name::encode(exit_pubkey))
        .expect("connect_with returns Connecting")
        .await
        .expect("anonymous handshake completes (exit requests no client cert)");
    const PROBE: &[u8] = b"this is not a valid warren setup frame";
    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(PROBE).await.expect("write garbage setup");
    send.finish().expect("finish setup stream");

    // The seam must route this unauthenticated connection to the decoy handler.
    tokio::time::timeout(Duration::from_secs(5), notify.notified())
        .await
        .expect("the unauthenticated connection must reach the decoy handler within 5s");

    // The decoy received the prober's request verbatim...
    assert_eq!(
        seen_request.lock().as_slice(),
        PROBE,
        "the decoy must receive the prober's request bytes"
    );
    // ...and could reply on the live connection (the seam did not close it).
    let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(4096))
        .await
        .expect("decoy reply does not hang")
        .expect("client receives the decoy reply on the live connection");
    assert_eq!(reply, DECOY_REPLY, "client must receive the decoy reply");

    client.close(0u32.into(), b"done");
    exit_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_connection_without_decoy_closes_without_warren_tell() {
    // With no decoy configured, a peer that completes TLS then sends garbage (an
    // active prober) must NOT receive the Warren-specific WARREN_AUTH_FAILED
    // ("WARR") code or a plaintext reason: that is an identification oracle.
    // It must look like a generic HTTP/3 endpoint rejecting a
    // malformed request: H3_GENERAL_PROTOCOL_ERROR with an empty reason.
    use warrenguard_transport_core::constants::{H3_GENERAL_PROTOCOL_ERROR, WARREN_AUTH_FAILED};

    let exit_key = SigningKey::from_bytes(&[9u8; 32]);
    let exit_pubkey = WarrenPubkey::from_bytes(*exit_key.verifying_key().as_bytes());

    let opts = ExitBindOpts {
        signing_key: Some(exit_key),
        unauthenticated_handler: None,
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts((Ipv4Addr::LOCALHOST, 0).into(), opts)
        .await
        .expect("exit binds");
    let endpoint_addr = exit
        .bound_addr()
        .ip_addrs()
        .next()
        .expect("exit has a bound socket addr");

    let exit_task = tokio::spawn(async move { exit.accept_one_handshake_for_test().await });

    let client_cfg = make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client cfg");
    let mut client =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    client.set_default_client_config(client_cfg);
    let conn = client
        .connect(endpoint_addr, &name::encode(exit_pubkey))
        .expect("connect returns Connecting")
        .await
        .expect("anonymous handshake completes (exit requests no client cert)");
    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"this is not a valid warren setup frame")
        .await
        .expect("write garbage setup");
    send.finish().expect("finish setup stream");

    let err = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("exit closes the unauthenticated connection within 5s");
    match err {
        quinn::ConnectionError::ApplicationClosed(ac) => {
            assert_ne!(
                ac.error_code, WARREN_AUTH_FAILED,
                "an unauthenticated peer must NOT receive the WARR probe-oracle code"
            );
            assert_eq!(
                ac.error_code, H3_GENERAL_PROTOCOL_ERROR,
                "close must mimic a generic HTTP/3 protocol error"
            );
            assert!(
                ac.reason.is_empty(),
                "no plaintext reason tell; got {:?}",
                ac.reason
            );
        }
        other => panic!("expected an application close, got {other:?}"),
    }

    client.close(0u32.into(), b"done");
    exit_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v7_unauthenticated_refusal_closes_without_a_warren_tell() {
    // Anti-oracle for the v7 (anonymous-token) admission path: an exit that
    // does not support v7 (no token admitter) must refuse a well-formed v7
    // client exactly like any unauthenticated peer, NOT with the Warren-specific
    // WARREN_AUTH_FAILED code and a cleartext "v7 not supported" reason. Such a
    // response would be a definitive Warren fingerprint that defeats the decoy
    // seam for an active prober. The default ExitBindOpts has no admitter, so a
    // valid SetupV7 reaches the "no admitter" arm.
    use warrenguard_transport_core::constants::{H3_GENERAL_PROTOCOL_ERROR, WARREN_AUTH_FAILED};
    use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken, SetupV7, encode_setup_v7};

    let exit_key = SigningKey::from_bytes(&[11u8; 32]);
    let exit_pubkey = WarrenPubkey::from_bytes(*exit_key.verifying_key().as_bytes());

    let opts = ExitBindOpts {
        signing_key: Some(exit_key),
        unauthenticated_handler: None,
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts((Ipv4Addr::LOCALHOST, 0).into(), opts)
        .await
        .expect("exit binds");
    let endpoint_addr = exit
        .bound_addr()
        .ip_addrs()
        .next()
        .expect("exit has a bound socket addr");

    let exit_task = tokio::spawn(async move { exit.accept_one_handshake_for_test().await });

    let client_cfg = make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client cfg");
    let mut client =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    client.set_default_client_config(client_cfg);
    let conn = client
        .connect(endpoint_addr, &name::encode(exit_pubkey))
        .expect("connect returns Connecting")
        .await
        .expect("anonymous handshake completes (exit requests no client cert)");

    let setup =
        SetupV7::primary_single(0, [0u8; 16], vec![SessionToken([0x11; SESSION_TOKEN_LEN])]);
    let frame = encode_setup_v7(&setup).expect("encode SetupV7");
    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(&frame).await.expect("write SetupV7");
    send.finish().expect("finish setup stream");

    let err = tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .expect("exit closes the v7-unsupported connection within 5s");
    match err {
        quinn::ConnectionError::ApplicationClosed(ac) => {
            assert_ne!(
                ac.error_code, WARREN_AUTH_FAILED,
                "a v7 refusal must NOT leak the WARR probe-oracle code"
            );
            assert_eq!(
                ac.error_code, H3_GENERAL_PROTOCOL_ERROR,
                "v7 refusal must mimic a generic HTTP/3 protocol error, same as v6"
            );
            assert!(
                ac.reason.is_empty(),
                "no plaintext reason tell (e.g. \"v7 not supported\"); got {:?}",
                ac.reason
            );
        }
        other => panic!("expected an application close, got {other:?}"),
    }

    client.close(0u32.into(), b"done");
    exit_task.abort();
}
