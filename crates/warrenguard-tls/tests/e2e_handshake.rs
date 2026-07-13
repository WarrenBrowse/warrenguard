//! End-to-end QUIC + TLS 1.3 RPK handshake covering both sides of
//! `warrenguard_tls::make_*_config` against a real `quinn::Endpoint`.
//!
//! Unit tests on each module cover the verifier in isolation; this
//! file is the integration anchor that proves the pieces wire up
//! correctly under a live QUIC handshake. Per CLAUDE.md §1 the file
//! stays local-only (loopback `127.0.0.1`); cloud-based bench
//! validation is handled separately.
//!
//! Since protocol v5 the exit requests no client certificate (removing an
//! active-probing tell). The client is anonymous at
//! the TLS layer and authenticates in-band by signing the QUIC TLS
//! channel binding; the first test proves that flow end-to-end.

use std::net::{Ipv4Addr, SocketAddr};

use ed25519_dalek::SigningKey;
use warrenguard_config::ALPN_H3;
use warrenguard_tls::{
    WarrenPubkey, channel_binding, default_crypto_provider, make_client_config, make_server_config,
    name, sign_client_auth, verify_client_auth,
};

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

fn pubkey_of(key: &SigningKey) -> WarrenPubkey {
    WarrenPubkey::from_bytes(*key.verifying_key().as_bytes())
}

/// Builds an endpoint pair (server, client) bound to loopback random
/// ports. The client is anonymous at the TLS layer (no client cert), so
/// only the `server_key` is needed to configure identities. Returns also
/// `server_addr` so the client knows where to dial.
///
/// `server_alpns` and `client_alpns` are passed independently so a test
/// controls each side's ALPN offer.
fn endpoint_pair(
    server_key: &SigningKey,
    server_alpns: &[&[u8]],
    client_alpns: &[&[u8]],
) -> (
    quinn::Endpoint,
    quinn::Endpoint,
    SocketAddr,
    quinn::ClientConfig,
) {
    let provider = default_crypto_provider();
    let server_cfg = make_server_config(server_key, provider.clone(), server_alpns)
        .expect("server config builds");
    let client_cfg = make_client_config(provider, client_alpns).expect("client config builds");

    let server = quinn::Endpoint::server(server_cfg, loopback()).expect("server bind");
    let server_addr = server.local_addr().expect("server local addr");

    let client = quinn::Endpoint::client(loopback()).expect("client bind");

    (server, client, server_addr, client_cfg)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_completes_without_client_cert_and_inband_proof_verifies() {
    let server_key = SigningKey::from_bytes(&[1u8; 32]);
    let client_key = SigningKey::from_bytes(&[2u8; 32]);
    let server_pubkey = pubkey_of(&server_key);
    let client_pubkey = pubkey_of(&client_key);

    let (server, client, server_addr, client_cfg) =
        endpoint_pair(&server_key, &[ALPN_H3], &[ALPN_H3]);

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("server gets Incoming");
        let conn = incoming.await.expect("server handshake completes");
        // The exit requests no client certificate, so it learns no client
        // identity from TLS: the active-probing tell is gone.
        assert!(
            conn.peer_identity().is_none(),
            "exit must NOT learn a client identity from TLS (no CertificateRequest)"
        );
        let cb = channel_binding(&conn).expect("server derives channel binding");
        (server, conn, cb)
    });

    let server_name = name::encode(server_pubkey);
    let client_conn = client
        .connect_with(client_cfg, server_addr, &server_name)
        .expect("connect_with returns Connecting")
        .await
        .expect("client handshake completes");

    // The client authenticates in-band: derive the channel binding and sign
    // a message binding it and the session device_id (this is what goes into
    // Setup).
    let device_id = [0xD1u8; 16]; // warrenguard_wire::DEVICE_ID_LEN
    let client_cb = channel_binding(&client_conn).expect("client derives channel binding");
    let proof = sign_client_auth(&client_key, &client_cb, &device_id);

    let (server, server_conn, server_cb) = server_task.await.expect("server task");

    // RFC 5705: both peers derive the identical exporter value.
    assert_eq!(
        client_cb, server_cb,
        "client and exit must derive the same channel binding"
    );
    // The exit accepts a valid proof against the asserted pubkey + device_id.
    assert!(
        verify_client_auth(&client_pubkey, &server_cb, &device_id, &proof),
        "the exit must accept a valid in-band auth proof"
    );
    // An attacker asserting someone else's allowlisted pubkey, without
    // holding its key, is rejected.
    let attacker = pubkey_of(&SigningKey::from_bytes(&[99u8; 32]));
    assert!(
        !verify_client_auth(&attacker, &server_cb, &device_id, &proof),
        "a proof must not verify against a pubkey that did not sign it"
    );
    // The proof is bound to the device_id: a different device_id is rejected.
    let other_device = [0xD2u8; 16];
    assert!(
        !verify_client_auth(&client_pubkey, &server_cb, &other_device, &proof),
        "a proof must not verify against a different device_id"
    );

    client_conn.close(0u32.into(), b"bye");
    server_conn.close(0u32.into(), b"bye");
    client.wait_idle().await;
    server.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_rejects_client_dialing_a_different_servers_pubkey() {
    let real_server_key = SigningKey::from_bytes(&[5u8; 32]);
    let other_server_key = SigningKey::from_bytes(&[6u8; 32]);

    let (server, client, server_addr, client_cfg) =
        endpoint_pair(&real_server_key, &[ALPN_H3], &[ALPN_H3]);

    // The server may or may not see an Incoming attempt; either way
    // the *client* must surface a verification error because the cert
    // SPKI does not match the SNI it asked for.
    let server_task = tokio::spawn(async move {
        // Drain whatever may show up so the test does not leak a task.
        if let Some(incoming) = server.accept().await {
            // The handshake will fail server-side too once the client
            // alerts; we just await it to avoid an early-drop alert
            // race that would mask the client's error.
            let _ = incoming.await;
        }
        server
    });

    let connecting = client
        .connect_with(
            client_cfg,
            server_addr,
            &name::encode(pubkey_of(&other_server_key)), // wrong identity in SNI
        )
        .expect("connect_with itself is allowed");
    let res = connecting.await;
    assert!(
        res.is_err(),
        "handshake MUST fail when the SNI demands a pubkey the server's RPK cert does not carry"
    );

    let server = server_task.await.unwrap();
    client.wait_idle().await;
    server.wait_idle().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_rejects_alpn_mismatch_between_client_and_server() {
    let server_key = SigningKey::from_bytes(&[8u8; 32]);

    // Server and client offer disjoint ALPNs, so there is no shared
    // application protocol and the handshake must abort.
    let provider = default_crypto_provider();
    let server_cfg = make_server_config(&server_key, provider.clone(), &[b"proto-a"]).unwrap();
    let client_cfg = make_client_config(provider, &[b"proto-b"]).unwrap();

    let server = quinn::Endpoint::server(server_cfg, loopback()).unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = quinn::Endpoint::client(loopback()).unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
        server
    });

    let res = client
        .connect_with(
            client_cfg,
            server_addr,
            &name::encode(pubkey_of(&server_key)),
        )
        .unwrap()
        .await;
    assert!(
        res.is_err(),
        "ALPN mismatch MUST abort the handshake (no shared application protocol)"
    );

    let server = server_task.await.unwrap();
    client.wait_idle().await;
    server.wait_idle().await;
}
