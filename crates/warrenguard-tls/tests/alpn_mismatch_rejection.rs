//! The QUIC handshake MUST reject
//! a client whose ALPN list does not intersect with the server's.
//! This is the negative-side ALPN test: the
//! existing `fingerprint_invariants.rs` only proves the happy path
//! (`b"h3"` negotiated correctly). A regression that silently allows
//! a non-`h3` ALPN to negotiate would defeat the wire
//! fingerprint hardening.

use std::net::{Ipv4Addr, SocketAddr};

use ed25519_dalek::SigningKey;
use warrenguard_config::ALPN_H3;
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name,
};

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_fails_when_client_offers_no_overlapping_alpn() {
    let server_key = SigningKey::from_bytes(&[70u8; 32]);

    let provider = default_crypto_provider();
    // Server insists on h3 only.
    let server_cfg = make_server_config(&server_key, provider.clone(), &[ALPN_H3])
        .expect("server config builds");
    // Client offers a non-matching ALPN.
    let mismatched_alpn: &[u8] = b"not-warren-and-not-h3";
    let client_cfg =
        make_client_config(provider, &[mismatched_alpn]).expect("client config builds");

    let server = quinn::Endpoint::server(server_cfg, loopback()).expect("server bind");
    let server_addr = server.local_addr().expect("server local_addr");
    let client = quinn::Endpoint::client(loopback()).expect("client bind");

    // Drain the server endpoint so the accept side does not hang
    // forever on the failed handshake. We do NOT assert on its
    // result; what matters is that the *client* observes the
    // handshake failure.
    let _server_task = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });

    let server_pubkey = WarrenPubkey::from_bytes(*server_key.verifying_key().as_bytes());
    let server_name = name::encode(server_pubkey);

    let result = client
        .connect_with(client_cfg, server_addr, &server_name)
        .expect("connect_with returns Connecting")
        .await;

    assert!(
        result.is_err(),
        "handshake MUST fail when client and server ALPN lists do not overlap. \
         Allowing a mismatched ALPN to negotiate would defeat the wire \
         fingerprint hardening."
    );
}
