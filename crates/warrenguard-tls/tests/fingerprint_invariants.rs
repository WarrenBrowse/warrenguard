//! Consolidated wire-fingerprint invariants.
//!
//! The Warren wire profile must satisfy the wire-profile invariants
//! (I1-I7) to (a) blend in with a casual HTTP/3 endpoint and (b) defeat
//! the GFW SNI extractor demonstrated in USENIX Security 2025 by Zohaib
//! et al. The live-handshake invariants (I1, I2, I6) are asserted below;
//! the rest are cross-referenced to their dedicated tests (see the two
//! lists that follow).
//!
//! Most of these invariants are *also* covered by more granular
//! tests in their respective crates (`warrenguard-relay` config tests,
//! `warrenguard-tls::name::tests`, and `warrenguard-transport-core`'s
//! `obfuscation_invariants` and `transport_config`). Duplicating them here is
//! deliberate: a single nightly CI workflow
//! (`.github/workflows/fingerprint-nightly.yml`) can exercise the
//! whole contract through one entry point, and the file gives a
//! reviewer a one-stop reading of what the wire profile must look
//! like before merging anything that touches the handshake path.
//!
//! Invariants exercised at the byte level via a real Quinn handshake
//! over loopback:
//!   - I1: ALPN negotiated = `b"h3"` (strict equality).
//!   - I2: SNI ends with `.exits.warrenbrowse.com`.
//!   - I6: SNI carries no `.invalid` TLD (RFC 2606), which would
//!     instantly flag a non-production protocol to DPI.
//!
//! Invariants exercised at source / config level (a pure-Rust loopback
//! test cannot observe wire-level features like the spin bit on
//! 1-RTT short headers without a packet capture framework, which a
//! cloud bench handles):
//!   - I3: >= 2 UDP datagrams in the first Initial flight (cross-referenced to
//!     `warrenguard-transport-core`'s `obfuscation_invariants::initial_crypto_first_fragment_size_present_on_client_path`).
//!   - I4: spin bit constant 0
//!     (cross-referenced to `warrenguard-transport-core::tests::transport_config::warren_transport_config_base_disables_spin_bit`).
//!   - I5: default server port = 443
//!     (cross-referenced to the `warrenguard-relay` `config_loading` bind-addr tests).
//!   - I7: the exit advertises only `h3` and actively rejects the legacy
//!     `warren/exit/1` ALPN (cross-referenced to
//!     `warrenguard-server/tests/exit_alpn_h3_only.rs`).

use std::net::{Ipv4Addr, SocketAddr};

use ed25519_dalek::SigningKey;
use warrenguard_config::ALPN_H3;
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name,
};

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

fn pubkey_of(key: &SigningKey) -> WarrenPubkey {
    WarrenPubkey::from_bytes(*key.verifying_key().as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fingerprint_invariants_i1_i2_i6_on_live_handshake() {
    let server_key = SigningKey::from_bytes(&[60u8; 32]);

    let provider = default_crypto_provider();
    // The exit advertises only `h3` (invariant I7): it never offers a
    // Warren-custom ALPN. That the exit actively REJECTS `warren/exit/1` is
    // proven by `warrenguard-server/tests/exit_alpn_h3_only.rs`.
    let server_cfg = make_server_config(&server_key, provider.clone(), &[ALPN_H3])
        .expect("server config builds");
    let client_cfg = make_client_config(provider, &[ALPN_H3]).expect("client config builds");

    let server = quinn::Endpoint::server(server_cfg, loopback()).expect("server bind");
    let server_addr = server.local_addr().expect("server local_addr");
    let client = quinn::Endpoint::client(loopback()).expect("client bind");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        (server, conn)
    });

    let server_pubkey = pubkey_of(&server_key);
    let server_name = name::encode(server_pubkey);

    // ----- I2 (SNI ends with .exits.warrenbrowse.com) -----
    assert!(
        server_name.ends_with(".exits.warrenbrowse.com"),
        "I2 broken: SNI must end with .exits.warrenbrowse.com to blend in with a casual \
         HTTP/3 endpoint, got {server_name}"
    );
    // ----- I6 (no RFC 2606 `.invalid` TLD on the emit path) -----
    assert!(
        !server_name.contains(".invalid"),
        "I6 broken: SNI emit path must not contain a `.invalid` TLD (RFC 2606 \
         `.invalid` trivially flags a non-production protocol to DPI), got {server_name}"
    );

    let client_conn = client
        .connect_with(client_cfg, server_addr, &server_name)
        .expect("connect_with returns Connecting")
        .await
        .expect("client handshake completes");

    let handshake_data = client_conn
        .handshake_data()
        .expect("handshake data set after handshake completes");
    let hsd = handshake_data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .expect("rustls-backed connections expose quinn::crypto::rustls::HandshakeData");

    let negotiated_alpn = hsd.protocol.as_deref();

    // ----- I1 (ALPN negotiated = `b"h3"`) -----
    assert_eq!(
        negotiated_alpn,
        Some(ALPN_H3),
        "I1 broken: negotiated ALPN must be `h3` exactly, got {:?}",
        negotiated_alpn
    );
    let (server, server_conn) = server_task.await.unwrap();
    client_conn.close(0u32.into(), b"bye");
    server_conn.close(0u32.into(), b"bye");
    client.wait_idle().await;
    server.wait_idle().await;
}
