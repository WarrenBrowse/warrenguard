//! End-to-end QUIC handshake tests against a real [`RelayServer`].
//!
//! Validates that the relay binds, advertises only `[ALPN_H3]`, accepts
//! an `h3` client dial, and rejects a client offering a non-`h3` ALPN
//! (e.g. the legacy `warren/exit/1` ALPN, which must never negotiate on
//! the relay path).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::ExitId;
use warrenguard_relay::{
    ExitDescriptorSigned, RelayConfig, RelayServer, exit_descriptor_signing_payload,
};
use warrenguard_tls::{default_crypto_provider, make_client_config, name as tls_name};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
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

fn relay_with_loopback_pool() -> (RelayServer, SocketAddr, SigningKey) {
    let op = det_signing_key(0x42);
    let relay_key = det_signing_key(0x77);
    let cfg = Arc::new(RelayConfig {
        bind_addr: "127.0.0.1:0".parse().expect("static addr parses"),
        signing_key_path: PathBuf::from("/dev/null"),
        operational_pubkey: op.verifying_key(),
        exits: vec![signed_descriptor(
            &op,
            ExitId::from_bytes([0xAA; 16]),
            [0x11; 32],
        )],
    });
    let server = RelayServer::new(cfg, &relay_key).expect("relay binds");
    let addr = server.local_addr().expect("local_addr after bind");
    (server, addr, relay_key)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_binds_on_random_local_port_and_advertises_h3_alpn() {
    let (server, server_addr, relay_key) = relay_with_loopback_pool();

    let client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config builds");
    let client_endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");

    let endpoint = server.endpoint();
    let accept_task = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("server gets incoming");
        incoming.await.expect("server handshake completes")
    });

    let server_name = tls_name::encode(warrenguard_tls::WarrenPubkey::from_bytes(
        *relay_key.verifying_key().as_bytes(),
    ));
    let conn = client_endpoint
        .connect_with(client_cfg, server_addr, &server_name)
        .expect("client connect kicks off")
        .await
        .expect("client handshake completes");

    let server_conn = tokio::time::timeout(Duration::from_secs(2), accept_task)
        .await
        .expect("server task completes within timeout")
        .expect("server task did not panic");

    assert!(
        conn.peer_identity().is_some(),
        "RPK identity must be present"
    );
    drop(conn);
    drop(server_conn);
    drop(server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_rejects_client_offering_non_h3_alpn() {
    let (server, server_addr, relay_key) = relay_with_loopback_pool();

    // Clients on the relay path MUST advertise `h3`. A client
    // that only offers a non-h3 ALPN must fail the handshake.
    let client_cfg = make_client_config(default_crypto_provider(), &[b"warren/relay/v999"])
        .expect("client config builds");
    let client_endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");

    let endpoint = server.endpoint();
    let accept_task = tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_secs(2), endpoint.accept()).await {
            Ok(Some(incoming)) => incoming.await.err(),
            _ => None,
        }
    });

    let server_name = tls_name::encode(warrenguard_tls::WarrenPubkey::from_bytes(
        *relay_key.verifying_key().as_bytes(),
    ));
    let result = client_endpoint
        .connect_with(client_cfg, server_addr, &server_name)
        .expect("client connect kicks off")
        .await;
    assert!(
        result.is_err(),
        "client offering non-h3 ALPN must fail to connect, got Ok"
    );

    // Drain server task without failing if it observed the failure.
    let _ = accept_task.await;
    drop(server);
}
