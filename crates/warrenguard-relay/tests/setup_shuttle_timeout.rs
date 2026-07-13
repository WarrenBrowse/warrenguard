//! A stuck setup shuttle must fail within its budget, not hold the session in
//! limbo: `forward_session` only starts once the shuttle returns, so an exit
//! that never finishes its setup reply would otherwise leave a session whose
//! streams look alive while zero datagrams are ever pumped (the client sees
//! "connected but no traffic").

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use warrenguard_config::ALPN_H3;
use warrenguard_relay::shuttle_setup_to_exit_with_timeout;
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

/// Spawns an exit that accepts the relay's bi stream, reads the setup frame,
/// and then never replies and never finishes its send side.
fn spawn_silent_exit(exit_key: &SigningKey) -> SocketAddr {
    let provider = default_crypto_provider();
    let server_cfg =
        make_server_config(exit_key, provider, &[ALPN_H3]).expect("exit server config");
    let endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("exit binds");
    let addr = endpoint.local_addr().expect("exit addr");
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok((_send, mut recv)) = conn.accept_bi().await else {
                    return;
                };
                let _ = recv.read_to_end(64 * 1024).await;
                // Hold the connection open forever without answering.
                std::future::pending::<()>().await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stuck_setup_shuttle_errors_within_its_budget() {
    let exit_key = SigningKey::from_bytes(&[0x51; 32]);
    let exit_pub = *exit_key.verifying_key().as_bytes();
    let exit_addr = spawn_silent_exit(&exit_key);

    let provider = default_crypto_provider();
    let endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client binds");
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(exit_pub));

    let client_cfg = make_client_config(provider.clone(), &[ALPN_H3]).expect("client config");
    let exit_conn = Arc::new(
        endpoint
            .connect_with(client_cfg, exit_addr, &server_name)
            .expect("connect setup")
            .await
            .expect("handshake"),
    );

    // Mint a client-side SendStream for the shuttle to answer on: a second
    // connection to the same silent endpoint is enough (never read from).
    let client_cfg = make_client_config(provider, &[ALPN_H3]).expect("client config");
    let client_conn = endpoint
        .connect_with(client_cfg, exit_addr, &server_name)
        .expect("connect setup")
        .await
        .expect("handshake");
    let (client_send, _client_recv) = client_conn.open_bi().await.expect("open bi");

    let started = std::time::Instant::now();
    let result = shuttle_setup_to_exit_with_timeout(
        &exit_conn,
        b"setup-frame",
        client_send,
        Duration::from_millis(300),
    )
    .await;
    let elapsed = started.elapsed();

    let err = result.expect_err("a silent exit must not hang the shuttle");
    assert!(
        err.to_string().contains("timed out"),
        "error must say it timed out, got: {err}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "shuttle must fail within its budget, took {elapsed:?}"
    );
}
