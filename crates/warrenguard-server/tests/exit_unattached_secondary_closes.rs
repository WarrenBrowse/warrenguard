//! Regression: a multi-conn secondary that never finds a matching primary
//! session (`AttributedSession::attached = false`) must have its QUIC
//! connection closed by the exit right away, not left open until Quinn's
//! idle timeout with no pump ever attached to service it.
//!
//! Drives the real production accept loop (`accept_forever_with_tun`, the
//! same path `client_multi_endpoint.rs` exercises for a well-formed
//! multi-conn session) so this covers `handshake_from_incoming`: the code
//! path that would otherwise register a no-op dispatch entry and spawn a
//! pump for the orphan connection. Loopback only, no secret.

use std::net::Ipv4Addr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warrenguard_config::ALPN_H3;
use warrenguard_server::ExitListener;
use warrenguard_tls::{default_crypto_provider, make_client_config, name};
use warrenguard_transport_core::constants::WARREN_NO_CAPACITY;
use warrenguard_transport_core::packet_device::FakeTun;
use warrenguard_wire::{DEVICE_ID_LEN, Setup, decode_setup_ack, encode_setup};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unattached_secondary_connection_is_closed_promptly_not_left_to_idle_timeout() {
    let exit = ExitListener::bind_localhost().await.expect("bind exit");
    let exit_addr = exit.bound_addr();
    let exit_pubkey = exit.pubkey();
    tokio::spawn(async move {
        let _ = exit.accept_forever_with_tun(FakeTun::new()).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let endpoint_addr = exit_addr
        .ip_addrs()
        .next()
        .expect("exit has a bound socket addr");

    // Raw, authenticated QUIC client (NOT ClientTunnel, which always opens a
    // primary first): it declares itself a SECONDARY (`connection_index = 1`
    // of `total_connections = 2`) without ever having opened a primary
    // connection, so `attribute_session` finds no matching session and
    // returns `attached = false`.
    let client_key = SigningKey::from_bytes(&[42u8; 32]);
    let client_pubkey = *client_key.verifying_key().as_bytes();

    let client_cfg = make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client cfg");
    let mut client =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    client.set_default_client_config(client_cfg);
    let conn = client
        .connect(endpoint_addr, &name::encode(exit_pubkey))
        .expect("connect returns Connecting")
        .await
        .expect("anonymous handshake completes (exit requests no client cert)");

    let cb = warrenguard_tls::channel_binding(&conn).expect("channel binding available");
    let device_id = [7u8; DEVICE_ID_LEN];
    let auth_sig = warrenguard_tls::sign_client_auth(&client_key, &cb, &device_id);
    let setup = Setup::multi_conn(0, 1, 2)
        .with_device_id(device_id)
        .with_auth(client_pubkey, auth_sig);
    let frame = encode_setup(&setup).expect("encode Setup");

    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(&frame).await.expect("write Setup");
    send.finish().expect("finish setup stream");

    // The exit still answers with a SetupAck (a well-behaved client learns
    // `multiconn_attached = false` from it and can retry), but it must also
    // close its own side of the connection right after.
    let ack_bytes = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(4096))
        .await
        .expect("SetupAck read does not hang")
        .expect("exit answers with a SetupAck even for an unattached secondary");
    let ack = decode_setup_ack(&ack_bytes).expect("SetupAck decodes");
    assert!(
        !ack.multiconn_attached,
        "the SetupAck must tell the client it did not attach"
    );

    // The guarded regression: an exit that never closes this connection
    // leaves it alive until Quinn's idle timeout (tens of seconds),
    // with a no-op dispatch entry registered and a pump spawned for it. It
    // must close within a couple of seconds of the ack.
    let close = tokio::time::timeout(Duration::from_secs(3), conn.closed())
        .await
        .expect("exit must close an unattached secondary promptly, not at idle timeout");
    match close {
        quinn::ConnectionError::ApplicationClosed(ac) => {
            assert_eq!(
                ac.error_code, WARREN_NO_CAPACITY,
                "unattached secondary must close with the attribution-failure code"
            );
        }
        other => panic!("expected an application close, got {other:?}"),
    }

    client.close(0u32.into(), b"done");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unattached_secondary_via_handshake_only_surfaces_as_err_and_closes() {
    // Same scenario through `handshake_only` (the single-accept, no-TUN
    // driver behind `accept_one_with_tun` / `accept_one` / `accept_forever`),
    // the second code path that must refuse: returning `Ok` for an
    // unattached secondary here would leave the connection
    // open, letting a caller like `accept_one_with_tun` spawn a pump on it.
    let exit = ExitListener::bind_localhost().await.expect("bind exit");
    let exit_addr = exit.bound_addr();
    let exit_pubkey = exit.pubkey();
    let exit_task = tokio::spawn(async move { exit.accept_one_handshake_for_test().await });

    let endpoint_addr = exit_addr
        .ip_addrs()
        .next()
        .expect("exit has a bound socket addr");

    let client_key = SigningKey::from_bytes(&[43u8; 32]);
    let client_pubkey = *client_key.verifying_key().as_bytes();

    let client_cfg = make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client cfg");
    let mut client =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    client.set_default_client_config(client_cfg);
    let conn = client
        .connect(endpoint_addr, &name::encode(exit_pubkey))
        .expect("connect returns Connecting")
        .await
        .expect("anonymous handshake completes (exit requests no client cert)");

    let cb = warrenguard_tls::channel_binding(&conn).expect("channel binding available");
    let device_id = [8u8; DEVICE_ID_LEN];
    let auth_sig = warrenguard_tls::sign_client_auth(&client_key, &cb, &device_id);
    let setup = Setup::multi_conn(0, 1, 2)
        .with_device_id(device_id)
        .with_auth(client_pubkey, auth_sig);
    let frame = encode_setup(&setup).expect("encode Setup");

    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(&frame).await.expect("write Setup");
    send.finish().expect("finish setup stream");

    let outcome = tokio::time::timeout(Duration::from_secs(5), exit_task)
        .await
        .expect("exit task does not hang")
        .expect("exit task does not panic");
    assert!(
        outcome.is_err(),
        "an unattached secondary must surface as an error, not a fake success"
    );

    let close = tokio::time::timeout(Duration::from_secs(3), conn.closed())
        .await
        .expect("exit must close an unattached secondary promptly, not at idle timeout");
    assert!(
        matches!(close, quinn::ConnectionError::ApplicationClosed(_)),
        "expected an application close, got {close:?}"
    );

    client.close(0u32.into(), b"done");
}
