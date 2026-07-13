//! End-to-end: a REAL quinn handshake driven entirely through the TCP carrier.
//!
//! The client's quinn endpoint runs on a [`TcpCarrierSocket`] whose "wire" is an
//! in-memory duplex stream (standing in for the cover-domain TLS stream, the
//! network boundary we mock). The other end of the duplex is de-encapsulated by
//! [`terminate_carrier`] and shuttled over loopback UDP to a real quinn server.
//! If the QUIC handshake completes and application bytes echo back, the framing
//! encapsulation and de-encapsulation are correct in both directions: a
//! handshake cannot succeed if a single datagram is mis-framed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use warrenguard_config::ALPN_H3;
use warrenguard_tcp_fallback::{
    TcpCarrierSocket, build_carrier_client_endpoint, terminate_carrier,
};
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name,
};

/// Fixed test identity for the exit; the SNI the client dials is derived from it.
fn exit_key() -> SigningKey {
    SigningKey::from_bytes(&[0x2a; 32])
}

/// Spawns a real quinn server on loopback UDP, returns its endpoint + address +
/// the SNI a client must present.
async fn spawn_quic_server() -> (Endpoint, SocketAddr, String) {
    let key = exit_key();
    let pubkey = WarrenPubkey::from_bytes(key.verifying_key().to_bytes());
    let sni = name::encode(pubkey);
    let server_config = make_server_config(&key, default_crypto_provider(), &[ALPN_H3])
        .expect("server config builds");
    let endpoint = Endpoint::server(server_config, (std::net::Ipv4Addr::LOCALHOST, 0).into())
        .expect("quinn server binds loopback UDP");
    let addr = endpoint.local_addr().expect("server local addr");
    (endpoint, addr, sni)
}

#[tokio::test]
async fn quic_handshake_and_echo_survive_the_carrier() {
    let (server, server_addr, sni) = spawn_quic_server().await;

    // The exit-side accept loop: one connection, one echoed bi-stream.
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("server accepts a connection");
        let conn = incoming.await.expect("server completes the handshake");
        let (mut send, mut recv) = conn.accept_bi().await.expect("server accepts a bi stream");
        let mut buf = vec![0u8; 4];
        recv.read_exact(&mut buf)
            .await
            .expect("server reads the ping");
        send.write_all(b"pong")
            .await
            .expect("server writes the pong");
        send.finish().expect("server finishes the stream");
        // Keep the connection alive until the client has read the pong.
        conn.closed().await;
        buf
    });

    // The carrier "wire": one in-memory duplex stands in for the cover TLS
    // stream. client_side <-> term_side.
    let (client_side, term_side) = tokio::io::duplex(256 * 1024);

    // Exit-side terminator shuttles the de-encapsulated datagrams to the real
    // quinn server over a fresh loopback UDP socket.
    tokio::spawn(async move {
        let _ = terminate_carrier(term_side, server_addr).await;
    });

    // Client-side: a quinn endpoint whose datapath is the carrier socket.
    let client_config =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config builds");
    let socket = TcpCarrierSocket::new(client_side, server_addr);
    let endpoint = build_carrier_client_endpoint(socket, client_config)
        .expect("carrier client endpoint builds");

    let connect = endpoint
        .connect(server_addr, &sni)
        .expect("connect starts over the carrier");
    let conn = tokio::time::timeout(Duration::from_secs(10), connect)
        .await
        .expect("handshake does not hang over the carrier")
        .expect("QUIC handshake completes through the TCP carrier");

    let (mut send, mut recv) = conn.open_bi().await.expect("client opens a bi stream");
    send.write_all(b"ping").await.expect("client writes ping");
    send.finish().expect("client finishes send");
    let mut back = vec![0u8; 4];
    recv.read_exact(&mut back).await.expect("client reads pong");
    assert_eq!(
        &back, b"pong",
        "app bytes must round-trip through the carrier"
    );

    conn.close(0u32.into(), b"done");

    let server_saw = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task completes")
        .expect("server task did not panic");
    assert_eq!(&server_saw, b"ping", "server received the exact ping bytes");

    let _ = Arc::new(endpoint);
}
