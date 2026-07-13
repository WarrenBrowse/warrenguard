//! Diagnostic for the stall: traces exactly when the
//! loopback flow stops progressing when the server-side relay-inbound
//! transport config sets `initial_datagram_min_size(1500)`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use quinn::{Endpoint, TransportConfig};
use warrenguard_config::ALPN_H3;
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn relay_inbound_with_pad(extra_min_first: u16) -> Arc<TransportConfig> {
    // Start from a Warren-shape inbound config (BBR + MTU 1350 +
    // keep-alive 20s + idle 60s + spin off + GSO off) so the only
    // variable in the matrix is the experimental
    // `initial_datagram_min_size` server-side knob. Using
    // `TransportConfig::default()` here masks the bug: a server with
    // initial_mtu = 1200 silently truncates the obfuscation-baseline
    // client's 1500 B Initial datagrams below the negotiated path-MTU
    // floor.
    if extra_min_first > 0 {
        // Build a stand-in by hand because the public Warren helpers
        // don't expose a "relay_inbound + extra pad" preset.
        let mut cfg = TransportConfig::default();
        cfg.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()))
            .initial_mtu(warrenguard_config::TUNNEL_INITIAL_MTU)
            .min_mtu(warrenguard_config::TUNNEL_MIN_MTU)
            .mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()))
            .stream_receive_window(quinn::VarInt::from_u32(
                warrenguard_config::QUIC_STREAM_RECV_WINDOW,
            ))
            .receive_window(quinn::VarInt::from_u32(
                warrenguard_config::QUIC_RECV_WINDOW,
            ))
            .send_window(warrenguard_config::QUIC_SEND_WINDOW)
            .enable_segmentation_offload(false)
            .allow_spin(false)
            .max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(Duration::from_secs(
                    warrenguard_config::QUIC_MAX_IDLE_TIMEOUT_SECS,
                ))
                .expect("idle timeout fits in VarInt"),
            ))
            .keep_alive_interval(Some(Duration::from_secs(
                warrenguard_config::QUIC_KEEP_ALIVE_INTERVAL_SECS,
            )))
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(
                warrenguard_config::QUIC_MAX_CONCURRENT_BIDI_STREAMS_EXIT,
            ))
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(0))
            .initial_datagram_min_size(extra_min_first);
        Arc::new(cfg)
    } else {
        warrenguard_transport_core::warren_transport_config_relay_inbound_with_gso(false)
    }
}

async fn run_one(server_pad: u16, client_pad: bool, label: &str) {
    eprintln!("\n[{label}] starting: server_pad={server_pad} client_pad={client_pad}");
    let relay_key = det_signing_key(0x77);

    let provider = default_crypto_provider();
    let mut server_cfg =
        make_server_config(&relay_key, provider, &[ALPN_H3]).expect("relay server config");
    server_cfg.transport_config(relay_inbound_with_pad(server_pad));
    let server_endpoint: Endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("relay bind");
    let server_addr: SocketAddr = server_endpoint.local_addr().expect("server addr");
    eprintln!("[{label}] server bound on {server_addr}");

    let server_handle = tokio::spawn({
        let ep = server_endpoint.clone();
        let label_owned = label.to_owned();
        async move {
            eprintln!("[{label_owned}] server: awaiting accept");
            if let Some(incoming) = ep.accept().await {
                eprintln!("[{label_owned}] server: incoming arrived, awaiting handshake");
                match incoming.await {
                    Ok(_c) => eprintln!("[{label_owned}] server: handshake Ok"),
                    Err(e) => eprintln!("[{label_owned}] server: handshake err: {e}"),
                }
            } else {
                eprintln!("[{label_owned}] server: accept returned None");
            }
        }
    });

    let mut client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
    if client_pad {
        client_cfg.transport_config(
            warrenguard_transport_core::warren_transport_config_client_with_gso(false),
        );
    } else {
        // Vanilla quinn defaults: no client padding.
        let mut tc = TransportConfig::default();
        tc.allow_spin(false)
            .enable_segmentation_offload(false)
            .max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(Duration::from_secs(10))
                    .expect("idle timeout fits in VarInt"),
            ))
            .keep_alive_interval(Some(Duration::from_secs(3)));
        client_cfg.transport_config(Arc::new(tc));
    }
    let client_endpoint =
        Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint bind");
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *relay_key.verifying_key().as_bytes(),
    ));
    eprintln!("[{label}] client: calling connect_with");
    let connecting = match client_endpoint.connect_with(client_cfg, server_addr, &server_name) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[{label}] client: connect_with setup error: {e}");
            return;
        }
    };

    let outcome = tokio::time::timeout(Duration::from_secs(5), connecting).await;
    match outcome {
        Err(_) => eprintln!("[{label}] client: handshake STALLED for 5 s (timeout fired)"),
        Ok(Err(e)) => eprintln!("[{label}] client: handshake error after some time: {e}"),
        Ok(Ok(_conn)) => eprintln!("[{label}] client: handshake Ok"),
    }

    // Best-effort cleanup; bound everything so the test always exits.
    let _ = tokio::time::timeout(Duration::from_millis(500), server_handle).await;
    server_endpoint.close(quinn::VarInt::from_u32(0), b"done");
    client_endpoint.close(quinn::VarInt::from_u32(0), b"done");
    eprintln!("[{label}] cleanup issued");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "loopback diag, stalls reproduce in cells other than \
            the targeted cell; the actual bug surfaces only on a cross-DC cloud backbone, not in CI"]
async fn diag_matrix_pad_options() {
    // Wrap the whole flow in a 30 s safety-net timeout so a hang in
    // any of the 4 matrix cells does not freeze cargo for minutes.
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        // (A) baseline: no server pad, no client pad. Sanity check
        //     loopback handshake works end-to-end.
        run_one(0, false, "A vanilla").await;
        // (B) client pad ON, server pad OFF. This is the /v1
        //     production profile (reverted state). Must work.
        run_one(0, true, "B client pad only").await;
        // (C) server pad ON, client pad OFF. Server pads its
        //     own Initials to 1500 B without the client splitting
        //     its ClientHello.
        run_one(1500, false, "C server pad only").await;
        // (D) BOTH client pad ON and server pad ON. The cloud
        //     configuration that stalled cross-DC.
        run_one(1500, true, "D both pad").await;
    })
    .await;
    match result {
        Ok(()) => eprintln!("\nALL CELLS COMPLETED (one or more may have stalled - see log)"),
        Err(_) => panic!("diag matrix test exceeded 30 s safety net; see log for which cell hung"),
    }
}
