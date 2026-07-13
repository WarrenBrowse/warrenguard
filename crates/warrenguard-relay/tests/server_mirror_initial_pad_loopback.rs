//! Reproduce attempt for the caveat: the cross-DC cloud
//! bench observed a handshake stall when `initial_datagram_min_size(1500)`
//! is added to the relay-inbound transport config server-side. tcpdump
//! showed `ClientHello 1200 B + 51 B server reply + silence`, then a
//! 60s timeout. The fix was reverted in commit `cb6e390`.
//!
//! This test tries to reproduce the same stall on loopback so the root
//! cause can be investigated without burning cloud nodes. If the
//! loopback handshake completes cleanly, the stall is path-MTU /
//! cross-DC-specific and the investigation has to happen on a cloud deployment.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use warrenguard_config::ALPN_H3;
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_server_config, name as tls_name,
};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn try_handshake_with_server_mirror_pad() -> Result<(), String> {
    let relay_key = det_signing_key(0x77);

    let provider = default_crypto_provider();
    let mut server_cfg = make_server_config(&relay_key, provider, &[ALPN_H3])
        .map_err(|e| format!("relay server config: {e}"))?;
    // Use the production relay-inbound transport config,
    // which now carries the bidirectional obfuscation knobs
    // (`initial_crypto_first_fragment_size(Some(64))` +
    // `initial_datagram_min_size(1500)`) and `initial_mtu = 1280`. The
    // server-side chunk cap requires the fork bump to
    // `0.11.13-warren.2` (see
    // `crates/warren-tls/tests/quinn_fork_patch.rs::vendored_quinn_proto_first_initial_chunk_cap_is_bidirectional`);
    // GSO is disabled so the test does not depend on the host kernel
    // supporting UDP_SEGMENT.
    server_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_relay_inbound_with_gso(false),
    );
    let server_endpoint: Endpoint = Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into())
        .map_err(|e| format!("relay bind: {e}"))?;
    let server_addr: SocketAddr = server_endpoint
        .local_addr()
        .map_err(|e| format!("server addr: {e}"))?;

    // The spawned server task gets `.abort()`-ed in cleanup (not just
    // dropped) because Quinn-held `Endpoint` clones inside an unfinished
    // `incoming.await` can otherwise keep the runtime busy long after
    // the test function returns - a loopback investigation
    // attributed a > 60 s stall in this exact test to that interaction
    // between `tokio::time::timeout` and the in-flight handshake on
    // a cloned `quinn::Endpoint`.
    let server_handle = tokio::spawn({
        let ep = server_endpoint.clone();
        async move {
            if let Some(incoming) = ep.accept().await {
                let _ = incoming.await;
            }
        }
    });

    let mut client_cfg = make_client_config(default_crypto_provider(), &[ALPN_H3])
        .map_err(|e| format!("client config: {e}"))?;
    client_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_client_with_gso(false),
    );
    let client_endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())
        .map_err(|e| format!("client endpoint bind: {e}"))?;
    let server_name = tls_name::encode(WarrenPubkey::from_bytes(
        *relay_key.verifying_key().as_bytes(),
    ));

    // Use `tokio::select!` rather than `tokio::time::timeout` wrapping
    // the `Connecting` future directly: the latter can leave a Drop
    // tail inside the connect future that interacts badly with the
    // cloned server endpoint in the JoinHandle above.
    let mut connecting = client_endpoint
        .connect_with(client_cfg, server_addr, &server_name)
        .expect("client connect setup");
    let connect_outcome = tokio::select! {
        biased;
        res = &mut connecting => Some(res),
        () = tokio::time::sleep(Duration::from_secs(10)) => None,
    };

    // Force the server task to drop its `Endpoint` clone immediately:
    // a passive `.await` here would block if the spawned task is in
    // an uncancellable point inside `incoming.await`.
    server_handle.abort();
    server_endpoint.close(quinn::VarInt::from_u32(0), b"test done");
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test done");
    let _ = tokio::time::timeout(Duration::from_secs(1), server_endpoint.wait_idle()).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), client_endpoint.wait_idle()).await;

    match connect_outcome {
        None => Err("loopback handshake stalled for 10 s".into()),
        Some(Err(e)) => Err(format!("loopback handshake errored: {e}")),
        Some(Ok(_conn)) => Ok(()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_inbound_server_mirror_initial_pad_completes_handshake_on_loopback() {
    // Wrap the whole flow in a 20 s safety-net timeout so a misbehaving
    // endpoint cleanup never hangs the CI for minutes.
    match tokio::time::timeout(
        Duration::from_secs(20),
        try_handshake_with_server_mirror_pad(),
    )
    .await
    {
        Err(_) => panic!(
            "test wall-clock exceeded 20 s; the stall reproduces on loopback. \
             Next step: instrument quinn-fork to identify which Initial datagram fails to emit \
             or to be accepted by the dialer"
        ),
        Ok(Err(e)) => panic!("{e}"),
        Ok(Ok(())) => {
            // Handshake completes on loopback: the stall is
            // cross-DC-specific (path MTU / backbone
            // reordering / packet loss). Investigation has to happen on
            // a real cross-DC cloud bench, not in CI.
        }
    }
}
