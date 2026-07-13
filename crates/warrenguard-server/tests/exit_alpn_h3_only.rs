//! Obfuscation invariant: the exit advertises ONLY the `h3` ALPN (RFC 9114),
//! so its TLS handshake is indistinguishable from a public HTTP/3 server at the
//! ALPN layer. It must NOT accept the historical Warren-custom `warren/exit/1`
//! ALPN: an exit that selected it would answer an active probe in a way no real
//! h3 server does, a wire-visible Warren tell. Loopback only,
//! no TUN, no secret.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use warrenguard_config::ALPN_H3;
use warrenguard_server::{ExitBindOpts, ExitListener};
use warrenguard_tls::{WarrenPubkey, default_crypto_provider, make_client_config, name};

/// The Warren-custom ALPN the exit used to accept during the pre-`h3` rollout.
/// A public HTTP/3 server rejects an unknown ALPN with `no_application_protocol`;
/// the exit must behave identically so the offer of a Warren protocol id is not
/// a fingerprint.
const LEGACY_WARREN_ALPN: &[u8] = b"warren/exit/1";

/// Dials the exit offering exactly one ALPN and returns the handshake result.
async fn dial_with_alpn(
    endpoint_addr: SocketAddr,
    exit_pubkey: WarrenPubkey,
    alpn: &[u8],
) -> Result<quinn::Connection, quinn::ConnectionError> {
    let client_cfg = make_client_config(default_crypto_provider(), &[alpn]).expect("client cfg");
    let mut client =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
    client.set_default_client_config(client_cfg);
    let connecting = client
        .connect(endpoint_addr, &name::encode(exit_pubkey))
        .expect("connect returns Connecting");
    // The handshake either completes or aborts on the ALPN alert; neither hangs.
    tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .expect("handshake resolves within 5s")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exit_offers_only_h3_and_rejects_the_legacy_warren_alpn() {
    let exit_key = SigningKey::from_bytes(&[11u8; 32]);
    let exit_pubkey = WarrenPubkey::from_bytes(*exit_key.verifying_key().as_bytes());
    let opts = ExitBindOpts {
        signing_key: Some(exit_key),
        ..Default::default()
    };
    let exit = Arc::new(
        ExitListener::bind_with_opts((Ipv4Addr::LOCALHOST, 0).into(), opts)
            .await
            .expect("exit binds"),
    );
    let endpoint_addr = exit
        .bound_addr()
        .ip_addrs()
        .next()
        .expect("exit has a bound socket addr");

    // Control: a real `h3` client completes the (anonymous) handshake. This
    // proves the exit and the harness are healthy, so the rejection below
    // isolates the ALPN rather than a broken setup.
    let e = exit.clone();
    let server = tokio::spawn(async move { e.accept_one_handshake_for_test().await });
    let h3 = dial_with_alpn(endpoint_addr, exit_pubkey, ALPN_H3).await;
    assert!(
        h3.is_ok(),
        "a real h3 client must still complete the handshake, got {h3:?}"
    );
    server.abort();

    // Tell: a probe offering only the Warren-custom `warren/exit/1` ALPN must be
    // rejected exactly like a public h3 server. No ALPN overlap => the exit must
    // never advertise a Warren-specific protocol id.
    let e = exit.clone();
    let server = tokio::spawn(async move { e.accept_one_handshake_for_test().await });
    let legacy = dial_with_alpn(endpoint_addr, exit_pubkey, LEGACY_WARREN_ALPN).await;
    server.abort();
    assert!(
        legacy.is_err(),
        "the exit must not accept the Warren-custom ALPN; a public h3 server rejects it"
    );
}
