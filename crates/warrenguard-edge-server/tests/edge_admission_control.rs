//! Regression for the M10 fix: `run_edge_listener` used to accept a
//! connection per task with NO pre-auth admission control at all (no QUIC
//! address validation, no per-IP rate/concurrency, no global cap), unlike its
//! sibling `run_edge_entry_listener`. Both now share the same
//! `EdgeAdmissionControl`. This proves the per-IP new-session token-bucket
//! rate limit is enforced on `run_edge_listener` specifically (not just its
//! sibling, which already had the protection before this fix).
//!
//! Loopback only. The admission-control layer runs entirely before the
//! application-level token/handshake logic, so this test never completes an
//! HTTP/3 WebTransport handshake: it only needs the QUIC connect itself to
//! succeed or be refused, which is enough to observe the per-IP rate limit.

use std::sync::Arc;
use std::time::Duration;

use quinn::Endpoint;
use tokio_util::sync::CancellationToken;

use warrenguard_edge_server::{edge_transport_config, run_edge_listener};
use warrenguard_server::{BoxFuture, SessionTokenAdmitter, TOKEN_SERIAL_LEN, TokenAdmission};
use warrenguard_wire::SessionToken;

/// Mirrors the crate-private `PER_IP_SESSION_BURST` constant in
/// `warrenguard-edge-server::lib`. Not exported (it is an internal tuning
/// constant), so this test pins the current value; bump it here if that
/// constant ever changes.
const PER_IP_SESSION_BURST: usize = 32;

/// A `SessionTokenAdmitter` that always rejects. The admission-control layer
/// under test runs entirely before this is ever consulted, so its answer is
/// irrelevant here; it exists only to satisfy `run_edge_listener`'s bound.
struct RejectAllGate;

impl SessionTokenAdmitter for RejectAllGate {
    fn admit<'a>(&'a self, _tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
        Box::pin(async { TokenAdmission::Reject })
    }

    fn renew_live<'a>(&'a self, _live: &'a [[u8; TOKEN_SERIAL_LEN]]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

fn mint_cover_cert() -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "warren-edge-admission-test-root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let leaf_params =
        CertificateParams::new(vec!["cover.example.com".to_string()]).expect("leaf params");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf sign");
    (
        vec![leaf_cert.der().to_vec()],
        leaf_key.serialize_der(),
        ca_cert.der().to_vec(),
    )
}

fn server_endpoint(chain: Vec<Vec<u8>>, key_der: Vec<u8>) -> Endpoint {
    use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let chain_der: Vec<CertificateDer<'static>> =
        chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let mut server_cfg = warrenguard_tls::make_server_config_x509(
        chain_der,
        key,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("x509 server config");
    server_cfg.transport_config(edge_transport_config());
    Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).expect("server bind")
}

fn client_endpoint(root_der: Vec<u8>) -> Endpoint {
    use quinn::rustls::pki_types::CertificateDer;
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der))
        .expect("trust test root");
    let mut client_cfg = warrenguard_tls::make_client_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("webpki client config");
    client_cfg.transport_config(edge_transport_config());
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
    endpoint.set_default_client_config(client_cfg);
    endpoint
}

#[tokio::test]
async fn run_edge_listener_refuses_once_the_per_ip_burst_is_exhausted() {
    let (chain, key_der, root_der) = mint_cover_cert();
    let server = server_endpoint(chain, key_der);
    let addr = server.local_addr().expect("bound addr");
    let shutdown = CancellationToken::new();
    let listener_shutdown = shutdown.clone();
    let listener = tokio::spawn(run_edge_listener(
        server,
        Arc::new(RejectAllGate),
        listener_shutdown,
    ));

    let client = client_endpoint(root_der);

    // Spend the whole per-IP burst back-to-back (no delay): every one of
    // these must be admitted (the QUIC handshake completes). All dial the
    // SAME loopback IP, whatever local port each gets, which is exactly the
    // shape `rate_limit_key` collapses to one bucket.
    let mut held = Vec::with_capacity(PER_IP_SESSION_BURST);
    for i in 0..PER_IP_SESSION_BURST {
        let conn = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .connect(addr, "cover.example.com")
                .expect("connect builds"),
        )
        .await
        .unwrap_or_else(|_| panic!("connection {i} must not time out"))
        .unwrap_or_else(|e| panic!("connection {i} must be admitted within the burst: {e}"));
        held.push(conn);
    }

    // One more, immediately (well within the refill interval): the per-IP
    // token bucket must be empty and refuse it (a QUIC-level
    // CONNECTION_REFUSED close), proving `run_edge_listener` now enforces the
    // same admission control as `run_edge_entry_listener`.
    let over_burst = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .connect(addr, "cover.example.com")
            .expect("connect builds"),
    )
    .await
    .expect("the refusal must arrive promptly, not hang");
    assert!(
        over_burst.is_err(),
        "a connection past the per-IP burst (with no time to refill) must be refused, not admitted"
    );

    // Keep the held connections alive until here so the burst was genuinely
    // still exhausted when the over-burst attempt was made.
    drop(held);
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
}
