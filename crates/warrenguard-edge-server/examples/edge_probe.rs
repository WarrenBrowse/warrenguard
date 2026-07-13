//! Local real-browser validation harness for the edge WebTransport server.
//!
//! Runs [`warrenguard_edge_server::run_edge_listener`] on a UDP port with a
//! freshly minted, short-lived ECDSA P-256 self-signed certificate, and prints
//! the certificate's SHA-256 so a real Chrome can open a WebTransport session to
//! it with `serverCertificateHashes` (which bypasses CA/hostname validation for
//! P-256 certs valid <= 14 days). This closes the real-browser interop loop
//! without any cloud deploy or the production cover certificate.
//!
//! Token gating is bypassed here (an `admit-all` gate): a stock browser has no
//! Warren token, and the point of this harness is to validate the HTTP/3 +
//! WebTransport handshake datapath against a real browser. Token verification is
//! covered by the crate's unit and integration tests.
//!
//! Usage: `cargo run --example edge_probe -- [bind_addr]` (default
//! `127.0.0.1:4433`).

use std::sync::Arc;

use quinn::Endpoint;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_util::sync::CancellationToken;

use warrenguard_edge_server::{
    SessionTokenAdmitter, TokenAdmission, edge_transport_config, serve_edge_session,
};
use warrenguard_server::{BoxFuture, TOKEN_SERIAL_LEN};
use warrenguard_wire::SessionToken;

/// Admits every WebTransport session (no token check). See the module note.
struct AdmitAll;
impl SessionTokenAdmitter for AdmitAll {
    fn admit<'a>(&'a self, _tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
        Box::pin(async { TokenAdmission::Admit { serial: [0u8; 32] } })
    }
    fn renew_live<'a>(&'a self, _live: &'a [[u8; TOKEN_SERIAL_LEN]]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warrenguard_edge_server=debug".into()),
        )
        .init();
    let bind: std::net::SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string())
        .parse()
        .expect("bind addr");

    // Short-lived ECDSA P-256 self-signed cert (Chrome serverCertificateHashes
    // requires P-256 and a validity window <= 14 days).
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "warren-edge-probe");
    params.not_before = rcgen::date_time_ymd(2026, 7, 10);
    params.not_after = rcgen::date_time_ymd(2026, 7, 20);
    let key = rcgen::KeyPair::generate().expect("p256 key");
    let cert = params.self_signed(&key).expect("self-signed");
    let cert_der = cert.der().to_vec();
    let key_der = key.serialize_der();

    let hash = <sha2::Sha256 as sha2::Digest>::digest(&cert_der);
    let hash_hex = hex::encode(hash);
    let js_array = hash
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let mut server_cfg = warrenguard_tls::make_server_config_x509(
        vec![CertificateDer::from(cert_der)],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("server config");
    server_cfg.transport_config(edge_transport_config());
    let endpoint = Endpoint::server(server_cfg, bind).expect("bind");

    println!("edge probe listening on https://{bind}  (ALPN h3, WebTransport)");
    println!("cert SHA-256 (hex): {hash_hex}");
    println!("serverCertificateHashes value (bytes): [{js_array}]");
    println!("Ctrl-C to stop.");

    let gate = Arc::new(AdmitAll);
    let shutdown = CancellationToken::new();
    // Verbose accept loop for diagnostics (real-browser interop bring-up).
    let accept_loop = {
        let gate = gate.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    maybe = endpoint.accept() => {
                        let Some(incoming) = maybe else { break; };
                        let remote = incoming.remote_address();
                        println!("[accept] incoming from {remote}");
                        let gate = gate.clone();
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(conn) => {
                                    let alpn = conn
                                        .handshake_data()
                                        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                                        .and_then(|d| d.protocol.clone())
                                        .map(|p| String::from_utf8_lossy(&p).into_owned())
                                        .unwrap_or_else(|| "<none>".into());
                                    let dgram = conn.max_datagram_size();
                                    println!("[conn] handshake OK from {remote}, alpn={alpn}, max_datagram_size={dgram:?}");
                                    match serve_edge_session(&conn, gate).await {
                                        Ok(outcome) => {
                                            println!("[session] {remote} outcome={outcome:?}");
                                            conn.closed().await;
                                            println!("[session] {remote} closed");
                                        }
                                        Err(e) => println!("[session] {remote} ERROR: {e}"),
                                    }
                                }
                                Err(e) => println!("[conn] handshake FAILED from {remote}: {e}"),
                            }
                        });
                    }
                }
            }
        })
    };
    let _ = tokio::signal::ctrl_c().await;
    shutdown.cancel();
    let _ = accept_loop.await;
}
