//! Real-browser validation harness for the FUNCTIONAL edge multi-hop entry
//! (`run_edge_entry_listener` -> `pump_multihop_entry`). Unlike `edge_probe`
//! (handshake only), this runs the full datapath against a self-contained fake
//! echo exit: a real browser opens a WebTransport session, writes a Warren
//! setup frame on a WT bidi stream, and sends a DATA datagram; the edge shuttles
//! the setup to the fake exit and pumps the datagram round-trip back.
//!
//! It prints the short-lived ECDSA P-256 cert's SHA-256 so a real Chrome can
//! pin it with `serverCertificateHashes`. `serve_edge_entry` is a blind bridge
//! (admission is end-to-end at the exit) and the exit is a local echo, so no
//! tokens, no cloud, no cover cert are needed: this validates ONLY the
//! real-browser WebTransport datapath through the edge.
//!
//! Usage: `cargo run --example edge_entry_probe -- [edge_bind] [exit_bind]`
//! (defaults `127.0.0.1:4433`, `127.0.0.1:4434`).

use quinn::Endpoint;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_util::sync::CancellationToken;

use warrenguard_edge_server::{PumpError, edge_transport_config, run_edge_entry_listener};
use warrenguard_multihop::ExitId;

/// Mints a self-signed CA + leaf for `name`; returns (leaf chain DER, leaf key
/// DER, root DER). RSA/ECDSA per rcgen default.
fn mint_ca_leaf(name: &str) -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let mut ca = CertificateParams::new(vec![]).expect("ca params");
    ca.distinguished_name
        .push(DnType::CommonName, "warren-edge-entry-probe-root");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca.self_signed(&ca_key).expect("ca self-sign");
    let leaf = CertificateParams::new(vec![name.to_string()]).expect("leaf params");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf sign");
    (
        vec![leaf_cert.der().to_vec()],
        leaf_key.serialize_der(),
        ca_cert.der().to_vec(),
    )
}

fn server_endpoint(chain: Vec<Vec<u8>>, key_der: Vec<u8>, bind: std::net::SocketAddr) -> Endpoint {
    let chain_der: Vec<CertificateDer<'static>> =
        chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let mut cfg = warrenguard_tls::make_server_config_x509(
        chain_der,
        key,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("server config");
    cfg.transport_config(edge_transport_config());
    Endpoint::server(cfg, bind).expect("bind")
}

fn client_endpoint(root_der: Vec<u8>) -> Endpoint {
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der))
        .expect("trust root");
    let mut cfg = warrenguard_tls::make_client_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("client config");
    cfg.transport_config(edge_transport_config());
    let mut ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
    ep.set_default_client_config(cfg);
    ep
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warrenguard_edge_server=debug".into()),
        )
        .init();
    let mut args = std::env::args().skip(1);
    let edge_bind: std::net::SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:4433".into())
        .parse()
        .expect("edge bind");
    let exit_bind: std::net::SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:4434".into())
        .parse()
        .expect("exit bind");

    // Fake echo exit: accepts the shuttled setup (replies with a canned frame)
    // and echoes every DATA datagram.
    let (exit_chain, exit_key, exit_root) = mint_ca_leaf("exit.local");
    let exit_server = server_endpoint(exit_chain, exit_key, exit_bind);
    let exit_addr = exit_server.local_addr().expect("exit addr");
    tokio::spawn(async move {
        while let Some(incoming) = exit_server.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let _ = recv.read_to_end(64 * 1024).await;
                    // Canned reply (opaque to the edge; a real exit seals an IpAssign).
                    let _ = send.write_all(b"warren-edge-entry-probe-setup-reply").await;
                    let _ = send.finish();
                }
                while let Ok(d) = conn.read_datagram().await {
                    if conn.send_datagram(d).is_err() {
                        break;
                    }
                }
            });
        }
    });

    // Edge endpoint: short-lived ECDSA P-256 cert for Chrome serverCertificateHashes.
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "warren-edge-entry-probe");
    params.not_before = rcgen::date_time_ymd(2026, 7, 10);
    params.not_after = rcgen::date_time_ymd(2026, 7, 20);
    let key = rcgen::KeyPair::generate().expect("p256 key");
    let cert = params.self_signed(&key).expect("self-signed");
    let cert_der = cert.der().to_vec();
    let key_der = key.serialize_der();
    let hash = <sha2::Sha256 as sha2::Digest>::digest(&cert_der);
    let js_array = hash
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let edge_endpoint = server_endpoint(vec![cert_der], key_der, edge_bind);
    println!("edge entry probe on https://{edge_bind}  (ALPN h3, WebTransport, functional pump)");
    println!("fake echo exit on {exit_addr}");
    println!("cert SHA-256 (hex): {}", hex::encode(hash));
    println!("serverCertificateHashes value (bytes): [{js_array}]");
    println!("Ctrl-C to stop.");

    let exit_client = client_endpoint(exit_root);
    let dialer = move |_exit_id: ExitId| {
        let exit_client = exit_client.clone();
        async move {
            exit_client
                .connect(exit_addr, "exit.local")
                .map_err(|_| PumpError::ExitDial)?
                .await
                .map_err(|_| PumpError::ExitDial)
        }
    };

    let shutdown = CancellationToken::new();
    let listener = tokio::spawn(run_edge_entry_listener(
        edge_endpoint,
        dialer,
        shutdown.clone(),
    ));
    let _ = tokio::signal::ctrl_c().await;
    shutdown.cancel();
    let _ = listener.await;
}
