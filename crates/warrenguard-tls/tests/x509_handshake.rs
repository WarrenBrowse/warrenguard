//! v6 X.509 exit mode: the exit presents a real X.509 certificate (so the TLS
//! handshake looks like an ordinary website) instead of an RFC 7250 raw
//! public key. These tests exercise the X.509 config builders with an
//! IN-MEMORY rustls TLS 1.3 handshake (no UDP, no sockets, no firewall):
//! they EMPIRICALLY verify chain validation rather than asserting webpki
//! semantics from memory.
//!
//! Fixtures (`tests/fixtures/*.der`, generated once with openssl, EC P-256
//! like a Let's Encrypt ECDSA cert): a test CA and a leaf for
//! `cover.example.com` signed by it.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

const CA_DER: &[u8] = include_bytes!("fixtures/ca.der");
const LEAF_DER: &[u8] = include_bytes!("fixtures/leaf.der");
const LEAF_KEY_DER: &[u8] = include_bytes!("fixtures/leaf_key.der");
const COVER_NAME: &str = "cover.example.com";
const ALPN_H3: &[u8] = b"h3";

fn exit_server_config() -> ServerConfig {
    let chain = vec![CertificateDer::from(LEAF_DER.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(LEAF_KEY_DER.to_vec()));
    warrenguard_tls::build_server_rustls_config_x509(
        chain,
        key,
        warrenguard_tls::default_crypto_provider(),
        &[ALPN_H3],
    )
    .expect("build x509 server config")
}

fn client_config(roots: RootCertStore) -> ClientConfig {
    warrenguard_tls::build_client_rustls_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[ALPN_H3],
    )
    .expect("build webpki client config")
}

fn roots_trusting_test_ca() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(CA_DER.to_vec()))
        .expect("add test CA to root store");
    roots
}

/// Drives a TLS 1.3 handshake between `client` and `server` entirely in
/// memory. Returns the client-side result: `Ok` once both sides finish, or
/// the first `rustls::Error` the client raises (e.g. certificate rejection).
fn run_handshake(
    server_cfg: ServerConfig,
    client_cfg: ClientConfig,
    name: &str,
) -> Result<(), rustls::Error> {
    let mut server = ServerConnection::new(Arc::new(server_cfg)).expect("server conn");
    let server_name = ServerName::try_from(name.to_owned()).expect("server name");
    let mut client = ClientConnection::new(Arc::new(client_cfg), server_name).expect("client conn");

    for _ in 0..16 {
        let mut c2s = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut c2s).expect("client write_tls");
        }
        let mut s = &c2s[..];
        while !s.is_empty() {
            server.read_tls(&mut s).expect("server read_tls");
        }
        server.process_new_packets().expect("server process");

        let mut s2c = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut s2c).expect("server write_tls");
        }
        let mut c = &s2c[..];
        while !c.is_empty() {
            client.read_tls(&mut c).expect("client read_tls");
        }
        // The client validates the server certificate chain here; a reject
        // surfaces as Err from this call.
        client.process_new_packets()?;

        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Ok(())
}

#[test]
fn x509_handshake_completes_when_client_trusts_the_ca() {
    // The exit presents a real cert chain; a client that trusts the issuing
    // CA validates it like a browser visiting a real site. This is the
    // "looks like an ordinary HTTPS/h3 server" property the X.509 mode buys.
    let result = run_handshake(
        exit_server_config(),
        client_config(roots_trusting_test_ca()),
        COVER_NAME,
    );
    assert!(
        result.is_ok(),
        "a webpki client trusting the issuing CA must complete the X.509 handshake: {result:?}"
    );
}

#[test]
fn x509_handshake_rejected_when_client_does_not_trust_the_ca() {
    // Empirical proof that real chain validation is in force (not bypassed):
    // a client with an empty trust store MUST reject the exit's cert.
    let result = run_handshake(
        exit_server_config(),
        client_config(RootCertStore::empty()),
        COVER_NAME,
    );
    assert!(
        matches!(result, Err(rustls::Error::InvalidCertificate(_))),
        "a client trusting no roots must reject the server cert, got {result:?}"
    );
}

#[test]
fn x509_quinn_configs_build_for_quic() {
    // The exit/client cutover consumes the QUIC-wrapped form. Building the
    // `quinn` configs exercises `QuicServerConfig::try_from` /
    // `QuicClientConfig::try_from`, which reject TLS configs that are not
    // QUIC-compatible - so a successful build is a real integration check,
    // not a tautology.
    let chain = vec![CertificateDer::from(LEAF_DER.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(LEAF_KEY_DER.to_vec()));
    let server = warrenguard_tls::make_server_config_x509(
        chain,
        key,
        warrenguard_tls::default_crypto_provider(),
        &[ALPN_H3],
    );
    assert!(
        server.is_ok(),
        "x509 quinn server config must build: {server:?}"
    );

    let client = warrenguard_tls::make_client_config_webpki(
        roots_trusting_test_ca(),
        warrenguard_tls::default_crypto_provider(),
        &[ALPN_H3],
    );
    assert!(
        client.is_ok(),
        "webpki quinn client config must build: {client:?}"
    );
}

#[test]
fn x509_handshake_rejected_on_wrong_server_name() {
    // SAN binding: the cert is for cover.example.com; dialing a different
    // name must fail name validation even with the CA trusted.
    let result = run_handshake(
        exit_server_config(),
        client_config(roots_trusting_test_ca()),
        "not-the-cover-name.example.com",
    );
    assert!(
        matches!(result, Err(rustls::Error::InvalidCertificate(_))),
        "a name not in the cert SAN must be rejected, got {result:?}"
    );
}
