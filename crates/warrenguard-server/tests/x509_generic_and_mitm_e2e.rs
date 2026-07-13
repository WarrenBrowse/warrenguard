//! v6 X.509 exit mode end-to-end, the two mandated proofs that the
//! loopback in-band test (`x509_handshake_e2e.rs`) does not cover:
//!
//! 1. A STANDARD quinn+rustls WebPKI client (a stand-in for a browser or
//!    curl, NOT a Warren `ClientTunnel`) completes the QUIC+TLS handshake
//!    against an X.509-mode exit. This is the actual closure proof:
//!    the exit "looks like an ordinary HTTPS/h3 server" to a generic active
//!    prober, with no RPK extension and no pubkey in the SNI.
//! 2. A MITM holding a WebPKI-valid certificate for the cover domain is
//!    still rejected, because it cannot forge the exit's in-band Ed25519
//!    signature over the channel binding. Exercised through the full
//!    transport stack, not just the unit-level `auth` test.
//!
//! Certificates are minted in-memory with rcgen (a CA + a cover-domain
//! leaf), so nothing is checked in. Loopback only; run via the
//! firewall-disabling wrapper on macOS.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use quinn::rustls::pki_types::CertificateDer;
use warrenguard_server::{ExitBindOpts, ExitListener};
use warrenguard_transport::ClientTunnel;
use warrenguard_wire::{WarrenExitAddr, WarrenPubkey};

/// Mints a self-signed CA (EC P-256), returning the rcgen handles plus its
/// DER for a client trust store.
fn mint_ca() -> (rcgen::Certificate, rcgen::KeyPair, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let ca_der = ca_cert.der().to_vec();
    (ca_cert, ca_key, ca_der)
}

/// Signs a leaf certificate for `cover` under `ca`, returning
/// `(leaf_der, leaf_key_pkcs8_der)`.
fn mint_leaf(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    cover: &str,
) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, KeyPair};
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_params = CertificateParams::new(vec![cover.to_owned()]).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, ca_cert, ca_key)
        .expect("CA-signed leaf");
    (leaf_cert.der().to_vec(), leaf_key.serialize_der())
}

/// Mints a CA and a leaf certificate for `cover`, returning DER bytes:
/// `(ca_der, leaf_der, leaf_key_pkcs8_der)`.
fn ca_and_leaf(cover: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (ca_cert, ca_key, ca_der) = mint_ca();
    let (leaf_der, leaf_key_der) = mint_leaf(&ca_cert, &ca_key, cover);
    (ca_der, leaf_der, leaf_key_der)
}

/// Builds a plain quinn+rustls WebPKI client endpoint trusting `ca_der`, and
/// dials `socket` with `sni`. Models a generic (non-Warren) client / active
/// prober. Returns the endpoint alongside the connection so the caller keeps
/// the endpoint alive for the connection's lifetime.
async fn webpki_dial(
    ca_der: Vec<u8>,
    socket: std::net::SocketAddr,
    sni: &str,
) -> Result<(quinn::Endpoint, quinn::Connection), quinn::ConnectionError> {
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der))
        .expect("trust the test CA");
    let client_cfg = warrenguard_tls::make_client_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("webpki client config");
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(socket, sni)
        .expect("connect builds")
        .await?;
    Ok((endpoint, conn))
}

/// Asserts a connection negotiated the `h3` ALPN (so it blends in with a
/// casual HTTP/3 endpoint).
fn assert_h3(conn: &quinn::Connection) {
    let hsd = conn
        .handshake_data()
        .expect("handshake data after completion")
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .expect("rustls handshake data");
    assert_eq!(
        hsd.protocol.as_deref(),
        Some(b"h3".as_slice()),
        "the X.509 exit must negotiate the h3 ALPN with a generic client"
    );
}

#[tokio::test]
async fn generic_webpki_client_completes_x509_handshake() {
    let (ca_der, leaf_der, leaf_key_der) = ca_and_leaf("cover.example.com");
    let opts = ExitBindOpts {
        tls_certificate: Some((vec![leaf_der], leaf_key_der)),
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts("127.0.0.1:0".parse().unwrap(), opts)
        .await
        .expect("bind x509-mode exit");
    let exit_socket = exit
        .bound_addr()
        .ip_addrs()
        .next()
        .expect("exit has a bound socket");
    tokio::spawn(exit.accept_one());

    // A plain quinn+rustls client: stock WebPKI verification against the CA,
    // no Warren in-band auth. It does not even send a `Setup`. The QUIC+TLS
    // handshake completing is the whole proof: a generic client (browser /
    // prober) sees an ordinary, cert-valid h3 endpoint.
    let (_endpoint, conn) = tokio::time::timeout(
        Duration::from_secs(5),
        webpki_dial(ca_der, exit_socket, "cover.example.com"),
    )
    .await
    .expect("handshake must not time out")
    .expect("a generic WebPKI client must complete the QUIC+TLS handshake to an X.509 exit");
    assert_h3(&conn);
}

#[tokio::test]
async fn one_exit_serves_two_cover_domains_routed_by_sni() {
    // Cover-domain rotation: one exit holds a default cert for
    // cover-a and an additional SNI-routed cert for cover-b, both under the
    // same CA. A generic client dialing either domain must complete the
    // handshake and receive the certificate whose SAN matches the dialed name,
    // so a deployer can rotate the cover domain (serve old + new at once)
    // without a redeploy.
    let (ca_cert, ca_key, ca_der) = mint_ca();
    let (leaf_a, key_a) = mint_leaf(&ca_cert, &ca_key, "cover-a.example.com");
    let (leaf_b, key_b) = mint_leaf(&ca_cert, &ca_key, "cover-b.example.com");
    let opts = ExitBindOpts {
        tls_certificate: Some((vec![leaf_a], key_a)),
        tls_certificates_by_sni: vec![("cover-b.example.com".to_owned(), vec![leaf_b], key_b)],
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts("127.0.0.1:0".parse().unwrap(), opts)
        .await
        .expect("bind multi-cover-domain exit");
    let exit_socket = exit.bound_addr().ip_addrs().next().expect("bound socket");
    // Drive each incoming QUIC handshake concurrently. The generic clients
    // send no `Setup`, so we only need the handshake to complete (cert served
    // + validated); reading a `Setup` is out of scope here. `exit` stays alive
    // in scope so its endpoint is not dropped.
    let ep = exit.endpoint_handle();
    let _accept = tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });

    let (_ep_a, conn_a) = tokio::time::timeout(
        Duration::from_secs(5),
        webpki_dial(ca_der.clone(), exit_socket, "cover-a.example.com"),
    )
    .await
    .expect("no timeout")
    .expect("the default cover domain (cover-a) must validate via WebPKI");
    assert_h3(&conn_a);

    let (_ep_b, conn_b) = tokio::time::timeout(
        Duration::from_secs(5),
        webpki_dial(ca_der, exit_socket, "cover-b.example.com"),
    )
    .await
    .expect("no timeout")
    .expect("the SNI-routed cover domain (cover-b) must validate via WebPKI");
    assert_h3(&conn_b);
}

#[tokio::test]
async fn cover_domain_sni_lookup_is_case_insensitive() {
    // rustls hands the resolver a lowercased SNI; the cover-domain map must be
    // normalized so a mixed-case registration still matches. Register cover-b
    // under an UPPERCASE key; a client dialing the lowercase name must still be
    // served the cover-b cert (not the default), so its WebPKI SAN check passes.
    // Before normalization this fell through to the default cert and failed.
    let (ca_cert, ca_key, ca_der) = mint_ca();
    let (leaf_a, key_a) = mint_leaf(&ca_cert, &ca_key, "cover-a.example.com");
    let (leaf_b, key_b) = mint_leaf(&ca_cert, &ca_key, "cover-b.example.com");
    let opts = ExitBindOpts {
        tls_certificate: Some((vec![leaf_a], key_a)),
        tls_certificates_by_sni: vec![("COVER-B.EXAMPLE.COM".to_owned(), vec![leaf_b], key_b)],
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts("127.0.0.1:0".parse().unwrap(), opts)
        .await
        .expect("bind multi-cover-domain exit");
    let exit_socket = exit.bound_addr().ip_addrs().next().expect("bound socket");
    let ep = exit.endpoint_handle();
    let _accept = tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            tokio::spawn(async move {
                let _ = incoming.await;
            });
        }
    });

    let (_ep, conn) = tokio::time::timeout(
        Duration::from_secs(5),
        webpki_dial(ca_der, exit_socket, "cover-b.example.com"),
    )
    .await
    .expect("no timeout")
    .expect("an uppercase-registered cover domain must match a lowercase SNI dial");
    assert_h3(&conn);
}

#[tokio::test]
async fn x509_client_fails_closed_on_all_unparseable_roots() {
    // An all-garbage root set must NOT build a trust-nothing WebPKI config that
    // silently fails every dial; the client bails at bind time with a clear
    // error. No server needed: the root store is built before any network I/O.
    let client =
        ClientTunnel::new().with_x509(vec![vec![0xde, 0xad, 0xbe, 0xef]], "x.example".into());
    let target = WarrenExitAddr::new(WarrenPubkey::from_bytes([0u8; 32]))
        .with_ip_addr("127.0.0.1:1".parse().unwrap());
    let err = client
        .handshake(target)
        .await
        .expect_err("a client with no valid X.509 root must fail closed");
    assert!(
        format!("{err}").contains("no valid root certificate"),
        "must fail closed on the empty trust anchor set, got: {err}"
    );
}

#[tokio::test]
async fn x509_webpki_mode_rejects_a_cert_not_chaining_to_mozilla_roots() {
    // `with_x509_webpki` must validate against the bundled Mozilla program, not
    // a permissive/empty store. An exit presenting a self-signed cert (which
    // chains to no public CA) must be rejected at the TLS layer, BEFORE the
    // in-band exit-identity check. This proves the Mozilla roots are actually
    // wired: an empty/permissive store would let the handshake reach (and fail
    // at) the in-band proof instead.
    let self_signed = rcgen::generate_simple_self_signed(vec!["cover.example.com".to_owned()])
        .expect("self-signed leaf");
    let leaf_der = self_signed.cert.der().to_vec();
    let key_der = self_signed.key_pair.serialize_der();
    let opts = ExitBindOpts {
        tls_certificate: Some((vec![leaf_der], key_der)),
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts("127.0.0.1:0".parse().unwrap(), opts)
        .await
        .expect("bind x509-mode exit");
    let exit_socket = exit.bound_addr().ip_addrs().next().expect("bound socket");
    let exit_id = exit.bound_addr().id;
    tokio::spawn(exit.accept_one());

    let client = ClientTunnel::new().with_x509_webpki("cover.example.com".to_owned());
    let target = WarrenExitAddr::new(exit_id).with_ip_addr(exit_socket);
    let err = tokio::time::timeout(Duration::from_secs(5), client.handshake(target))
        .await
        .expect("handshake must not time out")
        .expect_err("a self-signed cert must be rejected by the Mozilla-roots WebPKI verifier");
    assert!(
        !format!("{err}").contains("exit identity"),
        "rejection must happen at TLS (cert not trusted), not at the in-band proof, got: {err}"
    );
}

#[tokio::test]
async fn mitm_with_valid_cert_but_wrong_identity_is_rejected() {
    // The exit holds a real identity key and a CA-valid cover-domain cert.
    let (ca_der, leaf_der, leaf_key_der) = ca_and_leaf("cover.example.com");
    let opts = ExitBindOpts {
        tls_certificate: Some((vec![leaf_der], leaf_key_der)),
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts("127.0.0.1:0".parse().unwrap(), opts)
        .await
        .expect("bind x509-mode exit");
    let exit_socket = exit
        .bound_addr()
        .ip_addrs()
        .next()
        .expect("exit has a bound socket");
    tokio::spawn(exit.accept_one());

    // The client trusts the CA (so the cert validates via WebPKI), but it
    // expects a DIFFERENT exit identity than the one actually serving (the
    // pubkey it would have received from a signed roster). This models a MITM
    // that obtained a valid cert for the cover domain: WebPKI passes, but the
    // in-band proof is signed by the real exit key and cannot match the
    // expected pubkey, so the handshake must fail closed.
    let wrong_expected = WarrenPubkey::from_bytes(
        *SigningKey::from_bytes(&[0xAB; 32])
            .verifying_key()
            .as_bytes(),
    );
    let target = WarrenExitAddr::new(wrong_expected).with_ip_addr(exit_socket);
    let client = ClientTunnel::new().with_x509(vec![ca_der], "cover.example.com".to_owned());

    let err = tokio::time::timeout(Duration::from_secs(5), client.handshake(target))
        .await
        .expect("handshake must not time out")
        .expect_err("a WebPKI-valid cert with a forged identity must be rejected");
    assert!(
        format!("{err}").contains("exit identity"),
        "rejection must be the in-band exit-identity proof failing, got: {err}"
    );
}
