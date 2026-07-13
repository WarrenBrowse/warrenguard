//! The relay->exit C2 dialer ([`ExitConnPool`]) must use WebPKI (not
//! the RFC 7250 raw-public-key pin) and dial the cover domain as SNI when the
//! target exit descriptor advertises a `cover_domain`, so a relay can forward to
//! an X.509-mode exit on the unified `:443` dispatcher.
//!
//! Two assertions:
//! 1. with the exit's CA trusted, the WebPKI handshake completes;
//! 2. with the default (Mozilla) trust anchors, the SAME dial is REJECTED -
//!    proving WebPKI validation is load-bearing (not a permissive accept-all)
//!    and that the configurable trust anchor is what admits the test CA.
//!
//! The exit's Warren identity is bound separately by HPKE (the client seals to
//! `exit_x25519_multihop_pubkey`), so this leg needs no in-band proof; the dial
//! itself does not verify the descriptor signature (that gate runs earlier in
//! the relay's pool selection), so dummy signature bytes are fine here.
//!
//! Loopback only; run via the firewall-disabling wrapper on macOS.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use quinn::Endpoint;
use quinn::rustls::RootCertStore;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::ExitId;
use warrenguard_relay::{ExitConnPool, ExitDescriptorSigned};
use warrenguard_tls::{default_crypto_provider, make_server_config_x509};

const COVER_DOMAIN: &str = "cover.example.com";

/// `(ca_der, leaf_der, leaf_key_pkcs8_der)` for `COVER_DOMAIN`.
fn mint_ca_and_leaf() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_params = CertificateParams::new(vec![COVER_DOMAIN.to_owned()]).expect("leaf params");
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("CA-signed leaf");
    (
        ca.der().to_vec(),
        leaf.der().to_vec(),
        leaf_key.serialize_der(),
    )
}

struct FakeX509Exit {
    addr: SocketAddr,
    _endpoint: Endpoint,
    accept_handle: tokio::task::JoinHandle<()>,
}

impl Drop for FakeX509Exit {
    fn drop(&mut self) {
        self.accept_handle.abort();
    }
}

/// An X.509-mode exit dispatcher: presents the cover-domain cert, accepts and
/// holds connections (the C2 dial only needs the handshake to complete).
fn spawn_x509_exit(leaf_der: Vec<u8>, key_der: Vec<u8>) -> FakeX509Exit {
    let chain = vec![CertificateDer::from(leaf_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let server_cfg = make_server_config_x509(chain, key, default_crypto_provider(), &[ALPN_H3])
        .expect("x509 server config");
    let endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("x509 exit binds");
    let addr = endpoint.local_addr().expect("local_addr");
    let listen = endpoint.clone();
    let accept_handle = tokio::spawn(async move {
        while let Some(incoming) = listen.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    let _ = conn.closed().await;
                }
            });
        }
    });
    FakeX509Exit {
        addr,
        _endpoint: endpoint,
        accept_handle,
    }
}

/// An X.509 exit descriptor (cover_domain set). The dial does not verify the
/// descriptor signature, so dummy bytes suffice; `exit_ed25519_pubkey` is unused
/// in X.509 mode (the SNI is the cover domain, not the encoded pubkey).
fn x509_descriptor(endpoint: SocketAddr) -> ExitDescriptorSigned {
    ExitDescriptorSigned {
        exit_id: ExitId::from_bytes([0xC2; 16]),
        exit_ed25519_pubkey: [0u8; 32],
        exit_x25519_multihop_pubkey: [0x11; 32],
        endpoint: Some(endpoint),
        cover_domain: Some(COVER_DOMAIN.to_owned()),
        signature: [0u8; 64],
        dns_disabled: false,
        exit_mlkem768_pubkey: None,
    }
}

fn roots_with(ca_der: Vec<u8>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der))
        .expect("add test CA");
    roots
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c2_dial_completes_webpki_handshake_to_x509_exit() {
    let (ca_der, leaf_der, key_der) = mint_ca_and_leaf();
    let exit = spawn_x509_exit(leaf_der, key_der);
    let descriptor = x509_descriptor(exit.addr);

    let pool = ExitConnPool::new((Ipv4Addr::LOCALHOST, 0).into())
        .expect("pool binds")
        .with_gso(false)
        .with_webpki_roots(roots_with(ca_der));

    let conn = tokio::time::timeout(Duration::from_secs(5), pool.get_or_create(&descriptor))
        .await
        .expect("dial must not time out")
        .expect("the C2 WebPKI dial to an X.509 exit (CA trusted) must complete");
    assert!(
        conn.close_reason().is_none(),
        "the relay->exit connection must be live after a successful WebPKI handshake"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c2_dial_rejects_x509_exit_not_chaining_to_trusted_roots() {
    // Same X.509 exit, but the pool keeps the DEFAULT (Mozilla) trust anchors.
    // The self-issued test CA chains to no public root, so WebPKI must reject
    // the handshake - proving the dialer actually validates the chain.
    let (_ca_der, leaf_der, key_der) = mint_ca_and_leaf();
    let exit = spawn_x509_exit(leaf_der, key_der);
    let descriptor = x509_descriptor(exit.addr);

    let pool = ExitConnPool::new((Ipv4Addr::LOCALHOST, 0).into())
        .expect("pool binds")
        .with_gso(false);

    let result =
        tokio::time::timeout(Duration::from_secs(5), pool.get_or_create(&descriptor)).await;
    match result {
        Ok(Ok(_conn)) => {
            panic!("a cert not chaining to the trusted roots must NOT complete the WebPKI dial")
        }
        Ok(Err(_)) => {}
        Err(_) => panic!("dial should fail fast (cert untrusted), not time out"),
    }
}
