//! De-risk: prove that serving a v6 X.509 certificate chain on
//! the multi-hop dual-role dispatcher does NOT reintroduce the low-PMTU
//! handshake stall that the no-pad multi-hop transport profile exists to avoid.
//!
//! The historical stall (see `warren_transport_config_exit_multihop_with_gso`
//! doc) was caused by PADDING the ServerHello datagram to 1280 B: on an
//! intercontinental hop whose path MTU dipped below ~1308 B the single padded
//! datagram was silently dropped and the handshake never completed. The fix was
//! the no-pad profile (Initial-padding knobs omitted, `initial_mtu = 1280`).
//!
//! The open question was whether an X.509 cert chain (much larger
//! than a 32 B RFC 7250 raw public key) reintroduces the problem. It does not:
//! QUIC fragments the server's Certificate flight across Handshake packets each
//! sized to `initial_mtu` (1280), so a larger chain produces MORE 1280 B
//! datagrams, never a BIGGER one. This test pins that invariant on the wire by
//! wrapping the server socket and asserting no egress datagram during the
//! handshake exceeds 1280 B, while a deliberately multi-cert chain forces the
//! flight to span several datagrams (so the assertion actually bites).
//!
//! 1280 B is the same ceiling the SHIPPING padded relay-inbound profile already
//! emits (`initial_datagram_min_size(1280)`) and the production fleet tolerates,
//! so an X.509 flight that stays at or below it is within the proven envelope.
//!
//! Loopback only; run via the firewall-disabling wrapper on macOS.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::Transmit;
use quinn::{AsyncUdpSocket, UdpPoller};

/// The QUIC `initial_mtu` of the no-pad multi-hop profile (TUNNEL_INITIAL_MTU).
/// No handshake datagram may exceed this, or it risks the low-PMTU drop.
const MTU_FLOOR: usize = 1280;

/// An [`AsyncUdpSocket`] decorator that records the size of every datagram the
/// wrapped socket sends, so a test can assert the on-wire flight stays within a
/// path-MTU floor. Pure delegation (no `unsafe`); `may_fragment` returns `true`
/// to disable Quinn's post-handshake MTU discovery, keeping the recorded max a
/// deterministic function of the handshake flight alone.
#[derive(Debug)]
struct RecordingSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    max_datagram: Arc<AtomicUsize>,
    datagram_count: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicUsize>,
}

impl RecordingSocket {
    fn record(&self, transmit: &Transmit<'_>) {
        // With GSO a single Transmit encodes several datagrams of
        // `segment_size` bytes (the last possibly shorter); the per-datagram
        // size that hits the wire is `segment_size`. Without GSO the whole
        // `contents` is one datagram.
        let per_datagram = transmit.segment_size.unwrap_or(transmit.contents.len());
        self.max_datagram.fetch_max(per_datagram, Ordering::Relaxed);
        self.datagram_count.fetch_add(1, Ordering::Relaxed);
        self.total_bytes
            .fetch_add(transmit.contents.len(), Ordering::Relaxed);
    }
}

impl AsyncUdpSocket for RecordingSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.record(transmit);
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    // Force `allow_mtud = false` in the endpoint so no post-handshake DPLPMTUD
    // probe (which is intentionally large) pollutes the recorded handshake max.
    fn may_fragment(&self) -> bool {
        true
    }
}

/// Mints a self-signed root CA (EC P-256). Returns the rcgen handles plus DER
/// for the client trust store.
fn mint_ca(cn: &str) -> (rcgen::Certificate, rcgen::KeyPair, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params.self_signed(&key).expect("self-signed CA");
    let der = cert.der().to_vec();
    (cert, key, der)
}

/// Mints an intermediate CA signed by `issuer`.
fn mint_intermediate(
    issuer: &rcgen::Certificate,
    issuer_key: &rcgen::KeyPair,
    cn: &str,
) -> (rcgen::Certificate, rcgen::KeyPair) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let key = KeyPair::generate().expect("intermediate key");
    let mut params = CertificateParams::new(Vec::new()).expect("intermediate params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, cn);
    let cert = params
        .signed_by(&key, issuer, issuer_key)
        .expect("issuer-signed intermediate");
    (cert, key)
}

/// Mints a leaf for `cover` signed by `issuer`. Returns `(leaf_der, key_der)`.
fn mint_leaf(
    issuer: &rcgen::Certificate,
    issuer_key: &rcgen::KeyPair,
    cover: &str,
) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, KeyPair};
    let key = KeyPair::generate().expect("leaf key");
    let params = CertificateParams::new(vec![cover.to_owned()]).expect("leaf params");
    let cert = params
        .signed_by(&key, issuer, issuer_key)
        .expect("issuer-signed leaf");
    (cert.der().to_vec(), key.serialize_der())
}

/// Builds a quinn server endpoint that mirrors the dual-role dispatcher: an
/// X.509 server config plus the no-pad multi-hop exit transport profile, on a
/// [`RecordingSocket`]. Returns the endpoint and the recorded counters.
fn x509_multihop_server(
    chain: Vec<Vec<u8>>,
    key_der: Vec<u8>,
) -> (
    quinn::Endpoint,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
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
    server_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_exit_multihop_with_gso(false),
    );

    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
    let runtime = quinn::default_runtime().expect("tokio runtime present");
    let inner = runtime
        .wrap_udp_socket(std_sock)
        .expect("wrap server socket");
    let max_datagram = Arc::new(AtomicUsize::new(0));
    let datagram_count = Arc::new(AtomicUsize::new(0));
    let total_bytes = Arc::new(AtomicUsize::new(0));
    let recording = Arc::new(RecordingSocket {
        inner,
        max_datagram: Arc::clone(&max_datagram),
        datagram_count: Arc::clone(&datagram_count),
        total_bytes: Arc::clone(&total_bytes),
    });
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_cfg),
        recording,
        runtime,
    )
    .expect("server endpoint");
    (endpoint, max_datagram, datagram_count, total_bytes)
}

/// A generic WebPKI client using the GFW-facing multi-hop client transport
/// profile (the padded client-to-relay leg). Trusts `root_der`.
fn multihop_webpki_client(root_der: Vec<u8>) -> quinn::Endpoint {
    use quinn::rustls::pki_types::CertificateDer;
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der))
        .expect("trust the test root");
    let mut client_cfg = warrenguard_tls::make_client_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("webpki client config");
    client_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_client_multihop_with_gso(false),
    );
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
    endpoint.set_default_client_config(client_cfg);
    endpoint
}

#[tokio::test]
async fn x509_cert_flight_on_multihop_profile_never_exceeds_mtu_floor() {
    // A realistic deep chain (root -> int1 -> int2 -> leaf), presenting
    // [leaf, int2, int1]: ~3 EC P-256 certs, large enough that the server's
    // Certificate flight cannot fit in a single 1280 B datagram and MUST be
    // fragmented. This is the worst case for the PMTU concern.
    let (root, root_key, root_der) = mint_ca("warren-test-root");
    let (int1, int1_key) = mint_intermediate(&root, &root_key, "warren-test-int1");
    let (int2, int2_key) = mint_intermediate(&int1, &int1_key, "warren-test-int2");
    let (leaf_der, leaf_key_der) = mint_leaf(&int2, &int2_key, "cover.example.com");
    let chain = vec![leaf_der, int2.der().to_vec(), int1.der().to_vec()];

    let (server, max_datagram, datagram_count, total_bytes) =
        x509_multihop_server(chain, leaf_key_der);
    let server_addr = server.local_addr().expect("server addr");
    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming connection");
        let conn = incoming.await.expect("server-side handshake completes");
        // Hold the connection open briefly so the full handshake flight
        // (including the server's HANDSHAKE_DONE) is flushed and recorded.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(conn);
        server
    });

    let client = multihop_webpki_client(root_der);
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .connect(server_addr, "cover.example.com")
            .expect("connect builds"),
    )
    .await
    .expect("x509 multi-hop-profile handshake must not time out")
    .expect("x509 handshake over the no-pad multi-hop profile must complete");
    // The handshake completed; the cert flight is on the wire.
    drop(conn);
    let _server = accept.await.expect("accept task");

    let max = max_datagram.load(Ordering::Relaxed);
    let count = datagram_count.load(Ordering::Relaxed);
    let total = total_bytes.load(Ordering::Relaxed);

    assert!(
        total > MTU_FLOOR,
        "the deep 3-cert chain must produce a flight larger than one {MTU_FLOOR} B \
         datagram so this test actually exercises fragmentation; total egress was \
         {total} B across {count} datagrams"
    );
    assert!(
        count >= 2,
        "the cert flight must span multiple datagrams (it did not: {count}), \
         otherwise the no-oversized-datagram assertion is vacuous"
    );
    assert!(
        max <= MTU_FLOOR,
        "wire-fingerprint GATE: no handshake datagram may exceed the {MTU_FLOOR} B \
         MTU floor, or X.509 reintroduces the low-PMTU stall the no-pad profile \
         avoids. Largest egress datagram was {max} B (flight: {total} B / {count} \
         datagrams)"
    );
}
