//! TLS boundary glue for the carrier: the real WebPKI TLS 1.3 handshake to the
//! cover domain that the QUIC datagrams ride inside.
//!
//! This is the one place the fallback touches the network as TLS. The rustls
//! configs come from [`warrenguard_tls`] (client WebPKI against the cover roots,
//! server X.509 with the cover certificate), so the handshake is byte-for-byte
//! an ordinary HTTPS/443 handshake to a CT-logged domain. The ALPN and roots are
//! the caller's, so the engine bakes in no cover-domain policy.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::CarrierError;

/// A client TLS stream over TCP: the concrete carrier transport the client
/// wraps as a [`crate::TcpCarrierSocket`].
pub type ClientCarrierStream = tokio_rustls::client::TlsStream<TcpStream>;

/// A server TLS stream over TCP: the concrete carrier transport the exit
/// terminator de-encapsulates.
pub type ServerCarrierStream = tokio_rustls::server::TlsStream<TcpStream>;

/// Completes the WebPKI TLS 1.3 handshake to `cover_domain` over an established
/// `tcp` connection, presenting `cover_domain` as the SNI. `client_config` is a
/// rustls client config validating the cover roots (build it with
/// [`warrenguard_tls::build_client_rustls_config_webpki`], ALPN of the
/// deployer's choice).
///
/// # Errors
/// [`CarrierError::InvalidCoverDomain`] if `cover_domain` is not a valid TLS
/// name, or [`CarrierError::Tls`] if the handshake fails.
pub async fn connect_cover_tls(
    cover_domain: &str,
    tcp: TcpStream,
    client_config: Arc<rustls::ClientConfig>,
) -> Result<ClientCarrierStream, CarrierError> {
    let name = ServerName::try_from(cover_domain.to_owned())
        .map_err(|_| CarrierError::InvalidCoverDomain)?;
    // Nagle would coalesce QUIC datagrams and add latency; the carrier wants
    // each framed datagram out promptly, same as the UDP path.
    let _ = tcp.set_nodelay(true);
    TlsConnector::from(client_config)
        .connect(name, tcp)
        .await
        .map_err(CarrierError::Tls)
}

/// Builds the exit-side TLS acceptor that terminates carrier connections on
/// `:443/tcp`. `server_config` is a rustls server config serving the cover
/// certificate (build it with
/// [`warrenguard_tls::build_server_rustls_config_x509`], same ALPN as the QUIC
/// cover so the TCP path is not a distinct profile). Feed each accepted stream
/// to [`crate::serve_carrier`].
#[must_use]
pub fn cover_tls_acceptor(server_config: Arc<rustls::ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(server_config)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use rustls::RootCertStore;
    use tokio::net::TcpListener;

    use super::*;

    /// A client config that trusts only `roots` (empty, or a specific test CA),
    /// so the tests below control precisely whether the handshake's
    /// certificate verification must succeed or fail.
    fn client_config_trusting(roots: RootCertStore) -> Arc<rustls::ClientConfig> {
        Arc::new(
            warrenguard_tls::build_client_rustls_config_webpki(
                roots,
                warrenguard_tls::default_crypto_provider(),
                &[b"h3"],
            )
            .expect("client config builds"),
        )
    }

    /// Mints a self-signed cert + key for `domain`, mirroring the exit's v6
    /// X.509 cover-domain certificate.
    fn self_signed_server_config(domain: &str) -> Arc<rustls::ServerConfig> {
        let cert = rcgen::generate_simple_self_signed(vec![domain.to_owned()])
            .expect("rcgen self-signed cert");
        let chain =
            warrenguard_tls::load_cert_chain_pem(cert.cert.pem().as_bytes()).expect("cert chain");
        let key = warrenguard_tls::load_private_key_pem(cert.key_pair.serialize_pem().as_bytes())
            .expect("private key");
        Arc::new(
            warrenguard_tls::build_server_rustls_config_x509(
                chain,
                key,
                warrenguard_tls::default_crypto_provider(),
                &[b"h3"],
            )
            .expect("server config builds"),
        )
    }

    /// An SNI that is neither a valid DNS name nor a valid IP literal must be
    /// rejected before any TLS work happens, so no listener is even needed on
    /// the other end (the `TcpStream` is only there to satisfy the type).
    #[tokio::test]
    async fn connect_cover_tls_rejects_invalid_sni() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        // Accept and drop: the client must fail on the SNI before writing
        // anything, so this side is never touched, but keeping it alive
        // avoids a spurious connection-refused error racing the assertion.
        let _accept = tokio::spawn(async move { listener.accept().await });
        let tcp = TcpStream::connect(addr).await.expect("client connects");

        let client_config = client_config_trusting(RootCertStore::empty());
        let err = connect_cover_tls("not a valid sni !!", tcp, client_config)
            .await
            .expect_err("an invalid SNI must be rejected");
        assert!(
            matches!(err, CarrierError::InvalidCoverDomain),
            "got {err:?}"
        );
    }

    /// A real WebPKI handshake against a cert the client does not trust must
    /// surface as `CarrierError::Tls`, never silently succeed: the whole
    /// obfuscation guarantee rests on this being genuine certificate
    /// verification, not a stub.
    #[tokio::test]
    async fn connect_cover_tls_rejects_an_untrusted_cert() {
        let domain = "cover.warrenguard.test";
        let server_config = self_signed_server_config(domain);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            let (tcp, _peer) = listener.accept().await.expect("server accepts");
            // The client is expected to abort once it rejects the cert; a
            // handshake error on this side is the expected outcome, not a
            // test failure.
            let _ = cover_tls_acceptor(server_config).accept(tcp).await;
        });

        let tcp = TcpStream::connect(addr).await.expect("client connects");
        // Empty root store: the self-signed leaf has no matching trust
        // anchor, so certificate verification must fail.
        let client_config = client_config_trusting(RootCertStore::empty());

        let err = connect_cover_tls(domain, tcp, client_config)
            .await
            .expect_err("an untrusted cert must fail the handshake");
        assert!(matches!(err, CarrierError::Tls(_)), "got {err:?}");

        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server task completes")
            .expect("server task did not panic");
    }
}
