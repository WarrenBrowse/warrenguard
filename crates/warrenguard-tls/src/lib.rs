//! Warren TLS 1.3 configuration backed by raw Ed25519 public keys.
//!
//! This crate turns a peer's `ed25519_dalek::SigningKey` into the
//! [`quinn::ClientConfig`] and [`quinn::ServerConfig`] consumed by the
//! Warren tunnel layer. The EXIT identity is authenticated via TLS 1.3
//! raw public keys (RFC 7250): there is no PKI, no X.509 chain, and no
//! trust anchor list; the client verifies the exit's pubkey against the
//! SNI it dialed.
//!
//! The CLIENT identity is NOT a TLS concern. Since protocol v5 the exit
//! requests no client certificate (that mutual-auth CertificateRequest
//! was an active-probing tell). The client instead
//! authenticates in-band: it signs the QUIC TLS channel binding (see the
//! [`auth`] module) and carries the proof in-band during the handshake,
//! which the exit verifies before its allowlist gate.
//!
//! Three deliberate properties of this RPK layer:
//!
//! 1. 0-RTT is disabled on both sides. Client uses
//!    [`rustls::client::Resumption::disabled`] so no session ticket
//!    is ever stored; server sets `send_tls13_tickets = 0` so none is
//!    ever emitted. Warren's threat model rejects replay-vulnerable
//!    early data on the exit tunnel.
//! 2. TLS 1.2 is rejected at the rustls feature level and again by
//!    the verifier, removing any chance of downgrade.
//! 3. No retry-token / handshake-HMAC plumbing. That concern belongs
//!    to the `quinn::Endpoint` construction site in the transport
//!    crates, not to the TLS RPK layer.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use thiserror::Error;

pub use warrenguard_wire::WarrenPubkey;

pub mod auth;
pub mod certs;
pub mod name;
pub(crate) mod resolver;
mod verifier;

pub use auth::{
    channel_binding, sign_client_auth, sign_relay_auth, sign_server_auth, verify_client_auth,
    verify_relay_auth, verify_server_auth,
};
pub use certs::{
    CertLoadError, load_cert_chain_pem, load_private_key_pem, mozilla_root_store,
    root_store_from_der, root_store_from_pem,
};
use resolver::{MultiKeyCertResolver, ResolveRawPublicKeyCert};
use verifier::{PROTOCOL_VERSIONS, ServerCertificateVerifier};

/// Errors raised while building a TLS config for the Warren tunnel.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WarrenTlsError {
    /// The supplied [`rustls::crypto::CryptoProvider`] is missing the
    /// `TLS_AES_128_GCM_SHA256` cipher suite, which QUIC requires for
    /// initial-packet protection.
    #[error("crypto provider lacks the QUIC initial-packet cipher (TLS_AES_128_GCM_SHA256)")]
    NoInitialCipherSuite,
    /// rustls rejected the higher-level configuration.
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
    /// The QUIC TLS session could not export the channel-binding keying
    /// material used for in-band client authentication (e.g. the
    /// handshake has not completed). See [`crate::channel_binding`].
    #[error("could not export QUIC TLS channel binding")]
    ChannelBindingUnavailable,
}

impl From<quinn::crypto::rustls::NoInitialCipherSuite> for WarrenTlsError {
    fn from(_: quinn::crypto::rustls::NoInitialCipherSuite) -> Self {
        Self::NoInitialCipherSuite
    }
}

/// Returns the default ring-backed crypto provider used by Warren when
/// the caller does not bring its own. Lightweight, no system openssl
/// dependency. Tests typically use this; binaries can swap in
/// `aws_lc_rs` if FIPS or hardware-accelerated AES is needed.
#[must_use]
pub fn default_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Post-quantum crypto provider (feature `pq`): aws-lc-rs backed, offering the
/// hybrid key-exchange group `X25519MLKEM768` first and classical `X25519`
/// second.
///
/// This is ADDITIVE, never substitutive. `X25519` stays offered as the
/// mandatory classical fallback, so a peer that does not implement the hybrid
/// group negotiates exactly the classical security Warren ships today; if the
/// ML-KEM leg is ever broken, security is unchanged from today. The hybrid
/// group's ML-KEM keypair is a fresh TLS 1.3 key_share per handshake, so it is
/// already ephemeral and single-use with nothing to add.
///
/// The kx-group order is pinned EXPLICITLY rather than relying on the provider
/// default: a rustls minor bump must not be able to silently reorder the
/// ClientHello `key_share`, which would move the JA4 fingerprint without a test
/// noticing. Enabling this provider changes the ClientHello shape (extra
/// supported group + larger key_share), so it is gated behind the `pq` feature
/// and must not become the default channel until the JA4 parity nightly is
/// re-pinned against a Chrome-with-MLKEM capture (see the PQ plan section 6).
///
/// aws-lc-rs pulls a C toolchain build dependency, so it lives behind `pq`; the
/// default (ring) build is byte-identical. A target that cannot build aws-lc-rs
/// keeps [`default_crypto_provider`] and negotiates classical only (fail-open to
/// classical, never fail-closed).
#[cfg(feature = "pq")]
#[must_use]
pub fn pq_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    use rustls::crypto::aws_lc_rs;
    Arc::new(rustls::crypto::CryptoProvider {
        kx_groups: vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
        ],
        ..aws_lc_rs::default_provider()
    })
}

/// Builds the [`quinn::ClientConfig`] a Warren client uses to dial an
/// exit.
///
/// The client is anonymous at the TLS layer: it presents no client
/// certificate (since protocol v5 the exit requests none, and the client
/// proves its identity in-band via the [`auth`] module). The exit's
/// pubkey is still verified against the SNI by the
/// embedded [`ServerCertificateVerifier`]. `alpns` is the **ordered** list
/// of ALPN protocols the client offers in its ClientHello, most preferred
/// first; the server picks the first entry of its own list that also
/// appears here. An obfuscation-baseline client offers
/// `&[warrenguard_config::ALPN_H3]` to mimic IETF HTTP/3 on the wire.
///
/// 0-RTT is explicitly off: `enable_early_data` stays at rustls's
/// default `false` and `resumption` is set to
/// [`rustls::client::Resumption::disabled`] to suppress all session
/// ticket caching.
///
/// # Errors
/// - [`WarrenTlsError::NoInitialCipherSuite`] if `crypto_provider`
///   lacks `TLS_AES_128_GCM_SHA256`.
/// - [`WarrenTlsError::Rustls`] on any other rustls config failure.
pub fn make_client_config(
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<quinn::ClientConfig, WarrenTlsError> {
    let server_verifier = Arc::new(ServerCertificateVerifier);

    let mut crypto = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_no_client_auth();

    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    crypto.resumption = rustls::client::Resumption::disabled();
    crypto.enable_early_data = false;

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

/// Builds the [`quinn::ServerConfig`] a Warren exit serves to clients.
/// Same RPK and TLS 1.3 shape as the client side.
///
/// `alpns` is the **ordered** list of ALPN protocols the exit
/// advertises in its rustls `alpn_protocols`. rustls picks the first
/// entry of this list that also appears in the client's offer, so
/// the order encodes the exit's preference. A Warren exit passes
/// `&[ALPN_H3]` (only `h3`), so its ALPN is indistinguishable from a
/// public HTTP/3 server; it never advertises a Warren-specific protocol
/// id, which an active probe would fingerprint.
///
/// 0-RTT is explicitly off: `max_early_data_size` stays at rustls's
/// default `0` and `send_tls13_tickets` is forced to `0` so no
/// NewSessionTicket is ever sent to a client. Without a ticket no
/// resumption is possible, and without resumption no 0-RTT is
/// possible.
///
/// # Errors
/// Same shape as [`make_client_config`].
pub fn make_server_config(
    secret: &SigningKey,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<quinn::ServerConfig, WarrenTlsError> {
    let cert_resolver = Arc::new(ResolveRawPublicKeyCert::new(secret));

    // No client certificate is requested. Demanding mutual TLS auth was an
    // active-probing tell (no public HTTP/3 server sends a
    // CertificateRequest); since protocol v5 the client authenticates
    // in-band during the handshake instead.
    let mut crypto = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    crypto.send_tls13_tickets = 0;
    debug_assert_eq!(
        crypto.max_early_data_size, 0,
        "rustls ServerConfig default for max_early_data_size must remain 0"
    );

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    // Disable QUIC active path
    // migration. Warren is single-path in v1, and migration:true (the
    // Quinn default) lets an attacker who observes the 4-tuple send a
    // probe from a different IP and trigger PATH_CHALLENGE round-trips
    // that aid timing correlation against the user's outbound IP.
    server_cfg.migration(false);
    Ok(server_cfg)
}

/// Like [`make_server_config`] but supports key rotation overlap.
///
/// During the overlap window, the exit accepts TLS handshakes from
/// clients that pin EITHER the current key OR any of the previous
/// keys. The resolver inspects the client's SNI (which encodes the
/// expected pubkey) and selects the matching `CertifiedKey`.
///
/// # Errors
/// Same shape as [`make_server_config`].
pub fn make_server_config_with_rotation(
    current: &SigningKey,
    previous: &[SigningKey],
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<quinn::ServerConfig, WarrenTlsError> {
    let cert_resolver = Arc::new(MultiKeyCertResolver::new(current, previous));

    // No client cert requested (in-band auth since v5); see
    // make_server_config.
    let mut crypto = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    crypto.send_tls13_tickets = 0;
    debug_assert_eq!(
        crypto.max_early_data_size, 0,
        "rustls ServerConfig default for max_early_data_size must remain 0"
    );

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server_cfg.migration(false);
    Ok(server_cfg)
}

/// Builds the rustls **server** config a v6 exit serves: a real X.509
/// certificate chain (v6 X.509 exit mode), so the TLS handshake looks like an
/// ordinary HTTPS/h3 endpoint instead of presenting an RFC 7250 raw public
/// key (the browser-anomalous ClientHello tell). The exit's
/// Warren Ed25519 identity is no longer in TLS; it is proven in-band via
/// [`auth::sign_server_auth`].
///
/// `cert_chain` is the leaf-first DER chain (leaf wildcard cert issued for
/// the cover domain, then any intermediates); `key` is its private key
/// (typically ECDSA P-256, as issued by an ACME CA). Returns the rustls
/// config; the QUIC wrapper is applied at the v6 cutover. TLS 1.3 only,
/// no session tickets (0-RTT off), same as [`make_server_config`].
///
/// # Errors
/// [`WarrenTlsError::Rustls`] on a cert/key mismatch or any rustls config
/// failure.
pub fn build_server_rustls_config_x509(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<rustls::ServerConfig, WarrenTlsError> {
    let mut crypto = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    crypto.send_tls13_tickets = 0;
    Ok(crypto)
}

/// Builds the rustls **client** config a v6 client uses: standard WebPKI
/// verification of the exit's real X.509 chain against `roots` (Mozilla
/// roots in prod; a test CA in tests), exactly like a browser. This
/// replaces the custom RPK verifier (which decoded the exit pubkey from the
/// SNI). The exit's Warren identity is checked SEPARATELY, in-band, via
/// [`auth::verify_server_auth`] against the pubkey the client expects from
/// the signed roster.
///
/// Going pure X.509 (the client no longer offers
/// `server_certificate_type=RawPublicKey`) sidesteps the mixed cert-type
/// rustls bug (rustls#2257) and removes the passive RPK ClientHello tell.
/// TLS 1.3 only, resumption + 0-RTT disabled, same as [`make_client_config`].
///
/// # Errors
/// [`WarrenTlsError::Rustls`] on any rustls config failure.
pub fn build_client_rustls_config_webpki(
    roots: rustls::RootCertStore,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<rustls::ClientConfig, WarrenTlsError> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    crypto.resumption = rustls::client::Resumption::disabled();
    crypto.enable_early_data = false;
    Ok(crypto)
}

/// QUIC-wrapped [`build_server_rustls_config_x509`]: the [`quinn::ServerConfig`]
/// a v6 exit serves. Path migration is disabled, same as [`make_server_config`].
///
/// # Errors
/// Same shape as [`make_server_config`], plus a cert/key mismatch.
pub fn make_server_config_x509(
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<quinn::ServerConfig, WarrenTlsError> {
    let crypto = build_server_rustls_config_x509(cert_chain, key, crypto_provider, alpns)?;
    quic_server_config(crypto)
}

/// Builds the rustls **server** config a v6 exit serves when it presents more
/// than one cover-domain certificate, routing by SNI. `default_chain` /
/// `default_key` is the certificate served for an unrecognized or absent SNI
/// (so a probe always gets a real cert); each `(domain, chain, key)` in
/// `by_sni` is served when the ClientHello SNI equals `domain`. This is the
/// mechanism behind cover-domain rotation: an exit can serve the old and the
/// new cover domain at once during a migration. TLS 1.3 only, no tickets,
/// same as [`build_server_rustls_config_x509`].
///
/// # Errors
/// [`WarrenTlsError::Rustls`] if any private key fails to load or any rustls
/// config step fails.
pub fn build_server_rustls_config_x509_sni(
    default_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    default_key: rustls::pki_types::PrivateKeyDer<'static>,
    by_sni: Vec<(
        String,
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<rustls::ServerConfig, WarrenTlsError> {
    let default_ck = Arc::new(resolver::build_x509_certified_key(
        default_chain,
        default_key,
        &crypto_provider,
    )?);
    let mut by_name = std::collections::HashMap::with_capacity(by_sni.len());
    for (domain, chain, key) in by_sni {
        let ck = resolver::build_x509_certified_key(chain, key, &crypto_provider)?;
        // Normalize to match how rustls presents the ClientHello SNI to the
        // resolver: lowercased, trailing dot trimmed. DNS names are
        // case-insensitive, so a mixed-case or fully-qualified (trailing-dot)
        // registration must still match the dialed name instead of silently
        // falling through to the default cert.
        let key_name = domain.trim_end_matches('.').to_ascii_lowercase();
        by_name.insert(key_name, Arc::new(ck));
    }
    let cert_resolver = Arc::new(resolver::SniX509CertResolver::new(default_ck, by_name));
    let mut crypto = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    crypto.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    crypto.send_tls13_tickets = 0;
    Ok(crypto)
}

/// QUIC-wrapped [`build_server_rustls_config_x509_sni`]: the
/// [`quinn::ServerConfig`] a v6 exit serves when it routes several
/// cover-domain certificates by SNI. Path migration is disabled.
///
/// # Errors
/// Same shape as [`make_server_config_x509`].
pub fn make_server_config_x509_sni(
    default_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    default_key: rustls::pki_types::PrivateKeyDer<'static>,
    by_sni: Vec<(
        String,
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )>,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<quinn::ServerConfig, WarrenTlsError> {
    let crypto = build_server_rustls_config_x509_sni(
        default_chain,
        default_key,
        by_sni,
        crypto_provider,
        alpns,
    )?;
    quic_server_config(crypto)
}

/// Wraps a built rustls [`ServerConfig`](rustls::ServerConfig) into the
/// [`quinn::ServerConfig`] the exit binds, with path migration disabled
/// (shared by the X.509 server builders).
fn quic_server_config(crypto: rustls::ServerConfig) -> Result<quinn::ServerConfig, WarrenTlsError> {
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server_cfg.migration(false);
    Ok(server_cfg)
}

/// QUIC-wrapped [`build_client_rustls_config_webpki`]: the
/// [`quinn::ClientConfig`] a v6 client uses to validate the exit's real
/// X.509 chain against `roots` like a browser.
///
/// # Errors
/// Same shape as [`make_client_config`].
pub fn make_client_config_webpki(
    roots: rustls::RootCertStore,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    alpns: &[&[u8]],
) -> Result<quinn::ClientConfig, WarrenTlsError> {
    let crypto = build_client_rustls_config_webpki(roots, crypto_provider, alpns)?;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn make_client_config_builds_with_default_provider() {
        make_client_config(default_crypto_provider(), &[b"h3"])
            .expect("ring provider supports the QUIC initial cipher");
    }

    #[test]
    fn make_server_config_builds_with_default_provider() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        make_server_config(&key, default_crypto_provider(), &[b"h3"])
            .expect("ring provider supports the QUIC initial cipher");
    }

    #[test]
    fn make_client_config_fails_when_provider_lacks_quic_initial_cipher() {
        // Build a CryptoProvider that *has* providers but no cipher
        // suite at all - rustls will refuse, and our error type must
        // surface NoInitialCipherSuite. This exercises the
        // `From<quinn::crypto::rustls::NoInitialCipherSuite>` impl on
        // a real failure path.
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites.clear();
        let err = make_client_config(Arc::new(provider), &[b"h3"])
            .expect_err("an empty cipher suite list must fail");
        assert!(
            matches!(
                err,
                WarrenTlsError::Rustls(_) | WarrenTlsError::NoInitialCipherSuite
            ),
            "expected NoInitialCipherSuite or rustls error, got {err:?}"
        );
    }

    #[test]
    fn make_server_config_disables_active_path_migration() {
        // Warren is single-path v1 and explicitly disables QUIC active
        // path migration on the server side. Without `.migration(false)`,
        // an attacker who observes the 4-tuple can send a probe from
        // a different IP and trigger PATH_CHALLENGE round-trips that
        // aid timing correlation. Quinn defaults to `migration: true`,
        // so the invariant is asserted on the *final* `ServerConfig`
        // Debug representation (the `migration` field is `pub(crate)`
        // and only reachable through Debug).
        //
        // Side effect: with `migration: false`, Quinn's
        // `TransportParameters::new` propagates
        // `disable_active_migration: true` to the wire-level TP set
        // automatically (see `quinn-proto/src/transport_parameters.rs`
        // line ~163: `disable_active_migration: server_config
        // .is_some_and(|c| !c.migration)`). So a single
        // `.migration(false)` call covers BOTH the server-side
        // enforcement AND the client-facing TP annonce.
        let key = SigningKey::from_bytes(&[2u8; 32]);
        let cfg = make_server_config(&key, default_crypto_provider(), &[b"h3"])
            .expect("server config builds");
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("migration: false"),
            "make_server_config MUST disable active path migration. \
             Server config Debug did not contain `migration: false`."
        );
    }
}

#[cfg(all(test, feature = "pq"))]
mod pq_tests {
    use super::pq_crypto_provider;

    /// The PQ provider must offer the hybrid group FIRST (so the handshake
    /// negotiates post-quantum key agreement whenever the peer supports it) and
    /// STILL offer classical `X25519` as the mandatory fallback: PQ is additive,
    /// never a substitution that could strand a classical-only peer.
    #[test]
    fn pq_provider_offers_hybrid_first_then_classical_fallback() {
        let provider = pq_crypto_provider();
        let names: Vec<rustls::NamedGroup> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(
            names.first().copied(),
            Some(rustls::NamedGroup::X25519MLKEM768),
            "the hybrid PQ group must be offered first"
        );
        assert!(
            names.contains(&rustls::NamedGroup::X25519),
            "classical X25519 must remain offered as the additive fallback"
        );
    }

    /// The PQ provider must still satisfy the QUIC initial-cipher requirement so
    /// `make_client_config` builds: aws-lc-rs ships `TLS_AES_128_GCM_SHA256`.
    #[test]
    fn pq_provider_builds_a_client_config() {
        super::make_client_config(pq_crypto_provider(), &[b"h3"])
            .expect("aws-lc-rs provider supports the QUIC initial cipher");
    }
}
