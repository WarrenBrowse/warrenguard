//! Loading X.509 certificate material from PEM, and the root trust
//! anchors a v6 client validates the exit chain against.
//!
//! The v6 X.509 exit mode presents a real X.509 certificate on the exit, so
//! a deployer must feed the engine a PEM cert chain + private key (the ACME
//! `fullchain.pem` + `privkey.pem`) on the server, and the client must
//! validate that chain against a trust store: the bundled Mozilla CA
//! program for public-ACME certificates ([`mozilla_root_store`]), or a
//! self-hosted CA via [`root_store_from_pem`]. These helpers keep the
//! rustls-pemfile glue in one reusable place so every consumer (the CLI,
//! exit binaries, SDKs) loads cert material the same way instead of
//! reimplementing it.

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

/// Errors raised while loading PEM certificate material.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CertLoadError {
    /// The PEM input could not be read or contained malformed PEM blocks.
    #[error("reading PEM: {0}")]
    Pem(#[source] std::io::Error),
    /// The PEM input contained no `CERTIFICATE` block.
    #[error("PEM contained no certificate")]
    NoCertificate,
    /// The PEM input contained no recognizable private key block
    /// (PKCS#8, PKCS#1, or SEC1).
    #[error("PEM contained no private key")]
    NoPrivateKey,
    /// A certificate parsed from PEM was rejected by the trust store
    /// (not a valid trust anchor).
    #[error("adding root certificate to trust store: {0}")]
    Root(#[source] rustls::Error),
}

/// Parses a leaf-first PEM certificate chain (e.g. an ACME `fullchain.pem`)
/// into owned DER certificates.
///
/// # Errors
/// - [`CertLoadError::Pem`] if a PEM block is malformed.
/// - [`CertLoadError::NoCertificate`] if no `CERTIFICATE` block is present.
pub fn load_cert_chain_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, CertLoadError> {
    let mut reader = std::io::BufReader::new(pem);
    let chain = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(CertLoadError::Pem)?;
    if chain.is_empty() {
        return Err(CertLoadError::NoCertificate);
    }
    Ok(chain)
}

/// Parses the first private key (PKCS#8, PKCS#1, or SEC1) from PEM into an
/// owned DER key (e.g. an ACME `privkey.pem`).
///
/// # Errors
/// - [`CertLoadError::Pem`] if a PEM block is malformed.
/// - [`CertLoadError::NoPrivateKey`] if no private-key block is present.
pub fn load_private_key_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, CertLoadError> {
    let mut reader = std::io::BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(CertLoadError::Pem)?
        .ok_or(CertLoadError::NoPrivateKey)
}

/// Builds a [`RootCertStore`] from a PEM bundle of CA certificates, for a
/// deployer running a self-hosted CA instead of a public-ACME chain.
///
/// # Errors
/// - [`CertLoadError::Pem`] / [`CertLoadError::NoCertificate`] as in
///   [`load_cert_chain_pem`].
/// - [`CertLoadError::Root`] if a parsed certificate is not a valid trust
///   anchor.
pub fn root_store_from_pem(pem: &[u8]) -> Result<RootCertStore, CertLoadError> {
    let certs = load_cert_chain_pem(pem)?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert).map_err(CertLoadError::Root)?;
    }
    Ok(store)
}

/// Builds a [`RootCertStore`] from owned DER trust anchors (the shape the
/// transport keeps in its X.509 config). Certificates that fail to parse
/// are skipped; the count of successfully added anchors is returned so the
/// caller can fail closed on an all-garbage input.
#[must_use]
pub fn root_store_from_der(ders: &[Vec<u8>]) -> (RootCertStore, usize) {
    let mut store = RootCertStore::empty();
    let (added, _ignored) =
        store.add_parsable_certificates(ders.iter().map(|d| CertificateDer::from(d.clone())));
    (store, added)
}

/// The bundled Mozilla CA root program as a ready-to-use [`RootCertStore`].
///
/// This is what a v6 client uses in production to validate an exit that
/// presents a public-ACME certificate (Let's Encrypt etc.), exactly the way
/// a browser does. For a self-hosted CA, use [`root_store_from_pem`] instead.
#[must_use]
pub fn mozilla_root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    let (_added, _ignored) =
        store.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
    store
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mints a self-signed cert + key for `name` as PEM, the way an ACME CA
    /// would hand a deployer `fullchain.pem` / `privkey.pem`.
    fn self_signed_pem(name: &str) -> (String, String) {
        let cert =
            rcgen::generate_simple_self_signed(vec![name.to_owned()]).expect("rcgen self-signed");
        (cert.cert.pem(), cert.key_pair.serialize_pem())
    }

    #[test]
    fn load_cert_chain_pem_round_trips_a_single_leaf() {
        let (cert_pem, _) = self_signed_pem("cover.example.com");
        let chain = load_cert_chain_pem(cert_pem.as_bytes()).expect("load cert chain");
        assert_eq!(chain.len(), 1, "one CERTIFICATE block in, one DER cert out");
        assert!(!chain[0].as_ref().is_empty(), "DER cert is non-empty");
    }

    #[test]
    fn load_cert_chain_pem_rejects_input_without_a_certificate() {
        // A private key PEM has no CERTIFICATE block.
        let (_, key_pem) = self_signed_pem("cover.example.com");
        let err =
            load_cert_chain_pem(key_pem.as_bytes()).expect_err("a key-only PEM has no certificate");
        assert!(matches!(err, CertLoadError::NoCertificate), "got {err:?}");
    }

    #[test]
    fn load_private_key_pem_round_trips() {
        let (_, key_pem) = self_signed_pem("cover.example.com");
        load_private_key_pem(key_pem.as_bytes()).expect("load private key");
    }

    #[test]
    fn load_private_key_pem_rejects_input_without_a_key() {
        let (cert_pem, _) = self_signed_pem("cover.example.com");
        let err = load_private_key_pem(cert_pem.as_bytes())
            .expect_err("a cert-only PEM has no private key");
        assert!(matches!(err, CertLoadError::NoPrivateKey), "got {err:?}");
    }

    #[test]
    fn loaded_cert_and_key_build_a_server_config() {
        // The whole point: a PEM pair loaded here must drive the v6 X.509
        // server builder, proving the loaders produce rustls-usable material.
        let (cert_pem, key_pem) = self_signed_pem("cover.example.com");
        let chain = load_cert_chain_pem(cert_pem.as_bytes()).expect("chain");
        let key = load_private_key_pem(key_pem.as_bytes()).expect("key");
        crate::build_server_rustls_config_x509(
            chain,
            key,
            crate::default_crypto_provider(),
            &[b"h3"],
        )
        .expect("a loaded PEM pair must build the X.509 server config");
    }

    #[test]
    fn root_store_from_pem_loads_a_ca() {
        let (ca_pem, _) = self_signed_pem("ca.example.com");
        let store = root_store_from_pem(ca_pem.as_bytes()).expect("load CA");
        assert_eq!(store.len(), 1, "one CA cert in, one trust anchor out");
    }

    #[test]
    fn root_store_from_der_skips_garbage_and_counts_anchors() {
        let (ca_pem, _) = self_signed_pem("ca.example.com");
        let ca_der: Vec<Vec<u8>> = load_cert_chain_pem(ca_pem.as_bytes())
            .expect("ca")
            .into_iter()
            .map(|c| c.as_ref().to_vec())
            .collect();
        let mut ders = ca_der.clone();
        ders.push(vec![0xde, 0xad, 0xbe, 0xef]); // not a cert
        let (store, added) = root_store_from_der(&ders);
        assert_eq!(added, 1, "exactly the one real anchor is added");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn root_store_from_der_reports_zero_for_all_garbage() {
        // The whole reason this returns a count: an all-unparseable root set
        // must report 0 so the caller (the transport) can fail closed instead
        // of building a trust-nothing config that silently fails every dial.
        let (store, added) = root_store_from_der(&[vec![0xde, 0xad, 0xbe, 0xef], vec![0x00]]);
        assert_eq!(added, 0, "no garbage byte string can become a trust anchor");
        assert!(store.is_empty());
    }

    #[test]
    fn mozilla_root_store_is_populated() {
        let store = mozilla_root_store();
        assert!(
            store.len() > 100,
            "the Mozilla program ships well over 100 roots, got {}",
            store.len()
        );
    }
}
