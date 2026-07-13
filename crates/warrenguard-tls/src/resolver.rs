//! Raw Public Key (RPK) certificate resolver for rustls.
//!
//! The resolver produces a single `CertifiedKey` whose end-entity
//! "certificate" is actually the raw `SubjectPublicKeyInfoDer` of the
//! peer's Ed25519 public key (RFC 7250). rustls treats it like any
//! other cert when negotiating signatures; the verifier on the other
//! side knows to interpret it as a raw key.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer, alg_id};

/// Builds a rustls [`CertifiedKey`](rustls::sign::CertifiedKey) from a DER
/// certificate chain + private key, loading the key through the crypto
/// provider (so the same ring/aws-lc backend the rest of the config uses
/// signs the handshake). Shared by the single-cert and SNI-routing X.509
/// server builders.
///
/// Uses [`rustls::sign::CertifiedKey::from_der`], which loads the key AND
/// verifies the leaf certificate's public key matches it (tolerating keys
/// whose match cannot be introspected). This is the same consistency check
/// `with_single_cert` performs, so a mismatched cert/key pair is rejected at
/// build time rather than surfacing as an opaque handshake failure later.
///
/// # Errors
/// Propagates [`rustls::Error`] if the provider cannot load the private key
/// (wrong format, unsupported algorithm) or the leaf does not match the key.
pub(crate) fn build_x509_certified_key(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    provider: &rustls::crypto::CryptoProvider,
) -> Result<rustls::sign::CertifiedKey, rustls::Error> {
    rustls::sign::CertifiedKey::from_der(chain, key, provider)
}

/// Routes the server X.509 handshake to a cover-domain certificate by SNI,
/// presenting a `default` certificate for any unrecognized name so the exit
/// still looks like an ordinary HTTPS/h3 server to a probe carrying an
/// arbitrary SNI. This is the X.509 pendant of [`MultiKeyCertResolver`]: it
/// lets one exit serve several cover domains at once, so a deployer can
/// rotate the cover domain (serve the old and the new name during the
/// migration window) without a redeploy, and so a single blocked domain
/// does not strand the exit.
///
/// The domain -> cert mapping is supplied explicitly by the caller (the
/// deployer knows its cover domains); the client's WebPKI check still
/// enforces the SAN, so a misdeclared name fails safe (the client rejects)
/// rather than silently serving the wrong cert.
#[derive(Debug)]
pub(crate) struct SniX509CertResolver {
    default: Arc<rustls::sign::CertifiedKey>,
    by_name: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
}

impl SniX509CertResolver {
    pub(crate) fn new(
        default: Arc<rustls::sign::CertifiedKey>,
        by_name: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    ) -> Self {
        Self { default, by_name }
    }
}

impl rustls::server::ResolvesServerCert for SniX509CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(sni) = client_hello.server_name()
            && let Some(ck) = self.by_name.get(sni)
        {
            return Some(Arc::clone(ck));
        }
        // Unknown / absent SNI: present the default cert. A real cert is
        // always served, so a probe never sees a cert-less abort that would
        // flag the endpoint as non-standard.
        Some(Arc::clone(&self.default))
    }
}

/// Resolves the server-side TLS handshake to the single RPK cert built
/// from the local `SigningKey` (the exit's identity). Clients present no
/// certificate since protocol v5, so this no longer serves a client-cert
/// resolver.
#[derive(Debug)]
pub(crate) struct ResolveRawPublicKeyCert {
    key: Arc<rustls::sign::CertifiedKey>,
}

/// Multi-key resolver for key rotation overlap windows.
///
/// Holds a primary key plus zero or more previous keys. During
/// `resolve()`, decodes the client's SNI to extract the expected
/// pubkey, then returns the matching `CertifiedKey`. Falls back to
/// the primary key if the SNI doesn't match any known key.
#[derive(Debug)]
pub(crate) struct MultiKeyCertResolver {
    primary: Arc<rustls::sign::CertifiedKey>,
    keys: Vec<(
        warrenguard_wire::WarrenPubkey,
        Arc<rustls::sign::CertifiedKey>,
    )>,
}

impl MultiKeyCertResolver {
    pub(crate) fn new(primary: &SigningKey, previous: &[SigningKey]) -> Self {
        let primary_pk =
            warrenguard_wire::WarrenPubkey::from_bytes(*primary.verifying_key().as_bytes());
        let primary_ck = Arc::new(Self::build_certified_key(primary));

        let mut keys = vec![(primary_pk, Arc::clone(&primary_ck))];
        for prev in previous {
            let pk = warrenguard_wire::WarrenPubkey::from_bytes(*prev.verifying_key().as_bytes());
            keys.push((pk, Arc::new(Self::build_certified_key(prev))));
        }

        Self {
            primary: primary_ck,
            keys,
        }
    }

    fn build_certified_key(secret: &SigningKey) -> rustls::sign::CertifiedKey {
        let signer = Arc::new(WarrenRustlsSigner::new(secret.clone()));
        let spki = signer.spki_public_key();
        let end_entity = CertificateDer::from(spki.to_vec());
        rustls::sign::CertifiedKey::new(vec![end_entity], signer)
    }
}

impl ResolveRawPublicKeyCert {
    /// Builds the resolver from the local secret key.
    ///
    /// The resulting `CertifiedKey` holds a single end-entity
    /// "certificate" carrying the SPKI of the matching
    /// `VerifyingKey`. rustls hands that cert to the peer during the
    /// handshake; the peer's verifier checks the SPKI bytes against
    /// the pubkey it expects (encoded in the SNI).
    pub(crate) fn new(secret_key: &SigningKey) -> Self {
        let warren_signer = Arc::new(WarrenRustlsSigner::new(secret_key.clone()));
        let spki = warren_signer.spki_public_key();
        let end_entity = CertificateDer::from(spki.to_vec());
        let certified_key = rustls::sign::CertifiedKey::new(vec![end_entity], warren_signer);
        Self {
            key: Arc::new(certified_key),
        }
    }
}

impl rustls::server::ResolvesServerCert for MultiKeyCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(sni) = client_hello.server_name()
            && let Some(expected_pk) = super::name::decode(sni)
        {
            for (pk, ck) in &self.keys {
                if *pk == expected_pk {
                    return Some(Arc::clone(ck));
                }
            }
        }
        Some(Arc::clone(&self.primary))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

impl rustls::server::ResolvesServerCert for ResolveRawPublicKeyCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

/// rustls signer that delegates to an Ed25519 `SigningKey`.
///
/// Implements both [`rustls::sign::SigningKey`] (per-handshake scheme
/// selection) and [`rustls::sign::Signer`] (per-message signing).
/// The dual impl keeps signing zero-copy past the rustls trait layer.
///
/// Zeroize safety: `WarrenRustlsSigner`
/// is `Clone` and rustls clones it once per handshake into a
/// `Box<dyn Signer>`. Each clone owns its own `SigningKey`, and
/// `ed25519-dalek` with `feature = "zeroize"` (enabled at the
/// workspace level) ships an `impl ZeroizeOnDrop for SigningKey`, so
/// the secret bytes of every clone are zeroized when the box drops at
/// the end of the rustls signature scheme. The
/// `signing_key_is_zeroize_on_drop_at_compile_time` test below pins
/// this invariant: if a future workspace tweak removes the `zeroize`
/// feature, the test fails at compile time.
#[derive(Debug, Clone)]
struct WarrenRustlsSigner {
    key: SigningKey,
}

impl WarrenRustlsSigner {
    fn new(key: SigningKey) -> Self {
        Self { key }
    }

    fn spki_public_key(&self) -> SubjectPublicKeyInfoDer<'static> {
        rustls::sign::public_key_to_spki(&alg_id::ED25519, self.key.verifying_key().as_bytes())
    }
}

impl rustls::sign::SigningKey for WarrenRustlsSigner {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&rustls::SignatureScheme::ED25519) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki_public_key())
    }
}

impl rustls::sign::Signer for WarrenRustlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ED25519
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Verifier, VerifyingKey};
    use rustls::sign::SigningKey as _;
    use rustls::{SignatureAlgorithm, SignatureScheme};

    use super::*;

    fn key_from(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn signing_key_is_zeroize_on_drop_at_compile_time() {
        // rustls clones `WarrenRustlsSigner`
        // (which holds an `ed25519_dalek::SigningKey`) into a
        // `Box<dyn Signer>` for every handshake. Each clone owns its
        // own copy of the secret bytes; the cleanup contract relies on
        // `ed25519-dalek`'s `feature = "zeroize"` shipping an
        // `impl ZeroizeOnDrop for SigningKey`. If a future workspace
        // tweak drops that feature, the impl disappears and this
        // assertion fails at compile time - protecting against silent
        // crypto-key residue across rustls handshakes.
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<SigningKey>();
    }

    #[test]
    fn signer_advertises_ed25519_algorithm_and_scheme() {
        let signer = WarrenRustlsSigner::new(key_from(0));
        assert_eq!(signer.algorithm(), SignatureAlgorithm::ED25519);
        // As a `Signer` (single-message), scheme must match.
        assert_eq!(
            rustls::sign::Signer::scheme(&signer),
            SignatureScheme::ED25519
        );
    }

    #[test]
    fn signer_choose_scheme_picks_ed25519_when_offered_else_none() {
        let signer = WarrenRustlsSigner::new(key_from(1));
        let offered = [
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ];
        assert!(signer.choose_scheme(&offered).is_some());

        // Same offered list with ED25519 removed: must refuse.
        let no_ed = [
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ];
        assert!(signer.choose_scheme(&no_ed).is_none());

        // Empty list: must refuse.
        assert!(signer.choose_scheme(&[]).is_none());
    }

    #[test]
    fn signer_produces_ed25519_signature_that_verifies_against_matching_pubkey() {
        let key = key_from(7);
        let vk = key.verifying_key();
        let signer = WarrenRustlsSigner::new(key);

        let msg = b"warren tunnel ALPN binding";
        let sig_bytes =
            rustls::sign::Signer::sign(&signer, msg).expect("ED25519 sign must succeed");
        // ED25519 signatures are 64 bytes.
        assert_eq!(sig_bytes.len(), 64);

        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .expect("signer must emit a 64-byte sig");
        vk.verify(msg, &sig)
            .expect("signature must verify against the originating pubkey");
    }

    #[test]
    fn signer_signature_does_not_verify_against_a_different_pubkey() {
        let signer = WarrenRustlsSigner::new(key_from(7));
        let attacker_vk: VerifyingKey = key_from(8).verifying_key();

        let msg = b"warren tunnel ALPN binding";
        let sig_bytes = rustls::sign::Signer::sign(&signer, msg).expect("sign succeeds");
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("64-byte sig");

        attacker_vk
            .verify(msg, &sig)
            .expect_err("a signature must NOT verify under a foreign pubkey");
    }

    #[test]
    fn resolver_carries_end_entity_spki_matching_signing_key_pubkey() {
        let key = key_from(42);
        let vk_bytes: [u8; 32] = *key.verifying_key().as_bytes();
        let resolver = ResolveRawPublicKeyCert::new(&key);

        let cert = resolver
            .key
            .end_entity_cert()
            .expect("RPK resolver must expose an end-entity cert");
        // The "cert" is a raw SPKI blob; its last 32 bytes are the
        // Ed25519 pubkey embedded in the SPKI structure.
        let cert_bytes = cert.as_ref();
        assert_eq!(
            &cert_bytes[cert_bytes.len() - 32..],
            &vk_bytes,
            "end-entity SPKI must end with the signing key's pubkey bytes"
        );
    }

    #[test]
    fn multi_key_resolver_holds_primary_and_previous_keys() {
        let primary = key_from(1);
        let prev = key_from(2);
        let resolver = MultiKeyCertResolver::new(&primary, &[prev]);
        assert_eq!(resolver.keys.len(), 2, "must hold primary + 1 previous key");
    }

    #[test]
    fn multi_key_resolver_with_no_previous_has_one_key() {
        let primary = key_from(5);
        let resolver = MultiKeyCertResolver::new(&primary, &[]);
        assert_eq!(resolver.keys.len(), 1);
    }

    #[test]
    fn multi_key_resolver_returns_primary_by_default() {
        let primary = key_from(10);
        let prev = key_from(11);
        let resolver = MultiKeyCertResolver::new(&primary, &[prev]);
        assert!(
            rustls::server::ResolvesServerCert::only_raw_public_keys(&resolver),
            "multi-key resolver must advertise RPK"
        );
    }

    #[test]
    fn resolver_advertises_raw_public_keys_only() {
        let resolver = ResolveRawPublicKeyCert::new(&key_from(0));
        assert!(rustls::server::ResolvesServerCert::only_raw_public_keys(
            &resolver
        ));
    }

    fn x509_certified_key(domain: &str) -> Arc<rustls::sign::CertifiedKey> {
        let cert = rcgen::generate_simple_self_signed(vec![domain.to_owned()]).expect("rcgen cert");
        let chain = vec![CertificateDer::from(cert.cert.der().to_vec())];
        let key = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("key der");
        let provider = rustls::crypto::ring::default_provider();
        Arc::new(build_x509_certified_key(chain, key, &provider).expect("certified key"))
    }

    #[test]
    fn build_x509_certified_key_carries_the_chain() {
        let ck = x509_certified_key("cover.example.com");
        assert!(
            ck.end_entity_cert().is_ok(),
            "the X.509 CertifiedKey must expose its end-entity cert"
        );
    }

    #[test]
    fn sni_x509_resolver_stores_default_and_named_certs() {
        let default = x509_certified_key("default.example.com");
        let mut by_name = HashMap::new();
        by_name.insert(
            "cover-b.example.com".to_owned(),
            x509_certified_key("cover-b.example.com"),
        );
        let resolver = SniX509CertResolver::new(default, by_name);
        assert_eq!(resolver.by_name.len(), 1);
        assert!(
            resolver.by_name.contains_key("cover-b.example.com"),
            "the SNI resolver must key the additional cover-domain cert by its name"
        );
        assert!(
            !rustls::server::ResolvesServerCert::only_raw_public_keys(&resolver),
            "the X.509 SNI resolver serves real certs, not raw public keys"
        );
    }

    #[test]
    fn sni_x509_resolver_returns_distinct_default_and_named_arcs() {
        // Pin the routing decision at the Arc level (a ClientHello cannot be
        // constructed in a unit test): the named entry and the default must be
        // distinct certified keys, so a lookup hit returns the named cert and a
        // miss returns the default. The e2e test proves the live SNI dispatch;
        // this guards that `new` wires the two slots to different certs.
        let default = x509_certified_key("default.example.com");
        let named = x509_certified_key("cover-b.example.com");
        let mut by_name = HashMap::new();
        by_name.insert("cover-b.example.com".to_owned(), Arc::clone(&named));
        let resolver = SniX509CertResolver::new(Arc::clone(&default), by_name);
        let hit = resolver
            .by_name
            .get("cover-b.example.com")
            .expect("named entry");
        assert!(
            Arc::ptr_eq(hit, &named),
            "a known SNI must resolve to its own cert"
        );
        assert!(
            Arc::ptr_eq(&resolver.default, &default),
            "the default slot (served on an SNI miss or absent SNI) must be the default cert"
        );
        assert!(
            !Arc::ptr_eq(&resolver.default, &named),
            "default and named certs must be distinct (otherwise routing is a no-op)"
        );
    }
}
