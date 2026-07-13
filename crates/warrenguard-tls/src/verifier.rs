//! TLS 1.3 server-certificate verifier for raw public keys.
//!
//! Only the client-side verifier remains: the client checks that the
//! exit's RPK "certificate" carries the Ed25519 pubkey encoded in the SNI
//! it dialed, and that the `CertificateVerify` signature was produced by
//! the matching private key. The exit requests no client certificate
//! since protocol v5 (the client authenticates in-band; see
//! [`crate::auth`]), so
//! there is no client-cert verifier here anymore.
//!
//! TLS 1.2 is rejected at the rustls feature level (no `tls12`
//! feature) and again here, removing any downgrade surface.

use rustls::pki_types::{
    CertificateDer, ServerName, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer, UnixTime,
    alg_id,
};
use rustls::{
    CertificateError, DigitallySignedStruct, SignatureScheme, SupportedProtocolVersion,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature_with_raw_key},
};

/// Warren accepts TLS 1.3 and nothing else.
pub(crate) const PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

const ED25519_DALEK: Ed25519Dalek = Ed25519Dalek;
const SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&ED25519_DALEK],
    mapping: &[(SignatureScheme::ED25519, &[&ED25519_DALEK])],
};

/// rustls client-side verifier: the exit sends an RPK "cert"; this
/// struct decides whether to trust the embedded SPKI pubkey before
/// letting the handshake complete. It accepts the exit iff the RPK pubkey
/// equals the one the client encoded in the SNI it dialed, and the
/// `CertificateVerify` signature is valid under that key.
#[derive(Default, Debug)]
pub(crate) struct ServerCertificateVerifier;

impl ServerCertVerifier for ServerCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ServerName::DnsName(dns_name) = server_name else {
            return Err(rustls::Error::UnsupportedNameType);
        };
        let Some(remote_pubkey) = super::name::decode(dns_name.as_ref()) else {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ));
        };

        if !intermediates.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }

        let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
        let remote_public_spki =
            rustls::sign::public_key_to_spki(&alg_id::ED25519, remote_pubkey.as_bytes());

        if remote_public_spki != end_entity_as_spki {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &SUPPORTED_SIG_ALGS,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SUPPORTED_SIG_ALGS.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// `webpki`-compatible Ed25519 signature verifier backed by
/// `ed25519-dalek`. Used by [`verify_tls13_signature_with_raw_key`]
/// to actually check the bytes of the CertificateVerify signature.
#[derive(Debug)]
struct Ed25519Dalek;

impl SignatureVerificationAlgorithm for Ed25519Dalek {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), rustls::pki_types::InvalidSignature> {
        let pk_bytes: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| rustls::pki_types::InvalidSignature)?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes)
            .map_err(|_| rustls::pki_types::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| rustls::pki_types::InvalidSignature)?;
        // verify_strict (not the lenient verify): rejects small-order
        // public keys and non-canonical R/S encodings, closing the
        // malleability / cofactor surface on the CertificateVerify
        // signature. The peer's RPK identity is otherwise pinned, but a
        // strict check keeps the signature math unambiguous.
        public_key
            .verify_strict(message, &signature)
            .map_err(|_| rustls::pki_types::InvalidSignature)
    }

    fn public_key_alg_id(&self) -> rustls::pki_types::AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> rustls::pki_types::AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn fips(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::{Signer as _, SigningKey};
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::pki_types::DnsName;

    use super::*;
    use crate::WarrenPubkey;

    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000))
    }

    fn cert_for(key: &SigningKey) -> CertificateDer<'static> {
        let spki =
            rustls::sign::public_key_to_spki(&alg_id::ED25519, key.verifying_key().as_bytes());
        CertificateDer::from(spki.to_vec())
    }

    /// # Panics
    ///
    /// Panics if `name::encode` produces a string that fails `DnsName::try_from`.
    /// The encode/decode round trip is covered by `name::tests::roundtrip_*`,
    /// so this can only happen if those tests are broken.
    fn server_name_for(key: &SigningKey) -> ServerName<'static> {
        let pk = WarrenPubkey::from_bytes(*key.verifying_key().as_bytes());
        let name = crate::name::encode(pk);
        ServerName::DnsName(DnsName::try_from(name).expect("warren name must be a valid DnsName"))
    }

    /// Hand-builds a `DigitallySignedStruct` over the wire format
    /// (`Codec::read`), since rustls's `DigitallySignedStruct::new` is
    /// `pub(crate)`. The `internal::msgs::codec::{Codec, Reader}`
    /// re-export is `#[doc(hidden)]` but stable enough for integration
    /// tests per rustls's own doc-comment.
    fn dss_from_parts(scheme: SignatureScheme, sig: &[u8]) -> DigitallySignedStruct {
        let mut wire = Vec::with_capacity(4 + sig.len());
        scheme.encode(&mut wire);
        let len = u16::try_from(sig.len()).expect("sig length fits in u16");
        wire.extend_from_slice(&len.to_be_bytes());
        wire.extend_from_slice(sig);
        let mut reader = Reader::init(&wire);
        DigitallySignedStruct::read(&mut reader).expect("hand-crafted DSS must parse")
    }

    fn ed25519_dss(key: &SigningKey, msg: &[u8]) -> DigitallySignedStruct {
        let sig_bytes = key.sign(msg).to_bytes();
        dss_from_parts(SignatureScheme::ED25519, &sig_bytes)
    }

    // ---------------- ServerCertVerifier: NEGATIVE FIRST ---------------- //

    #[test]
    fn server_verifier_rejects_cert_with_pubkey_not_matching_sni() {
        let real_server = SigningKey::from_bytes(&[1u8; 32]);
        let attacker = SigningKey::from_bytes(&[2u8; 32]);

        let verifier = ServerCertificateVerifier;
        let err = verifier
            .verify_server_cert(
                &cert_for(&attacker), // attacker's pubkey in cert
                &[],
                &server_name_for(&real_server), // but SNI demands the real server's pubkey
                &[],
                now(),
            )
            .expect_err("MUST reject when SNI pubkey != cert SPKI pubkey");
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
            ),
            "expected InvalidCertificate(UnknownIssuer), got {err:?}"
        );
    }

    #[test]
    fn server_verifier_rejects_any_intermediates() {
        let server = SigningKey::from_bytes(&[3u8; 32]);
        let bogus_intermediate = cert_for(&SigningKey::from_bytes(&[4u8; 32]));

        let err = ServerCertificateVerifier
            .verify_server_cert(
                &cert_for(&server),
                &[bogus_intermediate],
                &server_name_for(&server),
                &[],
                now(),
            )
            .expect_err("MUST reject any intermediate cert in RPK mode");
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
            ),
            "expected UnknownIssuer for intermediates, got {err:?}"
        );
    }

    #[test]
    fn server_verifier_rejects_non_dns_server_name() {
        use std::net::Ipv4Addr;
        let server = SigningKey::from_bytes(&[5u8; 32]);
        let ip_name = ServerName::IpAddress(Ipv4Addr::new(127, 0, 0, 1).into());
        let err = ServerCertificateVerifier
            .verify_server_cert(&cert_for(&server), &[], &ip_name, &[], now())
            .expect_err("MUST reject non-DNS server names");
        assert!(matches!(err, rustls::Error::UnsupportedNameType));
    }

    #[test]
    fn server_verifier_rejects_dns_name_that_is_not_a_warren_sni() {
        let server = SigningKey::from_bytes(&[6u8; 32]);
        let evil_name = ServerName::DnsName(DnsName::try_from("evil.example.com").unwrap());
        let err = ServerCertificateVerifier
            .verify_server_cert(&cert_for(&server), &[], &evil_name, &[], now())
            .expect_err("MUST reject DNS names outside the Warren SNI namespace");
        assert!(matches!(
            err,
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
        ));
    }

    #[test]
    fn server_verifier_rejects_tls12_signature_unconditionally() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let dss = ed25519_dss(&key, b"x");
        let err = ServerCertificateVerifier
            .verify_tls12_signature(b"x", &cert_for(&key), &dss)
            .expect_err("MUST always reject TLS 1.2 signatures");
        assert!(matches!(
            err,
            rustls::Error::PeerIncompatible(rustls::PeerIncompatible::Tls12NotOffered)
        ));
    }

    #[test]
    fn server_verifier_rejects_tls13_signature_with_forged_bytes() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        // Forged: a valid-shape 64-byte ED25519 signature that wasn't
        // produced from `key` over `message`. Verification MUST fail.
        let forged = dss_from_parts(SignatureScheme::ED25519, &[0xaa; 64]);
        let err = ServerCertificateVerifier
            .verify_tls13_signature(b"protocol binding", &cert_for(&key), &forged)
            .expect_err("MUST reject a forged Ed25519 signature");
        // rustls maps this into a DecryptError on signature mismatch.
        assert!(
            !matches!(err, rustls::Error::General(_)),
            "rustls should surface a precise error, got {err:?}"
        );
    }

    // ---------------- ServerCertVerifier: POSITIVE ---------------- //

    #[test]
    fn server_verifier_accepts_matching_cert_and_sni() {
        let server = SigningKey::from_bytes(&[9u8; 32]);
        ServerCertificateVerifier
            .verify_server_cert(
                &cert_for(&server),
                &[],
                &server_name_for(&server),
                &[],
                now(),
            )
            .expect("matching SPKI + SNI must verify");
    }

    #[test]
    fn server_verifier_accepts_valid_tls13_ed25519_signature() {
        let key = SigningKey::from_bytes(&[10u8; 32]);
        let msg = b"warren tls13 transcript hash";
        let dss = ed25519_dss(&key, msg);
        ServerCertificateVerifier
            .verify_tls13_signature(msg, &cert_for(&key), &dss)
            .expect("a real Ed25519 signature over the message must verify");
    }

    #[test]
    fn server_verifier_advertises_only_ed25519_supported_scheme() {
        let schemes = ServerCertificateVerifier.supported_verify_schemes();
        assert_eq!(schemes, vec![SignatureScheme::ED25519]);
    }

    #[test]
    fn server_verifier_requires_raw_public_keys() {
        assert!(ServerCertificateVerifier.requires_raw_public_keys());
    }

    // ---------------- Ed25519Dalek verifier ---------------- //

    #[test]
    fn ed25519_verifier_rejects_pubkey_of_wrong_length() {
        // public_key=[u8; 31] is structurally invalid for Ed25519.
        let err = Ed25519Dalek
            .verify_signature(&[0u8; 31], b"x", &[0u8; 64])
            .expect_err("31-byte pubkey is not Ed25519");
        assert!(matches!(err, rustls::pki_types::InvalidSignature));
    }

    #[test]
    fn ed25519_verifier_rejects_signature_of_wrong_length() {
        let err = Ed25519Dalek
            .verify_signature(&[0u8; 32], b"x", &[0u8; 63])
            .expect_err("63-byte signature is not Ed25519");
        assert!(matches!(err, rustls::pki_types::InvalidSignature));
    }

    #[test]
    fn ed25519_verifier_accepts_a_canonical_signature() {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let msg = b"warren CertificateVerify binding";
        let sig = key.sign(msg).to_bytes();
        Ed25519Dalek
            .verify_signature(key.verifying_key().as_bytes(), msg, &sig)
            .expect("a genuine signature MUST verify under verify_strict");
    }

    #[test]
    fn ed25519_verifier_rejects_small_order_public_key() {
        // The all-zero encoding decodes to the Edwards identity point,
        // a low-order point. `VerifyingKey::from_bytes` accepts it, and
        // the lenient `Verifier::verify` admits a forged signature of
        // the right shape against it (cofactored equation), whereas
        // `verify_strict` rejects any low-order public key outright.
        // This locks in that the CertificateVerify path uses the strict
        // check so small-order / non-canonical keys cannot slip through.
        let small_order_pk = [0u8; 32];
        let err = Ed25519Dalek
            .verify_signature(&small_order_pk, b"x", &[0u8; 64])
            .expect_err("verify_strict MUST reject a small-order public key");
        assert!(matches!(err, rustls::pki_types::InvalidSignature));
    }
}
