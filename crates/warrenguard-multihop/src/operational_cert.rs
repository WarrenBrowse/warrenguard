//! Root → operational certification (PKI level 0 → level 1).
//!
//! The multi-hop trust chain has three levels:
//!
//! - **root** (offline cold): the long-lived anchor pinned in clients. It
//!   never signs descriptors directly; it only certifies operational keys.
//! - **operational** (offline warm): signs the relay/exit descriptors a
//!   client consumes (see [`crate::verify_relay_descriptor`] /
//!   [`crate::verify_exit_descriptor`]).
//! - **server** (online): signs only the freshness envelope of the
//!   directory the client fetches; it cannot forge descriptors.
//!
//! This module implements the root → operational link: the root signs the
//! 32-byte operational pubkey, producing a certificate the directory ships
//! alongside the operational-signed descriptors. A client that pins the
//! root key can therefore trust a freshly rotated operational key without
//! shipping a new client build.
//!
//! # `/v1` contract
//!
//! Canonical payload: `WARREN_PKI_ROOT_OPERATIONAL_V1 || operational_pubkey (32 B)`.
//! Total length 41 + 32 = 73 bytes. Frozen for all `/v1` deployments; any
//! breaking change must bump to `/v2` (CLAUDE.md § 3).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::WARREN_PKI_ROOT_OPERATIONAL_V1;

/// Errors raised by [`verify_operational_cert`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OperationalCertError {
    /// The 64-byte certificate signature did not verify against the root
    /// pubkey for the canonical
    /// `WARREN_PKI_ROOT_OPERATIONAL_V1 || operational_pubkey` payload.
    /// Either the certificate was tampered with, the operational key is
    /// not the one the root certified, or it was signed by a key other
    /// than the trusted root.
    #[error("operational certificate signature does not verify under the root key")]
    BadSignature,
}

/// Builds the canonical payload the root key signs to certify an
/// operational key.
///
/// Layout: `WARREN_PKI_ROOT_OPERATIONAL_V1 || operational_pubkey (32 B)`.
#[must_use]
pub fn operational_cert_signing_payload(operational_pubkey: &VerifyingKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(WARREN_PKI_ROOT_OPERATIONAL_V1.len() + 32);
    buf.extend_from_slice(WARREN_PKI_ROOT_OPERATIONAL_V1);
    buf.extend_from_slice(operational_pubkey.as_bytes());
    buf
}

/// Signs an operational pubkey with the offline **root** key. Run on the
/// operator's cold machine only.
#[must_use]
pub fn sign_operational_cert(root_key: &SigningKey, operational_pubkey: &VerifyingKey) -> [u8; 64] {
    let payload = operational_cert_signing_payload(operational_pubkey);
    root_key.sign(&payload).to_bytes()
}

/// Verifies that `operational_pubkey` is certified by `root_pubkey`.
///
/// # Errors
/// - [`OperationalCertError::BadSignature`] if the certificate does not
///   verify (tampered cert, wrong operational key, or wrong root key).
pub fn verify_operational_cert(
    root_pubkey: &VerifyingKey,
    operational_pubkey: &VerifyingKey,
    signature: &[u8; 64],
) -> Result<(), OperationalCertError> {
    let payload = operational_cert_signing_payload(operational_pubkey);
    let sig = Signature::from_bytes(signature);
    root_pubkey
        .verify_strict(&payload, &sig)
        .map_err(|_| OperationalCertError::BadSignature)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn payload_layout_is_frozen() {
        let op = key(0x01).verifying_key();
        let payload = operational_cert_signing_payload(&op);
        assert_eq!(payload.len(), WARREN_PKI_ROOT_OPERATIONAL_V1.len() + 32);
        assert!(payload.starts_with(WARREN_PKI_ROOT_OPERATIONAL_V1));
        assert_eq!(
            &payload[WARREN_PKI_ROOT_OPERATIONAL_V1.len()..],
            op.as_bytes()
        );
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let root = key(0xaa);
        let op = key(0xbb).verifying_key();
        let cert = sign_operational_cert(&root, &op);
        verify_operational_cert(&root.verifying_key(), &op, &cert).expect("must verify");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let root = key(0xaa);
        let op = key(0xbb).verifying_key();
        let mut cert = sign_operational_cert(&root, &op);
        cert[0] ^= 0xff;
        let err = verify_operational_cert(&root.verifying_key(), &op, &cert)
            .expect_err("tampered cert must reject");
        assert!(matches!(err, OperationalCertError::BadSignature));
    }

    #[test]
    fn wrong_root_key_is_rejected() {
        let root = key(0xaa);
        let attacker_root = key(0xcc);
        let op = key(0xbb).verifying_key();
        let cert = sign_operational_cert(&root, &op);
        // A certificate minted by the real root must NOT verify under a
        // different (attacker) root pubkey - this is the pin defeating a
        // server-substituted trust anchor.
        let err = verify_operational_cert(&attacker_root.verifying_key(), &op, &cert)
            .expect_err("wrong root must reject");
        assert!(matches!(err, OperationalCertError::BadSignature));
    }

    #[test]
    fn certifying_a_different_operational_key_is_rejected() {
        let root = key(0xaa);
        let op = key(0xbb).verifying_key();
        let other_op = key(0xdd).verifying_key();
        let cert = sign_operational_cert(&root, &op);
        // The cert binds `op`; presenting it for `other_op` must fail so a
        // compromised server cannot swap the operational key under a valid
        // root signature.
        let err = verify_operational_cert(&root.verifying_key(), &other_op, &cert)
            .expect_err("mismatched operational key must reject");
        assert!(matches!(err, OperationalCertError::BadSignature));
    }
}
