//! Operational-key attestation of a dual-role node's geo + identity, for
//! the dynamic multi-hop directory (`/v2` hardening).
//!
//! The directory's per-node `country` / `asn` and the exit hop's Ed25519
//! RPK identity would otherwise be covered only by the **online** server
//! envelope, letting a compromised directory fake circuit diversity
//! (mislabel two co-located nodes as different countries/ASNs) or redirect
//! the exit-leg TLS pin. This attestation binds those fields under the
//! **offline operational key**, so the client's country/AS diversity rule
//! and exit TLS pin become cryptographic guarantees, not server-trusted
//! labels.
//!
//! Where each attested field is consumed (so the bind is not cosmetic):
//! - `country` / `asn` - by the client's circuit selection
//!   (`valid_circuits`), which reads the same attested `NodeEntry` fields
//!   for the entry≠exit country/AS diversity rule.
//! - `exit_ed25519_pubkey` - by the **entry node's** relay→exit dial
//!   (`warren_relay::ExitConnPool::dial`), which pins it as the TLS RPK
//!   server name on the C2 handshake; an exit whose RPK does not match is
//!   rejected at handshake. Attesting it therefore prevents a compromised
//!   the directory from redirecting the relay->exit leg to a node it controls.
//! - `relay_id` - the node distinctness key, also covered by the relay
//!   descriptor signature.
//!
//! # `/v1` contract
//!
//! Canonical payload:
//! `WARREN_PKI_OPERATIONAL_NODE_V1 || node_id(16) || exit_ed25519_pubkey(32) || asn_u32_be(4) || country_bytes`.
//! `country` is the terminal field (variable length), signed verbatim as
//! the directory stores it. Frozen for `/v1`.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::WARREN_PKI_OPERATIONAL_NODE_V1;

/// Errors raised by [`verify_node_attestation`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NodeAttestationError {
    /// The signature did not verify against the operational pubkey for the
    /// canonical node-attestation payload. The carried `country` / `asn` /
    /// `exit_ed25519_pubkey` do not match what the operational key signed
    /// (a compromised server mislabeled geo or swapped the exit identity),
    /// or the attestation was produced by a different key.
    #[error("node attestation signature does not verify")]
    BadSignature,
}

/// Builds the canonical payload the operational key signs to attest a
/// node's geo + identity.
#[must_use]
pub fn node_attestation_signing_payload(
    node_id: &[u8; 16],
    exit_ed25519_pubkey: &[u8; 32],
    asn: u32,
    country: &str,
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(WARREN_PKI_OPERATIONAL_NODE_V1.len() + 16 + 32 + 4 + country.len());
    buf.extend_from_slice(WARREN_PKI_OPERATIONAL_NODE_V1);
    buf.extend_from_slice(node_id);
    buf.extend_from_slice(exit_ed25519_pubkey);
    buf.extend_from_slice(&asn.to_be_bytes());
    buf.extend_from_slice(country.as_bytes());
    buf
}

/// Signs a node attestation with the offline **operational** key.
#[must_use]
pub fn sign_node_attestation(
    operational_key: &SigningKey,
    node_id: &[u8; 16],
    exit_ed25519_pubkey: &[u8; 32],
    asn: u32,
    country: &str,
) -> [u8; 64] {
    let payload = node_attestation_signing_payload(node_id, exit_ed25519_pubkey, asn, country);
    operational_key.sign(&payload).to_bytes()
}

/// Verifies a node attestation against the operational pubkey.
///
/// # Errors
/// [`NodeAttestationError::BadSignature`] if the attestation does not
/// verify for the supplied `(node_id, exit_ed25519_pubkey, asn, country)`.
pub fn verify_node_attestation(
    operational_pubkey: &VerifyingKey,
    node_id: &[u8; 16],
    exit_ed25519_pubkey: &[u8; 32],
    asn: u32,
    country: &str,
    signature: &[u8; 64],
) -> Result<(), NodeAttestationError> {
    let payload = node_attestation_signing_payload(node_id, exit_ed25519_pubkey, asn, country);
    let sig = Signature::from_bytes(signature);
    operational_pubkey
        .verify_strict(&payload, &sig)
        .map_err(|_| NodeAttestationError::BadSignature)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let op = key(0x01);
        let node_id = [0x11; 16];
        let ed = [0x22; 32];
        let sig = sign_node_attestation(&op, &node_id, &ed, 24940, "fr");
        verify_node_attestation(&op.verifying_key(), &node_id, &ed, 24940, "fr", &sig)
            .expect("must verify");
    }

    #[test]
    fn tampered_country_is_rejected() {
        let op = key(0x01);
        let node_id = [0x11; 16];
        let ed = [0x22; 32];
        let sig = sign_node_attestation(&op, &node_id, &ed, 24940, "fr");
        // A compromised server relabeling the country must fail - this is
        // the whole point: geo diversity becomes cryptographic.
        let err = verify_node_attestation(&op.verifying_key(), &node_id, &ed, 24940, "de", &sig)
            .expect_err("relabeled country must reject");
        assert!(matches!(err, NodeAttestationError::BadSignature));
    }

    #[test]
    fn tampered_asn_is_rejected() {
        let op = key(0x01);
        let node_id = [0x11; 16];
        let ed = [0x22; 32];
        let sig = sign_node_attestation(&op, &node_id, &ed, 100, "fr");
        let err = verify_node_attestation(&op.verifying_key(), &node_id, &ed, 200, "fr", &sig)
            .expect_err("relabeled ASN must reject");
        assert!(matches!(err, NodeAttestationError::BadSignature));
    }

    #[test]
    fn swapped_exit_identity_is_rejected() {
        let op = key(0x01);
        let node_id = [0x11; 16];
        let sig = sign_node_attestation(&op, &node_id, &[0x22; 32], 100, "fr");
        // Swapping the exit Ed25519 RPK identity must fail: otherwise a
        // compromised directory could redirect the relay->exit TLS pin to a
        // node it controls while keeping the rest of the attestation intact.
        let err =
            verify_node_attestation(&op.verifying_key(), &node_id, &[0x33; 32], 100, "fr", &sig)
                .expect_err("swapped exit identity must reject");
        assert!(matches!(err, NodeAttestationError::BadSignature));
    }

    #[test]
    fn wrong_operational_key_is_rejected() {
        let op = key(0x01);
        let attacker = key(0x09);
        let node_id = [0x11; 16];
        let ed = [0x22; 32];
        let sig = sign_node_attestation(&op, &node_id, &ed, 100, "fr");
        let err =
            verify_node_attestation(&attacker.verifying_key(), &node_id, &ed, 100, "fr", &sig)
                .expect_err("wrong operational key must reject");
        assert!(matches!(err, NodeAttestationError::BadSignature));
    }
}
