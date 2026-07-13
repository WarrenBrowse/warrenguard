//! Relay descriptor `/v1` and mini-PKI verification.
//!
//! A [`RelayDescriptorSigned`] binds a 16-byte relay routing tag, the
//! relay's Ed25519 raw-public-key identity (pinned by the client at TLS
//! handshake), and the relay's QUIC endpoint, with a single signature
//! produced by the operational Ed25519 key over the canonical
//! [`crate::WARREN_PKI_OPERATIONAL_RELAY_V1`] payload.
//!
//! The same shape is reused by `warren-relay` for its exit descriptors
//! (see `crates/warren-relay/src/pki.rs`); a relay descriptor is the
//! mirror artifact a client consumes to pin its first hop.
//!
//! # TOML format
//!
//! Fixed-length crypto fields are encoded as hex strings so a deployment
//! TOML stays human-auditable. `endpoint` uses the standard `IP:PORT`
//! representation parsed by [`std::net::SocketAddr`].
//!
//! ```toml
//! relay_id            = "0011223344556677889900112233445566"  # 16 hex bytes
//! relay_ed25519_pubkey = "<64 hex chars>"                     # 32 bytes
//! endpoint            = "192.0.2.10:443"
//! signature           = "<128 hex chars>"                     # 64 bytes
//! ```
//!
//! # Trust model
//!
//! - The `operational_pubkey` is delivered out-of-band to the client and
//!   constitutes the trust anchor for the relay pool. A descriptor whose
//!   signature does not verify under that anchor MUST be refused: the
//!   relay is a hostile-by-default node in the threat model, so an
//!   unsigned or tampered descriptor is a routing-substitution attack.
//! - The signed payload covers only `relay_id` and `relay_ed25519_pubkey`.
//!   The `endpoint` and `cover_domain` fields are intentionally outside the
//!   signature so an operator can rotate the relay's public IP or cover
//!   domain without re-signing the pool. In RPK mode, pinning the RPK pubkey
//!   at the TLS layer is what defeats DNS or IP hijacking, not the address
//!   bytes. In X.509 cover-domain mode, the in-band relay-auth
//!   proof (bound to the channel binding, verified against the signed
//!   `relay_ed25519_pubkey`) plays that role, and the WebPKI SAN check binds
//!   the cover domain to a real certificate, so leaving `cover_domain`
//!   unsigned is safe.
//!
//! # `/v1` contract
//!
//! The canonical signing payload is
//! `WARREN_PKI_OPERATIONAL_RELAY_V1 || relay_id (16 B) || relay_ed25519_pubkey (32 B)`.
//! Total length 42 + 16 + 32 = 90 bytes. This constant tuple is frozen for
//! all `/v1` deployments. Any breaking change must bump to `/v2`
//! (CLAUDE.md § 3). The `cover_domain` field is additive and
//! UNSIGNED, so it does not alter this payload: a descriptor with or without
//! it verifies under the same `/v1` signature, and an RPK descriptor
//! (cover_domain absent) round-trips byte-for-byte.

use std::net::SocketAddr;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::WARREN_PKI_OPERATIONAL_RELAY_V1;

/// One signed entry in a client's relay pool.
///
/// Constructed offline by the operational signer and shipped to clients
/// (out-of-band, then loaded via [`Self`]'s serde derive). The relay
/// itself never sees or holds this struct; only clients verify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDescriptorSigned {
    /// 16-byte routing tag, opaque to the relay binary.
    #[serde(with = "hex_array_16")]
    pub relay_id: [u8; 16],
    /// Ed25519 identity key of the relay's QUIC server. How the client binds
    /// to it depends on `cover_domain`:
    /// - `None` (RPK mode): the client pins this value as the TLS raw public
    ///   key during the QUIC handshake (the SNI carries the encoded pubkey),
    ///   which is what defeats a DNS or IP hijack.
    /// - `Some` (X.509 cover-domain mode): the relay presents an
    ///   ordinary X.509 cover-domain certificate, so this key is NOT in the
    ///   TLS layer. The client confirms it reached this relay via the in-band
    ///   relay-identity proof (`warrenguard_tls::verify_relay_auth`) signed
    ///   by this key over the connection's channel binding.
    #[serde(with = "hex_array_32")]
    pub relay_ed25519_pubkey: [u8; 32],
    /// QUIC endpoint the client dials. Outside the signature on purpose
    /// (cf. module docs).
    pub endpoint: SocketAddr,
    /// X.509 cover-domain SNI. `None` = RPK mode (the historical
    /// default); `Some(domain)` = the client dials this domain as the TLS SNI,
    /// validates the relay's certificate via WebPKI, and then verifies the
    /// in-band relay-identity proof against `relay_ed25519_pubkey`. Outside the
    /// signature on purpose, exactly like `endpoint`: the relay-identity proof
    /// (bound to the channel binding) and the WebPKI SAN check are what bind
    /// the name to the relay, so an operator can change the cover domain
    /// without re-signing the pool. Serialized only when present, so a `/v1`
    /// (RPK) descriptor round-trips byte-for-byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_domain: Option<String>,
    /// Ed25519 signature over the canonical payload produced by
    /// [`relay_descriptor_signing_payload`].
    #[serde(with = "hex_array_64")]
    pub signature: [u8; 64],
}

/// Errors raised by [`verify_relay_descriptor`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelayPkiError {
    /// The 64-byte signature did not verify against the operational
    /// pubkey for the canonical
    /// `WARREN_PKI_OPERATIONAL_RELAY_V1 || relay_id || relay_ed25519_pubkey`
    /// payload. Either the descriptor was tampered with, or it was signed
    /// by a different operational key than the one currently trusted.
    #[error("relay descriptor signature does not verify")]
    BadSignature,
    /// The in-band relay-auth proof message did not have the
    /// expected length or version byte. The signature itself is verified
    /// separately by `warrenguard_tls::verify_relay_auth`.
    #[error("malformed relay-auth proof message")]
    MalformedRelayAuthProof,
}

/// Wire version byte prefixed to the in-band relay-auth proof message.
/// Bump to extend the message; never reuse a value for a new
/// layout.
pub const RELAY_AUTH_PROOF_VERSION: u8 = 1;

/// On-wire length of the relay-auth proof message: 1 version byte + a 64-byte
/// Ed25519 signature.
pub const RELAY_AUTH_PROOF_LEN: usize = 1 + 64;

/// Encodes the in-band relay-auth proof the entry relay sends to the client in
/// X.509 cover-domain mode: `RELAY_AUTH_PROOF_VERSION || sig (64 B)`.
/// `sig` is produced by `warrenguard_tls::sign_relay_auth` over the
/// client<->relay channel binding. The channel binding is derived by both peers
/// from the TLS session, never sent, so this message carries only the signature.
#[must_use]
pub fn encode_relay_auth_proof(sig: &[u8; 64]) -> [u8; RELAY_AUTH_PROOF_LEN] {
    let mut out = [0u8; RELAY_AUTH_PROOF_LEN];
    out[0] = RELAY_AUTH_PROOF_VERSION;
    out[1..].copy_from_slice(sig);
    out
}

/// Parses a relay-auth proof message, returning the 64-byte signature for the
/// caller to verify with `warrenguard_tls::verify_relay_auth`.
///
/// # Errors
/// [`RelayPkiError::MalformedRelayAuthProof`] if the length is not
/// [`RELAY_AUTH_PROOF_LEN`] or the version byte is not
/// [`RELAY_AUTH_PROOF_VERSION`]. This guards the framing only; an
/// authentic-looking but wrong signature is caught by the verifier.
pub fn decode_relay_auth_proof(bytes: &[u8]) -> Result<[u8; 64], RelayPkiError> {
    if bytes.len() != RELAY_AUTH_PROOF_LEN || bytes[0] != RELAY_AUTH_PROOF_VERSION {
        return Err(RelayPkiError::MalformedRelayAuthProof);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[1..]);
    Ok(sig)
}

/// Builds the canonical payload the operational signer must sign for a
/// given relay.
///
/// Layout: `WARREN_PKI_OPERATIONAL_RELAY_V1 || relay_id (16 B) || relay_ed25519_pubkey (32 B)`.
/// Total 42 + 16 + 32 = 90 bytes.
#[must_use]
pub fn relay_descriptor_signing_payload(
    relay_id: &[u8; 16],
    relay_ed25519_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(WARREN_PKI_OPERATIONAL_RELAY_V1.len() + 16 + 32);
    buf.extend_from_slice(WARREN_PKI_OPERATIONAL_RELAY_V1);
    buf.extend_from_slice(relay_id);
    buf.extend_from_slice(relay_ed25519_pubkey);
    buf
}

/// Verifies a [`RelayDescriptorSigned`] against the supplied operational
/// pubkey using the `/v1` PKI context.
///
/// # Errors
/// - [`RelayPkiError::BadSignature`] if the signature does not verify, or
///   if the embedded signature bytes do not parse as a valid Ed25519
///   signature (in `ed25519-dalek` 2.x, parsing accepts any 64-byte input
///   so the failure path is purely the verification call).
pub fn verify_relay_descriptor(
    operational_pubkey: &VerifyingKey,
    descriptor: &RelayDescriptorSigned,
) -> Result<(), RelayPkiError> {
    let payload =
        relay_descriptor_signing_payload(&descriptor.relay_id, &descriptor.relay_ed25519_pubkey);
    let signature = Signature::from_bytes(&descriptor.signature);
    operational_pubkey
        .verify_strict(&payload, &signature)
        .map_err(|_| RelayPkiError::BadSignature)
}

mod hex_array_16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        let bytes =
            hex::decode(&s).map_err(|e| D::Error::custom(format!("hex decode failed: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 16 bytes"))
    }
}

mod hex_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        let bytes =
            hex::decode(&s).map_err(|e| D::Error::custom(format!("hex decode failed: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

mod hex_array_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(value: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(d)?;
        let bytes =
            hex::decode(&s).map_err(|e| D::Error::custom(format!("hex decode failed: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn det_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn signing_payload_total_length_is_90_bytes() {
        let payload = relay_descriptor_signing_payload(&[0; 16], &[0; 32]);
        assert_eq!(
            payload.len(),
            WARREN_PKI_OPERATIONAL_RELAY_V1.len() + 16 + 32
        );
    }

    #[test]
    fn verifies_after_a_real_signature_round_trip() {
        let op = det_signing_key(0x33);
        let relay_id = [0x77; 16];
        let relay_pubkey = [0xAA; 32];
        let payload = relay_descriptor_signing_payload(&relay_id, &relay_pubkey);
        let sig = op.sign(&payload);
        let descriptor = RelayDescriptorSigned {
            relay_id,
            relay_ed25519_pubkey: relay_pubkey,
            endpoint: "192.0.2.10:443".parse().expect("static addr parses"),
            cover_domain: None,
            signature: sig.to_bytes(),
        };
        verify_relay_descriptor(&op.verifying_key(), &descriptor)
            .expect("freshly signed relay descriptor verifies");
    }

    #[test]
    fn rejects_wrong_operational_pubkey() {
        let signer = det_signing_key(0x33);
        let other = det_signing_key(0x44);
        let relay_id = [0x77; 16];
        let relay_pubkey = [0xAA; 32];
        let payload = relay_descriptor_signing_payload(&relay_id, &relay_pubkey);
        let sig = signer.sign(&payload);
        let descriptor = RelayDescriptorSigned {
            relay_id,
            relay_ed25519_pubkey: relay_pubkey,
            endpoint: "192.0.2.10:443".parse().expect("static addr parses"),
            cover_domain: None,
            signature: sig.to_bytes(),
        };
        let err = verify_relay_descriptor(&other.verifying_key(), &descriptor)
            .expect_err("verification under a different pubkey must reject");
        assert!(matches!(err, RelayPkiError::BadSignature));
    }

    // --- cover_domain is additive + unsigned ---

    #[test]
    fn signature_verifies_regardless_of_cover_domain_value() {
        // cover_domain is OUTSIDE the signed payload, so the SAME signature
        // must verify whether the field is absent, set, or changed. This pins
        // the "unsigned" contract: an operator can set/rotate the cover domain
        // without re-signing, and a hostile relay flipping the field cannot
        // invalidate the operational signature (the in-band relay-auth proof +
        // WebPKI SAN are what bind the name, not this signature).
        let op = det_signing_key(0x33);
        let relay_id = [0x77; 16];
        let relay_pubkey = [0xAA; 32];
        let sig = op.sign(&relay_descriptor_signing_payload(&relay_id, &relay_pubkey));
        let base = RelayDescriptorSigned {
            relay_id,
            relay_ed25519_pubkey: relay_pubkey,
            endpoint: "192.0.2.10:443".parse().expect("static addr parses"),
            cover_domain: None,
            signature: sig.to_bytes(),
        };
        for cover in [
            None,
            Some("nl1.edge.example.com".to_owned()),
            Some("other.example.com".to_owned()),
        ] {
            let descriptor = RelayDescriptorSigned {
                cover_domain: cover.clone(),
                ..base.clone()
            };
            verify_relay_descriptor(&op.verifying_key(), &descriptor).unwrap_or_else(|_| {
                panic!("the /v1 signature must verify for cover_domain = {cover:?}")
            });
        }
    }

    #[test]
    fn rpk_descriptor_omits_cover_domain_in_serialized_form() {
        // Backward-compat: an RPK (cover_domain = None) descriptor must
        // serialize WITHOUT a cover_domain key, so existing /v1 directories
        // round-trip byte-for-byte and old parsers are unaffected.
        let descriptor = RelayDescriptorSigned {
            relay_id: [0x11; 16],
            relay_ed25519_pubkey: [0x22; 32],
            endpoint: "192.0.2.10:443".parse().expect("static addr parses"),
            cover_domain: None,
            signature: [0x33; 64],
        };
        let json = serde_json::to_string(&descriptor).expect("serialize");
        assert!(
            !json.contains("cover_domain"),
            "an RPK descriptor must omit cover_domain entirely, got: {json}"
        );
        let back: RelayDescriptorSigned = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back, descriptor);
    }

    #[test]
    fn x509_descriptor_round_trips_cover_domain() {
        let descriptor = RelayDescriptorSigned {
            relay_id: [0x11; 16],
            relay_ed25519_pubkey: [0x22; 32],
            endpoint: "192.0.2.10:443".parse().expect("static addr parses"),
            cover_domain: Some("nl1.edge.example.com".to_owned()),
            signature: [0x33; 64],
        };
        let json = serde_json::to_string(&descriptor).expect("serialize");
        assert!(json.contains("nl1.edge.example.com"));
        let back: RelayDescriptorSigned = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(back.cover_domain.as_deref(), Some("nl1.edge.example.com"));
    }

    // --- in-band relay-auth proof framing ---

    #[test]
    fn relay_auth_proof_encode_decode_round_trips() {
        let sig = [0xCD; 64];
        let encoded = encode_relay_auth_proof(&sig);
        assert_eq!(encoded.len(), RELAY_AUTH_PROOF_LEN);
        assert_eq!(encoded[0], RELAY_AUTH_PROOF_VERSION, "version byte first");
        assert_eq!(&encoded[1..], &sig, "signature follows the version byte");
        assert_eq!(
            decode_relay_auth_proof(&encoded).expect("valid proof decodes"),
            sig
        );
    }

    #[test]
    fn relay_auth_proof_layout_is_frozen() {
        // Wire contract: version(1) || sig(64) = 65 bytes. A drift here breaks
        // every relay<->client proof exchange and MUST bump the version byte.
        assert_eq!(RELAY_AUTH_PROOF_VERSION, 1);
        assert_eq!(RELAY_AUTH_PROOF_LEN, 65);
        let encoded = encode_relay_auth_proof(&[0x01; 64]);
        let mut expected = vec![1u8];
        expected.extend_from_slice(&[0x01; 64]);
        assert_eq!(encoded.as_slice(), expected.as_slice());
    }

    #[test]
    fn relay_auth_proof_rejects_wrong_length_and_version() {
        // Too short, too long, and a bad version byte all fail closed.
        assert!(matches!(
            decode_relay_auth_proof(&[1u8; 64]),
            Err(RelayPkiError::MalformedRelayAuthProof)
        ));
        assert!(matches!(
            decode_relay_auth_proof(&[1u8; 66]),
            Err(RelayPkiError::MalformedRelayAuthProof)
        ));
        let mut wrong_version = encode_relay_auth_proof(&[0x05; 64]);
        wrong_version[0] = 2;
        assert!(matches!(
            decode_relay_auth_proof(&wrong_version),
            Err(RelayPkiError::MalformedRelayAuthProof)
        ));
    }
}
