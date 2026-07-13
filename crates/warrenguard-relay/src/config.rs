//! Relay configuration loader.
//!
//! Reads a TOML file containing the relay's bind address, its Ed25519
//! identity key path, the operational pubkey trust anchor, and the
//! signed exit pool. Validates every descriptor against the operational
//! pubkey before handing the resulting [`RelayConfig`] over to
//! [`crate::server::RelayServer`]. A descriptor with a bad signature,
//! the wrong operational pubkey, or a duplicate `exit_id` is rejected
//! immediately so a misconfigured deployment fails closed.
//!
//! The relay is version-agnostic about which PKI context signed a
//! descriptor: [`RelayConfig::validate`] accepts a descriptor signed under
//! the post-quantum, `/v2`, or `/v1` context (see
//! [`verify_descriptor_any_version`]). The relay never needs the richer
//! attestations those contexts add (`dns_disabled`, the ML-KEM key); it only
//! needs proof that the operational key vouches for the entry, so it does
//! not gate on which context produced that proof (see
//! `docs/90-PQ-HPKE-XWING.md`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
pub use warrenguard_multihop::ExitDescriptorSigned;
use warrenguard_multihop::ExitId;

use crate::pki::{self, PkiError};

/// Errors raised when loading or validating a relay configuration.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// I/O error reading the TOML file.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    /// TOML parse error.
    #[error("failed to parse config TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// Two exit descriptors share the same `exit_id`. The relay refuses
    /// to load such a pool to avoid ambiguous routing.
    #[error("duplicate exit_id in pool")]
    DuplicateExitId,
    /// One of the descriptors did not pass mini-PKI verification.
    #[error("exit descriptor failed PKI verification at index {index}: {source}")]
    Pki {
        /// Position of the offending descriptor in the input vec.
        index: usize,
        /// Underlying PKI error.
        #[source]
        source: PkiError,
    },
}

/// Top-level relay TOML schema.
///
/// `bind_addr` is the QUIC server bind address (production: a public
/// `<ip>:443`). `signing_key_path` points to the relay's local Ed25519
/// identity key file (consumed at startup by [`crate::server::RelayServer`]).
/// `operational_pubkey` is the trust anchor against which every entry in
/// `exits` is verified. `exits` is the signed exit pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Bind address of the relay QUIC server.
    pub bind_addr: SocketAddr,
    /// Filesystem path to the relay Ed25519 identity key.
    pub signing_key_path: PathBuf,
    /// Trust anchor for the exit pool. Encoded as a 64-character hex
    /// string in TOML.
    #[serde(
        serialize_with = "serialize_verifying_key",
        deserialize_with = "deserialize_verifying_key"
    )]
    pub operational_pubkey: VerifyingKey,
    /// Signed exit pool.
    pub exits: Vec<ExitDescriptorSigned>,
}

impl RelayConfig {
    /// Reads `path` and parses + validates the TOML.
    ///
    /// # Errors
    /// - [`ConfigError::Io`] when the file cannot be read.
    /// - [`ConfigError::Toml`] when TOML parsing fails.
    /// - [`ConfigError::DuplicateExitId`] when two entries share an `exit_id`.
    /// - [`ConfigError::Pki`] when any descriptor signature is invalid.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates the in-memory config: signatures + uniqueness.
    ///
    /// # Errors
    /// Same shape as [`RelayConfig::load`] but without I/O / parse
    /// failure paths.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (index, exit) in self.exits.iter().enumerate() {
            // Pool is bounded (a few dozen exits in practice), so a
            // linear duplicate check is O(n²) but stays well below the
            // overhead of hashing 16-byte ids. Keeping ExitId free of
            // a Hash derive avoids touching the frozen `/v1` API surface
            // of warren-multihop just to support the relay's loader.
            if self.exits[..index]
                .iter()
                .any(|e| e.exit_id == exit.exit_id)
            {
                return Err(ConfigError::DuplicateExitId);
            }
            verify_descriptor_any_version(&self.operational_pubkey, exit)
                .map_err(|source| ConfigError::Pki { index, source })?;
        }
        Ok(())
    }

    /// Returns the signed descriptor matching `exit_id`, if any. Used
    /// by the routing layer to resolve a first-datagram routing tag
    /// into a concrete dial target.
    #[must_use]
    pub fn find_exit(&self, exit_id: &ExitId) -> Option<&ExitDescriptorSigned> {
        self.exits.iter().find(|e| e.exit_id == *exit_id)
    }
}

/// Verifies `descriptor` under whichever PKI context the operational signer
/// used: post-quantum first, then `/v2`, then the legacy `/v1` context.
///
/// The relay is deliberately blind to which context produced the signature:
/// it never reads the richer attestations those contexts add (the
/// `dns_disabled` bit, the ML-KEM key), so accepting any of the three does
/// not weaken anything the relay itself enforces. This is what lets the
/// relay's exit pool mix `/v1`, `/v2`, and PQ descriptors during a rolling
/// fleet upgrade instead of requiring every descriptor to be re-signed under
/// one context at once.
///
/// # Errors
/// [`PkiError::BadSignature`] if none of the three contexts verify.
fn verify_descriptor_any_version(
    operational_pubkey: &VerifyingKey,
    descriptor: &ExitDescriptorSigned,
) -> Result<(), PkiError> {
    if pki::verify_exit_descriptor_pq(operational_pubkey, descriptor).is_ok() {
        return Ok(());
    }
    if pki::verify_exit_descriptor_v2(operational_pubkey, descriptor).is_ok() {
        return Ok(());
    }
    pki::verify_exit_descriptor(operational_pubkey, descriptor)
}

fn serialize_verifying_key<S: Serializer>(key: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(key.as_bytes()))
}

fn deserialize_verifying_key<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
    use serde::de::Error as _;
    let s = String::deserialize(d)?;
    let bytes = hex::decode(&s)
        .map_err(|e| D::Error::custom(format!("operational_pubkey is not hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| D::Error::custom("operational_pubkey must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| D::Error::custom(format!("operational_pubkey not a valid Ed25519 point: {e}")))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use warrenguard_multihop::{
        MLKEM768_ENCAPS_KEY_LEN, exit_descriptor_signing_payload_pq,
        exit_descriptor_signing_payload_v2,
    };

    use super::*;
    use crate::pki::exit_descriptor_signing_payload;

    fn det_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed_descriptor(
        op: &SigningKey,
        exit_id: ExitId,
        x25519: [u8; 32],
        endpoint: &str,
    ) -> ExitDescriptorSigned {
        let payload = exit_descriptor_signing_payload(exit_id, &x25519);
        let sig = op.sign(&payload);
        ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0xEE; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some(endpoint.parse().expect("static addr parses")),
            cover_domain: None,
            signature: sig.to_bytes(),
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        }
    }

    /// Signs a descriptor under the `/v2` context (covers `dns_disabled`).
    fn signed_descriptor_v2(
        op: &SigningKey,
        exit_id: ExitId,
        x25519: [u8; 32],
        endpoint: &str,
    ) -> ExitDescriptorSigned {
        let payload = exit_descriptor_signing_payload_v2(exit_id, &x25519, false);
        let sig = op.sign(&payload);
        ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0xEE; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some(endpoint.parse().expect("static addr parses")),
            cover_domain: None,
            signature: sig.to_bytes(),
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        }
    }

    /// Signs a descriptor under the post-quantum context (covers the
    /// ML-KEM-768 recipient key). The key content itself is opaque to the
    /// descriptor verifier (it checks length + signature, not ML-KEM
    /// validity), so a deterministic filler stands in for a real key.
    fn signed_descriptor_pq(
        op: &SigningKey,
        exit_id: ExitId,
        x25519: [u8; 32],
        endpoint: &str,
    ) -> ExitDescriptorSigned {
        let mlkem_ek: Vec<u8> = (0..MLKEM768_ENCAPS_KEY_LEN)
            .map(|i| (i % 251) as u8)
            .collect();
        let payload = exit_descriptor_signing_payload_pq(exit_id, &x25519, false, &mlkem_ek);
        let sig = op.sign(&payload);
        ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0xEE; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some(endpoint.parse().expect("static addr parses")),
            cover_domain: None,
            signature: sig.to_bytes(),
            dns_disabled: false,
            exit_mlkem768_pubkey: Some(mlkem_ek),
        }
    }

    #[test]
    fn validate_accepts_two_distinct_signed_entries() {
        let op = det_signing_key(0x42);
        let cfg = RelayConfig {
            bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
            signing_key_path: PathBuf::from("/etc/warren-relay/identity.key"),
            operational_pubkey: op.verifying_key(),
            exits: vec![
                signed_descriptor(
                    &op,
                    ExitId::from_bytes([0xAA; 16]),
                    [0x11; 32],
                    "10.0.0.1:443",
                ),
                signed_descriptor(
                    &op,
                    ExitId::from_bytes([0xBB; 16]),
                    [0x22; 32],
                    "10.0.0.2:443",
                ),
            ],
        };
        cfg.validate()
            .expect("two valid distinct entries must pass");
    }

    #[test]
    fn validate_rejects_duplicate_exit_id_even_with_valid_signatures() {
        let op = det_signing_key(0x42);
        let dup = ExitId::from_bytes([0xAA; 16]);
        let cfg = RelayConfig {
            bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
            signing_key_path: PathBuf::from("/etc/warren-relay/identity.key"),
            operational_pubkey: op.verifying_key(),
            exits: vec![
                signed_descriptor(&op, dup, [0x11; 32], "10.0.0.1:443"),
                signed_descriptor(&op, dup, [0x22; 32], "10.0.0.2:443"),
            ],
        };
        let err = cfg.validate().expect_err("duplicate must reject");
        assert!(matches!(err, ConfigError::DuplicateExitId));
    }

    #[test]
    fn find_exit_returns_matching_descriptor_when_present() {
        let op = det_signing_key(0x42);
        let exit_id = ExitId::from_bytes([0xAA; 16]);
        let cfg = RelayConfig {
            bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
            signing_key_path: PathBuf::from("/etc/warren-relay/identity.key"),
            operational_pubkey: op.verifying_key(),
            exits: vec![signed_descriptor(&op, exit_id, [0x11; 32], "10.0.0.1:443")],
        };
        let found = cfg.find_exit(&exit_id).expect("known exit must be found");
        assert_eq!(found.exit_id, exit_id);
        assert!(cfg.find_exit(&ExitId::from_bytes([0xFF; 16])).is_none());
    }

    #[test]
    fn validate_accepts_a_v2_signed_descriptor() {
        let op = det_signing_key(0x42);
        let cfg = RelayConfig {
            bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
            signing_key_path: PathBuf::from("/etc/warren-relay/identity.key"),
            operational_pubkey: op.verifying_key(),
            exits: vec![signed_descriptor_v2(
                &op,
                ExitId::from_bytes([0xAA; 16]),
                [0x11; 32],
                "10.0.0.1:443",
            )],
        };
        cfg.validate()
            .expect("the relay is version-agnostic and must load a /v2-signed descriptor");
    }

    #[test]
    fn validate_accepts_a_pq_signed_descriptor() {
        let op = det_signing_key(0x42);
        let cfg = RelayConfig {
            bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
            signing_key_path: PathBuf::from("/etc/warren-relay/identity.key"),
            operational_pubkey: op.verifying_key(),
            exits: vec![signed_descriptor_pq(
                &op,
                ExitId::from_bytes([0xAA; 16]),
                [0x11; 32],
                "10.0.0.1:443",
            )],
        };
        cfg.validate()
            .expect("the relay is version-agnostic and must load a PQ-signed descriptor");
    }

    #[test]
    fn validate_rejects_a_descriptor_signed_by_an_untrusted_key() {
        // A signature produced by an untrusted key must fail closed under
        // every cascaded context (PQ, /v2, /v1), not just the /v1 one this
        // descriptor happens to be shaped for.
        let trusted = det_signing_key(0x42);
        let attacker = det_signing_key(0x99);
        let descriptor = signed_descriptor(
            &attacker,
            ExitId::from_bytes([0xAA; 16]),
            [0x11; 32],
            "10.0.0.1:443",
        );
        let cfg = RelayConfig {
            bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
            signing_key_path: PathBuf::from("/etc/warren-relay/identity.key"),
            operational_pubkey: trusted.verifying_key(),
            exits: vec![descriptor],
        };
        let err = cfg
            .validate()
            .expect_err("a descriptor signed by an untrusted key must reject");
        assert!(matches!(err, ConfigError::Pki { index: 0, .. }));
    }
}
