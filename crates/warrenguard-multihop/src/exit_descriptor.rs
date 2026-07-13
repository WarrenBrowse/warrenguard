//! Exit descriptor `/v1` and mini-PKI verification.
//!
//! Mirror of [`crate::relay`] for the second hop: an
//! [`ExitDescriptorSigned`] binds a 16-byte exit routing tag, the exit's
//! Ed25519 raw-public-key identity (pinned by relay or client at TLS
//! handshake), the exit's long-lived X25519 HPKE recipient pubkey, and
//! the exit's QUIC endpoint, with a single Ed25519 signature produced by
//! the operational key over the canonical
//! [`crate::WARREN_PKI_OPERATIONAL_EXIT_V1`] payload.
//!
//! The same shape is consumed by `warren-relay` to populate its routing
//! pool and by the client to set up an HPKE session against the
//! advertised X25519 pubkey.
//!
//! # `/v1` contract
//!
//! The canonical signing payload is
//! `WARREN_PKI_OPERATIONAL_EXIT_V1 || exit_id (16 B) || exit_x25519_multihop_pubkey (32 B)`.
//! Total length 41 + 16 + 32 = 89 bytes. Frozen for all `/v1`
//! deployments; any wire-breaking change must bump to a `/v2` namespace.
//!
//! Note: the `exit_ed25519_pubkey` field is **not** covered by the
//! signature in `/v1`. Trust in that field still flows from the TOML
//! the operator publishes; the exit's RPK is pinned at handshake time
//! via the SNI-vs-cert verifier in `warren-tls`, so a swap-attack on
//! the field surfaces as a handshake failure rather than a silent
//! redirection. A `/v2` revision may bring the field under signature
//! coverage.

use std::net::SocketAddr;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::session::ExitId;
use crate::{
    WARREN_PKI_OPERATIONAL_EXIT_PQ_V1, WARREN_PKI_OPERATIONAL_EXIT_V1,
    WARREN_PKI_OPERATIONAL_EXIT_V2,
};

/// ML-KEM-768 encapsulation-key (recipient public key) length in bytes. The
/// value an exit publishes in [`ExitDescriptorSigned::exit_mlkem768_pubkey`].
pub const MLKEM768_ENCAPS_KEY_LEN: usize = 1184;

fn is_false(b: &bool) -> bool {
    !*b
}

/// One signed entry in an exit pool.
///
/// Constructed offline by the operational signer and shipped to the
/// relay (which routes traffic to the matching `endpoint`) and to the
/// client (which uses `exit_x25519_multihop_pubkey` as the HPKE
/// recipient).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitDescriptorSigned {
    /// 16-byte routing tag advertised in the cleartext header of every
    /// multi-hop datagram.
    #[serde(
        serialize_with = "serialize_exit_id",
        deserialize_with = "deserialize_exit_id"
    )]
    pub exit_id: ExitId,
    /// Ed25519 pubkey used as the TLS RPK identity of the exit's QUIC
    /// server. Pinned at the QUIC handshake; **not** covered by the
    /// signature in `/v1` (mitigated by RPK pinning + node attestation,
    /// cf. the module-level `/v1` contract). To be brought under
    /// signature coverage in a `/v2`.
    #[serde(with = "hex_array_32")]
    pub exit_ed25519_pubkey: [u8; 32],
    /// X25519 pubkey the client uses as the HPKE recipient when
    /// targeting this exit. Covered by the signature.
    #[serde(with = "hex_array_32")]
    pub exit_x25519_multihop_pubkey: [u8; 32],
    /// QUIC endpoint of the exit the relay must dial on cache miss.
    ///
    /// **Not** covered by the `/v1` signature (only `exit_id` and
    /// `exit_x25519_multihop_pubkey` are). A tampered `endpoint` can only
    /// redirect the relay->exit dial to a host that still has to present
    /// the signed `exit_ed25519_pubkey` as its TLS RPK, so a swap
    /// surfaces as a handshake failure rather than a silent redirection
    /// (same mitigation as `exit_ed25519_pubkey`). A `/v2` revision
    /// should bring this field under signature coverage.
    ///
    /// **`None` = redacted** (censorship-minimization): the
    /// client-facing `/v1/multihop/directory` omits the exit egress IP
    /// (the client never dials the exit, it dials the entry relay). Only
    /// the auth-gated relay-facing directory carries `Some(endpoint)`. The
    /// field is not under the descriptor signature, so omitting it keeps
    /// the operational signature valid; the server envelope is recomputed
    /// per-view at serve time. `#[serde(default)]` so a redacted directory
    /// deserializes (absent → `None`); skipped when `None` so a full
    /// descriptor serializes byte-identically to one that never carried
    /// the endpoint field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddr>,
    /// X.509 cover-domain SNI. `None` = RPK mode; `Some(domain)` =
    /// the relay->exit C2 dialer validates the exit's certificate via WebPKI
    /// and dials this domain as the SNI instead of pinning the RFC 7250 raw
    /// public key. The exit's Warren identity is still bound by HPKE (the
    /// client seals to `exit_x25519_multihop_pubkey`), so this field, like
    /// `endpoint`, is intentionally OUTSIDE the descriptor signature: a
    /// tampered cover domain cannot redirect traffic to a host that lacks the
    /// signed HPKE key. Serialized only when present, so a `/v1` (RPK)
    /// descriptor round-trips byte-for-byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_domain: Option<String>,
    /// Ed25519 signature, 64 bytes, hex-encoded in TOML.
    #[serde(with = "hex_array_64")]
    pub signature: [u8; 64],
    /// `/v2` attestation: when `true`, the exit refuses to act as the
    /// DNS resolver for client traffic; the multi-hop client MUST then
    /// boot with an explicit `--push-dns` upstream OR refuse to dial.
    ///
    /// Bound by the signature in `/v2`
    /// ([`exit_descriptor_signing_payload_v2`]). For backward
    /// compatibility with `/v1` descriptors (which never carried this
    /// byte and whose signature does NOT cover it), the field is
    /// `#[serde(default)]` and skipped in serialization when `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dns_disabled: bool,
    /// `/v2` post-quantum: the exit's long-lived ML-KEM-768 recipient key
    /// (1184 bytes), the ML-KEM half of the X-Wing hybrid seal. `None` on a
    /// classical descriptor.
    ///
    /// When present it is covered by the PQ signature
    /// ([`exit_descriptor_signing_payload_pq`]), which is the anti-downgrade
    /// anchor: a client that requested PQ decides PQ-vs-classical from THIS
    /// signed key, never from an unauthenticated wire bit, so a middlebox
    /// cannot strip it without invalidating the signature. `#[serde(default)]`
    /// and skipped when `None`, so a classical (`/v1`, `/v2`) descriptor
    /// serializes byte-identically to one that never carried the field.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_vec_opt")]
    pub exit_mlkem768_pubkey: Option<Vec<u8>>,
}

/// Errors raised by the exit-descriptor verifiers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExitPkiError {
    /// The 64-byte signature did not verify against the operational
    /// pubkey for the canonical
    /// `WARREN_PKI_OPERATIONAL_EXIT_V1 || exit_id || x25519_pubkey`
    /// payload. Either the descriptor was tampered with, or it was
    /// signed by a different operational key than the one currently
    /// trusted.
    #[error("exit descriptor signature does not verify")]
    BadSignature,

    /// PQ verification was requested but the descriptor carries no
    /// `exit_mlkem768_pubkey`. A classical descriptor cannot satisfy the PQ
    /// verifier.
    #[error("exit descriptor carries no ML-KEM key")]
    MissingPqKey,

    /// The descriptor's `exit_mlkem768_pubkey` is not
    /// [`MLKEM768_ENCAPS_KEY_LEN`] bytes.
    #[error("exit descriptor ML-KEM key has wrong length: {got}")]
    BadPqKeyLength {
        /// Observed byte length of the ML-KEM key.
        got: usize,
    },

    /// Anti-downgrade rejection: the client REQUIRED the post-quantum hybrid
    /// seal, but the exit's signed descriptor advertises no valid ML-KEM key.
    /// Falling back to classical here would let a middlebox strip PQ, so the
    /// dial is refused instead.
    #[error("pq required but the signed descriptor advertises no ML-KEM key (downgrade refused)")]
    PqDowngrade,
}

/// Builds the canonical payload the operational signer must sign for a
/// given exit.
///
/// Layout: `WARREN_PKI_OPERATIONAL_EXIT_V1 || exit_id (16 B) || x25519_pubkey (32 B)`.
/// Total 41 + 16 + 32 = 89 bytes.
#[must_use]
pub fn exit_descriptor_signing_payload(
    exit_id: ExitId,
    exit_x25519_multihop_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(WARREN_PKI_OPERATIONAL_EXIT_V1.len() + 16 + 32);
    buf.extend_from_slice(WARREN_PKI_OPERATIONAL_EXIT_V1);
    buf.extend_from_slice(exit_id.as_bytes());
    buf.extend_from_slice(exit_x25519_multihop_pubkey);
    buf
}

/// Builds the canonical payload the operational signer must sign in
/// the `/v2` PKI context, which extends `/v1` with the `dns_disabled`
/// attestation byte.
///
/// Layout: `WARREN_PKI_OPERATIONAL_EXIT_V2 || exit_id (16 B) || x25519_pubkey (32 B) || dns_disabled_byte`.
/// Total 41 + 16 + 32 + 1 = 90 bytes. `dns_disabled_byte` is `0x01`
/// when the attestation is set, `0x00` otherwise.
#[must_use]
pub fn exit_descriptor_signing_payload_v2(
    exit_id: ExitId,
    exit_x25519_multihop_pubkey: &[u8; 32],
    dns_disabled: bool,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(WARREN_PKI_OPERATIONAL_EXIT_V2.len() + 16 + 32 + 1);
    buf.extend_from_slice(WARREN_PKI_OPERATIONAL_EXIT_V2);
    buf.extend_from_slice(exit_id.as_bytes());
    buf.extend_from_slice(exit_x25519_multihop_pubkey);
    buf.push(u8::from(dns_disabled));
    buf
}

/// Verifies an [`ExitDescriptorSigned`] against the supplied operational
/// pubkey using the `/v1` PKI context.
///
/// **Security note**: `/v1` does NOT cover [`ExitDescriptorSigned::dns_disabled`].
/// Callers that depend on that attestation (e.g. multi-hop clients
/// gating DNS leak protection) MUST use [`verify_exit_descriptor_v2`]
/// instead.
///
/// # Errors
/// - [`ExitPkiError::BadSignature`] if the signature does not verify.
pub fn verify_exit_descriptor(
    operational_pubkey: &VerifyingKey,
    descriptor: &ExitDescriptorSigned,
) -> Result<(), ExitPkiError> {
    let payload = exit_descriptor_signing_payload(
        descriptor.exit_id,
        &descriptor.exit_x25519_multihop_pubkey,
    );
    let signature = Signature::from_bytes(&descriptor.signature);
    operational_pubkey
        .verify_strict(&payload, &signature)
        .map_err(|_| ExitPkiError::BadSignature)
}

/// Result of [`verify_exit_descriptor_with_dns_attestation`].
///
/// Tells the caller whether the `dns_disabled` field carried by the
/// descriptor is covered by the operational signature (`Attested`) or
/// only carried as an unsigned advisory hint (`Unattested`, legacy
/// `/v1` descriptors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDescAttestation {
    /// The `/v2` verifier accepted the descriptor; `dns_disabled` is
    /// bound under the signature and trustworthy.
    Attested {
        /// Value of the signed `dns_disabled` bit.
        dns_disabled: bool,
    },
    /// Only the legacy `/v1` verifier accepted the descriptor.
    /// `dns_disabled` was NOT covered by the signature; treat it as
    /// `false` and refuse the dial if the descriptor advertises
    /// `dns_disabled = true` (suspected downgrade attack).
    Unattested,
}

/// Verifies an [`ExitDescriptorSigned`] under both PKI contexts and
/// reports back whether `dns_disabled` was attested by the operational
/// signature.
///
/// Tries `/v2` first; falls back to `/v1` only on `/v2` failure. A
/// descriptor that advertises `dns_disabled = true` but only validates
/// under `/v1` is a downgrade-attack suspect and surfaces as
/// [`ExitDescAttestation::Unattested`]; the multi-hop client MUST
/// refuse the dial in that case.
///
/// # Errors
/// - [`ExitPkiError::BadSignature`] if neither `/v2` nor `/v1` verify
///   the descriptor.
pub fn verify_exit_descriptor_with_dns_attestation(
    operational_pubkey: &VerifyingKey,
    descriptor: &ExitDescriptorSigned,
) -> Result<ExitDescAttestation, ExitPkiError> {
    if verify_exit_descriptor_v2(operational_pubkey, descriptor).is_ok() {
        return Ok(ExitDescAttestation::Attested {
            dns_disabled: descriptor.dns_disabled,
        });
    }
    verify_exit_descriptor(operational_pubkey, descriptor)?;
    Ok(ExitDescAttestation::Unattested)
}

/// Verifies an [`ExitDescriptorSigned`] against the supplied operational
/// pubkey using the `/v2` PKI context, which binds
/// [`ExitDescriptorSigned::dns_disabled`] under the signature.
///
/// The `/v2` context is distinct from `/v1`
/// ([`WARREN_PKI_OPERATIONAL_EXIT_V2`] vs
/// [`WARREN_PKI_OPERATIONAL_EXIT_V1`]) so a `/v1` signature cannot
/// satisfy this verifier and vice-versa: a downgrade attack that
/// strips `dns_disabled = true` from a `/v2` descriptor and presents
/// it to [`verify_exit_descriptor`] would succeed only against a
/// separately-issued `/v1` signature, never against the same bytes.
///
/// # Errors
/// - [`ExitPkiError::BadSignature`] if the signature does not verify
///   against the canonical `/v2` payload.
pub fn verify_exit_descriptor_v2(
    operational_pubkey: &VerifyingKey,
    descriptor: &ExitDescriptorSigned,
) -> Result<(), ExitPkiError> {
    let payload = exit_descriptor_signing_payload_v2(
        descriptor.exit_id,
        &descriptor.exit_x25519_multihop_pubkey,
        descriptor.dns_disabled,
    );
    let signature = Signature::from_bytes(&descriptor.signature);
    operational_pubkey
        .verify_strict(&payload, &signature)
        .map_err(|_| ExitPkiError::BadSignature)
}

/// Builds the canonical payload the operational signer must sign in the `/v2`
/// post-quantum PKI context. Extends the `/v2` (`dns_disabled`) payload with the
/// exit's ML-KEM-768 recipient key.
///
/// Layout:
/// `WARREN_PKI_OPERATIONAL_EXIT_PQ_V1 || exit_id (16) || x25519_pubkey (32) || dns_disabled_byte (1) || mlkem768_ek (1184)`.
#[must_use]
pub fn exit_descriptor_signing_payload_pq(
    exit_id: ExitId,
    exit_x25519_multihop_pubkey: &[u8; 32],
    dns_disabled: bool,
    exit_mlkem768_pubkey: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        WARREN_PKI_OPERATIONAL_EXIT_PQ_V1.len() + 16 + 32 + 1 + exit_mlkem768_pubkey.len(),
    );
    buf.extend_from_slice(WARREN_PKI_OPERATIONAL_EXIT_PQ_V1);
    buf.extend_from_slice(exit_id.as_bytes());
    buf.extend_from_slice(exit_x25519_multihop_pubkey);
    buf.push(u8::from(dns_disabled));
    buf.extend_from_slice(exit_mlkem768_pubkey);
    buf
}

/// Verifies an [`ExitDescriptorSigned`] under the `/v2` post-quantum PKI
/// context, binding the ML-KEM-768 recipient key under the operational
/// signature.
///
/// The context string is distinct from `/v1` and `/v2`
/// ([`WARREN_PKI_OPERATIONAL_EXIT_PQ_V1`]), so a `/v1` or `/v2` signature can
/// never satisfy this verifier and vice-versa: an attacker who strips the
/// ML-KEM key from a PQ descriptor and presents it to [`verify_exit_descriptor`]
/// would need a separately issued `/v1` signature, never the same bytes.
///
/// # Errors
/// - [`ExitPkiError::MissingPqKey`] if the descriptor carries no ML-KEM key.
/// - [`ExitPkiError::BadPqKeyLength`] if the ML-KEM key is not
///   [`MLKEM768_ENCAPS_KEY_LEN`] bytes.
/// - [`ExitPkiError::BadSignature`] if the signature does not verify against the
///   canonical PQ payload.
pub fn verify_exit_descriptor_pq(
    operational_pubkey: &VerifyingKey,
    descriptor: &ExitDescriptorSigned,
) -> Result<(), ExitPkiError> {
    let ek = descriptor
        .exit_mlkem768_pubkey
        .as_deref()
        .ok_or(ExitPkiError::MissingPqKey)?;
    if ek.len() != MLKEM768_ENCAPS_KEY_LEN {
        return Err(ExitPkiError::BadPqKeyLength { got: ek.len() });
    }
    let payload = exit_descriptor_signing_payload_pq(
        descriptor.exit_id,
        &descriptor.exit_x25519_multihop_pubkey,
        descriptor.dns_disabled,
        ek,
    );
    let signature = Signature::from_bytes(&descriptor.signature);
    operational_pubkey
        .verify_strict(&payload, &signature)
        .map_err(|_| ExitPkiError::BadSignature)
}

/// Outcome of [`negotiate_pq`]: whether the post-quantum hybrid seal is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqAvailability {
    /// The exit published a validly SIGNED ML-KEM-768 key; the client uses the
    /// X-Wing hybrid seal and sets the `PQ_HPKE` wire feature bit.
    Available,
    /// The exit published no signed ML-KEM key and the client did not REQUIRE
    /// PQ, so it uses the classical X25519 seal (exactly as production ships
    /// today). The `PQ_HPKE` bit stays clear.
    ClassicalFallback,
}

/// Decide whether to use the post-quantum hybrid seal against an exit, with
/// anti-downgrade protection.
///
/// The decision is driven ONLY by the operational signature over the exit's
/// ML-KEM key, never by an unauthenticated wire bit. If the descriptor carries a
/// valid signed ML-KEM key, PQ is [`PqAvailability::Available`]. Otherwise:
/// a client that set `require_pq` is being downgraded and the dial is REFUSED
/// ([`ExitPkiError::PqDowngrade`]); a client that did not require PQ falls back
/// to the classical seal ([`PqAvailability::ClassicalFallback`]).
///
/// A middlebox that clears the client's `PQ_HPKE` bit cannot force a downgrade:
/// a `require_pq` client independently sees the signed ML-KEM key here and would
/// detect the mismatch (it expects a PQ-sealed reply and refuses a classical
/// one). A middlebox that strips the ML-KEM key from the descriptor invalidates
/// the signature, so `verify_exit_descriptor_pq` fails and the `require_pq`
/// client refuses.
///
/// # Errors
/// - [`ExitPkiError::PqDowngrade`] if `require_pq` is set but no valid signed
///   ML-KEM key is present.
pub fn negotiate_pq(
    operational_pubkey: &VerifyingKey,
    descriptor: &ExitDescriptorSigned,
    require_pq: bool,
) -> Result<PqAvailability, ExitPkiError> {
    if verify_exit_descriptor_pq(operational_pubkey, descriptor).is_ok() {
        Ok(PqAvailability::Available)
    } else if require_pq {
        Err(ExitPkiError::PqDowngrade)
    } else {
        Ok(PqAvailability::ClassicalFallback)
    }
}

mod hex_vec_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => s.serialize_str(&hex::encode(v)),
            None => s.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        use serde::de::Error as _;
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(hstr) => {
                Ok(Some(hex::decode(&hstr).map_err(|e| {
                    D::Error::custom(format!("hex decode failed: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }
}

fn serialize_exit_id<S: Serializer>(id: &ExitId, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(id.as_bytes()))
}

fn deserialize_exit_id<'de, D: Deserializer<'de>>(d: D) -> Result<ExitId, D::Error> {
    use serde::de::Error as _;
    let s = String::deserialize(d)?;
    let bytes =
        hex::decode(&s).map_err(|e| D::Error::custom(format!("exit_id is not hex: {e}")))?;
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| D::Error::custom("exit_id must be 16 bytes"))?;
    Ok(ExitId::from_bytes(arr))
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
    fn verifies_a_freshly_signed_descriptor() {
        let op = det_signing_key(0x42);
        let exit_id = ExitId::from_bytes([0x11; 16]);
        let x25519 = [0x22; 32];
        let payload = exit_descriptor_signing_payload(exit_id, &x25519);
        let sig = op.sign(&payload);
        let descriptor = ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0x33; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some("10.0.0.1:443".parse().expect("static addr")),
            cover_domain: None,
            signature: sig.to_bytes(),
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        };
        verify_exit_descriptor(&op.verifying_key(), &descriptor).expect("verify");
    }

    #[test]
    fn rejects_signature_tampered_by_one_byte() {
        let op = det_signing_key(0x42);
        let exit_id = ExitId::from_bytes([0x11; 16]);
        let x25519 = [0x22; 32];
        let payload = exit_descriptor_signing_payload(exit_id, &x25519);
        let mut sig = op.sign(&payload).to_bytes();
        sig[0] ^= 0x01;
        let descriptor = ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0x33; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some("10.0.0.1:443".parse().expect("static addr")),
            cover_domain: None,
            signature: sig,
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        };
        let err = verify_exit_descriptor(&op.verifying_key(), &descriptor)
            .expect_err("flipped signature byte must reject");
        assert!(matches!(err, ExitPkiError::BadSignature));
    }

    // ---------------- /v2 ---------------- //

    fn signed_v2(
        op: &SigningKey,
        exit_id: ExitId,
        x25519: [u8; 32],
        dns_disabled: bool,
    ) -> ExitDescriptorSigned {
        let payload = exit_descriptor_signing_payload_v2(exit_id, &x25519, dns_disabled);
        let sig = op.sign(&payload).to_bytes();
        ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0x33; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some("10.0.0.1:443".parse().expect("static addr")),
            cover_domain: None,
            signature: sig,
            dns_disabled,
            exit_mlkem768_pubkey: None,
        }
    }

    #[test]
    fn v2_verifies_with_dns_disabled_true() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], true);
        verify_exit_descriptor_v2(&op.verifying_key(), &d).expect("v2 verify");
    }

    #[test]
    fn v2_verifies_with_dns_disabled_false() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], false);
        verify_exit_descriptor_v2(&op.verifying_key(), &d).expect("v2 verify");
    }

    /// Flipping `dns_disabled` after signing MUST invalidate the `/v2`
    /// signature. Without that guarantee, a relay (or any
    /// MITM-with-stripped-permissions) could turn a "no DNS" exit into
    /// an exit that claims DNS without breaking the verification path,
    /// silently exposing clearnet DNS to the relay.
    #[test]
    fn v2_rejects_flipped_dns_disabled_after_signing() {
        let op = det_signing_key(0x42);
        let mut d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], true);
        d.dns_disabled = false;
        let err = verify_exit_descriptor_v2(&op.verifying_key(), &d)
            .expect_err("flipped dns_disabled must reject /v2 signature");
        assert!(matches!(err, ExitPkiError::BadSignature));
    }

    /// Downgrade protection: a `/v2` signature MUST NOT verify under
    /// the `/v1` verifier (different context strings) and vice-versa.
    /// A signer that emits a `/v1` signature cannot claim it as a
    /// `dns_disabled` attestation, and a `/v2` signature cannot be
    /// validated by a legacy `/v1`-only client (it must explicitly
    /// upgrade).
    #[test]
    fn v1_signature_does_not_verify_under_v2() {
        let op = det_signing_key(0x42);
        let exit_id = ExitId::from_bytes([0x11; 16]);
        let x25519 = [0x22; 32];
        let payload_v1 = exit_descriptor_signing_payload(exit_id, &x25519);
        let sig_v1 = op.sign(&payload_v1).to_bytes();
        let d = ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0x33; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some("10.0.0.1:443".parse().expect("static addr")),
            cover_domain: None,
            signature: sig_v1,
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        };
        let err = verify_exit_descriptor_v2(&op.verifying_key(), &d)
            .expect_err("v1 signature must not satisfy v2 verifier");
        assert!(matches!(err, ExitPkiError::BadSignature));
    }

    #[test]
    fn v2_signature_does_not_verify_under_v1() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], false);
        let err = verify_exit_descriptor(&op.verifying_key(), &d)
            .expect_err("v2 signature must not satisfy v1 verifier");
        assert!(matches!(err, ExitPkiError::BadSignature));
    }

    /// Legacy `/v1` descriptor serialized BEFORE the `dns_disabled`
    /// field existed must roundtrip cleanly via serde with
    /// `dns_disabled = false` default.
    #[test]
    fn legacy_v1_json_without_dns_disabled_deserializes_to_false() {
        let op = det_signing_key(0x42);
        let exit_id = ExitId::from_bytes([0x11; 16]);
        let x25519 = [0x22; 32];
        let sig = op.sign(&exit_descriptor_signing_payload(exit_id, &x25519));
        let legacy_json = serde_json::json!({
            "exit_id": hex::encode(exit_id.as_bytes()),
            "exit_ed25519_pubkey": hex::encode([0x33u8; 32]),
            "exit_x25519_multihop_pubkey": hex::encode(x25519),
            "endpoint": "10.0.0.1:443",
            "signature": hex::encode(sig.to_bytes()),
        });
        let d: ExitDescriptorSigned =
            serde_json::from_value(legacy_json).expect("legacy v1 JSON must decode");
        assert!(
            !d.dns_disabled,
            "missing field must default to false for backward compat"
        );
    }

    /// `dns_disabled = false` must be omitted from JSON output to keep
    /// `/v1` descriptors byte-identical post-upgrade (no spurious diff
    /// in committed TOML / JSON descriptors).
    #[test]
    fn dns_disabled_false_is_omitted_from_json() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], false);
        let json = serde_json::to_string(&d).expect("serialize");
        assert!(
            !json.contains("dns_disabled"),
            "dns_disabled = false must not appear in JSON; got {json}"
        );
    }

    /// A redacted descriptor (`endpoint = None`) must (a) omit
    /// the field from JSON, (b) still verify, since `endpoint` is not
    /// under the operational signature. This is what the client-facing
    /// directory carries: the exit crypto without the egress IP.
    #[test]
    fn redacted_endpoint_is_omitted_and_still_verifies() {
        let op = det_signing_key(0x42);
        let exit_id = ExitId::from_bytes([0x11; 16]);
        let x25519 = [0x22; 32];
        let sig = op.sign(&exit_descriptor_signing_payload(exit_id, &x25519));
        let d = ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0x33; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: None,
            cover_domain: None,
            signature: sig.to_bytes(),
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        };
        let json = serde_json::to_string(&d).expect("serialize");
        assert!(
            !json.contains("endpoint"),
            "redacted descriptor must not carry the egress IP; got {json}"
        );
        verify_exit_descriptor(&op.verifying_key(), &d)
            .expect("endpoint is outside the signature, so a redacted descriptor still verifies");
        let round: ExitDescriptorSigned =
            serde_json::from_str(&json).expect("redacted JSON must decode");
        assert!(round.endpoint.is_none(), "absent endpoint decodes to None");
    }

    #[test]
    fn dns_disabled_true_appears_in_json() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], true);
        let json = serde_json::to_string(&d).expect("serialize");
        assert!(
            json.contains("\"dns_disabled\":true"),
            "dns_disabled = true must appear in JSON; got {json}"
        );
    }

    // -------- verify_exit_descriptor_with_dns_attestation --------- //

    #[test]
    fn attestation_reports_v2_signed_dns_disabled_true() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], true);
        let attest =
            verify_exit_descriptor_with_dns_attestation(&op.verifying_key(), &d).expect("verify");
        assert_eq!(attest, ExitDescAttestation::Attested { dns_disabled: true });
    }

    #[test]
    fn attestation_reports_v2_signed_dns_disabled_false() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], false);
        let attest =
            verify_exit_descriptor_with_dns_attestation(&op.verifying_key(), &d).expect("verify");
        assert_eq!(
            attest,
            ExitDescAttestation::Attested {
                dns_disabled: false
            }
        );
    }

    /// Legacy `/v1` descriptor: signature only covers
    /// `(exit_id, x25519)`. The attestation MUST surface as `Unattested`
    /// so the caller can refuse a dial that pretends to advertise
    /// `dns_disabled` without a `/v2` signature.
    #[test]
    fn attestation_reports_v1_only_as_unattested() {
        let op = det_signing_key(0x42);
        let exit_id = ExitId::from_bytes([0x11; 16]);
        let x25519 = [0x22; 32];
        let sig = op.sign(&exit_descriptor_signing_payload(exit_id, &x25519));
        let d = ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0x33; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some("10.0.0.1:443".parse().expect("static addr")),
            cover_domain: None,
            signature: sig.to_bytes(),
            dns_disabled: true, // attacker-claimed but NOT signed
            exit_mlkem768_pubkey: None,
        };
        let attest =
            verify_exit_descriptor_with_dns_attestation(&op.verifying_key(), &d).expect("verify");
        assert_eq!(
            attest,
            ExitDescAttestation::Unattested,
            "v1-only signature must NOT attest dns_disabled even when the field is set"
        );
    }

    #[test]
    fn attestation_rejects_bad_signature() {
        let op = det_signing_key(0x42);
        let attacker = det_signing_key(0x99);
        let d = signed_v2(&attacker, ExitId::from_bytes([0x11; 16]), [0x22; 32], true);
        let err = verify_exit_descriptor_with_dns_attestation(&op.verifying_key(), &d)
            .expect_err("foreign signature must reject");
        assert!(matches!(err, ExitPkiError::BadSignature));
    }

    // ---------------- /v2 post-quantum descriptor ---------------- //

    /// A stand-in ML-KEM-768 encapsulation key: the descriptor verifier treats
    /// it as opaque 1184-byte material (it checks length + signature, not
    /// ML-KEM validity), so these tests do not need the `pq-hpke` crypto.
    fn dummy_mlkem_ek() -> Vec<u8> {
        (0..MLKEM768_ENCAPS_KEY_LEN)
            .map(|i| (i % 251) as u8)
            .collect()
    }

    fn signed_pq(
        op: &SigningKey,
        exit_id: ExitId,
        x25519: [u8; 32],
        dns_disabled: bool,
        mlkem_ek: Vec<u8>,
    ) -> ExitDescriptorSigned {
        let payload = exit_descriptor_signing_payload_pq(exit_id, &x25519, dns_disabled, &mlkem_ek);
        let sig = op.sign(&payload).to_bytes();
        ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0x33; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: None,
            cover_domain: None,
            signature: sig,
            dns_disabled,
            exit_mlkem768_pubkey: Some(mlkem_ek),
        }
    }

    #[test]
    fn pq_descriptor_verifies_and_negotiates_available() {
        let op = det_signing_key(0x42);
        let d = signed_pq(
            &op,
            ExitId::from_bytes([0x11; 16]),
            [0x22; 32],
            true,
            dummy_mlkem_ek(),
        );
        verify_exit_descriptor_pq(&op.verifying_key(), &d).expect("pq verify");
        assert_eq!(
            negotiate_pq(&op.verifying_key(), &d, true).expect("negotiate required"),
            PqAvailability::Available
        );
        assert_eq!(
            negotiate_pq(&op.verifying_key(), &d, false).expect("negotiate preferred"),
            PqAvailability::Available
        );
    }

    /// Anti-downgrade: a client that REQUIRES PQ against an exit with no signed
    /// ML-KEM key must refuse the dial, never silently fall back to classical.
    #[test]
    fn negotiate_required_pq_without_mlkem_key_refuses_downgrade() {
        let op = det_signing_key(0x42);
        let classical = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], true);
        assert!(classical.exit_mlkem768_pubkey.is_none());
        let err = negotiate_pq(&op.verifying_key(), &classical, true)
            .expect_err("required-pq client must refuse a non-PQ exit");
        assert!(matches!(err, ExitPkiError::PqDowngrade));
    }

    /// A client that only PREFERS PQ falls back to classical when the exit has
    /// no signed ML-KEM key.
    #[test]
    fn negotiate_preferred_pq_without_mlkem_key_falls_back() {
        let op = det_signing_key(0x42);
        let classical = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], false);
        assert_eq!(
            negotiate_pq(&op.verifying_key(), &classical, false).expect("fallback"),
            PqAvailability::ClassicalFallback
        );
    }

    /// Tampering the signed ML-KEM key invalidates the PQ signature, so a
    /// required-pq client is protected from a middlebox swapping the PQ key.
    #[test]
    fn pq_verify_rejects_tampered_mlkem_key() {
        let op = det_signing_key(0x42);
        let mut d = signed_pq(
            &op,
            ExitId::from_bytes([0x11; 16]),
            [0x22; 32],
            true,
            dummy_mlkem_ek(),
        );
        if let Some(ek) = d.exit_mlkem768_pubkey.as_mut() {
            ek[0] ^= 0x01;
        }
        assert!(matches!(
            verify_exit_descriptor_pq(&op.verifying_key(), &d),
            Err(ExitPkiError::BadSignature)
        ));
        assert!(matches!(
            negotiate_pq(&op.verifying_key(), &d, true),
            Err(ExitPkiError::PqDowngrade)
        ));
    }

    #[test]
    fn pq_verify_rejects_wrong_length_mlkem_key() {
        let op = det_signing_key(0x42);
        let mut d = signed_pq(
            &op,
            ExitId::from_bytes([0x11; 16]),
            [0x22; 32],
            true,
            dummy_mlkem_ek(),
        );
        d.exit_mlkem768_pubkey = Some(vec![0xAB; 100]);
        assert!(matches!(
            verify_exit_descriptor_pq(&op.verifying_key(), &d),
            Err(ExitPkiError::BadPqKeyLength { got: 100 })
        ));
    }

    #[test]
    fn pq_verify_rejects_missing_mlkem_key() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], true);
        assert!(matches!(
            verify_exit_descriptor_pq(&op.verifying_key(), &d),
            Err(ExitPkiError::MissingPqKey)
        ));
    }

    /// Context separation: a PQ signature must not satisfy the `/v1` or `/v2`
    /// verifiers, and vice-versa.
    #[test]
    fn pq_signature_does_not_cross_verify_with_v1_or_v2() {
        let op = det_signing_key(0x42);
        let exit_id = ExitId::from_bytes([0x11; 16]);
        let d = signed_pq(&op, exit_id, [0x22; 32], true, dummy_mlkem_ek());
        assert!(matches!(
            verify_exit_descriptor(&op.verifying_key(), &d),
            Err(ExitPkiError::BadSignature)
        ));
        assert!(matches!(
            verify_exit_descriptor_v2(&op.verifying_key(), &d),
            Err(ExitPkiError::BadSignature)
        ));

        // And a /v2 signature does not satisfy the PQ verifier (even if we
        // attach a well-formed ML-KEM key with a /v2, not /pq, signature).
        let mut v2 = signed_v2(&op, exit_id, [0x22; 32], true);
        v2.exit_mlkem768_pubkey = Some(dummy_mlkem_ek());
        assert!(matches!(
            verify_exit_descriptor_pq(&op.verifying_key(), &v2),
            Err(ExitPkiError::BadSignature)
        ));
    }

    /// A classical descriptor (no ML-KEM key) serializes byte-identically to
    /// before the field existed: the field is omitted from JSON when `None`.
    #[test]
    fn absent_mlkem_key_is_omitted_from_json() {
        let op = det_signing_key(0x42);
        let d = signed_v2(&op, ExitId::from_bytes([0x11; 16]), [0x22; 32], false);
        let json = serde_json::to_string(&d).expect("serialize");
        assert!(
            !json.contains("exit_mlkem768_pubkey"),
            "absent ML-KEM key must not appear in JSON; got {json}"
        );
    }
}
