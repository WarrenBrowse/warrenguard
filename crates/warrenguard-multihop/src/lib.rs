//! Warren multi-hop: HPKE-based payload encryption for the two-relayed QUIC
//! pattern.
//!
//! This crate covers the wire format, constants, and
//! the client/exit HPKE sessions. The relay binary, the client
//! integration, and the mini-PKI live in separate crates.
//!
//! # Threat model summary
//!
//! - Hop 1 (relay) is cryptographically blind to the payload: HPKE
//!   `ChaCha20Poly1305 + X25519 ECDH`, and the recipient (exit) private key
//!   never leaves the exit.
//! - End-to-end authenticated encryption from client to exit (HPKE base
//!   mode).
//! - Forward secrecy is **non-absolute** because the recipient X25519 key is
//!   long-lived. A compromise of that key would retroactively expose archived
//!   sessions. Mitigations: rigorous private-key handling + mandatory HPKE
//!   context rotation (`rekey`) every < 8 hours.
//!
//! # Wire format v1
//!
//! The wire format and every
//! `WARREN_*_V1` constant in this crate are frozen forever. Any
//! wire-breaking change must bump to a separate `/v2` namespace.
//!
//! # Cryptographic suite
//!
//! | RFC 9180 component | Value                                | ID     |
//! |--------------------|--------------------------------------|--------|
//! | KEM                | `DHKEM(X25519, HKDF-SHA256)`         | 0x0020 |
//! | KDF                | `HKDF-SHA256`                        | 0x0001 |
//! | AEAD               | `ChaCha20Poly1305`                   | 0x0003 |
//! | HPKE mode          | `mode_base`                          | 0x00   |

#![forbid(unsafe_code)]

mod close_codes;
mod control;
mod errors;
mod exit_descriptor;
mod node_attestation;
mod operational_cert;
mod pop;
mod relay;
mod replay;
mod session;
mod setup;
mod wire_format;
// The `/v2` PQ frame struct is wire, not crypto: it decodes on every build so
// a classical-only node recognizes (and cleanly refuses) a PQ frame instead of
// misparsing it. Only the X-Wing crypto below is gated by `pq-hpke`.
mod wire_format_v2;
// X-Wing hybrid KEM (X25519 + ML-KEM-768) and the `/v2` PQ HPKE session.
// Additive and OFF by default: the classical X25519 seal stays the production
// default until the PQ path is real-exit validated.
#[cfg(feature = "pq-hpke")]
mod pq_session;
#[cfg(feature = "pq-hpke")]
mod xwing;

pub use close_codes::{
    RejectionReason, WARREN_MH_DRAINING, WARREN_MH_FORCED_RECONNECT, WARREN_MH_REJECTED,
};
pub use control::{
    CONTROL_FIRST_BYTE, CONTROL_VERSION_V3, ControlError, PopSignature, WarrenControlMessage,
    encode_control, try_decode_control,
};
pub use errors::MultihopError;
pub use exit_descriptor::{
    ExitDescAttestation, ExitDescriptorSigned, ExitPkiError, MLKEM768_ENCAPS_KEY_LEN,
    PqAvailability, exit_descriptor_signing_payload, exit_descriptor_signing_payload_pq,
    exit_descriptor_signing_payload_v2, negotiate_pq, verify_exit_descriptor,
    verify_exit_descriptor_pq, verify_exit_descriptor_v2,
    verify_exit_descriptor_with_dns_attestation,
};
pub use node_attestation::{
    NodeAttestationError, node_attestation_signing_payload, sign_node_attestation,
    verify_node_attestation,
};
pub use operational_cert::{
    OperationalCertError, operational_cert_signing_payload, sign_operational_cert,
    verify_operational_cert,
};
pub use pop::{POP_CONTEXT_V2, pop_signing_message, sign_pop, verify_pop};
pub use relay::{
    RELAY_AUTH_PROOF_LEN, RELAY_AUTH_PROOF_VERSION, RelayDescriptorSigned, RelayPkiError,
    decode_relay_auth_proof, encode_relay_auth_proof, relay_descriptor_signing_payload,
    verify_relay_descriptor,
};
pub use replay::{REPLAY_WINDOW_SIZE, ReplayWindow};
pub use session::{
    ClientSession, ExitId, ExitSession, WARREN_AAD_TOTAL_LEN, WarrenAead, WarrenKdf, WarrenKem,
    compose_aad, parse_exit_x25519_pubkey,
};
pub use setup::{IpAssignment, SetupError};
pub use wire_format::{
    EncapsulatedKeyBytes, MULTIHOP_FRAME_MAX_OVERHEAD, WARREN_HPKE_VERSION, WarrenMultihopFrame,
    decode_frame, encode_frame,
};
pub use wire_format_v2::{
    MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD, MULTIHOP_FRAME_V2_MAX_OVERHEAD, WARREN_HPKE_VERSION_V2,
    WarrenMultihopFrameV2, decode_frame_v2, encode_frame_v2,
};

#[cfg(feature = "pq-hpke")]
pub use pq_session::{PqClientSession, PqExitSession};
#[cfg(feature = "pq-hpke")]
pub use xwing::{
    XWING_CT_LEN, XWING_LABEL, XWING_MLKEM_CT_LEN, XWING_MLKEM_EK_LEN, XWING_X25519_LEN,
    XWingCiphertext, XWingRecipientPublicKey, XWingRecipientSecretKey, XWingSharedSecret,
    derive_exit_xwing_recipient, xwing_combiner,
};

/// X25519 public key type alias (`hpke::kem::X25519HkdfSha256::PublicKey`).
/// Exposed at crate root so callers do not need to depend on `hpke`
/// directly to spell out the type.
pub type WarrenKemPublicKey = <session::WarrenKem as hpke::Kem>::PublicKey;

/// X25519 private key type alias (`hpke::kem::X25519HkdfSha256::PrivateKey`).
pub type WarrenKemPrivateKey = <session::WarrenKem as hpke::Kem>::PrivateKey;

/// X25519 encapsulated key type alias.
pub type WarrenKemEncappedKey = <session::WarrenKem as hpke::Kem>::EncappedKey;

/// Test-only helpers re-exported for vectors and property tests. Hidden
/// from rendered documentation.
#[doc(hidden)]
pub mod test_support {
    pub use crate::session::{derive_exit_keypair, pubkey_from_bytes, pubkey_to_bytes};

    /// X-Wing KAT support: replays the official draft vectors through the
    /// production combiner + KEM code. See [`crate::xwing::xwing_reference_flow`].
    #[cfg(feature = "pq-hpke")]
    pub use crate::xwing::{XWingReferenceOutput, xwing_reference_flow};
}

/// HPKE `info` field bound into the KEM ECDH derivation (RFC 9180 § 5.1).
///
/// Frozen for all `/v1` deployments. Any change requires a `/v2` namespace.
pub const WARREN_HPKE_INFO_V1: &[u8] = b"warren/multihop/v1/hpke-info";

/// HPKE AAD prefix bound into every sealed datagram.
///
/// Full AAD = `WARREN_HPKE_AAD_V1 || exit_id (16 B) || epoch_u32_be || seq_u64_be`.
/// Frozen for `/v1`.
pub const WARREN_HPKE_AAD_V1: &[u8] = b"warren/multihop/v1/aad";

/// Wire format version byte. `0x01` for the multihop v1 frame layout. A
/// future incompatible change must use a different byte and live in a `/v2`
/// crate or module.
pub const WARREN_HPKE_VERSION_V1: u8 = 0x01;

/// HKDF-SHA256 `salt` for the post-quantum (`/v2`) key schedule. The X-Wing
/// shared secret is the IKM; the extracted PRK is expanded per packet with the
/// `WARREN_PQ_HPKE_AAD_V2`-prefixed info below. Distinct domain from `/v1`
/// (which uses the `hpke` exporter, not HKDF), so a `/v1` and a `/v2` session
/// over the same `(epoch, seq)` never derive the same per-packet key. Frozen
/// for `/v2`.
pub const WARREN_PQ_HPKE_SALT_V2: &[u8] = b"warren/multihop/v2/pq-hkdf-salt";

/// AAD prefix bound into every post-quantum (`/v2`) sealed datagram, and the
/// domain prefix of the HKDF per-packet-key info.
///
/// Full AAD = `WARREN_PQ_HPKE_AAD_V2 || exit_id (16 B) || epoch_u32_be || seq_u64_be`.
/// Deliberately distinct from [`WARREN_HPKE_AAD_V1`] so the classical and PQ
/// datapaths are cryptographically domain-separated. Frozen for `/v2`.
pub const WARREN_PQ_HPKE_AAD_V2: &[u8] = b"warren/multihop/v2/pq-aad";

/// Ed25519 signature context for the operational key signing an exit's
/// post-quantum descriptor: its X25519 multihop pubkey, its `dns_disabled`
/// attestation, AND its long-lived ML-KEM-768 recipient key.
///
/// The signed message is
/// `WARREN_PKI_OPERATIONAL_EXIT_PQ_V1 || exit_id (16) || exit_x25519_pubkey (32) || dns_disabled_byte (1) || exit_mlkem768_pubkey (1184)`.
///
/// This is the anti-downgrade anchor: a client that requested the PQ hybrid
/// seal decides PQ-vs-classical from THIS signature over the ML-KEM key, never
/// from an unauthenticated wire bit, so a middlebox cannot strip the ML-KEM
/// key without invalidating the signature. Distinct context string from `/v1`
/// and `/v2` so no cross-version signature is ever accepted. Frozen for `/v2`.
pub const WARREN_PKI_OPERATIONAL_EXIT_PQ_V1: &[u8] =
    b"warren/multihop/v2/operational-signs-exit-pq";

/// Ed25519 signature context for the root key signing the operational key.
///
/// The signed message is `WARREN_PKI_ROOT_OPERATIONAL_V1 || operational_pubkey`.
/// Frozen for `/v1`. Defined here to anchor the contract.
pub const WARREN_PKI_ROOT_OPERATIONAL_V1: &[u8] = b"warren/multihop/v1/root-signs-operational";

/// Ed25519 signature context for the operational key signing an exit's
/// long-lived X25519 multihop pubkey.
///
/// The signed message is
/// `WARREN_PKI_OPERATIONAL_EXIT_V1 || exit_id_bytes || exit_x25519_pubkey`.
/// Frozen for `/v1`.
pub const WARREN_PKI_OPERATIONAL_EXIT_V1: &[u8] = b"warren/multihop/v1/operational-signs-exit";

/// Ed25519 signature context for the operational key signing an exit's
/// long-lived X25519 multihop pubkey AND its `dns_disabled` attestation.
///
/// The signed message is
/// `WARREN_PKI_OPERATIONAL_EXIT_V2 || exit_id_bytes || exit_x25519_pubkey || dns_disabled_byte`
/// where `dns_disabled_byte` is `0x01` when the exit refuses to act as
/// the captive DNS resolver for client traffic and `0x00` otherwise.
///
/// Multi-hop clients that boot without an explicit `push_dns` MUST
/// verify the descriptor under `/v2` and refuse the dial if
/// `dns_disabled == 1`, since downgrading to the legacy `/v1` verify
/// path would let an operational-key holder strip the attestation and
/// expose plaintext DNS to the relay.
///
/// Frozen for `/v2`.
pub const WARREN_PKI_OPERATIONAL_EXIT_V2: &[u8] = b"warren/multihop/v2/operational-signs-exit";

/// Ed25519 signature context for the operational key signing a relay's
/// Ed25519 identity pubkey.
///
/// The signed message is
/// `WARREN_PKI_OPERATIONAL_RELAY_V1 || relay_id_bytes || relay_ed25519_pubkey`.
/// Frozen for `/v1`.
pub const WARREN_PKI_OPERATIONAL_RELAY_V1: &[u8] = b"warren/multihop/v1/operational-signs-relay";

/// Ed25519 signature context for the operational key attesting a dual-role
/// node's geo + identity metadata in the dynamic multi-hop directory.
///
/// The signed message is
/// `WARREN_PKI_OPERATIONAL_NODE_V1 || node_id(16) || exit_ed25519_pubkey(32) || asn_u32_be(4) || country_bytes`.
///
/// This binds, under the offline operational key, the fields the
/// directory would otherwise carry only under the (online) server
/// envelope: the node's country + AS (so a compromised directory cannot
/// fake geographic/AS circuit diversity) and the exit hop's Ed25519 RPK
/// identity (so it cannot redirect the exit-leg TLS pin). Frozen for `/v1`.
pub const WARREN_PKI_OPERATIONAL_NODE_V1: &[u8] = b"warren/multihop/v1/operational-signs-node";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warren_hpke_info_v1_is_frozen() {
        assert_eq!(WARREN_HPKE_INFO_V1, b"warren/multihop/v1/hpke-info");
    }

    #[test]
    fn warren_hpke_aad_v1_is_frozen() {
        assert_eq!(WARREN_HPKE_AAD_V1, b"warren/multihop/v1/aad");
    }

    #[test]
    fn warren_hpke_version_v1_is_one() {
        assert_eq!(WARREN_HPKE_VERSION_V1, 0x01u8);
    }

    /// Defensive invariant: both `WARREN_HPKE_VERSION` (re-exported from
    /// `wire_format`) and `WARREN_HPKE_VERSION_V1` (re-exported from this
    /// crate root) must resolve to the same byte. They are currently
    /// declared with `pub const WARREN_HPKE_VERSION: u8 =
    /// WARREN_HPKE_VERSION_V1;` so compile-time equality is structural,
    /// but a future refactor could accidentally break the delegation
    /// (e.g., a developer typing `= 0x02` thinking they bump a different
    /// version layer). A wire-format byte mismatch between the two
    /// re-exports would silently corrupt every multihop frame from
    /// either side that imports the wrong path.
    #[test]
    fn warren_hpke_version_re_exports_agree() {
        assert_eq!(
            WARREN_HPKE_VERSION, WARREN_HPKE_VERSION_V1,
            "WARREN_HPKE_VERSION (via wire_format) and WARREN_HPKE_VERSION_V1 \
             (via crate root) MUST resolve to the same byte - they are the \
             same wire-format constant and any divergence would corrupt every \
             multihop frame."
        );
    }

    #[test]
    fn pki_context_constants_are_frozen() {
        assert_eq!(
            WARREN_PKI_ROOT_OPERATIONAL_V1,
            b"warren/multihop/v1/root-signs-operational"
        );
        assert_eq!(
            WARREN_PKI_OPERATIONAL_EXIT_V1,
            b"warren/multihop/v1/operational-signs-exit"
        );
        assert_eq!(
            WARREN_PKI_OPERATIONAL_EXIT_V2,
            b"warren/multihop/v2/operational-signs-exit"
        );
        assert_eq!(
            WARREN_PKI_OPERATIONAL_RELAY_V1,
            b"warren/multihop/v1/operational-signs-relay"
        );
        assert_eq!(
            WARREN_PKI_OPERATIONAL_NODE_V1,
            b"warren/multihop/v1/operational-signs-node"
        );
    }

    /// `/v1` and `/v2` exit-descriptor signing contexts must NOT collide
    /// with one another. A collision would let an operational signer
    /// produce a single Ed25519 signature accepted by both
    /// [`verify_exit_descriptor`] and [`verify_exit_descriptor_v2`],
    /// defeating the descriptor downgrade protection.
    #[test]
    fn operational_exit_v1_and_v2_contexts_are_distinct() {
        assert_ne!(
            WARREN_PKI_OPERATIONAL_EXIT_V1, WARREN_PKI_OPERATIONAL_EXIT_V2,
            "v1 and v2 exit signing contexts must differ to prevent cross-version signature acceptance"
        );
    }
}
