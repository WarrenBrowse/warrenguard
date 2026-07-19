//! Channel binding and the in-band ENTRY-RELAY identity proof.
//!
//! The QUIC TLS exporter (RFC 5705) yields a 32-byte value both peers, and only
//! both peers, can derive: [`channel_binding`]. It anchors the in-band identity
//! proof a cover-domain entry relay presents. When a relay serves an ordinary
//! X.509 cover-domain certificate (so the client->relay handshake looks like a
//! real website) its Warren identity is no longer pinned via an RFC 7250 raw
//! public key in the SNI; [`sign_relay_auth`] over the channel binding replaces
//! that pin, and [`verify_relay_auth`] confirms the client reached the
//! directory-vouched entry relay rather than a man-in-the-middle holding only a
//! valid cover-domain cert. Client possession of its own identity is proven
//! separately by the multi-hop PoP (`warrenguard-multihop`), which binds to the
//! HPKE encapsulated key and the exit id under its own context.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{WarrenPubkey, WarrenTlsError};

/// Domain-separation label for the QUIC TLS exporter used as the channel
/// binding. Versioned: any change to the binding construction MUST mint a new
/// label, never mutate this one, or two peers would silently compute different
/// bindings. The value is frozen wire: both peers must derive it byte-for-byte.
pub const CLIENT_AUTH_EXPORTER_LABEL: &[u8] = b"warrenguard in-band client auth v1";

/// Length of the channel-binding value exported from the QUIC TLS session.
pub const CHANNEL_BINDING_LEN: usize = 32;

/// Derives the 32-byte channel binding from a live QUIC connection by
/// exporting keying material under [`CLIENT_AUTH_EXPORTER_LABEL`] with an
/// empty context. Both peers derive the identical value; an on-path
/// observer cannot, since it never learns the TLS session secrets.
///
/// # Errors
/// [`WarrenTlsError::ChannelBindingUnavailable`] if the QUIC stack refuses
/// to export keying material (typically the handshake is not yet complete).
pub fn channel_binding(
    conn: &quinn::Connection,
) -> Result<[u8; CHANNEL_BINDING_LEN], WarrenTlsError> {
    let mut out = [0u8; CHANNEL_BINDING_LEN];
    conn.export_keying_material(&mut out, CLIENT_AUTH_EXPORTER_LABEL, b"")
        .map_err(|_| WarrenTlsError::ChannelBindingUnavailable)?;
    Ok(out)
}

/// Domain-separation context for the in-band ENTRY-RELAY identity proof, so a
/// relay signature can never be confused with any other Warren signature over
/// the same channel binding. Versioned with the layout: mint a new context to
/// change it, never mutate this one.
pub const RELAY_AUTH_CONTEXT_V1: &[u8] = b"warrenguard/inband-relay-auth/v1";

/// Builds the byte string the in-band RELAY auth signature covers:
/// [`RELAY_AUTH_CONTEXT_V1`] || `cb` (32 bytes). Fixed-length, so the encoding
/// is unambiguous without length prefixes. Relay and client MUST build it
/// identically.
#[must_use]
pub fn relay_auth_signing_message(cb: &[u8; CHANNEL_BINDING_LEN]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(RELAY_AUTH_CONTEXT_V1.len() + CHANNEL_BINDING_LEN);
    msg.extend_from_slice(RELAY_AUTH_CONTEXT_V1);
    msg.extend_from_slice(cb);
    msg
}

/// Signs the in-band ENTRY-RELAY identity proof with the relay's Ed25519
/// identity key. When the relay presents an ordinary X.509
/// cover-domain certificate (so the client->relay handshake looks like a real
/// website) the relay's Warren identity is no longer pinned via the RFC 7250
/// raw public key in the SNI; this signature replaces that pin. The client
/// confirms it reached the directory-vouched entry relay, not a man-in-the-
/// middle holding only a valid cover-domain cert (e.g. the shared wildcard
/// key, which any pool member holds). The 64-byte result rides a dedicated
/// wire message from relay to client.
#[must_use]
pub fn sign_relay_auth(secret: &SigningKey, cb: &[u8; CHANNEL_BINDING_LEN]) -> [u8; 64] {
    secret.sign(&relay_auth_signing_message(cb)).to_bytes()
}

/// Verifies an in-band RELAY proof: returns `true` iff `sig` is a valid
/// Ed25519 signature by `relay_pubkey` over the message binding `cb`. The
/// caller MUST pass the relay pubkey it expected from the signed multi-hop
/// directory, so a man-in-the-middle that terminated the client->relay TLS
/// handshake (controlling `cb`) but does not hold the relay's identity key
/// cannot forge the proof.
///
/// Fails closed (returns `false`) on a malformed pubkey; never panics. Uses
/// `verify_strict` to reject small-order keys and non-canonical signatures,
/// matching the RPK verifier.
#[must_use]
pub fn verify_relay_auth(
    relay_pubkey: &WarrenPubkey,
    cb: &[u8; CHANNEL_BINDING_LEN],
    sig: &[u8; 64],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(relay_pubkey.as_bytes()) else {
        return false;
    };
    verifying_key
        .verify_strict(&relay_auth_signing_message(cb), &Signature::from_bytes(sig))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn pubkey_of(key: &SigningKey) -> WarrenPubkey {
        WarrenPubkey::from_bytes(key.verifying_key().to_bytes())
    }

    const CB: [u8; CHANNEL_BINDING_LEN] = [0x42; CHANNEL_BINDING_LEN];

    #[test]
    fn channel_binding_exporter_label_is_frozen() {
        // Both peers derive the channel binding under this exact label; any
        // drift makes their bindings diverge and every in-band proof fail.
        assert_eq!(
            CLIENT_AUTH_EXPORTER_LABEL,
            b"warrenguard in-band client auth v1"
        );
    }

    #[test]
    fn valid_relay_proof_verifies_against_the_relay_pubkey() {
        let relay = key_from(0x51);
        let sig = sign_relay_auth(&relay, &CB);
        assert!(
            verify_relay_auth(&pubkey_of(&relay), &CB, &sig),
            "a relay proof signed by the relay key over the exact cb must verify"
        );
    }

    #[test]
    fn relay_proof_signed_by_another_key_is_rejected() {
        // The attack this stops: an MITM that completed the client->relay TLS
        // handshake (so it controls the channel binding, e.g. with the shared
        // wildcard cover-domain key) but does NOT hold the directory-vouched
        // relay Ed25519 identity cannot forge the proof.
        let real_relay = key_from(0x51);
        let mitm = key_from(0x52);
        let sig = sign_relay_auth(&mitm, &CB);
        assert!(
            !verify_relay_auth(&pubkey_of(&real_relay), &CB, &sig),
            "a proof not signed by the expected relay identity must NOT verify"
        );
    }

    #[test]
    fn relay_proof_is_bound_to_the_exact_channel_binding() {
        let relay = key_from(0x51);
        let sig = sign_relay_auth(&relay, &CB);
        let other_cb = [0x43u8; CHANNEL_BINDING_LEN];
        assert!(
            !verify_relay_auth(&pubkey_of(&relay), &other_cb, &sig),
            "a relay proof for one connection's exporter must not verify for another"
        );
    }

    #[test]
    fn tampered_relay_signature_and_malformed_pubkey_are_rejected() {
        let relay = key_from(0x51);
        let mut sig = sign_relay_auth(&relay, &CB);
        sig[0] ^= 0x01;
        assert!(
            !verify_relay_auth(&pubkey_of(&relay), &CB, &sig),
            "a single flipped signature bit must fail verification"
        );
        let good = sign_relay_auth(&relay, &CB);
        let bogus = WarrenPubkey::from_bytes([0xFF; 32]);
        assert!(!verify_relay_auth(&bogus, &CB, &good));
    }

    #[test]
    fn relay_proof_signing_message_layout_is_frozen() {
        // Wire-crypto contract: relay-context || cb, raw bytes, no length
        // prefixes and no device_id. Drift here breaks every relay proof and
        // MUST mint a new context.
        let msg = relay_auth_signing_message(&CB);
        let mut expected = b"warrenguard/inband-relay-auth/v1".to_vec();
        expected.extend_from_slice(&CB);
        assert_eq!(
            msg, expected,
            "relay-auth signing-message layout drifted - mint a new context string"
        );
    }
}
