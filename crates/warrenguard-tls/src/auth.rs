//! In-band client authentication (protocol v5+).
//!
//! Since v5 the exit no longer requests a TLS client certificate. That
//! mutual-auth CertificateRequest was an active-probing tell: no public
//! HTTP/3 server demands a client certificate, so a censor that completes
//! a handshake to the exit could fingerprint it as "not a real website".
//!
//! Instead the client proves possession of its Ed25519 identity in-band
//! during the handshake. It signs a domain-separated message binding:
//!   - the 32-byte channel binding exported from the QUIC TLS key schedule
//!     (RFC 5705) under a Warren-specific label, AND
//!   - the session's 16-byte `device_id`.
//!
//! The channel binding makes the proof unforgeable and connection-bound:
//! both peers, and only both peers, can derive that value, so a captured
//! proof replayed onto another exit fails (the other exit derives a
//! different exporter). Folding the `device_id` in makes the proof
//! self-contained: the authenticated identity is bound to the `device_id`
//! the exit will key its session and device-cap on, without relying on the
//! transport for that field's integrity (defense in depth; on the
//! single-hop path QUIC's AEAD already protects it end-to-end). This
//! mirrors the multi-hop PoP (`warrenguard-multihop`), which binds to the
//! HPKE encapsulated key and the exit id under its own context.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use warrenguard_wire::DEVICE_ID_LEN;

use crate::{WarrenPubkey, WarrenTlsError};

/// Domain-separation label for the QUIC TLS exporter used as the client
/// auth channel binding. Versioned: any change to the binding
/// construction MUST mint a new label, never mutate this one, or a v5
/// client and a future exit would silently compute different bindings.
pub const CLIENT_AUTH_EXPORTER_LABEL: &[u8] = b"warrenguard in-band client auth v1";

/// Domain-separation context prefixed to the signed message, so a client
/// Ed25519 signature produced for in-band auth can never be confused with
/// a signature the same identity key produces in another Warren context
/// (e.g. the multi-hop PoP, which uses `warren/multihop/pop/v2`). Versioned
/// with the signed-message layout: mint a new context to change the layout,
/// never mutate this one.
pub const CLIENT_AUTH_CONTEXT_V1: &[u8] = b"warrenguard/inband-auth/v1";

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

/// Builds the exact byte string the in-band auth signature covers:
/// [`CLIENT_AUTH_CONTEXT_V1`] || `cb` (32 bytes) || `device_id` (16 bytes).
/// All parts are fixed-length, so the encoding is unambiguous without
/// length prefixes. This is the wire-crypto contract: client and exit MUST
/// build it identically or every proof fails.
#[must_use]
pub fn client_auth_signing_message(
    cb: &[u8; CHANNEL_BINDING_LEN],
    device_id: &[u8; DEVICE_ID_LEN],
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(CLIENT_AUTH_CONTEXT_V1.len() + CHANNEL_BINDING_LEN + DEVICE_ID_LEN);
    msg.extend_from_slice(CLIENT_AUTH_CONTEXT_V1);
    msg.extend_from_slice(cb);
    msg.extend_from_slice(device_id);
    msg
}

/// Signs the in-band client auth proof with the client's Ed25519 identity
/// key. The 64-byte result is the client's in-band auth signature.
#[must_use]
pub fn sign_client_auth(
    secret: &SigningKey,
    cb: &[u8; CHANNEL_BINDING_LEN],
    device_id: &[u8; DEVICE_ID_LEN],
) -> [u8; 64] {
    secret
        .sign(&client_auth_signing_message(cb, device_id))
        .to_bytes()
}

/// Verifies an in-band auth proof: returns `true` iff `sig` is a valid
/// Ed25519 signature by `pubkey` over the message binding `cb` and
/// `device_id`. Fails closed (returns `false`) on a malformed pubkey (not a
/// valid Ed25519 point); never panics.
///
/// Uses `verify_strict` to reject small-order public keys and non-canonical
/// signatures, matching the exit-identity verifier
/// ([`crate::verifier`] `verify_tls13_signature_with_raw_key`). This closes
/// the cofactor / signature-malleability surface uniformly across both
/// Ed25519 verification paths.
#[must_use]
pub fn verify_client_auth(
    pubkey: &WarrenPubkey,
    cb: &[u8; CHANNEL_BINDING_LEN],
    device_id: &[u8; DEVICE_ID_LEN],
    sig: &[u8; 64],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey.as_bytes()) else {
        return false;
    };
    verifying_key
        .verify_strict(
            &client_auth_signing_message(cb, device_id),
            &Signature::from_bytes(sig),
        )
        .is_ok()
}

/// Domain-separation context for the in-band EXIT (server) identity proof
/// (v6 X.509 exit mode). Distinct from [`CLIENT_AUTH_CONTEXT_V1`] so an exit
/// signature and a client signature over the same channel binding are never
/// interchangeable. Versioned with the layout: mint a new context to change
/// it, never mutate this one.
pub const SERVER_AUTH_CONTEXT_V1: &[u8] = b"warrenguard/inband-server-auth/v1";

/// Builds the byte string the in-band EXIT auth signature covers:
/// [`SERVER_AUTH_CONTEXT_V1`] || `cb` (32 bytes). Fixed-length, so the
/// encoding is unambiguous without length prefixes. No `device_id`: that is
/// a client-side concept. Exit and client MUST build it identically.
#[must_use]
pub fn server_auth_signing_message(cb: &[u8; CHANNEL_BINDING_LEN]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SERVER_AUTH_CONTEXT_V1.len() + CHANNEL_BINDING_LEN);
    msg.extend_from_slice(SERVER_AUTH_CONTEXT_V1);
    msg.extend_from_slice(cb);
    msg
}

/// Signs the in-band EXIT identity proof with the exit's Ed25519 identity
/// key (v6 X.509 exit mode). The 64-byte result lets a client confirm it
/// reached the expected Warren exit even when the exit presents an ordinary
/// X.509 certificate (so the TLS handshake looks like a real website),
/// instead of authenticating the exit via an RFC 7250 raw public key (the
/// browser-anomalous ClientHello tell).
#[must_use]
pub fn sign_server_auth(secret: &SigningKey, cb: &[u8; CHANNEL_BINDING_LEN]) -> [u8; 64] {
    secret.sign(&server_auth_signing_message(cb)).to_bytes()
}

/// Verifies an in-band EXIT proof: returns `true` iff `sig` is a valid
/// Ed25519 signature by `exit_pubkey` over the message binding `cb`. The
/// caller MUST pass the exit pubkey it expected from the signed roster, so a
/// man-in-the-middle that terminated the TLS handshake (controlling `cb`)
/// but does not hold the exit's identity key cannot forge the proof.
///
/// Fails closed (returns `false`) on a malformed pubkey; never panics. Uses
/// `verify_strict` to reject small-order keys and non-canonical signatures,
/// matching [`verify_client_auth`] and the RPK verifier.
#[must_use]
pub fn verify_server_auth(
    exit_pubkey: &WarrenPubkey,
    cb: &[u8; CHANNEL_BINDING_LEN],
    sig: &[u8; 64],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(exit_pubkey.as_bytes()) else {
        return false;
    };
    verifying_key
        .verify_strict(
            &server_auth_signing_message(cb),
            &Signature::from_bytes(sig),
        )
        .is_ok()
}

/// Domain-separation context for the in-band ENTRY-RELAY identity proof.
/// Distinct from [`CLIENT_AUTH_CONTEXT_V1`] and
/// [`SERVER_AUTH_CONTEXT_V1`] so a relay signature can never be confused with
/// a client or exit signature over the same channel binding. Versioned with
/// the layout: mint a new context to change it, never mutate this one.
pub const RELAY_AUTH_CONTEXT_V1: &[u8] = b"warrenguard/inband-relay-auth/v1";

/// Builds the byte string the in-band RELAY auth signature covers:
/// [`RELAY_AUTH_CONTEXT_V1`] || `cb` (32 bytes). Same shape as the exit proof
/// (fixed-length, no length prefixes, no `device_id`), only the context
/// differs. Relay and client MUST build it identically.
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
/// matching [`verify_server_auth`] and [`verify_client_auth`].
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
    const DEV: [u8; DEVICE_ID_LEN] = [0x7A; DEVICE_ID_LEN];

    #[test]
    fn valid_proof_verifies_against_the_signing_pubkey() {
        let key = key_from(0x11);
        let sig = sign_client_auth(&key, &CB, &DEV);
        assert!(
            verify_client_auth(&pubkey_of(&key), &CB, &DEV, &sig),
            "a proof signed by the key owner over the exact (cb, device_id) must verify"
        );
    }

    #[test]
    fn proof_signed_by_another_key_is_rejected() {
        // The attack this exists to stop: asserting someone else's
        // allowlisted pubkey in-band without holding its private key.
        let owner = key_from(0x11);
        let attacker = key_from(0x22);
        let sig = sign_client_auth(&attacker, &CB, &DEV);
        assert!(
            !verify_client_auth(&pubkey_of(&owner), &CB, &DEV, &sig),
            "a proof signed by a different key must NOT verify against the asserted pubkey"
        );
    }

    #[test]
    fn proof_is_bound_to_the_exact_channel_binding() {
        // Cross-connection replay: a proof captured on one connection
        // (one exporter) must be invalid for any other connection.
        let key = key_from(0x11);
        let sig = sign_client_auth(&key, &CB, &DEV);
        let other_cb = [0x43u8; CHANNEL_BINDING_LEN];
        assert!(
            !verify_client_auth(&pubkey_of(&key), &other_cb, &DEV, &sig),
            "a proof for one connection's exporter must not verify for another"
        );
    }

    #[test]
    fn proof_is_bound_to_the_device_id() {
        // Defense in depth: a proof for one device_id must not verify for
        // another, so the authenticated identity cannot be re-bound to a
        // different device (and its device-cap slot).
        let key = key_from(0x11);
        let sig = sign_client_auth(&key, &CB, &DEV);
        let other_dev = [0x7Bu8; DEVICE_ID_LEN];
        assert!(
            !verify_client_auth(&pubkey_of(&key), &CB, &other_dev, &sig),
            "a proof for one device_id must not verify for another"
        );
    }

    #[test]
    fn tampered_signature_and_malformed_pubkey_are_rejected() {
        let key = key_from(0x11);
        let mut sig = sign_client_auth(&key, &CB, &DEV);
        sig[0] ^= 0x01;
        assert!(
            !verify_client_auth(&pubkey_of(&key), &CB, &DEV, &sig),
            "a single flipped signature bit must fail verification"
        );

        // A 32-byte blob that is not a valid Ed25519 point must fail closed
        // (no panic, no admit).
        let good_sig = sign_client_auth(&key, &CB, &DEV);
        let bogus_pubkey = WarrenPubkey::from_bytes([0xFF; 32]);
        assert!(!verify_client_auth(&bogus_pubkey, &CB, &DEV, &good_sig));
    }

    #[test]
    fn signing_message_layout_is_frozen() {
        // Wire-crypto contract: context || cb || device_id, raw bytes, no
        // length prefixes. A drift here breaks every client<->exit proof and
        // MUST mint a new context, never mutate the existing one.
        let msg = client_auth_signing_message(&CB, &DEV);
        let mut expected = b"warrenguard/inband-auth/v1".to_vec();
        expected.extend_from_slice(&CB);
        expected.extend_from_slice(&DEV);
        assert_eq!(
            msg, expected,
            "in-band auth signing-message layout drifted - mint a new context string"
        );
    }

    #[test]
    fn domain_separators_are_frozen() {
        // Client and exit must agree byte-for-byte or every proof fails.
        assert_eq!(
            CLIENT_AUTH_EXPORTER_LABEL,
            b"warrenguard in-band client auth v1"
        );
        assert_eq!(CLIENT_AUTH_CONTEXT_V1, b"warrenguard/inband-auth/v1");
    }

    // --- In-band EXIT (server) identity proof (v6 X.509 exit mode) ---

    #[test]
    fn valid_exit_proof_verifies_against_the_exit_pubkey() {
        let exit = key_from(0x31);
        let sig = sign_server_auth(&exit, &CB);
        assert!(
            verify_server_auth(&pubkey_of(&exit), &CB, &sig),
            "an exit proof signed by the exit key over the exact cb must verify"
        );
    }

    #[test]
    fn exit_proof_signed_by_another_key_is_rejected() {
        // The attack this stops: an MITM that completed the TLS handshake
        // (so it controls the channel binding) but does NOT hold the
        // expected exit's Ed25519 identity cannot forge the proof.
        let real_exit = key_from(0x31);
        let mitm = key_from(0x32);
        let sig = sign_server_auth(&mitm, &CB);
        assert!(
            !verify_server_auth(&pubkey_of(&real_exit), &CB, &sig),
            "a proof not signed by the expected exit identity must NOT verify"
        );
    }

    #[test]
    fn exit_proof_is_bound_to_the_exact_channel_binding() {
        let exit = key_from(0x31);
        let sig = sign_server_auth(&exit, &CB);
        let other_cb = [0x43u8; CHANNEL_BINDING_LEN];
        assert!(
            !verify_server_auth(&pubkey_of(&exit), &other_cb, &sig),
            "an exit proof for one connection's exporter must not verify for another"
        );
    }

    #[test]
    fn tampered_exit_signature_and_malformed_pubkey_are_rejected() {
        let exit = key_from(0x31);
        let mut sig = sign_server_auth(&exit, &CB);
        sig[0] ^= 0x01;
        assert!(
            !verify_server_auth(&pubkey_of(&exit), &CB, &sig),
            "a single flipped signature bit must fail verification"
        );
        let good = sign_server_auth(&exit, &CB);
        let bogus = WarrenPubkey::from_bytes([0xFF; 32]);
        assert!(!verify_server_auth(&bogus, &CB, &good));
    }

    #[test]
    fn exit_proof_signing_message_layout_is_frozen() {
        // Wire-crypto contract: server-context || cb, raw bytes, no length
        // prefixes and NO device_id (that is a client-side concept). Drift
        // here breaks every exit proof and MUST mint a new context.
        let msg = server_auth_signing_message(&CB);
        let mut expected = b"warrenguard/inband-server-auth/v1".to_vec();
        expected.extend_from_slice(&CB);
        assert_eq!(
            msg, expected,
            "exit-auth signing-message layout drifted - mint a new context string"
        );
    }

    #[test]
    fn exit_proof_context_differs_from_client_context() {
        // Domain separation: an exit signature and a client signature over
        // the SAME channel binding must never be interchangeable, or a
        // captured client proof could be replayed as an exit proof (or vice
        // versa). The distinct context prefixes guarantee it.
        assert_ne!(
            SERVER_AUTH_CONTEXT_V1, CLIENT_AUTH_CONTEXT_V1,
            "client and exit proofs MUST use distinct domain-separation contexts"
        );
        assert_eq!(SERVER_AUTH_CONTEXT_V1, b"warrenguard/inband-server-auth/v1");
    }

    // --- In-band ENTRY-RELAY identity proof ---

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

    #[test]
    fn relay_proof_context_is_distinct_from_client_and_exit() {
        // Three-way domain separation: a relay signature must never be
        // interchangeable with a client or exit signature over the same cb,
        // or a captured proof of one role could be replayed as another.
        assert_ne!(RELAY_AUTH_CONTEXT_V1, CLIENT_AUTH_CONTEXT_V1);
        assert_ne!(RELAY_AUTH_CONTEXT_V1, SERVER_AUTH_CONTEXT_V1);
        assert_eq!(RELAY_AUTH_CONTEXT_V1, b"warrenguard/inband-relay-auth/v1");
    }

    #[test]
    fn relay_and_exit_proofs_over_same_cb_do_not_cross_verify() {
        // Concrete cross-role replay guard: the SAME key signing over the SAME
        // cb produces a relay proof that must not verify as an exit proof, and
        // vice versa, because the domain contexts differ.
        let key = key_from(0x51);
        let relay_sig = sign_relay_auth(&key, &CB);
        let exit_sig = sign_server_auth(&key, &CB);
        assert!(
            !verify_server_auth(&pubkey_of(&key), &CB, &relay_sig),
            "a relay proof must not verify as an exit proof"
        );
        assert!(
            !verify_relay_auth(&pubkey_of(&key), &CB, &exit_sig),
            "an exit proof must not verify as a relay proof"
        );
    }
}
