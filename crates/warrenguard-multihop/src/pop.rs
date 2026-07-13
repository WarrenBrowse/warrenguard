//! Proof of possession (PoP) of the multi-hop account key.
//!
//! The exit's TLS peer on a multi-hop connection is the relay, not the
//! client, so the account pubkey asserted in the setup `IpRequest` is
//! otherwise self-declared: anyone who merely KNOWS an allowlisted
//! pubkey (they are not secret - allowlist snapshots, API headers)
//! could obtain egress. The PoP closes that hole: the client signs a
//! domain-separated message binding its account key to this session's
//! HPKE `encapsulated_key` and the destination `exit_id`, and the exit
//! verifies the signature against the asserted pubkey BEFORE consulting
//! the allowlist.
//!
//! Freshness model: the `encapsulated_key` is chosen by the client per
//! session, so a captured PoP is useless on any other session
//! (cross-session replay needs a new encapsulated key, which changes
//! the signed message). Intra-session replay of the whole setup frame
//! is rejected by the session-scoped anti-replay window on the exit.
//!
//! The signed message is deterministic raw-byte concatenation (no
//! serde): `context || exit_id (16 bytes) || encapsulated_key (32
//! bytes)`. All three parts are fixed-length, so the encoding is
//! unambiguous without length prefixes.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::control::PopSignature;
use crate::session::ExitId;
use crate::wire_format::EncapsulatedKeyBytes;

/// Domain-separation context for the multi-hop PoP signature. Versioned
/// with the control wire (`/v2`): a future change to the signed message
/// layout must mint a new context string, never mutate this one.
pub const POP_CONTEXT_V2: &[u8] = b"warren/multihop/pop/v2";

/// Build the exact byte string the PoP signature covers:
/// [`POP_CONTEXT_V2`] || `exit_id` (16 raw bytes) || `encapsulated_key`
/// (32 raw bytes).
#[must_use]
pub fn pop_signing_message(exit_id: &ExitId, encapsulated_key: &EncapsulatedKeyBytes) -> Vec<u8> {
    let mut msg = Vec::with_capacity(POP_CONTEXT_V2.len() + 16 + 32);
    msg.extend_from_slice(POP_CONTEXT_V2);
    msg.extend_from_slice(exit_id.as_bytes());
    msg.extend_from_slice(encapsulated_key);
    msg
}

/// Sign the proof of possession with the account signing key. The
/// result goes into the `IpRequest::pop_sig` field alongside the
/// matching `client_pubkey`.
#[must_use]
pub fn sign_pop(
    key: &SigningKey,
    exit_id: &ExitId,
    encapsulated_key: &EncapsulatedKeyBytes,
) -> PopSignature {
    PopSignature(
        key.sign(&pop_signing_message(exit_id, encapsulated_key))
            .to_bytes(),
    )
}

/// Verify a proof of possession against the asserted account pubkey.
/// Uses `verify_strict`, so it fails closed on a malformed or
/// small-order (weak) pubkey and on a non-canonical signature, matching
/// the strict Ed25519 posture of the in-band auth path. Returns `false`
/// unless the signature covers exactly this `(exit_id, encapsulated_key)`
/// pair.
#[must_use]
pub fn verify_pop(
    client_pubkey: &[u8; 32],
    exit_id: &ExitId,
    encapsulated_key: &EncapsulatedKeyBytes,
    sig: &PopSignature,
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(client_pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig.0);
    verifying_key
        .verify_strict(&pop_signing_message(exit_id, encapsulated_key), &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    const EXIT_ID: [u8; 16] = [0xAA; 16];
    const ENCAP: EncapsulatedKeyBytes = [0x5C; 32];

    #[test]
    fn valid_pop_verifies_against_the_signing_pubkey() {
        let key = det_key(0x11);
        let exit_id = ExitId::from_bytes(EXIT_ID);
        let sig = sign_pop(&key, &exit_id, &ENCAP);
        assert!(
            verify_pop(&key.verifying_key().to_bytes(), &exit_id, &ENCAP, &sig),
            "a signature by the key owner over the exact session binding must verify"
        );
    }

    #[test]
    fn pop_signed_by_another_key_is_rejected() {
        // The attack the PoP exists to stop: asserting someone else's
        // allowlisted pubkey without holding its private key.
        let owner = det_key(0x11);
        let attacker = det_key(0x22);
        let exit_id = ExitId::from_bytes(EXIT_ID);
        let sig = sign_pop(&attacker, &exit_id, &ENCAP);
        assert!(
            !verify_pop(&owner.verifying_key().to_bytes(), &exit_id, &ENCAP, &sig),
            "a signature by a different key must NOT verify against the asserted pubkey"
        );
    }

    #[test]
    fn pop_is_bound_to_the_exit_id_and_the_encapsulated_key() {
        // Cross-session / cross-exit replay: a PoP captured on one
        // session must be invalid for any other (exit_id, encap) pair.
        let key = det_key(0x11);
        let exit_id = ExitId::from_bytes(EXIT_ID);
        let pubkey = key.verifying_key().to_bytes();
        let sig = sign_pop(&key, &exit_id, &ENCAP);

        let other_exit = ExitId::from_bytes([0xBB; 16]);
        assert!(
            !verify_pop(&pubkey, &other_exit, &ENCAP, &sig),
            "a PoP for one exit must not verify for another"
        );
        let other_encap: EncapsulatedKeyBytes = [0x5D; 32];
        assert!(
            !verify_pop(&pubkey, &exit_id, &other_encap, &sig),
            "a PoP for one session's encapsulated key must not verify for another"
        );
    }

    #[test]
    fn tampered_signature_and_malformed_pubkey_are_rejected() {
        let key = det_key(0x11);
        let exit_id = ExitId::from_bytes(EXIT_ID);
        let pubkey = key.verifying_key().to_bytes();
        let mut sig = sign_pop(&key, &exit_id, &ENCAP);
        sig.0[0] ^= 0x01;
        assert!(
            !verify_pop(&pubkey, &exit_id, &ENCAP, &sig),
            "a single flipped signature bit must fail verification"
        );

        // A 32-byte blob that is not a valid Ed25519 point must fail
        // closed (no panic, no admit).
        let good_sig = sign_pop(&key, &exit_id, &ENCAP);
        let bogus_pubkey = [0xFF; 32];
        assert!(!verify_pop(&bogus_pubkey, &exit_id, &ENCAP, &good_sig));
    }

    #[test]
    fn pop_message_layout_is_frozen() {
        // The signed message is part of the wire contract: context ||
        // exit_id || encapsulated_key, raw bytes, no length prefixes.
        let exit_id = ExitId::from_bytes(EXIT_ID);
        let msg = pop_signing_message(&exit_id, &ENCAP);
        let mut expected = b"warren/multihop/pop/v2".to_vec();
        expected.extend_from_slice(&EXIT_ID);
        expected.extend_from_slice(&ENCAP);
        assert_eq!(
            msg, expected,
            "PoP signing message layout drifted - mint a new context string"
        );
    }

    #[test]
    fn pop_rejects_small_order_key_that_lenient_verify_would_admit() {
        // Pins the strict-verify posture. The Ed25519 identity point
        // (compressed 0x01,0x00..) is a small-order public key; with
        // R = identity and S = 0 the verification equation holds for ANY
        // message, so the lenient `verify()` admits the forgery.
        // `verify_pop` uses `verify_strict`, which rejects the weak key.
        // Reverting the call site to `.verify()` makes this test red.
        use ed25519_dalek::Verifier;

        let identity = {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        };
        let forged = {
            let mut s = [0u8; 64];
            s[0] = 1;
            PopSignature(s)
        };
        let exit_id = ExitId::from_bytes(EXIT_ID);
        let msg = pop_signing_message(&exit_id, &ENCAP);

        // This is a genuine strict-vs-lenient divergence, not merely an
        // invalid signature: the lenient path accepts it.
        let vk = VerifyingKey::from_bytes(&identity).expect("identity is a valid point encoding");
        let lenient = vk.verify(&msg, &Signature::from_bytes(&forged.0)).is_ok();
        assert!(
            lenient,
            "sanity: lenient verify must admit the small-order forgery"
        );

        // The strict path used in production rejects it.
        assert!(
            !verify_pop(&identity, &exit_id, &ENCAP, &forged),
            "a small-order (weak) account key must be rejected under strict verification"
        );
    }

    /// Replays the frozen cross-implementation golden vector in
    /// `vectors/pop.json` (the shared `warren-vectors` submodule at the repo
    /// root): a sibling SDK's Ed25519 stack signs the same
    /// `pop_signing_message` preimage from the same seed and must reproduce
    /// this exact signature. Pinned nowhere else in the workspace before this
    /// test existed.
    #[test]
    fn pop_signature_matches_frozen_cross_impl_vector() {
        #[derive(serde::Deserialize)]
        struct PopVectorFile {
            vectors: Vec<PopVector>,
        }
        #[derive(serde::Deserialize)]
        struct PopVector {
            exit_id_hex: String,
            encapsulated_key_hex: String,
            signing_key_seed_hex: String,
            signature_hex: String,
        }

        let path = format!("{}/../../vectors/pop.json", env!("CARGO_MANIFEST_DIR"));
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("read vectors/pop.json: {e}; run `git submodule update --init`")
        });
        let file: PopVectorFile = serde_json::from_str(&raw).expect("parse pop.json");
        let v = file.vectors.first().expect("pop.json carries a vector");

        let exit_id_bytes: [u8; 16] = hex::decode(&v.exit_id_hex)
            .expect("hex")
            .try_into()
            .expect("16 bytes");
        let encap: EncapsulatedKeyBytes = hex::decode(&v.encapsulated_key_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let seed: [u8; 32] = hex::decode(&v.signing_key_seed_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let expected_sig: [u8; 64] = hex::decode(&v.signature_hex)
            .expect("hex")
            .try_into()
            .expect("64 bytes");

        let exit_id = ExitId::from_bytes(exit_id_bytes);
        let key = SigningKey::from_bytes(&seed);
        let sig = sign_pop(&key, &exit_id, &encap);
        assert_eq!(
            sig.0, expected_sig,
            "PoP signature drifted from the frozen cross-impl vector in vectors/pop.json"
        );
    }
}
