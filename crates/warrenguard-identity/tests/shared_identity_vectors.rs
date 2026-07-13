//! Replays the shared identity golden vectors in `vectors/identity.json` (the
//! cross-repo warren-vectors anchor, a git submodule at the repo root). These
//! pin the byte-exact HKDF-SHA256 -> Ed25519 derivation and, with the `bip39`
//! feature, the mnemonic -> seed path that every consumer (SDKs, backend)
//! must reproduce; a failure means the derivation drifted from the frozen
//! cross-language contract.
//!
//! Complements (does not replace) the inline vector constants in `src/lib.rs`
//! (`vector_tests`, a fast in-crate regression signal with no submodule
//! dependency) by replaying the shared file directly, so a vector added or
//! changed there is never covered by neither the inline copy nor this file.

use serde::Deserialize;
use warrenguard_identity::derive_node_key;
#[cfg(feature = "bip39")]
use warrenguard_identity::seed_from_mnemonic;

#[derive(Deserialize)]
struct Vectors {
    derivation: DerivationSection,
    #[cfg(feature = "bip39")]
    bip39: Bip39Section,
}

#[derive(Deserialize)]
struct DerivationSection {
    vectors: Vec<DerivationVec>,
}

#[derive(Deserialize)]
struct DerivationVec {
    seed_hex: String,
    pubkey_hex: String,
}

#[cfg(feature = "bip39")]
#[derive(Deserialize)]
struct Bip39Section {
    vectors: Vec<Bip39Vec>,
}

#[cfg(feature = "bip39")]
#[derive(Deserialize)]
struct Bip39Vec {
    mnemonic: String,
    seed_hex: String,
    pubkey_hex: String,
}

fn load() -> Vectors {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/identity.json");
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("read vectors/identity.json: {e}; run `git submodule update --init`")
    });
    serde_json::from_str(&raw).expect("parse vectors/identity.json")
}

#[test]
fn derivation_vectors_match() {
    let v = load();
    // Regression guard: the file has grown a third (seed 0x01...) vector
    // that no inline constant in `src/lib.rs` replays. Iterating the whole
    // section (rather than pinning an index) means any future vector is
    // covered automatically too.
    assert!(
        v.derivation.vectors.len() >= 3,
        "expected at least 3 derivation vectors in vectors/identity.json"
    );
    for vec in &v.derivation.vectors {
        let seed: [u8; 32] = hex::decode(&vec.seed_hex)
            .expect("seed hex")
            .try_into()
            .expect("seed is 32 bytes");
        let key = derive_node_key(&seed);
        let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
        assert_eq!(
            pubkey_hex, vec.pubkey_hex,
            "derivation drifted for seed {}",
            vec.seed_hex
        );
    }
}

#[cfg(feature = "bip39")]
#[test]
fn bip39_vectors_match() {
    let v = load();
    for vec in &v.bip39.vectors {
        let seed = seed_from_mnemonic(&vec.mnemonic).expect("valid mnemonic");
        assert_eq!(
            hex::encode(*seed),
            vec.seed_hex,
            "BIP39 seed drifted for mnemonic {:?}",
            vec.mnemonic
        );
        let key = derive_node_key(&seed);
        let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
        assert_eq!(
            pubkey_hex, vec.pubkey_hex,
            "derived pubkey drifted for mnemonic {:?}",
            vec.mnemonic
        );
    }
}
