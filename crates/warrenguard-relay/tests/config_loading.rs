//! End-to-end tests for [`RelayConfig::load`]: TOML round-trip via
//! `tempfile`, signature verification, duplicate detection.
//!
//! These complement the unit tests in `src/config.rs` and `src/pki.rs`
//! by exercising the actual disk path the binary uses at startup.

use std::io::Write as _;

use ed25519_dalek::{Signer, SigningKey};
use tempfile::NamedTempFile;
use warrenguard_multihop::ExitId;
use warrenguard_relay::{
    ConfigError, ExitDescriptorSigned, RelayConfig, exit_descriptor_signing_payload,
};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sign_descriptor(
    op: &SigningKey,
    exit_id: ExitId,
    x25519: [u8; 32],
    ed25519_pubkey: [u8; 32],
    endpoint: &str,
) -> ExitDescriptorSigned {
    let payload = exit_descriptor_signing_payload(exit_id, &x25519);
    let sig = op.sign(&payload);
    ExitDescriptorSigned {
        exit_id,
        exit_ed25519_pubkey: ed25519_pubkey,
        exit_x25519_multihop_pubkey: x25519,
        endpoint: Some(endpoint.parse().expect("static addr parses")),
        cover_domain: None,
        signature: sig.to_bytes(),
        dns_disabled: false,
        exit_mlkem768_pubkey: None,
    }
}

fn write_temp_toml(toml_text: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(toml_text.as_bytes()).expect("write toml");
    f.flush().expect("flush");
    f
}

#[test]
fn loads_valid_signed_pool_from_toml_disk_round_trip() {
    let op = det_signing_key(0x42);
    let descriptor = sign_descriptor(
        &op,
        ExitId::from_bytes([0xAA; 16]),
        [0x11; 32],
        [0xEE; 32],
        "10.0.0.1:443",
    );
    let cfg = RelayConfig {
        bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
        signing_key_path: "/etc/warren-relay/identity.key".into(),
        operational_pubkey: op.verifying_key(),
        exits: vec![descriptor.clone()],
    };
    // Serialize through TOML to ensure the hex serde helpers round-trip.
    let toml_text = toml::to_string(&cfg).expect("serialize");
    let file = write_temp_toml(&toml_text);
    let loaded = RelayConfig::load(file.path()).expect("load valid signed pool");
    assert_eq!(loaded.exits.len(), 1);
    assert_eq!(loaded.exits[0].exit_id, descriptor.exit_id);
    assert_eq!(
        loaded.exits[0].exit_x25519_multihop_pubkey,
        descriptor.exit_x25519_multihop_pubkey
    );
    assert_eq!(loaded.exits[0].signature, descriptor.signature);
}

#[test]
fn rejects_pool_entry_with_bad_signature() {
    let op = det_signing_key(0x42);
    let mut descriptor = sign_descriptor(
        &op,
        ExitId::from_bytes([0xAA; 16]),
        [0x11; 32],
        [0xEE; 32],
        "10.0.0.1:443",
    );
    // Flip one byte: the signature is still 64 bytes but no longer
    // authenticates the payload.
    descriptor.signature[0] ^= 0x01;
    let cfg = RelayConfig {
        bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
        signing_key_path: "/etc/warren-relay/identity.key".into(),
        operational_pubkey: op.verifying_key(),
        exits: vec![descriptor],
    };
    let toml_text = toml::to_string(&cfg).expect("serialize");
    let file = write_temp_toml(&toml_text);
    let err = RelayConfig::load(file.path()).expect_err("must reject tampered signature");
    assert!(
        matches!(err, ConfigError::Pki { index: 0, .. }),
        "expected Pki at index 0, got {err:?}"
    );
}

#[test]
fn rejects_pool_entry_signed_by_a_different_operational_key() {
    let trusted = det_signing_key(0x42);
    let untrusted = det_signing_key(0x99);
    // Sign with `untrusted` but advertise `trusted.verifying_key()` as
    // the trust anchor. A naive loader would accept this; the verifier
    // must catch the mismatch.
    let descriptor = sign_descriptor(
        &untrusted,
        ExitId::from_bytes([0xAA; 16]),
        [0x11; 32],
        [0xEE; 32],
        "10.0.0.1:443",
    );
    let cfg = RelayConfig {
        bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
        signing_key_path: "/etc/warren-relay/identity.key".into(),
        operational_pubkey: trusted.verifying_key(),
        exits: vec![descriptor],
    };
    let toml_text = toml::to_string(&cfg).expect("serialize");
    let file = write_temp_toml(&toml_text);
    let err = RelayConfig::load(file.path())
        .expect_err("descriptor signed by a different op key must reject");
    assert!(matches!(err, ConfigError::Pki { index: 0, .. }));
}

#[test]
fn rejects_duplicate_exit_id_in_pool() {
    let op = det_signing_key(0x42);
    let dup = ExitId::from_bytes([0xAA; 16]);
    let cfg = RelayConfig {
        bind_addr: "0.0.0.0:443".parse().expect("static addr parses"),
        signing_key_path: "/etc/warren-relay/identity.key".into(),
        operational_pubkey: op.verifying_key(),
        exits: vec![
            sign_descriptor(&op, dup, [0x11; 32], [0xEE; 32], "10.0.0.1:443"),
            sign_descriptor(&op, dup, [0x22; 32], [0xEE; 32], "10.0.0.2:443"),
        ],
    };
    let toml_text = toml::to_string(&cfg).expect("serialize");
    let file = write_temp_toml(&toml_text);
    let err = RelayConfig::load(file.path()).expect_err("duplicate exit_id must reject");
    assert!(matches!(err, ConfigError::DuplicateExitId));
}

#[test]
fn rejects_unparseable_operational_pubkey_in_toml() {
    let toml_text = r#"
bind_addr = "0.0.0.0:443"
signing_key_path = "/etc/warren-relay/identity.key"
operational_pubkey = "this-is-not-hex"
exits = []
"#;
    let file = write_temp_toml(toml_text);
    let err = RelayConfig::load(file.path()).expect_err("garbage pubkey must reject");
    assert!(matches!(err, ConfigError::Toml(_)));
}
