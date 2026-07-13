//! Wire-format lock for the Warren exit descriptor JSON.
//!
//! An exit binary's `--info-out` and
//! provisioning scripts pipe a [`WarrenExitAddr`] serialized
//! as JSON between machines. Every consumer (a client's
//! `--info-in`, provisioning scripts, relay-selector json_io /
//! signed) must keep parsing the exact same shape, so this contract is
//! pinned here.
//!
//! The fixture below is a synthetic dual-stack descriptor with
//! documentation-range addresses and a test identity.
//! Any reformatting (field rename,
//! BTreeSet ordering change, tagged-vs-flat enum representation) trips
//! the tests in this file before it can reach a deployed binary.

use warrenguard_wire::WarrenExitAddr;

const FIXTURE: &str = include_str!("fixtures/exit_info_wire_v1.json");

/// Test 1 - deserialize.
///
/// The fixture is a synthetic dual-stack exit descriptor JSON. If this test
/// fails, the JSON shape of `WarrenExitAddr` has drifted and existing
/// consumers will break.
#[test]
fn deserializes_from_exit_descriptor_sample() {
    let _addr: WarrenExitAddr = serde_json::from_str(FIXTURE)
        .expect("WarrenExitAddr must accept the --info-out JSON shape");
}

/// Test 2 - Value-level roundtrip.
///
/// Stronger than a byte-for-byte string roundtrip: we re-emit
/// `WarrenExitAddr` and compare as a `serde_json::Value`. This
/// tolerates non-significant whitespace and trailing newline
/// differences while still rejecting any shape drift (field rename,
/// missing field, wrong enum tagging, dropped addr).
#[test]
fn warren_exit_addr_value_roundtrip_matches_fixture() {
    let fixture_value: serde_json::Value =
        serde_json::from_str(FIXTURE).expect("fixture parses as JSON");
    let parsed: WarrenExitAddr =
        serde_json::from_str(FIXTURE).expect("fixture parses as WarrenExitAddr");
    let emitted: serde_json::Value =
        serde_json::to_value(&parsed).expect("WarrenExitAddr serializes back");
    assert_eq!(
        emitted, fixture_value,
        "WarrenExitAddr JSON must be Value-level identical with the fixture"
    );
}

/// Test 3 - vector hex encoding.
///
/// Anchors the pubkey-field encoding: 64-character lower-case hex
/// inside the `"id"` field. The fixture pins a specific test identity
/// (`00010203..1e1f`); decoding it via `WarrenExitAddr` and
/// re-encoding the pubkey to hex must reproduce the literal string,
/// proving:
/// - the field is named `id`, not `pubkey` / `endpoint_id` / `node_id`
/// - the value is a hex string, not raw bytes or base32
/// - byte order is preserved
#[test]
fn pubkey_id_field_is_lowercase_hex_64_chars_byte_for_byte() {
    let v: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let id_str = v["id"]
        .as_str()
        .expect("fixture must carry an `id` string field");
    assert_eq!(
        id_str, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "fixture test identity is fixed; if this changes the fixture file must be regenerated"
    );
    assert_eq!(id_str.len(), 64, "exactly 64 hex chars");
    assert!(
        id_str
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "pubkey must be lower-case hex only"
    );

    let addr: WarrenExitAddr =
        serde_json::from_str(FIXTURE).expect("WarrenExitAddr parses fixture");
    assert_eq!(
        warrenguard_wire_pubkey_hex(&addr),
        id_str,
        "the pubkey carried by WarrenExitAddr must hex-encode back to the fixture's id verbatim"
    );
}

/// Tiny helper isolating the path that turns the struct's pubkey
/// field into a hex string. Keeps the test independent from whether
/// the field is named `pubkey`, `id`, or anything else; the impl will
/// satisfy this signature.
fn warrenguard_wire_pubkey_hex(addr: &WarrenExitAddr) -> String {
    addr.id.to_hex()
}
