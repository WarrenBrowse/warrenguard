//! X-Wing Known-Answer Tests (KATs).
//!
//! Two independent anchors prove the hybrid KEM is the EXACT X-Wing
//! construction, not a home-grown or XOR combiner:
//!
//! 1. `combiner_matches_independent_sha3_256`: the combiner byte layout is
//!    cross-checked against values computed by Python `hashlib.sha3_256` over
//!    `ss_M || ss_X || ct_X || pk_X || label`.
//! 2. `official_xwing_draft_vectors`: the full single-seed keygen -> encaps ->
//!    decaps flow is replayed through Warren's PRODUCTION combiner and KEM code
//!    (`xwing_reference_flow`) and asserted byte-for-byte against the official
//!    draft-connolly-cfrg-xwing-kem test vectors (`vectors/xwing_kem.json`, the
//!    shared `warren-vectors` submodule at the repo root, from
//!    dconnolly/draft-connolly-cfrg-xwing-kem `spec/test-vectors.json`). If
//!    the ML-KEM message / X25519 ephemeral halves of the encaps seed were
//!    swapped, the label placed first, or the ciphertext halves reordered, the
//!    public key / ciphertext / shared secret would not match.
//!
//! Only compiled with `--features pq-hpke`.
#![cfg(feature = "pq-hpke")]

use serde::Deserialize;
use warrenguard_multihop::test_support::xwing_reference_flow;
use warrenguard_multihop::xwing_combiner;

#[derive(Deserialize)]
struct XWingFile {
    vectors: Vec<XWingVector>,
}

#[derive(Deserialize)]
struct XWingVector {
    seed_hex: String,
    eseed_hex: String,
    ss_hex: String,
    sk_hex: String,
    pk_hex: String,
    ct_hex: String,
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

fn hex64(s: &str) -> [u8; 64] {
    hex::decode(s).expect("hex").try_into().expect("64 bytes")
}

fn read(rel: &str) -> String {
    let path = format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {rel}: {e}; run `git submodule update --init`"))
}

#[test]
fn official_xwing_draft_vectors() {
    let file: XWingFile =
        serde_json::from_str(&read("vectors/xwing_kem.json")).expect("parse xwing vectors");
    let vectors = file.vectors;
    assert_eq!(vectors.len(), 3, "expected the 3 official draft vectors");

    for (i, v) in vectors.iter().enumerate() {
        let seed = hex32(&v.seed_hex);
        let eseed = hex64(&v.eseed_hex);
        let expected_pk = hex::decode(&v.pk_hex).expect("hex");
        let expected_ct = hex::decode(&v.ct_hex).expect("hex");
        let expected_ss = hex32(&v.ss_hex);

        // X-Wing's secret key IS the 32-byte seed.
        assert_eq!(hex32(&v.sk_hex), seed, "vector {i}: sk must equal the seed");

        let out = xwing_reference_flow(&seed, &eseed).expect("reference flow");

        assert_eq!(
            out.public_key, expected_pk,
            "vector {i}: derived X-Wing public key must match the official vector"
        );
        assert_eq!(
            out.ciphertext, expected_ct,
            "vector {i}: encapsulated ciphertext must match the official vector"
        );
        assert_eq!(
            out.shared_secret_encaps, expected_ss,
            "vector {i}: encapsulation shared secret must match the official vector"
        );
        assert_eq!(
            out.shared_secret_decaps, expected_ss,
            "vector {i}: decapsulation must recover the official shared secret"
        );
    }
}

/// Independent SHA3-256 cross-check of the combiner byte layout (values from
/// Python `hashlib.sha3_256`). Two structured inputs, distinct per component.
#[test]
fn combiner_matches_independent_sha3_256() {
    // ss_m = 0x01*32, ss_x = 0x02*32, ct_x = 0x03*32, pk_x = 0x04*32.
    let a = xwing_combiner(&[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32]);
    assert_eq!(
        a.as_bytes(),
        &hex32("5c6bfaf8c3ec48ab3cee7c12129b39913b8a7fa1234115da7e1c55608ad19fb6")
    );

    // ss_m = 0..32, ss_x = 32..64, ct_x = 64..96, pk_x = 96..128.
    let seq = |start: u8| -> [u8; 32] {
        let mut o = [0u8; 32];
        for (i, b) in o.iter_mut().enumerate() {
            *b = start + i as u8;
        }
        o
    };
    let b = xwing_combiner(&seq(0), &seq(32), &seq(64), &seq(96));
    assert_eq!(
        b.as_bytes(),
        &hex32("0acca09f2fb739bc89668dbcd01ae5aebf9b72c6fe013297e3baa96854468491")
    );
}
