//! Generic Ed25519 node-key derivation for the WarrenGuard tunnel.
//!
//! The load-bearing primitive is [`derive_node_key`]: a 32-byte seed ->
//! HKDF-SHA256 (`warren/identity/v1` context) -> Ed25519 signing key, the raw
//! public half of which is the node identity pinned by the TLS raw-public-key
//! handshake. This crate is Warren-agnostic: no SS58 (the `wb…` brand codec
//! lives in the private `warren-ss58`), no `X-Warren-*` request signing (that
//! lives in the private `warren-identity`).
//!
//! BIP39 (the 12-word mnemonic <-> seed path and the on-disk mnemonic helper)
//! is gated behind the default-on `bip39` feature. A deployer that supplies a
//! raw seed (KMS/HSM/random) can drop it with `default-features = false` and
//! keep only `derive_node_key`. Every buffer holding a secret is zeroized.

#[cfg(feature = "bip39")]
use std::path::Path;

#[cfg(feature = "bip39")]
use bip39::Mnemonic;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use warrenguard_config::{HKDF_INFO_NODEKEY, HKDF_SALT_IDENTITY_V1};
use zeroize::Zeroize;
#[cfg(feature = "bip39")]
use zeroize::Zeroizing;

/// Errors from parsing / deriving a BIP39 mnemonic.
#[cfg(feature = "bip39")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MnemonicError {
    /// Invalid BIP39 mnemonic (unexpected length, unknown word, bad
    /// checksum, etc.).
    #[error("invalid BIP39 mnemonic: {0}")]
    Invalid(#[from] bip39::Error),
}

/// Errors from loading / persisting a mnemonic on disk.
#[cfg(feature = "bip39")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MnemonicLoadError {
    /// I/O on the mnemonic file (read, write, set_permissions).
    #[error("mnemonic file I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The file exists but does not contain a valid BIP39 mnemonic.
    /// We refuse to overwrite: it could be another valid mnemonic in
    /// a different encoding / language / for another project.
    #[error("file does not contain a valid BIP39 mnemonic: {0}")]
    InvalidContent(#[from] MnemonicError),
}

/// Converts a BIP39 mnemonic phrase (12 or 24 English words) to a
/// 32-byte seed, *ready to be passed to* [`derive_node_key`].
///
/// A BIP39 seed is natively 64 bytes (PBKDF2-SHA512). Warren keeps
/// only the first 32 and feeds them to HKDF-SHA256 to derive the
/// Ed25519 `SigningKey`. This truncation is safe because HKDF re-mixes
/// the input with its salt + info, so we do not lose usable entropy
/// beyond 32 bytes in a 256-bit symmetric-key scheme.
///
/// **Domain separation**: the BIP39 passphrase is intentionally empty
/// for Warren derivation - the auth wallet is *non-custodial* and the
/// mnemonic alone must suffice to reproduce the identity (no second
/// factor). Any future second factor will come from the upper layer
/// (local keyring passphrase), not from BIP39.
///
/// # Errors
///
/// BIP39 parsing error (unknown word, invalid length, bad checksum).
///
/// The return is wrapped in [`Zeroizing`] to guarantee the 32 secret
/// bytes are wiped from stack/heap at drop, even on intermediate
/// panic.
#[cfg(feature = "bip39")]
pub fn seed_from_mnemonic(mnemonic: &str) -> Result<Zeroizing<[u8; 32]>, MnemonicError> {
    let parsed = Mnemonic::parse(mnemonic)?;
    let mut full_seed = parsed.to_seed_normalized("");
    let mut seed32 = Zeroizing::new([0u8; 32]);
    seed32.copy_from_slice(&full_seed[..32]);
    full_seed.zeroize();
    Ok(seed32)
}

/// Loads a BIP39 mnemonic from `path`, or - if the file does not yet
/// exist - generates a new 12-word one, writes it with mode `0o600` on
/// Unix, and returns it.
///
/// Guarantees:
/// - **Idempotence**: successive calls with the same `path` return the
///   same mnemonic (identity persistence relies on this).
/// - **File security**: on Unix the file is created with `0o600`
///   (user read/write only) - no leak to other users or to
///   world-readable system backups.
/// - **Anti-corruption**: if the file exists but does not parse as a
///   valid BIP39 mnemonic, we return an error rather than silently
///   overwriting (preserves user data).
///
/// # Errors
///
/// I/O (read/write/permissions) or non-BIP39 file content.
///
/// # Panics
///
/// Never panics in practice: `Mnemonic::generate(12)` only fails for a word
/// count outside `{12, 15, 18, 21, 24}` (per BIP39), and `12` is a hardcoded
/// literal here.
#[cfg(feature = "bip39")]
pub fn load_or_create_mnemonic(path: &Path) -> Result<Zeroizing<String>, MnemonicLoadError> {
    // We do not use `path.exists()` then `create_new` - that TOCTOU
    // pattern raced when multiple processes / threads saw
    // `exists() == false` simultaneously, all tried `create_new(true)`,
    // only one succeeded, and the others surfaced an opaque
    // `AlreadyExists`. The pattern below is atomic: read first (hot
    // path: existing file), only attempt creation if the read returned
    // `NotFound`. If creation fails with `AlreadyExists` (race lost
    // against a neighbor), fall back on reading the winning file.
    //
    // `raw` (the untrimmed file content) and `trimmed` (the mnemonic
    // proper) both hold secret material, so both are `Zeroizing`: the
    // trim allocates a fresh copy that plain `Zeroize` on `raw` alone
    // would not reach.
    let read_and_validate = |p: &Path| -> Result<Zeroizing<String>, MnemonicLoadError> {
        let raw = Zeroizing::new(std::fs::read_to_string(p)?);
        let trimmed = Zeroizing::new(raw.trim().to_owned());
        let _ = seed_from_mnemonic(&trimmed)?;
        Ok(trimmed)
    };

    match std::fs::read_to_string(path) {
        Ok(raw) => {
            let raw = Zeroizing::new(raw);
            let trimmed = Zeroizing::new(raw.trim().to_owned());
            let _ = seed_from_mnemonic(&trimmed)?;
            warn_if_insecure_permissions(path);
            return Ok(trimmed);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { /* proceed to create */ }
        Err(e) => return Err(e.into()),
    }

    // `Mnemonic` itself derives `ZeroizeOnDrop` (the `zeroize` bip39
    // feature), so `generated` is scrubbed when it goes out of scope;
    // `.to_string()` still allocates a fresh `String` that needs its
    // own `Zeroizing` wrapper.
    let generated = Mnemonic::generate(12)
        .expect("BIP39 12-word generation never fails for a valid word count");
    let mnemonic = Zeroizing::new(generated.to_string());
    match write_mnemonic_file(path, &mnemonic) {
        Ok(()) => Ok(mnemonic),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Race: another process / thread won the creation.
            // `write_mnemonic_file` is atomic (tmp + hard_link), so if
            // the path exists its content is already fully written and
            // synchronized. Read directly without retry.
            read_and_validate(path)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(all(feature = "bip39", unix))]
fn warn_if_insecure_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{mode:o}"),
                "mnemonic file has insecure permissions, expected 0600"
            );
        }
    }
}

#[cfg(all(feature = "bip39", not(unix)))]
fn warn_if_insecure_permissions(_path: &Path) {}

/// Writes `mnemonic` to `path` with mode `0o600` (Unix) / OS default
/// (Windows). **Atomic**: writes first to a temporary file in the same
/// folder (mode 0o600 + sync_all), then `hard_link`s atomically to the
/// final `path`. `hard_link` fails with `AlreadyExists` when the
/// destination already exists - same semantics as `create_new(true)`
/// but with the guarantee that the file content is already written and
/// synced to disk BEFORE the final `path` appears to a concurrent
/// reader.
///
/// Without this scheme, `create_new(true)` would create an empty file
/// first and then `write_all` would write to it. A concurrent reader
/// (other thread / process) could then see the file exist but empty
/// during the `[create_new, write_all+sync_all]` window, read an empty
/// string, and `seed_from_mnemonic` validation would fail with
/// `BadWordCount(0)` instead of returning the winning mnemonic.
#[cfg(feature = "bip39")]
fn write_mnemonic_file(path: &Path, mnemonic: &str) -> std::io::Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("warren-mnemonic");
    // Tmp name unique to the (process, thread, nanos) triplet: avoids
    // intra-process inter-thread and inter-process collisions.
    let pid = std::process::id();
    let tid = format!("{:?}", std::thread::current().id());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp_path = parent.join(format!(".{stem}.tmp.{pid}.{tid}.{nanos}"));

    let _ = std::fs::remove_file(&tmp_path); // best-effort cleanup of any residue

    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;

        f.write_all(mnemonic.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    } // f close

    // `hard_link` is atomic OS-side and fails with `AlreadyExists` if
    // the destination exists - exact `create_new` semantics. Unlike
    // `rename` which silently *replaces* the destination.
    match std::fs::hard_link(&tmp_path, path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&tmp_path);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Derives the Warren `SigningKey` from a 32-byte seed (the first 32
/// bytes of the 64-byte BIP39 seed).
///
/// **Domain separation**: the HKDF salt and info are frozen constants.
/// NEVER modify without bumping the version (`identity/v2`).
///
/// # Panics
///
/// Never panics in practice: `Hkdf::expand` can only fail past 32 ×
/// 255 requested bytes, and we only request 32.
#[must_use]
pub fn derive_node_key(seed: &[u8; 32]) -> SigningKey {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_IDENTITY_V1), seed);
    let mut secret = [0u8; 32];
    hk.expand(HKDF_INFO_NODEKEY, &mut secret)
        .expect("32 bytes is short enough for HKDF-SHA256");
    let key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    key
}

// Gated on `bip39`: these unit tests exercise the mnemonic <-> seed path and the
// on-disk mnemonic helper, which only exist with the feature. The raw-seed
// primitive `derive_node_key` is proven to build `--no-default-features` and is
// covered there by the conformance suite (engine_api_surface + the e2e).
#[cfg(all(test, feature = "bip39"))]
mod tests {
    use super::*;

    /// Vector test: same seed → same key. Extend with an official
    /// vector once the exact mnemonic format is frozen.
    #[test]
    fn derivation_is_deterministic() {
        let seed = [0xab; 32];
        let k1 = derive_node_key(&seed);
        let k2 = derive_node_key(&seed);
        assert_eq!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let s1 = [0xab; 32];
        let s2 = [0xcd; 32];
        let k1 = derive_node_key(&s1);
        let k2 = derive_node_key(&s2);
        assert_ne!(k1.to_bytes(), k2.to_bytes());
    }

    /// Official 24-word BIP39 mnemonic (all-zero entropy). Pulled from
    /// the Trezor / BIP39 reference test vectors.
    const TEST_MNEMONIC_24_ZERO: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn seed_from_mnemonic_is_deterministic() {
        // Same mnemonic → same seed on every call. The base invariant
        // of Warren identity persistence.
        let s1 = seed_from_mnemonic(TEST_MNEMONIC_24_ZERO).expect("valid mnemonic");
        let s2 = seed_from_mnemonic(TEST_MNEMONIC_24_ZERO).expect("valid mnemonic");
        assert_eq!(s1, s2);
    }

    #[test]
    fn seed_from_mnemonic_is_not_all_zero() {
        // A stub returning `[0u8; 32]` would pass the deterministic
        // test. Verify derivation *actually* runs PBKDF2 BIP39 →
        // non-trivial seed.
        let seed = seed_from_mnemonic(TEST_MNEMONIC_24_ZERO).expect("valid mnemonic");
        assert_ne!(*seed, [0u8; 32], "seed must not be all-zero (stub leak?)");
    }

    #[test]
    fn different_mnemonics_produce_different_seeds() {
        let m1 = TEST_MNEMONIC_24_ZERO;
        let m2 = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
        let s1 = seed_from_mnemonic(m1).expect("valid m1");
        let s2 = seed_from_mnemonic(m2).expect("valid m2");
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn seed_from_mnemonic_rejects_invalid() {
        // Unknown word → parsing error.
        let res = seed_from_mnemonic("foo bar baz");
        assert!(res.is_err(), "garbage mnemonic must be rejected");
    }

    #[test]
    fn seed_from_mnemonic_rejects_bad_checksum() {
        // 24 valid words but with a broken checksum (last word
        // replaced by a dictionary word that does not validate the
        // all-zero checksum).
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let res = seed_from_mnemonic(bad);
        assert!(res.is_err(), "bad checksum must be rejected");
    }

    #[test]
    fn load_or_create_mnemonic_returns_zeroizing_string() {
        // Regression guard: the mnemonic is seed-equivalent secret material, so
        // the return type must be `Zeroizing<String>` (scrubbed on drop), not
        // a plain `String`. The explicit type annotation makes this a
        // compile-time check: reverting the signature to `String` fails to
        // build this test.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("zeroizing-check.txt");
        let m: Zeroizing<String> = load_or_create_mnemonic(&path).expect("create");
        seed_from_mnemonic(&m).expect("returned string must be a valid mnemonic");
    }

    #[test]
    fn load_or_create_creates_file_when_missing() {
        // First call: file does not exist → mnemonic generated and
        // persisted to disk.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("warren-mnemonic.txt");
        assert!(!path.exists(), "precondition: file must not exist");

        let m = load_or_create_mnemonic(&path).expect("first call must succeed");

        assert!(path.exists(), "file must be created");
        // Check what was returned is *really* a valid BIP39 mnemonic
        // (parse-able), not an empty placeholder.
        seed_from_mnemonic(&m).expect("returned string must be a valid mnemonic");
        // 12 words = Warren standard (UX/security tradeoff - 128 bits
        // of entropy suffice for a 256-bit symmetric-key scheme).
        assert_eq!(
            m.split_whitespace().count(),
            12,
            "must be a 12-word mnemonic"
        );
    }

    #[test]
    fn load_or_create_is_idempotent() {
        // Second call: file exists → mnemonic re-read, not regenerated.
        // This invariant guarantees the Warren identity survives client
        // restarts.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("warren-mnemonic.txt");

        let m1 = load_or_create_mnemonic(&path).expect("create");
        let m2 = load_or_create_mnemonic(&path).expect("load");

        assert_eq!(m1, m2, "second call must return the same mnemonic");
    }

    #[test]
    fn load_or_create_handles_concurrent_creation() {
        // Before the current implementation, `load_or_create_mnemonic`
        // used `path.exists()` then `OpenOptions::create_new(true)`.
        // Race possible: multiple threads / processes passed the check
        // at `false` simultaneously, all attempted `create_new`, only
        // one succeeded, and the others received `AlreadyExists` and
        // returned an opaque error instead of simply reading the file
        // that had just been created.
        //
        // This test is probabilistic: with 16 concurrent threads, the
        // odds that none hits the race window is tiny (≪ 1%). If it
        // becomes flaky in CI, raise the thread count or add a
        // `Barrier` to synchronize them.
        use std::sync::Arc;
        use std::thread;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = Arc::new(dir.path().join("concurrent.txt"));

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let p = Arc::clone(&path);
                thread::spawn(move || load_or_create_mnemonic(&p))
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Every thread must return Ok - only one created, the others
        // saw the file already present and read it.
        for (i, r) in results.iter().enumerate() {
            assert!(
                r.is_ok(),
                "thread {i} failed on load_or_create_mnemonic race: {r:?}"
            );
        }

        // All must return the same mnemonic (creator + readers see the
        // same data).
        let first = results[0].as_ref().expect("thread 0 ok");
        for (i, r) in results.iter().enumerate().skip(1) {
            assert_eq!(
                r.as_ref().unwrap(),
                first,
                "thread {i} returned a different mnemonic"
            );
        }
    }

    #[test]
    fn load_or_create_two_fresh_files_yield_different_mnemonics() {
        // Sanity: generation must use an RNG, so two independently
        // created fresh files must contain distinct mnemonics
        // (collision probability ≈ 1/2^256).
        let dir = tempfile::tempdir().expect("tempdir");
        let p1 = dir.path().join("a.txt");
        let p2 = dir.path().join("b.txt");

        let m1 = load_or_create_mnemonic(&p1).expect("create a");
        let m2 = load_or_create_mnemonic(&p2).expect("create b");

        assert_ne!(m1, m2, "two fresh mnemonics must differ");
    }

    #[test]
    fn load_or_create_rejects_garbage_file() {
        // A pre-existing file containing something other than a valid
        // BIP39 mnemonic must refuse to be used rather than be
        // silently overwritten (user-data loss).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("garbage.txt");
        std::fs::write(&path, "this is not a bip39 mnemonic").expect("write garbage");

        let res = load_or_create_mnemonic(&path);
        assert!(
            res.is_err(),
            "garbage file must be rejected, not overwritten"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_or_create_writes_with_mode_0600() {
        // Security: a file holding a BIP39 mnemonic must *never* be
        // world-readable. mode = 0o600 = user read/write only.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("perm.txt");
        load_or_create_mnemonic(&path).expect("create");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "mnemonic file must have mode 0600, got {mode:o}"
        );
    }
}

// Gated on `bip39`: the zero-entropy mnemonic vectors need `seed_from_mnemonic`.
// The seed-only and signature vectors are equally exercised under default
// features (which include `bip39`); see the note on `mod tests`.
#[cfg(all(test, feature = "bip39"))]
mod vector_tests {
    use super::*;

    /// Cryptographic vector test: if anyone changes the HKDF salt or
    /// info, the produced pubkey changes and this test breaks,
    /// **blocking** the merge.
    ///
    /// Expected value computed with:
    /// - HKDF salt = `b"warren/identity/v1"`
    /// - HKDF info = `b"vpn-node-key"`
    /// - seed      = `[0xab; 32]`
    /// - SHA-256 + ed25519-dalek 2.x
    ///
    /// Any change in the output = schema change = bump to
    /// `identity/v2`.
    #[test]
    fn seed_ab_produces_known_pubkey() {
        let seed = [0xab; 32];
        let key = derive_node_key(&seed);
        let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
        assert_eq!(
            pubkey_hex, "21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b",
            "WARREN identity schema changed - bump to identity/v2 if intentional"
        );
    }

    /// Same with a different seed (all zeros) to double-check. Two
    /// cryptographic anchors beat one.
    #[test]
    fn seed_zero_produces_known_pubkey() {
        let seed = [0u8; 32];
        let key = derive_node_key(&seed);
        let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
        assert_eq!(
            pubkey_hex, "d9d24d24f77550ec46914c30d83dc973063c759967d03af4efe508fb34ed5308",
            "WARREN identity schema changed - bump to identity/v2 if intentional"
        );
    }

    #[test]
    fn signature_roundtrips_through_verify() {
        // Sanity on the produced SigningKey: it can sign and verify
        // an arbitrary message. If HKDF produced invalid bytes for
        // ed25519, this would break. Covers the *real* functionality
        // of the key, not just its construction.
        use ed25519_dalek::{Signer, Verifier};
        let key = derive_node_key(&[0xab; 32]);
        let msg = b"warren-vpn-handshake-challenge";
        let sig = key.sign(msg);
        key.verifying_key()
            .verify(msg, &sig)
            .expect("signature must verify with its own pubkey");
    }

    #[test]
    fn signature_does_not_verify_with_wrong_key() {
        // Anti-confusion: a signature must *not* pass verification
        // with another pubkey. Guarantees identity separation is
        // respected by ed25519.
        use ed25519_dalek::{Signer, Verifier};
        let alice = derive_node_key(&[0xaa; 32]);
        let bob = derive_node_key(&[0xbb; 32]);
        let msg = b"only-alice-should-sign-this";
        let alice_sig = alice.sign(msg);
        bob.verifying_key()
            .verify(msg, &alice_sig)
            .expect_err("bob's pubkey must NOT verify alice's signature");
    }

    /// BIP39 vector test - freezes the seed produced by the canonical
    /// reference mnemonic (24 words, all-zero entropy). Any change to
    /// the passphrase, normalization, or 64→32-byte truncation breaks
    /// this test, **blocking** the merge.
    ///
    /// Computed with:
    /// - mnemonic   = `"abandon abandon ... art"` (24 words, entropy 0)
    /// - passphrase = `""` (empty, NFKD-normalized)
    /// - BIP39 → 64 bytes PBKDF2-SHA512 → first 32 bytes kept
    #[test]
    fn vector_zero_entropy_24w_seed_is_known() {
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let seed = super::seed_from_mnemonic(m).expect("valid mnemonic");
        let seed_hex = hex::encode(seed);
        assert_eq!(
            seed_hex, "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70",
            "WARREN BIP39 schema changed - bump to identity/v2 if intentional"
        );
    }

    /// Full chain: mnemonic → BIP39 seed → derive_node_key → pubkey.
    /// If anyone changes the pipeline (BIP39 or HKDF), this pubkey
    /// changes and an explicit bump to `identity/v2` is required.
    #[test]
    fn vector_zero_entropy_24w_pubkey_is_known() {
        let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let seed = super::seed_from_mnemonic(m).expect("valid mnemonic");
        let key = super::derive_node_key(&seed);
        let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
        assert_eq!(
            pubkey_hex, "fba874de8721df35921c9999a036c03bb098df35fc21fcbeac98af880ababdb9",
            "WARREN identity/BIP39 pipeline changed - bump to identity/v2 if intentional"
        );
    }

    #[test]
    fn signature_is_deterministic_per_message() {
        // Ed25519 is deterministic by construction (no RNG in the
        // signature). If we switched to a probabilistic scheme by
        // accident, this would break.
        use ed25519_dalek::Signer;
        let key = derive_node_key(&[0x42; 32]);
        let msg = b"deterministic-please";
        let sig1 = key.sign(msg);
        let sig2 = key.sign(msg);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}
