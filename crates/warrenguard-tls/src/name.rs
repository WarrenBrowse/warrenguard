//! TLS Server Name encoding of a Warren peer pubkey.
//!
//! The TLS handshake server-name (SNI) carries the pubkey of the
//! identity the client expects to talk to. Encoding is base32-DNSSEC
//! over the 32 pubkey bytes followed by a suffix.
//!
//! The suffix `.exits.warrenbrowse.com` makes the SNI
//! wire-indistinguishable from a casual HTTP/3 dial to a
//! production-looking domain.
//!
//! The 32-byte pubkey would encode to 64 hex characters, which exceeds
//! the 63-character DNS label limit; base32-DNSSEC produces a 52-byte
//! label that fits cleanly.

use data_encoding::BASE32_DNSSEC;

use crate::WarrenPubkey;

/// SNI suffix emitted by [`encode`] and accepted by [`decode`].
///
/// `.exits.warrenbrowse.com` mimics a casual HTTP/3 endpoint on the
/// production Warren domain. Mutating this breaks the wire mimicry
/// invariant and silently fails every deployed peer; bump to a new
/// constant (and add it to the [`decode`] accepted list) rather than
/// mutating the current value.
pub(crate) const SUFFIX: &str = ".exits.warrenbrowse.com";

/// Encodes a [`WarrenPubkey`] as the canonical TLS server name.
///
/// The output is always lower-case `<base32>.exits.warrenbrowse.com`,
/// with the base32 label exactly 52 characters long (the DNSSEC
/// alphabet fits 32 octets in 52 chars).
#[must_use]
pub fn encode(pk: WarrenPubkey) -> String {
    format!("{}{SUFFIX}", BASE32_DNSSEC.encode(pk.as_bytes()))
}

/// Decodes a TLS server name back into a [`WarrenPubkey`].
///
/// Accepts the canonical form `<base32>.exits.warrenbrowse.com`. Any
/// other shape, any other suffix, any base32 payload that does not
/// decode to exactly 32 bytes, returns `None`.
///
/// Strictness matters: a forgiving parser would let a hostile client
/// smuggle pubkey bytes via padded or alternative encodings, and the
/// server verifier compares against the canonical encoding of its
/// own pubkey.
#[must_use]
pub fn decode(name: &str) -> Option<WarrenPubkey> {
    let label = name.strip_suffix(SUFFIX)?;
    // Reject anything carrying extra labels under the suffix.
    if label.is_empty() || label.contains('.') {
        return None;
    }
    let decoded = BASE32_DNSSEC.decode(label.as_bytes()).ok()?;
    let bytes: [u8; 32] = decoded.try_into().ok()?;
    Some(WarrenPubkey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC8032_ZERO_SECRET_PUBKEY: WarrenPubkey = WarrenPubkey::from_bytes([
        0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d, 0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f, 0x0d,
        0x73, 0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6, 0x3a, 0xc0, 0x48, 0xa1, 0x8b, 0x59,
        0xda, 0x29,
    ]);
    const RFC8032_ZERO_SECRET_BASE32_LABEL: &str =
        "7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg";

    /// Invariant: every fresh SNI emitted by `encode` must carry the
    /// wire-mimicking suffix `.exits.warrenbrowse.com`, which is
    /// indistinguishable from a casual HTTP/3 dial to a
    /// production-looking domain.
    #[test]
    fn encode_emits_suffix() {
        let pk = WarrenPubkey::from_bytes([0u8; 32]);
        let sni = encode(pk);
        assert!(
            sni.ends_with(".exits.warrenbrowse.com"),
            "encode must emit .exits.warrenbrowse.com, got {sni}"
        );
    }

    /// Locks the encoding against the canonical RFC 8032 zero-secret
    /// test vector. If this snapshot drifts, every peer with a pinned
    /// SNI breaks - including the `ServerCertificateVerifier` that
    /// re-encodes its own pubkey to match the SNI sent by the client.
    #[test]
    fn rfc8032_zero_secret_pubkey_encodes_to_snapshot() {
        assert_eq!(
            encode(RFC8032_ZERO_SECRET_PUBKEY),
            format!("{RFC8032_ZERO_SECRET_BASE32_LABEL}{SUFFIX}"),
        );
    }

    /// Anchor: the suffix MUST remain `.exits.warrenbrowse.com`
    /// bytewise. Mutating the constant silently fails every deployed
    /// peer.
    #[test]
    fn suffix_constant_is_stable() {
        assert_eq!(SUFFIX, ".exits.warrenbrowse.com");
    }

    /// Cross-pin: the well-known RFC 8032 vector bytes above are what
    /// `ed25519_dalek::SigningKey::from_bytes(&[0; 32]).verifying_key()`
    /// produces. If ed25519-dalek ever changes that derivation, this
    /// test breaks and the snapshot above needs to be re-verified.
    #[test]
    fn zero_secret_derived_pubkey_matches_rfc8032_vector() {
        use ed25519_dalek::SigningKey;
        let signing = SigningKey::from_bytes(&[0u8; 32]);
        let vk_bytes: [u8; 32] = *signing.verifying_key().as_bytes();
        assert_eq!(
            hex::encode(vk_bytes),
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        );
        assert_eq!(
            vk_bytes,
            *RFC8032_ZERO_SECRET_PUBKEY.as_bytes(),
            "RFC8032_ZERO_SECRET_PUBKEY const must match the live ed25519-dalek derivation"
        );
    }

    #[test]
    fn arbitrary_pubkey_roundtrips_through_encode_decode() {
        let pk = WarrenPubkey::from_bytes([
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c,
        ]);
        let encoded = encode(pk);
        let decoded = decode(&encoded).expect("self-produced name must decode");
        assert_eq!(decoded, pk);
    }

    #[test]
    fn encoded_label_fits_dns_subdomain_limit() {
        let pk = WarrenPubkey::from_bytes([0xff; 32]);
        let encoded = encode(pk);
        let label = encoded.split('.').next().expect("at least one label");
        assert!(
            label.len() <= 63,
            "base32 label ({} chars) must fit DNS subdomain 63-char limit",
            label.len()
        );
    }

    #[test]
    fn decode_rejects_wrong_tld() {
        let pk = WarrenPubkey::from_bytes([0u8; 32]);
        let encoded = encode(pk);
        let bad_tld = encoded.replace(".com", ".net");
        assert!(
            decode(&bad_tld).is_none(),
            "only the canonical warrenbrowse.com suffix is accepted, got bad TLD: {bad_tld}"
        );
    }

    #[test]
    fn decode_rejects_wrong_subdomain_marker() {
        let pk = WarrenPubkey::from_bytes([0u8; 32]);
        let encoded = encode(pk);
        let bad_sub = encoded.replace(".exits.", ".relays.");
        assert!(
            decode(&bad_sub).is_none(),
            "only `.exits.warrenbrowse.com` is accepted by the decoder, got: {bad_sub}"
        );
    }

    #[test]
    fn decode_rejects_extra_labels() {
        let pk = WarrenPubkey::from_bytes([0u8; 32]);
        let encoded = encode(pk);
        let with_extra = format!("extra.{encoded}");
        assert!(decode(&with_extra).is_none());
        let with_trailing = format!("{encoded}.extra");
        assert!(decode(&with_trailing).is_none());
    }

    #[test]
    fn decode_rejects_empty_and_garbage() {
        assert!(decode("").is_none());
        assert!(decode(".").is_none());
        assert!(decode("not-base32!@#.exits.warrenbrowse.com").is_none());
        assert!(
            decode("xx.exits.warrenbrowse.com").is_none(),
            "too-short base32 label"
        );
    }

    #[test]
    fn decode_rejects_base32_that_does_not_yield_exactly_32_bytes() {
        // A valid base32-DNSSEC label of a 16-byte payload (not 32).
        let half = BASE32_DNSSEC.encode(&[0u8; 16]);
        let name = format!("{half}.exits.warrenbrowse.com");
        assert!(
            decode(&name).is_none(),
            "decoder must reject anything that isn't exactly 32 raw bytes"
        );
    }
}
