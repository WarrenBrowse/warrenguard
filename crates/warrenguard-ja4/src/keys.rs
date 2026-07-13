//! QUIC Initial packet key derivation (RFC 9001 s5.2).
//!
//! Initial packets are protected with keys derived deterministically from the
//! client's Destination Connection ID and a version-fixed salt, so any on-path
//! observer can reproduce them. This module derives the client's key, IV and
//! header-protection key for QUIC v1.

use hkdf::Hkdf;
use sha2::Sha256;

/// QUIC v1 Initial salt (RFC 9001 s5.2).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The client's Initial packet-protection keys derived from the DCID.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientInitialKeys {
    /// AES-128-GCM payload key.
    pub key: [u8; 16],
    /// AEAD nonce base (XORed with the packet number to form the nonce).
    pub iv: [u8; 12],
    /// Header-protection key (AES-128 ECB mask input).
    pub hp: [u8; 16],
}

/// HKDF-Expand-Label (RFC 8446 s7.1, as used by RFC 9001) with the `tls13 `
/// prefix and an empty context, returning exactly `N` bytes.
fn expand_label<const N: usize>(prk: &[u8], label: &[u8]) -> [u8; N] {
    let full_label = [b"tls13 ".as_slice(), label].concat();
    // struct { uint16 length; opaque label<7..255>; opaque context<0..255> }
    let mut info = Vec::with_capacity(3 + full_label.len() + 1);
    info.extend_from_slice(&(N as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(0); // empty context
    // `from_prk` only rejects a PRK shorter than the hash output; every caller
    // passes a 32-byte HMAC-SHA256 output, so this never fails. `expand` only
    // rejects `N > 255 * 32`; every label here is <= 32 bytes.
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("PRK is a 32-byte HMAC-SHA256 output");
    let mut okm = [0u8; N];
    hk.expand(&info, &mut okm)
        .expect("N <= 32 is within the HKDF-Expand output bound");
    okm
}

/// Derives the client Initial keys from the Destination Connection ID for
/// QUIC v1.
#[must_use]
pub fn derive_client_initial_keys(dcid: &[u8]) -> ClientInitialKeys {
    let (initial_secret, _hk) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT_V1), dcid);
    let client_secret: [u8; 32] = expand_label(initial_secret.as_slice(), b"client in");
    ClientInitialKeys {
        key: expand_label(&client_secret, b"quic key"),
        iv: expand_label(&client_secret, b"quic iv"),
        hp: expand_label(&client_secret, b"quic hp"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9001_appendix_a_client_initial_keys() {
        // Ground truth from RFC 9001 Appendix A.1: for the client Initial with
        // DCID 0x8394c8f03e515708, the derived key/iv/hp are fixed. Matching
        // them proves HKDF-Extract + HKDF-Expand-Label + the label wiring.
        let dcid = hex::decode("8394c8f03e515708").unwrap();
        let k = derive_client_initial_keys(&dcid);
        assert_eq!(
            hex::encode(k.key),
            "1f369613dd76d5467730efcbe3b1a22d",
            "quic key"
        );
        assert_eq!(hex::encode(k.iv), "fa044b2f42a3fd3b46fb255c", "quic iv");
        assert_eq!(
            hex::encode(k.hp),
            "9f50449e04a0e810283a1e9933adedd2",
            "quic hp"
        );
    }
}
