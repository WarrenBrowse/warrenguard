//! QUIC v1 Initial packet parsing and payload decryption (RFC 9001 s5.3-5.4).
//!
//! Initial protection is keyed off the DCID (public), so this reproduces what
//! any on-path observer can do: strip header protection, AEAD-open the payload,
//! and hand back the plaintext QUIC frames.

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};

use crate::error::Ja4Error;
use crate::keys::derive_client_initial_keys;
use crate::varint::decode_varint;

const LONG_HEADER_FORM: u8 = 0x80;
const GCM_TAG_LEN: usize = 16;
const SAMPLE_LEN: usize = 16;

/// Decrypts a client QUIC v1 Initial packet from the front of `datagram` and
/// returns the plaintext QUIC frames (the packet payload).
///
/// # Errors
///
/// Returns [`Ja4Error`] if the datagram is not a well-formed v1 Initial or the
/// AEAD tag does not verify.
pub fn decrypt_client_initial(datagram: &[u8]) -> Result<Vec<u8>, Ja4Error> {
    let first = *datagram.first().ok_or(Ja4Error::Truncated)?;
    if first & LONG_HEADER_FORM == 0 {
        return Err(Ja4Error::NotLongHeader);
    }
    // Long-header packet type is bits 5-4; Initial == 0.
    if (first & 0x30) >> 4 != 0 {
        return Err(Ja4Error::NotInitial);
    }
    let version = u32::from_be_bytes([
        *datagram.get(1).ok_or(Ja4Error::Truncated)?,
        *datagram.get(2).ok_or(Ja4Error::Truncated)?,
        *datagram.get(3).ok_or(Ja4Error::Truncated)?,
        *datagram.get(4).ok_or(Ja4Error::Truncated)?,
    ]);
    if version != 1 {
        return Err(Ja4Error::UnsupportedVersion(version));
    }

    let mut pos = 5;
    let dcid_len = usize::from(*datagram.get(pos).ok_or(Ja4Error::Truncated)?);
    pos += 1;
    let dcid = datagram
        .get(pos..pos + dcid_len)
        .ok_or(Ja4Error::Truncated)?
        .to_vec();
    pos += dcid_len;
    let scid_len = usize::from(*datagram.get(pos).ok_or(Ja4Error::Truncated)?);
    pos += 1 + scid_len; // skip the source connection id

    let (token_len, n) = decode_varint(datagram.get(pos..).ok_or(Ja4Error::Truncated)?)?;
    pos += n + usize::try_from(token_len).map_err(|_| Ja4Error::Truncated)?;
    let (length, n) = decode_varint(datagram.get(pos..).ok_or(Ja4Error::Truncated)?)?;
    pos += n;

    let pn_offset = pos;
    let length = usize::try_from(length).map_err(|_| Ja4Error::Truncated)?;
    // The protected region [pn_offset, pn_offset + length) must be present, and
    // the sample reaches pn_offset + 4 + 16.
    if datagram.len() < pn_offset + length || length < GCM_TAG_LEN {
        return Err(Ja4Error::Truncated);
    }

    let keys = derive_client_initial_keys(&dcid);

    // Header protection: AES-128-ECB of a 16-byte sample taken 4 bytes past the
    // packet-number offset yields the mask (RFC 9001 s5.4.2, s5.4.3).
    let sample_offset = pn_offset + 4;
    let sample = datagram
        .get(sample_offset..sample_offset + SAMPLE_LEN)
        .ok_or(Ja4Error::Truncated)?;
    let mut mask = GenericArray::clone_from_slice(sample);
    Aes128::new(GenericArray::from_slice(&keys.hp)).encrypt_block(&mut mask);

    let unprotected_first = first ^ (mask[0] & 0x0f);
    let pn_len = usize::from((unprotected_first & 0x03) + 1);
    let mut pn_bytes = [0u8; 4];
    let mut packet_number: u64 = 0;
    for (i, out) in pn_bytes.iter_mut().take(pn_len).enumerate() {
        let b = datagram[pn_offset + i] ^ mask[1 + i];
        *out = b;
        packet_number = (packet_number << 8) | u64::from(b);
    }

    // AAD is the fully unprotected header up to and including the packet number.
    let mut aad = datagram[..pn_offset + pn_len].to_vec();
    aad[0] = unprotected_first;
    aad[pn_offset..pn_offset + pn_len].copy_from_slice(&pn_bytes[..pn_len]);

    let nonce = build_nonce(&keys.iv, packet_number);
    let ciphertext = &datagram[pn_offset + pn_len..pn_offset + length];
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Ja4Error::AeadOpen)
}

/// nonce = the packet number left-padded to 12 bytes, XORed with the IV
/// (RFC 9001 s5.3).
fn build_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&packet_number.to_be_bytes());
    nonce.iter_mut().zip(iv).for_each(|(n, &i)| *n ^= i);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_matches_rfc9001_client_packet_number_two() {
        // RFC 9001 Appendix A.2: the sample client Initial uses packet number
        // 2; the IV is from A.1. nonce = iv with the low byte flipped by 2.
        let iv: [u8; 12] = hex::decode("fa044b2f42a3fd3b46fb255c")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(hex::encode(build_nonce(&iv, 2)), "fa044b2f42a3fd3b46fb255e");
    }

    #[test]
    fn rejects_short_header_packet() {
        // A short-header (1-RTT) packet has the form bit clear.
        assert_eq!(
            decrypt_client_initial(&[0x40, 0, 0, 0, 0, 0, 0]),
            Err(Ja4Error::NotLongHeader)
        );
    }

    #[test]
    fn rejects_non_v1_version() {
        // Long-header Initial (0xc0) but version 0xdeadbeef.
        let pkt = [0xc0, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00];
        assert_eq!(
            decrypt_client_initial(&pkt),
            Err(Ja4Error::UnsupportedVersion(0xdead_beef))
        );
    }
}
