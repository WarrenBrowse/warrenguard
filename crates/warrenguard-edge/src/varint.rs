//! QUIC/HTTP3 variable-length integers (RFC 9000 section 16). Used for HTTP/3
//! frame types and lengths, uni-stream types, settings identifiers, and QPACK
//! prefixed integers.

/// Decodes one variable-length integer from the front of `input`.
///
/// Returns the value and the number of bytes consumed, or `None` if `input` is
/// empty or does not hold the full multi-byte encoding the 2-bit length prefix
/// announces (a truncated integer).
pub fn decode(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    // The top two bits of the first byte select 1/2/4/8 total bytes.
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &byte in &input[1..len] {
        value = (value << 8) | u64::from(byte);
    }
    Some((value, len))
}

/// Encodes `value` as the shortest legal variable-length integer.
///
/// # Panics
/// Panics if `value` exceeds the 62-bit maximum (`2^62 - 1`), which cannot be
/// represented by the encoding.
pub fn encode(value: u64) -> Vec<u8> {
    if value < (1 << 6) {
        vec![value as u8]
    } else if value < (1 << 14) {
        ((value as u16) | 0x4000).to_be_bytes().to_vec()
    } else if value < (1 << 30) {
        ((value as u32) | 0x8000_0000).to_be_bytes().to_vec()
    } else if value < (1 << 62) {
        (value | 0xC000_0000_0000_0000).to_be_bytes().to_vec()
    } else {
        panic!("value exceeds the 62-bit varint maximum");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_rfc9000_boundaries() {
        for v in [
            0u64,
            63,
            64,
            0x3fff,
            0x4000,
            0x3fff_ffff,
            0x4000_0000,
            (1 << 62) - 1,
        ] {
            let bytes = encode(v);
            let (decoded, used) = decode(&bytes).expect("decodes");
            assert_eq!(decoded, v, "value {v}");
            assert_eq!(used, bytes.len(), "consumed all of {v}'s encoding");
        }
    }

    #[test]
    fn decode_matches_known_encodings() {
        // RFC 9000 section 16 worked examples.
        assert_eq!(decode(&[0x00]), Some((0, 1)));
        assert_eq!(decode(&[0x3f]), Some((63, 1)));
        assert_eq!(decode(&[0x40, 0x40]), Some((64, 2)));
        assert_eq!(decode(&[0x7f, 0xff]), Some((0x3fff, 2)));
        assert_eq!(decode(&[0x80, 0x00, 0x40, 0x00]), Some((0x4000, 4)));
    }

    #[test]
    fn decode_rejects_a_truncated_multibyte_integer() {
        // First byte announces a 2-byte integer but only one byte is present.
        assert_eq!(decode(&[0x40]), None);
        // 4-byte announced, 3 present.
        assert_eq!(decode(&[0x80, 0x00, 0x40]), None);
        assert_eq!(decode(&[]), None);
    }

    #[test]
    fn decode_returns_the_consumed_length_leaving_trailing_bytes() {
        let (v, used) = decode(&[0x00, 0xaa, 0xbb]).expect("decodes");
        assert_eq!((v, used), (0, 1));
    }
}
