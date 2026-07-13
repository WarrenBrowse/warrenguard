//! QUIC variable-length integer decoding (RFC 9000 s16).

use thiserror::Error;

/// Error decoding a QUIC variable-length integer.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum VarIntError {
    /// The input ended before the full varint was read.
    #[error("truncated varint: need {need} bytes, have {have}")]
    Truncated {
        /// Bytes the encoding requires.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },
}

/// Decodes a QUIC variable-length integer from the front of `input`.
///
/// Returns the value and the number of bytes consumed. The two most
/// significant bits of the first byte select the length (1, 2, 4, or 8
/// bytes); the remaining 62 bits are the big-endian value (RFC 9000 s16).
///
/// # Errors
///
/// [`VarIntError::Truncated`] if `input` is shorter than the encoded length.
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), VarIntError> {
    let first = *input
        .first()
        .ok_or(VarIntError::Truncated { need: 1, have: 0 })?;
    // Top 2 bits: 00 -> 1 byte, 01 -> 2, 10 -> 4, 11 -> 8.
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return Err(VarIntError::Truncated {
            need: len,
            have: input.len(),
        });
    }
    // The low 6 bits of the first byte are the high bits of the value.
    let mut value = u64::from(first & 0x3f);
    for &b in &input[1..len] {
        value = (value << 8) | u64::from(b);
    }
    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground-truth vectors from RFC 9000 Appendix A.1.

    #[test]
    fn rfc9000_eight_byte_vector() {
        let bytes = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        assert_eq!(decode_varint(&bytes).unwrap(), (151_288_809_941_952_652, 8));
    }

    #[test]
    fn rfc9000_four_byte_vector() {
        assert_eq!(
            decode_varint(&[0x9d, 0x7f, 0x3e, 0x7d]).unwrap(),
            (494_878_333, 4)
        );
    }

    #[test]
    fn rfc9000_two_byte_vector() {
        assert_eq!(decode_varint(&[0x7b, 0xbd]).unwrap(), (15_293, 2));
    }

    #[test]
    fn rfc9000_one_byte_vector() {
        assert_eq!(decode_varint(&[0x25]).unwrap(), (37, 1));
    }

    #[test]
    fn rfc9000_non_minimal_two_byte_encoding_of_37() {
        // 0x4025 is the two-byte encoding of the same value 37.
        assert_eq!(decode_varint(&[0x40, 0x25]).unwrap(), (37, 2));
    }

    #[test]
    fn truncated_inputs_are_rejected() {
        assert_eq!(
            decode_varint(&[0xc2, 0x19, 0x7c]),
            Err(VarIntError::Truncated { need: 8, have: 3 })
        );
        assert_eq!(
            decode_varint(&[]),
            Err(VarIntError::Truncated { need: 1, have: 0 })
        );
    }
}
