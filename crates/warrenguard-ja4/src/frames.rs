//! QUIC frame parsing over a decrypted Initial payload, reassembling the CRYPTO
//! stream that carries the TLS handshake (RFC 9000 s19).
//!
//! The engine deliberately splits its ClientHello across two Initial packets
//! (an obfuscation knob), so the reassembler accepts the decrypted
//! payloads of several packets and stitches their CRYPTO segments by offset.

use crate::error::Ja4Error;
use crate::varint::decode_varint;

/// A single CRYPTO frame's stream offset and its data.
struct CryptoSegment {
    offset: u64,
    data: Vec<u8>,
}

/// Parses the frames of one decrypted Initial payload and returns its CRYPTO
/// segments, skipping PADDING / PING / ACK frames.
fn crypto_segments(payload: &[u8]) -> Result<Vec<CryptoSegment>, Ja4Error> {
    let mut segments = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let (frame_type, n) = decode_varint(&payload[pos..])?;
        pos += n;
        match frame_type {
            // PADDING (0x00) and PING (0x01) are a single byte, already consumed.
            0x00 | 0x01 => {}
            // ACK (0x02) / ACK-with-ECN (0x03): parse the variable fields so we
            // can skip past them. A client's first Initial has none, but be
            // robust.
            0x02 | 0x03 => {
                pos += skip_varint(payload, pos)?; // largest_acked
                pos += skip_varint(payload, pos)?; // ack_delay
                let (range_count, n) =
                    decode_varint(payload.get(pos..).ok_or(Ja4Error::Truncated)?)?;
                pos += n; // ack_range_count
                pos += skip_varint(payload, pos)?; // first_ack_range
                for _ in 0..range_count {
                    pos += skip_varint(payload, pos)?; // gap
                    pos += skip_varint(payload, pos)?; // ack_range_length
                }
                if frame_type == 0x03 {
                    for _ in 0..3 {
                        pos += skip_varint(payload, pos)?; // ect0, ect1, ecn-ce
                    }
                }
            }
            // CRYPTO (0x06): offset, length, data.
            0x06 => {
                let (offset, a) = decode_varint(&payload[pos..])?;
                pos += a;
                let (length, b) = decode_varint(&payload[pos..])?;
                pos += b;
                let len = usize::try_from(length).map_err(|_| Ja4Error::Truncated)?;
                let data = payload
                    .get(pos..pos + len)
                    .ok_or(Ja4Error::Truncated)?
                    .to_vec();
                pos += len;
                segments.push(CryptoSegment { offset, data });
            }
            // No other frame type is valid in a client Initial.
            _ => return Err(Ja4Error::MalformedClientHello),
        }
    }
    Ok(segments)
}

/// Reads a varint at `pos` and returns the number of bytes it occupies.
fn skip_varint(payload: &[u8], pos: usize) -> Result<usize, Ja4Error> {
    let (_, n) = decode_varint(payload.get(pos..).ok_or(Ja4Error::Truncated)?)?;
    Ok(n)
}

/// Reassembles the TLS handshake bytes from the CRYPTO segments of one or more
/// decrypted Initial payloads. Segments are ordered by offset and required to
/// form a contiguous run from offset 0; overlapping duplicates are skipped.
///
/// # Errors
///
/// [`Ja4Error::NoClientHello`] if no contiguous handshake starting at offset 0
/// can be built; [`Ja4Error`] variants on malformed frames.
pub fn reassemble_client_hello(payloads: &[Vec<u8>]) -> Result<Vec<u8>, Ja4Error> {
    let mut segments = Vec::new();
    for p in payloads {
        segments.extend(crypto_segments(p)?);
    }
    segments.sort_by_key(|s| s.offset);

    let mut out = Vec::new();
    let mut expected: u64 = 0;
    for s in segments {
        let seg_end = s.offset + s.data.len() as u64;
        if seg_end <= expected {
            continue; // fully covered by an earlier segment (retransmit / overlap)
        }
        if s.offset > expected {
            return Err(Ja4Error::NoClientHello); // gap: not contiguous
        }
        // s.offset <= expected < seg_end: append only the new tail.
        let start = (expected - s.offset) as usize;
        out.extend_from_slice(&s.data[start..]);
        expected = seg_end;
    }
    if out.is_empty() {
        return Err(Ja4Error::NoClientHello);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a CRYPTO frame: 0x06, offset (varint), length (varint), data.
    fn crypto_frame(offset: u8, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06, offset, data.len() as u8];
        f.extend_from_slice(data);
        f
    }

    #[test]
    fn reassembles_single_crypto_frame_with_padding() {
        let mut payload = vec![0x00, 0x00]; // 2 PADDING frames
        payload.extend(crypto_frame(0, b"hello"));
        payload.extend([0x00, 0x00]); // trailing padding
        assert_eq!(
            reassemble_client_hello(&[payload]).unwrap(),
            b"hello".to_vec()
        );
    }

    #[test]
    fn stitches_two_initials_by_offset() {
        // The obfuscation split: offset 0 in one packet, offset 3 in another.
        let p1 = crypto_frame(0, b"hel");
        let p2 = crypto_frame(3, b"lo");
        assert_eq!(
            reassemble_client_hello(&[p2, p1]).unwrap(),
            b"hello".to_vec()
        );
    }

    #[test]
    fn rejects_a_gap() {
        let p = crypto_frame(1, b"ello"); // starts at 1, not 0
        assert_eq!(reassemble_client_hello(&[p]), Err(Ja4Error::NoClientHello));
    }

    #[test]
    fn stitches_partial_overlap() {
        // "hel" at offset 0, then "llo" at offset 2 overlapping the last byte;
        // only the new tail ("lo") is appended.
        let p1 = crypto_frame(0, b"hel");
        let p2 = crypto_frame(2, b"llo");
        assert_eq!(
            reassemble_client_hello(&[p1, p2]).unwrap(),
            b"hello".to_vec()
        );
    }
}
