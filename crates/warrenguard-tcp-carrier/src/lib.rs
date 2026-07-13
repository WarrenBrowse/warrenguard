//! TCP fallback carrier for the Warren QUIC data plane.
//!
//! When outbound UDP/443 is blocked or throttled (cafes, trains, corporate
//! LANs, some national censors), a QUIC/UDP-only tunnel simply does not connect.
//! The fallback carries the exact same QUIC datagrams the engine already
//! produces inside ONE real TLS 1.3 stream to the exit's cover domain on
//! `:443/tcp`. To an on-path observer this is an ordinary HTTPS connection to a
//! real, CT-logged domain, reusing the cover the exit already serves for QUIC:
//! there is no second wire profile to hide.
//!
//! This crate owns the lowest piece: the **stream framing** that turns the
//! packet-oriented QUIC datagram flow into a byte stream and back. QUIC (over
//! the wrapping stream) is length-delimited as `u16 length (big-endian) ||
//! datagram`, the standard udp2tcp / "datagram over stream" shape. The framing
//! lives INSIDE TLS, never on the wire in clear, so it adds no fingerprint.
//!
//! The framing is the wire contract between the client carrier and the exit-side
//! terminator: both reassemble the same way, so it is pinned by a byte-exact
//! golden test ([`tests`]). The quinn `AsyncUdpSocket` client shim and the
//! exit-side TLS terminator are built on top of this codec; they are the async
//! I/O wiring, not a second framing.
//!
//! # Why length-delimited and not raw
//!
//! TCP is a byte stream with no message boundaries: a single `read` can return
//! part of a datagram, exactly one, or several concatenated. The 2-byte length
//! prefix restores the datagram boundaries the QUIC engine expects when it reads
//! from its socket. A QUIC datagram on the Warren path is at most one path-MTU
//! (~1350 bytes), far under `u16::MAX`, so a 2-byte prefix always suffices and a
//! larger prefix would only waste bytes.

#![forbid(unsafe_code)]

use thiserror::Error;

/// The length prefix is a big-endian `u16`, so a single framed datagram may not
/// exceed this many payload bytes. QUIC datagrams on the Warren path are one
/// path-MTU (~1350 B), so this ceiling is never approached in practice; it is
/// enforced so an out-of-contract oversized datagram fails loudly instead of
/// silently truncating its length prefix.
pub const MAX_DATAGRAM_LEN: usize = u16::MAX as usize;

/// Number of bytes in the length prefix.
pub const LEN_PREFIX_BYTES: usize = 2;

/// Errors raised while framing or deframing carrier datagrams.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FramingError {
    /// A datagram exceeded [`MAX_DATAGRAM_LEN`] and cannot be length-prefixed
    /// with a `u16`. Carries only the offending length (a size, not identity
    /// material), safe to surface.
    #[error("datagram of {0} bytes exceeds the {MAX_DATAGRAM_LEN}-byte carrier frame limit")]
    DatagramTooLarge(usize),
}

/// Appends one length-delimited frame (`u16 len || datagram`) to `out`.
///
/// The caller owns `out` so multiple datagrams can be coalesced into one TLS
/// write without reallocating per datagram.
///
/// # Errors
/// [`FramingError::DatagramTooLarge`] if `datagram` is longer than
/// [`MAX_DATAGRAM_LEN`].
pub fn encode_frame(out: &mut Vec<u8>, datagram: &[u8]) -> Result<(), FramingError> {
    let len = datagram.len();
    if len > MAX_DATAGRAM_LEN {
        return Err(FramingError::DatagramTooLarge(len));
    }
    // `len <= u16::MAX` was just checked, so the cast cannot truncate.
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(datagram);
    Ok(())
}

/// Reassembles length-delimited datagrams from a TCP byte stream.
///
/// Feed it whatever bytes a `read` returned (a partial frame, one frame, or
/// several) via [`Deframer::push`], then drain complete datagrams with
/// [`Deframer::next_datagram`]. Bytes for an incomplete trailing frame are
/// retained until the rest arrives, so an arbitrary TCP segmentation of the
/// stream reassembles losslessly.
#[derive(Debug, Default)]
pub struct Deframer {
    buf: Vec<u8>,
    /// Read cursor into `buf`. Consumed datagrams are not copied out eagerly;
    /// the cursor advances and the buffer is compacted only when it grows, so a
    /// burst of small datagrams does not memmove on every drain.
    start: usize,
}

impl Deframer {
    /// A fresh, empty deframer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends freshly read stream bytes for reassembly.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Returns the next complete datagram, or `None` if the buffered bytes do
    /// not yet contain a full `u16 len || datagram` frame.
    ///
    /// Loop it until it returns `None` to drain every complete datagram a
    /// [`Self::push`] made available.
    pub fn next_datagram(&mut self) -> Option<Vec<u8>> {
        let available = self.buf.len() - self.start;
        if available < LEN_PREFIX_BYTES {
            self.compact();
            return None;
        }
        let len_bytes = [self.buf[self.start], self.buf[self.start + 1]];
        let payload_len = u16::from_be_bytes(len_bytes) as usize;
        let frame_len = LEN_PREFIX_BYTES + payload_len;
        if available < frame_len {
            self.compact();
            return None;
        }
        let payload_start = self.start + LEN_PREFIX_BYTES;
        let datagram = self.buf[payload_start..payload_start + payload_len].to_vec();
        self.start += frame_len;
        self.compact();
        Some(datagram)
    }

    /// Drops already-consumed bytes once they dominate the buffer, so a
    /// long-lived stream does not grow the backing `Vec` without bound.
    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start > self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector: the framing is the wire contract shared with the exit-side
    /// terminator, so its bytes are pinned exactly. A three-byte datagram
    /// `[0xAA,0xBB,0xCC]` frames as `00 03 AA BB CC`. Changing these bytes is a
    /// wire-format change and must bump a version, never silently mutate.
    #[test]
    fn encode_frame_golden_bytes() {
        let mut out = Vec::new();
        encode_frame(&mut out, &[0xAA, 0xBB, 0xCC]).expect("small datagram frames");
        assert_eq!(out, vec![0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn empty_datagram_frames_as_zero_length() {
        let mut out = Vec::new();
        encode_frame(&mut out, &[]).expect("empty datagram is valid");
        assert_eq!(out, vec![0x00, 0x00]);
    }

    #[test]
    fn oversized_datagram_is_rejected() {
        let mut out = Vec::new();
        let too_big = vec![0u8; MAX_DATAGRAM_LEN + 1];
        assert_eq!(
            encode_frame(&mut out, &too_big),
            Err(FramingError::DatagramTooLarge(MAX_DATAGRAM_LEN + 1))
        );
        assert!(out.is_empty(), "a rejected datagram writes nothing");
    }

    /// Decode-side counterpart to [`empty_datagram_frames_as_zero_length`]: a
    /// bare `[0x00, 0x00]` frame decodes to `Some(vec![])`, not `None`. This
    /// matters because the carrier's consumer (`pump_uplink` in
    /// `warrenguard-tcp-fallback`) forwards whatever this returns as a UDP
    /// send; a zero-length datagram is a legitimate (if degenerate) QUIC
    /// datagram and must be delivered, never silently treated as "no frame".
    #[test]
    fn deframer_decodes_a_zero_length_frame_as_an_empty_datagram() {
        let mut de = Deframer::new();
        de.push(&[0x00, 0x00]);
        assert_eq!(de.next_datagram(), Some(Vec::new()));
        assert_eq!(de.next_datagram(), None, "nothing left after draining");
    }

    /// A frame the stream never completes (the peer resets or closes
    /// mid-frame) must never surface as a datagram: the buffered partial
    /// bytes stay buffered, they are never delivered short. This is the
    /// property `pump_uplink` relies on when it hits EOF with a partial frame
    /// still in the deframer: it returns `Ok(())` and simply drops the
    /// deframer (and its buffered partial bytes) without trying to flush them.
    #[test]
    fn partial_frame_is_never_delivered_even_once_the_caller_stops_pushing() {
        let payload = b"never arrives complete";
        let mut wire = Vec::new();
        encode_frame(&mut wire, payload).unwrap();
        let (partial, _held_back) = wire.split_at(wire.len() - 3);
        let mut de = Deframer::new();
        de.push(partial);
        assert_eq!(
            de.next_datagram(),
            None,
            "an incomplete frame yields nothing, whether more bytes are \
             still coming or the stream has actually ended here"
        );
        // The caller (pump_uplink) never calls next_datagram() again once it
        // observes EOF; dropping the deframer with a partial frame still
        // buffered must not panic or otherwise surface those bytes.
        drop(de);
    }

    #[test]
    fn roundtrip_single_datagram() {
        let payload = b"hello quic datagram";
        let mut wire = Vec::new();
        encode_frame(&mut wire, payload).unwrap();
        let mut de = Deframer::new();
        de.push(&wire);
        assert_eq!(de.next_datagram().as_deref(), Some(&payload[..]));
        assert_eq!(de.next_datagram(), None);
    }

    #[test]
    fn multiple_datagrams_in_one_read_are_split() {
        let a = b"first";
        let b = b"second-datagram";
        let mut wire = Vec::new();
        encode_frame(&mut wire, a).unwrap();
        encode_frame(&mut wire, b).unwrap();
        let mut de = Deframer::new();
        de.push(&wire);
        assert_eq!(de.next_datagram().as_deref(), Some(&a[..]));
        assert_eq!(de.next_datagram().as_deref(), Some(&b[..]));
        assert_eq!(de.next_datagram(), None);
    }

    /// TCP can split a frame across reads at ANY byte boundary. The deframer
    /// must retain the partial frame and yield the datagram only once complete.
    /// This is the property a naive "one read = one datagram" carrier gets wrong.
    #[test]
    fn frame_split_across_reads_reassembles() {
        let payload = b"split me across tcp segments";
        let mut wire = Vec::new();
        encode_frame(&mut wire, payload).unwrap();
        let mut de = Deframer::new();
        // Feed one byte at a time (worst-case segmentation): nothing is
        // available until the final byte completes the frame.
        let (last, head) = wire.split_last().expect("frame is non-empty");
        for chunk in head.chunks(1) {
            de.push(chunk);
            assert_eq!(
                de.next_datagram(),
                None,
                "no datagram is available mid-frame"
            );
        }
        de.push(&[*last]);
        assert_eq!(de.next_datagram().as_deref(), Some(&payload[..]));
        assert_eq!(de.next_datagram(), None);
    }

    #[test]
    fn length_prefix_split_from_payload_reassembles() {
        // Boundary lands exactly between the 2-byte prefix and the payload.
        let payload = b"XYZ";
        let mut wire = Vec::new();
        encode_frame(&mut wire, payload).unwrap();
        let (prefix, body) = wire.split_at(LEN_PREFIX_BYTES);
        let mut de = Deframer::new();
        de.push(prefix);
        assert_eq!(de.next_datagram(), None, "prefix alone yields nothing");
        de.push(body);
        assert_eq!(de.next_datagram().as_deref(), Some(&payload[..]));
    }

    #[test]
    fn max_size_datagram_roundtrips() {
        let payload = vec![0x5A; MAX_DATAGRAM_LEN];
        let mut wire = Vec::new();
        encode_frame(&mut wire, &payload).unwrap();
        assert_eq!(wire.len(), LEN_PREFIX_BYTES + MAX_DATAGRAM_LEN);
        let mut de = Deframer::new();
        de.push(&wire);
        assert_eq!(de.next_datagram(), Some(payload));
    }

    /// A long-lived carrier must not grow its backing buffer without bound as
    /// datagrams are consumed: compaction reclaims consumed bytes.
    #[test]
    fn buffer_compacts_after_draining_many_frames() {
        let mut de = Deframer::new();
        for _ in 0..1000 {
            let mut wire = Vec::new();
            encode_frame(&mut wire, b"steady datagram flow").unwrap();
            de.push(&wire);
            assert!(de.next_datagram().is_some());
        }
        assert!(
            de.buf.len() < 4096,
            "consumed bytes must be reclaimed, buffer stayed at {}",
            de.buf.len()
        );
    }
}
