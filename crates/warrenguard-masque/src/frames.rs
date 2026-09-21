//! Incremental HTTP/3 framing over one QUIC receive stream.
//!
//! A tunnel's DATA frames can be as large as the client likes, so the reader
//! never buffers a whole frame: it yields a DATA payload chunk by chunk as the
//! transport delivers it, and skips every other frame type as RFC 9114
//! section 9 requires of unknown and reserved frames. Only the request head is
//! read as one bounded frame.

use bytes::{Buf, Bytes, BytesMut};
use quinn::RecvStream;
use warrenguard_edge::{FRAME_DATA, decode_varint};

/// The largest non-DATA frame the reader will skip or buffer on a request
/// stream. A request head is a few hundred bytes; a peer that sends more has
/// nothing legitimate to say.
pub(crate) const MAX_CONTROL_FRAME_BYTES: u64 = 16 * 1024;

/// How much the reader asks the transport for at a time.
const CHUNK: usize = 64 * 1024;

/// A frame type plus length header is at most two 8-byte varints.
const MAX_FRAME_HEADER_BYTES: usize = 16;

/// Why a stream stopped yielding frames. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FrameError {
    /// The peer reset the stream or the connection is gone.
    #[error("stream read failed")]
    Stream,
    /// The stream ended inside a frame, a frame header never completed, or a
    /// non-DATA frame exceeded the bound.
    #[error("malformed HTTP/3 framing")]
    Malformed,
}

/// Reads HTTP/3 frames off a request stream incrementally.
pub(crate) struct FrameReader {
    recv: RecvStream,
    /// Bytes received and not yet consumed.
    pending: Bytes,
    /// Bytes left in the DATA frame currently being yielded.
    remaining_data: u64,
    /// Bytes left to discard of a non-DATA frame being skipped.
    skip: u64,
    /// The peer finished the stream.
    finished: bool,
}

impl FrameReader {
    /// Wraps `recv`, with `prefix` as bytes already read off it by the caller.
    pub(crate) fn new(recv: RecvStream, prefix: Bytes) -> Self {
        Self {
            recv,
            pending: prefix,
            remaining_data: 0,
            skip: 0,
            finished: false,
        }
    }

    /// The stream's receive half, for a caller that wants to stop it.
    pub(crate) fn recv_mut(&mut self) -> &mut RecvStream {
        &mut self.recv
    }

    /// Reads whole frames until the first of type `wanted` and returns its
    /// payload, skipping other frames (each bounded by
    /// [`MAX_CONTROL_FRAME_BYTES`]). `Ok(None)` when the stream ends cleanly
    /// before such a frame.
    ///
    /// # Errors
    /// [`FrameError`] on a stream failure, a truncated frame, or a frame past
    /// the bound. A DATA frame before `wanted` is malformed too: a request
    /// stream opens with HEADERS.
    pub(crate) async fn next_frame(&mut self, wanted: u64) -> Result<Option<Bytes>, FrameError> {
        loop {
            let Some((ty, len, used)) = self.frame_header().await? else {
                return Ok(None);
            };
            if len > MAX_CONTROL_FRAME_BYTES || (ty == FRAME_DATA && ty != wanted) {
                return Err(FrameError::Malformed);
            }
            self.pending.advance(used);
            let len = len as usize;
            while self.pending.len() < len {
                if !self.fill().await? {
                    return Err(FrameError::Malformed);
                }
            }
            let payload = self.pending.split_to(len);
            if ty == wanted {
                return Ok(Some(payload));
            }
        }
    }

    /// Yields the next chunk of DATA payload, skipping every non-DATA frame.
    /// `Ok(None)` once the peer has finished the stream.
    ///
    /// # Errors
    /// [`FrameError`] on a stream failure or malformed framing.
    pub(crate) async fn next_data(&mut self) -> Result<Option<Bytes>, FrameError> {
        loop {
            if self.remaining_data > 0 {
                if self.pending.is_empty() && !self.fill().await? {
                    return Err(FrameError::Malformed);
                }
                let n = self.pending.len().min(self.remaining_data as usize);
                self.remaining_data -= n as u64;
                return Ok(Some(self.pending.split_to(n)));
            }
            if self.skip > 0 {
                if self.pending.is_empty() && !self.fill().await? {
                    return Err(FrameError::Malformed);
                }
                let n = self.pending.len().min(self.skip as usize);
                self.skip -= n as u64;
                self.pending.advance(n);
                continue;
            }
            let Some((ty, len, used)) = self.frame_header().await? else {
                return Ok(None);
            };
            self.pending.advance(used);
            if ty == FRAME_DATA {
                self.remaining_data = len;
            } else if len > MAX_CONTROL_FRAME_BYTES {
                return Err(FrameError::Malformed);
            } else {
                self.skip = len;
            }
        }
    }

    /// Parses the next frame header without consuming it: `(type, length,
    /// header bytes)`. `Ok(None)` on a clean end of stream between frames.
    async fn frame_header(&mut self) -> Result<Option<(u64, u64, usize)>, FrameError> {
        loop {
            if let Some((ty, n1)) = decode_varint(&self.pending)
                && let Some((len, n2)) = decode_varint(&self.pending[n1..])
            {
                return Ok(Some((ty, len, n1 + n2)));
            }
            if self.pending.len() >= MAX_FRAME_HEADER_BYTES {
                return Err(FrameError::Malformed);
            }
            if !self.fill().await? {
                return if self.pending.is_empty() {
                    Ok(None)
                } else {
                    Err(FrameError::Malformed)
                };
            }
        }
    }

    /// Appends the next transport chunk to `pending`. `Ok(false)` at the end
    /// of the stream.
    async fn fill(&mut self) -> Result<bool, FrameError> {
        if self.finished {
            return Ok(false);
        }
        match self.recv.read_chunk(CHUNK, true).await {
            Ok(Some(chunk)) => {
                if self.pending.is_empty() {
                    self.pending = chunk.bytes;
                } else {
                    // Only a header split across two chunks lands here, so the
                    // copy is a few bytes.
                    let mut joined =
                        BytesMut::with_capacity(self.pending.len() + chunk.bytes.len());
                    joined.extend_from_slice(&self.pending);
                    joined.extend_from_slice(&chunk.bytes);
                    self.pending = joined.freeze();
                }
                Ok(true)
            }
            Ok(None) => {
                self.finished = true;
                Ok(false)
            }
            Err(_) => Err(FrameError::Stream),
        }
    }
}

/// The header of a DATA frame carrying `len` payload bytes.
pub(crate) fn data_frame_header(len: usize) -> Bytes {
    let mut out = warrenguard_edge::encode_varint(FRAME_DATA);
    out.extend_from_slice(&warrenguard_edge::encode_varint(len as u64));
    Bytes::from(out)
}
