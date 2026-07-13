//! Lock-free-ish buffer pool for the TUN -> QUIC hot path.
//!
//! Each `take()` returns a pre-allocated `Vec<u8>` from the pool (or
//! creates a fresh one if empty). After filling the buffer from a TUN
//! read, the caller converts it to a [`bytes::Bytes`] via
//! [`PooledBuffer::into_bytes`]. When Quinn drops that `Bytes` (after
//! transmitting the datagram), the custom `Drop` impl on the inner
//! [`PooledBuffer`] returns the `Vec<u8>` to the pool for reuse.
//!
//! Net effect: under sustained load the allocator is called O(pool_size)
//! times total instead of O(packets) times. Under light load the pool
//! stays small (no pre-allocation).

use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;

/// Default per-buffer capacity. Matches the maximum IP packet size on a
/// 1280-MTU TUN (the Warren default). Buffers that grow beyond this
/// (e.g. via `recv_multiple` coalescing) keep their grown capacity when
/// recycled. Used by `take()` for fresh allocations when the pool is
/// empty.
const DEFAULT_BUF_CAPACITY: usize = 2048;

/// Maximum number of buffers kept in the pool. Beyond this, returned
/// buffers are dropped to the system allocator to avoid unbounded growth
/// during traffic spikes.
const MAX_POOL_SIZE: usize = 256;

/// Shared pool of reusable `Vec<u8>` buffers.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    buffers: Mutex<Vec<Vec<u8>>>,
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

impl BufferPool {
    /// Creates an empty pool (no pre-allocation).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(PoolInner {
                buffers: Mutex::new(Vec::with_capacity(MAX_POOL_SIZE)),
            }),
        }
    }

    /// Takes a buffer from the pool, or allocates a fresh one.
    #[must_use]
    pub fn take(&self) -> Vec<u8> {
        self.inner
            .buffers
            .lock()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(DEFAULT_BUF_CAPACITY))
    }

    /// Wraps a filled buffer into a [`Bytes`] that will return the
    /// underlying `Vec<u8>` to this pool when dropped.
    #[must_use]
    pub fn wrap(&self, buf: Vec<u8>) -> Bytes {
        Bytes::from_owner(PooledBuffer {
            buf,
            pool: self.inner.clone(),
        })
    }

    /// Returns an unused buffer to the pool without wrapping it in Bytes.
    pub fn return_buf_explicit(&self, buf: Vec<u8>) {
        Self::return_buf(&self.inner, buf);
    }

    fn return_buf(inner: &PoolInner, mut buf: Vec<u8>) {
        buf.clear();
        let mut pool = inner.buffers.lock();
        if pool.len() < MAX_POOL_SIZE {
            pool.push(buf);
        }
    }
}

/// Wrapper that returns the buffer to the pool on drop.
struct PooledBuffer {
    buf: Vec<u8>,
    pool: Arc<PoolInner>,
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        if !buf.is_empty() || buf.capacity() > 0 {
            BufferPool::return_buf(&self.pool, buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_returns_buffer_with_capacity() {
        let pool = BufferPool::new();
        let buf = pool.take();
        assert!(buf.capacity() >= DEFAULT_BUF_CAPACITY);
        assert!(buf.is_empty());
    }

    #[test]
    fn wrap_and_drop_recycles_buffer() {
        let pool = BufferPool::new();
        let mut buf = pool.take();
        buf.extend_from_slice(b"hello");
        let cap_before = buf.capacity();

        let bytes = pool.wrap(buf);
        assert_eq!(&*bytes, b"hello");
        drop(bytes);

        let recycled = pool.take();
        assert!(recycled.is_empty(), "recycled buffer must be cleared");
        assert_eq!(
            recycled.capacity(),
            cap_before,
            "recycled buffer keeps its capacity"
        );
    }

    #[test]
    fn pool_caps_at_max_size() {
        let pool = BufferPool::new();
        for _ in 0..MAX_POOL_SIZE + 50 {
            let mut buf = pool.take();
            buf.extend_from_slice(&[0u8; 100]);
            let bytes = pool.wrap(buf);
            drop(bytes);
        }
        let count = pool.inner.buffers.lock().len();
        assert!(
            count <= MAX_POOL_SIZE,
            "pool size {count} must not exceed {MAX_POOL_SIZE}"
        );
    }

    #[test]
    fn bytes_content_matches_original() {
        let pool = BufferPool::new();
        let mut buf = pool.take();
        let data = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 66, 0, 5, 8, 8, 8, 8,
        ];
        buf.extend_from_slice(&data);
        let bytes = pool.wrap(buf);
        assert_eq!(&*bytes, &data);
    }

    #[test]
    fn concurrent_take_and_return() {
        let pool = BufferPool::new();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let p = pool.clone();
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        let mut buf = p.take();
                        buf.extend_from_slice(&[42u8; 64]);
                        let bytes = p.wrap(buf);
                        assert_eq!(bytes[0], 42);
                        drop(bytes);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread must not panic");
        }
        let count = pool.inner.buffers.lock().len();
        assert!(count <= MAX_POOL_SIZE);
    }
}
