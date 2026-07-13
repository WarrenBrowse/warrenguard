//! Abstraction for a device that transports IP packets.
//!
//! The [`PacketDevice`] trait is implemented by:
//! - [`FakeTun`] (in-memory, for tests without sudo).
//! - `RealTun` (wraps `tun-rs` async_tokio).
//!
//! This abstraction lets us test the `TUN <-> QUIC datagrams` pumps
//! without depending on OS privileges. Tests use `FakeTun`; the
//! production binary uses `RealTun`.

use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc;

/// Device transporting IP packets, abstracted over OS details.
pub trait PacketDevice: Send + Sync + 'static {
    /// Receives the next inbound IP packet (towards the local side).
    ///
    /// # Errors
    ///
    /// Device closed or OS error.
    fn recv(&self) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send;

    /// Sends an outbound IP packet (towards the network).
    ///
    /// # Errors
    ///
    /// Device closed, packet larger than the MTU, or OS error.
    fn send(&self, packet: &[u8]) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Tries a non-blocking read. Returns:
    /// - `Ok(Some(pkt))` if a packet is immediately available.
    /// - `Ok(None)` if the queue is empty or not ready (kernel-level
    ///   `WouldBlock` equivalent).
    /// - `Err(e)` for a real error (device closed, EIO, etc.).
    ///
    /// **Why**: used by the uplink pump to drain several packets between
    /// scheduler yields, letting Quinn accumulate datagrams in its send
    /// queue and flush them in a single sendmsg GSO multi-segment.
    ///
    /// # Errors
    ///
    /// Device closed or OS error *other than* `WouldBlock` (which becomes
    /// `Ok(None)`).
    fn try_recv(&self) -> std::io::Result<Option<Vec<u8>>>;

    /// Receives up to `max` packets in **a single syscall** (batched I/O).
    /// The caller provides `out`, which is **appended** with the received
    /// packets. Returns the number of packets added to `out`.
    ///
    /// **Why**: on Linux with `IFF_VNET_HDR` enabled
    /// (`tun-rs::DeviceBuilder::offload(true)`), the kernel TUN driver
    /// coalesces N small packets into a single large chunk prefixed by a
    /// `virtio_net_hdr`, then `tun-rs::recv_multiple` re-splits them
    /// into individual packets in userspace. Syscall cost is amortized:
    /// 1 syscall for N packets instead of N.
    ///
    /// **Default impl** (FakeTun, RealTun macOS, Linux fallback without
    /// offload): single `recv()` then push into `out`, returning
    /// `Ok(1)` or propagating the error. Semantics remain "at least 1
    /// packet" like `recv()` - blocks if nothing to read.
    ///
    /// # Errors
    ///
    /// Device closed or OS error.
    fn recv_batch(
        &self,
        max: usize,
        out: &mut Vec<Vec<u8>>,
    ) -> impl Future<Output = std::io::Result<usize>> + Send {
        async move {
            // Default impl: single recv. RealTun Linux overrides with
            // `tun-rs::recv_multiple` when offload is active.
            let _ = max; // unused on the default path
            let pkt = self.recv().await?;
            out.push(pkt);
            Ok(1)
        }
    }

    /// Receives up to `bufs.len()` packets into **pre-allocated** buffers.
    /// Each `bufs[i]` is cleared and filled with one packet. Returns the
    /// number of buffers filled.
    ///
    /// Unlike [`Self::recv_batch`] which pushes new `Vec<u8>` onto `out`,
    /// this method fills CALLER-PROVIDED buffers. Combined with a
    /// [`crate::buffer_pool::BufferPool`], this avoids per-packet
    /// allocations on the hot path: the caller pre-fills `bufs` from
    /// `pool.take()`, and the filled buffers are later returned to the
    /// pool when Quinn drops the corresponding `Bytes`.
    ///
    /// **Default impl**: single `recv()` + copy into `bufs[0]`.
    /// `RealTun` overrides for both Plain (direct `device.recv`) and
    /// Offloaded (`recv_multiple` + copy from scratch) modes.
    fn recv_batch_into(
        &self,
        bufs: &mut [Vec<u8>],
    ) -> impl Future<Output = std::io::Result<usize>> + Send {
        async move {
            if bufs.is_empty() {
                return Ok(0);
            }
            let pkt = self.recv().await?;
            bufs[0].clear();
            bufs[0].extend_from_slice(&pkt);
            Ok(1)
        }
    }

    /// Writes up to `packets.len()` IP packets to the device in as few
    /// syscalls as possible. Returns the number of packets written.
    ///
    /// On Linux with `IFF_VNET_HDR` offload, `RealTun` overrides this
    /// with `tun-rs::send_multiple` + `GROTable`, which coalesces
    /// same-flow packets into a single `writev` call with a
    /// `virtio_net_hdr` GSO prefix. Syscall cost drops from N to ~1.
    ///
    /// **Default impl**: loops over [`Self::send`]. Safe, correct, but
    /// one syscall per packet.
    fn send_batch(
        &self,
        packets: &mut Vec<Vec<u8>>,
    ) -> impl Future<Output = std::io::Result<usize>> + Send {
        async move {
            let count = packets.len();
            for pkt in packets.iter() {
                self.send(pkt).await?;
            }
            Ok(count)
        }
    }

    /// Zero-copy variant of [`Self::send_batch`] that accepts a
    /// `Vec<bytes::Bytes>` batch from the downlink pump.
    ///
    /// The default implementation delegates to [`Self::send`] with a
    /// `Deref<Target=[u8]>` coercion (no extra copy). `RealTun` on Linux
    /// with offload uses `send_multiple` + `GROTable` via a temporary
    /// `Vec<Vec<u8>>` internally; on Plain-mode platforms the default
    /// here is equivalent to the `Vec<Vec<u8>>` variant in cost.
    ///
    /// The key benefit is on the **caller side**: the downlink pump can
    /// keep QUIC-provided `Bytes` handles in the batch without calling
    /// `.to_vec()` on each one, eliminating ~1 280-byte allocation per
    /// inbound packet at 1 Gbps (~97 k alloc/s).
    fn send_batch_bytes(
        &self,
        packets: &mut Vec<bytes::Bytes>,
    ) -> impl Future<Output = std::io::Result<usize>> + Send {
        async move {
            let count = packets.len();
            for pkt in packets.iter() {
                self.send(pkt.as_ref()).await?;
            }
            Ok(count)
        }
    }
}

/// In-memory implementation of the [`PacketDevice`] trait for tests.
///
/// - `inject_inbound(pkt)`: pushes a packet onto the queue read by `recv()`.
/// - `send(pkt)`: appends a packet to `take_outbound()`.
///
/// Cloning shares the queues (Arc), so injections / observations are
/// visible to all copies.
#[derive(Clone)]
pub struct FakeTun {
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    inbound_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeTun {
    /// Build a new empty `FakeTun`.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            inbound_tx: tx,
            inbound_rx: Arc::new(tokio::sync::Mutex::new(rx)),
            outbound: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Inject an IP packet "from the virtual network" that will be
    /// returned by the next `recv()`. Test-only helper.
    pub fn inject_inbound(&self, packet: Vec<u8>) {
        // The receiver keeps the tx alive on Self; a send can only fail
        // if the rx was dropped, which should not happen.
        let _ = self.inbound_tx.send(packet);
    }

    /// Take and clear the outbound queue (packets pushed via `send()`).
    /// Test-only helper.
    #[must_use]
    pub fn take_outbound(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbound.lock().expect("outbound mutex poisoned"))
    }
}

impl Default for FakeTun {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketDevice for FakeTun {
    async fn recv(&self) -> std::io::Result<Vec<u8>> {
        let mut rx = self.inbound_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "FakeTun closed"))
    }

    async fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        self.outbound
            .lock()
            .expect("outbound mutex poisoned")
            .push(packet.to_vec());
        Ok(())
    }

    fn try_recv(&self) -> std::io::Result<Option<Vec<u8>>> {
        // `tokio::sync::Mutex::try_lock` returns Some if the lock is
        // free, None otherwise. On contention (e.g. another task in
        // `recv().await`), we surface `Ok(None)` rather than blocking -
        // batching will retry next round. On the normal test path there
        // is a single consumer so try_lock always succeeds.
        let Ok(mut rx) = self.inbound_rx.try_lock() else {
            return Ok(None);
        };
        match rx.try_recv() {
            Ok(pkt) => Ok(Some(pkt)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "FakeTun closed",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recv_batch_into_fills_preallocated_buffer() {
        let tun = FakeTun::new();
        tun.inject_inbound(vec![0x45, 0, 0, 20]);

        let mut bufs = vec![Vec::with_capacity(64)];
        let cap_before = bufs[0].capacity();
        let n = tun.recv_batch_into(&mut bufs).await.unwrap();

        assert_eq!(n, 1, "must fill exactly 1 buffer");
        assert_eq!(bufs[0], vec![0x45, 0, 0, 20]);
        assert_eq!(
            bufs[0].capacity(),
            cap_before,
            "must reuse the pre-allocated capacity, not reallocate"
        );
    }

    #[tokio::test]
    async fn recv_batch_into_empty_slice_returns_zero() {
        let tun = FakeTun::new();
        tun.inject_inbound(vec![1, 2, 3]);
        let n = tun.recv_batch_into(&mut []).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn recv_batch_into_clears_buffer_before_filling() {
        let tun = FakeTun::new();
        tun.inject_inbound(vec![0x60, 0, 0, 40]);

        let mut bufs = vec![vec![0xFF; 100]]; // pre-filled with garbage
        let n = tun.recv_batch_into(&mut bufs).await.unwrap();

        assert_eq!(n, 1);
        assert_eq!(
            bufs[0],
            vec![0x60, 0, 0, 40],
            "old content must be replaced, not appended"
        );
    }

    #[tokio::test]
    async fn recv_batch_into_preserves_extra_capacity() {
        let tun = FakeTun::new();
        tun.inject_inbound(vec![1, 2]);

        let mut bufs = vec![Vec::with_capacity(2048)];
        tun.recv_batch_into(&mut bufs).await.unwrap();

        assert!(
            bufs[0].capacity() >= 2048,
            "pool-sized buffer must keep its capacity"
        );
        assert_eq!(bufs[0].len(), 2);
    }
}
