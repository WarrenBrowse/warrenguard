//! `PacketDevice` implementation backed by a raw Android VpnService fd.
//!
//! On Android the TUN interface is owned by the `VpnService` system process
//! and surfaces to user-space as a [`ParcelFileDescriptor`]; the application
//! cannot use `tun-rs::DeviceBuilder` (no Android backend in tun-rs 2.8), it
//! must drive read/write directly on the file descriptor handed in via JNI.
//!
//! This module wraps that fd in [`tokio::io::unix::AsyncFd`] for non-blocking
//! async I/O. Read / write syscalls go through the `nix` crate's safe
//! wrappers rather than raw `libc`, to satisfy the workspace
//! `unsafe_code = "forbid"` policy. No virtio_net_hdr / GSO offload -
//! Android's TUN driver does not expose those knobs, so
//! [`PacketDevice::recv_batch`] falls back to the single-`recv` default
//! impl from the trait.
//!
//! [`ParcelFileDescriptor`]: https://developer.android.com/reference/android/os/ParcelFileDescriptor

#![cfg(target_os = "android")]

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::unistd::{read, write};
use tokio::io::unix::AsyncFd;

use warrenguard_transport_core::packet_device::PacketDevice;

/// Maximum IP packet size we accept off the TUN. Sized for IPv6 jumbograms
/// (theoretical 65 535 bytes); Android sets a TUN MTU < 9 000 in practice
/// so this is a generous upper bound.
const TUN_MAX_PACKET: usize = 65535;

/// `PacketDevice` wrapping an Android VpnService TUN file descriptor.
///
/// Caller obtains the fd via `ParcelFileDescriptor.detachFd()` on the Kotlin
/// side and hands it in over JNI. We take ownership through [`OwnedFd`]; the
/// fd is closed when the last clone of this struct is dropped.
///
/// `Clone` is implemented (cheap `Arc` clone) so the same TUN can be
/// shared between the uplink and downlink halves of
/// [`warrenguard_pump::pump_bidirectional`] - the [`PacketDevice`] trait requires
/// `Clone` for that reason. The Arc-wrap pattern mirrors
/// [`warrenguard_transport_core::FakeTun`] and [`crate::RealTun`].
#[derive(Clone)]
pub struct AndroidTun {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl AndroidTun {
    /// Wrap a previously-`detachFd()`-ed Android TUN file descriptor.
    ///
    /// Sets `O_NONBLOCK` on the fd so that read / write syscalls return
    /// `EAGAIN` instead of blocking the thread, which is what [`AsyncFd`]
    /// needs to drive its readiness-based wakeup loop.
    ///
    /// # Errors
    ///
    /// `fcntl(F_GETFL/F_SETFL)` failure (e.g. EBADF if the fd is already
    /// closed), or `AsyncFd::new` registration failure with the tokio
    /// reactor (no current tokio runtime).
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let current = fcntl(fd.as_fd(), FcntlArg::F_GETFL).map_err(errno_to_io)?;
        let mut flags = OFlag::from_bits_truncate(current);
        flags.insert(OFlag::O_NONBLOCK);
        fcntl(fd.as_fd(), FcntlArg::F_SETFL(flags)).map_err(errno_to_io)?;
        Ok(Self {
            fd: Arc::new(AsyncFd::new(fd)?),
        })
    }
}

impl PacketDevice for AndroidTun {
    async fn recv(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut guard = self.fd.readable().await?;
            let mut buf = vec![0u8; TUN_MAX_PACKET];
            let result = guard.try_io(|inner| read_into(inner.get_ref().as_fd(), &mut buf));
            match result {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            let result = guard.try_io(|inner| write_all(inner.get_ref().as_fd(), packet));
            match result {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    fn try_recv(&self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; TUN_MAX_PACKET];
        match read_into(self.fd.get_ref().as_fd(), &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Issue a single `read(2)` into `buf`, returning the number of bytes
/// actually read. Forwards `EAGAIN` / `EWOULDBLOCK` to the caller as
/// `WouldBlock` so [`PacketDevice::try_recv`] can map it back to `Ok(None)`.
fn read_into(fd: std::os::fd::BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    read(fd, buf).map_err(errno_to_io)
}

/// Issue a single `write(2)` of `packet`. The Android TUN driver guarantees
/// atomic packet writes within MTU - short writes here indicate either a
/// closed fd or a packet larger than the MTU configured on the Builder.
fn write_all(fd: std::os::fd::BorrowedFd<'_>, packet: &[u8]) -> io::Result<()> {
    let n = write(fd, packet).map_err(errno_to_io)?;
    if n == packet.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "short write to Android TUN: wanted {} got {}",
                packet.len(),
                n
            ),
        ))
    }
}

/// Map a `nix::errno::Errno` to `std::io::Error`, preserving `WouldBlock`
/// so the [`PacketDevice::try_recv`] semantic round-trips.
fn errno_to_io(errno: Errno) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}
