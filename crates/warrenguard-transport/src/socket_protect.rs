//! Android tunnel-socket protection hook.
//!
//! On Android the VPN app's own UDP sockets are, by default, subject to
//! the VPN routes it installs. The Warren client's Quinn socket therefore
//! gets routed into the very TUN it just created (a routing loop), so the
//! QUIC handshake to the exit never leaves the device. `VpnService.protect`
//! is the platform fix: it binds a socket to the underlying physical
//! network so it bypasses the VPN.
//!
//! The socket is created deep inside [`crate::multihop`] (quinn owns it), so
//! the protect call cannot be made from the Android FFI layer directly. A
//! deployer's JNI bridge registers a protector here once per process; the
//! client invokes [`protect`] on every freshly bound endpoint socket before
//! any packet egresses.
//!
//! The hook compiles on every unix host, not just Android: only Android
//! registers a protector, so it is inert elsewhere, and that lets each dial
//! path keep ONE uncfg'd protect call whose fail-closed behaviour is provable
//! on a developer machine and in CI instead of only on a device.

use std::os::fd::RawFd;
use std::sync::{Arc, RwLock};

/// Protects a raw socket fd by routing it onto the underlying physical
/// network (`VpnService.protect`). Returns `true` on success. Set by a
/// deployer's JNI bridge; the JNI implementation attaches the calling
/// thread to the JVM and calls `VpnService.protect(int)`.
pub type SocketProtector = Arc<dyn Fn(RawFd) -> bool + Send + Sync>;

static PROTECTOR: RwLock<Option<SocketProtector>> = RwLock::new(None);

/// Registers the process-wide socket protector. Called once by the
/// deployer's JNI bridge for each tunnel session (the global ref points at
/// the current `VpnService` instance). A single VPN service owns the
/// process, so a global is the right scope.
pub fn set_protector(protector: SocketProtector) {
    *PROTECTOR.write().unwrap_or_else(|p| p.into_inner()) = Some(protector);
}

/// `true` once a protector is registered, i.e. this process is a VpnService
/// whose own sockets need the hook. A dial path consults it to decide whether
/// it must build the socket itself (to hold the fd before connect) or can keep
/// its plain, un-hooked fast path.
pub(crate) fn is_armed() -> bool {
    PROTECTOR
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .is_some()
}

/// Protects `fd` via the registered protector. Returns `true` when no
/// protector is registered (non-VpnService hosts, e.g. the CLI client and
/// tests, where there is no VPN to bypass) so those paths are unaffected.
#[must_use]
pub fn protect(fd: RawFd) -> bool {
    match &*PROTECTOR.read().unwrap_or_else(|p| p.into_inner()) {
        Some(protector) => protector(fd),
        None => true,
    }
}
