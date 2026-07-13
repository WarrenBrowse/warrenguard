//! Privileged per-OS TUN device open: Linux `TUNSETIFF` ioctl, macOS `utun`
//! control socket, Windows `wintun`. EXPERIMENTAL, requires root /
//! `CAP_NET_ADMIN`, and NOT YET validated against a real exit. Compiled only
//! under the `experimental-tun` feature, so the default build pulls none of it.
//!
//! The safe device seam (the [`warrenguard_tun_core::RawTunDevice`] / `TunIo` traits
//! and the [`warrenguard_tun_core::FramedTun`] framing adapter) lives in
//! `warren-tun-core` and is always available; this module only adds the raw
//! kernel device open on top of it.

#[cfg(feature = "experimental-tun")]
use std::io;
#[cfg(feature = "experimental-tun")]
use warrenguard_tun_core::RawTunDevice;

/// Encodes a generic Linux `ioctl` request code (`<asm-generic/ioctl.h>`) for
/// the `_IOW` (userland-writes) direction: `_IOC_WRITE = 1`, 8 direction/type
/// bits, 8 number bits, 14 size bits. This layout is shared by x86, x86_64,
/// arm, aarch64, mips and riscv, but NOT by powerpc/sparc, which use a
/// different direction-bit encoding; do not use this helper for those
/// architectures (see `linux::TUNSETIFF`'s `compile_error!` guard below).
///
/// Pure, no FFI: compiled whenever `linux::TUNSETIFF` needs it, and also under
/// `cfg(test)` so the derivation is unit-tested on any host, independent of
/// the target OS/arch actually opening a TUN device.
#[cfg(any(all(target_os = "linux", feature = "experimental-tun"), test))]
const fn generic_linux_iow_code(ioctl_type: u8, nr: u8, size: u32) -> u32 {
    const IOC_WRITE: u32 = 1;
    const IOC_NRBITS: u32 = 8;
    const IOC_TYPEBITS: u32 = 8;
    const IOC_SIZEBITS: u32 = 14;
    (IOC_WRITE << (IOC_NRBITS + IOC_TYPEBITS + IOC_SIZEBITS))
        | ((ioctl_type as u32) << IOC_NRBITS)
        | (size << (IOC_NRBITS + IOC_TYPEBITS))
        | (nr as u32)
}

/// Opens the kernel TUN device named `name` (EXPERIMENTAL, requires root /
/// `CAP_NET_ADMIN`). Compiled only under the `experimental-tun` feature.
///
/// NOT YET VALIDATED against a real exit: do not rely on this in production.
///
/// # Errors
///
/// An OS error if the device cannot be opened or configured.
#[cfg(all(target_os = "linux", feature = "experimental-tun"))]
pub fn open_tun(name: &str) -> io::Result<linux::TunFd> {
    linux::TunFd::open(name)
}

#[cfg(all(target_os = "linux", feature = "experimental-tun"))]
mod linux {
    use super::RawTunDevice;
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};

    // `TUNSETIFF` is `_IOW('T', 202, int)` (`<linux/if_tun.h>`), encoded per the
    // generic Linux ioctl layout (`_IOC_WRITE = 1`, 8 direction/type/nr bits,
    // 14 size bits) shared by x86, x86_64, arm, aarch64, mips and riscv. That
    // layout does NOT hold on powerpc/sparc, which use a different
    // direction-bit encoding and value set: fail the build there rather than
    // silently derive (or hardcode) a wrong ioctl number.
    #[cfg(any(
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc",
        target_arch = "sparc64",
    ))]
    compile_error!(
        "TUNSETIFF's ioctl number uses a different direction-bit encoding on \
         powerpc/sparc; this crate does not derive it for those architectures. \
         Add the correct encoding before building `experimental-tun` here."
    );
    #[cfg(not(any(
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc",
        target_arch = "sparc64",
    )))]
    const TUNSETIFF: libc::c_ulong =
        super::generic_linux_iow_code(b'T', 202, std::mem::size_of::<libc::c_int>() as u32)
            as libc::c_ulong;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const IFNAMSIZ: usize = 16;

    /// An owned Linux TUN file descriptor.
    #[derive(Debug)]
    pub struct TunFd {
        fd: OwnedFd,
    }

    impl TunFd {
        /// Opens `/dev/net/tun` and binds it to a TUN interface named `name`
        /// (truncated to `IFNAMSIZ - 1`), with no packet-info header (`IFF_NO_PI`,
        /// so reads/writes are bare IP packets, matching [`crate::Framing::Bare`]).
        pub fn open(name: &str) -> io::Result<Self> {
            use std::os::fd::AsRawFd;

            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/net/tun")?;

            // ifreq: char ifr_name[IFNAMSIZ]; then a union whose first field here
            // is the short flags. We zero the struct and fill name + flags.
            let mut ifr = [0u8; IFNAMSIZ + 64];
            let bytes = name.as_bytes();
            let take = bytes.len().min(IFNAMSIZ - 1);
            ifr[..take].copy_from_slice(&bytes[..take]);
            let flags = (IFF_TUN | IFF_NO_PI) as u16;
            ifr[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());

            // SAFETY: `file` is a valid open fd for the lifetime of this call;
            // `ifr` is a correctly sized, fully initialized buffer matching the
            // kernel's `struct ifreq` layout (name array + flags short). `ioctl`
            // reads `IFNAMSIZ + 2` bytes from it and writes back the resolved
            // name into the same buffer; no aliasing, no escape of the pointer.
            let rc = unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    TUNSETIFF,
                    ifr.as_mut_ptr().cast::<libc::c_void>(),
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `OpenOptions::open` succeeded, so the fd is open and owned;
            // `into_raw_fd` transfers ownership exactly once into `OwnedFd`.
            let fd = unsafe { OwnedFd::from_raw_fd(into_raw(file)) };
            Ok(Self { fd })
        }
    }

    fn into_raw(file: std::fs::File) -> std::os::fd::RawFd {
        use std::os::fd::IntoRawFd;
        file.into_raw_fd()
    }

    impl RawTunDevice for TunFd {
        fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::os::fd::AsRawFd;
            // SAFETY: `buf` is a valid, writable slice of `buf.len()` bytes; the
            // fd is open for the lifetime of `self`. `read` writes at most
            // `buf.len()` bytes and returns the count or a negative error.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            use std::os::fd::AsRawFd;
            // SAFETY: `frame` is a valid, readable slice of `frame.len()` bytes;
            // the fd is open for the lifetime of `self`. `write` reads at most
            // `frame.len()` bytes and returns the count or a negative error.
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    frame.as_ptr().cast::<libc::c_void>(),
                    frame.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl std::os::fd::AsRawFd for TunFd {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            std::os::fd::AsRawFd::as_raw_fd(&self.fd)
        }
    }
}

/// Opens a macOS `utun` device (EXPERIMENTAL, requires root). `name` of the form
/// `utunN` requests that unit; anything else lets the kernel pick a free unit.
/// Compiled only under the `experimental-tun` feature.
///
/// NOT YET VALIDATED against a real exit: do not rely on this in production.
///
/// # Errors
///
/// An OS error if the control socket cannot be opened or connected.
#[cfg(all(target_os = "macos", feature = "experimental-tun"))]
pub fn open_tun(name: &str) -> io::Result<macos::Utun> {
    // utun control unit U creates utun(U-1); unit 0 = kernel picks a free one.
    let unit = name
        .strip_prefix("utun")
        .and_then(|n| n.parse::<u32>().ok())
        .map_or(0, |n| n + 1);
    macos::Utun::open(unit)
}

#[cfg(all(target_os = "macos", feature = "experimental-tun"))]
mod macos {
    use super::RawTunDevice;
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};

    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
    // getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME) returns the kernel-assigned
    // interface name (for example "utun7"); not exported by the `libc` crate.
    const UTUN_OPT_IFNAME: libc::c_int = 2;

    /// An owned macOS `utun` control-socket file descriptor.
    #[derive(Debug)]
    pub struct Utun {
        fd: OwnedFd,
    }

    impl Utun {
        /// Opens the `utun` control socket and connects it to `unit` (0 = auto).
        pub fn open(unit: u32) -> io::Result<Self> {
            use std::os::fd::AsRawFd;

            // SAFETY: a plain socket(2) with constant arguments; the return is an
            // fd (>= 0) or -1 on error, checked immediately. No pointers.
            let raw =
                unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `raw` is a fresh, owned, valid socket fd from the call above;
            // ownership is transferred exactly once into `OwnedFd`.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };

            // Resolve the utun control id by name.
            // SAFETY: `ctl_info` is a plain-old-data C struct (a fixed-size char
            // array plus an integer id); an all-zero bit pattern is a valid value
            // for both fields. The name is copied in below and `ctl_id` is filled
            // by the `CTLIOCGINFO` ioctl further down, before either field is read.
            let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
            let name = UTUN_CONTROL_NAME;
            // ctl_name is a fixed C char array; copy the NUL-terminated name in.
            for (dst, src) in info.ctl_name.iter_mut().zip(name.iter()) {
                *dst = *src as libc::c_char;
            }
            // SAFETY: `fd` is valid; `&mut info` is a correctly typed, fully
            // initialized `ctl_info` the ioctl fills in (writes `ctl_id`).
            let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            let addr = libc::sockaddr_ctl {
                sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };
            // SAFETY: `fd` is valid; `&addr` is a fully initialized `sockaddr_ctl`
            // and the length matches its size, as connect(2) requires.
            let rc = unsafe {
                libc::connect(
                    fd.as_raw_fd(),
                    std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd })
        }

        /// Returns the kernel-assigned interface name (for example `utun7`),
        /// needed to install routes against this device.
        pub fn name(&self) -> io::Result<String> {
            use std::os::fd::AsRawFd;
            let mut buf = [0u8; libc::IFNAMSIZ + 1];
            let mut len = buf.len() as libc::socklen_t;
            // SAFETY: `fd` is valid; getsockopt writes at most `len` bytes into
            // `buf` and updates `len`. Level and option are the documented utun
            // control name query.
            let rc = unsafe {
                libc::getsockopt(
                    self.fd.as_raw_fd(),
                    libc::SYSPROTO_CONTROL,
                    UTUN_OPT_IFNAME,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    &mut len,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
        }
    }

    impl RawTunDevice for Utun {
        fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::os::fd::AsRawFd;
            // SAFETY: `buf` is a valid writable slice of `buf.len()` bytes; the fd
            // is open for the lifetime of `self`. read(2) writes at most that many
            // bytes and returns the count or a negative error.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(n as usize)
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            use std::os::fd::AsRawFd;
            // SAFETY: `frame` is a valid readable slice of `frame.len()` bytes; the
            // fd is open for the lifetime of `self`. write(2) reads at most that
            // many bytes and returns the count or a negative error.
            let n = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    frame.as_ptr().cast::<libc::c_void>(),
                    frame.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl std::os::fd::AsRawFd for Utun {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            std::os::fd::AsRawFd::as_raw_fd(&self.fd)
        }
    }
}

/// Opens a Windows Wintun device named `name` (EXPERIMENTAL, requires the
/// `wintun.dll` runtime and Administrator). Compiled only under the
/// `experimental-tun` feature. Cross-compile-checked on the Windows target but
/// NOT run (no Windows host or `wintun.dll` in the dev sandbox), so it is NOT YET
/// validated. Wintun delivers bare IP packets, matching [`Framing::Bare`].
///
/// # Not yet a datapath
///
/// This is only the device layer. There is no Windows routing/killswitch plan
/// (`crate::plan` emits `ip`/`route`/`pfctl`/`nft` argv for Unix only), so
/// nothing in this crate drives this end to end yet. Opening the device here
/// does not produce a working tunnel; a deployer still has to wire up Windows
/// routing, killswitch, and the driver loop on top of this device layer.
///
/// # Errors
///
/// An OS error if `wintun.dll` cannot be loaded, a required export is missing, or
/// the adapter/session cannot be created.
#[cfg(all(target_os = "windows", feature = "experimental-tun"))]
pub fn open_tun(name: &str) -> io::Result<windows::WintunDevice> {
    windows::WintunDevice::open(name)
}

#[cfg(all(target_os = "windows", feature = "experimental-tun"))]
mod windows {
    use super::RawTunDevice;
    use std::ffi::c_void;
    use std::io;

    // Minimal raw bindings (no third-party deps, matching this crate's stance).
    // `cargo check` does not link, so the windows target compile-checks these.
    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *const c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    const ERROR_NO_MORE_ITEMS: u32 = 259;
    /// Ring-buffer capacity (bytes), must be a power of two within Wintun's range.
    const RING_CAPACITY: u32 = 0x40_0000;

    type CreateAdapterFn =
        unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> *mut c_void;
    type CloseAdapterFn = unsafe extern "system" fn(*mut c_void);
    type StartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
    type EndSessionFn = unsafe extern "system" fn(*mut c_void);
    type ReceivePacketFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
    type ReleaseReceiveFn = unsafe extern "system" fn(*mut c_void, *const u8);
    type AllocateSendFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
    type SendPacketFn = unsafe extern "system" fn(*mut c_void, *const u8);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Loads `proc` from `dll`, erroring if the export is missing.
    fn proc(dll: *mut c_void, name: &[u8]) -> io::Result<*const c_void> {
        // SAFETY: `dll` is a valid module handle; `name` is a NUL-terminated
        // ASCII byte string. GetProcAddress returns null on a missing export.
        let p = unsafe { GetProcAddress(dll, name.as_ptr()) };
        if p.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "wintun export not found",
            ));
        }
        Ok(p)
    }

    /// Every Wintun entry point this device needs, resolved as a unit.
    struct Exports {
        create: CreateAdapterFn,
        close_adapter: CloseAdapterFn,
        start: StartSessionFn,
        end_session: EndSessionFn,
        receive: ReceivePacketFn,
        release: ReleaseReceiveFn,
        allocate: AllocateSendFn,
        send: SendPacketFn,
    }

    impl Exports {
        /// Resolves every export up front, before the adapter or session
        /// exists. A missing export discovered only while tearing down a
        /// live adapter/session (the previous ordering) would abort via `?`
        /// mid-cleanup and leak the handle and the DLL; resolving everything
        /// first means the only remaining error paths (adapter/session
        /// creation itself) never need a further `GetProcAddress` lookup.
        fn resolve(dll: *mut c_void) -> io::Result<Self> {
            // SAFETY: each pointer is a valid, non-null export of the matching
            // Wintun ABI (checked by `proc`); transmuting a code pointer to its
            // declared fn type is the documented way to call a GetProcAddress
            // result.
            unsafe {
                Ok(Self {
                    create: std::mem::transmute::<*const c_void, CreateAdapterFn>(proc(
                        dll,
                        b"WintunCreateAdapter\0",
                    )?),
                    close_adapter: std::mem::transmute::<*const c_void, CloseAdapterFn>(proc(
                        dll,
                        b"WintunCloseAdapter\0",
                    )?),
                    start: std::mem::transmute::<*const c_void, StartSessionFn>(proc(
                        dll,
                        b"WintunStartSession\0",
                    )?),
                    end_session: std::mem::transmute::<*const c_void, EndSessionFn>(proc(
                        dll,
                        b"WintunEndSession\0",
                    )?),
                    receive: std::mem::transmute::<*const c_void, ReceivePacketFn>(proc(
                        dll,
                        b"WintunReceivePacket\0",
                    )?),
                    release: std::mem::transmute::<*const c_void, ReleaseReceiveFn>(proc(
                        dll,
                        b"WintunReleaseReceivePacket\0",
                    )?),
                    allocate: std::mem::transmute::<*const c_void, AllocateSendFn>(proc(
                        dll,
                        b"WintunAllocateSendPacket\0",
                    )?),
                    send: std::mem::transmute::<*const c_void, SendPacketFn>(proc(
                        dll,
                        b"WintunSendPacket\0",
                    )?),
                })
            }
        }
    }

    /// An owned Wintun adapter + session and the resolved DLL entry points.
    pub struct WintunDevice {
        dll: *mut c_void,
        adapter: *mut c_void,
        session: *mut c_void,
        receive: ReceivePacketFn,
        release: ReleaseReceiveFn,
        allocate: AllocateSendFn,
        send: SendPacketFn,
        end_session: EndSessionFn,
        close_adapter: CloseAdapterFn,
    }

    impl WintunDevice {
        pub fn open(name: &str) -> io::Result<Self> {
            // SAFETY: `wintun.dll` name is NUL-terminated; null return = not found.
            let dll = unsafe { LoadLibraryW(wide("wintun.dll").as_ptr()) };
            if dll.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "wintun.dll not found",
                ));
            }

            let exports = match Exports::resolve(dll) {
                Ok(exports) => exports,
                Err(e) => {
                    // SAFETY: `dll` was loaded above and no export has been
                    // called yet (only looked up), so freeing it here is the
                    // only cleanup needed.
                    unsafe { FreeLibrary(dll) };
                    return Err(e);
                }
            };

            // SAFETY: `create` is the resolved `WintunCreateAdapter` export;
            // both name arguments are NUL-terminated wide strings that live
            // for the call (their temporaries drop at the end of this
            // statement, after `create` returns).
            let adapter = unsafe {
                (exports.create)(
                    wide(name).as_ptr(),
                    wide("Warren").as_ptr(),
                    std::ptr::null(),
                )
            };
            if adapter.is_null() {
                // SAFETY: reads the calling thread's last error immediately
                // after the failing call above; `dll` is still loaded and no
                // adapter/session was created, so freeing it here is correct.
                let err = unsafe { GetLastError() };
                unsafe { FreeLibrary(dll) };
                return Err(io::Error::from_raw_os_error(err as i32));
            }

            // SAFETY: `start` is the resolved `WintunStartSession` export;
            // `adapter` is the live handle just created above.
            let session = unsafe { (exports.start)(adapter, RING_CAPACITY) };
            if session.is_null() {
                // SAFETY: reads the last error right after the failing call;
                // `close_adapter` was already resolved above (not looked up
                // here), so tearing down the adapter cannot itself fail on a
                // missing export.
                let err = unsafe { GetLastError() };
                unsafe {
                    (exports.close_adapter)(adapter);
                    FreeLibrary(dll);
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }

            Ok(Self {
                dll,
                adapter,
                session,
                receive: exports.receive,
                release: exports.release,
                allocate: exports.allocate,
                send: exports.send,
                end_session: exports.end_session,
                close_adapter: exports.close_adapter,
            })
        }
    }

    impl RawTunDevice for WintunDevice {
        fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut size: u32 = 0;
            // SAFETY: `session` is a live Wintun session; `receive` returns a
            // pointer to `size` bytes owned by the ring (released below) or null.
            let pkt = unsafe { (self.receive)(self.session, &mut size) };
            if pkt.is_null() {
                // No packet ready maps to WouldBlock so the async driver can wait.
                let err = unsafe { GetLastError() };
                return if err == ERROR_NO_MORE_ITEMS {
                    Err(io::Error::new(io::ErrorKind::WouldBlock, "no packet"))
                } else {
                    Err(io::Error::from_raw_os_error(err as i32))
                };
            }
            let size = size as usize;
            // An oversized frame must not be silently truncated into the caller's
            // buffer: that would hand up a corrupt, half-copied IP packet with no
            // signal (the unix read paths return the whole frame and cannot
            // truncate this way). Release the ring slot, then surface it.
            if size > buf.len() {
                // SAFETY: `pkt` is the live ring slot returned above; release it
                // before returning so the ring does not leak the entry.
                unsafe { (self.release)(self.session, pkt) };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tun frame larger than read buffer",
                ));
            }
            // SAFETY: `pkt` points to `size` valid bytes and `size <= buf.len()`.
            unsafe {
                std::ptr::copy_nonoverlapping(pkt, buf.as_mut_ptr(), size);
                (self.release)(self.session, pkt);
            }
            Ok(size)
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            // SAFETY: allocate a send slot of the frame's size; null = ring full.
            let slot = unsafe { (self.allocate)(self.session, frame.len() as u32) };
            if slot.is_null() {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "send ring full"));
            }
            // SAFETY: `slot` points to `frame.len()` writable bytes owned by the
            // ring until `send` hands it to the driver.
            unsafe {
                std::ptr::copy_nonoverlapping(frame.as_ptr(), slot, frame.len());
                (self.send)(self.session, slot);
            }
            Ok(())
        }
    }

    impl Drop for WintunDevice {
        fn drop(&mut self) {
            // SAFETY: tear down in reverse order of creation; all handles are live
            // until here, and the DLL outlives the calls.
            unsafe {
                (self.end_session)(self.session);
                (self.close_adapter)(self.adapter);
                FreeLibrary(self.dll);
            }
        }
    }

    // The handles are owned by this struct and only used behind `&mut self`.
    // SAFETY: Wintun sessions are safe to move between threads; the device is
    // never aliased (it lives in one TunBridge).
    unsafe impl Send for WintunDevice {}
}

/// Sets `O_NONBLOCK` on `fd` so an async driver can multiplex it (Unix). Used by
/// the real-fd datapath loop; the framing/plan logic does not need it.
///
/// # Errors
///
/// The `fcntl` error if the flags cannot be read or set.
#[cfg(all(unix, feature = "experimental-tun"))]
pub fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: `F_GETFL`/`F_SETFL` take no pointer; `fd` is a caller-owned open fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same as above; sets the non-blocking bit on the existing flags.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::generic_linux_iow_code;

    /// Locks in `TUNSETIFF`'s derivation (`linux::TUNSETIFF`) against the
    /// well-known value from `<linux/if_tun.h>` / `<asm-generic/ioctl.h>`, so a
    /// future edit to the bit-shift math (e.g. swapping the `nr`/`type` shift
    /// amounts) fails a fast, host-independent test instead of only surfacing
    /// as an `ioctl(2)` `EINVAL` on a real Linux box.
    #[test]
    fn generic_iow_derives_the_known_tunsetiff_value() {
        // TUNSETIFF = _IOW('T', 202, int): type 'T', request number 202,
        // 4-byte payload (a C `int`).
        assert_eq!(generic_linux_iow_code(b'T', 202, 4), 0x4004_54ca);
    }

    /// A second known-answer vector (a different type/nr/size combination)
    /// so the test cannot pass merely by hardcoding the single TUNSETIFF
    /// output. `TUNSETPERSIST = _IOW('T', 203, int)`.
    #[test]
    fn generic_iow_derives_a_second_known_ioctl_value() {
        assert_eq!(generic_linux_iow_code(b'T', 203, 4), 0x4004_54cb);
    }
}
