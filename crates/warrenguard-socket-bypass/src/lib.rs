//! Keep the datapath's own tunnel socket OUT of the tunnel it installs, per OS,
//! at the socket level.
//!
//! # Why
//!
//! A full-tunnel VPN steers every destination into its TUN with a
//! `0.0.0.0/1` + `128.0.0.0/1` split. Its own QUIC carrier socket to the exit
//! must NOT be steered there (that would loop the tunnel into itself), so it has
//! to egress the physical link. The historical desktop escape was a
//! `<exit_ip>/32` host route: correct for the carrier, but it also let ANY
//! application flow to the exit IP leak out of the tunnel in the clear (the
//! Port Fail / TunnelCrack ServerIP deanonymisation).
//!
//! The fix (the WireGuard fwmark model, and TunnelCrack's own recommendation of
//! "everything in the tunnel except the VPN app's own traffic") is to key the
//! escape on the SOCKET, not the destination:
//!
//! - **Linux**: tag the socket with `SO_MARK`; a paired `ip rule fwmark <m>
//!   lookup main` routes just those packets through the physical table.
//! - **macOS**: bind the socket to the physical interface index with
//!   `IP_BOUND_IF` / `IPV6_BOUND_IF`, forcing egress there regardless of the
//!   routing table's tunnel capture.
//! - **Windows**: bind the socket to the physical interface index with
//!   `IP_UNICAST_IF` / `IPV6_UNICAST_IF`, same effect.
//! - **Android** stays on `VpnService.protect` (a JNI callback), wired in the
//!   transport layer; it is not a `setsockopt`, so it is not handled here.
//!
//! This crate is the desktop generalisation of that Android hook. [`apply`] is
//! fail-closed: if the mark/bind cannot be set, it returns an error and the
//! caller MUST NOT let the socket egress (exactly as the Android path refuses to
//! send when `protect` fails).
//!
//! # Unsafe exception
//!
//! There is no safe cross-OS wrapper for `IP_BOUND_IF` / `IP_UNICAST_IF`, so the
//! raw `setsockopt` FFI is unavoidable. The workspace forbids unsafe; this crate
//! downgrades to `deny` (in `Cargo.toml`) and admits unsafe only in the
//! documented per-OS blocks below, mirroring `warrenguard-winroute`.

#![cfg_attr(any(unix, windows), allow(unsafe_code))]

use std::io;

pub use warrenguard_tun_core::SocketBypass;

/// Applies the per-OS [`SocketBypass`] to `sock` so it egresses the physical
/// link instead of the tunnel. Call this on the freshly bound UDP socket BEFORE
/// it sends anything, and treat an error as fail-closed: do not use a socket
/// whose bypass could not be installed (it would leak the carrier, or worse,
/// loop into the tunnel).
///
/// # Errors
///
/// - The `setsockopt` syscall failed (`io::Error::last_os_error`).
/// - The [`SocketBypass`] variant does not match this target OS (e.g. a
///   `Fwmark` on macOS): returned as `Unsupported` rather than silently ignored,
///   so a mis-wired caller fails closed instead of leaking.
pub fn apply(sock: &std::net::UdpSocket, bypass: SocketBypass) -> io::Result<()> {
    match bypass {
        SocketBypass::Fwmark(mark) => apply_fwmark(sock, mark),
        SocketBypass::BoundIf(ifindex) => apply_bound_if(sock, ifindex),
        SocketBypass::UnicastIf(ifindex) => apply_unicast_if(sock, ifindex),
    }
}

/// Error for a bypass variant that this OS cannot honour. Fail-closed: better to
/// refuse the socket than to let it egress without the intended scoping.
fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("socket bypass {what} is not supported on this platform"),
    )
}

// ── Linux: SO_MARK ───────────────────────────────────────────────────

#[cfg(any(target_os = "linux", target_os = "android"))]
fn apply_fwmark(sock: &std::net::UdpSocket, mark: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `sock` owns a valid fd for the duration of the call; `&mark` points
    // at a live `u32` and `SO_MARK` takes a 4-byte integer, so the length is
    // correct. setsockopt does not retain the pointer.
    setsockopt_u32(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_MARK, mark)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn apply_fwmark(_sock: &std::net::UdpSocket, _mark: u32) -> io::Result<()> {
    Err(unsupported("SO_MARK"))
}

// ── macOS / Apple: IP_BOUND_IF / IPV6_BOUND_IF ───────────────────────

#[cfg(target_vendor = "apple")]
fn apply_bound_if(sock: &std::net::UdpSocket, ifindex: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    // Bind the option matching the socket's own family; setting IPV6_BOUND_IF on
    // a v4 socket (or the reverse) is rejected by the kernel.
    let is_v6 = sock.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    let (level, optname) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };
    // SAFETY: valid fd; `&ifindex` is a live `u32` and IP_BOUND_IF/IPV6_BOUND_IF
    // both take a 4-byte interface index. setsockopt copies the value.
    setsockopt_u32(fd, level, optname, ifindex)
}

#[cfg(not(target_vendor = "apple"))]
fn apply_bound_if(_sock: &std::net::UdpSocket, _ifindex: u32) -> io::Result<()> {
    Err(unsupported("IP_BOUND_IF"))
}

// ── Windows: IP_UNICAST_IF / IPV6_UNICAST_IF ─────────────────────────

#[cfg(windows)]
fn apply_unicast_if(sock: &std::net::UdpSocket, ifindex: u32) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
    };
    let socket = sock.as_raw_socket() as usize;
    let is_v6 = sock.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    if is_v6 {
        // IPV6_UNICAST_IF takes the index in HOST byte order.
        setsockopt_u32_win(socket, IPPROTO_IPV6, IPV6_UNICAST_IF, ifindex)
    } else {
        // IP_UNICAST_IF (v4) is the documented Windows gotcha: the interface
        // index must be in NETWORK byte order, unlike every other index option.
        setsockopt_u32_win(socket, IPPROTO_IP, IP_UNICAST_IF, ifindex.to_be())
    }
}

#[cfg(not(windows))]
fn apply_unicast_if(_sock: &std::net::UdpSocket, _ifindex: u32) -> io::Result<()> {
    Err(unsupported("IP_UNICAST_IF"))
}

// ── Raw setsockopt helpers ───────────────────────────────────────────

#[cfg(unix)]
fn setsockopt_u32(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    val: u32,
) -> io::Result<()> {
    // SAFETY: `fd` is a live socket fd owned by the caller's `UdpSocket`, `&val`
    // is a valid pointer to a `u32` living for the call, and `size_of::<u32>()`
    // is the exact option length for these integer options. setsockopt neither
    // stores the pointer nor mutates `val`.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            std::ptr::addr_of!(val).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn setsockopt_u32_win(socket: usize, level: i32, optname: i32, val: u32) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{SOCKET_ERROR, setsockopt};
    let bytes = val.to_ne_bytes();
    // SAFETY: `socket` is a live SOCKET owned by the caller's `UdpSocket`,
    // `bytes` is a 4-byte buffer living for the call, and its length is passed
    // explicitly. setsockopt copies the value and does not retain the pointer.
    let rc = unsafe { setsockopt(socket, level, optname, bytes.as_ptr(), bytes.len() as i32) };
    if rc == SOCKET_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn wrong_os_variant_fails_closed_not_silently_ignored() {
        // A mis-wired caller must get an error, never a silent success that would
        // let the socket egress without the intended scoping.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        #[cfg(target_vendor = "apple")]
        {
            // On macOS a Linux fwmark cannot be honoured.
            let err = apply(&sock, SocketBypass::Fwmark(0x1234)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
            // And a Windows unicast-if cannot either.
            let err = apply(&sock, SocketBypass::UnicastIf(1)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let err = apply(&sock, SocketBypass::BoundIf(1)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }
        #[cfg(windows)]
        {
            // On Windows neither a Linux fwmark nor a macOS bound-if can be
            // honoured; both must fail closed rather than silently no-op
            // (which would leave the socket un-scoped and let it egress
            // through the tunnel it is meant to bypass).
            let err = apply(&sock, SocketBypass::Fwmark(0x1234)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
            let err = apply(&sock, SocketBypass::BoundIf(1)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }
        let _ = &sock;
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn bound_if_binds_a_v4_socket_to_the_loopback_interface() {
        // IP_BOUND_IF is settable unprivileged, so this exercises the real
        // syscall end-to-end on macOS: binding to lo0's index must succeed.
        let lo = std::ffi::CString::new("lo0").unwrap();
        // SAFETY: `lo` is a valid NUL-terminated C string for the call.
        let idx = unsafe { libc::if_nametoindex(lo.as_ptr()) };
        assert!(idx > 0, "lo0 must resolve to an interface index");
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        apply(&sock, SocketBypass::BoundIf(idx)).expect("IP_BOUND_IF to lo0 must succeed");
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn bound_if_binds_a_v6_socket_via_ipv6_bound_if() {
        let lo = std::ffi::CString::new("lo0").unwrap();
        // SAFETY: valid NUL-terminated C string.
        let idx = unsafe { libc::if_nametoindex(lo.as_ptr()) };
        assert!(idx > 0);
        let sock = UdpSocket::bind("[::1]:0").expect("bind v6");
        apply(&sock, SocketBypass::BoundIf(idx)).expect("IPV6_BOUND_IF to lo0 must succeed");
    }

    /// Resolves the loopback interface index for IPv4 via `GetBestInterface`,
    /// the same technique `apply_unicast_if` itself has no need for (it takes
    /// the index as a caller-supplied argument) but which gives the test a
    /// real, live ifindex to bind against, exactly like the macOS tests use
    /// `if_nametoindex("lo0")`.
    #[cfg(windows)]
    fn loopback_ifindex_v4() -> u32 {
        use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
        let mut ifindex: u32 = 0;
        // GetBestInterface wants the destination address in network byte
        // order; on this little-endian target the host-order u32 for
        // 127.0.0.1 must be byte-swapped first, the same gotcha
        // `apply_unicast_if` documents for IP_UNICAST_IF itself.
        let dest = u32::from(std::net::Ipv4Addr::LOCALHOST).to_be();
        // SAFETY: `dest` is a plain network-order IPv4 address (no pointer),
        // and `ifindex` is a live `u32` for GetBestInterface to write into.
        let rc = unsafe { GetBestInterface(dest, &mut ifindex) };
        assert_eq!(rc, 0, "GetBestInterface(127.0.0.1) must succeed");
        ifindex
    }

    /// Same as [`loopback_ifindex_v4`] but for `::1`, via `GetBestInterfaceEx`
    /// (the IPv6-capable counterpart, which takes a generic `SOCKADDR`).
    #[cfg(windows)]
    fn loopback_ifindex_v6() -> u32 {
        use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx;
        use windows_sys::Win32::Networking::WinSock::{
            AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR, SOCKADDR_IN6, SOCKADDR_IN6_0,
        };
        let mut addr6 = [0u8; 16];
        addr6[15] = 1; // ::1
        let dest = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 { Byte: addr6 },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        };
        let mut ifindex: u32 = 0;
        // SAFETY: `dest` is a fully-initialized, live `SOCKADDR_IN6` for the
        // duration of the call; casting `&dest` to the generic `SOCKADDR`
        // pointer `GetBestInterfaceEx` expects is the documented usage
        // (it dispatches on `sin6_family`). `ifindex` is a live `u32`.
        let rc = unsafe {
            GetBestInterfaceEx(std::ptr::addr_of!(dest).cast::<SOCKADDR>(), &mut ifindex)
        };
        assert_eq!(rc, 0, "GetBestInterfaceEx(::1) must succeed");
        ifindex
    }

    #[cfg(windows)]
    #[test]
    fn unicast_if_binds_a_v4_socket_to_the_loopback_interface() {
        // IP_UNICAST_IF is settable unprivileged, so this exercises the real
        // syscall end-to-end on Windows: binding to the loopback interface's
        // index must succeed, byte-order gotcha (`to_be()`) included.
        let idx = loopback_ifindex_v4();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        apply(&sock, SocketBypass::UnicastIf(idx)).expect("IP_UNICAST_IF to loopback must succeed");
    }

    #[cfg(windows)]
    #[test]
    fn unicast_if_binds_a_v6_socket_via_ipv6_unicast_if() {
        let idx = loopback_ifindex_v6();
        let sock = UdpSocket::bind("[::1]:0").expect("bind v6");
        apply(&sock, SocketBypass::UnicastIf(idx))
            .expect("IPV6_UNICAST_IF to loopback must succeed");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn fwmark_requires_privilege_but_reaches_the_syscall() {
        // SO_MARK needs CAP_NET_ADMIN. Unprivileged, the syscall is REACHED and
        // returns EPERM (proving we call it); privileged, it succeeds. Either way
        // it is never a silent no-op.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        match apply(
            &sock,
            SocketBypass::Fwmark(warrenguard_tun_core::WARREN_TUNNEL_FWMARK),
        ) {
            Ok(()) => {}
            Err(e) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EPERM),
                "the only expected failure is EPERM (missing CAP_NET_ADMIN); got {e:?}"
            ),
        }
    }
}
