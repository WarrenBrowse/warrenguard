//! Detect the outbound local IP towards a given exit endpoint, without
//! emitting any actual network traffic.
//!
//! Used by `main.rs` to bind the Quinn `Endpoint` on a specific source
//! IP instead of the family-default unspecified address. Useful in
//! multi-NIC setups to force the outbound interface (e.g. when the
//! host has both Ethernet and Wi-Fi up and the routing table would
//! otherwise pick the wrong default).
//!
//! The same lookup, run with the datapath's carrier bypass installed
//! ([`detect_local_ip_with_bypass`]), is also how a caller tells a carrier
//! that escaped the tunnel from one being routed back into it: the escape
//! itself leaves no trace a sender can read.
//!
//! ## Mechanism
//!
//! Create a `UdpSocket` bound on the unspecified address of the
//! matching family, then call `connect(exit_addr)`. UDP `connect` does
//! NOT send any packet - it only stores the destination so the kernel
//! can pick the source IP from the routing table. We then read it back
//! via `local_addr()` and return it with port `0` so Quinn can pick a
//! random free port at bind time.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};

/// Pick the local IP the kernel would use to reach `exit_addr`, without
/// emitting any traffic. Returns a `SocketAddr` with port `0` and the
/// same address family as `exit_addr`.
///
/// # Errors
///
/// I/O errors at `UdpSocket::bind` or `connect`, typically when no route
/// to the destination exists (e.g. IPv6-only host asked for an IPv4
/// outbound).
pub fn detect_default_local_ip(exit_addr: SocketAddr) -> io::Result<SocketAddr> {
    detect_local_ip_with_bypass(exit_addr, None)
}

/// [`detect_default_local_ip`] with the datapath's own carrier bypass
/// installed on the probe socket first.
///
/// # Why (a black-holed carrier is not observable any other way)
///
/// The carrier socket's escape from the tunnel it carries (an `IP_BOUND_IF`
/// bind on macOS, a fwmark on Linux, `IP_UNICAST_IF` on Windows) leaves no
/// trace a sender can read: `sendmsg` returns `Ok` whether the packet left the
/// NIC or was swallowed by a route pointing back into the tunnel, and the QUIC
/// stack's own counters climb either way. UDP `connect` performs the same route
/// lookup the send would and emits nothing; `local_addr` then reports the
/// source address the kernel picked for it. Comparing that source against the
/// tunnel's own address answers the question a dead carrier poses and that no
/// counter can: did the escape hold, or is the carrier being routed into the
/// tunnel it carries.
///
/// Faithful to the routing decision, not to the socket: the datapath's carrier
/// is a wildcard-bound socket that re-derives its source per send, so this
/// probes the lookup rather than replaying that socket's history.
///
/// # Errors
///
/// The bind at [`UdpSocket::bind`] or the route lookup at `connect` (typically
/// no route to the destination), plus, when `bypass` is `Some`, its install:
/// **a bypass the kernel refuses fails the probe** rather than reporting an
/// unbypassed source, because a source measured without the bypass answers a
/// different question than the caller asked.
pub fn detect_local_ip_with_bypass(
    dest: SocketAddr,
    bypass: Option<warrenguard_tun_core::SocketBypass>,
) -> io::Result<SocketAddr> {
    let bind: SocketAddr = match dest {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    let sock = UdpSocket::bind(bind)?;
    if let Some(bypass) = bypass {
        warrenguard_socket_bypass::apply(&sock, bypass)?;
    }
    sock.connect(dest)?;
    let mut local = sock.local_addr()?;
    local.set_port(0);
    Ok(local)
}

/// Pick a local IP for the first reachable target in `candidates`. Used
/// when an exit descriptor carries multiple `SocketAddr` (e.g. a
/// dual-stack exit): we try each in order until one yields a
/// non-unspecified local IP.
///
/// # Errors
///
/// Returns the last underlying error if *every* candidate fails. Returns
/// `InvalidInput` if `candidates` is empty.
pub fn detect_default_local_ip_for_any(
    candidates: impl IntoIterator<Item = SocketAddr>,
) -> io::Result<SocketAddr> {
    let mut last_err: Option<io::Error> = None;
    let mut tried = 0usize;
    for cand in candidates {
        tried += 1;
        match detect_default_local_ip(cand) {
            Ok(local) if !local.ip().is_unspecified() => return Ok(local),
            Ok(local) => {
                // `connect` reported success but the kernel left the
                // source unspecified - happens with v6 sockets on hosts
                // without a default v6 route. Skip this candidate, the
                // bind would be useless.
                last_err = Some(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("local_addr for {cand} is unspecified ({local})"),
                ));
            }
            Err(e) => last_err = Some(e),
        }
    }
    if tried == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no candidate exit address provided",
        ));
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("no candidate produced a usable local IP")))
}

/// Convenience wrapper to detect the outbound local IP for a
/// [`WarrenExitAddr`]. Iterates over its direct `Ip` transport entries
/// and returns the first non-unspecified local IP.
///
/// # Errors
///
/// `InvalidInput` if the `WarrenExitAddr` carries no direct IP transport.
/// Otherwise, propagates the last error from [`detect_default_local_ip_for_any`].
pub fn detect_default_local_ip_for_endpoint(
    target: &warrenguard_wire::WarrenExitAddr,
) -> io::Result<SocketAddr> {
    let candidates: Vec<SocketAddr> = target.ip_addrs().collect();
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WarrenExitAddr has no direct IP transport - cannot detect outbound IP",
        ));
    }
    detect_default_local_ip_for_any(candidates)
}

/// Quick predicate: does the given bind address actually pin a single
/// interface? Returns `false` for `0.0.0.0` / `[::]` (unspecified).
/// Used by the binary to log a warning when the user explicitly passes
/// an unspecified `--bind-local-ip`.
#[must_use]
pub fn pins_a_specific_interface(addr: SocketAddr) -> bool {
    let ip: IpAddr = addr.ip();
    !ip.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: a loopback v4 target produces a loopback v4 source. This
    /// proves (a) the function returns *something*, (b) of the right
    /// address family, (c) non-unspecified, (d) port-stripped to 0.
    ///
    /// RED check: if we replace the impl with `Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))`,
    /// this test fails on the non-unspecified assertion.
    #[test]
    fn loopback_v4_target_yields_loopback_v4_source_port_zero() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7000));
        let local = detect_default_local_ip(target).expect("connect to loopback must succeed");
        assert!(
            local.is_ipv4(),
            "v4 target must yield v4 source, got {local}"
        );
        assert!(
            !local.ip().is_unspecified(),
            "must not return unspecified, got {local} - unspecified bind defeats \
             the multi-NIC pinning intent"
        );
        assert_eq!(
            local.port(),
            0,
            "port must be stripped to 0 so Quinn picks a free port"
        );
        assert_eq!(
            local.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "kernel must route loopback -> loopback"
        );
    }

    /// Symmetric IPv6 invariant. Skipped if the host has no v6 route to
    /// `::1` (vanishingly rare - `::1` is always available on a normal
    /// loopback).
    #[test]
    fn loopback_v6_target_yields_loopback_v6_source() {
        let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 7000, 0, 0));
        let local = match detect_default_local_ip(target) {
            Ok(l) => l,
            Err(e) => {
                // No v6 stack at all on this host - rare, accept as a
                // graceful skip rather than a hard fail.
                eprintln!("skip: host has no v6 loopback ({e})");
                return;
            }
        };
        assert!(
            local.is_ipv6(),
            "v6 target must yield v6 source, got {local}"
        );
        assert!(
            !local.ip().is_unspecified(),
            "must not return :: unspecified, got {local}"
        );
        assert_eq!(local.port(), 0, "port must be stripped to 0");
    }

    /// Address-family mismatch impossibility: requesting v4 must never
    /// return v6 and vice versa. Locks the dispatch on `SocketAddr::V4/V6`
    /// at the top of the function.
    #[test]
    fn v4_request_never_returns_v6() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let local = detect_default_local_ip(target).expect("loopback v4 reachable");
        assert!(
            matches!(local, SocketAddr::V4(_)),
            "v4 target must NOT produce v6 source - got {local}"
        );
    }

    /// `detect_default_local_ip_for_any` short-circuits on the first
    /// candidate that yields a usable local. Replace order should not
    /// matter for the localhost case: loopback wins immediately.
    #[test]
    fn for_any_returns_first_usable_candidate() {
        let candidates = vec![
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)),
            // Unreachable sentinel: if the first candidate doesn't short-
            // circuit, the iterator would still produce a usable result,
            // but the test would have been wrong about its precondition.
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2)),
        ];
        let local = detect_default_local_ip_for_any(candidates).expect("at least one works");
        assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    /// Empty candidate list -> `InvalidInput`. Prevents silently picking
    /// the wrong bind IP when the upstream `EndpointAddr` is malformed.
    #[test]
    fn for_any_empty_input_errors() {
        let err = detect_default_local_ip_for_any(std::iter::empty()).expect_err("empty must err");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// A `None` bypass must probe exactly what the plain helper probes:
    /// same source, same family, same stripped port. This is what lets a
    /// caller run the pair (bypassed, unbypassed) and read the DIFFERENCE
    /// as the effect of the bypass rather than of two unrelated code paths.
    #[test]
    fn a_none_bypass_probes_exactly_what_the_plain_helper_probes() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7001));
        assert_eq!(
            detect_local_ip_with_bypass(target, None).expect("loopback v4 reachable"),
            detect_default_local_ip(target).expect("loopback v4 reachable"),
        );
    }

    /// A bypass that cannot be installed must FAIL the probe, never report a
    /// source. Reporting one would answer the unbypassed question while the
    /// caller reads it as the bypassed one, which is the exact confusion the
    /// probe exists to remove.
    ///
    /// macOS only: `IP_BOUND_IF` is the bypass whose install can be refused by
    /// the kernel on a bad index. The Linux fwmark needs `CAP_NET_ADMIN`, so it
    /// would fail here for a reason unrelated to the property under test.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_bypass_the_kernel_refuses_fails_the_probe_instead_of_reporting_a_source() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7002));
        let err = detect_local_ip_with_bypass(
            target,
            Some(warrenguard_tun_core::SocketBypass::BoundIf(u32::MAX)),
        )
        .expect_err("an interface index that cannot exist must fail the bind");
        assert_ne!(
            err.kind(),
            io::ErrorKind::AddrNotAvailable,
            "the failure must come from the refused bind, not from address selection"
        );
    }

    /// `pins_a_specific_interface`: `0.0.0.0` and `[::]` must return
    /// `false` (= reintroduces the leak), every other IP returns `true`.
    #[test]
    fn pins_specific_iface_predicate() {
        assert!(!pins_a_specific_interface(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
        )));
        assert!(!pins_a_specific_interface(SocketAddr::V6(
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)
        )));
        assert!(pins_a_specific_interface(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
        )));
        assert!(pins_a_specific_interface(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 0)
        )));
    }
}
