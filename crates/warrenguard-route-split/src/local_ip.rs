//! Detect the outbound local IP towards a given exit endpoint, without
//! emitting any actual network traffic.
//!
//! Used by `main.rs` to bind the Quinn `Endpoint` on a specific source
//! IP instead of the family-default unspecified address. Useful in
//! multi-NIC setups to force the outbound interface (e.g. when the
//! host has both Ethernet and Wi-Fi up and the routing table would
//! otherwise pick the wrong default).
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
    let bind: SocketAddr = match exit_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(exit_addr)?;
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
