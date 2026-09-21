//! Which of a relay's addresses this host can dial, and what to bind for it.
//!
//! A relay publishes one endpoint per address family it binds
//! ([`RelayDescriptorSigned::endpoint`], plus
//! [`RelayDescriptorSigned::endpoint_v6`] when it has a second one). A client
//! network usually carries both families and the choice is free; on a network
//! that carries only one, dialing the wrong one is not slow, it is impossible:
//! `sendmsg` answers `ENETUNREACH` immediately and every retry does the same,
//! which is how an IPv6-only mobile network held a phone offline behind its own
//! kill switch (`incidents/2026-09-20-an-ipv6-only-mobile-network-*`).
//!
//! So the family is decided BEFORE the dial, from the host's own routing
//! table, and the bind follows the address that was chosen:
//!
//! - [`local_route`] asks the kernel whether a route exists, by connecting an
//!   unsent UDP socket. It is a route lookup, not traffic: nothing is emitted.
//!   The socket carries the SAME escape as the dial socket (the Android
//!   `VpnService.protect` hook, the desktop [`SocketBypass`]), so the answer
//!   describes the physical network rather than the tunnel being replaced.
//! - [`select`] walks the candidates in published order and takes the first the
//!   host can reach. An unknown verdict never eliminates a candidate: a probe
//!   that could not answer must not be the reason a dial is refused.
//! - [`bind_for`] moves a WILDCARD bind onto the chosen address's family. A
//!   PINNED bind is never rewritten (`warren-client` pins its outbound IP on
//!   purpose), it only restricts which candidates remain eligible.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

use warrenguard_multihop::RelayDescriptorSigned;
use warrenguard_socket_bypass::SocketBypass;

/// What the local routing table says about one candidate address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reachability {
    /// The host holds a route for this family: the dial can proceed.
    Routed,
    /// The kernel refused the route outright (`ENETUNREACH` and friends).
    /// Dialing it would fail on every single packet.
    Refused,
    /// The probe could not answer (socket creation failed, the tunnel escape
    /// could not be installed). Never used to eliminate a candidate.
    Unknown,
}

/// The relay's endpoints in dial order: the published primary first, then the
/// second family when the descriptor carries one. A second address of the SAME
/// family as the primary is dropped: it names no new family, and the only
/// reason this list exists is the family choice.
pub(crate) fn candidates(relay: &RelayDescriptorSigned) -> Vec<SocketAddr> {
    let mut out = vec![relay.endpoint];
    if let Some(alt) = relay.endpoint_v6
        && alt.is_ipv6() != relay.endpoint.is_ipv6()
    {
        out.push(alt);
    }
    out
}

/// The address to bind in order to dial `target`.
///
/// A wildcard bind is moved onto the target's family (binding `0.0.0.0` and
/// sending to an IPv6 peer cannot work); its port is preserved, which for every
/// client is the ephemeral `0`. A bind pinned to a concrete IP is returned
/// untouched: `warren-client` pins its outbound IP deliberately, and silently
/// rebinding it would defeat that.
pub(crate) fn bind_for(requested: SocketAddr, target: SocketAddr) -> SocketAddr {
    if !requested.ip().is_unspecified() || requested.is_ipv6() == target.is_ipv6() {
        return requested;
    }
    let ip = if target.is_ipv6() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    SocketAddr::new(ip, requested.port())
}

/// Whether `requested` can dial `target` at all: a pinned bind can only reach
/// its own family, a wildcard follows ([`bind_for`]).
fn bind_can_reach(requested: SocketAddr, target: SocketAddr) -> bool {
    requested.ip().is_unspecified() || requested.is_ipv6() == target.is_ipv6()
}

/// The endpoint to dial, or `None` when this host can reach none of them.
///
/// `probe` is injected so the decision is testable without a network; the
/// production caller passes [`local_route`].
pub(crate) fn select(
    relay: &RelayDescriptorSigned,
    requested_bind: SocketAddr,
    probe: impl Fn(SocketAddr) -> Reachability,
) -> Option<SocketAddr> {
    let eligible: Vec<SocketAddr> = candidates(relay)
        .into_iter()
        .filter(|target| bind_can_reach(requested_bind, *target))
        .collect();
    // When every eligible candidate is refused by the kernel this yields
    // `None`: returning the first anyway would reproduce the incident (a
    // doomed dial retried forever), and the caller turns `None` into a typed
    // error instead.
    eligible
        .iter()
        .find(|target| probe(**target) != Reachability::Refused)
        .copied()
}

/// Asks the kernel whether this host holds a route to `target`, by connecting
/// a UDP socket to it. `connect(2)` on a datagram socket performs the route
/// lookup and stores the peer; it emits nothing, so this costs one syscall pair
/// and no packet.
///
/// The probe socket is given the same tunnel escape as the dial socket, so what
/// it measures is the physical network:
/// - on Android the registered `VpnService.protect` hook (inert elsewhere);
/// - on desktop the caller's [`SocketBypass`], when the datapath passed one.
///
/// A failure to install either escape yields [`Reachability::Unknown`] rather than a
/// verdict: an unprotected socket would describe the tunnel's own routes, which
/// is precisely the wrong answer.
pub(crate) fn local_route(target: SocketAddr, bypass: Option<SocketBypass>) -> Reachability {
    let wildcard = bind_for(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        target,
    );
    let Ok(socket) = UdpSocket::bind(wildcard) else {
        return Reachability::Unknown;
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if !crate::socket_protect::protect(socket.as_raw_fd()) {
            return Reachability::Unknown;
        }
    }
    if let Some(bypass) = bypass
        && warrenguard_socket_bypass::apply(&socket, bypass).is_err()
    {
        return Reachability::Unknown;
    }
    match socket.connect(target) {
        Ok(()) => Reachability::Routed,
        Err(err) => match err.kind() {
            std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable => Reachability::Refused,
            _ => Reachability::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(endpoint: &str, endpoint_v6: Option<&str>) -> RelayDescriptorSigned {
        RelayDescriptorSigned {
            relay_id: [0x11; 16],
            relay_ed25519_pubkey: [0x22; 32],
            endpoint: endpoint.parse().expect("static addr parses"),
            endpoint_v6: endpoint_v6.map(|a| a.parse().expect("static addr parses")),
            cover_domain: None,
            tcp_fallback: false,
            signature: [0x33; 64],
        }
    }

    const V4: &str = "192.0.2.10:443";
    const V6: &str = "[2001:db8::10]:443";
    const WILDCARD_V4: &str = "0.0.0.0:0";
    const WILDCARD_V6: &str = "[::]:0";

    fn addr(raw: &str) -> SocketAddr {
        raw.parse().expect("static addr parses")
    }

    #[test]
    fn a_v4_only_descriptor_offers_one_candidate() {
        assert_eq!(candidates(&relay(V4, None)), vec![addr(V4)]);
    }

    #[test]
    fn a_dual_stack_descriptor_offers_the_primary_first() {
        assert_eq!(
            candidates(&relay(V4, Some(V6))),
            vec![addr(V4), addr(V6)],
            "the published primary is dialed first, so a dual-stack host keeps its current path"
        );
    }

    #[test]
    fn a_second_address_of_the_same_family_is_dropped() {
        // It names no new family, and family choice is the only thing the
        // second address exists for.
        assert_eq!(
            candidates(&relay(V4, Some("198.51.100.10:443"))),
            vec![addr(V4)]
        );
    }

    #[test]
    fn a_host_with_ipv4_keeps_dialing_the_primary() {
        let chosen = select(&relay(V4, Some(V6)), addr(WILDCARD_V4), |_| {
            Reachability::Routed
        });
        assert_eq!(chosen, Some(addr(V4)));
    }

    #[test]
    fn a_host_without_ipv4_falls_through_to_the_v6_endpoint() {
        // The incident, in one assertion: no IPv4 route, a v6 endpoint
        // published, so the dial goes there instead of failing forever.
        let chosen = select(&relay(V4, Some(V6)), addr(WILDCARD_V4), |target| {
            if target.is_ipv6() {
                Reachability::Routed
            } else {
                Reachability::Refused
            }
        });
        assert_eq!(chosen, Some(addr(V6)));
    }

    #[test]
    fn a_host_that_can_reach_nothing_selects_nothing() {
        let chosen = select(&relay(V4, Some(V6)), addr(WILDCARD_V4), |_| {
            Reachability::Refused
        });
        assert_eq!(
            chosen, None,
            "a doomed dial must be refused with a typed error, not retried forever"
        );
    }

    #[test]
    fn an_unknown_verdict_never_eliminates_a_candidate() {
        let chosen = select(&relay(V4, None), addr(WILDCARD_V4), |_| {
            Reachability::Unknown
        });
        assert_eq!(
            chosen,
            Some(addr(V4)),
            "a probe that could not answer must not refuse the dial"
        );
    }

    #[test]
    fn a_v4_only_host_with_no_v6_endpoint_selects_nothing() {
        let chosen = select(&relay(V4, None), addr(WILDCARD_V4), |_| {
            Reachability::Refused
        });
        assert_eq!(chosen, None);
    }

    #[test]
    fn a_pinned_bind_only_reaches_its_own_family() {
        // `warren-client` pins its outbound IP; the pin restricts the choice
        // instead of being silently rewritten.
        let pinned = addr("198.51.100.7:0");
        let chosen = select(&relay(V4, Some(V6)), pinned, |target| {
            if target.is_ipv6() {
                Reachability::Routed
            } else {
                Reachability::Refused
            }
        });
        assert_eq!(chosen, None, "a v4-pinned bind cannot dial a v6 endpoint");
    }

    #[test]
    fn a_wildcard_bind_follows_the_chosen_family() {
        assert_eq!(bind_for(addr(WILDCARD_V4), addr(V6)), addr(WILDCARD_V6));
        assert_eq!(bind_for(addr(WILDCARD_V6), addr(V4)), addr(WILDCARD_V4));
    }

    #[test]
    fn a_wildcard_bind_of_the_right_family_is_untouched() {
        assert_eq!(bind_for(addr(WILDCARD_V4), addr(V4)), addr(WILDCARD_V4));
        assert_eq!(bind_for(addr(WILDCARD_V6), addr(V6)), addr(WILDCARD_V6));
    }

    #[test]
    fn a_wildcard_bind_keeps_its_port() {
        assert_eq!(
            bind_for(addr("0.0.0.0:51820"), addr(V6)),
            addr("[::]:51820")
        );
    }

    #[test]
    fn a_pinned_bind_is_never_rewritten() {
        let pinned = addr("198.51.100.7:0");
        assert_eq!(
            bind_for(pinned, addr(V6)),
            pinned,
            "rewriting a deliberate outbound-IP pin would defeat it"
        );
    }

    #[tokio::test]
    async fn the_loopback_route_reads_as_routed() {
        // A real kernel lookup through the production path, no packet:
        // loopback always routes. Serialized with every other test that
        // touches the process-wide protector, since this path calls it.
        #[cfg(unix)]
        let _serial = crate::socket_protect::TEST_PROTECT_LOCK.lock().await;
        assert_eq!(local_route(addr("127.0.0.1:9"), None), Reachability::Routed);
    }
}
