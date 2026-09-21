//! Which of a relay's published addresses a host can dial, and what to bind.
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
//! The decision is pure and lives HERE, beside the descriptor it reads, because
//! two independent datapaths make it: the engine's own multi-hop client and the
//! SDK's userland transport. Each supplies its own reachability probe (they
//! bind sockets differently, and a probe must carry the same tunnel escape as
//! the dial it predicts), and both get the same answer from [`select`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::RelayDescriptorSigned;

/// What the local routing table says about one candidate address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// The host holds a route for this family: the dial can proceed.
    Routed,
    /// The kernel refused the route outright (`ENETUNREACH` and friends).
    /// Dialing it would fail on every single packet.
    Refused,
    /// The probe could not answer (socket creation failed, the tunnel escape
    /// could not be installed). Never used to eliminate a candidate.
    Unknown,
}

/// The endpoints in dial order: the published primary first, then the second
/// family when there is one. A second address of the SAME family as the
/// primary is dropped: it names no new family, and the only reason this list
/// exists is the family choice.
///
/// Takes the addresses rather than a descriptor so both datapaths can call it:
/// the engine's client holds a [`RelayDescriptorSigned`], a deployer's
/// transport holds whatever its own directory view projected
/// (see [`candidates`] for the descriptor-shaped convenience).
#[must_use]
pub fn candidates_of(primary: SocketAddr, alt: Option<SocketAddr>) -> Vec<SocketAddr> {
    let mut out = vec![primary];
    if let Some(alt) = alt
        && alt.is_ipv6() != primary.is_ipv6()
    {
        out.push(alt);
    }
    out
}

/// [`candidates_of`] for a relay descriptor.
#[must_use]
pub fn candidates(relay: &RelayDescriptorSigned) -> Vec<SocketAddr> {
    candidates_of(relay.endpoint, relay.endpoint_v6)
}

/// The address to bind in order to dial `target`.
///
/// A wildcard bind is moved onto the target's family (binding `0.0.0.0` and
/// sending to an IPv6 peer cannot work); its port is preserved, which for every
/// client is the ephemeral `0`. A bind pinned to a concrete IP is returned
/// untouched: `warren-client` pins its outbound IP deliberately, and silently
/// rebinding it would defeat that.
#[must_use]
pub fn bind_for(requested: SocketAddr, target: SocketAddr) -> SocketAddr {
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

/// The endpoint to dial among `candidates`, or `None` when this host can reach
/// none of them.
///
/// `probe` is injected: each datapath binds its sockets differently, and a
/// probe has to carry the same tunnel escape as the dial it predicts, so the
/// reachability answer belongs to the caller while the decision belongs here.
#[must_use]
pub fn select_from(
    candidates: &[SocketAddr],
    requested_bind: SocketAddr,
    probe: impl Fn(SocketAddr) -> Reachability,
) -> Option<SocketAddr> {
    let eligible: Vec<SocketAddr> = candidates
        .iter()
        .copied()
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

/// [`select_from`] for a relay descriptor.
#[must_use]
pub fn select(
    relay: &RelayDescriptorSigned,
    requested_bind: SocketAddr,
    probe: impl Fn(SocketAddr) -> Reachability,
) -> Option<SocketAddr> {
    select_from(&candidates(relay), requested_bind, probe)
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
    fn the_address_shaped_entry_point_answers_like_the_descriptor_one() {
        // A deployer's own transport holds two addresses, never a descriptor,
        // and must not have to reimplement the decision to use it.
        assert_eq!(
            candidates_of(addr(V4), Some(addr(V6))),
            candidates(&relay(V4, Some(V6)))
        );
        assert_eq!(
            select_from(
                &candidates_of(addr(V4), Some(addr(V6))),
                addr(WILDCARD_V4),
                |t| {
                    if t.is_ipv6() {
                        Reachability::Routed
                    } else {
                        Reachability::Refused
                    }
                }
            ),
            Some(addr(V6))
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
}
