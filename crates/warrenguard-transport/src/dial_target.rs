//! This host's reachability probe for a relay candidate, and the dial-time
//! glue around the shared decision in [`warrenguard_multihop::dial`].
//!
//! The probe belongs here rather than beside the decision because it has to
//! carry the SAME tunnel escape as the dial socket it predicts (the Android
//! `VpnService.protect` hook, the desktop [`SocketBypass`]); an unprotected
//! probe would describe the routes of the tunnel being replaced, which is
//! exactly the wrong answer.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use warrenguard_multihop::dial::{Reachability, bind_for};
use warrenguard_socket_bypass::SocketBypass;

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

/// The entry relays this host can dial now, as indices into `candidates` in
/// the caller's order: [`warrenguard_multihop::dial::reachable_entries`] with
/// the same kernel probe, tunnel escape included, as the dial itself uses.
///
/// Pass the entries the client's own policy allows (not the exit, not a
/// drained node, only the pinned entry country when the user pinned one), in
/// its order of preference, with the `bind_addr` and `socket_bypass` the
/// supervisor will dial with; then dial the first index returned. The order
/// is kept, so on a network that routes every family nothing changes.
///
/// # Errors
///
/// [`crate::multihop::MultiHopError::NoReachableEntry`] when the host routes
/// none of them. A pinned entry country is never widened here: the client
/// surfaces this error (and may offer to unpin) instead of moving the user
/// to a country they did not choose.
pub fn reachable_entries<'a>(
    candidates: impl IntoIterator<Item = &'a warrenguard_multihop::RelayDescriptorSigned>,
    bind_addr: SocketAddr,
    socket_bypass: Option<SocketBypass>,
) -> Result<Vec<usize>, crate::multihop::MultiHopError> {
    let chosen = warrenguard_multihop::dial::reachable_entries(candidates, bind_addr, |target| {
        local_route(target, socket_bypass)
    });
    if chosen.is_empty() {
        return Err(crate::multihop::MultiHopError::NoReachableEntry);
    }
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(endpoint: &str) -> warrenguard_multihop::RelayDescriptorSigned {
        warrenguard_multihop::RelayDescriptorSigned {
            relay_id: [0x11; 16],
            relay_ed25519_pubkey: [0x22; 32],
            endpoint: endpoint.parse().expect("static addr parses"),
            endpoint_v6: None,
            cover_domain: None,
            tcp_fallback: false,
            signature: [0x33; 64],
        }
    }

    /// A pinned IPv4 bind reaches no IPv6 address, which stands in for an
    /// IPv4-only network on any test host without touching its routes.
    const PINNED_V4: &str = "127.0.0.1:0";

    #[tokio::test]
    async fn the_engine_probe_offers_only_the_entries_this_host_can_route() {
        #[cfg(unix)]
        let _serial = crate::socket_protect::TEST_PROTECT_LOCK.lock().await;
        let v6_only = relay("[2001:db8::1]:443");
        let loopback = relay("127.0.0.1:9");

        let chosen = reachable_entries(
            [&v6_only, &loopback],
            PINNED_V4.parse().expect("static addr parses"),
            None,
        )
        .expect("the loopback entry is reachable");

        assert_eq!(chosen, vec![1]);
    }

    #[tokio::test]
    async fn no_routable_candidate_is_the_typed_no_reachable_entry() {
        #[cfg(unix)]
        let _serial = crate::socket_protect::TEST_PROTECT_LOCK.lock().await;
        let v6_only = relay("[2001:db8::1]:443");

        let chosen = reachable_entries(
            [&v6_only],
            PINNED_V4.parse().expect("static addr parses"),
            None,
        );

        assert!(
            matches!(
                chosen,
                Err(crate::multihop::MultiHopError::NoReachableEntry)
            ),
            "got {chosen:?}"
        );
    }

    #[tokio::test]
    async fn the_loopback_route_reads_as_routed() {
        // A real kernel lookup through the production path, no packet:
        // loopback always routes. Serialized with every other test that
        // touches the process-wide protector, since this path calls it.
        #[cfg(unix)]
        let _serial = crate::socket_protect::TEST_PROTECT_LOCK.lock().await;
        assert_eq!(
            local_route("127.0.0.1:9".parse().expect("static addr parses"), None),
            Reachability::Routed
        );
    }
}
