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

#[cfg(test)]
mod tests {
    use super::*;

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
