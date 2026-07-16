//! The shared carrier-socket bypass primitive: how the datapath keeps its own
//! tunnel socket out of the tunnel it installs, per OS.
//!
//! This is a small, zero-dep type shared by BOTH privileged datapaths and their
//! transport: `warrenguard-socket-bypass` (which applies it via `setsockopt`),
//! `warrenguard-route-split` (whose split-default picks it and whose fwmark rule
//! matches it), `warrenguard-transport` (which binds the QUIC socket with it),
//! and the app. It lives here in the always-on, zero-dependency tun-core seam so
//! every one of those crates can name the same type without a dependency cycle.

/// The Warren tunnel socket's firewall mark on Linux. The datapath tags its own
/// QUIC socket with this `SO_MARK`; the paired `ip rule fwmark <mark> lookup
/// main` (installed by `warrenguard-route-split`'s split-default) steers exactly
/// those packets out the physical table, while the split-default capture (in a
/// dedicated table) sends every other flow into the tunnel.
///
/// Keying the tunnel's escape on the socket mark instead of the exit destination
/// is what closes Port Fail / TunnelCrack ServerIP: traffic to the exit IP is no
/// longer special-cased, so a hostile app that dials the exit is captured by the
/// tunnel like anything else, and ONLY the daemon's own socket leaves in the
/// clear.
pub const WARREN_TUNNEL_FWMARK: u32 = 0x7761_7272;

/// How the datapath keeps its own tunnel socket out of the tunnel it installs,
/// per OS. This is the socket-level replacement for the destination-based exit
/// host route: only the socket carrying this bypass egresses the physical link,
/// so no application flow can leak by merely targeting the exit IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketBypass {
    /// Linux: tag the socket with `SO_MARK`, matched by the fwmark `ip rule` and
    /// by the `meta mark` killswitch accept. Family-agnostic.
    Fwmark(u32),
    /// macOS: bind the socket to the physical interface index (`IP_BOUND_IF` /
    /// `IPV6_BOUND_IF`), forcing egress there regardless of the routing table's
    /// `0.0.0.0/1` tunnel capture.
    BoundIf(u32),
    /// Windows: bind the socket to the physical interface index (`IP_UNICAST_IF`
    /// / `IPV6_UNICAST_IF`), same effect as the macOS bind.
    UnicastIf(u32),
}

impl SocketBypass {
    /// The Linux socket firewall mark, if this is the Linux variant. Used by the
    /// routing rule and the killswitch accept so all three agree on one value.
    #[must_use]
    pub fn fwmark(&self) -> Option<u32> {
        match self {
            Self::Fwmark(m) => Some(*m),
            Self::BoundIf(_) | Self::UnicastIf(_) => None,
        }
    }

    /// The physical interface index the socket binds to, if this is an
    /// interface-bind variant (macOS / Windows).
    #[must_use]
    pub fn bound_ifindex(&self) -> Option<u32> {
        match self {
            Self::BoundIf(i) | Self::UnicastIf(i) => Some(*i),
            Self::Fwmark(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_bypass_exposes_the_mark_or_ifindex_per_os() {
        assert_eq!(SocketBypass::Fwmark(0x1234).fwmark(), Some(0x1234));
        assert_eq!(SocketBypass::Fwmark(0x1234).bound_ifindex(), None);
        assert_eq!(SocketBypass::BoundIf(7).bound_ifindex(), Some(7));
        assert_eq!(SocketBypass::BoundIf(7).fwmark(), None);
        assert_eq!(SocketBypass::UnicastIf(9).bound_ifindex(), Some(9));
        assert_eq!(SocketBypass::UnicastIf(9).fwmark(), None);
    }
}
