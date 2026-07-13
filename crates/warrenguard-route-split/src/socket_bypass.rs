//! Carrier-socket bypass selection for the split-default route-split datapath.
//!
//! When the default route is split into the tunnel (`0.0.0.0/1` +
//! `128.0.0.0/1` onto the TUN, see [`default_route_split`](crate::default_route_split)),
//! the tunnel's OWN QUIC carrier socket must NOT be captured by that split, or
//! the tunnel loops into itself. The historical escape was a `<server_ip>/32`
//! host route, which also let ANY app packet to that IP leak off-tunnel in the
//! clear (the Port Fail / TunnelCrack ServerIP deanonymisation). The fix keys
//! the escape on the SOCKET instead of the destination: tag/bind the carrier
//! socket so it egresses the physical link, and drop the host route.
//!
//! This module only PICKS the per-OS [`SocketBypass`] to hand the transport
//! (e.g. `SupervisorConfig.socket_bypass`); the transport applies it fail-closed
//! via `warrenguard_socket_bypass::apply` BEFORE the socket's first send. It is
//! the route-split (datapath-B) counterpart of the SDK's privileged-TUN
//! datapath, so both datapaths share one socket-keyed escape model rather than
//! each open-coding the per-OS choice.

use warrenguard_tun_core::SocketBypass;

/// The carrier-socket bypass that pairs with the split-default route-split's own
/// escape, keyed on the socket so no `<server_ip>/32` host route is needed
/// (Port Fail / TunnelCrack ServerIP fix). Hand it to the transport so the
/// tunnel's QUIC socket egresses the physical link instead of being captured by
/// the `0.0.0.0/1` + `128.0.0.0/1` TUN split.
///
/// The mechanism matches the split's own escape rule, per OS:
/// - **Linux**: `SO_MARK = WARREN_TUNNEL_FWMARK`, matched by the
///   `fwmark <WARREN_TUNNEL_FWMARK> lookup main` rule the split installs;
///   `phys_ifindex` is unused (the mark, not the interface, keys the escape).
/// - **macOS**: `IP_BOUND_IF` to `phys_ifindex`.
/// - **Windows**: `IP_UNICAST_IF` to `phys_ifindex`.
///
/// `phys_ifindex` is the physical egress interface index, resolved before the
/// tunnel is installed (pass `0` on Linux, where it is ignored).
#[cfg(target_os = "linux")]
#[must_use]
pub fn tunnel_socket_bypass(_phys_ifindex: u32) -> SocketBypass {
    SocketBypass::Fwmark(warrenguard_tun_core::WARREN_TUNNEL_FWMARK)
}

/// See the Linux variant for the contract; macOS binds the socket to the
/// physical interface index via `IP_BOUND_IF`.
#[cfg(target_os = "macos")]
#[must_use]
pub fn tunnel_socket_bypass(phys_ifindex: u32) -> SocketBypass {
    SocketBypass::BoundIf(phys_ifindex)
}

/// See the Linux variant for the contract; Windows binds the socket to the
/// physical interface index via `IP_UNICAST_IF`.
#[cfg(target_os = "windows")]
#[must_use]
pub fn tunnel_socket_bypass(phys_ifindex: u32) -> SocketBypass {
    SocketBypass::UnicastIf(phys_ifindex)
}

/// The desktop split-default route-split guards only run on Linux/macOS/Windows,
/// so this is never reached on other targets; the fwmark form is the
/// family-agnostic default if it ever were, keeping the function total.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[must_use]
pub fn tunnel_socket_bypass(_phys_ifindex: u32) -> SocketBypass {
    SocketBypass::Fwmark(warrenguard_tun_core::WARREN_TUNNEL_FWMARK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_keys_the_escape_on_the_fwmark_not_the_interface() {
        // The Linux split installs `fwmark <WARREN_TUNNEL_FWMARK> lookup main`;
        // the carrier socket MUST carry that exact mark or the rule matches
        // nothing and the socket is captured into the TUN (self-poison). The
        // interface index does not shape the Linux selection.
        assert_eq!(
            tunnel_socket_bypass(0),
            SocketBypass::Fwmark(warrenguard_tun_core::WARREN_TUNNEL_FWMARK)
        );
        assert_eq!(
            tunnel_socket_bypass(7),
            SocketBypass::Fwmark(warrenguard_tun_core::WARREN_TUNNEL_FWMARK),
            "the interface index must not change the Linux fwmark selection"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_binds_the_socket_to_the_physical_interface_index() {
        // macOS has no fwmark; the escape is an IP_BOUND_IF bind to the physical
        // egress interface, so the resolved index is carried through verbatim.
        assert_eq!(tunnel_socket_bypass(7), SocketBypass::BoundIf(7));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_binds_the_socket_via_unicast_if() {
        // Windows keys the escape on IP_UNICAST_IF to the physical interface.
        assert_eq!(tunnel_socket_bypass(9), SocketBypass::UnicastIf(9));
    }
}
