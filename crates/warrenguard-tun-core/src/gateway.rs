//! Default-gateway discovery: the physical-link gateway the exit carrier route
//! pins to (see [`crate::plan::RouteOp::PinExitToPhysical`]).
//!
//! The PARSING is pure and unit-tested here; running `ip route` to obtain the
//! input is feature-gated (it is a process call, only meaningful with the host's
//! real routing table).

use std::net::IpAddr;

/// Parses the default gateway IP from `ip route show default` output, for
/// example `default via 192.168.1.1 dev eth0 proto dhcp metric 100`. Returns the
/// first `via <ip>` of a `default` route, or `None` if there is none.
#[must_use]
pub fn parse_default_gateway(ip_route_output: &str) -> Option<IpAddr> {
    for line in ip_route_output.lines() {
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("default") {
            continue;
        }
        // Scan for the `via <ip>` pair on this default route.
        let mut prev = "";
        for tok in tokens {
            if prev == "via"
                && let Ok(ip) = tok.parse::<IpAddr>()
            {
                return Some(ip);
            }
            prev = tok;
        }
    }
    None
}

/// Parses the physical default gateway from macOS `netstat -rn` output: the first
/// `default` route whose gateway column is an IP address. Interface-bound default
/// routes (gateway shown as `utunN` or `link#N`, for example an active VPN) are
/// skipped, so the physical next hop is found even behind another tunnel.
#[must_use]
pub fn parse_netstat_default_gateway(netstat_output: &str) -> Option<IpAddr> {
    for line in netstat_output.lines() {
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("default") {
            continue;
        }
        if let Some(gateway) = tokens.next()
            && let Ok(ip) = gateway.parse::<IpAddr>()
        {
            return Some(ip);
        }
    }
    None
}

/// Discovers the host's default gateway by running `ip route show default`
/// (Linux). EXPERIMENTAL, feature-gated (a process call against the live routing
/// table).
///
/// # Errors
///
/// If `ip` cannot be run, or no default route with a gateway is present.
#[cfg(all(feature = "experimental-tun", target_os = "linux"))]
pub fn discover_default_gateway() -> std::io::Result<IpAddr> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("ip route show default failed"));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_default_gateway(&text).ok_or_else(|| std::io::Error::other("no default gateway found"))
}

/// Discovers the host's default gateway by running `route -n get default`
/// (macOS). EXPERIMENTAL, feature-gated.
///
/// # Errors
///
/// If `route` cannot be run, or no default route with a gateway is present.
#[cfg(all(feature = "experimental-tun", target_os = "macos"))]
pub fn discover_default_gateway() -> std::io::Result<IpAddr> {
    // `netstat -rn` (not `route get default`) so the PHYSICAL gateway is found
    // even when another VPN owns the top default route via an interface.
    let out = std::process::Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other("netstat -rn failed"));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_netstat_default_gateway(&text)
        .ok_or_else(|| std::io::Error::other("no physical default gateway found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_a_typical_ipv4_default_route() {
        let out = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n\
                   10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n";
        assert_eq!(
            parse_default_gateway(out),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn parses_an_ipv6_default_route() {
        let out = "default via fe80::1 dev eth0 proto ra metric 1024\n";
        assert_eq!(
            parse_default_gateway(out),
            Some(IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()))
        );
    }

    #[test]
    fn returns_none_when_there_is_no_default_route() {
        let out = "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n";
        assert_eq!(parse_default_gateway(out), None);
    }

    #[test]
    fn macos_netstat_skips_a_vpn_default_and_finds_the_physical_gateway() {
        // utun4 (a VPN) owns the top default; the physical en0 default is next.
        let out = "Routing tables\n\
                   Internet:\n\
                   Destination        Gateway            Flags    Netif\n\
                   default            utun4              UGScg    utun4\n\
                   default            192.168.1.254      UGScIg   en0\n";
        assert_eq!(
            parse_netstat_default_gateway(out),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)))
        );
    }

    #[test]
    fn macos_netstat_none_when_only_interface_bound_defaults() {
        let out = "default            utun4              UGScg    utun4\n";
        assert_eq!(parse_netstat_default_gateway(out), None);
    }

    #[test]
    fn ignores_a_default_route_with_no_via_gateway() {
        // A link-scope default (no gateway) must not yield a bogus address.
        let out = "default dev tun0 scope link\n";
        assert_eq!(parse_default_gateway(out), None);
    }

    #[test]
    fn picks_the_first_default_when_several_exist() {
        let out = "default via 192.168.1.1 dev eth0 metric 100\n\
                   default via 192.168.2.1 dev wlan0 metric 600\n";
        assert_eq!(
            parse_default_gateway(out),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }
}
