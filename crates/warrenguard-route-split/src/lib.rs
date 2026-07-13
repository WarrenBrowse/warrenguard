//! WarrenGuard privileged system-VPN routing: OS-level default-route split,
//! DNS push, IPv6 killswitch and policy routing for the guard-based routing
//! model.

/// Outbound IP detection used to bind the client Quinn `Endpoint` on a
/// specific interface IP instead of the family-default unspecified
/// address. Useful in multi-NIC setups to force the outbound interface
/// (e.g. when the host has both Ethernet and Wi-Fi up and the routing
/// table would otherwise pick the wrong one).
pub mod local_ip;

/// Cross-OS IPv4 CIDR descriptor for the `--bypass-cidr` flag. The
/// runtime support that consumes it lives in the Linux-only
/// [`default_route_split`] module; the type itself stays cross-OS
/// so CLI parsers and library callers can manipulate it on every
/// platform.
pub mod bypass_cidr;

/// Per-OS carrier-socket bypass selection for the split-default datapath. When
/// the default route is split into the TUN, the tunnel's own QUIC socket escapes
/// via a socket mark/bind, not a `<server_ip>/32` host route (Port Fail /
/// TunnelCrack ServerIP fix); this picks the [`SocketBypass`](warrenguard_tun_core::SocketBypass)
/// the transport applies to that socket.
pub mod socket_bypass;

/// Policy routing helpers (shell-out to `ip` + `nft`).
/// Compiles everywhere for unit-testability; only `PolicyRoutingGuard::install`
/// is exercised at runtime on Linux.
pub mod policy_routing;

/// Split-default policy routing - forces all Internet traffic through the TUN
/// while preserving the client→exit UDP socket via an explicit exception.
/// Linux uses `ip rule` + multi-table; macOS / Windows use host-route
/// specificity over global routes.
// Non-gated (like the Windows module) so its pure command builders + planners
// and their tests compile on every host. The runtime exec types shell out to
// `ip`, which only exists on Linux, but they are only ever called on Linux.
pub mod default_route_split;
#[cfg(target_os = "macos")]
pub mod default_route_split_macos;
// Windows module is non-gated so its pure command builders + tests compile
// on every host. The runtime exec types are themselves cfg-gated inside.
pub mod default_route_split_windows;

/// Push a DNS server while the tunnel is up. Without this, the system client
/// typically uses a LAN upstream (systemd-resolved on Linux, networksetup
/// on macOS, Set-DnsClientServerAddress on Windows) which becomes
/// unreachable when the daemon's firewall blocks LAN or when split-default
/// routes render the LAN inaccessible. The tunnel still works for literal
/// IPs but `curl <hostname>` fails.
// Non-gated (like the Windows modules) so the pure file-manipulation
// logic + its tests compile and run on every host; the production
// default paths (/etc/resolv.conf) are only ever used on Linux.
pub mod dns_push;
#[cfg(target_os = "macos")]
pub mod dns_push_macos;
// Windows module is non-gated so its pure command builders + tests compile
// on every host. The runtime exec types are themselves cfg-gated inside.
pub mod dns_push_windows;

/// Cross-OS seam over the default-route split and DNS-push wiring. Collapses
/// the three `#[cfg]` copies of the install/uninstall dispatch in `main.rs`
/// behind a single [`platform_net::current_platform`] selection + a uniform
/// guard, while the per-OS command-building logic stays in the modules above.
pub mod platform_net;

/// IPv6 outbound killswitch. Multi-hop v1 routes only IPv4 through the
/// tunnel; without this guard, AAAA-resolved traffic leaks off-tunnel
/// over the physical interface. Linux nft `table ip6 warren_ipv6_block`
/// with `policy drop` (option B "killswitch IPv6 simple"). Compiles
/// everywhere for unit-testability; only `Ipv6KillswitchGuard::install`
/// is exercised at runtime on Linux.
pub mod ipv6_killswitch;
