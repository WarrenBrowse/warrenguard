//! Windows split-default routing for the Warren tunnel.
//!
//! Same goal as the Linux / macOS `default_route_split` modules: route every
//! Internet packet through the Warren TUN while keeping the Warren client ->
//! exit UDP socket on the host's original default route, so the tunnel can carry
//! its own control traffic without poisoning itself.
//!
//! ## Strategy
//!
//! Windows has no `ip rule` or pf-style policy routing in user space, so the
//! split is expressed as two global routes in the interface routing table:
//! `0.0.0.0/1` and `128.0.0.0/1`, pointing at the WinTUN adapter. Together
//! their specificity shadows the system default route without touching it.
//!
//! Naively, those two halves also capture the daemon's own outbound QUIC
//! socket to the exit, a routing loop that poisons the tunnel. An earlier
//! revision of this crate exempted it with a `<exit_ip>/32` host route
//! pointing at the physical gateway, captured at install time. That
//! destination-based exception is exactly the Port Fail / TunnelCrack
//! ServerIP deanonymization leak: it exempts the *destination*, so ANY
//! application's traffic to the exit IP escapes the tunnel in the clear, not
//! just the daemon's own carrier socket.
//!
//! This crate now plans ONLY the two `/1` halves; there is no route-level
//! exception, and the plan layer's [`RouteSpec`] cannot express a
//! destination-based one. The daemon's own carrier socket instead escapes at
//! the SOCKET level, keyed on the socket rather than the destination: bind it
//! to the physical interface with `IP_UNICAST_IF` (the sibling
//! `warrenguard_socket_bypass` crate). [`discover_physical_ifindex`] resolves
//! the interface index that bind needs.
//!
//! ## Implementation
//!
//! Route operations go straight through the Win32 IP Helper API
//! (`CreateIpForwardEntry2` / `DeleteIpForwardEntry2` / `GetIpForwardTable2`).
//! The previous port shelled out to `powershell.exe` `New-NetRoute` /
//! `Remove-NetRoute`, which paid ~1.4 s of PowerShell cold-start *per route op*;
//! the connect path runs ~8-10 of them, adding ~10 s of pure process startup.
//! The native API is sub-millisecond per op, matching the macOS / Linux paths.
//!
//! ## Crate layout
//!
//! The routing *plan* (the [`RouteSpec`] list, its ordering and interface
//! scoping) is pure and cross-platform, so it is unit-tested on any host. The
//! privileged executor and the RAII guards are `cfg(windows)`. This crate is the
//! one place in the Warren backend that admits `unsafe`: the workspace forbids
//! it everywhere else, and the IP Helper calls are isolated here with a
//! documented `# Safety` per block (see the `warrenguard-tun-device` precedent).
//!
//! ## Privileges
//!
//! `CreateIpForwardEntry2` / `DeleteIpForwardEntry2` require Administrator (the
//! daemon runs as SYSTEM).

// The IP Helper route calls are unsafe FFI, admitted ONLY on Windows. The
// non-Windows build is the pure routing-plan layer and stays unsafe-free.
#![cfg_attr(target_os = "windows", allow(unsafe_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// This engine's own Warren-branded default WinTUN adapter alias. A generic
/// deployer that names its adapter differently MUST pass that name to
/// [`plan_force_cleanup`] / [`force_cleanup_all`] instead of relying on this
/// constant: those functions have no live tunnel metadata to fall back on, so
/// an alias that does not match the adapter the daemon actually created makes
/// the crash-recovery sweep a silent no-op.
pub const WARREN_TUN_ALIAS: &str = "Warren";

// ── Pure routing plan (testable without the OS) ──────────────────────

/// A single planned route operation. Pure data, so the install/uninstall
/// ordering and scoping can be unit-tested without touching the routing table.
///
/// Every route this crate plans is on-link to the tunnel adapter (no gateway,
/// no destination-based exception): deliberately so, since a gateway-targeted
/// route is exactly the shape of the closed Port Fail leak (see the crate
/// docs). Removal is scoped to `tun_alias` so a co-resident VPN's identical
/// `/1` on its own adapter is never clobbered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    /// Network address of the destination prefix (its host bits are zero).
    pub dest: IpAddr,
    /// Destination prefix length (`1` for the split-default halves).
    pub prefix_len: u8,
    /// WinTUN adapter alias this route pins to, on-link.
    pub tun_alias: String,
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().expect("static literal")
}

/// Plan the IPv4 split-default install for `tun_name`: the `0.0.0.0/1` and
/// `128.0.0.0/1` halves, on-link to the tunnel adapter. No destination-based
/// exception is planned here (see the crate docs): the daemon's own carrier
/// socket escapes the split at the socket level instead
/// ([`discover_physical_ifindex`] + `warrenguard_socket_bypass`).
#[must_use]
pub fn plan_install_v4(tun_name: &str) -> Vec<RouteSpec> {
    vec![
        RouteSpec {
            dest: IpAddr::V4(v4("0.0.0.0")),
            prefix_len: 1,
            tun_alias: tun_name.to_owned(),
        },
        RouteSpec {
            dest: IpAddr::V4(v4("128.0.0.0")),
            prefix_len: 1,
            tun_alias: tun_name.to_owned(),
        },
    ]
}

/// Plan the IPv4 uninstall: remove the two `/1` halves, scoped to `tun_name` so
/// a co-resident VPN's identical `/1` (on its own adapter) is spared. Identical
/// to [`plan_install_v4`]: an add and its matching remove address the exact
/// same routes.
#[must_use]
pub fn plan_uninstall_v4(tun_name: &str) -> Vec<RouteSpec> {
    plan_install_v4(tun_name)
}

/// Plan the IPv6 split-default install (`::/1` + `8000::/1`) via the tunnel
/// alias. No v6 host-route exception: Windows exits are dialed over IPv4, so the
/// v6 split cannot capture the v4 QUIC socket.
#[must_use]
pub fn plan_install_v6(tun_name: &str) -> Vec<RouteSpec> {
    ["::", "8000::"]
        .iter()
        .map(|net| RouteSpec {
            dest: IpAddr::V6(net.parse::<Ipv6Addr>().expect("static literal")),
            prefix_len: 1,
            tun_alias: tun_name.to_owned(),
        })
        .collect()
}

/// Plan the IPv6 uninstall: remove the `::/1` + `8000::/1` halves, scoped to the
/// tunnel alias so a co-resident VPN's v6 split survives.
#[must_use]
pub fn plan_uninstall_v6(tun_name: &str) -> Vec<RouteSpec> {
    plan_install_v6(tun_name)
}

/// Plan the blind teardown of any split-default `/1` routes (v4 + v6) left in
/// the routing table by this process or a crashed predecessor, scoped to
/// `tun_alias`. The sweep has no live tunnel metadata to consult, so the
/// alias is the only way to reclaim only this deployer's own routes: never a
/// co-resident VPN's, and never a silent no-op for a deployer whose adapter
/// is not named [`WARREN_TUN_ALIAS`].
#[must_use]
pub fn plan_force_cleanup(tun_alias: &str) -> Vec<RouteSpec> {
    [
        IpAddr::V4(v4("0.0.0.0")),
        IpAddr::V4(v4("128.0.0.0")),
        IpAddr::V6("::".parse().expect("static")),
        IpAddr::V6("8000::".parse().expect("static")),
    ]
    .into_iter()
    .map(|dest| RouteSpec {
        dest,
        prefix_len: 1,
        tun_alias: tun_alias.to_owned(),
    })
    .collect()
}

/// One IPv4 default-route row, reduced to what the carrier-bypass interface
/// selection needs. Pure data so the selection is unit-testable on any host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultRouteCandidate {
    /// Route-level metric of the `0.0.0.0/0` row (`MIB_IPFORWARD_ROW2.Metric`).
    pub route_metric: u32,
    /// Metric of the interface carrying the row (`MIB_IPINTERFACE_ROW.Metric`).
    pub interface_metric: u32,
    /// Interface index handed to `IP_UNICAST_IF` if this candidate wins.
    pub ifindex: u32,
    /// Media state of the interface (`MIB_IPINTERFACE_ROW.Connected`). A
    /// statically-configured NIC keeps its persistent default route in the
    /// forward table with the cable unplugged, so route presence alone does
    /// not prove the interface can carry a packet.
    pub connected: bool,
}

/// Pick the interface of the best CONNECTED IPv4 default route the way
/// Windows itself ranks routes: by EFFECTIVE metric, the sum of the route
/// metric and the interface metric (lowest wins; earliest wins a tie).
/// Ranking on the route metric alone pins the carrier socket to the wrong
/// NIC whenever the two orderings disagree (e.g. a DHCP default with route
/// metric 0 on a deprioritized interface vs an operator-preferred NIC at
/// route metric 256 + interface metric 10), silently sending the whole
/// tunnel out an interface the host would never route it through.
/// Disconnected candidates are excluded outright: their persistent routes
/// outlive the unplugged cable, and pinning one strands every redial.
#[must_use]
pub fn select_best_default_ifindex(
    candidates: impl IntoIterator<Item = DefaultRouteCandidate>,
) -> Option<u32> {
    candidates
        .into_iter()
        .filter(|c| c.connected)
        .min_by_key(|c| c.route_metric.saturating_add(c.interface_metric))
        .map(|c| c.ifindex)
}

/// Validate a WinTUN adapter alias before it is handed to the routing API.
/// Defensive only (the native API takes the alias as a typed parameter, not a
/// shell argument, so there is no injection surface).
#[cfg(target_os = "windows")]
fn validate_tun_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("tun name is empty");
    }
    if name.len() > 64 {
        anyhow::bail!("tun name too long: {} chars", name.len());
    }
    if name.contains('\0') {
        anyhow::bail!("tun name contains a NUL byte");
    }
    Ok(())
}

// ── Native Win32 IP Helper executor (Windows only) ───────────────────

#[cfg(target_os = "windows")]
mod native {
    use super::{IpAddr, Ipv4Addr, Ipv6Addr, RouteSpec};
    use anyhow::{Result, anyhow};
    use std::ffi::c_void;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
        GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry,
        InitializeIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN,
        SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
    };

    /// Build a `SOCKADDR_INET` for an IP address (port/scope zeroed). For an
    /// on-link route the next hop is the family's unspecified address.
    fn sockaddr_inet(addr: IpAddr) -> SOCKADDR_INET {
        // SAFETY: SOCKADDR_INET is a plain-old-data union; an all-zero bit
        // pattern is a valid (AF_UNSPEC) value that we immediately overwrite.
        let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        match addr {
            IpAddr::V4(addr4) => {
                sa.Ipv4 = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    // `from_ne_bytes` lays the octets out in network byte order
                    // in memory on either endianness.
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(addr4.octets()),
                        },
                    },
                    sin_zero: [0; 8],
                };
            }
            IpAddr::V6(addr6) => {
                sa.Ipv6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: addr6.octets(),
                        },
                    },
                    Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
                };
            }
        }
        sa
    }

    /// Read an `IpAddr` back out of a `SOCKADDR_INET`, dispatching on its family.
    fn read_sockaddr_inet(sa: &SOCKADDR_INET) -> Option<IpAddr> {
        // SAFETY: reading `si_family` (the common first union member) is always
        // valid; the per-family address reads below are gated on it.
        let family = unsafe { sa.si_family };
        if family == AF_INET {
            let raw = unsafe { sa.Ipv4.sin_addr.S_un.S_addr };
            Some(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())))
        } else if family == AF_INET6 {
            let bytes = unsafe { sa.Ipv6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        } else {
            None
        }
    }

    fn family_of(addr: IpAddr) -> ADDRESS_FAMILY {
        match addr {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        }
    }

    /// Resolve a WinTUN adapter alias (e.g. `"Warren"`) to its interface LUID.
    fn alias_to_luid(alias: &str) -> Result<NET_LUID_LH> {
        let mut wide: Vec<u16> = alias.encode_utf16().collect();
        wide.push(0);
        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer valid for the call;
        // `luid` is a live out-param.
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        let rc = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
        if rc != NO_ERROR {
            return Err(anyhow!(
                "ConvertInterfaceAliasToLuid('{alias}') failed: {rc}"
            ));
        }
        Ok(luid)
    }

    /// Populate a freshly initialized `MIB_IPFORWARD_ROW2` from a [`RouteSpec`].
    /// Every route this crate plans is on-link to the tunnel adapter: the next
    /// hop is the unspecified address of the destination's family.
    fn build_row(spec: &RouteSpec) -> Result<MIB_IPFORWARD_ROW2> {
        // SAFETY: zeroed POD, then `InitializeIpForwardEntry2` fills the
        // OS-mandated defaults before we set the destination / next hop.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.DestinationPrefix.Prefix = sockaddr_inet(spec.dest);
        row.DestinationPrefix.PrefixLength = spec.prefix_len;
        row.InterfaceLuid = alias_to_luid(&spec.tun_alias)?;
        let unspec = match spec.dest {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        row.NextHop = sockaddr_inet(unspec);
        Ok(row)
    }

    /// Add one route. Tolerates "already exists" (idempotent install).
    pub(super) fn add_route(spec: &RouteSpec) -> Result<()> {
        let row = build_row(spec)?;
        // SAFETY: `row` is a fully initialized MIB_IPFORWARD_ROW2 passed by
        // const pointer for the duration of the call.
        let rc = unsafe { CreateIpForwardEntry2(&row) };
        if rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS {
            return Ok(());
        }
        Err(anyhow!(
            "CreateIpForwardEntry2({}/{}) failed: {rc}",
            spec.dest,
            spec.prefix_len
        ))
    }

    /// Remove every route matching `spec`'s destination prefix, and (for an alias
    /// target) the same interface, by enumerating the forwarding table.
    ///
    /// Enumeration (rather than deleting a single hand-built row) makes removal
    /// robust to a next-hop / metric that drifted since install. The match is
    /// scoped to the route's tunnel interface so a co-resident VPN's identical
    /// `/1` on another adapter is spared. Best effort: a route already gone is
    /// success.
    pub(super) fn delete_routes_matching(spec: &RouteSpec) -> Result<()> {
        let family = family_of(spec.dest);
        let scope_luid = alias_to_luid(&spec.tun_alias)?;

        let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        // SAFETY: `table` is a live out-param; on NO_ERROR it owns an allocation
        // we free via FreeMibTable below.
        let rc = unsafe { GetIpForwardTable2(family, &mut table) };
        if rc != NO_ERROR {
            return Err(anyhow!("GetIpForwardTable2 failed: {rc}"));
        }
        if table.is_null() {
            return Ok(());
        }

        // Walk the table snapshot, capturing the first hard failure. A plain
        // block (not an early `return`) so the unconditional FreeMibTable below
        // always runs; deleting a kernel route does not mutate this snapshot.
        let mut outcome: Result<()> = Ok(());
        {
            // SAFETY: GetIpForwardTable2 returned NO_ERROR and a non-null table;
            // its `NumEntries` header bounds the trailing `Table[]` flexible
            // array, so the slice is in-bounds.
            let num = unsafe { (*table).NumEntries } as usize;
            let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), num) };
            for row in rows {
                if row.DestinationPrefix.PrefixLength != spec.prefix_len {
                    continue;
                }
                if read_sockaddr_inet(&row.DestinationPrefix.Prefix) != Some(spec.dest) {
                    continue;
                }
                // NET_LUID_LH is a union over a u64; compare the raw value.
                // SAFETY: reading the `Value` member of a POD union is valid.
                if unsafe { row.InterfaceLuid.Value } != unsafe { scope_luid.Value } {
                    continue;
                }
                // SAFETY: `row` points into the live table allocation.
                let rc = unsafe { DeleteIpForwardEntry2(row) };
                if rc != NO_ERROR && rc != ERROR_NOT_FOUND {
                    outcome = Err(anyhow!(
                        "DeleteIpForwardEntry2({}/{}) failed: {rc}",
                        spec.dest,
                        spec.prefix_len
                    ));
                    break;
                }
            }
        }

        // SAFETY: `table` was allocated by GetIpForwardTable2 and is freed once.
        unsafe { FreeMibTable(table as *const c_void) };
        outcome
    }

    /// IPv4 metric and media state of the interface behind `luid`: the
    /// second half of the effective route metric Windows actually routes by,
    /// and whether the interface can carry a packet at all.
    fn interface_state_v4(luid: NET_LUID_LH) -> Result<(u32, bool)> {
        // SAFETY: MIB_IPINTERFACE_ROW is POD; InitializeIpInterfaceEntry
        // resets it to defaults before the keyed fields are set.
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = AF_INET;
        row.InterfaceLuid = luid;
        // SAFETY: `row` is a live, initialized out-param keyed by family+LUID.
        let rc = unsafe { GetIpInterfaceEntry(&mut row) };
        if rc != NO_ERROR {
            return Err(anyhow!("GetIpInterfaceEntry failed: {rc}"));
        }
        Ok((row.Metric, row.Connected))
    }

    /// Discover the interface index of the system's current best physical
    /// IPv4 default route, ranked by EFFECTIVE metric (route metric +
    /// interface metric) exactly like the Windows forwarder itself. This is
    /// the ifindex a caller feeds to `IP_UNICAST_IF` (via
    /// `warrenguard_socket_bypass`) to keep the daemon's own carrier socket
    /// egressing the physical NIC once the split-default `/1` routes capture
    /// everything else; pinning any other interface silently sends the whole
    /// tunnel somewhere the host would never route it (see
    /// `select_best_default_ifindex`).
    pub(super) fn discover_default_route_ifindex() -> Result<u32> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        // SAFETY: live out-param; ownership freed via FreeMibTable below.
        let rc = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
        if rc != NO_ERROR {
            return Err(anyhow!("GetIpForwardTable2(AF_INET) failed: {rc}"));
        }
        if table.is_null() {
            return Err(anyhow!("GetIpForwardTable2 returned an empty table"));
        }

        // Plain block (not an IIFE) so the unconditional FreeMibTable below
        // always runs; collect every default route with a real gateway.
        let mut candidates: Vec<super::DefaultRouteCandidate> = Vec::new();
        {
            // SAFETY: as in `delete_routes_matching`, `NumEntries` bounds the
            // flexible `Table[]` array.
            let num = unsafe { (*table).NumEntries } as usize;
            let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), num) };
            for row in rows {
                if row.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                // SAFETY: reading the common `si_family` union member is valid.
                if unsafe { row.DestinationPrefix.Prefix.si_family } != AF_INET {
                    continue;
                }
                let Some(IpAddr::V4(gw)) = read_sockaddr_inet(&row.NextHop) else {
                    continue;
                };
                // A real default route has a gateway; skip the unspecified next
                // hop (those are interface-scoped artifacts).
                if gw == Ipv4Addr::UNSPECIFIED {
                    continue;
                }
                let (interface_metric, connected) = match interface_state_v4(row.InterfaceLuid) {
                    Ok(state) => state,
                    Err(e) => {
                        // Skip rather than assume 0: a fake floor metric could
                        // crown an interface the host never routes through.
                        tracing::debug!(
                            ifindex = row.InterfaceIndex,
                            error = %e,
                            "skipping default route: no interface state"
                        );
                        continue;
                    }
                };
                candidates.push(super::DefaultRouteCandidate {
                    route_metric: row.Metric,
                    interface_metric,
                    ifindex: row.InterfaceIndex,
                    connected,
                });
            }
        }

        // SAFETY: `table` was allocated by GetIpForwardTable2 and is freed once.
        unsafe { FreeMibTable(table as *const c_void) };

        tracing::debug!(?candidates, "IPv4 default-route candidates");
        let best = super::select_best_default_ifindex(candidates.iter().copied())
            .ok_or_else(|| anyhow!("no IPv4 default route with a gateway found"))?;
        tracing::info!(
            ifindex = best,
            "carrier-socket bypass pinned to the best default-route interface"
        );
        Ok(best)
    }
}

// ── Runtime guards (Windows only) ────────────────────────────────────

/// RAII guard: holds the tunnel alias for cleanup at drop.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct DefaultRouteSplitGuard {
    tun_name: String,
    installed: bool,
}

#[cfg(target_os = "windows")]
impl DefaultRouteSplitGuard {
    /// Install the split-default routing for `tun_name`: the two `/1` halves,
    /// nothing else. The caller is responsible for keeping the daemon's own
    /// carrier socket off this split via the socket-level bypass (see
    /// [`discover_physical_ifindex`] and `warrenguard_socket_bypass`), not this
    /// guard: a route-level exception here would reopen the Port Fail leak.
    ///
    /// # Errors
    ///
    /// - `tun_name` invalid (empty, too long, or contains a NUL).
    /// - Missing privileges (Administrator required).
    /// - A route-add failed outright (other than "already exists").
    ///
    /// `async` with no `.await` in the body: the Win32 IP Helper calls
    /// (`CreateIpForwardEntry2` and friends) are synchronous, sub-millisecond
    /// syscalls, but the signature stays `async fn` to match the Linux/macOS
    /// guards' genuinely-async `install`, so a cross-platform caller (see
    /// `warrenguard-route-split`'s `PlatformNet` trait) can call all three
    /// through one `.await`-ing call site with no per-OS `#[cfg]`.
    pub async fn install(tun_name: &str) -> anyhow::Result<Self> {
        validate_tun_name(tun_name)?;

        for spec in plan_install_v4(tun_name) {
            native::add_route(&spec)
                .map_err(|e| anyhow::anyhow!("add route {}/{}: {e}", spec.dest, spec.prefix_len))?;
        }

        tracing::info!(
            tun = tun_name,
            "Warren default-route split installed (Windows)"
        );

        Ok(Self {
            tun_name: tun_name.to_owned(),
            installed: true,
        })
    }

    /// Remove every route we installed. Idempotent.
    ///
    /// `async` with no `.await` in the body, for the same cross-platform
    /// facade parity as [`Self::install`].
    pub async fn uninstall(mut self) -> anyhow::Result<()> {
        for spec in plan_uninstall_v4(&self.tun_name) {
            if let Err(e) = native::delete_routes_matching(&spec) {
                tracing::warn!(error = %e, dest = %spec.dest, "default-route split cleanup failed (non-fatal)");
            }
        }
        self.installed = false;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for DefaultRouteSplitGuard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // uninstall() was never awaited (panic, task abort, early return). A
        // leaked /1 split blackholes egress for the rest of the session, so
        // remove the routes here. The native delete is a synchronous syscall, so
        // unlike the old PowerShell teardown there is nothing to block on.
        tracing::warn!(
            tun = %self.tun_name,
            "DefaultRouteSplitGuard dropped without explicit uninstall; removing routes"
        );
        for spec in plan_uninstall_v4(&self.tun_name) {
            let _ = native::delete_routes_matching(&spec);
        }
        self.installed = false;
    }
}

/// RAII guard for the Windows IPv6 split-default routing. Mirrors
/// [`DefaultRouteSplitGuard`] for the v6 family, same `install(Option<Ipv6Addr>,
/// &str)` shape as the Linux/macOS v6 guards so a caller's routing facade
/// stays OS-agnostic.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct DefaultRouteSplitV6Guard {
    tun_name: String,
    installed: bool,
}

#[cfg(target_os = "windows")]
impl DefaultRouteSplitV6Guard {
    /// Install the v6 split-default (`::/1` + `8000::/1`) via the tunnel alias.
    /// `exit_ip_v6` is accepted for facade symmetry; a `Some` value only triggers
    /// a warning, since there is no route-level v6 exception here either (by
    /// design, see the crate docs) and the socket-level `IP_UNICAST_IF` bypass
    /// this crate exposes is IPv4-only so far.
    ///
    /// # Errors
    ///
    /// - `tun_name` invalid.
    /// - Missing privileges (Administrator), or a route-add failure.
    ///
    /// `async` with no `.await` in the body, kept for the same cross-platform
    /// facade parity as [`DefaultRouteSplitGuard::install`].
    pub async fn install(exit_ip_v6: Option<Ipv6Addr>, tun_name: &str) -> anyhow::Result<Self> {
        validate_tun_name(tun_name)?;
        if exit_ip_v6.is_some() {
            tracing::warn!(
                "Warren: v6-dialed exit on Windows uses the plain v6 split with no \
                 exit-socket bypass yet (IPv6 IP_UNICAST_IF is not wired). If the QUIC \
                 transport is IPv6 its carrier socket may be captured by the split; \
                 dial the exit over IPv4 until this lands."
            );
        }
        for spec in plan_install_v6(tun_name) {
            native::add_route(&spec).map_err(|e| {
                anyhow::anyhow!("add v6 route {}/{}: {e}", spec.dest, spec.prefix_len)
            })?;
        }
        tracing::info!(
            tun = tun_name,
            "Warren IPv6 split-default routing installed (Windows)"
        );
        Ok(Self {
            tun_name: tun_name.to_owned(),
            installed: true,
        })
    }

    /// Remove the v6 routes. Idempotent. Best-effort.
    ///
    /// `async` with no `.await` in the body, for the same cross-platform
    /// facade parity as [`DefaultRouteSplitGuard::install`].
    pub async fn uninstall(mut self) -> anyhow::Result<()> {
        for spec in plan_uninstall_v6(&self.tun_name) {
            if let Err(e) = native::delete_routes_matching(&spec) {
                tracing::warn!(error = %e, dest = %spec.dest, "v6 split cleanup failed (non-fatal)");
            }
        }
        self.installed = false;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for DefaultRouteSplitV6Guard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        tracing::warn!(
            "DefaultRouteSplitV6Guard dropped without explicit uninstall; removing v6 routes"
        );
        for spec in plan_uninstall_v6(&self.tun_name) {
            let _ = native::delete_routes_matching(&spec);
        }
        self.installed = false;
    }
}

/// Discover the interface index of the host's current best (lowest-metric)
/// physical IPv4 default route. A Windows caller feeds this to
/// `warrenguard_socket_bypass::apply(&socket, SocketBypass::UnicastIf(ifindex))`
/// so the daemon's own carrier socket keeps egressing the physical NIC once
/// [`DefaultRouteSplitGuard`] plants the `/1` halves that capture every other
/// destination, exit IP included. Re-resolving this after a default-route
/// change (e.g. from a migration watchdog) is how the bypass follows the host
/// onto a new physical interface; unlike the retired host-route exception, a
/// re-bind here only affects the daemon's own socket, never other traffic.
///
/// # Errors
///
/// No IPv4 default route with a gateway is currently present (host offline).
///
/// `async` with no `.await` in the body: `GetIpForwardTable2` /
/// `GetIpInterfaceEntry` are synchronous syscalls, but the signature mirrors
/// the macOS twin of this function (`default_route_split_macos::discover_physical_ifindex`,
/// genuinely async there), so a cross-platform caller needs no per-OS `#[cfg]`.
#[cfg(target_os = "windows")]
pub async fn discover_physical_ifindex() -> anyhow::Result<u32> {
    native::discover_default_route_ifindex()
        .map_err(|e| anyhow::anyhow!("cannot discover physical default-route ifindex: {e}"))
}

/// Blind reclaim of any split-default `/1` routes left in the routing table,
/// even from a crashed predecessor with no surviving guard, scoped to
/// `tun_alias` (the WinTUN adapter name the deployer's own daemon actually
/// created; see [`WARREN_TUN_ALIAS`] for this engine's own default). Best
/// effort and idempotent. Called by the cross-platform `force_route_cleanup()`
/// recovery hook from the tunnel state machine.
#[cfg(target_os = "windows")]
pub fn force_cleanup_all(tun_alias: &str) {
    for spec in plan_force_cleanup(tun_alias) {
        let _ = native::delete_routes_matching(&spec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // --- Port Fail / TunnelCrack ServerIP anti-regression -----------------
    //
    // The former `<exit_ip>/32` host route was a destination-based exception:
    // ANY application traffic to the exit IP rode it out of the tunnel in the
    // clear, not just the daemon's own carrier socket. These tests pin the
    // new contract: `plan_install_v4` never emits a `/32`, never references an
    // exit IP at all (the function no longer even takes one), and plants
    // exactly the two `/1` split-default halves.

    #[test]
    fn install_v4_never_emits_a_32_prefix_or_a_route_to_the_exit_ip() {
        let plan = plan_install_v4("warren0");
        assert!(
            plan.iter().all(|s| s.prefix_len != 32),
            "no /32 route may be planned, the host-route exception is closed: {plan:#?}"
        );
        // `plan_install_v4` takes no exit IP at all (the whole point of the
        // fix), so this also proves no planned route's destination can ever
        // equal one: pick a handful of plausible exit IPs and confirm none of
        // them show up as a `dest`.
        for exit_ip in [ip("192.0.2.10"), ip("203.0.113.7"), ip("198.51.100.1")] {
            assert!(
                plan.iter().all(|s| s.dest != IpAddr::V4(exit_ip)),
                "no route may target an exit IP ({exit_ip}): {plan:#?}"
            );
        }
    }

    #[test]
    fn install_v4_emits_exactly_the_two_split_default_halves_via_the_tun_alias() {
        let plan = plan_install_v4("warren0");
        assert_eq!(
            plan,
            vec![
                RouteSpec {
                    dest: IpAddr::V4(ip("0.0.0.0")),
                    prefix_len: 1,
                    tun_alias: "warren0".to_owned(),
                },
                RouteSpec {
                    dest: IpAddr::V4(ip("128.0.0.0")),
                    prefix_len: 1,
                    tun_alias: "warren0".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn uninstall_v4_removes_exactly_the_two_split_default_halves() {
        let plan = plan_uninstall_v4("warren0");
        assert_eq!(
            plan,
            plan_install_v4("warren0"),
            "uninstall must remove exactly the two halves install planted, nothing else"
        );
    }

    #[test]
    fn install_propagates_tun_name_into_the_split_ops() {
        // Sentinel against a typo that would silently route through the wrong
        // interface (= no traffic flows, hard to debug).
        let plan = plan_install_v4("warren-cli");
        for op in &plan {
            assert_eq!(op.tun_alias, "warren-cli");
        }
    }

    #[test]
    fn v6_install_emits_two_halves_via_the_tun_alias() {
        let plan = plan_install_v6("warren0");
        assert_eq!(plan.len(), 2, "two /1 halves, no v4-style host route");
        assert_eq!(plan[0].dest, IpAddr::V6("::".parse().unwrap()));
        assert_eq!(plan[1].dest, IpAddr::V6("8000::".parse().unwrap()));
        for half in &plan {
            assert_eq!(half.prefix_len, 1);
            assert_eq!(half.tun_alias, "warren0");
            assert!(
                matches!(half.dest, IpAddr::V6(_)),
                "v6 plan must not emit v4 routes"
            );
        }
    }

    // --- carrier-bypass default-route interface selection ------------------

    fn cand(route_metric: u32, interface_metric: u32, ifindex: u32) -> DefaultRouteCandidate {
        DefaultRouteCandidate {
            route_metric,
            interface_metric,
            ifindex,
            connected: true,
        }
    }

    #[test]
    fn best_default_route_ranks_by_effective_metric_not_route_metric_alone() {
        // Shape observed live (2026-07-13, multi-interface Windows host): a
        // DHCP default with route metric 0 rides a deprioritized interface
        // (metric 5000) while the host's preferred NIC holds route metric 256
        // + interface metric 10. Windows routes by the sum, so the bypass
        // must pin the second interface; ranking on the route metric alone
        // nests the tunnel inside whatever the wrong NIC leads to.
        let picked = select_best_default_ifindex([cand(0, 5000, 13), cand(256, 10, 18)]);
        assert_eq!(picked, Some(18));
    }

    #[test]
    fn best_default_route_selection_saturates_instead_of_wrapping() {
        // A u32::MAX interface metric must saturate, not wrap around into an
        // artificially tiny effective metric that steals the pick.
        let picked = select_best_default_ifindex([cand(2, u32::MAX, 1), cand(100, 100, 2)]);
        assert_eq!(picked, Some(2));
    }

    #[test]
    fn best_default_route_selection_is_none_when_no_candidate() {
        assert_eq!(select_best_default_ifindex([]), None);
    }

    #[test]
    fn best_default_route_skips_disconnected_interfaces() {
        // A statically-configured NIC keeps its persistent default route in
        // the forward table with the cable unplugged (observed live,
        // 2026-07-13 flap test): pinning it strands every redial on a dead
        // interface. The best CONNECTED candidate must win instead.
        let unplugged_best = DefaultRouteCandidate {
            connected: false,
            ..cand(256, 10, 18)
        };
        let picked = select_best_default_ifindex([unplugged_best, cand(0, 5000, 13)]);
        assert_eq!(picked, Some(13));
    }

    #[test]
    fn best_default_route_is_none_when_every_interface_is_down() {
        // Fail closed: an offline host cannot carry the tunnel, so the
        // connect must fail rather than pin an unplugged interface.
        let down = DefaultRouteCandidate {
            connected: false,
            ..cand(0, 25, 13)
        };
        assert_eq!(select_best_default_ifindex([down]), None);
    }

    #[test]
    fn force_cleanup_reclaims_the_four_split_halves() {
        let plan = plan_force_cleanup(WARREN_TUN_ALIAS);
        assert_eq!(plan.len(), 4, "v4 + v6 /1 halves");
        let dests: Vec<IpAddr> = plan.iter().map(|s| s.dest).collect();
        assert!(dests.contains(&IpAddr::V4(ip("0.0.0.0"))));
        assert!(dests.contains(&IpAddr::V4(ip("128.0.0.0"))));
        assert!(dests.contains(&IpAddr::V6("::".parse().unwrap())));
        assert!(dests.contains(&IpAddr::V6("8000::".parse().unwrap())));
        for s in &plan {
            assert_eq!(s.prefix_len, 1, "force cleanup only touches the /1 halves");
            assert_eq!(
                s.tun_alias, WARREN_TUN_ALIAS,
                "blind cleanup must be scoped to the Warren interface"
            );
        }
    }

    #[test]
    fn force_cleanup_scopes_to_a_non_warren_alias_instead_of_a_silent_no_op() {
        // A generic deployer names its adapter differently; the sweep must
        // scope to whatever alias it is given, not silently keep sweeping
        // (or failing to sweep) the hardcoded "Warren" name.
        let plan = plan_force_cleanup("acme-tunnel0");
        assert_eq!(plan.len(), 4, "v4 + v6 /1 halves");
        for s in &plan {
            assert_eq!(s.tun_alias, "acme-tunnel0");
        }
    }
}
