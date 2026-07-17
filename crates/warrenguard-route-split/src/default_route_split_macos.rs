//! macOS port of split-default routing.
//!
//! Same goal as the Linux module: push every Internet packet through
//! the Warren TUN while keeping the Warren client -> exit UDP socket
//! on the host's original default route, so the tunnel can carry its
//! own control traffic.
//!
//! macOS has no `ip rule` / multi-table policy routing, so the split is
//! expressed as two global `/1` routes whose longer prefix shadows the
//! system default without replacing it:
//!
//!   `0.0.0.0/1 -interface <tun>` and `128.0.0.0/1 -interface <tun>`
//!   cover all of IPv4 and win over `default` / `0.0.0.0/0`.
//!
//! The Warren client -> exit carrier socket is kept off the tunnel by a
//! **socket-keyed** bypass, not a destination route: the QUIC socket
//! carries the physical interface's `IP_BOUND_IF` (set in the transport
//! layer, see `warrenguard_socket_bypass` and
//! [`crate::socket_bypass::tunnel_socket_bypass`]), so the `/1` split may
//! capture the exit IP into the tunnel like any other destination without
//! poisoning the carrier. Keying the escape on the socket rather than on
//! the `<exit_ip>` destination is the Port Fail / TunnelCrack ServerIP fix:
//! an application dialing the exit IP is tunnelled, not leaked. No
//! `<exit_ip>/32` host route is emitted (contrast the historical
//! destination-keyed model); [`discover_physical_ifindex`] resolves the
//! interface index the caller binds the carrier socket to.
//!
//! ## Privileges
//!
//! `route` requires root on macOS. The binary must be launched with
//! `sudo`.
//!
//! ## Cross-cutting note
//!
//! macOS's `route` does not implement atomic install semantics: each
//! command lands one at a time. The uninstall order mirrors the install.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{LazyLock, Mutex, PoisonError};

use anyhow::{Context, Result, anyhow};
use tokio::process::Command;
use warrenguard_killswitch_os::validate_tun_name as ks_validate_tun_name;

/// The split-default `/1` pair. A leaked split that outlives its guard
/// blackholes the *next* connect's relay dial (the relay is not in the
/// host-route exception), so the tunnel cannot recover - the registry +
/// fail-safe `Drop` below exist to make that unreachable.
/// Representative host inside each split-default `/1` half, used to probe
/// whether the half currently egresses through a tunnel before reclaiming
/// a registry-less stale split (see [`force_cleanup_all`]).
const SPLIT_NET_PROBES: [(&str, &str); 2] =
    [("0.0.0.0/1", "1.0.0.0"), ("128.0.0.0/1", "200.0.0.0")];

/// Exit IP → TUN interface of every split this process installed.
/// Authoritative for in-process teardown; [`force_cleanup_all`] and the
/// guard `Drop` consult it so a split can never survive its guard. The
/// TUN name is what lets the reclaim sweep tell a Warren-owned `/1` from a
/// co-resident VPN's live one (see [`reclaim_decision`]).
static INSTALLED_SPLITS: LazyLock<Mutex<HashMap<Ipv4Addr, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn registry_insert(exit_ip: Ipv4Addr, tun_name: &str) {
    INSTALLED_SPLITS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(exit_ip, tun_name.to_owned());
}

fn registry_remove(exit_ip: Ipv4Addr) {
    INSTALLED_SPLITS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&exit_ip);
}

/// Snapshot of the TUN names Warren currently owns, for the reclaim sweep.
fn owned_tuns() -> HashSet<String> {
    INSTALLED_SPLITS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .values()
        .cloned()
        .collect()
}

/// TUN interface → optional v6 exit host-exception of every IPv6 split this
/// process installed. The v6 twin of [`INSTALLED_SPLITS`]: without it a
/// leaked `::/1`+`8000::/1` pair (a `Drop` that never ran under an async
/// abort, or a crashed predecessor) has NO out-of-process backstop and
/// blackholes all native IPv6 until reboot, which kills DNS on a network
/// whose only resolver is reached over IPv6 (RA/RDNSS). Keyed by TUN so the
/// reclaim sweep can tell a Warren-owned half from a co-resident VPN's.
static INSTALLED_SPLITS_V6: LazyLock<Mutex<HashMap<String, Option<Ipv6Addr>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn registry_insert_v6(tun_name: &str, exit_ip_v6: Option<Ipv6Addr>) {
    INSTALLED_SPLITS_V6
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(tun_name.to_owned(), exit_ip_v6);
}

fn registry_remove_v6(tun_name: &str) {
    INSTALLED_SPLITS_V6
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(tun_name);
}

/// Snapshot of the TUN names Warren owns an IPv6 split on, for the v6 sweep.
fn owned_tuns_v6() -> HashSet<String> {
    INSTALLED_SPLITS_V6
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .keys()
        .cloned()
        .collect()
}

/// Upper bound on a single synchronous `route`/`ifconfig` invocation in the
/// `Drop` / recovery paths. A wedged routing-socket call must never hang
/// teardown indefinitely (parity with the Linux/Windows bounded sync helpers).
/// On timeout the child is killed and the call reports failure.
const SYNC_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawn `program args...`, capture its output, and wait at most
/// [`SYNC_CLEANUP_TIMEOUT`] for it. Returns `None` on spawn failure or timeout
/// (the child is killed). Best-effort and panic-free, safe to call from `Drop`.
fn run_blocking_bounded(program: &str, args: &[&str]) -> Option<std::process::Output> {
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + SYNC_CLEANUP_TIMEOUT;
    // Micro-backoff poll: `route`/`ifconfig` typically exit in a few ms
    // and this runner is called several times per tunnel state
    // transition, so a coarse fixed period would multiply into ~100+ ms
    // of pure polling on every connect/disconnect.
    let mut poll = std::time::Duration::from_millis(1);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) => {}
            Err(_) => return None,
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(poll);
        poll = (poll * 2).min(std::time::Duration::from_millis(4));
    }
}

/// Synchronously delete the per-exit host-route exception. Exact (keyed
/// by `exit_ip`) so it never touches another product's routes. Best-effort
/// and panic-free - it can run inside `Drop`.
fn delete_host_route_blocking(exit_ip: Ipv4Addr) {
    let _ = run_blocking_bounded("route", &["delete", "-host", &exit_ip.to_string()]);
}

/// Interface `probe`'s route currently egresses through, via
/// `route -n get`. `None` when the probe does not resolve.
fn route_iface(probe: &str) -> Option<String> {
    let out = run_blocking_bounded("route", &["-n", "get", probe])?;
    out.status
        .success()
        .then(|| parse_default_iface(&String::from_utf8_lossy(&out.stdout)))
        .flatten()
}

/// IPv6 twin of [`route_iface`]: the interface `probe` egresses through, via
/// `route -n get -inet6`. The `-inet6` flag is load-bearing - without it the
/// query hits the v4 table and never sees a leaked `::/1` half.
fn route_iface_v6(probe: &str) -> Option<String> {
    let out = run_blocking_bounded("route", &["-n", "get", "-inet6", probe])?;
    out.status
        .success()
        .then(|| parse_default_iface(&String::from_utf8_lossy(&out.stdout)))
        .flatten()
}

/// Whether `name` is currently a live interface on the host.
fn iface_exists(name: &str) -> bool {
    run_blocking_bounded("ifconfig", &[name])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pure ownership decision for a split-default `/1` half, given the interface
/// it currently routes through.
///
/// A half is reclaimable iff it egresses through a tunnel that is either
/// Warren-owned (`owned`) or no longer present (`iface_present == false`,
/// i.e. a split a crashed process left dangling). A physical-NIC route, an
/// unresolved probe, or a **live foreign tunnel** (a co-resident VPN) is
/// never reclaimed - that is the fix for tearing down another VPN's split.
fn reclaim_decision(iface: Option<&str>, owned: &HashSet<String>, iface_present: bool) -> bool {
    match iface {
        Some(i) if is_tunnel_iface(i) => owned.contains(i) || !iface_present,
        _ => false,
    }
}

/// Delete the split-default `/1` halves Warren may legitimately reclaim
/// (owned or dangling), leaving any live foreign tunnel / physical route
/// untouched. Shared by the in-process force-cleanup and the connect-time
/// crash reclaim.
fn reclaim_split_halves(owned: &HashSet<String>) {
    for (net, probe) in SPLIT_NET_PROBES {
        let iface = route_iface(probe);
        let present = iface.as_deref().is_some_and(iface_exists);
        if reclaim_decision(iface.as_deref(), owned, present) {
            let _ = run_blocking_bounded("route", &["delete", "-net", net]);
        }
    }
}

/// Synchronously delete every split-default route Warren installed in
/// this process, for the force-disconnect / watchdog path. Idempotent and
/// privilege-tolerant (missing entries and missing root both no-op).
///
/// Registry-keyed host-route deletions are exact. The `/1` sweep is
/// ownership-scoped via [`reclaim_decision`], so a registry lost to a
/// prior crash is still recovered (the dangling TUN signals the leak)
/// without ever tearing down a co-resident VPN's live split.
pub fn force_cleanup_all() {
    let entries: Vec<(Ipv4Addr, String)> = {
        let guard = INSTALLED_SPLITS
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        guard.iter().map(|(ip, tun)| (*ip, tun.clone())).collect()
    };
    let owned: HashSet<String> = entries.iter().map(|(_, tun)| tun.clone()).collect();
    for (ip, _) in &entries {
        delete_host_route_blocking(*ip);
    }
    reclaim_split_halves(&owned);
    let mut guard = INSTALLED_SPLITS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    for (ip, _) in &entries {
        guard.remove(ip);
    }
}

/// Delete the IPv6 split-default `::/1`+`8000::/1` halves Warren may
/// legitimately reclaim (owned or dangling), leaving any live foreign tunnel
/// / physical route untouched. The v6 twin of [`reclaim_split_halves`].
fn reclaim_split_halves_v6(owned: &HashSet<String>) {
    for (net, probe) in SPLIT_NET_PROBES_V6 {
        let iface = route_iface_v6(probe);
        let present = iface.as_deref().is_some_and(iface_exists);
        if reclaim_decision(iface.as_deref(), owned, present) {
            let _ = run_blocking_bounded("route", &["delete", "-inet6", "-net", net]);
        }
    }
}

/// Synchronously delete every IPv6 split-default route Warren installed in
/// this process, for the force-disconnect / watchdog / crashed-predecessor
/// path. The v6 twin of [`force_cleanup_all`], and the missing backstop
/// whose absence let a leaked `::/1` blackhole native IPv6 (and thus DNS on
/// an IPv6-only-resolver network) until reboot. Idempotent, privilege- and
/// panic-tolerant.
///
/// Host-exception deletions are exact (keyed by the recorded exit IP); the
/// `/1` sweep is ownership-scoped via [`reclaim_decision`], so a registry
/// lost to a prior crash is still recovered (the dangling TUN signals the
/// leak) without ever tearing down a co-resident VPN's live v6 split.
pub fn force_cleanup_all_v6() {
    let entries: Vec<(String, Option<Ipv6Addr>)> = {
        let guard = INSTALLED_SPLITS_V6
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        guard
            .iter()
            .map(|(tun, exit)| (tun.clone(), *exit))
            .collect()
    };
    let owned = owned_tuns_v6();
    for (_, exit) in &entries {
        if let Some(exit_ip) = exit {
            let _ = run_blocking_bounded(
                "route",
                &["delete", "-inet6", "-host", &exit_ip.to_string()],
            );
        }
    }
    reclaim_split_halves_v6(&owned);
    let mut guard = INSTALLED_SPLITS_V6
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    for (tun, _) in &entries {
        guard.remove(tun);
    }
}

/// Parse `scutil`'s `show State:/Network/Global/IPv6` into the primary
/// service's `(interface, router)`. The interface is the one the system DNS
/// resolver is scoped to; the router is the link-local gateway to re-scope the
/// default through. `None` unless BOTH are present (never fabricate a route
/// from half-data).
fn parse_primary_ipv6(scutil_out: &str) -> Option<(String, String)> {
    let iface = parse_scutil_primary_iface(scutil_out)?;
    let router = scutil_out.lines().find_map(|line| {
        let val = line
            .trim()
            .strip_prefix("Router")?
            .trim_start()
            .strip_prefix(':')?
            .trim();
        (!val.is_empty()).then(|| val.to_owned())
    })?;
    Some((iface, router))
}

/// True iff a v6 `default` route exists but none egress the primary interface
/// `pif` - the exact fingerprint of a teardown that stranded the primary's
/// scoped default. Never true when there is no default at all (link down: not
/// this bug), so a stranded resolver is only repaired against a router SC
/// actually knows.
fn primary_scoped_default_missing(netstat_v6: &str, pif: &str) -> bool {
    let defaults: Vec<&str> = netstat_v6
        .lines()
        .filter(|l| l.starts_with("default"))
        .collect();
    if defaults.is_empty() {
        return false;
    }
    let scope = format!("%{pif}");
    let via_pif = defaults.iter().any(|l| {
        l.split_whitespace()
            .any(|f| f == pif || f.ends_with(&scope))
    });
    !via_pif
}

/// True iff no UNSCOPED v6 `default` route exists: every `default` line
/// carries the RTF_IFSCOPE `I` flag, or there is no default at all. Both are
/// teardown residue, not "link down": the kernel re-creates an RA default
/// only when the NEXT router advertisement arrives (minutes away on many
/// routers), and until then every unscoped v6 socket fails instantly. The
/// caller gates on SC's `State:/Network/Global/IPv6` still naming a router,
/// so a genuinely v6-less link never reaches this check.
fn unscoped_default_missing_v6(netstat_v6: &str) -> bool {
    !netstat_v6
        .lines()
        .filter(|l| l.starts_with("default"))
        .any(|l| {
            l.split_whitespace()
                .nth(2)
                .is_some_and(|flags| !flags.contains('I'))
        })
}

/// Argv for `route` to add the UNSCOPED v6 default via `router`. Same gateway
/// scoping as [`build_scoped_default_add_v6`] (a link-local gateway needs its
/// zone), but no `-ifscope`: this is the route ordinary (unscoped) sockets
/// resolve against.
fn build_unscoped_default_add_v6(pif: &str, router: &str) -> Vec<String> {
    let gateway = if router.contains('%') {
        router.to_owned()
    } else {
        format!("{router}%{pif}")
    };
    vec![
        "-n".into(),
        "add".into(),
        "-inet6".into(),
        "default".into(),
        gateway,
    ]
}

/// Argv for `route` to add the primary interface's scoped v6 default via
/// `router`. A link-local router is scoped to `pif`; `-n` avoids a name lookup
/// (which is exactly what is broken when this runs).
fn build_scoped_default_add_v6(pif: &str, router: &str) -> Vec<String> {
    let gateway = if router.contains('%') {
        router.to_owned()
    } else {
        format!("{router}%{pif}")
    };
    vec![
        "-n".into(),
        "add".into(),
        "-inet6".into(),
        "default".into(),
        "-ifscope".into(),
        pif.into(),
        gateway,
    ]
}

/// Read a `scutil` dictionary key, bounded and panic-free. scutil consumes
/// `show <key>` from stdin and exits at EOF (stdin dropped below). The output
/// is a handful of lines, well under a pipe buffer, so the unread-stdout
/// deadlock does not apply.
fn scutil_show(key: &str) -> Option<String> {
    use std::io::Write;
    let mut child = std::process::Command::new("scutil")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()?
        .write_all(format!("show {key}\n").as_bytes())
        .ok()?;
    let deadline = std::time::Instant::now() + SYNC_CLEANUP_TIMEOUT;
    // Micro-backoff poll, same rationale as `run_blocking_bounded`.
    let mut poll = std::time::Duration::from_millis(1);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let out = child.wait_with_output().ok()?;
                return Some(String::from_utf8_lossy(&out.stdout).into_owned());
            }
            Ok(None) => {}
            Err(_) => return None,
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(poll);
        poll = (poll * 2).min(std::time::Duration::from_millis(4));
    }
}

/// The repair [`plan_primary_defaults_repair_v6`] computed for one teardown
/// snapshot: which of the primary service's v6 default routes to re-add, and
/// the exact `route` argvs (program name excluded) that re-add them.
#[derive(Debug, PartialEq, Eq)]
struct PrimaryV6Repair {
    /// SC's `PrimaryInterface`: the interface whose defaults are repaired and
    /// the zone a link-local router is scoped to.
    pif: String,
    /// Re-adds the missing UNSCOPED default, when the table proves it missing.
    unscoped_add: Option<Vec<String>>,
    /// Re-adds the primary's missing IFSCOPE default, when proven missing.
    scoped_add: Option<Vec<String>>,
}

/// Pure decision core of [`restore_primary_defaults_v6`]: the contract between
/// the app's teardown glue and this repair, pinned here so neither side can
/// drift.
///
/// 1. **Never fabricate**: a plan exists only when SC's
///    `State:/Network/Global/IPv6` names BOTH `PrimaryInterface` and `Router`,
///    and re-adds exactly the route they describe.
/// 2. **Fingerprint-gated, idempotent**: only a default the `netstat` table
///    proves missing is re-added; a healed table plans nothing, so retries and
///    raced reconnects are no-ops.
/// 3. **Leak guard wins over the fingerprint**: while unscoped v6 egress still
///    resolves through a tunnel interface, nothing is planned even if defaults
///    look missing. The app's route manager clears tunnel routes
///    ASYNCHRONOUSLY relative to its reset path, so its immediate call plus a
///    short retry schedule is only safe because an early call here is a
///    guaranteed no-op; re-opening a physical path while a tunnel still
///    carries traffic would leak v6 (and the scoped resolver) outside it.
///    `None` egress (no v6 route resolves at all) is the post-teardown shape
///    and must NOT block the repair.
fn plan_primary_defaults_repair_v6(
    sc_global_ipv6: &str,
    netstat_v6: &str,
    v6_egress_iface: Option<&str>,
) -> Option<PrimaryV6Repair> {
    let (pif, router) = parse_primary_ipv6(sc_global_ipv6)?;
    let need_unscoped = unscoped_default_missing_v6(netstat_v6);
    let need_scoped = primary_scoped_default_missing(netstat_v6, &pif);
    if !need_unscoped && !need_scoped {
        return None;
    }
    if v6_egress_iface.is_some_and(is_tunnel_iface) {
        return None;
    }
    Some(PrimaryV6Repair {
        unscoped_add: need_unscoped.then(|| build_unscoped_default_add_v6(&pif, &router)),
        scoped_add: need_scoped.then(|| build_scoped_default_add_v6(&pif, &router)),
        pif,
    })
}

/// Restore the primary interface's IPv6 default routes (unscoped and scoped)
/// if the tunnel teardown stranded them. TWO production root causes on macOS:
///
/// - **Unscoped default lost**: the daemon's `restore_default_route` re-adds
///   the best unscoped default per family only from its own tracked view;
///   when that view is empty for v6 at teardown, nothing is re-added, and
///   unlike v4 (configd re-plumbs the DHCP default immediately) the kernel
///   re-creates the RA default only at the NEXT router advertisement,
///   minutes away. Until then every unscoped v6 socket fails and v6-capable
///   apps ride their fallback timers: the user sees "no internet" right
///   after disconnect.
/// - **Scoped default lost** (dual-homed): the same restore never re-adds
///   per-interface IFSCOPE defaults, stranding the primary-scoped system
///   resolver; mDNSResponder stops resolving even though unscoped
///   `ping`/`dig` still work via the surviving default.
///
/// Deterministic and ownership-safe: acts only on each bug's fingerprint and
/// re-adds exactly the route SC's own `PrimaryInterface` + `Router` describe.
/// Best-effort, panic- and privilege-tolerant, so it is safe on the teardown
/// path.
pub fn restore_primary_defaults_v6() {
    let Some(global) = scutil_show("State:/Network/Global/IPv6") else {
        return;
    };
    let Some(table) = run_blocking_bounded("netstat", &["-rn", "-f", "inet6"])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    else {
        return;
    };
    // The `2000::` probe resolves current unscoped v6 egress for the planner's
    // leak guard (see [`plan_primary_defaults_repair_v6`] point 3).
    let egress = route_iface_v6("2000::");
    let Some(plan) = plan_primary_defaults_repair_v6(&global, &table, egress.as_deref()) else {
        return;
    };
    if let Some(argv) = &plan.unscoped_add {
        tracing::warn!(
            interface = %plan.pif,
            "No unscoped IPv6 default survived tunnel teardown; restoring from SC's primary router so native IPv6 recovers before the next RA"
        );
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let _ = run_blocking_bounded("route", &args);
    }
    if let Some(argv) = &plan.scoped_add {
        tracing::warn!(
            interface = %plan.pif,
            "Primary interface lost its scoped IPv6 default route at tunnel teardown; restoring so the scoped DNS resolver is reachable again"
        );
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let _ = run_blocking_bounded("route", &args);
    }
    // Nudge the resolvers to re-evaluate reachability of the now-routable DNS
    // server (SCNetworkReachability caches the stale "unreachable" verdict).
    let _ = run_blocking_bounded("dscacheutil", &["-flushcache"]);
    let _ = run_blocking_bounded("killall", &["-HUP", "mDNSResponder"]);
}

/// Argv vector for the two split-default `route add -net /1 -interface
/// <tun>` lines, in install order.
///
/// The `route` binary path is **not** included; the caller invokes it
/// with `Command::new("route")`.
///
/// No exit host-route exception is built here (and none is needed): the
/// exit's carrier socket stays on the physical link via `IP_BOUND_IF` (set
/// on the QUIC socket in the transport layer), so the `/1` split can
/// capture the exit IP into the tunnel like any other destination. Keying
/// the escape on the socket, not the exit destination, is the Port Fail /
/// TunnelCrack ServerIP fix: an application dialing the exit IP is
/// tunnelled, not leaked.
#[must_use]
pub fn build_install_commands(tun_name: &str) -> Vec<Vec<String>> {
    vec![
        // Split-default routes pointing at the TUN. Each /1 covers
        // half the IPv4 space; together they shadow the system's
        // default route without touching it (the TUN routes have a
        // longer prefix than `default`/0.0.0.0/0, hence win).
        vec![
            "add".into(),
            "-net".into(),
            "0.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ],
        vec![
            "add".into(),
            "-net".into(),
            "128.0.0.0/1".into(),
            "-interface".into(),
            tun_name.into(),
        ],
    ]
}

/// The IPv6 split-default `/1` pair, the v6 analogue of the v4 `/1` halves.
/// `::/1` (`::` .. `7fff:…`) + `8000::/1` (`8000::` .. `ffff:…`) cover the
/// whole v6 space and shadow a native `::/0` default without replacing it
/// (longer prefix wins), exactly like the v4 halves.
const SPLIT_NETS_V6: [&str; 2] = ["::/1", "8000::/1"];

/// Representative host inside each IPv6 split-default `/1` half, used by the
/// out-of-process backstop to probe whether the half currently egresses
/// through a tunnel before reclaiming a registry-less stale split (see
/// [`force_cleanup_all_v6`]). The v6 analogue of [`SPLIT_NET_PROBES`]: `100::`
/// has its top bit clear (`::/1`), `c000::` has it set (`8000::/1`).
const SPLIT_NET_PROBES_V6: [(&str, &str); 2] = [("::/1", "100::"), ("8000::/1", "c000::")];

/// macOS argv builder for the IPv6 split-default routes (`route add
/// -inet6 -net <half> -interface <tun>`), optionally preceded by a v6
/// exit host-route exception when the exit is dialed over IPv6.
///
/// `exit_ip_v6` is `Some` only when the QUIC transport to the exit runs
/// over IPv6 (rare on macOS, where exits are dialed over v4): the
/// `-host <exit>/128 -interface <default_iface>` exception then keeps that
/// socket on the physical NIC so the v6 split does not loop it into the
/// tunnel. When the exit is dialed over IPv4 (`None`), the v6 split cannot
/// capture the v4 socket, so no exception is emitted.
///
/// The `route` binary path is not included; the caller invokes it with
/// `Command::new("route")`.
#[must_use]
pub fn build_install_commands_v6(
    _exit_ip_v6: Option<Ipv6Addr>,
    tun_name: &str,
    _default_iface: &str,
) -> Vec<Vec<String>> {
    // No v6 host-route exception: a v6-dialed exit socket stays on the physical
    // link via `IPV6_BOUND_IF` (transport layer), so the v6 split can capture the
    // exit like any other destination (Port Fail / TunnelCrack ServerIP fix).
    let mut cmds: Vec<Vec<String>> = Vec::with_capacity(2);
    for net in SPLIT_NETS_V6 {
        cmds.push(vec![
            "add".into(),
            "-inet6".into(),
            "-net".into(),
            net.into(),
            "-interface".into(),
            tun_name.into(),
        ]);
    }
    cmds
}

/// Argv builder to undo [`build_install_commands_v6`], reverse install
/// order: delete the `/1` halves (the install no longer creates a v6 host
/// exception, so there is none to remove).
#[must_use]
pub fn build_uninstall_commands_v6(_exit_ip_v6: Option<Ipv6Addr>) -> Vec<Vec<String>> {
    SPLIT_NETS_V6
        .iter()
        .map(|net| {
            vec![
                "delete".into(),
                "-inet6".into(),
                "-net".into(),
                (*net).into(),
            ]
        })
        .collect()
}

/// Parse the `interface: <name>` line out of `route -n get default`
/// output. Pure - exposed so the parser can be unit-tested against
/// recorded fixtures without invoking `route`.
#[must_use]
pub fn parse_default_iface(out: &str) -> Option<String> {
    out.lines().find_map(|line| {
        let trimmed = line.trim_start();
        trimmed
            .strip_prefix("interface: ")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    })
}

/// Parse the `gateway: <ip>` line out of `route -n get default` output.
/// Pure - unit-tested against fixtures. Returns `None` when the default
/// route has no gateway (point-to-point link), in which case the caller
/// falls back to the interface form of the host-route exception.
#[must_use]
pub fn parse_default_gateway(out: &str) -> Option<String> {
    out.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("gateway: ")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    })
}

/// Parse the `Router : <ip>` value out of `scutil`
/// `show State:/Network/Global/IPv4` output. Pure - unit-tested against
/// fixtures. This is the physical LAN gateway and, unlike `route get
/// default`, is unaffected by the tunnel's `0.0.0.0/1` split, so it
/// still names the real gateway once the tunnel routes are in place.
#[must_use]
pub fn parse_scutil_router(out: &str) -> Option<String> {
    out.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("Router")?;
        let val = rest.trim_start().strip_prefix(':')?.trim();
        (!val.is_empty()).then(|| val.to_owned())
    })
}

/// True if `name` denotes a virtual tunnel interface (our own TUN, or
/// any other VPN's). The exit host-route must NEVER be pinned to such
/// an interface: doing so routes the client -> exit QUIC socket back
/// into a tunnel, looping it onto itself (downlink collapses to zero).
#[must_use]
pub fn is_tunnel_iface(name: &str) -> bool {
    let n = name.trim();
    n.starts_with("utun") || n.starts_with("tun") || n.starts_with("ipsec") || n.starts_with("ppp")
}

/// Parse the `PrimaryInterface` value out of
/// `scutil` `show State:/Network/Global/IPv4` output (e.g.
/// `  PrimaryInterface : en8`). Pure - unit-tested against fixtures.
///
/// Unlike `route -n get default`, this reflects the primary network
/// *service* (the physical NIC), which is unaffected by the route-only
/// `0.0.0.0/1` split we install - so it still names the physical
/// interface even once the tunnel's default route is in place.
#[must_use]
pub fn parse_scutil_primary_iface(out: &str) -> Option<String> {
    out.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("PrimaryInterface")?;
        let val = rest.trim_start().strip_prefix(':')?.trim();
        (!val.is_empty()).then(|| val.to_owned())
    })
}

/// Decide the physical default interface to pin the exit host-route to,
/// given the (possibly tunnel-shadowed) `route -n get default` result
/// and the scutil `PrimaryInterface` fallback. Pure decision core so it
/// is fully unit-testable without invoking `route` / `scutil`.
///
/// Priority: `route get default` when it names a physical interface;
/// otherwise the scutil primary; otherwise an error. We deliberately
/// REFUSE to return a tunnel interface - pinning the exit route to a
/// tunnel loops it onto itself, which presents as "connects but no
/// downlink / no internet".
fn resolve_physical_default_iface(
    route_iface: Option<&str>,
    scutil_primary: Option<&str>,
) -> Result<String> {
    if let Some(r) = route_iface
        && !is_tunnel_iface(r)
    {
        return Ok(r.to_owned());
    }
    if let Some(p) = scutil_primary
        && !is_tunnel_iface(p)
    {
        return Ok(p.to_owned());
    }
    Err(anyhow!(
        "could not determine a physical default interface \
         (route get default = {route_iface:?}, scutil PrimaryInterface = {scutil_primary:?}); \
         refusing to pin the exit host-route to a tunnel interface (would loop the tunnel \
         onto itself and kill downlink)"
    ))
}

/// Decide the physical default *gateway* (LAN router) to pin the exit
/// host-route to, given the parsed `route -n get default` interface +
/// gateway and the scutil `Router` fallback. Pure decision core, fully
/// unit-testable.
///
/// - When `route get default` names a physical interface, trust its
///   `gateway:` (or `None` for a point-to-point link with no gateway →
///   the caller falls back to the interface form).
/// - When the route is missing or tunnel-shadowed, use the tunnel-
///   resistant scutil `Router` (the real LAN gateway).
///
/// A gateway is never borrowed from a tunnel default route (that would
/// re-introduce the self-loop the gateway form exists to prevent).
fn resolve_physical_gateway(
    route_iface: Option<&str>,
    route_gateway: Option<&str>,
    scutil_router: Option<&str>,
) -> Option<String> {
    if matches!(route_iface, Some(i) if !is_tunnel_iface(i)) {
        return route_gateway.map(str::to_owned);
    }
    scutil_router.map(str::to_owned)
}

/// One-shot discovery of the *physical* default route as
/// `(interface, optional gateway)`, for the exit host-route exception.
///
/// Invokes `route -n get default` once and parses both the interface
/// and gateway from that single output. Only when that result is
/// missing or tunnel-shadowed does it fall back to a single `scutil`
/// query (parsed for both `PrimaryInterface` and `Router`). Resolution
/// is delegated to the pure cores [`resolve_physical_default_iface`] /
/// [`resolve_physical_gateway`], both of which refuse a tunnel source.
///
/// # Errors
///
/// - No physical default route can be determined (offline / link down /
///   only tunnels present) - surfaced by [`resolve_physical_default_iface`].
async fn discover_physical_default() -> Result<(String, Option<String>)> {
    let route_out = route_get_default_raw().await;
    let route_iface = route_out.as_deref().and_then(parse_default_iface);
    let route_gateway = route_out.as_deref().and_then(parse_default_gateway);

    // Only pay for scutil when `route` is missing or tunnel-shadowed; in
    // the common pre-tunnel case `route` already names the physical NIC.
    let scutil_out = match route_iface.as_deref() {
        Some(iface) if !is_tunnel_iface(iface) => None,
        _ => scutil_global_ipv4_raw().await,
    };
    let scutil_iface = scutil_out.as_deref().and_then(parse_scutil_primary_iface);
    let scutil_router = scutil_out.as_deref().and_then(parse_scutil_router);

    let iface = resolve_physical_default_iface(route_iface.as_deref(), scutil_iface.as_deref())?;
    let gateway = resolve_physical_gateway(
        route_iface.as_deref(),
        route_gateway.as_deref(),
        scutil_router.as_deref(),
    );
    Ok((iface, gateway))
}

/// Discover the kernel interface index of the host's current physical
/// (non-tunnel) default-route interface. A macOS caller feeds this to
/// `warrenguard_socket_bypass::apply(&socket, SocketBypass::BoundIf(ifindex))`
/// so the daemon's own carrier socket keeps egressing the physical NIC once
/// [`DefaultRouteSplitGuard`] plants the `/1` halves that capture every other
/// destination, exit IP included. Re-resolving this after a default-route
/// change (e.g. a migration watchdog observing Wi-Fi <-> Ethernet) is how the
/// bypass follows the host onto its new physical interface; unlike the
/// retired host-route exception, a re-bind here only affects the daemon's own
/// socket, never other traffic. Idempotent and cheap enough to call on every
/// migration (same `route`/`scutil` shell-outs as [`discover_physical_default`]).
///
/// Fails closed exactly like [`discover_physical_default`]: it never guesses
/// a fallback interface when offline or only tunnels are present, because a
/// wrong index handed to `IP_BOUND_IF` would silently defeat that bypass's
/// own fail-closed contract.
///
/// # Errors
///
/// - No physical default route can be determined (offline / only tunnels
///   present) - see [`discover_physical_default`].
/// - The resolved interface name has no live kernel index (renamed or
///   removed between resolution and this call).
pub async fn discover_physical_ifindex() -> Result<u32> {
    async {
        let (iface, _gateway) = discover_physical_default().await?;
        ifindex_from_name(&iface)
    }
    .await
    .context("cannot discover physical default-route ifindex on macOS")
}

/// Kernel interface name -> index, isolated so the lookup itself is unit
/// testable against a stable real interface (`lo0`) without touching routing.
/// `nix::net::if_::if_nametoindex` is a safe wrapper over `if_nametoindex(3)`
/// and already treats a `0` result as its "not found" error case, so a
/// successful `Ok` here structurally cannot be the unspecified index `0`
/// (which would silently defeat an `IP_BOUND_IF` bind).
fn ifindex_from_name(name: &str) -> Result<u32> {
    nix::net::if_::if_nametoindex(name).map_err(|e| anyhow!("if_nametoindex({name:?}): {e}"))
}

/// Best-effort raw stdout of `route -n get default`. Returns `None`
/// (rather than erroring) so the caller can fall back to scutil.
async fn route_get_default_raw() -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .await
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Best-effort raw stdout of scutil `show State:/Network/Global/IPv4`
/// (parsed for both `PrimaryInterface` and `Router`). Returns `None` on
/// any failure so the pure resolvers surface a single clear diagnostic.
async fn scutil_global_ipv4_raw() -> Option<String> {
    let out = Command::new("sh")
        .args(["-c", "echo 'show State:/Network/Global/IPv4' | scutil"])
        .output()
        .await
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// RAII guard: holds the "installed" state for automatic best-effort
/// cleanup on drop.
#[derive(Debug)]
pub struct DefaultRouteSplitGuard {
    exit_ip: Ipv4Addr,
    installed: bool,
}

impl DefaultRouteSplitGuard {
    /// Install the split-default routing for `tun_name`. `exit_ip` is kept
    /// only as the registry / stale-route-cleanup key (see below); the
    /// exit's carrier socket stays on the physical link via `IP_BOUND_IF`,
    /// so no host-route exception is installed for it (Port Fail /
    /// TunnelCrack ServerIP fix).
    ///
    /// # Errors
    ///
    /// - `tun_name` invalid (non-alphanumeric, > 15 chars, empty).
    /// - Missing privileges (`route` requires root).
    /// - `route` not in `PATH`.
    /// - `RTM_ADD: File exists` is **tolerated** - install becomes
    ///   idempotent and survives a previous partial install.
    pub async fn install(exit_ip: Ipv4Addr, tun_name: &str) -> Result<Self> {
        ks_validate_tun_name(tun_name).context("invalid tun_name")?;

        // Connect-time crash recovery: a split leaked by a prior process
        // blackholes the relay path this install needs. Reclaim it
        // (ownership-scoped: only a dangling or Warren-owned `/1`, never a
        // co-resident VPN's live one).
        reclaim_split_halves(&owned_tuns());

        // Clear any stale host route to the exit before (re)installing.
        // A crashed prior session (or an old build, before this fix, that
        // used to pin one) can leave a `<exit_ip>` route parked on a utun
        // interface; `route add` tolerates "File exists" and would
        // otherwise keep that wrong route, looping the exit socket into
        // the tunnel (downlink=0).
        let _ =
            run_route_tolerant_no_such(&["delete".into(), "-host".into(), format!("{exit_ip}")])
                .await;

        let cmds = build_install_commands(tun_name);
        for args in &cmds {
            run_route_tolerant_exists(args)
                .await
                .with_context(|| format!("route {}", args.join(" ")))?;
        }

        tracing::info!(
            tun = tun_name,
            exit_ip = %exit_ip,
            "Warren default-route split installed (macOS)"
        );

        registry_insert(exit_ip, tun_name);

        Ok(Self {
            exit_ip,
            installed: true,
        })
    }

    /// Remove the routes, ownership-scoped exactly like [`Drop`] so a clean
    /// uninstall can never tear down a co-resident VPN's split: only a
    /// Warren-owned (or dangling) `/1` is reclaimed and only the exact per-exit
    /// host route is deleted. Idempotent and best-effort. Halves first so the
    /// physical default route resumes before the exit exception is removed.
    pub async fn uninstall(mut self) -> Result<()> {
        let owned = owned_tuns();
        reclaim_split_halves(&owned);
        delete_host_route_blocking(self.exit_ip);
        registry_remove(self.exit_ip);
        self.installed = false;
        Ok(())
    }
}

impl Drop for DefaultRouteSplitGuard {
    fn drop(&mut self) {
        if self.installed {
            // `uninstall().await` was never reached (early `?`, task
            // abort, panic). Delete synchronously so the split cannot
            // outlive its guard (the split-default `/1` halves). Never panics in Drop.
            tracing::warn!(
                exit_ip = %self.exit_ip,
                "DefaultRouteSplitGuard dropped without explicit uninstall - \
                 running synchronous fail-safe route cleanup"
            );
            let owned = owned_tuns();
            // Halves first (physical default resumes), then the host exception,
            // matching `uninstall`.
            reclaim_split_halves(&owned);
            delete_host_route_blocking(self.exit_ip);
            registry_remove(self.exit_ip);
            self.installed = false;
        }
    }
}

/// RAII guard for the macOS IPv6 split-default routing. Mirrors
/// [`DefaultRouteSplitGuard`] for the v6 family: installs `::/1` +
/// `8000::/1 -inet6 -interface <tun>` on construction and removes them on
/// [`uninstall`](Self::uninstall) / `Drop`.
///
/// Same `install(Option<Ipv6Addr>, &str)` shape as the Linux
/// `DefaultRouteSplitV6Guard` so a caller's routing facade is
/// OS-agnostic at the call site.
#[derive(Debug)]
pub struct DefaultRouteSplitV6Guard {
    exit_ip_v6: Option<Ipv6Addr>,
    /// TUN this split was installed on, the key under which it is registered
    /// in [`INSTALLED_SPLITS_V6`] so the out-of-process backstop can reclaim
    /// it if this guard's `Drop` never runs.
    tun_name: String,
    installed: bool,
}

impl DefaultRouteSplitV6Guard {
    /// Install the v6 split-default routing for `tun_name`. When the exit
    /// is dialed over IPv6, pass its address as `exit_ip_v6` so a v6 host
    /// exception keeps that QUIC socket on the physical NIC; pass `None`
    /// for the common v4-dialed case.
    ///
    /// # Errors
    ///
    /// - `tun_name` invalid.
    /// - Missing privileges (`route` requires root).
    /// - No default route to query (only when a v6 exit exception is
    ///   needed, i.e. `exit_ip_v6` is `Some`).
    /// - `RTM_ADD: File exists` is tolerated (idempotent).
    pub async fn install(exit_ip_v6: Option<Ipv6Addr>, tun_name: &str) -> Result<Self> {
        ks_validate_tun_name(tun_name).context("invalid tun_name")?;

        // The physical interface is only needed for the v6 host exception
        // (v6-dialed exit). For the common v4-dialed case it is unused, so
        // skip the discovery entirely.
        let default_iface = if exit_ip_v6.is_some() {
            let (iface, _gw) = discover_physical_default()
                .await
                .context("cannot install v6 split: no default route discovered")?;
            iface
        } else {
            String::new()
        };

        let cmds = build_install_commands_v6(exit_ip_v6, tun_name, &default_iface);
        for args in &cmds {
            run_route_tolerant_exists(args)
                .await
                .with_context(|| format!("route {}", args.join(" ")))?;
        }

        // Register before returning so a `Drop` that never runs (async abort,
        // hard kill) still leaves the out-of-process backstop a record to
        // reclaim from. Mirrors the v4 `registry_insert` ordering.
        registry_insert_v6(tun_name, exit_ip_v6);

        tracing::info!(
            tun = tun_name,
            exit_bypass_v6 = exit_ip_v6.is_some(),
            "Warren IPv6 split-default routing installed (macOS)"
        );

        Ok(Self {
            exit_ip_v6,
            tun_name: tun_name.to_owned(),
            installed: true,
        })
    }

    /// Remove the v6 routes. Idempotent - tolerates "not in table". Best-
    /// effort: log a warning but never abort.
    pub async fn uninstall(mut self) -> Result<()> {
        let cmds = build_uninstall_commands_v6(self.exit_ip_v6);
        for args in &cmds {
            if let Err(e) = run_route_tolerant_no_such(args).await {
                tracing::warn!(
                    error = %e,
                    cmd = %args.join(" "),
                    "v6 route cleanup failed (non-fatal)"
                );
            }
        }
        registry_remove_v6(&self.tun_name);
        self.installed = false;
        Ok(())
    }
}

impl Drop for DefaultRouteSplitV6Guard {
    fn drop(&mut self) {
        if !self.installed {
            registry_remove_v6(&self.tun_name);
            return;
        }
        // Synchronous fail-safe: a leaked `::/1`+`8000::/1` would blackhole
        // v6. Snapshot ownership BEFORE removing our own registry entry -
        // `self.tun_name` must still read as owned so `reclaim_split_halves_v6`
        // is willing to reclaim a half currently routed through it. Without
        // this ownership check (the bug this fixes), an unconditional delete
        // could tear down a co-resident VPN's live v6 split that happens to
        // occupy the same `::/1` / `8000::/1` slot. Mirrors the v4 Drop
        // above. Never panics.
        let owned = owned_tuns_v6();
        reclaim_split_halves_v6(&owned);
        if let Some(exit) = self.exit_ip_v6 {
            let _ =
                run_blocking_bounded("route", &["delete", "-inet6", "-host", &exit.to_string()]);
        }
        registry_remove_v6(&self.tun_name);
        self.installed = false;
    }
}

/// Run a `route` invocation, tolerating `File exists` (idempotent
/// install when a previous run left an entry behind).
async fn run_route_tolerant_exists(args: &[String]) -> Result<()> {
    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = Command::new("route")
        .args(&str_args)
        .output()
        .await
        .with_context(|| format!("spawn route {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // macOS's `route add` writes its diagnostic to stdout, not stderr,
    // so we scan both. The "File exists" string is BSD's standard
    // EEXIST translation for routing-socket errors.
    if stderr.contains("File exists") || stdout.contains("File exists") {
        return Ok(());
    }
    Err(anyhow!(
        "route {} failed: stderr={} stdout={}",
        args.join(" "),
        stderr.trim(),
        stdout.trim()
    ))
}

/// Run a `route` invocation, tolerating "not in table" / ENOENT
/// (idempotent uninstall when the entry was already removed).
async fn run_route_tolerant_no_such(args: &[String]) -> Result<()> {
    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = Command::new("route")
        .args(&str_args)
        .output()
        .await
        .with_context(|| format!("spawn route {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // BSD route reports missing entries with "not in table" on stderr
    // or "not found" on stdout depending on the macOS release. Tolerate
    // both for forward / backward compat.
    let combined = format!("{stderr}{stdout}");
    if combined.contains("not in table")
        || combined.contains("not found")
        || combined.contains("does not")
    {
        return Ok(());
    }
    Err(anyhow!(
        "route {} failed: stderr={} stdout={}",
        args.join(" "),
        stderr.trim(),
        stdout.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bounded runner sits on the connect prep AND disconnect paths
    /// (several calls each), so its completion latency must track the
    /// child's actual runtime, not a coarse poll period. A fixed 20 ms
    /// poll made every ~5 ms `route`/`ifconfig` call cost ~20-25 ms and
    /// added ~150 ms of pure polling to every tunnel state transition
    /// (measured on the production daemon).
    #[test]
    fn bounded_run_completes_a_short_child_promptly() {
        // Warm-up: exclude one-time process-spawn amortization (dyld
        // cache etc.) from the measured run.
        let _ = run_blocking_bounded("/bin/sleep", &["0"]);
        let started = std::time::Instant::now();
        let out = run_blocking_bounded("/bin/sleep", &["0.01"]);
        let elapsed = started.elapsed();
        assert!(out.is_some(), "child must complete");
        assert!(
            elapsed < std::time::Duration::from_millis(20),
            "a ~10 ms child must not pay a full coarse poll period, took {elapsed:?}"
        );
    }

    fn ip6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    // --- IPv6 split-default (macOS) ---

    #[test]
    fn v6_install_emits_inet6_split_halves_via_tun() {
        // The v4-dialed common case: no host exception, just the two
        // `-inet6 -net <half> -interface <tun>` halves. Anti-regression on
        // the `-inet6` flag (dropping it would touch the v4 table = no-op
        // for v6 traffic = leak through the firewall's blocked path).
        let cmds = build_install_commands_v6(None, "utun7", "en0");
        assert_eq!(cmds.len(), 2, "v4-dialed exit: 2 halves, no host route");
        assert_eq!(
            cmds[0],
            vec!["add", "-inet6", "-net", "::/1", "-interface", "utun7"]
        );
        assert_eq!(
            cmds[1],
            vec!["add", "-inet6", "-net", "8000::/1", "-interface", "utun7"]
        );
    }

    #[test]
    fn v6_install_never_adds_a_host_exception_even_when_v6_dialed() {
        // Port Fail fix: even a v6-dialed exit gets NO `-host <exit>` exception;
        // its socket stays on the NIC via IPV6_BOUND_IF, so the v6 split just
        // captures the two halves and the exit is tunnelled like anything else.
        let cmds = build_install_commands_v6(Some(ip6("2001:db8:1::2")), "utun7", "en0");
        assert_eq!(cmds.len(), 2, "no host route: only the 2 halves");
        let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("-host") && !joined.contains("2001:db8:1::2"),
            "no v6 exit host route may be emitted; got: {joined}"
        );
        assert_eq!(cmds[0][3], "::/1");
        assert_eq!(cmds[1][3], "8000::/1");
    }

    #[test]
    fn v6_builder_never_emits_ipv4_literals() {
        let cmds = build_install_commands_v6(Some(ip6("2001:db8:1::2")), "utun7", "en0");
        let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("0.0.0.0") && !joined.contains("128.0.0.0"),
            "v6 builder must not emit IPv4 routes, got: {joined}"
        );
    }

    #[test]
    fn v6_uninstall_deletes_only_the_halves_no_host_route() {
        // The install no longer creates a v6 exit host route, so teardown only
        // removes the two halves, even for a (hypothetical) v6-dialed exit.
        let cmds = build_uninstall_commands_v6(Some(ip6("2001:db8:1::2")));
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], vec!["delete", "-inet6", "-net", "::/1"]);
        assert_eq!(cmds[1], vec!["delete", "-inet6", "-net", "8000::/1"]);
        let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("-host"),
            "no host-route deletion may be emitted; got: {joined}"
        );
    }

    #[test]
    fn v6_uninstall_v4_dialed_only_deletes_halves() {
        let cmds = build_uninstall_commands_v6(None);
        assert_eq!(cmds.len(), 2, "no host exception to delete when v4-dialed");
        assert!(cmds.iter().all(|c| c.contains(&"-inet6".to_string())));
    }

    #[test]
    fn v6_split_net_probes_lie_in_their_respective_halves() {
        // The out-of-process v6 backstop probes each `/1` half's current
        // egress iface before reclaiming it (mirror of the v4 sweep). A
        // probe placed in the WRONG half would read another route's iface
        // and either spare a leaked half (v6 stays blackholed) or reclaim a
        // live one. `::/1` is top-bit 0, `8000::/1` is top-bit 1.
        assert_eq!(SPLIT_NET_PROBES_V6[0].0, "::/1");
        assert_eq!(SPLIT_NET_PROBES_V6[1].0, "8000::/1");
        let lower: Ipv6Addr = SPLIT_NET_PROBES_V6[0].1.parse().unwrap();
        let upper: Ipv6Addr = SPLIT_NET_PROBES_V6[1].1.parse().unwrap();
        assert_eq!(
            lower.octets()[0] & 0x80,
            0,
            "::/1 probe must have its top bit clear"
        );
        assert_eq!(
            upper.octets()[0] & 0x80,
            0x80,
            "8000::/1 probe must have its top bit set"
        );
    }

    #[test]
    fn v6_registry_tracks_owned_tuns_and_removal() {
        // The v6 reclaim sweep scopes deletions to Warren-owned tuns, and the
        // registry is that ownership source (the v4 twin uses INSTALLED_SPLITS
        // the same way). A missing insert would leave a leaked `::/1` with no
        // backstop; a missing remove would make a clean teardown look like a
        // live split. Unique names keep this isolated from parallel tests
        // sharing the process-wide registry.
        registry_insert_v6("utun-regtest-a", None);
        registry_insert_v6("utun-regtest-b", Some(ip6("2001:db8:1::2")));
        let owned = owned_tuns_v6();
        assert!(owned.contains("utun-regtest-a"));
        assert!(owned.contains("utun-regtest-b"));

        registry_remove_v6("utun-regtest-a");
        let owned = owned_tuns_v6();
        assert!(
            !owned.contains("utun-regtest-a"),
            "removed tun must be gone"
        );
        assert!(owned.contains("utun-regtest-b"), "sibling entry untouched");

        registry_remove_v6("utun-regtest-b");
    }

    #[test]
    fn v6_drop_reclaims_halves_ownership_scoped_not_unconditionally() {
        // Regression: an earlier Drop for DefaultRouteSplitV6Guard deleted
        // both `::/1` + `8000::/1` halves unconditionally, without the
        // ownership check `reclaim_split_halves_v6`/`reclaim_decision`
        // apply, so it could tear down a co-resident VPN's live v6 split
        // occupying the same slot. `route delete -inet6 -net <cidr>` is not
        // scoped to who installed it, so an unconditional delete cannot
        // distinguish "our leaked half" from "someone else's live one" -
        // installing a real split-default route here to exercise Drop for
        // real would require root and mutate this host's live routing
        // table, so this pins the fix at the source level instead (mirrors
        // `warrenguard-killswitch-os`'s `drop_rollback_contract.rs`
        // pattern): the Drop impl body must route the halves reclaim
        // through the ownership-scoped `reclaim_split_halves_v6`, like the
        // v4 Drop does, not a raw unconditional per-half delete loop.
        let src = include_str!("default_route_split_macos.rs");
        let start = src
            .find("impl Drop for DefaultRouteSplitV6Guard")
            .expect("Drop impl for DefaultRouteSplitV6Guard must exist");
        let body = &src[start..];
        let end = body.find("\n}\n").map(|i| i + 3).unwrap_or(body.len());
        let body = &body[..end];
        assert!(
            body.contains("reclaim_split_halves_v6("),
            "Drop for DefaultRouteSplitV6Guard must reclaim halves through \
             the ownership-scoped reclaim_split_halves_v6, like the v4 Drop \
             does; got:\n{body}"
        );
        assert!(
            !body.contains("for net in SPLIT_NETS_V6"),
            "the old unconditional per-half delete loop must not come back; \
             got:\n{body}"
        );
    }

    // --- primary-interface scoped IPv6 default restore ---

    const SCUTIL_GLOBAL_IPV6: &str = "\
<dictionary> {
  PrimaryInterface : en1
  PrimaryService : C3E42030-D8F9-44DC-9BA4-4F7BF67243B3
  Router : fe80::1234:56ff:fe78:9abc
}
";

    #[test]
    fn parse_primary_ipv6_extracts_interface_and_router() {
        // The restore reads SC's own view of the primary service so it never
        // guesses: PrimaryInterface is the DNS-scope interface, Router is the
        // link-local gateway to re-scope the default through.
        let got = parse_primary_ipv6(SCUTIL_GLOBAL_IPV6);
        assert_eq!(
            got,
            Some(("en1".to_owned(), "fe80::1234:56ff:fe78:9abc".to_owned()))
        );
    }

    #[test]
    fn parse_primary_ipv6_none_when_keys_absent() {
        // No global IPv6 state (IPv6 down / no RA) → nothing to restore, and
        // the caller must not fabricate a route from half-data.
        assert_eq!(parse_primary_ipv6("<dictionary> {\n}\n"), None);
        assert_eq!(
            parse_primary_ipv6("<dictionary> {\n  PrimaryInterface : en1\n}\n"),
            None,
            "router alone missing must yield None"
        );
    }

    #[test]
    fn primary_scoped_default_missing_true_when_only_other_iface_has_default() {
        // The bug's exact fingerprint: a v6 default survives via en0 but the
        // primary en1 has none, so its scoped DNS resolver is stranded.
        let table = "\
default                                 fe80::1234:56ff:fe78:9abc%en0           UGdScg                en0
default                                 fe80::1234:56ff:fe78:9abc%en0           UGcIg                 en0
::1                                     ::1                                     UHL                   lo0
";
        assert!(primary_scoped_default_missing(table, "en1"));
    }

    #[test]
    fn primary_scoped_default_missing_false_when_primary_has_default() {
        // Healthy: en1 already carries a default → never re-add (idempotent).
        let table = "\
default                                 fe80::1234:56ff:fe78:9abc%en0           UGdScg                en0
default                                 fe80::1234:56ff:fe78:9abc%en1           UGScIg                en1
";
        assert!(!primary_scoped_default_missing(table, "en1"));
    }

    #[test]
    fn primary_scoped_default_missing_false_when_no_default_at_all() {
        // No default anywhere (link down): not this bug, and re-adding a
        // scoped default to a router we cannot confirm would be a guess.
        let table = "\
::1                                     ::1                                     UHL                   lo0
2001:db8:101e:b950::/64                 link#24                                 UC                    en1
";
        assert!(!primary_scoped_default_missing(table, "en1"));
    }

    #[test]
    fn unscoped_default_missing_v6_true_when_only_ifscoped_defaults_remain() {
        // The teardown residue this repair exists for: only IFSCOPE (`I`)
        // defaults survive, so every unscoped v6 socket fails until the next
        // RA re-creates the kernel default.
        let table = "\
default                                 fe80::1234:56ff:fe78:9abc%en0           UGdScIg               en0
default                                 fe80::%utun3                            UGcIg                 utun3
::1                                     ::1                                     UHL                   lo0
";
        assert!(unscoped_default_missing_v6(table));
    }

    #[test]
    fn unscoped_default_missing_v6_false_when_an_unscoped_default_exists() {
        // Healthy: an unscoped default is present (no `I` flag) → never
        // re-add (idempotent), whatever scoped copies also exist.
        let table = "\
default                                 fe80::1234:56ff:fe78:9abc%en0           UGdScg                en0
default                                 fe80::1234:56ff:fe78:9abc%en1           UGScIg                en1
";
        assert!(!unscoped_default_missing_v6(table));
    }

    #[test]
    fn unscoped_default_missing_v6_true_when_no_default_at_all() {
        // A fully-deleted default IS this bug's shape (the kernel re-adds an
        // RA default only at the next RA): the caller's SC gate, not the
        // table, decides whether v6 is supposed to exist.
        let table = "\
::1                                     ::1                                     UHL                   lo0
2001:db8:101e:b950::/64                 link#24                                 UC                    en1
";
        assert!(unscoped_default_missing_v6(table));
    }

    #[test]
    fn build_unscoped_default_add_v6_keeps_the_route_unscoped() {
        // The gateway needs its link-local zone, but the route itself must
        // NOT be ifscoped: it is the route ordinary sockets resolve against.
        let cmd = build_unscoped_default_add_v6("en1", "fe80::1234:56ff:fe78:9abc");
        assert_eq!(
            cmd,
            vec![
                "-n",
                "add",
                "-inet6",
                "default",
                "fe80::1234:56ff:fe78:9abc%en1"
            ]
        );
        let cmd = build_unscoped_default_add_v6("en1", "fe80::1%en1");
        assert_eq!(cmd.last().unwrap(), "fe80::1%en1");
    }

    #[test]
    fn build_scoped_default_add_v6_scopes_router_to_primary() {
        // A link-local router MUST be scoped to the primary interface, else
        // `route add` cannot resolve the gateway. `-n` keeps `route` from
        // doing its own (currently broken) name lookup.
        let cmd = build_scoped_default_add_v6("en1", "fe80::1234:56ff:fe78:9abc");
        assert_eq!(
            cmd,
            vec![
                "-n",
                "add",
                "-inet6",
                "default",
                "-ifscope",
                "en1",
                "fe80::1234:56ff:fe78:9abc%en1"
            ]
        );
        // An already-scoped router is passed through unchanged.
        let cmd = build_scoped_default_add_v6("en1", "fe80::1%en1");
        assert_eq!(cmd.last().unwrap(), "fe80::1%en1");
    }

    /// Teardown residue: only an en0-scoped default survives, so for primary
    /// en1 BOTH the unscoped default and the en1-scoped default are missing.
    const NETSTAT_V6_BOTH_DEFAULTS_MISSING: &str = "\
default                                 fe80::1234:56ff:fe78:9abc%en0           UGdScIg               en0
::1                                     ::1                                     UHL                   lo0
";

    #[test]
    fn v6_repair_plans_exactly_the_missing_defaults_from_sc_primary_and_router() {
        // The composed contract: the plan is derived ONLY from SC's
        // PrimaryInterface + Router, and re-adds exactly the defaults the
        // table proves missing. `None` egress (no v6 route resolves, the
        // normal post-teardown shape) must not block the repair.
        let plan = plan_primary_defaults_repair_v6(
            SCUTIL_GLOBAL_IPV6,
            NETSTAT_V6_BOTH_DEFAULTS_MISSING,
            None,
        )
        .expect("both defaults missing and egress off-tunnel: a plan is due");
        assert_eq!(plan.pif, "en1");
        assert_eq!(
            plan.unscoped_add.as_deref(),
            Some(
                &[
                    "-n".to_owned(),
                    "add".into(),
                    "-inet6".into(),
                    "default".into(),
                    "fe80::1234:56ff:fe78:9abc%en1".into()
                ][..]
            ),
            "the unscoped default is rebuilt from SC's router, zone-scoped to \
             SC's primary interface"
        );
        assert_eq!(
            plan.scoped_add.as_deref(),
            Some(
                &[
                    "-n".to_owned(),
                    "add".into(),
                    "-inet6".into(),
                    "default".into(),
                    "-ifscope".into(),
                    "en1".into(),
                    "fe80::1234:56ff:fe78:9abc%en1".into()
                ][..]
            ),
            "the scoped default is pinned to SC's primary interface"
        );
    }

    #[test]
    fn v6_repair_plans_only_the_unscoped_default_when_the_scoped_survives() {
        // The two fingerprints gate independently: en1 still carries its
        // scoped default, so only the unscoped one is re-added.
        let table = "\
default                                 fe80::1234:56ff:fe78:9abc%en1           UGScIg                en1
";
        let plan = plan_primary_defaults_repair_v6(SCUTIL_GLOBAL_IPV6, table, Some("en1"))
            .expect("unscoped default missing: a plan is due");
        assert!(plan.unscoped_add.is_some());
        assert_eq!(
            plan.scoped_add, None,
            "a surviving scoped default must never be re-added"
        );
    }

    #[test]
    fn v6_repair_is_a_no_op_while_egress_still_rides_a_tunnel() {
        // THE talpid<->route-split timing contract: the app's route manager
        // clears tunnel routes asynchronously relative to its reset path, so
        // its immediate repair call (and any retry racing a reconnect) is
        // only safe because a snapshot whose v6 egress still resolves through
        // a tunnel plans NOTHING, missing defaults notwithstanding.
        let plan = plan_primary_defaults_repair_v6(
            SCUTIL_GLOBAL_IPV6,
            NETSTAT_V6_BOTH_DEFAULTS_MISSING,
            Some("utun5"),
        );
        assert_eq!(
            plan, None,
            "the leak guard must win over the missing-default fingerprint"
        );
    }

    #[test]
    fn v6_repair_is_a_no_op_on_a_healed_table() {
        // Idempotency half of the contract: retries on an already-healed
        // table (late retry, raced reconnect) must plan nothing.
        let healed = "\
default                                 fe80::1234:56ff:fe78:9abc%en1           UGdScg                en1
default                                 fe80::1234:56ff:fe78:9abc%en1           UGScIg                en1
";
        assert_eq!(
            plan_primary_defaults_repair_v6(SCUTIL_GLOBAL_IPV6, healed, Some("en1")),
            None
        );
    }

    #[test]
    fn v6_repair_never_fabricates_from_missing_sc_data() {
        // Half-data must never become a route: no Router in SC's global v6
        // state means nothing trustworthy to re-add, whatever the table says.
        let no_router = "<dictionary> {\n  PrimaryInterface : en1\n}\n";
        assert_eq!(
            plan_primary_defaults_repair_v6(no_router, NETSTAT_V6_BOTH_DEFAULTS_MISSING, None),
            None
        );
    }

    #[test]
    fn install_emits_no_exit_host_route_only_the_split_halves() {
        // Port Fail / TunnelCrack ServerIP fix: the exit socket stays on the
        // physical link via IP_BOUND_IF, so NO `route add -host <exit>`
        // exception is emitted. Only the /1 halves - and the builder no
        // longer even takes an exit IP / default iface / gateway, so no
        // such exception can be reintroduced at the call site either.
        let cmds = build_install_commands("utun7");
        assert_eq!(cmds.len(), 2, "only the two /1 halves; got: {cmds:#?}");
        let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("-host"),
            "no exit host-route exception may be emitted; got: {joined}"
        );
    }

    #[test]
    fn install_commands_are_the_split_default_halves_via_tun() {
        let cmds = build_install_commands("utun7");
        assert_eq!(cmds.len(), 2, "2 commands: the two /1 halves");
        assert_eq!(
            cmds[0],
            vec!["add", "-net", "0.0.0.0/1", "-interface", "utun7"],
        );
        assert_eq!(
            cmds[1],
            vec!["add", "-net", "128.0.0.0/1", "-interface", "utun7"],
        );
    }

    #[test]
    fn install_propagates_tun_name_into_route_add() {
        // Sentinel against a typo that would silently route through
        // the wrong interface (= no traffic flows, hard to debug).
        let cmds = build_install_commands("warren-cli");
        assert!(
            cmds[0].contains(&"warren-cli".to_string()),
            "tun name must be propagated verbatim, got {:#?}",
            cmds[0]
        );
        assert!(
            cmds[1].contains(&"warren-cli".to_string()),
            "tun name must be propagated verbatim, got {:#?}",
            cmds[1]
        );
    }

    // The v4 clean uninstall + Drop are now ownership-scoped (reclaim only
    // owned/dangling /1 halves + the exact per-exit host route), exactly like
    // `force_cleanup_all`; that logic is covered by the `reclaim_decision`
    // tests. There is no longer a pure `build_uninstall_commands` v4 builder.

    #[test]
    fn parse_default_iface_extracts_interface_from_real_output() {
        // Recorded `route -n get default` output from a real macOS
        // 14.x box. Anchors the parser against an authentic fixture
        // so a future macOS update that changes whitespace or label
        // casing surfaces here, not in production.
        let fixture = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";
        assert_eq!(parse_default_iface(fixture).as_deref(), Some("en0"));
    }

    #[test]
    fn parse_default_iface_handles_alternative_iface_names() {
        // Tethered iPhone shows up as `en4`, USB-Ethernet as `en6`,
        // utun-over-VPN as `utun3`. The parser must not hardcode a
        // prefix, only the `interface:` label.
        for iface in ["en4", "en6", "utun3", "bridge100"] {
            let fixture = format!("  interface: {iface}\n  flags: <whatever>\n");
            assert_eq!(parse_default_iface(&fixture), Some(iface.to_owned()));
        }
    }

    #[test]
    fn parse_default_iface_returns_none_when_label_absent() {
        // No default route (link down) → no `interface:` line. The
        // parser must return None so the caller surfaces a clear
        // diagnostic instead of swallowing the empty value.
        let fixture = "route: writing to routing socket: not in table\n";
        assert_eq!(parse_default_iface(fixture), None);
    }

    #[test]
    fn parse_default_iface_returns_none_on_blank_value() {
        // Defensive: an empty-after-prefix line must not yield Some("")
        // - a downstream `route add -interface ""` would silently send
        // packets to the wrong path.
        let fixture = "  interface: \n";
        assert_eq!(parse_default_iface(fixture), None);
    }

    #[test]
    fn parse_default_gateway_extracts_from_route_output() {
        // Real `route -n get default` from macOS 14/15. The gateway is
        // the LAN router used for the gateway-form exit exception.
        let fixture = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
";
        assert_eq!(
            parse_default_gateway(fixture).as_deref(),
            Some("192.168.1.254")
        );
    }

    #[test]
    fn parse_default_gateway_returns_none_when_absent() {
        // A point-to-point default route (e.g. a cellular/utun link) has
        // an `interface:` line but no `gateway:` line. The parser must
        // return None so the caller falls back to the interface form.
        let fixture = "  interface: utun3\n  flags: <UP,DONE>\n";
        assert_eq!(parse_default_gateway(fixture), None);
    }

    #[test]
    fn parse_scutil_router_extracts_physical_gateway() {
        // The scutil Router value is the tunnel-resistant physical LAN
        // gateway, used when `route get default` is shadowed by the tun.
        let fixture = "<dictionary> {\n  PrimaryInterface : en8\n  Router : 192.168.1.254\n}\n";
        assert_eq!(
            parse_scutil_router(fixture).as_deref(),
            Some("192.168.1.254")
        );
    }

    #[test]
    fn parse_scutil_router_returns_none_when_absent() {
        assert_eq!(parse_scutil_router("<dictionary> {\n}\n"), None);
    }

    #[test]
    fn reclaim_decision_never_touches_physical_or_unresolved() {
        let owned: HashSet<String> = HashSet::new();
        // Physical NIC carrying the half (no split installed) → keep.
        assert!(!reclaim_decision(Some("en0"), &owned, true));
        // Probe did not resolve → keep (we know nothing, touch nothing).
        assert!(!reclaim_decision(None, &owned, false));
    }

    #[test]
    fn reclaim_decision_deletes_owned_or_dangling_tunnel_split() {
        let mut owned: HashSet<String> = HashSet::new();
        owned.insert("utun7".to_owned());
        // Our own live split → reclaim (e.g. force-disconnect).
        assert!(reclaim_decision(Some("utun7"), &owned, true));
        // A split pointing at a TUN that no longer exists = a crashed
        // process's leak → reclaim even though it is not in `owned`.
        assert!(reclaim_decision(Some("utun9"), &owned, false));
    }

    #[test]
    fn reclaim_decision_spares_live_foreign_tunnel() {
        // THE fix: a co-resident VPN's split points at its own LIVE tun,
        // which we do not own. We must never tear it down.
        let owned: HashSet<String> = HashSet::new();
        assert!(!reclaim_decision(Some("utun5"), &owned, true));
        // Even with one of our own splits registered, a different live
        // foreign tun is left alone.
        let mut owned_other: HashSet<String> = HashSet::new();
        owned_other.insert("utun7".to_owned());
        assert!(!reclaim_decision(Some("utun5"), &owned_other, true));
    }

    #[test]
    fn is_tunnel_iface_classifies_virtual_vs_physical() {
        for tun in ["utun4", "utun0", "tun0", "ipsec0", "ppp0"] {
            assert!(is_tunnel_iface(tun), "{tun} must be classified as a tunnel");
        }
        for phys in ["en0", "en8", "bridge100", "eth0"] {
            assert!(
                !is_tunnel_iface(phys),
                "{phys} must NOT be classified as a tunnel"
            );
        }
    }

    #[test]
    fn parse_scutil_primary_iface_extracts_physical_nic() {
        // Real `scutil` `show State:/Network/Global/IPv4` shape.
        let fixture = "<dictionary> {\n  PrimaryInterface : en8\n  PrimaryService : ABC\n  Router : 192.168.1.254\n}\n";
        assert_eq!(parse_scutil_primary_iface(fixture).as_deref(), Some("en8"));
    }

    #[test]
    fn parse_scutil_primary_iface_returns_none_when_absent() {
        assert_eq!(parse_scutil_primary_iface("<dictionary> {\n}\n"), None);
    }

    #[test]
    fn resolve_prefers_physical_route_default() {
        // Common pre-tunnel case: `route get default` already names the
        // physical NIC; scutil is irrelevant.
        assert_eq!(
            resolve_physical_default_iface(Some("en8"), None).unwrap(),
            "en8"
        );
    }

    #[test]
    fn resolve_falls_back_to_scutil_when_route_is_a_tunnel() {
        // THE bug this fixes: once the tunnel's own default route is in
        // place, `route get default` returns the tun (e.g. utun4).
        // Pinning the exit host-route to utun4 loops the tunnel onto
        // itself (downlink=0, "connects but no internet"). We MUST fall
        // back to the physical PrimaryInterface from scutil.
        let got = resolve_physical_default_iface(Some("utun4"), Some("en8"))
            .expect("must resolve to the physical NIC via scutil");
        assert_eq!(
            got, "en8",
            "exit route must pin to the physical NIC, never the tunnel"
        );
    }

    #[test]
    fn resolve_uses_scutil_when_route_default_missing() {
        assert_eq!(
            resolve_physical_default_iface(None, Some("en0")).unwrap(),
            "en0"
        );
    }

    #[test]
    fn resolve_gateway_trusts_physical_route_gateway() {
        // Common case: route get default names a physical NIC with a
        // gateway → that gateway carries the gateway-form exit route.
        assert_eq!(
            resolve_physical_gateway(Some("en0"), Some("192.168.1.254"), None).as_deref(),
            Some("192.168.1.254")
        );
    }

    #[test]
    fn resolve_gateway_falls_back_to_scutil_router_when_route_is_tunnel() {
        // Tunnel-shadowed route get default → use the tunnel-resistant
        // scutil Router (the real LAN gateway), never a tunnel gateway.
        assert_eq!(
            resolve_physical_gateway(Some("utun4"), None, Some("192.168.1.254")).as_deref(),
            Some("192.168.1.254")
        );
        assert_eq!(
            resolve_physical_gateway(None, None, Some("10.0.0.1")).as_deref(),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn resolve_gateway_is_none_for_physical_point_to_point_without_gateway() {
        // A physical point-to-point link has no gateway → None, so the
        // caller uses the interface form. We must NOT borrow the scutil
        // Router for a physical route (it may name an unrelated service).
        assert_eq!(
            resolve_physical_gateway(Some("en0"), None, Some("192.168.1.254")),
            None
        );
        assert_eq!(resolve_physical_gateway(Some("utun4"), None, None), None);
    }

    #[test]
    fn resolve_errors_rather_than_pinning_exit_to_a_tunnel() {
        // If BOTH sources only see a tunnel (or nothing), we refuse:
        // erroring out is strictly safer than silently installing the
        // exit route via a tunnel and shipping a dead tunnel.
        assert!(
            resolve_physical_default_iface(Some("utun4"), Some("utun7")).is_err(),
            "two tunnels must yield an error, not a tunnel pin"
        );
        assert!(resolve_physical_default_iface(Some("utun4"), None).is_err());
        assert!(resolve_physical_default_iface(None, None).is_err());
    }

    // --- discover_physical_ifindex / ifindex_from_name ---------------------
    //
    // `lo0` is a stable, always-present macOS interface, so the name→index
    // lookup is exercised for real (no fixture) without touching routing.

    #[test]
    fn ifindex_from_name_resolves_a_real_interface() {
        let idx = ifindex_from_name("lo0").expect("lo0 must resolve on any macOS host");
        assert_ne!(
            idx, 0,
            "0 is the unspecified index and would defeat IP_BOUND_IF"
        );
    }

    #[test]
    fn ifindex_from_name_errors_on_a_nonexistent_interface() {
        assert!(ifindex_from_name("warren-test-no-such-iface99").is_err());
    }

    #[test]
    fn ifindex_from_name_never_returns_zero() {
        // Guard invariant: every `Ok` must be nonzero, or a caller feeding it
        // straight into `IP_BOUND_IF` would silently unbind instead of pin.
        for name in ["lo0", "warren-test-no-such-iface99", ""] {
            if let Ok(idx) = ifindex_from_name(name) {
                assert_ne!(idx, 0, "{name:?} resolved to the unspecified index 0");
            }
        }
    }
}
