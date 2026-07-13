//! Policy routing to send Internet traffic through the Warren TUN
//! while preserving the Warren client UDP socket connectivity to the
//! exit (i.e. avoid the routing loop that poisons the tunnel).
//!
//! ## Problem
//!
//! Naively adding `ip route add 0.0.0.0/1 dev <tun> + 128.0.0.0/1`
//! in the `main` table also captures **the outbound QUIC packets**
//! from the Warren client to the exit endpoint. The bypass
//! `<exit_ip>/32 dev eth0` (scope link without `via gateway`) does
//! not work on typical VPS providers (AWS, GCP, and similar) where the
//! exit IP is not on the same L2 as eth0: ARP fail, kernel re-routes
//! via the /1 dev tun, loop, tunnel auto-poison.
//!
//! ## Solution
//!
//! Policy routing with dedicated table 100 + a socket-keyed exception for
//! the tunnel's OWN carrier socket via the main table (where the eth0
//! default route lives). The exit IP itself is never special-cased by
//! destination (that shape is the Port Fail / TunnelCrack ServerIP hole:
//! it would grant the off-tunnel exception to any local process that
//! merely dials the exit's address, not just the daemon):
//!
//! ```text
//! table 100 :
//!     0.0.0.0/1 dev <tun>
//!     128.0.0.0/1 dev <tun>
//!
//! ip rule (increasing priority) :
//!     pref 50 : fwmark <WARREN_TUNNEL_FWMARK> lookup main   <- bypass: the daemon's own marked carrier socket uses the eth0 default route
//!     pref 51 : from all lookup 100                          <- everything else (including traffic to the exit IP): split-default via tun
//! ```
//!
//! For an outbound packet from the tunnel's own `SO_MARK`-tagged carrier socket:
//! - pref 50 matches -> table main -> default `via <gw> dev eth0` -> eth0 ok
//!
//! For an outbound packet to `8.8.8.8`, or to the exit IP from any OTHER
//! (unmarked) socket:
//! - pref 50 does not match -> pref 51 matches -> table 100 -> tun -> tunnelled, never leaked
//!
//! ## Platforms
//!
//! This module is the **Linux** recipe (`ip rule` + dedicated table 100),
//! shared by a desktop daemon (via a caller-side wrapper that
//! injects the split-tunnel fwmark bypass) and the standalone CLI (via
//! `--bypass-cidr`). The macOS and Windows ports are sibling modules with
//! their own primitives: macOS uses route-specificity in the global table
//! (`route add -net /1 -interface <tun>`), Windows uses the native Win32 IP
//! Helper API (`warrenguard-winroute`) on the WinTUN alias; both key the
//! carrier's own escape on a socket bind (`IP_BOUND_IF` / `IP_UNICAST_IF`),
//! not a host-route exception. See `default_route_split_macos` and
//! `default_route_split_windows`.
//!
//! ## Reference
//!
//! The recipe originates in a real-network postmortem: pinning the
//! exit-bypass and split routes in a dedicated table was the fix for the
//! tunnel self-poisoning its own QUIC socket.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow};
use tokio::process::Command;
use warrenguard_killswitch_os::validate_tun_name as ks_validate_tun_name;
use warrenguard_tun_core::WARREN_TUNNEL_FWMARK;

pub use crate::bypass_cidr::BypassCidr;

/// Dedicated Linux routing table number for split-default.
/// Distinct from `policy_routing` (which uses table 42) to avoid
/// conflicts if both features are enabled simultaneously.
const ROUTE_TABLE: u32 = 100;

/// Priority of the "bypass user-supplied CIDRs via main" rules.
/// Must be lower than `RULE_PREF_TUN` so these rules are evaluated
/// first: a match sends traffic to table main -> eth0 default route,
/// bypassing the tunnel entirely (typical use: preserve LAN reach
/// and inbound SSH on the host's primary interface).
///
/// Same priority as `RULE_PREF_EXIT_BYPASS` is intentional: both
/// classes of bypass take effect via the same mechanism (lookup
/// main); the kernel evaluates rules with identical pref in
/// arbitrary order, but since each rule has a distinct `to <cidr>`
/// filter no ambiguity arises.
const RULE_PREF_BYPASS_CIDR: u32 = 49;

/// Priority of the "bypass exit IP via main" rule. Must be lower
/// than `RULE_PREF_TUN` so this rule is evaluated first:
/// match -> table main -> eth0 default route.
const RULE_PREF_EXIT_BYPASS: u32 = 50;

/// Priority of the "all traffic via table 100" rule. Must be higher
/// than `RULE_PREF_EXIT_BYPASS` and `RULE_PREF_BYPASS_CIDR` so the
/// bypasses win for packets matching their `to <cidr>` filter.
const RULE_PREF_TUN: u32 = 51;

/// Builds the list of `ip` commands to run to install the split-default
/// policy routing. Pure function, testable without shell-out.
///
/// Returned format: `Vec<Vec<String>>` where each inner vec is the
/// args to pass to `ip` (`args[0]`, `args[1]`, ...).
///
/// `bypass_cidrs` is the (possibly empty) list of additional IPv4
/// networks that should skip the tunnel and reach the host's main
/// routing table. The default route 0.0.0.0/0 still flows through
/// the TUN; only traffic matching `to <cidr>` in this list is
/// diverted.
///
/// The `ip rule` that routes the tunnel's OWN carrier socket (tagged with
/// `SO_MARK = WARREN_TUNNEL_FWMARK` in the transport layer) to the `main` table
/// so it egresses the physical NIC, while the split-default (table 100) captures
/// everything else into the tunnel. `verb` is `add`/`del`. This is the socket
/// half of the Port Fail / TunnelCrack ServerIP fix; it sits at the exit-bypass
/// priority, the slot the old `<exit_ip>/32` destination rule used to hold.
#[must_use]
pub fn build_tunnel_socket_fwmark_rule(verb: &str) -> Vec<String> {
    vec![
        "rule".into(),
        verb.into(),
        "fwmark".into(),
        format!("{WARREN_TUNNEL_FWMARK:#x}"),
        "lookup".into(),
        "main".into(),
        "pref".into(),
        RULE_PREF_EXIT_BYPASS.to_string(),
    ]
}

/// **Why expose a pure function**: enables unit-testing the exact
/// command order and content without depending on a Linux kernel.
/// Pattern borrowed from `warrenguard_killswitch_os::build_ruleset`.
///
/// **Port Fail / TunnelCrack ServerIP fix**: the exit's carrier socket is kept
/// on the physical link by its `SO_MARK` (set on the QUIC socket in the
/// transport layer) plus the `fwmark <WARREN_TUNNEL_FWMARK> lookup main` rule
/// below, NOT by a `<exit_ip>/32` host route. Keying the escape on the socket
/// mark, not the destination, means application traffic to the exit IP is
/// captured by the tunnel like anything else and cannot leak.
#[must_use]
pub fn build_install_commands(tun_name: &str, bypass_cidrs: &[BypassCidr]) -> Vec<Vec<String>> {
    let mut cmds = vec![
        // Split-default routes in the dedicated table 100.
        vec![
            "route".into(),
            "add".into(),
            "0.0.0.0/1".into(),
            "dev".into(),
            tun_name.into(),
            "table".into(),
            ROUTE_TABLE.to_string(),
        ],
        vec![
            "route".into(),
            "add".into(),
            "128.0.0.0/1".into(),
            "dev".into(),
            tun_name.into(),
            "table".into(),
            ROUTE_TABLE.to_string(),
        ],
        // ip rule: the tunnel's OWN marked carrier socket -> table main -> eth0
        // default. Replaces the old `to <exit>/32 lookup main` destination rule.
        build_tunnel_socket_fwmark_rule("add"),
    ];

    // User-supplied bypass CIDRs: each one becomes a separate
    // `ip rule add to <cidr> lookup main pref 49` so packets to that
    // network reach the host's main table (and thus the original
    // default route via the physical interface) instead of the TUN.
    for cidr in bypass_cidrs {
        cmds.push(vec![
            "rule".into(),
            "add".into(),
            "to".into(),
            cidr.to_string(),
            "lookup".into(),
            "main".into(),
            "pref".into(),
            RULE_PREF_BYPASS_CIDR.to_string(),
        ]);
    }

    // ip rule: all other traffic -> table 100 -> tun
    cmds.push(vec![
        "rule".into(),
        "add".into(),
        "lookup".into(),
        ROUTE_TABLE.to_string(),
        "pref".into(),
        RULE_PREF_TUN.to_string(),
    ]);

    cmds
}

/// Builds the list of `ip` commands to run for cleanup. Inverse order:
/// ip rule first (frees the priority), then ip route.
/// Caller-side idempotent (tolerates "No such file or directory").
#[must_use]
pub fn build_uninstall_commands(bypass_cidrs: &[BypassCidr]) -> Vec<Vec<String>> {
    let mut cmds = vec![
        // ip rule del (inverse order: highest pref first)
        vec![
            "rule".into(),
            "del".into(),
            "lookup".into(),
            ROUTE_TABLE.to_string(),
            "pref".into(),
            RULE_PREF_TUN.to_string(),
        ],
        build_tunnel_socket_fwmark_rule("del"),
    ];

    // Drop the user-supplied bypass rules (pref 49) before flushing
    // the table. Order within this block is the reverse of install
    // for symmetry, although `ip rule del` is order-insensitive when
    // the (to + pref) tuple is fully specified.
    for cidr in bypass_cidrs.iter().rev() {
        cmds.push(vec![
            "rule".into(),
            "del".into(),
            "to".into(),
            cidr.to_string(),
            "lookup".into(),
            "main".into(),
            "pref".into(),
            RULE_PREF_BYPASS_CIDR.to_string(),
        ]);
    }

    // Flush table 100 (equivalent to deleting every route we
    // installed there, and more robust if the install was partial).
    cmds.push(vec![
        "route".into(),
        "flush".into(),
        "table".into(),
        ROUTE_TABLE.to_string(),
    ]);

    cmds
}

/// Build the single `ip rule add` that routes split-tunnel "excluded" traffic
/// (tagged with `fwmark` by the firewall) to the `main` table so it egresses
/// the physical interface instead of the TUN. Sits at the same priority as the
/// user-CIDR bypass rules (both are `lookup main` exceptions). This is the
/// Linux desktop daemon's bypass mechanism; the standalone CLI uses
/// `--bypass-cidr` instead, but the rest of the recipe is identical, which is
/// why both share these builders.
#[must_use]
pub fn build_split_tunnel_fwmark_install_rule(fwmark: &str) -> Vec<String> {
    vec![
        "rule".into(),
        "add".into(),
        "fwmark".into(),
        fwmark.into(),
        "lookup".into(),
        "main".into(),
        "pref".into(),
        RULE_PREF_BYPASS_CIDR.to_string(),
    ]
}

/// Reverse of [`build_split_tunnel_fwmark_install_rule`]: remove the fwmark
/// bypass rule by its full `(fwmark, lookup main, pref)` selector.
#[must_use]
pub fn build_split_tunnel_fwmark_uninstall_rule(fwmark: &str) -> Vec<String> {
    vec![
        "rule".into(),
        "del".into(),
        "fwmark".into(),
        fwmark.into(),
        "lookup".into(),
        "main".into(),
        "pref".into(),
        RULE_PREF_BYPASS_CIDR.to_string(),
    ]
}

/// IPv6 counterpart of [`build_split_tunnel_fwmark_install_rule`]. The v6 rule
/// database is separate (`ip -6 rule`), so the same fwmark bypass must be added
/// there too with the `-6` prefix; the firewall's `meta mark` is family-
/// agnostic, so excluded-app traffic is marked on both families.
#[must_use]
pub fn build_split_tunnel_fwmark_install_rule_v6(fwmark: &str) -> Vec<String> {
    let mut rule = vec!["-6".to_string()];
    rule.extend(build_split_tunnel_fwmark_install_rule(fwmark));
    rule
}

/// Reverse of [`build_split_tunnel_fwmark_install_rule_v6`].
#[must_use]
pub fn build_split_tunnel_fwmark_uninstall_rule_v6(fwmark: &str) -> Vec<String> {
    let mut rule = vec!["-6".to_string()];
    rule.extend(build_split_tunnel_fwmark_uninstall_rule(fwmark));
    rule
}

/// Plan an ownership-scoped, exit-IP-agnostic reclaim of the Warren
/// split-default artifacts that *blackhole* traffic when leaked by a crashed
/// predecessor, given the current `ip rule` database (`ip rule show` output).
///
/// Ownership signal: Warren's private routing table [`ROUTE_TABLE`]. Only two
/// artifacts blackhole traffic when leaked, and both are unambiguously ours:
/// the policy rule whose action is `lookup <ROUTE_TABLE>`, and the two `/1`
/// halves living *inside* that table. We delete the rule by its own priority
/// together with the `lookup <ROUTE_TABLE>` action (so a foreign rule sitting
/// at the same priority but pointing elsewhere is never removed), and the `/1`
/// routes by destination within the table (so a foreign route parked in the
/// table survives, unlike a blanket `route flush table`).
///
/// The `lookup main` bypass rules (the exit-IP and user-CIDR exceptions) are
/// deliberately NOT reclaimed here: leaking them only diverts a few specific
/// destinations to the physical default route (no blackhole), and they cannot
/// be told apart from a co-resident tool's `lookup main` rules with confidence.
/// A clean teardown still removes them via [`build_uninstall_commands`].
#[must_use]
pub fn plan_force_cleanup(ip_rule_show: &str) -> Vec<Vec<String>> {
    let table = ROUTE_TABLE.to_string();
    let mut cmds = Vec::new();
    for line in ip_rule_show.lines() {
        if let Some(pref) = rule_pref_targeting_table(line, &table) {
            cmds.push(vec![
                "rule".into(),
                "del".into(),
                "pref".into(),
                pref.to_string(),
                "lookup".into(),
                table.clone(),
            ]);
        }
    }
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        cmds.push(vec![
            "route".into(),
            "del".into(),
            half.into(),
            "table".into(),
            table.clone(),
        ]);
    }
    cmds
}

/// If `line` (one line of `ip rule show`) is a policy rule whose action is
/// `lookup <table>`, return its priority. Returns `None` for the kernel's
/// built-in `lookup main`/`local`/`default` rules and for any rule pointing at
/// a different table, so a foreign rule sharing one of our priorities is never
/// matched.
fn rule_pref_targeting_table(line: &str, table: &str) -> Option<u32> {
    let (pref_str, rest) = line.split_once(':')?;
    let pref: u32 = pref_str.trim().parse().ok()?;
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let targets_table = tokens.windows(2).any(|w| w[0] == "lookup" && w[1] == table);
    targets_table.then_some(pref)
}

/// IPv6 counterpart of [`build_install_commands`]. Builds the `ip -6`
/// commands that send the host's IPv6 Internet traffic through the
/// Warren TUN via the dedicated table [`ROUTE_TABLE`].
///
/// Linux keeps **separate** routing-rule databases per family
/// (`ip rule` vs `ip -6 rule`) and separate per-family tables even
/// when they share a number, so every command is prefixed with `-6`
/// and table `100` here is the v6 table, fully disjoint from the v4
/// table `100` installed by [`build_install_commands`].
///
/// The v6 split uses `::/1` + `8000::/1` (the v6 analogue of the
/// `0.0.0.0/1` + `128.0.0.0/1` v4 halves) so it overrides any native
/// `::/0` default route without deleting it.
///
/// `exit_ip_v6` is the exit's UDP endpoint **only when the client
/// dials the exit over IPv6**. In that case a `to <exit>/128 lookup
/// main` bypass (pref [`RULE_PREF_EXIT_BYPASS`]) is required to keep
/// the outbound QUIC socket off the tunnel (same self-poison
/// avoidance as v4). When the exit is dialed over IPv4 (the current
/// architecture), pass `None`: the v6 routes cannot capture the v4
/// QUIC socket, so no bypass is needed.
///
/// Returned format mirrors [`build_install_commands`]: `Vec<Vec<String>>`,
/// each inner vec the args to pass to `ip` (starting with `-6`).
#[must_use]
pub fn build_install_commands_v6(
    _exit_ip_v6: Option<Ipv6Addr>,
    tun_name: &str,
) -> Vec<Vec<String>> {
    let mut cmds = vec![
        vec![
            "-6".into(),
            "route".into(),
            "add".into(),
            "::/1".into(),
            "dev".into(),
            tun_name.into(),
            "table".into(),
            ROUTE_TABLE.to_string(),
        ],
        vec![
            "-6".into(),
            "route".into(),
            "add".into(),
            "8000::/1".into(),
            "dev".into(),
            tun_name.into(),
            "table".into(),
            ROUTE_TABLE.to_string(),
        ],
    ];

    // The tunnel's own carrier socket escapes via its firewall mark, in the v6
    // rule database too (the mark is L3-agnostic but the rule databases are
    // per-family). Replaces the old `to <exit>/128 lookup main` destination
    // bypass, so a v6-dialed exit socket escapes without special-casing the exit
    // IP (Port Fail / TunnelCrack ServerIP fix). `_exit_ip_v6` is retained only
    // for API symmetry with the v6 guard; it no longer shapes any route.
    cmds.push(build_tunnel_socket_fwmark_rule_v6("add"));

    cmds.push(vec![
        "-6".into(),
        "rule".into(),
        "add".into(),
        "lookup".into(),
        ROUTE_TABLE.to_string(),
        "pref".into(),
        RULE_PREF_TUN.to_string(),
    ]);

    cmds
}

/// IPv6 counterpart of [`build_tunnel_socket_fwmark_rule`]: the v4 rule prefixed
/// with `-6` so it lands in the separate v6 rule database.
#[must_use]
pub fn build_tunnel_socket_fwmark_rule_v6(verb: &str) -> Vec<String> {
    let mut rule = vec!["-6".to_string()];
    rule.extend(build_tunnel_socket_fwmark_rule(verb));
    rule
}

/// IPv6 counterpart of [`build_uninstall_commands`]. Inverse order:
/// `ip -6 rule del` first (frees the priorities), then flush the v6
/// table [`ROUTE_TABLE`]. Caller-side idempotent (tolerates "No such").
///
/// `exit_ip_v6` must match the value passed to
/// [`build_install_commands_v6`] so the matching bypass rule is
/// removed (when it was installed).
#[must_use]
pub fn build_uninstall_commands_v6(_exit_ip_v6: Option<Ipv6Addr>) -> Vec<Vec<String>> {
    let mut cmds = vec![
        vec![
            "-6".into(),
            "rule".into(),
            "del".into(),
            "lookup".into(),
            ROUTE_TABLE.to_string(),
            "pref".into(),
            RULE_PREF_TUN.to_string(),
        ],
        build_tunnel_socket_fwmark_rule_v6("del"),
    ];

    cmds.push(vec![
        "-6".into(),
        "route".into(),
        "flush".into(),
        "table".into(),
        ROUTE_TABLE.to_string(),
    ]);

    cmds
}

/// RAII guard for the IPv6 split-default policy routing. Mirrors
/// [`DefaultRouteSplitGuard`] for the v6 family: installs `::/1` +
/// `8000::/1` into the dedicated v6 table on construction and tears it
/// down on [`uninstall`](Self::uninstall).
///
/// Unlike the brute `ip -6 route add default dev <tun>`, the split-halves
/// override any pre-existing native `::/0` default **without** an
/// `RTNETLINK File exists` failure, so a host with native IPv6 cannot
/// keep leaking v6 traffic around the tunnel.
#[derive(Debug)]
pub struct DefaultRouteSplitV6Guard {
    exit_ip_v6: Option<Ipv6Addr>,
    /// Optional split-tunnel fwmark bypass for the v6 family (desktop daemon
    /// variant), mirroring the v4 guard. When set, install/uninstall also
    /// manage the `-6 rule fwmark <mark> lookup main pref 49` rule.
    split_tunnel_fwmark: Option<String>,
    installed: bool,
}

impl DefaultRouteSplitV6Guard {
    /// Installs the v6 split-default routing for `tun_name`. When the exit
    /// is dialed over IPv6, pass its address as `exit_ip_v6` so the QUIC
    /// socket to the exit keeps bypassing the tunnel (self-poison
    /// avoidance, same as v4); pass `None` when the exit is dialed over
    /// IPv4 (the v6 routes then cannot capture the v4 transport socket).
    ///
    /// # Errors
    ///
    /// - Invalid `tun_name` (non-alphanumeric, > 15 chars, empty).
    /// - Missing privileges (CAP_NET_ADMIN required).
    /// - `ip` not in PATH.
    /// - `RTNETLINK answers: File exists` is **tolerated** (idempotent).
    pub async fn install(
        exit_ip_v6: Option<Ipv6Addr>,
        tun_name: &str,
        split_tunnel_fwmark: Option<&str>,
    ) -> Result<Self> {
        ks_validate_tun_name(tun_name).context("invalid tun_name")?;

        let mut cmds = build_install_commands_v6(exit_ip_v6, tun_name);
        if let Some(fwmark) = split_tunnel_fwmark {
            cmds.push(build_split_tunnel_fwmark_install_rule_v6(fwmark));
        }
        for args in &cmds {
            run_ip_tolerant_exists(args)
                .await
                .with_context(|| format!("ip {}", args.join(" ")))?;
        }

        tracing::info!(
            tun = tun_name,
            table = ROUTE_TABLE,
            exit_bypass_v6 = exit_ip_v6.is_some(),
            split_tunnel_fwmark = split_tunnel_fwmark.unwrap_or("none"),
            "Warren IPv6 split-default routing installed"
        );

        Ok(Self {
            exit_ip_v6,
            split_tunnel_fwmark: split_tunnel_fwmark.map(str::to_owned),
            installed: true,
        })
    }

    /// All `ip -6` teardown commands for this guard: the shared recipe plus the
    /// optional split-tunnel fwmark rule. Shared by `uninstall` and `Drop`.
    fn teardown_commands(&self) -> Vec<Vec<String>> {
        let mut cmds = build_uninstall_commands_v6(self.exit_ip_v6);
        if let Some(fwmark) = &self.split_tunnel_fwmark {
            cmds.push(build_split_tunnel_fwmark_uninstall_rule_v6(fwmark));
        }
        cmds
    }

    /// Removes the v6 rules + flushes the v6 table. Idempotent: tolerates
    /// "No such" if already deleted. Best-effort: logs warn, does not fail.
    pub async fn uninstall(mut self) -> Result<()> {
        for args in &self.teardown_commands() {
            if let Err(e) = run_ip_tolerant_no_such(args).await {
                tracing::warn!(
                    error = %e,
                    cmd = %args.join(" "),
                    "ip -6 cmd cleanup failed (non-fatal)"
                );
            }
        }
        self.installed = false;
        Ok(())
    }
}

impl Drop for DefaultRouteSplitV6Guard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // uninstall() was never awaited. Leaked `::/1`+`8000::/1` routes in
        // table 100 (plus the pref-51 rule) blackhole all v6 egress, so tear
        // them down synchronously here. Drop cannot await; a brief blocking
        // `ip` call beats leaking a v6 blackhole.
        tracing::warn!(
            "DefaultRouteSplitV6Guard dropped without explicit uninstall; \
             removing v6 routes synchronously"
        );
        for args in self.teardown_commands() {
            run_ip_sync_tolerant(&args);
        }
        self.installed = false;
    }
}

/// RAII guard: holds the "installed" state for automatic cleanup on drop.
#[derive(Debug)]
pub struct DefaultRouteSplitGuard {
    bypass_cidrs: Vec<BypassCidr>,
    /// Optional split-tunnel fwmark bypass (desktop daemon variant). When set,
    /// install/uninstall also manage the `fwmark <mark> lookup main pref 49`
    /// rule so excluded-app traffic egresses the physical NIC. The standalone
    /// CLI leaves this `None` and uses `bypass_cidrs` instead.
    split_tunnel_fwmark: Option<String>,
    installed: bool,
}

impl DefaultRouteSplitGuard {
    /// Installs the split-default policy routing for `tun_name`. `exit_ip` is
    /// retained only for the install log and the `Some`/`None` install gate: the
    /// exit's carrier socket is now kept on the physical link by its `SO_MARK`
    /// plus the `fwmark <WARREN_TUNNEL_FWMARK> lookup main` rule, NOT a
    /// `<exit_ip>/32` host route (Port Fail / TunnelCrack ServerIP fix), so it no
    /// longer shapes any route. `bypass_cidrs` and `split_tunnel_fwmark` are the
    /// unrelated user-CIDR and excluded-app exclusions.
    ///
    /// # Errors
    ///
    /// - Invalid `tun_name` (non-alphanumeric, > 15 chars, empty).
    /// - Missing privileges (CAP_NET_ADMIN required).
    /// - `ip` not in PATH.
    /// - `RTNETLINK answers: File exists` is **tolerated** (idempotent).
    pub async fn install(
        exit_ip: Ipv4Addr,
        tun_name: &str,
        bypass_cidrs: &[BypassCidr],
        split_tunnel_fwmark: Option<&str>,
    ) -> Result<Self> {
        ks_validate_tun_name(tun_name).context("invalid tun_name")?;

        let mut cmds = build_install_commands(tun_name, bypass_cidrs);
        if let Some(fwmark) = split_tunnel_fwmark {
            cmds.push(build_split_tunnel_fwmark_install_rule(fwmark));
        }
        for args in &cmds {
            run_ip_tolerant_exists(args)
                .await
                .with_context(|| format!("ip {}", args.join(" ")))?;
        }

        tracing::info!(
            tun = tun_name,
            exit_ip = %exit_ip,
            table = ROUTE_TABLE,
            bypass_cidr_count = bypass_cidrs.len(),
            split_tunnel_fwmark = split_tunnel_fwmark.unwrap_or("none"),
            "Warren default-route split-tunnel installed"
        );

        Ok(Self {
            bypass_cidrs: bypass_cidrs.to_vec(),
            split_tunnel_fwmark: split_tunnel_fwmark.map(str::to_owned),
            installed: true,
        })
    }

    /// All `ip` teardown commands for this guard: the shared recipe plus the
    /// optional split-tunnel fwmark rule. Shared by `uninstall` and `Drop`.
    fn teardown_commands(&self) -> Vec<Vec<String>> {
        let mut cmds = build_uninstall_commands(&self.bypass_cidrs);
        if let Some(fwmark) = &self.split_tunnel_fwmark {
            cmds.push(build_split_tunnel_fwmark_uninstall_rule(fwmark));
        }
        cmds
    }

    /// Removes the rules. Idempotent: tolerates "No such file" if already
    /// deleted. Best-effort: logs warn but does not fail.
    pub async fn uninstall(mut self) -> Result<()> {
        for args in &self.teardown_commands() {
            if let Err(e) = run_ip_tolerant_no_such(args).await {
                tracing::warn!(
                    error = %e,
                    cmd = %args.join(" "),
                    "ip cmd cleanup failed (non-fatal)"
                );
            }
        }
        self.installed = false;
        Ok(())
    }
}

impl Drop for DefaultRouteSplitGuard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // uninstall() was never awaited (panic, task abort, early return). A
        // leaked table-100 split-default + its `lookup 100` rule blackholes
        // the next relay dial, so remove it synchronously here rather than
        // only logging.
        tracing::warn!(
            "DefaultRouteSplitGuard dropped without explicit uninstall; \
             removing routes synchronously"
        );
        for args in self.teardown_commands() {
            run_ip_sync_tolerant(&args);
        }
        self.installed = false;
    }
}

/// Upper bound on a single synchronous cleanup command. These run in `Drop`
/// and on recovery paths, so an `ip` invocation wedged on a stuck netlink
/// socket must never hang teardown indefinitely. On timeout the child is killed
/// and the failure logged.
const SYNC_CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Synchronous, best-effort `ip` invocation for the `Drop` paths that cannot
/// `await`. Tolerates "already gone" stderr, bounds its own runtime, and never
/// panics, so it is safe to call from `Drop` and during shutdown.
fn run_ip_sync_tolerant(args: &[String]) {
    let mut child = match std::process::Command::new("ip")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            tracing::warn!(error = %e, cmd = %args.join(" "), "spawn ip sync cleanup failed (non-fatal)");
            return;
        }
    };

    let Some(status) = wait_sync_command(&mut child, SYNC_CLEANUP_TIMEOUT) else {
        let _ = child.kill();
        let _ = child.wait();
        tracing::warn!(
            cmd = %args.join(" "),
            timeout = ?SYNC_CLEANUP_TIMEOUT,
            "ip sync cleanup did not complete within timeout (killed)"
        );
        return;
    };

    if status.success() {
        return;
    }

    let mut stderr = String::new();
    if let Some(mut handle) = child.stderr.take() {
        use std::io::Read;
        let _ = handle.read_to_string(&mut stderr);
    }
    if stderr.contains("No such") || stderr.contains("not found") || stderr.contains("does not") {
        return;
    }
    tracing::warn!(
        cmd = %args.join(" "),
        stderr = %stderr.trim(),
        "ip sync cleanup failed (non-fatal)"
    );
}

/// Poll-based portable bounded wait. `std` has no `wait_timeout`, so poll
/// `try_wait` on a short interval until the deadline. Returns `None` if the
/// child has not exited by the deadline (or the wait itself errored), in which
/// case the caller kills it.
fn wait_sync_command(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + timeout;
    // Micro-backoff poll: `ip` exits in a few ms and these calls stack
    // up on every tunnel state transition, so a coarse fixed period
    // would multiply into ~100+ ms of pure polling.
    let mut poll = std::time::Duration::from_millis(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "waiting on ip child failed (sync cleanup, non-fatal)");
                return None;
            }
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(poll);
        poll = (poll * 2).min(std::time::Duration::from_millis(4));
    }
}

/// Run `ip <args>` synchronously and capture stdout, bounded by
/// `SYNC_CLEANUP_TIMEOUT`. Best-effort: returns `None` on spawn failure,
/// timeout, or a non-zero exit. Used by the recovery sweep to read the current
/// `ip rule` database before planning what to reclaim.
#[cfg(target_os = "linux")]
fn run_ip_capture_sync(args: &[&str]) -> Option<String> {
    let mut child = std::process::Command::new("ip")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    match wait_sync_command(&mut child, SYNC_CLEANUP_TIMEOUT) {
        Some(status) if status.success() => {
            use std::io::Read;
            let mut out = String::new();
            child.stdout.take()?.read_to_string(&mut out).ok()?;
            Some(out)
        }
        Some(_) => None,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

/// Ownership-scoped synchronous reclaim of any Warren split-default artifacts
/// left behind, including by a crashed predecessor with no surviving guard.
/// Reads the live `ip rule` database and removes only the Warren-owned
/// blackhole artifacts (see [`plan_force_cleanup`]); a co-resident tool's rules
/// and routes are spared. Idempotent, never panics, safe to call from `Drop`
/// and from the tunnel state machine's recovery paths.
#[cfg(target_os = "linux")]
pub fn force_cleanup_all() {
    let ip_rule_show = run_ip_capture_sync(&["rule", "show"]).unwrap_or_default();
    for args in plan_force_cleanup(&ip_rule_show) {
        run_ip_sync_tolerant(&args);
    }
}

async fn run_ip_tolerant_exists(args: &[String]) -> Result<()> {
    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = Command::new("ip")
        .args(&str_args)
        .output()
        .await
        .with_context(|| format!("spawn ip {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("File exists") {
        return Ok(());
    }
    Err(anyhow!("ip {} failed: {}", args.join(" "), stderr.trim()))
}

async fn run_ip_tolerant_no_such(args: &[String]) -> Result<()> {
    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = Command::new("ip")
        .args(&str_args)
        .output()
        .await
        .with_context(|| format!("spawn ip {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("No such") || stderr.contains("not found") || stderr.contains("does not") {
        return Ok(());
    }
    Err(anyhow!("ip {} failed: {}", args.join(" "), stderr.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn ip6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    // --- split-tunnel fwmark bypass rule (desktop daemon variant) ---

    #[test]
    fn split_tunnel_fwmark_install_rule_routes_marked_traffic_to_main_at_pref_49() {
        // The excluded-app fwmark must be routed to `main` (= physical NIC) and
        // sit at the bypass priority, ahead of the `lookup 100` tun rule, so
        // marked packets leave around the tunnel instead of into it.
        let rule = build_split_tunnel_fwmark_install_rule("0x6d6f6c65");
        assert_eq!(
            rule,
            vec![
                "rule",
                "add",
                "fwmark",
                "0x6d6f6c65",
                "lookup",
                "main",
                "pref",
                "49"
            ]
        );
    }

    #[test]
    fn v6_split_tunnel_fwmark_install_rule_is_the_v4_rule_prefixed_with_dash_6() {
        // The v6 ip-rule database is separate (`ip -6 rule`), so the v6 fwmark
        // bypass must carry the `-6` prefix; everything else matches v4 (route
        // marked traffic to main at the bypass priority).
        let rule = build_split_tunnel_fwmark_install_rule_v6("0x6d6f6c65");
        assert_eq!(
            rule,
            vec![
                "-6",
                "rule",
                "add",
                "fwmark",
                "0x6d6f6c65",
                "lookup",
                "main",
                "pref",
                "49"
            ]
        );
    }

    #[test]
    fn v6_split_tunnel_fwmark_uninstall_is_the_exact_inverse_of_install() {
        let mark = "0x6d6f6c65";
        let install = build_split_tunnel_fwmark_install_rule_v6(mark);
        let uninstall = build_split_tunnel_fwmark_uninstall_rule_v6(mark);
        assert_eq!(install[0], "-6");
        assert_eq!(install[2], "add");
        assert_eq!(uninstall[2], "del");
        // The `-6` prefix + the whole selector after the verb are identical.
        assert_eq!(install[3..], uninstall[3..]);
    }

    #[test]
    fn split_tunnel_fwmark_uninstall_is_the_exact_inverse_of_install() {
        // Teardown must match install on the full (fwmark, lookup, pref) tuple
        // so it removes our rule and only ours.
        let mark = "0x6d6f6c65";
        let install = build_split_tunnel_fwmark_install_rule(mark);
        let uninstall = build_split_tunnel_fwmark_uninstall_rule(mark);
        assert_eq!(install[0], "rule");
        assert_eq!(install[1], "add");
        assert_eq!(uninstall[1], "del");
        // Everything after the verb is identical (the selector).
        assert_eq!(install[2..], uninstall[2..]);
    }

    // --- force-cleanup ownership-scoped reclaim (plan_force_cleanup) ---

    /// Canonical `ip rule show` output with Warren's split-default rule
    /// installed (pref 51 -> `lookup 100`) plus the kernel's built-in rules.
    const IP_RULE_SHOW_WITH_WARREN: &str = "\
0:\tfrom all lookup local
50:\tfrom all to 203.0.113.7 lookup main
51:\tfrom all lookup 100
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";

    #[test]
    fn force_cleanup_deletes_the_lookup_100_rule_by_its_priority() {
        // The split-default rule (`lookup 100`) is the artifact that blackholes
        // all traffic when leaked. It must be reclaimed, addressed by its own
        // priority + the `lookup 100` action so the deletion is precise.
        let plan = plan_force_cleanup(IP_RULE_SHOW_WITH_WARREN);
        assert!(
            plan.contains(&vec![
                "rule".to_string(),
                "del".to_string(),
                "pref".to_string(),
                "51".to_string(),
                "lookup".to_string(),
                "100".to_string(),
            ]),
            "must delete the lookup-100 rule at its priority; got: {plan:#?}"
        );
    }

    #[test]
    fn force_cleanup_deletes_the_two_v4_halves_inside_table_100_not_a_flush() {
        // The two /1 halves live inside the private table; removing them by
        // destination (rather than flushing the whole table) is what spares any
        // foreign route a co-resident tool might have parked in table 100.
        let plan = plan_force_cleanup(IP_RULE_SHOW_WITH_WARREN);
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            assert!(
                plan.contains(&vec![
                    "route".to_string(),
                    "del".to_string(),
                    half.to_string(),
                    "table".to_string(),
                    "100".to_string(),
                ]),
                "must delete {half} from table 100; got: {plan:#?}"
            );
        }
        assert!(
            !plan.iter().any(|c| c.contains(&"flush".to_string())),
            "must NOT flush the whole table; got: {plan:#?}"
        );
    }

    #[test]
    fn force_cleanup_spares_a_foreign_rule_parked_at_our_priority() {
        // A co-resident tool's rule sitting at pref 51 but pointing at a
        // DIFFERENT table must never be deleted: the old blind `ip rule del
        // pref 51` would have removed it. Ownership is the table, not the pref.
        let foreign = "\
0:\tfrom all lookup local
51:\tfrom all lookup 200
32766:\tfrom all lookup main
";
        let plan = plan_force_cleanup(foreign);
        assert!(
            !plan.iter().any(|c| c[0] == "rule"),
            "no rule deletion may target a foreign rule; got: {plan:#?}"
        );
    }

    #[test]
    fn force_cleanup_spares_lookup_main_bypass_rules() {
        // The exit-IP / bypass-CIDR exceptions (`lookup main`) are harmless if
        // leaked and indistinguishable from a co-resident tool's rules, so the
        // reclaim must never emit a deletion that targets the `main` table.
        let plan = plan_force_cleanup(IP_RULE_SHOW_WITH_WARREN);
        assert!(
            !plan.iter().any(|c| c.contains(&"main".to_string())),
            "must never delete a `lookup main` rule; got: {plan:#?}"
        );
        // And it must never touch the system default route.
        assert!(
            !plan
                .iter()
                .any(|c| c.contains(&"0.0.0.0/0".to_string()) || c.contains(&"default".to_string())),
            "must never touch the default route; got: {plan:#?}"
        );
    }

    #[test]
    fn force_cleanup_with_no_warren_rule_emits_only_the_route_dels() {
        // A clean host (no split-default rule installed) must still attempt the
        // idempotent /1 route dels (tolerated as "already gone" at runtime) and
        // emit zero rule deletions.
        let clean = "\
0:\tfrom all lookup local
32766:\tfrom all lookup main
32767:\tfrom all lookup default
";
        let plan = plan_force_cleanup(clean);
        assert!(
            plan.iter().all(|c| c[0] == "route"),
            "no rule deletions on a clean host; got: {plan:#?}"
        );
        assert_eq!(
            plan.len(),
            2,
            "exactly the two /1 route dels; got: {plan:#?}"
        );
    }

    // --- IPv6 split-default tests ---

    #[test]
    fn v6_install_first_two_commands_are_v6_split_halves_in_table_100() {
        // The v6 split must use ::/1 + 8000::/1 (the IPv6 analogue of
        // the v4 0.0.0.0/1 + 128.0.0.0/1 halves), prefixed `-6`, in the
        // dedicated table 100. Anti-regression: dropping `-6` would push
        // the routes into the v4 family (no-op for v6 traffic = leak).
        let cmds = build_install_commands_v6(None, "warren-cli");
        assert_eq!(
            cmds[0],
            vec![
                "-6",
                "route",
                "add",
                "::/1",
                "dev",
                "warren-cli",
                "table",
                "100"
            ]
        );
        assert_eq!(
            cmds[1],
            vec![
                "-6",
                "route",
                "add",
                "8000::/1",
                "dev",
                "warren-cli",
                "table",
                "100"
            ]
        );
    }

    #[test]
    fn v6_install_has_4_commands_ending_in_tun_lookup() {
        // 2 routes + the tunnel-socket fwmark bypass + the tun-lookup rule = 4.
        let cmds = build_install_commands_v6(None, "warren-cli");
        assert_eq!(cmds.len(), 4, "got: {cmds:#?}");
        assert_eq!(
            cmds.last().expect("non-empty"),
            &vec!["-6", "rule", "add", "lookup", "100", "pref", "51"]
        );
    }

    #[test]
    fn v6_install_uses_the_socket_fwmark_bypass_not_a_destination_rule() {
        // Port Fail fix: the v6 escape is keyed on the tunnel socket's firewall
        // mark, present regardless of whether the exit is dialed over v6, and it
        // NEVER references the exit IP by destination.
        for exit in [None, Some(ip6("2001:db8:1::2"))] {
            let cmds = build_install_commands_v6(exit, "warren-cli");
            assert_eq!(
                cmds[2],
                vec![
                    "-6",
                    "rule",
                    "add",
                    "fwmark",
                    "0x77617272",
                    "lookup",
                    "main",
                    "pref",
                    "50"
                ],
                "the v6 fwmark bypass must precede the tun-lookup rule; got: {cmds:#?}"
            );
            let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
            assert!(
                !joined.contains("/128") && !joined.contains("2001:db8:1::2"),
                "no host route to the exit may be emitted; got: {joined}"
            );
        }
    }

    #[test]
    fn v6_builder_never_emits_ipv4_routes() {
        // Anti-regression: the v6 builder must not accidentally emit any
        // IPv4 literal (a copy-paste of the v4 halves would silently fail
        // to capture v6 traffic).
        let cmds = build_install_commands_v6(Some(ip6("2001:db8:1::2")), "warren-cli");
        let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("0.0.0.0") && !joined.contains("128.0.0.0"),
            "v6 builder must not emit IPv4 routes, got: {joined}"
        );
    }

    #[test]
    fn v6_uninstall_dels_the_rules_then_flushes_table_100_not_main() {
        // Cleanup: the tun-lookup rule and the fwmark bypass are deleted first,
        // then the dedicated v6 table 100 is flushed (never `main`, which holds
        // the host's native ::/0 default). No exit-destination rule is referenced.
        let cmds = build_uninstall_commands_v6(None);
        assert_eq!(cmds.len(), 3, "got: {cmds:#?}");
        assert_eq!(
            cmds[0],
            vec!["-6", "rule", "del", "lookup", "100", "pref", "51"]
        );
        assert_eq!(
            cmds[1],
            vec![
                "-6",
                "rule",
                "del",
                "fwmark",
                "0x77617272",
                "lookup",
                "main",
                "pref",
                "50"
            ]
        );
        let flush = cmds.last().expect("non-empty");
        assert_eq!(
            flush[0..3],
            vec!["-6".to_string(), "route".to_string(), "flush".to_string()]
        );
        assert!(flush.contains(&"100".to_string()));
        assert!(
            !flush.contains(&"main".to_string()),
            "must NOT flush table main (= would destroy native v6 default)"
        );
    }

    fn cidr(network: &str, prefix: u8) -> BypassCidr {
        BypassCidr {
            network: ip(network),
            prefix,
        }
    }

    #[test]
    fn install_commands_count_is_4_without_bypass() {
        // 2 split-default routes + 2 ip rules = 4 total commands.
        // Test freezes this anti-regression contract: if someone adds
        // a command without documenting it, the test fails and forces
        // an update of both tests and docs.
        let cmds = build_install_commands("warren-cli", &[]);
        assert_eq!(
            cmds.len(),
            4,
            "expected 4 commands (2 routes + 2 rules), got {} : {:#?}",
            cmds.len(),
            cmds
        );
    }

    #[test]
    fn install_first_two_commands_are_split_default_routes() {
        // The first 2 commands must install the split-default routes
        // in the dedicated table. Test freezes the content for
        // anti-regression (if someone removes `table 100`, the tunnel
        // breaks in production).
        let cmds = build_install_commands("warren-cli", &[]);
        assert_eq!(
            cmds[0],
            vec![
                "route",
                "add",
                "0.0.0.0/1",
                "dev",
                "warren-cli",
                "table",
                "100"
            ]
        );
        assert_eq!(
            cmds[1],
            vec![
                "route",
                "add",
                "128.0.0.0/1",
                "dev",
                "warren-cli",
                "table",
                "100"
            ]
        );
    }

    #[test]
    fn install_third_command_is_the_tunnel_socket_fwmark_bypass_not_a_destination() {
        // Port Fail / TunnelCrack ServerIP fix: the pref-50 bypass sends the
        // tunnel's OWN marked carrier socket to main (physical), NOT a
        // `to <exit>/32` destination route. So an app dialing the exit IP is
        // captured by the tunnel, not leaked.
        let cmds = build_install_commands("warren-cli", &[]);
        assert_eq!(
            cmds[2],
            vec![
                "rule",
                "add",
                "fwmark",
                "0x77617272",
                "lookup",
                "main",
                "pref",
                "50"
            ]
        );
        let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("/32") && !joined.contains(" to "),
            "no destination host route may be emitted; got: {joined}"
        );
    }

    #[test]
    fn install_last_command_is_tun_lookup_rule_when_no_bypass() {
        // The pref 51 rule must look up table 100 for any traffic
        // that does not match pref 50. Anti-regression: if someone
        // changes the priority, the evaluation order breaks.
        let cmds = build_install_commands("warren-cli", &[]);
        let last = cmds.last().expect("non-empty install cmds");
        assert_eq!(last, &vec!["rule", "add", "lookup", "100", "pref", "51"]);
    }

    #[test]
    fn uninstall_uses_inverse_order_without_bypass() {
        // Inverse cleanup order: rules before routes (frees pref first,
        // then flushes the table). Anti-regression on a crucial detail
        // to allow an immediate reinstall.
        let cmds = build_uninstall_commands(&[]);
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0][0], "rule", "first cleanup must be rule del");
        assert_eq!(cmds[1][0], "rule", "second cleanup must be rule del");
        assert_eq!(cmds[2][0], "route", "last cleanup must be route flush");
    }

    #[test]
    fn uninstall_flushes_dedicated_table() {
        // The flush must target table 100 (dedicated), and definitely
        // NOT the main table which holds the default route etc.
        let cmds = build_uninstall_commands(&[]);
        let flush_cmd = cmds.last().expect("non-empty uninstall cmds");
        assert!(flush_cmd.contains(&"flush".to_string()));
        assert!(flush_cmd.contains(&"table".to_string()));
        assert!(flush_cmd.contains(&"100".to_string()));
        assert!(
            !flush_cmd.contains(&"main".to_string()),
            "must NOT flush table main (= would destroy default route)"
        );
    }

    #[test]
    fn install_never_references_an_exit_ip() {
        // The builder no longer takes an exit IP: with the escape keyed on the
        // socket mark, no destination route to any exit can be emitted. This
        // pins the vulnerability class closed at the builder level.
        let cmds = build_install_commands("tun0", &[]);
        let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("/32"),
            "no /32 host route may appear; got: {joined}"
        );
    }

    #[test]
    fn install_cmds_use_supplied_tun_name() {
        let cmds = build_install_commands("myown-tun", &[]);
        assert!(cmds[0].contains(&"myown-tun".to_string()));
        assert!(cmds[1].contains(&"myown-tun".to_string()));
    }

    // --- --bypass-cidr tests ---

    #[test]
    fn bypass_cidr_adds_one_rule_per_cidr_before_tun_lookup() {
        // A single bypass CIDR adds one extra `ip rule` between the
        // exit-bypass (pref 50) and the tun-lookup (pref 51). Order
        // matters: the bypass MUST come before the tun-lookup rule
        // so the cleanup-inverse uninstall stays correct.
        let bypass = [cidr("192.168.0.0", 16)];
        let cmds = build_install_commands("warren-cli", &bypass);
        assert_eq!(
            cmds.len(),
            5,
            "expected 4 base commands + 1 bypass rule = 5; got {cmds:#?}",
        );
        // Position 3 must be the new bypass rule (pref 49, lookup main).
        assert_eq!(
            cmds[3],
            vec![
                "rule",
                "add",
                "to",
                "192.168.0.0/16",
                "lookup",
                "main",
                "pref",
                "49",
            ],
            "bypass-cidr rule must be inserted between exit-bypass and tun-lookup",
        );
        // Position 4 is still the tun-lookup rule (pref 51).
        assert_eq!(
            cmds[4],
            vec!["rule", "add", "lookup", "100", "pref", "51"],
            "tun-lookup must remain the final rule after the bypass insert",
        );
    }

    #[test]
    fn bypass_cidr_supports_multiple_entries() {
        // Multiple bypass CIDRs each get their own `ip rule` with
        // pref 49. Order matches caller-supplied vec order (helpful
        // for reasoning + log readability).
        let bypass = [
            cidr("192.168.0.0", 16),
            cidr("10.0.0.0", 8),
            cidr("172.16.0.0", 12),
        ];
        let cmds = build_install_commands("warren-cli", &bypass);
        assert_eq!(
            cmds.len(),
            7,
            "expected 4 base + 3 bypass = 7 commands; got {cmds:#?}",
        );
        assert!(
            cmds[3].contains(&"192.168.0.0/16".to_string()),
            "first bypass cmd must reflect the first caller CIDR",
        );
        assert!(
            cmds[4].contains(&"10.0.0.0/8".to_string()),
            "second bypass cmd must reflect the second caller CIDR",
        );
        assert!(
            cmds[5].contains(&"172.16.0.0/12".to_string()),
            "third bypass cmd must reflect the third caller CIDR",
        );
        assert_eq!(
            cmds[6][0..2],
            vec!["rule".to_string(), "add".to_string()],
            "tun-lookup rule must still be last",
        );
        assert!(
            cmds[6].contains(&"51".to_string()),
            "tun-lookup pref must remain 51 after bypass inserts",
        );
    }

    #[test]
    fn bypass_cidr_uses_pref_below_exit_bypass_and_tun_lookup() {
        // The bypass pref (49) must be strictly lower than the
        // exit-bypass pref (50) and the tun-lookup pref (51). Anti
        // regression: if someone bumps pref 49 to 52, packets to the
        // bypass CIDR would route through the TUN instead of main.
        // Compile-time assertions: a violation fails the build itself, and
        // clippy does not flag a const comparison as `assert!(true)`.
        const _: () = assert!(
            RULE_PREF_BYPASS_CIDR < RULE_PREF_EXIT_BYPASS,
            "RULE_PREF_BYPASS_CIDR must be < RULE_PREF_EXIT_BYPASS",
        );
        const _: () = assert!(
            RULE_PREF_BYPASS_CIDR < RULE_PREF_TUN,
            "RULE_PREF_BYPASS_CIDR must be < RULE_PREF_TUN",
        );
    }

    #[test]
    fn empty_bypass_list_matches_original_4_command_install() {
        // Regression guard: passing an empty bypass list must produce
        // EXACTLY the original 4-command sequence (no leftover
        // placeholders or empty entries). Anti-regression for the
        // refactor that introduced the bypass loop.
        let baseline = build_install_commands("warren-cli", &[]);
        assert_eq!(baseline.len(), 4);
        assert_eq!(
            baseline[3],
            vec!["rule", "add", "lookup", "100", "pref", "51"]
        );
    }

    #[test]
    fn uninstall_includes_bypass_del_in_reverse_order() {
        // Cleanup must `ip rule del` every installed bypass CIDR.
        // Reverse order is preferred (helps reasoning about pref
        // collisions on partial-install retries) but `ip rule del`
        // with a fully-specified (to + pref) tuple is order-insensitive,
        // so this test only freezes the count + content, not strict
        // order.
        let bypass = [cidr("192.168.0.0", 16), cidr("10.0.0.0", 8)];
        let cmds = build_uninstall_commands(&bypass);
        // 2 base rule del + 2 bypass rule del + 1 route flush = 5.
        assert_eq!(cmds.len(), 5, "got: {cmds:#?}");
        let joined: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        assert!(
            joined
                .iter()
                .any(|c| c.contains("192.168.0.0/16") && c.contains("del")),
            "must include `rule del` for 192.168.0.0/16; got: {joined:#?}",
        );
        assert!(
            joined
                .iter()
                .any(|c| c.contains("10.0.0.0/8") && c.contains("del")),
            "must include `rule del` for 10.0.0.0/8; got: {joined:#?}",
        );
        // Route flush must remain the LAST command (frees the table
        // only after every rule is gone).
        assert_eq!(
            cmds.last().expect("non-empty uninstall cmds")[0],
            "route",
            "route flush must be the final cleanup command",
        );
    }
}
