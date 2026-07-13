//! Routing and killswitch PLAN computation.
//!
//! A privileged backend must (a) steer all traffic into the TUN device without
//! losing the route to the exit itself, and (b) optionally fail closed so traffic
//! cannot leak outside the tunnel. Both are expressed here as pure data: a backend
//! computes the plan, then a privileged applier runs it. Separating the two keeps
//! the policy (the hard part to get right) testable without root.
//!
//! NOTE: this module produces the intended operations; APPLYING them needs root
//! and is feature-gated. Nothing here has been validated against a real exit.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The in-tunnel gateway address `interface_up_commands_macos` addresses the
/// point-to-point `utun` peer as. Deliberately the SAME value as
/// `warrenguard_config::TUNNEL_GATEWAY_IP`, but this crate cannot depend on
/// `warrenguard-config` (zero-dep by design, see the crate doc), so the two
/// cannot be unified into one definition - only cross-checked. A dev-only
/// dependency does that in this module's tests (`gateway_ip_matches_the_
/// shared_tunnel_gateway_constant`), which fails loudly if the two ever
/// drift apart instead of silently mis-addressing the tunnel interface.
const MACOS_TUN_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

/// The TUN datapath parameters a backend would install on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Device name (for example `utun7` on macOS, `warren0` on Linux).
    pub name: String,
    /// Link MTU.
    pub mtu: u16,
    /// The tunnel IPv4 address and prefix length assigned by the exit.
    pub ipv4: (Ipv4Addr, u8),
    /// The tunnel IPv6 address and prefix length, if v6 was assigned.
    pub ipv6: Option<(std::net::Ipv6Addr, u8)>,
    /// The exit's public UDP endpoint: traffic to it must keep using the physical
    /// link (otherwise the tunnel would route its own carrier packets into itself).
    pub exit_endpoint: SocketAddr,
    /// DNS servers the exit assigned, pushed as the link resolvers and queried
    /// over the tunnel. Consumed by [`Self::dns_push_commands_linux`], which also
    /// installs the `~.` routing domain so no lookup leaks to the host resolver
    /// while the tunnel is up.
    pub dns: Vec<IpAddr>,
}

impl TunConfig {
    /// Renders the `ip` argv that brings the device UP and configures it BEFORE
    /// routing: assign the tunnel address(es), set the MTU, and set the link up.
    /// A TUN device created by `open_tun` exists but is down and unaddressed, so
    /// routes via it do nothing until this runs. Pure (no exec); unit-tested.
    #[must_use]
    pub fn interface_up_commands(&self) -> Vec<Vec<String>> {
        let (v4, v4_prefix) = self.ipv4;
        let mut cmds = vec![vec![
            "ip".to_owned(),
            "addr".to_owned(),
            "add".to_owned(),
            format!("{v4}/{v4_prefix}"),
            "dev".to_owned(),
            self.name.clone(),
        ]];
        if let Some((v6, v6_prefix)) = self.ipv6 {
            cmds.push(vec![
                "ip".to_owned(),
                "-6".to_owned(),
                "addr".to_owned(),
                "add".to_owned(),
                format!("{v6}/{v6_prefix}"),
                "dev".to_owned(),
                self.name.clone(),
            ]);
        }
        cmds.push(vec![
            "ip".to_owned(),
            "link".to_owned(),
            "set".to_owned(),
            "dev".to_owned(),
            self.name.clone(),
            "mtu".to_owned(),
            self.mtu.to_string(),
        ]);
        cmds.push(vec![
            "ip".to_owned(),
            "link".to_owned(),
            "set".to_owned(),
            "dev".to_owned(),
            self.name.clone(),
            "up".to_owned(),
        ]);
        cmds
    }
}

impl TunConfig {
    /// macOS: the `ifconfig` argv that addresses the point-to-point `utun` and
    /// brings it up BEFORE routing. `utun` is point-to-point, so the peer is the
    /// in-tunnel gateway (`10.66.0.1`). Pure (no exec); unit-tested.
    #[must_use]
    pub fn interface_up_commands_macos(&self) -> Vec<Vec<String>> {
        let (v4, _) = self.ipv4;
        let gateway = MACOS_TUN_GATEWAY_IP;
        let mut cmds = vec![vec![
            "ifconfig".to_owned(),
            self.name.clone(),
            "inet".to_owned(),
            v4.to_string(),
            gateway.to_string(),
            "mtu".to_owned(),
            self.mtu.to_string(),
            "up".to_owned(),
        ]];
        if let Some((v6, prefix)) = self.ipv6 {
            cmds.push(vec![
                "ifconfig".to_owned(),
                self.name.clone(),
                "inet6".to_owned(),
                format!("{v6}/{prefix}"),
            ]);
        }
        cmds
    }
}

impl TunConfig {
    /// Linux DNS push via systemd-resolved: set the exit-assigned resolvers on
    /// the TUN link AND install the `~.` routing domain so EVERY query is sent
    /// through this link's resolver. Without the routing domain, systemd-resolved
    /// still routes queries matched by another link's search domain to the host
    /// resolver, leaking them outside the tunnel (the DNS-leak vector).
    ///
    /// Returns an empty vec when the exit assigned no DNS (nothing to push).
    /// Pure (no exec); the privileged applier runs each argv. Reverted by
    /// [`Self::dns_teardown_commands_linux`].
    #[must_use]
    pub fn dns_push_commands_linux(&self) -> Vec<Vec<String>> {
        if self.dns.is_empty() {
            return Vec::new();
        }
        let mut set_resolvers = vec!["resolvectl".to_owned(), "dns".to_owned(), self.name.clone()];
        set_resolvers.extend(self.dns.iter().map(ToString::to_string));
        vec![
            set_resolvers,
            vec![
                "resolvectl".to_owned(),
                "domain".to_owned(),
                self.name.clone(),
                "~.".to_owned(),
            ],
        ]
    }

    /// Reverts [`Self::dns_push_commands_linux`]: drops the per-link resolver and
    /// routing-domain config so the host resolver is restored on shutdown. Empty
    /// when no DNS was pushed. Pure (no exec); applied best-effort on teardown.
    #[must_use]
    pub fn dns_teardown_commands_linux(&self) -> Vec<Vec<String>> {
        if self.dns.is_empty() {
            return Vec::new();
        }
        vec![vec![
            "resolvectl".to_owned(),
            "revert".to_owned(),
            self.name.clone(),
        ]]
    }

    /// macOS DNS push: point the primary network service's resolvers at the
    /// exit-assigned servers (`networksetup -setdnsservers <service> <ips>`). The
    /// split-default capture already routes those resolver IPs through the tunnel,
    /// so lookups resolve over the exit instead of leaking to the prior resolver.
    /// `service` is the primary network service name (e.g. `Wi-Fi`), discovered at
    /// apply time. Empty when the exit assigned no DNS. Pair with a backup of the
    /// current servers so [`dns_restore_commands_macos`] restores them faithfully.
    #[must_use]
    pub fn dns_push_commands_macos(&self, service: &str) -> Vec<Vec<String>> {
        if self.dns.is_empty() {
            return Vec::new();
        }
        let mut argv = vec![
            "networksetup".to_owned(),
            "-setdnsservers".to_owned(),
            service.to_owned(),
        ];
        argv.extend(self.dns.iter().map(ToString::to_string));
        vec![argv]
    }
}

/// macOS: renders the `networksetup -setdnsservers` argv that RESTORES the
/// `previous` resolvers captured before [`TunConfig::dns_push_commands_macos`].
/// An empty `previous` restores the DHCP-provided resolvers via the literal
/// `Empty` (networksetup's "clear" sentinel), so teardown never strands the
/// service with the in-tunnel resolver after the tunnel is gone. Pure (no exec).
#[must_use]
pub fn dns_restore_commands_macos(service: &str, previous: &[IpAddr]) -> Vec<Vec<String>> {
    let mut argv = vec![
        "networksetup".to_owned(),
        "-setdnsservers".to_owned(),
        service.to_owned(),
    ];
    if previous.is_empty() {
        argv.push("Empty".to_owned());
    } else {
        argv.extend(previous.iter().map(ToString::to_string));
    }
    vec![argv]
}

/// Parses the resolver list `networksetup -getdnsservers <service>` prints (one
/// IP per line), used to snapshot the current DNS before a push so teardown can
/// restore it. When DNS is unset, networksetup prints a human sentence ("There
/// aren't any DNS Servers set on ...") with no parseable address, yielding an
/// empty vec (restore then clears to DHCP). Non-address lines are ignored.
#[must_use]
pub fn parse_macos_dns_servers(output: &str) -> Vec<IpAddr> {
    output
        .lines()
        .filter_map(|l| l.trim().parse::<IpAddr>().ok())
        .collect()
}

/// Parses the primary (first enabled) network service name from
/// `networksetup -listnetworkserviceorder`. Lines read `(N) Service Name`; a
/// disabled service is prefixed `(*)`. The first enabled entry is the primary
/// egress service whose resolvers a full-tunnel VPN overrides. `None` if none.
#[must_use]
pub fn parse_primary_network_service(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        // Skip the disabled marker `(*) Name` and the hardware-port detail lines.
        if let Some(rest) = trimmed.strip_prefix('(')
            && let Some((tag, name)) = rest.split_once(')')
            && tag.chars().all(|c| c.is_ascii_digit())
            && !name.trim().is_empty()
        {
            return Some(name.trim().to_owned());
        }
    }
    None
}

/// The Warren tunnel socket's firewall mark on Linux. The datapath tags its own
/// QUIC socket with this `SO_MARK`; the paired `ip rule fwmark <mark> lookup
/// main` (emitted by [`RoutingPlan::to_ip_commands`]) steers exactly those
/// packets out the physical table, while the split-default capture (installed in
/// a dedicated table) sends every other flow into the tunnel.
///
/// This replaces the old `<exit_ip>/32` host route. Keying the tunnel's escape
/// on the socket mark instead of the exit destination is what closes Port Fail /
/// TunnelCrack ServerIP: traffic to the exit IP is no longer special-cased, so a
/// hostile app that dials the exit is captured by the tunnel like anything else,
/// and ONLY the daemon's own socket leaves in the clear.
pub const WARREN_TUNNEL_FWMARK: u32 = 0x7761_7272;

/// Dedicated routing table holding the split-default `/1` capture. Keeping the
/// capture out of `main` is what lets the marked socket fall through to `main`'s
/// real default route (the WireGuard fwmark model). Shares the table number
/// datapath B (`warrenguard-route-split`) already uses, so a host never runs two
/// differently numbered Warren split tables at once.
const TUN_ROUTE_TABLE: u32 = 100;

/// `ip rule` priority of the fwmark bypass (marked tunnel socket -> `main` ->
/// physical link). Must sort before [`RULE_PREF_TUN`] so the marked socket
/// escapes before the catch-all diverts everything into the tunnel table.
const RULE_PREF_FWMARK_BYPASS: u32 = 50;

/// `ip rule` priority of the catch-all (every unmarked flow -> tunnel table).
const RULE_PREF_TUN: u32 = 51;

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

/// A single routing operation in a [`RoutingPlan`]: a destination prefix steered
/// into the TUN device. The exit endpoint is no longer special-cased here (its
/// carrier socket escapes via [`SocketBypass`], not a route), so every op sends
/// traffic into the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOp {
    /// Capture `cidr` into the TUN device.
    RouteViaTun {
        /// Destination network in `addr/prefix` form.
        cidr: String,
    },
}

/// The split-default capture routed into the TUN device. The exit's carrier
/// socket is kept on the physical link by [`SocketBypass`] (a socket mark/bind),
/// not by a destination route, so this plan captures EVERY destination including
/// the exit IP: an application that dials the exit is tunnelled, not leaked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPlan {
    /// Capture operations to apply in order.
    pub ops: Vec<RouteOp>,
}

impl RoutingPlan {
    /// Computes the split-default capture plan.
    ///
    /// The default route is overridden with the classic `0.0.0.0/1` +
    /// `128.0.0.0/1` pair rather than `0.0.0.0/0`: two more-specific halves
    /// outrank the existing default without deleting it. On Linux the halves land
    /// in a dedicated table (see [`Self::to_ip_commands`]) so the fwmark bypass
    /// can send the marked socket through `main`; on macOS the socket's
    /// `IP_BOUND_IF` handles that. v6 uses the analogous `::/1` + `8000::/1`
    /// split when a v6 address was assigned.
    #[must_use]
    pub fn split_default(config: &TunConfig) -> Self {
        let mut ops = Vec::new();
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            ops.push(RouteOp::RouteViaTun {
                cidr: half.to_owned(),
            });
        }
        if config.ipv6.is_some() {
            for half in ["::/1", "8000::/1"] {
                ops.push(RouteOp::RouteViaTun {
                    cidr: half.to_owned(),
                });
            }
        }
        Self { ops }
    }

    /// True if any captured half is IPv6 (so the v6 rule database needs the
    /// paired fwmark + tunnel-lookup rules too).
    fn has_v6(&self) -> bool {
        self.ops.iter().any(|op| match op {
            RouteOp::RouteViaTun { cidr } => cidr.contains(':'),
        })
    }

    /// Renders the plan as `ip` argv vectors for the Linux applier, in order:
    /// the `/1` capture halves into the dedicated [`TUN_ROUTE_TABLE`], then the
    /// policy rules `fwmark <mark> lookup main` (marked tunnel socket escapes)
    /// and `lookup <table>` (everything else into the tunnel). v6 halves get the
    /// same rules in the `ip -6` database.
    ///
    /// Pure (no process is run): the applier executes each argv. Kept separate so
    /// the exact commands are unit-testable without privilege.
    #[must_use]
    pub fn to_ip_commands(&self, dev: &str) -> Vec<Vec<String>> {
        let mark = format!("{WARREN_TUNNEL_FWMARK:#x}");
        let table = TUN_ROUTE_TABLE.to_string();
        let mut cmds: Vec<Vec<String>> = Vec::new();
        for op in &self.ops {
            let RouteOp::RouteViaTun { cidr } = op;
            let mut argv = vec!["ip".to_owned()];
            if cidr.contains(':') {
                argv.push("-6".to_owned());
            }
            argv.extend(
                ["route", "replace", cidr, "dev", dev, "table", &table]
                    .into_iter()
                    .map(str::to_owned),
            );
            cmds.push(argv);
        }
        cmds.extend(Self::rule_commands("add", &mark, &table, false));
        if self.has_v6() {
            cmds.extend(Self::rule_commands("add", &mark, &table, true));
        }
        cmds
    }

    /// Renders the `ip` argv that REVERTS [`Self::to_ip_commands`]: the policy
    /// rules are deleted first (freeing the priorities) then the dedicated table
    /// is flushed. Pure (no exec); the applier runs each best-effort (a missing
    /// rule/route on teardown is not fatal).
    #[must_use]
    pub fn to_teardown_commands(&self, _dev: &str) -> Vec<Vec<String>> {
        let mark = format!("{WARREN_TUNNEL_FWMARK:#x}");
        let table = TUN_ROUTE_TABLE.to_string();
        let mut cmds: Vec<Vec<String>> = Vec::new();
        cmds.extend(Self::rule_commands("del", &mark, &table, false));
        cmds.push(vec![
            "ip".to_owned(),
            "route".to_owned(),
            "flush".to_owned(),
            "table".to_owned(),
            table.clone(),
        ]);
        if self.has_v6() {
            cmds.extend(Self::rule_commands("del", &mark, &table, true));
            cmds.push(vec![
                "ip".to_owned(),
                "-6".to_owned(),
                "route".to_owned(),
                "flush".to_owned(),
                "table".to_owned(),
                table.clone(),
            ]);
        }
        cmds
    }

    /// The two policy rules (`fwmark <mark> lookup main`, `lookup <table>`) for
    /// one address family. `verb` is `add`/`del`; `v6` prefixes with `-6`.
    fn rule_commands(verb: &str, mark: &str, table: &str, v6: bool) -> Vec<Vec<String>> {
        let bypass = [
            "rule",
            verb,
            "fwmark",
            mark,
            "lookup",
            "main",
            "pref",
            &RULE_PREF_FWMARK_BYPASS.to_string(),
        ];
        let tun = [
            "rule",
            verb,
            "lookup",
            table,
            "pref",
            &RULE_PREF_TUN.to_string(),
        ];
        [bypass.as_slice(), tun.as_slice()]
            .into_iter()
            .map(|rule| {
                let mut argv: Vec<String> = vec!["ip".to_owned()];
                if v6 {
                    argv.push("-6".to_owned());
                }
                argv.extend(rule.iter().map(|s| (*s).to_owned()));
                argv
            })
            .collect()
    }

    /// Renders the plan as macOS `route` argv vectors, in order. `add` (apply) or
    /// `delete` (teardown) is chosen by `verb`. Only the `/1` capture halves are
    /// emitted: the exit socket stays on the physical link via `IP_BOUND_IF`, so
    /// no host-route exception is needed. Pure (no exec); unit-tested.
    #[must_use]
    pub fn to_macos_commands(&self, dev: &str, verb: &str) -> Vec<Vec<String>> {
        self.ops
            .iter()
            .map(|op| match op {
                RouteOp::RouteViaTun { cidr } => {
                    let family = if cidr.contains(':') {
                        "-inet6"
                    } else {
                        "-inet"
                    };
                    vec![
                        "route".to_owned(),
                        "-n".to_owned(),
                        verb.to_owned(),
                        family.to_owned(),
                        "-net".to_owned(),
                        cidr.clone(),
                        "-interface".to_owned(),
                        dev.to_owned(),
                    ]
                }
            })
            .collect()
    }
}

/// A killswitch ruleset: only the tunnel and the datapath's own marked socket
/// are allowed out; everything else (including a v6 leak when v6 is not tunneled)
/// is dropped, so a dropped tunnel fails closed instead of leaking to the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillswitchPlan {
    /// The nftables ruleset text (Linux). Other backends render their own.
    pub nftables: String,
}

impl KillswitchPlan {
    /// Renders an nftables ruleset that drops all output except: loopback, the
    /// TUN device, and the datapath's own socket (matched by its `SO_MARK`, not
    /// by the exit destination). When no v6 address is tunneled, all IPv6 output
    /// is dropped (v6 leak block).
    ///
    /// The accept is keyed on `meta mark {WARREN_TUNNEL_FWMARK}` rather than
    /// `ip daddr <exit>`: only the daemon's tunnel socket carries that mark, so a
    /// hostile application that dials the exit IP is NOT let out here (it is
    /// captured by the tunnel instead). This is the killswitch half of the Port
    /// Fail / TunnelCrack ServerIP fix. The `meta mark` match is family-agnostic
    /// in the `inet` table, so it covers a v4- or v6-dialed exit socket alike.
    #[must_use]
    pub fn nftables(config: &TunConfig) -> Self {
        let block_v6 = config.ipv6.is_none();
        let mark = format!("{WARREN_TUNNEL_FWMARK:#x}");
        let mut s = String::new();
        s.push_str("table inet warren_killswitch {\n");
        s.push_str("  chain output {\n");
        s.push_str("    type filter hook output priority 0; policy drop;\n");
        s.push_str("    oif \"lo\" accept\n");
        s.push_str(&format!("    oif \"{}\" accept\n", config.name));
        // The datapath's own tunnel socket, identified by its firewall mark. Only
        // this socket escapes to the physical link; app traffic to the exit IP is
        // tunnelled, not accepted here.
        s.push_str(&format!("    meta mark {mark} accept\n"));
        if block_v6 {
            // Fail closed on v6 when the tunnel carries only v4: no v6 leak.
            s.push_str("    meta nfproto ipv6 drop\n");
        }
        s.push_str("  }\n}\n");
        Self { nftables: s }
    }

    /// The argv that loads this ruleset, reading it from stdin (`nft -f -`). The
    /// applier feeds [`Self::nftables`] to the child's stdin. Pure (no exec).
    #[must_use]
    pub fn nft_apply_argv() -> Vec<String> {
        vec!["nft".to_owned(), "-f".to_owned(), "-".to_owned()]
    }

    /// The argv that tears the ruleset down (`nft delete table inet
    /// warren_killswitch`), restoring normal output. Pure (no exec).
    #[must_use]
    pub fn nft_teardown_argv() -> Vec<String> {
        ["nft", "delete", "table", "inet", "warren_killswitch"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    /// macOS: a pf ruleset that fails closed. Default-drops all output, then
    /// passes loopback, the TUN device, and the datapath's own tunnel socket on
    /// the PHYSICAL interface `phys_iface`. `block out all` also stops any v6 leak
    /// when v6 is not tunneled. Pure (no exec); unit-tested.
    ///
    /// The exit accept is scoped `on <phys_iface>`: the datapath's socket is
    /// bound there with `IP_BOUND_IF`, while an application dialing the exit is
    /// routed into the tunnel (utun) by the split-default and never reaches the
    /// physical output. So only the daemon's own socket matches this pass, which
    /// is the macOS half of the Port Fail / TunnelCrack ServerIP fix. pf cannot
    /// match a socket mark the way nftables does; process-level scoping (a
    /// dedicated `group`) is the documented follow-up hardening for a hostile app
    /// that binds its own socket to the physical interface.
    #[must_use]
    pub fn pf_rules(config: &TunConfig, phys_iface: &str) -> String {
        let exit_ip = config.exit_endpoint.ip();
        let exit_port = config.exit_endpoint.port();
        let mut s = String::new();
        s.push_str("set block-policy drop\n");
        s.push_str("block out all\n");
        s.push_str("pass out quick on lo0 all\n");
        s.push_str(&format!("pass out quick on {} all\n", config.name));
        s.push_str(&format!(
            "pass out quick on {phys_iface} proto udp from any to {exit_ip} port {exit_port}\n"
        ));
        s
    }

    /// macOS: argv that loads the pf ruleset from stdin (`pfctl -f -`).
    #[must_use]
    pub fn pf_load_argv() -> Vec<String> {
        ["pfctl", "-f", "-"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    /// macOS: argv that enables pf with `pfctl -E` (reference-counted), which
    /// succeeds whether pf was already enabled or not, unlike `-e` (which errors
    /// if pf is already running, for example under another VPN).
    #[must_use]
    pub fn pf_enable_argv() -> Vec<String> {
        ["pfctl", "-E"].iter().map(|s| (*s).to_owned()).collect()
    }

    /// macOS: argv that flushes the loaded rules (`pfctl -F rules`).
    #[must_use]
    pub fn pf_flush_argv() -> Vec<String> {
        ["pfctl", "-F", "rules"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    /// macOS: argv that disables pf (`pfctl -d`), restoring the default
    /// (unfiltered) state on a host where pf was off, the macOS default.
    #[must_use]
    pub fn pf_disable_argv() -> Vec<String> {
        ["pfctl", "-d"].iter().map(|s| (*s).to_owned()).collect()
    }

    /// macOS: argv that prints pf status (`pfctl -s info`), whose first line is
    /// `Status: Enabled`/`Disabled`. Captured before apply to learn whether pf
    /// was already running, so teardown does not disable a pf another tool owns.
    #[must_use]
    pub fn pf_show_info_argv() -> Vec<String> {
        ["pfctl", "-s", "info"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    /// macOS: argv that dumps the current filter ruleset (`pfctl -sr`). Captured
    /// before apply so teardown can restore it instead of flushing to empty.
    #[must_use]
    pub fn pf_show_rules_argv() -> Vec<String> {
        ["pfctl", "-sr"].iter().map(|s| (*s).to_owned()).collect()
    }

    /// macOS: argv that loads a ruleset from `path` (`pfctl -f <path>`). Used at
    /// teardown to restore the snapshot taken at apply.
    #[must_use]
    pub fn pf_restore_argv(path: &str) -> Vec<String> {
        vec!["pfctl".to_owned(), "-f".to_owned(), path.to_owned()]
    }

    /// True if a `pfctl -s info` dump reports pf as enabled. The dump's first
    /// line is `Status: Enabled ...` or `Status: Disabled`; anything else (an
    /// unexpected format) is treated as not-enabled so teardown errs toward
    /// disabling rather than leaving a pf we may have enabled running.
    #[must_use]
    pub fn pf_status_is_enabled(info_stdout: &str) -> bool {
        info_stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix("Status:"))
            .is_some_and(|rest| rest.trim_start().starts_with("Enabled"))
    }

    /// The comment line prepended to the saved ruleset recording whether pf was
    /// already enabled before apply. `pfctl` ignores `#` comments, so the backup
    /// file is still directly reloadable with
    /// [`pf_restore_argv`](Self::pf_restore_argv).
    #[must_use]
    pub fn pf_backup_header(was_enabled: bool) -> String {
        format!("{PF_BACKUP_ENABLED_PREFIX}{was_enabled}\n")
    }

    /// Reads back the enable-state recorded by
    /// [`pf_backup_header`](Self::pf_backup_header). A missing/unparseable header
    /// reads as `false` (teardown then disables pf, the conservative choice on a
    /// host whose prior state we cannot prove).
    #[must_use]
    pub fn parse_pf_backup_was_enabled(backup: &str) -> bool {
        backup
            .lines()
            .find_map(|l| l.strip_prefix(PF_BACKUP_ENABLED_PREFIX))
            .map(|v| v.trim() == "true")
            .unwrap_or(false)
    }
}

/// Comment prefix recording pf's pre-apply enable-state in the saved ruleset.
const PF_BACKUP_ENABLED_PREFIX: &str = "# warren-pf-was-enabled=";

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn v4_config() -> TunConfig {
        TunConfig {
            name: "warren0".to_owned(),
            mtu: 1280,
            ipv4: (Ipv4Addr::new(10, 66, 0, 2), 16),
            ipv6: None,
            exit_endpoint: "203.0.113.9:51820".parse().unwrap(),
            dns: vec![IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1))],
        }
    }

    fn cidrs_of(plan: &RoutingPlan) -> Vec<&str> {
        plan.ops
            .iter()
            .map(|op| match op {
                RouteOp::RouteViaTun { cidr } => cidr.as_str(),
            })
            .collect()
    }

    #[test]
    fn socket_bypass_exposes_the_mark_or_ifindex_per_os() {
        assert_eq!(SocketBypass::Fwmark(0x1234).fwmark(), Some(0x1234));
        assert_eq!(SocketBypass::Fwmark(0x1234).bound_ifindex(), None);
        assert_eq!(SocketBypass::BoundIf(7).bound_ifindex(), Some(7));
        assert_eq!(SocketBypass::BoundIf(7).fwmark(), None);
        assert_eq!(SocketBypass::UnicastIf(9).bound_ifindex(), Some(9));
        assert_eq!(SocketBypass::UnicastIf(9).fwmark(), None);
    }

    #[test]
    fn split_default_captures_both_halves_and_never_pins_the_exit() {
        // Port Fail / TunnelCrack ServerIP: the exit endpoint must NOT get a
        // dedicated host route. The plan captures both /1 halves and nothing
        // else, so an app dialing the exit IP is tunnelled, not leaked. The
        // exit's carrier socket escapes via SocketBypass, not a route.
        let plan = RoutingPlan::split_default(&v4_config());
        assert_eq!(cidrs_of(&plan), ["0.0.0.0/1", "128.0.0.0/1"]);
        let exit_ip = v4_config().exit_endpoint.ip().to_string();
        assert!(
            !cidrs_of(&plan).iter().any(|c| c.contains(&exit_ip)),
            "the plan must contain no host route to the exit ({exit_ip})"
        );
        assert!(
            !cidrs_of(&plan).iter().any(|c| c.contains("/32")),
            "no /32 host route may appear in the capture plan"
        );
    }

    #[test]
    fn split_default_adds_the_v6_halves_only_when_v6_is_assigned() {
        let mut cfg = v4_config();
        cfg.ipv6 = Some((Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 2), 64));
        let plan = RoutingPlan::split_default(&cfg);
        assert_eq!(
            cidrs_of(&plan),
            ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
        );
    }

    #[test]
    fn killswitch_drops_by_default_and_allows_lo_tun_and_the_marked_socket() {
        // The exit accept is keyed on the socket MARK, not `ip daddr <exit>`, so
        // only the daemon's tunnel socket escapes: a hostile app dialing the exit
        // IP is not let out here (Port Fail / TunnelCrack ServerIP fix).
        let ks = KillswitchPlan::nftables(&v4_config());
        assert!(ks.nftables.contains("policy drop;"));
        assert!(ks.nftables.contains("oif \"lo\" accept"));
        assert!(ks.nftables.contains("oif \"warren0\" accept"));
        assert!(
            ks.nftables.contains("meta mark 0x77617272 accept"),
            "the marked tunnel socket must be the accepted egress; got:\n{}",
            ks.nftables
        );
        assert!(
            !ks.nftables.contains("ip daddr 203.0.113.9"),
            "the exit IP must NOT be special-cased by destination anymore"
        );
        assert!(
            !ks.nftables.contains("udp dport 51820"),
            "no destination-port accept for the exit endpoint may remain"
        );
    }

    #[test]
    fn interface_up_commands_address_then_mtu_then_up() {
        let cmds = v4_config().interface_up_commands();
        assert_eq!(
            cmds[0],
            vec!["ip", "addr", "add", "10.66.0.2/16", "dev", "warren0"]
        );
        assert_eq!(
            cmds[1],
            vec!["ip", "link", "set", "dev", "warren0", "mtu", "1280"]
        );
        assert_eq!(cmds[2], vec!["ip", "link", "set", "dev", "warren0", "up"]);
        assert_eq!(cmds.len(), 3, "v4-only: addr, mtu, up");
    }

    #[test]
    fn interface_up_commands_add_v6_address_when_assigned() {
        let mut cfg = v4_config();
        cfg.ipv6 = Some((Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 2), 64));
        let cmds = cfg.interface_up_commands();
        assert!(cmds.iter().any(|c| c
            == &vec![
                "ip".to_owned(),
                "-6".to_owned(),
                "addr".to_owned(),
                "add".to_owned(),
                "fd66::2/64".to_owned(),
                "dev".to_owned(),
                "warren0".to_owned()
            ]));
        // up is still last.
        assert_eq!(cmds.last().unwrap().last().unwrap(), "up");
    }

    #[test]
    fn dns_push_sets_link_resolvers_and_routes_all_queries_via_the_tunnel() {
        // DNS-leak guard: pushing the exit resolvers is not enough; without
        // the `~.` routing domain, systemd-resolved still sends queries for
        // names matched by another link's search domain to the host resolver,
        // leaking them outside the tunnel. Both argv must be rendered.
        let cmds = v4_config().dns_push_commands_linux();
        assert_eq!(
            cmds,
            vec![
                vec!["resolvectl", "dns", "warren0", "10.66.0.1"],
                vec!["resolvectl", "domain", "warren0", "~."],
            ],
            "DNS push must set the link resolver AND the `~.` routing domain so \
             no lookup escapes to the host resolver while the tunnel is up"
        );
    }

    #[test]
    fn dns_push_passes_every_assigned_resolver_in_order() {
        let mut cfg = v4_config();
        cfg.dns = vec![
            IpAddr::V4(Ipv4Addr::new(10, 66, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 1)),
        ];
        let cmds = cfg.dns_push_commands_linux();
        assert_eq!(
            cmds[0],
            vec!["resolvectl", "dns", "warren0", "10.66.0.1", "fd66::1"],
            "all assigned resolvers (v4 and v6) go on the link, in order"
        );
    }

    #[test]
    fn dns_teardown_reverts_the_link_so_the_host_resolver_returns() {
        let cmds = v4_config().dns_teardown_commands_linux();
        assert_eq!(cmds, vec![vec!["resolvectl", "revert", "warren0"]]);
    }

    #[test]
    fn no_dns_is_pushed_or_torn_down_when_the_exit_assigned_none() {
        let mut cfg = v4_config();
        cfg.dns.clear();
        assert!(
            cfg.dns_push_commands_linux().is_empty(),
            "no assigned resolver means nothing to push (and nothing to revert)"
        );
        assert!(cfg.dns_teardown_commands_linux().is_empty());
    }

    #[test]
    fn macos_dns_push_sets_the_service_resolvers() {
        let cmds = v4_config().dns_push_commands_macos("Wi-Fi");
        assert_eq!(
            cmds,
            vec![vec!["networksetup", "-setdnsservers", "Wi-Fi", "10.66.0.1"]],
            "the in-tunnel resolver is set on the primary service so lookups go \
             over the tunnel instead of the prior resolver"
        );
        let mut none = v4_config();
        none.dns.clear();
        assert!(none.dns_push_commands_macos("Wi-Fi").is_empty());
    }

    #[test]
    fn macos_dns_restore_brings_back_previous_servers_or_clears_to_dhcp() {
        let prev = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        assert_eq!(
            dns_restore_commands_macos("Wi-Fi", &prev),
            vec![vec!["networksetup", "-setdnsservers", "Wi-Fi", "1.1.1.1"]],
            "teardown restores the exact resolvers captured before the push"
        );
        assert_eq!(
            dns_restore_commands_macos("Wi-Fi", &[]),
            vec![vec!["networksetup", "-setdnsservers", "Wi-Fi", "Empty"]],
            "no prior resolver => clear to DHCP rather than strand the tunnel IP"
        );
    }

    #[test]
    fn macos_parses_current_dns_servers_and_the_unset_sentinel() {
        assert_eq!(
            parse_macos_dns_servers("1.1.1.1\n8.8.8.8\n"),
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ]
        );
        assert!(
            parse_macos_dns_servers("There aren't any DNS Servers set on Wi-Fi.").is_empty(),
            "the human 'unset' sentence parses to no servers (restore clears to DHCP)"
        );
    }

    #[test]
    fn macos_picks_the_first_enabled_network_service_as_primary() {
        let listing = "An asterisk (*) denotes that a network service is disabled.\n\
                       (1) Wi-Fi\n\
                       (Hardware Port: Wi-Fi, Device: en0)\n\
                       (2) Thunderbolt Bridge\n\
                       (Hardware Port: Thunderbolt Bridge, Device: bridge0)\n";
        assert_eq!(
            parse_primary_network_service(listing).as_deref(),
            Some("Wi-Fi"),
            "the first numbered (enabled) service is the primary egress"
        );
        assert!(parse_primary_network_service("no services here").is_none());
    }

    #[test]
    fn routing_plan_renders_dedicated_table_then_fwmark_and_tun_rules() {
        let cmds = RoutingPlan::split_default(&v4_config()).to_ip_commands("warren0");
        // The /1 halves land in the dedicated table (not main), so the marked
        // socket can fall through to main's physical default route.
        assert_eq!(
            cmds[0],
            vec![
                "ip",
                "route",
                "replace",
                "0.0.0.0/1",
                "dev",
                "warren0",
                "table",
                "100"
            ]
        );
        assert_eq!(
            cmds[1],
            vec![
                "ip",
                "route",
                "replace",
                "128.0.0.0/1",
                "dev",
                "warren0",
                "table",
                "100"
            ]
        );
        // The marked tunnel socket escapes via main; everything else -> table 100.
        assert_eq!(
            cmds[2],
            vec![
                "ip",
                "rule",
                "add",
                "fwmark",
                "0x77617272",
                "lookup",
                "main",
                "pref",
                "50"
            ],
            "the fwmark bypass must route the marked socket to main (physical)"
        );
        assert_eq!(
            cmds[3],
            vec!["ip", "rule", "add", "lookup", "100", "pref", "51"]
        );
        assert_eq!(cmds.len(), 4, "v4-only: 2 routes + 2 rules");
        // Anti-regression: no host route to the exit anywhere.
        let joined = cmds.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("203.0.113.9") && !joined.contains("/32"),
            "the exit IP must never be pinned by a route; got: {joined}"
        );
    }

    #[test]
    fn routing_plan_v6_adds_the_v6_rules_too() {
        let mut cfg = v4_config();
        cfg.ipv6 = Some((Ipv6Addr::new(0xfd66, 0, 0, 0, 0, 0, 0, 2), 64));
        let cmds = RoutingPlan::split_default(&cfg).to_ip_commands("warren0");
        // v6 halves use `ip -6 route ... table 100`.
        assert!(cmds.iter().any(|c| c
            == &vec![
                "ip", "-6", "route", "replace", "::/1", "dev", "warren0", "table", "100"
            ]));
        // The v6 rule database gets its own fwmark bypass + tun lookup.
        assert!(cmds.iter().any(|c| c
            == &vec![
                "ip",
                "-6",
                "rule",
                "add",
                "fwmark",
                "0x77617272",
                "lookup",
                "main",
                "pref",
                "50"
            ]));
        assert!(
            cmds.iter()
                .any(|c| c == &vec!["ip", "-6", "rule", "add", "lookup", "100", "pref", "51"])
        );
    }

    #[test]
    fn routing_teardown_deletes_rules_then_flushes_the_dedicated_table() {
        let plan = RoutingPlan::split_default(&v4_config());
        let down = plan.to_teardown_commands("warren0");
        // Rules deleted first (frees the priorities), then the table is flushed.
        assert_eq!(
            down[0],
            vec![
                "ip",
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
        assert_eq!(
            down[1],
            vec!["ip", "rule", "del", "lookup", "100", "pref", "51"]
        );
        assert_eq!(
            down[2],
            vec!["ip", "route", "flush", "table", "100"],
            "teardown flushes only our dedicated table, never main"
        );
        assert!(
            !down.iter().flatten().any(|t| t == "flush table main"),
            "teardown must never flush the main table"
        );
        assert!(
            down.iter().all(|c| !c.contains(&"203.0.113.9".to_owned())),
            "teardown must not reference the exit IP"
        );
    }

    #[test]
    fn killswitch_apply_and_teardown_argv_are_stable() {
        assert_eq!(KillswitchPlan::nft_apply_argv(), ["nft", "-f", "-"]);
        assert_eq!(
            KillswitchPlan::nft_teardown_argv(),
            ["nft", "delete", "table", "inet", "warren_killswitch"]
        );
    }

    #[test]
    fn macos_interface_up_uses_ifconfig_point_to_point() {
        let cmds = v4_config().interface_up_commands_macos();
        assert_eq!(
            cmds[0],
            vec![
                "ifconfig",
                "warren0",
                "inet",
                "10.66.0.2",
                "10.66.0.1",
                "mtu",
                "1280",
                "up"
            ]
        );
        assert_eq!(cmds.len(), 1, "v4-only: a single ifconfig line");
    }

    #[test]
    fn gateway_ip_matches_the_shared_tunnel_gateway_constant() {
        // This crate is deliberately zero-dep in production (see the crate
        // doc), so `MACOS_TUN_GATEWAY_IP` cannot be defined in terms of
        // `warrenguard_config::TUNNEL_GATEWAY_IP` - only cross-checked, via
        // this dev-dependency-only test. A drift here means the macOS utun
        // peer address and the exit-assigned tunnel gateway have silently
        // diverged, which would break routing on macOS.
        assert_eq!(
            MACOS_TUN_GATEWAY_IP,
            warrenguard_config::TUNNEL_GATEWAY_IP,
            "the macOS point-to-point gateway must match the shared \
             TUNNEL_GATEWAY_IP constant"
        );
    }

    #[test]
    fn macos_routes_capture_via_interface_without_pinning_the_exit() {
        // No `route add -host <exit>`: the exit socket stays on the physical link
        // via IP_BOUND_IF, so the macOS plan only installs the /1 capture.
        let add = RoutingPlan::split_default(&v4_config()).to_macos_commands("utun7", "add");
        assert_eq!(add.len(), 2, "v4-only: exactly the two /1 halves");
        assert_eq!(
            add[0],
            vec![
                "route",
                "-n",
                "add",
                "-inet",
                "-net",
                "0.0.0.0/1",
                "-interface",
                "utun7"
            ]
        );
        assert_eq!(
            add[1],
            vec![
                "route",
                "-n",
                "add",
                "-inet",
                "-net",
                "128.0.0.0/1",
                "-interface",
                "utun7"
            ]
        );
        let joined = add.iter().flatten().cloned().collect::<Vec<_>>().join(" ");
        assert!(
            !joined.contains("-host") && !joined.contains("203.0.113.9"),
            "no host-route exception to the exit may be emitted; got: {joined}"
        );
        let del = RoutingPlan::split_default(&v4_config()).to_macos_commands("utun7", "delete");
        assert_eq!(del[0][2], "delete");
        assert_eq!(add.len(), del.len());
    }

    #[test]
    fn macos_pf_rules_fail_closed_and_scope_the_exit_to_the_physical_iface() {
        // The exit pass is scoped `on en0` (the physical link the socket binds to
        // with IP_BOUND_IF); app traffic to the exit is routed into utun instead,
        // so only the daemon socket matches. Port Fail / TunnelCrack ServerIP fix.
        let pf = KillswitchPlan::pf_rules(&v4_config(), "en0");
        assert!(pf.contains("block out all"));
        assert!(pf.contains("pass out quick on lo0 all"));
        assert!(pf.contains("pass out quick on warren0 all"));
        assert!(
            pf.contains("pass out quick on en0 proto udp from any to 203.0.113.9 port 51820"),
            "the exit accept must be scoped to the physical interface; got:\n{pf}"
        );
        assert!(
            !pf.contains("pass out quick proto udp from any to 203.0.113.9"),
            "an unscoped (any-interface) exit accept must not remain"
        );
        assert_eq!(KillswitchPlan::pf_load_argv(), ["pfctl", "-f", "-"]);
        assert_eq!(KillswitchPlan::pf_disable_argv(), ["pfctl", "-d"]);
    }

    #[test]
    fn pf_snapshot_restore_argv_are_stable() {
        assert_eq!(KillswitchPlan::pf_show_info_argv(), ["pfctl", "-s", "info"]);
        assert_eq!(KillswitchPlan::pf_show_rules_argv(), ["pfctl", "-sr"]);
        assert_eq!(
            KillswitchPlan::pf_restore_argv("/var/run/x.conf"),
            ["pfctl", "-f", "/var/run/x.conf"]
        );
    }

    #[test]
    fn pf_status_parser_reads_enabled_and_disabled() {
        assert!(KillswitchPlan::pf_status_is_enabled(
            "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n"
        ));
        assert!(!KillswitchPlan::pf_status_is_enabled("Status: Disabled\n"));
        // Leading whitespace (some pfctl builds indent) must still parse.
        assert!(KillswitchPlan::pf_status_is_enabled("  Status: Enabled\n"));
        // An unexpected dump errs toward not-enabled (teardown then disables).
        assert!(!KillswitchPlan::pf_status_is_enabled("garbage output"));
    }

    #[test]
    fn pf_backup_header_round_trips_the_enable_state() {
        for was_enabled in [true, false] {
            let header = KillswitchPlan::pf_backup_header(was_enabled);
            // The saved ruleset is the header followed by the captured rules.
            let backup = format!("{header}pass out all\nblock in all\n");
            assert_eq!(
                KillswitchPlan::parse_pf_backup_was_enabled(&backup),
                was_enabled
            );
        }
        // A backup with no header (e.g. a raw ruleset) reads as not-enabled.
        assert!(!KillswitchPlan::parse_pf_backup_was_enabled(
            "pass out all\n"
        ));
    }

    #[test]
    fn killswitch_blocks_v6_when_v6_is_not_tunneled() {
        let v4_only = KillswitchPlan::nftables(&v4_config());
        assert!(
            v4_only.nftables.contains("meta nfproto ipv6 drop"),
            "a v4-only tunnel must fail closed on v6 to prevent a leak"
        );

        let mut dual = v4_config();
        dual.ipv6 = Some((Ipv6Addr::LOCALHOST, 64));
        let dual = KillswitchPlan::nftables(&dual);
        assert!(
            !dual.nftables.contains("meta nfproto ipv6 drop"),
            "a dual-stack tunnel must not block its own v6"
        );
    }
}
