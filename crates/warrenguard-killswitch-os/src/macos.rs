//! macOS killswitch - type-safe `pf` (Packet Filter) via `pfctl-rs`.
//!
//! Rules are loaded into a pf sub-anchor [`PF_ANCHOR_PATH`] =
//! `com.apple/250.warrenguard_killswitch_os`.
//!
//! ## Connection states (the leak this module must not miss)
//!
//! Loading the anchor rules does NOT stop a flow that already exists. pf
//! keeps a state table and consults it BEFORE it re-evaluates the ruleset,
//! so a connection opened before the install (for example by macOS's
//! default `pass all`) keeps carrying off-tunnel traffic past the new
//! block until its state entry disappears. The install therefore purges the
//! states the new policy does NOT pass, after the rules are loaded, then re-reads
//! the table and refuses to call the protection established while a state it
//! cannot account for is still there. A state the policy passes (loopback, the
//! tunnel, the carrier on the physical interface, a LAN range under `allow_lan`,
//! the DHCP ports under `allow_dhcp`) is left alone: killing the carrier's state
//! would drop the tunnel's own transport for no confidentiality gain. See
//! [`PfOps::purge_bypass_states`] for the decision rule and
//! [`MacosKillswitch::install`] for the failure semantics.
//!
//! An interface-scoped pass is judged on the state's LOCAL address, which is the
//! only field of an entry that can attribute it to an interface: the address a
//! packet egresses an interface with belongs to that interface, and
//! [`PfOps::interface_addresses`] supplies them. That attribution is what lets the
//! same decision serve both sides, which is why the purge and the confirmation
//! cannot disagree:
//!
//! - an entry to the exit whose local address belongs to `phys_iface` is a flow
//!   the scoped pass covers, so the purge preserves it and its recreation by the
//!   transport during the install fails nothing;
//! - an entry to the exit whose local address belongs to another interface is a
//!   flow that pass refuses, so the purge kills it, and if it survives the
//!   confirmation fails the install rather than accepting it on its destination
//!   alone;
//! - without the addresses (a lookup that failed, or an interface with none) no
//!   entry can be shown to match the scoped pass, and the conservative outcome is
//!   the fail-closed one.
//!
//! ## Manual verification on a real Mac
//!
//! Automated tests cannot cover this: `/dev/pf` needs root and CI has no
//! privileges. An operator can confirm the purge by hand:
//!
//! 1. With a physical connection already open, run `sudo pfctl -s states`
//!    and note the entries whose local address is neither the physical
//!    interface's nor loopback.
//! 2. Install the killswitch, then run `sudo pfctl -s states` again.
//! 3. The entries from step 1 must be gone. A state the policy passes, such as
//!    the carrier on the physical interface or a LAN destination under
//!    `allow_lan`, may still be present, and the tunnel's own states must not
//!    have been dropped by the purge. `ifconfig <phys_iface>` names the
//!    addresses the attribution uses.
//! 4. `sudo pfctl -s rules` must show the anchor rules under
//!    [`PF_ANCHOR_PATH`].

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use pfctl::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use pfctl::{AnchorKind, FilterRule, FilterRuleAction, FilterRuleBuilder, PfCtl, Proto};

use crate::{KillswitchError, KillswitchOpts, validate_tun_name};

/// pf anchor path used by Warren.
pub const PF_ANCHOR_PATH: &str = "com.apple/250.warrenguard_killswitch_os";

/// One pf filter rule, in a form pure enough to unit-test the ORDER and the
/// `quick` flags. The load-bearing invariant lives here: the default block must
/// NOT be `quick`. pf stops at the first `quick` match, so a `quick` block would
/// fire for every packet before the pass exceptions below and drop all egress,
/// the tunnel included (the datapath then forwards uplink but the host, and its
/// own in-tunnel probes, egress nothing). A plain block is the last-match
/// default that the `quick` pass exceptions override.
#[derive(Debug, Clone, PartialEq)]
struct PfRuleSpec {
    /// `true` = Pass, `false` = Drop(Return) (the default block).
    pass: bool,
    quick: bool,
    iface: Option<String>,
    udp: bool,
    v6: bool,
    dest: Option<PfDest>,
}

#[derive(Debug, Clone, PartialEq)]
enum PfDest {
    /// `to <net>` (port any).
    Net(IpNetwork),
    /// `to any port <p>`.
    AnyPort(u16),
}

/// The ordered killswitch rule specs. Pure and fully testable.
fn pf_rule_specs(opts: &KillswitchOpts) -> Vec<PfRuleSpec> {
    let pass = |iface: Option<String>, udp: bool, v6: bool, dest: Option<PfDest>| PfRuleSpec {
        pass: true,
        quick: true,
        iface,
        udp,
        v6,
        dest,
    };
    let mut specs = vec![
        // Default block, first but NON-quick (see [`PfRuleSpec`]); a partial
        // install (block present, passes not yet added) still fails closed.
        PfRuleSpec {
            pass: false,
            quick: false,
            iface: None,
            udp: false,
            v6: false,
            dest: None,
        },
        // Loopback.
        pass(Some("lo0".into()), false, false, None),
        // The tunnel interface: every captured packet egresses here.
        pass(Some(opts.tun_name.clone()), false, false, None),
    ];

    // The exit carrier (QUIC/UDP to each exit IP). Scoped to the physical
    // interface when the carrier socket is IP_BOUND_IF-bound (Port Fail /
    // TunnelCrack ServerIP fix: an unscoped rule would let ANY app dialing the
    // exit IP escape the tunnel). Unscoped in the macOS unbound-carrier model,
    // which instead escapes via a <exit>/32 physical host route.
    for addr in &opts.exit_addrs {
        let net = match addr {
            IpAddr::V4(v4) => IpNetwork::V4(Ipv4Network::new(*v4, 32).expect("single-host mask")),
            IpAddr::V6(v6) => IpNetwork::V6(Ipv6Network::new(*v6, 128).expect("single-host mask")),
        };
        specs.push(pass(
            opts.phys_iface.clone(),
            true,
            addr.is_ipv6(),
            Some(PfDest::Net(net)),
        ));
    }

    if opts.allow_lan {
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
            specs.push(pass(
                None,
                false,
                false,
                Some(PfDest::Net(cidr.parse().expect("valid CIDR"))),
            ));
        }
        for cidr in ["fc00::/7", "fe80::/10"] {
            specs.push(pass(
                None,
                false,
                true,
                Some(PfDest::Net(cidr.parse().expect("valid CIDR"))),
            ));
        }
    }

    if opts.allow_dhcp {
        for port in [67u16, 68] {
            specs.push(pass(None, true, false, Some(PfDest::AnyPort(port))));
        }
    }

    specs
}

/// Renders one [`PfRuleSpec`] into a pfctl [`FilterRule`].
fn spec_to_filter_rule(spec: &PfRuleSpec) -> Result<FilterRule, KillswitchError> {
    let mut b = FilterRuleBuilder::default();
    b.direction(pfctl::Direction::Out).quick(spec.quick);
    b.action(if spec.pass {
        FilterRuleAction::Pass
    } else {
        FilterRuleAction::Drop(pfctl::DropAction::Return)
    });
    if let Some(iface) = &spec.iface {
        b.interface(pfctl::Interface::from(iface.as_str()));
    }
    if spec.udp {
        b.proto(pfctl::Proto::Udp);
    }
    if spec.v6 {
        b.af(pfctl::AddrFamily::Ipv6);
    }
    match &spec.dest {
        Some(PfDest::Net(net)) => {
            b.to(pfctl::Endpoint::new(*net, pfctl::Port::Any));
        }
        Some(PfDest::AnyPort(port)) => {
            b.to(pfctl::Endpoint::new(pfctl::Ip::Any, *port));
        }
        None => {}
    }
    b.build()
        .map_err(|e| KillswitchError::Pf(format!("pf rule: {e}")))
}

/// Builds the filter rules for the killswitch. Pure: no privileges needed,
/// fully testable through [`pf_rule_specs`].
pub fn build_pf_rules(opts: &KillswitchOpts) -> Result<Vec<FilterRule>, KillswitchError> {
    pf_rule_specs(opts)
        .iter()
        .map(spec_to_filter_rule)
        .collect()
}

/// The destination-scoped flows the freshly loaded anchor passes, reduced to
/// what a pf state entry carries: the protocol, the remote address and the
/// remote port.
///
/// A state is judged against this set rather than against "anything that is not
/// loopback", because the policy's own exceptions are flows the anchor passes:
/// the exit carrier, a LAN range under `allow_lan`, the DHCP ports under
/// `allow_dhcp`. Their existing states are legitimate and must survive the purge:
/// killing the carrier's would drop the tunnel's own transport for no
/// confidentiality gain.
///
/// An interface-scoped pass is deliberately NOT permission here. `pf_rule_specs`
/// scopes the exit carrier to `phys_iface` when the caller named the physical
/// egress, and pf honours an existing state WITHOUT re-evaluating the ruleset, so
/// a state to the exit address on some other interface would keep flowing past a
/// rule that refuses it. `pfctl::State` exposes no interface name, so that state
/// cannot be shown to match the scoped pass: refusing to preserve what cannot be
/// established is the fail-closed direction, and the cost is one re-established
/// carrier connection.
#[derive(Debug, Default, Clone)]
struct PermittedFlows {
    rules: Vec<PermittedFlow>,
}

/// One destination-scoped pass rule of the anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IfaceScope {
    /// The pass matches any interface.
    Any,
    /// The pass is scoped to one interface, and these are the addresses the host
    /// reports for it. A state matches when its LOCAL address is one of them,
    /// which is what attributes the state to that interface: a state carries no
    /// interface name, and the local address of a packet that egresses an
    /// interface is one of that interface's addresses.
    Addresses(Vec<IpAddr>),
    /// The pass is scoped to an interface whose addresses could not be read, so no
    /// state can be shown to match it. Fail-closed: such a pass attributes
    /// nothing, and a state it might cover is treated as a bypass candidate.
    Unknown,
}

impl IfaceScope {
    fn permits(&self, local: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Addresses(addresses) => addresses.contains(&local),
            Self::Unknown => false,
        }
    }
}

#[derive(Debug, Clone)]
struct PermittedFlow {
    /// The rule is protocol-scoped to UDP (`pf_rule_specs` sets this on the exit
    /// carrier and the DHCP passes).
    udp_only: bool,
    /// The rule is IPv6-only; the other rules match either family.
    v6_only: bool,
    /// `None` matches any destination.
    dest: Option<IpNetwork>,
    /// `None` matches any destination port.
    dest_port: Option<u16>,
    /// The interface the rule is scoped to, judged against the state's local
    /// address.
    iface: IfaceScope,
}

impl PermittedFlow {
    /// Whether this rule passes the flow a state entry records, interface scope
    /// included: the scope is judged on the state's local address.
    fn matches(&self, view: &StateView) -> bool {
        self.iface.permits(view.local.ip())
            && (!self.v6_only || view.remote.is_ipv6())
            && (!self.udp_only || view.proto == Proto::Udp)
            && self
                .dest
                .as_ref()
                .is_none_or(|net| net.contains(view.remote.ip()))
            && self.dest_port.is_none_or(|port| port == view.remote.port())
    }
}

impl PermittedFlows {
    /// The pass rules of `opts`, in the form a state entry can be judged against.
    ///
    /// The interface-scoped passes (loopback, the tunnel) are deliberately NOT
    /// part of this set: `pfctl::State` exposes no interface name, so a state
    /// cannot be attributed to them. Loopback traffic is preserved by its
    /// addresses instead (see [`state_can_bypass`]), and a state on the tunnel
    /// cannot predate the tunnel this install just created.
    fn from_opts(
        opts: &KillswitchOpts,
        interface_addresses: &BTreeMap<String, Vec<IpAddr>>,
    ) -> Self {
        let rules = pf_rule_specs(opts)
            .into_iter()
            .filter(|spec| spec.pass)
            .map(|spec| {
                let (dest, dest_port) = match spec.dest {
                    Some(PfDest::Net(net)) => (Some(net), None),
                    Some(PfDest::AnyPort(port)) => (None, Some(port)),
                    None => (None, None),
                };
                let iface = match &spec.iface {
                    None => IfaceScope::Any,
                    Some(name) => match interface_addresses.get(name) {
                        Some(addresses) if !addresses.is_empty() => {
                            IfaceScope::Addresses(addresses.clone())
                        }
                        _ => IfaceScope::Unknown,
                    },
                };
                PermittedFlow {
                    udp_only: spec.udp,
                    v6_only: spec.v6,
                    dest,
                    dest_port,
                    iface,
                }
            })
            .collect();
        Self { rules }
    }

    /// Whether the new policy passes the flow this state entry records, from the
    /// fields the entry carries: protocol, local address, remote address, remote
    /// port.
    fn permits(&self, view: &StateView) -> bool {
        self.rules.iter().any(|rule| rule.matches(view))
    }
}

/// The fields of a pf state entry the purge decisions need, extracted once so
/// the decisions are testable without a live pf (a `pfctl::State` can only be
/// built by the ioctl binding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StateView {
    local: SocketAddr,
    remote: SocketAddr,
    proto: Proto,
}

impl StateView {
    /// Whether the flow is confined to the host: local IPC that cannot leave.
    fn is_loopback_only(&self) -> bool {
        self.local.ip().is_loopback() && self.remote.ip().is_loopback()
    }
}

/// Reads one pf state entry, or `None` when an accessor failed. An unreadable
/// entry is never assumed harmless.
fn state_view(state: &pfctl::State) -> Option<StateView> {
    Some(StateView {
        local: state.local_address().ok()?,
        remote: state.remote_address().ok()?,
        // A protocol pfctl-rs does not name is treated as `Any`, which no
        // `udp_only` pass accepts, so such a state is not provably permitted.
        proto: state.proto().unwrap_or(Proto::Any),
    })
}

/// Whether this state entry is a flow the new policy passes.
///
/// The decision is taken on what the entry carries (protocol, local address,
/// remote address, remote port) and the interface scope is judged on the LOCAL
/// address, which is the only field that can attribute an entry to an interface.
/// Loopback-to-loopback is local IPC and needs no attribution.
fn state_is_permitted(view: &StateView, permitted: &PermittedFlows) -> bool {
    view.is_loopback_only() || permitted.permits(view)
}

/// Whether the purge must kill this state: everything the policy does not pass.
///
/// A state the policy passes is preserved (killing the transport's own carrier
/// state would drop the tunnel for no confidentiality gain); everything else is a
/// connection that would egress off-tunnel without an exception, and pf answers a
/// surviving state without re-evaluating the ruleset.
fn state_must_be_killed(view: &StateView, permitted: &PermittedFlows) -> bool {
    !state_is_permitted(view, permitted)
}

/// One state entry that was still in the table when the purge re-read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Survivor {
    /// The entry was readable, so the decision can be taken on its fields.
    Read(StateView),
    /// An accessor failed, so nothing about the entry can be established.
    Unreadable,
}

/// What one purge pass observed.
#[derive(Debug, Default)]
struct PurgeReport {
    /// Number of states killed, for the log line.
    killed: u32,
    /// States still present when the table was re-read afterwards.
    survivors: Vec<Survivor>,
}

/// Whether a state the purge could not remove is a bypass, decided exactly as the
/// purge decided to kill it.
///
/// The confirmation keeps the same interface attribution as the purge, so a
/// surviving entry on an interface the scoped pass refuses is a bypass and fails
/// the install, while an entry on the pass's own interface (the transport's next
/// packet recreating its state between the kill and this read) is a flow the
/// policy passes and does not. Deciding the two differently, or ignoring the
/// interface on either side, is what would let an old off-interface state be
/// accepted as a recreation.
fn survivor_is_a_bypass(survivor: &Survivor, permitted: &PermittedFlows) -> bool {
    match survivor {
        Survivor::Read(view) => state_must_be_killed(view, permitted),
        // Nothing can be established about it, so it cannot be called harmless.
        Survivor::Unreadable => true,
    }
}

/// The verdict on a purge report.
///
/// Fatal only when a state NO pass rule covers survived: such a state cannot have
/// been created by the anchor, so it is a pre-existing connection that kept its
/// entry. A survivor that a pass rule covers is a flow the anchor itself passes,
/// which in practice is the transport's next packet recreating its state between
/// the kill and this confirmation read; failing on it would fail the install every
/// time the tunnel is up during one, and the rollback would remove the blocking
/// rules, the worse outcome for a killswitch.
fn verify_purge(report: &PurgeReport, permitted: &PermittedFlows) -> Result<(), KillswitchError> {
    let bypasses = report
        .survivors
        .iter()
        .filter(|survivor| survivor_is_a_bypass(survivor, permitted))
        .count();
    if bypasses > 0 {
        return Err(KillswitchError::Pf(format!(
            "{bypasses} surviving connection state(s) are covered by no pass rule of \
             the new policy. Off-tunnel traffic would keep flowing through them past \
             the block."
        )));
    }
    Ok(())
}

/// Seam over the pf operations the killswitch lifecycle performs.
/// pfctl-rs is a typed ioctl binding (no shell-out), so unlike the
/// Linux `CommandRunner` this seam mirrors pf *operations* rather than
/// a program+argv pair. The production impl ([`RealPfOps`]) opens
/// `/dev/pf` per operation; tests inject a recorder so the install /
/// rollback / `Drop` lifecycle is verified behaviorally without root.
trait PfOps: Send + Sync + std::fmt::Debug {
    /// `pfctl -e` equivalent (tolerates "already enabled").
    fn enable(&self) -> Result<(), KillswitchError>;
    /// `pfctl -s info`-equivalent: whether pf is CURRENTLY enabled.
    /// Captured before [`Self::enable`] so [`MacosKillswitch::uninstall`]
    /// / `Drop` can restore the host's original state instead of
    /// unconditionally leaving pf enabled forever (pf is off by default
    /// on macOS).
    fn is_enabled(&self) -> Result<bool, KillswitchError>;
    /// `pfctl -d` equivalent. Only called on teardown when
    /// [`Self::is_enabled`] reported pf as OFF before install.
    fn disable(&self) -> Result<(), KillswitchError>;
    /// The addresses the host reports for each named interface.
    ///
    /// A pf state entry carries no interface name, so its LOCAL address is the
    /// only field that can attribute it to the interface a pass rule is scoped to.
    /// An interface missing from the result, or reported with no address, is one
    /// whose passes cannot be attributed: see [`IfaceScope::Unknown`].
    fn interface_addresses(&self, ifaces: &[String]) -> BTreeMap<String, Vec<IpAddr>>;

    /// Register the Warren anchor [`PF_ANCHOR_PATH`].
    fn add_anchor(&self) -> Result<(), KillswitchError>;
    /// Drop every filter rule in the Warren anchor.
    fn flush_rules(&self) -> Result<(), KillswitchError>;
    /// Append one filter rule to the Warren anchor.
    fn add_rule(&self, rule: &FilterRule) -> Result<(), KillswitchError>;
    /// Kill every pf connection state the new policy does not provably pass,
    /// then re-read the table and report what is still there.
    ///
    /// Must run AFTER [`Self::add_rule`]: pf consults the state table before it
    /// re-evaluates the ruleset, so a connection opened before the install (by
    /// macOS's default `pass all`, for example) keeps flowing off-tunnel until
    /// its state entry is gone. See [`state_must_be_killed`] for the per-state
    /// decision.
    ///
    /// The report is data, not a verdict: whether a survivor is a bypass is
    /// [`survivor_is_a_bypass`]'s decision, which the lifecycle takes so it can be
    /// tested without `/dev/pf`.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Pf`] when the table cannot be read or a state cannot be
    /// killed. A killed state is confirmed by the re-read, so a kill that did not
    /// take effect shows up as a survivor rather than being silently assumed.
    fn purge_bypass_states(
        &self,
        permitted: &PermittedFlows,
    ) -> Result<PurgeReport, KillswitchError>;
}

/// Production [`PfOps`] backed by `pfctl-rs` against `/dev/pf`.
#[derive(Debug, Default)]
struct RealPfOps;

impl RealPfOps {
    fn pf() -> Result<PfCtl, KillswitchError> {
        PfCtl::new().map_err(|e| KillswitchError::Pf(format!("PfCtl::new: {e}")))
    }
}

impl PfOps for RealPfOps {
    fn enable(&self) -> Result<(), KillswitchError> {
        Self::pf()?
            .try_enable()
            .map_err(|e| KillswitchError::Pf(format!("pf enable: {e}")))
    }

    fn is_enabled(&self) -> Result<bool, KillswitchError> {
        Self::pf()?
            .is_enabled()
            .map_err(|e| KillswitchError::Pf(format!("pf is_enabled: {e}")))
    }

    fn disable(&self) -> Result<(), KillswitchError> {
        Self::pf()?
            .try_disable()
            .map_err(|e| KillswitchError::Pf(format!("pf disable: {e}")))
    }

    fn interface_addresses(&self, ifaces: &[String]) -> BTreeMap<String, Vec<IpAddr>> {
        let mut wanted: BTreeMap<&str, Vec<IpAddr>> = ifaces
            .iter()
            .map(|name| (name.as_str(), Vec::new()))
            .collect();
        let entries = match getifaddrs::getifaddrs() {
            Ok(entries) => entries,
            Err(e) => {
                // No address means no attribution, so every interface-scoped pass
                // stays conservative rather than being assumed to match.
                tracing::warn!(
                    error = %e,
                    "could not read the interface addresses: interface-scoped passes \
                     stay unattributable for this install"
                );
                return BTreeMap::new();
            }
        };
        for entry in entries {
            let Some(addresses) = wanted.get_mut(entry.name.as_str()) else {
                continue;
            };
            match entry.address {
                getifaddrs::Address::V4(address) => addresses.push(IpAddr::V4(address.address)),
                getifaddrs::Address::V6(address) => addresses.push(IpAddr::V6(address.address)),
                getifaddrs::Address::Mac(_) => {}
            }
        }
        wanted
            .into_iter()
            .map(|(name, addresses)| (name.to_owned(), addresses))
            .collect()
    }

    fn add_anchor(&self) -> Result<(), KillswitchError> {
        Self::pf()?
            .try_add_anchor(PF_ANCHOR_PATH, AnchorKind::Filter)
            .map_err(|e| KillswitchError::Pf(format!("add anchor: {e}")))
    }

    fn flush_rules(&self) -> Result<(), KillswitchError> {
        Self::pf()?
            .flush_rules(PF_ANCHOR_PATH, pfctl::RulesetKind::Filter)
            .map_err(|e| KillswitchError::Pf(format!("flush anchor: {e}")))
    }

    fn add_rule(&self, rule: &FilterRule) -> Result<(), KillswitchError> {
        Self::pf()?
            .add_rule(PF_ANCHOR_PATH, rule)
            .map_err(|e| KillswitchError::Pf(format!("add rule: {e}")))
    }

    fn purge_bypass_states(
        &self,
        permitted: &PermittedFlows,
    ) -> Result<PurgeReport, KillswitchError> {
        // `PfCtl::clear_states(PF_ANCHOR_PATH, ..)` is NOT usable here: it kills
        // only states whose `anchor` field equals our anchor's rule number, and
        // the anchor was registered moments ago, so it kills nothing and would
        // leave every pre-install state in place. The table has to be enumerated
        // and filtered per state instead.
        let mut pf = Self::pf()?;
        let states = pf
            .get_states()
            .map_err(|e| KillswitchError::Pf(format!("get states: {e}")))?;

        let mut killed = 0u32;
        for state in &states {
            let view = state_view(state);
            // An entry whose fields cannot be read cannot be shown to be
            // permitted, so it is killed too: the purge fails closed, and
            // `kill_state` works from the raw entry.
            let kill = view
                .as_ref()
                .is_none_or(|view| state_must_be_killed(view, permitted));
            if !kill {
                continue;
            }
            // No addresses in the error: this crate's no-log rule forbids putting
            // a peer address or source IP in a message, and the count of killed
            // states is what an operator acts on.
            pf.kill_state(state)
                .map_err(|e| KillswitchError::Pf(format!("kill a bypass connection state: {e}")))?;
            killed = killed.saturating_add(1);
        }

        // Re-read rather than assume the kills took effect: pf exposes no atomic
        // "kill and confirm", and a partially applied kill must never be reported
        // as protection. Only counts and classified views leave this function, so
        // the address-free logging rule holds.
        let survivors = pf
            .get_states()
            .map_err(|e| KillswitchError::Pf(format!("re-read states after purge: {e}")))?
            .iter()
            .map(|state| match state_view(state) {
                Some(view) => Survivor::Read(view),
                None => Survivor::Unreadable,
            })
            .collect();

        Ok(PurgeReport { killed, survivors })
    }
}

fn apply_rules(ops: &dyn PfOps, rules: &[FilterRule]) -> Result<(), KillswitchError> {
    ops.enable()?;
    ops.add_anchor()?;
    // Fatal on purpose. The anchor can hold a ruleset from a previous run
    // (an earlier install that crashed before teardown), and pfctl-rs
    // appends with `PF_CHANGE_ADD_TAIL`: loading on top of an unknown
    // previous ruleset yields a policy that is not the one we intended,
    // where a stale `pass` rule can re-open egress off-tunnel, while the
    // caller still reports a successful install. Loading NO rule is the
    // fail-closed outcome until the anchor is confirmed empty.
    ops.flush_rules()?;
    for rule in rules {
        if let Err(e) = ops.add_rule(rule) {
            // Partial install: the block-all rule is loaded FIRST, so
            // bailing here without cleanup would leave the host
            // firewalled (block-all active, allow rules missing) with
            // no guard to restore it. Roll the anchor back best-effort
            // before surfacing the original error.
            if let Err(fe) = ops.flush_rules() {
                tracing::error!(
                    error = %fe,
                    "pf rollback flush failed after a partial install - the \
                     anchor may hold a partial blocking ruleset. Run \
                     `sudo pfctl -a {PF_ANCHOR_PATH} -F rules` manually to \
                     recover internet"
                );
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Best-effort rollback of a partially applied install: drop the anchor rules,
/// then put pf's original enable state back. Mirrors `uninstall`.
async fn roll_back_install(ops: &std::sync::Arc<dyn PfOps>, pf_was_enabled: bool) {
    let rollback_ops = ops.clone();
    if let Err(fe) = tokio::task::spawn_blocking(move || rollback_ops.flush_rules())
        .await
        .map_err(|je| KillswitchError::Pf(format!("spawn_blocking flush: {je}")))
        .and_then(|inner| inner)
    {
        tracing::error!(
            error = %fe,
            "pf rollback flush failed after a failed install - the anchor may keep \
             blocking. Run `sudo pfctl -a {PF_ANCHOR_PATH} -F rules` manually to \
             recover internet"
        );
    }
    if pf_was_enabled {
        return;
    }
    let enabled_ops = ops.clone();
    if let Err(de) = tokio::task::spawn_blocking(move || enabled_ops.disable())
        .await
        .map_err(|je| KillswitchError::Pf(format!("spawn_blocking disable: {je}")))
        .and_then(|inner| inner)
    {
        tracing::error!(
            error = %de,
            "could not restore pf's original disabled state after the failed \
             install - run `sudo pfctl -d` manually if this host had pf off before \
             Warren ran"
        );
    }
}

/// pf-based macOS killswitch via pfctl-rs type-safe bindings.
#[derive(Debug)]
pub struct MacosKillswitch {
    installed: bool,
    /// Whether pf was already enabled on the host BEFORE this install
    /// turned it on. pf is off by default on macOS; a host that had it
    /// off must have it turned back off on teardown, not left enabled
    /// forever (see [`Self::uninstall`] / `Drop`).
    pf_was_enabled: bool,
    ops: std::sync::Arc<dyn PfOps>,
}

impl MacosKillswitch {
    /// Loads the killswitch rules via pfctl-rs and purges the connection
    /// states that could bypass them. Idempotent.
    ///
    /// The install is complete only when the state purge has confirmed that
    /// no bypassable state survives: pf consults the state table before it
    /// re-evaluates the ruleset, so a pre-existing connection would
    /// otherwise keep carrying off-tunnel traffic past the new block. When
    /// the purge fails or cannot be confirmed, no guard is constructed and
    /// the anchor rules plus pf's original enable state are rolled back
    /// best-effort before the error is returned.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::InvalidInput`] or [`KillswitchError::Pf`]. The
    /// `Pf` cases include a failed pre-load anchor flush and an
    /// unverifiable state purge.
    pub async fn install(opts: &KillswitchOpts) -> Result<Self, KillswitchError> {
        Self::install_with_ops(opts, std::sync::Arc::new(RealPfOps)).await
    }

    /// Same lifecycle as [`Self::install`] through an injected
    /// [`PfOps`] - the behavioral-test seam.
    async fn install_with_ops(
        opts: &KillswitchOpts,
        ops: std::sync::Arc<dyn PfOps>,
    ) -> Result<Self, KillswitchError> {
        validate_tun_name(&opts.tun_name)?;
        let rules = build_pf_rules(opts)?;
        // The interface addresses are what attribute a state entry to the
        // interface its pass is scoped to, so they are read before the permitted
        // set is built.
        let wanted: Vec<String> = opts
            .phys_iface
            .iter()
            .cloned()
            .chain(std::iter::once(opts.tun_name.clone()))
            .collect();
        let interfaces = ops.interface_addresses(&wanted);
        let permitted = PermittedFlows::from_opts(opts, &interfaces);

        // Snapshot pf's enable state BEFORE `apply_rules` turns it on
        // (its first step is `enable()`): reading it any later would
        // always observe the state WE just set, defeating the restore
        // below.
        let state_ops = ops.clone();
        let pf_was_enabled = tokio::task::spawn_blocking(move || state_ops.is_enabled())
            .await
            .map_err(|e| KillswitchError::Pf(format!("spawn_blocking is_enabled: {e}")))??;

        let apply_ops = ops.clone();
        tokio::task::spawn_blocking(move || apply_rules(apply_ops.as_ref(), &rules))
            .await
            .map_err(|e| KillswitchError::Pf(format!("spawn_blocking: {e}")))??;
        // Purge pre-existing states so connections opened before the
        // killswitch cannot keep leaking through established state
        // entries: pf consults that table before it re-evaluates the anchor
        // rules we just loaded. The call verifies the table afterwards and
        // fails when a bypass state survives, so its error is FATAL here:
        // returning a guard would announce a protection that is not
        // actually in place.
        let states_ops = ops.clone();
        let purge_permitted = permitted.clone();
        let purge =
            tokio::task::spawn_blocking(move || states_ops.purge_bypass_states(&purge_permitted))
                .await
                .map_err(|e| KillswitchError::Pf(format!("spawn_blocking states: {e}")));
        // Both the failure to purge and the verdict on what survived roll the
        // anchor back: returning a guard would announce a protection that is not
        // confirmed. The verdict itself is [`verify_purge`], a pure function, so
        // the race the purge cannot avoid is decided by a rule the test suite can
        // exercise without `/dev/pf`.
        let report = match purge.and_then(|inner| inner) {
            Ok(report) => report,
            Err(e) => {
                roll_back_install(&ops, pf_was_enabled).await;
                return Err(e);
            }
        };
        if let Err(e) = verify_purge(&report, &permitted) {
            roll_back_install(&ops, pf_was_enabled).await;
            return Err(e);
        }
        if !report.survivors.is_empty() {
            tracing::info!(
                recreated = report.survivors.len(),
                "connection state(s) present after the purge match a pass rule of the \
                 new policy, which only the anchor can have created"
            );
        }
        let killed_states = report.killed;
        tracing::info!(
            tun = %opts.tun_name,
            exit_count = opts.exit_addrs.len(),
            allow_lan = opts.allow_lan,
            allow_dhcp = opts.allow_dhcp,
            pf_was_enabled,
            killed_states,
            "Warren killswitch installed (macOS pf via pfctl-rs)"
        );
        Ok(Self {
            installed: true,
            pf_was_enabled,
            ops,
        })
    }

    /// Flushes anchor rules, then restores pf's original enable state if
    /// this install was the one that turned it on. Idempotent.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Pf`] if the anchor flush fails. A failure to
    /// restore the enable state is logged but does not fail the call
    /// (best-effort, matching the rest of this crate's teardown paths).
    pub async fn uninstall(mut self) -> Result<(), KillswitchError> {
        let ops = self.ops.clone();
        let res = tokio::task::spawn_blocking(move || ops.flush_rules())
            .await
            .map_err(|e| KillswitchError::Pf(format!("spawn_blocking: {e}")))?;
        self.restore_pf_enable_state_blocking().await;
        self.installed = false;
        res
    }

    /// If pf was OFF before install, turns it back off; a no-op when it
    /// was already on (never touches a state we did not create). Runs on
    /// the blocking pool since [`PfOps::disable`] is a synchronous ioctl.
    /// Best-effort: logs a warning on failure rather than propagating,
    /// mirroring the rest of this crate's teardown error handling.
    async fn restore_pf_enable_state_blocking(&self) {
        if self.pf_was_enabled {
            return;
        }
        let ops = self.ops.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || ops.disable())
            .await
            .map_err(|e| KillswitchError::Pf(format!("spawn_blocking disable: {e}")))
            .and_then(|inner| inner)
        {
            tracing::warn!(
                error = %e,
                "failed to restore pf's original disabled state after killswitch uninstall"
            );
        }
    }
}

impl Drop for MacosKillswitch {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // Best-effort synchronous rollback for the non-panic abnormal
        // paths (early return, task abort, debug-build unwind). With
        // `panic = "abort"` in release, this never runs on a real
        // panic: the anchor then keeps blocking (fail-closed, cf.
        // crate-level doc).
        match self.ops.flush_rules() {
            Ok(()) => {
                tracing::warn!(
                    "Warren killswitch dropped without explicit uninstall - \
                     synchronous pf flush succeeded"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Warren killswitch Drop pf flush failed - anchor may still \
                     hold rules. Run `sudo pfctl -a {PF_ANCHOR_PATH} -F all` \
                     manually."
                );
            }
        }
        // Restore pf's original disabled state too, same rule as
        // `uninstall`: a host where pf was off before install must not
        // be left with pf enabled forever just because the guard was
        // dropped instead of explicitly uninstalled.
        if !self.pf_was_enabled
            && let Err(e) = self.ops.disable()
        {
            tracing::error!(
                error = %e,
                "Warren killswitch Drop could not restore pf's original \
                 disabled state - pf may be left enabled. Run `sudo pfctl -d` \
                 manually if this host had pf off before Warren ran."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn opts_minimal() -> KillswitchOpts {
        KillswitchOpts {
            exit_addrs: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            tun_name: "utun7".into(),
            allow_lan: false,
            allow_dhcp: false,
            socket_mark: None,
            phys_iface: None,
        }
    }

    #[test]
    fn build_rules_produces_block_plus_passes() {
        let rules = build_pf_rules(&opts_minimal()).unwrap();
        assert!(
            rules.len() >= 4,
            "need at least block-all + loopback + tun + 1 exit IP = 4 rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn default_block_is_non_quick_so_pass_exceptions_are_reachable() {
        // pf stops at the first `quick` match. A `quick` default block (the old
        // bug) therefore fires for every packet before the pass exceptions and
        // blocks all egress, the tunnel included: the datapath forwards uplink
        // but the host egresses nothing. The block must be a plain (non-quick)
        // last-match default that the quick pass exceptions override.
        let specs = pf_rule_specs(&opts_minimal());
        let block = specs.first().expect("at least the default block");
        assert!(!block.pass, "the first rule is the default block");
        assert!(
            block.iface.is_none() && block.dest.is_none() && !block.udp,
            "the default block must match ALL outbound"
        );
        assert!(
            !block.quick,
            "the default block MUST be non-quick, else it preempts every pass \
             exception and blocks the tunnel too"
        );
        assert!(
            specs
                .iter()
                .any(|s| s.pass && s.quick && s.iface.as_deref() == Some("utun7")),
            "the tun interface must be a quick pass exception that overrides the block"
        );
        assert!(
            specs.iter().skip(1).all(|s| s.pass && s.quick),
            "every rule after the default block is a quick pass exception"
        );
    }

    #[test]
    fn build_rules_with_lan_adds_extra_rules() {
        let mut o = opts_minimal();
        o.allow_lan = true;
        let rules = build_pf_rules(&o).unwrap();
        assert!(
            rules.len() >= 9,
            "LAN should add 5 rules (3 v4 + 2 v6), got {}",
            rules.len()
        );
    }

    #[test]
    fn build_rules_with_dhcp_adds_two_rules() {
        let mut o = opts_minimal();
        o.allow_dhcp = true;
        let without = build_pf_rules(&opts_minimal()).unwrap().len();
        let with = build_pf_rules(&o).unwrap().len();
        assert_eq!(
            with - without,
            2,
            "DHCP should add exactly 2 rules (port 67 + 68)"
        );
    }

    #[test]
    fn build_rules_with_ipv6_exit() {
        let mut o = opts_minimal();
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0xc013, 0x14a1, 0, 0, 0, 1);
        o.exit_addrs.push(IpAddr::V6(v6));
        let rules = build_pf_rules(&o).unwrap();
        assert!(
            rules.len() >= 5,
            "2 exit IPs should produce at least 5 rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn build_rules_empty_exit_addrs_still_has_base_rules() {
        let mut o = opts_minimal();
        o.exit_addrs.clear();
        let rules = build_pf_rules(&o).unwrap();
        assert!(
            rules.len() >= 3,
            "even without exits: block-all + loopback + tun = 3 rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn anchor_path_uses_com_apple_subprefix() {
        assert!(PF_ANCHOR_PATH.starts_with("com.apple/"));
        assert!(PF_ANCHOR_PATH.contains("warren"));
    }

    #[test]
    fn build_rules_without_phys_iface_keeps_unscoped_exit_rule() {
        // Back-compat: phys_iface: None must keep the legacy
        // interface-agnostic exit-IP pass rule.
        let rules = build_pf_rules(&opts_minimal()).unwrap();
        let exit_v4 = Ipv4Addr::new(1, 2, 3, 4);
        let ip_net = IpNetwork::V4(Ipv4Network::new(exit_v4, 32).expect("single-host mask"));
        let expected = FilterRuleBuilder::default()
            .action(FilterRuleAction::Pass)
            .direction(pfctl::Direction::Out)
            .quick(true)
            .proto(pfctl::Proto::Udp)
            .to(pfctl::Endpoint::new(ip_net, pfctl::Port::Any))
            .build()
            .expect("expected exit rule");
        assert!(
            rules.contains(&expected),
            "without phys_iface the exit rule must stay unscoped (any \
             interface); rules: {rules:#?}"
        );
    }

    #[test]
    fn build_rules_with_phys_iface_scopes_exit_rule_to_interface() {
        // Port Fail / TunnelCrack-ServerIP fix: scoping the exit-IP
        // pass rule to the physical interface means only the daemon's
        // IP_BOUND_IF-bound socket can still match it; every other
        // process dialing the exit IP now gets captured into the
        // tunnel by the split-default route instead.
        let mut o = opts_minimal();
        o.phys_iface = Some("en0".into());
        let rules = build_pf_rules(&o).unwrap();

        let exit_v4 = Ipv4Addr::new(1, 2, 3, 4);
        let ip_net = IpNetwork::V4(Ipv4Network::new(exit_v4, 32).expect("single-host mask"));
        let expected = FilterRuleBuilder::default()
            .action(FilterRuleAction::Pass)
            .direction(pfctl::Direction::Out)
            .quick(true)
            .proto(pfctl::Proto::Udp)
            .to(pfctl::Endpoint::new(ip_net, pfctl::Port::Any))
            .interface(pfctl::Interface::from("en0"))
            .build()
            .expect("expected scoped exit rule");
        assert!(
            rules.contains(&expected),
            "exit-IP pass rule must be scoped to the physical interface \
             when phys_iface is set; rules: {rules:#?}"
        );

        let expected_block_all = FilterRuleBuilder::default()
            .action(FilterRuleAction::Drop(pfctl::DropAction::Return))
            .direction(pfctl::Direction::Out)
            .quick(false)
            .build()
            .expect("expected block-all rule");
        assert_eq!(
            rules[0], expected_block_all,
            "the block-all default is first but NON-quick (so the quick pass \
             exceptions override it), regardless of phys_iface"
        );
    }

    // ---- behavioral lifecycle (mock PfOps) ---------------------------

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct MockPf {
        ops: std::sync::Mutex<Vec<String>>,
        rules_added: AtomicUsize,
        flushes: AtomicUsize,
        /// When `Some(n)`, the n-th `add_rule` call (0-based) fails.
        fail_on_add_rule_index: Option<usize>,
        /// When `Some(n)`, the n-th `flush_rules` call (0-based) fails.
        fail_on_flush_index: Option<usize>,
        /// When `true`, `purge_bypass_states` fails, standing in for a table
        /// that could not be read or a state that could not be killed.
        fail_purge: bool,
        /// What the purge reports as still present when it re-reads the table.
        /// Models the race the purge cannot avoid: the transport recreating its
        /// own state between the kill and the confirmation read.
        purge_survivors: Vec<Survivor>,
        /// What `is_enabled` reports - the host's pf state before install.
        initially_enabled: bool,
        /// What `is_enabled` reports after `enable` / `disable` ran, so
        /// the restore path is observable the way it is on a real host.
        currently_enabled: std::sync::atomic::AtomicBool,
        /// Whether the permitted set handed to `purge_bypass_states` passes a
        /// LAN flow. Records the wiring from `KillswitchOpts` to the purge,
        /// which no predicate unit test can observe.
        purge_permits_lan: std::sync::atomic::AtomicBool,
        /// The addresses `interface_addresses` reports, by interface name.
        interface_addresses: BTreeMap<String, Vec<IpAddr>>,
    }

    impl MockPf {
        fn failing_at_rule(index: usize) -> Self {
            Self {
                fail_on_add_rule_index: Some(index),
                ..Self::default()
            }
        }

        /// A host whose pf enable state before install is `enabled`.
        fn starting_enabled(enabled: bool) -> Self {
            Self {
                initially_enabled: enabled,
                ..Self::default()
            }
        }

        /// A mock whose `purge_bypass_states` fails outright.
        fn failing_purge() -> Self {
            Self {
                fail_purge: true,
                ..Self::default()
            }
        }

        /// A mock whose purge reports these states as still in the table.
        fn reporting_survivors(survivors: Vec<Survivor>) -> Self {
            Self {
                purge_survivors: survivors,
                ..Self::default()
            }
        }

        /// The host addresses the seam reports for `iface`, which is what
        /// attributes a state entry to it.
        fn with_interface_addresses(mut self, iface: &str, addresses: &[IpAddr]) -> Self {
            self.interface_addresses
                .insert(iface.to_owned(), addresses.to_vec());
            self
        }

        /// A mock whose n-th `flush_rules` call fails.
        fn failing_flush(index: usize) -> Self {
            Self {
                fail_on_flush_index: Some(index),
                ..Self::default()
            }
        }

        fn recorded(&self) -> Vec<String> {
            self.ops.lock().expect("mock mutex").clone()
        }

        /// Whether the permitted set handed to the purge passed a LAN flow.
        fn purge_permitted_a_lan_flow(&self) -> bool {
            self.purge_permits_lan.load(Ordering::SeqCst)
        }

        fn record(&self, op: &str) {
            self.ops.lock().expect("mock mutex").push(op.to_owned());
        }
    }

    impl PfOps for MockPf {
        fn enable(&self) -> Result<(), KillswitchError> {
            self.record("enable");
            self.currently_enabled.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn is_enabled(&self) -> Result<bool, KillswitchError> {
            self.record("is_enabled");
            if self.currently_enabled.load(Ordering::SeqCst) {
                return Ok(true);
            }
            Ok(self.initially_enabled)
        }
        fn disable(&self) -> Result<(), KillswitchError> {
            self.record("disable");
            self.currently_enabled.store(false, Ordering::SeqCst);
            Ok(())
        }
        fn interface_addresses(&self, ifaces: &[String]) -> BTreeMap<String, Vec<IpAddr>> {
            self.record("interface_addresses");
            ifaces
                .iter()
                .filter_map(|name| {
                    self.interface_addresses
                        .get(name)
                        .map(|addresses| (name.clone(), addresses.clone()))
                })
                .collect()
        }

        fn add_anchor(&self) -> Result<(), KillswitchError> {
            self.record("add_anchor");
            Ok(())
        }
        fn flush_rules(&self) -> Result<(), KillswitchError> {
            let index = self.flushes.fetch_add(1, Ordering::SeqCst);
            self.record("flush_rules");
            if self.fail_on_flush_index == Some(index) {
                return Err(KillswitchError::Pf("mock flush_rules failure".into()));
            }
            Ok(())
        }
        fn add_rule(&self, _rule: &FilterRule) -> Result<(), KillswitchError> {
            let index = self.rules_added.fetch_add(1, Ordering::SeqCst);
            self.record("add_rule");
            if self.fail_on_add_rule_index == Some(index) {
                return Err(KillswitchError::Pf("mock add_rule failure".into()));
            }
            Ok(())
        }
        fn purge_bypass_states(
            &self,
            permitted: &PermittedFlows,
        ) -> Result<PurgeReport, KillswitchError> {
            let lan: SocketAddr = (Ipv4Addr::new(192, 168, 1, 20), 22).into();
            let local: SocketAddr = (Ipv4Addr::new(198, 51, 100, 7), 5000).into();
            self.purge_permits_lan.store(
                permitted.permits(&view(local, lan, Proto::Tcp)),
                Ordering::SeqCst,
            );
            self.record("purge_bypass_states");
            if self.fail_purge {
                return Err(KillswitchError::Pf(
                    "mock purge: the table could not be read".into(),
                ));
            }
            Ok(PurgeReport {
                killed: 3,
                survivors: self.purge_survivors.clone(),
            })
        }
    }

    fn flush_count(ops: &[String]) -> usize {
        ops.iter().filter(|o| *o == "flush_rules").count()
    }

    #[tokio::test]
    async fn drop_flushes_the_anchor_rules() {
        // pf already enabled before install: the Drop pf-restore step (see
        // the dedicated tests below) is then a no-op, so this test can
        // isolate the anchor-flush assertion on `ops.last()`.
        let pf = Arc::new(MockPf::starting_enabled(true));
        {
            let _guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
                .await
                .expect("install through mock pf");
        } // <- dropped without explicit uninstall

        let ops = pf.recorded();
        assert_eq!(
            ops.last().map(String::as_str),
            Some("flush_rules"),
            "Drop must flush the Warren anchor - the fail-closed rollback \
             after an abnormal exit; an empty Drop would leave the host \
             firewalled. Ops: {ops:?}"
        );
        assert_eq!(
            flush_count(&ops),
            2,
            "one install-time flush (clear previous) + exactly one Drop \
             flush; ops: {ops:?}"
        );
    }

    // ---- pf enable-state capture / restore (M9 promotion + standalone fix) --

    #[tokio::test]
    async fn install_captures_the_enable_state_before_turning_pf_on() {
        // The snapshot MUST happen before `enable()`, else it always reads
        // back the state WE just set and the restore below is a no-op no
        // matter what the host's real prior state was.
        let pf = Arc::new(MockPf::starting_enabled(false));
        let _guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect("install");
        let ops = pf.recorded();
        let enabled_pos = ops
            .iter()
            .position(|o| o == "is_enabled")
            .expect("is_enabled must be recorded");
        let enable_pos = ops
            .iter()
            .position(|o| o == "enable")
            .expect("enable must be recorded");
        assert!(
            enabled_pos < enable_pos,
            "is_enabled must be captured BEFORE enable() runs; ops: {ops:?}"
        );
    }

    #[tokio::test]
    async fn uninstall_disables_pf_when_it_was_off_before_install() {
        let pf = Arc::new(MockPf::starting_enabled(false));
        let guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect("install");
        guard.uninstall().await.expect("uninstall");
        let ops = pf.recorded();
        assert!(
            ops.contains(&"disable".to_owned()),
            "a host where pf was OFF before install must have it turned back \
             OFF on uninstall, not left enabled forever; ops: {ops:?}"
        );
    }

    #[tokio::test]
    async fn uninstall_leaves_pf_enabled_when_it_was_already_on_before_install() {
        let pf = Arc::new(MockPf::starting_enabled(true));
        let guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect("install");
        guard.uninstall().await.expect("uninstall");
        let ops = pf.recorded();
        assert!(
            !ops.contains(&"disable".to_owned()),
            "must never disable pf when it was already enabled by something \
             else before install; ops: {ops:?}"
        );
    }

    #[tokio::test]
    async fn drop_restores_pf_disabled_state_without_explicit_uninstall() {
        let pf = Arc::new(MockPf::starting_enabled(false));
        {
            let _guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
                .await
                .expect("install");
        } // <- dropped without explicit uninstall
        let ops = pf.recorded();
        assert!(
            ops.contains(&"disable".to_owned()),
            "Drop must restore pf's original OFF state too, not just the \
             explicit uninstall path; ops: {ops:?}"
        );
    }

    #[tokio::test]
    async fn drop_does_not_disable_pf_when_it_was_already_on_before_install() {
        let pf = Arc::new(MockPf::starting_enabled(true));
        {
            let _guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
                .await
                .expect("install");
        }
        let ops = pf.recorded();
        assert!(
            !ops.contains(&"disable".to_owned()),
            "Drop must not disable pf when the host had it on before install; \
             ops: {ops:?}"
        );
    }

    #[tokio::test]
    async fn partial_install_failure_rolls_back_the_anchor() {
        // Fail on the 3rd rule: the block-all rule (index 0) and the
        // loopback pass (index 1) are already loaded at that point, so
        // returning without a rollback would leave the host blocked
        // with no guard to clean up.
        let pf = Arc::new(MockPf::failing_at_rule(2));
        let err = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect_err("install must surface the add_rule failure");
        assert!(matches!(err, KillswitchError::Pf(_)), "got {err:?}");

        let ops = pf.recorded();
        let last_add = ops
            .iter()
            .rposition(|o| o == "add_rule")
            .expect("add_rule was attempted");
        assert!(
            ops[last_add..].iter().any(|o| o == "flush_rules"),
            "a partial install (block-all already loaded) must flush the \
             anchor before surfacing the error; ops: {ops:?}"
        );
        assert!(
            !ops.contains(&"purge_bypass_states".to_owned()),
            "no state purge after a failed install; ops: {ops:?}"
        );
    }

    #[tokio::test]
    async fn explicit_uninstall_then_drop_flushes_exactly_once() {
        let pf = Arc::new(MockPf::default());
        let guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect("install");
        guard.uninstall().await.expect("explicit uninstall");

        let ops = pf.recorded();
        assert_eq!(
            flush_count(&ops),
            2,
            "install-time flush + uninstall flush only: Drop after an \
             explicit uninstall must be a no-op; ops: {ops:?}"
        );
    }

    // ---- pre-existing connection-state purge -------------------------
    //
    // pf consults its state table BEFORE re-evaluating the ruleset, so a
    // connection opened before the install keeps flowing past the new
    // anchor block until its state entry is gone. The purge must
    // therefore run after the rules are loaded and must be fatal when it
    // cannot confirm the table is clean: an install that reports success
    // while a bypass state survives is a confidentiality bug.

    // ---- which states the purge may kill ------------------------------
    //
    // The purge must remove what the new policy refuses and preserve what it
    // passes: the exit carrier and the optional LAN and DHCP flows are exceptions
    // the anchor itself grants, so their existing states are legitimate. Treating
    // them as bypass candidates would drop the tunnel's own transport and could
    // make the confirmation read fail.

    const EXIT_V4: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);

    /// A state entry as the purge sees it.
    fn view(local: SocketAddr, remote: SocketAddr, proto: Proto) -> StateView {
        StateView {
            local,
            remote,
            proto,
        }
    }

    /// The host addresses the seam reports for one interface.
    fn addrs(iface: &str, addresses: &[&str]) -> BTreeMap<String, Vec<IpAddr>> {
        BTreeMap::from([(
            iface.to_owned(),
            addresses
                .iter()
                .map(|address| address.parse().expect("an address literal"))
                .collect(),
        )])
    }

    const EN0: &str = "192.0.2.10";
    const OTHER_IFACE_ADDR: &str = "198.51.100.7";

    #[test]
    fn the_permitted_set_keeps_every_pass_with_its_interface_scope() {
        // Every pass of the ruleset is kept, because the interface scope can now be
        // judged: a state's LOCAL address is what attributes it to an interface.
        let mut o = opts_minimal();
        o.allow_lan = true;
        o.allow_dhcp = true;
        let flows = PermittedFlows::from_opts(&o, &BTreeMap::new());
        // Loopback, tunnel, one exit host, three v4 LAN ranges, two v6 LAN ranges,
        // two DHCP ports.
        assert_eq!(flows.rules.len(), 3 + 3 + 2 + 2);
        assert!(
            flows.rules.iter().all(|r| r.iface != IfaceScope::Any)
                || flows.rules.iter().any(|r| r.dest.is_some()),
            "a pass with no destination scope must carry an interface scope, or it \
             would permit every flow: {:#?}",
            flows.rules
        );

        let mut scoped = opts_minimal();
        scoped.phys_iface = Some("en0".into());
        let unknown = PermittedFlows::from_opts(&scoped, &BTreeMap::new());
        assert!(
            unknown
                .rules
                .iter()
                .any(|r| r.iface == IfaceScope::Unknown && r.dest.is_some()),
            "without the interface addresses the carrier pass cannot be attributed: \
             {:#?}",
            unknown.rules
        );
        let known = PermittedFlows::from_opts(&scoped, &addrs("en0", &[EN0]));
        assert!(
            known.rules.iter().any(|r| r.iface
                == IfaceScope::Addresses(vec![EN0.parse::<IpAddr>().expect("address")])
                && r.dest.is_some()),
            "with them, the carrier pass is attributed by address: {:#?}",
            known.rules
        );
    }

    #[test]
    fn loopback_only_states_are_preserved() {
        let flows = PermittedFlows::from_opts(&opts_minimal(), &BTreeMap::new());
        let lo_a: SocketAddr = (Ipv4Addr::LOCALHOST, 1234).into();
        let lo_b: SocketAddr = (Ipv4Addr::LOCALHOST, 8080).into();
        let lo_v6: SocketAddr = (Ipv6Addr::LOCALHOST, 53).into();
        for (local, remote) in [(lo_a, lo_b), (lo_a, lo_v6), (lo_v6, lo_b)] {
            assert!(
                !state_must_be_killed(&view(local, remote, Proto::Tcp), &flows),
                "local IPC cannot leave the host and must be preserved: {local} {remote}"
            );
        }
    }

    #[test]
    fn the_exit_carrier_state_is_preserved_when_the_pass_is_not_interface_scoped() {
        let flows = PermittedFlows::from_opts(&opts_minimal(), &BTreeMap::new());
        let local: SocketAddr = (Ipv4Addr::new(198, 51, 100, 7), 5000).into();
        let carrier: SocketAddr = (EXIT_V4, 443).into();
        assert!(
            !state_must_be_killed(&view(local, carrier, Proto::Udp), &flows),
            "the carrier is a flow the anchor plainly passes: killing its state would \
             drop the tunnel's own transport"
        );
        assert!(
            state_must_be_killed(&view(local, carrier, Proto::Tcp), &flows),
            "the carrier exception is UDP-scoped, so a TCP state to the exit address is \
             not something the anchor passes"
        );
    }

    #[test]
    fn an_interface_scoped_pass_attributes_a_state_by_its_local_address() {
        // The distinction the confirmation has to keep. pf answers an existing
        // state without re-evaluating the ruleset, so an entry on an interface the
        // scoped pass refuses is a bypass; an entry whose LOCAL address is one of
        // the scoped interface's addresses is a flow that pass covers, which is
        // what the transport recreates between the kill and the read.
        let carrier: SocketAddr = (EXIT_V4, 443).into();
        let mut o = opts_minimal();
        o.phys_iface = Some("en0".into());
        let flows = PermittedFlows::from_opts(&o, &addrs("en0", &[EN0]));

        let on_en0 = view(
            (EN0.parse::<IpAddr>().expect("address"), 5000_u16).into(),
            carrier,
            Proto::Udp,
        );
        assert!(
            !state_must_be_killed(&on_en0, &flows),
            "a state whose local address is en0's is a flow the scoped pass covers"
        );
        assert!(
            !survivor_is_a_bypass(&Survivor::Read(on_en0), &flows),
            "and its recreation during the install must not fail the install"
        );

        let elsewhere = view(
            (
                OTHER_IFACE_ADDR.parse::<IpAddr>().expect("address"),
                5000_u16,
            )
                .into(),
            carrier,
            Proto::Udp,
        );
        assert!(
            state_must_be_killed(&elsewhere, &flows),
            "a state to the exit whose local address is another interface's is NOT \
             something the scoped pass covers"
        );
        assert!(
            survivor_is_a_bypass(&Survivor::Read(elsewhere), &flows),
            "and if it survives, the protection is not confirmed: the install must fail"
        );

        // No addresses read means no attribution, which must not be assumed to
        // match: the conservative outcome is the fail-closed one.
        let blind = PermittedFlows::from_opts(&o, &BTreeMap::new());
        assert!(
            state_must_be_killed(&on_en0, &blind),
            "an unattributable interface scope must not preserve a state"
        );
        assert!(survivor_is_a_bypass(&Survivor::Read(on_en0), &blind));
    }

    #[test]
    fn an_ordinary_public_flow_is_a_bypass_candidate_and_a_surviving_one_is_fatal() {
        let flows = PermittedFlows::from_opts(&opts_minimal(), &BTreeMap::new());
        let local: SocketAddr = (Ipv4Addr::new(192, 0, 2, 10), 5000).into();
        let remote: SocketAddr = (Ipv4Addr::new(93, 184, 216, 34), 443).into();
        let probe = view(local, remote, Proto::Tcp);
        assert!(
            state_must_be_killed(&probe, &flows),
            "a pre-existing connection with no exception in the policy is exactly what \
             the purge must kill"
        );
        assert!(
            survivor_is_a_bypass(&Survivor::Read(probe), &flows),
            "and if it survives, no pass rule can explain it: the install must fail"
        );
    }

    #[test]
    fn an_unreadable_survivor_is_a_bypass() {
        let flows = PermittedFlows::from_opts(&opts_minimal(), &BTreeMap::new());
        assert!(
            survivor_is_a_bypass(&Survivor::Unreadable, &flows),
            "nothing can be established about an unreadable entry, so it cannot be \
             called harmless"
        );
    }

    #[test]
    fn verify_purge_fails_only_on_a_survivor_the_policy_does_not_pass() {
        let mut o = opts_minimal();
        o.phys_iface = Some("en0".into());
        let flows = PermittedFlows::from_opts(&o, &addrs("en0", &[EN0]));
        let carrier: SocketAddr = (EXIT_V4, 443).into();
        let public: SocketAddr = (Ipv4Addr::new(93, 184, 216, 34), 443).into();

        let recreated = PurgeReport {
            killed: 2,
            survivors: vec![Survivor::Read(view(
                (EN0.parse::<IpAddr>().expect("address"), 5000_u16).into(),
                carrier,
                Proto::Udp,
            ))],
        };
        verify_purge(&recreated, &flows)
            .expect("a transport that recreated its authorised state must not fail the install");

        let off_interface = PurgeReport {
            killed: 1,
            survivors: vec![Survivor::Read(view(
                (
                    OTHER_IFACE_ADDR.parse::<IpAddr>().expect("address"),
                    5000_u16,
                )
                    .into(),
                carrier,
                Proto::Udp,
            ))],
        };
        assert!(
            verify_purge(&off_interface, &flows).is_err(),
            "a state to the exit on another interface is a bypass the scoped pass refuses"
        );

        let leaked = PurgeReport {
            killed: 2,
            survivors: vec![Survivor::Read(view(
                (EN0.parse::<IpAddr>().expect("address"), 5000_u16).into(),
                public,
                Proto::Tcp,
            ))],
        };
        assert!(
            verify_purge(&leaked, &flows).is_err(),
            "a survivor no pass rule covers is a pre-existing bypass"
        );
    }

    #[test]
    fn lan_states_are_preserved_only_when_the_lan_is_allowed() {
        let local: SocketAddr = (Ipv4Addr::new(192, 0, 2, 10), 5000).into();
        let lan: SocketAddr = (Ipv4Addr::new(192, 168, 1, 20), 22).into();
        assert!(
            state_must_be_killed(
                &view(local, lan, Proto::Tcp),
                &PermittedFlows::from_opts(&opts_minimal(), &BTreeMap::new())
            ),
            "with the LAN blocked, a LAN connection is a bypass candidate"
        );
        let mut o = opts_minimal();
        o.allow_lan = true;
        assert!(
            !state_must_be_killed(
                &view(local, lan, Proto::Tcp),
                &PermittedFlows::from_opts(&o, &BTreeMap::new())
            ),
            "with the LAN allowed the anchor passes it, so its state must survive"
        );
    }

    #[test]
    fn dhcp_states_are_preserved_only_when_dhcp_is_allowed_and_on_the_right_port() {
        let local: SocketAddr = (Ipv4Addr::new(0, 0, 0, 0), 68).into();
        let server: SocketAddr = (Ipv4Addr::new(255, 255, 255, 255), 67).into();
        assert!(
            state_must_be_killed(
                &view(local, server, Proto::Udp),
                &PermittedFlows::from_opts(&opts_minimal(), &BTreeMap::new())
            ),
            "DHCP is opt-in"
        );
        let mut o = opts_minimal();
        o.allow_dhcp = true;
        let flows = PermittedFlows::from_opts(&o, &BTreeMap::new());
        assert!(
            !state_must_be_killed(&view(local, server, Proto::Udp), &flows),
            "an allowed DHCP exchange must survive the purge"
        );
        let dns: SocketAddr = (Ipv4Addr::new(1, 1, 1, 1), 53).into();
        assert!(
            state_must_be_killed(&view(local, dns, Proto::Udp), &flows),
            "only ports 67 and 68 are passed, so a DNS state is still a bypass"
        );
    }

    #[tokio::test]
    async fn the_purge_receives_the_flows_the_policy_allows() {
        // The wiring, not just the predicate: the permitted set handed to the purge
        // must be the one the anchor installs. With the LAN allowed, a LAN
        // connection is a flow the policy passes; without it, the same connection is
        // a bypass candidate. Getting this wrong is what made the purge kill the
        // exit carrier and refuse an install whose carrier had reconnected.
        let pf = Arc::new(MockPf::default());
        let mut open = opts_minimal();
        open.allow_lan = true;
        let guard = MacosKillswitch::install_with_ops(&open, pf.clone())
            .await
            .expect("install with the LAN allowed");
        assert!(
            pf.purge_permitted_a_lan_flow(),
            "allow_lan must reach the purge predicate: {:#?}",
            pf.recorded()
        );
        drop(guard);

        let pf = Arc::new(MockPf::default());
        let guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect("install with the LAN blocked");
        assert!(
            !pf.purge_permitted_a_lan_flow(),
            "without allow_lan a pre-existing LAN connection is a bypass candidate"
        );
        drop(guard);
    }

    #[tokio::test]
    async fn purge_runs_after_the_rules_are_loaded_and_before_the_guard() {
        let pf = Arc::new(MockPf::default());
        let guard = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect("install");
        let ops = pf.recorded();
        // The guard exists only after the purge confirmed the table is
        // clean: `recorded()` already includes the uninstall flush below,
        // so read the install prefix first.
        let purge_pos = ops
            .iter()
            .position(|o| o == "purge_bypass_states")
            .expect("the install must purge pre-existing states");
        let last_add = ops
            .iter()
            .rposition(|o| o == "add_rule")
            .expect("the install must load rules");
        assert!(
            last_add < purge_pos,
            "the purge must run AFTER the anchor rules are loaded, else a \
             connection can be re-created by the old pass-all ruleset \
             between the purge and the load; ops: {ops:?}"
        );
        drop(guard);
    }

    #[tokio::test]
    async fn install_fails_and_rolls_back_when_the_purge_fails() {
        // Models the production verification step reporting bypass states
        // still present: the install must not claim protection it has not
        // confirmed.
        let pf = Arc::new(MockPf::failing_purge());
        let err = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect_err("a failed purge must fail the install, not warn");
        assert!(matches!(err, KillswitchError::Pf(_)), "got {err:?}");

        let ops = pf.recorded();
        let purge_pos = ops
            .iter()
            .position(|o| o == "purge_bypass_states")
            .expect("purge attempted");
        assert!(
            ops[purge_pos..].iter().any(|o| o == "flush_rules"),
            "the rollback must flush the anchor after a failed purge, else \
             the host is left firewalled with no guard to restore it; ops: \
             {ops:?}"
        );
        assert!(
            ops.contains(&"disable".to_owned()),
            "the rollback must restore pf's original enable state exactly as \
             uninstall does (this host had pf off before install); ops: {ops:?}"
        );
        assert!(
            !ops[purge_pos..].iter().any(|o| o == "add_rule"),
            "no rule may be loaded after the purge failed; ops: {ops:?}"
        );
    }

    #[tokio::test]
    async fn a_state_recreated_by_the_transport_does_not_fail_the_install() {
        // The race the purge cannot avoid: the transport's next packet recreates
        // its carrier state between the kill and the confirmation read. With
        // `phys_iface` the pass is interface-scoped, so the purge killed the state
        // it could not attribute; the state present afterwards is a flow the anchor
        // passes, and failing on it would strip the blocking rules every time the
        // tunnel is up during an install.
        let local: SocketAddr = (Ipv4Addr::new(192, 0, 2, 10), 5000).into();
        let carrier: SocketAddr = (EXIT_V4, 443).into();
        let mut o = opts_minimal();
        o.phys_iface = Some("en0".into());
        // The seam reports en0's addresses, which is what attributes the state to
        // the interface the carrier pass is scoped to.
        let pf = Arc::new(
            MockPf::reporting_survivors(vec![Survivor::Read(view(local, carrier, Proto::Udp))])
                .with_interface_addresses("en0", &[local.ip()]),
        );

        let guard = MacosKillswitch::install_with_ops(&o, pf.clone())
            .await
            .expect("a recreated authorised state must not fail the install");
        let ops = pf.recorded();
        let purge_pos = ops
            .iter()
            .position(|o| o == "purge_bypass_states")
            .expect("the purge ran");
        assert!(
            !ops[purge_pos..].iter().any(|o| o == "flush_rules"),
            "the install must not roll the anchor back for a recreation: {ops:?}"
        );
        drop(guard);
    }

    #[tokio::test]
    async fn a_state_to_the_exit_on_another_interface_fails_the_install() {
        // The hole a destination-only confirmation left open: a pre-existing state
        // to the exit address on an interface the scoped pass refuses. Its local
        // address is what gives it away, and the install must not report a
        // protection it has not confirmed.
        let local: SocketAddr = (Ipv4Addr::new(198, 51, 100, 7), 5000).into();
        let carrier: SocketAddr = (EXIT_V4, 443).into();
        let mut o = opts_minimal();
        o.phys_iface = Some("en0".into());
        let pf = Arc::new(
            MockPf::reporting_survivors(vec![Survivor::Read(view(local, carrier, Proto::Udp))])
                .with_interface_addresses("en0", &[EN0.parse::<IpAddr>().expect("address")]),
        );

        let err = MacosKillswitch::install_with_ops(&o, pf.clone())
            .await
            .expect_err("an off-interface state to the exit must fail the install");
        assert!(matches!(err, KillswitchError::Pf(_)), "got {err:?}");
        let ops = pf.recorded();
        let purge_pos = ops
            .iter()
            .position(|o| o == "purge_bypass_states")
            .expect("the purge ran");
        assert!(
            ops[purge_pos..].iter().any(|o| o == "flush_rules"),
            "and the anchor must be rolled back rather than announced: {ops:?}"
        );
    }

    #[tokio::test]
    async fn a_surviving_state_no_pass_rule_covers_fails_the_install() {
        let local: SocketAddr = (Ipv4Addr::new(192, 0, 2, 10), 5000).into();
        let public: SocketAddr = (Ipv4Addr::new(93, 184, 216, 34), 443).into();
        let pf = Arc::new(MockPf::reporting_survivors(vec![Survivor::Read(view(
            local,
            public,
            Proto::Tcp,
        ))]));

        let err = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect_err("a pre-existing state that survived must fail the install");
        assert!(matches!(err, KillswitchError::Pf(_)), "got {err:?}");
        let ops = pf.recorded();
        let purge_pos = ops
            .iter()
            .position(|o| o == "purge_bypass_states")
            .expect("the purge ran");
        assert!(
            ops[purge_pos..].iter().any(|o| o == "flush_rules"),
            "and the anchor must be rolled back, not left blocking with no guard: {ops:?}"
        );
    }

    #[tokio::test]
    async fn purge_failure_on_an_already_enabled_host_leaves_pf_enabled() {
        // The rollback restores the SNAPSHOT, not "off": a host that had
        // pf on before install must still have it on afterwards.
        let pf = Arc::new(MockPf {
            fail_purge: true,
            initially_enabled: true,
            ..MockPf::default()
        });
        let err = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect_err("purge failure must surface");
        assert!(matches!(err, KillswitchError::Pf(_)), "got {err:?}");
        let ops = pf.recorded();
        assert!(
            !ops.contains(&"disable".to_owned()),
            "pf was on before install: the rollback must not turn it off; \
             ops: {ops:?}"
        );
        assert!(
            pf.is_enabled().expect("mock is_enabled"),
            "pf must still be enabled after the rollback"
        );
    }

    #[tokio::test]
    async fn flush_failure_before_loading_rules_is_fatal() {
        // The pre-load flush is the only thing that clears an unknown
        // previous ruleset from the anchor. Swallowing its failure would
        // append the new rules to that stale set (a stale pass rule can
        // re-open egress) while still reporting a successful install.
        let pf = Arc::new(MockPf::failing_flush(0));
        let err = MacosKillswitch::install_with_ops(&opts_minimal(), pf.clone())
            .await
            .expect_err("a pre-load flush failure must abort the install");
        assert!(matches!(err, KillswitchError::Pf(_)), "got {err:?}");

        let ops = pf.recorded();
        assert!(
            !ops.contains(&"add_rule".to_owned()),
            "no rule may be appended to an anchor whose stale ruleset could \
             not be cleared; ops: {ops:?}"
        );
        assert!(
            !ops.contains(&"purge_bypass_states".to_owned()),
            "the install must stop before the state purge; ops: {ops:?}"
        );
    }
}
