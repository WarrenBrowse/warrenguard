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
//! states the new policy does NOT pass, after the rules are loaded, then
//! re-reads the table to confirm they are gone. A state the policy does pass
//! (loopback, an exit carrier that is not interface-scoped, a LAN range under
//! `allow_lan`, the DHCP ports under `allow_dhcp`) is left alone: killing the
//! carrier's state would drop the tunnel's own transport. An interface-scoped
//! carrier pass is NOT permission, because a state entry carries no interface
//! name and pf answers an existing state without re-evaluating the ruleset; a
//! state that cannot be attributed is killed rather than preserved. See
//! [`PfOps::purge_bypass_states`] for the decision rule and
//! [`MacosKillswitch::install`] for the failure semantics.
//!
//! ## Manual verification on a real Mac
//!
//! Automated tests cannot cover this: `/dev/pf` needs root and CI has no
//! privileges. An operator can confirm the purge by hand:
//!
//! 1. With a physical connection already open, run `sudo pfctl -s states`
//!    and note the entries that are not loopback and not the exit carrier.
//! 2. Install the killswitch, then run `sudo pfctl -s states` again.
//! 3. The entries from step 1 must be gone. The exit carrier (UDP to an exit
//!    address) and any state the policy passes, such as a LAN destination
//!    under `allow_lan`, may still be present, and the tunnel's own states
//!    must not have been dropped by the purge.
//! 4. `sudo pfctl -s rules` must show the anchor rules under
//!    [`PF_ANCHOR_PATH`].

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
#[derive(Debug, Default)]
struct PermittedFlows {
    rules: Vec<PermittedFlow>,
}

/// One destination-scoped pass rule of the anchor.
#[derive(Debug)]
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
    /// The rule is scoped to one interface (`pf_rule_specs` does this on the exit
    /// carrier when the caller named the physical egress), and a pf state entry
    /// carries no interface name, so a state cannot be shown to match it.
    iface_scoped: bool,
}

impl PermittedFlow {
    /// Whether this rule would pass a flow with this protocol and remote
    /// endpoint, from what a state entry records.
    ///
    /// An interface-scoped rule never matches here: see [`PermittedFlows`].
    fn matches(&self, proto: Proto, remote: SocketAddr) -> bool {
        !self.iface_scoped
            && (!self.v6_only || remote.is_ipv6())
            && (!self.udp_only || proto == Proto::Udp)
            && self
                .dest
                .as_ref()
                .is_none_or(|net| net.contains(remote.ip()))
            && self.dest_port.is_none_or(|port| port == remote.port())
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
    fn from_opts(opts: &KillswitchOpts) -> Self {
        let rules = pf_rule_specs(opts)
            .into_iter()
            .filter(|spec| spec.pass)
            .filter_map(|spec| {
                let (dest, dest_port) = match spec.dest {
                    Some(PfDest::Net(net)) => (Some(net), None),
                    Some(PfDest::AnyPort(port)) => (None, Some(port)),
                    None => return None,
                };
                Some(PermittedFlow {
                    udp_only: spec.udp,
                    v6_only: spec.v6,
                    dest,
                    dest_port,
                    iface_scoped: spec.iface.is_some(),
                })
            })
            .collect();
        Self { rules }
    }

    /// Whether the new policy passes a flow with this protocol and remote
    /// endpoint.
    fn permits(&self, proto: Proto, remote: SocketAddr) -> bool {
        self.rules.iter().any(|rule| rule.matches(proto, remote))
    }
}

/// Whether a pf state entry can carry traffic past the newly loaded anchor
/// block.
///
/// `true` means the state must be killed. Two classes are preserved, because the
/// anchor itself passes them:
///
/// - loopback-to-loopback: local IPC (the resolver, a same-host RPC). It cannot
///   leave the host, and the anchor's `on lo0` pass is not expressible as a state
///   predicate because a state carries no interface name.
/// - a flow whose remote endpoint matches one of the anchor's destination-scoped
///   passes, evaluated with the protocol the state records.
///
/// Everything else is a connection that would egress off-tunnel without an
/// exception: pf answers it from the state table before it re-evaluates the
/// anchor, so it is the bypass this purge exists to close.
///
/// The recorded direction is deliberately NOT an input: pf keeps an entry per
/// direction for one connection, and the endpoints are what decide whether the
/// flow leaves the host. Narrowing on the direction would preserve a surviving
/// entry of a real connection, which is the leak.
///
/// Interface-scoped clearing was rejected as the mechanism. pfctl(8) offers
/// `-i <iface>` ("restrict the operation to the given interface") and this crate
/// exposes `PfCtl::clear_interface_states(Interface)`, but the OS interface list
/// is not readable from pfctl-rs: it would need `getifaddrs` (unsafe, forbidden
/// here) or a shell-out, and `pfctl::State` exposes no interface name, so a state
/// on an interface the caller did not name would survive. Enumerating the table
/// and deciding per state needs no interface list at all.
fn state_can_bypass(
    local: SocketAddr,
    remote: SocketAddr,
    proto: Proto,
    permitted: &PermittedFlows,
) -> bool {
    if local.ip().is_loopback() && remote.ip().is_loopback() {
        return false;
    }
    !permitted.permits(proto, remote)
}

/// Whether one pf state table entry must be killed.
///
/// An entry whose addresses cannot be read cannot be shown to be permitted, so it
/// is killed: the purge fails closed, and `kill_state` works from the raw entry,
/// so an unreadable state is still removable. A protocol pfctl-rs does not name is
/// treated as `Any`, which no `udp_only` pass accepts, so such a state is killed
/// too.
fn state_must_be_killed(state: &pfctl::State, permitted: &PermittedFlows) -> bool {
    match (state.local_address(), state.remote_address()) {
        (Ok(local), Ok(remote)) => {
            let proto = state.proto().unwrap_or(Proto::Any);
            state_can_bypass(local, remote, proto, permitted)
        }
        _ => true,
    }
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
    /// Register the Warren anchor [`PF_ANCHOR_PATH`].
    fn add_anchor(&self) -> Result<(), KillswitchError>;
    /// Drop every filter rule in the Warren anchor.
    fn flush_rules(&self) -> Result<(), KillswitchError>;
    /// Append one filter rule to the Warren anchor.
    fn add_rule(&self, rule: &FilterRule) -> Result<(), KillswitchError>;
    /// Kill every pf connection state that could carry traffic past the
    /// newly loaded anchor rules, verify the table is clean, and return the
    /// number of states killed.
    ///
    /// Must run AFTER [`Self::add_rule`]: pf consults the state table before
    /// it re-evaluates the ruleset, so a connection opened before the
    /// install (by macOS's default `pass all`, for example) keeps flowing
    /// off-tunnel until its state entry is gone. See
    /// [`state_can_bypass`] for the per-state decision.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Pf`] when the table cannot be read, a state
    /// cannot be killed, or bypass states are still present when the table
    /// is re-read. The last case is a failure and NOT a warning: an install
    /// that reports success while a bypass state survives claims
    /// protection it has not confirmed.
    fn purge_bypass_states(&self, permitted: &PermittedFlows) -> Result<u32, KillswitchError>;
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

    fn purge_bypass_states(&self, permitted: &PermittedFlows) -> Result<u32, KillswitchError> {
        // `PfCtl::clear_states(PF_ANCHOR_PATH, ..)` is NOT usable here: it
        // kills only states whose `anchor` field equals our anchor's rule
        // number, and the anchor was registered moments ago, so it kills
        // nothing and would leave every pre-install state in place. The
        // table has to be enumerated and filtered per state instead.
        let mut pf = Self::pf()?;
        let states = pf
            .get_states()
            .map_err(|e| KillswitchError::Pf(format!("get states: {e}")))?;

        let mut killed = 0u32;
        for state in &states {
            if !state_must_be_killed(state, permitted) {
                continue;
            }
            // No addresses in the error: this crate's no-log rule forbids putting
            // a peer address or source IP in a message, and the count of killed
            // states is what an operator acts on.
            pf.kill_state(state)
                .map_err(|e| KillswitchError::Pf(format!("kill a bypass connection state: {e}")))?;
            killed = killed.saturating_add(1);
        }

        // Verification is the point of this function: re-read the table and
        // refuse the install if any bypass state is still there. pf exposes
        // no atomic "kill and confirm", and a partially applied kill must
        // never be reported as protection. Only the count is reported, for
        // the same no-log reason as above.
        let survivors = pf
            .get_states()
            .map_err(|e| KillswitchError::Pf(format!("re-read states after purge: {e}")))?
            .iter()
            .filter(|state| state_must_be_killed(state, permitted))
            .count();

        if survivors > 0 {
            return Err(KillswitchError::Pf(format!(
                "{survivors} bypass state(s) survived the purge after the \
                 killswitch rules were loaded. Off-tunnel traffic would keep \
                 flowing through them past the block."
            )));
        }

        Ok(killed)
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
        let permitted = PermittedFlows::from_opts(opts);

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
        let purge = tokio::task::spawn_blocking(move || states_ops.purge_bypass_states(&permitted))
            .await
            .map_err(|e| KillswitchError::Pf(format!("spawn_blocking states: {e}")));
        let killed_states = match purge.and_then(|inner| inner) {
            Ok(killed) => killed,
            Err(e) => {
                // Best-effort rollback before surfacing the error: the rules
                // are already loaded, so dropping both the anchor rules and
                // the enable state we may have turned on is what keeps the
                // host in its pre-install condition. Mirrors `uninstall`.
                let rollback_ops = ops.clone();
                if let Err(fe) = tokio::task::spawn_blocking(move || rollback_ops.flush_rules())
                    .await
                    .map_err(|je| KillswitchError::Pf(format!("spawn_blocking flush: {je}")))
                    .and_then(|inner| inner)
                {
                    tracing::error!(
                        error = %fe,
                        "pf rollback flush failed after a state purge that \
                         could not be verified - the anchor may keep blocking. \
                         Run `sudo pfctl -a {PF_ANCHOR_PATH} -F rules` manually \
                         to recover internet"
                    );
                }
                let enabled_ops = ops.clone();
                if !pf_was_enabled
                    && let Err(de) = tokio::task::spawn_blocking(move || enabled_ops.disable())
                        .await
                        .map_err(|je| KillswitchError::Pf(format!("spawn_blocking disable: {je}")))
                        .and_then(|inner| inner)
                {
                    tracing::error!(
                        error = %de,
                        "could not restore pf's original disabled state after \
                         the failed install - run `sudo pfctl -d` manually if \
                         this host had pf off before Warren ran"
                    );
                }
                return Err(e);
            }
        };
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
        /// When `true`, `purge_bypass_states` fails. This models the
        /// production verification step reporting surviving bypass
        /// states, which must be fatal to the install.
        fail_purge: bool,
        /// What `is_enabled` reports - the host's pf state before install.
        initially_enabled: bool,
        /// What `is_enabled` reports after `enable` / `disable` ran, so
        /// the restore path is observable the way it is on a real host.
        currently_enabled: std::sync::atomic::AtomicBool,
        /// Whether the permitted set handed to `purge_bypass_states` passes a
        /// LAN flow. Records the wiring from `KillswitchOpts` to the purge,
        /// which no predicate unit test can observe.
        purge_permits_lan: std::sync::atomic::AtomicBool,
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

        /// A mock whose `purge_bypass_states` fails, standing in for a
        /// real purge that reports bypass states still in the table.
        fn failing_purge() -> Self {
            Self {
                fail_purge: true,
                ..Self::default()
            }
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
        fn purge_bypass_states(&self, _permitted: &PermittedFlows) -> Result<u32, KillswitchError> {
            let lan: SocketAddr = (Ipv4Addr::new(192, 168, 1, 20), 22).into();
            self.purge_permits_lan
                .store(_permitted.permits(Proto::Tcp, lan), Ordering::SeqCst);
            self.record("purge_bypass_states");
            if self.fail_purge {
                return Err(KillswitchError::Pf(
                    "mock purge: bypass states survived".into(),
                ));
            }
            Ok(3)
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

    #[test]
    fn only_destination_scoped_passes_form_the_permitted_set() {
        // The loopback and tunnel passes are interface-scoped, and a state entry
        // carries no interface name, so they cannot be part of the predicate.
        let mut o = opts_minimal();
        o.allow_lan = true;
        o.allow_dhcp = true;
        let flows = PermittedFlows::from_opts(&o);
        // One exit host, three v4 LAN ranges, two v6 LAN ranges, two DHCP ports.
        assert_eq!(flows.rules.len(), 1 + 3 + 2 + 2);
        assert!(
            flows
                .rules
                .iter()
                .all(|r| r.dest.is_some() || r.dest_port.is_some()),
            "every permitted flow must be destination-scoped"
        );
        assert!(
            flows.rules.iter().all(|r| !r.iface_scoped),
            "opts_minimal names no physical interface, so no pass is interface-scoped"
        );

        let mut scoped = opts_minimal();
        scoped.phys_iface = Some("en0".into());
        let scoped = PermittedFlows::from_opts(&scoped);
        assert!(
            scoped.rules.iter().all(|r| r.iface_scoped),
            "naming the physical interface scopes the carrier pass, and the purge \
             must see that: {:#?}",
            scoped.rules
        );
    }

    #[test]
    fn loopback_only_states_are_preserved() {
        let flows = PermittedFlows::from_opts(&opts_minimal());
        let lo_a: SocketAddr = (Ipv4Addr::LOCALHOST, 1234).into();
        let lo_b: SocketAddr = (Ipv4Addr::LOCALHOST, 8080).into();
        let lo_v6: SocketAddr = (Ipv6Addr::LOCALHOST, 53).into();
        for (local, remote) in [(lo_a, lo_b), (lo_a, lo_v6), (lo_v6, lo_b)] {
            assert!(
                !state_can_bypass(local, remote, Proto::Tcp, &flows),
                "local IPC cannot leave the host and must be preserved: {local} {remote}"
            );
        }
    }

    #[test]
    fn the_exit_carrier_state_is_preserved() {
        let flows = PermittedFlows::from_opts(&opts_minimal());
        let local: SocketAddr = (Ipv4Addr::new(192, 0, 2, 10), 5000).into();
        let carrier: SocketAddr = (EXIT_V4, 443).into();
        assert!(
            !state_can_bypass(local, carrier, Proto::Udp, &flows),
            "the carrier is a flow the anchor passes: killing its state would drop \
             the tunnel's own transport"
        );
        assert!(
            state_can_bypass(local, carrier, Proto::Tcp, &flows),
            "the carrier exception is UDP-scoped, so a TCP state to the exit address \
             is not something the anchor passes"
        );
    }

    #[test]
    fn an_interface_scoped_carrier_pass_cannot_be_attributed_to_a_state() {
        // pf honours an existing state without re-evaluating the ruleset, and a
        // state entry carries no interface name. With the carrier pass scoped to
        // the daemon's physical interface, a state to the exit address might be on
        // another interface, which the scoped rule would refuse: refusing to
        // preserve it is the fail-closed direction.
        let local: SocketAddr = (Ipv4Addr::new(192, 0, 2, 10), 5000).into();
        let carrier: SocketAddr = (EXIT_V4, 443).into();
        let mut o = opts_minimal();
        o.phys_iface = Some("en0".into());
        assert!(
            state_can_bypass(local, carrier, Proto::Udp, &PermittedFlows::from_opts(&o)),
            "an interface-scoped pass must not preserve a state it cannot be shown \
             to match"
        );
    }

    #[test]
    fn an_ordinary_public_flow_is_a_bypass_candidate() {
        let flows = PermittedFlows::from_opts(&opts_minimal());
        let local: SocketAddr = (Ipv4Addr::new(192, 0, 2, 10), 5000).into();
        let remote: SocketAddr = (Ipv4Addr::new(93, 184, 216, 34), 443).into();
        assert!(
            state_can_bypass(local, remote, Proto::Tcp, &flows),
            "a pre-existing connection with no exception in the policy is exactly \
             what the purge must kill"
        );
    }

    #[test]
    fn lan_states_are_preserved_only_when_the_lan_is_allowed() {
        let local: SocketAddr = (Ipv4Addr::new(192, 0, 2, 10), 5000).into();
        let lan: SocketAddr = (Ipv4Addr::new(192, 168, 1, 20), 22).into();
        assert!(
            state_can_bypass(
                local,
                lan,
                Proto::Tcp,
                &PermittedFlows::from_opts(&opts_minimal())
            ),
            "with the LAN blocked, a LAN connection is a bypass candidate"
        );
        let mut o = opts_minimal();
        o.allow_lan = true;
        assert!(
            !state_can_bypass(local, lan, Proto::Tcp, &PermittedFlows::from_opts(&o)),
            "with the LAN allowed the anchor passes it, so its state must survive"
        );
    }

    #[test]
    fn dhcp_states_are_preserved_only_when_dhcp_is_allowed_and_on_the_right_port() {
        let local: SocketAddr = (Ipv4Addr::new(0, 0, 0, 0), 68).into();
        let server: SocketAddr = (Ipv4Addr::new(255, 255, 255, 255), 67).into();
        assert!(
            state_can_bypass(
                local,
                server,
                Proto::Udp,
                &PermittedFlows::from_opts(&opts_minimal())
            ),
            "DHCP is opt-in"
        );
        let mut o = opts_minimal();
        o.allow_dhcp = true;
        let flows = PermittedFlows::from_opts(&o);
        assert!(
            !state_can_bypass(local, server, Proto::Udp, &flows),
            "an allowed DHCP exchange must survive the purge"
        );
        let dns: SocketAddr = (Ipv4Addr::new(1, 1, 1, 1), 53).into();
        assert!(
            state_can_bypass(local, dns, Proto::Udp, &flows),
            "only ports 67 and 68 are passed, so a DNS state is still a bypass"
        );
    }

    #[tokio::test]
    async fn the_purge_receives_the_flows_the_policy_allows() {
        // The wiring, not just the predicate: the permitted set handed to the
        // purge must be the one the anchor installs. With the LAN allowed, a LAN
        // connection is a flow the policy passes and its state must be preserved;
        // without it, the same connection is a bypass candidate. Getting this
        // wrong is what made the purge kill the exit carrier and refuse an
        // install whose carrier had reconnected.
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
