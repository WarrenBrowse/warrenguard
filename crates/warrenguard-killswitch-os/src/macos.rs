//! macOS killswitch - type-safe `pf` (Packet Filter) via `pfctl-rs`.
//!
//! Rules are loaded into a pf sub-anchor [`PF_ANCHOR_PATH`] =
//! `com.apple/250.warrenguard_killswitch_os`.

use std::net::IpAddr;

use pfctl::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use pfctl::{AnchorKind, FilterRule, FilterRuleAction, FilterRuleBuilder, PfCtl};

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
    /// Clear connection states matching the Warren anchor.
    fn clear_states(&self) -> Result<(), KillswitchError>;
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

    fn clear_states(&self) -> Result<(), KillswitchError> {
        Self::pf()?
            .clear_states(PF_ANCHOR_PATH, AnchorKind::Filter)
            .map(|_| ())
            .map_err(|e| KillswitchError::Pf(format!("clear states: {e}")))
    }
}

fn apply_rules(ops: &dyn PfOps, rules: &[FilterRule]) -> Result<(), KillswitchError> {
    ops.enable()?;
    ops.add_anchor()?;
    if let Err(e) = ops.flush_rules() {
        tracing::debug!(error = %e, "flush existing rules (may be empty)");
    }
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
    /// Loads the killswitch rules via pfctl-rs. Idempotent.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::InvalidInput`] or [`KillswitchError::Pf`].
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
        // Flush pre-existing states so connections opened before the
        // killswitch cannot keep leaking through established state
        // entries.
        let states_ops = ops.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || states_ops.clear_states())
            .await
            .map_err(|e| KillswitchError::Pf(format!("spawn_blocking states: {e}")))
            .and_then(|inner| inner)
        {
            tracing::warn!(error = %e, "failed to flush pf states after killswitch install");
        }
        tracing::info!(
            tun = %opts.tun_name,
            exit_count = opts.exit_addrs.len(),
            allow_lan = opts.allow_lan,
            allow_dhcp = opts.allow_dhcp,
            pf_was_enabled,
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
        /// When `Some(n)`, the n-th `add_rule` call (0-based) fails.
        fail_on_add_rule_index: Option<usize>,
        /// What `is_enabled` reports - the host's pf state before install.
        initially_enabled: bool,
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

        fn recorded(&self) -> Vec<String> {
            self.ops.lock().expect("mock mutex").clone()
        }

        fn record(&self, op: &str) {
            self.ops.lock().expect("mock mutex").push(op.to_owned());
        }
    }

    impl PfOps for MockPf {
        fn enable(&self) -> Result<(), KillswitchError> {
            self.record("enable");
            Ok(())
        }
        fn is_enabled(&self) -> Result<bool, KillswitchError> {
            self.record("is_enabled");
            Ok(self.initially_enabled)
        }
        fn disable(&self) -> Result<(), KillswitchError> {
            self.record("disable");
            Ok(())
        }
        fn add_anchor(&self) -> Result<(), KillswitchError> {
            self.record("add_anchor");
            Ok(())
        }
        fn flush_rules(&self) -> Result<(), KillswitchError> {
            self.record("flush_rules");
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
        fn clear_states(&self) -> Result<(), KillswitchError> {
            self.record("clear_states");
            Ok(())
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
            !ops.contains(&"clear_states".to_owned()),
            "no state flush after a failed install; ops: {ops:?}"
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
}
