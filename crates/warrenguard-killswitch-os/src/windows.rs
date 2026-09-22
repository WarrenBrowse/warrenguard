//! Windows killswitch - the Windows Firewall (WFP's user-space surface).
//!
//! ## Why the previous policy leaked
//!
//! The firewall's rule precedence, documented by Microsoft ("Windows Firewall
//! rules"): an explicitly defined allow rule takes precedence over the DEFAULT
//! BLOCK SETTING; an explicit block rule takes precedence over any conflicting
//! allow rule; and more specific rules win over less specific ones, EXCEPT when
//! an explicit block rule is involved. Outbound rules follow the same order, and
//! Windows Firewall offers no administrator-controlled weighting.
//!
//! Setting `DefaultOutboundAction = Block` only changes the default, so it stops
//! traffic that matches no rule. Any pre-existing explicit Allow rule (a user's
//! "allow this app", a vendor installer's rule, a Group Policy exception) still
//! matches its traffic first and lets it egress the physical interface. A policy
//! built only from the profile default plus our own exceptions therefore
//! announces a killswitch while other applications keep their egress.
//!
//! ## The policy installed here
//!
//! 1. Turn the firewall on for all three profiles (see "Profile enable state").
//! 2. Set `DefaultOutboundAction = Block` on all three profiles: the fail-closed
//!    default for traffic that matches no rule at all, and the state a partial
//!    install is left in.
//! 3. Create ONE explicit outbound Block rule matching everything. Being an
//!    explicit block rule, it overrides every conflicting allow rule, including
//!    the pre-existing ones, whatever their origin.
//! 4. Create our exceptions as Allow rules carrying `-OverrideBlockRules True`:
//!    the documented outbound "allow bypass rule", "matching traffic is
//!    permitted through this rule even if other matching rules would block the
//!    traffic". Without that flag our own exceptions would lose to step 3's
//!    block rule, which is exactly why the flag is load bearing and why the
//!    install verifies it was applied.
//!
//! The exceptions are: loopback, the tunnel interface, UDP to each exit scoped
//! to the daemon's own executable (`-Program`, the Port Fail / TunnelCrack
//! ServerIP fix), and the optional LAN and DHCP ranges.
//!
//! ## Profile enable state
//!
//! A firewall that is switched off filters nothing, so `DefaultOutboundAction`
//! and every rule above are irrelevant while it is off. The install therefore
//! reads the profile state from the ACTIVE store (the resultant set, Group
//! Policy included), turns the firewall on, and then READS THE EFFECTIVE STATE
//! BACK: a profile that a policy still reports as disabled fails the install. A
//! Group Policy that forces the firewall off cannot be overridden locally, so
//! the install refuses instead of announcing a protection that is not active.
//!
//! ## The install is only done once it has been read back
//!
//! Every step above is verified against the active store before a guard is
//! constructed (see [`FirewallRunner::verify`]): the three profiles enabled,
//! their effective default outbound action `Block`, and every expected rule
//! present, outbound, enabled, with the expected action and, for an exception,
//! the override flag. If anything fails, the captured profile settings are
//! restored, the rules are removed, and the error is returned: a failed install
//! never reports success and never leaves the host half-configured under our
//! name.
//!
//! ## Why not the WFP API with explicit weights
//!
//! A native WFP implementation (`FwpmFilterAdd` with our own sub-layer and
//! weights) would express the policy without touching the profile defaults, and
//! is the eventual hardening. It needs FFI (this crate is
//! `#![forbid(unsafe_code)]`) and a Windows host to develop against; the
//! documented rule-level mechanism above reaches the same verdict for the cases
//! that matter here. The lifecycle is written against
//! [`FirewallRunner`] so that swap stays local.
//!
//! ## What the tests here cover, and what they cannot
//!
//! The policy, its read-back checks and its rollback are driven against a model
//! of the precedence rules above, on every host, so a regression in what the
//! host ends up with (or in the decision to report the install as done) fails CI
//! without Windows. The `cfg(target_os = "windows")` code around it is
//! type-checked with `cargo check -p warrenguard-killswitch-os --target
//! x86_64-pc-windows-msvc`.
//!
//! That still does not exercise the host: PowerShell is absent from the CI
//! hosts, so the generated commands, the query parsers and the
//! `-OverrideBlockRules` semantics are not run against a real firewall here. Run
//! `scripts/windows/killswitch-policy-smoke.ps1` on a throwaway Windows host to
//! confirm the two documented behaviours the policy rests on (a pre-existing
//! Allow rule survives the default block and dies to the explicit block rule; an
//! `-OverrideBlockRules` Allow survives the block rule), and re-run it after any
//! change to the rule set below.
//!
//! ## Privileges
//!
//! `New-NetFirewallRule`, `Set-NetFirewallProfile` and `Remove-NetFirewallRule`
//! require an elevated process (Administrator).

// On a host that is neither Windows nor running the test suite, the policy
// builders, the read-back verification and the lifecycle below are reachable
// only from the tests. They are deliberately host-independent so the policy and
// its rollback are exercised everywhere, which leaves the plain library build
// with items no production caller on that host can name.
#![cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]

use std::fmt::Write as _;
use std::net::IpAddr;
#[cfg(any(target_os = "windows", test))]
use std::time::Duration;

use crate::{KillswitchError, KillswitchOpts, validate_tun_name};

/// Common display-name prefix on every rule we install. Used by the uninstall
/// step to find and delete only our rules, and by the verification step to read
/// back only the rules we own.
pub const RULE_PREFIX: &str = "warren-killswitch-";

/// Windows firewall profiles whose settings we touch. Captured at install time,
/// restored on uninstall. All three are required to be enabled: a network
/// change switches the active profile, and a profile left disabled would be an
/// unfiltered path out of the host.
pub const FIREWALL_PROFILES: [&str; 3] = ["Domain", "Private", "Public"];

/// LAN ranges offered by `allow_lan`.
const LAN_RANGES_V4: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const LAN_RANGES_V6: &[&str] = &["fc00::/7", "fe80::/10"];

// ── Policy types ─────────────────────────────────────────────────────

/// The action of one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Allow,
    Block,
}

impl RuleAction {
    /// The exact token `-Action` accepts.
    fn as_token(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Block => "Block",
        }
    }
}

/// The destination condition of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Remote {
    /// A single host address (an exit).
    Host(IpAddr),
    /// A network in CIDR form (loopback, a LAN range).
    Network(&'static str),
}

impl Remote {
    /// The exact token `-RemoteAddress` accepts.
    fn as_token(&self) -> String {
        match self {
            Self::Host(addr) => addr.to_string(),
            Self::Network(cidr) => (*cidr).to_owned(),
        }
    }
}

/// One rule the killswitch installs, as data.
///
/// Typed rather than a PowerShell string because the security property is a
/// policy property (a block rule that outranks pre-existing allow rules, plus
/// exceptions that outrank the block rule), and a test that only greps a
/// generated command line cannot observe which policy the host ends up with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleSpec {
    /// Suffix after [`RULE_PREFIX`]; also the rule's identity on read-back.
    id: String,
    action: RuleAction,
    /// Permit the traffic even where another rule blocks it. Mandatory on every
    /// exception: the block-all rule matches the same traffic.
    override_block_rules: bool,
    iface: Option<String>,
    udp: bool,
    remote: Option<Remote>,
    remote_port: Option<u16>,
    program: Option<String>,
}

impl RuleSpec {
    /// The rule's display name, which is what the read-back looks for.
    fn display_name(&self) -> String {
        format!("{RULE_PREFIX}{}", self.id)
    }
}

/// A boolean-valued firewall profile setting. The cmdlets take and return these
/// three tokens, not a PowerShell boolean: `-Enabled $true` is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GpoBool {
    True,
    False,
    NotConfigured,
}

impl GpoBool {
    fn as_token(self) -> &'static str {
        match self {
            Self::True => "True",
            Self::False => "False",
            Self::NotConfigured => "NotConfigured",
        }
    }

    /// Parses a `Format-List` rendering, tolerating the raw and the friendly
    /// form because the rendering depends on the module's format data.
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "enabled" | "yes" => Some(Self::True),
            "false" | "0" | "disabled" | "no" => Some(Self::False),
            "notconfigured" | "2" => Some(Self::NotConfigured),
            _ => None,
        }
    }
}

/// A profile's `DefaultOutboundAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundAction {
    Allow,
    Block,
    NotConfigured,
}

impl OutboundAction {
    fn as_token(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::Block => "Block",
            Self::NotConfigured => "NotConfigured",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" | "0" => Some(Self::Allow),
            "block" | "1" => Some(Self::Block),
            "notconfigured" | "2" => Some(Self::NotConfigured),
            _ => None,
        }
    }
}

/// The profile settings the install overwrites and must put back verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileSnapshot {
    name: String,
    /// Local (PersistentStore) enable state. Restored on uninstall, which is
    /// what returns the effective state too when a policy is not forcing it.
    local_enabled: GpoBool,
    /// Local (PersistentStore) default outbound action.
    local_default_outbound_action: OutboundAction,
}

/// Everything the uninstall needs to leave the host as it found it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FirewallSnapshot {
    profiles: Vec<ProfileSnapshot>,
}

/// One mutation of the firewall configuration, in a form a model can apply and
/// PowerShell can render.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FirewallOp {
    /// Turn the firewall on for every profile we depend on.
    EnableProfiles,
    /// Leave the profiles blocking by default.
    SetDefaultOutboundActionBlock,
    /// Create one of our rules.
    CreateRule(RuleSpec),
    /// Delete every rule carrying [`RULE_PREFIX`].
    DeleteOurRules,
    /// Put one captured local profile setting back.
    RestoreProfile(ProfileSnapshot),
}

/// The firewall operations the install and teardown perform.
///
/// The lifecycle is written against this seam so the whole policy can be driven
/// against a model of the documented rule precedence, and so a future native
/// WFP backend can replace the PowerShell one without touching the lifecycle.
#[allow(async_fn_in_trait)]
trait FirewallRunner: Send + Sync + std::fmt::Debug {
    /// Read the local profile settings the install is about to overwrite.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] when the query fails or does not report all
    /// three profiles.
    async fn snapshot(&self) -> Result<FirewallSnapshot, KillswitchError>;

    /// Apply one mutation.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] when the command fails.
    async fn apply(&self, op: &FirewallOp) -> Result<(), KillswitchError>;

    /// Read the ACTIVE store back and fail unless every protection the install
    /// claims is actually in effect.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] when a profile is not effectively enabled,
    /// its effective default outbound action is not `Block`, or an expected
    /// rule is missing or does not carry the expected action and override flag.
    async fn verify(&self, rules: &[RuleSpec]) -> Result<(), KillswitchError>;
}

// ── Policy construction ──────────────────────────────────────────────

/// The rules of the installed policy, block rule first.
///
/// Order is load bearing twice over: the block rule is created before any
/// exception, so the interval in which an exception exists without the block is
/// empty, and the block rule is what neutralises pre-existing allow rules.
fn build_rules(opts: &KillswitchOpts, daemon_exe_path: &str) -> Vec<RuleSpec> {
    let allow = |id: String,
                 iface: Option<String>,
                 udp: bool,
                 remote: Option<Remote>,
                 remote_port: Option<u16>,
                 program: Option<String>| RuleSpec {
        id,
        action: RuleAction::Allow,
        // Every exception must outrank the block rule, so this is never
        // optional for an Allow rule here.
        override_block_rules: true,
        iface,
        udp,
        remote,
        remote_port,
        program,
    };

    let mut rules = Vec::with_capacity(8 + opts.exit_addrs.len());

    // The rule the policy rests on: an explicit block, which Windows Firewall
    // documents as taking precedence over any conflicting allow rule.
    rules.push(RuleSpec {
        id: "block-outbound".into(),
        action: RuleAction::Block,
        override_block_rules: false,
        iface: None,
        udp: false,
        remote: None,
        remote_port: None,
        program: None,
    });

    // Loopback explicitly, rather than relying on an implicit exemption: other
    // platform backends in this crate allow it, and a same-host service that
    // stopped working would look like a killswitch bug.
    rules.push(allow(
        "allow-loopback-v4".into(),
        None,
        false,
        Some(Remote::Network("127.0.0.0/8")),
        None,
        None,
    ));
    rules.push(allow(
        "allow-loopback-v6".into(),
        None,
        false,
        Some(Remote::Network("::1/128")),
        None,
        None,
    ));

    // The tunnel: every captured packet egresses here.
    rules.push(allow(
        "allow-tun".into(),
        Some(opts.tun_name.clone()),
        false,
        None,
        None,
        None,
    ));

    // The exit carrier. `-Program` keeps the exception on the daemon's own
    // socket: a destination-only allow would grant the off-tunnel path to any
    // process that dials the exit address (Port Fail / TunnelCrack ServerIP),
    // which matters because a locally injected route can make the exit resolve
    // on-link, outside the split default.
    for addr in &opts.exit_addrs {
        let label = if addr.is_ipv6() {
            "exit-udp-v6"
        } else {
            "exit-udp-v4"
        };
        rules.push(allow(
            format!("{label}-{addr}"),
            None,
            true,
            Some(Remote::Host(*addr)),
            None,
            Some(daemon_exe_path.to_owned()),
        ));
    }

    if opts.allow_lan {
        for cidr in LAN_RANGES_V4 {
            rules.push(allow(
                format!("lan-{cidr}"),
                None,
                false,
                Some(Remote::Network(cidr)),
                None,
                None,
            ));
        }
        for cidr in LAN_RANGES_V6 {
            rules.push(allow(
                format!("lan-{cidr}"),
                None,
                false,
                Some(Remote::Network(cidr)),
                None,
                None,
            ));
        }
    }

    if opts.allow_dhcp {
        // Both directions of the exchange: the client sends from 68 and the
        // implementation may also accept on 67.
        for port in [67u16, 68] {
            rules.push(allow(
                format!("dhcp-{port}"),
                None,
                true,
                None,
                Some(port),
                None,
            ));
        }
    }

    rules
}

/// The install sequence for `rules`.
fn install_ops(rules: &[RuleSpec]) -> Vec<FirewallOp> {
    let mut ops = Vec::with_capacity(rules.len() + 2);
    // Enable first: with the firewall off, nothing below filters anything.
    ops.push(FirewallOp::EnableProfiles);
    // The default block, as the fail-closed state a partial install is left in.
    ops.push(FirewallOp::SetDefaultOutboundActionBlock);
    ops.extend(rules.iter().cloned().map(FirewallOp::CreateRule));
    ops
}

/// The teardown sequence: remove our rules, then put the captured settings back.
fn uninstall_ops(snapshot: &FirewallSnapshot) -> Vec<FirewallOp> {
    let mut ops = Vec::with_capacity(snapshot.profiles.len() + 1);
    ops.push(FirewallOp::DeleteOurRules);
    ops.extend(
        snapshot
            .profiles
            .iter()
            .cloned()
            .map(FirewallOp::RestoreProfile),
    );
    ops
}

// ── PowerShell rendering ─────────────────────────────────────────────

/// Renders one operation as the argv after `powershell.exe`.
fn render_op(op: &FirewallOp) -> Vec<String> {
    let command = match op {
        FirewallOp::EnableProfiles => format!(
            "Set-NetFirewallProfile -Profile {} -Enabled True",
            FIREWALL_PROFILES.join(",")
        ),
        FirewallOp::SetDefaultOutboundActionBlock => format!(
            "Set-NetFirewallProfile -Profile {} -DefaultOutboundAction Block",
            FIREWALL_PROFILES.join(",")
        ),
        FirewallOp::CreateRule(rule) => render_create_rule(rule),
        FirewallOp::DeleteOurRules => {
            format!("Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' | Remove-NetFirewallRule")
        }
        FirewallOp::RestoreProfile(profile) => format!(
            "Set-NetFirewallProfile -Profile {} -Enabled {} -DefaultOutboundAction {}",
            profile.name,
            profile.local_enabled.as_token(),
            profile.local_default_outbound_action.as_token()
        ),
    };
    vec!["-NoProfile".into(), "-Command".into(), command]
}

fn render_create_rule(rule: &RuleSpec) -> String {
    let mut command = format!(
        "New-NetFirewallRule -DisplayName '{}' -Direction Outbound -Action {}",
        rule.display_name(),
        rule.action.as_token()
    );
    if rule.override_block_rules {
        command.push_str(" -OverrideBlockRules True");
    }
    if let Some(iface) = &rule.iface {
        let _ = write!(
            command,
            " -InterfaceAlias '{}'",
            escape_powershell_single_quoted(iface)
        );
    }
    if rule.udp {
        command.push_str(" -Protocol UDP");
    }
    if let Some(remote) = &rule.remote {
        let _ = write!(command, " -RemoteAddress {}", remote.as_token());
    }
    if let Some(port) = rule.remote_port {
        let _ = write!(command, " -RemotePort {port}");
    }
    if let Some(program) = &rule.program {
        let _ = write!(
            command,
            " -Program '{}'",
            escape_powershell_single_quoted(program)
        );
    }
    command
}

/// Doubles every embedded `'` so a value is safe to interpolate into a
/// PowerShell single-quoted string literal (the convention PowerShell itself
/// uses to escape a literal quote inside `'...'`). A Windows install path
/// essentially never contains one, but this keeps a pathological install
/// directory from breaking the generated command instead of merely narrowing
/// the WFP app-id exception.
fn escape_powershell_single_quoted(s: &str) -> String {
    s.replace('\'', "''")
}

/// Build the PowerShell argv list for the install sequence. Pure: no shell-out,
/// no privileges, directly testable.
///
/// `daemon_exe_path` is the running daemon's own executable, used to scope the
/// exit-UDP exception to this process only.
#[must_use]
pub fn build_install_commands(opts: &KillswitchOpts, daemon_exe_path: &str) -> Vec<Vec<String>> {
    install_ops(&build_rules(opts, daemon_exe_path))
        .iter()
        .map(render_op)
        .collect()
}

/// Pretty-printed policy description for logging / diagnostics.
#[must_use]
pub fn format_install_log(opts: &KillswitchOpts) -> String {
    let mut s = String::with_capacity(256);
    let _ = writeln!(s, "Warren killswitch (Windows Firewall)");
    let _ = writeln!(s, "  rule prefix     = {RULE_PREFIX}");
    let _ = writeln!(s, "  tunnel iface    = {}", opts.tun_name);
    let _ = writeln!(s, "  exit addresses  = {} entries", opts.exit_addrs.len());
    let _ = writeln!(s, "  allow_lan       = {}", opts.allow_lan);
    let _ = writeln!(s, "  allow_dhcp      = {}", opts.allow_dhcp);
    s
}

// ── Read-back and verification ───────────────────────────────────────

/// Query the profile settings in the store we are about to write.
#[cfg(target_os = "windows")]
const QUERY_PROFILES_LOCAL: &str = "Get-NetFirewallProfile -PolicyStore PersistentStore \
     -Profile Domain,Private,Public | Format-List Name,Enabled,DefaultOutboundAction";

/// Query the EFFECTIVE profile settings: the resultant set, Group Policy
/// included. Reading the persistent store instead would report what we wrote
/// rather than what is filtering.
#[cfg(target_os = "windows")]
const QUERY_PROFILES_EFFECTIVE: &str = "Get-NetFirewallProfile -PolicyStore ActiveStore \
     -Profile Domain,Private,Public | Format-List Name,Enabled,DefaultOutboundAction";

/// Query our own rules with their security filter, in a line-oriented form so
/// one round trip answers for every rule.
#[cfg(target_os = "windows")]
fn query_our_rules_command() -> String {
    format!(
        "Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName '{RULE_PREFIX}*' | \
         ForEach-Object {{ $f = $_ | Get-NetFirewallSecurityFilter; \
         'RULE|' + $_.DisplayName + '|' + $_.Direction + '|' + $_.Action + '|' + \
         $_.Enabled + '|' + $f.OverrideBlockRules }}"
    )
}

/// One parsed `Format-List` profile block. Every field is optional because a
/// partially reported profile must be a failure, not a default.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileSetting {
    name: String,
    enabled: Option<GpoBool>,
    default_outbound_action: Option<OutboundAction>,
}

/// Parses `Name` / `Enabled` / `DefaultOutboundAction` blocks from
/// `Get-NetFirewallProfile | Format-List`.
///
/// Pure, so the parser is tested against recorded-shape fixtures without
/// invoking PowerShell. Every field of a block is optional here: a missing one
/// is reported as absent and the caller refuses, rather than substituting a
/// value that would make an unverified host look protected.
fn parse_profile_settings(out: &str) -> Vec<ProfileSetting> {
    let mut settings: Vec<ProfileSetting> = Vec::new();
    for line in out.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let label = label.trim();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match label {
            "Name" => settings.push(ProfileSetting {
                name: value.to_owned(),
                enabled: None,
                default_outbound_action: None,
            }),
            "Enabled" => {
                if let Some(current) = settings.last_mut() {
                    current.enabled = GpoBool::parse(value);
                }
            }
            "DefaultOutboundAction" => {
                if let Some(current) = settings.last_mut() {
                    current.default_outbound_action = OutboundAction::parse(value);
                }
            }
            _ => {}
        }
    }
    settings
}

/// One parsed `RULE|...` line from [`query_our_rules_command`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleRow {
    display_name: String,
    direction: String,
    action: String,
    enabled: Option<GpoBool>,
    override_block_rules: bool,
}

/// Parses the line-oriented rule read-back. Unparseable lines are skipped: a
/// rule we cannot read is a rule we cannot confirm, and the verification below
/// fails on a missing rule anyway.
fn parse_rule_rows(out: &str) -> Vec<RuleRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("RULE|") else {
            continue;
        };
        let fields: Vec<&str> = rest.split('|').collect();
        if fields.len() != 5 {
            continue;
        }
        rows.push(RuleRow {
            display_name: fields[0].to_owned(),
            direction: fields[1].to_owned(),
            action: fields[2].to_owned(),
            enabled: GpoBool::parse(fields[3]),
            override_block_rules: GpoBool::parse(fields[4]) == Some(GpoBool::True),
        });
    }
    rows
}

/// Evaluates the read-back against the policy we intended to install.
///
/// Pure and total: it either confirms every protection or names the one that is
/// missing. This is the function that decides whether the install may report
/// success, so it is exercised directly with fixtures.
fn check_effective_state(
    profiles_out: &str,
    rules_out: &str,
    expected: &[RuleSpec],
) -> Result<(), KillswitchError> {
    let profiles = parse_profile_settings(profiles_out);
    for name in FIREWALL_PROFILES {
        let Some(setting) = profiles.iter().find(|p| p.name == name) else {
            return Err(KillswitchError::Windows(format!(
                "the active firewall policy does not report the {name} profile, \
                 so its protection cannot be confirmed"
            )));
        };
        if setting.enabled != Some(GpoBool::True) {
            return Err(KillswitchError::Windows(format!(
                "the {name} firewall profile is not enabled in the active policy \
                 (reported {:?}); the killswitch would filter nothing. A Group \
                 Policy that forces the firewall off cannot be overridden locally",
                setting.enabled.map(GpoBool::as_token)
            )));
        }
        if setting.default_outbound_action != Some(OutboundAction::Block) {
            return Err(KillswitchError::Windows(format!(
                "the {name} firewall profile does not block by default in the \
                 active policy (reported {:?})",
                setting
                    .default_outbound_action
                    .map(OutboundAction::as_token)
            )));
        }
    }

    if !expected.iter().any(|r| r.action == RuleAction::Block) {
        // A policy of exceptions only is not a killswitch: with nothing
        // blocking, the profile default is all that stands between a
        // pre-existing allow rule and the physical interface.
        return Err(KillswitchError::Windows(
            "the intended policy has no outbound block rule, so pre-existing \
             allow rules would decide what leaves the host"
                .into(),
        ));
    }

    let rows = parse_rule_rows(rules_out);
    for rule in expected {
        let name = rule.display_name();
        let Some(row) = rows.iter().find(|r| r.display_name == name) else {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} is missing from the active firewall policy"
            )));
        };
        if !row.direction.eq_ignore_ascii_case("Outbound") {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} is not an outbound rule"
            )));
        }
        if row.enabled != Some(GpoBool::True) {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} is not enabled in the active firewall policy"
            )));
        }
        if !row.action.eq_ignore_ascii_case(rule.action.as_token()) {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} has action {} in the active policy, expected {}",
                row.action,
                rule.action.as_token()
            )));
        }
        if rule.action == RuleAction::Block {
            continue;
        }
        // The load-bearing check: without the override flag our own exception
        // loses to the block rule, so the host would block the tunnel while the
        // install claims a working exception.
        if !row.override_block_rules {
            return Err(KillswitchError::Windows(format!(
                "the exception {name} does not carry OverrideBlockRules in the \
                 active policy, so the block rule outranks it and the traffic it \
                 is meant to permit stays blocked"
            )));
        }
    }
    Ok(())
}

// ── Runtime exec (Windows only) ──────────────────────────────────────

/// PowerShell-based Windows killswitch. Mirror of [`super::LinuxKillswitch`]
/// / [`super::MacosKillswitch`] for the install/uninstall lifecycle.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct WindowsKillswitch {
    snapshot: FirewallSnapshot,
    installed: bool,
}

#[cfg(target_os = "windows")]
impl WindowsKillswitch {
    /// Install the killswitch policy and confirm it is in effect.
    ///
    /// Idempotent against a previous partial install: the rule-removal step
    /// matches by display-name prefix and tolerates absent rules. A failure at
    /// any step restores the captured profile settings and removes our rules
    /// before surfacing, so a failed install never leaves the host blocked
    /// without a guard, and never reports success without a confirmed policy.
    ///
    /// # Errors
    ///
    /// - [`KillswitchError::InvalidInput`] if `opts.tun_name` is invalid.
    /// - [`KillswitchError::Windows`] if PowerShell fails, the process lacks
    ///   Administrator privileges, the running binary's own path could not be
    ///   resolved (needed for the WFP app-id scoping fix), a firewall profile
    ///   cannot be enabled, or the read-back does not confirm the policy.
    pub async fn install(opts: &KillswitchOpts) -> Result<Self, KillswitchError> {
        let daemon_exe_path = resolve_daemon_exe_path()?;
        let snapshot = install_with_runner(opts, &PowershellRunner, &daemon_exe_path).await?;
        Ok(Self {
            snapshot,
            installed: true,
        })
    }

    /// Remove our rules, then restore each profile's captured settings.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] if a step fails. The remaining steps still
    /// run, because leaving the host with our block rule in place and the
    /// profile defaults un-restored is the worse outcome.
    pub async fn uninstall(mut self) -> Result<(), KillswitchError> {
        self.installed = false;
        uninstall_with_runner(&PowershellRunner, &self.snapshot).await
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsKillswitch {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // Best-effort sync cleanup. Drop is sync, so this cannot await; each
        // invocation is bounded by SYNC_CLEANUP_TIMEOUT so a wedged
        // powershell.exe can never hang process teardown indefinitely
        // (parity with `warrenguard_route_split`'s sync cleanup helpers).
        // On timeout the child is killed - unrecoverable, but the process is
        // exiting anyway.
        for cmd in uninstall_ops(&self.snapshot).iter().map(render_op) {
            if run_sync_bounded("powershell.exe", &cmd, SYNC_CLEANUP_TIMEOUT).is_none() {
                tracing::warn!(
                    timeout = ?SYNC_CLEANUP_TIMEOUT,
                    "killswitch Drop cleanup command did not complete in time (killed)"
                );
            }
        }
        tracing::warn!(
            "Warren Windows killswitch dropped without explicit uninstall - \
             best-effort bounded sync cleanup ran"
        );
    }
}

/// Resolves the running daemon's own executable path, needed for the WFP
/// app-id scoping of the exit-UDP exception. Isolated so the (extremely rare,
/// for example the running binary was deleted or renamed post-exec) failure
/// path has a single, testable error mapping.
#[cfg(target_os = "windows")]
fn resolve_daemon_exe_path() -> Result<String, KillswitchError> {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| KillswitchError::Windows(format!("resolve current_exe: {e}")))
}

/// Production [`FirewallRunner`]: renders each operation to PowerShell and runs
/// it, and answers the read-back queries with the same shell.
#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct PowershellRunner;

#[cfg(target_os = "windows")]
impl FirewallRunner for PowershellRunner {
    async fn snapshot(&self) -> Result<FirewallSnapshot, KillswitchError> {
        let out = run_powershell_capture(QUERY_PROFILES_LOCAL).await?;
        let settings = parse_profile_settings(&out);
        let mut profiles = Vec::with_capacity(FIREWALL_PROFILES.len());
        for name in FIREWALL_PROFILES {
            let setting = settings.iter().find(|s| s.name == name).ok_or_else(|| {
                KillswitchError::Windows(format!(
                    "Get-NetFirewallProfile did not report the {name} profile"
                ))
            })?;
            profiles.push(ProfileSnapshot {
                name: name.to_owned(),
                // An unreadable pre-install value is refused rather than
                // guessed: restoring a wrong default would change a setting
                // the operator never asked us to touch.
                local_enabled: setting.enabled.ok_or_else(|| {
                    KillswitchError::Windows(format!(
                        "Get-NetFirewallProfile did not report the {name} profile's \
                         Enabled state, so it cannot be restored after uninstall"
                    ))
                })?,
                local_default_outbound_action: setting.default_outbound_action.ok_or_else(
                    || {
                        KillswitchError::Windows(format!(
                            "Get-NetFirewallProfile did not report the {name} profile's \
                             DefaultOutboundAction, so it cannot be restored after uninstall"
                        ))
                    },
                )?,
            });
        }
        Ok(FirewallSnapshot { profiles })
    }

    async fn apply(&self, op: &FirewallOp) -> Result<(), KillswitchError> {
        run_powershell(&render_op(op)).await
    }

    async fn verify(&self, rules: &[RuleSpec]) -> Result<(), KillswitchError> {
        let profiles = run_powershell_capture(QUERY_PROFILES_EFFECTIVE).await?;
        let ours = run_powershell_capture(&query_our_rules_command()).await?;
        check_effective_state(&profiles, &ours, rules)
    }
}

/// Runs `command` through `powershell.exe` and returns its stdout.
#[cfg(target_os = "windows")]
async fn run_powershell_capture(command: &str) -> Result<String, KillswitchError> {
    use tokio::process::Command;

    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", command])
        .output()
        .await
        .map_err(|e| KillswitchError::Windows(format!("spawn powershell.exe: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(KillswitchError::Windows(format!(
            "powershell.exe failed: {}",
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(target_os = "windows")]
async fn run_powershell(args: &[String]) -> Result<(), KillswitchError> {
    use tokio::process::Command;

    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = Command::new("powershell.exe")
        .args(&str_args)
        .output()
        .await
        .map_err(|e| KillswitchError::Windows(format!("spawn powershell.exe: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(KillswitchError::Windows(format!(
        "powershell.exe failed: {}",
        stderr.trim()
    )))
}

// The install / teardown state machine lives here, UNGATED, so the policy and
// its rollback are driven for real on every host by the test module. Only the
// PowerShell binding and the guard type below are Windows-only.

/// Installs the policy through `runner` and confirms it is in effect.
///
/// Returns the captured state the teardown needs. A failure at any step
/// restores that state and removes our rules before surfacing, so a failed
/// install neither reports success nor leaves the host half-configured.
///
/// # Errors
///
/// - [`KillswitchError::InvalidInput`] if `opts.tun_name` is invalid.
/// - [`KillswitchError::Windows`] if a command fails, a profile cannot be
///   enabled, or the read-back does not confirm the policy.
async fn install_with_runner<R: FirewallRunner>(
    opts: &KillswitchOpts,
    runner: &R,
    daemon_exe_path: &str,
) -> Result<FirewallSnapshot, KillswitchError> {
    validate_tun_name(&opts.tun_name)?;
    let snapshot = runner.snapshot().await?;
    let rules = build_rules(opts, daemon_exe_path);

    if let Err(error) = apply_ops(runner, &install_ops(&rules)).await {
        rollback(runner, &snapshot, &error).await;
        return Err(error);
    }
    if let Err(error) = runner.verify(&rules).await {
        // The policy is not in effect, so it must not stay half-applied under
        // our name, and the install must not report success.
        rollback(runner, &snapshot, &error).await;
        return Err(error);
    }

    tracing::info!(
        tun = %opts.tun_name,
        exit_count = opts.exit_addrs.len(),
        allow_lan = opts.allow_lan,
        allow_dhcp = opts.allow_dhcp,
        "Warren killswitch installed and verified (Windows Firewall)"
    );
    Ok(snapshot)
}

/// Removes our rules and puts the captured profile settings back.
///
/// Every step runs even after one fails: leaving the host with our block rule
/// in place and the profile defaults unrestored is the worse outcome. The first
/// failure is what surfaces.
///
/// # Errors
///
/// [`KillswitchError::Windows`] when a step fails.
async fn uninstall_with_runner<R: FirewallRunner>(
    runner: &R,
    snapshot: &FirewallSnapshot,
) -> Result<(), KillswitchError> {
    let mut first_error = None;
    for op in uninstall_ops(snapshot) {
        if let Err(e) = runner.apply(&op).await {
            tracing::warn!(error = %e, "killswitch uninstall command failed");
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Applies every operation, stopping at the first failure.
///
/// The install uses this: a step that failed means the policy is not the one
/// intended, and the caller rolls back instead of layering more changes on it.
async fn apply_ops<R: FirewallRunner>(
    runner: &R,
    ops: &[FirewallOp],
) -> Result<(), KillswitchError> {
    for op in ops {
        if let Err(e) = runner.apply(op).await {
            tracing::error!(error = %e, "killswitch firewall command failed");
            return Err(e);
        }
    }
    Ok(())
}

/// Best-effort restore of the captured state. The original error is what
/// surfaces; each failed restore is logged so an operator can see the host was
/// not fully returned to its previous configuration.
async fn rollback<R: FirewallRunner>(
    runner: &R,
    snapshot: &FirewallSnapshot,
    cause: &KillswitchError,
) {
    tracing::error!(
        error = %cause,
        "killswitch install failed; restoring the captured firewall settings"
    );
    for op in uninstall_ops(snapshot) {
        if let Err(e) = runner.apply(&op).await {
            tracing::warn!(
                error = %e,
                "killswitch rollback command failed (best-effort)"
            );
        }
    }
}

/// Upper bound on a single synchronous cleanup command run from [`Drop`].
/// `powershell.exe` cold-starts at roughly 1-1.5 s per invocation even when
/// healthy; this is a hang guard, not a normal-latency budget.
///
/// `cfg(any(target_os = "windows", test))`: the only production caller is
/// Windows-only ([`Drop for WindowsKillswitch`]), but the helper itself is
/// portable and is exercised for real by the test suite on every host.
#[cfg(any(target_os = "windows", test))]
const SYNC_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll-based bounded wait for a spawned child. `std` has no `wait_timeout`, so
/// poll `try_wait` on a short back-off interval until the deadline. Returns
/// `None` if the child has not exited by the deadline (the caller is
/// responsible for killing it), mirroring `warrenguard_route_split`'s
/// `wait_sync_command` helper.
#[cfg(any(target_os = "windows", test))]
fn wait_child_bounded(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + timeout;
    let mut poll = Duration::from_millis(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(poll);
        poll = (poll * 2).min(Duration::from_millis(64));
    }
}

/// Runs `program args...` synchronously, bounded by `timeout`. Returns `None`
/// on spawn failure or timeout (the child is killed in the timeout case);
/// best-effort and panic-free, so it is safe to call from `Drop`.
///
/// Deliberately portable (no OS-specific API) so the bounded-wait logic itself
/// is exercised by the test suite on every host, even though its only
/// production caller ([`WindowsKillswitch`]'s `Drop`) only ever runs on Windows.
#[cfg(any(target_os = "windows", test))]
fn run_sync_bounded(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Option<std::process::Output> {
    let mut child = std::process::Command::new(program)
        .args(args.iter().map(String::as_str))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    match wait_child_bounded(&mut child, timeout) {
        Some(status) => {
            use std::io::Read as _;
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut h) = child.stdout.take() {
                let _ = h.read_to_end(&mut stdout);
            }
            if let Some(mut h) = child.stderr.take() {
                let _ = h.read_to_end(&mut stderr);
            }
            Some(std::process::Output {
                status,
                stdout,
                stderr,
            })
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn opts_minimal() -> KillswitchOpts {
        KillswitchOpts {
            exit_addrs: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            tun_name: "warren0".into(),
            allow_lan: false,
            allow_dhcp: false,
            socket_mark: None,
            phys_iface: None,
        }
    }

    /// Stand-in for `resolve_daemon_exe_path()`'s result in tests that do not
    /// resolve the running binary's own path.
    const TEST_DAEMON_EXE: &str = r"C:\Program Files\Warren\warren-daemon.exe";
    /// A different application: the one whose pre-existing Allow rule is the
    /// regression this module exists for.
    const TEST_OTHER_APP: &str = r"C:\Program Files\Other\browser.exe";

    /// The rendered command lines, joined for readable assertions.
    fn rendered(opts: &KillswitchOpts) -> Vec<String> {
        build_install_commands(opts, TEST_DAEMON_EXE)
            .iter()
            .map(|argv| argv.join(" "))
            .collect()
    }

    fn rendered_for(rules: &[RuleSpec]) -> Vec<String> {
        install_ops(rules)
            .iter()
            .map(|op| render_op(op).join(" "))
            .collect()
    }

    // ---- the rendered policy -----------------------------------------

    #[test]
    fn install_enables_the_profiles_then_blocks_by_default() {
        // With the firewall switched off nothing below filters anything, so
        // enabling comes first. The default block is what a partial install is
        // left in, and it is NOT the rule the policy rests on (it does not
        // outrank a pre-existing allow rule; the explicit block rule does).
        let ops = install_ops(&build_rules(&opts_minimal(), TEST_DAEMON_EXE));
        assert_eq!(ops[0], FirewallOp::EnableProfiles);
        assert_eq!(ops[1], FirewallOp::SetDefaultOutboundActionBlock);
    }

    #[test]
    fn the_block_rule_is_created_first_and_every_exception_overrides_it() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let block_pos = rules
            .iter()
            .position(|r| r.action == RuleAction::Block)
            .expect("the policy has an explicit block rule");
        assert_eq!(
            block_pos, 0,
            "the block rule must be created before any exception, so the \
             interval in which an exception exists without the block is empty"
        );
        for rule in &rules[1..] {
            assert_eq!(rule.action, RuleAction::Allow, "{}", rule.id);
            assert!(
                rule.override_block_rules,
                "every exception must carry -OverrideBlockRules, else the block \
                 rule outranks it and the traffic it permits stays blocked: {}",
                rule.id
            );
        }
        for command in rendered_for(&rules) {
            if command.contains("-Action Allow") {
                assert!(
                    command.contains("-OverrideBlockRules True"),
                    "an exception was rendered without the override flag: {command}"
                );
            }
        }
        assert!(
            rendered_for(&rules)
                .iter()
                .any(|c| c.contains("-Action Block")),
            "the policy must render an explicit block rule"
        );
    }

    #[test]
    fn install_includes_tun_alias_allow_rule() {
        // Without this exception the tunnel is blocked once the block rule is in
        // place: the tunnel never opens.
        let commands = rendered(&opts_minimal());
        assert!(
            commands
                .iter()
                .any(|c| c.contains("-InterfaceAlias 'warren0'") && c.contains("-Action Allow")),
            "expected a tunnel-interface exception, got {commands:#?}"
        );
    }

    #[test]
    fn install_emits_one_allow_rule_per_exit_addr() {
        let mut o = opts_minimal();
        o.exit_addrs = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xc013, 0x14a1, 0, 0, 0, 1)),
        ];
        let rules = build_rules(&o, TEST_DAEMON_EXE);
        let exits: Vec<&RuleSpec> = rules.iter().filter(|r| r.id.contains("exit-udp")).collect();
        assert_eq!(exits.len(), 2, "one exception per exit address: {rules:#?}");
        assert!(exits.iter().all(|r| r.udp), "the carrier is UDP");
        assert!(
            exits.iter().all(|r| r.remote.is_some()),
            "the exit exception is destination scoped"
        );
    }

    #[test]
    fn install_udp_allow_rule_is_scoped_to_the_daemon_program_path() {
        // Port Fail / TunnelCrack-ServerIP: a destination-only exception grants
        // the off-tunnel path to ANY process that dials the exit address.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let exit = rules
            .iter()
            .find(|r| r.id.contains("exit-udp"))
            .expect("the exit exception exists");
        assert_eq!(
            exit.program.as_deref(),
            Some(TEST_DAEMON_EXE),
            "the exit exception must be scoped to the daemon's own executable"
        );
        assert!(
            rendered_for(&rules)
                .iter()
                .any(|c| c.contains(&format!("-Program '{TEST_DAEMON_EXE}'"))),
            "the app-id scope must reach the rendered command"
        );
    }

    #[test]
    fn program_path_with_embedded_single_quote_is_escaped_for_powershell() {
        let path = r"C:\Program Files\O'Brien\warren-daemon.exe";
        let rules = build_rules(&opts_minimal(), path);
        let exit_command = rendered_for(&rules)
            .into_iter()
            .find(|c| c.contains("exit-udp"))
            .expect("the exit exception is rendered");
        assert!(
            exit_command.contains(r"-Program 'C:\Program Files\O''Brien\warren-daemon.exe'"),
            "a quote in the install path must be doubled, not break the command: \
             {exit_command}"
        );
    }

    #[test]
    fn escape_powershell_single_quoted_doubles_every_quote() {
        assert_eq!(escape_powershell_single_quoted("plain"), "plain");
        assert_eq!(escape_powershell_single_quoted("a'b"), "a''b");
        assert_eq!(escape_powershell_single_quoted("a''b"), "a''''b");
    }

    #[test]
    fn install_excludes_lan_ranges_by_default() {
        let commands = rendered(&opts_minimal());
        assert!(
            !commands.iter().any(|c| c.contains("10.0.0.0/8")),
            "LAN must stay blocked by default: a killswitch that leaks to the \
             local network is not a killswitch"
        );
    }

    #[test]
    fn install_includes_lan_ranges_when_allow_lan_set() {
        let mut o = opts_minimal();
        o.allow_lan = true;
        let commands = rendered(&o);
        for cidr in LAN_RANGES_V4.iter().chain(LAN_RANGES_V6.iter()) {
            assert!(
                commands.iter().any(|c| c.contains(cidr)),
                "allow_lan must add {cidr}"
            );
        }
    }

    #[test]
    fn install_includes_dhcp_ports_when_allow_dhcp_set() {
        let mut o = opts_minimal();
        o.allow_dhcp = true;
        let rules = build_rules(&o, TEST_DAEMON_EXE);
        for port in [67u16, 68] {
            assert!(
                rules
                    .iter()
                    .any(|r| r.remote_port == Some(port) && r.override_block_rules),
                "allow_dhcp must add an overriding exception for port {port}"
            );
        }
    }

    #[test]
    fn rule_prefix_is_unique_enough_to_not_collide_with_other_apps() {
        assert!(RULE_PREFIX.starts_with("warren-"));
        let names: Vec<String> = build_rules(&opts_minimal(), TEST_DAEMON_EXE)
            .iter()
            .map(RuleSpec::display_name)
            .collect();
        assert!(
            names.iter().all(|n| n.starts_with(RULE_PREFIX)),
            "every rule must be removable by the prefix the teardown matches: {names:?}"
        );
        let unique: std::collections::BTreeSet<&String> = names.iter().collect();
        assert_eq!(
            unique.len(),
            names.len(),
            "duplicate display names: {names:?}"
        );
    }

    // ---- teardown rendering ------------------------------------------

    fn snapshot_all_allow() -> FirewallSnapshot {
        FirewallSnapshot {
            profiles: FIREWALL_PROFILES
                .iter()
                .map(|name| ProfileSnapshot {
                    name: (*name).to_owned(),
                    local_enabled: GpoBool::True,
                    local_default_outbound_action: OutboundAction::Allow,
                })
                .collect(),
        }
    }

    #[test]
    fn uninstall_removes_our_rules_before_restoring_the_profiles() {
        let commands: Vec<String> = uninstall_ops(&snapshot_all_allow())
            .iter()
            .map(|op| render_op(op).join(" "))
            .collect();
        assert!(
            commands[0].contains("Remove-NetFirewallRule"),
            "our rules come off first: {commands:#?}"
        );
        assert_eq!(commands.len(), 1 + FIREWALL_PROFILES.len());
    }

    #[test]
    fn uninstall_round_trips_each_profiles_captured_settings_verbatim() {
        let snapshot = FirewallSnapshot {
            profiles: vec![
                ProfileSnapshot {
                    name: "Domain".into(),
                    local_enabled: GpoBool::NotConfigured,
                    local_default_outbound_action: OutboundAction::Allow,
                },
                ProfileSnapshot {
                    name: "Private".into(),
                    local_enabled: GpoBool::False,
                    local_default_outbound_action: OutboundAction::Block,
                },
                ProfileSnapshot {
                    name: "Public".into(),
                    local_enabled: GpoBool::True,
                    local_default_outbound_action: OutboundAction::NotConfigured,
                },
            ],
        };
        let commands: Vec<String> = uninstall_ops(&snapshot)
            .iter()
            .map(|op| render_op(op).join(" "))
            .collect();
        assert!(
            commands.iter().any(|c| c.contains(
                "Set-NetFirewallProfile -Profile Domain -Enabled NotConfigured \
                 -DefaultOutboundAction Allow"
            )),
            "a profile the install did not have to change must be restored to \
             NotConfigured, not to a value we chose: {commands:#?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c.contains("Public") && c.contains("NotConfigured")),
            "a NotConfigured default must round trip: {commands:#?}"
        );
    }

    // ---- read-back parsing and verification --------------------------

    /// The shape `Get-NetFirewallProfile -PolicyStore ActiveStore ... |
    /// Format-List` produces for a host that filters and blocks by default.
    const EFFECTIVE_BLOCKING: &str = "\
Name                       : Domain
Enabled                    : True
DefaultOutboundAction      : Block

Name                       : Private
Enabled                    : True
DefaultOutboundAction      : Block

Name                       : Public
Enabled                    : True
DefaultOutboundAction      : Block
";

    /// The `RULE|...` lines the read-back command emits, built from the policy
    /// we intended, so the acceptance case really is the installed one.
    fn readback_for(rules: &[RuleSpec]) -> String {
        let mut out = String::new();
        for rule in rules {
            let _ = writeln!(
                out,
                "RULE|{}|Outbound|{}|True|{}",
                rule.display_name(),
                rule.action.as_token(),
                rule.override_block_rules
            );
        }
        out
    }

    #[test]
    fn parse_profile_settings_reads_every_block() {
        let settings = parse_profile_settings(EFFECTIVE_BLOCKING);
        assert_eq!(settings.len(), 3);
        assert_eq!(settings[0].name, "Domain");
        assert_eq!(settings[0].enabled, Some(GpoBool::True));
        assert_eq!(
            settings[0].default_outbound_action,
            Some(OutboundAction::Block)
        );
        assert_eq!(settings[2].name, "Public");
    }

    #[test]
    fn parse_profile_settings_yields_nothing_on_garbage_input() {
        assert!(parse_profile_settings("").is_empty());
        assert!(parse_profile_settings("not a profile listing").is_empty());
    }

    #[test]
    fn parse_rule_rows_reads_the_line_format() {
        let rows = parse_rule_rows("RULE|warren-killswitch-allow-tun|Outbound|Allow|True|True\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].display_name, "warren-killswitch-allow-tun");
        assert_eq!(rows[0].action, "Allow");
        assert_eq!(rows[0].enabled, Some(GpoBool::True));
        assert!(rows[0].override_block_rules);
        assert!(parse_rule_rows("noise").is_empty());
    }

    #[test]
    fn check_effective_state_accepts_the_policy_it_would_install() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        check_effective_state(EFFECTIVE_BLOCKING, &readback_for(&rules), &rules)
            .expect("the policy we install must pass the read-back");
    }

    #[test]
    fn check_effective_state_rejects_a_profile_that_is_not_enabled() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let out = EFFECTIVE_BLOCKING.replace(
            "Name                       : Public\nEnabled                    : True",
            "Name                       : Public\nEnabled                    : False",
        );
        let err = check_effective_state(&out, &readback_for(&rules), &rules)
            .expect_err("a disabled profile means nothing filters, so it cannot pass");
        assert!(format!("{err:#}").contains("Public"), "got {err:#}");
        assert!(
            format!("{err:#}").contains("Group Policy"),
            "the message must name the cause an operator can act on: {err:#}"
        );
    }

    #[test]
    fn check_effective_state_rejects_a_profile_that_does_not_block_by_default() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let out = EFFECTIVE_BLOCKING.replace(
            "Name                       : Domain\nEnabled                    : True\n\
             DefaultOutboundAction      : Block",
            "Name                       : Domain\nEnabled                    : True\n\
             DefaultOutboundAction      : Allow",
        );
        assert!(check_effective_state(&out, &readback_for(&rules), &rules).is_err());
    }

    #[test]
    fn check_effective_state_rejects_a_missing_rule() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let readback =
            readback_for(&rules).replace("warren-killswitch-allow-tun", "warren-killswitch-typo");
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, &rules)
            .expect_err("a rule that is not in the effective policy is not installed");
        assert!(format!("{err:#}").contains("allow-tun"), "got {err:#}");
    }

    #[test]
    fn check_effective_state_rejects_an_exception_without_the_override_flag() {
        // The load-bearing check. Without the flag the block rule outranks our
        // own exception, so the tunnel and the carrier stay blocked while a less
        // careful install would report success.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let readback = readback_for(&rules).replace(
            "|warren-killswitch-allow-tun|Outbound|Allow|True|true",
            "|warren-killswitch-allow-tun|Outbound|Allow|True|false",
        );
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, &rules)
            .expect_err("an exception without the override flag cannot be trusted");
        assert!(
            format!("{err:#}").contains("OverrideBlockRules"),
            "got {err:#}"
        );
    }

    #[test]
    fn check_effective_state_rejects_a_policy_with_no_block_rule() {
        // The invariant is checked against the policy we intended, so it cannot
        // be masked by a read-back that simply omits the rule.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let exceptions: Vec<RuleSpec> = rules
            .into_iter()
            .filter(|r| r.action == RuleAction::Allow)
            .collect();
        let readback = readback_for(&exceptions);
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, &exceptions)
            .expect_err("a policy that blocks nothing is not a killswitch");
        assert!(
            format!("{err:#}").contains("no outbound block rule"),
            "got {err:#}"
        );
    }

    #[test]
    fn check_effective_state_rejects_a_missing_block_rule() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let readback: String = readback_for(&rules)
            .lines()
            .filter(|l| !l.contains("block-outbound"))
            .map(|l| format!("{l}\n"))
            .collect();
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, &rules)
            .expect_err("without the block rule pre-existing allow rules decide again");
        assert!(format!("{err:#}").contains("block-outbound"), "got {err:#}");
    }

    // ---- a model of the documented rule precedence -------------------
    //
    // A test that greps the generated PowerShell cannot observe which policy the
    // host ends up with, so the policy is also driven against a model of the
    // decision Microsoft documents:
    //
    //   1. an explicit Allow rule beats the profile DEFAULT block setting;
    //   2. an explicit Block rule beats any conflicting Allow rule;
    //   3. more specific rules win, except against an explicit Block;
    //   4. an outbound Allow carrying OverrideBlockRules is an "allow bypass
    //      rule": it wins even where another rule blocks.
    //
    // The model is what makes the regression observable: under the OLD policy
    // (profile default block plus our exceptions) rule 1 keeps a pre-existing
    // Allow rule working, which is the leak.

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Verdict {
        Allow,
        Block,
    }

    /// One packet offered to the model.
    struct Packet<'a> {
        iface: &'a str,
        udp: bool,
        remote: IpAddr,
        remote_port: u16,
        program: &'a str,
    }

    /// A rule as the firewall holds it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ModelRule {
        name: String,
        action: RuleAction,
        override_block_rules: bool,
        iface: Option<String>,
        udp: bool,
        remote: Option<Remote>,
        remote_port: Option<u16>,
        program: Option<String>,
    }

    impl ModelRule {
        fn from_spec(spec: &RuleSpec) -> Self {
            Self {
                name: spec.display_name(),
                action: spec.action,
                override_block_rules: spec.override_block_rules,
                iface: spec.iface.clone(),
                udp: spec.udp,
                remote: spec.remote.clone(),
                remote_port: spec.remote_port,
                program: spec.program.clone(),
            }
        }

        fn matches(&self, packet: &Packet<'_>) -> bool {
            if let Some(iface) = &self.iface
                && iface != packet.iface
            {
                return false;
            }
            if self.udp && !packet.udp {
                return false;
            }
            if let Some(remote) = &self.remote {
                let hit = match remote {
                    Remote::Host(addr) => *addr == packet.remote,
                    Remote::Network(cidr) => network_contains(cidr, packet.remote),
                };
                if !hit {
                    return false;
                }
            }
            if let Some(port) = self.remote_port
                && port != packet.remote_port
            {
                return false;
            }
            if let Some(program) = &self.program
                && program != packet.program
            {
                return false;
            }
            true
        }
    }

    /// CIDR containment for the ranges the policy emits.
    fn network_contains(cidr: &str, addr: IpAddr) -> bool {
        let Some((net, prefix)) = cidr.split_once('/') else {
            return false;
        };
        let Ok(prefix) = prefix.parse::<u32>() else {
            return false;
        };
        match (net.parse::<Ipv4Addr>(), addr) {
            (Ok(net), IpAddr::V4(addr)) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            _ => match (net.parse::<Ipv6Addr>(), addr) {
                (Ok(net), IpAddr::V6(addr)) if prefix <= 128 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    };
                    (u128::from(net) & mask) == (u128::from(addr) & mask)
                }
                _ => false,
            },
        }
    }

    #[derive(Debug, Clone)]
    struct ModelProfile {
        /// What the local (PersistentStore) policy says, which is what the
        /// install writes and the teardown restores.
        local_enabled: GpoBool,
        local_default: OutboundAction,
        /// A Group Policy that fixes the profile: no local write can change it.
        policy_enabled: Option<bool>,
    }

    impl ModelProfile {
        fn enabled(&self) -> bool {
            self.policy_enabled
                .unwrap_or(self.local_enabled == GpoBool::True)
        }

        fn default_action(&self) -> OutboundAction {
            match self.local_default {
                OutboundAction::NotConfigured => OutboundAction::Allow,
                other => other,
            }
        }
    }

    #[derive(Debug)]
    struct FirewallModel {
        profiles: BTreeMap<String, ModelProfile>,
        /// Rules that existed before the install: a user's own "allow this app",
        /// a vendor installer's rule.
        preexisting: Vec<ModelRule>,
        ours: Vec<ModelRule>,
        active_profile: String,
    }

    impl FirewallModel {
        /// A stock host: the firewall on for all three profiles, outbound
        /// allowed by default, no policy override.
        fn stock() -> Self {
            let profiles = FIREWALL_PROFILES
                .iter()
                .map(|name| {
                    (
                        (*name).to_owned(),
                        ModelProfile {
                            local_enabled: GpoBool::True,
                            local_default: OutboundAction::Allow,
                            policy_enabled: None,
                        },
                    )
                })
                .collect();
            Self {
                profiles,
                preexisting: Vec::new(),
                ours: Vec::new(),
                active_profile: "Public".to_owned(),
            }
        }

        /// A stock host that already lets `program` out under an explicit Allow
        /// rule, which is what a user clicking "Allow" on the firewall prompt
        /// leaves behind.
        fn with_preexisting_allow(program: &str) -> Self {
            let mut model = Self::stock();
            model.preexisting.push(ModelRule {
                name: "vendor-app-allow".to_owned(),
                action: RuleAction::Allow,
                override_block_rules: false,
                iface: None,
                udp: false,
                remote: None,
                remote_port: None,
                program: Some(program.to_owned()),
            });
            model
        }

        /// The decision the firewall would reach for `packet`.
        fn decide(&self, packet: &Packet<'_>) -> Verdict {
            let profile = &self.profiles[&self.active_profile];
            if !profile.enabled() {
                // A firewall that is off filters nothing.
                return Verdict::Allow;
            }
            let matching = || {
                self.ours
                    .iter()
                    .chain(self.preexisting.iter())
                    .filter(|rule| rule.matches(packet))
            };
            if matching().any(|r| r.action == RuleAction::Allow && r.override_block_rules) {
                return Verdict::Allow;
            }
            if matching().any(|r| r.action == RuleAction::Block) {
                return Verdict::Block;
            }
            if matching().any(|r| r.action == RuleAction::Allow) {
                return Verdict::Allow;
            }
            match profile.default_action() {
                OutboundAction::Block => Verdict::Block,
                _ => Verdict::Allow,
            }
        }
    }

    /// Drives the lifecycle against [`FirewallModel`].
    #[derive(Debug)]
    struct ModelRunner {
        model: Mutex<FirewallModel>,
        /// When `Some(n)`, the n-th `apply` (0-based) fails.
        fail_apply_index: Option<usize>,
        applies: AtomicUsize,
        /// Stands in for a policy that keeps the profiles disabled whatever the
        /// local store says, so `EnableProfiles` writes and nothing changes.
        refuse_enable: bool,
        /// Stands in for a cmdlet that accepts `-OverrideBlockRules` and does
        /// not apply it.
        drop_override_flag: bool,
    }

    impl ModelRunner {
        fn new(model: FirewallModel) -> Self {
            Self {
                model: Mutex::new(model),
                fail_apply_index: None,
                applies: AtomicUsize::new(0),
                refuse_enable: false,
                drop_override_flag: false,
            }
        }

        fn failing_at(mut self, index: usize) -> Self {
            self.fail_apply_index = Some(index);
            self
        }

        fn dropping_override_flag(mut self) -> Self {
            self.drop_override_flag = true;
            self
        }

        fn model(&self) -> std::sync::MutexGuard<'_, FirewallModel> {
            self.model.lock().expect("model mutex")
        }
    }

    impl FirewallRunner for ModelRunner {
        async fn snapshot(&self) -> Result<FirewallSnapshot, KillswitchError> {
            let model = self.model();
            Ok(FirewallSnapshot {
                profiles: FIREWALL_PROFILES
                    .iter()
                    .map(|name| ProfileSnapshot {
                        name: (*name).to_owned(),
                        local_enabled: model.profiles[*name].local_enabled,
                        local_default_outbound_action: model.profiles[*name].local_default,
                    })
                    .collect(),
            })
        }

        async fn apply(&self, op: &FirewallOp) -> Result<(), KillswitchError> {
            let index = self.applies.fetch_add(1, Ordering::SeqCst);
            if self.fail_apply_index == Some(index) {
                return Err(KillswitchError::Windows(
                    "model: injected apply failure".into(),
                ));
            }
            let mut model = self.model();
            match op {
                FirewallOp::EnableProfiles => {
                    if !self.refuse_enable {
                        for profile in model.profiles.values_mut() {
                            profile.local_enabled = GpoBool::True;
                        }
                    }
                }
                FirewallOp::SetDefaultOutboundActionBlock => {
                    for profile in model.profiles.values_mut() {
                        profile.local_default = OutboundAction::Block;
                    }
                }
                FirewallOp::CreateRule(spec) => {
                    let mut rule = ModelRule::from_spec(spec);
                    if self.drop_override_flag {
                        rule.override_block_rules = false;
                    }
                    model.ours.push(rule);
                }
                FirewallOp::DeleteOurRules => model.ours.clear(),
                FirewallOp::RestoreProfile(snapshot) => {
                    if let Some(profile) = model.profiles.get_mut(&snapshot.name) {
                        profile.local_enabled = snapshot.local_enabled;
                        profile.local_default = snapshot.local_default_outbound_action;
                    }
                }
            }
            Ok(())
        }

        async fn verify(&self, rules: &[RuleSpec]) -> Result<(), KillswitchError> {
            let model = self.model();
            for name in FIREWALL_PROFILES {
                let profile = &model.profiles[name];
                if !profile.enabled() {
                    return Err(KillswitchError::Windows(format!(
                        "model: the {name} profile is not enabled in the active policy"
                    )));
                }
                if profile.default_action() != OutboundAction::Block {
                    return Err(KillswitchError::Windows(format!(
                        "model: the {name} profile does not block by default"
                    )));
                }
            }
            for spec in rules {
                let name = spec.display_name();
                let row = model
                    .ours
                    .iter()
                    .find(|rule| rule.name == name)
                    .ok_or_else(|| {
                        KillswitchError::Windows(format!("model: the rule {name} is missing"))
                    })?;
                if row.action != spec.action {
                    return Err(KillswitchError::Windows(format!(
                        "model: the rule {name} has the wrong action"
                    )));
                }
                if spec.override_block_rules && !row.override_block_rules {
                    return Err(KillswitchError::Windows(format!(
                        "model: the exception {name} does not carry OverrideBlockRules, \
                         so the block rule outranks it"
                    )));
                }
            }
            Ok(())
        }
    }

    /// A packet from `program` leaving on the physical interface towards a
    /// public address.
    fn outbound_from<'a>(iface: &'a str, program: &'a str, remote: IpAddr) -> Packet<'a> {
        Packet {
            iface,
            udp: false,
            remote,
            remote_port: 443,
            program,
        }
    }

    const PUBLIC_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    #[tokio::test]
    async fn a_preexisting_allow_rule_cannot_let_traffic_out_after_the_install() {
        // The regression this module exists for: the profile default block does
        // NOT outrank a pre-existing explicit Allow rule, so a policy built from
        // the default plus our exceptions leaves every other application's
        // egress wide open.
        let runner = ModelRunner::new(FirewallModel::with_preexisting_allow(TEST_OTHER_APP));
        let packet = outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Allow,
            "setup: the pre-existing Allow rule lets the application out"
        );

        install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect("install");

        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Block,
            "after the install the application's physical egress must be blocked: \
             an explicit Block rule outranks the pre-existing Allow rule"
        );
    }

    #[tokio::test]
    async fn the_tunnel_and_the_daemon_carrier_still_pass_after_the_install() {
        let runner = ModelRunner::new(FirewallModel::with_preexisting_allow(TEST_OTHER_APP));
        install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect("install");
        let model = runner.model();

        let on_tun = outbound_from("warren0", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            model.decide(&on_tun),
            Verdict::Allow,
            "everything on the tunnel interface is where legitimate traffic goes"
        );

        let carrier = Packet {
            iface: "Ethernet",
            udp: true,
            remote: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            remote_port: 443,
            program: TEST_DAEMON_EXE,
        };
        assert_eq!(
            model.decide(&carrier),
            Verdict::Allow,
            "the daemon's own transport to the exit must survive the block, or \
             the tunnel can never connect"
        );

        let impostor = Packet {
            program: TEST_OTHER_APP,
            ..carrier
        };
        assert_eq!(
            model.decide(&impostor),
            Verdict::Block,
            "another process dialing the exit address must not inherit the \
             daemon's exception (Port Fail / TunnelCrack ServerIP)"
        );

        let local = Packet {
            iface: "Ethernet",
            udp: false,
            remote: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote_port: 8080,
            program: TEST_OTHER_APP,
        };
        assert_eq!(
            model.decide(&local),
            Verdict::Allow,
            "loopback is local IPC and must keep working"
        );
    }

    #[tokio::test]
    async fn install_turns_a_disabled_firewall_on_and_confirms_it() {
        let mut model = FirewallModel::stock();
        for profile in model.profiles.values_mut() {
            profile.local_enabled = GpoBool::False;
        }
        let runner = ModelRunner::new(model);
        let packet = outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Allow,
            "setup: with the firewall off nothing filters"
        );

        let snapshot = install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect("the install must turn the profiles on rather than trust them");
        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Block,
            "an install that reported success must actually be filtering"
        );

        uninstall_with_runner(&runner, &snapshot)
            .await
            .expect("uninstall");
        assert!(
            !runner.model().profiles["Domain"].enabled(),
            "the captured disabled state must come back: we turned the firewall \
             on, so we turn it back off"
        );
    }

    #[tokio::test]
    async fn install_refuses_and_rolls_back_when_a_policy_keeps_a_profile_disabled() {
        // A Group Policy that forces the firewall off cannot be overridden from
        // the local store, so no policy of ours can filter. Refusing is the only
        // honest outcome; the alternative is announcing a killswitch that does
        // nothing.
        let mut model = FirewallModel::stock();
        model
            .profiles
            .get_mut("Public")
            .expect("the Public profile exists")
            .policy_enabled = Some(false);
        let runner = ModelRunner::new(model);

        let err = install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect_err("a profile the policy keeps off must fail the install");
        assert!(format!("{err:#}").contains("Public"), "got {err:#}");

        let model = runner.model();
        assert!(
            model.ours.is_empty(),
            "a failed install must not leave its rules on the host"
        );
        assert_eq!(
            model.profiles["Domain"].local_default,
            OutboundAction::Allow,
            "the captured profile settings must be restored"
        );
    }

    #[tokio::test]
    async fn install_refuses_and_rolls_back_when_the_profiles_cannot_be_enabled() {
        // The same refusal driven through the profile model of a policy that
        // pins every profile off: the enable command is accepted and has no
        // effect, so the read-back must catch it.
        let runner = ModelRunner::new(FirewallModel::stock());
        {
            let mut model = runner.model();
            for profile in model.profiles.values_mut() {
                profile.local_enabled = GpoBool::False;
                profile.policy_enabled = Some(false);
            }
        }

        let err = install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect_err("profiles that stay off must fail the install");
        assert!(matches!(err, KillswitchError::Windows(_)), "got {err:?}");
        assert!(runner.model().ours.is_empty());
    }

    #[tokio::test]
    async fn install_rolls_the_whole_policy_back_when_a_command_fails() {
        let runner =
            ModelRunner::new(FirewallModel::with_preexisting_allow(TEST_OTHER_APP)).failing_at(3);
        let err = install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect_err("a failing command must fail the install");
        assert!(matches!(err, KillswitchError::Windows(_)), "got {err:?}");

        let model = runner.model();
        assert!(
            model.ours.is_empty(),
            "the rollback must remove every rule we created"
        );
        assert_eq!(
            model.decide(&outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR)),
            Verdict::Allow,
            "and the host must be back to its previous state, where the \
             pre-existing Allow rule decides"
        );
        assert_eq!(
            model.profiles["Domain"].local_default,
            OutboundAction::Allow
        );
    }

    #[tokio::test]
    async fn install_is_not_reported_done_when_an_exception_loses_the_override_flag() {
        // The command was accepted; the flag is not in the effective policy. Our
        // exception then loses to the block rule, so the tunnel and the carrier
        // stay blocked. Reporting success here would be an announced protection
        // that is not active.
        let runner = ModelRunner::new(FirewallModel::stock()).dropping_override_flag();
        let err = install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect_err("an exception without the override flag must fail the install");
        assert!(
            format!("{err:#}").contains("OverrideBlockRules"),
            "got {err:#}"
        );
        assert!(
            runner.model().ours.is_empty(),
            "the failed install must not leave its rules behind"
        );
    }

    #[tokio::test]
    async fn uninstall_restores_the_profiles_and_removes_only_our_rules() {
        let runner = ModelRunner::new(FirewallModel::with_preexisting_allow(TEST_OTHER_APP));
        let snapshot = install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect("install");
        assert_eq!(
            runner
                .model()
                .decide(&outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR)),
            Verdict::Block,
            "setup: the policy is in effect"
        );

        uninstall_with_runner(&runner, &snapshot)
            .await
            .expect("uninstall");

        let model = runner.model();
        assert!(model.ours.is_empty(), "our rules must all be removed");
        assert_eq!(
            model.preexisting.len(),
            1,
            "a rule we did not create must survive the teardown untouched"
        );
        assert_eq!(
            model.decide(&outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR)),
            Verdict::Allow,
            "the pre-existing allow rule works again once the killswitch is gone"
        );
        assert_eq!(
            model.profiles["Domain"].local_default,
            OutboundAction::Allow,
            "the captured default outbound action must come back"
        );
    }

    #[tokio::test]
    async fn a_host_that_already_blocked_by_default_is_restored_verbatim() {
        let mut model = FirewallModel::stock();
        for profile in model.profiles.values_mut() {
            profile.local_default = OutboundAction::Block;
        }
        let runner = ModelRunner::new(model);
        let snapshot = install_with_runner(&opts_minimal(), &runner, TEST_DAEMON_EXE)
            .await
            .expect("install");

        uninstall_with_runner(&runner, &snapshot)
            .await
            .expect("uninstall");
        assert_eq!(
            runner.model().profiles["Domain"].local_default,
            OutboundAction::Block,
            "the uninstall restores what it captured, not a hard-coded Allow"
        );
    }

    // ---- portable bounded-wait helper (exercised on every host; its only
    // production caller, WindowsKillswitch's Drop, only ever runs on
    // Windows and must be validated for real there) --------------------

    #[cfg(unix)]
    mod bounded_wait {
        use super::*;

        #[test]
        fn run_sync_bounded_returns_output_for_a_fast_command() {
            // Reuses the actual production bound (not a smaller literal) so
            // the constant Drop relies on is exercised by this test too.
            let out = run_sync_bounded("/bin/echo", &["hello".to_string()], SYNC_CLEANUP_TIMEOUT)
                .expect("echo must complete well within the bound");
            assert!(out.status.success());
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
        }

        #[test]
        fn run_sync_bounded_kills_and_returns_none_on_timeout() {
            // A "wedged powershell.exe" stand-in: a process that outlives
            // the bound must be killed, not silently awaited to completion,
            // or Drop could hang process teardown indefinitely.
            let started = std::time::Instant::now();
            let out = run_sync_bounded(
                "/bin/sleep",
                &["30".to_string()],
                Duration::from_millis(200),
            );
            assert!(
                out.is_none(),
                "a wedged child must report as timed out, not succeed later"
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "the bound must actually cap the wait, took {:?}",
                started.elapsed()
            );
        }

        #[test]
        fn run_sync_bounded_reports_a_missing_program_as_failure() {
            // posix_spawn may defer the exec failure: under emulation (the
            // CI linux runners are amd64 under Rosetta) the spawn itself
            // succeeds and the missing program only surfaces as a 127 exit
            // at wait time, while a native host reports it synchronously as
            // a spawn failure (None). Both count as "reported as failure,
            // without wedging or panicking", which is the contract the
            // killswitch Drop relies on.
            match run_sync_bounded(
                "/warren-test-missing-dir/definitely-not-a-real-binary",
                &[],
                Duration::from_secs(1),
            ) {
                None => {}
                Some(out) => assert!(
                    !out.status.success(),
                    "a missing program cannot report success"
                ),
            }
        }
    }
}
