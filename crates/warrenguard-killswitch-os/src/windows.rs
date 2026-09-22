//! Windows killswitch - the Windows Firewall (WFP's user-space surface).
//!
//! ## The rule precedence this policy rests on
//!
//! Microsoft documents three behaviours ("Windows Firewall rules"): an
//! explicitly defined allow rule takes precedence over the DEFAULT BLOCK
//! setting; an explicit block rule takes precedence over any conflicting allow
//! rule; and more specific rules win over less specific ones, except when an
//! explicit block rule is involved. Outbound rules follow the same order, and
//! the platform offers no administrator-assigned weighting.
//! `Set-NetFirewallProfile` states the same thing for the setting itself:
//! "Block: Blocks outbound network traffic that does not match an outbound
//! rule."
//!
//! Two consequences drive this design:
//!
//! - Setting `DefaultOutboundAction = Block` alone stops nothing that an
//!   existing Allow rule matches. Every pre-existing outbound allow rule (a
//!   user's answer to a firewall prompt, a vendor installer's rule, a Group
//!   Policy exception) keeps its egress, which is why an install that only
//!   flipped the default was announcing a protection it did not have.
//! - The obvious repair, one explicit Block-everything rule plus exceptions,
//!   cannot carry the tunnel and the carrier. An explicit block rule outranks
//!   every conflicting allow rule, so an exception survives it only with
//!   `-OverrideBlockRules`, and Microsoft's documentation of that parameter is
//!   self-contradictory for outbound traffic: it states the traffic "must be
//!   authenticated by using a separate IPsec rule", then carves out outbound
//!   rules on Windows 7 and later ("no accounts are required"). No Windows host
//!   is in CI here and the engine has no IPsec story, so a tunnel whose survival
//!   depends on which reading is right is not something this module can ship as
//!   verified. It therefore does not use that mechanism at all.
//!
//! ## The policy installed here
//!
//! 1. Remove every rule carrying [`RULE_PREFIX`], including the leftovers of a
//!    session that ended without its teardown running.
//! 2. Turn the firewall on for all three profiles.
//! 3. Set `DefaultOutboundAction = Block` on all three.
//! 4. Create ONE explicit outbound Block rule. Being an explicit block rule it
//!    outranks every conflicting allow rule, which is what keeps the policy
//!    binding for the whole session: an allow rule created later (a user
//!    answering a firewall prompt, a software installer, a Group Policy refresh)
//!    loses to it.
//! 5. Create the exceptions as Allow rules carrying `-OverrideBlockRules True`,
//!    the documented outbound "allow bypass rule", so that they outrank step 4's
//!    block: loopback, the tunnel interface, UDP to each exit scoped to the
//!    daemon's own executable (`-Program`, the Port Fail / TunnelCrack ServerIP
//!    closure), and the optional LAN and DHCP ranges.
//! 6. Disable every OTHER enabled outbound allow rule, recording each rule name
//!    so the teardown re-enables exactly those. This is defence in depth, and it
//!    is what makes the verified property categorical: after the install the only
//!    enabled outbound allow rules are ours, so the policy holds even on a build
//!    where the override in step 5 behaves unexpectedly.
//!
//! ## The one question a non-Windows host cannot settle
//!
//! `-OverrideBlockRules` is documented as an outbound "allow bypass rule" from
//! Windows 7 on: "matching traffic is permitted through this rule even if other
//! matching rules would block the traffic". The Windows Filtering Platform
//! mechanism behind it is the hard permit: "The traffic can be blocked at
//! another sub-layer only by a callout Veto". The same page states earlier, about
//! the general case, that such traffic "must be authenticated by using a
//! separate IPsec rule". This engine has no IPsec story and no Windows host in
//! CI, so the two readings are:
//!
//! - if the outbound carve-out holds, the exceptions work and step 4 keeps the
//!   policy binding against allow rules created later;
//! - if it does not hold on some build, the exceptions lose to step 4's block
//!   rule, so the tunnel and the carrier are blocked: a dead tunnel, visible
//!   immediately. Step 6 still stops every OTHER application, so the failure mode
//!   is an outage, never an exposure.
//!
//! Shipping this policy therefore REQUIRES
//! `scripts/windows/killswitch-policy-smoke.ps1` to pass on the fleet's Windows
//! build: it decides the question with real traffic, and its persistence step
//! confirms that a rule created after the install no longer opens the egress.
//! Until that has run, the Windows policy is implemented and verified as far as a
//! non-Windows host can take it, and this document says exactly that.
//!
//! ## Residual risks
//!
//! - The override reading above: a Windows host decides it, and the failure mode
//!   is a dead tunnel rather than a leak.
//! - A Group Policy that forces the firewall off, that disables local rules, or
//!   that owns an enabled outbound allow rule this install cannot disable: each
//!   one fails the install instead of announcing a protection that is not there.
//! - Cancellation: the guard is armed BEFORE the first mutation, so an install
//!   future dropped between two PowerShell invocations still runs the synchronous
//!   teardown from `Drop`. A rollback that completed cleanly disarms it, and a
//!   partial one leaves it armed to retry.
//! - Cancellation, second half: every command runs to completion on a blocking
//!   task that holds a gate, and the teardown takes that gate before its first
//!   command, so the restoration starts only once the in-flight command has
//!   finished and its writes are the last ones. Termination timing is deliberately
//!   not relied on: tokio leaves a spawned child running when its output future is
//!   dropped, and on Windows `TerminateProcess` may return before the process is
//!   actually gone. The wait is bounded (a teardown that can hang process exit for
//!   ever is the worse failure) and an expired bound is logged as the race it is.
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
//! hosts, so the generated commands, the query parsers and the cmdlet behaviour
//! are not run against a real firewall here. Run
//! `scripts/windows/killswitch-policy-smoke.ps1` on a throwaway Windows host to
//! confirm the mechanism (a pre-existing allow rule survives the default block
//! until it is disabled; a plain allow rule survives the default block), and
//! re-run it after any change to the rule set below.
//!
//! ## Privileges
//!
//! `New-NetFirewallRule`, `Set-NetFirewallProfile`, `Disable-NetFirewallRule`,
//! `Enable-NetFirewallRule` and `Remove-NetFirewallRule` require an elevated
//! process (Administrator).
//!
//! ## Why not the WFP API with explicit weights
//!
//! A native WFP implementation (`FwpmFilterAdd` with our own sub-layer and
//! weights) could express a block rule with exceptions without depending on
//! `-OverrideBlockRules` or on disabling the operator's rules, and is the
//! eventual hardening. It needs FFI (this crate is
//! `#![forbid(unsafe_code)]`) and a Windows host to develop against. The
//! lifecycle is written against [`FirewallRunner`] so that swap stays local.

// On a host that is neither Windows nor running the test suite, the policy
// builders, the read-back verification and the lifecycle below are reachable
// only from the tests. They are deliberately host-independent so the policy and
// its rollback are exercised everywhere, which leaves the plain library build
// with items no production caller on that host can name.
#![cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]

use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
#[cfg(any(target_os = "windows", test))]
use std::time::Duration;

use crate::{KillswitchError, KillswitchOpts, validate_tun_name};

/// Common display-name prefix on every rule we install. Used by the install to
/// remove leftovers from a previous session, and by the read-back to tell our
/// rules from the operator's.
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
    /// The action the documented precedence gives an explicit block rule. This
    /// policy installs no block rule of its own (an explicit block would force
    /// the exceptions onto the IPsec-conditional `-OverrideBlockRules`
    /// mechanism, see the module doc), so on a Windows build the variant is
    /// carried only for the test model that pins the documented precedence.
    #[allow(dead_code)]
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
/// policy property (the effective set of enabled outbound allow rules), and a
/// test that only greps a generated command line cannot observe it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleSpec {
    /// Suffix after [`RULE_PREFIX`]; also the rule's identity on read-back.
    id: String,
    action: RuleAction,
    /// Permit the traffic even where another rule blocks it. Mandatory on every
    /// exception: the explicit block rule matches the same traffic.
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

/// The local profile settings the install overwrites and must put back.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileSnapshot {
    name: String,
    /// Local (PersistentStore) enable state. Restoring it is what returns the
    /// effective state too when no policy is forcing the profile.
    local_enabled: GpoBool,
    /// Local (PersistentStore) default outbound action.
    local_default_outbound_action: OutboundAction,
}

/// Everything the uninstall needs to leave the host as it found it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FirewallSnapshot {
    profiles: Vec<ProfileSnapshot>,
    /// Names of the enabled outbound allow rules that were not ours, in the
    /// order the snapshot found them. The install disables them and the
    /// teardown re-enables exactly these.
    foreign_allows: Vec<String>,
}

/// One mutation of the firewall configuration, in a form a model can apply and
/// PowerShell can render.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FirewallOp {
    /// Delete every rule carrying [`RULE_PREFIX`].
    DeleteOurRules,
    /// Turn the firewall on for every profile we depend on.
    EnableProfiles,
    /// Leave the profiles blocking by default.
    SetDefaultOutboundActionBlock,
    /// Disable the pre-existing outbound allow rules, by rule name.
    DisableForeignAllows(Vec<String>),
    /// Create one of our rules.
    CreateRule(RuleSpec),
    /// Re-enable rules a previous install disabled, by rule name.
    EnableRules(Vec<String>),
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
    /// Read what the install is about to overwrite or disable.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] when a query fails or does not report all
    /// three profiles.
    async fn snapshot(&self) -> Result<FirewallSnapshot, KillswitchError>;

    /// Apply one mutation.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] when the command fails.
    async fn apply(&self, op: &FirewallOp) -> Result<(), KillswitchError>;

    /// Best-effort SYNCHRONOUS teardown, for [`Drop`], which cannot await.
    ///
    /// Implementations must be bounded: a wedged PowerShell must not hang process
    /// teardown. The asynchronous path is
    /// [`uninstall_with_runner`](self), which reports errors.
    fn sync_teardown(&self, snapshot: &FirewallSnapshot);

    /// Read the ACTIVE store back and fail unless every protection the install
    /// claims is actually in effect.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] when a profile is not effectively enabled,
    /// does not block by default, has local rules disabled by policy, or when an
    /// expected rule is missing, misconfigured or accompanied by an enabled
    /// outbound allow rule that is not ours.
    async fn verify(&self, rules: &[RuleSpec]) -> Result<(), KillswitchError>;
}

// ── Policy construction ──────────────────────────────────────────────

/// The rules of the installed policy.
fn build_rules(opts: &KillswitchOpts, daemon_exe_path: &str) -> Vec<RuleSpec> {
    let allow = |id: String,
                 iface: Option<String>,
                 udp: bool,
                 remote: Option<Remote>,
                 remote_port: Option<u16>,
                 program: Option<String>| RuleSpec {
        id,
        action: RuleAction::Allow,
        // Every exception must outrank the block rule, so this is never optional
        // for an Allow rule here.
        override_block_rules: true,
        iface,
        udp,
        remote,
        remote_port,
        program,
    };

    let mut rules = Vec::with_capacity(8 + opts.exit_addrs.len());

    // The rule the policy rests on, and the reason it stays binding for the whole
    // session: an explicit block, which Windows Firewall documents as taking
    // precedence over any conflicting allow rule, including one created later.
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

    // Loopback explicitly, rather than relying on an implicit exemption: the
    // other platform backends in this crate allow it, and a same-host service
    // that stopped working would look like a killswitch bug.
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

/// The install sequence for `rules` on a host in state `snapshot`.
fn install_ops(rules: &[RuleSpec], snapshot: &FirewallSnapshot) -> Vec<FirewallOp> {
    let mut ops = Vec::with_capacity(rules.len() + 5);
    // Leftovers first. An exception from a session that ended abnormally (an
    // allow-lan rule installed when the LAN was allowed and not allowed now)
    // would otherwise survive the whole install: the rules we add do not
    // contradict it, and a check of the expected set never looks at it.
    ops.push(FirewallOp::DeleteOurRules);
    // Enable first: with the firewall off, nothing below filters anything.
    ops.push(FirewallOp::EnableProfiles);
    // The default block: nothing egresses unless an allow rule matches.
    ops.push(FirewallOp::SetDefaultOutboundActionBlock);
    // The step that makes the policy hold: with the operator's own allow rules
    // disabled, the default block applies to them too. This is a categorical
    // property, not a specificity contest.
    if !snapshot.foreign_allows.is_empty() {
        ops.push(FirewallOp::DisableForeignAllows(
            snapshot.foreign_allows.clone(),
        ));
    }
    ops.extend(rules.iter().cloned().map(FirewallOp::CreateRule));
    ops
}

/// The teardown sequence: remove our rules, put the disabled rules back, then
/// restore the captured profile settings.
fn uninstall_ops(snapshot: &FirewallSnapshot) -> Vec<FirewallOp> {
    let mut ops = Vec::with_capacity(snapshot.profiles.len() + 2);
    ops.push(FirewallOp::DeleteOurRules);
    if !snapshot.foreign_allows.is_empty() {
        ops.push(FirewallOp::EnableRules(snapshot.foreign_allows.clone()));
    }
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
        FirewallOp::DeleteOurRules => {
            format!("Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' | Remove-NetFirewallRule")
        }
        FirewallOp::EnableProfiles => format!(
            "Set-NetFirewallProfile -Profile {} -Enabled True",
            FIREWALL_PROFILES.join(",")
        ),
        FirewallOp::SetDefaultOutboundActionBlock => format!(
            "Set-NetFirewallProfile -Profile {} -DefaultOutboundAction Block",
            FIREWALL_PROFILES.join(",")
        ),
        FirewallOp::DisableForeignAllows(names) => format!(
            "Disable-NetFirewallRule -Name {} -ErrorAction Stop",
            quoted_name_list(names)
        ),
        FirewallOp::CreateRule(rule) => render_create_rule(rule),
        FirewallOp::EnableRules(names) => format!(
            "Enable-NetFirewallRule -Name {} -ErrorAction Stop",
            quoted_name_list(names)
        ),
        FirewallOp::RestoreProfile(profile) => format!(
            "Set-NetFirewallProfile -Profile {} -Enabled {} -DefaultOutboundAction {}",
            profile.name,
            profile.local_enabled.as_token(),
            profile.local_default_outbound_action.as_token()
        ),
    };
    vec!["-NoProfile".into(), "-Command".into(), command]
}

/// Renders rule names as a PowerShell single-quoted list.
fn quoted_name_list(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("'{}'", escape_powershell_single_quoted(name)))
        .collect::<Vec<_>>()
        .join(",")
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
const QUERY_PROFILES_LOCAL: &str = "Get-NetFirewallProfile -PolicyStore PersistentStore \
     -Profile Domain,Private,Public | Format-List Name,Enabled,DefaultOutboundAction";

/// Query the EFFECTIVE profile settings: the resultant set, Group Policy
/// included. Reading the persistent store instead would report what we wrote
/// rather than what is filtering.
const QUERY_PROFILES_EFFECTIVE: &str = "Get-NetFirewallProfile -PolicyStore ActiveStore \
     -Profile Domain,Private,Public | Format-List Name,Enabled,DefaultOutboundAction,\
     AllowLocalFirewallRules";

/// Query every enabled outbound allow rule that is not ours, in a line-oriented
/// form. This is the categorical check: with the profiles blocking by default,
/// such a rule is the only way traffic leaves the host outside our exceptions.
fn query_foreign_allows_command() -> String {
    format!(
        "Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound \
         -Action Allow -Enabled True | Where-Object {{ $_.DisplayName -notlike \
         '{RULE_PREFIX}*' }} | ForEach-Object {{ 'FOREIGN|' + $_.Name + '|' + \
         $_.DisplayName }}"
    )
}

/// Query our own rules together with their conditions, in a line-oriented form
/// so one round trip answers for every rule.
fn query_our_rules_command() -> String {
    format!(
        "Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName '{RULE_PREFIX}*' | \
         ForEach-Object {{ $s = $_ | Get-NetFirewallSecurityFilter; \
         $a = $_ | Get-NetFirewallApplicationFilter; \
         $p = $_ | Get-NetFirewallPortFilter; $d = $_ | Get-NetFirewallAddressFilter; \
         $i = $_ | Get-NetFirewallInterfaceFilter; \
         'RULE|' + $_.DisplayName + '|' + $_.Direction + '|' + $_.Action + '|' + \
         $_.Enabled + '|' + $s.OverrideBlockRules + '|' + $a.Program + '|' + \
         $p.Protocol + '|' + [string]$d.RemoteAddress + '|' + [string]$p.RemotePort \
         + '|' + [string]$i.InterfaceAlias }}"
    )
}

/// One parsed `Format-List` profile block. Every field is optional because a
/// partially reported profile must be a failure, not a default.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileSetting {
    name: String,
    enabled: Option<GpoBool>,
    default_outbound_action: Option<OutboundAction>,
    /// `AllowLocalFirewallRules`: when a policy sets this to False, local rules
    /// (ours) are ignored, and a policy made of local rules filters nothing.
    local_rules_allowed: Option<GpoBool>,
}

/// Parses `Name` / `Enabled` / `DefaultOutboundAction` / `AllowLocalFirewallRules`
/// blocks from `Get-NetFirewallProfile | Format-List`.
///
/// Pure, so the parser is tested against documented-shape fixtures without
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
                local_rules_allowed: None,
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
            "AllowLocalFirewallRules" => {
                if let Some(current) = settings.last_mut() {
                    current.local_rules_allowed = GpoBool::parse(value);
                }
            }
            _ => {}
        }
    }
    settings
}

/// One parsed `RULE|...` line from [`query_our_rules_command`], reduced to the
/// conditions the verification compares.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleRow {
    display_name: String,
    direction: String,
    action: String,
    enabled: Option<GpoBool>,
    override_block_rules: bool,
    program: Option<String>,
    protocol: Option<String>,
    remote_address: Option<String>,
    remote_port: Option<String>,
    iface: Option<String>,
}

impl RuleRow {
    /// Whether a condition read back as `actual` matches what the policy asked
    /// for. A condition the policy requires but the read-back did not report is
    /// a mismatch: a rule whose scope cannot be read is not a rule whose scope
    /// can be trusted.
    fn condition_matches(expected: Option<&str>, actual: Option<&str>) -> bool {
        let Some(expected) = expected else {
            return true;
        };
        let Some(actual) = actual else {
            return false;
        };
        // Windows paths, alias lists and protocol names are case-insensitive;
        // `contains` also absorbs the space-joined form PowerShell produces for
        // a one-element array.
        actual
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase())
    }
}

/// Parses the line-oriented rule read-back. Unparseable lines are skipped: a
/// rule we cannot read is a rule we cannot confirm, and the verification fails
/// on a missing rule anyway.
fn parse_rule_rows(out: &str) -> Vec<RuleRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("RULE|") else {
            continue;
        };
        let fields: Vec<&str> = rest.split('|').collect();
        if fields.len() != 10 {
            continue;
        }
        let value = |raw: &str| {
            let raw = raw.trim();
            // PowerShell renders an absent property as an empty string.
            if raw.is_empty() {
                None
            } else {
                Some(raw.to_owned())
            }
        };
        rows.push(RuleRow {
            display_name: fields[0].to_owned(),
            direction: fields[1].to_owned(),
            action: fields[2].to_owned(),
            enabled: GpoBool::parse(fields[3]),
            override_block_rules: GpoBool::parse(fields[4]) == Some(GpoBool::True),
            program: value(fields[5]),
            protocol: value(fields[6]),
            remote_address: value(fields[7]),
            remote_port: value(fields[8]),
            iface: value(fields[9]),
        });
    }
    rows
}

/// One parsed `FOREIGN|...` line: an enabled outbound allow rule that is not
/// ours.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ForeignRow {
    name: String,
    display_name: String,
}

fn parse_foreign_rows(out: &str) -> Vec<ForeignRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("FOREIGN|") else {
            continue;
        };
        let (name, display_name) = rest.split_once('|').unwrap_or((rest, rest));
        rows.push(ForeignRow {
            name: name.trim().to_owned(),
            display_name: display_name.trim().to_owned(),
        });
    }
    rows
}

/// How many offending rule names an error message names before it stops. Enough
/// to act on, bounded so a machine with a hundred of them cannot flood a log.
const MAX_NAMED_RULES: usize = 3;

/// Evaluates the read-back against the policy we intended to install.
///
/// Pure and total: it either confirms every protection or names the one that is
/// missing. This is the function that decides whether the install may report
/// success, so it is exercised directly with fixtures.
fn check_effective_state(
    profiles_out: &str,
    rules_out: &str,
    foreign_out: &str,
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
        if setting.local_rules_allowed == Some(GpoBool::False) {
            return Err(KillswitchError::Windows(format!(
                "the active policy for the {name} profile ignores local firewall \
                 rules, so this killswitch cannot filter anything on this host"
            )));
        }
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
        // The load-bearing check for an exception: without the override it loses
        // to the block rule, so the traffic it is meant to permit (the tunnel, the
        // carrier) stays blocked while a less careful install would report
        // success. The block rule itself must NOT carry it.
        match rule.action {
            RuleAction::Allow if !row.override_block_rules => {
                return Err(KillswitchError::Windows(format!(
                    "the exception {name} does not carry OverrideBlockRules in the \
                     active policy, so the block rule outranks it and the traffic it \
                     is meant to permit stays blocked"
                )));
            }
            RuleAction::Block if row.override_block_rules => {
                return Err(KillswitchError::Windows(format!(
                    "the block rule {name} carries OverrideBlockRules in the active \
                     policy, which would make it outrank the rules it is meant to \
                     overrule"
                )));
            }
            _ => {}
        }
        // The conditions matter as much as the rule: an exception that lost its
        // `-Program` scope would hand the off-tunnel path to any process, and one
        // that lost its `-RemoteAddress` scope would hand it any destination.
        if !RuleRow::condition_matches(rule.program.as_deref(), row.program.as_deref()) {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} does not carry the expected -Program scope in the \
                 active policy (reported {:?})",
                row.program
            )));
        }
        if !RuleRow::condition_matches(rule.iface.as_deref(), row.iface.as_deref()) {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} does not carry the expected -InterfaceAlias scope in \
                 the active policy (reported {:?})",
                row.iface
            )));
        }
        if rule.udp && !RuleRow::condition_matches(Some("UDP"), row.protocol.as_deref()) {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} is not protocol-scoped to UDP in the active policy \
                 (reported {:?})",
                row.protocol
            )));
        }
        let remote = rule.remote.as_ref().map(Remote::as_token);
        if !RuleRow::condition_matches(remote.as_deref(), row.remote_address.as_deref()) {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} does not carry the expected -RemoteAddress scope in the \
                 active policy (reported {:?})",
                row.remote_address
            )));
        }
        let port = rule.remote_port.map(|p| p.to_string());
        if !RuleRow::condition_matches(port.as_deref(), row.remote_port.as_deref()) {
            return Err(KillswitchError::Windows(format!(
                "the rule {name} does not carry the expected -RemotePort scope in the \
                 active policy (reported {:?})",
                row.remote_port
            )));
        }
    }

    // A rule of ours we did not expect is a leftover from a session whose
    // teardown never ran, or a rule this install failed to remove. It grants
    // whatever it was created for while the policy claims otherwise, so it is a
    // failure rather than a detail.
    let unexpected: Vec<&str> = rows
        .iter()
        .map(|r| r.display_name.as_str())
        .filter(|name| !expected.iter().any(|e| e.display_name() == *name))
        .collect();
    if !unexpected.is_empty() {
        return Err(KillswitchError::Windows(format!(
            "the active firewall policy holds {} rule(s) of ours that this install \
             did not create: {}",
            unexpected.len(),
            unexpected
                .iter()
                .take(MAX_NAMED_RULES)
                .copied()
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    // The categorical property the whole policy rests on: with the profiles
    // blocking by default and no other enabled allow rule, no traffic leaves the
    // host outside our exceptions. The offending rule names are named (bounded)
    // because the operator has to act on this on their own machine.
    let foreign = parse_foreign_rows(foreign_out);
    if !foreign.is_empty() {
        return Err(KillswitchError::Windows(format!(
            "{} enabled outbound allow rule(s) that this install did not disable \
             would still let traffic out: {}",
            foreign.len(),
            foreign
                .iter()
                .take(MAX_NAMED_RULES)
                .map(|r| r.display_name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

// The install / teardown state machine lives here, UNGATED, so the policy and
// its rollback are driven for real on every host by the test module. Only the
// PowerShell binding and the guard type below are Windows-only.

/// Installs the policy and returns the captured state with the guard DISARMED.
///
/// A test seam: the tests drive the teardown themselves and want the outcome
/// observed rather than a `Drop` retry afterwards. Production goes through
/// [`KillswitchGuard::install`], which keeps the guard armed.
///
/// # Errors
///
/// Same as [`KillswitchGuard::install`].
#[cfg(test)]
async fn install_without_guard<R: FirewallRunner>(
    opts: &KillswitchOpts,
    runner: Arc<R>,
    daemon_exe_path: &str,
) -> Result<FirewallSnapshot, KillswitchError> {
    let mut guard = KillswitchGuard::install(opts, runner, daemon_exe_path).await?;
    guard.armed = false;
    Ok(guard.snapshot.clone())
}

/// The installed policy: the captured state, the runner, and whether the
/// teardown still has to happen.
///
/// `Drop` runs the synchronous teardown while the guard is armed. The flag is
/// cleared only once `uninstall` has actually completed: a cancelled or failed
/// uninstall must still leave the operator's rules re-enabled and the captured
/// profile settings restored, which is the whole reason the guard exists. Before
/// this was a bare `bool` cleared at the top of `uninstall`, cancelling the
/// future between two PowerShell invocations silently skipped the restoration.
struct KillswitchGuard<R: FirewallRunner> {
    runner: Arc<R>,
    snapshot: FirewallSnapshot,
    armed: bool,
}

impl<R: FirewallRunner> std::fmt::Debug for KillswitchGuard<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KillswitchGuard")
            .field("runner", &self.runner)
            .field("snapshot", &self.snapshot)
            .field("armed", &self.armed)
            .finish()
    }
}

impl<R: FirewallRunner> KillswitchGuard<R> {
    /// Install the policy through `runner` and return the armed guard.
    ///
    /// The guard is armed BEFORE the first mutation: from here on every await
    /// point is cancel-safe, because dropping an armed guard runs the synchronous
    /// teardown. Arming it only once the install had returned left the window
    /// between the first `Set-NetFirewallProfile` and that return with nothing able
    /// to restore the captured state.
    ///
    /// # Errors
    ///
    /// - [`KillswitchError::InvalidInput`] if `opts.tun_name` is invalid.
    /// - [`KillswitchError::Windows`] if a command fails, a profile cannot be
    ///   enabled, or the read-back does not confirm the policy.
    async fn install(
        opts: &KillswitchOpts,
        runner: Arc<R>,
        daemon_exe_path: &str,
    ) -> Result<Self, KillswitchError> {
        validate_tun_name(&opts.tun_name)?;
        // Reading the current state is not a mutation, so nothing has to be
        // restored when it fails.
        let snapshot = runner.snapshot().await?;
        let rules = build_rules(opts, daemon_exe_path);
        let mut guard = Self {
            runner,
            snapshot,
            armed: true,
        };
        guard.apply_policy(&rules).await?;
        Ok(guard)
    }

    /// Apply the policy and confirm it, rolling back when either step fails.
    ///
    /// A rollback that completed cleanly disarms the guard, since there is then
    /// nothing left to restore; a partial one leaves it armed so `Drop` retries the
    /// idempotent teardown commands.
    async fn apply_policy(&mut self, rules: &[RuleSpec]) -> Result<(), KillswitchError> {
        let runner = self.runner.clone();
        if let Err(error) = apply_ops(runner.as_ref(), &install_ops(rules, &self.snapshot)).await {
            if rollback(runner.as_ref(), &self.snapshot, &error).await {
                self.armed = false;
            }
            return Err(error);
        }
        if let Err(error) = runner.verify(rules).await {
            // The policy is not in effect, so it must not stay half-applied under
            // our name, and the install must not report success.
            if rollback(runner.as_ref(), &self.snapshot, &error).await {
                self.armed = false;
            }
            return Err(error);
        }
        tracing::info!(
            disabled_rules = self.snapshot.foreign_allows.len(),
            "Warren Windows killswitch installed and verified"
        );
        Ok(())
    }

    /// Remove our rules, re-enable the ones we disabled, then restore the
    /// captured profile settings.
    ///
    /// The guard stays armed unless this completes: a failure leaves it able to
    /// retry from `Drop`, and a cancellation drops it mid-teardown, which is
    /// exactly when `Drop` has to finish the job.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] if a step failed.
    async fn uninstall(mut self) -> Result<(), KillswitchError> {
        let result = uninstall_with_runner(self.runner.as_ref(), &self.snapshot).await;
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl<R: FirewallRunner> Drop for KillswitchGuard<R> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        tracing::warn!(
            "Warren Windows killswitch guard dropped without a completed uninstall - \
             running the bounded synchronous teardown"
        );
        self.runner.sync_teardown(&self.snapshot);
    }
}

/// Removes our rules, puts the disabled rules back, then restores the captured
/// profile settings.
///
/// Every step runs even after one fails: leaving the host with the operator's
/// rules disabled and the profile defaults unrestored is the worse outcome. The
/// first failure is what surfaces.
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
/// Best-effort restore of the captured state. Returns whether every step was
/// applied, which decides whether the guard still has anything to retry.
async fn rollback<R: FirewallRunner>(
    runner: &R,
    snapshot: &FirewallSnapshot,
    cause: &KillswitchError,
) -> bool {
    tracing::error!(
        error = %cause,
        "killswitch install failed; restoring the captured firewall settings"
    );
    let mut restored = true;
    for op in uninstall_ops(snapshot) {
        if let Err(e) = runner.apply(&op).await {
            tracing::warn!(
                error = %e,
                "killswitch rollback command failed (best-effort)"
            );
            restored = false;
        }
    }
    restored
}

// ── Runtime exec (Windows only) ──────────────────────────────────────

/// PowerShell-based Windows killswitch. Mirror of [`super::LinuxKillswitch`]
/// / [`super::MacosKillswitch`] for the install/uninstall lifecycle.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct WindowsKillswitch(KillswitchGuard<PowershellRunner>);

#[cfg(target_os = "windows")]
impl WindowsKillswitch {
    /// Install the killswitch policy and confirm it is in effect.
    ///
    /// Idempotent: it removes any rule of ours before installing, so a previous
    /// session that ended without its teardown cannot change this one's policy.
    ///
    /// # Errors
    ///
    /// - [`KillswitchError::InvalidInput`] if `opts.tun_name` is invalid.
    /// - [`KillswitchError::Windows`] if PowerShell fails, the process lacks
    ///   Administrator privileges, the running binary's own path could not be
    ///   resolved (needed for the WFP app-id scoping fix), a firewall profile
    ///   cannot be enabled, a pre-existing allow rule cannot be disabled, or the
    ///   read-back does not confirm the policy.
    pub async fn install(opts: &KillswitchOpts) -> Result<Self, KillswitchError> {
        let daemon_exe_path = resolve_daemon_exe_path()?;
        KillswitchGuard::install(
            opts,
            Arc::new(PowershellRunner::default()),
            &daemon_exe_path,
        )
        .await
        .map(Self)
    }

    /// Remove our rules, re-enable the rules we disabled, then restore the
    /// captured profile settings.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] if a step fails; the remaining steps still
    /// run.
    pub async fn uninstall(self) -> Result<(), KillswitchError> {
        self.0.uninstall().await
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
/// it, and answers the read-back queries with the same shell. Every command goes
/// through [`CommandGate`], so the guard's synchronous teardown cannot start while
/// one is still applying.
#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct PowershellRunner {
    gate: CommandGate,
}

#[cfg(target_os = "windows")]
impl FirewallRunner for PowershellRunner {
    async fn snapshot(&self) -> Result<FirewallSnapshot, KillswitchError> {
        let out = run_powershell_capture(self.gate.clone(), QUERY_PROFILES_LOCAL).await?;
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
                // guessed: restoring a wrong default would change a setting the
                // operator never asked us to touch.
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

        let foreign = parse_foreign_rows(
            &run_powershell_capture(self.gate.clone(), &query_foreign_allows_command()).await?,
        );
        Ok(FirewallSnapshot {
            profiles,
            foreign_allows: foreign.into_iter().map(|r| r.name).collect(),
        })
    }

    async fn apply(&self, op: &FirewallOp) -> Result<(), KillswitchError> {
        run_powershell(self.gate.clone(), &render_op(op)).await
    }

    fn sync_teardown(&self, snapshot: &FirewallSnapshot) {
        // The restoration must not start while a command is still applying: the gate
        // is what makes that an ordering guarantee rather than a hope about how
        // quickly a termination request lands. It is bounded, because a teardown that
        // can hang process exit for ever is the worse failure.
        if self.gate.take_blocking(SYNC_CLEANUP_TIMEOUT).is_none() {
            tracing::error!(
                timeout = ?SYNC_CLEANUP_TIMEOUT,
                "a firewall command was still running when the guard restored: the \
                 restoration ran after the bound and a late command may have applied \
                 a change after it"
            );
        }
        for cmd in uninstall_ops(snapshot).iter().map(render_op) {
            if run_sync_bounded("powershell.exe", &cmd, SYNC_CLEANUP_TIMEOUT).is_none() {
                tracing::warn!(
                    timeout = ?SYNC_CLEANUP_TIMEOUT,
                    "killswitch synchronous teardown command did not complete in time (killed)"
                );
            }
        }
    }

    async fn verify(&self, rules: &[RuleSpec]) -> Result<(), KillswitchError> {
        let profiles = run_powershell_capture(self.gate.clone(), QUERY_PROFILES_EFFECTIVE).await?;
        let ours = run_powershell_capture(self.gate.clone(), &query_our_rules_command()).await?;
        let foreign =
            run_powershell_capture(self.gate.clone(), &query_foreign_allows_command()).await?;
        check_effective_state(&profiles, &ours, &foreign, rules)
    }
}

/// Serializes an in-flight PowerShell command with the guard's synchronous
/// teardown.
///
/// Tokio leaves a spawned child running when its output future is dropped, and
/// `kill_on_drop` only *requests* termination: on Windows `TerminateProcess` may
/// return before the process is actually gone, so the guard's restoration could
/// still race a command that has not finished applying its change. Instead of
/// depending on termination timing, every command runs to completion on a blocking
/// task that holds this gate (a blocking task is not cancelled when the future
/// waiting on it is dropped), and the teardown takes the gate before its first
/// command. The restoration therefore starts only once the in-flight command has
/// finished, and its writes are the last ones.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Default, Clone)]
struct CommandGate {
    gate: Arc<std::sync::Mutex<()>>,
}

#[cfg(any(target_os = "windows", test))]
impl CommandGate {
    /// Runs `f` while holding the gate. Blocking; the production callers run it on
    /// a blocking task.
    fn run<T>(&self, f: impl FnOnce() -> T) -> T {
        // A poisoned gate means another command panicked; the ordering guarantee is
        // what matters, not the panic, so the guard is taken either way.
        let _held = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f()
    }

    /// Takes the gate, waiting at most `timeout` for an in-flight command.
    ///
    /// `None` means the wait expired: the caller proceeds anyway (a teardown that
    /// can hang process exit forever is worse than a logged race) and says so.
    fn take_blocking(&self, timeout: Duration) -> Option<std::sync::MutexGuard<'_, ()>> {
        let deadline = std::time::Instant::now() + timeout;
        let mut poll = Duration::from_millis(1);
        loop {
            match self.gate.try_lock() {
                Ok(held) => return Some(held),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    return Some(poisoned.into_inner());
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(poll);
            poll = (poll * 2).min(Duration::from_millis(64));
        }
    }
}

/// Runs `program args...` with the gate held, on a blocking task.
///
/// The command runs to completion and its child is reaped before the gate is
/// released, so a dropped future leaves the ordering guarantee intact: whatever
/// the command applied is visible to the teardown that follows it.
#[cfg(any(target_os = "windows", test))]
async fn run_gated_command(
    gate: CommandGate,
    program: &'static str,
    args: Vec<String>,
) -> Result<String, KillswitchError> {
    tokio::task::spawn_blocking(move || {
        gate.run(|| {
            let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
            let out = std::process::Command::new(program)
                .args(&str_args)
                .stdin(std::process::Stdio::null())
                .output()
                .map_err(|e| KillswitchError::Windows(format!("spawn {program}: {e}")))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                return Err(KillswitchError::Windows(format!(
                    "{program} failed: {}",
                    stderr.trim()
                )));
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        })
    })
    .await
    .map_err(|e| KillswitchError::Windows(format!("join the {program} task: {e}")))?
}

/// Runs one PowerShell command through the gate and returns its stdout.
#[cfg(target_os = "windows")]
async fn run_powershell_capture(
    gate: CommandGate,
    command: &str,
) -> Result<String, KillswitchError> {
    run_gated_command(
        gate,
        "powershell.exe",
        vec!["-NoProfile".into(), "-Command".into(), command.to_owned()],
    )
    .await
}

#[cfg(target_os = "windows")]
async fn run_powershell(gate: CommandGate, args: &[String]) -> Result<(), KillswitchError> {
    run_gated_command(gate, "powershell.exe", args.to_vec())
        .await
        .map(|_| ())
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
    /// Stable rule identities, the way the read-back reports them.
    const FOREIGN_RULE_NAME: &str = "{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}";
    const FOREIGN_RULE_DISPLAY: &str = "Microsoft Edge";

    fn rendered_ops(ops: &[FirewallOp]) -> Vec<String> {
        ops.iter().map(|op| render_op(op).join(" ")).collect()
    }

    // ---- the policy shape --------------------------------------------

    #[test]
    fn the_policy_is_a_block_rule_plus_overriding_exceptions() {
        // Design invariant, not a style preference. The block rule is what keeps
        // the policy binding for the whole session (an allow rule created later
        // loses to it), and the exceptions are what keeps the tunnel alive under
        // that block rule, so every exception must carry the override and the
        // block rule must not.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let block = rules.first().expect("the policy has rules");
        assert_eq!(block.action, RuleAction::Block, "{rules:#?}");
        assert!(
            !block.override_block_rules,
            "the block rule must not carry the override, or it would outrank the \
             rules it exists to overrule"
        );
        assert!(
            rules.iter().skip(1).all(|r| r.action == RuleAction::Allow),
            "everything after the block rule is an exception: {rules:#?}"
        );
        for command in rendered_ops(&install_ops(
            &rules,
            &FirewallSnapshot {
                profiles: Vec::new(),
                foreign_allows: vec![FOREIGN_RULE_NAME.to_owned()],
            },
        )) {
            if command.contains("-Action Allow") {
                assert!(
                    command.contains("-OverrideBlockRules True"),
                    "an exception without the override loses to the block rule: {command}"
                );
            }
            if command.contains("-Action Block") {
                assert!(
                    !command.contains("-OverrideBlockRules"),
                    "the block rule must not carry the override: {command}"
                );
            }
        }
    }

    #[test]
    fn install_deletes_leftovers_enables_the_profiles_then_blocks_by_default() {
        let ops = install_ops(&build_rules(&opts_minimal(), TEST_DAEMON_EXE), &snapshot());
        assert_eq!(
            ops[0],
            FirewallOp::DeleteOurRules,
            "a rule of ours left by a session that ended abnormally must go before \
             the policy is rebuilt: {ops:#?}"
        );
        assert_eq!(ops[1], FirewallOp::EnableProfiles);
        assert_eq!(ops[2], FirewallOp::SetDefaultOutboundActionBlock);
        for op in &ops[3..] {
            assert!(
                !matches!(op, FirewallOp::DeleteOurRules),
                "the removal must not be interleaved with the rule creation"
            );
        }
        let block = ops
            .iter()
            .position(|op| matches!(op, FirewallOp::CreateRule(r) if r.action == RuleAction::Block))
            .expect("the block rule is created");
        let first_exception = ops
            .iter()
            .position(|op| matches!(op, FirewallOp::CreateRule(r) if r.action == RuleAction::Allow))
            .expect("the exceptions are created");
        assert!(
            block < first_exception,
            "the block rule must exist before any exception, so no exception is ever \
             live without it: {ops:#?}"
        );
    }

    #[test]
    fn the_operator_rules_are_disabled_before_our_exceptions_are_created() {
        let mut snapshot = snapshot();
        snapshot.foreign_allows = vec![FOREIGN_RULE_NAME.to_owned()];
        let commands = rendered_ops(&install_ops(
            &build_rules(&opts_minimal(), TEST_DAEMON_EXE),
            &snapshot,
        ));
        let disable = commands
            .iter()
            .position(|c| c.contains("Disable-NetFirewallRule"))
            .expect("the operator's allow rules must be disabled");
        let first_exception = commands
            .iter()
            .position(|c| c.contains("New-NetFirewallRule"))
            .expect("our exceptions must be created");
        assert!(
            disable < first_exception,
            "the default block alone does not outrank a pre-existing allow rule, so \
             the rule must be disabled before the policy is announced: {commands:#?}"
        );
        assert!(
            commands[disable].contains(FOREIGN_RULE_NAME),
            "the disabled rules must be named by their stable Name: {:#?}",
            commands[disable]
        );
    }

    #[test]
    fn uninstall_re_enables_the_disabled_rules_before_restoring_the_profiles() {
        let mut snapshot = snapshot();
        snapshot.foreign_allows = vec![FOREIGN_RULE_NAME.to_owned()];
        let commands = rendered_ops(&uninstall_ops(&snapshot));
        assert!(
            commands[0].contains("Remove-NetFirewallRule"),
            "our rules come off first: {commands:#?}"
        );
        let enable = commands
            .iter()
            .position(|c| c.contains("Enable-NetFirewallRule"))
            .expect("the rules we disabled must be put back");
        let restore = commands
            .iter()
            .position(|c| c.contains("Set-NetFirewallProfile"))
            .expect("the profile settings must be restored");
        assert!(
            enable < restore,
            "restoring the profile defaults before re-enabling the operator's rules \
             would leave a window in which neither filters as before: {commands:#?}"
        );
        assert_eq!(commands.len(), 1 + 1 + FIREWALL_PROFILES.len());
    }

    fn snapshot() -> FirewallSnapshot {
        FirewallSnapshot {
            profiles: FIREWALL_PROFILES
                .iter()
                .map(|name| ProfileSnapshot {
                    name: (*name).to_owned(),
                    local_enabled: GpoBool::True,
                    local_default_outbound_action: OutboundAction::Allow,
                })
                .collect(),
            foreign_allows: Vec::new(),
        }
    }

    #[test]
    fn install_includes_tun_alias_allow_rule() {
        // Without this exception the tunnel is blocked once the profiles block
        // by default: the tunnel never opens.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let commands = rendered_ops(&install_ops(&rules, &snapshot()));
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
            rendered_ops(&install_ops(&rules, &snapshot()))
                .iter()
                .any(|c| c.contains(&format!("-Program '{TEST_DAEMON_EXE}'"))),
            "the app-id scope must reach the rendered command"
        );
    }

    #[test]
    fn program_path_with_embedded_single_quote_is_escaped_for_powershell() {
        let path = r"C:\Program Files\O'Brien\warren-daemon.exe";
        let rules = build_rules(&opts_minimal(), path);
        let exit_command = rendered_ops(&install_ops(&rules, &snapshot()))
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
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let commands = rendered_ops(&install_ops(&rules, &snapshot()));
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
        let rules = build_rules(&o, TEST_DAEMON_EXE);
        let commands = rendered_ops(&install_ops(&rules, &snapshot()));
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
                rules.iter().any(|r| r.remote_port == Some(port)),
                "allow_dhcp must add an exception for port {port}"
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
            "every rule must be removable by the prefix the install and the read-back \
             match: {names:?}"
        );
        let unique: std::collections::BTreeSet<&String> = names.iter().collect();
        assert_eq!(
            unique.len(),
            names.len(),
            "duplicate display names: {names:?}"
        );
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
            foreign_allows: Vec::new(),
        };
        let commands = rendered_ops(&uninstall_ops(&snapshot));
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
AllowLocalFirewallRules    : True

Name                       : Private
Enabled                    : True
DefaultOutboundAction      : Block
AllowLocalFirewallRules    : True

Name                       : Public
Enabled                    : True
DefaultOutboundAction      : Block
AllowLocalFirewallRules    : True
";

    /// The `RULE|...` lines the read-back command emits, built from the policy we
    /// intended, so the acceptance case really is the installed one.
    fn readback_for(rules: &[RuleSpec]) -> String {
        let mut out = String::new();
        for rule in rules {
            let _ = writeln!(
                out,
                "RULE|{}|Outbound|{}|True|{}|{}|{}|{}|{}|{}",
                rule.display_name(),
                rule.action.as_token(),
                rule.override_block_rules,
                rule.program.as_deref().unwrap_or(""),
                if rule.udp { "UDP" } else { "Any" },
                rule.remote
                    .as_ref()
                    .map(Remote::as_token)
                    .unwrap_or_default(),
                rule.remote_port.map(|p| p.to_string()).unwrap_or_default(),
                rule.iface.as_deref().unwrap_or("")
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
        assert_eq!(settings[0].local_rules_allowed, Some(GpoBool::True));
        assert_eq!(settings[2].name, "Public");
    }

    #[test]
    fn parse_profile_settings_yields_nothing_on_garbage_input() {
        assert!(parse_profile_settings("").is_empty());
        assert!(parse_profile_settings("not a profile listing").is_empty());
    }

    #[test]
    fn parse_rule_rows_reads_every_condition() {
        let rows = parse_rule_rows(
            "RULE|warren-killswitch-allow-tun|Outbound|Allow|True|True||Any|||warren0\n",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].display_name, "warren-killswitch-allow-tun");
        assert_eq!(rows[0].action, "Allow");
        assert_eq!(rows[0].enabled, Some(GpoBool::True));
        assert!(rows[0].override_block_rules);
        assert_eq!(rows[0].protocol.as_deref(), Some("Any"));
        assert_eq!(rows[0].iface.as_deref(), Some("warren0"));
        assert!(rows[0].remote_address.is_none());
        assert!(rows[0].program.is_none());
        assert!(parse_rule_rows("noise").is_empty());
    }

    #[test]
    fn parse_foreign_rows_reads_the_name_and_the_display_name() {
        let rows = parse_foreign_rows(&format!(
            "FOREIGN|{FOREIGN_RULE_NAME}|{FOREIGN_RULE_DISPLAY}\n"
        ));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, FOREIGN_RULE_NAME);
        assert_eq!(rows[0].display_name, FOREIGN_RULE_DISPLAY);
        assert!(parse_foreign_rows("").is_empty());
    }

    #[test]
    fn check_effective_state_accepts_the_policy_it_would_install() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        check_effective_state(EFFECTIVE_BLOCKING, &readback_for(&rules), "", &rules)
            .expect("the policy we install must pass the read-back");
    }

    #[test]
    fn check_effective_state_rejects_a_profile_that_is_not_enabled() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let out = EFFECTIVE_BLOCKING.replace(
            "Name                       : Public\nEnabled                    : True",
            "Name                       : Public\nEnabled                    : False",
        );
        let err = check_effective_state(&out, &readback_for(&rules), "", &rules)
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
        assert!(check_effective_state(&out, &readback_for(&rules), "", &rules).is_err());
    }

    #[test]
    fn check_effective_state_rejects_a_policy_that_ignores_local_rules() {
        // A policy that sets AllowLocalFirewallRules to False makes every local
        // rule (ours included) inert, so the host would filter nothing while the
        // rules read back as present.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let out = EFFECTIVE_BLOCKING.replace(
            "AllowLocalFirewallRules    : True",
            "AllowLocalFirewallRules    : False",
        );
        let err = check_effective_state(&out, &readback_for(&rules), "", &rules)
            .expect_err("local rules ignored means no filtering at all");
        assert!(
            format!("{err:#}").contains("ignores local firewall rules"),
            "got {err:#}"
        );
    }

    #[test]
    fn check_effective_state_rejects_an_exception_without_the_override_flag() {
        // The load-bearing check for the tunnel: without the override the
        // exception loses to the block rule, so the traffic it permits stays
        // blocked while the install would otherwise report success.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let readback = readback_for(&rules).replace(
            "|warren-killswitch-allow-tun|Outbound|Allow|True|true|",
            "|warren-killswitch-allow-tun|Outbound|Allow|True|false|",
        );
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, "", &rules)
            .expect_err("an exception without the override cannot be trusted");
        assert!(
            format!("{err:#}").contains("OverrideBlockRules"),
            "got {err:#}"
        );
    }

    #[test]
    fn check_effective_state_rejects_a_block_rule_that_carries_the_override() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let readback = readback_for(&rules).replace(
            "|warren-killswitch-block-outbound|Outbound|Block|True|false|",
            "|warren-killswitch-block-outbound|Outbound|Block|True|true|",
        );
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, "", &rules)
            .expect_err("a block rule carrying the override outranks what it must overrule");
        assert!(format!("{err:#}").contains("block rule"), "got {err:#}");
    }

    #[test]
    fn check_effective_state_rejects_a_missing_rule() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let readback =
            readback_for(&rules).replace("warren-killswitch-allow-tun", "warren-killswitch-typo");
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, "", &rules)
            .expect_err("a rule that is not in the effective policy is not installed");
        assert!(format!("{err:#}").contains("allow-tun"), "got {err:#}");
    }

    #[test]
    fn check_effective_state_rejects_an_exception_that_lost_its_program_scope() {
        // An exception without its `-Program` scope hands the off-tunnel path to
        // any process that dials the exit address.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let readback = readback_for(&rules).replace(TEST_DAEMON_EXE, "");
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, "", &rules)
            .expect_err("a widened exception must not pass as verified");
        assert!(format!("{err:#}").contains("-Program"), "got {err:#}");
    }

    #[test]
    fn check_effective_state_rejects_an_exception_that_lost_its_destination_scope() {
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        // Only the remote-address field: the rule's display name carries the
        // address too, and widening the destination is what is under test.
        let readback = readback_for(&rules).replace("|UDP|1.2.3.4|", "|UDP|Any|");
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, "", &rules)
            .expect_err("an exception that lost its destination scope must not pass");
        assert!(format!("{err:#}").contains("-RemoteAddress"), "got {err:#}");
    }

    #[test]
    fn check_effective_state_rejects_a_leftover_rule_of_ours() {
        // A rule of ours that this install did not create grants whatever it was
        // left for (an allow-lan rule from a previous session, for instance)
        // while the policy claims to be the one we just installed.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let readback = format!(
            "{}RULE|warren-killswitch-lan-10.0.0.0/8|Outbound|Allow|True|True||Any|10.0.0.0/8||\n",
            readback_for(&rules)
        );
        let err = check_effective_state(EFFECTIVE_BLOCKING, &readback, "", &rules)
            .expect_err("a leftover rule of ours must fail the install");
        assert!(
            format!("{err:#}").contains("warren-killswitch-lan"),
            "got {err:#}"
        );
    }

    #[test]
    fn check_effective_state_rejects_an_undisabled_operator_rule() {
        // The categorical property: with the profiles blocking by default, any
        // enabled allow rule that is not ours is a way out of the host.
        let rules = build_rules(&opts_minimal(), TEST_DAEMON_EXE);
        let foreign = format!("FOREIGN|{FOREIGN_RULE_NAME}|{FOREIGN_RULE_DISPLAY}\n");
        let err =
            check_effective_state(EFFECTIVE_BLOCKING, &readback_for(&rules), &foreign, &rules)
                .expect_err("an enabled foreign allow rule means the policy does not hold");
        assert!(
            format!("{err:#}").contains(FOREIGN_RULE_DISPLAY),
            "the message must name the rule an operator has to deal with: {err:#}"
        );
    }

    // ---- a model of the documented rule precedence -------------------
    //
    // A test that greps the generated PowerShell cannot observe which policy the
    // host ends up with, so the policy is also driven against a model of the
    // decision Microsoft documents:
    //
    //   1. an explicitly defined allow rule beats the profile DEFAULT block
    //      setting;
    //   2. an explicit Block rule beats any conflicting allow rule;
    //   3. more specific rules win, except against an explicit Block.
    //
    // The model is what makes the regression observable: with the OLD policy
    // (profile default block plus our exceptions) rule 1 keeps a pre-existing
    // allow rule working, which is the leak. The model keeps rule 2 even though
    // this policy creates no block rule, and a dedicated test asserts it, so the
    // model is a claim about Windows rather than a restatement of our code.

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
        display_name: String,
        action: RuleAction,
        /// The documented outbound "allow bypass rule": the traffic is permitted
        /// even where another matching rule blocks it.
        override_block_rules: bool,
        enabled: bool,
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
                display_name: spec.display_name(),
                action: spec.action,
                override_block_rules: spec.override_block_rules,
                enabled: true,
                iface: spec.iface.clone(),
                udp: spec.udp,
                remote: spec.remote.clone(),
                remote_port: spec.remote_port,
                program: spec.program.clone(),
            }
        }

        fn matches(&self, packet: &Packet<'_>) -> bool {
            if !self.enabled {
                return false;
            }
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
        /// rule, which is what a user accepting the firewall prompt leaves
        /// behind.
        fn with_preexisting_allow(program: &str) -> Self {
            let mut model = Self::stock();
            model.preexisting.push(ModelRule {
                name: FOREIGN_RULE_NAME.to_owned(),
                display_name: FOREIGN_RULE_DISPLAY.to_owned(),
                action: RuleAction::Allow,
                override_block_rules: false,
                enabled: true,
                iface: None,
                udp: false,
                remote: None,
                remote_port: None,
                program: Some(program.to_owned()),
            });
            model
        }

        fn rules(&self) -> impl Iterator<Item = &ModelRule> {
            self.ours.iter().chain(self.preexisting.iter())
        }

        /// The decision the firewall would reach for `packet`.
        fn decide(&self, packet: &Packet<'_>) -> Verdict {
            let profile = &self.profiles[&self.active_profile];
            if !profile.enabled() {
                // A firewall that is off filters nothing.
                return Verdict::Allow;
            }
            // Documented precedence, in order: an Allow carrying
            // OverrideBlockRules (the outbound "allow bypass rule") wins even
            // where another rule blocks; an explicit Block wins over any other
            // conflicting Allow; otherwise an Allow matches.
            if self.rules().any(|r| {
                r.action == RuleAction::Allow && r.override_block_rules && r.matches(packet)
            }) {
                return Verdict::Allow;
            }
            if self
                .rules()
                .any(|r| r.action == RuleAction::Block && r.matches(packet))
            {
                return Verdict::Block;
            }
            if self
                .rules()
                .any(|r| r.action == RuleAction::Allow && r.matches(packet))
            {
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
        /// `apply` index from which every command stalls for ever, so a test can
        /// cancel the future at a chosen point and exercise the guard's `Drop`
        /// (`usize::MAX` never stalls).
        stall_from: AtomicUsize,
        /// When set, every `apply` fails, so a test can make a teardown fail
        /// without failing the install.
        fail_applies: std::sync::atomic::AtomicBool,
        /// Names of the events the guard tests observe, in order: an `apply`
        /// marker per command and one `sync_teardown` for the guard's `Drop`.
        ops: Mutex<Vec<String>>,
        /// Rules this host will not let us disable, standing in for a rule that
        /// comes from a Group Policy or an MDM policy store.
        pinned_foreign: Vec<String>,
        /// Rules of ours that the removal cannot delete, standing in for a
        /// leftover this install fails to clear.
        undeletable_ours: Vec<ModelRule>,
        /// Whether the local rules are merged into the effective policy.
        allow_local_rules: bool,
    }

    impl ModelRunner {
        fn new(model: FirewallModel) -> Self {
            Self {
                model: Mutex::new(model),
                fail_apply_index: None,
                applies: AtomicUsize::new(0),
                refuse_enable: false,
                drop_override_flag: false,
                stall_from: AtomicUsize::new(usize::MAX),
                fail_applies: std::sync::atomic::AtomicBool::new(false),
                ops: Mutex::new(Vec::new()),
                pinned_foreign: Vec::new(),
                undeletable_ours: Vec::new(),
                allow_local_rules: true,
            }
        }

        fn failing_at(mut self, index: usize) -> Self {
            self.fail_apply_index = Some(index);
            self
        }

        fn pinning_foreign(mut self, names: Vec<String>) -> Self {
            self.pinned_foreign = names;
            self
        }

        fn leaving_behind(mut self, rules: Vec<ModelRule>) -> Self {
            self.undeletable_ours = rules;
            self
        }

        fn ignoring_local_rules(mut self) -> Self {
            self.allow_local_rules = false;
            self
        }

        fn dropping_override_flag(mut self) -> Self {
            self.drop_override_flag = true;
            self
        }

        /// Make every `apply` from `index` on stall, so the caller can cancel the
        /// future at a chosen point.
        fn stalling_from(&self, index: usize) {
            self.stall_from.store(index, Ordering::SeqCst);
        }

        /// Make every later `apply` stall.
        fn stalling(&self) {
            self.stalling_from(0);
        }

        /// Make every later `apply` fail.
        fn failing_applies(&self) {
            self.fail_applies.store(true, Ordering::SeqCst);
        }

        fn model(&self) -> std::sync::MutexGuard<'_, FirewallModel> {
            self.model.lock().expect("model mutex")
        }

        fn recorded(&self) -> Vec<String> {
            self.ops.lock().expect("ops mutex").clone()
        }

        fn record(&self, event: &str) {
            self.ops.lock().expect("ops mutex").push(event.to_owned());
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
                foreign_allows: model
                    .preexisting
                    .iter()
                    .filter(|r| r.enabled && r.action == RuleAction::Allow)
                    .map(|r| r.name.clone())
                    .collect(),
            })
        }

        async fn apply(&self, op: &FirewallOp) -> Result<(), KillswitchError> {
            let index = self.applies.fetch_add(1, Ordering::SeqCst);
            if index >= self.stall_from.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if self.fail_applies.load(Ordering::SeqCst) {
                return Err(KillswitchError::Windows(
                    "model: injected apply failure".into(),
                ));
            }
            self.record("apply");
            if self.fail_apply_index == Some(index) {
                return Err(KillswitchError::Windows(
                    "model: injected apply failure".into(),
                ));
            }
            let mut model = self.model();
            match op {
                FirewallOp::DeleteOurRules => {
                    model.ours = self.undeletable_ours.clone();
                }
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
                FirewallOp::DisableForeignAllows(names) => {
                    for rule in &mut model.preexisting {
                        if names.contains(&rule.name) && !self.pinned_foreign.contains(&rule.name) {
                            rule.enabled = false;
                        }
                    }
                }
                FirewallOp::CreateRule(spec) => {
                    let mut rule = ModelRule::from_spec(spec);
                    if self.drop_override_flag {
                        rule.override_block_rules = false;
                    }
                    model.ours.push(rule);
                }
                FirewallOp::EnableRules(names) => {
                    for rule in &mut model.preexisting {
                        if names.contains(&rule.name) {
                            rule.enabled = true;
                        }
                    }
                }
                FirewallOp::RestoreProfile(snapshot) => {
                    if let Some(profile) = model.profiles.get_mut(&snapshot.name) {
                        profile.local_enabled = snapshot.local_enabled;
                        profile.local_default = snapshot.local_default_outbound_action;
                    }
                }
            }
            Ok(())
        }

        fn sync_teardown(&self, snapshot: &FirewallSnapshot) {
            // What `Drop` does on a real host, in the model: undo our rules,
            // re-enable the operator's, put the captured profile settings back.
            let mut model = self.model();
            model.ours = self.undeletable_ours.clone();
            for name in &snapshot.foreign_allows {
                if let Some(rule) = model.preexisting.iter_mut().find(|r| &r.name == name) {
                    rule.enabled = true;
                }
            }
            for saved in &snapshot.profiles {
                if let Some(profile) = model.profiles.get_mut(&saved.name) {
                    profile.local_enabled = saved.local_enabled;
                    profile.local_default = saved.local_default_outbound_action;
                }
            }
            self.record("sync_teardown");
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
            if !self.allow_local_rules {
                return Err(KillswitchError::Windows(
                    "model: the active policy ignores local firewall rules".into(),
                ));
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
                if row.action != spec.action || !row.enabled {
                    return Err(KillswitchError::Windows(format!(
                        "model: the rule {name} is not in effect"
                    )));
                }
                if spec.override_block_rules && !row.override_block_rules {
                    return Err(KillswitchError::Windows(format!(
                        "model: the exception {name} does not carry OverrideBlockRules, so \
                         the block rule outranks it"
                    )));
                }
            }
            if let Some(leftover) = model.ours.iter().find(|rule| {
                !rules
                    .iter()
                    .any(|spec| spec.display_name() == rule.display_name)
            }) {
                return Err(KillswitchError::Windows(format!(
                    "model: the leftover rule {} is still installed",
                    leftover.display_name
                )));
            }
            if let Some(foreign) = model
                .preexisting
                .iter()
                .find(|rule| rule.enabled && rule.action == RuleAction::Allow)
            {
                return Err(KillswitchError::Windows(format!(
                    "model: the enabled allow rule {} was not disabled",
                    foreign.display_name
                )));
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
    const LAN_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    #[test]
    fn the_model_reproduces_the_documented_precedence() {
        // Guards the model itself. If the model were a restatement of this
        // module's policy, the regression test below would pass by construction.
        let mut model = FirewallModel::stock();
        let packet = outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            model.decide(&packet),
            Verdict::Allow,
            "an allow-by-default profile lets traffic out with no rule at all"
        );

        model
            .profiles
            .get_mut("Public")
            .expect("profile")
            .local_default = OutboundAction::Block;
        assert_eq!(
            model.decide(&packet),
            Verdict::Block,
            "the documented default block stops traffic no rule matches"
        );

        model.preexisting.push(ModelRule {
            name: "app-allow".into(),
            display_name: "app-allow".into(),
            action: RuleAction::Allow,
            override_block_rules: false,
            enabled: true,
            iface: None,
            udp: false,
            remote: None,
            remote_port: None,
            program: Some(TEST_OTHER_APP.to_owned()),
        });
        assert_eq!(
            model.decide(&packet),
            Verdict::Allow,
            "documented rule 1: an explicit allow rule outranks the default block"
        );

        model.ours.push(ModelRule {
            name: "block-all".into(),
            display_name: "block-all".into(),
            action: RuleAction::Block,
            override_block_rules: false,
            enabled: true,
            iface: None,
            udp: false,
            remote: None,
            remote_port: None,
            program: None,
        });
        assert_eq!(
            model.decide(&packet),
            Verdict::Block,
            "documented rule 2: an explicit block rule outranks a conflicting allow"
        );

        model.preexisting.push(ModelRule {
            name: "app-bypass".into(),
            display_name: "app-bypass".into(),
            action: RuleAction::Allow,
            override_block_rules: true,
            enabled: true,
            iface: None,
            udp: false,
            remote: None,
            remote_port: None,
            program: Some(TEST_OTHER_APP.to_owned()),
        });
        assert_eq!(
            model.decide(&packet),
            Verdict::Allow,
            "documented outbound allow bypass rule: a matching Allow carrying \
             OverrideBlockRules is permitted even where the block rule matches"
        );
    }

    #[tokio::test]
    async fn a_preexisting_allow_rule_cannot_let_traffic_out_after_the_install() {
        // The regression this module exists for: the profile default block does
        // NOT outrank a pre-existing explicit Allow rule, so a policy built from
        // the default plus our exceptions leaves every other application's egress
        // wide open.
        let runner = Arc::new(ModelRunner::new(FirewallModel::with_preexisting_allow(
            TEST_OTHER_APP,
        )));
        let packet = outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Allow,
            "setup: the pre-existing Allow rule lets the application out"
        );

        install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");

        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Block,
            "after the install the application's physical egress must be blocked: \
             its allow rule is disabled, so the default block applies to it"
        );
    }

    #[tokio::test]
    async fn the_tunnel_and_the_daemon_carrier_still_pass_after_the_install() {
        let runner = Arc::new(ModelRunner::new(FirewallModel::with_preexisting_allow(
            TEST_OTHER_APP,
        )));
        install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");
        let model = runner.model();

        let on_tun = outbound_from("warren0", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            model.decide(&on_tun),
            Verdict::Allow,
            "everything on the tunnel interface is where legitimate traffic goes: \
             a plain allow rule outranks the default block"
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
            "the daemon's own transport to the exit must survive, or the tunnel can \
             never connect"
        );

        let impostor = Packet {
            program: TEST_OTHER_APP,
            ..carrier
        };
        assert_eq!(
            model.decide(&impostor),
            Verdict::Block,
            "another process dialing the exit address must not inherit the daemon's \
             exception (Port Fail / TunnelCrack ServerIP)"
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
        let runner = Arc::new(ModelRunner::new(model));
        let packet = outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Allow,
            "setup: with the firewall off nothing filters"
        );

        let snapshot = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("the install must turn the profiles on rather than trust them");
        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Block,
            "an install that reported success must actually be filtering"
        );

        uninstall_with_runner(runner.as_ref(), &snapshot)
            .await
            .expect("uninstall");
        assert!(
            !runner.model().profiles["Domain"].enabled(),
            "the captured disabled state must come back: we turned the firewall on, \
             so we turn it back off"
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
        let runner = Arc::new(ModelRunner::new(model));

        let err = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
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
    async fn install_refuses_and_rolls_back_when_a_rule_cannot_be_disabled() {
        // The categorical property cannot be established on a host whose policy
        // store owns an allow rule we may not disable. Reporting success would
        // announce a killswitch that still lets that traffic out.
        let mut model = FirewallModel::with_preexisting_allow(TEST_OTHER_APP);
        model
            .profiles
            .values_mut()
            .for_each(|p| p.local_enabled = GpoBool::True);
        let runner =
            Arc::new(ModelRunner::new(model).pinning_foreign(vec![FOREIGN_RULE_NAME.to_owned()]));

        let err = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect_err("an allow rule we cannot disable must fail the install");
        assert!(
            format!("{err:#}").contains(FOREIGN_RULE_DISPLAY),
            "the message must name the rule an operator has to deal with: {err:#}"
        );

        let model = runner.model();
        assert!(model.ours.is_empty(), "the rollback must remove our rules");
        assert_eq!(
            model.profiles["Domain"].local_default,
            OutboundAction::Allow,
            "and restore what it captured"
        );
    }

    #[tokio::test]
    async fn install_refuses_when_the_policy_ignores_local_rules() {
        let runner = Arc::new(ModelRunner::new(FirewallModel::stock()).ignoring_local_rules());
        let err = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect_err("local rules ignored means our policy filters nothing");
        assert!(
            format!("{err:#}").contains("local firewall rules"),
            "got {err:#}"
        );
    }

    #[tokio::test]
    async fn install_removes_the_leftovers_of_a_previous_session() {
        // A session that ended abnormally leaves its rules behind. Reinstalling
        // with narrower options (the LAN no longer allowed here) must not leave
        // the old, wider exception in place.
        let leftover = ModelRule {
            name: format!("{RULE_PREFIX}lan-10.0.0.0/8"),
            display_name: format!("{RULE_PREFIX}lan-10.0.0.0/8"),
            action: RuleAction::Allow,
            override_block_rules: true,
            enabled: true,
            iface: None,
            udp: false,
            remote: Some(Remote::Network("10.0.0.0/8")),
            remote_port: None,
            program: None,
        };
        let mut model = FirewallModel::stock();
        model.ours.push(leftover);
        let runner = Arc::new(ModelRunner::new(model));
        let lan_packet = outbound_from("Ethernet", TEST_OTHER_APP, LAN_ADDR);

        let snapshot = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");
        assert_eq!(
            runner.model().decide(&lan_packet),
            Verdict::Block,
            "the leftover LAN exception must not survive an install that does not \
             allow the LAN"
        );

        uninstall_with_runner(runner.as_ref(), &snapshot)
            .await
            .expect("uninstall");
        assert!(runner.model().ours.is_empty());
    }

    #[tokio::test]
    async fn install_refuses_when_a_leftover_rule_cannot_be_removed() {
        let leftover = ModelRule {
            name: format!("{RULE_PREFIX}lan-10.0.0.0/8"),
            display_name: format!("{RULE_PREFIX}lan-10.0.0.0/8"),
            action: RuleAction::Allow,
            override_block_rules: true,
            enabled: true,
            iface: None,
            udp: false,
            remote: Some(Remote::Network("10.0.0.0/8")),
            remote_port: None,
            program: None,
        };
        let runner = Arc::new(
            ModelRunner::new(FirewallModel::stock()).leaving_behind(vec![leftover.clone()]),
        );
        let err = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect_err("a rule we cannot remove must fail the install");
        assert!(format!("{err:#}").contains("lan-10.0.0.0/8"), "got {err:#}");
    }

    #[tokio::test]
    async fn install_rolls_the_whole_policy_back_when_a_command_fails() {
        let runner = Arc::new(
            ModelRunner::new(FirewallModel::with_preexisting_allow(TEST_OTHER_APP)).failing_at(4),
        );
        let err = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect_err("a failing command must fail the install");
        assert!(matches!(err, KillswitchError::Windows(_)), "got {err:?}");

        let model = runner.model();
        assert!(
            model.ours.is_empty(),
            "the rollback must remove every rule we created"
        );
        assert!(
            model.preexisting.iter().all(|r| r.enabled),
            "and put the operator's rules back"
        );
        assert_eq!(
            model.profiles["Domain"].local_default,
            OutboundAction::Allow,
            "and restore the captured profile defaults"
        );
    }

    #[tokio::test]
    async fn uninstall_restores_the_profiles_and_the_disabled_rules() {
        let runner = Arc::new(ModelRunner::new(FirewallModel::with_preexisting_allow(
            TEST_OTHER_APP,
        )));
        let snapshot = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");
        let packet = outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Block,
            "setup: the policy is in effect"
        );

        uninstall_with_runner(runner.as_ref(), &snapshot)
            .await
            .expect("uninstall");

        let model = runner.model();
        assert!(model.ours.is_empty(), "our rules must all be removed");
        assert!(
            model.preexisting.iter().all(|r| r.enabled),
            "a rule we disabled must be re-enabled, untouched otherwise"
        );
        assert_eq!(
            model.decide(&packet),
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
        let runner = Arc::new(ModelRunner::new(model));
        let snapshot = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");

        uninstall_with_runner(runner.as_ref(), &snapshot)
            .await
            .expect("uninstall");
        assert_eq!(
            runner.model().profiles["Domain"].local_default,
            OutboundAction::Block,
            "the uninstall restores what it captured, not a hard-coded Allow"
        );
    }

    #[test]
    fn the_generated_install_and_teardown_commands_are_pinned_exactly() {
        // A frozen generated surface: a change here changes what an elevated
        // PowerShell runs on the host, so it has to be deliberate and reviewable
        // rather than a side effect of a refactor. Behaviour is pinned by the
        // model tests below; this pins the text a reviewer compares against the
        // cmdlet documentation, which is the only review a non-Windows host can
        // offer.
        let mut snapshot = snapshot();
        snapshot.foreign_allows = vec![FOREIGN_RULE_NAME.to_owned()];
        let install = rendered_ops(&install_ops(
            &build_rules(&opts_minimal(), TEST_DAEMON_EXE),
            &snapshot,
        ));
        assert_eq!(
            install,
            vec![
                "-NoProfile -Command Get-NetFirewallRule -DisplayName 'warren-killswitch-*' \
                 | Remove-NetFirewallRule"
                    .to_owned(),
                "-NoProfile -Command Set-NetFirewallProfile -Profile Domain,Private,Public \
                 -Enabled True"
                    .to_owned(),
                "-NoProfile -Command Set-NetFirewallProfile -Profile Domain,Private,Public \
                 -DefaultOutboundAction Block"
                    .to_owned(),
                format!(
                    "-NoProfile -Command Disable-NetFirewallRule -Name '{FOREIGN_RULE_NAME}' \
                     -ErrorAction Stop"
                ),
                "-NoProfile -Command New-NetFirewallRule -DisplayName \
                 'warren-killswitch-block-outbound' -Direction Outbound -Action Block"
                    .to_owned(),
                "-NoProfile -Command New-NetFirewallRule -DisplayName \
                 'warren-killswitch-allow-loopback-v4' -Direction Outbound -Action Allow \
                 -OverrideBlockRules True -RemoteAddress 127.0.0.0/8"
                    .to_owned(),
                "-NoProfile -Command New-NetFirewallRule -DisplayName \
                 'warren-killswitch-allow-loopback-v6' -Direction Outbound -Action Allow \
                 -OverrideBlockRules True -RemoteAddress ::1/128"
                    .to_owned(),
                "-NoProfile -Command New-NetFirewallRule -DisplayName \
                 'warren-killswitch-allow-tun' -Direction Outbound -Action Allow \
                 -OverrideBlockRules True -InterfaceAlias 'warren0'"
                    .to_owned(),
                format!(
                    "-NoProfile -Command New-NetFirewallRule -DisplayName \
                     'warren-killswitch-exit-udp-v4-1.2.3.4' -Direction Outbound -Action Allow \
                     -OverrideBlockRules True -Protocol UDP -RemoteAddress 1.2.3.4 \
                     -Program '{TEST_DAEMON_EXE}'"
                ),
            ]
        );

        let uninstall = rendered_ops(&uninstall_ops(&snapshot));
        assert_eq!(
            uninstall,
            vec![
                "-NoProfile -Command Get-NetFirewallRule -DisplayName 'warren-killswitch-*' \
                 | Remove-NetFirewallRule"
                    .to_owned(),
                format!(
                    "-NoProfile -Command Enable-NetFirewallRule -Name '{FOREIGN_RULE_NAME}' \
                     -ErrorAction Stop"
                ),
                "-NoProfile -Command Set-NetFirewallProfile -Profile Domain -Enabled True \
                 -DefaultOutboundAction Allow"
                    .to_owned(),
                "-NoProfile -Command Set-NetFirewallProfile -Profile Private -Enabled True \
                 -DefaultOutboundAction Allow"
                    .to_owned(),
                "-NoProfile -Command Set-NetFirewallProfile -Profile Public -Enabled True \
                 -DefaultOutboundAction Allow"
                    .to_owned(),
            ]
        );
    }

    #[test]
    fn the_read_back_queries_are_pinned_exactly() {
        // The verification is only as good as the four queries it reads: a
        // renamed property or a dropped filter would silently make a check
        // vacuous, and no non-Windows host can execute them. Pinning the text
        // makes such a change visible in review.
        assert_eq!(
            QUERY_PROFILES_LOCAL,
            "Get-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain,Private,Public \
             | Format-List Name,Enabled,DefaultOutboundAction"
        );
        assert_eq!(
            QUERY_PROFILES_EFFECTIVE,
            "Get-NetFirewallProfile -PolicyStore ActiveStore -Profile Domain,Private,Public \
             | Format-List Name,Enabled,DefaultOutboundAction,AllowLocalFirewallRules"
        );
        assert_eq!(
            query_foreign_allows_command(),
            "Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound -Action Allow \
             -Enabled True | Where-Object { $_.DisplayName -notlike 'warren-killswitch-*' } \
             | ForEach-Object { 'FOREIGN|' + $_.Name + '|' + $_.DisplayName }"
        );
        assert_eq!(
            query_our_rules_command(),
            "Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName 'warren-killswitch-*' \
             | ForEach-Object { $s = $_ | Get-NetFirewallSecurityFilter; $a = $_ | \
             Get-NetFirewallApplicationFilter; $p = $_ | Get-NetFirewallPortFilter; $d = $_ | \
             Get-NetFirewallAddressFilter; $i = $_ | Get-NetFirewallInterfaceFilter; 'RULE|' \
             + $_.DisplayName + '|' + $_.Direction + '|' + $_.Action + '|' + $_.Enabled + \
             '|' + $s.OverrideBlockRules + '|' + $a.Program + '|' + $p.Protocol + '|' + \
             [string]$d.RemoteAddress + '|' + [string]$p.RemotePort + '|' + \
             [string]$i.InterfaceAlias }"
        );
    }

    // ---- the policy stays binding for the whole session ---------------
    //
    // Disabling the allow rules present at install time establishes the policy
    // once. The explicit block rule is what keeps it established, because an allow
    // rule created LATER (a user answering a firewall prompt, a software
    // installer, a Group Policy refresh) loses to an explicit block but outranks
    // a mere profile default.

    #[tokio::test]
    async fn a_rule_created_after_the_install_cannot_reopen_the_egress() {
        let runner = Arc::new(ModelRunner::new(FirewallModel::stock()));
        install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");
        let packet = outbound_from("Ethernet", TEST_OTHER_APP, PUBLIC_ADDR);
        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Block,
            "setup: the installed policy blocks the application"
        );

        runner.model().preexisting.push(ModelRule {
            name: "installed-later".into(),
            display_name: "installed later".into(),
            action: RuleAction::Allow,
            override_block_rules: false,
            enabled: true,
            iface: None,
            udp: false,
            remote: None,
            remote_port: None,
            program: Some(TEST_OTHER_APP.to_owned()),
        });

        assert_eq!(
            runner.model().decide(&packet),
            Verdict::Block,
            "an allow rule created after the install must still lose to the block \
             rule: the disable-at-install step alone would leave that window open \
             for the rest of the session"
        );
    }

    #[tokio::test]
    async fn install_is_not_reported_done_when_an_exception_loses_the_override_flag() {
        // The command was accepted and the flag is not in the effective policy.
        // Our exception then loses to the block rule, so the tunnel and the
        // carrier stay blocked: reporting success would announce a protection (a
        // working tunnel) that is not there.
        let runner = Arc::new(ModelRunner::new(FirewallModel::stock()).dropping_override_flag());
        let err = install_without_guard(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
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

    // ---- the guard stays armed until the teardown has run --------------
    //
    // `Drop` cannot await, so the guard keeps a synchronous teardown for the paths
    // where the asynchronous one did not complete: an uninstall that failed, or a
    // future cancelled mid-teardown. Clearing the flag before the first command
    // (the earlier shape) silently skipped the restoration of the operator's rules
    // and of the captured profile settings.

    #[tokio::test]
    async fn a_cancelled_install_restores_what_it_already_changed() {
        // The guard is armed BEFORE the first mutation, so a cancellation in the
        // middle of the install still drops an armed guard: the operator's rules
        // come back and the profiles are restored. Armed only once the install had
        // returned (the earlier shape), this window had nothing to undo it, and the
        // host was left with its firewall modified and no guard.
        let mut model = FirewallModel::with_preexisting_allow(TEST_OTHER_APP);
        for profile in model.profiles.values_mut() {
            profile.local_enabled = GpoBool::False;
        }
        let runner = Arc::new(ModelRunner::new(model));
        // Let the removal, the enable, the default block and the disable of the
        // operator's rule through, then stall: the host is mid-install.
        runner.stalling_from(4);

        let outcome = tokio::time::timeout(
            Duration::from_millis(50),
            KillswitchGuard::install(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE),
        )
        .await;
        assert!(outcome.is_err(), "the model runner was told to stall");

        assert!(
            runner.recorded().contains(&"sync_teardown".to_owned()),
            "a cancelled install must still run the guard's teardown: {:#?}",
            runner.recorded()
        );
        let model = runner.model();
        assert!(model.ours.is_empty(), "no rule of ours may be left behind");
        assert!(
            model.preexisting.iter().all(|r| r.enabled),
            "the operator's rules must be re-enabled"
        );
        assert_eq!(
            model.profiles["Domain"].local_enabled,
            GpoBool::False,
            "and the captured profile enable state restored"
        );
        assert_eq!(
            model.profiles["Domain"].local_default,
            OutboundAction::Allow,
            "and the captured default outbound action"
        );
    }

    #[tokio::test]
    async fn a_completed_uninstall_disarms_the_guard() {
        let runner = Arc::new(ModelRunner::new(FirewallModel::with_preexisting_allow(
            TEST_OTHER_APP,
        )));
        let guard = KillswitchGuard::install(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");
        guard.uninstall().await.expect("uninstall");
        assert!(
            !runner.recorded().contains(&"sync_teardown".to_owned()),
            "a completed uninstall must not be followed by a second teardown from \
             Drop: {:#?}",
            runner.recorded()
        );
    }

    #[tokio::test]
    async fn a_failed_uninstall_keeps_the_guard_armed() {
        let runner = Arc::new(ModelRunner::new(FirewallModel::with_preexisting_allow(
            TEST_OTHER_APP,
        )));
        let guard = KillswitchGuard::install(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");
        runner.failing_applies();
        {
            let err = guard
                .uninstall()
                .await
                .expect_err("every teardown command fails");
            assert!(matches!(err, KillswitchError::Windows(_)), "got {err:?}");
        } // the guard is dropped here, still armed
        assert!(
            runner.recorded().contains(&"sync_teardown".to_owned()),
            "an uninstall that did not complete must leave the guard able to retry: \
             {:#?}",
            runner.recorded()
        );
        let model = runner.model();
        assert!(model.ours.is_empty(), "the retry must remove our rules");
        assert!(
            model.preexisting.iter().all(|r| r.enabled),
            "and re-enable the operator's"
        );
        assert_eq!(
            model.profiles["Domain"].local_default,
            OutboundAction::Allow,
            "and restore the captured profile settings"
        );
    }

    #[tokio::test]
    async fn a_cancelled_uninstall_still_restores_the_captured_state() {
        let runner = Arc::new(ModelRunner::new(FirewallModel::with_preexisting_allow(
            TEST_OTHER_APP,
        )));
        let guard = KillswitchGuard::install(&opts_minimal(), runner.clone(), TEST_DAEMON_EXE)
            .await
            .expect("install");
        // Every later command stalls, so the timeout cancels the future and the
        // guard is dropped mid-teardown.
        runner.stalling();
        let outcome = tokio::time::timeout(Duration::from_millis(50), guard.uninstall()).await;
        assert!(outcome.is_err(), "the model runner was told to stall");

        assert!(
            runner.recorded().contains(&"sync_teardown".to_owned()),
            "a cancelled uninstall must still run the guard's synchronous teardown: \
             {:#?}",
            runner.recorded()
        );
        let model = runner.model();
        assert!(model.ours.is_empty(), "our rules must be removed");
        assert!(
            model.preexisting.iter().all(|r| r.enabled),
            "the operator's rules must be re-enabled"
        );
        assert_eq!(
            model.profiles["Domain"].local_default,
            OutboundAction::Allow,
            "and the captured profile settings restored"
        );
    }

    // ---- an in-flight command and the restoration cannot overlap ---------
    //
    // The guard restores the firewall from `Drop`, which cannot await, so the
    // restoration must not start while a command is still applying. The gate is
    // what guarantees the order: the command runs to completion on a blocking task
    // that holds it (a blocking task is not cancelled with the future waiting on
    // it), and the teardown takes it before its first command. Termination timing is
    // deliberately out of the picture: on Windows `TerminateProcess` may return
    // before the process is gone.

    #[cfg(unix)]
    #[tokio::test]
    async fn a_cancelled_command_still_holds_the_gate_until_it_finishes() {
        let gate = CommandGate::default();
        let marker =
            std::env::temp_dir().join(format!("warren-gate-ordering-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let script = format!("sleep 1; : > {}", marker.display());

        // The future is cancelled, the command is not: the blocking task keeps
        // running and keeps holding the gate.
        let cancelled = tokio::time::timeout(
            Duration::from_millis(100),
            run_gated_command(gate.clone(), "/bin/sh", vec!["-c".to_owned(), script]),
        )
        .await;
        assert!(cancelled.is_err(), "the command was meant to be cancelled");

        let held = gate
            .take_blocking(Duration::from_secs(10))
            .expect("the gate is released once the command exits");
        assert!(
            marker.exists(),
            "the restoration must not start before the cancelled command finished: {} \
             was not written yet",
            marker.display()
        );
        drop(held);
        let _ = std::fs::remove_file(&marker);
    }

    #[test]
    fn the_teardown_gives_up_after_the_bound() {
        // A wedged command must not hang process exit for ever: the teardown takes
        // the gate with a bound and reports the race instead.
        let gate = CommandGate::default();
        let holder = gate.clone();
        let (acquired, holding) = std::sync::mpsc::channel::<()>();
        let (release, hold) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            holder.run(|| {
                let _ = acquired.send(());
                let _ = hold.recv();
            });
        });
        // Wait until the command really holds the gate, or the test would take it
        // first and measure nothing.
        holding.recv().expect("the holder acquired the gate");

        let started = std::time::Instant::now();
        assert!(
            gate.take_blocking(Duration::from_millis(100)).is_none(),
            "a command that outlives the bound must not block the teardown"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the bound must cap the wait, took {:?}",
            started.elapsed()
        );
        let _ = release.send(());
        worker.join().expect("the holder thread joins");
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
