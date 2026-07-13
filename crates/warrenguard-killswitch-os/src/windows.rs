//! Windows killswitch - PowerShell `New-NetFirewallRule` implementation.
//!
//! ## Strategy
//!
//! Windows Firewall (the user-space interface to WFP) evaluates Block
//! rules before Allow rules at the same priority, so the Linux/macOS
//! recipe of "default-block + explicit-allow exceptions" cannot be
//! expressed by adding a single Block-everything rule and a few
//! Allow exceptions in parallel. The canonical workaround - also used
//! by WireGuard, OpenVPN, Mullvad on Windows - is:
//!
//! 1. Capture the current per-profile [`Domain`, `Private`, `Public`]
//!    `DefaultOutboundAction` settings.
//! 2. Set `DefaultOutboundAction = Block` for all three profiles.
//! 3. Add a handful of Allow rules tagged with our display-name
//!    prefix (`warren-killswitch-*`) for: the tunnel `InterfaceAlias`,
//!    UDP to the exit IPs, optional LAN ranges, optional DHCP.
//! 4. On uninstall, remove the rules by display-name prefix and
//!    restore each profile's captured `DefaultOutboundAction`.
//!
//! Loopback (`127.0.0.0/8`) is implicitly allowed by Windows Firewall
//! itself - no explicit rule needed.
//!
//! ## Privileges
//!
//! `New-NetFirewallRule` and `Set-NetFirewallProfile` require an
//! elevated process (running as Administrator). The binary must be
//! launched via `Run as administrator` or invoked from an elevated
//! shell.
//!
//! ## Future work
//!
//! A direct WFP-API implementation via the `windows` crate would let
//! us avoid touching the user's per-profile defaults (less system-
//! wide impact) at the cost of a non-trivial unsafe surface. The
//! current PowerShell approach is what consumer VPN apps ship today;
//! migrating to WFP is tracked as a future hardening item.

use std::fmt::Write;
use std::net::IpAddr;
#[cfg(any(target_os = "windows", test))]
use std::time::Duration;

use crate::{KillswitchError, KillswitchOpts};

#[cfg(target_os = "windows")]
use crate::validate_tun_name;

/// Common display-name prefix on every rule we install. Used by the
/// uninstall step to find and delete only our rules without touching
/// pre-existing user firewall configuration.
pub const RULE_PREFIX: &str = "warren-killswitch-";

/// Windows firewall profiles whose `DefaultOutboundAction` we toggle.
/// Captured at install time, restored on uninstall.
pub const FIREWALL_PROFILES: [&str; 3] = ["Domain", "Private", "Public"];

/// Build the PowerShell command list (each entry is the argv after
/// `powershell.exe -NoProfile -Command`) needed to install the
/// killswitch. Pure: no shell-out, no privileges, easy to unit-test.
///
/// Order is load-bearing: `Set-NetFirewallProfile -DefaultOutboundAction
/// Block` happens FIRST so the gap between "block enabled" and "allow
/// rules in place" is as short as possible. With the wintun adapter
/// in `--use-tun` mode the kernel routes traffic through it from the
/// moment we apply the block, so we still need the allow rules - but
/// we minimise the leak window by adding them right after.
///
/// `daemon_exe_path` is the running daemon's own executable path, used to
/// scope the exit-UDP allow rule to this process only (see
/// [`allow_udp_to_remote_address_command`] - the Port Fail / TunnelCrack
/// ServerIP fix).
#[must_use]
pub fn build_install_commands(opts: &KillswitchOpts, daemon_exe_path: &str) -> Vec<Vec<String>> {
    let mut cmds = Vec::with_capacity(8 + opts.exit_addrs.len());

    // 1. Block-by-default at the firewall profile level.
    cmds.push(set_default_outbound_action_block_command());

    // 2. Allow tunnel interface by alias name.
    cmds.push(allow_interface_alias_command(&opts.tun_name));

    // 3. Allow UDP to each exit IP (the QUIC handshake + keepalive
    //    socket lives here), scoped to this process (see
    //    `allow_udp_to_remote_address_command`).
    for addr in &opts.exit_addrs {
        cmds.push(allow_udp_to_remote_address_command(addr, daemon_exe_path));
    }

    if opts.allow_lan {
        for cidr in LAN_RANGES_V4 {
            cmds.push(allow_remote_address_command(cidr, "lan"));
        }
        for cidr in LAN_RANGES_V6 {
            cmds.push(allow_remote_address_command(cidr, "lan"));
        }
    }

    if opts.allow_dhcp {
        // DHCP client (port 68) and server (port 67), UDP. Both are
        // needed: the client sends discovery from 68 and receives
        // server replies on 68, but the implementation may also
        // accept on 67.
        cmds.push(allow_udp_dhcp_command(67));
        cmds.push(allow_udp_dhcp_command(68));
    }

    cmds
}

/// Build the PowerShell command list for uninstall. Order matters:
/// remove the rules FIRST so an in-flight allowed connection isn't
/// suddenly blocked while the rules are still listed but the default
/// action is back to Allow (= unrelated leak); then restore the
/// captured per-profile default actions.
///
/// `original_actions` is the snapshot returned by
/// [`parse_default_outbound_actions`] at install time.
#[must_use]
pub fn build_uninstall_commands(original_actions: &[(String, String)]) -> Vec<Vec<String>> {
    let mut cmds = Vec::with_capacity(1 + original_actions.len());

    // Remove every rule we installed (matched by display-name prefix).
    cmds.push(vec![
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' \
             | Remove-NetFirewallRule"
        ),
    ]);

    // Restore each profile's captured DefaultOutboundAction.
    for (profile, action) in original_actions {
        cmds.push(vec![
            "-NoProfile".into(),
            "-Command".into(),
            format!(
                "Set-NetFirewallProfile -Profile {profile} \
                 -DefaultOutboundAction {action}"
            ),
        ]);
    }

    cmds
}

/// Parse the multi-line `Get-NetFirewallProfile` output into a
/// vector of (profile_name, current_default_outbound_action) pairs
/// that the uninstall path will round-trip.
///
/// Expected output format (one pair of lines per profile):
///
/// ```text
/// Name                       : Domain
/// DefaultOutboundAction      : Allow
/// Name                       : Private
/// DefaultOutboundAction      : NotConfigured
/// Name                       : Public
/// DefaultOutboundAction      : Block
/// ```
///
/// Pure - exposed so the parser can be unit-tested against recorded
/// fixtures without invoking PowerShell.
#[must_use]
pub fn parse_default_outbound_actions(out: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut current_name: Option<String> = None;
    for line in out.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Name")
            && let Some(value) = extract_value_after_colon(rest)
        {
            // "Name                : Domain" → "Domain"
            current_name = Some(value);
        } else if let Some(rest) = trimmed.strip_prefix("DefaultOutboundAction")
            && let (Some(name), Some(value)) =
                (current_name.take(), extract_value_after_colon(rest))
        {
            pairs.push((name, value));
        }
    }
    pairs
}

/// Async seam over `powershell.exe` execution. Counterpart of the
/// crate-level sync [`crate::CommandRunner`] for the Windows lifecycle,
/// whose helpers are async end-to-end (`run_powershell` is tokio
/// based). Tests inject a recording mock; the production impl wraps
/// the real `powershell.exe` spawn.
#[allow(async_fn_in_trait)]
pub trait PsCommandRunner {
    /// Run one PowerShell invocation (the argv after `powershell.exe`).
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] when the process cannot be spawned or
    /// exits non-zero.
    async fn run(&self, args: &[String]) -> Result<(), KillswitchError>;
}

/// Run the full install command sequence, restoring the captured
/// per-profile `DefaultOutboundAction`s when any command fails.
///
/// The very first install command flips the global outbound default to
/// `Block` for all three profiles. Without this rollback, a failure on
/// any later allow-rule used to propagate via `?` and leave the host
/// blocked - no tunnel allow rule, no guard to restore the defaults -
/// until manual intervention. Even a failure on the Block flip itself
/// gets the rollback: PowerShell may have applied the flip to a subset
/// of the three profiles before erroring.
///
/// Restoration is best-effort (each failed restore is logged); the
/// original install error is what surfaces.
///
/// `daemon_exe_path` is forwarded to [`build_install_commands`] for the
/// WFP app-id scoping fix.
///
/// # Errors
///
/// The first failing install command's error, after the best-effort
/// rollback ran.
pub async fn run_install_with_rollback<R: PsCommandRunner>(
    runner: &R,
    opts: &KillswitchOpts,
    original_actions: &[(String, String)],
    daemon_exe_path: &str,
) -> Result<(), KillswitchError> {
    for cmd in build_install_commands(opts, daemon_exe_path) {
        if let Err(install_err) = runner.run(&cmd).await {
            tracing::error!(
                error = %install_err,
                "killswitch install command failed; restoring the captured \
                 per-profile DefaultOutboundAction before surfacing"
            );
            for restore in build_uninstall_commands(original_actions) {
                if let Err(e) = runner.run(&restore).await {
                    tracing::warn!(
                        error = %e,
                        "killswitch install rollback command failed (best-effort)"
                    );
                }
            }
            return Err(install_err);
        }
    }
    Ok(())
}

/// Pretty-printed command string for logging / diagnostics.
#[must_use]
pub fn format_install_log(opts: &KillswitchOpts) -> String {
    let mut s = String::with_capacity(256);
    let _ = writeln!(s, "Warren killswitch (Windows PowerShell)");
    let _ = writeln!(s, "  rule prefix     = {RULE_PREFIX}");
    let _ = writeln!(s, "  tunnel iface    = {}", opts.tun_name);
    let _ = writeln!(s, "  exit addresses  = {} entries", opts.exit_addrs.len());
    let _ = writeln!(s, "  allow_lan       = {}", opts.allow_lan);
    let _ = writeln!(s, "  allow_dhcp      = {}", opts.allow_dhcp);
    s
}

// ── PowerShell command builders ──────────────────────────────────────

fn set_default_outbound_action_block_command() -> Vec<String> {
    vec![
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "Set-NetFirewallProfile -Profile {} -DefaultOutboundAction Block",
            FIREWALL_PROFILES.join(",")
        ),
    ]
}

fn allow_interface_alias_command(alias: &str) -> Vec<String> {
    vec![
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "New-NetFirewallRule -DisplayName '{RULE_PREFIX}allow-tun' \
             -Direction Outbound -Action Allow -InterfaceAlias '{alias}'"
        ),
    ]
}

// Port Fail / TunnelCrack-ServerIP fix (WFP app-id scoping): a plain
// `-RemoteAddress <exit>` allow is destination-based, the same shape
// closed on Linux (`meta mark`, via `KillswitchOpts::socket_mark`) and
// macOS (`on <iface>`, via `KillswitchOpts::phys_iface`) - it grants the
// off-tunnel exception to ANY local process that dials the exit IP, not
// just the daemon. That matters even though the split-default routing
// (`warrenguard-route-split` + `warrenguard-winroute`) captures the exit
// IP into the tunnel for everyone by default: the classic TunnelCrack
// ServerIP shape relies on a locally-injected/attacker-controlled route
// (a malicious DHCP option, a directly-connected segment) that makes the
// exit's exact address resolve on-link, more specific than our `/1`
// split and entirely outside our control - in that scenario a
// destination-only firewall allow is the ONLY thing standing between a
// hostile process and a clear-text leak.
//
// The fix adds `-Program <daemon_exe_path>` (`FWPM_CONDITION_ALE_APP_ID`
// under the hood), so the exception additionally requires an exact
// process match: any OTHER process dialing the same exit address is
// still refused by the WFP default-block, regardless of what routes it
// manages to reach. Removing the rule outright was considered and
// rejected: the daemon's own carrier socket egresses the PHYSICAL
// interface via `IP_UNICAST_IF` (`warrenguard-socket-bypass`), not the
// TUN alias, so with no allow rule at all the WFP default-block would
// also block the daemon's own handshake/keepalive traffic - fail-closed,
// but the tunnel could never connect. `-RemoteAddress`/`-Protocol UDP`
// are kept alongside `-Program` for defense in depth (narrower than an
// app-wide allow).
fn allow_udp_to_remote_address_command(addr: &IpAddr, daemon_exe_path: &str) -> Vec<String> {
    let label = match addr {
        IpAddr::V4(_) => "exit-udp-v4",
        IpAddr::V6(_) => "exit-udp-v6",
    };
    let program = escape_powershell_single_quoted(daemon_exe_path);
    vec![
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "New-NetFirewallRule -DisplayName '{RULE_PREFIX}{label}-{addr}' \
             -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress {addr} \
             -Program '{program}'"
        ),
    ]
}

/// Doubles every embedded `'` so a value is safe to interpolate into a
/// PowerShell single-quoted string literal (the convention PowerShell
/// itself uses to escape a literal quote inside `'...'`). A Windows
/// install path essentially never contains one, but this keeps a
/// pathological install directory from breaking the generated
/// `New-NetFirewallRule` command instead of merely narrowing the WFP
/// app-id exception.
fn escape_powershell_single_quoted(s: &str) -> String {
    s.replace('\'', "''")
}

fn allow_remote_address_command(cidr: &str, label: &str) -> Vec<String> {
    vec![
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "New-NetFirewallRule -DisplayName '{RULE_PREFIX}{label}-{cidr}' \
             -Direction Outbound -Action Allow -RemoteAddress {cidr}"
        ),
    ]
}

fn allow_udp_dhcp_command(port: u16) -> Vec<String> {
    vec![
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "New-NetFirewallRule -DisplayName '{RULE_PREFIX}dhcp-{port}' \
             -Direction Outbound -Action Allow -Protocol UDP -RemotePort {port}"
        ),
    ]
}

const LAN_RANGES_V4: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
const LAN_RANGES_V6: &[&str] = &["fc00::/7", "fe80::/10"];

/// Strip "Name <whitespace> : <value>" → "<value>". Used by the
/// `Get-NetFirewallProfile` output parser. Returns `None` for an
/// empty value (defensive: a blank action would otherwise be
/// round-tripped to a `Set-NetFirewallProfile -DefaultOutboundAction
/// ''` invocation that fails).
fn extract_value_after_colon(s: &str) -> Option<String> {
    let (_, rest) = s.split_once(':')?;
    let value = rest.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

// ── Runtime exec (Windows only) ──────────────────────────────────────

/// PowerShell-based Windows killswitch. Mirror of [`super::LinuxKillswitch`]
/// / [`super::MacosKillswitch`] for the install/uninstall lifecycle.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct WindowsKillswitch {
    original_default_actions: Vec<(String, String)>,
    installed: bool,
}

#[cfg(target_os = "windows")]
impl WindowsKillswitch {
    /// Capture the current per-profile `DefaultOutboundAction`, set
    /// each profile to `Block`, then add the `warren-killswitch-*`
    /// allow rules. Idempotent against a previous partial install:
    /// the rule-removal step in [`Self::uninstall`] tolerates absent
    /// rules. A command failure mid-sequence restores the captured
    /// defaults before surfacing (cf. [`run_install_with_rollback`]),
    /// so a failed install never leaves the host blocked.
    ///
    /// # Errors
    ///
    /// - [`KillswitchError::InvalidInput`] if `opts.tun_name` is invalid.
    /// - [`KillswitchError::Windows`] if PowerShell fails, the process
    ///   lacks Administrator privileges, or the running binary's own
    ///   path could not be resolved (needed for the WFP app-id scoping
    ///   fix, see [`allow_udp_to_remote_address_command`]).
    pub async fn install(opts: &KillswitchOpts) -> Result<Self, KillswitchError> {
        validate_tun_name(&opts.tun_name)?;

        let daemon_exe_path = resolve_daemon_exe_path()?;
        let original_default_actions = capture_default_actions().await?;

        run_install_with_rollback(
            &TokioPsRunner,
            opts,
            &original_default_actions,
            &daemon_exe_path,
        )
        .await?;

        tracing::info!(
            tun = %opts.tun_name,
            exit_count = opts.exit_addrs.len(),
            allow_lan = opts.allow_lan,
            allow_dhcp = opts.allow_dhcp,
            "Warren killswitch installed (Windows PowerShell)"
        );

        Ok(Self {
            original_default_actions,
            installed: true,
        })
    }

    /// Remove all `warren-killswitch-*` rules, then restore each
    /// profile's captured `DefaultOutboundAction`.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Windows`] only if the PowerShell process fails
    /// outright; individual rule-removal misses are tolerated by
    /// `Get-NetFirewallRule | Remove-NetFirewallRule`.
    pub async fn uninstall(mut self) -> Result<(), KillswitchError> {
        let cmds = build_uninstall_commands(&self.original_default_actions);
        for cmd in cmds {
            if let Err(e) = run_powershell(&cmd).await {
                tracing::warn!(
                    error = %e,
                    "killswitch uninstall PowerShell command failed (non-fatal)"
                );
            }
        }
        self.installed = false;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsKillswitch {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // Best-effort sync cleanup. Drop is sync, so this cannot await; each
        // invocation is bounded by `SYNC_CLEANUP_TIMEOUT` so a wedged
        // powershell.exe can never hang process teardown indefinitely
        // (parity with `warrenguard_route_split`'s sync cleanup helpers).
        // On timeout the child is killed - unrecoverable, but the process
        // is exiting anyway.
        let cmds = build_uninstall_commands(&self.original_default_actions);
        for cmd in cmds {
            if run_sync_bounded("powershell.exe", &cmd, SYNC_CLEANUP_TIMEOUT).is_none() {
                tracing::warn!(
                    cmd = %cmd.join(" "),
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

/// Production [`PsCommandRunner`]: spawns the real `powershell.exe`.
#[cfg(target_os = "windows")]
struct TokioPsRunner;

#[cfg(target_os = "windows")]
impl PsCommandRunner for TokioPsRunner {
    async fn run(&self, args: &[String]) -> Result<(), KillswitchError> {
        run_powershell(args).await
    }
}

/// Resolves the running daemon's own executable path, needed for the WFP
/// app-id scoping fix (see [`allow_udp_to_remote_address_command`]).
/// Isolated so the (extremely rare - e.g. the running binary was deleted
/// or renamed post-exec) failure path has a single, testable error
/// mapping.
#[cfg(target_os = "windows")]
fn resolve_daemon_exe_path() -> Result<String, KillswitchError> {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| KillswitchError::Windows(format!("resolve current_exe: {e}")))
}

#[cfg(target_os = "windows")]
async fn capture_default_actions() -> Result<Vec<(String, String)>, KillswitchError> {
    use tokio::process::Command;

    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetFirewallProfile -Profile Domain,Private,Public \
             | Format-List Name,DefaultOutboundAction",
        ])
        .output()
        .await
        .map_err(|e| KillswitchError::Windows(format!("spawn powershell.exe: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(KillswitchError::Windows(format!(
            "Get-NetFirewallProfile failed: {}",
            stderr.trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pairs = parse_default_outbound_actions(&stdout);
    if pairs.len() != FIREWALL_PROFILES.len() {
        return Err(KillswitchError::Windows(format!(
            "Get-NetFirewallProfile returned {} profiles, expected {} \
             (output: {})",
            pairs.len(),
            FIREWALL_PROFILES.len(),
            stdout.trim()
        )));
    }
    Ok(pairs)
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

/// Upper bound on a single synchronous cleanup command run from [`Drop`].
/// `powershell.exe` cold-starts at roughly 1-1.5 s per invocation even when
/// healthy; this is a hang guard, not a normal-latency budget.
///
/// `cfg(any(target_os = "windows", test))`: the only production caller is
/// Windows-only ([`Drop for WindowsKillswitch`]), but the helper itself is
/// portable and is exercised for real by the test suite on every host (see
/// the `bounded_wait` tests below) - `test` keeps it out of a non-Windows
/// production build's dead-code surface while still compiling it there.
#[cfg(any(target_os = "windows", test))]
const SYNC_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll-based bounded wait for a spawned child. `std` has no
/// `wait_timeout`, so poll `try_wait` on a short back-off interval until
/// the deadline. Returns `None` if the child has not exited by the
/// deadline (the caller is responsible for killing it), mirroring
/// `warrenguard_route_split`'s `wait_sync_command` helper.
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

/// Runs `program args...` synchronously, bounded by `timeout`. Returns
/// `None` on spawn failure or timeout (the child is killed in the timeout
/// case); best-effort and panic-free, so it is safe to call from `Drop`.
///
/// Deliberately portable (no OS-specific API) so the bounded-wait logic
/// itself is exercised by the test suite on every host, even though its
/// only production caller ([`WindowsKillswitch`]'s `Drop`) only ever runs
/// on Windows and can only be validated for real there.
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
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    /// Stand-in for `resolve_daemon_exe_path()`'s result in tests that do
    /// not exercise the async lifecycle directly.
    const TEST_DAEMON_EXE: &str = "C:\\Program Files\\Warren\\warren-daemon.exe";

    #[test]
    fn install_first_command_blocks_outbound_default() {
        // The very first command MUST be the firewall profile flip to
        // Block. Reordering it after the Allow rules leaves a
        // wide-open window in which traffic can leak before the
        // Block kicks in. Anchored explicitly.
        let cmds = build_install_commands(&opts_minimal(), TEST_DAEMON_EXE);
        let first = &cmds[0];
        assert!(
            first
                .iter()
                .any(|s| s.contains("DefaultOutboundAction Block")),
            "first command must enable the block; got {first:?}"
        );
    }

    #[test]
    fn install_includes_tun_alias_allow_rule() {
        // Without this allow rule the tunnel itself is blocked once
        // the default action flips to Block - the tunnel never opens.
        let cmds = build_install_commands(&opts_minimal(), TEST_DAEMON_EXE);
        let joined = cmds
            .iter()
            .flat_map(|c| c.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.contains("-InterfaceAlias 'warren0'"),
            "must allow the tun_name verbatim; full cmd dump: {joined}"
        );
    }

    #[test]
    fn install_emits_one_allow_rule_per_exit_addr() {
        let mut opts = opts_minimal();
        opts.exit_addrs = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ];
        let cmds = build_install_commands(&opts, TEST_DAEMON_EXE);
        let allow_count = cmds
            .iter()
            .filter(|c| c.iter().any(|s| s.contains("-Protocol UDP -RemoteAddress")))
            .count();
        assert_eq!(
            allow_count, 3,
            "one UDP allow per exit address (v4 + v6); cmds: {cmds:#?}"
        );
    }

    #[test]
    fn install_udp_allow_rule_is_scoped_to_the_daemon_program_path() {
        // Port Fail / TunnelCrack ServerIP fix: the exit-UDP allow must also
        // require an app-id match (`-Program`), so only the daemon's own
        // process may use the destination-based exception; any other
        // process dialing the same exit address is still refused by the
        // WFP default-block.
        let cmds = build_install_commands(&opts_minimal(), TEST_DAEMON_EXE);
        let joined = cmds
            .iter()
            .flat_map(|c| c.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.contains(&format!("-Program '{TEST_DAEMON_EXE}'")),
            "exit-UDP allow rule must be scoped to the daemon's own exe path; got {joined}"
        );
        assert!(
            joined.contains("-RemoteAddress") && joined.contains("-Protocol UDP"),
            "the destination/protocol narrowing must be kept alongside \
             -Program (defense in depth), not replaced by it; got {joined}"
        );
    }

    #[test]
    fn program_path_with_embedded_single_quote_is_escaped_for_powershell() {
        let path = "C:\\Program Files\\Warren's App\\daemon.exe";
        let cmds = build_install_commands(&opts_minimal(), path);
        let joined = cmds
            .iter()
            .flat_map(|c| c.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.contains("Warren''s App"),
            "an embedded single quote must be doubled for the PowerShell \
             string literal, not left to break the generated command; \
             got {joined}"
        );
    }

    #[test]
    fn escape_powershell_single_quoted_doubles_every_quote() {
        assert_eq!(escape_powershell_single_quoted("no quotes"), "no quotes");
        assert_eq!(escape_powershell_single_quoted("a'b"), "a''b");
        assert_eq!(escape_powershell_single_quoted("a'b'c"), "a''b''c");
    }

    #[test]
    fn install_excludes_lan_ranges_by_default() {
        let cmds = build_install_commands(&opts_minimal(), TEST_DAEMON_EXE);
        let joined = cmds
            .iter()
            .flat_map(|c| c.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            !joined.contains("192.168."),
            "LAN must be blocked by default - opt-in via allow_lan"
        );
    }

    #[test]
    fn install_includes_lan_ranges_when_allow_lan_set() {
        let mut opts = opts_minimal();
        opts.allow_lan = true;
        let cmds = build_install_commands(&opts, TEST_DAEMON_EXE);
        let joined = cmds
            .iter()
            .flat_map(|c| c.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"] {
            assert!(
                joined.contains(cidr),
                "missing LAN range {cidr} in {joined}"
            );
        }
    }

    #[test]
    fn install_includes_dhcp_ports_when_allow_dhcp_set() {
        // Mirror Linux nft / macOS pf: DHCP client/server ports both
        // need an allow when allow_dhcp is set, otherwise the
        // server-side reply on port 68 is dropped after the default
        // action flips to Block.
        let mut opts = opts_minimal();
        opts.allow_dhcp = true;
        let cmds = build_install_commands(&opts, TEST_DAEMON_EXE);
        let joined = cmds
            .iter()
            .flat_map(|c| c.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            joined.contains("-RemotePort 67"),
            "DHCP server port missing"
        );
        assert!(
            joined.contains("-RemotePort 68"),
            "DHCP client port missing"
        );
    }

    #[test]
    fn uninstall_removes_rules_before_restoring_default_action() {
        // Reverse of install order: rules first, then DefaultOutboundAction
        // restore. This avoids a window where the Block default action is
        // briefly active without our Allow rules - that window would
        // sever the in-flight Caddy / tunnel connections during cleanup.
        let snapshot = vec![
            ("Domain".to_string(), "Allow".to_string()),
            ("Private".to_string(), "Allow".to_string()),
            ("Public".to_string(), "NotConfigured".to_string()),
        ];
        let cmds = build_uninstall_commands(&snapshot);
        assert_eq!(cmds.len(), 4, "1 rule-cleanup + 3 profile restores");
        assert!(
            cmds[0]
                .iter()
                .any(|s| s.contains("Get-NetFirewallRule") && s.contains("Remove-NetFirewallRule")),
            "first cleanup must drop the rules; got {:?}",
            cmds[0]
        );
        assert!(
            cmds[1]
                .iter()
                .any(|s| s.contains("Set-NetFirewallProfile") && s.contains("Domain")),
            "second cleanup must restore Domain; got {:?}",
            cmds[1]
        );
    }

    #[test]
    fn uninstall_round_trips_each_profiles_captured_default_action() {
        // If we collapse all three profiles to a single "restore" we
        // lose the per-profile granularity that the original system
        // had (Domain=Allow, Public=NotConfigured, etc.). Anchored
        // here so the round-trip semantics survive future refactors.
        let snapshot = vec![
            ("Domain".to_string(), "Allow".to_string()),
            ("Private".to_string(), "NotConfigured".to_string()),
            ("Public".to_string(), "Block".to_string()),
        ];
        let cmds = build_uninstall_commands(&snapshot);
        let joined = cmds
            .iter()
            .skip(1)
            .map(|c| c.join(" "))
            .collect::<Vec<_>>()
            .join(" || ");
        assert!(joined.contains("Domain -DefaultOutboundAction Allow"));
        assert!(joined.contains("Private -DefaultOutboundAction NotConfigured"));
        assert!(joined.contains("Public -DefaultOutboundAction Block"));
    }

    #[test]
    fn parse_default_outbound_actions_extracts_all_three_profiles() {
        // Recorded `Get-NetFirewallProfile -Profile Domain,Private,Public
        // | Format-List Name,DefaultOutboundAction` output. Anchors the
        // parser against the canonical PowerShell `Format-List` shape;
        // a future PowerShell change to label casing / whitespace
        // surfaces here, not in production.
        let fixture = "
Name                  : Domain
DefaultOutboundAction : Allow

Name                  : Private
DefaultOutboundAction : NotConfigured

Name                  : Public
DefaultOutboundAction : Block
";
        let pairs = parse_default_outbound_actions(fixture);
        assert_eq!(
            pairs,
            vec![
                ("Domain".to_string(), "Allow".to_string()),
                ("Private".to_string(), "NotConfigured".to_string()),
                ("Public".to_string(), "Block".to_string()),
            ]
        );
    }

    #[test]
    fn parse_default_outbound_actions_yields_empty_on_garbage_input() {
        // Defensive: on a totally unexpected output (PowerShell error,
        // localised system, etc.) we must NOT fabricate fake pairs -
        // the install path checks the count and aborts cleanly,
        // preventing a bogus uninstall path.
        assert!(parse_default_outbound_actions("").is_empty());
        assert!(parse_default_outbound_actions("totally unrelated\nstuff").is_empty());
    }

    // ---- install rollback (mock async runner) ------------------------

    /// Recording [`PsCommandRunner`] that fails at invocation index
    /// `fail_at` (counting only the install-phase calls is not needed:
    /// the index is global, and rollback calls come after the failure).
    struct ScriptedRunner {
        calls: std::sync::Mutex<Vec<Vec<String>>>,
        fail_at: Option<usize>,
    }

    impl ScriptedRunner {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                fail_at,
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().expect("mutex").clone()
        }
    }

    impl PsCommandRunner for ScriptedRunner {
        async fn run(&self, args: &[String]) -> Result<(), KillswitchError> {
            let index = {
                let mut calls = self.calls.lock().expect("mutex");
                calls.push(args.to_vec());
                calls.len() - 1
            };
            if self.fail_at == Some(index) {
                return Err(KillswitchError::Windows(format!(
                    "mock powershell failure at command {index}"
                )));
            }
            Ok(())
        }
    }

    fn snapshot() -> Vec<(String, String)> {
        vec![
            ("Domain".to_string(), "Allow".to_string()),
            ("Private".to_string(), "NotConfigured".to_string()),
            ("Public".to_string(), "Allow".to_string()),
        ]
    }

    #[tokio::test]
    async fn install_failure_after_block_restores_captured_default_actions() {
        // Index 0 = the global Block flip, index 1 = tun allow rule,
        // index 2 = the first exit-IP allow rule -> fail there. The
        // host is blocked at that point; without the restore sequence
        // it stays blocked with no guard to fix it (the historical
        // support-net-1 bug: `?` propagated without restoration).
        let runner = ScriptedRunner::new(Some(2));
        let opts = opts_minimal();
        let actions = snapshot();
        let err = run_install_with_rollback(&runner, &opts, &actions, TEST_DAEMON_EXE)
            .await
            .expect_err("install must surface the command failure");
        assert!(matches!(err, KillswitchError::Windows(_)), "got {err:?}");

        let calls = runner.calls();
        let install_cmds = build_install_commands(&opts, TEST_DAEMON_EXE);
        let restore_cmds = build_uninstall_commands(&actions);
        assert_eq!(
            calls.len(),
            3 + restore_cmds.len(),
            "3 install attempts (block, tun, failed exit rule) then the \
             full restore sequence; calls: {calls:#?}"
        );
        assert_eq!(
            &calls[..3],
            &install_cmds[..3],
            "install commands must run in build_install_commands order"
        );
        assert_eq!(
            &calls[3..],
            &restore_cmds[..],
            "after the failure, the exact uninstall sequence (rule \
             cleanup + per-profile DefaultOutboundAction restore) must \
             run so the host is not left blocked"
        );
    }

    #[tokio::test]
    async fn install_failure_on_the_block_flip_itself_still_restores() {
        // PowerShell may apply `Set-NetFirewallProfile -Profile
        // Domain,Private,Public` to a subset of profiles before
        // erroring: the captured defaults must be restored even when
        // the very first command fails.
        let runner = ScriptedRunner::new(Some(0));
        let actions = snapshot();
        let err = run_install_with_rollback(&runner, &opts_minimal(), &actions, TEST_DAEMON_EXE)
            .await
            .expect_err("install must surface the failure");
        assert!(matches!(err, KillswitchError::Windows(_)));

        let calls = runner.calls();
        let restore_cmds = build_uninstall_commands(&actions);
        assert_eq!(
            &calls[1..],
            &restore_cmds[..],
            "the restore sequence must run even when the Block flip \
             itself failed (partial multi-profile application)"
        );
    }

    #[tokio::test]
    async fn successful_install_runs_no_restore_command() {
        let runner = ScriptedRunner::new(None);
        let opts = opts_minimal();
        run_install_with_rollback(&runner, &opts, &snapshot(), TEST_DAEMON_EXE)
            .await
            .expect("clean install");
        assert_eq!(
            runner.calls(),
            build_install_commands(&opts, TEST_DAEMON_EXE),
            "a clean install must run exactly the install commands - a \
             spurious restore would yank the Block default from under \
             the live killswitch"
        );
    }

    #[test]
    fn rule_prefix_is_unique_enough_to_not_collide_with_other_apps() {
        // The uninstall step matches `warren-killswitch-*`. If the
        // prefix changes to a generic word like `warren-*` we risk
        // deleting unrelated rules from other Warren-suite tools.
        // Anchored to keep the namespace isolated.
        assert!(RULE_PREFIX.starts_with("warren-killswitch-"));
        assert!(RULE_PREFIX.contains('-'));
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
        fn run_sync_bounded_returns_none_for_a_missing_program() {
            // Absolute path into a directory that cannot exist: a bare
            // program name goes through the Windows executable-search rules
            // (test-exe dir, CWD, PATH, App Execution Aliases), which are
            // environment-dependent and resolved to something on hosted CI
            // runners, flaking this test. Spawn failure itself is what the
            // killswitch relies on mapping to None.
            assert!(
                run_sync_bounded(
                    "C:\\warren-test-missing-dir\\definitely-not-a-real-binary.exe",
                    &[],
                    Duration::from_secs(1)
                )
                .is_none()
            );
        }
    }
}
