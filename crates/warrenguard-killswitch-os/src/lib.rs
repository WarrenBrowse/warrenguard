//! Warren killswitch - prevents off-tunnel traffic leaks while a
//! client tunnel is active.
//!
//! ## Architecture
//!
//! - [`KillswitchOpts`]: config (exit IPs, TUN name, LAN/DHCP
//!   exceptions).
//! - [`build_linux_ruleset`]: *pure* helper that generates the
//!   nftables ruleset as a `String`. Testable without privileges or
//!   shell-out.
//! - [`LinuxKillswitch`]: install/uninstall via shell-out
//!   `nft -f -` / `nft delete table inet warrenguard_killswitch_os`.
//!
//! ## Platforms
//!
//! - Linux: nftables ([`build_linux_ruleset`] + [`LinuxKillswitch`]).
//! - macOS: pf ([`build_macos_pf_ruleset`] + [`MacosKillswitch`]).
//! - Windows: PowerShell `New-NetFirewallRule` (= Windows Filtering
//!   Platform via user-space surface), implemented in [`mod@windows`].
//!   A native WFP-API binding (no PowerShell shell-out) is a
//!   follow-up hardening
//!   item; the PowerShell path is the same approach WireGuard /
//!   OpenVPN / Mullvad ship today and is production-grade.
//!
//! ## Strategy
//!
//! Install a dedicated nft table `inet warrenguard_killswitch_os` with an
//! `output` chain set to *policy drop*. Only the following is
//! permitted:
//! - `lo` (loopback, required),
//! - the TUN tunnel (the client emits encrypted traffic there),
//! - UDP to the exit IPs (QUIC handshake + keepalive).
//!
//! With optional `--allow-lan` and `--allow-dhcp` exceptions. No clear
//! traffic escapes the tunnel. On clean shutdown (Ctrl-C / SIGTERM /
//! explicit `uninstall`), the table is removed - the output chain
//! falls back to the OS default behavior.
//!
//! ## Failure semantics (fail-closed)
//!
//! What happens on a *panic* depends on the build profile:
//!
//! - **Debug builds** unwind, so the guard's `Drop` runs and
//!   best-effort removes the table.
//! - **Release builds** compile with `panic = "abort"` (workspace
//!   profile): NO destructor runs on a panic, and the firewall rules
//!   stay installed. The host keeps blocking all off-tunnel traffic -
//!   no leak, but also no connectivity - until
//!   `nft delete table inet warrenguard_killswitch_os` (Linux) /
//!   `pfctl -a com.apple/250.warrenguard_killswitch_os -F rules` (macOS) is
//!   run manually or the host reboots. This is deliberate: a crash
//!   must never fail open.
//!
//! `Drop` still matters for the non-panic abnormal paths (early
//! `?` return, task abort, scope exit without `uninstall().await`).

#![warn(missing_docs)]

use std::net::IpAddr;

// Not part of the public API: a typed builder consumed only by
// `build_linux_ruleset` below. `pub(crate)` keeps it out of `missing_docs`
// scope (its structs mirror nftables syntax field-for-field, documenting
// each one would only restate the field name) while still allowing the
// module to grow its own dedicated tests.
pub(crate) mod nft_typed;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{MacosKillswitch, PF_ANCHOR_PATH, build_pf_rules};

// Windows module is left non-gated so its pure command builders + tests
// compile on every host. The runtime exec type (`WindowsKillswitch`) is
// itself `cfg(target_os = "windows")` inside the module.
mod windows;

#[cfg(target_os = "windows")]
pub use windows::WindowsKillswitch;
pub use windows::{
    FIREWALL_PROFILES as WINDOWS_FIREWALL_PROFILES, PsCommandRunner,
    RULE_PREFIX as WINDOWS_RULE_PREFIX, build_install_commands as build_windows_install_commands,
    build_uninstall_commands as build_windows_uninstall_commands,
    format_install_log as format_windows_install_log,
    parse_default_outbound_actions as parse_windows_default_outbound_actions,
    run_install_with_rollback as run_windows_install_with_rollback,
};

/// Configuration options for a Warren killswitch.
///
/// ## Socket-scoping the tunnel's own exception (Port Fail / TunnelCrack-ServerIP)
///
/// The naive off-tunnel exception - "allow outbound UDP whose
/// *destination* is the exit IP" - is exploitable: it is a
/// destination-based rule, so it grants the exception to *any* local
/// process that dials the exit IP, not just the Warren daemon. Under
/// split-default routing (system-VPN mode) the exit IP is deliberately
/// routed outside the TUN, so an attacker-controlled or curious app
/// that connects directly to the exit's address leaks the connection
/// in the clear - the "Port Fail" variant of the TunnelCrack
/// ServerIP attack.
///
/// The fix is to scope the exception to the daemon's *own socket*
/// instead of the destination: [`socket_mark`](Self::socket_mark) on
/// Linux (`SO_MARK` + `meta mark <mark> accept`) and
/// [`phys_iface`](Self::phys_iface) on macOS (`IP_BOUND_IF` +
/// `on <iface>`). With either set, the split-default route captures
/// the exit IP into the tunnel like any other destination, and only
/// the daemon's tagged/bound socket keeps bypassing it. `None`
/// preserves the legacy destination-based exception for callers that
/// have not wired up socket tagging yet.
#[derive(Debug, Clone)]
pub struct KillswitchOpts {
    /// All IP addresses where the Warren exit may be reachable
    /// (typically v4 + v6 if dual-stack). Outbound UDP to these IPs is
    /// allowed off-tunnel to enable QUIC handshake and keepalive.
    /// If empty → no UDP traffic is allowed off-tunnel, so the
    /// initial handshake is impossible.
    ///
    /// Ignored on Linux when [`socket_mark`](Self::socket_mark) is
    /// `Some` (the mark-based rule replaces the per-exit exception).
    pub exit_addrs: Vec<IpAddr>,

    /// Name of the Warren TUN interface. All traffic emitted from this
    /// interface is allowed (the tunnel encrypts then redirects).
    pub tun_name: String,

    /// If `true`, allows traffic to RFC1918 / ULA / link-local
    /// destinations off-tunnel. Useful to avoid breaking local SSH,
    /// printers, etc. Otherwise (recommended prod default), everything
    /// exits via the tunnel except the exit itself.
    pub allow_lan: bool,

    /// If `true`, allows UDP 67/68 (DHCP client) so that network
    /// configuration is not lost if the lease expires while the tunnel
    /// is up.
    pub allow_dhcp: bool,

    /// Linux firewall mark (`SO_MARK`) applied to the daemon's own
    /// tunnel-establishment socket. When `Some(mark)`, the nftables
    /// ruleset allows the marked socket instead of the per-exit
    /// `ip daddr <exit>` exception, closing the Port Fail hole
    /// described above (see the struct doc). `None` keeps the legacy
    /// exit-address exception.
    pub socket_mark: Option<u32>,

    /// Name of the physical egress interface (e.g. `en0`) the daemon
    /// binds its tunnel socket to via `IP_BOUND_IF`. When `Some(iface)`,
    /// the macOS pf exit-IP pass rule is scoped `on <iface>` instead of
    /// being interface-agnostic, closing the same Port Fail hole on
    /// macOS. `None` keeps the legacy unscoped exit-address rule.
    pub phys_iface: Option<String>,
}

/// Name of the nftables table used by the killswitch. Reserved for
/// Warren.
pub const NFT_TABLE_NAME: &str = "warrenguard_killswitch_os";

/// Canonical teardown argv for the Linux killswitch (`nft delete table
/// inet warrenguard_killswitch_os`). Shared by the explicit `uninstall` path
/// and the `Drop` rollback so both tear down the exact same table.
const NFT_DELETE_TABLE_ARGS: [&str; 4] = ["delete", "table", "inet", NFT_TABLE_NAME];

/// Outcome of one firewall command execution, reduced to what the
/// killswitch lifecycle needs (success flag + captured stderr).
/// Mirrors `std::process::Output` without the unconstructible
/// `ExitStatus`, so test runners can fabricate failures.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// `true` iff the process exited with status 0.
    pub success: bool,
    /// Captured stderr (lossy UTF-8). Feeds error messages and the
    /// "table already absent" idempotence check on uninstall.
    pub stderr: String,
}

/// Execution seam for the external firewall commands (`nft` on Linux).
///
/// The production implementation ([`ProcessRunner`]) spawns the real
/// process; tests inject a recording mock so the install / uninstall /
/// `Drop` rollback lifecycle is verified *behaviorally* (which exact
/// command runs, and when) without privileges. Synchronous on purpose:
/// the fail-closed rollback runs inside `Drop`, which cannot `await`.
/// Async call sites wrap invocations in `spawn_blocking`.
pub trait CommandRunner: Send + Sync + std::fmt::Debug {
    /// Run `program` with `args`, optionally piping `stdin` into it,
    /// and wait for completion.
    ///
    /// # Errors
    ///
    /// `std::io::Error` when the process cannot be spawned or its I/O
    /// pipes fail. A non-zero exit status is NOT an `Err`; it is
    /// reported through [`CommandOutput::success`].
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> std::io::Result<CommandOutput>;
}

/// Production [`CommandRunner`]: spawns the real process via
/// `std::process::Command`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&str>,
    ) -> std::io::Result<CommandOutput> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        if let Some(content) = stdin {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| std::io::Error::other("child stdin pipe missing"))?;
            pipe.write_all(content.as_bytes())?;
            drop(pipe);
        }
        let out = child.wait_with_output()?;
        Ok(CommandOutput {
            success: out.status.success(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Backend-agnostic install/uninstall lifecycle for a Warren
/// killswitch. Each platform impl (Linux nftables / macOS pf /
/// Windows PowerShell-or-WFP) realises this surface; binaries can
/// swap implementations behind feature flags without touching the
/// call sites.
///
/// Provides a stable seam so a future `WindowsKillswitchWfp`
/// native-API implementation can drop in next to `WindowsKillswitch`
/// (PowerShell) without API churn at the consuming-binary level.
#[allow(async_fn_in_trait)]
pub trait KillswitchBackend: Sized {
    /// Install the killswitch, returning a guard whose drop releases
    /// the rules best-effort. Note that with `panic = "abort"`
    /// (release profile) no `Drop` runs on a panic: the rules then
    /// stay installed, fail-closed (cf. crate-level doc).
    ///
    /// # Errors
    /// - [`KillswitchError::InvalidInput`] on bad options
    /// - Backend-specific variants (`Nft`, `Pf`) on tool failure
    async fn install_with(opts: &KillswitchOpts) -> Result<Self, KillswitchError>;

    /// Explicit uninstall. Preferred over relying on `Drop` so error
    /// surfaces aren't swallowed.
    ///
    /// # Errors
    /// Backend-specific failure from the underlying syscall / tool.
    async fn uninstall_explicit(self) -> Result<(), KillswitchError>;
}

/// Error returned by Linux killswitch operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KillswitchError {
    /// Input validation failed (TUN name with suspicious characters,
    /// etc.).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// `nft` is missing, cannot be spawned, or exits with an error
    /// (insufficient privileges, invalid ruleset, etc.).
    #[error("nft execution failed: {0}")]
    Nft(String),

    /// `pfctl` (macOS) is missing, cannot be spawned, or exits with an
    /// error (insufficient privileges, invalid ruleset, etc.).
    #[error("pfctl execution failed: {0}")]
    Pf(String),

    /// `powershell.exe` / `New-NetFirewallRule` / `Set-NetFirewallProfile`
    /// (Windows) is missing, cannot be spawned, exits with an error
    /// (insufficient privileges - not Administrator - or a rejected
    /// command), or the running binary's own path could not be resolved
    /// (needed for the WFP app-id scoping fix, see [`mod@windows`]).
    #[error("Windows firewall operation failed: {0}")]
    Windows(String),

    /// I/O between Warren and the firewall process (pipe closed, etc.).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Validates that a TUN interface name is safe to interpolate into a
/// firewall ruleset (Linux nftables or macOS pf) without causing a
/// syntactic regression. Expected format: 1-15 ASCII characters from
/// `[a-zA-Z0-9_-]` (Linux limit IFNAMSIZ = 16 with NUL terminator;
/// macOS utun* respects the same bound).
///
/// Public so a consumer's policy-routing code can reuse the same
/// logic without duplication.
///
/// # Errors
///
/// [`KillswitchError::InvalidInput`] if the name is empty, > 15
/// characters, or contains characters outside `[a-zA-Z0-9_-]`.
pub fn validate_tun_name(name: &str) -> Result<(), KillswitchError> {
    if name.is_empty() || name.len() > 15 {
        return Err(KillswitchError::InvalidInput(format!(
            "tun_name length {} out of range [1, 15]",
            name.len()
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(KillswitchError::InvalidInput(format!(
            "tun_name {name:?} contains characters outside [a-zA-Z0-9_-]"
        )));
    }
    Ok(())
}

/// Generates the nftables ruleset implementing the Linux killswitch.
///
/// **Pure**: no shell-out, no privileges required, directly testable.
/// The caller (typically [`LinuxKillswitch::install`]) pipes the
/// string into `nft -f -`.
///
/// The ruleset uses the atomic update pattern: `add table`
/// (idempotent, no-op if the table exists) + `flush table` (clears
/// existing chains) + `table { ... }` (re-declares the output chain
/// with rules). Semantically explicit and robust across nft versions.
#[must_use]
pub fn build_linux_ruleset(opts: &KillswitchOpts) -> String {
    nft_typed::build_killswitch_ruleset(
        NFT_TABLE_NAME,
        &opts.tun_name,
        &opts.exit_addrs,
        opts.allow_lan,
        opts.allow_dhcp,
        opts.socket_mark,
    )
    .render()
}

/// nftables-based Linux killswitch. Represents the "installed" state:
/// the instance cannot be created without calling [`Self::install`],
/// which shells out to `nft -f -`. Uninstall is explicit via
/// [`Self::uninstall`] (or `Drop` for best-effort cleanup).
///
/// `Drop` is not async, so cleanup is attempted synchronously via the
/// injected [`CommandRunner`] on a best-effort basis. Callers should
/// prefer explicit `uninstall().await` to surface errors.
///
/// The type is intentionally NOT `cfg(target_os = "linux")`-gated
/// (same pattern as the [`mod@windows`] command builders): the whole
/// lifecycle compiles on every host so the fail-closed rollback is
/// testable behaviorally with a mock runner. The default runner
/// shells out to `nft`, which only exists on Linux at runtime.
#[derive(Debug)]
pub struct LinuxKillswitch {
    /// Marker that the table has been installed. Drop uses this for a
    /// best-effort delete.
    installed: bool,
    /// Command execution seam ([`ProcessRunner`] in production).
    runner: std::sync::Arc<dyn CommandRunner>,
}

impl LinuxKillswitch {
    /// Installs the killswitch by injecting the Warren ruleset via
    /// `nft -f -`. Idempotent: the ruleset starts with `flush table`
    /// which clears any previous installation.
    ///
    /// # Errors
    ///
    /// - [`KillswitchError::InvalidInput`] if `opts.tun_name` is not a
    ///   valid identifier.
    /// - [`KillswitchError::Nft`] if `nft` is not in `$PATH`, lacks
    ///   privileges (`CAP_NET_ADMIN`), or rejects the ruleset.
    pub async fn install(opts: &KillswitchOpts) -> Result<Self, KillswitchError> {
        Self::install_with_runner(opts, std::sync::Arc::new(ProcessRunner)).await
    }

    /// Same lifecycle as [`Self::install`], through an injected
    /// [`CommandRunner`]. This is the behavioral-test seam: a recording
    /// mock observes exactly which `nft` invocations the install /
    /// uninstall / `Drop` rollback paths emit.
    ///
    /// # Errors
    ///
    /// Same as [`Self::install`].
    pub async fn install_with_runner(
        opts: &KillswitchOpts,
        runner: std::sync::Arc<dyn CommandRunner>,
    ) -> Result<Self, KillswitchError> {
        validate_tun_name(&opts.tun_name)?;
        let ruleset = build_linux_ruleset(opts);
        run_nft_with_stdin(runner.clone(), ruleset).await?;
        tracing::info!(
            tun = %opts.tun_name,
            exit_count = opts.exit_addrs.len(),
            allow_lan = opts.allow_lan,
            allow_dhcp = opts.allow_dhcp,
            "Warren killswitch installed (nftables)"
        );
        Ok(Self {
            installed: true,
            runner,
        })
    }

    /// Removes the Warren nftables table. Idempotent. Marks the
    /// instance as uninstalled so `Drop` does not retry.
    ///
    /// # Errors
    ///
    /// [`KillswitchError::Nft`] if `nft delete table` fails for a
    /// reason other than the table being absent (which is tolerated).
    pub async fn uninstall(mut self) -> Result<(), KillswitchError> {
        let res = uninstall_table(self.runner.clone()).await;
        // Mark uninstalled even on error: if nft failed once, retrying
        // in Drop would only pollute logs.
        self.installed = false;
        res
    }
}

impl KillswitchBackend for LinuxKillswitch {
    async fn install_with(opts: &KillswitchOpts) -> Result<Self, KillswitchError> {
        Self::install(opts).await
    }
    async fn uninstall_explicit(self) -> Result<(), KillswitchError> {
        self.uninstall().await
    }
}

#[cfg(target_os = "macos")]
impl KillswitchBackend for MacosKillswitch {
    async fn install_with(opts: &KillswitchOpts) -> Result<Self, KillswitchError> {
        Self::install(opts).await
    }
    async fn uninstall_explicit(self) -> Result<(), KillswitchError> {
        self.uninstall().await
    }
}

#[cfg(target_os = "windows")]
impl KillswitchBackend for WindowsKillswitch {
    async fn install_with(opts: &KillswitchOpts) -> Result<Self, KillswitchError> {
        Self::install(opts).await
    }
    async fn uninstall_explicit(self) -> Result<(), KillswitchError> {
        self.uninstall().await
    }
}

impl Drop for LinuxKillswitch {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // Best-effort synchronous: cannot await inside Drop. If the
        // caller forgot `uninstall().await` (early return, task abort,
        // debug-build unwind), still try to remove the table so a
        // killswitch is not left active. NOTE: release builds use
        // `panic = "abort"`, so this never runs on an actual panic -
        // the rules then stay installed (fail-closed, cf. module doc).
        let res = self.runner.run("nft", &NFT_DELETE_TABLE_ARGS, None);
        match res {
            Ok(out) if out.success => {
                tracing::warn!(
                    "Warren killswitch was dropped without explicit uninstall - \
                     synchronous cleanup succeeded"
                );
            }
            Ok(out) => {
                tracing::error!(
                    stderr = %out.stderr.trim(),
                    "Warren killswitch Drop cleanup failed - the table may still \
                     be active. Run `sudo nft delete table inet warrenguard_killswitch_os` \
                     manually to recover internet"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Warren killswitch Drop cleanup could not invoke nft"
                );
            }
        }
    }
}

/// Pipes `ruleset` to `nft -f -` stdin via the runner and returns an
/// error if the process exits with a non-zero status.
///
/// `nft -f -` applies the piped ruleset *atomically*: on a non-zero
/// exit nothing was committed, so a failed install needs no rollback
/// (and the caller constructs no guard).
async fn run_nft_with_stdin(
    runner: std::sync::Arc<dyn CommandRunner>,
    ruleset: String,
) -> Result<(), KillswitchError> {
    let out = tokio::task::spawn_blocking(move || runner.run("nft", &["-f", "-"], Some(&ruleset)))
        .await
        .map_err(|e| KillswitchError::Nft(format!("join nft task: {e}")))?
        .map_err(|e| KillswitchError::Nft(format!("spawn nft: {e}")))?;

    if !out.success {
        return Err(KillswitchError::Nft(format!(
            "nft -f - failed: {}",
            out.stderr.trim()
        )));
    }
    Ok(())
}

async fn uninstall_table(runner: std::sync::Arc<dyn CommandRunner>) -> Result<(), KillswitchError> {
    let out = tokio::task::spawn_blocking(move || runner.run("nft", &NFT_DELETE_TABLE_ARGS, None))
        .await
        .map_err(|e| KillswitchError::Nft(format!("join nft task: {e}")))?
        .map_err(|e| KillswitchError::Nft(format!("spawn nft delete: {e}")))?;

    if out.success {
        tracing::info!("Warren killswitch uninstalled");
        return Ok(());
    }

    // `No such file or directory` when the table does not exist -
    // tolerated.
    if out.stderr.contains("No such") || out.stderr.contains("does not exist") {
        tracing::info!("Warren killswitch uninstall: table already absent (idempotent)");
        return Ok(());
    }

    Err(KillswitchError::Nft(format!(
        "nft delete table failed: {}",
        out.stderr.trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn opts_minimal() -> KillswitchOpts {
        KillswitchOpts {
            exit_addrs: vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            tun_name: "tun-warren".into(),
            allow_lan: false,
            allow_dhcp: false,
            socket_mark: None,
            phys_iface: None,
        }
    }

    #[test]
    fn ruleset_blocks_all_by_default_via_drop_policy() {
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            s.contains("policy drop;"),
            "must use drop policy for output chain - otherwise everything passes by default"
        );
    }

    #[test]
    fn ruleset_allows_loopback() {
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            s.contains("oifname \"lo\" accept"),
            "loopback must be allowed (DNS resolver local, IPC, etc.)"
        );
    }

    #[test]
    fn ruleset_allows_tunnel_interface_by_name() {
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            s.contains("oifname \"tun-warren\" accept"),
            "the TUN interface name must appear verbatim - that is where all legitimate \
             traffic exits"
        );
    }

    #[test]
    fn ruleset_allows_udp_to_exit_ipv4() {
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            s.contains("ip daddr 1.2.3.4 meta l4proto udp accept"),
            "exit IPv4 must be allowed for handshake + keepalive"
        );
    }

    #[test]
    fn ruleset_allows_udp_to_exit_ipv6() {
        let mut o = opts_minimal();
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0xc013, 0x14a1, 0, 0, 0, 1);
        o.exit_addrs.push(IpAddr::V6(v6));
        let s = build_linux_ruleset(&o);
        assert!(
            s.contains("ip6 daddr 2001:db8:c013:14a1::1 meta l4proto udp accept"),
            "exit IPv6 must be allowed (dual-stack handshake)"
        );
    }

    #[test]
    fn ruleset_without_socket_mark_keeps_legacy_exit_daddr_accept() {
        // Back-compat: a caller that has not wired up SO_MARK tagging
        // still gets the historical destination-based exception.
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            s.contains("ip daddr 1.2.3.4 meta l4proto udp accept"),
            "socket_mark: None must preserve the legacy per-exit exception"
        );
    }

    #[test]
    fn ruleset_with_socket_mark_replaces_exit_daddr_with_meta_mark_accept() {
        // Port Fail / TunnelCrack-ServerIP fix: a destination-based
        // exception lets ANY app dialing the exit IP escape the
        // tunnel. Scoping the exception to the daemon's own marked
        // socket closes that hole - the exit IP is then captured into
        // the tunnel like any other destination.
        let mut o = opts_minimal();
        o.socket_mark = Some(0x7761_7272);
        let s = build_linux_ruleset(&o);
        assert!(
            s.contains("meta mark 0x77617272 accept"),
            "expected the socket-mark accept rule, got:\n{s}"
        );
        assert!(
            !s.contains("ip daddr 1.2.3.4"),
            "the per-exit destination exception must NOT be emitted \
             when socket_mark is set - that is the leak this closes:\n{s}"
        );
        assert!(
            s.contains("policy drop;"),
            "fail-closed default must be preserved regardless of socket_mark"
        );
        assert!(
            s.contains("oifname \"lo\" accept"),
            "loopback exception must be preserved regardless of socket_mark"
        );
        assert!(
            s.contains("oifname \"tun-warren\" accept"),
            "tunnel exception must be preserved regardless of socket_mark"
        );
    }

    #[test]
    fn ruleset_does_not_allow_lan_by_default() {
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            !s.contains("192.168.0.0/16"),
            "LAN must be blocked by default - kill switch strict means no leak"
        );
    }

    #[test]
    fn ruleset_includes_lan_ranges_when_allow_lan_set() {
        let mut o = opts_minimal();
        o.allow_lan = true;
        let s = build_linux_ruleset(&o);
        assert!(s.contains("ip daddr 192.168.0.0/16 accept"));
        assert!(s.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(s.contains("ip daddr 172.16.0.0/12 accept"));
        assert!(s.contains("ip6 daddr fc00::/7 accept"));
    }

    #[test]
    fn ruleset_does_not_allow_dhcp_by_default() {
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            !s.contains("dport {67, 68}"),
            "DHCP must be blocked by default - opt-in via allow_dhcp"
        );
    }

    #[test]
    fn ruleset_allows_dhcp_when_set() {
        let mut o = opts_minimal();
        o.allow_dhcp = true;
        let s = build_linux_ruleset(&o);
        assert!(s.contains("udp dport {67, 68} accept"));
    }

    #[test]
    fn ruleset_uses_atomic_update_pattern() {
        // We use `add table; flush table; table { ... }` (atomic
        // update) instead of `table; delete table; table { ... }`,
        // which used to create an intermediate empty table with
        // inverted semantics.
        let s = build_linux_ruleset(&opts_minimal());
        let add_pos = s
            .find("add table inet warrenguard_killswitch_os")
            .expect("add");
        let flush_pos = s
            .find("flush table inet warrenguard_killswitch_os")
            .expect("flush");
        let create_pos = s
            .find("table inet warrenguard_killswitch_os {")
            .expect("create body");
        assert!(add_pos < flush_pos, "add must come before flush");
        assert!(
            flush_pos < create_pos,
            "flush must come before the table body declaration"
        );
        assert!(
            !s.contains("delete table inet warrenguard_killswitch_os"),
            "anti-regression: do not bring back the `delete table` pattern that \
             created an intermediate empty table"
        );
    }

    #[test]
    fn ruleset_with_no_exit_addrs_yields_no_udp_accept_lines() {
        let mut o = opts_minimal();
        o.exit_addrs.clear();
        let s = build_linux_ruleset(&o);
        assert!(
            !s.contains("meta l4proto udp accept"),
            "without exit addrs, no UDP traffic must escape the killswitch - \
             handshake will simply fail (acceptable: better fail than leak)"
        );
    }

    #[test]
    fn ruleset_uses_constant_table_name() {
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            s.contains(NFT_TABLE_NAME),
            "the public NFT_TABLE_NAME constant must be used so uninstall can target it"
        );
    }

    #[test]
    fn ruleset_does_not_use_ct_state_established() {
        let s = build_linux_ruleset(&opts_minimal());
        assert!(
            !s.contains("ct state"),
            "ct state established,related leaks pre-killswitch connections - \
             explicit interface/IP rules already cover all legitimate output"
        );
    }

    #[test]
    fn validate_tun_name_accepts_typical_warren_names() {
        validate_tun_name("warren0").expect("warren0 is a valid linux iface name");
        validate_tun_name("tun0").expect("tun0 is valid");
        validate_tun_name("warren-cli").expect("hyphenated is valid");
        validate_tun_name("utun7").expect("utun7 (macOS-style) valid syntactically");
    }

    #[test]
    fn validate_tun_name_rejects_empty() {
        assert!(matches!(
            validate_tun_name(""),
            Err(KillswitchError::InvalidInput(_))
        ));
    }

    #[test]
    fn validate_tun_name_rejects_overlong() {
        // IFNAMSIZ = 16 with NUL → 15 max.
        let too_long = "a".repeat(16);
        assert!(matches!(
            validate_tun_name(&too_long),
            Err(KillswitchError::InvalidInput(_))
        ));
    }

    #[test]
    fn validate_tun_name_rejects_shell_injection_attempt() {
        // Hypothetical attack where the name contains characters that
        // would break nft syntax. Not a shell-out risk (no shell is
        // used), but keeps the generated ruleset clean.
        for malicious in ["evil; nft delete", "with space", "back\\slash", "tab\there"] {
            assert!(
                matches!(
                    validate_tun_name(malicious),
                    Err(KillswitchError::InvalidInput(_))
                ),
                "{malicious:?} should be rejected"
            );
        }
    }

    // ---- install / uninstall error paths ----------------------------
    //
    // These exercise the error paths that bail BEFORE spawning `nft`,
    // so no `CAP_NET_ADMIN` and no privileged binary are required.
    // The lifecycle type compiles on every host (cf. struct doc), so
    // they run everywhere.

    #[tokio::test]
    async fn install_rejects_invalid_tun_name_before_nft_spawn() {
        // The validation runs before any privileged operation, so this
        // test passes on any box (including unprivileged CI).
        let mut opts = opts_minimal();
        opts.tun_name = "evil; nft delete".into();
        let err = LinuxKillswitch::install(&opts)
            .await
            .expect_err("install must reject malicious tun name");
        assert!(
            matches!(err, KillswitchError::InvalidInput(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn install_rejects_overlong_tun_name_before_nft_spawn() {
        // IFNAMSIZ - names beyond the kernel cap must be refused at
        // boundary, never silently truncated by nft.
        let mut opts = opts_minimal();
        opts.tun_name = "a".repeat(16);
        let err = LinuxKillswitch::install(&opts)
            .await
            .expect_err("install must reject overlong tun name");
        assert!(matches!(err, KillswitchError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn install_rejects_empty_tun_name_before_nft_spawn() {
        let mut opts = opts_minimal();
        opts.tun_name = String::new();
        let err = LinuxKillswitch::install(&opts)
            .await
            .expect_err("install must reject empty tun name");
        assert!(matches!(err, KillswitchError::InvalidInput(_)));
    }

    // ---- behavioral fail-closed lifecycle (mock runner) -------------
    //
    // The fail-closed contract used to be "tested" only by grepping
    // the source for `impl Drop` (tests/drop_rollback_contract.rs); an
    // empty Drop body would have passed. These tests verify the actual
    // behavior through the CommandRunner seam: which nft command runs,
    // with which arguments, and when.

    use std::sync::Arc;

    /// One recorded runner invocation: (program, args, stdin).
    type RecordedCall = (String, Vec<String>, Option<String>);

    #[derive(Debug, Default)]
    struct RecordingRunner {
        calls: std::sync::Mutex<Vec<RecordedCall>>,
        /// When `Some`, every invocation reports a non-zero exit with
        /// this stderr.
        fail_with_stderr: Option<String>,
    }

    impl RecordingRunner {
        fn failing(stderr: &str) -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                fail_with_stderr: Some(stderr.to_owned()),
            }
        }

        fn calls(&self) -> Vec<RecordedCall> {
            self.calls.lock().expect("runner mutex").clone()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            stdin: Option<&str>,
        ) -> std::io::Result<CommandOutput> {
            self.calls.lock().expect("runner mutex").push((
                program.to_owned(),
                args.iter().map(|s| (*s).to_owned()).collect(),
                stdin.map(str::to_owned),
            ));
            Ok(match &self.fail_with_stderr {
                Some(stderr) => CommandOutput {
                    success: false,
                    stderr: stderr.clone(),
                },
                None => CommandOutput {
                    success: true,
                    stderr: String::new(),
                },
            })
        }
    }

    #[tokio::test]
    async fn drop_invokes_the_exact_nft_teardown_command() {
        let runner = Arc::new(RecordingRunner::default());
        {
            let _guard = LinuxKillswitch::install_with_runner(&opts_minimal(), runner.clone())
                .await
                .expect("install through mock runner");
        } // <- guard dropped without explicit uninstall

        let calls = runner.calls();
        assert_eq!(
            calls.len(),
            2,
            "exactly install + teardown: an empty Drop (the regression \
             this test exists for) would leave only 1 call"
        );
        let (program, args, stdin) = &calls[0];
        assert_eq!(program, "nft");
        assert_eq!(args, &["-f", "-"], "install pipes the ruleset to nft -f -");
        assert!(
            stdin.as_deref().is_some_and(|s| s.contains(NFT_TABLE_NAME)),
            "the piped ruleset must declare the Warren table"
        );
        let (program, args, stdin) = &calls[1];
        assert_eq!(program, "nft");
        assert_eq!(
            args,
            &["delete", "table", "inet", "warrenguard_killswitch_os"],
            "Drop must remove the exact Warren table - the fail-closed \
             rollback the product depends on after an abnormal exit"
        );
        assert!(stdin.is_none(), "teardown takes no stdin");
    }

    #[tokio::test]
    async fn failed_install_constructs_no_guard_and_runs_no_teardown() {
        let runner = Arc::new(RecordingRunner::failing("Operation not permitted"));
        let err = LinuxKillswitch::install_with_runner(&opts_minimal(), runner.clone())
            .await
            .expect_err("install must surface the nft failure");
        assert!(matches!(err, KillswitchError::Nft(_)), "got {err:?}");

        let calls = runner.calls();
        assert_eq!(
            calls.len(),
            1,
            "nft -f - applies the ruleset atomically: a failed install \
             commits nothing, so no rollback command must run (and no \
             guard exists to emit one)"
        );
    }

    #[tokio::test]
    async fn explicit_uninstall_then_drop_tears_down_exactly_once() {
        let runner = Arc::new(RecordingRunner::default());
        let guard = LinuxKillswitch::install_with_runner(&opts_minimal(), runner.clone())
            .await
            .expect("install");
        guard.uninstall().await.expect("explicit uninstall");
        // `uninstall` consumed the guard and Drop already ran on its
        // `self` with installed=false: no double teardown.
        let calls = runner.calls();
        assert_eq!(
            calls.len(),
            2,
            "install + one teardown only: Drop after an explicit \
             uninstall must be a no-op (double-delete would error-log \
             on every clean shutdown)"
        );
    }

    #[tokio::test]
    async fn uninstall_tolerates_already_absent_table() {
        let runner = Arc::new(RecordingRunner::failing(
            "Error: No such file or directory; delete table inet warrenguard_killswitch_os",
        ));
        // Drive `uninstall_table` directly (install would fail with a
        // failing runner): it is the unit that owns the idempotence
        // contract for both `uninstall()` and the Drop path.
        uninstall_table(runner.clone())
            .await
            .expect("a missing table is the desired end state - uninstall must be idempotent");
        assert_eq!(runner.calls().len(), 1);
    }

    #[tokio::test]
    async fn uninstall_surfaces_real_nft_failures() {
        let runner = Arc::new(RecordingRunner::failing("Operation not permitted"));
        let err = uninstall_table(runner)
            .await
            .expect_err("a real nft failure (not 'absent table') must surface");
        assert!(matches!(err, KillswitchError::Nft(_)));
    }
}
