//! Privileged applier: runs the routing and killswitch plans (Linux).
//!
//! EXPERIMENTAL, requires root / `CAP_NET_ADMIN`, NOT YET REAL-EXIT VALIDATED.
//! Compiled only under the `experimental-tun` feature. The argv it runs come from
//! [`crate::plan`] (pure and unit-tested); this module is the thin process glue
//! that executes them, which can only be exercised with privilege.
//!
//! Shelling out to `ip`/`nft` (rather than linking a netlink crate) keeps the
//! default build dependency-free; the commands are the testable contract.

use std::io::{self, Write};
use std::process::{Command, Stdio};

use crate::plan::{KillswitchPlan, RoutingPlan, TunConfig};

/// Runs `argv`, optionally feeding `stdin`, and maps a non-zero exit to an error.
///
/// # Errors
///
/// The spawn error, or [`io::ErrorKind::Other`] if the command exits non-zero.
fn run(argv: &[String], stdin: Option<&str>) -> io::Result<()> {
    // Guard the slice index: a caller passing an empty argv is a bug, but it must
    // surface as a recoverable error, not a panic mid-teardown.
    let program = argv
        .first()
        .ok_or_else(|| io::Error::other("empty command argv"))?;
    let mut cmd = Command::new(program);
    cmd.args(&argv[1..]);
    // Discard the child's stdout/stderr: success/failure is read from the exit
    // status, and inheriting a parent pipe that is no longer drained would kill
    // the child with SIGPIPE when it writes (for example pfctl warnings).
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn()?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("no stdin pipe"))?
            .write_all(input.as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{program} exited with {status}")))
    }
}

/// Runs `argv` and returns its captured stdout, mapping a non-zero exit to an
/// error. Used for the read-only pf snapshot commands (`pfctl -s info`/`-sr`).
///
/// # Errors
///
/// The spawn error, or [`io::ErrorKind::Other`] if the command exits non-zero.
#[cfg(target_os = "macos")]
fn run_capture(argv: &[String]) -> io::Result<String> {
    let program = argv
        .first()
        .ok_or_else(|| io::Error::other("empty command argv"))?;
    let out = Command::new(program)
        .args(&argv[1..])
        .stderr(Stdio::null())
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{program} exited with {}",
            out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Where the pre-apply pf snapshot is saved so teardown can restore it. Kept in
/// root-owned `/var/run` (not world-writable `/tmp`): the killswitch only runs
/// as root, and a non-root-writable directory denies a symlink-swap on the path.
#[cfg(target_os = "macos")]
fn pf_backup_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/run/warren-killswitch-pf-backup.conf")
}

/// Configures the TUN interface BEFORE routing: assigns the tunnel address(es),
/// sets the MTU, and brings the link up (a freshly opened device is down and
/// unaddressed, so routes via it do nothing until this runs).
///
/// # Errors
///
/// The first `ip` invocation that fails.
pub fn configure_interface(config: &TunConfig) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let cmds = config.interface_up_commands_macos();
    #[cfg(not(target_os = "macos"))]
    let cmds = config.interface_up_commands();
    for argv in cmds {
        run(&argv, None)?;
    }
    Ok(())
}

/// Applies the split-default capture `plan` to the `dev` device. The exit's
/// carrier socket is kept on the physical link by its [`SocketBypass`] (a socket
/// mark/bind set in the transport layer), not by a route, so this installs no
/// host-route exception to the exit: application traffic to the exit IP is
/// captured by the tunnel like anything else (Port Fail / TunnelCrack ServerIP
/// fix).
///
/// # Errors
///
/// The first `ip route`/`ip rule` (Linux) or `route` (macOS) invocation that
/// fails.
pub fn apply_routing(plan: &RoutingPlan, dev: &str) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let cmds = plan.to_macos_commands(dev, "add");
    #[cfg(not(target_os = "macos"))]
    let cmds = plan.to_ip_commands(dev);
    for argv in cmds {
        run(&argv, None)?;
    }
    Ok(())
}

/// Loads the killswitch ruleset (`nft -f -` on Linux, `pfctl` on macOS), failing
/// closed. `phys_iface` is the physical egress interface name; the macOS pf
/// ruleset scopes the datapath socket's exit accept to it (the Linux nftables
/// ruleset keys on the socket mark instead and ignores it).
///
/// # Errors
///
/// If `nft`/`pfctl` cannot be run or rejects the ruleset.
pub fn apply_killswitch(config: &TunConfig, phys_iface: &str) -> io::Result<()> {
    apply_killswitch_impl(config, phys_iface)
}

#[cfg(target_os = "macos")]
fn apply_killswitch_impl(config: &TunConfig, phys_iface: &str) -> io::Result<()> {
    // A backup still on disk means a previous datapath died before its Drop
    // teardown ran (SIGKILL, Ctrl-C outside the runtime): the host is still
    // carrying that run's killswitch. Restore it FIRST. Snapshotting without
    // this would capture the stale block-all ruleset as the "pre-existing
    // state" and teardown would restore the poison, stranding the host with no
    // egress until someone hand-repairs pf (observed on a dev Mac 2026-07-12).
    if pf_backup_path().exists() {
        let _ = teardown_killswitch_impl();
    }
    // Snapshot pf's prior state BEFORE touching it, so teardown restores the
    // pre-existing ruleset and enable-state instead of wiping them (the old
    // teardown ran `pfctl -F rules` + `-d`, clobbering any host firewall config
    // and fighting pf's `-E` refcount when another VPN was already running).
    //
    // Best-effort and non-fatal: the read-only `pfctl -s info`/`-sr` snapshot
    // never blocks installing the killswitch. If it fails, teardown finds no
    // backup and falls back to the old flush+disable. The killswitch rules and
    // `-E` enable below are unchanged, so this cannot weaken the active block.
    if let Ok(info) = run_capture(&KillswitchPlan::pf_show_info_argv())
        && let Ok(rules) = run_capture(&KillswitchPlan::pf_show_rules_argv())
    {
        let was_enabled = KillswitchPlan::pf_status_is_enabled(&info);
        let backup = format!("{}{}", KillswitchPlan::pf_backup_header(was_enabled), rules);
        write_pf_backup_at(&pf_backup_path(), &backup);
    }
    run(
        &KillswitchPlan::pf_load_argv(),
        Some(&KillswitchPlan::pf_rules(config, phys_iface)),
    )?;
    run(&KillswitchPlan::pf_enable_argv(), None)
}

/// Writes the pf ruleset snapshot, unless one is already on disk: an existing
/// backup is the true pre-warren state from a run that died before teardown,
/// and must survive (second line of defense behind the reconcile above).
#[cfg(target_os = "macos")]
fn write_pf_backup_at(path: &std::path::Path, backup: &str) {
    if path.exists() {
        return;
    }
    let _ = std::fs::write(path, backup);
}

#[cfg(not(target_os = "macos"))]
fn apply_killswitch_impl(config: &TunConfig, phys_iface: &str) -> io::Result<()> {
    // Linux keys the exit accept on the socket firewall mark, so the physical
    // interface name is not needed here.
    let _ = phys_iface;
    // Idempotent after a dirty crash: a stale `warren_killswitch` table left by
    // a datapath that died before teardown would make `nft -f` fail (the chain
    // already exists) and leave the host fail-closed with no way forward.
    // Deleting a table that does not exist just fails, which is ignored.
    let _ = run(&KillswitchPlan::nft_teardown_argv(), None);
    run(
        &KillswitchPlan::nft_apply_argv(),
        Some(&KillswitchPlan::nftables(config).nftables),
    )
}

/// Reverts the routes [`apply_routing`] installed (best-effort: a route already
/// gone is not fatal, so individual `ip route del` failures are ignored). Pair
/// this with [`teardown_killswitch`] to fully restore the routing table on
/// datapath shutdown.
pub fn revert_routing(plan: &RoutingPlan, dev: &str) {
    #[cfg(target_os = "macos")]
    let cmds = plan.to_macos_commands(dev, "delete");
    #[cfg(not(target_os = "macos"))]
    let cmds = plan.to_teardown_commands(dev);
    for argv in cmds {
        let _ = run(&argv, None);
    }
}

/// Pushes the exit-assigned DNS resolvers and routes EVERY query through the
/// tunnel, closing the DNS-leak vector: once the split-default routing captures
/// traffic, lookups must not keep hitting the host's prior resolver. No-op when
/// the exit assigned no DNS.
///
/// - **Linux** (systemd-resolved): sets the per-link resolvers + the `~.` routing
///   domain (`resolvectl`), reverted cleanly per link.
/// - **macOS** (`networksetup`): snapshots the primary service's current resolvers
///   to a root-owned backup, then points that service at the in-tunnel resolver;
///   [`revert_dns`] restores the snapshot. Like the routing/killswitch appliers
///   here, the macOS path is implemented but its live behaviour is pending a
///   rooted real-exit validation.
///
/// # Errors
///
/// The first `resolvectl` (Linux) or `networksetup` (macOS) invocation that fails.
pub fn apply_dns(config: &TunConfig) -> io::Result<()> {
    #[cfg(not(target_os = "macos"))]
    for argv in config.dns_push_commands_linux() {
        run(&argv, None)?;
    }
    #[cfg(target_os = "macos")]
    if !config.dns.is_empty() {
        // Same dirty-crash reconcile as the killswitch: a backup still on disk
        // means a previous run's resolver override is still applied. Restore it
        // before snapshotting, so the snapshot below captures the host's real
        // resolvers and not the stale in-tunnel one.
        if dns_backup_path().exists() {
            revert_dns(config);
        }
        let listing = run_capture(&[
            "networksetup".to_owned(),
            "-listnetworkserviceorder".to_owned(),
        ])?;
        let service = crate::plan::parse_primary_network_service(&listing)
            .ok_or_else(|| io::Error::other("no primary network service to set DNS on"))?;
        // Snapshot the current resolvers BEFORE overriding them, so teardown
        // restores the exact prior config instead of clobbering it.
        let current = run_capture(&[
            "networksetup".to_owned(),
            "-getdnsservers".to_owned(),
            service.clone(),
        ])
        .unwrap_or_default();
        let previous = crate::plan::parse_macos_dns_servers(&current);
        write_dns_backup(&service, &previous);
        for argv in config.dns_push_commands_macos(&service) {
            run(&argv, None)?;
        }
    }
    Ok(())
}

/// Reverts [`apply_dns`] (best-effort: a missing resolver/backup on teardown is
/// not fatal), so the host resolver returns on datapath shutdown. On Linux it
/// reverts the link; on macOS it restores the snapshot taken at apply (clearing
/// to DHCP if none was captured). No-op when no DNS was pushed.
pub fn revert_dns(config: &TunConfig) {
    #[cfg(not(target_os = "macos"))]
    for argv in config.dns_teardown_commands_linux() {
        let _ = run(&argv, None);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = config;
        if let Some((service, previous)) = read_dns_backup() {
            for argv in crate::plan::dns_restore_commands_macos(&service, &previous) {
                let _ = run(&argv, None);
            }
            let _ = std::fs::remove_file(dns_backup_path());
        }
    }
}

/// Backup path for the macOS pre-push resolver snapshot. Root-owned `/var/run`
/// (not world-writable `/tmp`), mirroring the killswitch backup, so a non-root
/// user cannot pre-seed a malicious "previous" resolver list for teardown.
#[cfg(target_os = "macos")]
fn dns_backup_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/run/warren-dns-backup.conf")
}

/// Records the primary service name (line 1) and the resolvers to restore (one
/// IP per remaining line) so [`revert_dns`] can put them back. Best-effort: a
/// failed write just means teardown finds no backup and clears to DHCP.
#[cfg(target_os = "macos")]
fn write_dns_backup(service: &str, previous: &[std::net::IpAddr]) {
    write_dns_backup_at(&dns_backup_path(), service, previous);
}

/// [`write_dns_backup`] against an explicit path, unless a backup is already on
/// disk: an existing backup holds the true pre-warren resolvers from a run that
/// died before teardown, and overwriting it would make teardown restore the
/// stale in-tunnel resolver instead (second line of defense behind the
/// reconcile in [`apply_dns`]).
#[cfg(target_os = "macos")]
fn write_dns_backup_at(path: &std::path::Path, service: &str, previous: &[std::net::IpAddr]) {
    if path.exists() {
        return;
    }
    let mut body = String::from(service);
    body.push('\n');
    for ip in previous {
        body.push_str(&ip.to_string());
        body.push('\n');
    }
    let _ = std::fs::write(path, body);
}

/// Reads back [`write_dns_backup`]: `(service, previous_resolvers)`. `None` when
/// no backup exists (nothing was pushed, or the snapshot write failed).
#[cfg(target_os = "macos")]
fn read_dns_backup() -> Option<(String, Vec<std::net::IpAddr>)> {
    read_dns_backup_at(&dns_backup_path())
}

/// [`read_dns_backup`] against an explicit path.
#[cfg(target_os = "macos")]
fn read_dns_backup_at(path: &std::path::Path) -> Option<(String, Vec<std::net::IpAddr>)> {
    let body = std::fs::read_to_string(path).ok()?;
    let mut lines = body.lines();
    let service = lines.next()?.trim().to_owned();
    if service.is_empty() {
        return None;
    }
    let previous = crate::plan::parse_macos_dns_servers(&lines.collect::<Vec<_>>().join("\n"));
    Some((service, previous))
}

/// Tears the killswitch down, restoring normal output. On macOS this flushes the
/// rules and disables pf (back to the default unfiltered state); on Linux it
/// deletes the nftables table.
///
/// # Errors
///
/// If the teardown command cannot be run (a missing rule is treated as success
/// by the caller).
pub fn teardown_killswitch() -> io::Result<()> {
    teardown_killswitch_impl()
}

#[cfg(target_os = "macos")]
fn teardown_killswitch_impl() -> io::Result<()> {
    let path = pf_backup_path();
    match std::fs::read_to_string(&path) {
        Ok(backup) => {
            // Restore the captured ruleset (pfctl ignores the `#` header comment),
            // returning the host's filter rules to their pre-apply state instead
            // of flushing them to empty.
            let restore = run(
                &KillswitchPlan::pf_restore_argv(&path.to_string_lossy()),
                None,
            );
            // Only disable pf if it was OFF before we enabled it. If it was
            // already on (e.g. another VPN owns it), `pfctl -E` was
            // reference-counted, so leaving it enabled respects that owner.
            if !KillswitchPlan::parse_pf_backup_was_enabled(&backup) {
                let _ = run(&KillswitchPlan::pf_disable_argv(), None);
            }
            let _ = std::fs::remove_file(&path);
            restore
        }
        // No snapshot (it failed or never ran): fall back to the old best-effort
        // teardown rather than leaving Warren's block rules loaded.
        Err(_) => {
            let _ = run(&KillswitchPlan::pf_flush_argv(), None);
            run(&KillswitchPlan::pf_disable_argv(), None)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn teardown_killswitch_impl() -> io::Result<()> {
    run(&KillswitchPlan::nft_teardown_argv(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_rejects_an_empty_argv_without_panicking() {
        // The slice guard must turn a bug (empty argv) into a recoverable error
        // before any indexing or spawn happens.
        let err = run(&[], None).unwrap_err();
        assert!(err.to_string().contains("empty command argv"));
    }

    /// A unique scratch path in the OS temp dir (no tempfile dev-dep).
    #[cfg(target_os = "macos")]
    fn scratch_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "warren-tun-apply-test-{}-{tag}-{seq}",
            std::process::id()
        ))
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dns_backup_round_trips_service_and_resolvers() {
        let path = scratch_path("dns-roundtrip");
        let previous: Vec<std::net::IpAddr> =
            vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        write_dns_backup_at(&path, "Wi-Fi", &previous);
        let (service, restored) = read_dns_backup_at(&path).expect("backup readable");
        let _ = std::fs::remove_file(&path);
        assert_eq!(service, "Wi-Fi");
        assert_eq!(restored, previous);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dns_backup_never_overwrites_a_stale_one() {
        // A backup already on disk means a previous datapath died before its
        // teardown ran: it holds the TRUE pre-warren resolvers. Writing over it
        // would capture the stale in-tunnel resolver as the "previous" state
        // and teardown would then restore the poison instead of the original.
        let path = scratch_path("dns-keep-oldest");
        let original: Vec<std::net::IpAddr> = vec!["192.0.2.1".parse().unwrap()];
        write_dns_backup_at(&path, "Wi-Fi", &original);
        let poison: Vec<std::net::IpAddr> = vec!["10.66.0.1".parse().unwrap()];
        write_dns_backup_at(&path, "USB LAN", &poison);
        let (service, restored) = read_dns_backup_at(&path).expect("backup readable");
        let _ = std::fs::remove_file(&path);
        assert_eq!(service, "Wi-Fi");
        assert_eq!(restored, original);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pf_backup_never_overwrites_a_stale_one() {
        // Same keep-oldest invariant for the pf ruleset snapshot: after a dirty
        // crash the on-disk snapshot is the host's real pre-warren ruleset; the
        // next apply must not replace it with a snapshot of warren's own
        // killswitch (block-all) rules.
        let path = scratch_path("pf-keep-oldest");
        write_pf_backup_at(
            &path,
            "# warren-pf-was-enabled=true\nanchor \"com.apple/*\" all\n",
        );
        write_pf_backup_at(&path, "# warren-pf-was-enabled=true\nblock out all\n");
        let kept = std::fs::read_to_string(&path).expect("backup readable");
        let _ = std::fs::remove_file(&path);
        assert!(kept.contains("com.apple"), "original snapshot must survive");
        assert!(!kept.contains("block out all"), "poison snapshot must not");
    }
}
