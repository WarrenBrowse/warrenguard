//! macOS port of `dns_push`.
//!
//! Same goal as the Linux module: while the tunnel runs, override the
//! system resolver so DNS lookups travel via the tunnel rather than via
//! a LAN-bound DHCP-provided nameserver that the killswitch / default
//! route split has rendered unreachable.
//!
//! macOS does not consult `/etc/resolv.conf` from `mDNSResponder` (the
//! system resolver daemon) on modern releases - patching that file is
//! a no-op for `getaddrinfo`. The canonical control plane is the
//! `networksetup` CLI: per-network-service DNS overrides land in the
//! `State:/Network/Service/<id>/DNS` SCDynamicStore key, which
//! `mDNSResponder` reads.
//!
//! ## Strategy
//!
//! 1. Enumerate enabled services via `networksetup -listallnetworkservices`
//!    (skipping disabled entries marked with a leading `*`).
//! 2. For each service, snapshot its current DNS config via
//!    `networksetup -getdnsservers <service>` - either DHCP-supplied
//!    ("There aren't any DNS Servers..." line) or a user-set list.
//! 3. Apply our override list with `networksetup -setdnsservers
//!    <service> <ip1> <ip2> ...` for every snapshot we kept.
//! 4. On uninstall, restore each service to its previous state - DHCP
//!    via `Empty`, or the captured list verbatim.
//!
//! ## Privileges
//!
//! `networksetup -setdnsservers` requires root. The binary must be run
//! with `sudo` when this guard is active.

use std::net::Ipv4Addr;

use anyhow::{Context, Result, anyhow};
use tokio::process::Command;

/// Per-service DNS configuration as reported by `networksetup
/// -getdnsservers`. We have to round-trip exactly what we found so the
/// uninstall path can re-establish DHCP vs manual on a service-by-
/// service basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsConfig {
    /// `networksetup -getdnsservers <service>` returned the
    /// "There aren't any DNS Servers..." line - the service uses the
    /// DHCP-supplied resolvers.
    Dhcp,
    /// The service has manually-configured resolvers. The list is in
    /// declaration order (which matters for resolution priority).
    Manual(Vec<Ipv4Addr>),
}

/// Parse the multi-line output of `networksetup -listallnetworkservices`
/// into the list of services that are enabled and worth overriding.
///
/// The first line is a headline ("An asterisk (*) denotes that a
/// network service is disabled.") that we must skip. Disabled services
/// are prefixed with `*` and we drop them - `networksetup
/// -setdnsservers` errors on a disabled service.
#[must_use]
pub fn parse_listall_services(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // Drop the headline ("An asterisk (*) denotes..."), blanks,
            // and disabled services (the leading-`*` lines that
            // `networksetup -setdnsservers` would refuse anyway).
            if trimmed.is_empty() || trimmed.starts_with('*') || trimmed.starts_with("An asterisk")
            {
                return None;
            }
            Some(trimmed.to_owned())
        })
        .collect()
}

/// Parse `networksetup -getdnsservers <service>` output into a
/// [`DnsConfig`]. The "no DNS configured" sentinel line maps to
/// [`DnsConfig::Dhcp`]; everything else is parsed as a list of IPv4
/// resolvers.
///
/// Returns [`DnsConfig::Dhcp`] also when the output is unexpectedly
/// empty (defensive - better to round-trip "DHCP" than leave the
/// service stuck on our override after uninstall).
#[must_use]
pub fn parse_getdnsservers(out: &str) -> DnsConfig {
    let mut ips = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("There aren't any") {
            return DnsConfig::Dhcp;
        }
        if let Ok(ip) = line.parse::<Ipv4Addr>() {
            ips.push(ip);
        }
    }
    if ips.is_empty() || is_resolver_override(&ips) {
        DnsConfig::Dhcp
    } else {
        DnsConfig::Manual(ips)
    }
}

/// Whether a captured server list is a VPN daemon's own resolver override
/// rather than a configuration that belongs to the user.
///
/// A tunnel resolver binds a non-canonical address in `127/8` and answers only
/// while the daemon that bound it is alive. Restoring such a list on uninstall
/// points the service at an address nothing listens on, which costs the host
/// every name lookup: `networksetup` writes a *manual* override, so no reboot,
/// network change or DHCP lease ever clears it. Reporting DHCP instead restores
/// what the user had before any VPN touched the service, and a daemon still
/// running re-applies its own override from its store watcher.
///
/// The canonical `127.0.0.1` is spared: that is where a user-run resolver
/// (dnscrypt-proxy, Pi-hole) listens, and no tunnel resolver binds it.
fn is_resolver_override(ips: &[Ipv4Addr]) -> bool {
    !ips.is_empty()
        && ips
            .iter()
            .all(|ip| ip.is_loopback() && *ip != Ipv4Addr::LOCALHOST)
}

/// Build the `networksetup -setdnsservers <service> <ip1> <ip2> ...`
/// argv for installing our override on a single service.
///
/// `dns` must be non-empty - an empty list would translate to the
/// magic word `Empty` which means "fall back to DHCP", not "no DNS at
/// all". Callers should check non-emptiness before invoking install.
#[must_use]
pub fn build_set_command(service: &str, dns: &[Ipv4Addr]) -> Vec<String> {
    let mut args = vec!["-setdnsservers".into(), service.to_owned()];
    for ip in dns {
        args.push(ip.to_string());
    }
    args
}

/// Build the `networksetup -setdnsservers <service> ...` argv that
/// reverts a service to its captured original state. DHCP services
/// take the magic word `Empty`; manual services take the original IP
/// list verbatim.
#[must_use]
pub fn build_restore_command(service: &str, original: &DnsConfig) -> Vec<String> {
    match original {
        DnsConfig::Dhcp => vec!["-setdnsservers".into(), service.to_owned(), "Empty".into()],
        DnsConfig::Manual(ips) => {
            let mut args = vec!["-setdnsservers".into(), service.to_owned()];
            for ip in ips {
                args.push(ip.to_string());
            }
            args
        }
    }
}

/// RAII guard: holds the captured backup list for restore on drop.
#[derive(Debug)]
pub struct DnsPushGuard {
    /// (service_name, original_dns_config) pairs to round-trip on
    /// uninstall. Built once at install time and never mutated, so a
    /// crash during an in-flight `setdnsservers` still has the full
    /// backup available for cleanup.
    backups: Vec<(String, DnsConfig)>,
    installed: bool,
}

impl DnsPushGuard {
    /// Snapshot every enabled network service's current DNS config,
    /// then apply our override.
    ///
    /// # Errors
    ///
    /// - `dns_servers` is empty (would push `Empty` = "back to DHCP",
    ///   the opposite of what the caller asked for).
    /// - `networksetup` is not in `PATH`.
    /// - The current process lacks root (the `setdnsservers` step
    ///   fails with a privilege error).
    /// - The system has no enabled services at all (rare - laptop
    ///   booted with all NICs disabled).
    pub async fn install(dns_servers: &[Ipv4Addr]) -> Result<Self> {
        if dns_servers.is_empty() {
            anyhow::bail!("--push-dns requires at least one DNS server IP");
        }

        let services = list_enabled_services()
            .await
            .context("listing macOS network services for DNS push")?;
        if services.is_empty() {
            anyhow::bail!(
                "no enabled network services found via `networksetup \
                 -listallnetworkservices` - cannot push DNS"
            );
        }

        let mut backups = Vec::with_capacity(services.len());
        for service in services {
            let cfg = capture_service_dns(&service)
                .await
                .with_context(|| format!("capturing DNS for service {service:?}"))?;
            backups.push((service, cfg));
        }

        for (service, _) in &backups {
            let args = build_set_command(service, dns_servers);
            run_networksetup(&args)
                .await
                .with_context(|| format!("setting DNS for service {service:?}"))?;
        }

        tracing::info!(
            servers = ?dns_servers,
            services = backups.len(),
            "Warren DNS push installed (macOS networksetup)"
        );

        Ok(Self {
            backups,
            installed: true,
        })
    }

    /// Restore every captured service to its original DNS state.
    /// Idempotent - failure on a single service is logged but does
    /// not stop the remaining restores from running, so a transient
    /// `networksetup` glitch on one NIC can't leave the other ones
    /// pinned to our override.
    pub async fn uninstall(mut self) -> Result<()> {
        for (service, original) in &self.backups {
            let args = build_restore_command(service, original);
            if let Err(e) = run_networksetup(&args).await {
                tracing::warn!(
                    error = %e,
                    service = %service,
                    "DNS restore failed for service (non-fatal)"
                );
            }
        }
        self.installed = false;
        Ok(())
    }
}

impl Drop for DnsPushGuard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // Best-effort sync cleanup: Drop is sync, and we already
        // own the backup snapshot. Spawn a blocking `networksetup`
        // for each service; ignore individual failures (we can't
        // re-raise from Drop).
        tracing::warn!(
            services = self.backups.len(),
            "DnsPushGuard dropped without explicit uninstall - running \
             best-effort sync restore"
        );
        for (service, original) in &self.backups {
            let args = build_restore_command(service, original);
            let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = std::process::Command::new("networksetup")
                .args(&str_args)
                .output();
        }
    }
}

/// Helper: invoke `networksetup -listallnetworkservices` and parse the
/// enabled-services list.
async fn list_enabled_services() -> Result<Vec<String>> {
    let out = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .await
        .context("spawn `networksetup -listallnetworkservices`")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "`networksetup -listallnetworkservices` failed: {}",
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_listall_services(&stdout))
}

/// Helper: invoke `networksetup -getdnsservers <service>` and parse
/// the captured DNS config.
async fn capture_service_dns(service: &str) -> Result<DnsConfig> {
    let out = Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()
        .await
        .context("spawn `networksetup -getdnsservers`")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "`networksetup -getdnsservers {service}` failed: {}",
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_getdnsservers(&stdout))
}

/// Helper: invoke `networksetup` with the given argv. Errors carry
/// stderr verbatim for diagnostics (privilege failures show up here).
async fn run_networksetup(args: &[String]) -> Result<()> {
    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = Command::new("networksetup")
        .args(&str_args)
        .output()
        .await
        .with_context(|| format!("spawn networksetup {}", args.join(" ")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "networksetup {} failed: {}",
            args.join(" "),
            stderr.trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_listall_skips_headline_and_empty_lines() {
        // The first line is the headline (always present on real macOS
        // output). Tabs / blank lines that occasionally appear between
        // entries on flaky terminals must not turn into ghost services.
        let fixture = "\
An asterisk (*) denotes that a network service is disabled.
Wi-Fi
USB 10/100/1000 LAN

iPhone USB
";
        let services = parse_listall_services(fixture);
        assert_eq!(services, vec!["Wi-Fi", "USB 10/100/1000 LAN", "iPhone USB"]);
    }

    #[test]
    fn parse_listall_drops_disabled_services_with_asterisk() {
        // Disabled services are prefixed with `*`. `networksetup
        // -setdnsservers` errors on them, so we must filter them out
        // at list time - otherwise install fails halfway through.
        let fixture = "\
An asterisk (*) denotes that a network service is disabled.
Wi-Fi
*Display Ethernet
Bluetooth PAN
";
        let services = parse_listall_services(fixture);
        assert_eq!(services, vec!["Wi-Fi", "Bluetooth PAN"]);
    }

    #[test]
    fn parse_getdnsservers_returns_dhcp_on_no_dns_sentinel() {
        // The literal "There aren't any DNS Servers" output is the
        // only signal macOS gives that the service uses DHCP. Anchored
        // here so a future locale change in `networksetup` surfaces
        // immediately rather than silently rounding-tripping a manual
        // DHCP backup as `Manual([])`.
        let fixture = "There aren't any DNS Servers set on Wi-Fi.\n";
        assert_eq!(parse_getdnsservers(fixture), DnsConfig::Dhcp);
    }

    #[test]
    fn parse_getdnsservers_collects_ips_in_order() {
        // Ordering matters: macOS resolves against the DNS list in
        // declaration order, so a backup that preserves order is the
        // contract.
        let fixture = "1.1.1.1\n8.8.8.8\n9.9.9.9\n";
        assert_eq!(
            parse_getdnsservers(fixture),
            DnsConfig::Manual(vec![ip("1.1.1.1"), ip("8.8.8.8"), ip("9.9.9.9")])
        );
    }

    #[test]
    fn parse_getdnsservers_rejects_blank_output_as_dhcp_defensively() {
        // Defensive: if `networksetup` ever prints an empty body the
        // restore path must round-trip to "DHCP", not to "manual empty
        // list" which would write `Empty` literally and confuse the
        // caller. The DHCP fallback here is the safer choice.
        assert_eq!(parse_getdnsservers(""), DnsConfig::Dhcp);
        assert_eq!(parse_getdnsservers("   \n\n  "), DnsConfig::Dhcp);
    }

    #[test]
    fn parse_getdnsservers_reads_a_resolver_override_as_dhcp() {
        // A service pointing only at a non-canonical loopback address is
        // carrying some VPN daemon's resolver override, not a DNS
        // configuration anyone can restore: that address answers only
        // while the daemon that bound it lives. Capturing it as the
        // original is how uninstall strands the host with no name
        // resolution at all, since a manual override survives every
        // reboot and DHCP lease. Round-trip to DHCP instead.
        assert_eq!(parse_getdnsservers("127.55.251.5\n"), DnsConfig::Dhcp);
        assert_eq!(
            parse_getdnsservers("127.30.203.97\n127.41.79.67\n"),
            DnsConfig::Dhcp
        );
    }

    #[test]
    fn parse_getdnsservers_keeps_canonical_localhost() {
        // A user-run resolver (dnscrypt-proxy, Pi-hole) binds 127.0.0.1,
        // and no VPN resolver ever does. That is a real configuration and
        // must round-trip verbatim.
        assert_eq!(
            parse_getdnsservers("127.0.0.1\n"),
            DnsConfig::Manual(vec![ip("127.0.0.1")])
        );
    }

    #[test]
    fn parse_getdnsservers_keeps_a_list_mixing_loopback_and_real_servers() {
        // Only an all-loopback list is a resolver override. A list that
        // also names a reachable server is a deliberate configuration and
        // is restored as it was found.
        assert_eq!(
            parse_getdnsservers("127.55.251.5\n1.1.1.1\n"),
            DnsConfig::Manual(vec![ip("127.55.251.5"), ip("1.1.1.1")])
        );
    }

    #[test]
    fn build_set_command_uses_setdnsservers_with_service_then_ips() {
        let cmd = build_set_command("Wi-Fi", &[ip("9.9.9.9"), ip("1.1.1.1")]);
        assert_eq!(cmd, vec!["-setdnsservers", "Wi-Fi", "9.9.9.9", "1.1.1.1"]);
    }

    #[test]
    fn build_restore_command_for_dhcp_uses_empty_keyword() {
        // `networksetup -setdnsservers <s> Empty` is the macOS magic
        // word for "fall back to DHCP". A literal empty argv would
        // error out instead. Anchored to avoid a regression that
        // accidentally drops the `Empty` token.
        let cmd = build_restore_command("Wi-Fi", &DnsConfig::Dhcp);
        assert_eq!(cmd, vec!["-setdnsservers", "Wi-Fi", "Empty"]);
    }

    #[test]
    fn build_restore_command_for_manual_round_trips_the_original_list() {
        let original = DnsConfig::Manual(vec![ip("192.168.1.1"), ip("192.168.1.2")]);
        let cmd = build_restore_command("Ethernet", &original);
        assert_eq!(
            cmd,
            vec!["-setdnsservers", "Ethernet", "192.168.1.1", "192.168.1.2"]
        );
    }

    #[test]
    fn build_restore_command_preserves_service_name_with_spaces() {
        // macOS network service names commonly include spaces
        // ("USB 10/100/1000 LAN"). The argv layout treats them as a
        // single token - never join into one whitespace-collapsed
        // string here.
        let cmd = build_restore_command("USB 10/100/1000 LAN", &DnsConfig::Dhcp);
        assert_eq!(cmd[1], "USB 10/100/1000 LAN");
        assert_eq!(cmd.len(), 3);
    }
}
