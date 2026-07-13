//! Windows port of `dns_push`.
//!
//! Same goal as the Linux / macOS modules: while the tunnel runs,
//! override the system resolver so DNS lookups travel via the tunnel
//! rather than via the LAN-bound DHCP-supplied nameserver that the
//! killswitch / default-route split has rendered unreachable.
//!
//! ## Strategy
//!
//! Windows configures DNS per-adapter via `Set-DnsClientServerAddress`.
//! Like the macOS port we snapshot the current per-adapter state, set
//! our override, and round-trip on uninstall.
//!
//! 1. Enumerate IPv4-enabled NICs via `Get-NetAdapter` filtered by
//!    `Status -eq 'Up'`.
//! 2. Snapshot each NIC's current `ServerAddresses` via
//!    `Get-DnsClientServerAddress -InterfaceIndex <ifindex>
//!     -AddressFamily IPv4`. Empty list = DHCP-supplied (treated as
//!    [`DnsConfig::Dhcp`] for round-trip).
//! 3. Apply our override list with `Set-DnsClientServerAddress
//!    -InterfaceIndex <ifindex> -ServerAddresses <ip1>,<ip2>`.
//! 4. On uninstall, restore each NIC: empty list → reset to DHCP via
//!    `Set-DnsClientServerAddress -ResetServerAddresses`; manual list
//!    → re-apply the captured IPs verbatim.
//!
//! ## Privileges
//!
//! `Set-DnsClientServerAddress` requires Administrator. The binary
//! must be launched via `Run as administrator` or invoked from an
//! elevated shell.

use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
use anyhow::{Context, Result, anyhow};
#[cfg(target_os = "windows")]
use tokio::process::Command;

/// Per-adapter DNS configuration. Captured at install time so the
/// uninstall path can re-establish DHCP-vs-manual on a per-NIC basis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsConfig {
    /// Empty `ServerAddresses` returned by `Get-DnsClientServerAddress`
    /// - the adapter relies on the DHCP-supplied resolvers.
    Dhcp,
    /// Manually-configured resolvers, in declaration order
    /// (resolution priority).
    Manual(Vec<Ipv4Addr>),
}

/// Parse the Format-List output of `Get-NetAdapter -Physical
/// | Where-Object Status -eq 'Up' | Format-List Name,InterfaceIndex`
/// into the list of (alias, ifindex) pairs we will override.
///
/// Returns the "Up" adapters in the order PowerShell printed them
/// (typically by interface metric - most preferred first).
#[must_use]
pub fn parse_adapters(out: &str) -> Vec<(String, u32)> {
    let mut adapters = Vec::new();
    let mut current_name: Option<String> = None;
    for line in out.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed
            .strip_prefix("Name")
            .and_then(|s| s.split_once(':'))
            .map(|(_, v)| v.trim())
            && !value.is_empty()
        {
            current_name = Some(value.to_owned());
        } else if let Some(value) = trimmed
            .strip_prefix("InterfaceIndex")
            .and_then(|s| s.split_once(':'))
            .map(|(_, v)| v.trim())
            && let (Some(name), Ok(ifindex)) = (current_name.take(), value.parse::<u32>())
        {
            adapters.push((name, ifindex));
        }
    }
    adapters
}

/// Parse `Get-DnsClientServerAddress -InterfaceIndex <i>
/// -AddressFamily IPv4 | Format-List ServerAddresses` output into a
/// [`DnsConfig`].
///
/// Expected format (one of):
///
/// ```text
/// ServerAddresses : {}
/// ```
///
/// or:
///
/// ```text
/// ServerAddresses : {1.1.1.1, 8.8.8.8}
/// ```
///
/// The braces always surround a (possibly empty) comma-separated
/// list. An empty list maps to [`DnsConfig::Dhcp`].
#[must_use]
pub fn parse_get_dnsclient(out: &str) -> DnsConfig {
    for line in out.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("ServerAddresses") {
            // "ServerAddresses : {1.1.1.1, 8.8.8.8}" → "{1.1.1.1, 8.8.8.8}"
            let value = rest
                .split_once(':')
                .map(|(_, v)| v.trim())
                .unwrap_or(rest.trim());
            let inner = value.trim_start_matches('{').trim_end_matches('}').trim();
            if inner.is_empty() {
                return DnsConfig::Dhcp;
            }
            let ips: Vec<Ipv4Addr> = inner
                .split(',')
                .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
                .collect();
            return if ips.is_empty() {
                DnsConfig::Dhcp
            } else {
                DnsConfig::Manual(ips)
            };
        }
    }
    DnsConfig::Dhcp
}

/// Build the PowerShell argv to set DNS for one adapter. The
/// `-ServerAddresses` parameter takes a comma-separated list inside
/// the same string token (PowerShell parses it as an array).
///
/// `dns` must be non-empty - an empty list would translate to a
/// `Set-DnsClientServerAddress` invocation with no -ServerAddresses
/// value (PowerShell error). Use [`build_restore_command`] with
/// [`DnsConfig::Dhcp`] for "fall back to DHCP" semantics instead.
#[must_use]
pub fn build_set_command(ifindex: u32, dns: &[Ipv4Addr]) -> Vec<String> {
    let list = dns
        .iter()
        .map(Ipv4Addr::to_string)
        .collect::<Vec<_>>()
        .join(",");
    vec![
        "-NoProfile".into(),
        "-Command".into(),
        format!(
            "Set-DnsClientServerAddress -InterfaceIndex {ifindex} \
             -ServerAddresses {list}"
        ),
    ]
}

/// Build the PowerShell argv to revert one adapter to its captured
/// state. DHCP services use `-ResetServerAddresses` (Windows-canonical
/// "fall back to DHCP"); manual services re-apply the captured IPs.
#[must_use]
pub fn build_restore_command(ifindex: u32, original: &DnsConfig) -> Vec<String> {
    match original {
        DnsConfig::Dhcp => vec![
            "-NoProfile".into(),
            "-Command".into(),
            format!(
                "Set-DnsClientServerAddress -InterfaceIndex {ifindex} \
                 -ResetServerAddresses"
            ),
        ],
        DnsConfig::Manual(ips) => {
            let list = ips
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(",");
            vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "Set-DnsClientServerAddress -InterfaceIndex {ifindex} \
                     -ServerAddresses {list}"
                ),
            ]
        }
    }
}

// ── Runtime exec (Windows only) ──────────────────────────────────────

/// RAII guard: holds the captured backup list for restore on drop.
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct DnsPushGuard {
    backups: Vec<((String, u32), DnsConfig)>,
    installed: bool,
}

#[cfg(target_os = "windows")]
impl DnsPushGuard {
    /// Snapshot every "Up" adapter's current DNS config, then apply
    /// the override.
    ///
    /// # Errors
    ///
    /// - `dns_servers` empty.
    /// - PowerShell not in `PATH`.
    /// - Process not running as Administrator.
    /// - No adapters are "Up" (rare - air-gapped boot).
    pub async fn install(dns_servers: &[Ipv4Addr]) -> Result<Self> {
        if dns_servers.is_empty() {
            anyhow::bail!("--push-dns requires at least one DNS server IP");
        }

        let adapters = list_up_adapters()
            .await
            .context("listing Windows network adapters for DNS push")?;
        if adapters.is_empty() {
            anyhow::bail!(
                "no `Up` network adapters found via `Get-NetAdapter` - \
                 cannot push DNS"
            );
        }

        let mut backups = Vec::with_capacity(adapters.len());
        for (name, ifindex) in adapters {
            let cfg = capture_adapter_dns(ifindex)
                .await
                .with_context(|| format!("capturing DNS for adapter {name:?} ({ifindex})"))?;
            backups.push(((name, ifindex), cfg));
        }

        for ((name, ifindex), _) in &backups {
            let args = build_set_command(*ifindex, dns_servers);
            run_powershell(&args)
                .await
                .with_context(|| format!("setting DNS for adapter {name:?} ({ifindex})"))?;
        }

        tracing::info!(
            servers = ?dns_servers,
            adapters = backups.len(),
            "Warren DNS push installed (Windows Set-DnsClientServerAddress)"
        );

        Ok(Self {
            backups,
            installed: true,
        })
    }

    /// Restore every captured adapter to its original DNS state.
    /// Idempotent - failure on a single adapter is logged but does
    /// not stop the remaining restores from running.
    pub async fn uninstall(mut self) -> Result<()> {
        for ((name, ifindex), original) in &self.backups {
            let args = build_restore_command(*ifindex, original);
            if let Err(e) = run_powershell(&args).await {
                tracing::warn!(
                    error = %e,
                    adapter = %name,
                    ifindex = *ifindex,
                    "DNS restore failed for adapter (non-fatal)"
                );
            }
        }
        self.installed = false;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for DnsPushGuard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // Best-effort sync cleanup: spawn one PowerShell per adapter.
        tracing::warn!(
            adapters = self.backups.len(),
            "DnsPushGuard dropped without explicit uninstall - running \
             best-effort sync restore"
        );
        for ((_name, ifindex), original) in &self.backups {
            let args = build_restore_command(*ifindex, original);
            let _ = std::process::Command::new("powershell.exe")
                .args(args.iter().map(String::as_str))
                .output();
        }
    }
}

#[cfg(target_os = "windows")]
async fn list_up_adapters() -> Result<Vec<(String, u32)>> {
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapter -Physical \
             | Where-Object Status -eq 'Up' \
             | Format-List Name,InterfaceIndex",
        ])
        .output()
        .await
        .context("spawn powershell.exe Get-NetAdapter")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("Get-NetAdapter failed: {}", stderr.trim()));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_adapters(&stdout))
}

#[cfg(target_os = "windows")]
async fn capture_adapter_dns(ifindex: u32) -> Result<DnsConfig> {
    let ps_command = format!(
        "Get-DnsClientServerAddress -InterfaceIndex {ifindex} \
         -AddressFamily IPv4 | Format-List ServerAddresses"
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &ps_command])
        .output()
        .await
        .context("spawn powershell.exe Get-DnsClientServerAddress")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "Get-DnsClientServerAddress failed: {}",
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_get_dnsclient(&stdout))
}

#[cfg(target_os = "windows")]
async fn run_powershell(args: &[String]) -> Result<()> {
    let str_args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = Command::new("powershell.exe")
        .args(&str_args)
        .output()
        .await
        .context("spawn powershell.exe")?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    Err(anyhow!("powershell.exe failed: {}", stderr.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_adapters_extracts_name_and_ifindex_pairs() {
        // Recorded `Get-NetAdapter -Physical | Where-Object Status -eq
        // 'Up' | Format-List Name,InterfaceIndex` output. Anchors the
        // parser against the real PowerShell shape; future label
        // casing changes surface here.
        let fixture = "
Name           : Wi-Fi
InterfaceIndex : 12

Name           : Ethernet
InterfaceIndex : 8
";
        let pairs = parse_adapters(fixture);
        assert_eq!(
            pairs,
            vec![("Wi-Fi".to_string(), 12), ("Ethernet".to_string(), 8),]
        );
    }

    #[test]
    fn parse_adapters_skips_pairs_with_invalid_ifindex() {
        // Defensive: garbage ifindex value must not propagate into the
        // install path (Set-DnsClientServerAddress would error and
        // half-apply the override).
        let fixture = "
Name           : Ghost
InterfaceIndex : not-a-number

Name           : RealNic
InterfaceIndex : 5
";
        assert_eq!(parse_adapters(fixture), vec![("RealNic".to_string(), 5)]);
    }

    #[test]
    fn parse_get_dnsclient_returns_dhcp_on_empty_braces() {
        // The "{}" case is the canonical "no DNS configured = DHCP"
        // signal Windows gives. Anchored explicitly.
        let fixture = "ServerAddresses : {}\n";
        assert_eq!(parse_get_dnsclient(fixture), DnsConfig::Dhcp);
    }

    #[test]
    fn parse_get_dnsclient_returns_manual_with_ip_list() {
        let fixture = "ServerAddresses : {1.1.1.1, 8.8.8.8}\n";
        assert_eq!(
            parse_get_dnsclient(fixture),
            DnsConfig::Manual(vec![ip("1.1.1.1"), ip("8.8.8.8")])
        );
    }

    #[test]
    fn parse_get_dnsclient_returns_dhcp_on_garbage_brace_content() {
        // Defensive: if PowerShell ever prints unexpected braces
        // (e.g. error spilled into Format-List), the restore path
        // must round-trip to DHCP rather than fabricate fake IPs.
        let fixture = "ServerAddresses : {weird, output, here}\n";
        assert_eq!(parse_get_dnsclient(fixture), DnsConfig::Dhcp);
    }

    #[test]
    fn build_set_command_joins_ips_with_comma() {
        // PowerShell `-ServerAddresses` parses the value as an array
        // when comma-separated. Spaces around the comma break the
        // parser on some PowerShell versions; the test pins
        // comma-without-space.
        let cmd = build_set_command(12, &[ip("9.9.9.9"), ip("1.1.1.1")]);
        let payload = cmd.last().unwrap();
        assert!(
            payload.contains("-ServerAddresses 9.9.9.9,1.1.1.1"),
            "ip list must be comma-joined without spaces; got {payload:?}"
        );
        assert!(
            payload.contains("-InterfaceIndex 12"),
            "ifindex must be propagated; got {payload:?}"
        );
    }

    #[test]
    fn build_restore_command_for_dhcp_uses_reset_server_addresses() {
        // `-ResetServerAddresses` is the Windows magic flag for "fall
        // back to DHCP". A literal `-ServerAddresses` with empty value
        // would error instead.
        let cmd = build_restore_command(12, &DnsConfig::Dhcp);
        let payload = cmd.last().unwrap();
        assert!(
            payload.contains("-ResetServerAddresses"),
            "DHCP restore must use -ResetServerAddresses; got {payload:?}"
        );
    }

    #[test]
    fn build_restore_command_for_manual_round_trips_the_original_list() {
        let original = DnsConfig::Manual(vec![ip("192.168.1.1"), ip("192.168.1.2")]);
        let cmd = build_restore_command(8, &original);
        let payload = cmd.last().unwrap();
        assert!(payload.contains("-InterfaceIndex 8"));
        assert!(
            payload.contains("-ServerAddresses 192.168.1.1,192.168.1.2"),
            "manual restore must round-trip the captured list verbatim; got {payload:?}"
        );
    }
}
