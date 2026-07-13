//! Policy routing to fix asymmetric routing on the Warren client side
//! when an internal service receives traffic via NAT-PMP DNAT.
//!
//! ## Problem
//!
//! Without policy routing, a client-side service (e.g. `python -m http.server
//! 0.0.0.0:8080`) sees incoming connections arrive via `warren0`
//! (DNAT redirects from the public exit IP). But without extra
//! configuration, the SYN-ACK reply leaves through the default route `eth0`
//! with a source IP `10.66.0.x` non-routable on the Internet, dropped at
//! the first hop, timeout on the caller side.
//!
//! ## Solution
//!
//! Mark (`fwmark`) packets incoming via `warren0` at the `prerouting`
//! level, save that mark in conntrack, and on the return path (`output`)
//! restore the mark from conntrack onto the outgoing packet. An `ip rule`
//! directs marked packets to a dedicated routing table pointing to
//! `warren0` as default.
//!
//! Result: the SYN-ACK leaves through the tunnel, reaches the exit, is
//! de-masqueraded, returns to the caller via the symmetric path.
//!
//! ## Platforms
//!
//! Linux only (`ip` + `nft`). macOS could be implemented via `pf`
//! route-to + scrub but out of scope for the POC.
//!
//! ## POC limits
//!
//! - Best-effort: if `ip` or `nft` fail (missing privileges, table
//!   already busy), the tunnel still comes up but NAT-PMP e2e will not
//!   work. Logs at warn level for diagnosis.
//! - Not unit-tested (shell-out OS-dependent). Validation = a real
//!   cross-DC bench run.

use std::process::Stdio;

use anyhow::{Context, Result, anyhow};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use warrenguard_killswitch_os::validate_tun_name as ks_validate_tun_name;

/// fwmark used by Warren to tag packets incoming via the TUN.
/// Arbitrary value 0x42, chosen to avoid conflict with classic fwmarks
/// (Tailscale = 0x80000, WireGuard = 0xca6c, ...).
const FWMARK: u32 = 0x42;

/// Dedicated Linux routing table number. No need to modify
/// `/etc/iproute2/rt_tables`, a raw number is used.
const ROUTE_TABLE: u32 = 42;

/// Name of the nftables table used. Distinct from `warrenguard_killswitch_os`
/// to allow both enabled simultaneously without conflict.
const NFT_TABLE: &str = "warren_policy";

/// RAII guard: holds the "installed" state for automatic cleanup on drop.
#[derive(Debug)]
pub struct PolicyRoutingGuard {
    installed: bool,
}

impl PolicyRoutingGuard {
    /// Install policy routing rules for `tun_name`. Idempotent:
    /// re-applies rules if they already exist (RTNETLINK File exists
    /// is tolerated).
    ///
    /// # Errors
    ///
    /// Error if `ip` or `nft` are not in PATH, or insufficient
    /// privileges (CAP_NET_ADMIN required).
    pub async fn install(tun_name: &str) -> Result<Self> {
        validate_tun_name(tun_name)?;

        // 1) ip rule: route fwmarked packets to table 42.
        //    `RTNETLINK answers: File exists` tolerated (idempotent).
        run_ip_tolerant_exists(&[
            "rule",
            "add",
            "fwmark",
            &format!("{FWMARK:#x}"),
            "table",
            &ROUTE_TABLE.to_string(),
            "pref",
            "100",
        ])
        .await
        .context("ip rule add fwmark")?;

        // 2) ip route: default via the TUN in table 42. Idempotent
        //    via `replace`.
        run_ip(&[
            "route",
            "replace",
            "default",
            "dev",
            tun_name,
            "table",
            &ROUTE_TABLE.to_string(),
        ])
        .await
        .context("ip route replace default")?;

        // 3) nft: mark packets incoming via TUN, restore mark from
        //    conntrack on return.
        let ruleset = build_nft_ruleset(tun_name);
        run_nft_with_stdin(&["-f", "-"], &ruleset)
            .await
            .context("nft load policy ruleset")?;

        tracing::info!(
            tun = tun_name,
            fwmark = %format!("{FWMARK:#x}"),
            table = ROUTE_TABLE,
            nft_table = NFT_TABLE,
            "Warren policy routing installed"
        );

        Ok(Self { installed: true })
    }

    /// Remove the rules. Idempotent: tolerates "not found" if a rule
    /// has already been removed by another process.
    ///
    /// # Errors
    ///
    /// No fatal error, each command is best-effort. Logs at warn level
    /// if the OS returns an error other than not-found.
    pub async fn uninstall(mut self) -> Result<()> {
        // Reverse order: nft first (simpler to remove), then ip route,
        // then ip rule.
        if let Err(e) = run_nft_tolerant_missing(&["delete", "table", "inet", NFT_TABLE]).await {
            tracing::warn!(error = %e, "nft delete policy table failed (non-fatal)");
        }
        if let Err(e) = run_ip(&["route", "flush", "table", &ROUTE_TABLE.to_string()]).await {
            tracing::warn!(error = %e, "ip route flush table failed (non-fatal)");
        }
        if let Err(e) = run_ip_tolerant_no_such(&[
            "rule",
            "del",
            "fwmark",
            &format!("{FWMARK:#x}"),
            "table",
            &ROUTE_TABLE.to_string(),
        ])
        .await
        {
            tracing::warn!(error = %e, "ip rule del fwmark failed (non-fatal)");
        }
        self.installed = false;
        tracing::info!("Warren policy routing uninstalled");
        Ok(())
    }
}

impl Drop for PolicyRoutingGuard {
    fn drop(&mut self) {
        if !self.installed {
            return;
        }
        // Best-effort synchronous cleanup (Drop is not async). On
        // SIGKILL this will not run, the user must clean up manually.
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", NFT_TABLE])
            .output();
        let _ = std::process::Command::new("ip")
            .args(["route", "flush", "table", &ROUTE_TABLE.to_string()])
            .output();
        let _ = std::process::Command::new("ip")
            .args([
                "rule",
                "del",
                "fwmark",
                &format!("{FWMARK:#x}"),
                "table",
                &ROUTE_TABLE.to_string(),
            ])
            .output();
        tracing::warn!(
            "Warren policy routing dropped without explicit uninstall - \
             synchronous cleanup attempted"
        );
    }
}

/// Wrapper over [`warrenguard_killswitch_os::validate_tun_name`] mapping its
/// `KillswitchError::InvalidInput` to `anyhow::Error`. Avoids duplicating
/// the validation logic.
fn validate_tun_name(name: &str) -> Result<()> {
    ks_validate_tun_name(name).map_err(|e| anyhow!("{e}"))
}

fn build_nft_ruleset(tun_name: &str) -> String {
    // Atomic, idempotent `add table / flush table / table { ... }`
    // pattern, mirroring `warren-killswitch::install`. `add table`
    // is a nft no-op when the table already exists, `flush table`
    // clears existing chains, and the trailing `table { ... }`
    // block repopulates them. Safer than the historical
    // `table X / delete table / table X { ... }` which behaved
    // differently across nft versions when the table was absent.
    //
    // `type route hook output`: enables re-routing after mark modification
    // (`type filter` does not trigger route re-lookup).
    // Cf. https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_metainformation
    format!(
        r#"# Warren policy routing
add table inet {NFT_TABLE}
flush table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
    chain prerouting {{
        type filter hook prerouting priority mangle;
        iifname "{tun_name}" ct state new ct mark set {FWMARK:#x}
    }}
    chain output {{
        type route hook output priority mangle;
        meta mark set ct mark
    }}
}}
"#
    )
}

async fn run_ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .await
        .with_context(|| format!("spawn ip {}", args.join(" ")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!(
            "ip {} failed (exit {}): {}",
            args.join(" "),
            out.status,
            stderr.trim()
        ));
    }
    Ok(())
}

async fn run_ip_tolerant_exists(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .await
        .with_context(|| format!("spawn ip {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("File exists") {
        // Idempotent: the rule already exists, which is what we want.
        return Ok(());
    }
    Err(anyhow!("ip {} failed: {}", args.join(" "), stderr.trim()))
}

async fn run_ip_tolerant_no_such(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .await
        .with_context(|| format!("spawn ip {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("No such") || stderr.contains("not found") {
        return Ok(());
    }
    Err(anyhow!("ip {} failed: {}", args.join(" "), stderr.trim()))
}

async fn run_nft_tolerant_missing(args: &[&str]) -> Result<()> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .await
        .with_context(|| format!("spawn nft {}", args.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("No such") || stderr.contains("does not exist") {
        return Ok(());
    }
    Err(anyhow!("nft {} failed: {}", args.join(" "), stderr.trim()))
}

async fn run_nft_with_stdin(args: &[&str], content: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn nft {}", args.join(" ")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("child stdin pipe missing"))?;
    stdin
        .write_all(content.as_bytes())
        .await
        .context("write nft stdin")?;
    drop(stdin);
    let out = child.wait_with_output().await.context("wait nft")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("nft -f - exited {}: {}", out.status, stderr.trim()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_uses_constant_table_name_and_fwmark() {
        let s = build_nft_ruleset("warren0");
        assert!(s.contains(NFT_TABLE), "must use the const table name");
        assert!(
            s.contains(&format!("{FWMARK:#x}")),
            "must reference the fwmark"
        );
    }

    #[test]
    fn ruleset_marks_inbound_via_tun_only() {
        let s = build_nft_ruleset("warren0");
        assert!(
            s.contains("iifname \"warren0\" ct state new ct mark set"),
            "prerouting must filter on iifname tun + ct state new"
        );
    }

    #[test]
    fn ruleset_uses_route_hook_for_output() {
        let s = build_nft_ruleset("warren0");
        // `type route hook output` is required to re-route after mark
        // modification, `type filter` does not trigger re-lookup.
        assert!(
            s.contains("type route hook output"),
            "output chain must use 'type route' to trigger re-routing"
        );
    }

    #[test]
    fn ruleset_uses_atomic_add_flush_pattern() {
        // The pattern must mirror the killswitch ruleset (see
        // `warren-killswitch::lib.rs` test
        // `ruleset_uses_atomic_update_pattern`): `add table` +
        // `flush table` is documented as idempotent by `nft(8)`.
        // The earlier `table X / delete table / table X { ... }`
        // pattern was version-dependent (some nft builds would
        // create an empty table on `table X` without `add`, others
        // would fail if it already existed).
        let s = build_nft_ruleset("warren0");
        let add_pos = s.find("add table inet warren_policy").expect("add present");
        let flush_pos = s
            .find("flush table inet warren_policy")
            .expect("flush present");
        let body_pos = s
            .find("table inet warren_policy {")
            .expect("table body present");
        assert!(
            add_pos < flush_pos && flush_pos < body_pos,
            "expected order: add table -> flush table -> table {{ ... }}; \
             received ruleset:\n{s}"
        );
        assert!(
            !s.contains("delete table inet warren_policy"),
            "the fragile `delete table` pattern must no longer be used; \
             received ruleset:\n{s}"
        );
    }

    #[test]
    fn validate_tun_name_accepts_valid() {
        assert!(validate_tun_name("warren0").is_ok());
        assert!(validate_tun_name("tun0").is_ok());
    }

    #[test]
    fn validate_tun_name_rejects_invalid() {
        assert!(validate_tun_name("").is_err());
        assert!(validate_tun_name(&"a".repeat(16)).is_err());
        assert!(validate_tun_name("evil; rm -rf").is_err());
    }
}
