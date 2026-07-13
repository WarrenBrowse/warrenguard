//! IPv6 outbound killswitch active while the multi-hop tunnel is
//! IPv4-only. Prevents IPv6 traffic from silently leaking off-tunnel.
//!
//! Without this guard, an Internet host that resolves to a AAAA record
//! would be reached over the physical interface (eth0 / wlan0) bypassing
//! the multi-hop pipeline entirely, exposing the user's real IPv6
//! address and breaking the privacy contract.
//!
//! The implementation is the simplest possible
//! (option B "killswitch IPv6 simple" recommended by the brief):
//! a Linux nft `table ip6 warren_ipv6_block` with a single output chain
//! whose policy is `drop`. The exceptions are the minimum required for
//! IPv6 to remain operational *on the host stack* without being routed
//! to the Internet:
//!
//! - loopback (`oif "lo" accept`),
//! - link-local destinations (`fe80::/10`),
//! - IPv6 Neighbor Discovery ICMPv6 (router/neighbor solicit/advert) so
//!   SLAAC and ND keep working.
//!
//! The dedicated `ip6` family confines the policy drop to IPv6 packets
//! only; IPv4 traffic is never seen by this table so the killswitch is
//! orthogonal to any IPv4 path the multi-hop tunnel needs (relay dial,
//! eth0 default route, policy routing table 100).
//!
//! ## Platforms
//!
//! Linux only. macOS could be implemented via `pf`, Windows via WFP;
//! the multi-hop UI lands on Linux first.
//!
//! ## Future extension
//!
//! When the multi-hop pipeline grows IPv6 routing inside the tunnel
//! (option A: route IPv6 through the multi-hop pipe),
//! this guard becomes a no-op and is replaced by an IPv6 TUN bridge.
//! Until then, killswitch is the safe default.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fmt::Write;
use std::net::Ipv6Addr;

const NFT_TABLE: &str = "warren_ipv6_block";

/// Builds the nftables ruleset implementing the IPv6 outbound killswitch.
///
/// **Pure**: no shell-out, no privileges required, directly testable.
/// Callers shell the string into `nft -f -`.
///
/// `allowed_exit_v6` lists the exit's IPv6 transport endpoints that MUST
/// stay reachable so a v6-dialed QUIC socket to the exit survives the
/// block. Pass an empty slice when the exit is dialed over IPv4 (the
/// common case): the killswitch then drops every off-tunnel v6 packet
/// except the host-stack essentials below. Without these allow rules a
/// v6-dialed transport would be killed by the very guard meant to
/// prevent leaks.
///
/// `socket_mark`: when `Some(mark)`, the exit exception is scoped to the
/// daemon's own `SO_MARK`-tagged carrier socket (`meta mark <mark>
/// accept`) instead of a per-endpoint `ip6 daddr <exit> accept` - the
/// same Port Fail / TunnelCrack ServerIP fix already applied to the main
/// killswitch (`warrenguard_killswitch_os::build_linux_ruleset`): a plain
/// destination match would grant the off-tunnel exception to ANY local
/// process dialing the exit's v6 address, not just the daemon.
/// `allowed_exit_v6` is then ignored (the exit address is left to be
/// captured/dropped like any other destination). `None` keeps the legacy
/// per-endpoint exception for a caller that has not wired up socket
/// tagging on this path yet.
#[must_use]
pub fn build_ipv6_block_ruleset(allowed_exit_v6: &[Ipv6Addr], socket_mark: Option<u32>) -> String {
    let mut s = String::with_capacity(512);
    // Atomic add/flush/body pattern mirroring the killswitch and
    // policy-routing rulesets so the install path is idempotent
    // across nft versions.
    let _ = writeln!(s, "# Warren IPv6 outbound killswitch");
    let _ = writeln!(s, "add table ip6 {NFT_TABLE}");
    let _ = writeln!(s, "flush table ip6 {NFT_TABLE}");
    let _ = writeln!(s, "table ip6 {NFT_TABLE} {{");
    let _ = writeln!(s, "    chain output {{");
    let _ = writeln!(
        s,
        "        type filter hook output priority filter; policy drop;"
    );
    if let Some(mark) = socket_mark {
        // The daemon's own tunnel socket, identified by its firewall mark.
        // Only this socket escapes; app traffic to a v6 exit address is
        // dropped (or captured by the tunnel elsewhere), not accepted here.
        let _ = writeln!(s, "        meta mark {mark:#x} accept");
    } else {
        // Exit transport endpoints: allow the QUIC socket to a v6-dialed
        // exit so the tunnel that carries everything else stays up.
        // Emitted first (most specific) for readability; nft `accept`
        // order is irrelevant here since each rule matches a disjoint
        // daddr.
        for exit in allowed_exit_v6 {
            let _ = writeln!(s, "        ip6 daddr {exit} accept");
        }
    }
    // Loopback: required for any host-internal IPv6 path (::1, mdns, ...).
    let _ = writeln!(s, "        oif \"lo\" accept");
    // Link-local destinations: ND, SLAAC, RA traffic lives here. Blocking
    // fe80::/10 would break IPv6 auto-configuration on every interface.
    let _ = writeln!(s, "        ip6 daddr fe80::/10 accept");
    // ICMPv6 Neighbor Discovery: explicit accept so SLAAC works even
    // when the destination is fe80::/10 (already covered) AND when a
    // router solicit goes to ff02::2 (NOT covered by fe80::/10).
    let _ = writeln!(
        s,
        "        icmpv6 type {{nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert}} accept"
    );
    let _ = writeln!(s, "    }}");
    let _ = writeln!(s, "}}");
    s
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::process::Stdio;

    use anyhow::{Context, Result, anyhow};
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    use super::{NFT_TABLE, build_ipv6_block_ruleset};

    /// RAII guard for the IPv6 outbound killswitch on Linux. Holds the
    /// installed state for automatic cleanup on drop.
    #[derive(Debug)]
    pub struct Ipv6KillswitchGuard {
        installed: bool,
    }

    impl Ipv6KillswitchGuard {
        /// Install the IPv6 killswitch by piping the ruleset into
        /// `nft -f -`. Idempotent: the ruleset begins with `add` +
        /// `flush` which absorb a previous installation.
        ///
        /// `socket_mark`: see [`build_ipv6_block_ruleset`] - when `Some`,
        /// scopes the exit exception to the daemon's marked carrier socket
        /// instead of the v6 destination (Port Fail / TunnelCrack ServerIP
        /// fix).
        ///
        /// # Errors
        ///
        /// - `nft` not in PATH, missing privileges (CAP_NET_ADMIN), or
        ///   ruleset rejected by the running kernel.
        pub async fn install(
            allowed_exit_v6: &[std::net::Ipv6Addr],
            socket_mark: Option<u32>,
        ) -> Result<Self> {
            let ruleset = build_ipv6_block_ruleset(allowed_exit_v6, socket_mark);
            run_nft_with_stdin(&ruleset)
                .await
                .context("nft load ipv6 killswitch ruleset")?;
            tracing::info!(
                table = NFT_TABLE,
                "Warren IPv6 outbound killswitch installed"
            );
            Ok(Self { installed: true })
        }

        /// Remove the killswitch table. Idempotent: tolerates "No such
        /// file" if a parallel process already removed it.
        ///
        /// # Errors
        ///
        /// Non-fatal: logs warn on any unexpected nft failure but never
        /// returns an error; the binary's shutdown path should be best-
        /// effort.
        pub async fn uninstall(mut self) -> Result<()> {
            if let Err(e) = run_nft_tolerant_missing(&["delete", "table", "ip6", NFT_TABLE]).await {
                tracing::warn!(error = %e, "nft delete ipv6 killswitch table failed (non-fatal)");
            }
            self.installed = false;
            tracing::info!("Warren IPv6 outbound killswitch uninstalled");
            Ok(())
        }
    }

    impl Drop for Ipv6KillswitchGuard {
        fn drop(&mut self) {
            if !self.installed {
                return;
            }
            // Best-effort sync cleanup. Drop is not async, so we cannot
            // await the tokio version; SIGKILL is unrecoverable but
            // the parent process is also dead so the kernel cleans up.
            let _ = std::process::Command::new("nft")
                .args(["delete", "table", "ip6", NFT_TABLE])
                .output();
            tracing::warn!(
                "Warren IPv6 killswitch dropped without explicit uninstall - \
                 synchronous cleanup attempted"
            );
        }
    }

    async fn run_nft_with_stdin(content: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn nft -f -")?;
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
            return Err(anyhow!("nft -f - exit {}: {}", out.status, stderr.trim()));
        }
        Ok(())
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
}

#[cfg(target_os = "linux")]
pub use linux_impl::Ipv6KillswitchGuard;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_uses_ip6_family_not_inet() {
        // Anti-regression: the `ip6` family confines the policy drop
        // to IPv6 packets only. Using `inet` family instead would make
        // the table see IPv4 traffic too, requiring an explicit
        // `meta nfproto ipv4 accept` rule. Easier to mis-order and
        // accidentally drop IPv4 traffic. Stick with `ip6`.
        let s = build_ipv6_block_ruleset(&[], None);
        assert!(
            s.contains("table ip6 warren_ipv6_block"),
            "must use ip6 family, got: {s}"
        );
        assert!(
            !s.contains("inet warren_ipv6_block"),
            "must NOT use inet family (would shadow IPv4 traffic), got: {s}"
        );
    }

    #[test]
    fn ruleset_output_chain_has_policy_drop() {
        let s = build_ipv6_block_ruleset(&[], None);
        assert!(
            s.contains("type filter hook output priority filter; policy drop;"),
            "output chain must default to drop, got: {s}"
        );
    }

    #[test]
    fn ruleset_accepts_loopback() {
        let s = build_ipv6_block_ruleset(&[], None);
        assert!(
            s.contains("oif \"lo\" accept"),
            "must accept loopback (::1 traffic), got: {s}"
        );
    }

    #[test]
    fn ruleset_accepts_link_local_for_neighbor_discovery() {
        let s = build_ipv6_block_ruleset(&[], None);
        assert!(
            s.contains("ip6 daddr fe80::/10 accept"),
            "must accept link-local destinations (ND, SLAAC, RA), got: {s}"
        );
    }

    #[test]
    fn ruleset_accepts_icmpv6_neighbor_discovery_messages() {
        let s = build_ipv6_block_ruleset(&[], None);
        // SLAAC + ND require both directions of router/neighbor solicit
        // and advert. Missing any of the four breaks IPv6 auto-config
        // silently and the user has no idea why DNS over IPv6 stopped
        // working.
        for needed in [
            "nd-router-solicit",
            "nd-router-advert",
            "nd-neighbor-solicit",
            "nd-neighbor-advert",
        ] {
            assert!(
                s.contains(needed),
                "must accept ICMPv6 {needed} (essential for SLAAC / ND), got: {s}"
            );
        }
    }

    #[test]
    fn ruleset_allows_exit_v6_endpoints_so_v6_transport_survives() {
        // A v6-dialed QUIC socket to the exit MUST stay reachable, else
        // the killswitch kills the very tunnel that carries everything
        // else. The allow rule must be a daddr match for the exit, and
        // the chain must still default-drop everything else.
        let exit: Ipv6Addr = "2001:db8:c17:1892::1".parse().unwrap();
        let s = build_ipv6_block_ruleset(&[exit], None);
        assert!(
            s.contains("ip6 daddr 2001:db8:c17:1892::1 accept"),
            "must allow the exit v6 transport endpoint, got: {s}"
        );
        assert!(
            s.contains("policy drop;"),
            "everything else must still be dropped, got: {s}"
        );
    }

    #[test]
    fn ruleset_with_socket_mark_replaces_exit_daddr_with_meta_mark_accept() {
        // Port Fail / TunnelCrack ServerIP fix: a destination-based exit
        // exception lets ANY app dialing the exit's v6 address escape the
        // block. Scoping the exception to the daemon's own marked socket
        // closes that hole - matches the fix already applied to the main
        // killswitch ruleset.
        let exit: Ipv6Addr = "2001:db8:c17:1892::1".parse().unwrap();
        let s = build_ipv6_block_ruleset(&[exit], Some(0x7761_7272));
        assert!(
            s.contains("meta mark 0x77617272 accept"),
            "expected the socket-mark accept rule, got:\n{s}"
        );
        assert!(
            !s.contains("ip6 daddr 2001:db8:c17:1892::1"),
            "the per-exit destination exception must NOT be emitted when \
             socket_mark is set - that is the leak this closes:\n{s}"
        );
        assert!(
            s.contains("policy drop;"),
            "fail-closed default must be preserved regardless of socket_mark"
        );
        assert!(
            s.contains("oif \"lo\" accept"),
            "loopback exception must be preserved regardless of socket_mark"
        );
    }

    #[test]
    fn ruleset_without_socket_mark_keeps_legacy_exit_daddr_accept() {
        // Back-compat: a caller that has not wired up socket tagging on
        // this path still gets the historical destination-based exception.
        let exit: Ipv6Addr = "2001:db8:c17:1892::1".parse().unwrap();
        let s = build_ipv6_block_ruleset(&[exit], None);
        assert!(
            s.contains("ip6 daddr 2001:db8:c17:1892::1 accept"),
            "socket_mark: None must preserve the legacy per-exit exception"
        );
    }

    #[test]
    fn ruleset_empty_exit_list_drops_all_internet_v6() {
        // The IPv4-dialed common case: no exit allow rule, every
        // off-tunnel v6 destination dropped (only lo / link-local / ND
        // survive). Anti-regression that an empty slice does not somehow
        // emit a stray accept.
        let s = build_ipv6_block_ruleset(&[], None);
        assert!(
            !s.contains("ip6 daddr 2") && !s.contains("ip6 daddr 3"),
            "no global-unicast accept may be emitted for an empty exit list, got: {s}"
        );
    }

    #[test]
    fn ruleset_uses_atomic_add_flush_body_pattern() {
        // Mirrors the killswitch and policy-routing rulesets
        // so the install is idempotent across nft versions. A drift to
        // the fragile `table X / delete table / table X { ... }`
        // pattern would surface here.
        let s = build_ipv6_block_ruleset(&[], None);
        let add_pos = s
            .find("add table ip6 warren_ipv6_block")
            .expect("add line present");
        let flush_pos = s
            .find("flush table ip6 warren_ipv6_block")
            .expect("flush line present");
        let body_pos = s
            .find("table ip6 warren_ipv6_block {")
            .expect("table body present");
        assert!(
            add_pos < flush_pos && flush_pos < body_pos,
            "expected order add < flush < body; got positions add={add_pos} flush={flush_pos} body={body_pos} in ruleset:\n{s}"
        );
    }
}
