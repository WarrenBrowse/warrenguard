//! Type-safe nftables ruleset builder.
//!
//! Replaces raw `writeln!` string interpolation with Rust enums and
//! structs. The output is still a string piped to `nft -f -`, but
//! rule construction is now checked at compile time (no typos in
//! "accept", "drop", interface names validated, IP formatting
//! delegated to `IpAddr::fmt`).

use std::fmt::Write;
use std::net::IpAddr;

/// nftables address family.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Family {
    Inet,
}

/// Chain hook point.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Hook {
    Output,
}

/// Default chain policy.
///
/// Only `Drop` is ever constructed: every Warren killswitch chain is
/// fail-closed by design (cf. crate doc), so an `Accept`-default policy
/// variant would only invite a future ruleset that defeats the
/// killswitch by construction. Kept as an enum (rather than inlining
/// `"drop"`) so [`NftRuleset::render`] documents the nftables grammar
/// explicitly.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Policy {
    Drop,
}

/// Chain type.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ChainType {
    Filter,
}

/// Rule verdict.
///
/// Only `Accept` is ever constructed: every rule this crate builds is an
/// exception carved out of the chain's `Drop` [`Policy`] (loopback, the
/// TUN device, the marked/bound tunnel socket, optional LAN/DHCP). A
/// rule-level `Drop` verdict would be redundant with the chain policy.
/// Kept as an enum for the same documentation reason as [`Policy`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum Verdict {
    Accept,
}

/// Match condition for a rule.
#[derive(Debug, Clone)]
pub(crate) enum Match {
    Oifname(String),
    IpDaddr(IpAddr),
    Ip6Daddr(IpAddr),
    IpDaddrCidr(String),
    Ip6DaddrCidr(String),
    L4ProtoUdp,
    UdpDports(Vec<u16>),
    /// Linux `SO_MARK` on the daemon's own tunnel socket. Scopes an
    /// accept rule to that specific socket instead of a destination,
    /// closing the Port Fail / TunnelCrack-ServerIP hole a
    /// destination-based `ip daddr <exit>` rule opens (see
    /// `KillswitchOpts` doc).
    MetaMark(u32),
}

/// A single nftables rule.
#[derive(Debug, Clone)]
pub(crate) struct NftRule {
    pub(crate) matches: Vec<Match>,
    pub(crate) verdict: Verdict,
}

/// A chain with its rules.
pub(crate) struct NftChain {
    pub(crate) name: String,
    pub(crate) chain_type: ChainType,
    pub(crate) hook: Hook,
    pub(crate) policy: Policy,
    pub(crate) rules: Vec<NftRule>,
}

/// A complete nftables ruleset.
pub(crate) struct NftRuleset {
    pub(crate) table_name: String,
    pub(crate) family: Family,
    pub(crate) chains: Vec<NftChain>,
}

impl NftRuleset {
    /// Render to the nft batch format consumed by `nft -f -`.
    #[must_use]
    pub(crate) fn render(&self) -> String {
        let family = match self.family {
            Family::Inet => "inet",
        };
        let mut s = String::with_capacity(2048);
        let _ = writeln!(s, "add table {family} {}", self.table_name);
        let _ = writeln!(s, "flush table {family} {}", self.table_name);
        let _ = writeln!(s, "table {family} {} {{", self.table_name);

        for chain in &self.chains {
            let ct = match chain.chain_type {
                ChainType::Filter => "filter",
            };
            let hook = match chain.hook {
                Hook::Output => "output",
            };
            let policy = match chain.policy {
                Policy::Drop => "drop",
            };
            let _ = writeln!(s, "    chain {} {{", chain.name);
            let _ = writeln!(
                s,
                "        type {ct} hook {hook} priority filter; policy {policy};"
            );

            for rule in &chain.rules {
                let _ = write!(s, "        ");
                for m in &rule.matches {
                    match m {
                        Match::Oifname(name) => {
                            let _ = write!(s, "oifname \"{name}\" ");
                        }
                        Match::IpDaddr(addr) => {
                            let _ = write!(s, "ip daddr {addr} ");
                        }
                        Match::Ip6Daddr(addr) => {
                            let _ = write!(s, "ip6 daddr {addr} ");
                        }
                        Match::IpDaddrCidr(cidr) => {
                            let _ = write!(s, "ip daddr {cidr} ");
                        }
                        Match::Ip6DaddrCidr(cidr) => {
                            let _ = write!(s, "ip6 daddr {cidr} ");
                        }
                        Match::L4ProtoUdp => {
                            let _ = write!(s, "meta l4proto udp ");
                        }
                        Match::UdpDports(ports) => {
                            let p: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                            let _ = write!(s, "udp dport {{{}}} ", p.join(", "));
                        }
                        Match::MetaMark(mark) => {
                            let _ = write!(s, "meta mark {mark:#x} ");
                        }
                    }
                }
                let verdict = match rule.verdict {
                    Verdict::Accept => "accept",
                };
                let _ = writeln!(s, "{verdict}");
            }
            let _ = writeln!(s, "    }}");
        }
        let _ = writeln!(s, "}}");
        s
    }
}

/// Build the killswitch nftables ruleset from typed opts.
///
/// `socket_mark`: when `Some(mark)`, the exit exception is scoped to
/// the daemon's own `SO_MARK`-tagged socket (`meta mark <mark>
/// accept`) instead of the per-exit `ip daddr <exit>` destination
/// match - the Port Fail / TunnelCrack-ServerIP fix (see
/// `KillswitchOpts` doc). `exit_addrs` is then ignored for this
/// exception (the exit IP is left to be captured by the tunnel's
/// split-default route like any other destination). `None` keeps the
/// legacy destination-based exception.
#[must_use]
pub(crate) fn build_killswitch_ruleset(
    table_name: &str,
    tun_name: &str,
    exit_addrs: &[IpAddr],
    allow_lan: bool,
    allow_dhcp: bool,
    socket_mark: Option<u32>,
) -> NftRuleset {
    let mut rules = Vec::new();

    rules.push(NftRule {
        matches: vec![Match::Oifname("lo".into())],
        verdict: Verdict::Accept,
    });

    rules.push(NftRule {
        matches: vec![Match::Oifname(tun_name.into())],
        verdict: Verdict::Accept,
    });

    if let Some(mark) = socket_mark {
        rules.push(NftRule {
            matches: vec![Match::MetaMark(mark)],
            verdict: Verdict::Accept,
        });
    } else {
        for addr in exit_addrs {
            let addr_match = match addr {
                IpAddr::V4(_) => Match::IpDaddr(*addr),
                IpAddr::V6(_) => Match::Ip6Daddr(*addr),
            };
            rules.push(NftRule {
                matches: vec![addr_match, Match::L4ProtoUdp],
                verdict: Verdict::Accept,
            });
        }
    }

    if allow_lan {
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
            rules.push(NftRule {
                matches: vec![Match::IpDaddrCidr(cidr.into())],
                verdict: Verdict::Accept,
            });
        }
        for cidr in ["fc00::/7", "fe80::/10"] {
            rules.push(NftRule {
                matches: vec![Match::Ip6DaddrCidr(cidr.into())],
                verdict: Verdict::Accept,
            });
        }
    }

    if allow_dhcp {
        rules.push(NftRule {
            matches: vec![Match::UdpDports(vec![67, 68])],
            verdict: Verdict::Accept,
        });
    }

    NftRuleset {
        table_name: table_name.into(),
        family: Family::Inet,
        chains: vec![NftChain {
            name: "output".into(),
            chain_type: ChainType::Filter,
            hook: Hook::Output,
            policy: Policy::Drop,
            rules,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn rendered_ruleset_contains_table_and_chain() {
        let rs = build_killswitch_ruleset(
            "warrenguard_killswitch_os",
            "tun0",
            &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            false,
            false,
            None,
        );
        let s = rs.render();
        assert!(s.contains("table inet warrenguard_killswitch_os"));
        assert!(s.contains("chain output"));
        assert!(s.contains("policy drop;"));
    }

    #[test]
    fn rendered_ruleset_has_loopback_and_tun() {
        let rs = build_killswitch_ruleset("t", "warren0", &[], false, false, None);
        let s = rs.render();
        assert!(s.contains("oifname \"lo\" accept"));
        assert!(s.contains("oifname \"warren0\" accept"));
    }

    #[test]
    fn rendered_ruleset_has_exit_ip_udp() {
        // Back-compat: socket_mark: None must keep the legacy
        // destination-based exception.
        let rs = build_killswitch_ruleset(
            "t",
            "tun0",
            &[IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))],
            false,
            false,
            None,
        );
        let s = rs.render();
        assert!(s.contains("ip daddr 5.6.7.8 meta l4proto udp accept"));
    }

    #[test]
    fn rendered_ruleset_has_ipv6_exit() {
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let rs = build_killswitch_ruleset("t", "tun0", &[IpAddr::V6(v6)], false, false, None);
        let s = rs.render();
        assert!(s.contains("ip6 daddr 2001:db8::1 meta l4proto udp accept"));
    }

    #[test]
    fn rendered_ruleset_with_socket_mark_uses_meta_mark_and_omits_exit_daddr() {
        // Port Fail / TunnelCrack-ServerIP fix: the socket-mark accept
        // rule replaces the per-exit destination exception outright,
        // so no other process dialing the exit IP can slip through.
        let rs = build_killswitch_ruleset(
            "t",
            "tun0",
            &[IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))],
            false,
            false,
            Some(0x77617272),
        );
        let s = rs.render();
        assert!(s.contains("meta mark 0x77617272 accept"));
        assert!(
            !s.contains("ip daddr 5.6.7.8"),
            "the destination-based exception must not coexist with the \
             socket-mark one: {s}"
        );
        assert!(s.contains("policy drop;"));
        assert!(s.contains("oifname \"lo\" accept"));
        assert!(s.contains("oifname \"tun0\" accept"));
    }

    #[test]
    fn rendered_ruleset_has_lan_when_enabled() {
        let rs = build_killswitch_ruleset("t", "tun0", &[], true, false, None);
        let s = rs.render();
        assert!(s.contains("ip daddr 10.0.0.0/8 accept"));
        assert!(s.contains("ip daddr 192.168.0.0/16 accept"));
        assert!(s.contains("ip6 daddr fc00::/7 accept"));
    }

    #[test]
    fn rendered_ruleset_has_no_lan_by_default() {
        let rs = build_killswitch_ruleset("t", "tun0", &[], false, false, None);
        let s = rs.render();
        assert!(!s.contains("192.168"));
    }

    #[test]
    fn rendered_ruleset_has_dhcp_when_enabled() {
        let rs = build_killswitch_ruleset("t", "tun0", &[], false, true, None);
        let s = rs.render();
        assert!(s.contains("udp dport {67, 68} accept"));
    }

    #[test]
    fn rendered_ruleset_does_not_contain_ct_state() {
        let rs = build_killswitch_ruleset(
            "t",
            "tun0",
            &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            true,
            true,
            None,
        );
        let s = rs.render();
        assert!(
            !s.contains("ct state"),
            "ct state leaks pre-killswitch connections"
        );
    }
}
