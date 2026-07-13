//! Cross-OS representation of an IPv4 CIDR an operator wants to
//! keep OFF the tunnel (i.e. preserve on the host's original main
//! routing table). Used by the Linux split-default policy routing
//! installer ([`crate::default_route_split`]) and by any caller's
//! `--bypass-cidr`-style flag.
//!
//! Kept in its own non-`cfg`-gated module so the type is reachable
//! from cross-OS code (CLI arg parsing, library callers on
//! macOS/Windows that may want to log or persist the value even
//! before the platform-specific runtime support lands).

use std::net::Ipv4Addr;

use thiserror::Error;

/// A user-supplied bypass CIDR: traffic destined for this IPv4
/// network skips the tunnel and uses the host's main routing table.
///
/// Typical use: `192.168.0.0/16` to keep LAN reachable while the
/// tunnel is up, or `10.0.0.0/8` to preserve inbound SSH on a
/// private management network. The renderer does not normalise host
/// bits beyond `prefix`; the caller is expected to supply the
/// network address (e.g. `192.168.0.0/16`, not `192.168.1.42/16`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BypassCidr {
    /// The network address.
    pub network: Ipv4Addr,
    /// CIDR prefix length, in `0..=32`. `/0` is rejected upstream
    /// (it would defeat the tunnel entirely).
    pub prefix: u8,
}

impl std::fmt::Display for BypassCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Reasons [`BypassCidr::from_str`] may refuse a value.
#[derive(Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ParseBypassCidrError {
    /// No `/` separator.
    #[error("missing '/<prefix>' separator")]
    MissingPrefix,
    /// The network half was not a valid `Ipv4Addr`.
    #[error("invalid IPv4 network: {0}")]
    BadNetwork(String),
    /// The prefix half was not a decimal integer in 0..=32.
    #[error("invalid CIDR prefix (need 1..=32): {0}")]
    BadPrefix(String),
    /// Caller passed `/0`, which would route all traffic to main
    /// (defeating the tunnel). Rejected loudly.
    #[error("CIDR prefix /0 is not allowed (it would bypass the entire tunnel)")]
    PrefixZeroForbidden,
}

impl std::str::FromStr for BypassCidr {
    type Err = ParseBypassCidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (net, pfx) = s
            .split_once('/')
            .ok_or(ParseBypassCidrError::MissingPrefix)?;
        let network: Ipv4Addr = net
            .parse()
            .map_err(|_| ParseBypassCidrError::BadNetwork(net.to_string()))?;
        let prefix: u8 = pfx
            .parse()
            .map_err(|_| ParseBypassCidrError::BadPrefix(pfx.to_string()))?;
        if prefix == 0 {
            return Err(ParseBypassCidrError::PrefixZeroForbidden);
        }
        if prefix > 32 {
            return Err(ParseBypassCidrError::BadPrefix(pfx.to_string()));
        }
        Ok(Self { network, prefix })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_lan_cidr() {
        let c: BypassCidr = "192.168.0.0/16".parse().expect("valid CIDR");
        assert_eq!(c.network, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(c.prefix, 16);
    }

    #[test]
    fn parses_host_route() {
        let c: BypassCidr = "10.0.0.5/32".parse().expect("valid /32");
        assert_eq!(c.network, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(c.prefix, 32);
    }

    #[test]
    fn rejects_missing_slash() {
        let err = "192.168.0.0".parse::<BypassCidr>().unwrap_err();
        assert_eq!(err, ParseBypassCidrError::MissingPrefix);
    }

    #[test]
    fn rejects_zero_prefix() {
        // /0 means "all of IPv4" - bypassing the entire tunnel is
        // never what the operator means, so we refuse it loudly
        // instead of silently producing an unusable config.
        let err = "0.0.0.0/0".parse::<BypassCidr>().unwrap_err();
        assert_eq!(err, ParseBypassCidrError::PrefixZeroForbidden);
    }

    #[test]
    fn rejects_oversized_prefix() {
        let err = "10.0.0.0/33".parse::<BypassCidr>().unwrap_err();
        assert!(matches!(err, ParseBypassCidrError::BadPrefix(_)));
    }

    #[test]
    fn rejects_non_ipv4_network() {
        let err = "::1/128".parse::<BypassCidr>().unwrap_err();
        assert!(matches!(err, ParseBypassCidrError::BadNetwork(_)));
    }

    #[test]
    fn display_renders_canonical_form() {
        let c = BypassCidr {
            network: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 8,
        };
        assert_eq!(c.to_string(), "10.0.0.0/8");
    }
}
