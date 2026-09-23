//! Per-source-IP connection rate limiting.
//!
//! A per-key token bucket ([`warrenguard_ratelimit::ConnectionRateLimiter`])
//! throttles how fast a single source may open new connections. This
//! complements the global concurrency cap in [`crate::server`]: the cap bounds
//! simultaneous connections, the rate limiter bounds connection *churn* so one
//! source cannot monopolize accept throughput.
//!
//! Keying notes (this is a censorship-circumvention proxy, so be careful):
//! - IPv4 is keyed by the full address (/32).
//! - IPv6 is keyed by the /64 prefix: a single end user is typically assigned a
//!   whole /64, so keying per /128 would let them rotate addresses within their
//!   prefix to bypass the limit.
//! - Many legitimate users sit behind a single CGNAT IPv4 in censored regions,
//!   so limits should stay generous; operators can disable rate limiting
//!   entirely (`--per-ip-per-second 0`).
//!
//! Privacy - rate limiting by IP is NOT the same as logging IPs, and this code
//! is consistent with the no-log stance:
//! - The source IP is held only as an in-RAM map key with a transient token
//!   count as its value. It is never written to logs, metrics, or disk.
//! - The key is reclaimed within `RATE_LIMIT_CLEANUP_INTERVAL` (60 s) of its
//!   budget fully recovering; there is no accumulating history of "who
//!   connected when".
//! - The kernel already knows the peer IP of every active TCP connection (its
//!   socket/conntrack table), so this transient in-memory counter exposes
//!   nothing beyond what the OS holds for any TCP service. The only thing that
//!   would persist and deanonymize users - log lines with peer addresses - is
//!   deliberately not emitted anywhere.

use std::net::{IpAddr, Ipv6Addr};
use std::num::{NonZeroU32, NonZeroUsize};
use std::time::{Duration, Instant};

use warrenguard_ratelimit::ConnectionRateLimiter;

/// Per-IP rate limit parameters.
#[derive(Debug, Clone, Copy)]
pub struct PerIpLimit {
    /// Sustained new connections allowed per second, per key.
    pub per_second: NonZeroU32,
    /// Maximum burst of connections allowed before throttling kicks in.
    pub burst: NonZeroU32,
}

/// Per-IP connection rate limiter.
pub struct IpRateLimiter {
    inner: ConnectionRateLimiter<IpAddr>,
    /// Idle time after which a key's budget is back to a full burst, so
    /// forgetting it is lossless.
    full_recovery: Duration,
}

impl IpRateLimiter {
    /// Build a limiter from the given per-IP limit.
    ///
    /// `max_keys` bounds the number of distinct source keys tracked at once:
    /// once reached, [`Self::check`] refuses a NEW source (fail-closed) until
    /// [`Self::cleanup`] or the limiter's own reclaim frees a slot, while the
    /// sources already tracked keep their budgets. The key map therefore
    /// cannot be turned into a memory-exhaustion vector by a flood of distinct
    /// source IPs, nor that flood into a lockout of the sources it found.
    #[must_use]
    pub fn new(limit: PerIpLimit, max_keys: NonZeroUsize) -> Self {
        let refill = (Duration::from_secs(1) / limit.per_second.get()).max(Duration::from_nanos(1));
        Self {
            inner: ConnectionRateLimiter::with_max_tracked(limit.burst.get(), refill, max_keys),
            full_recovery: refill.saturating_mul(limit.burst.get()),
        }
    }

    /// Returns `true` if a new connection from `ip` is allowed right now.
    ///
    /// Fails closed (returns `false`) for a source not yet tracked when the
    /// key map is saturated.
    #[must_use]
    pub fn check(&self, ip: IpAddr) -> bool {
        self.inner.try_acquire(&normalize_key(ip))
    }

    /// Drop the keys whose budget has fully recovered, and return the memory
    /// once the map is mostly empty. Call periodically to bound memory under a
    /// churn of distinct source IPs.
    pub fn cleanup(&self) {
        self.inner.retain_active(self.full_recovery, Instant::now());
    }

    /// Number of tracked keys (for metrics/tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.tracked_count()
    }

    /// Whether the limiter currently tracks no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.tracked_count() == 0
    }
}

/// Normalize an IP into a rate-limit key: IPv4 as-is, IPv6 masked to its /64.
pub(crate) fn normalize_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(per_second: u32, burst: u32) -> PerIpLimit {
        PerIpLimit {
            per_second: NonZeroU32::new(per_second).unwrap(),
            burst: NonZeroU32::new(burst).unwrap(),
        }
    }

    const NO_KEY_CAP: NonZeroUsize = NonZeroUsize::MAX;

    #[test]
    fn allows_burst_then_throttles() {
        let rl = IpRateLimiter::new(limit(1, 3), NO_KEY_CAP);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        // Burst of 3 is allowed immediately; the 4th is throttled.
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip), "4th connection should be rate limited");
    }

    #[test]
    fn limits_are_per_key() {
        let rl = IpRateLimiter::new(limit(1, 1), NO_KEY_CAP);
        let a: IpAddr = "203.0.113.5".parse().unwrap();
        let b: IpAddr = "203.0.113.6".parse().unwrap();
        assert!(rl.check(a));
        assert!(!rl.check(a), "second from A throttled");
        assert!(rl.check(b), "B has its own bucket");
    }

    #[test]
    fn fails_closed_when_key_map_saturated() {
        // Cap of 1 key: the first distinct source registers, any further
        // distinct source is refused until cleanup.
        let rl = IpRateLimiter::new(limit(100, 100), NonZeroUsize::MIN);
        assert!(rl.check("203.0.113.1".parse().unwrap()));
        assert!(
            !rl.check("203.0.113.2".parse().unwrap()),
            "second distinct key must be refused at capacity"
        );
    }

    #[test]
    fn a_tracked_source_keeps_its_budget_when_the_key_map_is_full() {
        // A flood of distinct sources that fills the map must not lock out
        // the sources already tracked: only a NEW source is refused.
        let rl = IpRateLimiter::new(limit(100, 100), NonZeroUsize::MIN);
        let known: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(rl.check(known));
        assert!(!rl.check("203.0.113.2".parse().unwrap()));
        assert!(rl.check(known), "a tracked source keeps being served");
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn cleanup_frees_the_capacity_of_recovered_sources() {
        // One token per millisecond, burst 1: a source idle 1 ms has fully
        // recovered, so dropping it loses nothing.
        let rl = IpRateLimiter::new(limit(1_000, 1), NonZeroUsize::MIN);
        assert!(rl.check("203.0.113.1".parse().unwrap()));
        std::thread::sleep(std::time::Duration::from_millis(5));
        rl.cleanup();
        assert!(rl.is_empty());
        assert!(rl.check("203.0.113.2".parse().unwrap()));
    }

    #[test]
    fn ipv6_is_keyed_by_64_prefix() {
        let rl = IpRateLimiter::new(limit(1, 1), NO_KEY_CAP);
        // Two addresses in the same /64 share a bucket.
        let a: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1234:ffff:ffff:ffff:ffff".parse().unwrap();
        assert!(rl.check(a));
        assert!(!rl.check(b), "same /64 should share the limit");
        // A different /64 has its own bucket.
        let c: IpAddr = "2001:db8:abcd:9999::1".parse().unwrap();
        assert!(rl.check(c));
    }

    #[test]
    fn normalize_masks_ipv6_to_64() {
        let masked = normalize_key("2001:db8:abcd:1234:5678:9abc:def0:1234".parse().unwrap());
        assert_eq!(masked, "2001:db8:abcd:1234::".parse::<IpAddr>().unwrap());
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(normalize_key(v4), v4);
    }
}
