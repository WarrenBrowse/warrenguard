//! Per-source-IP connection rate limiting.
//!
//! Uses `governor`'s keyed GCRA limiter (Generic Cell Rate Algorithm, a
//! leaky-bucket variant) to throttle how fast a single source may open new
//! connections. This complements the global concurrency cap in [`crate::server`]:
//! the cap bounds simultaneous connections, the rate limiter bounds connection
//! *churn* so one source cannot monopolize accept throughput.
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
//! - The source IP is held only as an in-RAM map key with a transient GCRA
//!   counter as its value. It is never written to logs, metrics, or disk.
//! - The counter decays and the key is reclaimed within
//!   `RATE_LIMIT_CLEANUP_INTERVAL` (60 s); there is no accumulating history of
//!   "who connected when".
//! - The kernel already knows the peer IP of every active TCP connection (its
//!   socket/conntrack table), so this transient in-memory counter exposes
//!   nothing beyond what the OS holds for any TCP service. The only thing that
//!   would persist and deanonymize users - log lines with peer addresses - is
//!   deliberately not emitted anywhere.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;

use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

/// A keyed GCRA rate limiter over source IP keys.
type KeyedLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

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
    inner: KeyedLimiter,
    max_keys: usize,
}

impl IpRateLimiter {
    /// Build a limiter from the given per-IP limit.
    ///
    /// `max_keys` bounds the number of distinct source keys tracked at once:
    /// once reached, [`Self::check`] fails closed (refuses new connections)
    /// until the next [`Self::cleanup`], so the key map cannot be turned into
    /// a memory-exhaustion vector by a flood of distinct source IPs.
    #[must_use]
    pub fn new(limit: PerIpLimit, max_keys: usize) -> Self {
        let quota = Quota::per_second(limit.per_second).allow_burst(limit.burst);
        Self {
            inner: RateLimiter::keyed(quota),
            max_keys,
        }
    }

    /// Returns `true` if a new connection from `ip` is allowed right now.
    ///
    /// Fails closed (returns `false`) when the key map is saturated, bounding
    /// memory at the cost of refusing new sources until the next cleanup.
    #[must_use]
    pub fn check(&self, ip: IpAddr) -> bool {
        // `check_key` inserts a new entry on first sight of a key, so guard the
        // map size *before* calling it to keep memory bounded under a flood.
        if self.inner.len() >= self.max_keys {
            return false;
        }
        self.inner.check_key(&normalize_key(ip)).is_ok()
    }

    /// Drop limiter state for keys that have fully recovered, then release the
    /// freed capacity back to the allocator. Call periodically to bound memory
    /// under a churn of distinct source IPs.
    pub fn cleanup(&self) {
        self.inner.retain_recent();
        self.inner.shrink_to_fit();
    }

    /// Number of tracked keys (for metrics/tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the limiter currently tracks no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
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

    const NO_KEY_CAP: usize = usize::MAX;

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
        let rl = IpRateLimiter::new(limit(100, 100), 1);
        assert!(rl.check("203.0.113.1".parse().unwrap()));
        assert!(
            !rl.check("203.0.113.2".parse().unwrap()),
            "second distinct key must be refused at capacity"
        );
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
