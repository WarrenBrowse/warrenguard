//! Per-source-IP cap on concurrently active relay sessions.
//!
//! [`crate::ratelimit::IpRateLimiter`] bounds how *fast* a source IP opens new
//! connections; the server's global [`tokio::sync::Semaphore`] bounds the
//! *total* concurrent connections. Neither stops one source IP from slowly
//! accumulating long-lived relays, one every few seconds within its rate
//! budget, until it alone approaches the global cap and starves every other
//! client sharing this proxy - a realistic shape for a CGNAT IP with many
//! simultaneous users, not just a hostile one. This closes that gap: a guard
//! is held for each session's lifetime and released on drop, so the count
//! reflects live sessions, not a rate.
//!
//! This mirrors the `PerIpConcurrency` hardening already applied to the
//! sibling `warrenguard-edge-server` ingress, kept here as a small
//! self-contained type rather than a cross-crate dependency (both crates stay
//! independently publishable).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::ratelimit::normalize_key;

/// Caps the number of concurrently active relay sessions per source IP.
///
/// IPv6 is keyed by its /64, matching [`crate::ratelimit::IpRateLimiter`]: a
/// single end user is typically assigned a whole /64, so keying per /128
/// would let them dodge the cap by rotating addresses within their prefix.
pub struct PerIpConcurrency {
    map: Arc<Mutex<HashMap<IpAddr, u32>>>,
    max: u32,
}

/// Frees its source IP's reserved slot on drop (RAII), so a session that ends
/// for any reason (clean close, relay error, panic) always releases its slot.
pub struct PerIpConcurrencyGuard {
    map: Arc<Mutex<HashMap<IpAddr, u32>>>,
    key: IpAddr,
}

impl PerIpConcurrency {
    /// Builds a cap of `max` concurrent sessions per source IP key.
    #[must_use]
    pub fn new(max: u32) -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
            max,
        }
    }

    /// Reserves a slot for `ip`, or `None` if it is already at `max`. Reads
    /// before inserting so a refused key never leaves a zero-count entry
    /// behind. Fails closed (refuses) on a poisoned lock, since a poisoned
    /// map cannot be trusted to reflect the true live-session count.
    #[must_use]
    pub fn try_acquire(&self, ip: IpAddr) -> Option<PerIpConcurrencyGuard> {
        let key = normalize_key(ip);
        let mut map = self.map.lock().ok()?;
        let count = map.get(&key).copied().unwrap_or(0);
        if count >= self.max {
            return None;
        }
        map.insert(key, count + 1);
        Some(PerIpConcurrencyGuard {
            map: Arc::clone(&self.map),
            key,
        })
    }

    /// Number of distinct source keys currently holding at least one slot
    /// (tests/metrics only).
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.map.lock().map(|m| m.len()).unwrap_or(0)
    }
}

impl Drop for PerIpConcurrencyGuard {
    fn drop(&mut self) {
        let Ok(mut map) = self.map.lock() else {
            return;
        };
        let Some(count) = map.get_mut(&self.key) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_up_to_max_then_refuses() {
        let conc = PerIpConcurrency::new(2);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let _g1 = conc.try_acquire(ip).expect("1st session admitted");
        let _g2 = conc.try_acquire(ip).expect("2nd session admitted");
        assert!(
            conc.try_acquire(ip).is_none(),
            "3rd concurrent session from the same IP must be refused"
        );
    }

    #[test]
    fn dropping_a_guard_frees_the_slot() {
        let conc = PerIpConcurrency::new(1);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let g1 = conc.try_acquire(ip).expect("1st session admitted");
        assert!(conc.try_acquire(ip).is_none(), "at cap");
        drop(g1);
        assert!(
            conc.try_acquire(ip).is_some(),
            "freed slot must be re-admitted"
        );
    }

    #[test]
    fn limits_are_independent_per_source_ip() {
        let conc = PerIpConcurrency::new(1);
        let a: IpAddr = "203.0.113.5".parse().unwrap();
        let b: IpAddr = "203.0.113.6".parse().unwrap();
        let _ga = conc.try_acquire(a).expect("A admitted");
        assert!(conc.try_acquire(a).is_none(), "A at cap");
        assert!(conc.try_acquire(b).is_some(), "B has its own budget");
    }

    #[test]
    fn ipv6_is_keyed_by_64_prefix() {
        let conc = PerIpConcurrency::new(1);
        let a: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1234:ffff:ffff:ffff:ffff".parse().unwrap();
        let _ga = conc.try_acquire(a).expect("first /64 member admitted");
        assert!(
            conc.try_acquire(b).is_none(),
            "same /64 must share the concurrency budget"
        );
    }

    #[test]
    fn a_fully_drained_key_is_evicted_from_the_map() {
        let conc = PerIpConcurrency::new(3);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let g1 = conc.try_acquire(ip).unwrap();
        let g2 = conc.try_acquire(ip).unwrap();
        assert_eq!(conc.tracked_keys(), 1);
        drop(g1);
        drop(g2);
        assert_eq!(
            conc.tracked_keys(),
            0,
            "a key at zero live sessions must not linger in the map"
        );
    }
}
