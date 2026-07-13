//! Atomic counters and privacy-preserving structured logs.
//!
//! The relay is the most sensitive Warren node from a privacy
//! standpoint: it observes the timing and size of every client
//! datagram even though it cannot decrypt the payload. CLAUDE.md § 6
//! therefore forbids:
//! - logging a client `SocketAddr` or its IP fragment,
//! - logging a peer pubkey (RPK identity) in full,
//! - logging an `exit_id`, a `nonce`, or any HPKE ciphertext byte.
//!
//! All emitted log records are aggregated counts. The counters are
//! held in a [`RelayMetrics`] value typically kept as
//! `Arc<RelayMetrics>` so multiple session tasks can `fetch_add`
//! concurrently. A Prometheus-style scrape endpoint is intentionally
//! out of scope of `/v1`: the binary may expose a loopback
//! `/metrics` later, but the counters themselves are stable and
//! reusable.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters covering the relay's hot paths.
#[derive(Debug, Default)]
pub struct RelayMetrics {
    /// Number of client sessions whose first datagram successfully
    /// resolved to an exit.
    pub sessions_dispatched: AtomicU64,
    /// Number of first datagrams rejected because they were malformed
    /// (see [`crate::session::WARREN_VARINT_INVALID_FRAME`]).
    pub sessions_rejected_malformed: AtomicU64,
    /// Number of first datagrams rejected because the exit_id was
    /// unknown ([`crate::session::WARREN_VARINT_UNKNOWN_EXIT`]).
    pub sessions_rejected_unknown_exit: AtomicU64,
    /// Number of times the exit pool reused a cached connection.
    pub exit_pool_hits: AtomicU64,
    /// Number of times the exit pool dialed a fresh connection.
    pub exit_pool_misses: AtomicU64,
    /// Cumulative number of datagrams forwarded `client -> exit`.
    pub datagrams_client_to_exit: AtomicU64,
    /// Cumulative number of datagrams forwarded `exit -> client`.
    pub datagrams_exit_to_client: AtomicU64,
    /// Cumulative number of datagrams dropped on `client -> exit`
    /// because they exceeded `max_datagram_size` of the exit
    /// connection.
    pub datagrams_dropped_too_large_c2e: AtomicU64,
    /// Same as above on the `exit -> client` direction.
    pub datagrams_dropped_too_large_e2c: AtomicU64,
}

impl RelayMetrics {
    /// Returns a fresh zeroed metrics block.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments `sessions_dispatched` by 1.
    pub fn inc_sessions_dispatched(&self) {
        self.sessions_dispatched.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `sessions_rejected_malformed` by 1.
    pub fn inc_sessions_rejected_malformed(&self) {
        self.sessions_rejected_malformed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `sessions_rejected_unknown_exit` by 1.
    pub fn inc_sessions_rejected_unknown_exit(&self) {
        self.sessions_rejected_unknown_exit
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `exit_pool_hits` by 1.
    pub fn inc_exit_pool_hit(&self) {
        self.exit_pool_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `exit_pool_misses` by 1.
    pub fn inc_exit_pool_miss(&self) {
        self.exit_pool_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `n` to `datagrams_client_to_exit`.
    pub fn add_c2e(&self, n: u64) {
        self.datagrams_client_to_exit
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Adds `n` to `datagrams_exit_to_client`.
    pub fn add_e2c(&self, n: u64) {
        self.datagrams_exit_to_client
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Adds `n` to `datagrams_dropped_too_large_c2e`.
    pub fn add_dropped_c2e(&self, n: u64) {
        self.datagrams_dropped_too_large_c2e
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Adds `n` to `datagrams_dropped_too_large_e2c`.
    pub fn add_dropped_e2c(&self, n: u64) {
        self.datagrams_dropped_too_large_e2c
            .fetch_add(n, Ordering::Relaxed);
    }

    /// Returns the current snapshot of all counters. Useful for tests
    /// and for the eventual `/metrics` endpoint. Reads use
    /// [`Ordering::Relaxed`]; cross-counter consistency is best-effort
    /// (no transactional view).
    #[must_use]
    pub fn snapshot(&self) -> RelayMetricsSnapshot {
        RelayMetricsSnapshot {
            sessions_dispatched: self.sessions_dispatched.load(Ordering::Relaxed),
            sessions_rejected_malformed: self.sessions_rejected_malformed.load(Ordering::Relaxed),
            sessions_rejected_unknown_exit: self
                .sessions_rejected_unknown_exit
                .load(Ordering::Relaxed),
            exit_pool_hits: self.exit_pool_hits.load(Ordering::Relaxed),
            exit_pool_misses: self.exit_pool_misses.load(Ordering::Relaxed),
            datagrams_client_to_exit: self.datagrams_client_to_exit.load(Ordering::Relaxed),
            datagrams_exit_to_client: self.datagrams_exit_to_client.load(Ordering::Relaxed),
            datagrams_dropped_too_large_c2e: self
                .datagrams_dropped_too_large_c2e
                .load(Ordering::Relaxed),
            datagrams_dropped_too_large_e2c: self
                .datagrams_dropped_too_large_e2c
                .load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time view of [`RelayMetrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayMetricsSnapshot {
    /// See [`RelayMetrics::sessions_dispatched`].
    pub sessions_dispatched: u64,
    /// See [`RelayMetrics::sessions_rejected_malformed`].
    pub sessions_rejected_malformed: u64,
    /// See [`RelayMetrics::sessions_rejected_unknown_exit`].
    pub sessions_rejected_unknown_exit: u64,
    /// See [`RelayMetrics::exit_pool_hits`].
    pub exit_pool_hits: u64,
    /// See [`RelayMetrics::exit_pool_misses`].
    pub exit_pool_misses: u64,
    /// See [`RelayMetrics::datagrams_client_to_exit`].
    pub datagrams_client_to_exit: u64,
    /// See [`RelayMetrics::datagrams_exit_to_client`].
    pub datagrams_exit_to_client: u64,
    /// See [`RelayMetrics::datagrams_dropped_too_large_c2e`].
    pub datagrams_dropped_too_large_c2e: u64,
    /// See [`RelayMetrics::datagrams_dropped_too_large_e2c`].
    pub datagrams_dropped_too_large_e2c: u64,
}

/// Folds a [`crate::forward::ForwardSummary`] into the metrics block.
/// Convenience helper so call sites do not pull the field names of
/// `ForwardSummary` into their critical path.
pub fn record_forward_summary(metrics: &RelayMetrics, summary: &crate::forward::ForwardSummary) {
    metrics.add_c2e(summary.client_to_exit);
    metrics.add_e2c(summary.exit_to_client);
    metrics.add_dropped_c2e(summary.dropped_client_to_exit_too_large);
    metrics.add_dropped_e2c(summary.dropped_exit_to_client_too_large);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::ForwardSummary;

    #[test]
    fn record_forward_summary_aggregates_each_field_independently() {
        let m = RelayMetrics::new();
        record_forward_summary(
            &m,
            &ForwardSummary {
                client_to_exit: 3,
                exit_to_client: 5,
                dropped_client_to_exit_too_large: 1,
                dropped_exit_to_client_too_large: 2,
            },
        );
        record_forward_summary(
            &m,
            &ForwardSummary {
                client_to_exit: 7,
                exit_to_client: 11,
                dropped_client_to_exit_too_large: 0,
                dropped_exit_to_client_too_large: 4,
            },
        );
        let snap = m.snapshot();
        assert_eq!(snap.datagrams_client_to_exit, 10);
        assert_eq!(snap.datagrams_exit_to_client, 16);
        assert_eq!(snap.datagrams_dropped_too_large_c2e, 1);
        assert_eq!(snap.datagrams_dropped_too_large_e2c, 6);
    }

    #[test]
    fn session_counters_increment_independently() {
        let m = RelayMetrics::new();
        m.inc_sessions_dispatched();
        m.inc_sessions_dispatched();
        m.inc_sessions_rejected_malformed();
        m.inc_sessions_rejected_unknown_exit();
        m.inc_exit_pool_hit();
        m.inc_exit_pool_miss();
        m.inc_exit_pool_miss();
        let snap = m.snapshot();
        assert_eq!(snap.sessions_dispatched, 2);
        assert_eq!(snap.sessions_rejected_malformed, 1);
        assert_eq!(snap.sessions_rejected_unknown_exit, 1);
        assert_eq!(snap.exit_pool_hits, 1);
        assert_eq!(snap.exit_pool_misses, 2);
    }
}
