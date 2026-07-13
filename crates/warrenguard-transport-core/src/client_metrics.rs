//! Per-client atomic traffic counters for exit-side observability.
//!
//! Each connected client gets a [`ClientMetrics`] instance shared
//! between the pump tasks and the dispatch table. Counters are
//! `AtomicU64` with `Relaxed` ordering (advisory data, not control).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;
use warrenguard_wire::WarrenPubkey;

/// Per-client traffic counters. Cheap to clone (Arc-backed internally
/// by the registry).
pub struct ClientMetrics {
    pub(crate) bytes_tx: AtomicU64,
    pub(crate) bytes_rx: AtomicU64,
    pub(crate) datagrams_tx: AtomicU64,
    pub(crate) datagrams_rx: AtomicU64,
    pub(crate) connected_at: Instant,
}

impl ClientMetrics {
    /// Creates a zero-initialized metrics instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            datagrams_tx: AtomicU64::new(0),
            datagrams_rx: AtomicU64::new(0),
            connected_at: Instant::now(),
        }
    }

    /// Records a transmitted datagram (exit -> client).
    pub fn record_tx(&self, bytes: u64) {
        self.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
        self.datagrams_tx.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a received datagram (client -> exit).
    pub fn record_rx(&self, bytes: u64) {
        self.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
        self.datagrams_rx.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a point-in-time view of the counters.
    #[must_use]
    pub fn snapshot(&self) -> ClientMetricsSnapshot {
        ClientMetricsSnapshot {
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            datagrams_tx: self.datagrams_tx.load(Ordering::Relaxed),
            datagrams_rx: self.datagrams_rx.load(Ordering::Relaxed),
            connected_secs: self.connected_at.elapsed().as_secs(),
        }
    }
}

impl Default for ClientMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time view of a client's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientMetricsSnapshot {
    /// Total bytes sent to this client (exit -> client).
    pub bytes_tx: u64,
    /// Total bytes received from this client (client -> exit).
    pub bytes_rx: u64,
    /// Total datagrams sent to this client.
    pub datagrams_tx: u64,
    /// Total datagrams received from this client.
    pub datagrams_rx: u64,
    /// Seconds since the client connected.
    pub connected_secs: u64,
}

/// Registry of per-client metrics. Thread-safe via `RwLock`.
///
/// Entries are reference-counted: each accepted connection calls
/// [`Self::register`] and must pair it with one [`Self::unregister`]
/// when its pump ends. The entry is removed only when the last
/// registration drops, so a multi-conn session (or a second device of
/// the same account) never loses its counters mid-flight, and the map
/// cannot grow unboundedly under connection churn (before this,
/// nothing ever unregistered).
pub struct MetricsRegistry {
    clients: RwLock<HashMap<WarrenPubkey, MetricsEntry>>,
}

struct MetricsEntry {
    metrics: std::sync::Arc<ClientMetrics>,
    refs: usize,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a client connection and returns the identity's shared
    /// metrics handle. Increments the registration count; pair each
    /// call with one [`Self::unregister`].
    pub fn register(&self, pubkey: WarrenPubkey) -> std::sync::Arc<ClientMetrics> {
        let mut map = self.clients.write();
        let entry = map.entry(pubkey).or_insert_with(|| MetricsEntry {
            metrics: std::sync::Arc::new(ClientMetrics::new()),
            refs: 0,
        });
        entry.refs += 1;
        entry.metrics.clone()
    }

    /// Drops one registration for this identity. The entry (and the
    /// final snapshot, returned) goes away only when the last
    /// registration is released; earlier calls return `None`.
    pub fn unregister(&self, pubkey: &WarrenPubkey) -> Option<ClientMetricsSnapshot> {
        let mut map = self.clients.write();
        let entry = map.get_mut(pubkey)?;
        entry.refs = entry.refs.saturating_sub(1);
        if entry.refs == 0 {
            map.remove(pubkey).map(|e| e.metrics.snapshot())
        } else {
            None
        }
    }

    /// Number of clients currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.clients.read().len()
    }

    /// True if no clients are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clients.read().is_empty()
    }

    /// Snapshot all clients' metrics.
    #[must_use]
    pub fn snapshot_all(&self) -> Vec<(WarrenPubkey, ClientMetricsSnapshot)> {
        self.clients
            .read()
            .iter()
            .map(|(k, v)| (*k, v.metrics.snapshot()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(seed: u8) -> WarrenPubkey {
        WarrenPubkey::from_bytes([seed; 32])
    }

    #[test]
    fn new_metrics_start_at_zero() {
        let m = ClientMetrics::new();
        let snap = m.snapshot();
        assert_eq!(snap.bytes_tx, 0);
        assert_eq!(snap.bytes_rx, 0);
        assert_eq!(snap.datagrams_tx, 0);
        assert_eq!(snap.datagrams_rx, 0);
    }

    #[test]
    fn record_tx_increments_bytes_and_count() {
        let m = ClientMetrics::new();
        m.record_tx(1500);
        m.record_tx(800);
        let snap = m.snapshot();
        assert_eq!(snap.bytes_tx, 2300, "bytes must accumulate");
        assert_eq!(snap.datagrams_tx, 2, "each record_tx = 1 datagram");
        assert_eq!(snap.bytes_rx, 0, "rx must stay at zero");
        assert_eq!(snap.datagrams_rx, 0);
    }

    #[test]
    fn record_rx_increments_bytes_and_count() {
        let m = ClientMetrics::new();
        m.record_rx(500);
        let snap = m.snapshot();
        assert_eq!(snap.bytes_rx, 500);
        assert_eq!(snap.datagrams_rx, 1);
        assert_eq!(snap.bytes_tx, 0);
    }

    #[test]
    fn connected_secs_advances() {
        let m = ClientMetrics::new();
        let snap = m.snapshot();
        assert!(
            snap.connected_secs <= 1,
            "freshly created metrics should report ~0s connected"
        );
    }

    #[test]
    fn registry_register_and_unregister() {
        let reg = MetricsRegistry::new();
        assert!(reg.is_empty());

        let pk = test_pubkey(1);
        let handle = reg.register(pk);
        assert_eq!(reg.len(), 1);

        handle.record_tx(100);
        let snap = reg.unregister(&pk).expect("must be registered");
        assert_eq!(snap.bytes_tx, 100);
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_register_same_key_returns_same_handle() {
        let reg = MetricsRegistry::new();
        let pk = test_pubkey(2);
        let h1 = reg.register(pk);
        h1.record_tx(50);
        let h2 = reg.register(pk);
        h2.record_tx(50);
        let snap = h1.snapshot();
        assert_eq!(
            snap.bytes_tx, 100,
            "both handles must point to the same underlying counters"
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_snapshot_all() {
        let reg = MetricsRegistry::new();
        let pk1 = test_pubkey(10);
        let pk2 = test_pubkey(20);
        reg.register(pk1).record_tx(111);
        reg.register(pk2).record_rx(222);

        let all = reg.snapshot_all();
        assert_eq!(all.len(), 2);
        let find = |pk: WarrenPubkey| all.iter().find(|(k, _)| *k == pk).map(|(_, v)| *v);
        assert_eq!(find(pk1).unwrap().bytes_tx, 111);
        assert_eq!(find(pk2).unwrap().bytes_rx, 222);
    }

    #[test]
    fn unregister_unknown_returns_none() {
        let reg = MetricsRegistry::new();
        assert!(reg.unregister(&test_pubkey(99)).is_none());
    }

    #[test]
    fn refcounted_entry_survives_until_last_unregister() {
        // Two connections of the same identity (multi-conn session or
        // a second device): the first unregister must NOT evict the
        // shared counters still in use by the other connection.
        let reg = MetricsRegistry::new();
        let pk = test_pubkey(3);
        let h1 = reg.register(pk);
        let _h2 = reg.register(pk);
        h1.record_tx(10);

        assert!(
            reg.unregister(&pk).is_none(),
            "first unregister of two must keep the entry alive"
        );
        assert_eq!(reg.len(), 1, "entry must still be tracked");

        let snap = reg
            .unregister(&pk)
            .expect("last unregister must return the final snapshot");
        assert_eq!(snap.bytes_tx, 10);
        assert!(reg.is_empty(), "entry must be gone after the last release");
    }
}
