//! Port-forwarding backend *with no network effect*. Delegates only
//! to the in-RAM [`Allocator`]. Used on macOS dev and in integration
//! tests; in Linux prod the `nftables` backend is wired instead.
//!
//! **Preferred-port policy**: the client's suggested external port is
//! forwarded verbatim to the allocator, which honours it when it is
//! inside the configured range (`49152..=65535`) and currently free,
//! and otherwise falls back to a free port (RFC 6886 §3.3). Honouring
//! the suggestion is what makes a self-hosted service reachable on a
//! stable port; the allocator's range, per-client quota, cooldown and
//! rate limit remain the abuse mitigations (a client can never grab a
//! port held by someone else, nor a privileged/well-known port below
//! 49152).

use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use crate::allocator::Allocator;
use crate::{Allocation, NatPmpError, PortForwardingBackend, Proto};

/// Stub backend: pure RAM, no DNAT or nftables. Thread-safe via
/// `Arc<Allocator>` (the allocator has its own internal `Mutex`).
pub struct StubBackend {
    allocator: Arc<Allocator>,
}

impl StubBackend {
    /// Builds a stub backend with the Warren default allocator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            allocator: Arc::new(Allocator::new()),
        }
    }

    /// Builds a stub from an existing `Allocator` (useful for tests
    /// that need to shrink the config).
    #[must_use]
    pub fn with_allocator(allocator: Arc<Allocator>) -> Self {
        Self { allocator }
    }

    /// Read-only access to the allocator for tests / metrics.
    #[must_use]
    pub fn allocator(&self) -> &Arc<Allocator> {
        &self.allocator
    }
}

impl Default for StubBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PortForwardingBackend for StubBackend {
    fn allocate(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested_external_port: u16,
        lifetime: Duration,
    ) -> impl Future<Output = Result<Allocation, NatPmpError>> + Send {
        let allocator = Arc::clone(&self.allocator);
        let lifetime_secs = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
        async move {
            allocator.allocate(
                client_ip,
                proto,
                internal_port,
                suggested_external_port,
                lifetime_secs,
            )
        }
    }

    fn release(&self, alloc: &Allocation) -> impl Future<Output = Result<(), NatPmpError>> + Send {
        let allocator = Arc::clone(&self.allocator);
        let alloc = alloc.clone();
        async move {
            allocator.release(&alloc);
            Ok(())
        }
    }

    fn release_by_client(
        &self,
        client_ip: Ipv4Addr,
        internal_port: u16,
        proto: Proto,
    ) -> impl Future<Output = bool> + Send {
        let allocator = Arc::clone(&self.allocator);
        async move {
            allocator
                .release_by_client(client_ip, internal_port, proto)
                .is_some()
        }
    }

    fn rate_limit_status(&self, client_ip: Ipv4Addr) -> crate::protocol::RateLimitInfo {
        self.allocator.rate_limit_status(client_ip)
    }

    fn restore(&self, entries: Vec<Allocation>) -> impl Future<Output = Vec<Allocation>> + Send {
        let allocator = Arc::clone(&self.allocator);
        async move { allocator.restore(entries) }
    }
}
