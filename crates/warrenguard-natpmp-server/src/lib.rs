//! NAT-PMP server on the Warren exit side (RFC 6886).
//!
//! ## Modules
//!
//! - [`protocol`] - RFC 6886 wire format (parse/serialize, pure, no
//!   I/O).
//! - [`allocator`] - in-RAM port pool with abuse mitigations: 5 min
//!   cooldown, per-port-per-user anti-rotation, 5/min rate-limit,
//!   lifetime clamp `[60..3600]`.
//! - [`server`] - tokio UDP loop on port 5351, dispatching the
//!   protocol.
//! - [`stub_backend`] - pure RAM `PortForwardingBackend` (dev on
//!   macOS / tests).
//! - [`nftables`] - Linux `PortForwardingBackend` that injects DNAT
//!   rules via `nft -f -` (atomic nftables maps). `ShellNftExecutor`
//!   is `cfg(target_os = "linux")`; script rendering stays
//!   cross-platform.

pub mod allocator;
pub mod nftables;
pub mod protocol;
pub mod server;
pub mod stub_backend;

use std::future::Future;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Transport protocol requested by a NAT-PMP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// TCP (RFC 6886 opcode 2).
    Tcp,
    /// UDP (RFC 6886 opcode 1).
    Udp,
}

/// Active NAT-PMP allocation. Stored *only* in RAM on the exit
/// (no-log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    /// Allocated external port (49152-65535).
    pub external_port: u16,
    /// Internal IP of the tunnel client (10.66.x.y).
    pub internal_ip: Ipv4Addr,
    /// Internal client port (ideally equal to `external_port`).
    pub internal_port: u16,
    /// TCP or UDP protocol.
    pub proto: Proto,
    /// Expiration instant; past it, the nftables rule is removed.
    pub expires_at: Instant,
}

/// Server-side NAT-PMP errors.
///
/// This is a **public** error type: unlike the server's own logging
/// (which deliberately never emits the client's tunnel-inner address,
/// see `server.rs`), a deployer embedding this crate may reasonably log
/// or display a `NatPmpError` it receives back. So `Display` never
/// renders a client address in clear, even though some variants carry
/// one as a field for programmatic use (allocator bookkeeping, wire-response
/// scoping, tests): rendering it here would make every such log line a
/// correlation handle across NAT-PMP sessions, breaking the no-log
/// discipline by proxy. Callers that need the address must read the
/// field directly, never `Display`/`to_string()`.
// `Clone` so it can travel inside `AllocateOutcome.result`
// (`Result<Allocation, NatPmpError>`), which the allocator returns by
// value on every path. All variants hold only `Copy`/`Clone` payloads.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum NatPmpError {
    /// The client has a source IP outside the tunnel pool CIDR.
    #[error("client address outside tunnel CIDR")]
    NotAuthorized(Ipv4Addr),
    /// Application rate limit exceeded for this client. Carries the
    /// offending client IP (not rendered by `Display`, see the enum
    /// doc) and the retry-after delay (seconds until the oldest
    /// in-window allocation expires and a slot frees), so the wire
    /// response can hand the UI an actionable countdown instead of
    /// a bare "out of resources".
    #[error("rate limit exceeded (retry after {retry_after_secs}s)")]
    RateLimited {
        /// Offending source IP (tunnel inner address). Not rendered by
        /// `Display`; see the enum doc.
        client: Ipv4Addr,
        /// Seconds until a rate-limit slot frees for this client.
        retry_after_secs: u16,
    },
    /// No free port in the configured range.
    #[error("no available external port")]
    Exhausted,
    /// Per-client allocation quota reached. Carries the offending
    /// client IP (not rendered by `Display`, see the enum doc) so the
    /// wire-side error response can be scoped without leaking the
    /// quota value to other tenants.
    #[error("per-client quota exceeded")]
    QuotaExceeded(Ipv4Addr),
    /// The client requested a specific external port (`suggested != 0`)
    /// that is not available to it - held or in post-release cooldown
    /// for a *different* client, or outside the allocator range. Under
    /// Warren's strict honour-or-error policy the request is rejected
    /// with this error instead of silently substituting another port,
    /// so the UI can tell the user the exact port is taken. Carries the
    /// offending external port for the wire response / UI message.
    #[error("suggested external port {0} unavailable")]
    SuggestedPortInUse(u16),
    /// Backend rule injection / removal error (nftables stub).
    #[error("backend error: {0}")]
    Backend(String),
}

/// Backend injecting port-forwarding (DNAT) rules. Platform-specific.
///
/// Desugars `fn -> impl Future + Send` rather than using `async fn` to
/// guarantee the futures are `Send` (required by tokio multi-thread).
pub trait PortForwardingBackend: Send + Sync {
    /// Reserves an external port for `client_ip` and injects a DNAT
    /// rule pointing at `client_ip:internal_port`. `internal_port` is
    /// the client-side port (the one bound on the client's socket),
    /// distinct from the external port the allocator picks. The DNAT
    /// redirects `<exit_pub>:external → client_ip:internal_port`.
    ///
    /// `suggested_external_port` is the port the client asked for
    /// (RFC 6886 §3.3). `0` means "no preference, server picks". A
    /// non-zero suggestion is honoured when it is inside the
    /// allocator's range and currently free; otherwise the allocator
    /// falls back to a free port (the granted port is echoed back to
    /// the client). The backend forwards this verbatim to the
    /// allocator - it must not override it.
    ///
    /// # Errors
    ///
    /// See [`NatPmpError`].
    fn allocate(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested_external_port: u16,
        lifetime: Duration,
    ) -> impl Future<Output = Result<Allocation, NatPmpError>> + Send;

    /// Releases an allocation, removing the corresponding DNAT rule.
    ///
    /// # Errors
    ///
    /// See [`NatPmpError`].
    fn release(&self, alloc: &Allocation) -> impl Future<Output = Result<(), NatPmpError>> + Send;

    /// Releases a mapping identified by `(client_ip, internal_port,
    /// proto)`. Conforms to RFC 6886 §3.3.2 (Map request with
    /// `lifetime=0` = delete). The client sends its `internal_port`
    /// (the local port it bound); the backend finds the associated
    /// external_port internally.
    ///
    /// Returns `true` iff a matching mapping was found AND belonged
    /// to the requesting client (anti-DoS: Bob cannot delete Alice's
    /// mapping).
    fn release_by_client(
        &self,
        client_ip: Ipv4Addr,
        internal_port: u16,
        proto: Proto,
    ) -> impl Future<Output = bool> + Send;

    /// Reads the current per-source rate-limit budget for `client_ip`
    /// without consuming a slot. The server attaches this to every Map
    /// response (in the optional [`protocol::RateLimitInfo`] trailer) so
    /// the client/UI can warn before a ban and show a retry countdown
    /// after one. Pure read - never mutates the allocation table.
    fn rate_limit_status(&self, client_ip: Ipv4Addr) -> crate::protocol::RateLimitInfo;

    /// Reinstates mappings saved before a process restart (hot-swap
    /// persistence): re-seeds the allocator AND re-installs the
    /// matching forwarding rules. Expired entries, ports already held,
    /// and entries whose rule injection fails are skipped. Returns the
    /// entries actually live again (allocator + rule both in place) so
    /// the caller can log or re-persist exactly that set. Never
    /// charges quota or rate limits.
    fn restore(&self, entries: Vec<Allocation>) -> impl Future<Output = Vec<Allocation>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natpmp_error_not_authorized_display_never_leaks_the_ip() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let err = NatPmpError::NotAuthorized(ip);
        let s = err.to_string();
        // Public error type: Display must never render the client
        // address (no-log discipline by correlation, see the enum doc).
        assert!(!s.contains("192.168.1.1"), "IP leaked into Display: {s}");
        assert!(s.contains("outside tunnel CIDR"), "missing reason in: {s}");
    }

    #[test]
    fn natpmp_error_rate_limited_display_never_leaks_the_ip() {
        let ip = Ipv4Addr::new(10, 66, 0, 99);
        let err = NatPmpError::RateLimited {
            client: ip,
            retry_after_secs: 42,
        };
        let s = err.to_string();
        assert!(!s.contains("10.66.0.99"), "IP leaked into Display: {s}");
        assert!(s.contains("42"), "retry-after must surface in Display: {s}");
    }

    #[test]
    fn natpmp_error_quota_exceeded_display_never_leaks_the_ip() {
        let ip = Ipv4Addr::new(10, 66, 1, 7);
        let err = NatPmpError::QuotaExceeded(ip);
        let s = err.to_string();
        assert!(!s.contains("10.66.1.7"), "IP leaked into Display: {s}");
        assert!(s.contains("quota"), "missing reason in: {s}");
    }

    #[test]
    fn natpmp_error_backend_propagates_inner_message() {
        // When the nftables backend fails, the underlying cause must
        // be traceable through Display.
        let inner = "nft: Operation not permitted".to_string();
        let err = NatPmpError::Backend(inner.clone());
        assert!(err.to_string().contains(&inner));
    }
}
