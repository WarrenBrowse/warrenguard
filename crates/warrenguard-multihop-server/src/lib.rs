//! WarrenGuard multi-hop exit termination datapath.
//!
//! Holds the multihop HPKE termination loop and the IPv4/IPv6 pool
//! allocator, kept as a standalone library so the termination logic is
//! consumable outside a binary and testable in isolation. This crate is
//! intentionally control-plane free: a deployer's binary keeps the config
//! parsing, allowlist refresh, and CRL refresh wiring. The data-plane stays
//! hermetic to the control-plane.

#![forbid(unsafe_code)]

/// Multihop termination: HPKE-aware Quinn datagram loop wired against
/// the [`warrenguard_multihop`] `/v1` wire format, consumed end-to-end
/// behind a `warrenguard-relay`.
pub mod multihop;

/// IPv4 pool allocator for multi-hop client IP negotiation.
/// Each accepted multi-hop connection draws one
/// host address from a configurable subnet; the pump returns it
/// on connection close so the pool survives sustained churn.
pub mod ip_pool;
