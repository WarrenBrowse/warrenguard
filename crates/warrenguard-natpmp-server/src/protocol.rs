//! NAT-PMP wire format (RFC 6886). Pure parse/serialize, shared with
//! the client through [`warrenguard_natpmp_protocol`]. This module re-exports
//! the contents for backwards-compatible callers that still write
//! `warrenguard_natpmp_server::protocol::*`.

pub use warrenguard_natpmp_protocol::*;
