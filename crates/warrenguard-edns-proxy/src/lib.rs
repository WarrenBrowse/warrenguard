//! Warren Encrypted DNS proxy server.
//!
//! This crate implements the *server* side of the Mullvad-derived
//! "Encrypted DNS proxy" censorship-circumvention scheme whose client is
//! the upstream `mullvad-encrypted-dns-proxy` crate (mullvadvpn-app). It is
//! wire-compatible with that unmodified client.
//!
//! How the scheme works:
//! 1. The client resolves a Warren-controlled domain over DoH and gets back
//!    `AAAA` records. Each record is not a routable address but an *encoded*
//!    proxy configuration (IPv4 + port + optional XOR key) - see [`config`].
//! 2. The client opens a TCP connection to the encoded proxy address and
//!    runs its API TLS session through it, XOR-obfuscating the bytes.
//! 3. This server ([`server::ProxyServer`]) strips the XOR layer and
//!    forwards the recovered stream to the Warren API.
//!
//! Operators publish the `AAAA` records using [`config::ProxyConfig::to_ipv6`].

pub mod concurrency;
pub mod config;
pub mod ratelimit;
pub mod server;
pub mod xor;

pub use concurrency::{PerIpConcurrency, PerIpConcurrencyGuard};
pub use config::{DEFAULT_PREFIX, Error, ObfuscationConfig, ProxyConfig};
pub use ratelimit::{IpRateLimiter, PerIpLimit};
pub use server::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CONNECTIONS, DEFAULT_PER_IP_BURST,
    DEFAULT_PER_IP_MAX_CONCURRENT, DEFAULT_PER_IP_PER_SECOND, Metrics, ProxyServer, ServerConfig,
};
pub use xor::{XorKey, XorObfuscator};
