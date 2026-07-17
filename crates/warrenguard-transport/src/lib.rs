//! WarrenGuard client transport: the initiator-side tunnel datapath built on the
//! shared engine primitives. Holds the QUIC client ([`ClientTunnel`] /
//! [`ClientSession`]), the multi-connection bonded session ([`MultiSession`]),
//! and the per-platform TUN device backends (real utun/`/dev/net/tun`, Android
//! `VpnService` fd, iOS `NEPacketTunnelFlow`).

#[cfg(target_os = "android")]
mod android_tun;
pub mod bench;
pub mod bundle;
mod client;
// Reusable in-tunnel egress-liveness probe (the single liveness home): a
// transport-agnostic scheduler plus a TUN-routed datapath probe, so every
// client detects "QUIC alive but exit forwards nothing" with the same debounce
// and escalation semantics instead of reimplementing them.
// Single home of the client drain-reaction anti-stampede policy (ADR 36):
// the advisory type plus the jitter/cooldown/avoid-TTL decisions every client
// tier consumes instead of re-deciding its own constants.
pub mod drain_policy;
pub mod egress_probe;
pub mod ip_assign;
// `ios_tun` is portable (pure tokio + mpsc) so it compiles on every target for
// host-side unit tests; public exposure is gated to iOS below.
mod ios_tun;
pub mod multi_hop_pump;
mod multi_session;
pub mod multihop;
// Single home of the "host moved to another network" detection (route/source
// change watcher); consumers react through their own redial machinery.
pub mod network_monitor;
pub mod redial_policy;
#[cfg(target_os = "android")]
pub mod socket_protect;
// `real_tun` drives `tun-rs::AsyncDevice`, which has no Android nor iOS backend.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod real_tun;
// The system-VPN pump driver installs OS routes (via `warrenguard-route-split`),
// so it is gated behind `system-vpn` to keep the userland SDK closure free of the
// privileged killswitch-os/pfctl deps (SDK purity invariant).
#[cfg(feature = "system-vpn")]
pub mod supervised_pump;
pub mod supervisor;
// Client-side TLS-over-TCP fallback orchestration (anti-censorship datapath):
// decides when a UDP-blocked dial is retried over the carrier. The heavy dial
// logic lives on `ClientTunnel` (needs its private config seam); this module is
// the pure policy + cover-config helpers.
mod tcp_fallback;
#[cfg(test)]
mod test_support;

#[cfg(target_os = "android")]
pub use android_tun::AndroidTun;
pub use client::{ClientSession, ClientTunnel};
#[cfg(target_os = "ios")]
pub use ios_tun::IosTun;
pub use ip_assign::{IpAssignChannel, IpAssignSpec};
pub use multi_session::MultiSession;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use real_tun::RealTun;
// The engine's supervisor-facing reconnect verdict, re-exported so a consumer
// naming it through the transport crate does not reach into `warrenguard-wire`.
pub use warrenguard_wire::{FatalCause, Retryability};
