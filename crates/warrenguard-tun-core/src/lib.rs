//! Safe, always-on TUN seam for the Warren datapath.
//!
//! This crate is the userland-safe half of the TUN backend: it compiles on every
//! target with zero `unsafe` and zero third-party dependencies, so a no-root
//! (proxy) build can depend on it without ever pulling privileged code.
//!
//! - [`frame`]: OS-agnostic TUN packet framing (macOS utun's 4-byte address
//!   family prefix vs the bare-IP framing on Linux/Windows) and IP-version
//!   detection. Pure, fully unit-tested.
//! - [`plan`]: routing and killswitch PLAN computation (which routes and firewall
//!   rules a backend would install). Pure, fully unit-tested. Computing the plan
//!   is separated from applying it so the policy is testable without privilege.
//!   **Status**: `KillswitchPlan`/`RoutingPlan` here are the ORIGINAL design
//!   (nft table `warren_killswitch`, `ip rule` table 100), consumed only by
//!   `warrenguard-tun-device`'s `apply` module - itself gated behind the
//!   `experimental-tun` feature and explicitly documented as NOT YET
//!   REAL-EXIT VALIDATED. The PRODUCTION, real-exit-validated killswitch and
//!   routing stack is `warrenguard-killswitch-os` (nft table
//!   `warrenguard_killswitch_os`) + `warrenguard-route-split` (the `ip
//!   rule`/table 100 split-default with the socket-mark Port Fail /
//!   TunnelCrack ServerIP fix), used unconditionally by the deployed
//!   system-VPN datapath (no experimental gate). New routing/killswitch
//!   policy work belongs in those two crates, not here. This module is kept
//!   (not removed) only because `warrenguard-tun-device` re-exports it
//!   unconditionally (`pub use warrenguard_tun_core::{.. plan}`, not itself
//!   feature-gated), so deleting it would break that crate's default build;
//!   per the workspace CORE-FIRST rule the validated stack wins for new
//!   work, this one is frozen.
//! - [`gateway`]: default-gateway parsing from the host routing table.
//! - [`device`]: the device seam ([`device::RawTunDevice`] / [`device::TunIo`])
//!   and a framing adapter over any byte stream ([`device::FramedTun`]),
//!   unit-tested over an in-memory mock.
//!
//! The actual per-OS device open (`open_tun`) and the routing/killswitch applier
//! are the privileged half and live in the `warrenguard-tun-device` crate behind
//! its `experimental-tun` feature.

pub mod device;
pub mod frame;
pub mod gateway;
pub mod plan;

pub use device::{FramedTun, RawTunDevice, TunIo};
pub use frame::{Framing, PacketFamily};
pub use gateway::parse_default_gateway;
pub use plan::{
    KillswitchPlan, RouteOp, RoutingPlan, SocketBypass, TunConfig, WARREN_TUNNEL_FWMARK,
};
