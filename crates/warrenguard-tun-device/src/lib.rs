//! Warren privileged TUN backend. EXPERIMENTAL, NOT YET REAL-EXIT VALIDATED.
//!
//! The non-root proxy datapath (SOCKS5/HTTP over the netstack) is the supported,
//! validated path. This crate is the foundation for the optional privileged
//! backend: a real kernel TUN device that captures all OS traffic transparently,
//! with split-default routing, DNS push and a killswitch.
//!
//! # Status
//!
//! Per the project rule that tunnel features are validated against a real exit
//! with privilege before being claimed done (and that cannot happen from the dev
//! sandbox), this crate ships ONLY the parts that are reviewable and testable
//! without a device or root:
//!
//! - [`frame`]: the OS-agnostic TUN packet framing (macOS utun's 4-byte address
//!   family prefix vs the bare-IP framing on Linux/Windows) and IP-version
//!   detection. Pure, fully unit-tested.
//! - [`plan`]: the routing and killswitch PLAN computation (which routes and
//!   firewall rules a backend would install). Pure, fully unit-tested. Computing
//!   the plan is separated from applying it precisely so the policy is testable
//!   without privilege.
//! - [`device`]: the device seam ([`device::TunIo`]) and a framing adapter over
//!   any byte stream ([`device::FramedTun`]), unit-tested over an in-memory mock.
//!   The actual per-OS device open (`device::open_tun`) is compiled ONLY under
//!   the `experimental-tun` feature and is NOT exercised by any test (it needs
//!   root and a real kernel device).
//!
//! Nothing here may be claimed to work end to end until it is validated against a
//! real Warren exit with privilege. Applying a routing/killswitch plan or opening
//! a device is gated behind `experimental-tun` so it cannot be reached by accident.
//!
//! # Unsafe exception
//!
//! Opening the kernel TUN device is unavoidably `unsafe` (the `TUNSETIFF` ioctl on
//! Linux, the `utun` control socket on macOS). The workspace forbids unsafe; this
//! crate downgrades the lint to `deny` in its manifest and admits unsafe ONLY when
//! the `experimental-tun` feature is on, via the single documented allow below.
//! The default (feature-off) build contains zero unsafe, following the
//! same documented boundary-exception pattern as other privileged FFI crates.
#![cfg_attr(feature = "experimental-tun", allow(unsafe_code))]

// Unix-only: the applier shells out to `ip`/`route`/`pfctl`/`nft`, which have no
// Windows equivalent. Gating it here keeps the Linux/macOS codepath from
// compiling on a Windows build with the feature.
#[cfg(all(unix, feature = "experimental-tun"))]
pub mod apply;
pub mod device;

// The safe seam (framing, plan, gateway, the device traits and the framing
// adapter) lives in `warrenguard-tun-core` and is re-exported here for
// convenience. Keeping the privileged device open in this separately-named
// crate is what lets a userland build depend only on `warrenguard-tun-core`
// and keep this crate out of its dependency closure.
pub use warrenguard_tun_core::{
    FramedTun, Framing, KillswitchPlan, PacketFamily, RawTunDevice, RouteOp, RoutingPlan,
    TunConfig, TunIo, frame, gateway, parse_default_gateway, plan,
};
