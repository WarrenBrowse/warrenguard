//! Safe, always-on TUN seam for the Warren datapath.
//!
//! This crate is the userland-safe half of the TUN backend: it compiles on every
//! target with zero `unsafe` and zero third-party dependencies, so a no-root
//! (proxy) build can depend on it without ever pulling privileged code.
//!
//! - [`frame`]: OS-agnostic TUN packet framing (macOS utun's 4-byte address
//!   family prefix vs the bare-IP framing on Linux/Windows) and IP-version
//!   detection. Pure, fully unit-tested.
//! - [`bypass`]: the [`SocketBypass`] primitive and [`WARREN_TUNNEL_FWMARK`],
//!   the socket-keyed carrier escape shared by the transport, socket-bypass,
//!   route-split and the app. It lives here in the zero-dep seam so every one
//!   of those crates can name the same type without a dependency cycle.
//! - [`gateway`]: default-gateway parsing from the host routing table.
//! - [`device`]: the device seam ([`device::RawTunDevice`] / [`device::TunIo`])
//!   and a framing adapter over any byte stream ([`device::FramedTun`]),
//!   unit-tested over an in-memory mock.
//!
//! The production, real-exit-validated routing/killswitch/DNS stack is
//! `warrenguard-route-split` + `warrenguard-killswitch-os`; new routing or
//! killswitch policy belongs there, not here. The actual per-OS device open
//! (`open_tun`) is the privileged half and lives in the `warrenguard-tun-device`
//! crate behind its `experimental-tun` feature.

pub mod bypass;
pub mod device;
pub mod frame;
pub mod gateway;

pub use bypass::{SocketBypass, WARREN_TUNNEL_FWMARK};
pub use device::{FramedTun, RawTunDevice, TunIo};
pub use frame::{Framing, PacketFamily};
pub use gateway::parse_default_gateway;
