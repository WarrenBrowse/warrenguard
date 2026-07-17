//! Warren privileged TUN backend: the single engine home for the raw kernel
//! device open (the injectable async `PacketDevice` wrappers live in
//! `warrenguard-transport`).
//!
//! The non-root proxy datapath (SOCKS5/HTTP over the netstack) is the default
//! path. This crate is the optional privileged backend's device layer: a real
//! kernel TUN device that captures all OS traffic transparently, composed
//! downstream with split-default routing, DNS push and a killswitch.
//!
//! # Status
//!
//! - [`frame`]: the OS-agnostic TUN packet framing (macOS utun's 4-byte address
//!   family prefix vs the bare-IP framing on Linux/Windows) and IP-version
//!   detection. Pure, fully unit-tested.
//! - [`device`]: the device seam ([`device::TunIo`]) and a framing adapter over
//!   any byte stream ([`device::FramedTun`]), unit-tested over an in-memory mock.
//!   The per-OS device open (`device::open_tun`) is compiled ONLY under the
//!   `experimental-tun` feature (it needs root and a real kernel device).
//!   The macOS utun open is REAL-EXIT VALIDATED end to end (privileged
//!   system-VPN datapath: egress via the exit, DNS through the tunnel, clean
//!   restore). The Linux and Windows opens compile and are review-covered but
//!   are NOT yet real-exit validated; do not claim them working end to end.
//!
//! Opening a device is gated behind `experimental-tun` so it cannot be reached
//! by accident. The routing, killswitch and DNS glue is NOT here: the
//! production, real-exit-validated stack lives in `warrenguard-route-split` +
//! `warrenguard-killswitch-os`, the single home.
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

pub mod device;

// The safe seam (framing, gateway, the SocketBypass primitive, the device traits
// and the framing adapter) lives in `warrenguard-tun-core` and is re-exported
// here for convenience. Keeping the privileged device open in this
// separately-named crate is what lets a userland build depend only on
// `warrenguard-tun-core` and keep this crate out of its dependency closure.
pub use warrenguard_tun_core::{
    FramedTun, Framing, PacketFamily, RawTunDevice, SocketBypass, TunIo, WARREN_TUNNEL_FWMARK,
    bypass, frame, gateway, parse_default_gateway,
};
