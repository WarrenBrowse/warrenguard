//! WarrenGuard server: the exit-side tunnel datapath built on the shared engine
//! primitives. Holds the QUIC server / handshake ([`ExitListener`]), the
//! per-client downlink dispatcher ([`tun_dispatch`]), the dynamic authorization
//! allowlist and the exit-side session state.

mod allowlist;
mod authorizer;
mod exit;
mod exit_state;
pub mod tun_dispatch;
mod unauthenticated;

pub use allowlist::{AllowlistHandle, AllowlistSnapshot};
pub use authorizer::{AllowAll, Authorizer, StaticAllowlist};
pub use exit::{
    AdmitResult, BoxFuture, DeviceCapEnforcer, DeviceCapError, ExitBindOpts, ExitDrainSignal,
    ExitListener, ExitPeerSourcesHandle, ExitRevocationHandle, ExitSessionsHandle,
    HandshakeRateLimit, SessionTokenAdmitter, TOKEN_SERIAL_LEN, TokenAdmission,
    attach_secret_for_serial, session_key_value,
};
pub use unauthenticated::{UnauthenticatedHandler, UnauthenticatedProbe};
