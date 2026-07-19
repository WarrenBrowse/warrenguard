//! WarrenGuard server: the exit-side tunnel primitives built on the shared
//! engine. Holds the per-client downlink dispatcher ([`tun_dispatch`]), the
//! dynamic authorization allowlist, the token-admission and decoy seams, and the
//! read-only exit session handles the multihop exit terminator exposes.

mod allowlist;
mod authorizer;
mod exit;
pub mod tun_dispatch;
mod unauthenticated;

pub use allowlist::{AllowlistHandle, AllowlistSnapshot};
pub use authorizer::{AllowAll, Authorizer, StaticAllowlist};
pub use exit::{
    BoxFuture, ExitPeerSourcesHandle, ExitRevocationHandle, ExitSessionsHandle,
    SessionTokenAdmitter, TOKEN_SERIAL_LEN, TokenAdmission, attach_secret_for_serial,
    session_key_value,
};
pub use unauthenticated::{UnauthenticatedHandler, UnauthenticatedProbe};
