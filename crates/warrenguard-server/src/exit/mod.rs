//! Exit-side tunnel primitives: the token-admission and device-cap seams, and
//! the read-only session handles the exit terminator exposes.

mod device_cap;
mod session;
mod session_token;

// Re-export public types so external consumers keep the same path.
pub use device_cap::{AdmitResult, BoxFuture, DeviceCapEnforcer, DeviceCapError};
pub use session::{ExitPeerSourcesHandle, ExitRevocationHandle, ExitSessionsHandle};
pub use session_token::{
    SessionTokenAdmitter, TOKEN_SERIAL_LEN, TokenAdmission, attach_secret_for_serial,
    session_key_value,
};
