//! Exit-side tunnel primitives: the token-admission seam and the read-only
//! session handles the exit terminator exposes.

use std::future::Future;
use std::pin::Pin;

mod session;
mod session_token;

/// A `Send` future returning `T`, boxed so a trait using it stays
/// `dyn`-compatible. The engine carries no `async-trait` dependency, and a
/// native `async fn` in a trait is not yet `dyn`-compatible, so the admission
/// seams expose their async method as a method returning this boxed future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// Re-export public types so external consumers keep the same path.
pub use session::{ExitRevocationHandle, ExitSessionsHandle};
pub use session_token::{
    SessionTokenAdmitter, TOKEN_SERIAL_LEN, TokenAdmission, attach_secret_for_serial,
    session_key_value,
};
