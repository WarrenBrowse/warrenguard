//! Global per-account device-cap enforcement hook for the exit.
//!
//! The exit does not depend on any control-plane client; instead it accepts
//! an injected [`DeviceCapEnforcer`] trait object. The concrete production
//! implementation lives in the deployer's exit binary and calls its
//! control-plane API's open/close session endpoints against the global
//! device-session ledger (v2 cross-exit device cap). Tests stub the trait
//! with a local fake.
//!
//! ## Why a boxed future instead of `#[async_trait]`
//!
//! The engine deliberately carries no `async-trait` dependency
//! (avoided whenever a native form works). Native
//! `async fn` in a trait is not yet `dyn`-compatible, so the
//! enforcement points need a `dyn DeviceCapEnforcer`. We therefore
//! expose the async method as a method returning a boxed,
//! `Send`-bounded future (`BoxFuture`), which keeps the trait object
//! usable behind `Arc<dyn ...>` while staying `async`-friendly for the
//! caller.

use std::future::Future;
use std::pin::Pin;

use warrenguard_wire::{DEVICE_ID_LEN, WarrenPubkey};

/// A `Send` future returning `T`, boxed so the trait stays
/// `dyn`-compatible.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Outcome of a device-cap admission check for a PRIMARY connection.
///
/// `Err` is reserved for *transport* failures (the ledger could not be
/// reached / replied with an unexpected error). The accept path treats
/// `Err` as **fail-open** (admit + warn) so a control-plane outage never
/// blacks out the tunnel - availability is preferred over strict cap
/// enforcement.
pub type AdmitResult = Result<bool, DeviceCapError>;

/// Transport-level failure of a device-cap check. Carries a short,
/// no-PII context string for logging.
#[derive(Debug, Clone)]
pub struct DeviceCapError(pub String);

impl std::fmt::Display for DeviceCapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "device-cap check failed: {}", self.0)
    }
}

impl std::error::Error for DeviceCapError {}

/// Injected hook the exit calls to enforce the global per-account device
/// cap. Implemented in the deployer's exit binary against its control-plane
/// device-session ledger; stubbed in tests.
///
/// Contract:
/// - [`Self::open_or_renew`] is called only for a PRIMARY connection
///   (`connection_index == 0`) of a `(pubkey, device_id)`. Returns
///   `Ok(true)` when admitted (fresh lease or renewal), `Ok(false)`
///   when denied (cap reached), `Err` on transport failure (the caller
///   fails open).
/// - [`Self::close`] is called when a device's last connection closes
///   (graceful teardown / revocation). Best-effort, fire-and-forget; it
///   returns nothing and must not block the teardown path.
pub trait DeviceCapEnforcer: Send + Sync {
    /// Open or renew the lease for `(pubkey, device_id)`. See the trait
    /// docs for the admission semantics.
    fn open_or_renew<'a>(
        &'a self,
        pubkey: &'a WarrenPubkey,
        device_id: &'a [u8; DEVICE_ID_LEN],
    ) -> BoxFuture<'a, AdmitResult>;

    /// Release the lease for `(pubkey, device_id)`. Best-effort; the
    /// implementation typically spawns the network call so teardown is
    /// not blocked.
    fn close(&self, pubkey: &WarrenPubkey, device_id: &[u8; DEVICE_ID_LEN]);
}
