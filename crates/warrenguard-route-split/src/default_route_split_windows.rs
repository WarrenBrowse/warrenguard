//! Windows split-default routing.
//!
//! The implementation moved to the dedicated [`warrenguard_winroute`] crate so the
//! privileged Win32 IP Helper FFI (`CreateIpForwardEntry2` /
//! `DeleteIpForwardEntry2` / `GetIpForwardTable2`) can live behind an isolated,
//! documented `unsafe` boundary: this crate (like the rest of the backend)
//! `forbid`s unsafe. The previous PowerShell `*-NetRoute` port cost ~1.4 s of
//! process cold-start per route op and dominated the Windows connect latency;
//! the native API is sub-millisecond.
//!
//! Re-exported here so a caller's routing facade keeps importing the guards
//! from this module path unchanged.

pub use warrenguard_winroute::*;
