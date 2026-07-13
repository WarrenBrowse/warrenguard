//! Cross-OS seam for a client's default-route split and DNS-push wiring.
//!
//! Without this seam, a caller's connect/disconnect path would carry three
//! `#[cfg]` copies of `install_default_route_split_if_requested` /
//! `install_dns_push_if_requested` plus three `#[cfg]` copies of the
//! matching uninstall blocks. The per-OS *logic* (the `build_*_commands`
//! planners in [`crate::default_route_split`],
//! [`crate::default_route_split_macos`],
//! [`crate::default_route_split_windows`], and the DNS-push modules) is well
//! unit-tested and stays exactly where it lives. Only the *contract* shared
//! by the three OSes is factored here:
//!
//! - "install the route split iff an exit IP was requested",
//! - "install the DNS push iff a server list was requested",
//! - "tear the guard down asynchronously, best-effort".
//!
//! [`current_platform`] returns the `cfg`-selected [`PlatformNet`] so the
//! binary has a single generic call site per concern. The returned guards
//! are uniform [`RouteSplitGuard`] / [`DnsPushGuard`] wrappers around the
//! per-OS concrete guard, so the caller no longer needs a `#[cfg]` ladder to
//! uninstall either.
//!
//! Guard-drop semantics are preserved exactly: each wrapper merely *owns* the
//! per-OS concrete guard. If a wrapper is dropped without `uninstall`, the
//! inner guard's own synchronous fail-safe `Drop` fires unchanged (bounded
//! teardown, ownership-scoped `force_cleanup`). The wrapper adds no `Drop` of
//! its own.

use std::net::Ipv4Addr;

use anyhow::Result;

/// Uniform RAII guard for an installed default-route split, regardless of OS.
///
/// Wraps the `cfg`-selected concrete guard. Calling [`Self::uninstall`]
/// performs the OS-specific async teardown; dropping it without calling
/// `uninstall` falls through to the inner guard's synchronous fail-safe
/// `Drop` (unchanged from the per-OS modules).
#[must_use = "dropping the guard without `uninstall` falls back to the inner \
              guard's synchronous fail-safe Drop; hold it for the tunnel's life"]
pub struct RouteSplitGuard {
    #[cfg(target_os = "linux")]
    inner: crate::default_route_split::DefaultRouteSplitGuard,
    #[cfg(target_os = "macos")]
    inner: crate::default_route_split_macos::DefaultRouteSplitGuard,
    #[cfg(target_os = "windows")]
    inner: crate::default_route_split_windows::DefaultRouteSplitGuard,
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    inner: (),
}

impl RouteSplitGuard {
    /// Tear down the route split, best-effort. Delegates to the OS guard's
    /// async `uninstall`.
    ///
    /// # Errors
    ///
    /// Propagates the OS guard's teardown error (already best-effort and
    /// logged on the per-OS path; the binary treats it as non-fatal).
    pub async fn uninstall(self) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            self.inner.uninstall().await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let () = self.inner;
            Ok(())
        }
    }
}

/// Uniform RAII guard for an installed DNS push, regardless of OS.
///
/// Wraps the `cfg`-selected concrete guard. The Linux concrete guard's
/// teardown is synchronous; the wrapper exposes a single async `uninstall`
/// so the caller is `#[cfg]`-free. Dropping without `uninstall` falls through
/// to the inner guard's `Drop`.
#[must_use = "dropping the guard without `uninstall` falls back to the inner \
              guard's Drop; hold it for the tunnel's life"]
pub struct DnsPushGuard {
    #[cfg(target_os = "linux")]
    inner: crate::dns_push::DnsPushGuard,
    #[cfg(target_os = "macos")]
    inner: crate::dns_push_macos::DnsPushGuard,
    #[cfg(target_os = "windows")]
    inner: crate::dns_push_windows::DnsPushGuard,
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    inner: (),
}

impl DnsPushGuard {
    /// Restore the original DNS configuration, best-effort.
    ///
    /// # Errors
    ///
    /// Propagates the OS guard's restore error (non-fatal at the call site).
    pub async fn uninstall(self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // The Linux resolv.conf restore is synchronous; the wrapper keeps
            // a uniform async signature so the call site needs no `#[cfg]`.
            self.inner.uninstall()
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.inner.uninstall().await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let () = self.inner;
            Ok(())
        }
    }
}

/// The shared contract the three first-class OSes (and the unsupported
/// fallback) implement. The binary holds the `cfg`-selected impl from
/// [`current_platform`] and dispatches through it once per concern, instead
/// of carrying three `#[cfg]` copies of each install/uninstall block.
pub trait PlatformNet {
    /// Short OS tag, for logs and tests (`"linux"`, `"macos"`, `"windows"`,
    /// or `"unsupported"`).
    fn name(&self) -> &'static str;

    /// Install the split-default policy routing iff `exit_ip_v4` is `Some`.
    /// Returns `Ok(None)` when no split was requested (infallible no-op).
    ///
    /// # Errors
    ///
    /// On the three first-class OSes: missing privileges or the OS routing
    /// tool not in `PATH`. On an unsupported OS: a request (`Some(_)`) fails
    /// loudly rather than silently leaving the user unprotected.
    fn install_default_route_split(
        &self,
        exit_ip_v4: Option<Ipv4Addr>,
        tun_name: &str,
    ) -> impl std::future::Future<Output = Result<Option<RouteSplitGuard>>> + Send;

    /// Push `dns_servers` iff the list is non-empty. Returns `Ok(None)` when
    /// no DNS push was requested (infallible no-op).
    ///
    /// # Errors
    ///
    /// On the three first-class OSes: missing privileges or the OS DNS tool
    /// not available. On an unsupported OS: a non-empty request fails loudly.
    fn install_dns_push(
        &self,
        dns_servers: &[Ipv4Addr],
    ) -> impl std::future::Future<Output = Result<Option<DnsPushGuard>>> + Send;
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{DnsPushGuard, PlatformNet, RouteSplitGuard};
    use anyhow::{Context, Result};
    use std::net::Ipv4Addr;

    /// Linux platform: `ip rule` multi-table split + `/etc/resolv.conf` push.
    pub(super) struct Platform;

    impl PlatformNet for Platform {
        fn name(&self) -> &'static str {
            "linux"
        }

        async fn install_default_route_split(
            &self,
            exit_ip_v4: Option<Ipv4Addr>,
            tun_name: &str,
        ) -> Result<Option<RouteSplitGuard>> {
            let Some(ip) = exit_ip_v4 else {
                return Ok(None);
            };
            // The single-hop client binary does not yet expose
            // --bypass-cidr; pass an empty list and no fwmark. The multihop
            // POC binary is the wired consumer of those optional features.
            let inner = crate::default_route_split::DefaultRouteSplitGuard::install(
                ip,
                tun_name,
                &[],
                None,
            )
            .await
            .context("failed to install default-route split - need root + ip in PATH")?;
            Ok(Some(RouteSplitGuard { inner }))
        }

        async fn install_dns_push(&self, dns_servers: &[Ipv4Addr]) -> Result<Option<DnsPushGuard>> {
            if dns_servers.is_empty() {
                return Ok(None);
            }
            let inner = crate::dns_push::DnsPushGuard::install(dns_servers)
                .context("failed to install DNS push - need root + writable /etc/resolv.conf")?;
            Ok(Some(DnsPushGuard { inner }))
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{DnsPushGuard, PlatformNet, RouteSplitGuard};
    use anyhow::{Context, Result};
    use std::net::Ipv4Addr;

    /// macOS platform: host-route specificity split + `networksetup` DNS push.
    pub(super) struct Platform;

    impl PlatformNet for Platform {
        fn name(&self) -> &'static str {
            "macos"
        }

        async fn install_default_route_split(
            &self,
            exit_ip_v4: Option<Ipv4Addr>,
            tun_name: &str,
        ) -> Result<Option<RouteSplitGuard>> {
            let Some(ip) = exit_ip_v4 else {
                return Ok(None);
            };
            let inner =
                crate::default_route_split_macos::DefaultRouteSplitGuard::install(ip, tun_name)
                    .await
                    .context("failed to install default-route split - need sudo + route in PATH")?;
            Ok(Some(RouteSplitGuard { inner }))
        }

        async fn install_dns_push(&self, dns_servers: &[Ipv4Addr]) -> Result<Option<DnsPushGuard>> {
            if dns_servers.is_empty() {
                return Ok(None);
            }
            let inner = crate::dns_push_macos::DnsPushGuard::install(dns_servers)
                .await
                .context("failed to install DNS push - need sudo + networksetup in PATH")?;
            Ok(Some(DnsPushGuard { inner }))
        }
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use super::{DnsPushGuard, PlatformNet, RouteSplitGuard};
    use anyhow::{Context, Result};
    use std::net::Ipv4Addr;

    /// Windows platform: split-default `/1` routes, no destination-based exit
    /// exception (closed as the Port Fail / TunnelCrack ServerIP leak; the
    /// daemon's own carrier socket instead escapes via a socket-level
    /// `IP_UNICAST_IF` bind, see `warrenguard_winroute::discover_physical_ifindex`).
    pub(super) struct Platform;

    impl PlatformNet for Platform {
        fn name(&self) -> &'static str {
            "windows"
        }

        async fn install_default_route_split(
            &self,
            exit_ip_v4: Option<Ipv4Addr>,
            tun_name: &str,
        ) -> Result<Option<RouteSplitGuard>> {
            if exit_ip_v4.is_none() {
                return Ok(None);
            }
            let inner =
                crate::default_route_split_windows::DefaultRouteSplitGuard::install(tun_name)
                    .await
                    .context(
                        "failed to install default-route split - need Administrator \
                         privileges (routes are installed via the native Win32 IP Helper \
                         API, not powershell.exe)",
                    )?;
            Ok(Some(RouteSplitGuard { inner }))
        }

        async fn install_dns_push(&self, dns_servers: &[Ipv4Addr]) -> Result<Option<DnsPushGuard>> {
            if dns_servers.is_empty() {
                return Ok(None);
            }
            let inner = crate::dns_push_windows::DnsPushGuard::install(dns_servers)
                .await
                .context("failed to install DNS push - need Administrator + powershell.exe")?;
            Ok(Some(DnsPushGuard { inner }))
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod imp {
    use super::{DnsPushGuard, PlatformNet, RouteSplitGuard};
    use anyhow::{Result, bail};
    use std::net::Ipv4Addr;

    /// Fallback for OSes without a route-split / DNS-push backend. Refuses
    /// feature *requests* loudly so the user is never silently unprotected.
    pub(super) struct Platform;

    impl PlatformNet for Platform {
        fn name(&self) -> &'static str {
            "unsupported"
        }

        async fn install_default_route_split(
            &self,
            exit_ip_v4: Option<Ipv4Addr>,
            _tun_name: &str,
        ) -> Result<Option<RouteSplitGuard>> {
            if exit_ip_v4.is_some() {
                bail!(
                    "--default-route-via-tun is currently Linux + macOS + Windows only on this build."
                );
            }
            Ok(None)
        }

        async fn install_dns_push(&self, dns_servers: &[Ipv4Addr]) -> Result<Option<DnsPushGuard>> {
            if !dns_servers.is_empty() {
                bail!("--push-dns is currently Linux + macOS + Windows only on this build.");
            }
            Ok(None)
        }
    }
}

/// Returns the `cfg`-selected [`PlatformNet`] implementation for the host OS.
/// The single point that resolves "which OS backend" so the binary dispatches
/// generically over the trait instead of via three `#[cfg]` copies.
#[must_use]
pub fn current_platform() -> impl PlatformNet {
    imp::Platform
}
