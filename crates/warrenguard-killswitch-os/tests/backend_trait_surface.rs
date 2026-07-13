//! Source-level regression that pins the [`KillswitchBackend`] trait
//! surface. A future refactor that drops
//! the trait, renames its methods, or removes an impl breaks this
//! test before users notice the regression.
//!
//! The trait is the seam for swapping the Windows PowerShell backend
//! to a native WFP-API binding later.

#[cfg(target_os = "linux")]
#[test]
fn linux_killswitch_impls_trait() {
    fn assert_backend<T: warrenguard_killswitch_os::KillswitchBackend>() {}
    assert_backend::<warrenguard_killswitch_os::LinuxKillswitch>();
}

#[cfg(target_os = "macos")]
#[test]
fn macos_killswitch_impls_trait() {
    fn assert_backend<T: warrenguard_killswitch_os::KillswitchBackend>() {}
    assert_backend::<warrenguard_killswitch_os::MacosKillswitch>();
}

#[cfg(target_os = "windows")]
#[test]
fn windows_killswitch_impls_trait() {
    fn assert_backend<T: warrenguard_killswitch_os::KillswitchBackend>() {}
    assert_backend::<warrenguard_killswitch_os::WindowsKillswitch>();
}
