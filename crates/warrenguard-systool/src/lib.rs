//! Where the engine finds the operating-system tools it runs.
//!
//! The engine configures routes, firewalls and DNS by running system tools
//! (`ip`, `nft`, `route`, `networksetup`, `scutil`, `powershell.exe`...), from
//! processes that run as root or as an administrator. A tool started by its bare
//! name is resolved through the `PATH` of that process, which comes from
//! whoever launched it: `sudo` passes the caller's `PATH` through unless the
//! host sets `secure_path` (macOS does not), and a daemon started from a user
//! shell inherits that shell's. A directory the launching account can write,
//! placed ahead of the system ones, then decides what runs with privileges.
//!
//! [`SystemTool`] resolves every tool from fixed system locations instead: the
//! root-owned directories in [`TRUSTED_DIRS`] on Unix, and the directory
//! `GetSystemDirectoryW` reports on Windows. A [`Command`] built here also
//! gets the search paths the tool itself uses from the system rather than from
//! the launcher: [`TRUSTED_PATH`] as its `PATH` on Unix, so a tool that starts
//! another program by name resolves it the same way; on Windows, the system's
//! own `PATH` and PowerShell module path, since Windows PowerShell loads the
//! module behind each firewall or DNS cmdlet from the first `PSModulePath`
//! directory that has one.
//!
//! The workspace `clippy.toml` refuses `Command::new` everywhere else, so a new
//! spawn site cannot bypass this crate by accident.

// `GetSystemDirectoryW` is FFI, admitted on Windows only; every other build of
// this crate is unsafe-free.
#![cfg_attr(windows, allow(unsafe_code))]

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::Command;

/// The directories a Unix tool is resolved from, searched in this order. Each
/// is owned by root on every host the engine supports.
#[cfg(unix)]
pub const TRUSTED_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// [`TRUSTED_DIRS`] as a `PATH` value: the `PATH` every tool started through
/// [`SystemTool::command`] runs with.
#[cfg(unix)]
pub const TRUSTED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// An operating-system tool the engine runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SystemTool {
    /// `sh`, the POSIX shell.
    Sh,
    /// `ip`, Linux iproute2.
    Ip,
    /// `nft`, Linux nftables.
    Nft,
    /// `netstat`.
    Netstat,
    /// `route`, the BSD routing tool.
    Route,
    /// `ifconfig`.
    Ifconfig,
    /// `networksetup`, macOS network services.
    Networksetup,
    /// `scutil`, the macOS dynamic store.
    Scutil,
    /// `dscacheutil`, the macOS directory-service cache.
    Dscacheutil,
    /// `killall`.
    Killall,
    /// `powershell.exe`, Windows PowerShell.
    PowerShell,
}

impl SystemTool {
    /// Every tool this crate knows.
    pub const ALL: [Self; 11] = [
        Self::Sh,
        Self::Ip,
        Self::Nft,
        Self::Netstat,
        Self::Route,
        Self::Ifconfig,
        Self::Networksetup,
        Self::Scutil,
        Self::Dscacheutil,
        Self::Killall,
        Self::PowerShell,
    ];

    /// The tool's file name, which also names it in error messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sh => "sh",
            Self::Ip => "ip",
            Self::Nft => "nft",
            Self::Netstat => "netstat",
            Self::Route => "route",
            Self::Ifconfig => "ifconfig",
            Self::Networksetup => "networksetup",
            Self::Scutil => "scutil",
            Self::Dscacheutil => "dscacheutil",
            Self::Killall => "killall",
            Self::PowerShell => "powershell.exe",
        }
    }

    /// The absolute path of the tool on this host.
    ///
    /// # Errors
    ///
    /// An [`io::ErrorKind::NotFound`] error whose source is [`ToolNotFound`]
    /// when the tool is not where this host keeps it (the tool of another
    /// operating system never is). On Windows, the error `GetSystemDirectoryW`
    /// reports when it fails.
    pub fn path(self) -> io::Result<PathBuf> {
        imp::locate(self)
    }

    /// A [`Command`] that runs this tool from [`Self::path`], with the search
    /// paths described in the crate documentation.
    ///
    /// # Errors
    ///
    /// See [`Self::path`].
    pub fn command(self) -> io::Result<Command> {
        let path = self.path()?;
        #[allow(
            clippy::disallowed_methods,
            reason = "the one place a resolved absolute tool path becomes a Command"
        )]
        let mut command = Command::new(path);
        imp::pin_search_paths(&mut command)?;
        Ok(command)
    }

    /// [`Self::command`] as a `tokio` command, for async call sites.
    ///
    /// # Errors
    ///
    /// See [`Self::path`].
    #[cfg(feature = "tokio")]
    pub fn tokio_command(self) -> io::Result<tokio::process::Command> {
        self.command().map(tokio::process::Command::from)
    }
}

/// The source of the [`io::ErrorKind::NotFound`] error [`SystemTool::path`]
/// returns for a tool this host does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ToolNotFound(pub SystemTool);

impl fmt::Display for ToolNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "system tool `{}` is not installed in a trusted system directory",
            self.0.name()
        )
    }
}

impl std::error::Error for ToolNotFound {}

fn not_found(tool: SystemTool) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, ToolNotFound(tool))
}

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{SystemTool, TRUSTED_DIRS, TRUSTED_PATH, not_found};

    pub(crate) fn pin_search_paths(command: &mut Command) -> io::Result<()> {
        command.env("PATH", TRUSTED_PATH);
        Ok(())
    }

    pub(crate) fn locate(tool: SystemTool) -> io::Result<PathBuf> {
        if tool == SystemTool::PowerShell {
            return Err(not_found(tool));
        }
        TRUSTED_DIRS
            .iter()
            .map(|dir| Path::new(dir).join(tool.name()))
            .find(|path| is_executable_file(path))
            .ok_or_else(|| not_found(tool))
    }

    fn is_executable_file(path: &Path) -> bool {
        std::fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::OsStringExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    use super::{SystemTool, not_found};

    /// The only directory Windows PowerShell may load a module from.
    const POWERSHELL_HOME: &str = r"WindowsPowerShell\v1.0";

    /// Gives the child the system's own `PATH`, `PSModulePath`, `SystemRoot`
    /// and `windir`, all derived from the System32 directory the kernel
    /// reports, so none of them is the launcher's.
    pub(crate) fn pin_search_paths(command: &mut Command) -> io::Result<()> {
        let system = system_directory()?;
        let windows = system
            .parent()
            .map_or_else(|| system.clone(), Path::to_path_buf);
        let powershell_home = system.join(POWERSHELL_HOME);
        let path = std::env::join_paths([&system, &windows, &powershell_home])
            .map_err(io::Error::other)?;
        command
            .env("PATH", path)
            .env("PSModulePath", powershell_home.join("Modules"))
            .env("SystemRoot", &windows)
            .env("windir", &windows);
        Ok(())
    }

    pub(crate) fn locate(tool: SystemTool) -> io::Result<PathBuf> {
        if tool != SystemTool::PowerShell {
            return Err(not_found(tool));
        }
        let path = system_directory()?
            .join(POWERSHELL_HOME)
            .join("powershell.exe");
        if path.is_file() {
            Ok(path)
        } else {
            Err(not_found(tool))
        }
    }

    /// The System32 directory, as the kernel reports it. Never read from the
    /// environment (`SystemRoot`, `windir`): the launcher sets those.
    fn system_directory() -> io::Result<PathBuf> {
        // MAX_PATH fits every real install; a longer one takes one more round.
        let mut buffer = vec![0u16; 260];
        loop {
            let capacity = u32::try_from(buffer.len())
                .map_err(|_| io::Error::other("system directory path too long"))?;
            // SAFETY: `buffer` is a live, writable allocation of `capacity`
            // UTF-16 units, and GetSystemDirectoryW writes at most `capacity`
            // units into it, terminating null included.
            let written = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity) } as usize;
            if written == 0 {
                return Err(io::Error::last_os_error());
            }
            if written < buffer.len() {
                buffer.truncate(written);
                return Ok(PathBuf::from(OsString::from_wide(&buffer)));
            }
            // Too small: `written` is the size needed, terminating null included.
            buffer.resize(written, 0);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;

    use super::{SystemTool, not_found};

    pub(crate) fn pin_search_paths(_command: &mut Command) -> io::Result<()> {
        Ok(())
    }

    pub(crate) fn locate(tool: SystemTool) -> io::Result<PathBuf> {
        Err(not_found(tool))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_shell_resolves_to_an_executable_in_a_trusted_directory() {
        let path = SystemTool::Sh.path().expect("every Unix host has a shell");

        assert!(
            TRUSTED_DIRS
                .iter()
                .any(|dir| path.parent() == Some(std::path::Path::new(dir))),
            "resolved outside the trusted directories: {}",
            path.display()
        );
    }

    #[test]
    fn a_tool_of_another_operating_system_is_not_found() {
        let err = SystemTool::PowerShell
            .path()
            .expect_err("Unix has no powershell.exe");

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let source = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<ToolNotFound>())
            .expect("the error names the missing tool");
        assert_eq!(*source, ToolNotFound(SystemTool::PowerShell));
        assert_eq!(
            err.to_string(),
            "system tool `powershell.exe` is not installed in a trusted system directory"
        );
    }

    #[test]
    fn the_trusted_path_lists_the_trusted_directories() {
        assert_eq!(TRUSTED_PATH, TRUSTED_DIRS.join(":"));
    }

    #[test]
    fn a_started_tool_sees_only_the_trusted_path() {
        let out = SystemTool::Sh
            .command()
            .expect("shell resolves")
            .args(["-c", "printf %s \"$PATH\""])
            .output()
            .expect("shell runs");

        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), TRUSTED_PATH);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn powershell_resolves_under_the_system_directory() {
        let path = SystemTool::PowerShell
            .path()
            .expect("every supported Windows ships Windows PowerShell");

        assert!(path.is_absolute());
        assert!(path.ends_with(r"WindowsPowerShell\v1.0\powershell.exe"));
        // The kernel reports `system32` in whatever case the install uses.
        let system = path.ancestors().nth(3).and_then(std::path::Path::file_name);
        assert!(
            system.is_some_and(|name| name.eq_ignore_ascii_case("system32")),
            "{}",
            path.display()
        );
    }

    #[test]
    fn powershell_loads_modules_from_the_system_directory_first() {
        let out = SystemTool::PowerShell
            .command()
            .expect("powershell resolves")
            .args(["-NoProfile", "-Command", "$env:PSModulePath"])
            .output()
            .expect("powershell runs");

        let module_path = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        let first = module_path.trim().split(';').next().unwrap_or_default();
        assert!(
            first.ends_with(r"\system32\windowspowershell\v1.0\modules"),
            "{module_path}"
        );
    }

    #[test]
    fn a_unix_tool_is_not_found() {
        let err = SystemTool::Ip.path().expect_err("Windows has no iproute2");

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
