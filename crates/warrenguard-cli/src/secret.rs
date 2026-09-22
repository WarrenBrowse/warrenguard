//! Secret input for the reference CLI.
//!
//! A secret handed to a process in its arguments is readable by every local
//! user through `ps` (and through the container/runtime metadata of most
//! supervisors), so the CLI accepts a protected file instead. This module owns
//! the two properties that make that path worth using: the buffer is zeroized
//! on drop, and the value can never reach a log line or a `Debug` rendering by
//! accident.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Upper bound on a secret file. A path that was meant to be a key file but
/// points at a disk image or `/dev/zero` must fail fast instead of making the
/// process allocate without limit.
pub(crate) const MAX_SECRET_LEN: usize = 64 * 1024;

/// A secret string, zeroized on drop, that renders as `Secret(<redacted>)`.
///
/// Deliberately not `Clone`: a clone is another live copy of the secret that
/// nothing tracks. Call sites that need to share one pass a reference.
pub(crate) struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps an already-owned secret string.
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The secret itself.
    ///
    /// The returned reference must not be logged, formatted into an error, or
    /// stored past the caller's own use: everything outside this module treats
    /// it as a value that may not leave the process.
    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

/// The argument parser owns a copy of every value it parses, so this type has
/// to be `Clone`. Each copy is scrubbed on drop exactly like the original; the
/// only thing cloning costs is one more live buffer for the duration.
impl Clone for Secret {
    fn clone(&self) -> Self {
        Self::new(self.0.as_str().to_owned())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl std::str::FromStr for Secret {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.to_owned()))
    }
}

/// Reads a secret from `path`, refusing a file that group or others can read or
/// write.
///
/// The permission check is the reason this path exists: `chmod 600` is what
/// makes the file a better home for a durable identity than the process
/// arguments. Only regular files are checked, because an inherited descriptor
/// or a pipe (`--seed-file /dev/fd/3`) carries no mode of its own; that form is
/// the operator's own explicit grant, and it is the form that keeps the secret
/// off disk entirely.
///
/// # Errors
///
/// Fails when the path cannot be opened, is a directory, exceeds
/// [`MAX_SECRET_LEN`], is not UTF-8, or (for a regular file) is readable or
/// writable by group or others. The error text never contains the secret.
pub(crate) fn read_secret_file(path: &Path) -> Result<Secret> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)
        .with_context(|| format!("open the secret file {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("stat the secret file {}", path.display()))?;
    if meta.is_dir() {
        bail!("the secret file {} is a directory", path.display());
    }
    check_regular_file_permissions(&meta, path)?;

    let mut buf = Zeroizing::new(Vec::<u8>::new());
    file.take(MAX_SECRET_LEN as u64 + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("read the secret file {}", path.display()))?;
    if buf.len() > MAX_SECRET_LEN {
        bail!(
            "the secret file {} is larger than the {} byte limit for a secret",
            path.display(),
            MAX_SECRET_LEN
        );
    }
    let text = std::str::from_utf8(&buf)
        .with_context(|| format!("the secret file {} is not UTF-8 text", path.display()))?;
    Ok(Secret::new(text.trim().to_owned()))
}

/// Reads a secret as raw bytes (a 32-byte key file, not a text secret).
///
/// Shares the permission check of [`read_secret_file`] so every secret file
/// this CLI accepts is held to the same standard.
///
/// # Errors
///
/// Same as [`read_secret_file`], minus the UTF-8 requirement.
pub(crate) fn read_secret_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)
        .with_context(|| format!("open the secret file {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("stat the secret file {}", path.display()))?;
    if meta.is_dir() {
        bail!("the secret file {} is a directory", path.display());
    }
    check_regular_file_permissions(&meta, path)?;

    let mut buf = Zeroizing::new(Vec::<u8>::new());
    file.take(MAX_SECRET_LEN as u64 + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("read the secret file {}", path.display()))?;
    if buf.len() > MAX_SECRET_LEN {
        bail!(
            "the secret file {} is larger than the {} byte limit for a secret",
            path.display(),
            MAX_SECRET_LEN
        );
    }
    Ok(buf)
}

/// Refuses a regular file that other accounts can read or write.
#[cfg(unix)]
fn check_regular_file_permissions(meta: &std::fs::Metadata, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if !meta.is_file() {
        return Ok(());
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "the secret file {} is accessible to group or others (mode {:03o}); \
             run `chmod 600 {}`",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

/// Windows has no mode bits to inspect; the file inherits the ACL of the
/// directory the operator chose for it.
#[cfg(not(unix))]
fn check_regular_file_permissions(_meta: &std::fs::Metadata, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A unique directory per test, removed by [`TempSecret::drop`].
    pub(crate) struct TempSecret(std::path::PathBuf);

    impl TempSecret {
        pub(crate) fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "warrenguard-cli-secret-{}-{}",
                std::process::id(),
                name
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create the temp dir");
            Self(dir)
        }

        /// Writes `contents` with `mode` and returns the path.
        pub(crate) fn write(&self, contents: &str, mode: u32) -> std::path::PathBuf {
            let path = self.0.join("secret");
            std::fs::write(&path, contents).expect("write the secret file");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                    .expect("set the file mode");
            }
            #[cfg(not(unix))]
            let _ = mode;
            path
        }
    }

    impl Drop for TempSecret {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reads_a_protected_file_and_trims_the_trailing_newline() {
        let dir = TempSecret::new("reads-protected");
        let path = dir.write("aa11\n", 0o600);
        let secret = read_secret_file(&path).expect("a 0600 file is accepted");
        assert_eq!(secret.expose(), "aa11");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_file_readable_by_group_or_others() {
        // 0644 is what a plain `printf secret > file` produces under the usual
        // umask; accepting it would put the identity back in a world-readable
        // place, which is the defect this path exists to close.
        let dir = TempSecret::new("refuses-world-readable");
        let path = dir.write("aa11\n", 0o644);
        let err = read_secret_file(&path).expect_err("0644 must be refused");
        assert!(
            format!("{err:#}").contains("chmod 600"),
            "the error must tell the operator how to fix it: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_file_writable_by_others_even_when_not_readable() {
        // 0622 lets another account replace the identity the daemon loads.
        let dir = TempSecret::new("refuses-world-writable");
        let path = dir.write("aa11\n", 0o622);
        assert!(read_secret_file(&path).is_err(), "0622 must be refused");
    }

    #[test]
    fn refuses_a_missing_file() {
        let dir = TempSecret::new("missing");
        let path = dir.0.join("does-not-exist");
        let err = read_secret_file(&path).expect_err("a missing file must fail");
        assert!(format!("{err:#}").contains("does-not-exist"));
    }

    #[test]
    fn refuses_a_directory() {
        let dir = TempSecret::new("directory");
        assert!(
            read_secret_file(&dir.0).is_err(),
            "a directory is not a secret"
        );
    }

    #[test]
    fn refuses_a_non_utf8_file_without_echoing_it() {
        let dir = TempSecret::new("non-utf8");
        let path = dir.0.join("secret");
        std::fs::write(&path, [0xffu8, 0xfe, 0xfd]).expect("write bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        }
        let err = read_secret_file(&path).expect_err("non-UTF-8 must be refused");
        assert!(
            !format!("{err:#}").contains('\u{fffd}'),
            "the error must not carry the file contents: {err:#}"
        );
    }

    #[test]
    fn debug_never_renders_the_secret() {
        let secret = Secret::new("SuperSecretTokenValue".to_owned());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(
            !rendered.contains("SuperSecretTokenValue"),
            "a `Debug` rendering must never carry a secret"
        );
    }

    #[test]
    fn reads_raw_bytes_for_a_key_file() {
        let dir = TempSecret::new("raw-bytes");
        let path = dir.0.join("ikm");
        std::fs::write(&path, [7u8; 32]).expect("write bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        }
        let bytes = read_secret_bytes(&path).expect("a 0600 key file is accepted");
        assert_eq!(&bytes[..], &[7u8; 32]);
    }
}
