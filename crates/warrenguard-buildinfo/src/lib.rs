//! Compile-time build metadata for server binaries.
//!
//! The constants are baked by `build.rs` (see that file for the SHA
//! resolution order). A deployer's admin/version endpoint surfaces them
//! so an operator can
//! verify which commit is *actually* running in production - the
//! semver alone (`CARGO_PKG_VERSION`) does not change between two
//! deploys built from the same release line.

/// Crate semver (the shared workspace `Cargo.toml` version). This is the
/// crate's internal version; it does NOT necessarily track the git
/// release tags - use [`RELEASE`] for "which release is deployed".
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Release identifier tracking the git tags, e.g. `v0.3.1` (at a tag) or
/// `v0.3.0-7-g4d607b92` (7 commits past `v0.3.0`). This is the
/// authoritative "what version is running" string. Baked from
/// `WARREN_RELEASE` (CI build arg) or `git describe` (local builds).
pub const RELEASE: &str = env!("WARREN_BUILD_RELEASE");

/// Full 40-char git commit SHA, or `"unknown"` if unavailable at build.
pub const GIT_SHA: &str = env!("WARREN_BUILD_GIT_SHA");

/// First 12 chars of the git commit SHA, or `"unknown"`.
pub const GIT_SHORT: &str = env!("WARREN_BUILD_GIT_SHORT");

/// UTC RFC3339 build timestamp, or `"unknown"`.
pub const BUILD_TIME: &str = env!("WARREN_BUILD_TIME");

/// Human-readable one-line summary, e.g. `v0.3.0-7-g4d607b92 (0.1.0)`.
#[must_use]
pub fn summary() -> String {
    format!("{RELEASE} ({VERSION})")
}

// The build-timestamp resolution policy lives in `build_time`, shared
// with `build.rs` (which `include!`s it). It is compiled here only under
// `cfg(test)` so its unit tests run via `cargo test`; the runtime crate
// exposes the resolved value through the baked [`BUILD_TIME`] constant.
#[cfg(test)]
mod build_time;

#[cfg(test)]
mod tests {
    #[test]
    // The consts are compile-time `env!` values, so clippy can fold the
    // `is_empty()` checks to a constant. We keep the asserts anyway: they
    // are the contract guard that build.rs never emits an empty string
    // for one of the baked fields.
    #[allow(clippy::const_is_empty)]
    fn consts_are_populated() {
        // build.rs always emits a value (at minimum "unknown"), so the
        // env! lookups must resolve to a non-empty string.
        assert!(!super::VERSION.is_empty());
        assert!(!super::RELEASE.is_empty());
        assert!(!super::GIT_SHA.is_empty());
        assert!(!super::GIT_SHORT.is_empty());
        assert!(!super::BUILD_TIME.is_empty());
    }

    #[test]
    fn summary_contains_release_and_version() {
        let s = super::summary();
        assert!(s.starts_with(super::RELEASE));
        assert!(s.contains(super::VERSION));
    }
}
