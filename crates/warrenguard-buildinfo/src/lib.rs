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

/// Engine-repo release identifier: the `git describe` of the checkout this
/// crate lives in, `-dirty`-suffixed when that tree has uncommitted or
/// untracked changes. Deploy builds inject the CONSUMING product's release
/// into [`RELEASE`], which erases the engine's own state from the binary;
/// this constant keeps it visible, because the engine is a path-dep whose
/// working-tree state (including stray WIP) is compiled in verbatim. Baked
/// from `WARREN_ENGINE_RELEASE` (build-arg for gitless or orchestrated
/// builds) or `git describe` in the engine checkout.
pub const ENGINE_RELEASE: &str = env!("WARREN_BUILD_ENGINE_RELEASE");

/// Human-readable one-line summary, e.g.
/// `v0.3.0-7-g4d607b92 (0.1.0) (engine 922c614)`. The engine suffix is
/// omitted when [`RELEASE`] already IS the engine describe (standalone
/// engine builds), and kept even when the engine resolves to `unknown`
/// so broken provenance is loud rather than silent.
#[must_use]
pub fn summary() -> String {
    compose_summary(RELEASE, VERSION, ENGINE_RELEASE)
}

/// [`summary`] as a pure function of its inputs, split out so the format
/// (which deploy tooling greps for `-dirty` and parses for a committish)
/// is pinned by tests independently of this build's baked constants.
/// Parentheses, not brackets: every char must clear the Warren API
/// heartbeat sanitizer whitelist or the deploy becomes invisible to the
/// rollout controller (see `summary_stays_inside_the_heartbeat_charset`).
fn compose_summary(release: &str, version: &str, engine: &str) -> String {
    if engine == release {
        format!("{release} ({version})")
    } else {
        format!("{release} ({version}) (engine {engine})")
    }
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

    #[test]
    #[allow(clippy::const_is_empty)]
    fn engine_release_is_populated() {
        assert!(!super::ENGINE_RELEASE.is_empty());
    }

    #[test]
    fn summary_appends_engine_when_it_differs_from_release() {
        assert_eq!(
            super::compose_summary("v0.6.40-1-gabc1234", "0.1.0", "922c614"),
            "v0.6.40-1-gabc1234 (0.1.0) (engine 922c614)",
            "a product build must expose which engine tree it embeds"
        );
    }

    #[test]
    fn summary_stays_inside_the_heartbeat_charset() {
        // The Warren API stores a heartbeat version only when every char is
        // in its defense-in-depth whitelist (alnum . _ + ( ) - space); a
        // char outside it makes the whole deploy invisible to the rollout
        // controller (learned the hard way with `[engine ...]`, 2026-07-22).
        let s = super::compose_summary("v0.6.40-6-g465871a1", "0.1.0", "0b869dc-dirty");
        assert!(
            s.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '(' | ')' | '-' | ' ')
            }),
            "summary must only use heartbeat-whitelisted characters, got: {s}"
        );
    }

    #[test]
    fn summary_omits_engine_when_it_equals_release() {
        assert_eq!(
            super::compose_summary("922c614", "0.1.0", "922c614"),
            "922c614 (0.1.0)",
            "a standalone engine build must not repeat its own describe"
        );
    }

    #[test]
    fn summary_propagates_a_dirty_engine_marker() {
        let s = super::compose_summary("v0.6.40", "0.1.0", "922c614-dirty");
        assert!(
            s.contains("-dirty"),
            "a dirty engine tree must stay visible so deploy tooling can refuse the build"
        );
    }
}
