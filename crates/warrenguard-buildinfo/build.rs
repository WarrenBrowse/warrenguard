//! Build script: bakes the git commit SHA + build timestamp into
//! compile-time env vars consumed by `src/lib.rs`.
//!
//! Resolution order for the commit SHA:
//! 1. `WARREN_GIT_SHA` env var - authoritative in container builds where
//!    `.git/` is excluded from the Docker context (see
//!    `infra/docker/.dockerignore`); threaded in as a `--build-arg` by
//!    `infra/docker/*.Dockerfile` + `infra/docker/update-prod.sh`.
//! 2. `git rev-parse HEAD` - local dev builds with a `.git` checkout.
//! 3. `"unknown"` - neither available.
//!
//! The build timestamp comes from `WARREN_BUILD_TIME` if set, else from
//! `SOURCE_DATE_EPOCH` (reproducible builds), else the system `date -u`
//! (UTC RFC3339), else `"unknown"`. The resolution policy itself lives
//! in the dependency-free `build_time` module (also unit-tested from
//! `src/lib.rs`).

use std::path::PathBuf;
use std::process::Command;

// Shared, pure timestamp-resolution logic. Included rather than imported
// because a build script is not part of the crate's own module tree.
#[path = "src/build_time.rs"]
mod build_time;

fn main() {
    let (sha_full, sha_short) = resolve_git_sha();
    let build_time = resolve_build_time();
    let release = resolve_release(&sha_short);
    let engine_release = resolve_engine_release();

    println!("cargo:rustc-env=WARREN_BUILD_GIT_SHA={sha_full}");
    println!("cargo:rustc-env=WARREN_BUILD_GIT_SHORT={sha_short}");
    println!("cargo:rustc-env=WARREN_BUILD_TIME={build_time}");
    println!("cargo:rustc-env=WARREN_BUILD_RELEASE={release}");
    println!("cargo:rustc-env=WARREN_BUILD_ENGINE_RELEASE={engine_release}");

    // Re-bake when the injected env vars change so a new deploy from the
    // same source tree but a new commit picks up the value.
    println!("cargo:rerun-if-env-changed=WARREN_GIT_SHA");
    println!("cargo:rerun-if-env-changed=WARREN_BUILD_TIME");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-env-changed=WARREN_RELEASE");
    println!("cargo:rerun-if-env-changed=WARREN_ENGINE_RELEASE");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/build_time.rs");

    // Best-effort: rebuild when HEAD moves in a local checkout. Container
    // builds have no `.git`, so this is simply skipped there.
    for path in git_rerun_paths() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn resolve_git_sha() -> (String, String) {
    if let Ok(sha) = std::env::var("WARREN_GIT_SHA") {
        let sha = sha.trim().to_owned();
        if !sha.is_empty() {
            let short = sha.chars().take(12).collect();
            return (sha, short);
        }
    }
    if let Some(sha) = run("git", &["rev-parse", "HEAD"]) {
        let short = run("git", &["rev-parse", "--short=12", "HEAD"])
            .unwrap_or_else(|| sha.chars().take(12).collect());
        return (sha, short);
    }
    ("unknown".to_owned(), "unknown".to_owned())
}

/// Resolve the human-readable *release* string - the thing that tracks
/// the git release tags, unlike `CARGO_PKG_VERSION` (which is the crate
/// semver and may lag the release line).
///
/// Order:
/// 1. `WARREN_RELEASE` env - the release tag injected in container
///    builds (CI passes `github.ref_name`, e.g. `v0.3.1`).
/// 2. `git describe --tags --always --dirty` - local checkout, e.g.
///    `v0.3.0-7-g4d607b92` (7 commits past v0.3.0) or `v0.3.1` at a tag.
/// 3. fallback to `g<short-sha>` so the field is never empty.
fn resolve_release(sha_short: &str) -> String {
    if let Ok(rel) = std::env::var("WARREN_RELEASE") {
        let rel = rel.trim().to_owned();
        if !rel.is_empty() {
            return rel;
        }
    }
    if let Some(desc) = run("git", &["describe", "--tags", "--always", "--dirty"]) {
        return desc;
    }
    if sha_short == "unknown" {
        "unknown".to_owned()
    } else {
        format!("g{sha_short}")
    }
}

/// Resolve the ENGINE release: the describe of the repo this crate lives in
/// (the engine checkout), `--dirty` included. Unlike [`resolve_release`],
/// whose env override carries the CONSUMING product's release in deploy
/// builds, the override here exists for gitless builds and for orchestrating
/// scripts that compute the value fresh on the host: a build-script cache
/// cannot observe a tree turning dirty, so an injected value is the only
/// guaranteed-fresh source.
fn resolve_engine_release() -> String {
    if let Ok(rel) = std::env::var("WARREN_ENGINE_RELEASE") {
        let rel = rel.trim().to_owned();
        if !rel.is_empty() {
            return rel;
        }
    }
    run("git", &["describe", "--tags", "--always", "--dirty"])
        .unwrap_or_else(|| "unknown".to_owned())
}

fn resolve_build_time() -> String {
    let build_time_env = std::env::var("WARREN_BUILD_TIME").ok();
    let source_date_epoch = std::env::var("SOURCE_DATE_EPOCH").ok();
    // System `date` in UTC RFC3339, avoiding a chrono build dependency.
    // Only consulted when neither explicit override is present.
    let system_fallback = run("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]);
    build_time::resolve_build_time(
        build_time_env.as_deref(),
        source_date_epoch.as_deref(),
        system_fallback.as_deref(),
    )
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    if s.is_empty() { None } else { Some(s) }
}

/// Paths whose change should force a re-bake of the git SHA in a local
/// checkout. Returns `.git/HEAD`, `.git/packed-refs`, and the concrete
/// ref file `HEAD` points at (e.g. `.git/refs/heads/main`) - the latter
/// is what actually changes on a fresh commit to the current branch, so
/// watching `HEAD` alone would miss new commits.
fn git_rerun_paths() -> Vec<PathBuf> {
    let Some(git_dir) = find_git_dir() else {
        return Vec::new();
    };
    let mut paths = vec![git_dir.join("HEAD"), git_dir.join("packed-refs")];

    // Resolve a symbolic `HEAD` (`ref: refs/heads/<branch>`) to its ref
    // file so a same-branch commit triggers a rebuild. A detached HEAD
    // (raw SHA) needs no extra path - `.git/HEAD` itself changes then.
    let head_ref = std::fs::read_to_string(git_dir.join("HEAD"))
        .ok()
        .and_then(|head| {
            head.trim()
                .strip_prefix("ref: ")
                .map(|ref_rel| git_dir.join(ref_rel))
        });
    if let Some(ref_path) = head_ref {
        paths.push(ref_path);
    }
    paths
}

fn find_git_dir() -> Option<PathBuf> {
    let mut dir = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from)?;
    loop {
        let candidate = dir.join(".git");
        // Only the directory form is handled (the common case). A
        // worktree `.git` *file* is rare here and simply skipped.
        if candidate.join("HEAD").exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}
