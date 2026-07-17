//! Pure, dependency-free build-timestamp resolution.
//!
//! Shared by `build.rs` (which bakes `WARREN_BUILD_TIME`) and the
//! crate's unit tests. Kept free of `std::process`/`std::env` so the
//! resolution policy is deterministic and testable: the build script
//! reads the environment and the system clock, then hands the raw
//! strings here.
//!
//! Resolution order (see [`resolve_build_time`]):
//! 1. `WARREN_BUILD_TIME` if set + non-empty - explicit override.
//! 2. `SOURCE_DATE_EPOCH` if set + a valid non-negative integer -
//!    formatted as UTC RFC3339 for reproducible builds
//!    (<https://reproducible-builds.org/docs/source-date-epoch/>).
//! 3. the system-clock fallback string the caller supplies (UTC
//!    RFC3339 from `date -u`), or `"unknown"` when that is `None`.

/// Resolve the build timestamp string from the three inputs the build
/// script collects. Pure: same inputs always yield the same output.
///
/// `build_time_env` is `WARREN_BUILD_TIME`, `source_date_epoch` is
/// `SOURCE_DATE_EPOCH`, and `system_fallback` is the `date -u` result
/// (`None` when the command failed).
pub(crate) fn resolve_build_time(
    build_time_env: Option<&str>,
    source_date_epoch: Option<&str>,
    system_fallback: Option<&str>,
) -> String {
    if let Some(t) = build_time_env {
        let t = t.trim();
        if !t.is_empty() {
            return t.to_owned();
        }
    }
    if let Some(epoch) = source_date_epoch
        && let Some(formatted) = format_epoch_utc(epoch.trim())
    {
        return formatted;
    }
    match system_fallback {
        Some(s) if !s.trim().is_empty() => s.trim().to_owned(),
        _ => "unknown".to_owned(),
    }
}

/// Format a `SOURCE_DATE_EPOCH` string (seconds since the Unix epoch)
/// as `YYYY-MM-DDTHH:MM:SSZ`, matching the `date -u +%Y-%m-%dT%H:%M:%SZ`
/// fallback. Returns `None` if the string is not a non-negative
/// integer.
fn format_epoch_utc(epoch: &str) -> Option<String> {
    let secs: i64 = epoch.parse().ok()?;
    if secs < 0 {
        return None;
    }
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Convert a count of days since 1970-01-01 to a `(year, month, day)`
/// civil date (proleptic Gregorian). Howard Hinnant's `civil_from_days`
/// algorithm - exact, branch-light, no leap-year tables.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::{format_epoch_utc, resolve_build_time};

    #[test]
    fn source_date_epoch_is_formatted_as_utc_rfc3339() {
        // The epoch constant's expected rendering was verified against `date -u`.
        let out = resolve_build_time(None, Some("1717200000"), Some("2099-12-31T23:59:59Z"));
        assert_eq!(
            out, "2024-06-01T00:00:00Z",
            "SOURCE_DATE_EPOCH must override the system clock for reproducible builds"
        );
    }

    #[test]
    fn explicit_build_time_wins_over_source_date_epoch() {
        let out = resolve_build_time(
            Some("2030-01-02T03:04:05Z"),
            Some("1717200000"),
            Some("2099-12-31T23:59:59Z"),
        );
        assert_eq!(out, "2030-01-02T03:04:05Z");
    }

    #[test]
    fn absent_source_date_epoch_falls_back_to_system_clock() {
        let out = resolve_build_time(None, None, Some("2099-12-31T23:59:59Z"));
        assert_eq!(out, "2099-12-31T23:59:59Z");
    }

    #[test]
    fn no_inputs_at_all_yield_unknown() {
        assert_eq!(resolve_build_time(None, None, None), "unknown");
        // Blank strings count as absent.
        assert_eq!(
            resolve_build_time(Some("  "), Some("  "), Some("  ")),
            "unknown"
        );
    }

    #[test]
    fn invalid_source_date_epoch_is_ignored_for_the_fallback() {
        // Non-numeric and negative epochs are not valid timestamps; the
        // resolver must drop to the system fallback rather than emit a
        // bogus date.
        assert_eq!(
            resolve_build_time(None, Some("not-a-number"), Some("2099-01-01T00:00:00Z")),
            "2099-01-01T00:00:00Z"
        );
        assert_eq!(
            resolve_build_time(None, Some("-5"), Some("2099-01-01T00:00:00Z")),
            "2099-01-01T00:00:00Z"
        );
    }

    #[test]
    fn epoch_zero_is_the_unix_epoch() {
        assert_eq!(
            format_epoch_utc("0").as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
    }

    #[test]
    fn epoch_handles_a_leap_day() {
        assert_eq!(
            format_epoch_utc("1709164800").as_deref(),
            Some("2024-02-29T00:00:00Z")
        );
    }
}
