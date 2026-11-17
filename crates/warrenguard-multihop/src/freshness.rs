//! Setup freshness and session binding: the constants and the refusal code a
//! dated setup request is checked against.
//!
//! A setup frame is sealed under a session anyone holding the exit's public
//! key can create, and it carries the whole admission (a proof of possession,
//! tokens or a route locator). Without a time inside it, a captured frame is
//! admitted again as soon as the exit forgets the session it built. A dated
//! request carries the client's wall clock inside the sealed plaintext, so the
//! holder of a captured frame cannot re-date it, and the exit refuses it once
//! it is older than [`SETUP_CLOCK_SKEW_SECS`]; within that bound the exit
//! remembers every dated setup key for [`RECENT_SETUP_RETENTION_SECS`] and
//! refuses a second presentation.

/// Largest difference, in seconds, between a dated setup's `client_unix_secs`
/// and the exit's clock that the exit admits.
pub const SETUP_CLOCK_SKEW_SECS: u64 = 120;

/// How long an exit remembers the `encapsulated_key` of a dated setup. Twice
/// the skew bound: a frame presented again is either still remembered or
/// already too old, whichever side of the exit's clock it was dated on.
pub const RECENT_SETUP_RETENTION_SECS: u64 = 2 * SETUP_CLOCK_SKEW_SECS;

/// Whether `client_unix_secs` is within [`SETUP_CLOCK_SKEW_SECS`] of
/// `exit_unix_secs`, on either side.
#[must_use]
pub const fn within_setup_skew(client_unix_secs: u64, exit_unix_secs: u64) -> bool {
    client_unix_secs.abs_diff(exit_unix_secs) <= SETUP_CLOCK_SKEW_SECS
}

/// Reason code of a [`crate::WarrenControlMessage::SetupRefused`], a plain
/// `u8` on the wire so a code this build does not know still decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SetupRefusalCode {
    /// `0`: not authorized (no valid proof of possession, not allowlisted),
    /// the dated counterpart of the plain `Rejected`.
    Unspecified,
    /// `1`: the request's time is further than [`SETUP_CLOCK_SKEW_SECS`] from
    /// the exit's clock.
    ClockSkew,
    /// `2`: the exit already saw a setup under this `encapsulated_key`.
    Replayed,
    /// `3`: the exit cannot vouch for this setup's freshness right now (its
    /// set of recent setup keys is full, or it restarted within the
    /// retention window and the request predates the restart). Not the
    /// account: another exit.
    Busy,
    /// A code this build does not know. Read as [`Self::Unspecified`].
    Other(u8),
}

impl SetupRefusalCode {
    /// Decode a wire code.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Unspecified,
            1 => Self::ClockSkew,
            2 => Self::Replayed,
            3 => Self::Busy,
            other => Self::Other(other),
        }
    }

    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::ClockSkew => 1,
            Self::Replayed => 2,
            Self::Busy => 3,
            Self::Other(code) => code,
        }
    }

    /// A stable label for metrics and logs (no identifier).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::ClockSkew => "clock_skew",
            Self::Replayed => "replayed",
            Self::Busy => "busy",
            Self::Other(_) => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_skew_bound_is_inclusive_on_both_sides_of_the_exit_clock() {
        let now = 1_800_000_000;
        assert!(within_setup_skew(now - SETUP_CLOCK_SKEW_SECS, now));
        assert!(within_setup_skew(now + SETUP_CLOCK_SKEW_SECS, now));
        assert!(!within_setup_skew(now - SETUP_CLOCK_SKEW_SECS - 1, now));
        assert!(
            !within_setup_skew(now + SETUP_CLOCK_SKEW_SECS + 1, now),
            "a request dated in the future past the bound is refused too"
        );
    }

    #[test]
    fn refusal_codes_round_trip_and_an_unknown_code_survives() {
        for code in [
            SetupRefusalCode::Unspecified,
            SetupRefusalCode::ClockSkew,
            SetupRefusalCode::Replayed,
            SetupRefusalCode::Busy,
        ] {
            assert_eq!(SetupRefusalCode::from_code(code.code()), code);
        }
        assert_eq!(SetupRefusalCode::Busy.code(), 3);
        assert_eq!(SetupRefusalCode::from_code(9), SetupRefusalCode::Other(9));
        assert_eq!(SetupRefusalCode::Other(9).code(), 9);
        assert_eq!(SetupRefusalCode::ClockSkew.as_str(), "clock_skew");
    }

    #[test]
    fn retention_covers_a_frame_on_either_side_of_the_skew_bound() {
        assert_eq!(RECENT_SETUP_RETENTION_SECS, 240);
    }
}
