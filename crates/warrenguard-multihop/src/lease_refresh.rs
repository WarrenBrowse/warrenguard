//! Epoch lease refresh: the typed status of a
//! [`crate::WarrenControlMessage::LeaseRefreshAck`].
//!
//! A session admitted on an anonymous token holds its fleet-wide lease only
//! within the token's epoch. The client announces with a
//! [`crate::WarrenControlMessage::LeaseRefresh`] carrying no token that it
//! will present a token of each new epoch; the exit asks for one (`due`)
//! once the lease belongs to a past epoch, spends the token the client then
//! presents and moves the session's lease onto its serial, and may end a
//! session that does not refresh (`expired`, then
//! [`crate::WARREN_MH_LEASE_EXPIRED`]).

/// Status of a [`crate::WarrenControlMessage::LeaseRefreshAck`], a plain
/// `u8` on the wire so a code this build does not know still decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LeaseRefreshStatus {
    /// `0`: the announcement was noted; the exit will ask when a token is due.
    Registered,
    /// `1`: the presented token was spent and the session holds its lease.
    Refreshed,
    /// `2`: the presented token was refused (not of the current epoch, or its
    /// serial is held elsewhere); present another.
    Refused,
    /// `3`: the control plane could not be asked; present the token again
    /// later.
    Unavailable,
    /// `4`: the session holds no token lease (a wallet or route session, or
    /// an exit that admits no token); nothing to refresh.
    NotEligible,
    /// `5`: the session's lease belongs to a past epoch; present a token of
    /// the current one.
    Due,
    /// `6`: the lease was not refreshed in time; the exit ends the session.
    Expired,
    /// A status this build does not know.
    Other(u8),
}

impl LeaseRefreshStatus {
    /// Decode a wire status.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Registered,
            1 => Self::Refreshed,
            2 => Self::Refused,
            3 => Self::Unavailable,
            4 => Self::NotEligible,
            5 => Self::Due,
            6 => Self::Expired,
            other => Self::Other(other),
        }
    }

    /// The wire status.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Registered => 0,
            Self::Refreshed => 1,
            Self::Refused => 2,
            Self::Unavailable => 3,
            Self::NotEligible => 4,
            Self::Due => 5,
            Self::Expired => 6,
            Self::Other(code) => code,
        }
    }

    /// A stable label for metrics and logs (no identifier).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Refreshed => "refreshed",
            Self::Refused => "refused",
            Self::Unavailable => "unavailable",
            Self::NotEligible => "not_eligible",
            Self::Due => "due",
            Self::Expired => "expired",
            Self::Other(_) => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_keeps_its_wire_code() {
        let frozen = [
            (LeaseRefreshStatus::Registered, 0),
            (LeaseRefreshStatus::Refreshed, 1),
            (LeaseRefreshStatus::Refused, 2),
            (LeaseRefreshStatus::Unavailable, 3),
            (LeaseRefreshStatus::NotEligible, 4),
            (LeaseRefreshStatus::Due, 5),
            (LeaseRefreshStatus::Expired, 6),
        ];
        for (status, code) in frozen {
            assert_eq!(status.code(), code, "{} moved", status.as_str());
            assert_eq!(LeaseRefreshStatus::from_code(code), status);
        }
    }

    #[test]
    fn an_unknown_code_decodes_and_encodes_back_unchanged() {
        let status = LeaseRefreshStatus::from_code(42);
        assert_eq!(status, LeaseRefreshStatus::Other(42));
        assert_eq!(status.code(), 42);
        assert_eq!(status.as_str(), "other");
    }
}
