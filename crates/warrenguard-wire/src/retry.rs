//! The retryability verdict a client supervisor consumes to react to a failed
//! (re)connect.
//!
//! The ENGINE owns this classification: it decodes the exit's close code and
//! sealed rejection and maps them to one of three actions, so every client (the
//! app, the SDK, warrend, the FRB/napi bridges) reacts identically instead of
//! re-deriving the policy per client and drifting. The consumers `match` on the
//! verdict; they never re-decide it.
//!
//! Three actions, keeping every distinction the exit expresses:
//! - [`Retryability::Fatal`] stops the supervisor and surfaces a
//!   [`FatalCause`] to the user (the account/identity is the problem, or the
//!   refusal is opaque and definitive): an immediate redial reproduces it and
//!   no other exit helps.
//! - [`Retryability::RetrySameTarget`] is a transient failure (bind contention,
//!   handshake stall, a network blip): retry the SAME target after a backoff.
//! - [`Retryability::RetryReselect`] is a refusal that is not the client's fault
//!   and that a DIFFERENT exit would not share (a planned maintenance drain, or
//!   an exhausted IP pool): retrying the same exit re-hits it, so reselect
//!   another exit. NOT fatal.

/// How a client supervisor should react to a failed (re)connect, as decided by
/// the engine from the exit's close code / sealed rejection.
///
/// A plain `Copy` enum so it maps cleanly across the FFI boundary to every
/// sibling-language SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Retryability {
    /// Definitive refusal tied to the account/identity or an opaque policy
    /// close: stop and surface the [`FatalCause`]. Retrying reproduces it, and
    /// no other exit resolves it (only the user provisioning/renewing does).
    Fatal(FatalCause),
    /// Transient failure: retry the SAME target after a backoff.
    RetrySameTarget,
    /// The dialed exit refused for a reason a DIFFERENT exit would not share
    /// (planned drain, IP-pool exhaustion): reselect another exit. Not fatal.
    RetryReselect,
}

/// Why a [`Retryability::Fatal`] verdict stops the supervisor: a stable,
/// user-surfaceable cause. Carries no identity material (no-log discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FatalCause {
    /// Identity not authorized: no active subscription, or not enrolled in the
    /// exit's allowlist.
    NotAuthorized,
    /// The account already holds its maximum number of simultaneous devices.
    DeviceLimit,
    /// The exit closed with the opaque policy-rejection code and the sealed
    /// cause did not arrive: definitive, but the specific reason is unknown.
    PolicyRefused,
}

impl Retryability {
    /// Whether the verdict stops the supervisor (any [`Self::Fatal`]).
    #[must_use]
    pub fn is_fatal(self) -> bool {
        matches!(self, Self::Fatal(_))
    }

    /// The fatal cause, or `None` for the two retryable verdicts.
    #[must_use]
    pub fn fatal_cause(self) -> Option<FatalCause> {
        match self {
            Self::Fatal(cause) => Some(cause),
            Self::RetrySameTarget | Self::RetryReselect => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fatal_reports_fatal_and_carries_its_cause() {
        assert!(Retryability::Fatal(FatalCause::NotAuthorized).is_fatal());
        assert_eq!(
            Retryability::Fatal(FatalCause::DeviceLimit).fatal_cause(),
            Some(FatalCause::DeviceLimit)
        );
        assert!(!Retryability::RetrySameTarget.is_fatal());
        assert!(!Retryability::RetryReselect.is_fatal());
        assert_eq!(Retryability::RetryReselect.fatal_cause(), None);
    }
}
