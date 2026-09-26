//! Route admission by anchor: the exit-side policy seam.
//!
//! A route session is admitted against the device's live, anchored main
//! session instead of a token of its own. The engine carries the two sealed
//! blobs (the route locator on the setup stream, the anchor registration as an
//! uplink datagram on the main session) but never opens either: only the
//! deployer's control plane holds the key. So, like
//! [`SessionTokenAdmitter`](super::SessionTokenAdmitter), the verdicts come
//! from an injected [`RouteAdmitter`] implemented in the deployer's exit
//! binary, which knows its own authenticated identity and talks to its
//! control plane. The engine never talks HTTP and never names this exit in
//! what it hands over: the control plane derives the exit from the caller's
//! authenticated key, so a locator sealed for another exit cannot open.

use warrenguard_multihop::{RouteAnchorStatus, RouteRejectCode, RouteSerial, SealedToApi};

use super::BoxFuture;
use super::TOKEN_SERIAL_LEN;

/// Verdict on a route session's locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteAdmission {
    /// Admitted: the session is keyed by `route_serial`, stable for this
    /// (anchor, exit), so a redial of the same route lands on the same
    /// sticky allocation.
    Admit {
        /// The route serial `r` the control plane assigned.
        route_serial: RouteSerial,
    },
    /// Refused with a code the client sees sealed. A policy that could not
    /// reach its control plane refuses with
    /// [`RouteRejectCode::Unavailable`]: a locator cannot be checked
    /// offline, so route admission fails closed and the client falls back
    /// to a token route.
    Refuse(RouteRejectCode),
}

/// Verdict on an anchor registration, sent back to the client as a
/// `RouteAnchorAck`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorVerdict {
    /// The ack status.
    pub status: RouteAnchorStatus,
    /// How many routes the anchor admits (meaningful when bound).
    pub max_routes: u16,
}

impl AnchorVerdict {
    /// A verdict with no route count, for every status but `bound`.
    #[must_use]
    pub const fn status(status: RouteAnchorStatus) -> Self {
        Self {
            status,
            max_routes: 0,
        }
    }
}

/// Injected hook the exit calls for route admission. Implemented in the
/// deployer's exit binary against its control plane; stubbed in tests.
///
/// Contract:
/// - [`Self::admit_route`] is called once per route setup with the locator
///   the client presented. The implementation hands it to its control plane,
///   which opens it with this exit's authenticated id as associated data.
/// - [`Self::anchor`] is called for an anchor registration of a live v7 main
///   session admitted on (or rebound to) `lease_serial`, which this exit holds
///   the lease of. The engine has already spent a presented token through the
///   [`SessionTokenAdmitter`](super::SessionTokenAdmitter) and rebound the
///   session before calling, so `lease_serial` is always the current one.
/// - Renewals, the re-submission of a route's retained locator and the
///   release of route leases are driven by the deployer from the session
///   registry (live anchor and route serials, route end observer), exactly
///   as token leases are.
pub trait RouteAdmitter: Send + Sync {
    /// Admit or refuse a route session presenting `locator`.
    fn admit_route<'a>(&'a self, locator: &'a SealedToApi) -> BoxFuture<'a, RouteAdmission>;

    /// Attach (or re-home) the anchor sealed in `sealed_anchor` to the main
    /// session whose lease serial is `lease_serial`.
    fn anchor<'a>(
        &'a self,
        lease_serial: &'a [u8; TOKEN_SERIAL_LEN],
        sealed_anchor: &'a SealedToApi,
    ) -> BoxFuture<'a, AnchorVerdict>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_only_verdict_names_no_route_count() {
        let verdict = AnchorVerdict::status(RouteAnchorStatus::NeedsToken);
        assert_eq!(verdict.status, RouteAnchorStatus::NeedsToken);
        assert_eq!(verdict.max_routes, 0);
    }
}
