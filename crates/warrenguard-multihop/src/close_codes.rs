//! QUIC application close codes for multi-hop session rejections.
//!
//! The exit closes a connection when it definitively refuses a client
//! (e.g. the client pubkey is not on the subscription allowlist, or the
//! exit's IP pool is exhausted). The client maps the close back to a
//! [`RejectionReason`] so the supervisor can distinguish a *policy*
//! rejection (which will keep failing until the user's state changes)
//! from a *transient* network loss (which is worth an immediate
//! reconnect).
//!
//! **Anti-oracle invariant**: the exit's TLS peer on a multi-hop
//! connection is the RELAY, which is hostile by threat model. Every
//! policy rejection therefore closes with ONE opaque code
//! ([`WARREN_MH_REJECTED`]) and EMPTY reason bytes, so the relay cannot
//! learn the client's subscription status (not-allowlisted vs
//! pool-exhausted) and correlate it with the client's source IP. The
//! cause detail travels to the CLIENT only, HPKE-sealed, as a
//! `WarrenControlMessage::Rejected` / `IpExhausted` reply on the setup
//! stream before the close (see [`RejectionReason::from_sealed_detail`]).
//!
//! These codes are the wire contract between the exit and the
//! client. They live here, in the shared protocol crate, so the
//! two sides cannot drift. Codes are spelled out as `u32` rather than
//! `quinn::VarInt` because this crate has no quinn dependency; both call
//! sites convert at the boundary.
//!
//! Value scheme: ASCII tags so a code is recognizable in a capture.
//! `0x57_4D_xx_xx` is `"WM.."` (Warren Multi-hop). Never reuse a value
//! for a different meaning; append new ones instead. Retired values
//! (never to be reassigned): `0x57_4D_41_31` (`"WMA1"`, per-cause
//! not-allowlisted) and `0x57_4D_49_31` (`"WMI1"`, per-cause
//! ip-exhausted), both replaced by the single opaque
//! [`WARREN_MH_REJECTED`].

/// Single opaque policy-rejection close code. Sent for EVERY definitive
/// policy refusal (not-allowlisted, missing/invalid proof of possession,
/// IP pool exhausted) with empty reason bytes, so the relay cannot
/// distinguish causes. ASCII `"WMR1"`.
pub const WARREN_MH_REJECTED: u32 = 0x57_4D_52_31;

/// Client-initiated forced reconnect: the migration watchdog (or any
/// supervisor consumer) closes its own relay connection so the
/// supervisor redials from a fresh socket after a network change the
/// QUIC path could not migrate across. This is NOT a policy rejection
/// and must never map to a [`RejectionReason`]: mapping it would trip
/// the supervisor's fatal path and turn a routine fallback into a
/// terminal tunnel error. ASCII `"WMF1"`.
pub const WARREN_MH_FORCED_RECONNECT: u32 = 0x57_4D_46_31;

/// Drain-deadline hard-close (ADR 36, smooth exit maintenance). The exit
/// is going down for maintenance: it first emits a soft, HPKE-sealed
/// [`WarrenControlMessage::ExitDraining`] advisory carrying the deadline,
/// giving the client time to make-before-break onto another exit. At the
/// deadline, any connection still attached is closed with THIS code as a
/// backstop. Like [`WARREN_MH_FORCED_RECONNECT`] it is operational, NOT a
/// policy rejection, so it must never map to a [`RejectionReason`]. It is
/// distinct from `FORCED_RECONNECT` so the client re-selects a DIFFERENT
/// exit instead of redialing the one that is draining. ASCII `"WMD1"`.
pub const WARREN_MH_DRAINING: u32 = 0x57_4D_44_31;

/// A definitive, policy-level reason an exit refused a multi-hop
/// session. Distinct from a transient network loss: a rejection will
/// recur on an immediate redial, so the supervisor surfaces it upward
/// instead of spinning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// Client not authorized: pubkey absent from the exit allowlist, or
    /// the proof of possession was missing/invalid. Learned from the
    /// HPKE-sealed `Rejected` detail (never from the close code, which
    /// is opaque by design).
    NotAllowlisted,
    /// Exit IP pool exhausted. Learned from the HPKE-sealed
    /// `IpExhausted` detail.
    IpExhausted,
    /// The exit closed with the opaque policy-rejection code but the
    /// sealed detail did not arrive (e.g. the reply stream was cut).
    /// Definitive all the same: an immediate redial would hit the same
    /// refusal.
    PolicyRefused,
}

impl RejectionReason {
    /// Map a QUIC application close code to a [`RejectionReason`], or
    /// `None` if the code is not the multi-hop policy-rejection code (a
    /// benign or unrecognized close). The code is opaque on purpose, so
    /// this always yields [`Self::PolicyRefused`]; callers upgrade it to
    /// a specific reason from the sealed detail when one arrived (see
    /// [`Self::from_sealed_detail`]).
    #[must_use]
    pub fn from_close_code(code: u32) -> Option<Self> {
        (code == WARREN_MH_REJECTED).then_some(Self::PolicyRefused)
    }

    /// The QUIC application close code the exit sends for this reason:
    /// always the single opaque [`WARREN_MH_REJECTED`] (anti-oracle, see
    /// the module docs).
    #[must_use]
    pub fn close_code(self) -> u32 {
        WARREN_MH_REJECTED
    }

    /// Map the HPKE-sealed rejection detail the exit wrote on the setup
    /// stream before closing to a specific [`RejectionReason`]. `None`
    /// for any control message that is not a rejection detail (e.g. a
    /// normal `IpAssign`).
    #[must_use]
    pub fn from_sealed_detail(msg: &crate::WarrenControlMessage) -> Option<Self> {
        match msg {
            crate::WarrenControlMessage::Rejected => Some(Self::NotAllowlisted),
            crate::WarrenControlMessage::IpExhausted => Some(Self::IpExhausted),
            crate::WarrenControlMessage::IpRequest { .. }
            | crate::WarrenControlMessage::IpRequestV7 { .. }
            | crate::WarrenControlMessage::IpAssign { .. }
            // A drain advisory is operational, not a setup rejection: it
            // must NOT map to a fatal RejectionReason (same contract as
            // WARREN_MH_FORCED_RECONNECT), or the supervisor would treat a
            // routine maintenance migration as a terminal tunnel error.
            | crate::WarrenControlMessage::ExitDraining { .. } => None,
        }
    }

    /// Short stable label for logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAllowlisted => "not-allowlisted",
            Self::IpExhausted => "ip-pool-exhausted",
            Self::PolicyRefused => "policy-refused",
        }
    }

    /// The engine's supervisor-facing verdict for this rejection.
    ///
    /// Not-allowlisted and the opaque policy refusal are fatal: the account is
    /// unauthorized (or the cause is unknown and definitive), and no other exit
    /// resolves it. Pool exhaustion is NOT fatal and NOT worth redialing the
    /// same exit: it is not the client's fault and a different exit likely has
    /// capacity, so it reselects, exactly like a drain. This is the single home
    /// for the exhaustion classification the single-hop path
    /// (`WARREN_NO_CAPACITY`) shares.
    #[must_use]
    pub fn retryability(self) -> warrenguard_wire::Retryability {
        use warrenguard_wire::{FatalCause, Retryability};
        match self {
            Self::NotAllowlisted => Retryability::Fatal(FatalCause::NotAuthorized),
            Self::PolicyRefused => Retryability::Fatal(FatalCause::PolicyRefused),
            Self::IpExhausted => Retryability::RetryReselect,
        }
    }
}

impl core::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WarrenControlMessage;

    #[test]
    fn every_rejection_reason_closes_with_the_same_opaque_code() {
        // Anti-oracle: a hostile relay must not be able to distinguish
        // rejection causes by close code. If this test fails, someone
        // reintroduced per-cause codes on the relay-facing branch.
        for reason in [
            RejectionReason::NotAllowlisted,
            RejectionReason::IpExhausted,
            RejectionReason::PolicyRefused,
        ] {
            assert_eq!(
                reason.close_code(),
                WARREN_MH_REJECTED,
                "ANTI-ORACLE: {reason} must close with the single opaque code"
            );
        }
    }

    #[test]
    fn opaque_close_code_maps_to_a_generic_policy_refusal() {
        assert_eq!(
            RejectionReason::from_close_code(WARREN_MH_REJECTED),
            Some(RejectionReason::PolicyRefused),
            "the opaque code alone yields the generic reason; the sealed detail refines it"
        );
    }

    #[test]
    fn unknown_and_retired_close_codes_are_not_rejections() {
        assert_eq!(RejectionReason::from_close_code(0), None);
        assert_eq!(RejectionReason::from_close_code(0xDEAD_BEEF), None);
        // Retired per-cause codes ("WMA1" / "WMI1") are gone for good:
        // both binaries redeploy together, so nothing emits them and a
        // client must not map them anymore.
        assert_eq!(RejectionReason::from_close_code(0x57_4D_41_31), None);
        assert_eq!(RejectionReason::from_close_code(0x57_4D_49_31), None);
    }

    #[test]
    fn forced_reconnect_is_never_a_rejection() {
        // The watchdog's self-inflicted close must look like a transient
        // loss to the supervisor (redial), not a policy rejection (fatal).
        assert_eq!(
            RejectionReason::from_close_code(WARREN_MH_FORCED_RECONNECT),
            None
        );
    }

    #[test]
    fn draining_is_never_a_rejection() {
        // The drain-deadline hard-close (ADR 36) is operational, not a
        // policy refusal: the client already got the soft ExitDraining
        // advisory and should re-select a DIFFERENT exit. Mapping it to a
        // RejectionReason would trip the supervisor's fatal path and turn a
        // routine maintenance migration into a terminal tunnel error.
        assert_eq!(RejectionReason::from_close_code(WARREN_MH_DRAINING), None);
    }

    #[test]
    fn draining_close_code_is_distinct_and_stable() {
        // The wire contract: "WMD1". Distinct from every other multi-hop
        // code so the client maps it to "exit is draining, migrate away"
        // rather than "reconnect to the same exit" (FORCED_RECONNECT) or
        // "policy refused" (REJECTED).
        assert_eq!(WARREN_MH_DRAINING, 0x57_4D_44_31);
        assert_ne!(WARREN_MH_DRAINING, WARREN_MH_REJECTED);
        assert_ne!(WARREN_MH_DRAINING, WARREN_MH_FORCED_RECONNECT);
    }

    #[test]
    fn rejection_verdicts_are_pinned_per_cause() {
        use warrenguard_wire::{FatalCause, Retryability};
        // Fatal set: an unauthorized account (or an opaque definitive refusal)
        // must STOP the supervisor, never loop as a reconnect. If this flips to
        // a retryable verdict, a rejected user spins "Reconnecting" forever.
        assert_eq!(
            RejectionReason::NotAllowlisted.retryability(),
            Retryability::Fatal(FatalCause::NotAuthorized),
            "not-allowlisted must be fatal (unauthorized account)"
        );
        assert_eq!(
            RejectionReason::PolicyRefused.retryability(),
            Retryability::Fatal(FatalCause::PolicyRefused),
            "an opaque policy refusal is definitive, so fatal"
        );
        // Exhaustion is a capacity issue on THIS exit, not the account: reselect.
        assert_eq!(
            RejectionReason::IpExhausted.retryability(),
            Retryability::RetryReselect,
            "pool exhaustion must reselect another exit, not surface fatal"
        );
    }

    #[test]
    fn sealed_detail_refines_the_generic_reason() {
        assert_eq!(
            RejectionReason::from_sealed_detail(&WarrenControlMessage::Rejected),
            Some(RejectionReason::NotAllowlisted)
        );
        assert_eq!(
            RejectionReason::from_sealed_detail(&WarrenControlMessage::IpExhausted),
            Some(RejectionReason::IpExhausted)
        );
        let assign = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 2],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        assert_eq!(
            RejectionReason::from_sealed_detail(&assign),
            None,
            "a normal IpAssign must never read as a rejection"
        );
    }
}
