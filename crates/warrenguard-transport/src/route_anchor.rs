//! Route admission by anchor, client side.
//!
//! A main supervisor built with a [`RouteAnchorHandle`] anchors its logical
//! main session: after every v7 setup it seals the handle's anchor secret to
//! the serial of the token that setup was admitted on and sends it to the
//! exit as a `RouteAnchorRequest` datagram, retried until a
//! `RouteAnchorAck`. Route supervisors built with
//! [`crate::supervisor::SessionAdmission::Route`] then present a fresh
//! locator sealed for their exit instead of a token.
//!
//! The secret is created here, lives in memory only, and leaves the process
//! only sealed: the handle never returns it, its `Debug` prints nothing of
//! it, and it is never logged. State transitions are logged with no
//! identifier.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use warrenguard_multihop::{
    ExitId, RouteAnchorSecret, RouteAnchorStatus, RouteEndReason, RouteKemPublicKey,
    RouteRejectCode, RouteSealError, SealedToApi, WarrenControlMessage, encode_control,
    seal_route_anchor, seal_route_locator, session_token_serial,
};
use warrenguard_wire::SessionToken;

use crate::multihop::MultiHopClient;
use crate::supervisor::SessionTokenProvider;

/// What a main supervisor needs to anchor: the control plane's route KEM
/// key, as published in its token directory.
#[derive(Debug, Clone)]
pub struct RouteAnchorConfig {
    /// The control plane's route KEM public key and key id.
    pub kem: RouteKemPublicKey,
}

/// Where the anchor of a main session stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorState {
    /// No verdict yet for the current main session.
    Unanchored,
    /// The control plane bound the anchor; it admits up to `max_routes`
    /// routes.
    Anchored {
        /// Routes the anchor admits at most.
        max_routes: u16,
    },
    /// The main session cannot anchor (older main exit, control plane down,
    /// a wallet session, or a refusal): routes fall back to tokens until the
    /// next main setup.
    Unavailable,
}

struct AnchorInner {
    secret: RouteAnchorSecret,
    kem: RouteKemPublicKey,
    state: watch::Sender<AnchorState>,
}

/// The anchor of one logical main session, shared (in process) by the main
/// supervisor and every route supervisor of the same tunnel. Owns the anchor
/// secret, which it never returns.
#[derive(Clone)]
pub struct RouteAnchorHandle(Arc<AnchorInner>);

impl RouteAnchorHandle {
    /// A fresh anchor with a newly drawn secret.
    #[must_use]
    pub fn new(config: RouteAnchorConfig) -> Self {
        Self(Arc::new(AnchorInner {
            secret: RouteAnchorSecret::generate(),
            kem: config.kem,
            state: watch::channel(AnchorState::Unanchored).0,
        }))
    }

    /// Follow the anchor state.
    #[must_use]
    pub fn state(&self) -> watch::Receiver<AnchorState> {
        self.0.state.subscribe()
    }

    /// The anchor state now.
    #[must_use]
    pub fn current_state(&self) -> AnchorState {
        *self.0.state.borrow()
    }

    /// A route locator for `exit_id`: the secret sealed to the control plane
    /// with that exit's id as associated data, with a fresh ephemeral key.
    ///
    /// # Errors
    ///
    /// [`RouteSealError`] when the route KEM key refuses the seal.
    pub fn seal_locator(&self, exit_id: &ExitId) -> Result<SealedToApi, RouteSealError> {
        seal_route_locator(&self.0.kem, &self.0.secret, exit_id)
    }

    fn seal_anchor(&self, serial: &[u8; 32]) -> Result<SealedToApi, RouteSealError> {
        seal_route_anchor(&self.0.kem, &self.0.secret, serial)
    }

    pub(crate) fn set_state(&self, state: AnchorState) {
        let previous = self.0.state.send_replace(state);
        if previous != state {
            match state {
                AnchorState::Anchored { max_routes } => {
                    tracing::info!(max_routes, "route anchor bound");
                }
                AnchorState::Unavailable => {
                    tracing::info!("route anchor unavailable; routes fall back to tokens");
                }
                AnchorState::Unanchored => {}
            }
        }
    }

    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl core::fmt::Debug for RouteAnchorHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RouteAnchorHandle")
            .field("state", &self.current_state())
            .finish_non_exhaustive()
    }
}

/// How a route supervisor is admitted: against `anchor`, at an exit the
/// consumer knows offers route admission.
#[derive(Clone, Debug)]
pub struct RouteSessionAdmission {
    /// The main session's anchor, shared in process.
    pub anchor: RouteAnchorHandle,
    /// Whether the target exit offers route admission, from the consumer's
    /// capability list (the control plane's token directory). `false` ends
    /// the run at once with [`RouteRefusal::Rejected`]`(NotOffered)`, before
    /// any dial.
    pub exit_offers_routes: bool,
}

impl PartialEq for RouteSessionAdmission {
    fn eq(&self, other: &Self) -> bool {
        self.anchor.same(&other.anchor) && self.exit_offers_routes == other.exit_offers_routes
    }
}

impl Eq for RouteSessionAdmission {}

/// Why a route session was not (or is no longer) served, so the consumer can
/// fall back to a token route. Never carries an identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteRefusal {
    /// The exit answered `RouteRejected` with this code, or (for
    /// `NotOffered`) the consumer said it does not offer route admission.
    Rejected(RouteRejectCode),
    /// The exit refused with the plain `Rejected`: it predates route
    /// admission.
    Legacy,
    /// The main session has no usable anchor.
    AnchorUnavailable,
    /// The exit ended an admitted route (`RouteEnded`, or its policy close).
    Ended(RouteEndReason),
}

impl core::fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rejected(code) => write!(f, "route rejected ({code})"),
            Self::Legacy => f.write_str("route rejected by an exit without route admission"),
            Self::AnchorUnavailable => f.write_str("no route anchor available"),
            Self::Ended(reason) => write!(f, "route ended ({})", reason.as_str()),
        }
    }
}

/// A route control message the bundle intercepted on the downlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteDownlink {
    Ack {
        status: RouteAnchorStatus,
        max_routes: u16,
    },
    Ended(RouteEndReason),
}

impl RouteDownlink {
    /// The route control message `msg` carries, if any.
    pub(crate) fn from_control(msg: &WarrenControlMessage) -> Option<Self> {
        match msg {
            WarrenControlMessage::RouteAnchorAck { status, max_routes } => Some(Self::Ack {
                status: RouteAnchorStatus::from_code(*status),
                max_routes: *max_routes,
            }),
            WarrenControlMessage::RouteEnded { reason_code } => {
                Some(Self::Ended(RouteEndReason::from_code(*reason_code)))
            }
            _ => None,
        }
    }
}

/// Sender half of a bundle's route control intercept.
pub(crate) type RouteTap = mpsc::UnboundedSender<RouteDownlink>;

/// Waits between two sends of one anchor request (doc 107 section 10.1:
/// retried at 1, 2, 4, 8 and 16 s); after the last one with no ack the
/// anchor is unavailable for this setup.
pub(crate) const ANCHOR_RETRY_WAITS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];

/// Wait before a new cycle after the control plane answered `unavailable`.
const ANCHOR_UNAVAILABLE_RETRY: Duration = Duration::from_secs(16);

/// Anchor one main session: send the request sealed to `serial`, follow the
/// acks, re-send on `lost`, present a fresh token on `needs token`. Runs
/// until the session's acks stop (the bundle is gone) or a verdict makes the
/// anchor unavailable for this setup. The caller aborts it when the session
/// is replaced.
pub(crate) async fn run_anchoring(
    anchor: RouteAnchorHandle,
    primary: Arc<MultiHopClient>,
    mut serial: [u8; 32],
    tokens: Option<SessionTokenProvider>,
    mut acks: mpsc::UnboundedReceiver<RouteDownlink>,
    waits: [Duration; 5],
) {
    let mut token: Option<SessionToken> = None;
    loop {
        let Ok(sealed) = anchor.seal_anchor(&serial) else {
            anchor.set_state(AnchorState::Unavailable);
            return;
        };
        let Ok(request) = encode_control(&WarrenControlMessage::RouteAnchorRequest {
            sealed_anchor: sealed,
            session_token: token.map(Box::new),
        }) else {
            anchor.set_state(AnchorState::Unavailable);
            return;
        };
        // One sealed request per cycle, re-sent byte for byte: the exit
        // answers a repeat from its last verdict without calling its control
        // plane when only the ack was lost.
        let mut verdict = None;
        for wait in waits {
            if primary.send_packet(&request).is_err() {
                return;
            }
            match tokio::time::timeout(wait, next_ack(&mut acks)).await {
                Ok(Some(ack)) => {
                    verdict = Some(ack);
                    break;
                }
                Ok(None) => return,
                Err(_) => {}
            }
        }
        let Some((status, max_routes)) = verdict else {
            // An older main exit drops the request, a control plane that is
            // down never answers: routes fall back to tokens.
            anchor.set_state(AnchorState::Unavailable);
            return;
        };
        match status {
            RouteAnchorStatus::Bound => {
                anchor.set_state(AnchorState::Anchored { max_routes });
                token = None;
                // Stay on the session: the exit reports a lost anchor.
                loop {
                    match next_ack(&mut acks).await {
                        None => return,
                        Some((RouteAnchorStatus::Lost, _)) => break,
                        Some(_) => {}
                    }
                }
                tracing::info!("route anchor lost; registering it again");
            }
            RouteAnchorStatus::Lost => {}
            RouteAnchorStatus::NeedsToken => {
                let lead = tokens
                    .as_ref()
                    .and_then(|provider| provider().into_iter().next());
                let Some(lead) = lead else {
                    anchor.set_state(AnchorState::Unavailable);
                    return;
                };
                serial = session_token_serial(&lead);
                token = Some(lead);
            }
            RouteAnchorStatus::Unavailable => {
                anchor.set_state(AnchorState::Unavailable);
                if tokio::time::timeout(ANCHOR_UNAVAILABLE_RETRY, drain_until_closed(&mut acks))
                    .await
                    .is_ok()
                {
                    return;
                }
            }
            // Not eligible, refused, or a status this build does not know.
            _ => {
                anchor.set_state(AnchorState::Unavailable);
                return;
            }
        }
    }
}

/// The next anchor ack, skipping any other route message. `None` once the
/// intercept is gone with its bundle.
async fn next_ack(
    acks: &mut mpsc::UnboundedReceiver<RouteDownlink>,
) -> Option<(RouteAnchorStatus, u16)> {
    loop {
        match acks.recv().await? {
            RouteDownlink::Ack { status, max_routes } => return Some((status, max_routes)),
            RouteDownlink::Ended(_) => {}
        }
    }
}

/// Resolves once the intercept is gone; consumes whatever arrives meanwhile.
async fn drain_until_closed(acks: &mut mpsc::UnboundedReceiver<RouteDownlink>) {
    while acks.recv().await.is_some() {}
}

/// The route setup request for `exit_id`, with a fresh locator.
pub(crate) fn route_request(
    admission: &RouteSessionAdmission,
    exit_id: &ExitId,
    prefer_ipv4: Option<std::net::Ipv4Addr>,
    wants_ipv6: bool,
    wants_daita: bool,
) -> Result<WarrenControlMessage, RouteSealError> {
    Ok(WarrenControlMessage::IpRequestRoute {
        prefer_ipv4: prefer_ipv4.map(|ip| ip.octets()),
        wants_ipv6,
        route_locator: admission.anchor.seal_locator(exit_id)?,
        wants_daita,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use warrenguard_multihop::RouteKemSecretKey;

    fn handle() -> (RouteKemSecretKey, RouteAnchorHandle) {
        let key = RouteKemSecretKey::derive(&[0x71; 32], 1).expect("kem");
        let handle = RouteAnchorHandle::new(RouteAnchorConfig {
            kem: key.public_key().clone(),
        });
        (key, handle)
    }

    #[test]
    fn a_handle_seals_one_secret_for_every_exit_and_never_shows_it() {
        let (key, handle) = handle();
        let a = ExitId::from_bytes([1; 16]);
        let b = ExitId::from_bytes([2; 16]);
        let to_a = key
            .open_locator(&handle.seal_locator(&a).expect("seal"), &a)
            .expect("opens for its exit");
        let to_b = key
            .open_locator(&handle.seal_locator(&b).expect("seal"), &b)
            .expect("opens for its exit");
        assert_eq!(
            to_a.anchor_ref(),
            to_b.anchor_ref(),
            "one anchor, every exit"
        );
        let anchor = key
            .open_anchor(&handle.seal_anchor(&[9; 32]).expect("seal"), &[9; 32])
            .expect("the anchor blob is bound to the serial");
        assert_eq!(anchor.anchor_ref(), to_a.anchor_ref());
        let rendered = format!("{handle:?}");
        assert_eq!(
            rendered, "RouteAnchorHandle { state: Unanchored, .. }",
            "Debug renders the state only"
        );
    }

    #[test]
    fn two_handles_hold_two_secrets() {
        let (key, one) = handle();
        let other = RouteAnchorHandle::new(RouteAnchorConfig {
            kem: key.public_key().clone(),
        });
        let exit = ExitId::from_bytes([1; 16]);
        let a = key
            .open_locator(&one.seal_locator(&exit).expect("seal"), &exit)
            .expect("open");
        let b = key
            .open_locator(&other.seal_locator(&exit).expect("seal"), &exit)
            .expect("open");
        assert_ne!(a.anchor_ref(), b.anchor_ref());
        assert_ne!(
            RouteSessionAdmission {
                anchor: one,
                exit_offers_routes: true
            },
            RouteSessionAdmission {
                anchor: other,
                exit_offers_routes: true
            }
        );
    }

    #[test]
    fn only_route_messages_are_intercepted() {
        assert_eq!(
            RouteDownlink::from_control(&WarrenControlMessage::RouteAnchorAck {
                status: 5,
                max_routes: 0
            }),
            Some(RouteDownlink::Ack {
                status: RouteAnchorStatus::Lost,
                max_routes: 0
            })
        );
        assert_eq!(
            RouteDownlink::from_control(&WarrenControlMessage::RouteEnded { reason_code: 1 }),
            Some(RouteDownlink::Ended(RouteEndReason::AnchorGone))
        );
        assert_eq!(
            RouteDownlink::from_control(&WarrenControlMessage::ExitDraining {
                deadline_unix_secs: 1,
                reason_code: 0
            }),
            None,
            "a drain advisory stays with the pump's consumer"
        );
    }
}
