//! Route admission by anchor on the exit: the per-connection control
//! emitter, the anchor handler of a main session, and the registry state a
//! deployer's renewal loop reads and acts on.
//!
//! The engine never opens a sealed blob and never talks to a control plane:
//! verdicts come from the injected [`RouteAdmitter`], token spends from the
//! [`SessionTokenAdmitter`]. What the engine owns is the per-session
//! bookkeeping those verdicts hang on (which main session is anchored and on
//! which lease serial, which route session presented which locator) and the
//! sealed downlink messages that report them to the client.
//!
//! No-log: nothing here logs a serial, a route serial, a blob or a digest.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use quinn::{Connection, SendDatagramError, VarInt};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use warrenguard_multihop::{
    RouteAnchorStatus, RouteEndReason, RouteRejectCode, SEALED_TO_API_LEN, SealedToApi,
    WARREN_MH_REJECTED, WarrenControlMessage, encode_control,
};
use warrenguard_server::{
    AnchorVerdict, RouteAdmission, RouteAdmitter, SessionTokenAdmitter, TOKEN_SERIAL_LEN,
    TokenAdmission,
};
use warrenguard_wire::{SessionToken, WarrenPubkey};
use zeroize::Zeroizing;

use super::{ClosableConn, MultihopSessionRegistry, RouteSessionEndObserver, SessionKey};
use crate::datapath::AnchorRequestFrame;
use crate::ip_pool::ConnId;
use crate::metrics::{AnchorRequestResult, RouteTeardown, route_admission_metrics};

/// Downlink control messages queued per connection. Anchor acks and route
/// ends are rare; a full queue drops the message, which the client's retry
/// schedule (or the exit's next renewal tick) covers.
pub(super) const CONTROL_QUEUE: usize = 16;

/// A session calls its control plane at most once per this interval for its
/// anchor, whatever the client sends (doc 107 section 9.1).
const ANCHOR_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// `RouteEnded` rides unreliable datagrams: it is sent this many times,
/// spaced by [`ROUTE_END_SPACING`], before the close that would discard any
/// datagram still queued.
const ROUTE_END_REPEATS: u32 = 3;
const ROUTE_END_SPACING: Duration = Duration::from_millis(50);

/// Ceiling on one anchor registration (token spend plus policy call). A
/// policy that never answers must not leave the session's call in flight
/// forever, which would stop it from ever anchoring again.
const ANCHOR_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on one route admission call. Under the client's own setup
/// round-trip bound, so the sealed refusal still reaches it.
pub(super) const ROUTE_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Route admissions this exit forwards to its policy per second, sustained
/// and in a burst, and at most this many at once. A locator cannot be checked
/// offline, so without this any peer able to complete a setup could make the
/// exit spend its control-plane budget on forged locators; the budget left
/// over keeps the anchor registrations of its admitted sessions going.
const ROUTE_OPEN_RATE_PER_SEC: f64 = 200.0;
const ROUTE_OPEN_BURST: f64 = 400.0;
const ROUTE_OPEN_MAX_IN_FLIGHT: usize = 128;

/// The route policy of an exit with its local admission limits.
#[derive(Clone)]
pub(crate) struct RouteGate {
    pub(super) admitter: Arc<dyn RouteAdmitter>,
    bucket: Arc<Mutex<super::TokenBucket>>,
    in_flight: Arc<tokio::sync::Semaphore>,
}

impl RouteGate {
    pub(super) fn new(admitter: Arc<dyn RouteAdmitter>) -> Self {
        Self::with_limits(
            admitter,
            ROUTE_OPEN_RATE_PER_SEC,
            ROUTE_OPEN_BURST,
            ROUTE_OPEN_MAX_IN_FLIGHT,
        )
    }

    fn with_limits(
        admitter: Arc<dyn RouteAdmitter>,
        rate_per_sec: f64,
        burst: f64,
        max_in_flight: usize,
    ) -> Self {
        Self {
            admitter,
            bucket: Arc::new(Mutex::new(super::TokenBucket::new(
                rate_per_sec,
                burst,
                Instant::now(),
            ))),
            in_flight: Arc::new(tokio::sync::Semaphore::new(max_in_flight)),
        }
    }

    /// Ask the policy about `locator`, within the local limits: past them, or
    /// past [`ROUTE_CALL_TIMEOUT`], the route is refused as unavailable.
    pub(super) async fn admit_route(&self, locator: &SealedToApi) -> RouteAdmission {
        let unavailable = RouteAdmission::Refuse(RouteRejectCode::Unavailable);
        if !self.bucket.lock().try_take(Instant::now()) {
            return unavailable;
        }
        let Ok(_permit) = self.in_flight.try_acquire() else {
            return unavailable;
        };
        tokio::time::timeout(ROUTE_CALL_TIMEOUT, self.admitter.admit_route(locator))
            .await
            .unwrap_or(unavailable)
    }
}

/// What a connection's control emitter is asked to send.
#[derive(Debug)]
pub(crate) enum Outbound {
    /// Seal and send one control datagram.
    Control(WarrenControlMessage),
    /// Tell a route session why it ends, then close it.
    EndRoute(RouteEndReason),
}

/// Sender half of a connection's control emitter.
pub(crate) type ControlTx = mpsc::Sender<Outbound>;

/// Spawn the task that seals and sends a connection's downlink control
/// messages with its CURRENT session (so a rekey is followed, as the drain
/// emitter does). `seal_current` is the only version-specific part.
pub(super) fn spawn_control_emitter<F>(
    mut rx: mpsc::Receiver<Outbound>,
    seal_current: F,
    reverse_seq: Arc<std::sync::atomic::AtomicU64>,
    conn: Connection,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(&[u8], u64) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let send = |msg: &WarrenControlMessage| -> bool {
            let Ok(plaintext) = encode_control(msg) else {
                return true;
            };
            let seq = reverse_seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            match seal_current(&plaintext, seq) {
                Some(bytes) => !matches!(
                    conn.send_datagram(bytes.into()),
                    Err(SendDatagramError::ConnectionLost(_))
                ),
                None => true,
            }
        };
        while let Some(out) = rx.recv().await {
            match out {
                Outbound::Control(msg) => {
                    if !send(&msg) {
                        return;
                    }
                }
                Outbound::EndRoute(reason) => {
                    let msg = WarrenControlMessage::RouteEnded {
                        reason_code: reason.code(),
                    };
                    for i in 0..ROUTE_END_REPEATS {
                        if !send(&msg) {
                            return;
                        }
                        if i + 1 < ROUTE_END_REPEATS {
                            tokio::time::sleep(ROUTE_END_SPACING).await;
                        }
                    }
                    tokio::time::sleep(ROUTE_END_SPACING).await;
                    // The same single opaque close every policy refusal uses:
                    // the relay learns nothing, the client read `RouteEnded`.
                    conn.close(VarInt::from_u32(WARREN_MH_REJECTED), &[]);
                    return;
                }
            }
        }
    })
}

/// One v7 main session's anchor bookkeeping, keyed by the serial the session
/// was admitted on (its registry key).
struct AnchorSlot {
    /// The serial whose lease the session holds now: the admission serial,
    /// or the serial of the token an anchor request presented since.
    lease_serial: [u8; TOKEN_SERIAL_LEN],
    /// The control plane bound the anchor and has not reported it lost.
    anchored: bool,
    /// A control-plane call for this session is running.
    in_flight: bool,
    /// When the last control-plane call started.
    last_call: Option<Instant>,
    /// Digest of the last request that reached the control plane, and its
    /// verdict: a byte-identical repeat is answered from it.
    last: Option<([u8; 32], AnchorVerdict)>,
}

impl AnchorSlot {
    fn new(serial: [u8; TOKEN_SERIAL_LEN]) -> Self {
        Self {
            lease_serial: serial,
            anchored: false,
            in_flight: false,
            last_call: None,
            last: None,
        }
    }
}

/// The route admission state of a [`MultihopSessionRegistry`].
#[derive(Default)]
pub(super) struct RegistryRouteState {
    control: Mutex<HashMap<(SessionKey, ConnId), ControlTx>>,
    anchors: Mutex<HashMap<[u8; TOKEN_SERIAL_LEN], AnchorSlot>>,
    /// Locator each live route session presented, retained so the deployer
    /// can re-submit it after its control plane restarted.
    locators: Mutex<HashMap<[u8; 32], Zeroizing<[u8; SEALED_TO_API_LEN]>>>,
    /// Route serials the policy ended, so their teardown is not also counted
    /// as a plain close.
    ended_by_policy: Mutex<HashSet<[u8; 32]>>,
    end_observer: OnceLock<RouteSessionEndObserver>,
}

impl RegistryRouteState {
    pub(super) fn attach_control(&self, key: SessionKey, conn_id: ConnId, tx: ControlTx) {
        self.control.lock().insert((key, conn_id), tx);
    }

    pub(super) fn detach_control(&self, key: SessionKey, conn_id: ConnId) {
        self.control.lock().remove(&(key, conn_id));
    }

    fn controls_of(&self, key: SessionKey) -> Vec<(ConnId, ControlTx)> {
        self.control
            .lock()
            .iter()
            .filter(|((k, _), _)| *k == key)
            .map(|((_, id), tx)| (*id, tx.clone()))
            .collect()
    }

    pub(super) fn retain_locator(&self, route_serial: [u8; 32], locator: &SealedToApi) {
        self.locators
            .lock()
            .insert(route_serial, Zeroizing::new(locator.to_bytes()));
    }

    /// Forget a route whose last connection ended, and count its teardown.
    /// Called under the `live` lock, so a session registering the same key
    /// cannot lose its fresh state to it.
    pub(super) fn forget_route(&self, route_serial: &[u8; 32]) {
        self.locators.lock().remove(route_serial);
        if !self.ended_by_policy.lock().remove(route_serial) {
            route_admission_metrics().record_teardown(RouteTeardown::Close);
        }
    }

    pub(super) fn end_observer(&self) -> Option<&RouteSessionEndObserver> {
        self.end_observer.get()
    }

    /// Forget a token session's anchor state and return the lease serial it
    /// held last. Called under the `live` lock, like [`Self::forget_route`].
    pub(super) fn forget_anchor(
        &self,
        key_serial: &[u8; TOKEN_SERIAL_LEN],
    ) -> Option<[u8; TOKEN_SERIAL_LEN]> {
        self.anchors
            .lock()
            .remove(key_serial)
            .map(|slot| slot.lease_serial)
    }

    /// The lease serial of each token session key, in order (the key itself
    /// for a session never rebound).
    pub(super) fn lease_serials_of(
        &self,
        keys: &[[u8; TOKEN_SERIAL_LEN]],
    ) -> Vec<[u8; TOKEN_SERIAL_LEN]> {
        let anchors = self.anchors.lock();
        keys.iter()
            .map(|key| anchors.get(key).map_or(*key, |slot| slot.lease_serial))
            .collect()
    }

    /// A key is registered afresh: no state of an earlier session under the
    /// same key may carry over. Called under the `live` lock.
    pub(super) fn reset_for_new_session(&self, key: SessionKey) {
        match key {
            SessionKey::TokenSerial(serial) => {
                self.anchors.lock().remove(serial.as_bytes());
            }
            SessionKey::Route(serial) => {
                self.ended_by_policy.lock().remove(serial.as_bytes());
            }
            SessionKey::Wallet(_) => {}
        }
    }
}

/// What the rx pump needs to hand an anchor request over. Built once per
/// connection after its setup.
pub(crate) struct AnchorContext {
    pub(super) registry: Option<Arc<MultihopSessionRegistry>>,
    pub(super) key: Option<SessionKey>,
    pub(super) reply: ControlTx,
    pub(super) token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,
    pub(super) route: Option<RouteGate>,
}

impl AnchorContext {
    /// Handle one anchor request read off this connection's uplink.
    /// `plaintext` is the request as it arrived, for the repeat check.
    pub(crate) fn submit(&self, plaintext: &[u8], frame: AnchorRequestFrame) {
        let (Some(registry), Some(SessionKey::TokenSerial(serial)), Some(route)) =
            (self.registry.as_ref(), self.key, self.route.as_ref())
        else {
            // A wallet session never anchors (it would join a pubkey to the
            // route exits on the control plane), nor does a route session, a
            // session with no identity, or any session of an exit with route
            // admission off.
            route_admission_metrics().record_anchor(AnchorRequestResult::NotEligible);
            send_ack(
                &self.reply,
                AnchorVerdict::status(RouteAnchorStatus::NotEligible),
            );
            return;
        };
        registry.handle_anchor_request(
            *serial.as_bytes(),
            Sha256::digest(plaintext).into(),
            frame,
            self.reply.clone(),
            self.token_admitter.clone(),
            Arc::clone(&route.admitter),
        );
    }
}

fn send_ack(reply: &ControlTx, verdict: AnchorVerdict) {
    let _ = reply.try_send(Outbound::Control(WarrenControlMessage::RouteAnchorAck {
        status: verdict.status.code(),
        max_routes: verdict.max_routes,
    }));
}

enum AnchorDecision {
    Repeat(AnchorVerdict),
    Throttled,
    Call([u8; TOKEN_SERIAL_LEN]),
    Gone,
}

/// What rebinding a session to a freshly spent serial came to.
enum Rebind {
    /// The session holds the new lease now.
    Done,
    /// Another live session of this exit holds that serial: never rebind onto
    /// it, or the other session's lease would be released while it serves.
    HeldElsewhere,
    /// The session ended meanwhile.
    Gone,
}

impl<C: ClosableConn> MultihopSessionRegistry<C> {
    /// Hook the control emitter of one connection to its session, so the
    /// registry can reach the client (anchor lost, route ended).
    pub(super) fn attach_control(&self, key: SessionKey, conn_id: ConnId, tx: ControlTx) {
        self.route.attach_control(key, conn_id, tx);
    }

    fn handle_anchor_request(
        self: &Arc<Self>,
        key_serial: [u8; TOKEN_SERIAL_LEN],
        digest: [u8; 32],
        frame: AnchorRequestFrame,
        reply: ControlTx,
        token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,
        route_admitter: Arc<dyn RouteAdmitter>,
    ) {
        let key = SessionKey::TokenSerial(WarrenPubkey::from_bytes(key_serial));
        // `live` then `anchors`, the one order every path takes: the slot is
        // created only while the session is known live, and its removal at
        // the session's end happens under `live` too.
        let live = self.live.lock();
        let decision = if live.contains_key(&key) {
            let mut anchors = self.route.anchors.lock();
            let slot = anchors
                .entry(key_serial)
                .or_insert_with(|| AnchorSlot::new(key_serial));
            let now = Instant::now();
            match slot.last {
                Some((last_digest, verdict)) if last_digest == digest => {
                    AnchorDecision::Repeat(verdict)
                }
                _ if slot.in_flight
                    || slot
                        .last_call
                        .is_some_and(|at| now.duration_since(at) < ANCHOR_MIN_INTERVAL) =>
                {
                    AnchorDecision::Throttled
                }
                _ => {
                    slot.in_flight = true;
                    slot.last_call = Some(now);
                    AnchorDecision::Call(slot.lease_serial)
                }
            }
        } else {
            AnchorDecision::Gone
        };
        drop(live);
        match decision {
            AnchorDecision::Gone => {}
            AnchorDecision::Repeat(verdict) => {
                route_admission_metrics().record_anchor(AnchorRequestResult::Deduplicated);
                send_ack(&reply, verdict);
            }
            AnchorDecision::Throttled => {
                route_admission_metrics().record_anchor(AnchorRequestResult::Throttled);
            }
            AnchorDecision::Call(lease_serial) => {
                let registry = Arc::clone(self);
                tokio::spawn(async move {
                    let verdict = tokio::time::timeout(
                        ANCHOR_CALL_TIMEOUT,
                        registry.resolve_anchor(
                            key_serial,
                            lease_serial,
                            frame,
                            token_admitter,
                            route_admitter,
                        ),
                    )
                    .await
                    .unwrap_or(AnchorVerdict::status(RouteAnchorStatus::Unavailable));
                    if let Some(slot) = registry.route.anchors.lock().get_mut(&key_serial) {
                        slot.in_flight = false;
                        slot.anchored = verdict.status == RouteAnchorStatus::Bound;
                        slot.last = Some((digest, verdict));
                    }
                    route_admission_metrics()
                        .record_anchor(AnchorRequestResult::of_status(verdict.status));
                    send_ack(&reply, verdict);
                });
            }
        }
    }

    /// The control-plane side of one anchor request: spend a presented token
    /// and rebind the session to it first, then ask the policy.
    async fn resolve_anchor(
        &self,
        key_serial: [u8; TOKEN_SERIAL_LEN],
        lease_serial: [u8; TOKEN_SERIAL_LEN],
        frame: AnchorRequestFrame,
        token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,
        route_admitter: Arc<dyn RouteAdmitter>,
    ) -> AnchorVerdict {
        let AnchorRequestFrame {
            sealed_anchor,
            session_token,
        } = frame;
        let lease_serial = match session_token {
            None => lease_serial,
            Some(token) => {
                let Some(admitter) = token_admitter else {
                    return AnchorVerdict::status(RouteAnchorStatus::Refused);
                };
                let token: SessionToken = *token;
                match admitter.admit(std::slice::from_ref(&token)).await {
                    TokenAdmission::Admit { serial } => match self.rebind(key_serial, serial) {
                        Rebind::Done => serial,
                        Rebind::HeldElsewhere | Rebind::Gone => {
                            return AnchorVerdict::status(RouteAnchorStatus::Refused);
                        }
                    },
                    _ => return AnchorVerdict::status(RouteAnchorStatus::Refused),
                }
            }
        };
        route_admitter.anchor(&lease_serial, &sealed_anchor).await
    }

    /// Make the session keyed by `key_serial` hold the lease of `new`, the
    /// serial of a token its anchor request just spent. The serial it leaves
    /// behind is reported ended so the deployer releases it; the sticky
    /// allocation keeps its key. Refused when another live session of this
    /// exit holds `new` (the control plane re-admits a same-exit duplicate,
    /// so only this registry can tell), and when the session ended
    /// meanwhile, in which case `new` is released since nobody holds it.
    fn rebind(&self, key_serial: [u8; TOKEN_SERIAL_LEN], new: [u8; TOKEN_SERIAL_LEN]) -> Rebind {
        let key = SessionKey::TokenSerial(WarrenPubkey::from_bytes(key_serial));
        let (outcome, release) = {
            let live = self.live.lock();
            let mut anchors = self.route.anchors.lock();
            let held_elsewhere = live.keys().any(|other| match other {
                SessionKey::TokenSerial(other) if *other.as_bytes() != key_serial => {
                    let other = *other.as_bytes();
                    anchors.get(&other).map_or(other, |slot| slot.lease_serial) == new
                }
                _ => false,
            });
            if held_elsewhere {
                (Rebind::HeldElsewhere, None)
            } else {
                match (live.contains_key(&key), anchors.get_mut(&key_serial)) {
                    (true, Some(slot)) => {
                        let old = std::mem::replace(&mut slot.lease_serial, new);
                        (Rebind::Done, (old != new).then_some(old))
                    }
                    _ => (Rebind::Gone, Some(new)),
                }
            }
        };
        if let (Some(serial), Some(observer)) = (release, self.token_end_observer.get()) {
            observer(serial);
        }
        outcome
    }

    /// Lease serials of the live v7 main sessions whose anchor is bound: the
    /// anchor list of the deployer's renewal batch.
    #[must_use]
    pub fn live_anchor_serials(&self) -> Vec<[u8; TOKEN_SERIAL_LEN]> {
        let live: Vec<[u8; TOKEN_SERIAL_LEN]> = self
            .live
            .lock()
            .keys()
            .filter_map(|key| match key {
                SessionKey::TokenSerial(serial) => Some(*serial.as_bytes()),
                _ => None,
            })
            .collect();
        let anchors = self.route.anchors.lock();
        live.iter()
            .filter_map(|key| anchors.get(key))
            .filter(|slot| slot.anchored)
            .map(|slot| slot.lease_serial)
            .collect()
    }

    /// The deployer's renewal found no anchor for the session holding the
    /// lease of `lease_serial`: tell the client (`RouteAnchorAck{lost}` on
    /// every connection of the session) so it resends its request. The main
    /// session itself is untouched. Returns whether a live session was told.
    pub fn notify_anchor_lost(&self, lease_serial: &[u8; TOKEN_SERIAL_LEN]) -> bool {
        let key_serial = {
            let mut anchors = self.route.anchors.lock();
            let Some((key_serial, slot)) = anchors
                .iter_mut()
                .find(|(_, slot)| &slot.lease_serial == lease_serial)
            else {
                return false;
            };
            slot.anchored = false;
            slot.last = None;
            *key_serial
        };
        let key = SessionKey::TokenSerial(WarrenPubkey::from_bytes(key_serial));
        // One connection is enough: an ack carries no correlation, so one per
        // bonded leg would read as several verdicts on the client.
        let Some((_, tx)) = self.route.controls_of(key).into_iter().next() else {
            return false;
        };
        send_ack(&tx, AnchorVerdict::status(RouteAnchorStatus::Lost));
        route_admission_metrics().record_anchor(AnchorRequestResult::LostSent);
        true
    }

    /// Route serials of the route sessions holding at least one live
    /// connection: the route list of the deployer's renewal batch.
    #[must_use]
    pub fn live_route_serials(&self) -> Vec<[u8; 32]> {
        self.live
            .lock()
            .keys()
            .filter_map(|key| match key {
                SessionKey::Route(serial) => Some(*serial.as_bytes()),
                _ => None,
            })
            .collect()
    }

    /// Whether a route session under `route_serial` holds a live connection.
    #[must_use]
    pub fn is_route_serial_live(&self, route_serial: &[u8; 32]) -> bool {
        self.live
            .lock()
            .contains_key(&SessionKey::Route(WarrenPubkey::from_bytes(*route_serial)))
    }

    /// Number of live route sessions (the `warren_exit_route_sessions_live`
    /// gauge). A count only.
    #[must_use]
    pub fn live_route_session_count(&self) -> usize {
        self.live
            .lock()
            .keys()
            .filter(|key| matches!(key, SessionKey::Route(_)))
            .count()
    }

    /// The locator the live route session under `route_serial` presented,
    /// for the deployer to re-submit when its renewal reports the route
    /// unknown (a restarted control plane). `None` once the session ended.
    #[must_use]
    pub fn route_locator(&self, route_serial: &[u8; 32]) -> Option<SealedToApi> {
        self.route
            .locators
            .lock()
            .get(route_serial)
            .map(|bytes| SealedToApi::from_bytes(bytes))
    }

    /// End the route session under `route_serial` because the policy says so
    /// (its anchor is gone): every connection gets `RouteEnded{reason}` and
    /// is then closed with the opaque policy close. Returns how many
    /// connections were ended. Idempotent.
    pub fn end_route(&self, route_serial: &[u8; 32], reason: RouteEndReason) -> usize
    where
        C: Clone,
    {
        let key = SessionKey::Route(WarrenPubkey::from_bytes(*route_serial));
        let conns: Vec<(ConnId, C)> = {
            let live = self.live.lock();
            let Some(conns) = live.get(&key) else {
                return 0;
            };
            // Marked under `live`, so it cannot outlive the session it ends.
            if self.route.ended_by_policy.lock().insert(*route_serial) {
                route_admission_metrics().record_teardown(match reason {
                    RouteEndReason::AnchorGone => RouteTeardown::AnchorGone,
                    _ => RouteTeardown::Close,
                });
            }
            conns.iter().map(|(id, c)| (*id, c.clone())).collect()
        };
        let controls: HashMap<ConnId, ControlTx> =
            self.route.controls_of(key).into_iter().collect();
        for (id, conn) in &conns {
            let told = controls
                .get(id)
                .is_some_and(|tx| tx.try_send(Outbound::EndRoute(reason)).is_ok());
            if !told {
                conn.close_rejected();
            }
        }
        conns.len()
    }

    /// Wire the callback told a route serial each time the last connection
    /// of that route session ends: the moment a deployer releases the route
    /// lease. Set once; returns `false`, keeping the first, when one is
    /// already wired.
    pub fn set_route_session_end_observer(&self, observer: RouteSessionEndObserver) -> bool {
        self.route.end_observer.set(observer).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use warrenguard_multihop::{RouteRejectCode, RouteSerial};
    use warrenguard_server::{BoxFuture, RouteAdmission};

    use super::*;

    #[derive(Clone, Default)]
    struct FakeConn {
        closes: Arc<AtomicUsize>,
    }

    impl ClosableConn for FakeConn {
        fn close_rejected(&self) {
            self.closes.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Records every call; answers `verdict`.
    struct FakePolicy {
        verdict: AnchorVerdict,
        anchor_calls: Mutex<Vec<[u8; 32]>>,
    }

    impl FakePolicy {
        fn answering(status: RouteAnchorStatus) -> Arc<Self> {
            Arc::new(Self {
                verdict: AnchorVerdict {
                    status,
                    max_routes: 32,
                },
                anchor_calls: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> Vec<[u8; 32]> {
            self.anchor_calls.lock().clone()
        }
    }

    impl RouteAdmitter for FakePolicy {
        fn admit_route<'a>(&'a self, _: &'a SealedToApi) -> BoxFuture<'a, RouteAdmission> {
            Box::pin(async { RouteAdmission::Refuse(RouteRejectCode::NotOffered) })
        }

        fn anchor<'a>(
            &'a self,
            lease_serial: &'a [u8; TOKEN_SERIAL_LEN],
            _: &'a SealedToApi,
        ) -> BoxFuture<'a, AnchorVerdict> {
            self.anchor_calls.lock().push(*lease_serial);
            Box::pin(async move { self.verdict })
        }
    }

    /// Admits every token on the serial of its first 32 bytes, or refuses.
    /// With a gate, each admission waits for it (and says it started).
    struct FakeTokens {
        admit: bool,
        gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    }

    impl SessionTokenAdmitter for FakeTokens {
        fn admit<'a>(&'a self, tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
            Box::pin(async move {
                if let Some((started, release)) = &self.gate {
                    started.notify_one();
                    release.notified().await;
                }
                if !self.admit {
                    return TokenAdmission::Denied;
                }
                let mut serial = [0u8; 32];
                serial.copy_from_slice(&tokens[0].0[..32]);
                TokenAdmission::Admit { serial }
            })
        }

        fn renew_live<'a>(&'a self, _: &'a [[u8; 32]]) -> BoxFuture<'a, ()> {
            Box::pin(async {})
        }
    }

    const MAIN: [u8; 32] = [0x10; 32];

    fn main_key() -> SessionKey {
        SessionKey::TokenSerial(WarrenPubkey::from_bytes(MAIN))
    }

    fn route_key(serial: [u8; 32]) -> SessionKey {
        SessionKey::Route(WarrenPubkey::from_bytes(serial))
    }

    fn registry_with_main() -> Arc<MultihopSessionRegistry<FakeConn>> {
        let registry = MultihopSessionRegistry::<FakeConn>::new();
        registry.register_key(main_key(), 1, FakeConn::default());
        registry
    }

    fn frame(fill: u8, token: Option<u8>) -> AnchorRequestFrame {
        AnchorRequestFrame {
            sealed_anchor: SealedToApi::from_bytes(&[fill; SEALED_TO_API_LEN]),
            session_token: token
                .map(|t| Box::new(SessionToken([t; warrenguard_wire::SESSION_TOKEN_LEN]))),
        }
    }

    fn request(
        registry: &Arc<MultihopSessionRegistry<FakeConn>>,
        digest: u8,
        frame: AnchorRequestFrame,
        reply: &ControlTx,
        tokens: Option<Arc<dyn SessionTokenAdmitter>>,
        policy: &Arc<FakePolicy>,
    ) {
        registry.handle_anchor_request(
            MAIN,
            [digest; 32],
            frame,
            reply.clone(),
            tokens,
            Arc::clone(policy) as Arc<dyn RouteAdmitter>,
        );
    }

    async fn next_ack(rx: &mut mpsc::Receiver<Outbound>) -> (u8, u16) {
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(Outbound::Control(WarrenControlMessage::RouteAnchorAck {
                status,
                max_routes,
            }))) => (status, max_routes),
            other => panic!("expected a RouteAnchorAck, got {other:?}"),
        }
    }

    async fn nothing_sent(rx: &mut mpsc::Receiver<Outbound>) {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err(), "no ack was expected");
    }

    #[tokio::test]
    async fn a_bound_anchor_is_acked_and_joins_the_renewal_list() {
        let registry = registry_with_main();
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let (tx, mut rx) = mpsc::channel(8);
        request(&registry, 1, frame(0xA1, None), &tx, None, &policy);
        assert_eq!(next_ack(&mut rx).await, (0, 32));
        assert_eq!(
            policy.calls(),
            vec![MAIN],
            "the policy is asked on the lease serial"
        );
        assert_eq!(registry.live_anchor_serials(), vec![MAIN]);
    }

    #[tokio::test]
    async fn a_byte_identical_repeat_is_answered_without_a_second_call() {
        let registry = registry_with_main();
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let (tx, mut rx) = mpsc::channel(8);
        request(&registry, 1, frame(0xA1, None), &tx, None, &policy);
        next_ack(&mut rx).await;
        request(&registry, 1, frame(0xA1, None), &tx, None, &policy);
        assert_eq!(
            next_ack(&mut rx).await,
            (0, 32),
            "answered from the last verdict"
        );
        assert_eq!(policy.calls().len(), 1, "a lost ack costs the API nothing");
    }

    #[tokio::test]
    async fn a_new_request_within_the_interval_is_throttled() {
        let registry = registry_with_main();
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let (tx, mut rx) = mpsc::channel(8);
        request(&registry, 1, frame(0xA1, None), &tx, None, &policy);
        next_ack(&mut rx).await;
        request(&registry, 2, frame(0xA2, None), &tx, None, &policy);
        nothing_sent(&mut rx).await;
        assert_eq!(
            policy.calls().len(),
            1,
            "at most one call per 2 s per session"
        );
    }

    #[tokio::test]
    async fn a_request_for_a_session_that_is_gone_is_dropped() {
        let registry = MultihopSessionRegistry::<FakeConn>::new();
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let (tx, mut rx) = mpsc::channel(8);
        request(&registry, 1, frame(0xA1, None), &tx, None, &policy);
        nothing_sent(&mut rx).await;
        assert!(policy.calls().is_empty());
    }

    #[tokio::test]
    async fn a_presented_token_is_spent_and_the_session_rebound_before_the_call() {
        let registry = registry_with_main();
        let ended = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&ended);
        assert!(registry.set_token_session_end_observer(Box::new(move |s| sink.lock().push(s))));
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let tokens: Arc<dyn SessionTokenAdmitter> = Arc::new(FakeTokens {
            admit: true,
            gate: None,
        });
        let (tx, mut rx) = mpsc::channel(8);
        request(
            &registry,
            1,
            frame(0xA1, Some(0x77)),
            &tx,
            Some(tokens),
            &policy,
        );
        assert_eq!(next_ack(&mut rx).await.0, 0);
        let fresh = [0x77; 32];
        assert_eq!(
            policy.calls(),
            vec![fresh],
            "the anchor attaches to the new lease"
        );
        assert_eq!(registry.live_token_serials(), vec![fresh]);
        assert!(registry.is_token_serial_live(&fresh));
        assert!(
            !registry.is_token_serial_live(&MAIN),
            "the admission serial is no longer this session's lease"
        );
        assert_eq!(
            *ended.lock(),
            vec![MAIN],
            "the left-behind lease is reported for release"
        );
        assert_eq!(registry.live_anchor_serials(), vec![fresh]);

        // When the session ends, the lease it held last is the one reported.
        registry.unregister_key(main_key(), 1);
        assert_eq!(*ended.lock(), vec![MAIN, fresh]);
    }

    #[tokio::test]
    async fn a_refused_token_is_acked_refused_without_asking_the_policy() {
        let registry = registry_with_main();
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let tokens: Arc<dyn SessionTokenAdmitter> = Arc::new(FakeTokens {
            admit: false,
            gate: None,
        });
        let (tx, mut rx) = mpsc::channel(8);
        request(
            &registry,
            1,
            frame(0xA1, Some(0x77)),
            &tx,
            Some(tokens),
            &policy,
        );
        assert_eq!(next_ack(&mut rx).await.0, RouteAnchorStatus::Refused.code());
        assert!(policy.calls().is_empty());
        assert_eq!(registry.live_token_serials(), vec![MAIN]);
        assert!(registry.live_anchor_serials().is_empty());
    }

    #[tokio::test]
    async fn a_lost_anchor_is_reported_and_the_next_request_reaches_the_policy() {
        let registry = registry_with_main();
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let (tx, mut rx) = mpsc::channel(8);
        registry.attach_control(main_key(), 1, tx.clone());
        request(&registry, 1, frame(0xA1, None), &tx, None, &policy);
        next_ack(&mut rx).await;

        assert!(registry.notify_anchor_lost(&MAIN));
        assert_eq!(next_ack(&mut rx).await.0, RouteAnchorStatus::Lost.code());
        assert!(registry.live_anchor_serials().is_empty());
        assert!(
            !registry.notify_anchor_lost(&[0x99; 32]),
            "no session holds that lease"
        );

        // The same bytes again after the interval: not a repeat any more.
        {
            let mut anchors = registry.route.anchors.lock();
            let slot = anchors.get_mut(&MAIN).expect("slot");
            slot.last_call = slot.last_call.map(|t| t - ANCHOR_MIN_INTERVAL);
        }
        request(&registry, 1, frame(0xA1, None), &tx, None, &policy);
        assert_eq!(next_ack(&mut rx).await.0, 0);
        assert_eq!(policy.calls().len(), 2);
    }

    #[tokio::test]
    async fn only_a_v7_main_session_of_an_exit_with_a_policy_may_anchor() {
        let policy: Arc<dyn RouteAdmitter> = FakePolicy::answering(RouteAnchorStatus::Bound);
        let wallet = SessionKey::Wallet(WarrenPubkey::from_bytes([0x33; 32]));
        let route = route_key([0x44; 32]);
        for (key, route_admitter) in [
            (Some(wallet), Some(Arc::clone(&policy))),
            (Some(route), Some(Arc::clone(&policy))),
            (None, Some(Arc::clone(&policy))),
            (Some(main_key()), None),
        ] {
            let (tx, mut rx) = mpsc::channel(8);
            let ctx = AnchorContext {
                registry: Some(MultihopSessionRegistry::new()),
                key,
                reply: tx,
                token_admitter: None,
                route: route_admitter.map(RouteGate::new),
            };
            ctx.submit(b"request", frame(0xA1, None));
            assert_eq!(
                next_ack(&mut rx).await.0,
                RouteAnchorStatus::NotEligible.code()
            );
        }
    }

    #[tokio::test]
    async fn a_route_session_is_listed_apart_and_ended_by_the_policy() {
        let registry = MultihopSessionRegistry::<FakeConn>::new();
        let serial = *RouteSerial::from_bytes([0x44; 32]).as_bytes();
        let told = FakeConn::default();
        let untold = FakeConn::default();
        registry.register_key(route_key(serial), 1, told.clone());
        registry.register_key(route_key(serial), 2, untold.clone());
        registry.register_key(main_key(), 3, FakeConn::default());
        let locator = SealedToApi::from_bytes(&[0x5C; SEALED_TO_API_LEN]);
        registry.route.retain_locator(serial, &locator);
        let (tx, mut rx) = mpsc::channel(8);
        registry.attach_control(route_key(serial), 1, tx);

        assert_eq!(registry.live_route_serials(), vec![serial]);
        assert_eq!(registry.live_route_session_count(), 1);
        assert!(registry.is_route_serial_live(&serial));
        assert_eq!(
            registry.live_token_serials(),
            vec![MAIN],
            "a route serial never holds a token lease"
        );
        assert_eq!(registry.route_locator(&serial), Some(locator));

        assert_eq!(registry.end_route(&serial, RouteEndReason::AnchorGone), 2);
        assert!(matches!(
            rx.try_recv(),
            Ok(Outbound::EndRoute(RouteEndReason::AnchorGone))
        ));
        assert_eq!(
            told.closes.load(Ordering::Acquire),
            0,
            "its emitter closes it"
        );
        assert_eq!(
            untold.closes.load(Ordering::Acquire),
            1,
            "no emitter: closed at once"
        );

        let ended = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&ended);
        assert!(registry.set_route_session_end_observer(Box::new(move |s| sink.lock().push(s))));
        registry.unregister_key(route_key(serial), 1);
        assert!(
            ended.lock().is_empty(),
            "a bonded leg leaving is not the end"
        );
        registry.unregister_key(route_key(serial), 2);
        assert_eq!(*ended.lock(), vec![serial]);
        assert_eq!(
            registry.route_locator(&serial),
            None,
            "the locator goes with it"
        );
        assert!(!registry.is_route_serial_live(&serial));
        assert_eq!(registry.end_route(&serial, RouteEndReason::AnchorGone), 0);
    }
    #[tokio::test]
    async fn a_token_whose_serial_another_session_holds_is_never_rebound_onto() {
        // Session B holds S2. A presents a token of S2 on its anchor request:
        // rebinding A onto S2 would report S1 ended while A still serves on
        // it, and the deployer would release a lease in use.
        let registry = registry_with_main();
        let other = [0x77; 32];
        registry.register_key(
            SessionKey::TokenSerial(WarrenPubkey::from_bytes(other)),
            2,
            FakeConn::default(),
        );
        let ended = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&ended);
        registry.set_token_session_end_observer(Box::new(move |s| sink.lock().push(s)));
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let tokens: Arc<dyn SessionTokenAdmitter> = Arc::new(FakeTokens {
            admit: true,
            gate: None,
        });
        let (tx, mut rx) = mpsc::channel(8);
        request(
            &registry,
            1,
            frame(0xA1, Some(0x77)),
            &tx,
            Some(tokens),
            &policy,
        );
        assert_eq!(next_ack(&mut rx).await.0, RouteAnchorStatus::Refused.code());
        assert!(ended.lock().is_empty(), "no lease is released");
        let mut live = registry.live_token_serials();
        live.sort_unstable();
        assert_eq!(live, vec![MAIN, other], "each session keeps its own lease");
        assert!(policy.calls().is_empty());
    }

    #[tokio::test]
    async fn a_session_that_ends_during_the_token_spend_leaves_no_state_behind() {
        let registry = registry_with_main();
        let ended = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&ended);
        registry.set_token_session_end_observer(Box::new(move |s| sink.lock().push(s)));
        let (started, release) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        let tokens: Arc<dyn SessionTokenAdmitter> = Arc::new(FakeTokens {
            admit: true,
            gate: Some((Arc::clone(&started), Arc::clone(&release))),
        });
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        let (tx, mut rx) = mpsc::channel(8);
        request(
            &registry,
            1,
            frame(0xA1, Some(0x77)),
            &tx,
            Some(tokens),
            &policy,
        );
        started.notified().await;

        registry.unregister_key(main_key(), 1);
        release.notify_one();
        assert_eq!(next_ack(&mut rx).await.0, RouteAnchorStatus::Refused.code());
        assert_eq!(
            *ended.lock(),
            vec![MAIN, [0x77; 32]],
            "the session's lease, then the one spent for nobody, are both released"
        );
        assert!(
            registry.route.anchors.lock().is_empty(),
            "no slot for a dead key"
        );

        // The same key registering again starts clean.
        registry.register_key(main_key(), 4, FakeConn::default());
        assert_eq!(registry.live_token_serials(), vec![MAIN]);
        assert!(registry.live_anchor_serials().is_empty());
    }

    #[tokio::test]
    async fn a_lost_anchor_is_reported_once_whatever_the_bond_width() {
        let registry = registry_with_main();
        registry.register_key(main_key(), 2, FakeConn::default());
        let (tx1, mut rx1) = mpsc::channel(8);
        let (tx2, mut rx2) = mpsc::channel(8);
        registry.attach_control(main_key(), 1, tx1.clone());
        registry.attach_control(main_key(), 2, tx2);
        let policy = FakePolicy::answering(RouteAnchorStatus::Bound);
        request(&registry, 1, frame(0xA1, None), &tx1, None, &policy);
        next_ack(&mut rx1).await;
        assert!(registry.notify_anchor_lost(&MAIN));
        let lost = usize::from(rx1.try_recv().is_ok()) + usize::from(rx2.try_recv().is_ok());
        assert_eq!(lost, 1, "one lost ack per session, not per leg");
    }

    /// Never answers.
    struct SilentPolicy;

    impl RouteAdmitter for SilentPolicy {
        fn admit_route<'a>(&'a self, _: &'a SealedToApi) -> BoxFuture<'a, RouteAdmission> {
            Box::pin(std::future::pending())
        }

        fn anchor<'a>(
            &'a self,
            _: &'a [u8; TOKEN_SERIAL_LEN],
            _: &'a SealedToApi,
        ) -> BoxFuture<'a, AnchorVerdict> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_policy_that_never_answers_cannot_wedge_the_anchor_or_the_setup() {
        let registry = registry_with_main();
        let (tx, mut rx) = mpsc::channel(8);
        registry.handle_anchor_request(
            MAIN,
            [1; 32],
            frame(0xA1, None),
            tx.clone(),
            None,
            Arc::new(SilentPolicy),
        );
        // The paused clock jumps to the call's own deadline first.
        match tokio::time::timeout(ANCHOR_CALL_TIMEOUT * 3, rx.recv()).await {
            Ok(Some(Outbound::Control(WarrenControlMessage::RouteAnchorAck {
                status, ..
            }))) => {
                assert_eq!(status, RouteAnchorStatus::Unavailable.code());
            }
            other => panic!("expected an unavailable ack, got {other:?}"),
        }
        assert!(
            !registry
                .route
                .anchors
                .lock()
                .get(&MAIN)
                .expect("slot")
                .in_flight,
            "the session may anchor again"
        );

        let gate = RouteGate::new(Arc::new(SilentPolicy));
        let locator = SealedToApi::from_bytes(&[0x11; SEALED_TO_API_LEN]);
        let verdict = tokio::spawn({
            let gate = gate.clone();
            async move { gate.admit_route(&locator).await }
        });
        assert_eq!(
            verdict.await.expect("no panic"),
            RouteAdmission::Refuse(RouteRejectCode::Unavailable)
        );
    }

    #[tokio::test]
    async fn route_admissions_past_the_local_limits_are_refused_unavailable() {
        let policy: Arc<dyn RouteAdmitter> = Arc::new(SilentPolicy);
        let locator = SealedToApi::from_bytes(&[0x11; SEALED_TO_API_LEN]);
        // A bucket of two: the third admission in the same instant is refused
        // without reaching the policy.
        let gate = RouteGate::with_limits(Arc::clone(&policy), 0.0, 2.0, 16);
        let pending: Vec<_> = (0..2)
            .map(|_| {
                let gate = gate.clone();
                tokio::spawn(async move { gate.admit_route(&locator).await })
            })
            .collect();
        tokio::task::yield_now().await;
        assert_eq!(
            gate.admit_route(&locator).await,
            RouteAdmission::Refuse(RouteRejectCode::Unavailable)
        );
        // One in flight at most: the second waits on nothing, it is refused.
        let narrow = RouteGate::with_limits(policy, 100.0, 100.0, 1);
        let first = tokio::spawn({
            let narrow = narrow.clone();
            async move { narrow.admit_route(&locator).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            narrow.admit_route(&locator).await,
            RouteAdmission::Refuse(RouteRejectCode::Unavailable)
        );
        first.abort();
        for task in pending {
            task.abort();
        }
    }
}
