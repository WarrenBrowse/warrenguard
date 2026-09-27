//! Epoch lease refresh on the exit: the handler of a token session's
//! `LeaseRefresh` datagrams, and the registry calls a deployer's renewal loop
//! makes once a session's lease belongs to a past epoch.
//!
//! A session admitted on a token holds its fleet-wide lease only within the
//! token's epoch. The engine does not know epochs: the deployer tells it
//! which lease went stale ([`MultihopSessionRegistry::lease_refresh_due`]),
//! and the engine asks the client for a token of the current epoch, spends
//! the one the client presents through the injected
//! [`SessionTokenAdmitter`] and moves the session's lease onto its serial
//! (the rebind an anchor request with a token also makes). Whether and when
//! a session that does not refresh is ended is the deployer's call
//! ([`MultihopSessionRegistry::end_expired_leases`]); the registry says how
//! long the lease has been stale and whether the client announced it
//! refreshes.
//!
//! No-log: nothing here logs a serial, a token or a digest.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

// The tokio clock, so the throttle and the staleness follow a paused test
// clock; it is the system's monotonic clock otherwise.
use tokio::time::Instant;

use sha2::{Digest, Sha256};
use warrenguard_multihop::{LeaseRefreshStatus, WarrenControlMessage};
use warrenguard_server::{SessionTokenAdmitter, TOKEN_SERIAL_LEN, TokenAdmission};
use warrenguard_wire::{SessionToken, WarrenPubkey};

use super::route::{AnchorContext, AnchorSlot, ControlTx, Outbound, Rebind};
use super::{ClosableConn, MultihopSessionRegistry, SessionKey};
use crate::ip_pool::ConnId;
use crate::metrics::{LeaseRefreshResult, lease_refresh_metrics};

/// A session spends at most one refresh token per this interval, whatever
/// the client sends.
const REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Ceiling on one refresh spend. A control plane that never answers must not
/// leave the session's spend in flight forever, which would stop it from
/// ever refreshing.
const REFRESH_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// One token session's lease refresh state, held in its [`AnchorSlot`].
#[derive(Default)]
pub(super) struct LeaseSlot {
    /// The client announced it presents a token of each new epoch.
    capable: bool,
    /// When the deployer first reported the session's lease stale, cleared
    /// by a refresh.
    stale_since: Option<Instant>,
    /// A spend for this session is running.
    in_flight: bool,
    /// When the last spend started.
    last_call: Option<Instant>,
    /// Digest of the last request that reached the admitter, and its verdict:
    /// a byte-identical repeat is answered from it. Never an `unavailable`
    /// verdict, which the client answers by presenting the same token again.
    last: Option<([u8; 32], LeaseRefreshStatus)>,
    /// The deployer's period (its epoch) in which this lease was last counted
    /// stale.
    counted_period: Option<u64>,
}

impl LeaseSlot {
    /// The session holds a lease of the current epoch again.
    pub(super) fn refreshed(&mut self) {
        self.stale_since = None;
    }
}

/// A session to end, with its connections.
type ExpiringSession<C> = (SessionKey, Vec<(ConnId, C)>);

/// What the registry knows of a session whose lease the deployer reported
/// stale, for the deployer to decide whether to end it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleLease {
    /// How long ago the deployer first reported this lease stale.
    pub stale_for: Duration,
    /// Whether the session's client announced it refreshes its lease.
    pub capable: bool,
    /// Whether this report is the first to find the lease stale in the
    /// deployer's current period, the one the stale counters count.
    pub first_in_period: bool,
}

fn send_ack(reply: &ControlTx, status: LeaseRefreshStatus) {
    let _ = reply.try_send(Outbound::Control(WarrenControlMessage::LeaseRefreshAck {
        status: status.code(),
    }));
}

enum RefreshDecision {
    Repeat(LeaseRefreshStatus),
    Throttled,
    Call,
}

impl AnchorContext {
    /// Handle one `LeaseRefresh` read off this connection's uplink.
    /// `plaintext` is the request as it arrived, for the repeat check.
    pub(crate) fn submit_lease_refresh(
        &self,
        plaintext: &[u8],
        session_token: Option<Box<SessionToken>>,
    ) {
        let (Some(registry), Some(SessionKey::TokenSerial(serial)), Some(admitter)) = (
            self.registry.as_ref(),
            self.key,
            self.token_admitter.as_ref(),
        ) else {
            // Only a session admitted on a token holds a lease to refresh: a
            // wallet session, a route session, or a session of an exit with no
            // token admitter has none.
            lease_refresh_metrics().record(LeaseRefreshResult::NotEligible);
            send_ack(&self.reply, LeaseRefreshStatus::NotEligible);
            return;
        };
        registry.handle_lease_refresh(
            *serial.as_bytes(),
            Sha256::digest(plaintext).into(),
            session_token.map(|token| *token),
            self.reply.clone(),
            Arc::clone(admitter),
        );
    }
}

impl<C: ClosableConn> MultihopSessionRegistry<C> {
    fn handle_lease_refresh(
        self: &Arc<Self>,
        key_serial: [u8; TOKEN_SERIAL_LEN],
        digest: [u8; 32],
        session_token: Option<SessionToken>,
        reply: ControlTx,
        admitter: Arc<dyn SessionTokenAdmitter>,
    ) {
        let key = SessionKey::TokenSerial(WarrenPubkey::from_bytes(key_serial));
        // `live` then `anchors`, the order every path takes (see `route`).
        let live = self.live.lock();
        if !live.contains_key(&key) {
            return;
        }
        let mut anchors = self.route.anchors.lock();
        let slot = &mut anchors
            .entry(key_serial)
            .or_insert_with(|| AnchorSlot::new(key_serial))
            .lease;
        let Some(token) = session_token else {
            slot.capable = true;
            drop(anchors);
            drop(live);
            lease_refresh_metrics().record(LeaseRefreshResult::Announced);
            send_ack(&reply, LeaseRefreshStatus::Registered);
            return;
        };
        let now = Instant::now();
        let decision = match slot.last {
            Some((last_digest, status)) if last_digest == digest => RefreshDecision::Repeat(status),
            _ if slot.in_flight
                || slot
                    .last_call
                    .is_some_and(|at| now.duration_since(at) < REFRESH_MIN_INTERVAL) =>
            {
                RefreshDecision::Throttled
            }
            _ => {
                slot.in_flight = true;
                slot.last_call = Some(now);
                RefreshDecision::Call
            }
        };
        drop(anchors);
        drop(live);
        match decision {
            RefreshDecision::Repeat(status) => {
                lease_refresh_metrics().record(LeaseRefreshResult::Deduplicated);
                send_ack(&reply, status);
            }
            RefreshDecision::Throttled => {
                lease_refresh_metrics().record(LeaseRefreshResult::Throttled);
            }
            RefreshDecision::Call => {
                let registry = Arc::clone(self);
                tokio::spawn(async move {
                    let status = tokio::time::timeout(
                        REFRESH_CALL_TIMEOUT,
                        registry.resolve_lease_refresh(key_serial, token, admitter),
                    )
                    .await
                    .unwrap_or(LeaseRefreshStatus::Unavailable);
                    if let Some(slot) = registry.route.anchors.lock().get_mut(&key_serial) {
                        slot.lease.in_flight = false;
                        // An `unavailable` is never replayed: the client's retry of
                        // the same token must reach the admitter again, or one slow
                        // spend would leave the session stale for its whole grace.
                        slot.lease.last =
                            (status != LeaseRefreshStatus::Unavailable).then_some((digest, status));
                        // A client that refreshes is one that will again.
                        slot.lease.capable |= status == LeaseRefreshStatus::Refreshed;
                    }
                    lease_refresh_metrics().record(LeaseRefreshResult::of_status(status));
                    send_ack(&reply, status);
                });
            }
        }
    }

    /// Spend `token` and move the session keyed by `key_serial` onto its
    /// serial.
    async fn resolve_lease_refresh(
        &self,
        key_serial: [u8; TOKEN_SERIAL_LEN],
        token: SessionToken,
        admitter: Arc<dyn SessionTokenAdmitter>,
    ) -> LeaseRefreshStatus {
        match admitter.admit(std::slice::from_ref(&token)).await {
            TokenAdmission::Admit { serial } => match self.rebind(key_serial, serial) {
                Rebind::Done => LeaseRefreshStatus::Refreshed,
                Rebind::HeldElsewhere | Rebind::Gone => LeaseRefreshStatus::Refused,
            },
            TokenAdmission::Denied | TokenAdmission::Reject => LeaseRefreshStatus::Refused,
        }
    }

    /// Map every live token session's current lease serial to its registry
    /// key, once per call, so a round over every stale lease of the exit
    /// costs one pass over the sessions rather than one per lease. Called
    /// with `live` and `anchors` held. Two sessions share a lease only while
    /// an overlap swap drains the old one on the serial the new one was
    /// admitted on, both the same client's: either key then serves.
    fn keys_by_lease(
        live: &HashMap<SessionKey, HashMap<ConnId, C>>,
        anchors: &HashMap<[u8; TOKEN_SERIAL_LEN], AnchorSlot>,
    ) -> HashMap<[u8; TOKEN_SERIAL_LEN], [u8; TOKEN_SERIAL_LEN]> {
        live.keys()
            .filter_map(|key| match key {
                SessionKey::TokenSerial(serial) => {
                    let key = *serial.as_bytes();
                    Some((anchors.get(&key).map_or(key, |slot| slot.lease_serial), key))
                }
                SessionKey::Wallet(_) | SessionKey::Route(_) => None,
            })
            .collect()
    }

    /// The deployer found the leases in `lease_serials` to belong to a past
    /// epoch, `period` being the deployer's current one. For each, records
    /// when it first did, asks a client that announced the capability for a
    /// token of the current epoch (`LeaseRefreshAck{due}` on one connection),
    /// and says how long the lease has been stale and whether the client
    /// refreshes; `None` where no live session holds that lease. Call it at
    /// each renewal round while leases stay stale: the ask is repeated, so a
    /// lost datagram costs one round. A stale lease counts once per `period`
    /// in `stale_capable` or `stale_incapable`, so a session that never
    /// refreshes counts in every epoch it lives through, as a refreshing one
    /// does.
    pub fn lease_refresh_due(
        &self,
        lease_serials: &[[u8; TOKEN_SERIAL_LEN]],
        period: u64,
    ) -> Vec<Option<StaleLease>> {
        let now = Instant::now();
        let mut ask = Vec::new();
        let (mut capable_count, mut incapable_count) = (0u64, 0u64);
        let verdicts: Vec<Option<StaleLease>> = {
            let live = self.live.lock();
            let mut anchors = self.route.anchors.lock();
            let keys = Self::keys_by_lease(&live, &anchors);
            lease_serials
                .iter()
                .map(|lease| {
                    let key = *keys.get(lease)?;
                    let slot = &mut anchors
                        .entry(key)
                        .or_insert_with(|| AnchorSlot::new(key))
                        .lease;
                    let since = *slot.stale_since.get_or_insert(now);
                    let first_in_period = slot.counted_period != Some(period);
                    if first_in_period {
                        slot.counted_period = Some(period);
                        if slot.capable {
                            capable_count += 1;
                        } else {
                            incapable_count += 1;
                        }
                    }
                    if slot.capable {
                        ask.push(SessionKey::TokenSerial(WarrenPubkey::from_bytes(key)));
                    }
                    Some(StaleLease {
                        stale_for: now.duration_since(since),
                        capable: slot.capable,
                        first_in_period,
                    })
                })
                .collect()
        };
        let metrics = lease_refresh_metrics();
        for _ in 0..capable_count {
            metrics.record(LeaseRefreshResult::StaleCapable);
        }
        for _ in 0..incapable_count {
            metrics.record(LeaseRefreshResult::StaleIncapable);
        }
        // One connection per session is enough: the ack carries no
        // correlation, and one per bonded leg would start one refresh per leg.
        let controls = self.route.first_controls_of(&ask);
        for key in &ask {
            if let Some(tx) = controls.get(key) {
                send_ack(tx, LeaseRefreshStatus::Due);
                metrics.record(LeaseRefreshResult::DueSent);
            }
        }
        verdicts
    }

    /// End the sessions holding the leases in `lease_serials` because they
    /// were not refreshed in time: every connection gets
    /// `LeaseRefreshAck{expired}` and is then closed with the operational
    /// lease-expired code, which its client redials after on a token of the
    /// current epoch. Returns, per lease, how many connections were ended.
    pub fn end_expired_leases(&self, lease_serials: &[[u8; TOKEN_SERIAL_LEN]]) -> Vec<usize>
    where
        C: Clone,
    {
        let sessions: Vec<Option<ExpiringSession<C>>> = {
            let live = self.live.lock();
            let anchors = self.route.anchors.lock();
            let keys = Self::keys_by_lease(&live, &anchors);
            lease_serials
                .iter()
                .map(|lease| {
                    let key = SessionKey::TokenSerial(WarrenPubkey::from_bytes(*keys.get(lease)?));
                    let conns = live
                        .get(&key)
                        .map(|conns| conns.iter().map(|(id, c)| (*id, c.clone())).collect())
                        .unwrap_or_default();
                    Some((key, conns))
                })
                .collect()
        };
        let controls = self.route.controls_by_conn();
        sessions
            .into_iter()
            .map(|session| {
                let Some((key, conns)) = session else {
                    return 0;
                };
                for (id, conn) in &conns {
                    let told = controls
                        .get(&(key, *id))
                        .is_some_and(|tx| tx.try_send(Outbound::EndLease).is_ok());
                    if !told {
                        conn.close_lease_expired();
                    }
                }
                if !conns.is_empty() {
                    lease_refresh_metrics().record(LeaseRefreshResult::Expired);
                }
                conns.len()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;
    use tokio::sync::mpsc;
    use warrenguard_server::BoxFuture;

    use super::*;

    #[derive(Clone, Default)]
    struct FakeConn {
        rejected: Arc<AtomicUsize>,
        expired: Arc<AtomicUsize>,
    }

    impl ClosableConn for FakeConn {
        fn close_rejected(&self) {
            self.rejected.fetch_add(1, Ordering::AcqRel);
        }
        fn close_lease_expired(&self) {
            self.expired.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Admits a token on the serial of its first 32 bytes, refuses it, or
    /// never answers; counts spends.
    struct FakeTokens {
        verdict: Option<bool>,
        /// The first spend never answers, the later ones follow `verdict`.
        hang_first: bool,
        spends: AtomicUsize,
    }

    impl FakeTokens {
        fn new(verdict: Option<bool>) -> Arc<Self> {
            Arc::new(Self {
                verdict,
                hang_first: false,
                spends: AtomicUsize::new(0),
            })
        }
    }

    impl SessionTokenAdmitter for FakeTokens {
        fn admit<'a>(&'a self, tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
            let first = self.spends.fetch_add(1, Ordering::AcqRel) == 0;
            Box::pin(async move {
                if first && self.hang_first {
                    std::future::pending::<()>().await;
                }
                match self.verdict {
                    None => std::future::pending().await,
                    Some(false) => TokenAdmission::Denied,
                    Some(true) => {
                        let mut serial = [0u8; 32];
                        serial.copy_from_slice(&tokens[0].0[..32]);
                        TokenAdmission::Admit { serial }
                    }
                }
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

    fn token(fill: u8) -> SessionToken {
        SessionToken([fill; warrenguard_wire::SESSION_TOKEN_LEN])
    }

    /// A registry with one live main on MAIN, one connection, its control
    /// sender attached; plus the context its rx pump would use.
    fn main_session(
        tokens: Option<Arc<FakeTokens>>,
    ) -> (
        Arc<MultihopSessionRegistry<FakeConn>>,
        AnchorContext,
        mpsc::Receiver<Outbound>,
        FakeConn,
    ) {
        let registry = MultihopSessionRegistry::<FakeConn>::new();
        let conn = FakeConn::default();
        registry.register_key(main_key(), 1, conn.clone());
        let (tx, rx) = mpsc::channel(16);
        registry.attach_control(main_key(), 1, tx.clone());
        let ctx = AnchorContext {
            registry: None,
            key: Some(main_key()),
            reply: tx,
            token_admitter: tokens.map(|t| t as Arc<dyn SessionTokenAdmitter>),
            route: None,
        };
        (registry, ctx, rx, conn)
    }

    /// One lease reported stale in period 1, as a renewal round does.
    fn due(registry: &MultihopSessionRegistry<FakeConn>, lease: [u8; 32]) -> Option<StaleLease> {
        registry.lease_refresh_due(&[lease], 1).pop().flatten()
    }

    fn end(registry: &MultihopSessionRegistry<FakeConn>, lease: [u8; 32]) -> usize {
        registry.end_expired_leases(&[lease]).iter().sum()
    }

    fn submit(
        registry: &Arc<MultihopSessionRegistry<FakeConn>>,
        ctx: &AnchorContext,
        request: Option<SessionToken>,
    ) {
        let bytes = warrenguard_multihop::encode_control(&WarrenControlMessage::LeaseRefresh {
            session_token: request.map(Box::new),
        })
        .expect("encode");
        registry.handle_lease_refresh(
            MAIN,
            Sha256::digest(&bytes).into(),
            request,
            ctx.reply.clone(),
            Arc::clone(ctx.token_admitter.as_ref().expect("admitter")),
        );
    }

    async fn next_status(rx: &mut mpsc::Receiver<Outbound>) -> LeaseRefreshStatus {
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(Outbound::Control(WarrenControlMessage::LeaseRefreshAck { status }))) => {
                LeaseRefreshStatus::from_code(status)
            }
            other => panic!("expected a LeaseRefreshAck, got {other:?}"),
        }
    }

    async fn nothing_sent(rx: &mut mpsc::Receiver<Outbound>) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err(), "nothing was expected");
    }

    #[tokio::test]
    async fn an_announcement_marks_the_session_capable_and_is_acked_registered() {
        let (registry, ctx, mut rx, _) = main_session(Some(FakeTokens::new(Some(true))));
        let stale = due(&registry, MAIN).expect("live");
        assert!(!stale.capable, "nothing announced yet");
        nothing_sent(&mut rx).await;

        submit(&registry, &ctx, None);
        assert_eq!(next_status(&mut rx).await, LeaseRefreshStatus::Registered);
        assert!(due(&registry, MAIN).expect("live").capable);
        assert_eq!(
            next_status(&mut rx).await,
            LeaseRefreshStatus::Due,
            "a capable client is asked for a token"
        );
    }

    #[tokio::test]
    async fn a_token_moves_the_lease_and_ends_the_staleness() {
        let tokens = FakeTokens::new(Some(true));
        let (registry, ctx, mut rx, _) = main_session(Some(Arc::clone(&tokens)));
        let ended = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&ended);
        registry.set_token_session_end_observer(Box::new(move |s| sink.lock().push(s)));
        submit(&registry, &ctx, None);
        next_status(&mut rx).await;
        due(&registry, MAIN).expect("live");
        next_status(&mut rx).await;
        tokio::time::sleep(Duration::from_millis(80)).await;

        submit(&registry, &ctx, Some(token(0x77)));
        assert_eq!(next_status(&mut rx).await, LeaseRefreshStatus::Refreshed);
        let fresh = [0x77; 32];
        assert_eq!(registry.live_token_serials(), vec![fresh]);
        assert_eq!(
            *ended.lock(),
            vec![MAIN],
            "the lease left behind is released"
        );
        assert_eq!(
            due(&registry, MAIN),
            None,
            "no session holds the old lease any more"
        );
        let again = due(&registry, fresh).expect("live");
        assert!(
            again.stale_for < Duration::from_millis(50),
            "a refresh clears the staleness: a later report starts a new one"
        );
    }

    #[tokio::test]
    async fn a_refused_token_is_acked_refused_and_keeps_the_lease() {
        let (registry, ctx, mut rx, _) = main_session(Some(FakeTokens::new(Some(false))));
        due(&registry, MAIN).expect("live");
        submit(&registry, &ctx, Some(token(0x77)));
        assert_eq!(next_status(&mut rx).await, LeaseRefreshStatus::Refused);
        assert_eq!(registry.live_token_serials(), vec![MAIN]);
    }

    #[tokio::test]
    async fn a_repeat_is_answered_without_a_second_spend_and_a_new_token_is_throttled() {
        let tokens = FakeTokens::new(Some(false));
        let (registry, ctx, mut rx, _) = main_session(Some(Arc::clone(&tokens)));
        submit(&registry, &ctx, Some(token(0x77)));
        assert_eq!(next_status(&mut rx).await, LeaseRefreshStatus::Refused);
        submit(&registry, &ctx, Some(token(0x77)));
        assert_eq!(next_status(&mut rx).await, LeaseRefreshStatus::Refused);
        submit(&registry, &ctx, Some(token(0x78)));
        nothing_sent(&mut rx).await;
        assert_eq!(
            tokens.spends.load(Ordering::Acquire),
            1,
            "at most one spend per 2 s per session, none for a repeat"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_spend_that_never_answers_is_acked_unavailable_and_frees_the_session() {
        let (registry, ctx, mut rx, _) = main_session(Some(FakeTokens::new(None)));
        submit(&registry, &ctx, Some(token(0x77)));
        match tokio::time::timeout(REFRESH_CALL_TIMEOUT * 3, rx.recv()).await {
            Ok(Some(Outbound::Control(WarrenControlMessage::LeaseRefreshAck { status }))) => {
                assert_eq!(
                    LeaseRefreshStatus::from_code(status),
                    LeaseRefreshStatus::Unavailable
                );
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
                .lease
                .in_flight
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_token_presented_again_after_unavailable_reaches_the_admitter_again() {
        let tokens = Arc::new(FakeTokens {
            verdict: Some(true),
            hang_first: true,
            spends: AtomicUsize::new(0),
        });
        let (registry, ctx, mut rx, _) = main_session(Some(Arc::clone(&tokens)));
        submit(&registry, &ctx, Some(token(0x77)));
        match tokio::time::timeout(REFRESH_CALL_TIMEOUT * 3, rx.recv()).await {
            Ok(Some(Outbound::Control(WarrenControlMessage::LeaseRefreshAck { status }))) => {
                assert_eq!(
                    LeaseRefreshStatus::from_code(status),
                    LeaseRefreshStatus::Unavailable
                );
            }
            other => panic!("expected an unavailable ack, got {other:?}"),
        }
        tokio::time::sleep(REFRESH_MIN_INTERVAL).await;

        // The client presents the same token again, byte for byte.
        submit(&registry, &ctx, Some(token(0x77)));

        assert_eq!(
            next_status(&mut rx).await,
            LeaseRefreshStatus::Refreshed,
            "an unavailable verdict is never replayed from the cache"
        );
        assert_eq!(tokens.spends.load(Ordering::Acquire), 2);
        assert_eq!(registry.live_token_serials(), vec![[0x77; 32]]);
    }

    #[tokio::test]
    async fn a_session_that_never_refreshes_counts_stale_once_in_every_period() {
        let (registry, _ctx, _rx, _) = main_session(Some(FakeTokens::new(Some(true))));
        let report = |period| {
            registry.lease_refresh_due(&[MAIN], period)[0]
                .expect("live")
                .first_in_period
        };
        assert!(report(7), "the first round of a period counts it");
        assert!(!report(7), "later rounds of the same period do not");
        assert!(
            report(8),
            "the next epoch counts it again, as it counts a session that refreshed"
        );
    }

    #[tokio::test]
    async fn only_a_session_admitted_on_a_token_is_eligible() {
        let wallet = SessionKey::Wallet(WarrenPubkey::from_bytes([0x33; 32]));
        let route = SessionKey::Route(WarrenPubkey::from_bytes([0x44; 32]));
        let tokens: Arc<dyn SessionTokenAdmitter> = FakeTokens::new(Some(true));
        for (key, admitter) in [
            (Some(wallet), Some(Arc::clone(&tokens))),
            (Some(route), Some(Arc::clone(&tokens))),
            (None, Some(Arc::clone(&tokens))),
            (Some(main_key()), None),
        ] {
            let (tx, mut rx) = mpsc::channel(8);
            let ctx = AnchorContext {
                registry: Some(MultihopSessionRegistry::new()),
                key,
                reply: tx,
                token_admitter: admitter,
                route: None,
            };
            ctx.submit_lease_refresh(b"request", Some(Box::new(token(0x77))));
            assert_eq!(next_status(&mut rx).await, LeaseRefreshStatus::NotEligible);
        }
    }

    #[tokio::test]
    async fn staleness_is_measured_from_the_first_report_and_asked_on_one_leg_only() {
        let (registry, ctx, mut rx, _) = main_session(Some(FakeTokens::new(Some(true))));
        let (tx2, mut rx2) = mpsc::channel(8);
        registry.register_key(main_key(), 2, FakeConn::default());
        registry.attach_control(main_key(), 2, tx2);
        submit(&registry, &ctx, None);
        next_status(&mut rx).await;

        let first = due(&registry, MAIN).expect("live");
        tokio::time::sleep(Duration::from_millis(30)).await;
        let second = due(&registry, MAIN).expect("live");
        assert!(second.stale_for >= first.stale_for + Duration::from_millis(30));
        let asked = [&mut rx, &mut rx2]
            .into_iter()
            .map(|rx| std::iter::from_fn(|| rx.try_recv().ok()).count())
            .sum::<usize>();
        assert_eq!(asked, 2, "one due per report, on a single leg");
        assert_eq!(due(&registry, [0x99; 32]), None);
    }

    #[tokio::test]
    async fn an_expired_session_is_told_then_closed_with_the_lease_code() {
        let (registry, _ctx, mut rx, told) = main_session(Some(FakeTokens::new(Some(true))));
        let untold = FakeConn::default();
        registry.register_key(main_key(), 2, untold.clone());

        assert_eq!(end(&registry, MAIN), 2);
        assert!(matches!(rx.try_recv(), Ok(Outbound::EndLease)));
        assert_eq!(
            told.expired.load(Ordering::Acquire),
            0,
            "its emitter closes it"
        );
        assert_eq!(
            untold.expired.load(Ordering::Acquire),
            1,
            "no emitter: closed at once"
        );
        assert_eq!(
            untold.rejected.load(Ordering::Acquire),
            0,
            "never the policy close, which a client reads as fatal"
        );
        assert_eq!(end(&registry, [0x99; 32]), 0);
    }
}
