//! Epoch lease refresh, client side.
//!
//! A session admitted on a token holds its fleet-wide lease only within the
//! token's epoch. After every setup on a token, the supervisor announces to
//! the exit that it refreshes (`LeaseRefresh` with no token, retried until
//! acknowledged). When the exit reports the lease stale (`due`, sent at its
//! first renewal after the epoch boundary and repeated while the lease stays
//! stale), the session waits a random delay, so the fleet's sessions do not
//! all spend at the same second, then presents the tokens its provider hands
//! out one at a time until the exit moves the lease onto one. The serial of
//! that token is published so the route anchor, if any, follows it.
//!
//! An exit that predates the refresh never acknowledges the announcement and
//! never asks: the task then ends, and so does the exit's reason to end the
//! session. Logs carry counts and states, never a token or a serial.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use warrenguard_multihop::{
    LeaseRefreshStatus, WarrenControlMessage, encode_control, session_token_serial,
};
use warrenguard_wire::SessionToken;

use crate::multihop::MultiHopClient;
use crate::supervisor::SessionTokenProvider;

/// Sender half of a bundle's lease refresh intercept.
pub(crate) type LeaseTap = mpsc::UnboundedSender<LeaseRefreshStatus>;

/// When lease refresh requests are sent and re-sent.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LeaseSchedule {
    /// Waits between two sends of one request; after the last one with no
    /// answer the request is given up (for the announcement: the exit
    /// predates the refresh).
    pub(crate) waits: [Duration; 5],
    /// Upper bound of the random wait between a `due` and the first token,
    /// so every session of the fleet does not spend in the same second.
    pub(crate) jitter_max: Duration,
    /// Pause after a refused token before the next: the exit spends at most
    /// one token per 2 s per session and drops anything sooner.
    pub(crate) refused_pause: Duration,
    /// Wait before presenting a token again after `unavailable`.
    pub(crate) unavailable_retry: Duration,
    /// How many times one token is presented again after `unavailable`.
    pub(crate) unavailable_tries: u32,
}

impl LeaseSchedule {
    /// The production schedule. The exit gives a stale lease minutes of
    /// grace, several of its 30 s renewal rounds, and asks at each round:
    /// the jitter plus one walk of a stack of five tokens fits in one round
    /// with room for a retry.
    pub(crate) const DEFAULT: Self = Self {
        waits: [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
        ],
        jitter_max: Duration::from_secs(20),
        refused_pause: Duration::from_millis(2_100),
        unavailable_retry: Duration::from_secs(16),
        unavailable_tries: 3,
    };
}

/// What one request came to.
enum Answer {
    /// The exit answered this status.
    Status(LeaseRefreshStatus),
    /// Nothing came back after every retry.
    Silent,
    /// The intercept is gone with its bundle: the session ended.
    Closed,
}

/// Refresh one session's lease for as long as the session lives. `serial`
/// holds the serial of the lease the session holds now and is updated on
/// every refresh. The caller aborts the task when the session is replaced.
pub(crate) async fn run_lease_refresh(
    primary: Arc<MultiHopClient>,
    tokens: Option<SessionTokenProvider>,
    mut acks: mpsc::UnboundedReceiver<LeaseRefreshStatus>,
    serial: watch::Sender<[u8; 32]>,
    schedule: LeaseSchedule,
) {
    let Ok(announce) = encode_control(&WarrenControlMessage::LeaseRefresh {
        session_token: None,
    }) else {
        return;
    };
    let mut due = match request(&primary, &announce, false, &mut acks, &schedule).await {
        Answer::Status(LeaseRefreshStatus::Registered) => false,
        // The announcement's ack was lost and the exit already asks.
        Answer::Status(LeaseRefreshStatus::Due) => true,
        Answer::Silent => {
            tracing::debug!("exit does not refresh session leases");
            return;
        }
        Answer::Status(_) | Answer::Closed => return,
    };
    loop {
        if !due && !wait_for_due(&mut acks).await {
            return;
        }
        due = false;
        let jitter = schedule.jitter_max.mul_f64(rand::random::<f64>());
        if pause(jitter, &mut acks).await {
            return;
        }
        match refresh_once(&primary, tokens.as_ref(), &mut acks, &schedule).await {
            Some(Some(token)) => {
                serial.send_replace(session_token_serial(&token));
                tracing::info!("session lease refreshed onto a token of the current epoch");
            }
            // Nothing refreshed: the exit asks again at its next renewal.
            Some(None) => {}
            None => return,
        }
    }
}

/// Present the provider's tokens one at a time until the exit refreshes the
/// lease onto one. `Some(Some(token))` on success, `Some(None)` when no token
/// was taken, `None` once the session is gone or cannot refresh.
async fn refresh_once(
    primary: &MultiHopClient,
    tokens: Option<&SessionTokenProvider>,
    acks: &mut mpsc::UnboundedReceiver<LeaseRefreshStatus>,
    schedule: &LeaseSchedule,
) -> Option<Option<SessionToken>> {
    let mut stack: VecDeque<SessionToken> =
        tokens.map(|provider| provider().into()).unwrap_or_default();
    let offered = stack.len();
    let mut unavailable = 0;
    while let Some(token) = stack.front().copied() {
        let Ok(request_bytes) = encode_control(&WarrenControlMessage::LeaseRefresh {
            session_token: Some(Box::new(token)),
        }) else {
            return None;
        };
        match request(primary, &request_bytes, true, acks, schedule).await {
            Answer::Status(LeaseRefreshStatus::Refreshed) => return Some(Some(token)),
            Answer::Status(LeaseRefreshStatus::Refused) => {
                stack.pop_front();
                if pause(schedule.refused_pause, acks).await {
                    return None;
                }
            }
            Answer::Status(LeaseRefreshStatus::Unavailable)
                if unavailable < schedule.unavailable_tries =>
            {
                // The same token again: the exit re-admits the serial it
                // already spent for this session, so nothing is spent twice.
                unavailable += 1;
                if pause(schedule.unavailable_retry, acks).await {
                    return None;
                }
            }
            Answer::Status(LeaseRefreshStatus::NotEligible | LeaseRefreshStatus::Expired)
            | Answer::Closed => return None,
            Answer::Status(_) | Answer::Silent => return Some(None),
        }
    }
    // No-log: counts only.
    tracing::warn!(
        offered,
        "no token of the current epoch refreshed the session lease"
    );
    Some(None)
}

/// Send `bytes`, re-sending byte for byte on the schedule, and return the
/// first answer to it. Queued acks are dropped first: they carry no
/// correlation, and one from an earlier request must not be read as this
/// one's. A `due` or `registered` is never the answer to a token.
async fn request(
    primary: &MultiHopClient,
    bytes: &[u8],
    presents_token: bool,
    acks: &mut mpsc::UnboundedReceiver<LeaseRefreshStatus>,
    schedule: &LeaseSchedule,
) -> Answer {
    while acks.try_recv().is_ok() {}
    for wait in schedule.waits {
        if primary.send_packet(bytes).is_err() {
            return Answer::Closed;
        }
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, acks.recv()).await {
                Ok(None) => return Answer::Closed,
                Ok(Some(LeaseRefreshStatus::Due | LeaseRefreshStatus::Registered))
                    if presents_token => {}
                Ok(Some(status)) => return Answer::Status(status),
                Err(_) => break,
            }
        }
    }
    Answer::Silent
}

/// Wait for the exit to ask for a token. `false` once the session is gone.
async fn wait_for_due(acks: &mut mpsc::UnboundedReceiver<LeaseRefreshStatus>) -> bool {
    loop {
        match acks.recv().await {
            None => return false,
            Some(LeaseRefreshStatus::Due) => return true,
            Some(LeaseRefreshStatus::Expired) => {
                tracing::info!("exit ended the session: its lease was not refreshed in time");
            }
            Some(_) => {}
        }
    }
}

/// Sleep `wait`, consuming whatever arrives meanwhile. `true` when the
/// session ended during it.
async fn pause(wait: Duration, acks: &mut mpsc::UnboundedReceiver<LeaseRefreshStatus>) -> bool {
    tokio::time::timeout(wait, async { while acks.recv().await.is_some() {} })
        .await
        .is_ok()
}
