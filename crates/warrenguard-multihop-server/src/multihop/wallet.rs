//! The wallet-signed sessions of this exit, as the deployer's
//! [`WalletSessionGate`](warrenguard_server::WalletSessionGate) counts them.
//!
//! The registry keys every connection of one wallet under one key, whatever
//! device it comes from, so it cannot say how many sessions a wallet runs
//! here. A session is one tunnel address the wallet holds: bonded connections
//! and reconnects that join that address belong to it. This table groups the
//! connections that way, draws the random id the gate sees for each session,
//! and says when a session the gate admitted has ended.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use warrenguard_server::{WALLET_SESSION_ID_LEN, WalletSession};

use crate::ip_pool::ConnId;

/// Where a wallet connection stands once it holds an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalletSlot {
    /// It joined a session the gate already admitted: serve it.
    Admitted,
    /// It starts a session, or joins one whose admission is still in
    /// flight: ask the gate about this session.
    NeedsGate(WalletSession),
}

struct Entry {
    id: [u8; WALLET_SESSION_ID_LEN],
    conns: HashSet<ConnId>,
    admitted: bool,
}

/// Wallet sessions of this exit, keyed by `(account key, tunnel IPv4)`.
#[derive(Default)]
pub(crate) struct RegistryWalletState {
    inner: Mutex<Tables>,
}

#[derive(Default)]
struct Tables {
    sessions: HashMap<([u8; 32], Ipv4Addr), Entry>,
    by_conn: HashMap<ConnId, ([u8; 32], Ipv4Addr)>,
}

impl RegistryWalletState {
    /// Records `conn` as holding `ipv4` for the account `pubkey` and says
    /// whether the gate must be asked. The first connection of a session
    /// draws its id; later ones reuse it.
    pub(crate) fn slot(&self, pubkey: [u8; 32], ipv4: Ipv4Addr, conn: ConnId) -> WalletSlot {
        let mut t = self.inner.lock();
        let entry = t.sessions.entry((pubkey, ipv4)).or_insert_with(|| Entry {
            id: fresh_session_id(),
            conns: HashSet::new(),
            admitted: false,
        });
        entry.conns.insert(conn);
        let slot = if entry.admitted {
            WalletSlot::Admitted
        } else {
            WalletSlot::NeedsGate(WalletSession::new(pubkey, entry.id))
        };
        t.by_conn.insert(conn, (pubkey, ipv4));
        slot
    }

    /// The gate admitted `session`: its later connections join without
    /// asking, and its end is reported.
    pub(crate) fn mark_admitted(&self, session: &WalletSession) {
        let mut t = self.inner.lock();
        if let Some(entry) = t
            .sessions
            .values_mut()
            .find(|entry| entry.id == *session.id())
        {
            entry.admitted = true;
        }
    }

    /// Removes `conn`. Returns the session when `conn` was its last
    /// connection and the gate had admitted it: the deployer's count must
    /// release it. A session the gate never admitted holds nothing to
    /// release.
    pub(crate) fn leave(&self, conn: ConnId) -> Option<WalletSession> {
        let mut t = self.inner.lock();
        let key = t.by_conn.remove(&conn)?;
        let entry = t.sessions.get_mut(&key)?;
        entry.conns.remove(&conn);
        if !entry.conns.is_empty() {
            return None;
        }
        let entry = t.sessions.remove(&key)?;
        entry.admitted.then(|| WalletSession::new(key.0, entry.id))
    }

    /// How many connections the table tracks, admitted or not.
    #[cfg(test)]
    pub(crate) fn tracked_conns(&self) -> usize {
        self.inner.lock().by_conn.len()
    }

    /// Every admitted session holding at least one connection.
    pub(crate) fn live(&self) -> Vec<WalletSession> {
        self.inner
            .lock()
            .sessions
            .iter()
            .filter(|(_, entry)| entry.admitted)
            .map(|((pubkey, _), entry)| WalletSession::new(*pubkey, entry.id))
            .collect()
    }
}

/// A session id nobody can predict or link to the tunnel address: a hash of a
/// process-wide random salt and a counter. The counter keeps ids unique within
/// the process even if the salt could not be drawn.
fn fresh_session_id() -> [u8; WALLET_SESSION_ID_LEN] {
    static SALT: OnceLock<[u8; 32]> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let salt = SALT.get_or_init(|| {
        use rand_core::TryRngCore;
        let mut salt = [0u8; 32];
        if rand_core::OsRng.try_fill_bytes(&mut salt).is_err() {
            tracing::warn!("wallet session ids fall back to an unsalted counter");
        }
        salt
    });
    let mut h = Sha256::new();
    h.update(b"warren/wallet-session-id/v1");
    h.update(salt);
    h.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    let mut id = [0u8; WALLET_SESSION_ID_LEN];
    id.copy_from_slice(&h.finalize()[..WALLET_SESSION_ID_LEN]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    const WALLET: [u8; 32] = [0x5A; 32];
    const IP1: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
    const IP2: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 3);

    fn needs_gate(slot: WalletSlot) -> WalletSession {
        match slot {
            WalletSlot::NeedsGate(session) => session,
            WalletSlot::Admitted => panic!("expected the gate to be asked"),
        }
    }

    #[test]
    fn a_connection_joining_an_admitted_session_is_not_asked_again() {
        let state = RegistryWalletState::default();
        let session = needs_gate(state.slot(WALLET, IP1, 1));
        state.mark_admitted(&session);

        assert_eq!(state.slot(WALLET, IP1, 2), WalletSlot::Admitted);
    }

    #[test]
    fn two_addresses_of_one_wallet_are_two_sessions_with_distinct_ids() {
        let state = RegistryWalletState::default();

        let first = needs_gate(state.slot(WALLET, IP1, 1));
        let second = needs_gate(state.slot(WALLET, IP2, 2));

        assert_ne!(first.id(), second.id(), "each session needs its own slot");
    }

    #[test]
    fn a_connection_joining_a_session_still_in_admission_asks_under_the_same_id() {
        let state = RegistryWalletState::default();
        let first = needs_gate(state.slot(WALLET, IP1, 1));

        let joiner = needs_gate(state.slot(WALLET, IP1, 2));

        assert_eq!(first.id(), joiner.id(), "one session, one slot at the gate");
    }

    #[test]
    fn the_last_connection_leaving_an_admitted_session_ends_it() {
        let state = RegistryWalletState::default();
        let session = needs_gate(state.slot(WALLET, IP1, 1));
        state.mark_admitted(&session);
        state.slot(WALLET, IP1, 2);

        assert_eq!(state.leave(1), None, "a bonded sibling still holds it");
        assert_eq!(state.leave(2), Some(session));
        assert!(state.live().is_empty());
    }

    #[test]
    fn a_session_the_gate_never_admitted_ends_without_a_release() {
        let state = RegistryWalletState::default();
        needs_gate(state.slot(WALLET, IP1, 1));

        assert_eq!(
            state.leave(1),
            None,
            "nothing was counted, nothing to release"
        );
    }

    #[test]
    fn only_admitted_sessions_are_live() {
        let state = RegistryWalletState::default();
        let admitted = needs_gate(state.slot(WALLET, IP1, 1));
        state.mark_admitted(&admitted);
        let pending = needs_gate(state.slot(WALLET, IP2, 2));

        assert_eq!(state.live(), vec![admitted]);
        assert!(!state.live().contains(&pending));
    }

    #[test]
    fn leaving_an_unknown_connection_is_a_no_op() {
        let state = RegistryWalletState::default();

        assert_eq!(state.leave(42), None);
    }
}
