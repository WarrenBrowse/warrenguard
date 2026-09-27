//! Admission hook for wallet-signed sessions.
//!
//! A wallet-signed setup names the account (its Ed25519 pubkey, proven by a
//! signature), so every device of one account presents the same key and the
//! exit alone cannot bound how many of them run at once across a fleet. The
//! deployer can: the engine hands each NEW wallet session to a
//! [`WalletSessionGate`] before serving it, and the gate answers from whatever
//! fleet-wide count the deployer keeps.
//!
//! A session here is one tunnel address a wallet holds on this exit: every
//! connection of a bonded client, and every reconnect that joins the address
//! it held, belongs to the same session and is never asked about again. The
//! exit draws a random [`WalletSession::id`] for each session, so the deployer
//! can count sessions without learning the tunnel address.
//!
//! On one exit this bounds distinct addresses, not devices: devices of one
//! account that share an address (a client that sends no placement hint, or
//! one that names another live session's address) count once. They also share
//! that address's downlink, which is what makes the sharing useless as a way
//! around the count.
//!
//! Renewal and release stay with the deployer, which reads the live sessions
//! and their ends from the multi-hop session registry, as it does for token
//! serials.

use super::BoxFuture;

/// Length of the random id the exit draws for each wallet session.
pub const WALLET_SESSION_ID_LEN: usize = 16;

/// One wallet-signed session on this exit: the account key the client proved
/// and the random id the exit drew for the session.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WalletSession {
    pubkey: [u8; 32],
    id: [u8; WALLET_SESSION_ID_LEN],
}

impl WalletSession {
    /// A session of the account `pubkey` under the exit-drawn `id`.
    #[must_use]
    pub fn new(pubkey: [u8; 32], id: [u8; WALLET_SESSION_ID_LEN]) -> Self {
        Self { pubkey, id }
    }

    /// The account key the client proved at setup.
    #[must_use]
    pub fn pubkey(&self) -> &[u8; 32] {
        &self.pubkey
    }

    /// The id the exit drew for this session. Random, unrelated to the
    /// tunnel address and to any other exit's id for the same account.
    #[must_use]
    pub fn id(&self) -> &[u8; WALLET_SESSION_ID_LEN] {
        &self.id
    }
}

/// Renders neither the account key nor the id: both are identifiers.
impl std::fmt::Debug for WalletSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalletSession(..)")
    }
}

/// What the deployer answers about a new wallet session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalletAdmission {
    /// Serve it. Also the answer when the deployer's count could not be
    /// reached, if it prefers availability to a strict bound.
    Admit,
    /// The account already holds its maximum of simultaneous sessions.
    DeviceLimit,
    /// The deployer no longer admits wallet-signed sessions for this account.
    Retired,
}

/// Injected hook the exit calls before serving a new wallet-signed session.
/// Implemented in the deployer's exit binary; stubbed in tests.
///
/// Asked about a session from the setup of its first connection, and never
/// for a connection that joins a session the gate already admitted. It can be
/// asked several times, concurrently, about the same session
/// ([`WalletSession::id`] unchanged): every connection that joins while the
/// first answer is still pending asks too. The answer must therefore be
/// idempotent per id, counting a session once however often it is asked.
///
/// The client's setup waits on the answer, so the deployer bounds its own
/// latency. A refused connection is closed with the sealed
/// `RejectedDeviceLimit` detail whichever refusal the gate gave.
pub trait WalletSessionGate: Send + Sync {
    /// Admit `session`, or refuse it.
    fn open<'a>(&'a self, session: &'a WalletSession) -> BoxFuture<'a, WalletAdmission>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_renders_neither_the_key_nor_the_id() {
        let session = WalletSession::new([0xAB; 32], [0xCD; WALLET_SESSION_ID_LEN]);

        let rendered = format!("{session:?}");

        assert_eq!(
            rendered, "WalletSession(..)",
            "neither the account key nor the session id may reach a log"
        );
    }

    #[test]
    fn accessors_return_what_the_session_was_built_with() {
        let session = WalletSession::new([1; 32], [2; WALLET_SESSION_ID_LEN]);

        assert_eq!(session.pubkey(), &[1; 32]);
        assert_eq!(session.id(), &[2; WALLET_SESSION_ID_LEN]);
    }
}
