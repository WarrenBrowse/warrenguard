//! Protocol v7 anonymous session-token admission hook for the exit.
//!
//! Where the older per-wallet device cap named the wallet, v7 gates a PRIMARY
//! connection through a [`SessionTokenAdmitter`]:
//! the exit hands over the client's Privacy Pass tokens and gets back an
//! anonymous 32-byte serial, having verified one offline and spent it against
//! the control plane's per-serial lease. The exit never learns the wallet.
//!
//! Like the other admission seams, the concrete implementation lives in the
//! deployer's exit binary: it holds the synced issuer
//! directory (for the offline verify) and the control-plane API client (for
//! the spend/renew). The engine stays token-agnostic, treating a token as an
//! opaque bearer blob and keying the session by the returned serial.
//!
//! ## Session keying and multi-conn attach
//!
//! v7 has no identity, so the "same Ed25519 key" secondary-attach check of v6
//! is gone. Instead:
//!
//! - The exit keys a v7 session's map slot by [`session_key_value`], a 32-byte
//!   value derived from the multi-conn attach capability, so the existing
//!   `(WarrenPubkey, device_id)` [`SessionKey`](super::session::SessionKey)
//!   machinery (IP allocation, eviction, revocation) is reused verbatim with
//!   the derived value standing in for the pubkey.
//! - The primary's attach capability is [`attach_secret_for_serial`], derived
//!   deterministically from the spent serial. Deriving it (rather than minting
//!   a fresh random) makes a primary reconnect that re-presents the same token
//!   idempotent: same serial -> same attach_secret -> same session-key value ->
//!   the existing session and its IP are reused, exactly like a v6 reconnect.
//! - A secondary carries no token; it echoes the primary's attach_secret, and
//!   the exit finds the session by the same derived key value. The capability
//!   is transmitted only inside the QUIC-encrypted tunnel and is unguessable
//!   (128-bit), so it authorizes attach without revealing any identity.

use sha2::{Digest, Sha256};
use warrenguard_wire::{ATTACH_SECRET_LEN, SessionToken, WarrenPubkey};

use super::BoxFuture;

/// Length of a Privacy Pass token serial: SHA-256 of the token input.
pub const TOKEN_SERIAL_LEN: usize = 32;

/// Outcome of a v7 PRIMARY token-admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenAdmission {
    /// A token verified offline and its serial was spent (or the spend
    /// could not reach the control plane and was failed-open: availability
    /// over strict enforcement). The session is keyed by `serial`.
    Admit {
        /// The 32-byte serial of the admitted token.
        serial: [u8; TOKEN_SERIAL_LEN],
    },
    /// No presented token verified for the current epoch (malformed,
    /// tampered, or all wrong-epoch). The caller closes the connection.
    Reject,
    /// A token verified but its serial is already leased to a live session
    /// elsewhere (cross-exit double-spend). The caller closes the connection
    /// with the device-limit code.
    Denied,
}

/// Injected hook the exit calls to admit a v7 PRIMARY connection. Implemented
/// in the deployer's exit binary against the issuer directory (offline verify)
/// and the control-plane per-serial lease (spend/renew); stubbed in tests.
///
/// Contract:
/// - [`Self::admit`] is called only for a PRIMARY (`connection_index == 0`).
///   It tries the presented `tokens` in order, verifying each offline against
///   the current epoch key; the first that verifies is spent and its serial
///   returned via [`TokenAdmission::Admit`]. All-invalid -> [`TokenAdmission::Reject`];
///   a valid-but-already-spent serial -> [`TokenAdmission::Denied`]. A transport
///   failure to the control plane is failed-open (Admit) so an API outage never
///   blacks out the tunnel, exactly like the v6 device cap.
/// - [`Self::renew_live`] re-asserts the lease for every serial in `live` (called
///   periodically by the exit binary), and forgets any serial it holds that is
///   no longer live so its retained token can be dropped.
pub trait SessionTokenAdmitter: Send + Sync {
    /// Verify-and-spend the first valid token in `tokens`. See the trait docs.
    fn admit<'a>(&'a self, tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission>;

    /// Re-assert leases for exactly the serials in `live`; drop any others.
    fn renew_live<'a>(&'a self, live: &'a [[u8; TOKEN_SERIAL_LEN]]) -> BoxFuture<'a, ()>;
}

/// Derives the multi-conn attach capability from a spent token serial.
///
/// Deterministic (a reconnect re-presenting the same token re-derives the same
/// capability) and domain-separated from [`session_key_value`]. Unguessable
/// without the serial, which never leaves the exit; the capability itself
/// travels only inside the encrypted tunnel.
#[must_use]
pub fn attach_secret_for_serial(serial: &[u8; TOKEN_SERIAL_LEN]) -> [u8; ATTACH_SECRET_LEN] {
    let mut h = Sha256::new();
    h.update(b"warren/v7/attach-secret/v1");
    h.update(serial);
    let digest = h.finalize();
    let mut out = [0u8; ATTACH_SECRET_LEN];
    out.copy_from_slice(&digest[..ATTACH_SECRET_LEN]);
    out
}

/// Derives the 32-byte session-map key value from an attach capability, for
/// use in the pubkey slot of a v7 [`SessionKey`](super::session::SessionKey).
///
/// Both the primary (which holds the serial, hence the capability) and a
/// secondary (which echoes the capability) compute the same value, so both
/// land on the same session-map slot. Domain-separated from
/// [`attach_secret_for_serial`].
#[must_use]
pub fn session_key_value(attach_secret: &[u8; ATTACH_SECRET_LEN]) -> WarrenPubkey {
    let mut h = Sha256::new();
    h.update(b"warren/v7/session-key/v1");
    h.update(attach_secret);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    WarrenPubkey::from_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_secret_is_deterministic_and_serial_bound() {
        let s1 = [7u8; TOKEN_SERIAL_LEN];
        let s2 = {
            let mut s = [7u8; TOKEN_SERIAL_LEN];
            s[0] = 8;
            s
        };
        // Same serial -> same capability (reconnect idempotency).
        assert_eq!(attach_secret_for_serial(&s1), attach_secret_for_serial(&s1));
        // Different serial -> different capability (no cross-session collision).
        assert_ne!(attach_secret_for_serial(&s1), attach_secret_for_serial(&s2));
    }

    #[test]
    fn primary_and_secondary_agree_on_the_session_key() {
        // The primary derives attach_secret from its serial; a secondary is
        // handed that same attach_secret. Both must map to one session slot.
        let serial = [0x42u8; TOKEN_SERIAL_LEN];
        let cap = attach_secret_for_serial(&serial);
        let key_from_primary = session_key_value(&cap);
        let key_from_secondary = session_key_value(&cap); // secondary echoes `cap`
        assert_eq!(key_from_primary, key_from_secondary);
    }

    #[test]
    fn session_key_domain_is_separated_from_attach_secret() {
        // The two derivations must not coincide, or a capability could be
        // mistaken for a session-key value.
        let serial = [0x11u8; TOKEN_SERIAL_LEN];
        let cap = attach_secret_for_serial(&serial);
        let skey = session_key_value(&cap);
        // First 16 bytes of the session-key value must not equal the
        // capability it was derived from (distinct domain strings).
        assert_ne!(&skey.as_bytes()[..ATTACH_SECRET_LEN], &cap[..]);
    }
}
