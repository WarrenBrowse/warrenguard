//! Pluggable admission control for the exit handshake.
//!
//! The exit admits or refuses a client by its Ed25519 public key. Warren backs
//! this with a subscription-driven [`crate::AllowlistHandle`], but the engine
//! itself is policy-agnostic: a generic WarrenGuard deployer can plug in
//! [`AllowAll`] (open relay) or [`StaticAllowlist`] (a fixed key set) instead.
//!
//! The trait is **admit-only**. Live revocation (closing already-open
//! connections when a key is retired) is a separate concern wired through the
//! concrete handle, not this trait.

use std::collections::HashSet;

use warrenguard_wire::WarrenPubkey;

/// Decides whether a client public key may complete the exit handshake.
pub trait Authorizer: Send + Sync {
    /// Returns `true` if `remote_id` is authorized at `now_unix_secs`.
    ///
    /// `now_unix_secs` is passed in (rather than read internally) so the
    /// decision is testable and consistent with the rest of the accept loop.
    fn is_allowed(&self, remote_id: &WarrenPubkey, now_unix_secs: u64) -> bool;
}

/// Admits every client. The default for a generic deployer that does its own
/// gating upstream, and the behaviour when no allowlist is configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn is_allowed(&self, _remote_id: &WarrenPubkey, _now_unix_secs: u64) -> bool {
        true
    }
}

/// Admits a fixed set of public keys (no TTL, no revocation). Useful for a
/// self-hosted deployment with a static roster.
#[derive(Debug, Clone, Default)]
pub struct StaticAllowlist {
    allowed: HashSet<WarrenPubkey>,
}

impl StaticAllowlist {
    /// Builds an allowlist from an explicit key set.
    #[must_use]
    pub fn new(allowed: HashSet<WarrenPubkey>) -> Self {
        Self { allowed }
    }
}

impl Authorizer for StaticAllowlist {
    fn is_allowed(&self, remote_id: &WarrenPubkey, _now_unix_secs: u64) -> bool {
        self.allowed.contains(remote_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> WarrenPubkey {
        WarrenPubkey::from_bytes([byte; 32])
    }

    #[test]
    fn allow_all_admits_every_key() {
        assert!(AllowAll.is_allowed(&key(0), 0));
        assert!(AllowAll.is_allowed(&key(0xff), u64::MAX));
    }

    #[test]
    fn static_allowlist_admits_only_listed_keys() {
        let list = StaticAllowlist::new([key(1), key(2)].into_iter().collect());
        assert!(list.is_allowed(&key(1), 100), "listed key admitted");
        assert!(list.is_allowed(&key(2), 100), "listed key admitted");
        assert!(!list.is_allowed(&key(3), 100), "unlisted key refused");
    }

    #[test]
    fn empty_static_allowlist_refuses_everything() {
        let list = StaticAllowlist::default();
        assert!(!list.is_allowed(&key(1), 100), "deny-all by default");
    }
}
