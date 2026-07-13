//! Pool of long-lived QUIC connections to Warren exits.
//!
//! [`ExitConnPool::get_or_create`] returns a live `quinn::Connection`
//! to the exit identified by an [`ExitDescriptorSigned`], either by
//! reusing the cached one or by dialing fresh. The pool reuses a
//! single client `quinn::Endpoint` for all exits to share UDP socket
//! state and OS resources, and pins each exit by its TLS RPK
//! `exit_ed25519_pubkey` so a hostile server cannot impersonate one.
//!
//! Concurrency: pool state is guarded by a `parking_lot::Mutex` held
//! only for synchronous `HashMap` operations; the heavy `connect().await`
//! happens outside the lock so dial latency does not serialize unrelated
//! lookups. Two callers racing on the same exit_id with no live entry
//! may both dial; the loser of the second-insertion race drops its
//! brand-new connection and returns the winner's, which is acceptable
//! for an opportunistic pool.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use parking_lot::Mutex;
use quinn::{ClientConfig, Connection, Endpoint};
use thiserror::Error;
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::ExitId;
use warrenguard_tls::{
    WarrenPubkey, WarrenTlsError, default_crypto_provider, make_client_config,
    make_client_config_webpki, mozilla_root_store, name as tls_name,
};
use warrenguard_transport_core::{
    warren_transport_config_relay_outbound_multihop_with_gso,
    warren_transport_config_relay_outbound_with_gso,
};

use crate::config::ExitDescriptorSigned;

/// Errors raised by [`ExitConnPool`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExitPoolError {
    /// Building the rustls/Quinn client config failed.
    #[error("TLS client config error: {0}")]
    Tls(#[from] WarrenTlsError),
    /// Binding the local client `quinn::Endpoint` failed.
    #[error("failed to bind exit-pool client endpoint: {0}")]
    BindClient(#[from] std::io::Error),
    /// Quinn refused the connect attempt at the construction stage.
    #[error("connect refused by quinn: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// The handshake failed (TLS error, RPK mismatch, etc.).
    #[error("connection handshake failed: {0}")]
    Handshake(#[from] quinn::ConnectionError),
    /// The exit descriptor carries no endpoint (it was redacted for the
    /// client-facing directory). A relay must obtain the full,
    /// endpoint-bearing descriptor from the auth-gated relay directory
    /// before dialing.
    #[error("exit descriptor has no endpoint (redacted client copy)")]
    MissingEndpoint,
}

/// Pool of QUIC client connections to Warren exits, keyed by
/// `exit_id`.
#[must_use]
pub struct ExitConnPool {
    endpoint: Endpoint,
    state: Arc<Mutex<HashMap<[u8; 16], Arc<Connection>>>>,
    /// WebPKI trust anchors for the X.509 relay->exit dial (when the
    /// target exit advertises a `cover_domain`). `None` = the bundled Mozilla
    /// program (production). A deployer using a private CA, or a test using an
    /// in-memory CA, sets this via [`Self::with_webpki_roots`]. Unused in RPK
    /// mode (the SNI-pinned raw-public-key handshake needs no roots).
    webpki_roots: Option<quinn::rustls::RootCertStore>,
    enable_warren_obfuscation: bool,
    /// UDP segmentation offload (GSO) for the relay->exit dial. Must be
    /// `false` on KVM/virtio NICs that lack hardware
    /// `UDP_SEGMENT`: with GSO on, quinn-udp's first send gets `EIO`,
    /// halts, and loses the in-flight handshake packets, stalling the
    /// relay->exit Quinn handshake until the exit's 30 s accept cap
    /// drops it. Mirrors the `--no-gso` flag the exit binary already
    /// honors for its own listener.
    enable_gso: bool,
}

impl ExitConnPool {
    /// Builds an exit pool that dials from a fresh local client
    /// endpoint bound to `bind_addr` (use `Ipv4Addr::UNSPECIFIED` with
    /// port 0 in production; tests typically pass loopback). The relay is
    /// anonymous at the TLS layer toward the exit (the exit requests no
    /// client certificate since protocol v5), so no
    /// relay identity is needed here.
    ///
    /// Defaults to the multi-hop transport profile **without** the
    /// Initial-padding knobs. Production relays opt into the
    /// full Warren wire-mimicry profile via
    /// [`Self::new_with_warren_obfuscation`]; tests use this default
    /// to keep loopback handshakes fast (the
    /// split-Initial knobs stall a handshake when the exit's
    /// inbound transport config does not pre-negotiate the matching
    /// transport parameter, which is the case in tests).
    ///
    /// # Errors
    /// - [`ExitPoolError::BindClient`] if the UDP socket cannot be
    ///   bound.
    pub fn new(bind_addr: SocketAddr) -> Result<Self, ExitPoolError> {
        let endpoint = Endpoint::client(bind_addr)?;
        Ok(Self {
            endpoint,
            state: Arc::new(Mutex::new(HashMap::new())),
            webpki_roots: None,
            enable_warren_obfuscation: false,
            enable_gso: true,
        })
    }

    /// Variant of [`Self::new`] that opts into the full Warren
    /// wire-mimicry profile
    /// ([`warren_transport_config_relay_outbound_with_gso`]) for the
    /// relay -> exit dial. Use this constructor in the relay binary
    /// once the matching cross-DC handshake test has cleared the
    /// dial against the exit's vanilla inbound transport config.
    ///
    /// # Errors
    /// - [`ExitPoolError::BindClient`] if the UDP socket cannot be
    ///   bound.
    pub fn new_with_warren_obfuscation(bind_addr: SocketAddr) -> Result<Self, ExitPoolError> {
        let endpoint = Endpoint::client(bind_addr)?;
        Ok(Self {
            endpoint,
            state: Arc::new(Mutex::new(HashMap::new())),
            webpki_roots: None,
            enable_warren_obfuscation: true,
            enable_gso: true,
        })
    }

    /// Overrides the WebPKI trust anchors used for the X.509 relay->exit dial.
    /// Builder-style; chain onto any constructor. `None` (the
    /// default) uses the bundled Mozilla roots. Set this for a private-CA
    /// deployment or an in-memory test CA.
    pub fn with_webpki_roots(mut self, roots: quinn::rustls::RootCertStore) -> Self {
        self.webpki_roots = Some(roots);
        self
    }

    /// Sets UDP segmentation offload for the relay->exit dial. Pass
    /// `false` on KVM/virtio NICs (mirrors the exit binary's
    /// `--no-gso`). Builder-style so callers can chain it onto any of
    /// the constructors. See [`ExitConnPool::enable_gso`].
    pub fn with_gso(mut self, enable_gso: bool) -> Self {
        self.enable_gso = enable_gso;
        self
    }

    /// Convenience constructor binding on `0.0.0.0:0`. Used by the
    /// relay binary; tests usually prefer the explicit
    /// [`Self::new`] form so they can specify loopback bindings.
    ///
    /// # Errors
    /// Same as [`Self::new`].
    pub fn new_default() -> Result<Self, ExitPoolError> {
        Self::new((Ipv4Addr::UNSPECIFIED, 0).into())
    }

    /// Returns the local address the pool's endpoint is bound on.
    ///
    /// # Errors
    /// Propagates the `quinn::Endpoint::local_addr` I/O error.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Dials a **fresh, un-pooled** connection to the exit, bypassing
    /// the cache entirely.
    ///
    /// Use this when each client session needs its own relay->exit
    /// connection: opaque-datagram forwarding cannot be multiplexed onto
    /// a shared connection (a single `read_datagram` loop per connection
    /// would steal datagrams across client sessions), and
    /// [`crate::forward::forward_session`] closes the exit connection
    /// when its client leaves - which would tear down a *pooled*
    /// connection out from under any concurrent or subsequent session.
    /// The dual-role relay therefore dials per session.
    ///
    /// # Errors
    /// Same as [`Self::get_or_create`].
    pub async fn dial_fresh(
        &self,
        descriptor: &ExitDescriptorSigned,
    ) -> Result<Connection, ExitPoolError> {
        self.dial(descriptor).await
    }

    /// Returns the live connection to `descriptor.exit_id`, dialing
    /// fresh on cache miss or on stale entry (`close_reason() != None`).
    ///
    /// # Errors
    /// - [`ExitPoolError::Tls`] when building the client config fails.
    /// - [`ExitPoolError::Connect`] when Quinn rejects the dial setup.
    /// - [`ExitPoolError::Handshake`] when the handshake fails
    ///   (including RPK pin mismatch).
    pub async fn get_or_create(
        &self,
        descriptor: &ExitDescriptorSigned,
    ) -> Result<Arc<Connection>, ExitPoolError> {
        let key = *descriptor.exit_id.as_bytes();
        // Fast path: cache hit + still alive.
        {
            let map = self.state.lock();
            if let Some(conn) = map.get(&key)
                && conn.close_reason().is_none()
            {
                return Ok(conn.clone());
            }
        }

        // Slow path: dial without holding the mutex so concurrent
        // unrelated lookups stay fast.
        let new_conn = self.dial(descriptor).await?;
        let new_conn = Arc::new(new_conn);

        // Re-check under the lock: another task may have raced us and
        // inserted a live connection. If so, drop our connection and
        // return the winner's. This is the standard double-checked
        // insertion pattern for opportunistic pools.
        let mut map = self.state.lock();
        if let Some(existing) = map.get(&key)
            && existing.close_reason().is_none()
        {
            return Ok(existing.clone());
        }
        map.insert(key, new_conn.clone());
        Ok(new_conn)
    }

    async fn dial(&self, descriptor: &ExitDescriptorSigned) -> Result<Connection, ExitPoolError> {
        // In X.509 cover-domain mode the exit serves an ordinary
        // public-CA certificate on its unified :443, so the RPK client config
        // would fail the TLS handshake. Validate the exit's cert via WebPKI and
        // dial its cover domain as the SNI. The exit's Warren identity is bound
        // independently by HPKE (the client seals to the signed
        // `exit_x25519_multihop_pubkey`), so this leg needs no extra in-band
        // proof; the dispatcher may open a server-initiated relay-auth stream,
        // which this dialer simply never accepts.
        let mut client_cfg: ClientConfig = if descriptor.cover_domain.is_some() {
            let roots = self.webpki_roots.clone().unwrap_or_else(mozilla_root_store);
            make_client_config_webpki(roots, default_crypto_provider(), &[ALPN_H3])?
        } else {
            make_client_config(default_crypto_provider(), &[ALPN_H3])?
        };
        // Apply the Warren relay-outbound transport config so the
        // relay -> exit dial benefits from BBR, MTU 1350, DPLPMTUD
        // and 1 Gbps x 50 ms BDP windows. Without this the dial
        // would inherit Quinn's vanilla `initial_mtu = 1200`,
        // collapsing the negotiated path-MTU to ~1100 B and silently
        // dropping multi-hop frames whose plaintext payload reaches
        // ~1000 B (stall). The `enable_warren_obfuscation`
        // toggle controls whether the Initial-padding knobs
        // are also applied (production: yes, tests: no).
        let transport_config = if self.enable_warren_obfuscation {
            warren_transport_config_relay_outbound_with_gso(self.enable_gso)
        } else {
            warren_transport_config_relay_outbound_multihop_with_gso(self.enable_gso)
        };
        client_cfg.transport_config(transport_config);

        // RPK mode: pin the exit's RPK via the SNI (the warren-tls verifier
        // compares the SNI-encoded pubkey to the cert the server presents, so a
        // hostile exit returning a different ed25519 pubkey is rejected at the
        // handshake). X.509 mode: dial the cover domain as the SNI for the
        // WebPKI SAN check.
        let server_name = match &descriptor.cover_domain {
            Some(domain) => domain.clone(),
            None => tls_name::encode(WarrenPubkey::from_bytes(descriptor.exit_ed25519_pubkey)),
        };
        let endpoint = descriptor.endpoint.ok_or(ExitPoolError::MissingEndpoint)?;
        let connecting = self
            .endpoint
            .connect_with(client_cfg, endpoint, &server_name)?;
        let conn = connecting.await?;
        Ok(conn)
    }

    /// Reports whether `exit_id` currently has a live cached connection,
    /// without dialing.
    ///
    /// Lets a caller record an accurate pool-hit/-miss metric around a
    /// [`Self::get_or_create`] call (`is_cached` before, then
    /// `inc_exit_pool_hit`/`inc_exit_pool_miss` after, matching what was
    /// observed) without changing `get_or_create`'s signature, which every
    /// existing call site depends on. This is inherently best-effort under
    /// concurrency (another task may race between the check and the
    /// `get_or_create` call), acceptable for an opportunistic metric on an
    /// opportunistic pool.
    #[must_use]
    pub fn is_cached(&self, exit_id: &ExitId) -> bool {
        let map = self.state.lock();
        map.get(exit_id.as_bytes())
            .is_some_and(|conn| conn.close_reason().is_none())
    }

    /// Number of distinct exit entries currently cached. Test-facing.
    #[doc(hidden)]
    #[must_use]
    pub fn cached_entry_count(&self) -> usize {
        self.state.lock().len()
    }
}
