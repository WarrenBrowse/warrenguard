//! Quinn-backed relay server with the obfuscation baseline knobs.
//!
//! [`RelayServer::new`] binds a `quinn::Endpoint` configured with:
//! - The Warren TLS 1.3 raw-public-key server config (`warrenguard_tls`)
//!   advertising only `[ALPN_H3]`. The legacy `warren/exit/1` ALPN is
//!   not offered on the relay path: any client still on the V1 ALPN
//!   targets the exit directly, never the relay.
//! - [`warren_transport_config_relay_inbound`] (BBR, MTU, spin bit
//!   off, 100 concurrent bidi streams). The Initial-padding
//!   knobs are deliberately limited to the dialer side: see
//!   [`warrenguard_transport_core::warren_transport_config_relay_outbound`] for the
//!   relay-to-exit profile.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use thiserror::Error;
use warrenguard_config::ALPN_H3;
use warrenguard_tls::{WarrenTlsError, default_crypto_provider, make_server_config};
use warrenguard_transport_core::{
    warren_transport_config_relay_inbound, warren_transport_config_relay_inbound_multihop_with_gso,
    warren_transport_config_relay_inbound_with_gso,
};

use crate::config::RelayConfig;

/// Errors raised while bringing up a [`RelayServer`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServerError {
    /// `warren-tls` could not build the rustls/Quinn server config.
    #[error("TLS server config error: {0}")]
    Tls(#[from] WarrenTlsError),
    /// Binding the `quinn::Endpoint` failed (port in use, perms, etc.).
    #[error("failed to bind QUIC endpoint on {addr}: {source}")]
    Bind {
        /// Address we tried to bind.
        addr: std::net::SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// A bound Warren relay server.
///
/// Hold this value alive to keep the relay listening. Dropping it closes
/// the `Endpoint` and rejects all subsequent client dials. Internal
/// state required to service a connection (config, signing key) is held
/// by value so the server is self-contained.
#[must_use]
pub struct RelayServer {
    endpoint: quinn::Endpoint,
    config: Arc<RelayConfig>,
}

impl RelayServer {
    /// Builds a relay server bound to `config.bind_addr` using the
    /// supplied Ed25519 `signing_key` as the relay's QUIC identity.
    ///
    /// The endpoint advertises only `[ALPN_H3]` and uses the
    /// obfuscation-baseline inbound transport config so the wire profile
    /// is Chrome-indistinguishable on the relay-facing side.
    ///
    /// # Errors
    /// - [`ServerError::Tls`] if `warrenguard_tls` rejects the supplied
    ///   crypto provider (unlikely with the default ring provider).
    /// - [`ServerError::Bind`] if binding the UDP socket fails (port
    ///   already in use, missing `CAP_NET_BIND_SERVICE` on port < 1024,
    ///   etc.).
    pub fn new(config: Arc<RelayConfig>, signing_key: &SigningKey) -> Result<Self, ServerError> {
        Self::new_inner(config, signing_key, warren_transport_config_relay_inbound())
    }

    /// Variant of [`Self::new`] with an explicit GSO toggle for the
    /// client-facing inbound listener. Pass `false` on KVM/virtio NICs:
    /// with GSO on, quinn-udp's `UDP_SEGMENT` send gets
    /// `EIO` and loses the in-flight handshake-response packets, which
    /// stalls the client->relay handshake over a real (non-loopback)
    /// path - the dual-role relay runs on the same virtio NIC the exit
    /// already disables GSO on. Mirrors `ExitConnPool::with_gso` for the
    /// outbound leg.
    ///
    /// # Errors
    /// Same as [`Self::new`].
    pub fn new_with_gso(
        config: Arc<RelayConfig>,
        signing_key: &SigningKey,
        enable_gso: bool,
    ) -> Result<Self, ServerError> {
        Self::new_inner(
            config,
            signing_key,
            warren_transport_config_relay_inbound_with_gso(enable_gso),
        )
    }

    /// Multi-hop variant of [`Self::new_with_gso`]: the inbound
    /// listener uses [`warren_transport_config_relay_inbound_multihop_with_gso`],
    /// which drops the Initial-padding knobs.
    ///
    /// The dual-role relay forwarder MUST use this constructor: the
    /// multi-hop client leg dials with the no-pad profile, so a padded
    /// ServerHello on this listener would stall the handshake on a real
    /// network path whenever the path MTU dips below the pad target.
    ///
    /// # Errors
    /// Same as [`Self::new`].
    pub fn new_multihop_with_gso(
        config: Arc<RelayConfig>,
        signing_key: &SigningKey,
        enable_gso: bool,
    ) -> Result<Self, ServerError> {
        Self::new_inner(
            config,
            signing_key,
            warren_transport_config_relay_inbound_multihop_with_gso(enable_gso),
        )
    }

    fn new_inner(
        config: Arc<RelayConfig>,
        signing_key: &SigningKey,
        transport: std::sync::Arc<quinn::TransportConfig>,
    ) -> Result<Self, ServerError> {
        let provider = default_crypto_provider();
        let mut server_cfg = make_server_config(signing_key, provider, &[ALPN_H3])?;
        server_cfg.transport_config(transport);
        // QUIC connection migration: the client-facing relay hop
        // accepts address
        // migration so a WiFi<->ethernet/4G handover revalidates the
        // path (~1 RTT PATH_CHALLENGE) instead of forcing a full
        // re-handshake. This deliberately overrides the
        // `migration(false)` default from `make_server_config`: the
        // timing-correlation argument protects the
        // EXIT (invariant #7, which keeps `migration(false)` there);
        // the relay already terminates the client connection and sees
        // the client IP, and PATH_CHALLENGE is only ever triggered by
        // packets that decrypt under the established connection keys,
        // which an off-path attacker cannot forge.
        server_cfg.migration(true);

        let bind_addr = config.bind_addr;
        let endpoint =
            quinn::Endpoint::server(server_cfg, bind_addr).map_err(|source| ServerError::Bind {
                addr: bind_addr,
                source,
            })?;

        Ok(Self { endpoint, config })
    }

    /// Returns the address the relay is actually bound to.
    ///
    /// Useful when `config.bind_addr` requested port `0`: the OS picks
    /// the actual port and tests need to dial it back.
    ///
    /// # Errors
    /// Propagates the `quinn::Endpoint::local_addr` I/O error.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Returns the relay's loaded config. The pool inside is what the
    /// session handler consults on every first datagram.
    #[must_use]
    pub fn config(&self) -> &Arc<RelayConfig> {
        &self.config
    }

    /// Returns a clone of the underlying `quinn::Endpoint`. Exposed so
    /// the binary's signal handler can call `wait_idle()` for graceful
    /// shutdown after the accept loop has been cancelled.
    #[must_use]
    pub fn endpoint(&self) -> quinn::Endpoint {
        self.endpoint.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ed25519_dalek::{Signer, SigningKey};
    use warrenguard_multihop::ExitId;

    use super::*;
    use crate::config::ExitDescriptorSigned;
    use crate::pki::exit_descriptor_signing_payload;

    fn det_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed_descriptor(
        op: &SigningKey,
        exit_id: ExitId,
        x25519: [u8; 32],
        endpoint: &str,
    ) -> ExitDescriptorSigned {
        let payload = exit_descriptor_signing_payload(exit_id, &x25519);
        let sig = op.sign(&payload);
        ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: [0xEE; 32],
            exit_x25519_multihop_pubkey: x25519,
            endpoint: Some(endpoint.parse().expect("static addr parses")),
            cover_domain: None,
            signature: sig.to_bytes(),
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        }
    }

    fn loopback_config(op: &SigningKey) -> RelayConfig {
        RelayConfig {
            bind_addr: "127.0.0.1:0".parse().expect("static addr parses"),
            signing_key_path: PathBuf::from("/dev/null"),
            operational_pubkey: op.verifying_key(),
            exits: vec![signed_descriptor(
                op,
                ExitId::from_bytes([0xAA; 16]),
                [0x11; 32],
                "10.0.0.1:443",
            )],
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_addr_reports_a_bound_loopback_port() {
        let op = det_signing_key(0x42);
        let signing_key = det_signing_key(0x77);
        let cfg = Arc::new(loopback_config(&op));
        let server = RelayServer::new(cfg, &signing_key).expect("server binds on 127.0.0.1:0");
        let addr = server.local_addr().expect("local_addr after bind");
        assert!(addr.ip().is_loopback(), "expected loopback ip, got {addr}");
        assert_ne!(addr.port(), 0, "OS-assigned port must be non-zero");
    }
}
