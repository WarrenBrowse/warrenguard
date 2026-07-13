//! Client side of the Warren tunnel - initiates the Quinn connection
//! to the exit, runs the `Setup` / `SetupAck` handshake, and pumps
//! datagrams <-> TUN.
//!
//! The client is anonymous at the TLS layer (the exit requests no client
//! certificate since protocol v5). It proves its
//! Ed25519 identity in-band by signing this connection's channel binding
//! (via [`warrenguard_tls::sign_client_auth`]) and carrying the proof
//! in `Setup`. The exit's identity is still pinned: the SNI carries the
//! expected exit pubkey via [`warrenguard_tls::name::encode`] and the
//! server-cert verifier checks it. Relay-mode and DNS discovery are out of
//! scope: Warren is strictly direct-dial.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use quinn::{Connection, Endpoint};
use warrenguard_config::{ALPN_H3, MAX_CONNECTIONS_PER_SESSION};
use warrenguard_wire::{
    MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, SessionToken, Setup, SetupAck, SetupV7,
    WarrenExitAddr, WarrenPubkey, decode_setup_ack, decode_setup_ack_v7, encode_setup_v7,
};
use zeroize::Zeroize;

use crate::MultiSession;
use warrenguard_socket_bypass::SocketBypass;
use warrenguard_transport_core::error::{Result, TunnelError};

/// Warren tunnel client: holds an Ed25519 keypair (ephemeral via
/// [`Self::new`] for tests, persistent via [`Self::with_signing_key`]
/// backed by `derive_node_key`), and can initiate a
/// handshake with an `ExitListener`.
pub struct ClientTunnel {
    signing_key: SigningKey,
    use_warren_tuning: bool,
    /// When `false`, disables UDP_SEGMENT offload upfront via
    /// `enable_segmentation_offload(false)`. Set to `false` on KVM/virtio
    /// NICs that don't support hardware UDP segmentation. Default
    /// `true` (best perf on bare metal).
    enable_gso: bool,
    /// Client features bitmask (cf. `warrenguard_wire::features`). Default 0
    /// (back-compat with v0 client). Set via [`Self::with_features`] to
    /// announce `IPV6`, `MULTIPATH`, etc.
    features: u32,
    /// When `true`, the client advertises DAITA v2 support via
    /// `Setup::daita_support`. The exit MAY then return a `DaitaConfig`
    /// in `SetupAck::daita_spec`; the client side mirrors that spec
    /// locally to drive its own [`DaitaFramework`]. Default `false`
    /// (opt-in via [`Self::with_daita`]).
    daita_support: bool,
    /// When `true`, the client transport config
    /// DISABLES the keep-alive PING and the consumer MUST run the
    /// idle-cover pump (`pump_*_with_idle_cover`) so jittered, size-varied
    /// dummies refresh the NAT mapping and reset the idle timeout instead
    /// of the fixed-period beacon (a passive traffic-analysis tell). The
    /// config and the pump MUST flip together: enabling this without the
    /// matching pump leaves the connection with no liveness mechanism
    /// beyond the idle timeout. Default `false` at the struct level: the
    /// consumer wires [`Self::with_idle_cover`] from the `WARREN_IDLE_COVER`
    /// knob (default on). Mutually exclusive with DAITA (DAITA provides its own
    /// cover), so the consumer sets this only when DAITA is not requested.
    idle_cover: bool,
    /// When `true` (Stealth profile), the client transport config pads every
    /// outgoing QUIC packet to the path MTU (`TransportConfig::pad_to_mtu`), so
    /// uplink packet sizes are uniform and do not leak inner-payload lengths to
    /// a passive observer. Costs uplink bandwidth (small packets are padded to
    /// the full MTU), so it is opt-in via [`Self::with_pad_to_mtu`] and off by
    /// default. Independent of the `features::PAD_TO_MTU` advisory wire bit.
    pad_to_mtu: bool,
    /// When `Some`, the client Quinn `Endpoint` is bound on this
    /// specific `SocketAddr` (i.e. the client public eth0/wlan0 IP).
    /// Useful in multi-NIC setups to force the outbound interface. When
    /// `None`, binds on the family-appropriate unspecified address
    /// (0.0.0.0:0 or [::]:0).
    bind_local_ip: Option<SocketAddr>,
    /// Random, **ephemeral per-run** device identifier announced in every
    /// `Setup.device_id`. Generated once at construction and shared by
    /// the primary + all multi-conn connections of this client, so the
    /// exit counts this whole client as **one** device when enforcing
    /// its per-account device cap. Never persisted.
    device_id: [u8; warrenguard_wire::DEVICE_ID_LEN],
    /// ALPN protocols offered in the QUIC/TLS handshake, in preference
    /// order. Defaults to `[ALPN_H3]` (the HTTP/3-mimicry obfuscation
    /// value). Set via [`Self::with_alpn_protocols`] to source the value
    /// from the v6 exit-list endpoint instead of the compile-time
    /// constant, so the server can drive the connection-type/obfuscation
    /// profile without an app release.
    alpn_protocols: Vec<Vec<u8>>,
    /// v7 anonymous session tokens (Privacy Pass). When `Some` and
    /// non-empty, the single-conn handshake sends a [`SetupV7`] presenting
    /// these Privacy Pass tokens instead of the v6 wallet-signed [`Setup`], so
    /// the exit admits the session WITHOUT learning the wallet. token[0] is
    /// spent; the rest are an epoch-rollover lookahead. `None`/empty keeps the
    /// v6 wallet-authenticated path. Set via [`Self::with_session_tokens`].
    session_tokens: Option<Vec<SessionToken>>,
    /// v6 X.509 exit mode. `Some((roots, server_name))`
    /// switches the client to validate the exit's real X.509 chain via
    /// WebPKI against `roots` (custom DER anchors or the bundled Mozilla
    /// program) and to dial the cover-domain `server_name` as SNI, instead
    /// of pinning the exit's Ed25519 raw public key encoded in the SNI. The
    /// exit's Warren identity is then verified in-band
    /// (`SetupAck::exit_auth_sig`). `None` (default) keeps the RPK-via-SNI
    /// handshake.
    x509: Option<(X509Roots, String)>,
    /// When `Some`, the endpoint's UDP socket is marked/bound to the physical
    /// link BEFORE its first send, so it stays out of the full-tunnel capture a
    /// system-VPN datapath installs (`SO_MARK` on Linux, `IP_BOUND_IF` on macOS,
    /// `IP_UNICAST_IF` on Windows). This replaces the old `<exit_ip>/32` host
    /// route: keying the escape on the socket, not the destination, is what
    /// closes Port Fail / TunnelCrack ServerIP. `None` (default) for the userland
    /// proxy datapath (no OS tunnel to bypass) and mobile (handled by
    /// `VpnService.protect` / the NE exemption). Set via
    /// [`Self::with_socket_bypass`]. Fail-closed: if the mark/bind cannot be set,
    /// the endpoint bind fails rather than letting the socket leak.
    socket_bypass: Option<SocketBypass>,
}

/// Trust anchors a v6 X.509 client validates the exit chain against.
#[derive(Clone)]
enum X509Roots {
    /// Explicit DER trust anchors: a self-hosted CA, or a test CA fixture.
    Der(Vec<Vec<u8>>),
    /// The bundled Mozilla CA root program, for an exit that presents a
    /// public-ACME certificate (the production path).
    Mozilla,
}

impl ClientTunnel {
    /// Build a client with a fresh keypair (POC / test mode).
    /// Warren tuning is enabled by default; see [`Self::with_warren_tuning`]
    /// to disable for comparative benches.
    #[must_use]
    pub fn new() -> Self {
        // `rand::random::<[u8; 32]>()` ultimately taps `OsRng`; pinning
        // the seed shape here avoids the `SigningKey::generate` API
        // path, whose `CryptoRng + RngCore` bounds couple to a specific
        // `rand_core` version through `ed25519-dalek 2.x` that may not
        // match the workspace `rand` pin.
        let mut seed: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&seed);
        // The raw seed is a copy of the private key; wipe it once the
        // ZeroizeOnDrop `SigningKey` holds it, so it never lingers on the stack.
        seed.zeroize();
        Self {
            signing_key,
            use_warren_tuning: true,
            enable_gso: true,
            features: 0,
            daita_support: false,
            idle_cover: false,
            pad_to_mtu: false,
            bind_local_ip: None,
            device_id: rand::random(),
            alpn_protocols: vec![ALPN_H3.to_vec()],
            x509: None,
            session_tokens: None,
            socket_bypass: None,
        }
    }

    /// Build a client from a caller-provided Ed25519 `SigningKey`,
    /// typically obtained via `derive_node_key`. Allows
    /// reusing the same Warren identity across client restarts.
    #[must_use]
    pub fn with_signing_key(signing: &SigningKey) -> Self {
        Self {
            signing_key: signing.clone(),
            use_warren_tuning: true,
            enable_gso: true,
            features: 0,
            daita_support: false,
            idle_cover: false,
            pad_to_mtu: false,
            bind_local_ip: None,
            device_id: rand::random(),
            alpn_protocols: vec![ALPN_H3.to_vec()],
            x509: None,
            session_tokens: None,
            socket_bypass: None,
        }
    }

    /// Sets the ALPN protocols offered in the handshake, in preference
    /// order, sourced from the selected exit's v6 listener(s). Empty
    /// input is ignored (keeps the `[ALPN_H3]` default) so a malformed
    /// list can never produce a no-ALPN client config (QUIC requires
    /// at least one).
    ///
    /// Bridge contract: callers pass UTF-8-encoded ALPN tokens obtained
    /// from their relay descriptor (e.g. a `dial_alpns` field). The default
    /// token `"h3"` encodes to [`ALPN_H3`]; keep the two in sync.
    #[must_use]
    pub fn with_alpn_protocols(mut self, alpns: Vec<Vec<u8>>) -> Self {
        if !alpns.is_empty() {
            self.alpn_protocols = alpns;
        }
        self
    }

    /// Opt the client into the v6 X.509 exit mode: validate the exit's
    /// real certificate chain via WebPKI against `roots_der` (DER trust
    /// anchors, e.g. the Mozilla roots in prod or a test CA in tests) and
    /// dial `server_name` (the cover domain) as SNI, instead of pinning the
    /// exit's Ed25519 raw public key in the SNI. The exit's Warren identity
    /// is then verified in-band (`SetupAck::exit_auth_sig`), independent of
    /// the SNI. The matching exit must run with `ExitBindOpts::tls_certificate`
    /// set. Leave unset (default) for the RPK-via-SNI handshake.
    #[must_use]
    pub fn with_x509(mut self, roots_der: Vec<Vec<u8>>, server_name: String) -> Self {
        self.x509 = Some((X509Roots::Der(roots_der), server_name));
        self
    }

    /// Opt the client into X.509 mode validating the exit chain against the
    /// bundled Mozilla CA root program (the production path: the exit
    /// presents a public-ACME wildcard certificate for the cover domain).
    /// `server_name` is the cover-domain SNI to dial. Like [`Self::with_x509`]
    /// the exit's Warren identity is then verified in-band, independent of
    /// the SNI and the WebPKI chain.
    #[must_use]
    pub fn with_x509_webpki(mut self, server_name: String) -> Self {
        self.x509 = Some((X509Roots::Mozilla, server_name));
        self
    }

    /// The SNI to dial: the cover domain in X.509 mode, otherwise the
    /// exit's pubkey encoded as a hostname (RPK pinning).
    ///
    /// In X.509 mode the per-exit cover domain from the signed roster
    /// (`target.cover_domain`) takes precedence over the fixed builder/env
    /// domain, so a multi-exit client dials each exit's own (rotatable) cover
    /// domain; the fixed value is the fallback for a roster that carries none.
    fn dial_server_name(&self, target: &WarrenExitAddr) -> String {
        match &self.x509 {
            Some((_, fixed)) => target.cover_domain.clone().unwrap_or_else(|| fixed.clone()),
            None => warrenguard_tls::name::encode(target.id),
        }
    }

    /// Override the per-run `Setup::device_id`. The constructor already
    /// picks a random id; this builder lets callers (tests, or a host
    /// app that owns a stable device id) pin a specific value. All
    /// connections of the client - primary plus every multi-conn
    /// secondary - carry the stamped id so the exit sees ONE device.
    #[must_use]
    pub fn with_device_id(mut self, device_id: [u8; warrenguard_wire::DEVICE_ID_LEN]) -> Self {
        self.device_id = device_id;
        self
    }

    /// Provide v7 anonymous session tokens for the handshake. When the slice
    /// is non-empty, the single-conn [`Self::connect`] path sends a
    /// [`SetupV7`] presenting these tokens instead of the v6 wallet-signed
    /// [`Setup`], so the exit admits the session without learning the wallet.
    /// The first token is spent; any others are an epoch-rollover lookahead
    /// (bounded by [`warrenguard_wire::MAX_SESSION_TOKENS`], the exit rejects
    /// more). An empty slice clears the tokens and restores the v6 path.
    #[must_use]
    pub fn with_session_tokens(mut self, tokens: Vec<SessionToken>) -> Self {
        self.session_tokens = (!tokens.is_empty()).then_some(tokens);
        self
    }

    /// Enable or disable Warren tuning (BBR + MTU 1350 + BDP windows + idle
    /// 60s). Disable only to bench the delta vs Quinn defaults; prod
    /// must always leave it enabled.
    #[must_use]
    pub fn with_warren_tuning(mut self, enabled: bool) -> Self {
        self.use_warren_tuning = enabled;
        self
    }

    /// Enable or disable UDP segmentation offload (GSO) at the QUIC
    /// transport layer. `false` is required on KVM/virtio NICs
    /// (`tx-udp-segmentation: off [fixed]`); otherwise quinn-udp tries,
    /// gets `EIO`, halts and falls back. Default `true` (best perf on bare
    /// metal that supports GSO).
    #[must_use]
    pub fn with_gso(mut self, enabled: bool) -> Self {
        self.enable_gso = enabled;
        self
    }

    /// Announce client features in the `Setup.features` bitmask
    /// (cf. `warrenguard_wire::features`). Combine with bitwise OR:
    ///
    /// ```ignore
    /// let client = ClientTunnel::new()
    ///     .with_features(features::IPV6 | features::PORT_FORWARD);
    /// ```
    #[must_use]
    pub fn with_features(mut self, features: u32) -> Self {
        self.features = features;
        self
    }

    /// Opt the client into DAITA v2: the handshake `Setup` carries
    /// `daita_support = true`, prompting the exit to ship a
    /// [`warrenguard_wire::DaitaConfig`] in `SetupAck::daita_spec`
    /// (when the exit has a configured pool). The client then mirrors
    /// the spec to instantiate a local `DaitaFramework` (driven by the pump).
    ///
    /// Pass `enable = false` to explicitly opt out (default).
    #[must_use]
    pub fn with_daita(mut self, enable: bool) -> Self {
        self.daita_support = enable;
        self
    }

    /// True if the client advertises DAITA v2 support. Observability
    /// hook for tests / metrics: the exit decides whether to honour
    /// the request based on its own pool configuration.
    #[must_use]
    pub fn daita_support(&self) -> bool {
        self.daita_support
    }

    /// Opt the client into idle cover: the client
    /// transport config disables the fixed keep-alive PING and the
    /// consumer MUST run the matching idle-cover pump
    /// (`pump_bidirectional_with_idle_cover` /
    /// `pump_multi_bidirectional_with_idle_cover`) so jittered,
    /// size-varied dummies refresh NAT and reset the idle timeout instead
    /// of the browser-anomalous fixed-period beacon.
    ///
    /// The consumer reads [`Self::idle_cover`] to pick that pump, so the
    /// config and pump always flip together. Leave `false` (default) when
    /// DAITA is requested: DAITA provides its own cover and the two are
    /// mutually exclusive.
    #[must_use]
    pub fn with_idle_cover(mut self, enabled: bool) -> Self {
        self.idle_cover = enabled;
        self
    }

    /// True if the client disables the keep-alive PING in favour of the
    /// idle-cover pump. The pump dispatch MUST read this and run the
    /// `*_with_idle_cover` variant when set, or the connection has no
    /// liveness beyond the idle timeout.
    #[must_use]
    pub fn idle_cover(&self) -> bool {
        self.idle_cover
    }

    /// Resolves the client's cover-defense request from a single
    /// [`warrenguard_config::knobs::CoverDefenses`] and flips
    /// [`Self::with_daita`] and [`Self::with_idle_cover`] together.
    ///
    /// This is the knob-driven switch: the consumer resolves the coupled
    /// decision once from the process knobs via
    /// [`warrenguard_config::knobs::cover_defenses`] (which enforces the
    /// DAITA / idle-cover mutual exclusion) and threads it here, so the
    /// handshake advertisement (`daita_support`) and the pump selection
    /// (`idle_cover`) can never disagree. Off by default: a client that never
    /// calls this requests neither defense.
    #[must_use]
    pub fn with_cover_defenses(
        mut self,
        defenses: warrenguard_config::knobs::CoverDefenses,
    ) -> Self {
        self.daita_support = defenses.daita;
        self.idle_cover = defenses.idle_cover;
        self
    }

    /// Enable Stealth-profile uplink padding: the client transport config pads
    /// every outgoing QUIC packet to the path MTU so uplink packet sizes are
    /// uniform (a traffic-analysis defense). Off by default; costs uplink
    /// bandwidth.
    #[must_use]
    pub fn with_pad_to_mtu(mut self, enabled: bool) -> Self {
        self.pad_to_mtu = enabled;
        self
    }

    /// True if the client pads its uplink QUIC packets to the path MTU.
    #[must_use]
    pub fn pad_to_mtu(&self) -> bool {
        self.pad_to_mtu
    }

    /// Bind the client Quinn `Endpoint` on this specific `SocketAddr`
    /// instead of the family-default unspecified address. Useful in
    /// multi-NIC setups to force the outbound interface (e.g. when the
    /// host has both Ethernet and Wi-Fi up and the routing table would
    /// otherwise pick the wrong one).
    #[must_use]
    pub fn with_bind_local_ip(mut self, addr: SocketAddr) -> Self {
        self.bind_local_ip = Some(addr);
        self
    }

    /// Keep the endpoint's UDP socket on the physical link, out of the
    /// full-tunnel capture a system-VPN datapath installs, via a socket-level
    /// mark/bind (`SO_MARK` on Linux, `IP_BOUND_IF` on macOS, `IP_UNICAST_IF` on
    /// Windows). The privileged TUN datapath sets this so it can drop the old
    /// `<exit_ip>/32` host route: with the escape keyed on the socket instead of
    /// the exit destination, application traffic to the exit IP is tunnelled like
    /// everything else and cannot leak (Port Fail / TunnelCrack ServerIP). Leave
    /// unset for the userland proxy (no OS tunnel) and mobile (`VpnService`).
    #[must_use]
    pub fn with_socket_bypass(mut self, bypass: SocketBypass) -> Self {
        self.socket_bypass = Some(bypass);
        self
    }

    /// The socket bypass pinned by [`Self::with_socket_bypass`], if any.
    #[must_use]
    pub fn socket_bypass(&self) -> Option<SocketBypass> {
        self.socket_bypass
    }

    /// Ed25519 public key of this client. Stable identifier announced
    /// during the QUIC TLS handshake (via [`warrenguard_tls`]) and embedded
    /// in future signed Warren API requests.
    #[must_use]
    pub fn node_id(&self) -> WarrenPubkey {
        WarrenPubkey::from_bytes(*self.signing_key.verifying_key().as_bytes())
    }

    /// Returns the bind address pinned by [`Self::with_bind_local_ip`],
    /// or `None` when the client uses the family-default unspecified
    /// bind. Used by client-binary tests to assert that
    /// the prod build chain always pins a specific interface.
    #[must_use]
    pub fn bind_local_ip(&self) -> Option<SocketAddr> {
        self.bind_local_ip
    }

    /// Establishes the Quinn connection to `target`, opens a
    /// bidirectional stream, sends `Setup`, reads `SetupAck`, returns it.
    ///
    /// # Errors
    ///
    /// Client bind error, connect error, or malformed frame.
    pub async fn handshake(&self, target: WarrenExitAddr) -> Result<SetupAck> {
        self.handshake_with_version(target, PROTOCOL_VERSION).await
    }

    /// Variant of [`Self::handshake`] that allows injecting an arbitrary
    /// protocol version. Used by tests to verify that the exit rejects
    /// unknown versions.
    ///
    /// Not part of the supported public API surface: exists only so this
    /// crate's and downstream consumers' tests can exercise the version
    /// mismatch path. `#[doc(hidden)]` rather than `#[cfg(test)]`-gated,
    /// since a downstream consumer's own integration test already depends
    /// on this being compiled in a normal (non-test) build of this crate.
    ///
    /// # Errors
    ///
    /// See [`Self::handshake`].
    #[doc(hidden)]
    pub async fn handshake_with_version(
        &self,
        target: WarrenExitAddr,
        protocol_version: u8,
    ) -> Result<SetupAck> {
        let remote = pick_remote_addr(&target)?;
        let endpoint = self.bind_client_endpoint(remote)?;
        let server_name = self.dial_server_name(&target);
        let conn = endpoint
            .connect(remote, &server_name)
            .map_err(|source| TunnelError::QuicConnect {
                target: remote.to_string(),
                source,
            })?
            .await
            .map_err(|source| TunnelError::QuicConnection {
                context: "connect to exit",
                source,
            })?;
        let (mut send, mut recv) =
            conn.open_bi()
                .await
                .map_err(|source| TunnelError::QuicConnection {
                    context: "open_bi",
                    source,
                })?;

        // Bypass `encode_setup` to inject an arbitrary version: `encode_setup`
        // has no runtime version validation, but going through the same
        // serialization is cleaner.
        let setup = Setup {
            protocol_version,
            features: self.features,
            connection_index: 0,
            total_connections: 1,
            daita_support: self.daita_support,
            device_id: self.device_id,
            // Stamped by `stamp_inband_auth` just below; zero placeholders here.
            client_pubkey: [0u8; warrenguard_wire::CLIENT_PUBKEY_LEN],
            auth_sig: warrenguard_wire::AuthSig([0u8; warrenguard_wire::AUTH_SIG_LEN]),
        };
        // Stamp the real in-band auth proof so the normal `handshake()` path
        // (version == PROTOCOL_VERSION) authenticates. For the version-inject
        // test path the exit rejects at decode (version gate) BEFORE the auth
        // check, so a valid proof here is harmless to that test.
        let setup = stamp_inband_auth(setup, &conn, &self.signing_key)?;
        let bytes = postcard::to_allocvec(&setup).map_err(|e| TunnelError::SetupWire {
            context: "encode Setup".into(),
            source: Box::new(e),
        })?;
        send.write_all(&bytes)
            .await
            .map_err(|e| TunnelError::QuicStream {
                context: "write Setup".into(),
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| TunnelError::QuicStream {
            context: "finish stream".into(),
            source: Box::new(e),
        })?;

        let resp = recv.read_to_end(MAX_SETUP_FRAME_BYTES).await.map_err(|e| {
            handshake_rejection(&conn).unwrap_or_else(|| TunnelError::QuicStream {
                context: "read SetupAck".into(),
                source: Box::new(e),
            })
        })?;
        let ack = decode_setup_ack(&resp).map_err(|e| TunnelError::SetupWire {
            context: "decode SetupAck".into(),
            source: Box::new(e),
        })?;

        verify_exit_identity(&conn, target.id, &ack)?;
        Ok(ack)
    }
}

impl Default for ClientTunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientTunnel {
    /// Variant of [`Self::handshake`] that returns an active [`ClientSession`]
    /// usable to send/receive QUIC RFC 9221 datagrams, equivalent to the
    /// IP pipe of the tunnel.
    ///
    /// # Errors
    ///
    /// See [`Self::handshake`].
    pub async fn connect(&self, target: WarrenExitAddr) -> Result<ClientSession> {
        let remote = pick_remote_addr(&target)?;
        let endpoint = self.bind_client_endpoint(remote)?;
        let server_name = self.dial_server_name(&target);
        let conn = endpoint
            .connect(remote, &server_name)
            .map_err(|source| TunnelError::QuicConnect {
                target: remote.to_string(),
                source,
            })?
            .await
            .map_err(|source| TunnelError::QuicConnection {
                context: "connect to exit",
                source,
            })?;
        self.from_established_connection(endpoint, conn, target.id)
            .await
    }

    /// Completes the Setup/SetupAck handshake on an already-established QUIC
    /// connection and returns the active [`ClientSession`], skipping the dial
    /// performed by [`Self::connect`].
    ///
    /// For callers that dial the exit through their own QUIC glue (a
    /// different bind/transport-config seam than [`Self::bind_client_endpoint`])
    /// and only need this crate's Setup/SetupAck protocol logic layered on top.
    /// `expected_exit_pubkey` is checked against the in-band exit-identity
    /// proof (`SetupAck::exit_auth_sig`, v6), independent of
    /// however the caller pinned the exit's identity at the TLS layer.
    ///
    /// # Errors
    ///
    /// See [`Self::connect`].
    pub async fn from_established_connection(
        &self,
        endpoint: Endpoint,
        conn: Connection,
        expected_exit_pubkey: WarrenPubkey,
    ) -> Result<ClientSession> {
        let (mut send, mut recv) =
            conn.open_bi()
                .await
                .map_err(|source| TunnelError::QuicConnection {
                    context: "open_bi",
                    source,
                })?;

        // v7 anonymous path: if session tokens were provided, present them
        // instead of the wallet-signed v6 Setup. The exit verifies token[0]
        // offline and never learns the wallet.
        if let Some(tokens) = self.session_tokens.clone() {
            return self
                .handshake_v7_single(endpoint, conn, expected_exit_pubkey, send, recv, tokens)
                .await;
        }

        // Stamp the per-run device_id so the exit keys the session by
        // `(pubkey, device_id)` (v2 device cap). Without this the
        // single-conn path would always send the all-zero sentinel and
        // two distinct devices of one account would collide on one IP.
        let setup = Setup::single_conn(self.features).with_device_id(self.device_id);
        let setup = stamp_inband_auth(setup, &conn, &self.signing_key)?;
        let bytes = postcard::to_allocvec(&setup).map_err(|e| TunnelError::SetupWire {
            context: "encode Setup".into(),
            source: Box::new(e),
        })?;
        send.write_all(&bytes)
            .await
            .map_err(|e| TunnelError::QuicStream {
                context: "write Setup".into(),
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| TunnelError::QuicStream {
            context: "finish stream".into(),
            source: Box::new(e),
        })?;

        let resp = recv.read_to_end(MAX_SETUP_FRAME_BYTES).await.map_err(|e| {
            handshake_rejection(&conn).unwrap_or_else(|| TunnelError::QuicStream {
                context: "read SetupAck".into(),
                source: Box::new(e),
            })
        })?;
        let ack = decode_setup_ack(&resp).map_err(|e| TunnelError::SetupWire {
            context: "decode SetupAck".into(),
            source: Box::new(e),
        })?;

        verify_exit_identity(&conn, expected_exit_pubkey, &ack)?;
        Ok(ClientSession {
            // Keep the endpoint alive for the lifetime of the session,
            // otherwise the connection dies in early drop.
            _endpoint: endpoint,
            conn,
            assigned_ipv4: std::net::Ipv4Addr::from(ack.tunnel_ipv4),
            assigned_ipv6: ack.tunnel_ipv6.map(std::net::Ipv6Addr::from),
            assigned_max_mtu: ack.max_mtu,
            daita_spec: ack.daita_spec,
        })
    }

    /// v7 single-conn handshake: send a [`SetupV7`] primary presenting
    /// `tokens`, decode the [`SetupAckV7`], verify the exit identity in-band
    /// (same channel binding as v6), and build the session. The exit spends
    /// token[0] and never learns the wallet.
    async fn handshake_v7_single(
        &self,
        endpoint: Endpoint,
        conn: Connection,
        expected_exit_pubkey: WarrenPubkey,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        tokens: Vec<SessionToken>,
    ) -> Result<ClientSession> {
        let mut setup = SetupV7::primary_single(self.features, self.device_id, tokens);
        setup.daita_support = self.daita_support;
        let bytes = encode_setup_v7(&setup).map_err(|e| TunnelError::SetupWire {
            context: "encode SetupV7".into(),
            source: Box::new(e),
        })?;
        send.write_all(&bytes)
            .await
            .map_err(|e| TunnelError::QuicStream {
                context: "write SetupV7".into(),
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| TunnelError::QuicStream {
            context: "finish stream".into(),
            source: Box::new(e),
        })?;

        let resp = recv.read_to_end(MAX_SETUP_FRAME_BYTES).await.map_err(|e| {
            handshake_rejection(&conn).unwrap_or_else(|| TunnelError::QuicStream {
                context: "read SetupAckV7".into(),
                source: Box::new(e),
            })
        })?;
        let ack = decode_setup_ack_v7(&resp).map_err(|e| TunnelError::SetupWire {
            context: "decode SetupAckV7".into(),
            source: Box::new(e),
        })?;

        // Same in-band exit-identity proof as v6 (`exit_auth_sig` over the
        // channel binding); the ack layout differs but the field is identical.
        let cb = warrenguard_tls::channel_binding(&conn)
            .map_err(|_| TunnelError::ChannelBindingExport)?;
        if !warrenguard_tls::verify_server_auth(&expected_exit_pubkey, &cb, &ack.exit_auth_sig.0) {
            return Err(TunnelError::ExitAuthFailed);
        }
        Ok(ClientSession {
            _endpoint: endpoint,
            conn,
            assigned_ipv4: std::net::Ipv4Addr::from(ack.tunnel_ipv4),
            assigned_ipv6: ack.tunnel_ipv6.map(std::net::Ipv6Addr::from),
            assigned_max_mtu: ack.max_mtu,
            daita_spec: ack.daita_spec,
        })
    }

    /// Multi-conn: opens `n` parallel QUIC connections to the same exit,
    /// all signed by this shared Ed25519 identity. The exit aggregates
    /// these N conns under a single session (cf. the exit listener)
    /// and assigns them **the same** tunnel IP.
    ///
    /// All connections are multiplexed over a **single** Quinn endpoint
    /// (i.e. one local UDP socket). The N `Connection`s are distinct QUIC
    /// objects above this socket - their internal Quinn locks are
    /// independent, allowing the tokio scheduler to serve them on
    /// different cores (real perf gain vs `tokio::spawn` on a single
    /// `Connection`).
    ///
    /// Connection index `0` is the **primary**: it receives the IP from
    /// SetupAck. The remaining N-1 secondaries (index 1..N-1) wait for
    /// the primary to succeed before sending their Setup, so the exit
    /// can attach them to the existing session.
    ///
    /// # Errors
    ///
    /// Bind, connect, or handshake errors. If the primary fails, returns
    /// immediately. If a secondary fails, also returns (no partial
    /// fallback, session consistency is required).
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` (absurd: 0 conns = no tunnel).
    pub async fn connect_multi(&self, target: WarrenExitAddr, n: u8) -> Result<MultiSession> {
        assert!(n >= 1, "connect_multi requires at least one connection");
        // Client-side cap validation: fail fast rather than paying the
        // TCP/TLS cost only to be refused by the exit.
        if n > MAX_CONNECTIONS_PER_SESSION {
            return Err(TunnelError::Protocol(format!(
                "connect_multi(N={n}) > MAX_CONNECTIONS_PER_SESSION ({MAX_CONNECTIONS_PER_SESSION}): \
                 Warren-side DoS cap. Reduce N or bump the constant."
            )));
        }

        let remote = pick_remote_addr(&target)?;
        // Spread the N connections across up to N independent client endpoints
        // (one UDP socket each), so the session's datapath I/O runs on several
        // endpoint drivers instead of funnelling through one. Distinct client
        // source ports also let a SO_REUSEPORT exit hash the flows across
        // cores. `WARREN_CLIENT_DATAPATH_SOCKETS` controls the count; auto (the
        // default) is one endpoint per connection. Connection `i` is dialed on
        // `endpoints[i % endpoints.len()]`.
        let ep_count = warrenguard_config::knobs::client_datapath_sockets(n as usize);
        let mut endpoints = Vec::with_capacity(ep_count);
        for _ in 0..ep_count {
            endpoints.push(self.bind_client_endpoint(remote)?);
        }
        let server_name = self.dial_server_name(&target);

        // Primary (idx=0): wait for it first to retrieve the assigned IP.
        // Secondaries rely on the session being already known on the exit.
        let primary_conn = endpoints[0]
            .connect(remote, &server_name)
            .map_err(|source| TunnelError::QuicConnect {
                target: remote.to_string(),
                source,
            })?
            .await
            .map_err(|source| TunnelError::QuicConnection {
                context: "primary connect to exit",
                source,
            })?;
        let primary_ack = handshake_one(
            &primary_conn,
            &self.signing_key,
            target.id,
            self.features,
            self.daita_support,
            0,
            n,
            self.device_id,
        )
        .await?;
        if !primary_ack.multiconn_attached {
            return Err(TunnelError::Protocol(
                "exit refused primary multiconn attachment (multiconn_attached=false)".to_owned(),
            ));
        }

        let mut conns: Vec<Connection> = Vec::with_capacity(n as usize);
        conns.push(primary_conn);

        // Secondaries: connect + handshake **sequentially**. The parallel
        // pattern (`try_join_all`) had non-deterministic behavior on N>=3
        // (intermittent timeouts) - the exit accept loop is sequential, so
        // parallelizing on the client brings no measurable handshake gain
        // (a few ms total). The real perf win is on the **pump** once the
        // session is established.
        for idx in 1..n {
            let conn = endpoints[idx as usize % endpoints.len()]
                .connect(remote, &server_name)
                .map_err(|source| TunnelError::QuicConnect {
                    target: format!("{remote} [secondary {idx}]"),
                    source,
                })?
                .await
                .map_err(|source| TunnelError::QuicConnection {
                    context: "secondary connect to exit",
                    source,
                })?;
            // Reuse the same features as the primary so the exit interprets
            // them consistently (same session = same flags).
            let ack = handshake_one(
                &conn,
                &self.signing_key,
                target.id,
                self.features,
                self.daita_support,
                idx,
                n,
                self.device_id,
            )
            .await?;
            if !ack.multiconn_attached {
                return Err(TunnelError::Protocol(format!(
                    "exit refused secondary[{idx}] multiconn attachment \
                     (multiconn_attached=false)"
                )));
            }
            if ack.tunnel_ipv4 != primary_ack.tunnel_ipv4 {
                return Err(TunnelError::Protocol(format!(
                    "exit assigned different IP to secondary[{idx}] \
                     ({:?}) vs primary ({:?}) - exit aggregation broken",
                    ack.tunnel_ipv4, primary_ack.tunnel_ipv4
                )));
            }
            conns.push(conn);
        }

        MultiSession::new(
            endpoints,
            conns,
            std::net::Ipv4Addr::from(primary_ack.tunnel_ipv4),
            primary_ack.tunnel_ipv6.map(std::net::Ipv6Addr::from),
            primary_ack.max_mtu,
            primary_ack.daita_spec,
        )
    }

    /// Forge a single handshake with arbitrary `(connection_index, total)`,
    /// short-circuiting the primary-first logic of `connect_multi`. Allows
    /// testing the refusal paths on the exit (e.g. secondary arriving
    /// without a known primary).
    ///
    /// **Not for prod use**, does not consume the `Connection` into a
    /// `MultiSession`, just returns the raw `SetupAck` for assertion.
    ///
    /// # Errors
    ///
    /// I/O on the `Endpoint`, `Setup` encoding, or `SetupAck` decoding.
    #[doc(hidden)]
    pub async fn forge_handshake_for_test(
        &self,
        target: WarrenExitAddr,
        idx: u8,
        total: u8,
    ) -> Result<SetupAck> {
        let remote = pick_remote_addr(&target)?;
        let endpoint = self.bind_client_endpoint(remote)?;
        let server_name = self.dial_server_name(&target);
        let conn = endpoint
            .connect(remote, &server_name)
            .map_err(|source| TunnelError::QuicConnect {
                target: remote.to_string(),
                source,
            })?
            .await
            .map_err(|source| TunnelError::QuicConnection {
                context: "forge_handshake_for_test connect",
                source,
            })?;
        handshake_one(
            &conn,
            &self.signing_key,
            target.id,
            self.features,
            self.daita_support,
            idx,
            total,
            self.device_id,
        )
        .await
    }

    /// Builds the Warren-configured client Quinn `Endpoint` and installs
    /// the RPK-based default client config + Warren transport tuning.
    /// Centralizes the bind + crypto plumbing used by `connect`,
    /// `connect_multi`, `handshake_*`, and the test-only helpers.
    fn bind_client_endpoint(&self, remote: SocketAddr) -> Result<Endpoint> {
        let bind_addr = match self.bind_local_ip {
            Some(addr) => addr,
            None => match remote {
                SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                }
            },
        };
        // On Android the endpoint socket must be protected (routed onto the
        // underlying physical network) BEFORE it sends anything, or the VPN
        // routes loop the QUIC handshake back into the TUN. We bind the
        // socket ourselves so we can `VpnService.protect` its fd, then hand
        // it to quinn. On every other platform `Endpoint::client` (which is
        // exactly bind + `Endpoint::new`) is kept verbatim.
        #[cfg(target_os = "android")]
        let mut endpoint = {
            use std::os::fd::AsRawFd;
            let socket =
                std::net::UdpSocket::bind(bind_addr).map_err(|source| TunnelError::Bind {
                    addr: bind_addr.to_string(),
                    source,
                })?;
            if !crate::socket_protect::protect(socket.as_raw_fd()) {
                return Err(TunnelError::Bind {
                    addr: bind_addr.to_string(),
                    source: std::io::Error::other("VpnService.protect rejected the tunnel socket"),
                });
            }
            let runtime = quinn::default_runtime().ok_or_else(|| {
                TunnelError::Internal("no async runtime for quinn endpoint".to_owned())
            })?;
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime).map_err(
                |source| TunnelError::Bind {
                    addr: bind_addr.to_string(),
                    source,
                },
            )?
        };
        // Desktop: when a system-VPN datapath is active it configures a
        // `socket_bypass`, so we bind our own socket, mark/bind it to the
        // physical link BEFORE quinn sends anything, then hand it to quinn. This
        // is the desktop analogue of the Android `protect` path above and lets
        // the datapath drop the `<exit_ip>/32` host route (Port Fail fix).
        // Fail-closed: a socket whose bypass cannot be set must not egress. With
        // no bypass configured (userland proxy), `Endpoint::client` is kept
        // verbatim.
        #[cfg(not(target_os = "android"))]
        let mut endpoint = match self.socket_bypass {
            Some(bypass) => {
                let socket =
                    std::net::UdpSocket::bind(bind_addr).map_err(|source| TunnelError::Bind {
                        addr: bind_addr.to_string(),
                        source,
                    })?;
                warrenguard_socket_bypass::apply(&socket, bypass).map_err(|source| {
                    TunnelError::Bind {
                        addr: bind_addr.to_string(),
                        source,
                    }
                })?;
                let runtime = quinn::default_runtime().ok_or_else(|| {
                    TunnelError::Internal("no async runtime for quinn endpoint".to_owned())
                })?;
                quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
                    .map_err(|source| TunnelError::Bind {
                        addr: bind_addr.to_string(),
                        source,
                    })?
            }
            None => quinn::Endpoint::client(bind_addr).map_err(|source| TunnelError::Bind {
                addr: bind_addr.to_string(),
                source,
            })?,
        };
        let alpns: Vec<&[u8]> = self.alpn_protocols.iter().map(Vec::as_slice).collect();
        let mut client_cfg = if let Some((roots, _)) = &self.x509 {
            // v6 X.509 exit mode: validate the exit's real cert
            // chain via WebPKI like a browser; the Warren identity is checked
            // separately in-band (verify_exit_identity / exit_auth_sig).
            let store = match roots {
                X509Roots::Der(ders) => {
                    let (store, added) = warrenguard_tls::root_store_from_der(ders);
                    if added == 0 {
                        // Fail closed: an all-unparseable root set would build
                        // a WebPKI config that trusts nothing and silently
                        // fails every handshake. Surface it at bind time.
                        return Err(TunnelError::Internal(
                            "X.509 mode: no valid root certificate in the supplied anchors".into(),
                        ));
                    }
                    store
                }
                X509Roots::Mozilla => {
                    let store = warrenguard_tls::mozilla_root_store();
                    if store.is_empty() {
                        // Fail closed, symmetric with the Der arm: an empty
                        // trust store would build a WebPKI config that trusts
                        // nothing and silently fails every handshake. Surface
                        // it at bind time instead.
                        return Err(TunnelError::Internal(
                            "X.509 mode: bundled Mozilla root store is empty".into(),
                        ));
                    }
                    store
                }
            };
            warrenguard_tls::make_client_config_webpki(
                store,
                warrenguard_tls::default_crypto_provider(),
                &alpns,
            )
        } else {
            warrenguard_tls::make_client_config(warrenguard_tls::default_crypto_provider(), &alpns)
        }
        .map_err(|e| TunnelError::Internal(format!("build TLS client config failed: {e}")))?;
        if self.use_warren_tuning {
            // With `pad_to_mtu=false, idle_cover=false` this is byte-identical
            // to the historical `..._with_gso(gso)`. `idle_cover` disables the
            // keep-alive PING (the consumer runs the idle-cover pump instead);
            // `pad_to_mtu` pads uplink packets to the MTU (Stealth profile).
            client_cfg.transport_config(
                warrenguard_transport_core::warren_transport_config_client_full(
                    self.enable_gso,
                    self.pad_to_mtu,
                    self.idle_cover,
                ),
            );
        }
        endpoint.set_default_client_config(client_cfg);
        Ok(endpoint)
    }
}

/// Pick the first SocketAddr from a [`WarrenExitAddr`]. Returns an
/// error if the address list is empty.
fn pick_remote_addr(target: &WarrenExitAddr) -> Result<SocketAddr> {
    target.ip_addrs().next().ok_or(TunnelError::NoExitAddr)
}

/// Maps an exit application-close *code* to the structured, non-retryable
/// [`TunnelError`] business rejection it represents, if any.
///
/// Pure (no live connection needed) so the mapping table is unit-tested
/// directly. Returns `None` for any code that is not a Warren business
/// rejection, so the caller keeps the underlying transport error.
///
/// This is the client end of the rejection-reason contract: the exit's
/// listener closes the QUIC connection with a distinct application code per
/// business reason, and the client turns it back into a precise error the
/// daemon/UI can show the user instead of a misleading generic "connection
/// lost" / "no matching relay".
fn rejection_from_close_code(code: quinn::VarInt) -> Option<TunnelError> {
    if code == warrenguard_transport_core::constants::WARREN_AUTH_FAILED {
        // Identity not authorized: no active subscription / not enrolled.
        Some(TunnelError::AuthRejected)
    } else if code == warrenguard_transport_core::constants::WARREN_DEVICE_LIMIT {
        // Account already at its max simultaneous devices.
        Some(TunnelError::DeviceLimitReached)
    } else if code == warrenguard_transport_core::constants::WARREN_EXIT_DRAINING {
        // The exit is draining for maintenance: retrying THIS exit is
        // pointless, the caller must re-select another one.
        Some(TunnelError::ExitDrainingRefused)
    } else {
        None
    }
}

/// If `conn` was closed by the exit with a Warren business-rejection
/// application code, returns the matching structured [`TunnelError`].
///
/// We inspect [`Connection::close_reason`] rather than down-casting the
/// read-error chain: it is the canonical source of the peer's close code
/// in quinn 0.11 and is set by the time the stream read fails with
/// `ConnectionLost`. A rejection MUST NOT be retried (retrying re-derives
/// the same outcome and, upstream, surfaces a misleading "no matching
/// relay"); the user needs to act (renew subscription, free a device…).
fn handshake_rejection(conn: &Connection) -> Option<TunnelError> {
    match conn.close_reason() {
        Some(quinn::ConnectionError::ApplicationClosed(close)) => {
            rejection_from_close_code(close.error_code)
        }
        _ => None,
    }
}

/// Stamps the in-band client auth proof (protocol v5) onto `setup`: signs a
/// message binding THIS connection's QUIC TLS channel binding and the
/// session `device_id` with the client identity key, and records
/// `(client_pubkey, auth_sig)`. The exit requests no TLS client certificate
/// (an active-probing tell; see `warrenguard-tls::auth`),
/// so this is how the client proves its identity. Each QUIC connection has a
/// distinct channel binding, so every connection of a multi-conn session is
/// stamped individually (over the same shared `device_id`).
fn stamp_inband_auth(setup: Setup, conn: &Connection, signing_key: &SigningKey) -> Result<Setup> {
    let cb =
        warrenguard_tls::channel_binding(conn).map_err(|_| TunnelError::ChannelBindingExport)?;
    let sig = warrenguard_tls::sign_client_auth(signing_key, &cb, &setup.device_id);
    Ok(setup.with_auth(*signing_key.verifying_key().as_bytes(), sig))
}

/// Internal helper: opens a bidirectional stream on `conn`, sends `Setup`
/// with `(idx, total)`, reads `SetupAck`. Factors out the handshake for
/// `connect()` mono-conn and `connect_multi()` N-conn.
/// Verifies the in-band exit-identity proof in `SetupAck` (v6 X.509 exit mode):
/// the exit must have signed THIS connection's channel binding with the
/// Ed25519 identity the client dialed (`expected`). This is what lets the
/// client trust the exit once it presents an ordinary X.509 certificate
/// instead of a raw public key: a man-in-the-middle holding a valid cert
/// for the cover domain still cannot forge the exit's signature.
fn verify_exit_identity(conn: &Connection, expected: WarrenPubkey, ack: &SetupAck) -> Result<()> {
    let cb =
        warrenguard_tls::channel_binding(conn).map_err(|_| TunnelError::ChannelBindingExport)?;
    if warrenguard_tls::verify_server_auth(&expected, &cb, &ack.exit_auth_sig.0) {
        Ok(())
    } else {
        Err(TunnelError::ExitAuthFailed)
    }
}

// Internal multi-conn handshake helper; the parameters mirror the
// per-connection handshake inputs (identity, expected exit, features,
// DAITA, conn index/total, device id). Bundling them into a struct would
// add an indirection that only this private call path uses.
#[allow(clippy::too_many_arguments)]
async fn handshake_one(
    conn: &Connection,
    signing_key: &SigningKey,
    expected_exit_pubkey: WarrenPubkey,
    features: u32,
    daita_support: bool,
    idx: u8,
    total: u8,
    device_id: [u8; warrenguard_wire::DEVICE_ID_LEN],
) -> Result<SetupAck> {
    let (mut send, mut recv) =
        conn.open_bi()
            .await
            .map_err(|source| TunnelError::QuicConnection {
                context: "open_bi",
                source,
            })?;
    // Stamp the per-run device_id on every connection so the exit counts
    // one device for this whole session (primary + multi-conn secondaries).
    let setup = if total == 1 {
        if daita_support {
            Setup::single_conn_with_daita(features)
        } else {
            Setup::single_conn(features)
        }
    } else if daita_support {
        Setup::multi_conn_with_daita(features, idx, total)
    } else {
        Setup::multi_conn(features, idx, total)
    }
    .with_device_id(device_id);
    let setup = stamp_inband_auth(setup, conn, signing_key)?;
    let bytes = postcard::to_allocvec(&setup).map_err(|e| TunnelError::SetupWire {
        context: format!("encode Setup (idx={idx})").into(),
        source: Box::new(e),
    })?;
    send.write_all(&bytes)
        .await
        .map_err(|e| TunnelError::QuicStream {
            context: format!("write Setup (idx={idx})").into(),
            source: Box::new(e),
        })?;
    send.finish().map_err(|e| TunnelError::QuicStream {
        context: format!("finish stream (idx={idx})").into(),
        source: Box::new(e),
    })?;
    let resp = recv.read_to_end(MAX_SETUP_FRAME_BYTES).await.map_err(|e| {
        handshake_rejection(conn).unwrap_or_else(|| TunnelError::QuicStream {
            context: format!("read SetupAck (idx={idx})").into(),
            source: Box::new(e),
        })
    })?;
    let ack = decode_setup_ack(&resp).map_err(|e| TunnelError::SetupWire {
        context: format!("decode SetupAck (idx={idx})").into(),
        source: Box::new(e),
    })?;
    verify_exit_identity(conn, expected_exit_pubkey, &ack)?;
    Ok(ack)
}

/// Active client session: tunnel open, ready to pump datagrams.
pub struct ClientSession {
    _endpoint: Endpoint,
    conn: Connection,
    assigned_ipv4: std::net::Ipv4Addr,
    /// Optional tunnel IPv6 (`Some` when the client announced
    /// `features::IPV6` and the exit allocated one).
    assigned_ipv6: Option<std::net::Ipv6Addr>,
    assigned_max_mtu: u16,
    /// DAITA v2 machine spec negotiated by the exit at handshake time.
    /// `None` when the client did not opt-in
    /// (`Setup::daita_support = false`) or when the exit had no
    /// `DaitaPool` configured. A caller's pump adapter
    /// reads this to decide whether to invoke
    /// [`warrenguard_pump::pump_bidirectional_with_daita`] instead of the
    /// regular [`warrenguard_pump::pump_bidirectional`].
    daita_spec: Option<warrenguard_wire::DaitaConfig>,
}

impl ClientSession {
    /// Sends a QUIC datagram (unreliable, unordered, RFC 9221).
    ///
    /// # Errors
    ///
    /// Datagram too large for the path MTU, or connection closed.
    pub fn send_datagram(&self, payload: Vec<u8>) -> Result<()> {
        self.conn
            .send_datagram(Bytes::from(payload))
            .map_err(|source| TunnelError::QuicSendDatagram {
                context: "client".into(),
                source,
            })
    }

    /// Awaits the next incoming datagram.
    ///
    /// # Errors
    ///
    /// Connection closed, or corrupt datagram.
    pub async fn read_datagram(&self) -> Result<Bytes> {
        self.conn
            .read_datagram()
            .await
            .map_err(|source| TunnelError::QuicReadDatagram {
                context: "client".into(),
                source,
            })
    }

    /// Returns a copy of the underlying `Connection`. `Connection` is
    /// `Clone` (internal Arc); this lets callers spawn pumps in separate
    /// tasks without transferring session ownership.
    #[must_use]
    pub fn clone_conn(&self) -> Connection {
        self.conn.clone()
    }

    /// Tunnel IPv4 assigned by the exit in the `SetupAck`.
    #[must_use]
    pub fn assigned_ipv4(&self) -> std::net::Ipv4Addr {
        self.assigned_ipv4
    }

    /// Optional tunnel IPv6 assigned by the exit.
    #[must_use]
    pub fn assigned_ipv6(&self) -> Option<std::net::Ipv6Addr> {
        self.assigned_ipv6
    }

    /// The conservative session MTU the exit advertised in the `SetupAck`.
    /// Advisory only: it is a fixed value, not negotiated, and the real path
    /// MTU is governed by QUIC DPLPMTUD. Do not size a TUN directly to it.
    #[must_use]
    pub fn assigned_max_mtu(&self) -> u16 {
        self.assigned_max_mtu
    }

    /// Maximum size of a QUIC RFC 9221 datagram on this connection, as
    /// imposed by the path MTU and the peer-announced limit.
    ///
    /// Returns `None` if datagrams are not supported by the peer (should
    /// not happen on the Warren side).
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// DAITA v2 spec negotiated at handshake. `None` when the
    /// session runs without traffic-analysis defense (client opted out
    /// or exit refused). The adapter consumes this to decide between
    /// [`warrenguard_pump::pump_bidirectional`] (no DAITA) and
    /// [`warrenguard_pump::pump_bidirectional_with_daita`].
    #[must_use]
    pub fn daita_spec(&self) -> Option<&warrenguard_wire::DaitaConfig> {
        self.daita_spec.as_ref()
    }

    /// Sends a QUIC datagram, accepting anything convertible into
    /// [`bytes::Bytes`] so a caller already holding a `Bytes` (or a `Vec<u8>`,
    /// which converts into one without a copy) can send it as-is. Distinct
    /// from [`Self::send_datagram`] (which always takes ownership of a
    /// `Vec<u8>`) only in the accepted input type; behaves identically
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send_datagram`].
    pub fn send_datagram_bytes(&self, payload: impl Into<Bytes>) -> Result<()> {
        self.conn
            .send_datagram(payload.into())
            .map_err(|source| TunnelError::QuicSendDatagram {
                context: "client".into(),
                source,
            })
    }

    /// The largest inner payload a cover datagram can carry on the current
    /// path. Falls back to the 1280-byte base MTU before the first PMTU
    /// probe. Unlike the multihop path there is no per-datagram sealing
    /// overhead to subtract: a single-hop datagram carries the inner packet
    /// (or DAITA padding) directly.
    #[must_use]
    pub fn max_inner_payload(&self) -> usize {
        const BASE_MTU: usize = 1280;
        self.conn.max_datagram_size().unwrap_or(BASE_MTU)
    }

    /// Sends one DAITA cover (dummy) datagram: a
    /// [`warrenguard_pump::DAITA_DUMMY_FIRST_BYTE`] tag followed by
    /// `padding_len` zero bytes. The exit drops it (the first byte is not a
    /// valid IP version), so it shapes traffic without reaching the
    /// destination.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send_datagram`].
    pub fn send_cover_traffic(&self, padding_len: usize) -> Result<()> {
        let mut dummy = Vec::with_capacity(padding_len + 1);
        dummy.push(warrenguard_pump::DAITA_DUMMY_FIRST_BYTE);
        dummy.resize(padding_len + 1, 0u8);
        self.send_datagram(dummy)
    }

    /// Builds a [`warrenguard_daita::DaitaState`] from [`Self::daita_spec`],
    /// ready to drive cover traffic on this session. Returns `None` if the
    /// exit did not negotiate DAITA.
    ///
    /// # Errors
    ///
    /// [`warrenguard_daita::DaitaError`] if the negotiated machine spec is
    /// unparseable or a cap is out of range (the maybenot framework rejects
    /// the configuration).
    #[must_use]
    pub fn build_daita_state(
        &self,
        start_time: std::time::Instant,
    ) -> Option<std::result::Result<warrenguard_daita::DaitaState, warrenguard_daita::DaitaError>>
    {
        let spec = self.daita_spec.as_ref()?;
        let cfg = warrenguard_daita::DaitaConfig::from_specs(
            spec.machine_specs.clone(),
            spec.max_padding_frac,
            spec.max_blocking_frac,
        );
        Some(warrenguard_daita::DaitaState::from_config(&cfg, start_time))
    }

    /// Closes the connection cleanly.
    pub fn disconnect(&self) {
        self.conn.close(0u32.into(), b"client disconnect");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_to_mtu_builder_defaults_off_and_threads_through() {
        // Stealth profile: uplink padding is opt-in. Default OFF so
        // the client does not silently pay the bandwidth cost, and the builder
        // threads the flag into the transport config.
        assert!(
            !ClientTunnel::new().pad_to_mtu(),
            "pad_to_mtu must default OFF"
        );
        assert!(
            ClientTunnel::new().with_pad_to_mtu(true).pad_to_mtu(),
            "with_pad_to_mtu(true) must enable the flag"
        );
        assert!(
            !ClientTunnel::new()
                .with_pad_to_mtu(true)
                .with_pad_to_mtu(false)
                .pad_to_mtu(),
            "with_pad_to_mtu(false) must clear it"
        );
    }

    #[test]
    fn idle_cover_builder_defaults_off_and_threads_through() {
        // idle cover is opt-in. The default MUST be off so the
        // keep-alive PING (NAT refresh + liveness) is never silently
        // disabled, and the builder MUST thread the flag so the consumer
        // can pick the matching idle-cover pump. Config and pump flip
        // together or the connection loses its only liveness mechanism.
        assert!(
            !ClientTunnel::new().idle_cover(),
            "idle cover must default OFF (keep-alive stays on)"
        );
        assert!(
            ClientTunnel::new().with_idle_cover(true).idle_cover(),
            "with_idle_cover(true) must enable the flag the pump dispatch reads"
        );
        assert!(
            !ClientTunnel::new()
                .with_idle_cover(true)
                .with_idle_cover(false)
                .idle_cover(),
            "with_idle_cover(false) must re-disable it"
        );
    }

    #[test]
    fn with_cover_defenses_threads_the_resolved_knob_switch() {
        use warrenguard_config::knobs::resolve_cover_defenses;

        // The knob-driven client switch: resolve the coupled decision once
        // and flip both flags together, so the DAITA / idle-cover mutual
        // exclusion the resolver enforces reaches the handshake and the pump.
        let daita_only =
            ClientTunnel::new().with_cover_defenses(resolve_cover_defenses(true, true));
        assert!(
            daita_only.daita_support(),
            "requesting DAITA must set daita_support so the handshake advertises it"
        );
        assert!(
            !daita_only.idle_cover(),
            "DAITA supersedes idle cover: with_cover_defenses must not enable idle cover \
             while DAITA is requested"
        );

        let idle_only =
            ClientTunnel::new().with_cover_defenses(resolve_cover_defenses(false, true));
        assert!(
            idle_only.idle_cover() && !idle_only.daita_support(),
            "idle-cover-only defenses must enable idle cover and leave DAITA off"
        );

        let plain = ClientTunnel::new().with_cover_defenses(resolve_cover_defenses(false, false));
        assert!(
            !plain.daita_support() && !plain.idle_cover(),
            "no knob set must leave both defenses off (default byte-identical path)"
        );
    }

    #[test]
    fn cover_defenses_default_off_on_a_fresh_client() {
        // The struct stays neutral: a fresh client requests neither defense,
        // so a build that never calls the switches is unchanged. The consumer
        // resolves the WARREN_DAITA / WARREN_IDLE_COVER knobs (idle cover is
        // on by default THERE) and flips the switches accordingly.
        let c = ClientTunnel::new();
        assert!(
            !c.daita_support() && !c.idle_cover(),
            "a fresh ClientTunnel must default to no cover defense (the knobs are wired by the \
             consumer, not the struct)"
        );
    }

    #[test]
    fn auth_failed_close_code_maps_to_auth_rejected() {
        assert!(
            matches!(
                rejection_from_close_code(
                    warrenguard_transport_core::constants::WARREN_AUTH_FAILED
                ),
                Some(TunnelError::AuthRejected)
            ),
            "WARREN_AUTH_FAILED must surface as the non-retryable AuthRejected so the UI \
             shows 'identity not authorized' instead of a generic connection loss"
        );
    }

    #[test]
    fn device_limit_close_code_maps_to_device_limit_reached() {
        // Regression: the device-cap rejection used to fall through to a
        // generic transport error and surface upstream as a misleading
        // "no exit available" instead of a clear device-limit message.
        assert!(
            matches!(
                rejection_from_close_code(
                    warrenguard_transport_core::constants::WARREN_DEVICE_LIMIT
                ),
                Some(TunnelError::DeviceLimitReached)
            ),
            "WARREN_DEVICE_LIMIT must surface as the non-retryable DeviceLimitReached"
        );
    }

    #[test]
    fn unknown_close_code_is_not_a_business_rejection() {
        // A non-Warren application code must keep the underlying transport
        // error (caller falls back to QuicStream), never be misread as a
        // business rejection.
        assert!(
            rejection_from_close_code(quinn::VarInt::from_u32(0x0000_0001)).is_none(),
            "unknown codes must not map to a business rejection"
        );
    }
}

/// Live loopback tests: a minimal fake exit completes the real Setup/SetupAck
/// exchange (including a correctly-signed `exit_auth_sig`), exercising
/// [`ClientTunnel::from_established_connection`] end-to-end and the userland
/// accessors ([`ClientSession::max_inner_payload`],
/// [`ClientSession::send_cover_traffic`], [`ClientSession::send_datagram_bytes`],
/// [`ClientSession::build_daita_state`]) a delegating SDK wrapper relies on.
#[cfg(test)]
mod live_session_tests {
    use ed25519_dalek::SigningKey;
    use warrenguard_wire::{AuthSig, decode_setup, encode_setup_ack};

    use super::*;

    /// Spawns a loopback exit whose TLS RPK identity is `tls_key` (so the
    /// client's SNI pin succeeds), decodes the client's `Setup`, replies with
    /// a `SetupAck` signed by `auth_sign_key` (negotiating `daita_spec` when
    /// `Some`), then echoes every datagram back. Passing a `auth_sign_key`
    /// distinct from `tls_key` forges the in-band exit-identity proof while
    /// keeping the TLS-layer identity valid, isolating the exit_auth_sig
    /// check from the SNI pin. Returns the bound address.
    async fn spawn_fake_exit(
        tls_key: SigningKey,
        auth_sign_key: SigningKey,
        daita_spec: Option<warrenguard_wire::DaitaConfig>,
    ) -> SocketAddr {
        let exit_pubkey = tls_key.verifying_key().to_bytes();
        let cfg = warrenguard_tls::make_server_config(
            &tls_key,
            warrenguard_tls::default_crypto_provider(),
            &[b"h3"],
        )
        .expect("server config");
        let endpoint =
            quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).expect("server bind");
        let addr = endpoint.local_addr().expect("local addr");

        tokio::spawn(async move {
            let conn = endpoint
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            let bytes = recv
                .read_to_end(MAX_SETUP_FRAME_BYTES)
                .await
                .expect("read setup");
            let _setup = decode_setup(&bytes).expect("decode setup");

            let cb = warrenguard_tls::channel_binding(&conn).expect("server channel binding");
            let ack = SetupAck {
                protocol_version: PROTOCOL_VERSION,
                tunnel_ipv4: [10, 77, 0, 2],
                tunnel_ipv6: None,
                exit_pubkey,
                max_mtu: 1350,
                multiconn_attached: true,
                daita_spec,
                exit_auth_sig: AuthSig(warrenguard_tls::sign_server_auth(&auth_sign_key, &cb)),
            };
            send.write_all(&encode_setup_ack(&ack).expect("encode ack"))
                .await
                .expect("write ack");
            send.finish().expect("finish");

            while let Ok(dg) = conn.read_datagram().await {
                if conn.send_datagram(dg).is_err() {
                    break;
                }
            }
            drop(endpoint);
        });

        addr
    }

    #[tokio::test]
    async fn connect_verifies_exit_auth_sig_and_the_new_accessors_work() {
        let exit_key = SigningKey::from_bytes(&[0x42; 32]);
        let exit_pubkey = exit_key.verifying_key().to_bytes();

        let machine = warrenguard_daita::DaitaPool::default_pool()
            .pick_named_os("tamaraw")
            .expect("tamaraw is in the default pool");
        let daita_spec = warrenguard_wire::DaitaConfig {
            machine_specs: machine.machine_specs.clone(),
            max_padding_frac: machine.max_padding_frac,
            max_blocking_frac: machine.max_blocking_frac,
        };
        let addr = spawn_fake_exit(exit_key.clone(), exit_key, Some(daita_spec)).await;

        let client_key = SigningKey::from_bytes(&[0x24; 32]);
        let target = WarrenExitAddr::from_ip_addrs(WarrenPubkey::from_bytes(exit_pubkey), [addr]);
        let session = ClientTunnel::with_signing_key(&client_key)
            .connect(target)
            .await
            .expect("connect must succeed against a correctly-signed exit_auth_sig");

        assert_eq!(
            session.assigned_ipv4(),
            std::net::Ipv4Addr::new(10, 77, 0, 2)
        );
        assert!(
            session.max_inner_payload() > 0,
            "must fall back to the base MTU"
        );
        session
            .send_cover_traffic(16)
            .expect("send_cover_traffic must succeed on a live session");
        session
            .send_datagram_bytes(bytes::Bytes::from_static(b"zero-copy"))
            .expect("send_datagram_bytes must succeed on a live session");

        let state = session
            .build_daita_state(std::time::Instant::now())
            .expect("daita_spec was negotiated, so build_daita_state must return Some")
            .expect("the curated tamaraw spec must build a valid DaitaState");
        assert!(state.is_enabled());

        session.disconnect();
    }

    #[tokio::test]
    async fn connect_rejects_a_forged_exit_auth_sig() {
        // TLS identity is correct (the client's SNI pin succeeds and the
        // handshake completes), but the exit signs SetupAck.exit_auth_sig
        // with a DIFFERENT key: the in-band exit-identity proof must fail to
        // verify even though the TLS layer already accepted the peer.
        let tls_key = SigningKey::from_bytes(&[0x42; 32]);
        let impostor_key = SigningKey::from_bytes(&[0x99; 32]);
        let exit_pubkey = tls_key.verifying_key().to_bytes();
        let addr = spawn_fake_exit(tls_key, impostor_key, None).await;

        let client_key = SigningKey::from_bytes(&[0x24; 32]);
        let target = WarrenExitAddr::from_ip_addrs(WarrenPubkey::from_bytes(exit_pubkey), [addr]);
        // `ClientSession` is not `Debug` (no-log discipline), so match directly
        // rather than `Result::expect_err`.
        let err = match ClientTunnel::with_signing_key(&client_key)
            .connect(target)
            .await
        {
            Ok(_) => panic!("a SetupAck signed by a different key must be rejected"),
            Err(e) => e,
        };
        assert!(
            matches!(err, TunnelError::ExitAuthFailed),
            "expected ExitAuthFailed, got {err:?}"
        );
    }
}
