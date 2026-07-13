//! Exit side of the Warren tunnel - accepts incoming Quinn connections,
//! runs the `Setup` / `SetupAck` handshake, and pumps datagrams <-> TUN.

mod accept;
mod device_cap;
mod drain;
mod session;
mod session_token;

// Re-export public types so external consumers keep the same path.
pub use device_cap::{AdmitResult, BoxFuture, DeviceCapEnforcer, DeviceCapError};
pub use drain::ExitDrainSignal;
pub use session::{ExitPeerSourcesHandle, ExitRevocationHandle, ExitSessionsHandle};
pub use session_token::{
    SessionTokenAdmitter, TOKEN_SERIAL_LEN, TokenAdmission, attach_secret_for_serial,
    session_key_value,
};
// Re-export `pub(crate)` types for sibling crate modules.
pub(crate) use session::{MultiSessionState, SessionKey};
// Items used by sub-modules but not outside the `exit` module.
use session::{attribute_session, attribute_session_v7, close_connections_for_impl};

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use quinn::Endpoint;
use tokio::sync::Mutex as AsyncMutex;
use warrenguard_config::ALPN_H3;
use warrenguard_wire::{
    MAX_SETUP_FRAME_BYTES, PROTOCOL_VERSION, PROTOCOL_VERSION_V7, Setup, SetupAck, SetupAckV7,
    WarrenExitAddr, WarrenPubkey, WarrenTransportAddr, decode_setup, decode_setup_v7,
    encode_setup_ack, encode_setup_ack_v7,
};

use crate::allowlist::AllowlistHandle;
use crate::exit_state::PersistedState;
use crate::unauthenticated::UnauthenticatedHandler;
use warrenguard_daita::daita_pool::DaitaPool;
use warrenguard_transport_core::constants::{
    H3_GENERAL_PROTOCOL_ERROR, WARREN_AUTH_FAILED, WARREN_DEVICE_LIMIT, WARREN_DEVICE_LIMIT_REASON,
    WARREN_EXIT_DRAINING, WARREN_EXIT_DRAINING_REASON, WARREN_NO_CAPACITY,
    WARREN_NO_CAPACITY_REASON,
};
use warrenguard_transport_core::error::{Result, TunnelError};

/// Runtime options for [`ExitListener::bind_with_opts`].
///
/// `Debug` is implemented manually because [`Self::device_cap_enforcer`]
/// holds a `dyn` trait object that is not `Debug`; it is rendered as a
/// presence flag.
#[derive(Clone)]
pub struct ExitBindOpts {
    /// Enables Warren tuning (BBR, MTU 1350, BDP windows, idle 60s).
    /// `true` by default. Disable only to bench the measurable benefit
    /// of tuning vs Quinn defaults.
    pub use_warren_tuning: bool,

    /// Ed25519 `SigningKey` for persistent identity. `None` = generate an
    /// ephemeral keypair on each boot (POC default). For stable production
    /// exits, provide a key derived from a BIP39 mnemonic via
    /// `derive_node_key`.
    pub signing_key: Option<SigningKey>,

    /// Previous signing keys accepted during a key rotation overlap
    /// window. Clients that still pin an old pubkey will connect
    /// with the old key in their SNI; the TLS resolver presents the
    /// matching key. Empty = no rotation in progress (default).
    pub previous_signing_keys: Vec<SigningKey>,

    /// When `false`, disables UDP_SEGMENT offload upfront. Set to `false`
    /// on cloud KVM/virtio NICs that don't support hardware UDP
    /// segmentation. Default `true`.
    pub enable_gso: bool,

    /// When `true` (Stealth-exit deployment), the exit transport config pads
    /// every outgoing QUIC packet to the path MTU so downlink packet sizes are
    /// uniform (a traffic-analysis defense, the exit-side counterpart of the
    /// client's `ClientTunnel::with_pad_to_mtu`). Endpoint-wide: it
    /// applies to every connection this exit serves, so enable it only on an
    /// exit dedicated to the Stealth profile. Default `false`; costs downlink
    /// bandwidth.
    pub pad_to_mtu: bool,

    /// Path to the JSON state file for multi-client persistence
    /// (session -> tunnel IP hints). `None` = no persistence (POC /
    /// test mode, state lost on restart). For production, provide a
    /// stable path like `/var/lib/warren/state.json`.
    pub state_file: Option<PathBuf>,

    /// Maximum number of tunnel IPv4 addresses (= concurrent
    /// single-hop sessions) this exit hands out, clamped to the
    /// 10.66.0.0/16 pool size. `None` = the full pool (65 533 hosts).
    /// Lower it to bound per-exit session fan-out, or in tests that
    /// exercise pool exhaustion.
    pub ipv4_pool_capacity: Option<u16>,

    /// Per-`WarrenPubkey` rate limit on the **downlink** (exit -> client).
    /// `None` = no limit. `Some(bps)` = each identity has a token bucket
    /// of `bps` bytes/second, capacity = 1 second of burst.
    ///
    /// Typical conversions: 100 Mbps = 12_500_000 B/s.
    /// 1 Gbps = 125_000_000 B/s.
    pub rate_limit_per_client_bps: Option<u64>,

    /// Same as the downlink limiter but for the **uplink** (client -> exit
    /// -> Internet). Distinct bucket from the downlink: a client may have
    /// asymmetric quotas (e.g. 100 Mbps down + 50 Mbps up).
    pub rate_limit_uplink_per_client_bps: Option<u64>,

    /// Dynamic allowlist of Ed25519 pubkeys authorized to handshake.
    /// `None` = permissive mode (all QUIC TLS clients allowed, legacy
    /// single-tenant POC path).
    /// `Some(handle)` = only pubkeys present in the live handle
    /// complete the handshake; others are refused with
    /// `WARREN_AUTH_FAILED` **before** any tunnel IP attribution.
    ///
    /// For multi-tenant production, the consumer binary spawns a
    /// refresh loop that polls its control-plane for the active
    /// allowlist and lands snapshots on the same handle; the exit's
    /// accept loop reads `is_allowed` on every connection.
    pub allowlist: Option<AllowlistHandle>,

    /// Maximum number of concurrent handshakes the accept loop will
    /// process simultaneously. Each incoming QUIC connection spawns a
    /// tokio task that runs the TLS + Warren Setup exchange; this cap
    /// prevents a burst of connections (legitimate reconnect storm or
    /// DDoS) from spawning unbounded tasks. Default 256.
    ///
    /// The permit covers the HANDSHAKE phase only (it is released as
    /// soon as the SetupAck exchange completes, before the per-session
    /// pump starts), so this does NOT bound the number of live
    /// sessions. Each in-flight handshake costs ~10-50 KB RAM and is
    /// further bounded by `WARREN_HANDSHAKE_TIMEOUT_SECS`, so 256
    /// concurrent permits = ~12 MB peak memory - negligible on any
    /// exit server.
    pub max_concurrent_handshakes: usize,

    /// Per-source-IP handshake admission policy. `None` = no per-IP
    /// limit (only the global `max_concurrent_handshakes` semaphore
    /// applies). See [`HandshakeRateLimit`] for the design rationale
    /// (why this layer is deliberately generous and CGNAT-tolerant).
    pub handshake_rate_limit: Option<HandshakeRateLimit>,

    /// DAITA v2 machine pool offered to clients that advertise
    /// `Setup::daita_support = true`. `None` = exit refuses to deploy
    /// DAITA even when the client requests it (default for backwards
    /// compatibility). `Some(pool)` = on each accepted handshake, the
    /// exit picks one machine from the pool and ships its
    /// [`DaitaConfig`] back in `SetupAck::daita_spec`. Use
    /// [`warrenguard_daita::DaitaPool::default_pool`] for the curated set of 5
    /// machines (NetFlow, Tamaraw, FRONT, Interspace, Scrambler).
    ///
    /// Multi-conn caveat: each Quinn connection of a multi-session
    /// currently picks independently. Sharing the same pick across
    /// all N connections of a session is tracked as future work.
    pub daita_pool: Option<DaitaPool>,

    /// Optional global per-account device-cap enforcer (v2). When
    /// `Some`, the accept path consults it on every NEW
    /// `(pubkey, device_id)` PRIMARY connection: admitted devices
    /// proceed, denied devices are refused with [`WARREN_DEVICE_LIMIT`],
    /// and a transport failure fails OPEN (admit + warn). `None` (the
    /// default) disables the cap entirely, preserving the exact
    /// pre-v2 behaviour for bench / standalone exits.
    pub device_cap_enforcer: Option<Arc<dyn DeviceCapEnforcer>>,

    /// Optional v7 anonymous session-token admitter. When `Some`, the accept
    /// path accepts protocol v7 [`SetupV7`](warrenguard_wire::SetupV7) frames
    /// (dual-accept alongside v6): a PRIMARY presents Privacy Pass tokens, this
    /// admitter verifies one offline and spends its serial, and the session is
    /// keyed by the returned serial. `None` (the default) refuses v7 frames,
    /// so a bench / standalone exit stays v6-only. See [`SessionTokenAdmitter`].
    pub token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,

    /// Optional active-probe decoy seam. When `Some`, a
    /// connection that completes the handshake but does NOT present a
    /// valid, authenticated Warren `Setup` (absent/undecodable frame,
    /// channel binding unavailable, or auth proof that fails to verify) is
    /// handed to this handler instead of being closed. `None` (the
    /// default) closes such connections cleanly, as before. The decoy
    /// itself lives in the deployer; see [`UnauthenticatedHandler`].
    /// Authorization failures (valid auth, but allowlist/device-cap denied)
    /// are NOT routed here.
    pub unauthenticated_handler: Option<Arc<dyn UnauthenticatedHandler>>,

    /// Optional X.509 certificate chain (leaf-first DER) + private key (DER)
    /// the exit presents instead of its Ed25519 raw public key (v6 X.509
    /// exit mode). When `Some`, the TLS handshake looks like an ordinary
    /// HTTPS/h3 server and the Warren identity is proven in-band via
    /// `SetupAck::exit_auth_sig`; the matching client must dial in X.509
    /// mode (webpki + cover-domain SNI). `None` (default) presents the
    /// Ed25519 RPK as before. Prod wires the pushed wildcard cert here once
    /// the cover domain exists; tests use a local CA fixture.
    /// `(cert_chain_der, private_key_der)`: leaf-first DER cert chain + the
    /// DER private key (PKCS#8 / PKCS#1 / SEC1, auto-detected). Stored as
    /// bytes so `ExitBindOpts` stays `Clone`.
    pub tls_certificate: Option<(Vec<Vec<u8>>, Vec<u8>)>,

    /// Additional cover-domain X.509 certificates served by SNI (cover-domain
    /// rotation). Each `(domain, cert_chain_der, private_key_der)` is presented
    /// when the ClientHello SNI equals `domain`; `tls_certificate` is the
    /// default served for any other or absent name. This is the mechanism
    /// behind cover-domain rotation: an exit serves the old and the new
    /// cover domain at once during a migration, so a single blocked domain
    /// never strands it. Empty (default) means one cover-domain cert. Only
    /// honoured when `tls_certificate` is `Some` (the required default
    /// fallback); ignored in RPK mode.
    pub tls_certificates_by_sni: Vec<(String, Vec<Vec<u8>>, Vec<u8>)>,

    /// Exit-wide drain watch. `Some(rx)` when the deployer's control-plane
    /// can mark this exit as draining for planned maintenance: while the
    /// channel holds `Some(ExitDrainSignal)`, NEW authenticated handshakes
    /// are refused with `WARREN_EXIT_DRAINING` (fail-fast reconnects), and
    /// every live connection receives the in-band `ExitDraining` control
    /// datagram until the deadline, then a hard close with the same code.
    /// `None` (default) disables drain signalling entirely (bench /
    /// standalone exits).
    pub drain_rx: Option<tokio::sync::watch::Receiver<Option<ExitDrainSignal>>>,

    /// Number of UDP datapath sockets the exit binds on the listen address,
    /// via `SO_REUSEPORT`. `1` (default) = the historic single-socket exit.
    /// `N > 1` binds N sockets sharing one port, each backing an independent
    /// `quinn::Endpoint` driver; the kernel 4-tuple-hashes inbound QUIC flows
    /// across them, so a multi-conn client's connections land on distinct
    /// cores instead of serializing through one recv loop. This is the lever
    /// that breaks the single-endpoint throughput ceiling; a deployer sets it
    /// to roughly the exit's core count. Clamped to `1` on platforms without
    /// `SO_REUSEPORT` load-balancing (non-Unix), where multi-bind would not
    /// distribute. `0` is treated as `1`.
    pub datapath_sockets: usize,
}

/// Upper bound on the number of distinct source IPs the handshake rate
/// limiter tracks at once. Mirrors the edns-proxy limiter's key cap: once
/// reached, new IPs are rejected fail-closed so a flood of distinct (possibly
/// spoofed) source IPs cannot grow the map without bound between GC ticks.
const HANDSHAKE_RL_MAX_KEYS: usize = 65_536;

/// Per-source-IP handshake admission policy (a token bucket).
///
/// # Why this exists, and why it is deliberately generous
///
/// Terminating a QUIC+TLS handshake costs crypto CPU *before* the client
/// is authenticated against the allowlist. The exit therefore needs a
/// pre-auth admission control so a flood cannot burn that CPU. There are
/// **two layers**, and it is important not to confuse their jobs:
///
/// 1. **The global ceiling** is [`ExitBindOpts::max_concurrent_handshakes`]:
///    a semaphore bounding how many handshakes run *concurrently*, released
///    the instant each SetupAck completes. This is the real cap on
///    aggregate unauthenticated crypto cost, and it is independent of how
///    the load is spread across source IPs.
/// 2. **This per-IP token bucket** exists only so that a *single* source
///    IP cannot monopolise that global budget. It is fairness, not the
///    cost ceiling.
///
/// Because layer 1 already bounds total cost, layer 2 can and MUST be
/// generous: sizing it tightly is actively harmful behind **carrier-grade
/// NAT (CGNAT)**, where hundreds of legitimate Warren users share one
/// public IPv4, and a reconnect wave (an exit restart, a mobile network
/// handover, a PoP failover) is a burst of *thousands* of handshakes from
/// that one IP within a second. A tight per-IP limit would throttle those
/// real users while doing nothing that layer 1 does not already do.
///
/// A **token bucket** (not a fixed window) is used so admission is smooth:
/// a source IP is allowed at `refill_per_sec` steady-state with a `burst`
/// allowance to absorb a reconnect storm, without the 2x edge-of-window
/// unfairness of a reset-every-second counter. The map of tracked IPs is
/// itself bounded (`max_keys`, fail-closed) and GC prunes fully-recovered
/// IPs, so memory scales with the number of *currently active* source IPs,
/// not with history.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeRateLimit {
    /// Token-bucket burst capacity per source IP: the largest instantaneous
    /// reconnect wave one IP may present before it is throttled.
    pub burst: u32,
    /// Sustained refill rate in tokens (handshakes) per second per IP.
    pub refill_per_sec: u32,
    /// Max distinct source IPs tracked at once. A distinct-IP flood is
    /// rejected fail-closed past this bound so the map cannot grow without
    /// limit between GC ticks.
    pub max_keys: usize,
}

impl HandshakeRateLimit {
    /// Convenience: a bucket with the shared default key cap.
    #[must_use]
    pub fn new(burst: u32, refill_per_sec: u32) -> Self {
        Self {
            burst,
            refill_per_sec,
            max_keys: HANDSHAKE_RL_MAX_KEYS,
        }
    }
}

/// One source IP's token bucket. `tokens` is a fractional count refilled
/// lazily on each `check` from the elapsed time since `last`.
struct TokenBucket {
    tokens: f64,
    last: Instant,
}

/// Per-IP handshake token-bucket limiter. See [`HandshakeRateLimit`] for
/// the design rationale.
///
/// Uses `parking_lot::Mutex` (matching `active_conns` and the IP
/// allocators elsewhere in this module) rather than `std::sync::Mutex`:
/// it never poisons, so the hot handshake path never needs a
/// panicking `.expect()` to unwrap a `LockResult`.
pub(crate) struct HandshakeRateLimiter {
    buckets: parking_lot::Mutex<HashMap<IpAddr, TokenBucket>>,
    burst: f64,
    refill_per_sec: f64,
    max_keys: usize,
}

impl HandshakeRateLimiter {
    pub(crate) fn new(cfg: HandshakeRateLimit) -> Self {
        Self {
            buckets: parking_lot::Mutex::new(HashMap::new()),
            burst: f64::from(cfg.burst.max(1)),
            refill_per_sec: f64::from(cfg.refill_per_sec),
            max_keys: cfg.max_keys,
        }
    }

    /// Admit (consume one token) or reject one handshake from `ip`.
    pub(crate) fn check(&self, ip: IpAddr) -> bool {
        use std::collections::hash_map::Entry;
        let now = Instant::now();
        let mut buckets = self.buckets.lock();
        let at_capacity = buckets.len() >= self.max_keys;
        match buckets.entry(ip) {
            Entry::Occupied(mut occ) => {
                let b = occ.get_mut();
                let elapsed = now.duration_since(b.last).as_secs_f64();
                b.tokens = (b.tokens + elapsed * self.refill_per_sec).min(self.burst);
                b.last = now;
                if b.tokens >= 1.0 {
                    b.tokens -= 1.0;
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(vac) => {
                if at_capacity {
                    // Fail-closed: the map already tracks `max_keys` distinct
                    // source IPs (a distinct-IP flood / spoofing). Reject the
                    // new IP without inserting so memory stays bounded between
                    // GC ticks.
                    return false;
                }
                // A never-seen IP starts with a full bucket and spends one.
                vac.insert(TokenBucket {
                    tokens: self.burst - 1.0,
                    last: now,
                });
                self.burst >= 1.0
            }
        }
    }

    /// Drop buckets that have fully refilled back to `burst` (idle IPs):
    /// they carry no state worth keeping, so memory tracks only IPs that
    /// are currently rate-limited or actively handshaking.
    pub(crate) fn gc(&self) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock();
        buckets.retain(|_, b| {
            let elapsed = now.duration_since(b.last).as_secs_f64();
            (b.tokens + elapsed * self.refill_per_sec) < self.burst
        });
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.buckets.lock().len()
    }
}

impl std::fmt::Debug for ExitBindOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExitBindOpts")
            .field("use_warren_tuning", &self.use_warren_tuning)
            .field("signing_key", &self.signing_key.is_some())
            .field("previous_signing_keys", &self.previous_signing_keys.len())
            .field("enable_gso", &self.enable_gso)
            .field("state_file", &self.state_file)
            .field("ipv4_pool_capacity", &self.ipv4_pool_capacity)
            .field("rate_limit_per_client_bps", &self.rate_limit_per_client_bps)
            .field(
                "rate_limit_uplink_per_client_bps",
                &self.rate_limit_uplink_per_client_bps,
            )
            .field("allowlist", &self.allowlist.is_some())
            .field("max_concurrent_handshakes", &self.max_concurrent_handshakes)
            .field("handshake_rate_limit", &self.handshake_rate_limit)
            .field("daita_pool", &self.daita_pool.is_some())
            .field("device_cap_enforcer", &self.device_cap_enforcer.is_some())
            .field("token_admitter", &self.token_admitter.is_some())
            .field(
                "unauthenticated_handler",
                &self.unauthenticated_handler.is_some(),
            )
            .field("drain_rx", &self.drain_rx.is_some())
            .field("tls_certificate", &self.tls_certificate.is_some())
            .field(
                "tls_certificates_by_sni",
                &self.tls_certificates_by_sni.len(),
            )
            .field("datapath_sockets", &self.datapath_sockets)
            .finish()
    }
}

impl Default for ExitBindOpts {
    fn default() -> Self {
        Self {
            use_warren_tuning: true,
            signing_key: None,
            previous_signing_keys: Vec::new(),
            enable_gso: true,
            pad_to_mtu: false,
            state_file: None,
            ipv4_pool_capacity: None,
            rate_limit_per_client_bps: None,
            rate_limit_uplink_per_client_bps: None,
            allowlist: None,
            max_concurrent_handshakes: 256,
            // Generic engine default: generous per-IP token bucket (see
            // `HandshakeRateLimit` for why generous, not tight). The real
            // cost ceiling is `max_concurrent_handshakes` above. Deliberately
            // NOT wired to `WARREN_HS_RATE_BURST` / `WARREN_HS_RATE_PER_SEC`
            // here: this default must stay fixed so an existing deployer or
            // test building `ExitBindOpts::default()` sees no behaviour change
            // from those env vars. A deployer's own exit binary reads the
            // knobs and overrides this field explicitly to make them live;
            // see the "Deployer-wired knobs" section of docs/35-ENV-KNOBS.md.
            handshake_rate_limit: Some(HandshakeRateLimit::new(512, 256)),
            daita_pool: None,
            device_cap_enforcer: None,
            token_admitter: None,
            unauthenticated_handler: None,
            drain_rx: None,
            tls_certificate: None,
            tls_certificates_by_sni: Vec::new(),
            // Deliberately NOT wired to `WARREN_EXIT_DATAPATH_SOCKETS` here:
            // this default must stay a single socket for back-compat (see
            // `reuseport_multi_endpoint::default_bind_opts_keep_a_single_datapath_socket`).
            // A deployer's own exit binary reads the knob and overrides this
            // field explicitly to opt into SO_REUSEPORT sharding; see the
            // "Deployer-wired knobs" section of docs/35-ENV-KNOBS.md.
            datapath_sockets: 1,
        }
    }
}

/// First allocatable host offset within `10.66.0.0/16`: offset 0 is
/// the network address and offset 1 the exit-side gateway.
const IPV4_FIRST_HOST_OFFSET: u16 = 2;
/// Last allocatable host offset: `u16::MAX` (10.66.255.255) is the /16
/// broadcast address and must never be handed out.
const IPV4_LAST_HOST_OFFSET: u16 = u16::MAX - 1;
/// Number of allocatable hosts in the full /16 pool.
const IPV4_POOL_MAX_HOSTS: u16 = IPV4_LAST_HOST_OFFSET - IPV4_FIRST_HOST_OFFSET + 1;

fn ipv4_from_offset(offset: u16) -> Ipv4Addr {
    Ipv4Addr::new(10, 66, (offset >> 8) as u8, (offset & 0xff) as u8)
}

/// Maps a tunnel IPv4 back to its pool offset. Returns `None` for
/// addresses outside `10.66.0.0/16` and for the reserved offsets
/// (network, gateway, broadcast), so reserved addresses can never be
/// pushed into the free queue by a buggy caller.
fn ipv4_pool_offset(ip: Ipv4Addr) -> Option<u16> {
    let o = ip.octets();
    if o[0] != 10 || o[1] != 66 {
        return None;
    }
    let offset = u16::from_be_bytes([o[2], o[3]]);
    (IPV4_FIRST_HOST_OFFSET..=IPV4_LAST_HOST_OFFSET)
        .contains(&offset)
        .then_some(offset)
}

/// Recycling IPv4 allocator within the `10.66.0.0/16` pool.
///
/// Semantics mirror the multihop IP-pool
/// allocator: a FIFO free queue plus a bounded sticky-hint map keyed
/// by `(pubkey, device_id)` so a reconnecting device lands on its
/// previous address when that address is still free (best-effort).
/// Released addresses go back to the tail of the queue; the pool is
/// exhausted only when every address is held by a live session.
///
/// The sticky map self-cleans: handing an address to a different key
/// evicts the stale binding, so `sticky.len() <= capacity` regardless
/// of how many distinct identities ever connect.
pub(super) struct IpAllocator {
    inner: parking_lot::Mutex<IpAllocatorState>,
}

struct IpAllocatorState {
    free: VecDeque<u16>,
    sticky: HashMap<SessionKey, u16>,
    /// Inverse of `sticky` (one owner per offset), kept in lockstep so
    /// the self-cleaning eviction is O(1) instead of a map scan.
    sticky_rev: HashMap<u16, SessionKey>,
    /// Highest offset this pool may ever contain; releases beyond it
    /// are ignored so a capacity-bounded pool cannot silently grow.
    max_offset: u16,
}

impl IpAllocatorState {
    /// Records `offset` as the sticky hint for `key`, evicting any
    /// stale binding another key held on the same offset (one owner
    /// per address keeps the map bounded by the pool capacity).
    fn bind_sticky(&mut self, key: SessionKey, offset: u16) {
        if let Some(old_offset) = self.sticky.insert(key, offset)
            && old_offset != offset
        {
            self.sticky_rev.remove(&old_offset);
        }
        if let Some(stale_key) = self.sticky_rev.insert(offset, key)
            && stale_key != key
        {
            self.sticky.remove(&stale_key);
        }
    }
}

impl IpAllocator {
    /// Full `/16` pool (65 533 allocatable hosts).
    pub(crate) fn new() -> Self {
        Self::with_capacity(IPV4_POOL_MAX_HOSTS)
    }

    /// Pool limited to the first `capacity` hosts (clamped to the /16
    /// maximum). Useful to bound the number of concurrent sessions an
    /// exit accepts, and for exhaustion tests.
    pub(crate) fn with_capacity(capacity: u16) -> Self {
        let capacity = capacity.clamp(1, IPV4_POOL_MAX_HOSTS);
        let max_offset = IPV4_FIRST_HOST_OFFSET + capacity - 1;
        Self {
            inner: parking_lot::Mutex::new(IpAllocatorState {
                free: (IPV4_FIRST_HOST_OFFSET..=max_offset).collect(),
                sticky: HashMap::new(),
                sticky_rev: HashMap::new(),
                max_offset,
            }),
        }
    }

    /// Allocates an address for `key`. Prefers the sticky hint recorded
    /// for this key when that address is still free; otherwise pops the
    /// FIFO free queue.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Internal`] when every address is held by a live
    /// session (true exhaustion - releases make the pool usable again).
    pub(crate) fn allocate(
        &self,
        key: &SessionKey,
    ) -> warrenguard_transport_core::Result<Ipv4Addr> {
        let mut state = self.inner.lock();
        // 1. Sticky hit: this key's previous address is still free.
        if let Some(&preferred) = state.sticky.get(key)
            && let Some(pos) = state.free.iter().position(|&o| o == preferred)
        {
            state.free.remove(pos);
            return Ok(ipv4_from_offset(preferred));
        }
        // 2. FIFO pop, recording the new sticky binding.
        let Some(offset) = state.free.pop_front() else {
            return Err(TunnelError::Internal(
                "IPv4 pool exhausted (all addresses held by live sessions)".into(),
            ));
        };
        state.bind_sticky(*key, offset);
        Ok(ipv4_from_offset(offset))
    }

    /// Returns `ip` to the free queue and records it as the sticky hint
    /// for `key` so an immediate reconnect of the same device prefers
    /// the same address. Idempotent; reserved or out-of-pool addresses
    /// are ignored.
    pub(crate) fn release(&self, ip: Ipv4Addr, key: &SessionKey) {
        let Some(offset) = ipv4_pool_offset(ip) else {
            return;
        };
        let mut state = self.inner.lock();
        if offset > state.max_offset || state.free.contains(&offset) {
            return;
        }
        // Tail push: a fresh client is unlikely to land on a just-
        // released address (subtle anti-fingerprinting, mirrors
        // ip_pool.rs), while the releasing key keeps a sticky hint to
        // reclaim it on reconnect.
        state.free.push_back(offset);
        state.bind_sticky(*key, offset);
    }

    /// Records a sticky hint without touching the free queue. Only for
    /// boot-time restoration from the persisted state, when the hinted
    /// address is known to be free (no live sessions yet).
    pub(crate) fn install_hint(&self, key: &SessionKey, ip: Ipv4Addr) {
        let Some(offset) = ipv4_pool_offset(ip) else {
            return;
        };
        let mut state = self.inner.lock();
        if offset > state.max_offset {
            return;
        }
        state.bind_sticky(*key, offset);
    }

    #[cfg(test)]
    fn free_count(&self) -> usize {
        self.inner.lock().free.len()
    }

    #[cfg(test)]
    fn sticky_count(&self) -> usize {
        self.inner.lock().sticky.len()
    }
}

/// Recycling IPv6 allocator within `fdcc:f:1::/64` (ULA RFC 4193).
///
/// A `/64` carries 2^64 host slots, so free hosts are **not**
/// enumerated: a monotonic interface-ID counter mints fresh offsets on
/// demand and a `recycled` queue reuses offsets returned by
/// [`Self::release`] before advancing the counter (mirrors the
/// multihop `ip_pool::IpAllocatorV6`). Sticky hints follow the same
/// `(pubkey, device_id)` semantics as the v4 allocator.
pub(super) struct IpAllocatorV6 {
    inner: parking_lot::Mutex<IpAllocatorV6State>,
}

struct IpAllocatorV6State {
    /// Next never-before-minted interface-ID offset. Starts at 2
    /// (offset 0 = network, 1 = exit-side gateway).
    next: u64,
    recycled: VecDeque<u64>,
    sticky: HashMap<SessionKey, u64>,
    /// Inverse of `sticky`; see [`IpAllocatorState::sticky_rev`].
    sticky_rev: HashMap<u64, SessionKey>,
}

impl IpAllocatorV6State {
    fn bind_sticky(&mut self, key: SessionKey, offset: u64) {
        if let Some(old_offset) = self.sticky.insert(key, offset)
            && old_offset != offset
        {
            self.sticky_rev.remove(&old_offset);
        }
        if let Some(stale_key) = self.sticky_rev.insert(offset, key)
            && stale_key != key
        {
            self.sticky.remove(&stale_key);
        }
    }
}

fn ipv6_from_offset(offset: u64) -> Ipv6Addr {
    Ipv6Addr::new(
        0xfdcc,
        0x000f,
        0x0001,
        0,
        ((offset >> 48) & 0xffff) as u16,
        ((offset >> 32) & 0xffff) as u16,
        ((offset >> 16) & 0xffff) as u16,
        (offset & 0xffff) as u16,
    )
}

/// Maps a tunnel IPv6 back to its interface-ID offset. Returns `None`
/// outside `fdcc:f:1::/64` and for the reserved offsets 0/1.
fn ipv6_pool_offset(ip: Ipv6Addr) -> Option<u64> {
    let seg = ip.segments();
    if seg[0] != 0xfdcc || seg[1] != 0x000f || seg[2] != 0x0001 || seg[3] != 0 {
        return None;
    }
    let offset = (u64::from(seg[4]) << 48)
        | (u64::from(seg[5]) << 32)
        | (u64::from(seg[6]) << 16)
        | u64::from(seg[7]);
    (offset >= 2).then_some(offset)
}

impl IpAllocatorV6 {
    pub(crate) fn new() -> Self {
        Self::with_next(2)
    }

    /// Constructor with an explicit mint counter, used by exhaustion
    /// tests (organically unreachable on a /64).
    pub(crate) fn with_next(next: u64) -> Self {
        Self {
            inner: parking_lot::Mutex::new(IpAllocatorV6State {
                next: next.max(2),
                recycled: VecDeque::new(),
                sticky: HashMap::new(),
                sticky_rev: HashMap::new(),
            }),
        }
    }

    /// Allocates an interface ID for `key`. Prefers the sticky hint
    /// when that offset sits in the recycled queue, then recycled
    /// offsets, then mints a fresh one.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Internal`] when the mint counter is saturated and
    /// the recycled queue is empty.
    pub(crate) fn allocate(
        &self,
        key: &SessionKey,
    ) -> warrenguard_transport_core::Result<Ipv6Addr> {
        let mut state = self.inner.lock();
        // 1. Sticky hit: this key's previous offset sits in the
        //    recycled queue.
        if let Some(&preferred) = state.sticky.get(key)
            && let Some(pos) = state.recycled.iter().position(|&o| o == preferred)
        {
            state.recycled.remove(pos);
            return Ok(ipv6_from_offset(preferred));
        }
        // 2. Recycled offsets before advancing the mint counter.
        if let Some(offset) = state.recycled.pop_front() {
            state.bind_sticky(*key, offset);
            return Ok(ipv6_from_offset(offset));
        }
        // 3. Mint a fresh interface ID.
        if state.next == u64::MAX {
            return Err(TunnelError::Internal("IPv6 pool exhausted".into()));
        }
        let offset = state.next;
        state.next += 1;
        state.bind_sticky(*key, offset);
        Ok(ipv6_from_offset(offset))
    }

    /// Returns `ip` to the recycled queue and refreshes the sticky hint
    /// for `key`. Idempotent; out-of-pool addresses are ignored.
    pub(crate) fn release(&self, ip: Ipv6Addr, key: &SessionKey) {
        let Some(offset) = ipv6_pool_offset(ip) else {
            return;
        };
        let mut state = self.inner.lock();
        if offset >= state.next || state.recycled.contains(&offset) {
            return;
        }
        state.recycled.push_back(offset);
        state.bind_sticky(*key, offset);
    }

    /// Boot-time hint restoration; see [`IpAllocator::install_hint`].
    /// The hinted offset enters the recycled queue (it has no live
    /// holder after a restart) and the mint counter jumps past it so
    /// it is never minted twice.
    pub(crate) fn install_hint(&self, key: &SessionKey, ip: Ipv6Addr) {
        let Some(offset) = ipv6_pool_offset(ip) else {
            return;
        };
        let mut state = self.inner.lock();
        if offset >= state.next {
            state.next = offset.saturating_add(1).max(state.next);
            state.recycled.push_back(offset);
        } else if !state.recycled.contains(&offset) {
            state.recycled.push_back(offset);
        }
        state.bind_sticky(*key, offset);
    }
}

/// Listener on the exit side: a `quinn::Endpoint` configured for the
/// Warren tunnel pool, ready to accept handshakes.
pub struct ExitListener {
    /// One `quinn::Endpoint` per `SO_REUSEPORT` datapath socket. Length 1 is
    /// the default single-socket exit; length N shards the QUIC recv across N
    /// endpoint drivers. `endpoints[0]` is the primary: it backs `bound_addr`,
    /// `endpoint_handle` and the single-accept test/CLI helpers, and all
    /// endpoints share the same listen port so a client dials one address.
    pub(super) endpoints: Vec<Endpoint>,
    /// Local Ed25519 pubkey derived from the binding `SigningKey`.
    /// Cached because Quinn does not expose the configured server-cert
    /// pubkey via the endpoint handle.
    pub(super) local_pubkey: WarrenPubkey,
    /// The exit's Ed25519 identity key. Held so the handshake can sign the
    /// in-band exit-identity proof (`SetupAck::exit_auth_sig`, v6 X.509
    /// exit mode) over each connection's channel binding. The key is already
    /// in-process (it backs the RPK/X.509 server cert resolver); storing it
    /// here adds no new exposure.
    pub(super) signing_key: SigningKey,
    pub(super) allocator: Arc<IpAllocator>,
    /// Separate IPv6 allocator (fdcc:f:1::/64 pool).
    pub(super) allocator_v6: Arc<IpAllocatorV6>,
    /// Active multi-conn sessions, indexed by `(pubkey, device_id)`
    /// (pubkey = in-band `Setup::client_pubkey`, verified via the
    /// channel-binding proof; device_id = `Setup::device_id`). Keying by the device dimension
    /// is the v2 device-cap change: distinct devices of one account get
    /// distinct sessions/IPs instead of colliding. Async tokio mutex
    /// because we `.await` elsewhere in the handshake.
    pub(super) sessions: Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
    /// Debounced background persister for the session map, when a
    /// state file is configured. `None` = ephemeral mode.
    pub(super) state_persister: Option<Arc<crate::exit_state::StatePersister>>,
    /// Per-identity rate limiter, downlink direction (exit -> client).
    /// `None` = no limit (POC default).
    pub(super) rate_limiter_downlink:
        Option<Arc<warrenguard_ratelimit::IdentityLimiter<WarrenPubkey>>>,
    /// Per-identity rate limiter, uplink direction (client -> exit ->
    /// Internet). Independent from the downlink.
    pub(super) rate_limiter_uplink:
        Option<Arc<warrenguard_ratelimit::IdentityLimiter<WarrenPubkey>>>,
    /// Handle to the background task that sweeps buckets for identities
    /// no longer present in the sessions map. `None` if no rate limiter
    /// is active. Aborted in `Drop` to avoid leaking the task when
    /// `ExitListener` is dropped (tests, graceful shutdown).
    sweep_handle: Option<tokio::task::JoinHandle<()>>,
    /// See [`ExitBindOpts::allowlist`]. Cloned cheaply (single `Arc`
    /// inside the handle) so the accept loop, the revocation handler
    /// and the polling refresher all share the same live state.
    pub(super) allowlist: Option<AllowlistHandle>,
    /// See [`ExitBindOpts::daita_pool`]. Shared by every accept-loop
    /// path; pool entries are cheap to clone and the pool itself is
    /// immutable post-construction.
    pub(super) daita_pool: Option<DaitaPool>,
    pub(super) max_concurrent_handshakes: usize,
    pub(super) handshake_rate_limit: Option<HandshakeRateLimit>,
    /// Live Quinn connections currently held open per identity. Pushed
    /// after a successful handshake; consumed by
    /// [`Self::close_connections_for`] when the refresher signals a
    /// revocation. `parking_lot::Mutex` because the hot path
    /// (push-after-handshake, close-on-revoke) is brief and never
    /// holds the lock across an `.await`, and we want neither the
    /// poison surface nor the throughput cost of std's flag.
    pub(super) active_conns: Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
    /// Per-client traffic counters.
    pub(super) metrics_registry: Arc<warrenguard_transport_core::client_metrics::MetricsRegistry>,
    /// Optional global per-account device-cap enforcer (v2). Injected by
    /// the binary; `None` = no cap (behaves exactly as before this
    /// change). See [`DeviceCapEnforcer`] and [`ExitBindOpts::device_cap_enforcer`].
    pub(super) device_cap_enforcer: Option<Arc<dyn DeviceCapEnforcer>>,
    /// Optional v7 anonymous session-token admitter. Injected by the binary;
    /// `None` = v7 refused (v6-only exit). See [`SessionTokenAdmitter`] and
    /// [`ExitBindOpts::token_admitter`].
    pub(super) token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,
    /// Optional active-probe decoy seam. See
    /// [`ExitBindOpts::unauthenticated_handler`] and [`UnauthenticatedHandler`].
    pub(super) unauthenticated_handler: Option<Arc<dyn UnauthenticatedHandler>>,
    /// Exit-wide drain watch. See [`ExitBindOpts::drain_rx`].
    pub(super) drain_rx: Option<tokio::sync::watch::Receiver<Option<ExitDrainSignal>>>,
}

/// Binds `count` UDP datapath sockets on `addr` with `SO_REUSEPORT` and wraps
/// each in its own `quinn::Endpoint` sharing `server_cfg`. The kernel
/// 4-tuple-hashes inbound QUIC flows across the sockets, so N endpoints run N
/// independent recv loops (one per core) instead of serializing through one.
///
/// `count <= 1`, or any non-Unix target (no `SO_REUSEPORT` load-balancing),
/// takes the historic single-socket `Endpoint::server` path unchanged.
///
/// For an ephemeral listen port (`addr` port 0, used by tests), the first
/// socket's kernel-assigned port is resolved and the remaining sockets bind to
/// that exact port, so the whole group actually shares one port instead of
/// each grabbing a different ephemeral one.
fn bind_datapath_endpoints(
    addr: SocketAddr,
    count: usize,
    server_cfg: quinn::ServerConfig,
) -> Result<Vec<Endpoint>> {
    let bind_err = |source| TunnelError::Bind {
        addr: addr.to_string(),
        source,
    };

    let want = count.max(1);
    if want == 1 || !cfg!(unix) {
        if want > 1 {
            tracing::warn!(
                requested = want,
                "SO_REUSEPORT datapath sharding is Unix-only; binding a single socket"
            );
        }
        let endpoint = quinn::Endpoint::server(server_cfg, addr).map_err(bind_err)?;
        return Ok(vec![endpoint]);
    }

    #[cfg(unix)]
    {
        use socket2::{Domain, Protocol, Socket, Type};

        let runtime = quinn::default_runtime().ok_or_else(|| {
            TunnelError::Internal("no async runtime for quinn datapath endpoints".to_owned())
        })?;

        let mut endpoints = Vec::with_capacity(want);
        let mut bind_addr = addr;
        for i in 0..want {
            let domain = if bind_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(bind_err)?;
            // Every socket in the group must set SO_REUSEPORT (and REUSEADDR)
            // BEFORE bind, or the second bind fails with EADDRINUSE.
            sock.set_reuse_address(true).map_err(bind_err)?;
            sock.set_reuse_port(true).map_err(bind_err)?;
            sock.bind(&bind_addr.into()).map_err(bind_err)?;
            // Pin the rest of the group to the port the kernel chose for the
            // first ephemeral bind, so they share one port rather than each
            // taking a distinct ephemeral port.
            if i == 0 && bind_addr.port() == 0 {
                let resolved = sock
                    .local_addr()
                    .map_err(bind_err)?
                    .as_socket()
                    .ok_or_else(|| {
                        TunnelError::Internal("datapath socket has no local addr".to_owned())
                    })?;
                bind_addr.set_port(resolved.port());
            }
            sock.set_nonblocking(true).map_err(bind_err)?;
            let std_sock: std::net::UdpSocket = sock.into();
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_cfg.clone()),
                std_sock,
                runtime.clone(),
            )
            .map_err(bind_err)?;
            endpoints.push(endpoint);
        }
        tracing::info!(
            sockets = endpoints.len(),
            "exit datapath bound with SO_REUSEPORT sharding"
        );
        Ok(endpoints)
    }
}

impl Drop for ExitListener {
    fn drop(&mut self) {
        if let Some(h) = self.sweep_handle.take() {
            h.abort();
        }
    }
}

impl ExitListener {
    /// Bind on the provided `addr`. Used in production by the exit binary
    /// to expose the exit publicly (typically `<public_ip>:7000`).
    ///
    /// # Errors
    ///
    /// UDP socket bind error (port in use, permission denied, etc.) or
    /// Quinn Endpoint init error.
    pub async fn bind(addr: SocketAddr) -> Result<Self> {
        Self::bind_with_opts(addr, ExitBindOpts::default()).await
    }

    /// Variant of [`Self::bind`] with runtime options, notably to enable
    /// or disable Warren tuning (BBR + MTU 1350 + BDP windows) for
    /// benchmarking the measurable benefit vs Quinn defaults.
    ///
    /// # Errors
    ///
    /// See [`Self::bind`].
    pub async fn bind_with_opts(addr: SocketAddr, opts: ExitBindOpts) -> Result<Self> {
        let signing_key = match opts.signing_key {
            Some(sk) => sk,
            None => {
                // `SigningKey::generate` couples to a specific
                // `rand_core` version through ed25519-dalek that may
                // not match the workspace `rand` pin; explicitly seed
                // from `rand::random()` so we depend only on the
                // workspace rand crate.
                let seed: [u8; 32] = rand::random();
                SigningKey::from_bytes(&seed)
            }
        };
        let local_pubkey = WarrenPubkey::from_bytes(*signing_key.verifying_key().as_bytes());

        // Offer ONLY `h3` (RFC 9114): the exit's ALPN must be indistinguishable
        // from a public HTTP/3 server. The historical Warren-custom
        // `warren/exit/1` id is deliberately NOT accepted; an exit that selected
        // it would answer an active probe in a way no real h3 server does, a
        // wire-visible Warren tell. A client old enough to only speak
        // `warren/exit/1` predates the in-band-auth Setup and is wire-rejected
        // anyway, so accepting it bought no interop, only the tell.
        let alpns: &[&[u8]] = &[ALPN_H3];
        // `tls_certificates_by_sni` is the default fallback's companion: without
        // `tls_certificate` set, the X.509 branch is skipped entirely and the
        // SNI certs are silently discarded. Catch that misconfiguration in
        // tests/debug rather than serving RPK when the deployer asked for X.509.
        debug_assert!(
            opts.tls_certificate.is_some() || opts.tls_certificates_by_sni.is_empty(),
            "tls_certificates_by_sni requires tls_certificate (the default cover-domain cert); \
             without it the SNI certs are ignored and the exit serves RPK"
        );
        let mut server_cfg = if let Some((chain_der, key_der)) = opts.tls_certificate {
            // v6 X.509 exit mode: present a real cert so the
            // handshake looks like an ordinary HTTPS/h3 server. The Warren
            // identity is no longer in TLS; it is proven in-band via
            // `SetupAck::exit_auth_sig`.
            let to_chain = |chain: Vec<Vec<u8>>| {
                chain
                    .into_iter()
                    .map(rustls::pki_types::CertificateDer::from)
                    .collect::<Vec<_>>()
            };
            let to_key = |key: Vec<u8>| {
                rustls::pki_types::PrivateKeyDer::try_from(key).map_err(|e| {
                    TunnelError::Internal(format!("exit TLS private key is not valid DER: {e}"))
                })
            };
            let default_chain = to_chain(chain_der);
            let default_key = to_key(key_der)?;
            if opts.tls_certificates_by_sni.is_empty() {
                warrenguard_tls::make_server_config_x509(
                    default_chain,
                    default_key,
                    warrenguard_tls::default_crypto_provider(),
                    alpns,
                )
            } else {
                // Cover-domain rotation: route each declared
                // domain to its own cert, falling back to the default for any
                // other SNI.
                let mut by_sni = Vec::with_capacity(opts.tls_certificates_by_sni.len());
                for (domain, chain, key) in opts.tls_certificates_by_sni {
                    by_sni.push((domain, to_chain(chain), to_key(key)?));
                }
                warrenguard_tls::make_server_config_x509_sni(
                    default_chain,
                    default_key,
                    by_sni,
                    warrenguard_tls::default_crypto_provider(),
                    alpns,
                )
            }
        } else if opts.previous_signing_keys.is_empty() {
            warrenguard_tls::make_server_config(
                &signing_key,
                warrenguard_tls::default_crypto_provider(),
                alpns,
            )
        } else {
            warrenguard_tls::make_server_config_with_rotation(
                &signing_key,
                &opts.previous_signing_keys,
                warrenguard_tls::default_crypto_provider(),
                alpns,
            )
        }
        .map_err(|e| TunnelError::Internal(format!("build TLS server config failed: {e}")))?;
        if opts.use_warren_tuning {
            server_cfg.transport_config(
                warrenguard_transport_core::warren_transport_config_exit_full(
                    opts.enable_gso,
                    opts.pad_to_mtu,
                ),
            );
        }

        let endpoints = bind_datapath_endpoints(addr, opts.datapath_sockets, server_cfg)?;

        // Recycling allocators. Persisted sessions (if any) become
        // sticky hints only: no connection survives a restart, so the
        // live session map always starts empty and every address stays
        // allocatable. A reconnecting device still lands on its
        // previous tunnel IPs while they remain free (best-effort).
        let allocator = Arc::new(match opts.ipv4_pool_capacity {
            Some(capacity) => IpAllocator::with_capacity(capacity),
            None => IpAllocator::new(),
        });
        let allocator_v6 = Arc::new(IpAllocatorV6::new());
        if let Some(path) = &opts.state_file {
            for (key, v4, v6) in PersistedState::load_or_default(path).into_sticky_hints() {
                allocator.install_hint(&key, v4);
                if let Some(v6) = v6 {
                    allocator_v6.install_hint(&key, v6);
                }
            }
        }
        let sessions_map: HashMap<SessionKey, MultiSessionState> = HashMap::new();

        // Per-identity token buckets if rate_limit_*_bps is configured.
        // Capacity = 1 second of burst to absorb spikes without drop.
        // Distinct buckets per direction (down/up).
        let rate_limiter_downlink = opts.rate_limit_per_client_bps.map(|bps| {
            tracing::info!(
                rate_bps = bps,
                rate_mbps = bps as f64 / 125_000.0,
                "per-identity rate limiter enabled (downlink exit -> client)"
            );
            Arc::new(warrenguard_ratelimit::IdentityLimiter::new(bps, bps))
        });
        let rate_limiter_uplink = opts.rate_limit_uplink_per_client_bps.map(|bps| {
            tracing::info!(
                rate_bps = bps,
                rate_mbps = bps as f64 / 125_000.0,
                "per-identity rate limiter enabled (uplink client -> exit -> Internet)"
            );
            Arc::new(warrenguard_ratelimit::IdentityLimiter::new(bps, bps))
        });

        let sessions = Arc::new(AsyncMutex::new(sessions_map));

        // Debounced off-thread persistence (at most one fsync per
        // second, last state wins); the handshake path only flips a
        // dirty flag.
        let state_persister = opts.state_file.clone().map(|path| {
            Arc::new(crate::exit_state::StatePersister::spawn(
                path,
                sessions.clone(),
            ))
        });

        // If at least one rate_limiter is active, spawn a background task
        // that periodically purges buckets whose identity is no longer
        // present in the sessions map. Avoids a memory leak under churn
        // of N million ephemeral clients. Sweep every 60 s, negligible
        // cost, short over-provisioning window.
        let sweep_handle = if rate_limiter_downlink.is_some() || rate_limiter_uplink.is_some() {
            let sessions_for_sweep = sessions.clone();
            let rate_d = rate_limiter_downlink.clone();
            let rate_u = rate_limiter_uplink.clone();
            Some(tokio::spawn(async move {
                // tokio::time::interval ticks immediately the first time -
                // ignore that first tick to avoid sweeping before any
                // sessions have been established.
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let alive: std::collections::HashSet<WarrenPubkey> = {
                        let map = sessions_for_sweep.lock().await;
                        // Rate-limit buckets are keyed by pubkey; collapse
                        // the `(pubkey, device_id)` session keys onto the
                        // pubkey dimension so a device of an account keeps
                        // the account's bucket alive.
                        map.keys().map(|(pk, _device_id)| *pk).collect()
                    };
                    if let Some(ref l) = rate_d {
                        let before = l.tracked_count();
                        l.retain(|k| alive.contains(k));
                        let after = l.tracked_count();
                        if before != after {
                            tracing::debug!(
                                purged = before - after,
                                remaining = after,
                                "sweep downlink rate limiter"
                            );
                        }
                    }
                    if let Some(ref l) = rate_u {
                        let before = l.tracked_count();
                        l.retain(|k| alive.contains(k));
                        let after = l.tracked_count();
                        if before != after {
                            tracing::debug!(
                                purged = before - after,
                                remaining = after,
                                "sweep uplink rate limiter"
                            );
                        }
                    }
                }
            }))
        } else {
            None
        };

        Ok(Self {
            endpoints,
            local_pubkey,
            signing_key,
            allocator,
            allocator_v6,
            sessions,
            state_persister,
            rate_limiter_downlink,
            rate_limiter_uplink,
            sweep_handle,
            allowlist: opts.allowlist,
            max_concurrent_handshakes: opts.max_concurrent_handshakes,
            handshake_rate_limit: opts.handshake_rate_limit,
            daita_pool: opts.daita_pool,
            active_conns: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            metrics_registry: Arc::new(
                warrenguard_transport_core::client_metrics::MetricsRegistry::new(),
            ),
            device_cap_enforcer: opts.device_cap_enforcer,
            token_admitter: opts.token_admitter,
            unauthenticated_handler: opts.unauthenticated_handler,
            drain_rx: opts.drain_rx,
        })
    }

    /// Bind on `127.0.0.1:0` (random port), thin wrapper over
    /// [`Self::bind`] for local tests and POC back-compat.
    ///
    /// # Errors
    ///
    /// See [`Self::bind`].
    pub async fn bind_localhost() -> Result<Self> {
        Self::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).await
    }

    /// Local `SocketAddr` this listener is bound on. Returns `None` on a
    /// degenerate case where the underlying UDP socket has no local
    /// address (should not happen post-bind).
    #[must_use]
    pub fn local_socket_addr(&self) -> Option<SocketAddr> {
        self.endpoints[0].local_addr().ok()
    }

    /// Number of `SO_REUSEPORT` datapath sockets this exit is listening on
    /// (see [`ExitBindOpts::datapath_sockets`]). `1` for a single-socket exit.
    #[must_use]
    pub fn datapath_socket_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Local `SocketAddr` of every datapath socket. With sharding enabled they
    /// all share one port (the reuseport group); useful to assert the group
    /// formed and for observability.
    #[must_use]
    pub fn local_socket_addrs(&self) -> Vec<SocketAddr> {
        self.endpoints
            .iter()
            .filter_map(|e| e.local_addr().ok())
            .collect()
    }

    /// Ed25519 pubkey of this exit (TLS RPK identity).
    #[must_use]
    pub fn pubkey(&self) -> WarrenPubkey {
        self.local_pubkey
    }

    /// Address of the exit, reachable by a local client. The returned
    /// [`WarrenExitAddr`] embeds the local pubkey + the single bound
    /// socket address.
    #[must_use]
    pub fn bound_addr(&self) -> WarrenExitAddr {
        let mut addr = WarrenExitAddr::new(self.local_pubkey);
        if let Ok(sa) = self.endpoints[0].local_addr() {
            addr.addrs.insert(WarrenTransportAddr::Ip(sa));
        }
        addr
    }

    /// Clones the primary Quinn `Endpoint`. Lets callers close the endpoint
    /// from the outside (`endpoint.close(...)`) to trigger clean termination of
    /// [`Self::accept_forever`] / [`Self::accept_forever_with_tun`], useful in
    /// tests and for graceful production shutdown. With datapath sharding the
    /// accept path stops as soon as this primary endpoint closes; the remaining
    /// sharded endpoints are torn down when the [`ExitListener`] is dropped.
    #[must_use]
    pub fn endpoint_handle(&self) -> Endpoint {
        self.endpoints[0].clone()
    }

    /// Cloneable read-only handle over the live `(pubkey ->
    /// assigned IPv4)` session map. Consumed by an exit binary's
    /// port-forward sync so each NAT-PMP allocation
    /// can be attributed to the owning client pubkey before being
    /// pushed to the API mirror.
    #[must_use]
    pub fn sessions_handle(&self) -> ExitSessionsHandle {
        ExitSessionsHandle {
            sessions: Arc::clone(&self.sessions),
        }
    }

    /// Cloneable read-only handle over the REAL source IPv4s of the
    /// currently-connected subscribers. Consumed by an exit binary's Port
    /// Fail defense-in-depth maintainer to keep the nftables drop set fresh.
    #[must_use]
    pub fn peer_sources_handle(&self) -> ExitPeerSourcesHandle {
        ExitPeerSourcesHandle {
            active_conns: Arc::clone(&self.active_conns),
        }
    }

    /// Returns a shared handle to the per-client traffic metrics registry.
    #[must_use]
    pub fn metrics_registry(
        &self,
    ) -> Arc<warrenguard_transport_core::client_metrics::MetricsRegistry> {
        self.metrics_registry.clone()
    }

    /// Accepts *one* incoming connection, processes the handshake, then
    /// returns.
    ///
    /// On the server side we read the `Setup` frame and assign a tunnel
    /// IP from the 10.66.0.0/16 pool via [`IpAllocator`].
    ///
    /// # Errors
    ///
    /// Quinn connection error, invalid `Setup` frame, or write error.
    pub async fn accept_one(self) -> Result<()> {
        self.handle_one_through_retries().await
    }

    /// Accept `n` connections sequentially. Used by integration tests
    /// validating IP uniqueness across sessions.
    ///
    /// # Errors
    ///
    /// See [`Self::accept_one`].
    pub async fn accept_n(self, n: usize) -> Result<()> {
        for _ in 0..n {
            self.handle_one_through_retries().await?;
        }
        Ok(())
    }

    /// `handle_one` variant that absorbs `StatelessRetryIssued` so a
    /// single-shot caller (`accept_one`, `accept_n`, integration test
    /// driver) ends up with a real completed handshake. Otherwise the
    /// caller would see the retry token signal - useful for the long-
    /// lived `accept_forever` loop but not for one-off accepts.
    async fn handle_one_through_retries(&self) -> Result<()> {
        loop {
            match self.handle_one().await {
                Ok(()) => return Ok(()),
                Err(TunnelError::StatelessRetryIssued) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Infinite accept loop. Used by the exit binary to stay
    /// in service until kill / signal.
    ///
    /// # Errors
    ///
    /// An error on an individual connection is *logged* and the loop
    /// continues; we return `Err` only when accept itself fails
    /// permanently (endpoint closed).
    pub async fn accept_forever(self) -> Result<()> {
        loop {
            // Cap the time spent in a single handshake at
            // WARREN_HANDSHAKE_TIMEOUT_SECS. A slow-loris client that
            // completed QUIC but never sends a Setup frame would
            // otherwise hold this task until Quinn's idle timeout
            // (minutes).
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(warrenguard_config::WARREN_HANDSHAKE_TIMEOUT_SECS),
                self.handle_one(),
            )
            .await;
            let res = match outcome {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!(
                        timeout_secs = warrenguard_config::WARREN_HANDSHAKE_TIMEOUT_SECS,
                        "handshake exceeded cap; dropping this accept iteration"
                    );
                    continue;
                }
            };
            if let Err(e) = res {
                if matches!(e, TunnelError::EndpointClosed) {
                    tracing::info!("accept loop terminated: endpoint closed");
                    return Err(e);
                }
                if matches!(e, TunnelError::StatelessRetryIssued) {
                    // Routine: spoofed-source initial got a retry
                    // token, honest client will retry with it.
                    // Mirrors `accept_forever_with_tun`'s handling.
                    tracing::debug!("issued stateless retry; continuing accept loop");
                    continue;
                }
                tracing::warn!(error = %e, "handshake failed");
            }
        }
    }

    /// Accept ONE connection, run the handshake, then launch the
    /// bidirectional TUN <-> datagrams pump for that session.
    ///
    /// The shared `tun` is cloned for both pump directions (`Clone` is
    /// shallow: shared Arc).
    ///
    /// # Errors
    ///
    /// Handshake error, or pump error (connection closed, TUN broken).
    pub async fn accept_one_with_tun<T>(&self, tun: T) -> Result<()>
    where
        T: warrenguard_transport_core::PacketDevice + Clone,
    {
        // Must use the *retrying* variant so a
        // loopback test client (or any honest client whose very first
        // initial lands on an un-validated remote address) is not
        // surfaced as `StatelessRetryIssued` to the caller. The
        // production `accept_forever_with_tun` already wraps this via
        // its own retry loop; the per-connection `accept_one_with_tun`
        // helper must do the same locally.
        let (conn, _client_id) = self.handshake_only_retrying().await?;
        warrenguard_pump::pump_bidirectional(tun, conn).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn handshake_from_incoming(
        incoming: quinn::Incoming,
        sessions: Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
        allocator: Arc<IpAllocator>,
        allocator_v6: Arc<IpAllocatorV6>,
        persister: Option<Arc<crate::exit_state::StatePersister>>,
        local_pubkey: WarrenPubkey,
        exit_signing_key: SigningKey,
        allowlist: Option<AllowlistHandle>,
        daita_pool: Option<DaitaPool>,
        active_conns: Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
        device_cap_enforcer: Option<Arc<dyn DeviceCapEnforcer>>,
        token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,
        unauthenticated_handler: Option<Arc<dyn UnauthenticatedHandler>>,
        drain_rx: Option<tokio::sync::watch::Receiver<Option<ExitDrainSignal>>>,
    ) -> Result<(quinn::Connection, SessionKey, Ipv4Addr, Option<Ipv6Addr>)> {
        let handshake_t = std::time::Instant::now();
        let conn = incoming
            .await
            .map_err(|source| TunnelError::QuicConnection {
                context: "complete incoming connection",
                source,
            })?;

        let (mut send, mut recv) =
            conn.accept_bi()
                .await
                .map_err(|source| TunnelError::QuicConnection {
                    context: "accept_bi",
                    source,
                })?;
        let buf =
            recv.read_to_end(MAX_SETUP_FRAME_BYTES)
                .await
                .map_err(|e| TunnelError::QuicStream {
                    context: "read Setup".into(),
                    source: Box::new(e),
                })?;

        // Dual-accept: a leading v7 version byte routes to the anonymous
        // session-token path; anything else falls through to the v6 decode
        // below (which itself rejects a bad version / non-Warren frame,
        // routing to the decoy seam). Keeps the v6 layout byte-for-byte.
        if buf.first() == Some(&PROTOCOL_VERSION_V7) {
            return Self::admit_v7(
                conn,
                send,
                buf,
                &sessions,
                &allocator,
                &allocator_v6,
                &persister,
                &active_conns,
                local_pubkey,
                &exit_signing_key,
                daita_pool.as_ref(),
                token_admitter.as_ref(),
                unauthenticated_handler.as_ref(),
                drain_rx.as_ref(),
            )
            .await;
        }

        let setup = match decode_setup(&buf) {
            Ok(s) => s,
            Err(e) => {
                // Not a Warren client: route to the decoy seam if configured,
                // else close. See reject_unauthenticated.
                return Err(reject_unauthenticated(
                    conn,
                    send,
                    unauthenticated_handler.as_ref(),
                    buf,
                    TunnelError::SetupWire {
                        context: "decode Setup".into(),
                        source: Box::new(e),
                    },
                ));
            }
        };

        // In-band client auth (protocol v5): the exit requested no TLS
        // client certificate (that CertificateRequest was an
        // active-probing tell), so the client declares
        // its identity in `Setup::client_pubkey` and proves possession by
        // signing this connection's channel binding in `Setup::auth_sig`.
        // Verify the proof BEFORE the allowlist gate; an unverifiable
        // proof is rejected exactly like an unknown identity (and routed to
        // the decoy seam if one is configured).
        let remote_id = WarrenPubkey::from_bytes(setup.client_pubkey);
        let cb = match warrenguard_tls::channel_binding(&conn) {
            Ok(cb) => cb,
            Err(_) => {
                return Err(reject_unauthenticated(
                    conn,
                    send,
                    unauthenticated_handler.as_ref(),
                    buf.clone(),
                    TunnelError::ChannelBindingExport,
                ));
            }
        };
        if !warrenguard_tls::verify_client_auth(
            &remote_id,
            &cb,
            &setup.device_id,
            &setup.auth_sig.0,
        ) {
            return Err(reject_unauthenticated(
                conn,
                send,
                unauthenticated_handler.as_ref(),
                buf.clone(),
                TunnelError::InbandAuthFailed,
            ));
        }
        if !is_allowed(allowlist.as_ref(), remote_id) {
            let _ = send.reset(WARREN_AUTH_FAILED);
            conn.close(WARREN_AUTH_FAILED, b"pubkey not in allowlist");
            return Err(TunnelError::AllowlistDenied);
        }

        // Drain admission gate: while the exit is draining, refuse NEW
        // sessions with a dedicated close code so a reconnecting client
        // fails fast and re-selects another exit instead of landing on a
        // node about to go away. Placed AFTER the in-band auth so an
        // unauthenticated prober still sees the decoy behaviour and learns
        // nothing; established sessions are untouched (the drain deadline
        // hard-close handles stragglers).
        if drain::is_draining(drain_rx.as_ref()) {
            let _ = send.reset(WARREN_EXIT_DRAINING);
            conn.close(WARREN_EXIT_DRAINING, WARREN_EXIT_DRAINING_REASON);
            return Err(TunnelError::ExitDrainingRefused);
        }

        // v2 device cap: gate NEW PRIMARY devices BEFORE allocating an
        // IP or registering the connection. A denied device gets a
        // distinct `WARREN_DEVICE_LIMIT` close so the client can show a
        // clear message; a transport failure fails open (admit).
        let device_cap_t = std::time::Instant::now();
        let cap_decision =
            evaluate_device_cap(device_cap_enforcer.as_ref(), &sessions, remote_id, &setup).await;
        let device_cap_ms = device_cap_t.elapsed().as_millis();
        if let CapDecision::Deny = cap_decision {
            // Log the slow-deny case too: a slow enforcer round trip is
            // exactly the latency you want visible, and the admit-path
            // log below is not reached on a denial.
            tracing::info!(
                total_ms = handshake_t.elapsed().as_millis(),
                device_cap_ms,
                "exit handshake denied (device cap)"
            );
            let _ = send.reset(WARREN_DEVICE_LIMIT);
            conn.close(WARREN_DEVICE_LIMIT, WARREN_DEVICE_LIMIT_REASON);
            return Err(TunnelError::DeviceLimitReached);
        }

        // The connection is registered in `active_conns` by
        // `attribute_session` itself, under the sessions lock and only
        // AFTER a successful attribution: a failed handshake never
        // leaves a connection clone keeping the conn artificially
        // alive in the map. On attribution failure (pool exhausted)
        // the connection is closed explicitly so the client fails fast
        // with a deterministic close code instead of relying on drop
        // semantics.
        let attributed = match attribute_session(
            &sessions,
            &allocator,
            &allocator_v6,
            &persister,
            &active_conns,
            &conn,
            remote_id,
            &setup,
            daita_pool.as_ref(),
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                let _ = send.reset(WARREN_NO_CAPACITY);
                conn.close(WARREN_NO_CAPACITY, WARREN_NO_CAPACITY_REASON);
                return Err(e);
            }
        };

        let ack = SetupAck {
            protocol_version: PROTOCOL_VERSION,
            tunnel_ipv4: attributed.ipv4.octets(),
            tunnel_ipv6: attributed.ipv6.map(|v| v.octets()),
            exit_pubkey: *local_pubkey.as_bytes(),
            max_mtu: attributed.max_mtu,
            multiconn_attached: attributed.attached,
            daita_spec: attributed.daita_spec,
            // In-band exit-identity proof (v6): sign this
            // connection's channel binding so the client confirms it
            // reached the expected Warren exit. Reuses the `cb` already
            // computed above for the client-auth check.
            exit_auth_sig: warrenguard_wire::AuthSig(warrenguard_tls::sign_server_auth(
                &exit_signing_key,
                &cb,
            )),
        };
        let resp = encode_setup_ack(&ack).map_err(|e| TunnelError::SetupWire {
            context: "encode SetupAck".into(),
            source: Box::new(e),
        })?;
        send.write_all(&resp)
            .await
            .map_err(|e| TunnelError::QuicStream {
                context: "write SetupAck".into(),
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| TunnelError::QuicStream {
            context: "finish stream".into(),
            source: Box::new(e),
        })?;
        // Setup-latency attribution (no identity material: durations
        // only). Measure `total_ms` BEFORE the up-to-500 ms client-ACK
        // grace below, so a client slow to ACK the SetupAck does not
        // inflate every reading. `device_cap_ms` isolates the
        // synchronous exit->API lease call, the one network round trip
        // this path can inject.
        tracing::info!(
            total_ms = handshake_t.elapsed().as_millis(),
            device_cap_ms,
            attached = attributed.attached,
            "exit handshake admitted"
        );
        let _ = tokio::time::timeout(Duration::from_millis(500), send.stopped()).await;
        if !attributed.attached {
            return Err(reject_unattached(&conn));
        }
        Ok((
            conn,
            (remote_id, setup.device_id),
            attributed.ipv4,
            attributed.ipv6,
        ))
    }

    /// Protocol v7 admission: an anonymous session-token handshake, the
    /// dual-accept counterpart of the v6 path. Called after the accept loop
    /// has read the Setup frame and seen a v7 version byte. Verifies + spends
    /// a Privacy Pass token (primary) or attaches via the capability
    /// (secondary), writes a [`SetupAckV7`], and returns the same
    /// `(conn, SessionKey, ipv4, ipv6)` tuple as the v6 path so the pump code
    /// is identical.
    ///
    /// The `send` stream and `buf` are handed over from the caller (already
    /// read). Rejections close the connection with the same QUIC codes the v6
    /// path uses so a client cannot distinguish v6 from v7 refusals. In
    /// particular every UNAUTHENTICATED refusal (malformed body, channel
    /// binding unavailable, no v7 support, no valid token) is routed through
    /// [`reject_unauthenticated`] exactly as v6 routes its equivalents: such a
    /// peer is indistinguishable from an active prober, so it must be diverted
    /// to the decoy (or closed with `H3_GENERAL_PROTOCOL_ERROR` + empty reason),
    /// never fingerprinted with a Warren-specific code or cleartext reason.
    #[allow(clippy::too_many_arguments)]
    async fn admit_v7(
        conn: quinn::Connection,
        mut send: quinn::SendStream,
        buf: Vec<u8>,
        sessions: &Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
        allocator: &Arc<IpAllocator>,
        allocator_v6: &Arc<IpAllocatorV6>,
        persister: &Option<Arc<crate::exit_state::StatePersister>>,
        active_conns: &Arc<parking_lot::Mutex<HashMap<SessionKey, Vec<quinn::Connection>>>>,
        local_pubkey: WarrenPubkey,
        exit_signing_key: &SigningKey,
        daita_pool: Option<&DaitaPool>,
        token_admitter: Option<&Arc<dyn SessionTokenAdmitter>>,
        unauthenticated_handler: Option<&Arc<dyn UnauthenticatedHandler>>,
        drain_rx: Option<&tokio::sync::watch::Receiver<Option<ExitDrainSignal>>>,
    ) -> Result<(quinn::Connection, SessionKey, Ipv4Addr, Option<Ipv6Addr>)> {
        let setup = match decode_setup_v7(&buf) {
            Ok(s) => s,
            Err(e) => {
                // A v7 version byte with a malformed body is indistinguishable
                // from an active prober: divert to the decoy seam if configured,
                // else close with H3_GENERAL_PROTOCOL_ERROR + empty reason. Same
                // contract as the v6 `decode_setup` failure above; never a
                // Warren-specific code or cleartext reason.
                return Err(reject_unauthenticated(
                    conn,
                    send,
                    unauthenticated_handler,
                    buf,
                    TunnelError::SetupWire {
                        context: "decode SetupV7".into(),
                        source: Box::new(e),
                    },
                ));
            }
        };

        // Exit-identity proof needs the channel binding, exactly as v6.
        let cb = match warrenguard_tls::channel_binding(&conn) {
            Ok(cb) => cb,
            Err(_) => {
                return Err(reject_unauthenticated(
                    conn,
                    send,
                    unauthenticated_handler,
                    buf,
                    TunnelError::ChannelBindingExport,
                ));
            }
        };

        // Drain gate: refuse NEW v7 sessions while draining, same as v6.
        if drain::is_draining(drain_rx) {
            let _ = send.reset(WARREN_EXIT_DRAINING);
            conn.close(WARREN_EXIT_DRAINING, WARREN_EXIT_DRAINING_REASON);
            return Err(TunnelError::ExitDrainingRefused);
        }

        // A v7-incapable exit (no admitter) cannot tell a v7 client from a
        // prober, so it refuses like any unauthenticated peer (decoy or empty
        // H3 close). A genuine v7 client reads the H3 close as "no v7 here" and
        // re-selects, exactly as it would on any refusal.
        let Some(admitter) = token_admitter else {
            return Err(reject_unauthenticated(
                conn,
                send,
                unauthenticated_handler,
                buf,
                TunnelError::InbandAuthFailed,
            ));
        };

        // PRIMARY: verify + spend a token to obtain the serial. SECONDARY:
        // no token; derive the session key from the echoed attach capability.
        let (session_pubkey, serial) = if setup.is_primary() {
            match admitter.admit(&setup.session_tokens).await {
                TokenAdmission::Admit { serial } => {
                    let cap = session_token::attach_secret_for_serial(&serial);
                    (session_token::session_key_value(&cap), Some(serial))
                }
                TokenAdmission::Reject => {
                    // No valid token = unauthenticated: same decoy/H3 treatment
                    // as a v6 in-band auth failure, not a Warren fingerprint.
                    return Err(reject_unauthenticated(
                        conn,
                        send,
                        unauthenticated_handler,
                        buf,
                        TunnelError::InbandAuthFailed,
                    ));
                }
                TokenAdmission::Denied => {
                    let _ = send.reset(WARREN_DEVICE_LIMIT);
                    conn.close(WARREN_DEVICE_LIMIT, WARREN_DEVICE_LIMIT_REASON);
                    return Err(TunnelError::DeviceLimitReached);
                }
            }
        } else {
            (session_token::session_key_value(&setup.attach_secret), None)
        };

        let attributed = match attribute_session_v7(
            sessions,
            allocator,
            allocator_v6,
            persister,
            active_conns,
            &conn,
            session_pubkey,
            setup.device_id,
            serial,
            setup.connection_index,
            setup.total_connections,
            setup.features,
            setup.daita_support,
            daita_pool,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                let _ = send.reset(WARREN_NO_CAPACITY);
                conn.close(WARREN_NO_CAPACITY, WARREN_NO_CAPACITY_REASON);
                return Err(e);
            }
        };

        // The attach capability returned to the PRIMARY is what its
        // secondaries echo to join; a secondary's ack carries all-zero (it
        // presented the capability, it does not receive a new one).
        let attach_secret = match serial {
            Some(s) => session_token::attach_secret_for_serial(&s),
            None => [0u8; warrenguard_wire::ATTACH_SECRET_LEN],
        };
        let ack = SetupAckV7 {
            protocol_version: PROTOCOL_VERSION_V7,
            tunnel_ipv4: attributed.ipv4.octets(),
            tunnel_ipv6: attributed.ipv6.map(|v| v.octets()),
            exit_pubkey: *local_pubkey.as_bytes(),
            max_mtu: attributed.max_mtu,
            multiconn_attached: attributed.attached,
            daita_spec: attributed.daita_spec,
            exit_auth_sig: warrenguard_wire::AuthSig(warrenguard_tls::sign_server_auth(
                exit_signing_key,
                &cb,
            )),
            attach_secret,
        };
        let resp = encode_setup_ack_v7(&ack).map_err(|e| TunnelError::SetupWire {
            context: "encode SetupAckV7".into(),
            source: Box::new(e),
        })?;
        send.write_all(&resp)
            .await
            .map_err(|e| TunnelError::QuicStream {
                context: "write SetupAckV7".into(),
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| TunnelError::QuicStream {
            context: "finish stream".into(),
            source: Box::new(e),
        })?;
        let _ = tokio::time::timeout(Duration::from_millis(500), send.stopped()).await;
        if !attributed.attached {
            return Err(reject_unattached(&conn));
        }
        Ok((
            conn,
            (session_pubkey, setup.device_id),
            attributed.ipv4,
            attributed.ipv6,
        ))
    }

    /// Accepts a connection, runs the handshake, reads *one* incoming
    /// datagram and pushes it into `out`. Helper for integration tests.
    ///
    /// # Errors
    ///
    /// Handshake or datagram receive error.
    pub async fn accept_and_capture_one_datagram(
        self,
        out: std::sync::Arc<tokio::sync::Mutex<Option<Vec<u8>>>>,
    ) -> Result<()> {
        let (conn, _client_id) = self.handshake_only_retrying().await?;
        let dg = conn
            .read_datagram()
            .await
            .map_err(|source| TunnelError::QuicReadDatagram {
                context: "accept_and_capture_one_datagram".into(),
                source,
            })?;
        *out.lock().await = Some(dg.to_vec());
        Ok(())
    }

    /// Accepts a connection, runs the handshake, reads one datagram and
    /// replies with `response`. Helper for the bidirectional test.
    ///
    /// # Errors
    ///
    /// See [`Self::accept_and_capture_one_datagram`].
    pub async fn echo_one_datagram_with(self, response: Vec<u8>) -> Result<()> {
        let (conn, _client_id) = self.handshake_only_retrying().await?;
        let _incoming =
            conn.read_datagram()
                .await
                .map_err(|source| TunnelError::QuicReadDatagram {
                    context: "echo incoming".into(),
                    source,
                })?;
        conn.send_datagram(bytes::Bytes::from(response))
            .map_err(|source| TunnelError::QuicSendDatagram {
                context: "echo response".into(),
                source,
            })?;
        // Give the client time to read before dropping.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), conn.closed()).await;
        Ok(())
    }

    /// Variant of [`Self::handshake_only`] that loops
    /// silently over `StatelessRetryIssued` so loopback test clients
    /// (whose first packet always lands on an un-validated remote
    /// address) end up with a real
    /// `Connection` rather than the retry-token error. Honest
    /// production clients dial again with the token attached, which
    /// surfaces as a second `accept()` iteration on the endpoint; the
    /// in-process test helpers need to mirror that production
    /// behaviour. A 30 s outer timeout still bounds the wait so a
    /// stuck test fails loudly rather than hanging the suite.
    async fn handshake_only_retrying(&self) -> Result<(quinn::Connection, WarrenPubkey)> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(TunnelError::Internal(
                    "handshake_only_retrying timeout (30 s) - client never connected".to_owned(),
                ));
            }
            match tokio::time::timeout(remaining, self.handshake_only()).await {
                Ok(Ok(pair)) => return Ok(pair),
                Ok(Err(TunnelError::StatelessRetryIssued)) => continue,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(TunnelError::Internal(
                        "handshake_only_retrying timeout (30 s) - client never connected"
                            .to_owned(),
                    ));
                }
            }
        }
    }

    /// Accepts the next incoming connection from ANY datapath endpoint.
    ///
    /// With a single socket (the default) this is exactly
    /// `endpoints[0].accept()`. With `SO_REUSEPORT` sharding it races an
    /// `accept()` across every endpoint and yields whichever socket the kernel
    /// routed the client's flow to. The resulting connection is owned by (and
    /// does all of its subsequent I/O on) that endpoint's driver, so a single
    /// accept task does not re-serialize the datapath: parallelism comes from
    /// the kernel pinning each 4-tuple to a fixed socket, not from which task
    /// accepts. Returns `None` when an endpoint reports closed (shutdown).
    pub(super) async fn accept_any(&self) -> Option<quinn::Incoming> {
        if self.endpoints.len() == 1 {
            return self.endpoints[0].accept().await;
        }
        use std::future::Future;
        let mut accepts: Vec<_> = self
            .endpoints
            .iter()
            .map(|e| Box::pin(e.accept()))
            .collect();
        std::future::poll_fn(move |cx| {
            for a in &mut accepts {
                match a.as_mut().poll(cx) {
                    std::task::Poll::Ready(Some(inc)) => return std::task::Poll::Ready(Some(inc)),
                    // Any endpoint reporting closed means the exit is shutting
                    // down; stop accepting on the whole group.
                    std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                    std::task::Poll::Pending => {}
                }
            }
            std::task::Poll::Pending
        })
        .await
    }

    /// Internal variant: accept the connection + handshake, but return
    /// the `Connection` to the caller for custom follow-up (datagrams).
    /// Returns the authenticated client pubkey alongside the connection
    /// so the pump path can wire per-identity rate limiting without
    /// re-extracting the peer identity from rustls.
    async fn handshake_only(&self) -> Result<(quinn::Connection, WarrenPubkey)> {
        let Some(incoming) = self.accept_any().await else {
            return Err(TunnelError::EndpointClosed);
        };

        if !incoming.remote_address_validated() && incoming.may_retry() {
            match incoming.retry() {
                Ok(()) => return Err(TunnelError::StatelessRetryIssued),
                Err(retry_err) => {
                    tracing::debug!(
                        ?retry_err,
                        "stateless retry could not be issued; falling back to handshake"
                    );
                    return Err(TunnelError::StatelessRetryIssued);
                }
            }
        }

        let conn = incoming
            .await
            .map_err(|source| TunnelError::QuicConnection {
                context: "complete incoming connection",
                source,
            })?;

        let (mut send, mut recv) =
            conn.accept_bi()
                .await
                .map_err(|source| TunnelError::QuicConnection {
                    context: "accept_bi",
                    source,
                })?;
        let buf =
            recv.read_to_end(MAX_SETUP_FRAME_BYTES)
                .await
                .map_err(|e| TunnelError::QuicStream {
                    context: "read Setup".into(),
                    source: Box::new(e),
                })?;

        // Dual-accept (see `handshake_from_incoming`): route a v7 frame to the
        // anonymous session-token path, mapping its 4-tuple down to the
        // `(conn, pubkey)` this helper returns.
        if buf.first() == Some(&PROTOCOL_VERSION_V7) {
            return Self::admit_v7(
                conn,
                send,
                buf,
                &self.sessions,
                &self.allocator,
                &self.allocator_v6,
                &self.state_persister,
                &self.active_conns,
                self.local_pubkey,
                &self.signing_key,
                self.daita_pool.as_ref(),
                self.token_admitter.as_ref(),
                self.unauthenticated_handler.as_ref(),
                self.drain_rx.as_ref(),
            )
            .await
            .map(|(c, sk, _, _)| (c, sk.0));
        }

        let setup = match decode_setup(&buf) {
            Ok(s) => s,
            Err(e) => {
                return Err(reject_unauthenticated(
                    conn,
                    send,
                    self.unauthenticated_handler.as_ref(),
                    buf,
                    TunnelError::SetupWire {
                        context: "decode Setup".into(),
                        source: Box::new(e),
                    },
                ));
            }
        };

        // In-band client auth (protocol v5); see handshake_from_incoming
        // for the rationale. Verify the proof before the allowlist gate.
        let remote_id = WarrenPubkey::from_bytes(setup.client_pubkey);
        let cb = match warrenguard_tls::channel_binding(&conn) {
            Ok(cb) => cb,
            Err(_) => {
                return Err(reject_unauthenticated(
                    conn,
                    send,
                    self.unauthenticated_handler.as_ref(),
                    buf.clone(),
                    TunnelError::ChannelBindingExport,
                ));
            }
        };
        if !warrenguard_tls::verify_client_auth(
            &remote_id,
            &cb,
            &setup.device_id,
            &setup.auth_sig.0,
        ) {
            return Err(reject_unauthenticated(
                conn,
                send,
                self.unauthenticated_handler.as_ref(),
                buf.clone(),
                TunnelError::InbandAuthFailed,
            ));
        }
        if !is_allowed(self.allowlist.as_ref(), remote_id) {
            let _ = send.reset(WARREN_AUTH_FAILED);
            conn.close(WARREN_AUTH_FAILED, b"pubkey not in allowlist");
            return Err(TunnelError::AllowlistDenied);
        }

        // Drain admission gate (same rationale as `handshake_from_incoming`).
        if drain::is_draining(self.drain_rx.as_ref()) {
            let _ = send.reset(WARREN_EXIT_DRAINING);
            conn.close(WARREN_EXIT_DRAINING, WARREN_EXIT_DRAINING_REASON);
            return Err(TunnelError::ExitDrainingRefused);
        }

        // v2 device cap (same gate as `handshake_from_incoming`).
        if let CapDecision::Deny = evaluate_device_cap(
            self.device_cap_enforcer.as_ref(),
            &self.sessions,
            remote_id,
            &setup,
        )
        .await
        {
            let _ = send.reset(WARREN_DEVICE_LIMIT);
            conn.close(WARREN_DEVICE_LIMIT, WARREN_DEVICE_LIMIT_REASON);
            return Err(TunnelError::DeviceLimitReached);
        }

        let attributed = match attribute_session(
            &self.sessions,
            &self.allocator,
            &self.allocator_v6,
            &self.state_persister,
            &self.active_conns,
            &conn,
            remote_id,
            &setup,
            self.daita_pool.as_ref(),
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                // Explicit close on the attribution error path; see
                // `handshake_from_incoming`.
                let _ = send.reset(WARREN_NO_CAPACITY);
                conn.close(WARREN_NO_CAPACITY, WARREN_NO_CAPACITY_REASON);
                return Err(e);
            }
        };

        let ack = SetupAck {
            protocol_version: PROTOCOL_VERSION,
            tunnel_ipv4: attributed.ipv4.octets(),
            tunnel_ipv6: attributed.ipv6.map(|v| v.octets()),
            exit_pubkey: *self.local_pubkey.as_bytes(),
            max_mtu: attributed.max_mtu,
            multiconn_attached: attributed.attached,
            daita_spec: attributed.daita_spec,
            // In-band exit-identity proof (v6); reuses the
            // `cb` already computed above for the client-auth check.
            exit_auth_sig: warrenguard_wire::AuthSig(warrenguard_tls::sign_server_auth(
                &self.signing_key,
                &cb,
            )),
        };
        let resp = encode_setup_ack(&ack).map_err(|e| TunnelError::SetupWire {
            context: "encode SetupAck".into(),
            source: Box::new(e),
        })?;
        send.write_all(&resp)
            .await
            .map_err(|e| TunnelError::QuicStream {
                context: "write SetupAck".into(),
                source: Box::new(e),
            })?;
        send.finish().map_err(|e| TunnelError::QuicStream {
            context: "finish stream".into(),
            source: Box::new(e),
        })?;
        let _ = tokio::time::timeout(Duration::from_millis(500), send.stopped()).await;
        if !attributed.attached {
            return Err(reject_unattached(&conn));
        }
        Ok((conn, remote_id))
    }

    /// Close every active Quinn connection whose `remote_id` is in
    /// `removed`, with QUIC error code [`WARREN_AUTH_FAILED`]. Returns
    /// the number of connections actually closed (`0` if no tracked
    /// session matched any of the supplied IDs).
    ///
    /// Driven by the allowlist refresher: when a snapshot retires a
    /// pubkey, the resulting `(old \ new)` set is delivered to a
    /// task that calls this method. Each closed `Connection`
    /// terminates its pump loop on the next read (Quinn delivers the
    /// peer-error to the read side), so the `sessions` map and the
    /// pump tasks unwind naturally without explicit cancellation.
    ///
    /// Idempotent: closing an already-closed connection is a no-op,
    /// and a pubkey absent from the map contributes `0` to the count.
    pub async fn close_connections_for(&self, removed: &HashSet<WarrenPubkey>) -> usize {
        close_connections_for_impl(
            &self.active_conns,
            &self.sessions,
            &self.allocator,
            &self.allocator_v6,
            removed,
        )
        .await
    }

    /// Detach a cheap revocation handle that can be moved into a
    /// separate task. Required because [`Self::accept_forever_with_tun`]
    /// consumes `self`, so the production code path cannot keep
    /// `&exit` around for the revocation loop.
    #[must_use]
    pub fn revocation_handle(&self) -> ExitRevocationHandle {
        ExitRevocationHandle {
            active_conns: self.active_conns.clone(),
            sessions: self.sessions.clone(),
            allocator: self.allocator.clone(),
            allocator_v6: self.allocator_v6.clone(),
        }
    }

    /// Single-accept driver for the handshake-only mode (no TUN pump).
    ///
    /// `handle_one` is now
    /// a thin wrapper over [`Self::handshake_only`]. Previously the two
    /// paths each carried their own ~130-line copy of the handshake
    /// (accept -> bi-stream -> Setup -> allowlist -> SetupAck), which had
    /// already silently diverged once on the stateless retry guard.
    /// Sharing the same code path eliminates the divergence class
    /// entirely and means the next security/wire change only needs to
    /// be applied in one place.
    ///
    /// Returning `Ok(())` and dropping the `Connection` mirrors the
    /// previous behaviour: `pump_bidirectional` is never spawned (no
    /// TUN), and Quinn drains the connection on drop.
    async fn handle_one(&self) -> Result<()> {
        self.handshake_only().await.map(|(conn, _client_id)| {
            // Explicit drop for self-documentation. Quinn closes the
            // connection in its background driver as soon as the last
            // handle is dropped; the previous version waited
            // 500 ms for the client to FIN the send stream before
            // dropping, which is already done inside `handshake_only`.
            drop(conn);
        })
    }
}

/// Checks whether a remote pubkey is authorized by the configured
/// allowlist handle at the current wall-clock instant. Returns `true`
/// when:
/// - no allowlist is configured (POC permissive mode), OR
/// - the pubkey is currently present in the dynamic
///   [`AllowlistHandle`] AND its per-entry `expires_at` is strictly
///   in the future AND it is not on the CRL.
///
/// Calls [`AllowlistHandle::is_allowed_at`] under the hood so the
/// allowlist contract (per-entry TTL + CRL precedence) is honoured
/// in production. The wall-clock comes from [`warrenguard_config::unix_now`]
/// so the check is consistent with the rest of the daemon.
///
/// Pure helper isolated so RED->GREEN tests can run without spawning a
/// Quinn `Endpoint`; the inline check in `handshake_only` / `handle_one`
/// delegates here for consistency.
fn is_allowed(allowlist: Option<&AllowlistHandle>, remote_id: WarrenPubkey) -> bool {
    use crate::authorizer::{AllowAll, Authorizer};
    let now = warrenguard_config::unix_now();
    // Admission goes through the `Authorizer` trait: a configured allowlist acts
    // as the authorizer, and the no-allowlist case is `AllowAll` (a generic
    // deployer can swap in `StaticAllowlist` or its own policy).
    match allowlist {
        None => AllowAll.is_allowed(&remote_id, now),
        // Fully qualified: `AllowlistHandle` also has an inherent `is_allowed`
        // (a 1-arg convenience) that would otherwise shadow the trait method.
        Some(handle) => Authorizer::is_allowed(handle, &remote_id, now),
    }
}

/// Routes a handshake-complete but UNAUTHENTICATED connection: a
/// peer that did not present a valid, channel-bound Warren `Setup`. If a decoy
/// handler is configured, hand it the live connection and report
/// [`TunnelError::DivertedToDecoy`] (a quiet, expected outcome); otherwise
/// reset the setup stream and close with a generic HTTP/3 error and empty
/// reason (no Warren-specific tell), and report `specific_err`.
/// `send`/`conn` are consumed either way.
///
/// Only protocol-level / auth-proof failures reach here. Authorization denials
/// (a valid, authenticated client the allowlist or device cap rejects) keep
/// their structured close and never divert.
fn reject_unauthenticated(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    handler: Option<&Arc<dyn UnauthenticatedHandler>>,
    request: Vec<u8>,
    specific_err: TunnelError,
) -> TunnelError {
    match handler {
        Some(h) => {
            tracing::debug!("unauthenticated connection diverted to decoy handler");
            // Hand the live connection AND the consumed request stream to the
            // decoy; do NOT close or send a Warren-specific signal. The decoy
            // answers the prober's request on `send` so the cover domain looks
            // like an ordinary HTTP/3 endpoint.
            h.handle(
                conn,
                crate::unauthenticated::UnauthenticatedProbe::new(send, request),
            );
            TunnelError::DivertedToDecoy
        }
        None => {
            // No decoy: close indistinguishably from a generic HTTP/3 endpoint
            // rejecting a malformed request. No Warren-specific code or plaintext
            // reason that an active prober could fingerprint. The
            // `specific_err` is returned locally for logging and flow only; it
            // never reaches the wire.
            let _ = send.reset(H3_GENERAL_PROTOCOL_ERROR);
            conn.close(H3_GENERAL_PROTOCOL_ERROR, b"");
            specific_err
        }
    }
}

/// Closes an unattached connection and returns the error the caller must
/// propagate. Called once `attribute_session`/`attribute_session_v7` came
/// back with `attached: false` (a secondary with no matching primary
/// session, or a `total_connections` protocol violation) and the
/// `SetupAck`/`SetupAckV7` carrying `multiconn_attached: false` has
/// already been written.
///
/// That ack is enough to tell a well-behaved client to close and retry on
/// its own, and nothing was registered in `active_conns` for an
/// unattached attempt (see `attribute_session`), so there is no live
/// session to leak. But without this explicit close the QUIC connection
/// itself would keep sitting open with no pump ever attached to service
/// it, held alive until Quinn's idle timeout instead of releasing its
/// resources immediately; returning `Err` here (instead of `Ok`) also
/// stops the accept-loop caller from spawning a pump / registering a
/// no-op dispatch entry for a connection the client is already
/// discarding.
fn reject_unattached(conn: &quinn::Connection) -> TunnelError {
    conn.close(WARREN_NO_CAPACITY, WARREN_NO_CAPACITY_REASON);
    TunnelError::Protocol("secondary connection did not attach to an existing session".into())
}

/// Outcome of the device-cap gate evaluated in the handshake path.
enum CapDecision {
    /// Proceed to IP attribution. Covers: no enforcer configured, a
    /// secondary connection, an admitted PRIMARY, a renewal of an
    /// existing device, and the fail-open case (transport error).
    Admit,
    /// Refuse this PRIMARY: a NEW device hit the cap. The caller closes
    /// the connection with [`WARREN_DEVICE_LIMIT`].
    Deny,
}

/// Pure-ish device-cap gate, shared by both handshake code paths.
///
/// Only PRIMARY connections (`connection_index == 0`) consult the
/// enforcer; secondaries (idx > 0) always [`CapDecision::Admit`] (they
/// attach to an already-admitted device). A primary that matches an
/// EXISTING `(pubkey, device_id)` session is a reconnect: we still call
/// `open_or_renew` to refresh the lease but always admit, reusing the
/// IP. A primary for a NEW device is admitted on `Ok(true)`, denied on
/// `Ok(false)`, and **fail-open** (admit + warn) on `Err` so a
/// control-plane outage never blacks out the tunnel.
async fn evaluate_device_cap(
    enforcer: Option<&Arc<dyn DeviceCapEnforcer>>,
    sessions: &Arc<AsyncMutex<HashMap<SessionKey, MultiSessionState>>>,
    remote_id: WarrenPubkey,
    setup: &Setup,
) -> CapDecision {
    // No enforcer -> cap disabled, behave exactly as before.
    let Some(enforcer) = enforcer else {
        return CapDecision::Admit;
    };
    // Secondaries never touch the enforcer.
    if setup.connection_index != 0 {
        return CapDecision::Admit;
    }

    let device_id = setup.device_id;
    let key: SessionKey = (remote_id, device_id);
    let is_existing = {
        let map = sessions.lock().await;
        map.contains_key(&key)
    };

    match enforcer.open_or_renew(&remote_id, &device_id).await {
        Ok(true) => CapDecision::Admit,
        Ok(false) => {
            if is_existing {
                // Reconnect of an already-admitted device. A `false`
                // here is unexpected (the device already holds a lease)
                // but we must not evict a live session on it: admit and
                // reuse the existing IP.
                CapDecision::Admit
            } else {
                CapDecision::Deny
            }
        }
        Err(e) => {
            // Fail-open: availability beats strict capping. A ledger
            // outage must never refuse honest clients.
            tracing::warn!(
                error = %e,
                "device-cap check failed, admitting (fail-open)"
            );
            CapDecision::Admit
        }
    }
}

/// Pure decision helper for `SetupAck::daita_spec` accounting for the
/// existing [`MultiSessionState::daita_spec`] of the same Warren
/// identity. Used by [`session::attribute_session`] to share the spec across
/// every connection of a multi-conn session.
///
/// Decision matrix:
///
/// | `setup.daita_support` | `setup.connection_index` | `existing_spec` | `pool`     | Result          |
/// |-----------------------|--------------------------|-----------------|------------|-----------------|
/// | `false`               | any                      | any             | any        | `None`          |
/// | `true`                | `0` (primary)            | `Some(cfg)`     | any        | `Some(cfg)` *(reconnect reuse)* |
/// | `true`                | `0` (primary)            | `None`          | `Some(p)`  | `p.pick(rng)`   |
/// | `true`                | `0` (primary)            | `None`          | `None`     | `None`          |
/// | `true`                | `> 0` (secondary)        | `Some(cfg)`     | any        | `Some(cfg)` *(inherit primary)* |
/// | `true`                | `> 0` (secondary)        | `None`          | any        | `None` *(orphan)* |
///
/// The "reconnect reuse" case (primary with existing spec) prevents a
/// reconnect storm from rotating machines on every retry, which would
/// otherwise nullify the fingerprint-resistance benefit of DAITA.
fn select_daita_spec_with_existing(
    setup: &Setup,
    existing_spec: Option<&warrenguard_wire::DaitaConfig>,
    pool: Option<&DaitaPool>,
    rng: &mut impl rand_v9::Rng,
) -> Option<warrenguard_wire::DaitaConfig> {
    select_daita_spec_raw(
        setup.daita_support,
        setup.connection_index,
        existing_spec,
        pool,
        rng,
    )
}

/// Version-agnostic DAITA-spec selection: the same rule as
/// [`select_daita_spec_with_existing`] but taking the two `Setup` fields it
/// depends on directly, so the v7 attribution path (which has a
/// [`SetupV7`](warrenguard_wire::SetupV7), not a [`Setup`]) can reuse it.
pub(super) fn select_daita_spec_raw(
    daita_support: bool,
    connection_index: u8,
    existing_spec: Option<&warrenguard_wire::DaitaConfig>,
    pool: Option<&DaitaPool>,
    rng: &mut impl rand_v9::Rng,
) -> Option<warrenguard_wire::DaitaConfig> {
    if !daita_support {
        return None;
    }
    if let Some(spec) = existing_spec {
        // Reconnect (primary) or attached secondary: inherit the
        // already-chosen spec. The pool is irrelevant here.
        return Some(spec.clone());
    }
    if connection_index != 0 {
        // Secondary without an established primary session: no spec to
        // inherit. The handshake itself will set `multiconn_attached =
        // false` in this case; emitting `None` is consistent.
        return None;
    }
    pool?.pick(rng)
}

/// Default negotiated MTU on the exit side. Constant
/// for consistency between `handshake_only` (mono or primary) and the
/// multi-conn aggregation (all secondaries inherit the primary's
/// `max_mtu` stored in `MultiSessionState`).
const DEFAULT_MAX_MTU: u16 = 1350;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: a `Setup` with all fields explicit. These tests
    /// exercise session attribution/device-cap logic, not the in-band auth
    /// gate, so the auth fields carry zero sentinels.
    fn setup_for(daita_support: bool, conn_idx: u8, total: u8) -> Setup {
        Setup {
            protocol_version: PROTOCOL_VERSION,
            features: 0,
            connection_index: conn_idx,
            total_connections: total,
            daita_support,
            device_id: [0u8; warrenguard_wire::DEVICE_ID_LEN],
            client_pubkey: [0u8; warrenguard_wire::CLIENT_PUBKEY_LEN],
            auth_sig: warrenguard_wire::AuthSig([0u8; warrenguard_wire::AUTH_SIG_LEN]),
        }
    }

    #[test]
    fn select_daita_spec_returns_none_when_client_did_not_opt_in() {
        // Even with a fully-stocked pool, if the client did not flip
        // `daita_support`, the exit MUST emit `daita_spec: None`. The
        // contract is opt-in: never deploy DAITA on a client that did
        // not ask for it (the client UI surface depends on this).
        let pool = DaitaPool::default_pool();
        let setup = setup_for(false, 0, 1);
        let got = select_daita_spec_with_existing(&setup, None, Some(&pool), &mut rand_v9::rng());
        assert!(
            got.is_none(),
            "select_daita_spec MUST return None when client.daita_support=false"
        );
    }

    #[test]
    fn select_daita_spec_returns_none_when_exit_has_no_pool() {
        // Symmetric to the previous test: even if the client wants
        // DAITA, an exit without a configured pool MUST respond with
        // None (it has no machines to offer).
        let setup = setup_for(true, 0, 1);
        let got = select_daita_spec_with_existing(&setup, None, None, &mut rand_v9::rng());
        assert!(
            got.is_none(),
            "select_daita_spec MUST return None when exit pool is unset"
        );
    }

    #[test]
    fn select_daita_spec_returns_none_for_orphan_multi_conn_secondary() {
        // Multi-conn secondary arrives WITHOUT an established primary
        // session: no spec to inherit, so the SetupAck carries
        // daita_spec=None. The handshake itself will also set
        // multiconn_attached=false in this case (cf.
        // `attribute_session`'s secondary branch).
        let pool = DaitaPool::default_pool();
        let secondary = setup_for(true, 2, 4);
        let got =
            select_daita_spec_with_existing(&secondary, None, Some(&pool), &mut rand_v9::rng());
        assert!(
            got.is_none(),
            "orphan multi-conn secondary MUST receive daita_spec=None (no primary to inherit from)"
        );
    }

    #[test]
    fn select_daita_spec_with_existing_secondary_inherits_primary_spec() {
        // Multi-conn secondary WITH an established primary spec: the
        // exit MUST hand back the same spec so every connection of the
        // session runs the same maybenot machines. Otherwise the
        // signal an attacker observes across the N connections would
        // not collapse into a single fingerprint defense.
        let pool = DaitaPool::default_pool();
        let primary_spec = pool
            .pick(&mut rand_v9::rng())
            .expect("default pool yields at least one machine");
        let secondary = setup_for(true, 2, 4);
        let got = select_daita_spec_with_existing(
            &secondary,
            Some(&primary_spec),
            Some(&pool),
            &mut rand_v9::rng(),
        )
        .expect("secondary with existing spec MUST inherit");
        assert_eq!(
            got, primary_spec,
            "secondary MUST inherit byte-identical primary spec, not a fresh pick"
        );
    }

    #[test]
    fn select_daita_spec_with_existing_primary_reuses_on_reconnect() {
        // A primary that reconnects (existing session in the map)
        // MUST inherit the spec already negotiated, not re-pick. A
        // reconnect storm picking fresh machines every iteration
        // would defeat the fingerprint defense.
        let pool = DaitaPool::default_pool();
        let existing = pool
            .pick(&mut rand_v9::rng())
            .expect("default pool yields at least one machine");
        let primary = setup_for(true, 0, 4);
        let got = select_daita_spec_with_existing(
            &primary,
            Some(&existing),
            Some(&pool),
            &mut rand_v9::rng(),
        )
        .expect("primary reconnect MUST yield the existing spec");
        assert_eq!(
            got, existing,
            "primary reconnect MUST reuse the existing spec, never re-pick"
        );
    }

    #[test]
    fn select_daita_spec_with_existing_returns_none_when_daita_support_false() {
        // Defense in depth: even when an existing spec is present in
        // the session state, a Setup that drops `daita_support` (= a
        // stale or downgraded reconnect) MUST get None back. This
        // matches the opt-in invariant.
        let pool = DaitaPool::default_pool();
        let spec = pool
            .pick(&mut rand_v9::rng())
            .expect("default pool yields at least one machine");
        let downgraded = setup_for(false, 0, 1);
        let got = select_daita_spec_with_existing(
            &downgraded,
            Some(&spec),
            Some(&pool),
            &mut rand_v9::rng(),
        );
        assert!(
            got.is_none(),
            "client downgrading to daita_support=false MUST get None even when a spec exists"
        );
    }

    #[test]
    fn select_daita_spec_returns_some_enabled_when_client_opt_in_and_pool_present() {
        // The nominal happy path: client opts in, exit has the curated
        // pool, primary connection. The returned config must be
        // semantically enabled (at least one machine spec).
        let pool = DaitaPool::default_pool();
        let primary = setup_for(true, 0, 1);
        let got = select_daita_spec_with_existing(&primary, None, Some(&pool), &mut rand_v9::rng())
            .expect("nominal path must yield Some(cfg)");
        assert!(
            got.is_enabled(),
            "the picked DaitaConfig MUST carry at least one machine spec"
        );
    }

    #[test]
    fn exit_bind_opts_default_disables_daita_pool() {
        // Tripwire: any drift in the default that silently enables
        // DAITA would break the opt-in contract advertised in the UI
        // and surprise existing deployments.
        let opts = ExitBindOpts::default();
        assert!(
            opts.daita_pool.is_none(),
            "ExitBindOpts::default() MUST keep daita_pool = None for opt-in semantics"
        );
    }

    #[test]
    fn exit_bind_opts_default_handshake_rate_limit_is_the_fixed_engine_default() {
        // Back-compat guard, mirrors
        // `reuseport_multi_endpoint::default_bind_opts_keep_a_single_datapath_socket`:
        // `ExitBindOpts::default()` is deliberately NOT wired to
        // `WARREN_HS_RATE_BURST` / `WARREN_HS_RATE_PER_SEC` (a deployer's own
        // exit binary reads those knobs and overrides this field explicitly),
        // so the default must stay exactly this fixed bucket regardless of
        // what the env vars are set to in the test process.
        let opts = ExitBindOpts::default();
        let limit = opts
            .handshake_rate_limit
            .expect("the engine default keeps the per-IP handshake limiter on");
        assert_eq!(limit.burst, 512, "default burst must not silently drift");
        assert_eq!(
            limit.refill_per_sec, 256,
            "default refill rate must not silently drift"
        );
    }

    /// `(pubkey, device_id)` session key helper for allocator tests.
    fn skey(pk: u8, dev: u8) -> SessionKey {
        (
            WarrenPubkey::from_bytes([pk; 32]),
            [dev; warrenguard_wire::DEVICE_ID_LEN],
        )
    }

    #[test]
    fn ip_allocator_returns_distinct_addresses() {
        let alloc = IpAllocator::new();
        let a = alloc.allocate(&skey(1, 1)).unwrap();
        let b = alloc.allocate(&skey(2, 2)).unwrap();
        let c = alloc.allocate(&skey(3, 3)).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn ip_allocator_starts_after_gateway() {
        let alloc = IpAllocator::new();
        let first = alloc.allocate(&skey(1, 1)).unwrap();
        assert_eq!(first, Ipv4Addr::new(10, 66, 0, 2));
    }

    #[test]
    fn ip_allocator_stays_in_pool_for_first_thousand() {
        let alloc = IpAllocator::new();
        for i in 0..1000u16 {
            let ip = alloc
                .allocate(&skey((i % 251) as u8, (i / 251) as u8))
                .unwrap();
            let o = ip.octets();
            assert_eq!(o[0], 10);
            assert_eq!(o[1], 66);
        }
    }

    #[test]
    fn ip_allocator_v4_exhaustion_returns_error() {
        let alloc = IpAllocator::with_capacity(1);
        assert!(alloc.allocate(&skey(1, 1)).is_ok());
        assert!(
            alloc.allocate(&skey(2, 2)).is_err(),
            "must return Err on pool exhaustion, not panic"
        );
    }

    #[test]
    fn ip_allocator_v6_exhaustion_returns_error() {
        let alloc = IpAllocatorV6::with_next(u64::MAX - 1);
        assert!(alloc.allocate(&skey(1, 1)).is_ok());
        assert!(
            alloc.allocate(&skey(2, 2)).is_err(),
            "must return Err on pool exhaustion, not panic"
        );
    }

    #[test]
    fn ip_allocator_v4_stays_exhausted_and_never_wraps_to_reserved_ips() {
        // Fill the whole pool, then assert the allocator stays exhausted
        // (an IP is recyclable ONLY once no live holder remains) and
        // that no reserved address (network 10.66.0.0, gateway
        // 10.66.0.1, broadcast 10.66.255.255) nor any duplicate was
        // ever handed out.
        let alloc = IpAllocator::new();
        let mut seen = std::collections::HashSet::new();
        let mut last = Ipv4Addr::UNSPECIFIED;
        for i in 0..u32::from(IPV4_POOL_MAX_HOSTS) {
            let key = skey((i % 251) as u8 + 1, (i / 251) as u8);
            // Distinct (pubkey, device) per allocation; the pubkey byte
            // cycles so devices disambiguate.
            let key = ((key.0), {
                let mut d = key.1;
                d[15] = (i % 256) as u8;
                d[14] = ((i >> 8) % 256) as u8;
                d
            });
            let ip = alloc.allocate(&key).expect("pool not yet exhausted");
            assert_ne!(ip, Ipv4Addr::new(10, 66, 0, 0), "network address leaked");
            assert_ne!(ip, Ipv4Addr::new(10, 66, 0, 1), "gateway address leaked");
            assert_ne!(
                ip,
                Ipv4Addr::new(10, 66, 255, 255),
                "broadcast address leaked"
            );
            assert!(seen.insert(ip), "duplicate IP {ip} while holders are live");
            last = ip;
        }
        assert_eq!(
            last,
            Ipv4Addr::new(10, 66, 255, 254),
            "the last usable host of the /16 must be allocatable"
        );
        for _ in 0..4 {
            assert!(
                alloc.allocate(&skey(0, 0)).is_err(),
                "exhausted allocator must keep erroring while every IP has a live holder"
            );
        }
        // Releasing exactly one address makes exactly that address
        // allocatable again - never a reserved or still-held one.
        let released = Ipv4Addr::new(10, 66, 7, 7);
        alloc.release(released, &skey(9, 9));
        assert_eq!(
            alloc.allocate(&skey(10, 10)).expect("one slot free again"),
            released,
            "the recycled address must be the released one, nothing else is free"
        );
        assert!(
            alloc.allocate(&skey(11, 11)).is_err(),
            "pool must be exhausted again after the single free slot is consumed"
        );
    }

    #[test]
    fn ip_allocator_v6_stays_exhausted_and_never_wraps() {
        let alloc = IpAllocatorV6::with_next(u64::MAX - 1);
        assert!(alloc.allocate(&skey(1, 1)).is_ok());
        for _ in 0..4 {
            assert!(
                alloc.allocate(&skey(2, 2)).is_err(),
                "exhausted v6 allocator must keep erroring, never wrap to the network address"
            );
        }
    }

    #[test]
    fn ip_allocator_v4_never_exhausts_under_alloc_release_churn() {
        // The N-1 DoS scenario: a single subscriber loops handshakes
        // with fresh random device_ids (or a fleet of clients restarts
        // daily). With the old monotonic allocator every iteration
        // burned an offset forever and the pool died permanently. With
        // recycling, 10 000 connect/disconnect cycles against a pool of
        // 8 addresses must never exhaust.
        let alloc = IpAllocator::with_capacity(8);
        for i in 0..10_000u32 {
            let key = skey((i % 256) as u8, ((i >> 8) % 256) as u8);
            let ip = alloc.allocate(&key).unwrap_or_else(|e| {
                panic!("pool exhausted at iteration {i}: {e} - recycling broken")
            });
            alloc.release(ip, &key);
        }
        assert_eq!(
            alloc.free_count(),
            8,
            "all addresses must be free again after the churn"
        );
    }

    #[test]
    fn ip_allocator_v4_reconnect_gets_same_ip_after_release() {
        // Sticky hint: the same (pubkey, device_id) reconnecting after
        // its session was evicted must land on its previous address
        // while that address is still free (preserves the pre-eviction
        // reconnect-same-IP behaviour).
        let alloc = IpAllocator::new();
        let key = skey(1, 1);
        // Burn a few other allocations so FIFO order alone would NOT
        // return the same address.
        let _a = alloc.allocate(&skey(2, 2)).unwrap();
        let ip = alloc.allocate(&key).unwrap();
        alloc.release(ip, &key);
        let _b = alloc.allocate(&skey(3, 3)).unwrap();
        let again = alloc.allocate(&key).unwrap();
        assert_eq!(
            again, ip,
            "reconnect of the same (pubkey, device_id) must prefer its previous IP"
        );
    }

    #[test]
    fn ip_allocator_v4_sticky_hint_never_steals_a_held_ip() {
        let alloc = IpAllocator::with_capacity(4);
        let holder = skey(1, 1);
        let ip = alloc.allocate(&holder).unwrap();
        // Another key gets a (stale) hint pointing at the held address.
        let intruder = skey(2, 2);
        alloc.install_hint(&intruder, ip);
        let got = alloc.allocate(&intruder).unwrap();
        assert_ne!(
            got, ip,
            "a sticky hint must never hand out an address still held by a live session"
        );
    }

    #[test]
    fn ip_allocator_v4_sticky_map_stays_bounded_by_capacity() {
        // A malicious client rotating identities must not inflate the
        // hint map beyond the pool capacity (mirrors ip_pool.rs's
        // self-cleaning invariant).
        let alloc = IpAllocator::with_capacity(4);
        for i in 0..100u8 {
            let key = skey(i, i);
            let ip = alloc.allocate(&key).expect("capacity 4, churn of 1");
            alloc.release(ip, &key);
        }
        assert!(
            alloc.sticky_count() <= 4,
            "sticky map must stay bounded by the pool capacity, got {}",
            alloc.sticky_count()
        );
    }

    #[test]
    fn ip_allocator_v4_release_ignores_reserved_and_foreign_ips() {
        let alloc = IpAllocator::with_capacity(2);
        // Exhaust the pool.
        let _a = alloc.allocate(&skey(1, 1)).unwrap();
        let _b = alloc.allocate(&skey(2, 2)).unwrap();
        // None of these may re-open the pool.
        alloc.release(Ipv4Addr::new(10, 66, 0, 0), &skey(3, 3));
        alloc.release(Ipv4Addr::new(10, 66, 0, 1), &skey(3, 3));
        alloc.release(Ipv4Addr::new(10, 66, 255, 255), &skey(3, 3));
        alloc.release(Ipv4Addr::new(192, 168, 1, 1), &skey(3, 3));
        // Out-of-capacity offset (pool is limited to the first 2 hosts).
        alloc.release(Ipv4Addr::new(10, 66, 0, 9), &skey(3, 3));
        assert!(
            alloc.allocate(&skey(4, 4)).is_err(),
            "reserved/foreign releases must never create allocatable slots"
        );
    }

    #[test]
    fn ip_allocator_v4_double_release_is_idempotent() {
        let alloc = IpAllocator::with_capacity(2);
        let key = skey(1, 1);
        let ip = alloc.allocate(&key).unwrap();
        alloc.release(ip, &key);
        alloc.release(ip, &key);
        // Both remaining slots allocatable, the double-released address
        // only once.
        let x = alloc.allocate(&skey(2, 2)).unwrap();
        let y = alloc.allocate(&skey(3, 3)).unwrap();
        assert_ne!(x, y, "double release must not duplicate a free slot");
        assert!(alloc.allocate(&skey(4, 4)).is_err());
    }

    #[test]
    fn ip_allocator_v6_recycles_and_prefers_sticky_offset() {
        let alloc = IpAllocatorV6::new();
        let key = skey(1, 1);
        let _other = alloc.allocate(&skey(2, 2)).unwrap();
        let ip = alloc.allocate(&key).unwrap();
        alloc.release(ip, &key);
        let again = alloc.allocate(&key).unwrap();
        assert_eq!(
            again, ip,
            "v6 reconnect of the same (pubkey, device_id) must prefer its previous address"
        );
    }

    #[test]
    fn ip_allocator_v6_boot_hint_is_honoured_on_first_allocate() {
        // Restart semantics: a hint installed from the persisted state
        // must route the reconnecting device back onto its previous
        // interface ID even though the fresh allocator never minted it.
        let alloc = IpAllocatorV6::new();
        let key = skey(1, 1);
        let previous = Ipv6Addr::new(0xfdcc, 0xf, 0x1, 0, 0, 0, 0, 7);
        alloc.install_hint(&key, previous);
        let got = alloc.allocate(&key).unwrap();
        assert_eq!(got, previous, "boot hint must be honoured while free");
        // And a different client must NOT receive the same address.
        let other = alloc.allocate(&skey(2, 2)).unwrap();
        assert_ne!(other, previous);
    }

    #[test]
    fn ip_allocator_v4_boot_hint_is_honoured_on_first_allocate() {
        let alloc = IpAllocator::new();
        let key = skey(1, 1);
        let previous = Ipv4Addr::new(10, 66, 0, 7);
        alloc.install_hint(&key, previous);
        let got = alloc.allocate(&key).unwrap();
        assert_eq!(got, previous, "boot hint must be honoured while free");
    }

    fn fixed_pubkey(seed: u8) -> WarrenPubkey {
        WarrenPubkey::from_bytes([seed; 32])
    }

    /// Build an `AllowlistHandle` pre-populated with one snapshot
    /// containing the supplied seeds. Centralised so each test reads
    /// like English instead of fiddling with snapshot wiring.
    fn allowlist_handle_with(seeds: &[u8]) -> AllowlistHandle {
        let (handle, _rx) = AllowlistHandle::new();
        let pubkeys: HashSet<WarrenPubkey> = seeds.iter().copied().map(fixed_pubkey).collect();
        handle.apply_snapshot(crate::allowlist::AllowlistSnapshot::from_legacy_set(
            1, pubkeys, 1_000,
        ));
        handle
    }

    /// Critical regression: without an allowlist configured, the exit
    /// must remain permissive (= pre-allowlist behavior). If we
    /// regressed to `false` by default, all existing POC deployments
    /// (no allowlist) would refuse their own clients.
    #[test]
    fn is_allowed_returns_true_when_no_allowlist_configured() {
        assert!(is_allowed(None, fixed_pubkey(1)));
    }

    /// Critical regression: a client whose pubkey is in the allowlist
    /// MUST be able to handshake. Otherwise the exit refuses even
    /// explicitly provisioned clients = total outage.
    #[test]
    fn is_allowed_returns_true_when_remote_id_in_allowlist() {
        let handle = allowlist_handle_with(&[1, 2]);
        assert!(is_allowed(Some(&handle), fixed_pubkey(2)));
    }

    /// Critical regression: a client whose pubkey is NOT in the
    /// allowlist MUST be refused. This is the fundamental security
    /// property of the allowlist gate.
    #[test]
    fn is_allowed_returns_false_when_remote_id_not_in_allowlist() {
        let handle = allowlist_handle_with(&[1]);
        // The attacker has a different pubkey (seed=99) which they
        // cannot change (derived from their own SigningKey). The exit
        // must refuse even if they complete the QUIC TLS handshake.
        assert!(!is_allowed(Some(&handle), fixed_pubkey(99)));
    }

    /// Edge case: an empty allowlist (no client authorized) refuses
    /// every handshake. Use case: exit in maintenance or graceful
    /// drain. The newly-built handle from `AllowlistHandle::new`
    /// before any snapshot has been applied is the canonical "empty
    /// allowlist" state.
    #[test]
    fn is_allowed_returns_false_when_allowlist_is_empty() {
        let (handle, _rx) = AllowlistHandle::new();
        assert!(!is_allowed(Some(&handle), fixed_pubkey(1)));
    }

    /// Dynamic membership: a snapshot landed at runtime must take
    /// effect for the NEXT `is_allowed` call. Regression here would
    /// mean the gate caches its source-of-truth in a way the polling
    /// refresher could not influence, defeating the whole phase.
    #[test]
    fn is_allowed_reflects_runtime_snapshot_change() {
        let (handle, _rx) = AllowlistHandle::new();
        // Before the first snapshot: fail-closed.
        assert!(!is_allowed(Some(&handle), fixed_pubkey(7)));

        let mut pubkeys = HashSet::new();
        pubkeys.insert(fixed_pubkey(7));
        handle.apply_snapshot(crate::allowlist::AllowlistSnapshot::from_legacy_set(
            1, pubkeys, 1_000,
        ));
        assert!(is_allowed(Some(&handle), fixed_pubkey(7)));

        // Revocation: gen bump, pubkey gone.
        handle.apply_snapshot(crate::allowlist::AllowlistSnapshot::from_legacy_set(
            2,
            HashSet::new(),
            2_000,
        ));
        assert!(!is_allowed(Some(&handle), fixed_pubkey(7)));
    }

    fn limiter(burst: u32, per_sec: u32) -> HandshakeRateLimiter {
        HandshakeRateLimiter::new(HandshakeRateLimit::new(burst, per_sec))
    }

    fn limiter_with_keys(burst: u32, per_sec: u32, max_keys: usize) -> HandshakeRateLimiter {
        HandshakeRateLimiter::new(HandshakeRateLimit {
            burst,
            refill_per_sec: per_sec,
            max_keys,
        })
    }

    #[test]
    fn token_bucket_allows_up_to_burst_then_rejects() {
        // Zero refill isolates the burst allowance from time-based refill.
        let rl = limiter(5, 0);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..5 {
            assert!(rl.check(ip), "must admit up to the burst capacity");
        }
        assert!(
            !rl.check(ip),
            "must reject once the burst is spent and nothing has refilled"
        );
    }

    #[test]
    fn token_bucket_refills_at_the_configured_rate() {
        // Burst 1 so the bucket empties immediately; 100/s refill means one
        // token is back well within 60 ms.
        let rl = limiter(1, 100);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(rl.check(ip), "first handshake spends the single token");
        assert!(!rl.check(ip), "bucket is empty immediately after");
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            rl.check(ip),
            "a token must have refilled at 100/s within 60 ms"
        );
    }

    #[test]
    fn token_bucket_is_independent_per_ip() {
        let rl = limiter(2, 0);
        let ip_a: IpAddr = "1.2.3.4".parse().unwrap();
        let ip_b: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.check(ip_a));
        assert!(rl.check(ip_a));
        assert!(!rl.check(ip_a), "ip_a burst exhausted");
        assert!(rl.check(ip_b), "ip_b has its own bucket");
        assert!(rl.check(ip_b));
        assert!(!rl.check(ip_b), "ip_b burst exhausted");
    }

    #[test]
    fn cgnat_burst_is_absorbed_by_a_generous_bucket() {
        // The whole point of the redesign: a shared CGNAT egress IP whose
        // users reconnect en masse must be admitted, not throttled. With the
        // engine default (burst 512), a 400-user reconnect wave from one IP
        // all gets through.
        let rl = limiter(512, 256);
        let cgnat_ip: IpAddr = "203.0.113.7".parse().unwrap();
        let admitted = (0..400).filter(|_| rl.check(cgnat_ip)).count();
        assert_eq!(
            admitted, 400,
            "a 400-handshake reconnect burst from one CGNAT IP must be fully admitted \
             (the global concurrency semaphore, not this bucket, is the cost ceiling)"
        );
    }

    #[test]
    fn token_bucket_rejects_new_ips_at_key_capacity() {
        // High burst so only the key cap is exercised. Cap = 2 distinct IPs.
        let rl = limiter_with_keys(1000, 0, 2);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let c: IpAddr = "10.0.0.3".parse().unwrap();
        assert!(rl.check(a), "first distinct IP accepted");
        assert!(
            rl.check(b),
            "second distinct IP accepted (fills the key cap)"
        );
        assert!(
            !rl.check(c),
            "third distinct IP rejected fail-closed once the key cap is full"
        );
        assert_eq!(
            rl.entry_count(),
            2,
            "map must not grow past max_keys under a distinct-IP flood"
        );
        assert!(
            rl.check(a),
            "an already-tracked IP keeps working at key capacity"
        );
    }

    #[test]
    fn gc_prunes_fully_refilled_idle_ips() {
        // Burst 4, fast refill: after a short idle the bucket refills to full
        // and GC drops it (no state worth keeping), so memory tracks only
        // actively-limited IPs.
        let rl = limiter(4, 1000);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(rl.check(ip));
        assert_eq!(rl.entry_count(), 1);
        std::thread::sleep(Duration::from_millis(60));
        rl.gc();
        assert_eq!(
            rl.entry_count(),
            0,
            "an IP whose bucket has refilled to burst must be pruned"
        );
    }
}
