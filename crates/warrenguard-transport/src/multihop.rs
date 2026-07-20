//! Multi-hop client tunnel.
//!
//! This module also exposes [`WarrenPumpHandle`], the minimal `send` /
//! `recv` surface a deployer's pump loop consumes. [`MultiHopClient`]
//! implements the trait below so the pump loop stays transport-agnostic.
//!
//! Wraps a QUIC connection to a Warren relay with an HPKE multi-message
//! session bound to the destination exit's long-lived X25519 pubkey. Every
//! outbound payload is sealed with the forward direction; every reverse
//! datagram is opened with the direction-tagged reverse pattern from
//! [`warrenguard_multihop::ClientSession::open_response`].
//!
//! The relay-facing QUIC handshake authenticates the relay via TLS raw
//! public keys: the SNI carries the base32-encoded relay Ed25519 pubkey
//! (cf. [`warrenguard_tls::name::encode`]), and warren-tls' `ServerCertificateVerifier`
//! refuses to complete the handshake unless the peer's RPK matches that
//! SNI. A descriptor whose `relay_ed25519_pubkey` does not match the
//! actual relay therefore fails at handshake, defeating an IP / DNS
//! hijack on the first hop.
//!
//! The relay descriptor itself is verified by [`Self::connect`] against
//! the supplied operational pubkey BEFORE the dial: a tampered
//! descriptor cannot push the dial to an attacker-chosen endpoint
//! because the embedded `relay_ed25519_pubkey` would no longer match a
//! genuine relay's RPK.

use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "pq-hpke")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ed25519_dalek::{SigningKey, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use quinn::{Connection, Endpoint, TransportConfig};
use thiserror::Error;
use warrenguard_backoff::Backoff;
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::{
    ClientSession, ExitId, IpAssignment, MULTIHOP_FRAME_MAX_OVERHEAD, MultihopError,
    RELAY_AUTH_PROOF_LEN, RejectionReason, RelayDescriptorSigned, RelayPkiError, ReplayWindow,
    WARREN_MH_DRAINING, WarrenControlMessage, WarrenKemPublicKey, decode_frame,
    decode_relay_auth_proof, encode_control, encode_frame, parse_exit_x25519_pubkey,
    verify_relay_descriptor,
};
#[cfg(feature = "pq-hpke")]
use warrenguard_multihop::{
    MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD, PqClientSession, XWingRecipientPublicKey, decode_frame_v2,
    encode_frame_v2,
};
use warrenguard_socket_bypass::SocketBypass;
use warrenguard_tcp_fallback::tls::connect_cover_tls;
use warrenguard_tcp_fallback::{
    FallbackPolicy, TcpCarrierSocket, build_carrier_client_endpoint, connect_with_fallback,
};
use warrenguard_tls::{
    WarrenTlsError, channel_binding, default_crypto_provider, make_client_config,
    make_client_config_webpki, mozilla_root_store, verify_relay_auth,
};

use crate::tcp_fallback::{COVER_TCP_PORT, build_cover_client_config, connect_tcp_carrier};
use warrenguard_transport_core::{
    warren_transport_config_client_multihop_with_gso, warren_transport_config_client_with_gso,
};
use warrenguard_wire::{SessionToken, WarrenPubkey};

/// Wall-clock ceiling for receiving the entry relay's in-band identity proof
/// in X.509 cover-domain mode. The proof rides a server-initiated
/// uni stream sent right after the handshake, so this only needs to absorb one
/// RTT plus scheduling jitter; a relay that does not produce it promptly is
/// treated as failing the identity check.
const RELAY_PROOF_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors emitted by the multi-hop client across connect / send / recv /
/// rekey.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MultiHopError {
    /// The relay descriptor failed to verify against the configured
    /// operational pubkey. The dial is aborted before any UDP traffic
    /// is emitted.
    #[error("relay descriptor PKI verification failed: {0}")]
    RelayPki(#[from] RelayPkiError),
    /// Building the TLS client config failed (provider missing the
    /// QUIC initial cipher, etc.).
    #[error("TLS client config build failed: {0}")]
    Tls(#[from] WarrenTlsError),
    /// Binding the local Quinn endpoint failed.
    #[error("failed to bind local QUIC endpoint on {addr}: {source}")]
    Bind {
        /// Address requested at bind time.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `Endpoint::connect` rejected the dial parameters (bad endpoint
    /// shape, missing default client config, etc.).
    #[error("QUIC connect setup failed: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// The QUIC handshake itself failed (peer aborted, timeout, RPK
    /// pin mismatch surfaced as a TLS verifier rejection, etc.).
    #[error("QUIC handshake failed: {0}")]
    Handshake(#[source] quinn::ConnectionError),
    /// The relay's UDP handshake failed and the armed TLS-over-TCP fallback
    /// carrier also failed (cover-domain TLS handshake, the carrier's inner
    /// QUIC handshake, or the cover-config build). Carries an opaque I/O error:
    /// no address or identity material is rendered. Retriable like a plain
    /// handshake failure, since a UDP-hostile network can be transiently
    /// TCP-hostile and the descriptor/PKI have already verified.
    #[error("tcp fallback carrier failed: {0}")]
    TcpFallback(#[source] std::io::Error),
    /// HPKE setup or rekey failed.
    #[error("HPKE session error: {0}")]
    Session(#[from] MultihopError),
    /// Wire-format encode failed (postcard internal failure; never on
    /// well-formed inputs).
    #[error("encode multi-hop frame: {0}")]
    Encode(postcard::Error),
    /// Wire-format decode rejected a frame received from the relay.
    #[error("decode multi-hop frame: {0}")]
    Decode(postcard::Error),
    /// Quinn refused to enqueue the datagram (over MTU, datagrams
    /// disabled, connection lost).
    #[error("send datagram: {0}")]
    Send(#[from] quinn::SendDatagramError),
    /// The bidi setup stream could not be opened, written, or read to
    /// completion (peer reset, connection lost). Setup runs over a
    /// reliable QUIC stream - unlike data datagrams - so a failure here
    /// is fatal to the connection rather than a droppable packet.
    #[error("setup stream {context}: {detail}")]
    SetupStream {
        /// Which stream step failed (open / write / finish / read).
        context: &'static str,
        /// Underlying Quinn error rendered as text (the concrete
        /// open/write/read error types differ, so they are flattened
        /// to a string at the boundary).
        detail: String,
    },
    /// The peer closed the connection before a datagram could be read.
    #[error("read datagram failed: {0}")]
    Recv(#[source] quinn::ConnectionError),
    /// A received frame addressed a different exit than the session is
    /// pinned to. Treated as a protocol violation by the relay or a
    /// hostile cross-session injection attempt.
    #[error("received frame exit_id does not match session")]
    UnexpectedExitId,
    /// Anti-replay rejected the seq / epoch tuple (duplicate or too
    /// old).
    #[error("anti-replay rejection (epoch {epoch}, seq {seq})")]
    Replay {
        /// Frame epoch.
        epoch: u32,
        /// Frame seq.
        seq: u64,
    },
    /// The exit definitively refused the session via an application
    /// close code (e.g. the client pubkey is not on the subscription
    /// allowlist). Unlike a transient network loss, an immediate redial
    /// would hit the same refusal, so the supervisor surfaces this
    /// upward instead of hot-looping.
    #[error("exit rejected session: {0}")]
    Rejected(RejectionReason),
    /// X.509 cover-domain mode only: the entry relay did not prove
    /// possession of the Ed25519 identity pinned in its signed descriptor. The
    /// WebPKI handshake succeeded (the relay holds a valid cover-domain cert,
    /// e.g. the shared wildcard) but the in-band relay-auth proof was absent,
    /// malformed, or signed by the wrong key. Fail-closed: a man-in-the-middle
    /// holding only the cover cert must not be dialed.
    #[error("entry relay identity proof failed: {0}")]
    RelayIdentity(&'static str),
}

impl MultiHopError {
    /// Whether the error is consistent with a transient network blip
    /// (cold-start backbone variance, transient bind contention, peer
    /// handshake stall) so the dial is worth retrying after a backoff.
    ///
    /// Configuration errors (PKI mismatch, TLS provider setup,
    /// wire-format decode of a poisoned descriptor) are never retried:
    /// they would burn every attempt and surface the same error.
    #[must_use]
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            MultiHopError::Bind { .. }
                | MultiHopError::Connect(_)
                | MultiHopError::Handshake(_)
                | MultiHopError::TcpFallback(_),
        )
    }

    /// Which hop DELIBERATELY refused this dial, or `None` for every
    /// other failure. A refusal is deterministic (the node's admission
    /// gate is closed, e.g. a maintenance drain): an immediate redial of
    /// the same circuit hits the same answer, so callers should retarget
    /// or stop hammering instead of treating it like a transient blip.
    ///
    /// Detected refusals:
    /// - the entry relay's QUIC `CONNECTION_REFUSED` transport close
    ///   (its listener refuses every new connection while drained),
    /// - the exit's maintenance-drain application close code
    ///   ([`WARREN_MH_DRAINING`]), which by design never maps to a
    ///   [`RejectionReason`] (a drain is maintenance, not policy).
    ///
    /// The exit's drain refusal can also surface post-handshake on the
    /// setup stream; that path flattens the close into a string
    /// ([`MultiHopError::SetupStream`]) and is deliberately not matched
    /// here (fragile), the redial then re-hits the refusal at dial time
    /// where this classification catches it.
    #[must_use]
    pub fn dial_refusal(&self) -> Option<DialRefusedHop> {
        let (MultiHopError::Handshake(err) | MultiHopError::Recv(err)) = self else {
            return None;
        };
        match err {
            quinn::ConnectionError::ConnectionClosed(close)
                if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED =>
            {
                Some(DialRefusedHop::Entry)
            }
            quinn::ConnectionError::ApplicationClosed(ac)
                if u64::from(ac.error_code) == u64::from(WARREN_MH_DRAINING) =>
            {
                Some(DialRefusedHop::Exit)
            }
            _ => None,
        }
    }

    /// The engine's supervisor-facing verdict for this failure: fatal (stop),
    /// retry-same-target (transient), or retry-with-reselect (a deliberate
    /// refusal a different exit would not share). The single home for the
    /// multi-hop reconnect policy, consumed by a supervisor instead of being
    /// re-derived per client.
    ///
    /// A policy rejection carries its own verdict (fatal for an unauthorized
    /// account, reselect for exhaustion). A dial refusal by the entry relay or
    /// the exit's drain reselects (redialing the same circuit re-hits the closed
    /// admission gate). Everything else retries the same target under backoff.
    #[must_use]
    pub fn retryability(&self) -> warrenguard_wire::Retryability {
        if let MultiHopError::Rejected(reason) = self {
            return reason.retryability();
        }
        if self.dial_refusal().is_some() {
            return warrenguard_wire::Retryability::RetryReselect;
        }
        warrenguard_wire::Retryability::RetrySameTarget
    }
}

/// Which hop of the dialed circuit refused a dial attempt (see
/// [`MultiHopError::dial_refusal`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialRefusedHop {
    /// The entry relay refused the QUIC connection outright.
    Entry,
    /// The exit refused the session with its drain close code.
    Exit,
}

/// Whether the TLS-over-TCP fallback carrier is armed for `relay`: it both
/// advertises the carrier (`tcp_fallback`) AND carries a cover domain. The
/// cover domain is the outer TLS SNI and implies X.509 mode, so without it
/// there is no carrier to dial. Gated purely on the descriptor, so an RPK relay
/// (no cover domain) is never dialed over TCP even if the flag is set, and a
/// relay that does not advertise the carrier keeps the plain UDP dial. The
/// deployer's `WARREN_ENABLE_TCP_FALLBACK` master switch is applied on top of
/// this at the call site (see `dial_relay`), keeping this a pure descriptor
/// predicate.
#[must_use]
fn carrier_armed(relay: &RelayDescriptorSigned) -> bool {
    relay.tcp_fallback && relay.cover_domain.is_some()
}

/// Trust anchors for the relay's cover-domain certificate, shared by the inner
/// QUIC WebPKI handshake (in cover mode) and the outer carrier cover-TLS.
/// `None` (production) selects the bundled Mozilla program, i.e. the
/// public-ACME cover cert a real relay presents. A `#[cfg(test)]` seam injects
/// a throwaway CA so a loopback test completes a genuine cover handshake.
#[must_use]
fn cover_trust_anchors() -> Option<Vec<Vec<u8>>> {
    #[cfg(test)]
    {
        tests::test_cover_trust_anchors()
    }
    #[cfg(not(test))]
    {
        None
    }
}

/// The `:443/tcp` cover endpoint the carrier dials: the relay's advertised IP
/// on the fixed cover HTTPS port. A `#[cfg(test)]` seam redirects it to a
/// loopback terminator, since a test cannot bind `:443`.
#[must_use]
fn carrier_cover_endpoint(relay_endpoint: SocketAddr) -> SocketAddr {
    #[cfg(test)]
    if let Some(addr) = tests::test_carrier_endpoint() {
        return addr;
    }
    SocketAddr::new(relay_endpoint.ip(), COVER_TCP_PORT)
}

/// Rekey trigger thresholds. The session rotates the HPKE context as
/// soon as either limit is hit.
///
/// The design mandates a context rotation within 8 h of session
/// lifetime to keep the AEAD key well below the NIST SP 800-38D 2^32
/// invocation ceiling and to bound the forward-secrecy exposure of a
/// long-lived recipient X25519 key. Warren defaults are
/// conservative below the spec ceiling.
#[derive(Debug, Clone, Copy)]
pub struct RekeyPolicy {
    /// Force a rekey after this many forward-direction frames in the
    /// current epoch. Defaults to 10 million, an order of magnitude
    /// below the 2^32 AEAD ceiling.
    pub max_frames: u64,
    /// Force a rekey after this much wall-clock time in the current
    /// epoch. Defaults to 30 min, well below the 8 h ceiling.
    pub max_age: Duration,
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self {
            max_frames: 10_000_000,
            max_age: Duration::from_secs(30 * 60),
        }
    }
}

/// Upper bound on a single multi-hop setup-stream message
/// (`read_to_end` cap). The setup frame is one HPKE-sealed
/// [`warrenguard_multihop::WarrenMultihopFrame`] carrying the
/// `encapsulated_key` plus a small control payload (`IpRequest` or
/// `IpAssign`), a few hundred bytes in practice. 64 KiB is generous but
/// strictly bounds the memory a hostile relay could force the receiver
/// to buffer on the setup stream.
pub const MAX_MULTIHOP_SETUP_FRAME_BYTES: usize = 64 * 1024;

/// Doctrine overlap window after a rekey during which the previous
/// epoch's `AeadCtxS` and `ReplayWindow` are retained client-side so
/// in-flight reverse-direction frames can still decrypt. Set to the
/// upper bound of the 2-5 s envelope.
const PENDING_OLD_EPOCH_TTL: Duration = Duration::from_secs(5);

/// `/v2` only: minimum spacing between resent PQ epoch-bootstrap pings while
/// the current epoch stays unacked. Frequent relative to the 5 s doctrine
/// overlap window above: a handful of retries at this cadence lands the new
/// epoch at the exit well before the overlap prunes, even against moderate
/// datagram loss, without spamming the exit on every `send_packet` call.
#[cfg(feature = "pq-hpke")]
const PQ_SETUP_PING_RESEND_INTERVAL: Duration = Duration::from_millis(200);

/// Per-epoch anti-replay tracker. The receive path picks the matching
/// instance for `frame.epoch` so a straggler from the just-closed
/// epoch is checked against its own window (and a doubled-up old
/// frame still gets rejected as a replay during the overlap).
struct EpochReplay {
    epoch: u32,
    window: ReplayWindow,
}

/// Current + optional pending replay state. The pending slot is
/// installed by [`MultiHopClient::rekey`] alongside the lib-level
/// [`ClientSession::pending_old_epoch_value`] and is cleared by
/// [`MultiHopClient::prune_pending_overlap_if_expired`] once the
/// doctrine overlap window has elapsed.
struct ReplayState {
    current: EpochReplay,
    pending: Option<EpochReplay>,
}

impl ReplayState {
    fn new() -> Self {
        Self {
            current: EpochReplay {
                epoch: 0,
                window: ReplayWindow::new(),
            },
            pending: None,
        }
    }

    /// Locate the window matching `epoch`: the current epoch's window,
    /// or the pending previous-epoch window during the rekey overlap.
    /// The `bool` flags the pending slot. `None` for any other epoch
    /// (a deeper old epoch, or a typo by a hostile relay).
    fn slot_mut(&mut self, epoch: u32) -> Option<(&mut ReplayWindow, bool)> {
        if epoch == self.current.epoch {
            return Some((&mut self.current.window, false));
        }
        match self.pending.as_mut() {
            Some(pending) if pending.epoch == epoch => Some((&mut pending.window, true)),
            _ => None,
        }
    }
}

/// Two-phase anti-replay gate around an AEAD open.
///
/// Phase 1 probes the window WITHOUT recording ([`ReplayWindow::check`]);
/// only after `open` authenticated the frame does phase 2 commit the
/// seq ([`ReplayWindow::check_and_record`]). Recording before
/// verification would let a hostile relay forge an arbitrary far-future
/// `seq` on an unauthenticated frame and slam the window past the
/// legitimate in-flight sequence numbers (cheap DoS on the downlink).
///
/// Returns the plaintext plus whether the frame matched the pending
/// (previous-epoch) window. A seq recorded by a concurrent caller
/// between the two phases - or an epoch slot pruned mid-open -
/// surfaces as [`MultiHopError::Replay`].
fn open_replay_gated<F>(
    replay: &Mutex<ReplayState>,
    epoch: u32,
    seq: u64,
    open: F,
) -> Result<(Vec<u8>, bool), MultiHopError>
where
    F: FnOnce() -> Result<Vec<u8>, MultiHopError>,
{
    {
        let mut state = replay.lock();
        let Some((window, _)) = state.slot_mut(epoch) else {
            return Err(MultiHopError::Replay { epoch, seq });
        };
        window
            .check(seq, epoch)
            .map_err(|_| MultiHopError::Replay { epoch, seq })?;
    }

    // AEAD open outside the lock: only an authenticated frame may
    // advance the window.
    let plaintext = open()?;

    let is_pending = {
        let mut state = replay.lock();
        let Some((window, is_pending)) = state.slot_mut(epoch) else {
            return Err(MultiHopError::Replay { epoch, seq });
        };
        window
            .check_and_record(seq, epoch)
            .map_err(|_| MultiHopError::Replay { epoch, seq })?;
        is_pending
    };
    Ok((plaintext, is_pending))
}

/// Maps a [`MultihopError`] from a wire-frame encode call
/// ([`encode_frame`] / [`encode_frame_v2`]) to the transport's error type.
/// Shared by the `/v1` and `/v2` branches of
/// [`MultiHopClient::seal_next_forward_frame`] so the mapping stays
/// identical regardless of frame version.
fn map_multihop_encode_err(e: MultihopError) -> MultiHopError {
    match e {
        MultihopError::Decode(p) => MultiHopError::Encode(p),
        other => MultiHopError::Session(other),
    }
}

/// Maps a [`MultihopError`] from a wire-frame decode call
/// ([`decode_frame`] / [`decode_frame_v2`]) to the transport's error type.
/// Shared by the `/v1` and `/v2` branches of
/// [`MultiHopClient::decode_and_open_reply`].
fn map_multihop_decode_err(e: MultihopError) -> MultiHopError {
    match e {
        MultihopError::Decode(p) => MultiHopError::Decode(p),
        other => MultiHopError::Session(other),
    }
}

/// The HPKE session a [`MultiHopClient`] holds: exactly one of the classical
/// `/v1` DHKEM(X25519) session or (`pq-hpke` only) the `/v2` X-Wing hybrid
/// session, picked once at construction and never mixed. The `/v2` variant
/// also carries the X-Wing recipient public key alongside the session, since
/// [`PqClientSession::rekey`] needs to re-encapsulate against it and (unlike
/// the classical recipient) it is not otherwise retained on
/// [`MultiHopClient`].
enum ClientSessionKind {
    V1(RwLock<ClientSession>),
    #[cfg(feature = "pq-hpke")]
    V2 {
        session: RwLock<PqClientSession>,
        // Boxed: `XWingRecipientPublicKey` embeds the ~1184-byte ML-KEM-768
        // encapsulation key inline, which would otherwise make every
        // `ClientSessionKind` (including a `/v1` one) pay for the largest
        // variant's stack footprint.
        recipient: Box<XWingRecipientPublicKey>,
    },
}

impl ClientSessionKind {
    fn epoch(&self) -> u32 {
        match self {
            Self::V1(s) => s.read().epoch(),
            #[cfg(feature = "pq-hpke")]
            Self::V2 { session, .. } => session.read().epoch(),
        }
    }

    fn encapsulated_key(&self) -> [u8; 32] {
        match self {
            Self::V1(s) => s.read().encapsulated_key(),
            #[cfg(feature = "pq-hpke")]
            Self::V2 { session, .. } => session.read().encapsulated_key(),
        }
    }

    fn prune_pending_old_epoch(&self) {
        match self {
            Self::V1(s) => s.write().prune_pending_old_epoch(),
            #[cfg(feature = "pq-hpke")]
            Self::V2 { session, .. } => session.write().prune_pending_old_epoch(),
        }
    }

    /// Worst-case per-frame wire overhead of a PAYLOAD-BEARING frame of this
    /// session's version, for [`MultiHopClient::max_inner_payload`]. The `/v2`
    /// bound is the DATA-frame overhead (empty `pq_ct`), not the setup-frame
    /// one: after the ML-KEM ciphertext was decoupled onto its own dedicated
    /// empty-payload bootstrap ping, no datagram ever carries both `pq_ct` and
    /// a caller payload, so reserving the 1088-byte ciphertext here would only
    /// starve the tunnel MTU by ~1 KB for a frame shape that never occurs.
    fn max_frame_overhead(&self) -> usize {
        match self {
            Self::V1(_) => MULTIHOP_FRAME_MAX_OVERHEAD,
            #[cfg(feature = "pq-hpke")]
            Self::V2 { .. } => MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD,
        }
    }

    /// Borrow the classical `/v1` session, or `None` when this is a `/v2`
    /// session. Used by the
    /// [`crate::multihop::MultiHopClient::setup_over_stream`] `IpAssignment`
    /// capture to take the `/v1`-specific re-open path
    /// ([`ClientSession::open_setup_reply`]); a `/v2` session instead parses
    /// its already-opened reply plaintext through the version-agnostic
    /// [`warrenguard_multihop::ip_assignment_from_setup_plaintext`].
    fn as_v1(&self) -> Option<&RwLock<ClientSession>> {
        match self {
            Self::V1(s) => Some(s),
            #[cfg(feature = "pq-hpke")]
            Self::V2 { .. } => None,
        }
    }
}

/// Multi-hop client tunnel.
///
/// Owns the Quinn `Endpoint` + `Connection` to the relay and an
/// [`HPKE ClientSession`](ClientSession) keyed to the destination exit.
///
/// All methods take `&self` to enable single-task interleaved
/// `select!`-style use of [`Self::send`] and [`Self::recv`]; internal
/// mutation goes through `parking_lot` locks held only across CPU work
/// (no `.await` is performed under any lock).
pub struct MultiHopClient {
    // Keep the endpoint alive for the lifetime of the connection; an
    // early drop would tear down the underlying UDP socket and break
    // all in-flight datagrams.
    endpoint: Endpoint,
    conn: Connection,
    session: ClientSessionKind,
    seq_send: AtomicU64,
    frames_in_epoch: AtomicU64,
    last_rekey: Mutex<Instant>,
    rekey_policy: RekeyPolicy,
    exit_pubkey: WarrenKemPublicKey,
    exit_id: ExitId,
    replay: Mutex<ReplayState>,
    pending_old_epoch_at: Mutex<Option<Instant>>,
    pending_old_epoch_ttl: Duration,
    metrics: MultiHopMetrics,
    /// In X.509 cover-domain mode, the directory-vouched relay pubkey to verify
    /// the in-band relay-auth proof against. `None` in RPK mode (the TLS layer
    /// pins the identity). The proof is read during the first setup exchange,
    /// after the client has sent its setup frame and before it reads the reply
    /// or sends any data; a node emits the proof only to a peer that
    /// has proven it is a Warren client, so it cannot be sent before the frame.
    relay_auth_pubkey: Option<WarrenPubkey>,
    /// The exit's IP allocation, captured as a side effect of a successful
    /// [`Self::setup_over_stream`] whose reply decodes to
    /// [`WarrenControlMessage::IpAssign`]. `None` before setup, or if the
    /// reply was a policy refusal (`Rejected` / `IpExhausted`) instead.
    assignment: Mutex<Option<IpAssignment>>,
    /// `/v2` only: whether the exit has proven (by a reverse frame observed
    /// on the current epoch) that it established this epoch's PQ session.
    /// While `false`, DATA frames seal under the RETAINED previous epoch
    /// (see [`PqClientSession::seal_pending_old_epoch`]), never the new one:
    /// the new epoch's `pq_ct` only ever rides its own dedicated small setup
    /// ping ([`Self::send_pq_setup_ping`]), so a rekey's ML-KEM ciphertext
    /// can never oversize a caller's full-size DATA frame. Reset to `false`
    /// on every rekey; explicitly set `true` right after a successful
    /// [`Self::setup_over_stream`] (epoch 0's setup rides the reliable
    /// stream, so it counts as acked immediately) and by
    /// [`Self::decode_and_open_reply`] once a reverse frame proves the exit
    /// decapsulated the current epoch.
    #[cfg(feature = "pq-hpke")]
    pq_setup_acked: AtomicBool,
    /// `/v2` only: when [`Self::send_pq_setup_ping`] last fired, so
    /// [`Self::maybe_resend_pq_setup_ping`] can rate-limit the resend to
    /// [`PQ_SETUP_PING_RESEND_INTERVAL`] instead of re-pinging on every
    /// `send_packet` call while unacked.
    #[cfg(feature = "pq-hpke")]
    pq_setup_ping_last_sent: Mutex<Option<Instant>>,
}

/// Atomic counters that aggregate per-session activity. Mutation paths
/// touch only `Relaxed` ordering: counters are advisory observability
/// data, not control-flow signals.
#[derive(Debug, Default)]
pub struct MultiHopMetrics {
    frames_sent: AtomicU64,
    frames_recv: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    rekey_count: AtomicU64,
    replay_rejects: AtomicU64,
    decode_errors: AtomicU64,
    unexpected_exit_id: AtomicU64,
    decode_fallback_to_old_epoch: AtomicU64,
    /// `/v2` only: dedicated epoch-bootstrap pings sent (the initial one on
    /// [`crate::multihop::MultiHopClient::rekey`] plus every rate-limited
    /// resend while the epoch stays unacked). Bounded by the datagram loss
    /// rate on the path; a runaway counter means the exit is not seeing the
    /// rekey's `pq_ct` at all (worth investigating).
    #[cfg(feature = "pq-hpke")]
    pq_setup_resends: AtomicU64,
}

/// Snapshot of [`MultiHopMetrics`] for a single point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MultiHopMetricsSnapshot {
    /// Forward-direction frames sealed and emitted.
    pub frames_sent: u64,
    /// Reverse-direction frames decoded and opened.
    pub frames_recv: u64,
    /// Plaintext bytes sent (before HPKE seal).
    pub bytes_sent: u64,
    /// Plaintext bytes received (after HPKE open).
    pub bytes_recv: u64,
    /// Number of completed rekey rotations.
    pub rekey_count: u64,
    /// Datagrams rejected by the anti-replay window.
    pub replay_rejects: u64,
    /// Datagrams rejected by the wire-format decoder.
    pub decode_errors: u64,
    /// Datagrams whose `exit_id` did not match the active session.
    pub unexpected_exit_id: u64,
    /// Reverse-direction frames whose `epoch` fell into the
    /// [doctrine 5 s overlap window](`crate::multi_hop`) and were
    /// successfully decrypted using the cached previous-epoch
    /// `AeadCtxS`. A non-zero counter is normal under sustained
    /// rekeys; a runaway counter (>> rekey_count) would indicate the
    /// exit side is leaking large bursts of old-epoch reverse frames,
    /// which is worth investigating.
    pub decode_fallback_to_old_epoch: u64,
    /// `/v2` only (always `0` on a `/v1` session): dedicated epoch-bootstrap
    /// pings sent while the latest rekey was not yet acked by the exit.
    #[cfg(feature = "pq-hpke")]
    pub pq_setup_resends: u64,
}

impl MultiHopMetrics {
    fn snapshot(&self) -> MultiHopMetricsSnapshot {
        MultiHopMetricsSnapshot {
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_recv: self.frames_recv.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            rekey_count: self.rekey_count.load(Ordering::Relaxed),
            replay_rejects: self.replay_rejects.load(Ordering::Relaxed),
            decode_errors: self.decode_errors.load(Ordering::Relaxed),
            unexpected_exit_id: self.unexpected_exit_id.load(Ordering::Relaxed),
            decode_fallback_to_old_epoch: self.decode_fallback_to_old_epoch.load(Ordering::Relaxed),
            #[cfg(feature = "pq-hpke")]
            pq_setup_resends: self.pq_setup_resends.load(Ordering::Relaxed),
        }
    }
}

impl MultiHopClient {
    /// Verify the relay descriptor, dial the relay over QUIC, and set up
    /// an HPKE session for the destination exit.
    ///
    /// The Quinn transport config applied to the dial is
    /// [`warren_transport_config_client_multihop_with_gso`] (BBR +
    /// MTU 1350 + DPLPMTUD + 1 Gbps × 50 ms BDP windows + spin bit
    /// off + GSO), **without** the Initial-padding knobs.
    /// This profile keeps loopback tests fast (no `initial_datagram_min_size`
    /// vs server-side mirror handshake stall) while
    /// still restoring the path-MTU regression that occurred at
    /// payload >= 1000 B.
    ///
    /// Production binaries (the bench probe on real servers, a
    /// product client's multi-hop wiring) call
    /// [`MultiHopClient::connect_with_warren_obfuscation`] instead to
    /// opt into the full Warren wire-mimicry profile.
    ///
    /// # Errors
    ///
    /// See [`MultiHopError`]. The relay PKI check runs *before* any UDP
    /// traffic is emitted, so a tampered descriptor cannot push the
    /// dial to an attacker-chosen endpoint.
    // The dial parameters (relay, exit id + key, op key, client key, bind, GSO,
    // socket bypass) are all independent inputs threaded straight to the socket
    // bind; grouping them into a struct would only add indirection.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        relay: &RelayDescriptorSigned,
        exit_id: ExitId,
        exit_x25519_multihop_pubkey: &[u8; 32],
        operational_pubkey: &VerifyingKey,
        client_signing_key: &SigningKey,
        bind_addr: SocketAddr,
        enable_gso: bool,
        socket_bypass: Option<SocketBypass>,
    ) -> Result<Self, MultiHopError> {
        Self::connect_with_transport_config(
            relay,
            exit_id,
            exit_x25519_multihop_pubkey,
            operational_pubkey,
            client_signing_key,
            bind_addr,
            warren_transport_config_client_multihop_with_gso(enable_gso),
            socket_bypass,
        )
        .await
    }

    /// Variant of [`Self::connect`] that opts into the full Warren
    /// wire-mimicry profile
    /// ([`warren_transport_config_client_with_gso`]): identical to the
    /// default plus `initial_crypto_first_fragment_size(Some(64))` and
    /// `initial_datagram_min_size(1500)`. These split the TLS ClientHello
    /// across two padded Initial UDP datagrams so a passive observer
    /// cannot reconstruct the SNI from a single datagram (GFW SNI
    /// extractor, USENIX Security 2025).
    ///
    /// **Caveat**: this profile stalls the handshake against
    /// a relay-inbound peer that does not pre-negotiate the matching
    /// transport parameter. [`warrenguard_transport_core::warren_transport_config_relay_inbound`]
    /// deliberately does *not* mirror these knobs (server-side cap
    /// would break ServerHello). Use only against a real relay
    /// deployment; loopback tests must call [`Self::connect`].
    ///
    /// # Errors
    ///
    /// See [`Self::connect`].
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_warren_obfuscation(
        relay: &RelayDescriptorSigned,
        exit_id: ExitId,
        exit_x25519_multihop_pubkey: &[u8; 32],
        operational_pubkey: &VerifyingKey,
        client_signing_key: &SigningKey,
        bind_addr: SocketAddr,
        enable_gso: bool,
        socket_bypass: Option<SocketBypass>,
    ) -> Result<Self, MultiHopError> {
        Self::connect_with_transport_config(
            relay,
            exit_id,
            exit_x25519_multihop_pubkey,
            operational_pubkey,
            client_signing_key,
            bind_addr,
            warren_transport_config_client_with_gso(enable_gso),
            socket_bypass,
        )
        .await
    }

    /// PQ (`/v2` X-Wing) twin of [`Self::connect_with_warren_obfuscation`].
    ///
    /// Builds the identical obfuscated client transport config
    /// ([`warren_transport_config_client_with_gso`]) so the QUIC/TLS
    /// fingerprint is unchanged, then dials the PQ hybrid HPKE session.
    /// `mlkem768_ek` and `require_pq` carry the same meaning as in
    /// [`Self::connect_with_transport_config_pq`]: `require_pq` fails closed
    /// on a bad ML-KEM key, otherwise falls back to the classical `/v1`
    /// session over the same `exit_x25519_multihop_pubkey`.
    ///
    /// # Errors
    ///
    /// See [`Self::connect_with_transport_config_pq`].
    #[cfg(feature = "pq-hpke")]
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_warren_obfuscation_pq(
        relay: &RelayDescriptorSigned,
        exit_id: ExitId,
        exit_x25519_multihop_pubkey: &[u8; 32],
        mlkem768_ek: &[u8],
        require_pq: bool,
        operational_pubkey: &VerifyingKey,
        client_signing_key: &SigningKey,
        bind_addr: SocketAddr,
        enable_gso: bool,
        socket_bypass: Option<SocketBypass>,
    ) -> Result<Self, MultiHopError> {
        Self::connect_with_transport_config_pq(
            relay,
            exit_id,
            exit_x25519_multihop_pubkey,
            mlkem768_ek,
            require_pq,
            operational_pubkey,
            client_signing_key,
            bind_addr,
            warren_transport_config_client_with_gso(enable_gso),
            socket_bypass,
        )
        .await
    }

    /// Bench-internal expert API. Promoted to `pub` for the
    /// multi-hop bench profiling probe so it can
    /// dial with an ad-hoc [`TransportConfig`] (alternate congestion
    /// controller for H3 BBR vs Cubic comparison, alternate
    /// `initial_mtu`, etc.) without going through the two stable
    /// presets ([`Self::connect`] / [`Self::connect_with_warren_obfuscation`]).
    /// Production client code paths must call one of the stable
    /// presets.
    ///
    /// # Errors
    ///
    /// Same as [`Self::connect`].
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_transport_config(
        relay: &RelayDescriptorSigned,
        exit_id: ExitId,
        exit_x25519_multihop_pubkey: &[u8; 32],
        operational_pubkey: &VerifyingKey,
        // v5: the relay->exit dial is anonymous at the TLS layer (the exit
        // requests no client cert); the client identity is proven in-band via
        // the multi-hop PoP, not here. Kept in the signature for API
        // stability; intentionally unused by the dial.
        _client_signing_key: &SigningKey,
        bind_addr: SocketAddr,
        transport_config: Arc<TransportConfig>,
        // When `Some`, the freshly bound UDP socket is marked/bound to the
        // physical link before its first send (Port Fail fix). `None` keeps the
        // verbatim client bind (userland proxy, or Android which uses `protect`).
        socket_bypass: Option<SocketBypass>,
    ) -> Result<Self, MultiHopError> {
        // Validated again (and turned into the HPKE session) inside
        // `from_established_connection` below; parsed here too so a malformed
        // key fails before any UDP traffic is emitted, matching the relay-PKI
        // check inside `dial_relay`.
        let _ = parse_exit_x25519_pubkey(exit_x25519_multihop_pubkey)?;
        let (endpoint, conn, relay_auth_pubkey) = Self::dial_relay(
            relay,
            operational_pubkey,
            bind_addr,
            transport_config,
            socket_bypass,
        )
        .await?;
        tracing::info!("multi-hop session established");
        Self::from_established_connection(
            endpoint,
            conn,
            exit_id,
            exit_x25519_multihop_pubkey,
            relay_auth_pubkey,
        )
    }

    /// PQ (`/v2` X-Wing) twin of [`Self::connect_with_transport_config`].
    ///
    /// `mlkem768_ek` is the exit's raw ML-KEM-768 encapsulation key material
    /// (`warrenguard_multihop::MLKEM768_ENCAPS_KEY_LEN` bytes) read from its
    /// PQ-signed descriptor, typically via
    /// [`warrenguard_multihop::negotiate_pq`]. `require_pq` decides the
    /// failure mode when `mlkem768_ek` does not parse: `true` fails closed
    /// (anti-downgrade); `false` falls back to the classical `/v1` session
    /// over the same `exit_x25519_multihop_pubkey`. See
    /// [`Self::from_established_connection_pq`] for the exact rule.
    ///
    /// # Errors
    ///
    /// Same as [`Self::connect_with_transport_config`], plus
    /// [`MultiHopError::Session`] wrapping the ML-KEM key-length failure
    /// when `require_pq` is set.
    #[cfg(feature = "pq-hpke")]
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_transport_config_pq(
        relay: &RelayDescriptorSigned,
        exit_id: ExitId,
        exit_x25519_multihop_pubkey: &[u8; 32],
        mlkem768_ek: &[u8],
        require_pq: bool,
        operational_pubkey: &VerifyingKey,
        _client_signing_key: &SigningKey,
        bind_addr: SocketAddr,
        transport_config: Arc<TransportConfig>,
        socket_bypass: Option<SocketBypass>,
    ) -> Result<Self, MultiHopError> {
        let _ = parse_exit_x25519_pubkey(exit_x25519_multihop_pubkey)?;
        let (endpoint, conn, relay_auth_pubkey) = Self::dial_relay(
            relay,
            operational_pubkey,
            bind_addr,
            transport_config,
            socket_bypass,
        )
        .await?;
        tracing::info!("multi-hop session established");
        Self::from_established_connection_pq(
            endpoint,
            conn,
            exit_id,
            exit_x25519_multihop_pubkey,
            mlkem768_ek,
            require_pq,
            relay_auth_pubkey,
        )
    }

    /// Verify the relay descriptor and dial the relay over QUIC. Shared by
    /// [`Self::connect_with_transport_config`] and its PQ twin
    /// [`Self::connect_with_transport_config_pq`]: the two only differ in
    /// which HPKE session they build over the resulting connection.
    ///
    /// # Errors
    ///
    /// [`MultiHopError::RelayPki`], [`MultiHopError::Tls`],
    /// [`MultiHopError::Bind`], [`MultiHopError::Connect`], or
    /// [`MultiHopError::Handshake`].
    async fn dial_relay(
        relay: &RelayDescriptorSigned,
        operational_pubkey: &VerifyingKey,
        bind_addr: SocketAddr,
        transport_config: Arc<TransportConfig>,
        // When `Some`, the freshly bound UDP socket is marked/bound to the
        // physical link before its first send (Port Fail fix). `None` keeps the
        // verbatim client bind (userland proxy, or Android which uses `protect`).
        socket_bypass: Option<SocketBypass>,
    ) -> Result<(Endpoint, Connection, Option<WarrenPubkey>), MultiHopError> {
        // On Android the socket is protected by `VpnService.protect` (below), not
        // a setsockopt, so any desktop bypass value is irrelevant there.
        #[cfg(target_os = "android")]
        let _ = socket_bypass;
        verify_relay_descriptor(operational_pubkey, relay)?;

        // In X.509 cover-domain mode the relay presents an ordinary
        // public-CA certificate the client validates via WebPKI (Mozilla roots),
        // dialing the cover domain as the SNI. The relay's Warren identity is
        // then confirmed in-band (see `verify_relay_proof`) instead of by
        // pinning the RFC 7250 raw public key in the SNI. With no cover_domain
        // the historical RPK path is kept verbatim.
        let mut client_cfg = if relay.cover_domain.is_some() {
            // Production trusts the Mozilla program (the relay presents a
            // public-ACME cover cert); a `#[cfg(test)]` seam swaps in a
            // throwaway CA so a loopback carrier handshake can validate.
            // Behaviour-neutral in production: the seam yields `None`, i.e. the
            // bundled Mozilla roots, exactly as before.
            let roots = match cover_trust_anchors() {
                Some(ders) => warrenguard_tls::root_store_from_der(&ders).0,
                None => mozilla_root_store(),
            };
            make_client_config_webpki(roots, default_crypto_provider(), &[ALPN_H3])?
        } else {
            make_client_config(default_crypto_provider(), &[ALPN_H3])?
        };
        client_cfg.transport_config(transport_config);
        // Clone the inner QUIC config for the carrier BEFORE the UDP endpoint
        // consumes it via `set_default_client_config`: the carrier dials the
        // relay with the IDENTICAL config so the TCP path is byte-for-byte the
        // UDP session (same X.509 identity check, transport params). Only when
        // armed (`quinn::ClientConfig: Clone`) AND the deployer has not disabled
        // the carrier via `WARREN_ENABLE_TCP_FALLBACK` (fail-closed: a disabled
        // carrier keeps the plain UDP dial and never opens :443/tcp).
        let carrier_client_cfg = (carrier_armed(relay)
            && warrenguard_config::knobs::tcp_fallback_enabled())
        .then(|| client_cfg.clone());

        // On Android the endpoint socket must be protected (routed onto the
        // underlying physical network) BEFORE it sends anything, or the VPN
        // routes loop the QUIC handshake back into the TUN. We bind the socket
        // ourselves so we can `VpnService.protect` its fd, then hand it to
        // quinn. On every other platform `Endpoint::client` (bind +
        // `Endpoint::new`) is kept verbatim.
        #[cfg(target_os = "android")]
        let mut endpoint = {
            use std::os::fd::AsRawFd;
            let socket =
                std::net::UdpSocket::bind(bind_addr).map_err(|source| MultiHopError::Bind {
                    addr: bind_addr,
                    source,
                })?;
            if !crate::socket_protect::protect(socket.as_raw_fd()) {
                return Err(MultiHopError::Bind {
                    addr: bind_addr,
                    source: std::io::Error::other(
                        "VpnService.protect rejected the multi-hop tunnel socket",
                    ),
                });
            }
            let runtime = quinn::default_runtime().ok_or_else(|| MultiHopError::Bind {
                addr: bind_addr,
                source: std::io::Error::other("no async runtime for quinn endpoint"),
            })?;
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime).map_err(
                |source| MultiHopError::Bind {
                    addr: bind_addr,
                    source,
                },
            )?
        };
        // Desktop: when a system-VPN datapath is active it passes a
        // `socket_bypass`, so we bind our own socket, mark/bind it to the
        // physical link (`SO_MARK` / `IP_BOUND_IF` / `IP_UNICAST_IF`) BEFORE
        // quinn sends anything, then hand it to quinn. This lets the datapath
        // drop the `<exit_ip>/32` host route (Port Fail / TunnelCrack ServerIP
        // fix). Fail-closed: a socket whose bypass cannot be set must not egress.
        // With no bypass (userland proxy), `Endpoint::client` is kept verbatim.
        #[cfg(not(target_os = "android"))]
        let mut endpoint = match socket_bypass {
            Some(bypass) => {
                let socket =
                    std::net::UdpSocket::bind(bind_addr).map_err(|source| MultiHopError::Bind {
                        addr: bind_addr,
                        source,
                    })?;
                warrenguard_socket_bypass::apply(&socket, bypass).map_err(|source| {
                    MultiHopError::Bind {
                        addr: bind_addr,
                        source,
                    }
                })?;
                let runtime = quinn::default_runtime().ok_or_else(|| MultiHopError::Bind {
                    addr: bind_addr,
                    source: std::io::Error::other("no async runtime for quinn endpoint"),
                })?;
                quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
                    .map_err(|source| MultiHopError::Bind {
                        addr: bind_addr,
                        source,
                    })?
            }
            None => Endpoint::client(bind_addr).map_err(|source| MultiHopError::Bind {
                addr: bind_addr,
                source,
            })?,
        };
        endpoint.set_default_client_config(client_cfg);

        let relay_pubkey = WarrenPubkey::from_bytes(relay.relay_ed25519_pubkey);
        let server_name = match &relay.cover_domain {
            Some(domain) => domain.clone(),
            None => warrenguard_tls::name::encode(relay_pubkey),
        };
        // When the carrier is armed, race the UDP dial against the TLS-over-TCP
        // carrier so a UDP-hostile network still connects; otherwise keep the
        // plain UDP dial verbatim (behaviour-neutral for every RPK / non-carrier
        // relay). The winning path's endpoint is carried out and kept alive for
        // the connection.
        let (endpoint, conn) = match carrier_client_cfg {
            Some(inner_cfg) => {
                Self::dial_relay_with_carrier(
                    relay,
                    endpoint,
                    &server_name,
                    inner_cfg,
                    socket_bypass,
                )
                .await?
            }
            None => {
                let conn = endpoint
                    .connect(relay.endpoint, &server_name)?
                    .await
                    .map_err(MultiHopError::Handshake)?;
                (endpoint, conn)
            }
        };

        // In X.509 cover-domain mode the relay proves its
        // directory-vouched Ed25519 identity in-band, but it emits that proof
        // only to a peer that has shown it is a Warren client (it sent a setup
        // frame) - so a censor probing the cover domain never sees a
        // Warren-specific stream. We therefore defer the proof verification to
        // the first setup exchange (`setup_over_stream`), right after the setup
        // frame is written and before the reply is read or any data is sent.
        // RPK mode pins the identity at the TLS layer and needs no in-band proof.
        let relay_auth_pubkey = relay.cover_domain.is_some().then_some(relay_pubkey);

        Ok((endpoint, conn, relay_auth_pubkey))
    }

    /// Races the relay's UDP QUIC dial (on the already-bound `endpoint`)
    /// against the TLS-over-TCP fallback carrier. The carrier is dialed ONLY
    /// after the UDP handshake fails or times out (see
    /// [`warrenguard_tcp_fallback::connect_with_fallback`]); on a working UDP
    /// network it is never touched. The winner's endpoint is returned and MUST
    /// be kept alive for the connection. The carrier dials the relay's inner
    /// QUIC with the identical `inner_cfg` and `server_name` and a synthetic
    /// peer equal to the UDP target, so the QUIC state machine and X.509
    /// identity check are unchanged: the carrier only swaps the socket
    /// underneath.
    ///
    /// # Errors
    /// [`MultiHopError::TcpFallback`] when the UDP handshake failed and the
    /// armed carrier also failed (cover-config build, cover-domain TLS
    /// handshake, or the carrier's inner QUIC handshake). No address or
    /// identity material is rendered.
    async fn dial_relay_with_carrier(
        relay: &RelayDescriptorSigned,
        endpoint: Endpoint,
        server_name: &str,
        inner_cfg: quinn::ClientConfig,
        // Same bypass as the UDP endpoint: when `Some`, the carrier's TCP socket
        // is pinned to the physical link before connect (system-VPN Port Fail
        // fix); `None` keeps the plain connect (userland proxy).
        socket_bypass: Option<SocketBypass>,
    ) -> Result<(Endpoint, Connection), MultiHopError> {
        // The synthetic quinn peer and both dials target the relay's advertised
        // QUIC endpoint; only the socket beneath differs between the arms.
        let target = relay.endpoint;
        // `carrier_armed` guaranteed a cover domain; an empty SNI would only
        // fail the TLS name parse (an honest error), never panic.
        let cover_domain = relay.cover_domain.as_deref().unwrap_or_default().to_owned();
        // Production trusts the Mozilla program; a `#[cfg(test)]` seam injects a
        // throwaway CA. A build failure disarms the carrier, surfaced only if
        // UDP also fails (below).
        let cover_config =
            build_cover_client_config(cover_trust_anchors().as_deref()).map_err(|_| {
                MultiHopError::TcpFallback(std::io::Error::other(
                    "cover TLS client config build failed",
                ))
            })?;
        let carrier_endpoint = carrier_cover_endpoint(target);

        // The UDP error is only surfaced by the engine when the fallback is
        // disabled, which cannot happen on this (armed) path, so it is mapped
        // to an opaque io::Error (no address, no-log) purely to satisfy the
        // race's shared Result type.
        let udp = async {
            let conn = endpoint
                .connect(target, server_name)
                .map_err(|_| std::io::Error::other("udp quic connect setup failed"))?
                .await
                .map_err(|_| std::io::Error::other("udp quic handshake failed"))?;
            Ok::<(Endpoint, Connection), std::io::Error>((endpoint, conn))
        };
        let tcp = || async move {
            // Under a full-tunnel system VPN the carrier's TCP socket must be
            // pinned to the physical link (like the UDP endpoint), or it loops
            // into the TUN. With no bypass (userland proxy) this is the plain
            // connect, verbatim.
            let tcp = connect_tcp_carrier(carrier_endpoint, socket_bypass).await?;
            let stream = connect_cover_tls(&cover_domain, tcp, cover_config)
                .await
                .map_err(|_| std::io::Error::other("cover-domain tls handshake failed"))?;
            // The synthetic quinn peer MUST equal the connect target so quinn
            // routes the carrier's inbound datagrams to this connection's path.
            let socket = TcpCarrierSocket::new(stream, target);
            let carrier_ep = build_carrier_client_endpoint(socket, inner_cfg)
                .map_err(|_| std::io::Error::other("carrier quic endpoint build failed"))?;
            let conn = carrier_ep
                .connect(target, server_name)
                .map_err(|_| std::io::Error::other("carrier quic connect setup failed"))?
                .await
                .map_err(|_| std::io::Error::other("carrier quic handshake failed"))?;
            Ok::<(Endpoint, Connection), std::io::Error>((carrier_ep, conn))
        };

        // Armed (this path is only reached when the carrier is armed): race the
        // UDP handshake against the TCP carrier, with the parallel-dial head
        // start taken from `WARREN_TCP_FALLBACK_RACE_MS`. A UDP-hostile network
        // then connects in ~race-delay + one TCP RTT instead of stalling out the
        // full UDP deadline first.
        let policy = FallbackPolicy {
            tcp_race_delay: warrenguard_config::knobs::tcp_fallback_race_delay(),
            ..FallbackPolicy::enabled()
        };
        connect_with_fallback(&policy, udp, tcp)
            .await
            .map_err(|source| MultiHopError::TcpFallback(std::io::Error::other(source)))
    }

    /// Build a client session directly on top of an already-established QUIC
    /// connection to the destination peer, skipping the relay-descriptor
    /// verification and dial performed by [`Self::connect`] /
    /// [`Self::connect_with_transport_config`].
    ///
    /// For callers that authenticate the dialed peer through a different
    /// channel (e.g. a separately signed exit directory) and already hold a
    /// live QUIC connection to it. `relay_auth_pubkey` mirrors the field
    /// [`Self::connect`] derives in X.509 cover-domain mode:
    /// `Some` makes [`Self::setup_over_stream`] verify the peer's in-band
    /// identity proof before reading the setup reply; `None` (RPK mode)
    /// skips it.
    ///
    /// # Errors
    ///
    /// [`MultiHopError::Session`] if building the HPKE session against
    /// `exit_x25519_multihop_pubkey` fails (malformed key or ephemeral KEM
    /// failure).
    pub fn from_established_connection(
        endpoint: Endpoint,
        conn: Connection,
        exit_id: ExitId,
        exit_x25519_multihop_pubkey: &[u8; 32],
        relay_auth_pubkey: Option<WarrenPubkey>,
    ) -> Result<Self, MultiHopError> {
        let exit_pubkey = parse_exit_x25519_pubkey(exit_x25519_multihop_pubkey)?;
        let session = ClientSession::new(
            &exit_pubkey,
            exit_id,
            &mut rand_core::UnwrapErr(rand_core::OsRng),
        )?;
        Ok(Self {
            endpoint,
            conn,
            session: ClientSessionKind::V1(RwLock::new(session)),
            seq_send: AtomicU64::new(0),
            frames_in_epoch: AtomicU64::new(0),
            last_rekey: Mutex::new(Instant::now()),
            rekey_policy: RekeyPolicy::default(),
            exit_pubkey,
            exit_id,
            replay: Mutex::new(ReplayState::new()),
            pending_old_epoch_at: Mutex::new(None),
            pending_old_epoch_ttl: PENDING_OLD_EPOCH_TTL,
            metrics: MultiHopMetrics::default(),
            relay_auth_pubkey,
            assignment: Mutex::new(None),
            #[cfg(feature = "pq-hpke")]
            pq_setup_acked: AtomicBool::new(false),
            #[cfg(feature = "pq-hpke")]
            pq_setup_ping_last_sent: Mutex::new(None),
        })
    }

    /// PQ (`/v2` X-Wing) twin of [`Self::from_established_connection`].
    ///
    /// `mlkem768_ek` is the exit's raw ML-KEM-768 encapsulation key material;
    /// `exit_x25519_multihop_pubkey` doubles as the X-Wing recipient's X25519
    /// half (the same key `/v1` uses as its HPKE recipient). Building the
    /// X-Wing recipient from `mlkem768_ek` can fail (wrong length, or an
    /// empty slice for an exit with no PQ key at all):
    /// - `require_pq == true` propagates that failure (anti-downgrade:
    ///   falling back silently would let a middlebox strip PQ from a client
    ///   that demanded it).
    /// - `require_pq == false` falls back to the classical `/v1` session
    ///   over `exit_x25519_multihop_pubkey`, exactly as
    ///   [`Self::from_established_connection`] would have built it.
    ///
    /// # Errors
    ///
    /// [`MultiHopError::Session`] if `require_pq` and `mlkem768_ek` fails to
    /// parse, or if building the selected HPKE session fails.
    #[cfg(feature = "pq-hpke")]
    pub fn from_established_connection_pq(
        endpoint: Endpoint,
        conn: Connection,
        exit_id: ExitId,
        exit_x25519_multihop_pubkey: &[u8; 32],
        mlkem768_ek: &[u8],
        require_pq: bool,
        relay_auth_pubkey: Option<WarrenPubkey>,
    ) -> Result<Self, MultiHopError> {
        match XWingRecipientPublicKey::from_descriptor_bytes(
            mlkem768_ek,
            exit_x25519_multihop_pubkey,
        ) {
            Ok(recipient) => Self::from_established_connection_v2(
                endpoint,
                conn,
                exit_id,
                recipient,
                relay_auth_pubkey,
            ),
            Err(e) if require_pq => Err(MultiHopError::Session(e)),
            Err(_) => Self::from_established_connection(
                endpoint,
                conn,
                exit_id,
                exit_x25519_multihop_pubkey,
                relay_auth_pubkey,
            ),
        }
    }

    /// Builds a `/v2` session over an already-negotiated
    /// [`XWingRecipientPublicKey`]. Split out of
    /// [`Self::from_established_connection_pq`] so the anti-downgrade
    /// decision (propagate vs. fall back to `/v1`) stays a single small
    /// `match`.
    #[cfg(feature = "pq-hpke")]
    fn from_established_connection_v2(
        endpoint: Endpoint,
        conn: Connection,
        exit_id: ExitId,
        recipient: XWingRecipientPublicKey,
        relay_auth_pubkey: Option<WarrenPubkey>,
    ) -> Result<Self, MultiHopError> {
        // The X-Wing recipient's X25519 half doubles as the classical
        // `exit_pubkey` field: it is never used for a `/v2` session's own
        // crypto (rekey re-encapsulates against `recipient` instead), but
        // keeping the field populated avoids making it `Option` just for
        // this branch.
        let exit_pubkey_bytes = *recipient.x25519_pubkey();
        let exit_pubkey = parse_exit_x25519_pubkey(&exit_pubkey_bytes)?;
        let pq_session = PqClientSession::new(
            &recipient,
            exit_id,
            &mut rand_core::UnwrapErr(rand_core::OsRng),
        )?;
        Ok(Self {
            endpoint,
            conn,
            session: ClientSessionKind::V2 {
                session: RwLock::new(pq_session),
                recipient: Box::new(recipient),
            },
            seq_send: AtomicU64::new(0),
            frames_in_epoch: AtomicU64::new(0),
            last_rekey: Mutex::new(Instant::now()),
            rekey_policy: RekeyPolicy::default(),
            exit_pubkey,
            exit_id,
            replay: Mutex::new(ReplayState::new()),
            pending_old_epoch_at: Mutex::new(None),
            pending_old_epoch_ttl: PENDING_OLD_EPOCH_TTL,
            metrics: MultiHopMetrics::default(),
            relay_auth_pubkey,
            assignment: Mutex::new(None),
            pq_setup_acked: AtomicBool::new(false),
            pq_setup_ping_last_sent: Mutex::new(None),
        })
    }

    /// Reads and verifies the entry relay's in-band identity proof,
    /// which the relay sends on a SERVER-initiated bi stream once the client has
    /// proven it is a Warren client (by sending its setup frame) in X.509
    /// cover-domain mode - never to a bare prober, which the relay diverts to a
    /// decoy instead. The
    /// proof is `RELAY_AUTH_PROOF_VERSION || sig`, where `sig` is the relay's
    /// Ed25519 signature over this connection's channel binding. We verify it
    /// against `expected_relay_pubkey` (the pubkey from the signed descriptor
    /// the client chose to dial), so a man-in-the-middle that completed the
    /// WebPKI handshake with only a valid cover-domain certificate (e.g. the
    /// shared wildcard key) is rejected. Fails closed on a missing, malformed,
    /// or mis-signed proof.
    async fn verify_relay_proof(
        conn: &Connection,
        expected_relay_pubkey: &WarrenPubkey,
    ) -> Result<(), MultiHopError> {
        Self::verify_relay_proof_with_timeout(conn, expected_relay_pubkey, RELAY_PROOF_TIMEOUT)
            .await
    }

    /// [`Self::verify_relay_proof`] with an injectable timeout. Split out
    /// so a test exercising the "relay never answers" path can use a
    /// timeout in the tens of milliseconds instead of paying the real
    /// [`RELAY_PROOF_TIMEOUT`] (5 s) in wall-clock time; production always
    /// goes through [`Self::verify_relay_proof`], which pins the real
    /// constant.
    async fn verify_relay_proof_with_timeout(
        conn: &Connection,
        expected_relay_pubkey: &WarrenPubkey,
        timeout: Duration,
    ) -> Result<(), MultiHopError> {
        let cb = channel_binding(conn)?;
        // INVARIANT: the relay-auth proof is the ONLY server-initiated bi stream
        // the node ever opens (see the exit side's `send_relay_auth_proof`), so
        // accepting the first one and treating it as the proof is unambiguous.
        // The relay opens a SERVER-initiated bi stream carrying the proof; we
        // accept it. A bi stream (not a server-initiated uni stream) is used
        // because the multi-hop client profile advertises zero peer-initiated
        // uni streams; the bidi limit is non-zero, so this needs no
        // transport-config change and gives reliable delivery. The relay opens
        // (rather than the client) so the same emit path is safe on the unified
        // dispatcher's relay->exit C2 connections, whose dialer just never
        // accepts the stream. We read the proof from the recv half.
        let (mut send, mut recv) = tokio::time::timeout(timeout, conn.accept_bi())
            .await
            .map_err(|_| MultiHopError::RelayIdentity("timed out awaiting relay-auth stream"))?
            .map_err(|_| MultiHopError::RelayIdentity("relay opened no auth stream"))?;
        let _ = send.finish();
        let bytes = tokio::time::timeout(timeout, recv.read_to_end(RELAY_AUTH_PROOF_LEN))
            .await
            .map_err(|_| MultiHopError::RelayIdentity("timed out reading relay-auth proof"))?
            .map_err(|_| MultiHopError::RelayIdentity("short or oversized relay-auth proof"))?;
        let sig = decode_relay_auth_proof(&bytes)
            .map_err(|_| MultiHopError::RelayIdentity("malformed relay-auth proof"))?;
        if !verify_relay_auth(expected_relay_pubkey, &cb, &sig) {
            conn.close(quinn::VarInt::from_u32(0), b"relay identity proof failed");
            return Err(MultiHopError::RelayIdentity(
                "relay-auth signature does not match the descriptor pubkey",
            ));
        }
        Ok(())
    }

    /// Retry-wrapped variant of [`Self::connect`] /
    /// [`Self::connect_with_warren_obfuscation`] that survives a
    /// cold-start backbone blip on the first hop (observed in a
    /// sustained 30 min cross-DC bench run; see also
    /// the [`warrenguard_backoff`] crate doctrine).
    ///
    /// Each retriable failure
    /// ([`MultiHopError::is_retriable`] returns `true`) consumes one of
    /// the `max_attempts` slots from `backoff.take(max_attempts)` and
    /// sleeps the yielded jittered delay before the next dial. The
    /// first yielded delay is always [`std::time::Duration::ZERO`] so
    /// the first attempt fires immediately.
    ///
    /// Non-retriable errors (TLS config, PKI mismatch) propagate out on
    /// the first occurrence without burning the remaining slots.
    ///
    /// `use_warren_obfuscation` picks the underlying dial path:
    /// `true` -> [`Self::connect_with_warren_obfuscation`] (Warren wire
    /// mimicry), `false` -> [`Self::connect`] (multi-hop
    /// profile without the Initial padding).
    ///
    /// # Errors
    ///
    /// - The first non-retriable [`MultiHopError`] observed, or
    /// - the last retriable [`MultiHopError`] after exhausting
    ///   `max_attempts`.
    /// - When `max_attempts == 0`, returns a synthetic
    ///   [`MultiHopError::Handshake`] wrapping
    ///   [`quinn::ConnectionError::TimedOut`] so a caller does not silently
    ///   skip the dial.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_retry(
        relay: &RelayDescriptorSigned,
        exit_id: ExitId,
        exit_x25519_multihop_pubkey: &[u8; 32],
        operational_pubkey: &VerifyingKey,
        client_signing_key: &SigningKey,
        bind_addr: SocketAddr,
        enable_gso: bool,
        use_warren_obfuscation: bool,
        socket_bypass: Option<SocketBypass>,
        backoff: Backoff,
        max_attempts: usize,
    ) -> Result<Self, MultiHopError> {
        if max_attempts == 0 {
            return Err(MultiHopError::Handshake(quinn::ConnectionError::TimedOut));
        }
        let mut last_err: Option<MultiHopError> = None;
        for delay in backoff.take(max_attempts) {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let attempt = if use_warren_obfuscation {
                Self::connect_with_warren_obfuscation(
                    relay,
                    exit_id,
                    exit_x25519_multihop_pubkey,
                    operational_pubkey,
                    client_signing_key,
                    bind_addr,
                    enable_gso,
                    socket_bypass,
                )
                .await
            } else {
                Self::connect(
                    relay,
                    exit_id,
                    exit_x25519_multihop_pubkey,
                    operational_pubkey,
                    client_signing_key,
                    bind_addr,
                    enable_gso,
                    socket_bypass,
                )
                .await
            };
            match attempt {
                Ok(c) => return Ok(c),
                Err(e) if e.is_retriable() => {
                    tracing::warn!(
                        error = %e,
                        "multi-hop connect attempt failed, retrying after backoff"
                    );
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        // Loop body ran `max_attempts >= 1` iterations and never hit
        // `return Ok`, so a retriable error is guaranteed to have been
        // recorded in `last_err`.
        Err(last_err.expect("max_attempts>=1 always produces at least one attempt"))
    }

    /// Read-only snapshot of the per-session counters. Allocates a
    /// fresh struct on every call; intended for periodic scraping or
    /// for end-of-session reports.
    #[must_use]
    pub fn metrics(&self) -> MultiHopMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Override the default [`RekeyPolicy`]. Useful in tests to exercise
    /// the rekey path without sending 10 million frames.
    pub fn set_rekey_policy(&mut self, policy: RekeyPolicy) {
        self.rekey_policy = policy;
    }

    /// Read-only access to the active rekey policy.
    #[must_use]
    pub fn rekey_policy(&self) -> RekeyPolicy {
        self.rekey_policy
    }

    /// Borrow the destination exit identifier.
    #[must_use]
    pub fn exit_id(&self) -> ExitId {
        self.exit_id
    }

    /// Local UDP socket address the client is bound on.
    ///
    /// # Errors
    ///
    /// Propagates the underlying `Endpoint::local_addr` I/O error
    /// (only triggers on a torn-down endpoint, which should not
    /// happen during normal operation).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Maximum size, in bytes, of a single datagram that may be
    /// passed to [`Self::send`]. Returns `None` if datagrams are
    /// disabled by the peer.
    ///
    /// Surfaces [`quinn::Connection::max_datagram_size`] so call
    /// sites and regression tests can verify the negotiated path-MTU
    /// matches the Warren transport config (notably
    /// [`warrenguard_transport_core::warren_transport_config_client_multihop_with_gso`]
    /// raises Quinn's vanilla 1200 B initial MTU to 1350 B, which
    /// surfaces here as a `max_datagram_size` near 1300 B once the
    /// handshake completes).
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Rebind the underlying QUIC endpoint onto a fresh UDP socket.
    ///
    /// The relay observes the new source 4-tuple on the next outgoing
    /// packet and (with `migration(true)` on its server config)
    /// revalidates the path via PATH_CHALLENGE: the connection
    /// survives, no re-handshake. With a wildcard-bound socket the OS
    /// usually migrates the source address by itself on a route
    /// change; an explicit rebind covers the cases where the old
    /// socket is wedged (e.g. bound port black-holed by a NAT reset).
    ///
    /// # Errors
    ///
    /// Propagates `quinn::Endpoint::rebind` (socket registration with
    /// the runtime failed; the old socket is retained on error).
    pub fn rebind(&self, socket: std::net::UdpSocket) -> std::io::Result<()> {
        self.endpoint.rebind(socket)
    }

    /// Closes the relay connection with the dedicated
    /// [`warrenguard_multihop::WARREN_MH_FORCED_RECONNECT`] application code
    /// so the supervisor redials from a fresh socket. Used by the
    /// migration watchdog when a network change leaves the current
    /// QUIC path dead and passive migration did not recover it.
    ///
    /// A locally-initiated close surfaces to [`Self::closed`] as
    /// `ConnectionError::LocallyClosed`, which `rejection_from_conn_error`
    /// never maps to a [`RejectionReason`], so the supervisor treats it
    /// as a transient loss (redial), never as a fatal rejection.
    pub fn force_close_for_reconnect(&self) {
        self.conn.close(
            warrenguard_multihop::WARREN_MH_FORCED_RECONNECT.into(),
            b"forced-reconnect",
        );
    }

    /// Snapshot of the underlying Quinn connection statistics
    /// ([`quinn::ConnectionStats`]). Surfaces the BBR / Cubic
    /// congestion window (`path.cwnd`), smoothed RTT (`path.rtt`),
    /// current path MTU, lost packets, datagram counters, etc.
    /// Allocates a fresh struct on every call; intended for periodic
    /// scraping during a bench session (a bench binary's
    /// `--cwnd-trace-out`).
    #[must_use]
    pub fn quinn_stats(&self) -> quinn::ConnectionStats {
        self.conn.stats()
    }

    /// Clone of the underlying Quinn connection, for observers that
    /// outlive a borrow (e.g. `warrenguard_transport_core::spawn_path_probe`).
    #[must_use]
    pub fn clone_conn(&self) -> Connection {
        self.conn.clone()
    }

    /// Sends a DAITA v2 padding (dummy) frame through the multi-hop
    /// session. Internally builds a payload whose first
    /// byte is [`warrenguard_pump::DAITA_DUMMY_FIRST_BYTE`] (=0xFF) - a
    /// non-IP first nibble that the receiver's
    /// [`warrenguard_pump::is_daita_dummy`] check classifies as a dummy
    /// and drops before reaching the TUN. The dummy is then sealed
    /// via HPKE exactly like a normal packet, so a passive observer
    /// of the relay→exit ciphertext cannot distinguish padding from
    /// real traffic.
    ///
    /// Returns the on-wire size of the emitted frame so the caller
    /// can update its DAITA overhead metric.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send`].
    pub async fn send_daita_padding(&self) -> Result<usize, MultiHopError> {
        // Account for HPKE seal + outer frame overhead so
        // the sealed datagram fits within Quinn's negotiated
        // `max_datagram_size`. Mirrors the exit-side dummy sizing in
        // `serve_one_connection_with_tun_and_daita`. Before this fix
        // we built a `max_datagram_size`-byte plaintext, then `send`
        // grew it by ~89 B for the WarrenMultihopFrame envelope +
        // AEAD tag, pushing the on-wire size past Quinn's limit. The
        // resulting `SendDatagramError::TooLarge` was logged at
        // `trace!` and silently dropped the dummy, locking client
        // DAITA padding output at zero on cross-DC cloud paths
        // where the negotiated max stays at the conservative
        // initial-MTU floor.
        //
        // The 96 B subtraction = ~70 B WarrenMultihopFrame header
        // (exit_id + encapsulated_key + epoch + seq + length tags) +
        // ~16 B AEAD tag + ~10 B safety margin for path-MTU race.
        // The 1184 cap matches the exit-side `min(1184)` clamp so
        // both directions emit byte-identical dummies on the same
        // path.
        let max_plaintext = self
            .max_datagram_size()
            .unwrap_or(1200)
            .saturating_sub(96)
            .min(1184);
        let dummy = vec![warrenguard_pump::DAITA_DUMMY_FIRST_BYTE; max_plaintext];
        // Reuse the regular send path so the HPKE seal + rekey + seq
        // accounting all stay consistent across normal and padding
        // packets - a divergence here would itself be a fingerprint.
        self.send(&dummy).await?;
        Ok(max_plaintext)
    }

    /// Seal `payload` and forward it to the relay as a single QUIC
    /// datagram. Internally allocates the next forward-direction seq,
    /// runs the HPKE per-packet seal, and enqueues the resulting frame
    /// for transmission. May trigger an automatic rekey when the
    /// configured [`RekeyPolicy`] threshold is reached.
    ///
    /// # Errors
    ///
    /// - [`MultiHopError::Session`] on AEAD / HPKE failure.
    /// - [`MultiHopError::Encode`] if the wire encoder fails (does not
    ///   happen on well-formed payloads).
    /// - [`MultiHopError::Send`] if Quinn refuses the datagram.
    pub async fn send(&self, payload: &[u8]) -> Result<(), MultiHopError> {
        // quinn::Connection::send_datagram is itself synchronous; this stays
        // `async fn` only for API symmetry with `Self::recv`. `Self::send_packet`
        // is the same body without the `async` shape, for a caller on a
        // synchronous seam.
        self.send_packet(payload)
    }

    /// Synchronous counterpart to [`Self::send`]: seals `payload` and
    /// enqueues it as a QUIC datagram without an `async` wait
    /// (`quinn::Connection::send_datagram` does not block). Internally
    /// allocates the next forward-direction seq, runs the HPKE per-packet
    /// seal, and enqueues the resulting frame for transmission. May trigger
    /// an automatic rekey when the configured [`RekeyPolicy`] threshold is
    /// reached.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send`].
    pub fn send_packet(&self, payload: &[u8]) -> Result<(), MultiHopError> {
        // Drop the previous-epoch state if the doctrine 5 s overlap
        // window has elapsed since the last rekey. Lazy cleanup keeps
        // the pump loop free of a dedicated timer task while bounding
        // the leak surface to a single rekey worth of state.
        self.prune_pending_overlap_if_expired();

        // Check rekey BEFORE sealing the next frame. The lib's
        // ClientSession::rekey now retains the previous AeadCtxS in a
        // pending-old-epoch slot so in-flight reverse frames keep
        // decoding through the doctrine 5 s overlap.
        let frames_so_far = self.frames_in_epoch.load(Ordering::Acquire);
        if self.should_rekey(frames_so_far) {
            self.rekey()?;
        }

        // Piggyback the PQ epoch-bootstrap retry on ordinary traffic, the
        // same lazy-on-traffic style as `prune_pending_overlap_if_expired`
        // above: no dedicated timer task, no-op once acked or rate-limited.
        #[cfg(feature = "pq-hpke")]
        self.maybe_resend_pq_setup_ping();

        let bytes = self.seal_next_forward_frame(payload)?;
        let wire_len = bytes.len() as u64;
        self.conn.send_datagram(Bytes::from(bytes))?;
        self.frames_in_epoch.fetch_add(1, Ordering::AcqRel);
        self.metrics.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        let _ = wire_len;
        Ok(())
    }

    /// Sends a cover-traffic (dummy) frame whose plaintext is
    /// [`warrenguard_pump::DAITA_DUMMY_FIRST_BYTE`] followed by `padding_len`
    /// zero bytes, sealed and sent exactly like [`Self::send_packet`].
    /// Distinct from [`Self::send_daita_padding`] (which auto-sizes to the
    /// path MTU): this lets the caller pick an exact padding length, e.g. to
    /// mirror a maybenot machine's chosen action size.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send_packet`].
    pub fn send_cover_traffic(&self, padding_len: usize) -> Result<(), MultiHopError> {
        let mut dummy = Vec::with_capacity(1 + padding_len);
        dummy.push(warrenguard_pump::DAITA_DUMMY_FIRST_BYTE);
        dummy.resize(1 + padding_len, 0);
        self.send_packet(&dummy)
    }

    /// Read one reverse-direction datagram from the relay and return
    /// the decrypted plaintext. Blocks until a datagram arrives or the
    /// connection terminates.
    ///
    /// # Errors
    ///
    /// - [`MultiHopError::Recv`] if the connection is closed.
    /// - [`MultiHopError::Decode`] if the bytes do not parse as a
    ///   [`warrenguard_multihop::WarrenMultihopFrame`].
    /// - [`MultiHopError::UnexpectedExitId`] if the frame targets a
    ///   different exit than the active session.
    /// - [`MultiHopError::Replay`] on a duplicate seq within the active
    ///   epoch.
    /// - [`MultiHopError::Session`] on AEAD verification failure (a
    ///   forward-direction frame, a frame from a stale epoch, or a
    ///   tampered ciphertext).
    pub async fn recv(&self) -> Result<Vec<u8>, MultiHopError> {
        self.prune_pending_overlap_if_expired();

        let datagram = self
            .conn
            .read_datagram()
            .await
            .map_err(MultiHopError::Recv)?;
        self.decode_and_open_reply(&datagram)
    }

    /// Seal `payload` for [`Self::setup_over_stream`]'s request frame,
    /// consuming the same forward-direction seq counter
    /// [`Self::seal_next_forward_frame`] uses so the epoch frame count stays
    /// consistent regardless of which transport carried a given seq.
    ///
    /// `/v1` has no separate "setup" seal, so this simply delegates to
    /// [`Self::seal_next_forward_frame`] unchanged. `/v2` always seals with
    /// [`PqClientSession::seal_setup`] (carrying `pq_ct`) instead of going
    /// through [`Self::seal_next_forward_frame`]'s unacked-DATA branching:
    /// unlike a DATA frame, this request IS the (or a) conduit meant to
    /// deliver the current epoch's `pq_ct` to the exit, reliably, over the
    /// stream.
    fn seal_setup_stream_request(&self, payload: &[u8]) -> Result<Vec<u8>, MultiHopError> {
        #[cfg(feature = "pq-hpke")]
        if let ClientSessionKind::V2 { session, .. } = &self.session {
            let seq = self.seq_send.fetch_add(1, Ordering::AcqRel);
            let frame = {
                let sess = session.read();
                let epoch = sess.epoch();
                sess.seal_setup(payload, epoch, seq)?
            };
            return encode_frame_v2(&frame).map_err(map_multihop_encode_err);
        }
        self.seal_next_forward_frame(payload)
    }

    /// Seal `payload` as the next forward-direction DATA frame and return the
    /// encoded wire bytes. Allocates the next seq, runs the per-packet HPKE
    /// seal under the active epoch, and serialises the resulting wire frame.
    /// Used by the datagram [`Self::send`] path; [`Self::setup_over_stream`]'s
    /// own request frame goes through [`Self::seal_setup_stream_request`]
    /// instead (see its doc for why the two must not share this branching).
    ///
    /// `/v2` only: DATA frames NEVER carry `pq_ct`. While the current epoch
    /// is unacked, they instead seal under the RETAINED previous epoch
    /// ([`PqClientSession::seal_pending_old_epoch`]), which the exit already
    /// established; the new epoch's `pq_ct` rides only its own dedicated
    /// small setup ping ([`Self::send_pq_setup_ping`]), decoupled from
    /// whatever size the caller's payload happens to be. Reattaching `pq_ct`
    /// to a caller's DATA frame here was the historical bug: an unacked full
    /// MTU DATA frame plus the 1088-byte ML-KEM ciphertext oversizes past
    /// the path datagram cap and Quinn refuses to send it
    /// ([`quinn::SendDatagramError::TooLarge`]), which a lossy-pump caller
    /// then treats as an ordinary transient drop, silently losing every
    /// large uplink packet for as long as the epoch stays unacked.
    fn seal_next_forward_frame(&self, payload: &[u8]) -> Result<Vec<u8>, MultiHopError> {
        let seq = self.seq_send.fetch_add(1, Ordering::AcqRel);
        match &self.session {
            ClientSessionKind::V1(session) => {
                let frame = {
                    let sess = session.read();
                    let epoch = sess.epoch();
                    sess.seal(payload, epoch, seq)?
                };
                encode_frame(&frame).map_err(map_multihop_encode_err)
            }
            #[cfg(feature = "pq-hpke")]
            ClientSessionKind::V2 { session, .. } => {
                let frame = {
                    let sess = session.read();
                    if self.pq_setup_acked.load(Ordering::Acquire) {
                        sess.seal(payload, sess.epoch(), seq)?
                    } else if sess.has_pending_old_epoch() {
                        // (b) preferred: the exit already established the
                        // OLD epoch (it accepted the pre-rekey traffic), so
                        // full-size DATA keeps flowing there for the
                        // doctrine overlap window while the new epoch
                        // bootstraps on its own ping. Bounded by
                        // `PENDING_OLD_EPOCH_TTL`: normal RTTs ack well
                        // inside it.
                        sess.seal_pending_old_epoch(payload, seq)?
                    } else {
                        // (a) fallback: the overlap window elapsed with no
                        // ack yet (should not happen at normal RTTs; a
                        // resent ping is still in flight, see
                        // `maybe_resend_pq_setup_ping`). Seal under the new
                        // epoch with NO pq_ct: the exit cannot open this
                        // without a setup frame it kept, so it is dropped
                        // until a ping lands and flips the epoch to acked.
                        // Losing packets here is the lesser evil versus
                        // reattaching pq_ct, which is exactly the
                        // oversized-frame bug this design fixes.
                        sess.seal(payload, sess.epoch(), seq)?
                    }
                };
                encode_frame_v2(&frame).map_err(map_multihop_encode_err)
            }
        }
    }

    /// Decode `bytes` as a reverse-direction frame, enforce the
    /// `exit_id` pin + per-epoch anti-replay window, HPKE-open it, and
    /// return the recovered plaintext. Shared by the datagram
    /// [`Self::recv`] path and the [`Self::setup_over_stream`] reply
    /// path so the crypto + replay accounting are identical regardless
    /// of which transport carried the frame.
    fn decode_and_open_reply(&self, bytes: &[u8]) -> Result<Vec<u8>, MultiHopError> {
        match &self.session {
            ClientSessionKind::V1(session) => {
                let frame = decode_frame(bytes).map_err(|e| {
                    self.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                    map_multihop_decode_err(e)
                })?;
                if frame.exit_id != self.exit_id {
                    self.metrics
                        .unexpected_exit_id
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(MultiHopError::UnexpectedExitId);
                }
                // Two-phase verify-then-record anti-replay (cf.
                // open_replay_gated): the window matching the frame's epoch
                // (current, or the rekey-overlap pending slot) is probed
                // before the AEAD open and committed only once the frame
                // authenticated. A frame whose epoch matches neither slot (a
                // deeper old epoch, or a typo by a hostile relay) is counted
                // as a replay reject and surfaced as MultiHopError::Replay.
                let gated = open_replay_gated(&self.replay, frame.epoch, frame.seq, move || {
                    let sess = session.read();
                    // Consume the decoded frame: decrypt in place in its own
                    // buffer, no per-packet ciphertext copy on the
                    // reverse-direction datapath.
                    Ok(sess.open_response_owned(frame)?)
                });
                let (plaintext, _frame_epoch_is_pending) = self.record_reply_metrics(gated)?;
                Ok(plaintext)
            }
            #[cfg(feature = "pq-hpke")]
            ClientSessionKind::V2 { session, .. } => {
                let frame = decode_frame_v2(bytes).map_err(|e| {
                    self.metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                    map_multihop_decode_err(e)
                })?;
                if frame.exit_id != self.exit_id {
                    self.metrics
                        .unexpected_exit_id
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(MultiHopError::UnexpectedExitId);
                }
                let gated = open_replay_gated(&self.replay, frame.epoch, frame.seq, move || {
                    let sess = session.read();
                    Ok(sess.open_response(&frame)?)
                });
                let (plaintext, frame_epoch_is_pending) = self.record_reply_metrics(gated)?;
                // The resend-until-ack signal: a reverse frame that matched
                // the CURRENT (not the rekey-overlap pending) window proves
                // the exit has decapsulated this epoch's pq_ct, so the
                // forward path can stop re-carrying it.
                if !frame_epoch_is_pending {
                    self.pq_setup_acked.store(true, Ordering::Release);
                }
                Ok(plaintext)
            }
        }
    }

    /// Shared tail of the reply-open chokepoint: given the result of
    /// [`open_replay_gated`], update the frames/bytes/replay/fallback
    /// counters and return the plaintext plus whether the frame matched the
    /// rekey-overlap pending epoch. Identical accounting for `/v1` and
    /// `/v2` replies.
    fn record_reply_metrics(
        &self,
        gated: Result<(Vec<u8>, bool), MultiHopError>,
    ) -> Result<(Vec<u8>, bool), MultiHopError> {
        let (plaintext, frame_epoch_is_pending) = match gated {
            Ok(opened) => opened,
            Err(e) => {
                if matches!(e, MultiHopError::Replay { .. }) {
                    self.metrics.replay_rejects.fetch_add(1, Ordering::Relaxed);
                }
                return Err(e);
            }
        };
        if frame_epoch_is_pending {
            self.metrics
                .decode_fallback_to_old_epoch
                .fetch_add(1, Ordering::Relaxed);
        }
        self.metrics.frames_recv.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_recv
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);
        Ok((plaintext, frame_epoch_is_pending))
    }

    /// Perform the multi-hop SETUP round-trip over a reliable bidi QUIC
    /// stream and return the decrypted reply plaintext (the exit's
    /// HPKE-sealed [`WarrenControlMessage::IpAssign`]).
    ///
    /// The first multi-hop frame carries the HPKE `encapsulated_key`. On
    /// a real network path the very first QUIC DATAGRAM is frequently
    /// lost (the path is still warming up, the datagram queue is not yet
    /// ACK-paced), which would strand the HPKE setup. To avoid that, the
    /// setup round-trip runs over a reliable finish-delimited bidi stream
    /// rather than datagrams. The relay shuttles the raw stream bytes
    /// between this stream and the relay→exit stream without ever
    /// decrypting them.
    ///
    /// DATA continues to flow over datagrams via [`Self::send`] /
    /// [`Self::recv`] after this returns. The seq allocated to the setup
    /// frame is the same forward-direction counter the data path uses,
    /// so the exit's anti-replay window stays consistent.
    ///
    /// # Errors
    ///
    /// - [`MultiHopError::SetupStream`] on any stream open/write/finish/read
    ///   failure (reliable transport: a failure is fatal, not droppable).
    /// - [`MultiHopError::Session`] / [`MultiHopError::Encode`] if sealing
    ///   the request frame fails.
    /// - The decode/open/replay/exit_id errors from the shared reply path
    ///   ([`MultiHopError::Decode`], [`MultiHopError::UnexpectedExitId`],
    ///   [`MultiHopError::Replay`], [`MultiHopError::Session`]).
    pub async fn setup_over_stream(
        &self,
        identity: Option<&SigningKey>,
        wants_ipv6: bool,
        wants_daita: bool,
    ) -> Result<Vec<u8>, MultiHopError> {
        self.setup_over_stream_with_tokens(identity, wants_ipv6, wants_daita, None)
            .await
    }

    /// Variant of [`Self::setup_over_stream`] that presents anonymous v7
    /// session tokens instead of an identity proof of possession.
    ///
    /// When `session_tokens` is `Some` and non-empty the setup frame carries
    /// a [`WarrenControlMessage::IpRequestV7`]: the exit admits on the
    /// Privacy Pass token (verified offline, spent by anonymous serial) and
    /// never learns the account pubkey, closing the exit-side identity
    /// linkage the v6 `IpRequest` PoP leaves open. `identity` is then unused
    /// for admission (the token IS the authorization) and only its presence
    /// as a fallback is ignored. `None` or an empty slice keeps the v6 path
    /// verbatim.
    ///
    /// # Errors
    ///
    /// Same as [`Self::setup_over_stream`].
    pub async fn setup_over_stream_with_tokens(
        &self,
        identity: Option<&SigningKey>,
        wants_ipv6: bool,
        wants_daita: bool,
        session_tokens: Option<&[SessionToken]>,
    ) -> Result<Vec<u8>, MultiHopError> {
        self.setup_over_stream_with_options(identity, wants_ipv6, wants_daita, session_tokens, None)
            .await
    }

    /// Variant of [`Self::setup_over_stream_with_tokens`] that also carries
    /// a session-placement hint in the request's `prefer_ipv4` field.
    ///
    /// The hint closes the two-live-sessions downlink collision on the
    /// exit: `Some(0.0.0.0)` declares an INDEPENDENT session start (the
    /// exit never co-houses it on an inner IP another live session of the
    /// same identity holds), `Some(addr)` declares this connection part of
    /// the session currently assigned `addr` (bonded secondaries, overlap
    /// and fast reconnects keep their session's address), `None` keeps the
    /// legacy hint-less request. Advisory on the wire: exits predating the
    /// hint ignore the field entirely.
    ///
    /// # Errors
    ///
    /// Same as [`Self::setup_over_stream`].
    pub async fn setup_over_stream_with_options(
        &self,
        identity: Option<&SigningKey>,
        wants_ipv6: bool,
        wants_daita: bool,
        session_tokens: Option<&[SessionToken]>,
        prefer_ipv4: Option<std::net::Ipv4Addr>,
    ) -> Result<Vec<u8>, MultiHopError> {
        // Sign over the session's CURRENT encapsulated_key. Setup runs
        // before any traffic, so no rekey can race the seal below; if one
        // ever did, the exit would reject the stale PoP and the supervisor
        // would redial cleanly.
        let request_msg = compose_setup_request(
            identity,
            &self.exit_id,
            &self.session.encapsulated_key(),
            wants_ipv6,
            wants_daita,
            session_tokens,
            prefer_ipv4,
        );
        let plaintext = encode_control(&request_msg).map_err(|e| match e {
            warrenguard_multihop::ControlError::Decode(p) => MultiHopError::Encode(p),
            _ => MultiHopError::Encode(postcard::Error::SerializeBufferFull),
        })?;
        let request = self.seal_setup_stream_request(&plaintext)?;

        let (mut send, mut recv) =
            self.conn
                .open_bi()
                .await
                .map_err(|e| MultiHopError::SetupStream {
                    context: "open_bi",
                    detail: e.to_string(),
                })?;
        send.write_all(&request)
            .await
            .map_err(|e| MultiHopError::SetupStream {
                context: "write request",
                detail: e.to_string(),
            })?;
        send.finish().map_err(|e| MultiHopError::SetupStream {
            context: "finish request",
            detail: e.to_string(),
        })?;

        // In X.509 cover-domain mode, now that the setup frame is on
        // the wire (so the relay knows we are a Warren client and has emitted
        // its proof), verify the relay's in-band identity proof BEFORE reading
        // the reply or sending any data. A MITM holding only a valid
        // cover-domain certificate cannot forge it, so we fail closed. The
        // cleartext exit_id rode the just-sent frame inside the TLS-encrypted
        // stream, visible only to a peer that already terminated TLS with a
        // valid cover cert, never to the on-path censor.
        if let Some(relay_pubkey) = self.relay_auth_pubkey {
            Self::verify_relay_proof(&self.conn, &relay_pubkey).await?;
        }

        let reply = recv
            .read_to_end(MAX_MULTIHOP_SETUP_FRAME_BYTES)
            .await
            .map_err(|e| MultiHopError::SetupStream {
                context: "read reply",
                detail: e.to_string(),
            })?;

        // The setup frame consumed one forward-direction seq via
        // `seal_next_forward_frame`; mirror the data path's per-frame
        // accounting so the epoch frame count and the metrics counter
        // stay consistent with the seq counter.
        self.frames_in_epoch.fetch_add(1, Ordering::AcqRel);
        self.metrics.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        let opened = self.decode_and_open_reply(&reply)?;
        // Explicit, on top of `decode_and_open_reply`'s generic pending-epoch
        // check reaching the same conclusion for epoch 0: the setup round
        // trip is a RELIABLE stream, so a successful open here already
        // proves the exit decapsulated this epoch's pq_ct. The datagram data
        // path can therefore start acked immediately, without waiting to
        // observe a separate reverse datagram first.
        #[cfg(feature = "pq-hpke")]
        if matches!(self.session, ClientSessionKind::V2 { .. }) {
            self.pq_setup_acked.store(true, Ordering::Release);
        }
        // Opportunistically capture the typed IP allocation for
        // `Self::assignment` and friends. Best-effort: a `Rejected` /
        // `IpExhausted` reply (or any other non-IpAssign control message)
        // leaves `assignment` at `None`; the caller still gets the raw
        // plaintext back to interpret itself.
        //
        // `/v2`: the reply plaintext is already opened above; the inner
        // `IpAssign` is byte-identical to `/v1`, so it parses through the
        // version-agnostic `ip_assignment_from_setup_plaintext` (which builds
        // `IpAssignment` inside `warrenguard-multihop`, honoring its
        // `#[non_exhaustive]` boundary).
        #[cfg(feature = "pq-hpke")]
        if matches!(self.session, ClientSessionKind::V2 { .. })
            && let Ok(assignment) =
                warrenguard_multihop::ip_assignment_from_setup_plaintext(&opened)
        {
            *self.assignment.lock() = Some(assignment);
        }
        // `/v1`: a second, cheap `open_setup_reply` over the same reply bytes
        // (HPKE open is a pure function of the ciphertext, so re-running it is
        // idempotent, not a state mutation).
        if let Some(v1) = self.session.as_v1()
            && let Ok(frame) = decode_frame(&reply)
            && let Ok(assignment) = v1.read().open_setup_reply(&frame)
        {
            *self.assignment.lock() = Some(assignment);
        }
        Ok(opened)
    }

    /// The exit's IP allocation, captured during [`Self::setup_over_stream`].
    /// `None` before setup has completed, or if the setup reply was a policy
    /// refusal rather than an `IpAssign`.
    #[must_use]
    pub fn assignment(&self) -> Option<IpAssignment> {
        self.assignment.lock().clone()
    }

    /// The maybenot machine the exit granted for THIS session, or `None` when
    /// it did not grant the defense.
    ///
    /// `None` after a setup in which the client asked for DAITA is the exit
    /// saying the defense is NOT running. The caller must surface that, never
    /// run the plain pump while reporting the tunnel as defended.
    #[must_use]
    pub fn daita_spec(&self) -> Option<warrenguard_wire::DaitaConfig> {
        self.assignment
            .lock()
            .as_ref()
            .and_then(|a| a.daita_spec.clone())
    }

    /// The assigned tunnel IPv4, if [`Self::assignment`] is populated.
    #[must_use]
    pub fn assigned_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.assignment
            .lock()
            .as_ref()
            .map(|a| std::net::Ipv4Addr::from(a.ipv4))
    }

    /// The assigned tunnel IPv6, if the exit granted dual-stack and
    /// [`Self::assignment`] is populated.
    #[must_use]
    pub fn assigned_ipv6(&self) -> Option<std::net::Ipv6Addr> {
        self.assignment
            .lock()
            .as_ref()
            .and_then(|a| a.ipv6)
            .map(std::net::Ipv6Addr::from)
    }

    /// The largest inner IP packet that fits in one sealed datagram: the path
    /// datagram size minus the worst-case frame overhead. Falls back to the
    /// 1280-byte base MTU before the first PMTU probe. On a `/v2` session the
    /// overhead bound is the DATA-frame one (empty `pq_ct`): every payload-
    /// bearing datagram is a data frame, and the ML-KEM ciphertext rides only
    /// its own empty-payload bootstrap ping, so a `/v2` session gets the same
    /// usable payload as `/v1` instead of one starved by ~1 KB of `pq_ct`.
    #[must_use]
    pub fn max_inner_payload(&self) -> usize {
        const BASE_MTU: usize = 1280;
        let path = self.max_datagram_size().unwrap_or(BASE_MTU);
        path.saturating_sub(self.session.max_frame_overhead())
    }

    /// The current HPKE epoch (starts at `0`, `+1` per [`Self::rekey`]).
    #[must_use]
    pub fn current_epoch(&self) -> u32 {
        self.session.epoch()
    }

    /// Time since the current epoch was installed (construction or last
    /// [`Self::rekey`]).
    #[must_use]
    pub fn since_last_rekey(&self) -> Duration {
        self.last_rekey.lock().elapsed()
    }

    /// Unconditionally end the rekey overlap: drop the previous-epoch HPKE
    /// context and its per-epoch anti-replay window immediately, regardless
    /// of whether [`PENDING_OLD_EPOCH_TTL`] has elapsed yet. Complements the
    /// automatic lazy pruning in [`Self::send`] / [`Self::recv`] for callers
    /// that track the overlap deadline themselves (e.g. an external
    /// [`RekeyPolicy`]-shaped doctrine with a caller-chosen overlap window).
    /// Idempotent.
    pub fn prune_old_epoch(&self) {
        self.session.prune_pending_old_epoch();
        self.replay.lock().pending = None;
        *self.pending_old_epoch_at.lock() = None;
    }

    /// Force an immediate rekey. Allocates a fresh HPKE setup against
    /// the same destination exit, bumps the epoch, and resets the
    /// forward-direction seq counter and the reverse-direction
    /// replay window.
    ///
    /// Returns the new epoch number on success.
    ///
    /// # Errors
    ///
    /// - [`MultiHopError::Session`] if the underlying HPKE rekey fails
    ///   (KEM ECDH error or epoch overflow at `u32::MAX`).
    pub fn rekey(&self) -> Result<u32, MultiHopError> {
        let new_epoch = match &self.session {
            ClientSessionKind::V1(session) => {
                let mut sess = session.write();
                sess.rekey(
                    &self.exit_pubkey,
                    &mut rand_core::UnwrapErr(rand_core::OsRng),
                )?;
                sess.epoch()
            }
            #[cfg(feature = "pq-hpke")]
            ClientSessionKind::V2 { session, recipient } => {
                let mut sess = session.write();
                sess.rekey(recipient, &mut rand_core::UnwrapErr(rand_core::OsRng))?;
                // A rekey's pq_ct rides lossy datagrams (unlike epoch 0's,
                // which rides the reliable setup stream): the new epoch
                // needs its own bootstrap ping until the exit acks it (see
                // `send_pq_setup_ping` below and `decode_and_open_reply`).
                self.pq_setup_acked.store(false, Ordering::Release);
                sess.epoch()
            }
        };
        self.seq_send.store(0, Ordering::Release);
        self.frames_in_epoch.store(0, Ordering::Release);
        *self.last_rekey.lock() = Instant::now();
        // Move the current replay window into the pending slot so
        // in-flight reverse frames from the old epoch are still
        // replay-checked correctly during the doctrine overlap
        // window. Install a fresh window for the new epoch. Cf. the
        // matching ClientSession::pending_old_epoch slot in
        // warren-multihop.
        {
            let mut state = self.replay.lock();
            let fresh = EpochReplay {
                epoch: new_epoch,
                window: ReplayWindow::new(),
            };
            let old = std::mem::replace(&mut state.current, fresh);
            state.pending = Some(old);
        }
        *self.pending_old_epoch_at.lock() = Some(Instant::now());
        self.metrics.rekey_count.fetch_add(1, Ordering::Relaxed);
        tracing::info!("multi-hop session rekey applied");

        // Bootstrap the new epoch on its own small datagram immediately,
        // decoupled from the data path (see the module docs on the
        // historical oversized-DATA-frame bug). Best-effort: a lost or
        // momentarily oversized ping is retried by `send_packet` via
        // `maybe_resend_pq_setup_ping`, so a failure here must never fail
        // the rekey call itself. Sent after the seq/replay bookkeeping
        // above so the ping consumes seq 0 of the fresh epoch's counter,
        // exactly like any other first frame of an epoch.
        #[cfg(feature = "pq-hpke")]
        if let ClientSessionKind::V2 { session, .. } = &self.session {
            let _ = self.send_pq_setup_ping(session);
        }

        Ok(new_epoch)
    }

    /// Seal and send a dedicated small PQ epoch-bootstrap datagram: an
    /// empty-payload `/v2` SETUP frame carrying `pq_ct`, sized at
    /// [`warrenguard_multihop::MULTIHOP_FRAME_V2_MAX_OVERHEAD`] alone
    /// (well under any real path datagram cap) so it always fits
    /// regardless of whatever size the caller's own DATA payloads are.
    /// Called immediately from [`Self::rekey`] and re-called
    /// (rate-limited) from [`Self::maybe_resend_pq_setup_ping`] while the
    /// epoch stays unacked.
    ///
    /// # Errors
    ///
    /// Propagates a seal, encode, or Quinn send failure. Every caller
    /// treats this as best-effort (a lost or momentarily oversized ping is
    /// retried on the next [`Self::send_packet`] call), so a failure here
    /// must never fail the caller's own send or the rekey that triggered it.
    #[cfg(feature = "pq-hpke")]
    fn send_pq_setup_ping(&self, session: &RwLock<PqClientSession>) -> Result<(), MultiHopError> {
        let seq = self.seq_send.fetch_add(1, Ordering::AcqRel);
        let frame = {
            let sess = session.read();
            let epoch = sess.epoch();
            sess.seal_setup(&[], epoch, seq)?
        };
        let bytes = encode_frame_v2(&frame).map_err(map_multihop_encode_err)?;
        self.conn.send_datagram(Bytes::from(bytes))?;
        self.metrics
            .pq_setup_resends
            .fetch_add(1, Ordering::Relaxed);
        self.metrics.frames_sent.fetch_add(1, Ordering::Relaxed);
        *self.pq_setup_ping_last_sent.lock() = Some(Instant::now());
        Ok(())
    }

    /// Opportunistically resend [`Self::send_pq_setup_ping`] from the data
    /// path: called on every [`Self::send_packet`] so a lost ping (the
    /// datagram path is lossy by design) gets retried without a dedicated
    /// timer task, the same lazy-on-traffic style as
    /// [`Self::prune_pending_overlap_if_expired`]. No-op once acked, and
    /// rate-limited to [`PQ_SETUP_PING_RESEND_INTERVAL`] so steady traffic
    /// does not re-ping on every packet.
    #[cfg(feature = "pq-hpke")]
    fn maybe_resend_pq_setup_ping(&self) {
        let ClientSessionKind::V2 { session, .. } = &self.session else {
            return;
        };
        if self.pq_setup_acked.load(Ordering::Acquire) {
            return;
        }
        let due = {
            let last = self.pq_setup_ping_last_sent.lock();
            match *last {
                None => true,
                Some(t) => t.elapsed() >= PQ_SETUP_PING_RESEND_INTERVAL,
            }
        };
        if !due {
            return;
        }
        // Best-effort: see `Self::send_pq_setup_ping`'s doc.
        let _ = self.send_pq_setup_ping(session);
    }

    /// If a previous rekey is still in its overlap window and the
    /// doctrine TTL has elapsed, prune the pending old-epoch state
    /// from both the lib session and the per-epoch replay tracker.
    /// Called at the start of [`Self::send`] and [`Self::recv`] so
    /// the cleanup happens lazily on the next traffic event after
    /// expiry, without needing a dedicated background task.
    fn prune_pending_overlap_if_expired(&self) {
        let should_prune = {
            let at = self.pending_old_epoch_at.lock();
            match *at {
                Some(t) => t.elapsed() >= self.pending_old_epoch_ttl,
                None => false,
            }
        };
        if !should_prune {
            return;
        }
        self.session.prune_pending_old_epoch();
        self.replay.lock().pending = None;
        *self.pending_old_epoch_at.lock() = None;
    }

    fn should_rekey(&self, frames_sent: u64) -> bool {
        if frames_sent >= self.rekey_policy.max_frames {
            return true;
        }
        let last = *self.last_rekey.lock();
        last.elapsed() >= self.rekey_policy.max_age
    }

    /// Drop the QUIC connection cleanly with the supplied close code.
    /// Useful in tests to release the relay-side resources before the
    /// next iteration.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(quinn::VarInt::from_u32(code), reason);
    }

    /// Future that resolves with the underlying QUIC connection's close
    /// reason as soon as it terminates (timeout, peer reset, local
    /// close, application close). Surfaces
    /// [`quinn::Connection::closed`] without leaking the Quinn type into
    /// upstream code.
    ///
    /// The supervisor task uses this to watch for mid-session
    /// disconnects and trigger a transparent reconnect.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.conn.closed().await
    }

    /// Non-blocking peek at the connection's close reason, if it has
    /// already terminated. Returns `None` while the connection is still
    /// live. Used by the supervisor to classify a setup-stream failure:
    /// if the exit closed with a known rejection code, the failure is a
    /// definitive policy refusal rather than a transient blip.
    #[must_use]
    pub fn rejection_reason(&self) -> Option<RejectionReason> {
        rejection_from_conn_error(&self.conn.close_reason()?)
    }
}

/// Map a QUIC [`quinn::ConnectionError`] to a [`RejectionReason`] when
/// it carries the exit's opaque multi-hop policy-rejection close code.
/// Returns `None` for transient errors (timeout, reset, local close) or
/// any application close code that is not the rejection code.
///
/// The close code is deliberately opaque (one code, empty reason bytes,
/// anti-oracle on the relay-facing branch), so this yields the generic
/// [`RejectionReason::PolicyRefused`]; the specific cause, when it
/// arrived, comes from the HPKE-sealed detail the exit wrote on the
/// setup stream before closing (`RejectionReason::from_sealed_detail`).
#[must_use]
pub fn rejection_from_conn_error(err: &quinn::ConnectionError) -> Option<RejectionReason> {
    let quinn::ConnectionError::ApplicationClosed(ac) = err else {
        return None;
    };
    u32::try_from(u64::from(ac.error_code))
        .ok()
        .and_then(RejectionReason::from_close_code)
}

pub use warrenguard_pump::WarrenPumpHandle;

impl WarrenPumpHandle for MultiHopClient {
    type Error = MultiHopError;

    async fn pump_send(&self, payload: &[u8]) -> Result<(), MultiHopError> {
        self.send(payload).await
    }

    async fn pump_recv(&self) -> Result<Vec<u8>, MultiHopError> {
        self.recv().await
    }

    async fn pump_send_daita_dummy(&self) -> Result<usize, MultiHopError> {
        self.send_daita_padding().await
    }

    fn pump_close(&self, code: u32, reason: &[u8]) {
        self.close(code, reason);
    }
}

/// Test-only accessor for the client's HPKE `encapsulated_key`, so a
/// loopback test harness can build the matching exit-side
/// [`warrenguard_multihop::ExitSession`] without going through the
/// setup-stream wire exchange. `session` is private to this module;
/// Builds the setup-stream control request. Pure so the request shape,
/// notably the session-placement `prefer_ipv4` hint pass-through, is
/// testable without a live session.
///
/// v7 anonymous admission: the token is the authorization, so the request
/// carries no account pubkey and no PoP. The exit verifies the token
/// offline and keys the session by its anonymous serial. Chosen over the
/// v6 `IpRequest` whenever tokens are supplied and non-empty.
///
/// v6 `IpRequest`: carries the sticky/allowlist pubkey and the Ed25519
/// proof of possession over this session's HPKE `encapsulated_key`
/// (domain-separated, exit-bound) so a strict exit can verify possession
/// instead of trusting a bare assertion. The production binary always
/// passes the key; `None` is for permissive/bench exits only.
fn compose_setup_request(
    identity: Option<&SigningKey>,
    exit_id: &ExitId,
    encapsulated_key: &warrenguard_multihop::EncapsulatedKeyBytes,
    wants_ipv6: bool,
    wants_daita: bool,
    session_tokens: Option<&[SessionToken]>,
    prefer_ipv4: Option<std::net::Ipv4Addr>,
) -> WarrenControlMessage {
    let prefer_ipv4 = prefer_ipv4.map(|ip| ip.octets());
    match session_tokens {
        Some(tokens) if !tokens.is_empty() => WarrenControlMessage::IpRequestV7 {
            prefer_ipv4,
            wants_ipv6,
            session_tokens: tokens.to_vec(),
            wants_daita,
        },
        _ => {
            let (client_pubkey, pop_sig) = match identity {
                Some(key) => (
                    Some(key.verifying_key().to_bytes()),
                    Some(warrenguard_multihop::sign_pop(
                        key,
                        exit_id,
                        encapsulated_key,
                    )),
                ),
                None => (None, None),
            };
            WarrenControlMessage::IpRequest {
                prefer_ipv4,
                client_pubkey,
                wants_ipv6,
                pop_sig,
                wants_daita,
            }
        }
    }
}

/// exposed crate-wide (not just to this file's own `mod tests`) so the
/// shared loopback helper in `crate::test_support` can reach it.
#[cfg(test)]
pub(crate) fn client_encapsulated_key_for_test(
    client: &MultiHopClient,
) -> warrenguard_multihop::EncapsulatedKeyBytes {
    client.session.encapsulated_key()
}

/// Test-only accessor for a `/v2` client's PQ setup material
/// (`encapsulated_key`, `pq_ct`), so a loopback test harness can build the
/// matching [`warrenguard_multihop::PqExitSession`] without going through
/// the setup-stream wire exchange. Only ever called on a client built via
/// [`MultiHopClient::from_established_connection_pq`].
#[cfg(all(test, feature = "pq-hpke"))]
pub(crate) fn client_pq_setup_material_for_test(client: &MultiHopClient) -> ([u8; 32], Vec<u8>) {
    let ClientSessionKind::V2 { session, .. } = &client.session else {
        panic!("client_pq_setup_material_for_test called on a /v1 session");
    };
    let sess = session.read();
    (sess.encapsulated_key(), sess.pq_ct().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;

    // Per-test carrier seams read by `super::cover_trust_anchors` /
    // `super::carrier_cover_endpoint`. Thread-local (not a global) so the
    // current-thread `#[tokio::test]` runtime that arms them isolates each
    // test: production never sees them (both seams return `None` off-test).
    thread_local! {
        static TEST_COVER_ANCHORS: RefCell<Option<Vec<Vec<u8>>>> = const { RefCell::new(None) };
        static TEST_CARRIER_ENDPOINT: RefCell<Option<SocketAddr>> = const { RefCell::new(None) };
    }

    pub(super) fn test_cover_trust_anchors() -> Option<Vec<Vec<u8>>> {
        TEST_COVER_ANCHORS.with(|c| c.borrow().clone())
    }

    pub(super) fn test_carrier_endpoint() -> Option<SocketAddr> {
        TEST_CARRIER_ENDPOINT.with(|c| *c.borrow())
    }

    fn arm_test_carrier(anchors: Vec<Vec<u8>>, endpoint: SocketAddr) {
        TEST_COVER_ANCHORS.with(|c| *c.borrow_mut() = Some(anchors));
        TEST_CARRIER_ENDPOINT.with(|c| *c.borrow_mut() = Some(endpoint));
    }

    /// Stand-in for an AEAD authentication failure: any non-replay
    /// session error works, the gate must propagate it untouched.
    fn mock_aead_failure() -> MultiHopError {
        MultiHopError::Session(MultihopError::UnsupportedVersion {
            got: 0,
            expected: 1,
        })
    }

    #[test]
    fn compose_setup_request_carries_the_session_placement_hint_v6_and_v7() {
        // The exit keys per-session downlink ownership off this hint: it
        // must reach the wire on BOTH admission variants, and its absence
        // must keep the legacy hint-less request byte-identical.
        let exit_id = ExitId::from_bytes([0x0E; 16]);
        let encap = [0x33; 32];
        let key = SigningKey::from_bytes(&[0x11; 32]);
        let hint = std::net::Ipv4Addr::new(10, 66, 0, 42);

        match compose_setup_request(Some(&key), &exit_id, &encap, true, false, None, Some(hint)) {
            WarrenControlMessage::IpRequest {
                prefer_ipv4,
                client_pubkey,
                pop_sig,
                ..
            } => {
                assert_eq!(prefer_ipv4, Some([10, 66, 0, 42]));
                assert_eq!(client_pubkey, Some(key.verifying_key().to_bytes()));
                let sig = pop_sig.expect("identity present implies a PoP");
                assert!(
                    warrenguard_multihop::verify_pop(
                        &key.verifying_key().to_bytes(),
                        &exit_id,
                        &encap,
                        &sig
                    ),
                    "the PoP must still cover (exit_id, encapsulated_key)"
                );
            }
            other => panic!("expected a v6 IpRequest, got {other:?}"),
        }

        let tokens = vec![SessionToken([0xAB; warrenguard_wire::SESSION_TOKEN_LEN])];
        match compose_setup_request(
            None,
            &exit_id,
            &encap,
            false,
            true,
            Some(&tokens),
            Some(std::net::Ipv4Addr::UNSPECIFIED),
        ) {
            WarrenControlMessage::IpRequestV7 { prefer_ipv4, .. } => {
                assert_eq!(
                    prefer_ipv4,
                    Some([0, 0, 0, 0]),
                    "the session-fresh sentinel must ride the v7 request too"
                );
            }
            other => panic!("expected a v7 IpRequestV7, got {other:?}"),
        }

        match compose_setup_request(Some(&key), &exit_id, &encap, false, false, None, None) {
            WarrenControlMessage::IpRequest { prefer_ipv4, .. } => {
                assert_eq!(prefer_ipv4, None, "no hint stays a legacy request");
            }
            other => panic!("expected a v6 IpRequest, got {other:?}"),
        }
    }

    #[test]
    fn aead_failure_does_not_burn_the_replay_window() {
        let replay = Mutex::new(ReplayState::new());
        // Legit traffic brought the window up to seq 10.
        open_replay_gated(&replay, 0, 10, || Ok(vec![1])).expect("legit frame accepted");

        // Hostile relay forges a far-future seq on a frame that cannot
        // authenticate: the open fails, and the window must NOT move.
        let err = open_replay_gated(&replay, 0, 1_000_000, || Err(mock_aead_failure()))
            .expect_err("unauthenticated frame must fail");
        assert!(
            matches!(err, MultiHopError::Session(_)),
            "the AEAD error propagates untouched, got {err:?}"
        );

        // The legitimate next in-flight seq (far below the forged one)
        // must still be accepted. Record-before-verify - the historical
        // behavior - would have slammed the window 1024 seqs past it
        // and silently dropped every in-flight downlink frame.
        open_replay_gated(&replay, 0, 11, || Ok(vec![2])).expect(
            "window must be untouched by the unauthenticated forged-seq frame \
             (verify-then-record contract)",
        );
    }

    #[test]
    fn successful_open_records_and_rejects_the_replay() {
        let replay = Mutex::new(ReplayState::new());
        open_replay_gated(&replay, 0, 7, || Ok(vec![1])).expect("first delivery accepted");
        let err = open_replay_gated(&replay, 0, 7, || Ok(vec![1]))
            .expect_err("the authenticated seq was recorded; a replay must be rejected");
        assert!(matches!(err, MultiHopError::Replay { epoch: 0, seq: 7 }));
    }

    // --- entry-relay in-band identity proof (client side) ---

    /// What the mock relay writes on the auth bi stream.
    enum MockProof {
        /// A proof signed by this key over the connection's channel binding.
        SignedBy(ed25519_dalek::SigningKey),
        /// A well-framed proof but signed by the wrong key (MITM with a valid
        /// cover-domain cert but not the relay's identity key).
        SignedByWrongKey(ed25519_dalek::SigningKey),
        /// Garbage bytes (wrong length / version): a framing failure.
        Garbage,
        /// Nothing: the relay never produces a proof.
        Silent,
    }

    /// Spins up an RPK loopback (the proof exchange is independent of the TLS
    /// cert type, so RPK keeps the test free of cert fixtures), where the
    /// "relay" opens a server-initiated bi stream and writes `proof`. Returns
    /// the established client connection plus the endpoints to keep alive.
    async fn loopback_with_mock_proof(proof: MockProof) -> (Connection, Endpoint, Endpoint) {
        let tls_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let server_cfg =
            warrenguard_tls::make_server_config(&tls_key, default_crypto_provider(), &[ALPN_H3])
                .expect("server cfg");
        let server_ep =
            Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).expect("server bind");
        let addr = server_ep.local_addr().expect("server addr");

        let server_for_task = server_ep.clone();
        tokio::spawn(async move {
            let Some(incoming) = server_for_task.accept().await else {
                return;
            };
            let conn = incoming.await.expect("server handshake");
            let cb = channel_binding(&conn).expect("server channel binding");
            let bytes: Vec<u8> = match proof {
                MockProof::SignedBy(k) | MockProof::SignedByWrongKey(k) => {
                    warrenguard_multihop::encode_relay_auth_proof(
                        &warrenguard_tls::sign_relay_auth(&k, &cb),
                    )
                    .to_vec()
                }
                MockProof::Garbage => vec![0xFFu8; 10],
                MockProof::Silent => {
                    // Hold the connection open without ever answering the
                    // client's auth stream, so the client must time out.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    return;
                }
            };
            let (mut send, _recv) = conn.open_bi().await.expect("open auth stream");
            send.write_all(&bytes).await.expect("write proof");
            let _ = send.finish();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client_cfg =
            make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client cfg");
        let mut client_ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
        client_ep.set_default_client_config(client_cfg);
        let sni = warrenguard_tls::name::encode(WarrenPubkey::from_bytes(
            tls_key.verifying_key().to_bytes(),
        ));
        let conn = client_ep
            .connect(addr, &sni)
            .expect("connect builds")
            .await
            .expect("client handshake");
        (conn, server_ep, client_ep)
    }

    #[tokio::test]
    async fn relay_proof_accepts_the_directory_vouched_identity() {
        let relay_key = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
        let expected = WarrenPubkey::from_bytes(relay_key.verifying_key().to_bytes());
        let (conn, _s, _c) = loopback_with_mock_proof(MockProof::SignedBy(relay_key)).await;
        MultiHopClient::verify_relay_proof(&conn, &expected)
            .await
            .expect("a proof signed by the expected relay key must verify");
    }

    #[tokio::test]
    async fn relay_proof_rejects_a_mitm_with_a_valid_cert_but_wrong_key() {
        // The MITM completed the (RPK here, WebPKI in prod) handshake and holds
        // SOME key, but not the directory-vouched relay identity. Fail closed.
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x66; 32]);
        let expected_relay = WarrenPubkey::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes(),
        );
        let (conn, _s, _c) = loopback_with_mock_proof(MockProof::SignedByWrongKey(attacker)).await;
        let err = MultiHopClient::verify_relay_proof(&conn, &expected_relay)
            .await
            .expect_err("a proof not signed by the expected relay identity must be rejected");
        assert!(
            matches!(err, MultiHopError::RelayIdentity(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn relay_proof_rejects_a_malformed_message() {
        let expected = WarrenPubkey::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes(),
        );
        let (conn, _s, _c) = loopback_with_mock_proof(MockProof::Garbage).await;
        let err = MultiHopClient::verify_relay_proof(&conn, &expected)
            .await
            .expect_err("a malformed proof must be rejected");
        assert!(
            matches!(err, MultiHopError::RelayIdentity(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn relay_proof_times_out_when_relay_is_silent() {
        let expected = WarrenPubkey::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes(),
        );
        let (conn, _s, _c) = loopback_with_mock_proof(MockProof::Silent).await;
        // The client opens the auth stream but the relay never answers; the
        // bounded read must surface a RelayIdentity error rather than hang.
        // Injects a short timeout instead of paying the real 5 s
        // `RELAY_PROOF_TIMEOUT` in wall-clock time; the mock relay's own
        // 30 s sleep is irrelevant since the client must time out first
        // regardless of which timeout duration is used.
        let short_timeout = Duration::from_millis(150);
        let err = tokio::time::timeout(
            short_timeout + Duration::from_secs(2),
            MultiHopClient::verify_relay_proof_with_timeout(&conn, &expected, short_timeout),
        )
        .await
        .expect("verify_relay_proof must respect its own timeout, not hang")
        .expect_err("a silent relay must fail the identity check");
        assert!(
            matches!(err, MultiHopError::RelayIdentity(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_epoch_rejects_before_paying_for_the_open() {
        let replay = Mutex::new(ReplayState::new());
        let err = open_replay_gated(&replay, 99, 0, || {
            panic!("the AEAD open must not run for a frame from an unknown epoch")
        })
        .expect_err("unknown epoch is a replay reject");
        assert!(matches!(err, MultiHopError::Replay { epoch: 99, .. }));
    }

    #[test]
    fn pending_epoch_slot_flags_the_old_epoch_fallback() {
        let mut state = ReplayState::new();
        state.current = EpochReplay {
            epoch: 1,
            window: ReplayWindow::new(),
        };
        state.pending = Some(EpochReplay {
            epoch: 0,
            window: ReplayWindow::new(),
        });
        let replay = Mutex::new(state);
        let (_, pending) =
            open_replay_gated(&replay, 0, 3, || Ok(vec![])).expect("old-epoch straggler accepted");
        assert!(pending, "epoch 0 lives in the pending slot");
        let (_, pending) =
            open_replay_gated(&replay, 1, 3, || Ok(vec![])).expect("current-epoch frame accepted");
        assert!(!pending, "epoch 1 is the current slot");
    }

    #[test]
    fn rekey_policy_default_is_conservative() {
        // The design mandates rekey < 8 h. Both default thresholds
        // must sit well below the AEAD / wall-clock ceiling so a long
        // session never approaches a NIST SP 800-38D-violating regime.
        let p = RekeyPolicy::default();
        assert!(
            p.max_age < Duration::from_secs(8 * 3600),
            "default rekey age must be < 8 h, got {:?}",
            p.max_age
        );
        assert!(
            p.max_frames < (1u64 << 32),
            "default rekey frame count must be < 2^32, got {}",
            p.max_frames
        );
        assert!(
            p.max_frames > 0,
            "default rekey frame count must be positive"
        );
    }

    #[test]
    fn metrics_snapshot_observes_each_atomic_independently() {
        // Mutate each counter from the inside of the module (the
        // fields are crate-private) and verify the snapshot reflects
        // each value separately. Anchors the field <-> snapshot
        // mapping so a typo (e.g. swapping frames_sent and
        // frames_recv) is caught before the metrics ship.
        let m = MultiHopMetrics::default();
        m.frames_sent.fetch_add(11, Ordering::Relaxed);
        m.frames_recv.fetch_add(22, Ordering::Relaxed);
        m.bytes_sent.fetch_add(33, Ordering::Relaxed);
        m.bytes_recv.fetch_add(44, Ordering::Relaxed);
        m.rekey_count.fetch_add(55, Ordering::Relaxed);
        m.replay_rejects.fetch_add(66, Ordering::Relaxed);
        m.decode_errors.fetch_add(77, Ordering::Relaxed);
        m.unexpected_exit_id.fetch_add(88, Ordering::Relaxed);
        m.decode_fallback_to_old_epoch
            .fetch_add(99, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.frames_sent, 11);
        assert_eq!(s.frames_recv, 22);
        assert_eq!(s.bytes_sent, 33);
        assert_eq!(s.bytes_recv, 44);
        assert_eq!(s.rekey_count, 55);
        assert_eq!(s.replay_rejects, 66);
        assert_eq!(s.decode_errors, 77);
        assert_eq!(s.unexpected_exit_id, 88);
        assert_eq!(s.decode_fallback_to_old_epoch, 99);
    }

    #[test]
    fn multi_hop_error_replay_renders_seq_and_epoch_in_display() {
        // The Display impl from `thiserror` must surface both fields
        // so the no-pubkey/no-IP logs still convey actionable context
        // when a frame is replay-rejected.
        let err = MultiHopError::Replay {
            epoch: 7,
            seq: 12345,
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("7") && rendered.contains("12345"),
            "expected seq and epoch in error rendering, got `{rendered}`"
        );
    }

    #[test]
    fn rejection_from_conn_error_maps_the_opaque_exit_close_code() {
        // Wire contract: the exit closes EVERY refused multi-hop session
        // with the single opaque code; the client MUST decode it to a
        // (generic) RejectionReason so the supervisor surfaces a clean
        // fatal instead of hot-looping. A drift here silently reopens the
        // reconnect-storm bug.
        let err = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(warrenguard_multihop::WARREN_MH_REJECTED),
            reason: bytes::Bytes::from_static(b""),
        });
        assert_eq!(
            rejection_from_conn_error(&err),
            Some(RejectionReason::PolicyRefused)
        );
    }

    #[test]
    fn rejection_from_conn_error_ignores_transient_and_unknown_closes() {
        // A transient network loss (timeout, reset) must NOT be mistaken
        // for a definitive rejection, or a recoverable blip would be
        // escalated to a blocked error state. Likewise an unrecognized
        // application close code is not a rejection, and reason bytes
        // alone must never map (the wire contract is the code; matching
        // free-form bytes would reintroduce a spoofable side channel).
        assert_eq!(
            rejection_from_conn_error(&quinn::ConnectionError::TimedOut),
            None
        );
        for reason_bytes in [&b"benign"[..], b"not-allowlisted", b"ip-pool-exhausted"] {
            let unknown = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0),
                reason: bytes::Bytes::copy_from_slice(reason_bytes),
            });
            assert_eq!(rejection_from_conn_error(&unknown), None);
        }
    }

    #[test]
    fn dial_refusal_classifies_the_entry_connection_refused_close() {
        // A drained entry relay answers every new dial with the QUIC
        // CONNECTION_REFUSED transport close. Missing this classification
        // reintroduces the observed refusal storm: the supervisor backoff
        // hammers the same drained node instead of letting the deployer
        // retarget (5160 refusals in 19 minutes on a real rollout).
        let err = MultiHopError::Handshake(quinn::ConnectionError::ConnectionClosed(
            quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::CONNECTION_REFUSED,
                frame_type: None,
                reason: bytes::Bytes::from_static(b""),
            },
        ));
        assert_eq!(err.dial_refusal(), Some(DialRefusedHop::Entry));
        // The refusal stays retriable: the retry loop keeps running so a
        // deployer retarget is picked up on the next attempt.
        assert!(err.is_retriable());
    }

    #[test]
    fn dial_refusal_classifies_the_exit_drain_close_on_dial_and_recv() {
        // The exit's maintenance-drain close is a refusal for a NEW dial
        // whether it surfaces during the handshake or on the first read.
        for make in [MultiHopError::Handshake, MultiHopError::Recv] {
            let err = make(quinn::ConnectionError::ApplicationClosed(
                quinn::ApplicationClose {
                    error_code: quinn::VarInt::from_u32(warrenguard_multihop::WARREN_MH_DRAINING),
                    reason: bytes::Bytes::from_static(b""),
                },
            ));
            assert_eq!(err.dial_refusal(), Some(DialRefusedHop::Exit));
        }
    }

    #[test]
    fn dial_refusal_ignores_transient_and_policy_closes() {
        // Transient losses and the policy-rejection close must NOT read
        // as a drain refusal: the policy path has its own fatal handling
        // (RejectionReason) and a timeout is a blip worth plain retrying.
        assert_eq!(
            MultiHopError::Handshake(quinn::ConnectionError::TimedOut).dial_refusal(),
            None
        );
        let policy = MultiHopError::Handshake(quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(warrenguard_multihop::WARREN_MH_REJECTED),
                reason: bytes::Bytes::from_static(b""),
            },
        ));
        assert_eq!(policy.dial_refusal(), None);
        let other_transport_close = MultiHopError::Handshake(
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: quinn::TransportErrorCode::INTERNAL_ERROR,
                frame_type: None,
                reason: bytes::Bytes::from_static(b""),
            }),
        );
        assert_eq!(other_transport_close.dial_refusal(), None);
    }

    #[test]
    fn retryability_verdicts_pin_the_reconnect_policy() {
        use warrenguard_wire::{FatalCause, Retryability};
        // A policy rejection is fatal and STOPS the supervisor (never a silent
        // reconnect loop): the single most important arm of this classifier.
        assert_eq!(
            MultiHopError::Rejected(RejectionReason::NotAllowlisted).retryability(),
            Retryability::Fatal(FatalCause::NotAuthorized)
        );
        // Exhaustion reselects rather than surfacing fatal.
        assert_eq!(
            MultiHopError::Rejected(RejectionReason::IpExhausted).retryability(),
            Retryability::RetryReselect
        );
        // A drained-exit dial refusal reselects a different exit.
        let drain = MultiHopError::Handshake(quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(warrenguard_multihop::WARREN_MH_DRAINING),
                reason: bytes::Bytes::from_static(b""),
            },
        ));
        assert_eq!(drain.retryability(), Retryability::RetryReselect);
        // A plain timeout retries the same target.
        assert_eq!(
            MultiHopError::Handshake(quinn::ConnectionError::TimedOut).retryability(),
            Retryability::RetrySameTarget
        );
    }

    #[test]
    fn is_retriable_yes_for_transient_network_errors() {
        // Anti-regression: every error variant that maps to a network
        // condition the cold-start backoff is supposed to absorb must
        // be flagged retriable. A drift here would silently make
        // connect_with_retry burn the first attempt and return.
        assert!(
            MultiHopError::Bind {
                addr: "127.0.0.1:0".parse().expect("static addr parses"),
                source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "test"),
            }
            .is_retriable()
        );
        assert!(MultiHopError::Handshake(quinn::ConnectionError::TimedOut).is_retriable());
        // A failed armed carrier is treated like a handshake failure: a
        // UDP-hostile network can be transiently TCP-hostile, and the
        // descriptor/PKI have already verified, so a redial is worthwhile.
        assert!(MultiHopError::TcpFallback(std::io::Error::other("carrier failed")).is_retriable());
    }

    /// A minimal descriptor for the arming decision (signature/keys unused by
    /// `carrier_armed`, which reads only `tcp_fallback` + `cover_domain`).
    fn armed_probe_descriptor(
        tcp_fallback: bool,
        cover_domain: Option<&str>,
    ) -> RelayDescriptorSigned {
        RelayDescriptorSigned {
            relay_id: [0u8; 16],
            relay_ed25519_pubkey: [0u8; 32],
            endpoint: "127.0.0.1:1".parse().expect("static addr parses"),
            cover_domain: cover_domain.map(str::to_owned),
            tcp_fallback,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn carrier_armed_requires_both_the_advert_and_a_cover_domain() {
        assert!(
            carrier_armed(&armed_probe_descriptor(true, Some("cover.example"))),
            "advertised carrier + cover domain must arm the carrier"
        );
        assert!(
            !carrier_armed(&armed_probe_descriptor(true, None)),
            "an RPK relay (no cover domain) must never arm the carrier even with tcp_fallback set"
        );
        assert!(
            !carrier_armed(&armed_probe_descriptor(false, Some("cover.example"))),
            "a relay that does not advertise the carrier must stay UDP-only"
        );
        assert!(
            !carrier_armed(&armed_probe_descriptor(false, None)),
            "neither advertised nor cover-capable must stay UDP-only"
        );
    }

    /// `(ca_der, leaf_chain_der, leaf_key_pkcs8_der)` for `cover_domain`: a
    /// throwaway CA and a leaf it signs, so a WebPKI handshake trusting the CA
    /// validates a server presenting the leaf. Mirrors the relay C2 X.509 test.
    fn mint_cover_ca_and_leaf(cover_domain: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("self-signed CA");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_params =
            CertificateParams::new(vec![cover_domain.to_owned()]).expect("leaf params");
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("CA-signed leaf");
        (
            ca.der().to_vec(),
            leaf.der().to_vec(),
            leaf_key.serialize_der(),
        )
    }

    /// End-to-end: with the relay's UDP endpoint black-holed, `dial_relay` must
    /// fall back to the TLS-over-TCP carrier and complete the relay QUIC
    /// handshake through it. The inner relay QUIC server presents a cover-domain
    /// X.509 cert on loopback UDP; a TCP terminator fronts it with the outer
    /// cover-TLS and shuttles de-encapsulated datagrams to it; the descriptor
    /// arms the carrier and points UDP at a bound-but-silent socket. The
    /// `#[cfg(test)]` seams trust the throwaway CA on both TLS layers and
    /// redirect the carrier off `:443` to the loopback terminator (production
    /// stays on Mozilla roots + `:443`).
    #[tokio::test]
    async fn udp_blocked_relay_completes_the_handshake_over_the_tcp_carrier() {
        use std::net::Ipv4Addr;

        use ed25519_dalek::Signer;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::net::{TcpListener, UdpSocket};
        use warrenguard_multihop::relay_descriptor_signing_payload;
        use warrenguard_multihop::test_support::{derive_exit_keypair, pubkey_to_bytes};
        use warrenguard_tcp_fallback::terminate_carrier;
        use warrenguard_tcp_fallback::tls::cover_tls_acceptor;
        use warrenguard_transport_core::warren_transport_config_client_multihop_with_gso;

        let cover_domain = "cover.warrenguard.test";
        let (ca_der, leaf_der, leaf_key_der) = mint_cover_ca_and_leaf(cover_domain);
        let transport = warren_transport_config_client_multihop_with_gso(false);

        // Inner relay QUIC server (cover-domain X.509) on loopback UDP: the
        // dispatcher the terminator shuttles to. Applying the same multihop
        // transport config to both ends keeps the handshake loopback-safe.
        let inner_chain = vec![CertificateDer::from(leaf_der.clone())];
        let inner_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der.clone()));
        let mut relay_server_cfg = warrenguard_tls::make_server_config_x509(
            inner_chain,
            inner_key,
            default_crypto_provider(),
            &[ALPN_H3],
        )
        .expect("inner relay x509 server config");
        relay_server_cfg.transport_config(transport.clone());
        let relay_ep = Endpoint::server(relay_server_cfg, (Ipv4Addr::LOCALHOST, 0).into())
            .expect("inner relay quinn server binds");
        let dispatcher = relay_ep.local_addr().expect("inner relay addr");
        let accept_ep = relay_ep.clone();
        let relay_accept = tokio::spawn(async move {
            if let Some(incoming) = accept_ep.accept().await
                && let Ok(conn) = incoming.await
            {
                conn.closed().await;
            }
        });

        // Outer carrier terminator: a cover-TLS acceptor on a loopback TCP port
        // (the carrier target), shuttling to the inner relay QUIC server.
        let cover_chain = vec![CertificateDer::from(leaf_der)];
        let cover_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der));
        let cover_server_cfg = Arc::new(
            warrenguard_tls::build_server_rustls_config_x509(
                cover_chain,
                cover_key,
                default_crypto_provider(),
                crate::tcp_fallback::COVER_TCP_ALPN,
            )
            .expect("cover-TLS server config"),
        );
        let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("carrier TCP listener binds");
        let carrier_addr = tcp_listener.local_addr().expect("carrier TCP addr");
        let term_task = tokio::spawn(async move {
            if let Ok((tcp, _peer)) = tcp_listener.accept().await
                && let Ok(tls) = cover_tls_acceptor(cover_server_cfg).accept(tcp).await
            {
                let _ = terminate_carrier(tls, dispatcher).await;
            }
        });

        // A bound-but-silent UDP socket: the descriptor's UDP endpoint. Nothing
        // ever answers, so the UDP handshake times out and the carrier takes
        // over (deterministic, unlike a closed port's OS-dependent ICMP).
        let dead_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("silent UDP socket binds");
        let dead_addr = dead_udp.local_addr().expect("silent UDP addr");

        arm_test_carrier(vec![ca_der], carrier_addr);

        let operational = SigningKey::from_bytes(&[0x42; 32]);
        let relay_id = [0xAB; 16];
        // Only feeds the in-band relay-auth proof, which `connect` defers to the
        // first setup exchange (not reached here); the descriptor signature is
        // over relay_id + relay_ed25519_pubkey.
        let relay_pubkey = [0x11u8; 32];
        let signature = operational
            .sign(&relay_descriptor_signing_payload(&relay_id, &relay_pubkey))
            .to_bytes();
        let relay = RelayDescriptorSigned {
            relay_id,
            relay_ed25519_pubkey: relay_pubkey,
            endpoint: dead_addr,
            cover_domain: Some(cover_domain.to_owned()),
            tcp_fallback: true,
            signature,
        };

        let (_exit_priv, exit_pub) = derive_exit_keypair(&[0x99; 32]);
        let exit_x25519 = pubkey_to_bytes(&exit_pub);
        let client_signing = SigningKey::from_bytes(&[0x88; 32]);

        let client = MultiHopClient::connect_with_transport_config(
            &relay,
            ExitId::from_bytes([0u8; 16]),
            &exit_x25519,
            &operational.verifying_key(),
            &client_signing,
            (Ipv4Addr::LOCALHOST, 0).into(),
            transport,
            None,
        )
        .await
        .expect("carrier must complete the relay QUIC handshake when UDP is black-holed");

        // Holding the client proves a live connection came back over the
        // carrier; drop it and the sockets/tasks after the assertion.
        drop(client);
        drop(dead_udp);
        relay_accept.abort();
        term_task.abort();
    }

    #[tokio::test]
    async fn connect_with_retry_max_attempts_zero_returns_handshake_timedout() {
        // Anti-regression for the early-return contract documented at
        // the top of connect_with_retry. `max_attempts == 0` must NEVER
        // silently turn into "no dial, no error" (which would let a
        // misconfigured binary boot without ever touching the network
        // and stay up indefinitely with a dead `Arc<MultiHopClient>`).
        // The synthetic `Handshake(TimedOut)` is documented in the
        // function's `# Errors` section.
        use ed25519_dalek::SigningKey;

        let dummy_op = SigningKey::from_bytes(&[0x42; 32]);
        let dummy_client = SigningKey::from_bytes(&[0x88; 32]);
        let dummy_relay = warrenguard_multihop::RelayDescriptorSigned {
            relay_id: [0u8; 16],
            relay_ed25519_pubkey: [0u8; 32],
            endpoint: "127.0.0.1:1".parse().expect("static addr parses"),
            cover_domain: None,
            tcp_fallback: false,
            signature: [0u8; 64],
        };

        let result = MultiHopClient::connect_with_retry(
            &dummy_relay,
            warrenguard_multihop::ExitId::from_bytes([0u8; 16]),
            &[0u8; 32],
            &dummy_op.verifying_key(),
            &dummy_client,
            "0.0.0.0:0".parse().expect("static addr parses"),
            true,
            false,
            None,
            Backoff::HANDSHAKE,
            0,
        )
        .await;

        match result {
            Err(MultiHopError::Handshake(quinn::ConnectionError::TimedOut)) => {}
            Err(other) => panic!(
                "max_attempts=0 must short-circuit with Handshake(TimedOut), got Err({other})"
            ),
            Ok(_) => {
                panic!("max_attempts=0 must short-circuit with Err(Handshake(TimedOut)), got Ok(_)")
            }
        }
    }

    #[test]
    fn is_retriable_no_for_configuration_errors() {
        // Anti-regression: PKI / wire decode / replay errors must NOT
        // trigger a retry. Their cause is structural (bad descriptor,
        // tampered frame), so retrying would just burn attempts.
        assert!(
            !MultiHopError::RelayPki(warrenguard_multihop::RelayPkiError::BadSignature)
                .is_retriable()
        );
        assert!(!MultiHopError::UnexpectedExitId.is_retriable());
        assert!(!MultiHopError::Replay { epoch: 0, seq: 0 }.is_retriable());
    }

    #[test]
    fn multi_hop_error_unexpected_exit_id_renders_without_pubkey() {
        // The error type carries no pubkey bytes by design; verify
        // the Display impl does not invent one (CLAUDE.md § 6 forbids
        // logging client identifiers).
        let err = MultiHopError::UnexpectedExitId;
        let rendered = err.to_string();
        assert!(
            !rendered.contains("0x")
                && !rendered.contains("01020304")
                && rendered.contains("exit_id"),
            "expected a clean error string, got `{rendered}`"
        );
    }

    // ------------------------------------------------------------------
    // should_rekey / rekey (live loopback, pure-logic thresholds)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn should_rekey_true_only_at_or_past_the_frame_count_threshold() {
        let mut pair =
            crate::test_support::spawn_loopback_multihop(ExitId::from_bytes([0x61; 16])).await;
        Arc::get_mut(&mut pair.client)
            .expect("sole owner before any clone")
            .set_rekey_policy(RekeyPolicy {
                max_frames: 5,
                max_age: Duration::from_secs(3600),
            });
        assert!(
            !pair.client.should_rekey(4),
            "below the frame threshold must not rekey"
        );
        assert!(
            pair.client.should_rekey(5),
            "at the frame threshold must rekey"
        );
        assert!(
            pair.client.should_rekey(6),
            "past the frame threshold must rekey"
        );
    }

    #[tokio::test]
    async fn should_rekey_true_once_the_age_threshold_elapses() {
        let mut pair =
            crate::test_support::spawn_loopback_multihop(ExitId::from_bytes([0x62; 16])).await;
        Arc::get_mut(&mut pair.client)
            .expect("sole owner before any clone")
            .set_rekey_policy(RekeyPolicy {
                max_frames: u64::MAX,
                max_age: Duration::from_millis(20),
            });
        assert!(
            !pair.client.should_rekey(0),
            "a fresh session under the age threshold must not rekey"
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            pair.client.should_rekey(0),
            "past the age threshold must rekey regardless of frame count"
        );
    }

    #[tokio::test]
    async fn rekey_round_trip_new_epoch_frame_decrypts_in_both_directions() {
        let mut pair =
            crate::test_support::spawn_loopback_multihop(ExitId::from_bytes([0x63; 16])).await;

        // Uplink before the rekey: epoch 0.
        pair.client
            .send(b"\x45pre-rekey")
            .await
            .expect("send epoch 0");
        let wire0 = tokio::time::timeout(Duration::from_secs(2), pair.exit_conn.read_datagram())
            .await
            .expect("must not time out")
            .expect("datagram");
        let frame0 = decode_frame(&wire0).expect("decode epoch-0 frame");
        assert_eq!(frame0.epoch, 0);

        let new_epoch = pair.client.rekey().expect("rekey must succeed");
        assert_eq!(new_epoch, 1, "the first rekey must move epoch 0 -> 1");

        // Uplink after the rekey: epoch 1, seq counter reset to 0.
        pair.client
            .send(b"\x45post-rekey")
            .await
            .expect("send epoch 1");
        let wire1 = tokio::time::timeout(Duration::from_secs(2), pair.exit_conn.read_datagram())
            .await
            .expect("must not time out")
            .expect("datagram");
        let frame1 = decode_frame(&wire1).expect("decode epoch-1 frame");
        assert_eq!(
            frame1.epoch, 1,
            "post-rekey frames must carry the new epoch"
        );
        assert_eq!(frame1.seq, 0, "the forward seq counter must reset on rekey");

        // Downlink round-trip: a real exit re-derives its receiver context
        // from the new epoch's encapsulated_key on seeing this first
        // post-rekey frame; mirror that, then confirm the client's own
        // `recv()` (which gates on the SAME new epoch) opens it correctly.
        pair.rebuild_exit_session_for_current_epoch();
        let reply = pair
            .exit_session
            .seal_response(b"\x45reply-epoch-1", new_epoch, 0)
            .expect("seal_response");
        let reply_wire = encode_frame(&reply).expect("encode_frame");
        pair.exit_conn
            .send_datagram(bytes::Bytes::from(reply_wire))
            .expect("send_datagram");
        let recovered = tokio::time::timeout(Duration::from_secs(2), pair.client.recv())
            .await
            .expect("must not time out")
            .expect("recv must decrypt the new-epoch reply");
        assert_eq!(recovered, b"\x45reply-epoch-1");
    }

    #[tokio::test]
    async fn setup_over_stream_populates_the_ip_assignment_v1() {
        // The classical capture, unchanged: a `/v1` setup reply carrying
        // `IpAssign` must land in `assignment()`. Guards the shared-parse
        // refactor (`open_setup_reply` now delegates to
        // `ip_assignment_from_setup_plaintext`) against a `/v1` regression.
        let pair =
            crate::test_support::spawn_loopback_multihop(ExitId::from_bytes([0x64; 16])).await;
        assert!(
            pair.client.assignment().is_none(),
            "no assignment before the setup exchange"
        );

        let server_task = pair.spawn_setup_stream_server();
        pair.client
            .setup_over_stream(None, false, false)
            .await
            .expect("setup_over_stream must succeed");
        server_task.await.expect("server task");

        let assignment = pair
            .client
            .assignment()
            .expect("a /v1 setup reply carrying IpAssign must populate assignment()");
        assert_eq!(assignment.ipv4, [10, 66, 0, 2]);
        assert_eq!(assignment.prefix_len, 24);
        assert_eq!(assignment.gateway_ipv4, [10, 66, 0, 1]);
        assert_eq!(
            pair.client.assigned_ipv4(),
            Some(std::net::Ipv4Addr::new(10, 66, 0, 2))
        );
    }

    // ------------------------------------------------------------------
    // `/v2` PQ (X-Wing) twins of the rekey tests above, plus the
    // resend-until-ack state machine itself.
    // ------------------------------------------------------------------

    #[cfg(feature = "pq-hpke")]
    mod pq_tests {
        use super::*;
        use warrenguard_multihop::WarrenMultihopFrameV2;

        #[tokio::test]
        async fn full_size_payload_after_rekey_must_not_be_dropped_as_too_large_pq() {
            let pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x75; 16]))
                    .await;
            pair.client.rekey().expect("rekey must succeed");

            // Mirrors a real deployer: the TUN MTU is sized against the small
            // classical overhead, not per-session/version-aware. This payload
            // fits comfortably if sealed with no `pq_ct` attached, but a
            // rekey's ML-KEM ciphertext (1088 B) blows the path datagram cap
            // if it ever rides a full-size DATA frame.
            let path_datagram_cap = pair
                .client
                .max_datagram_size()
                .expect("an established QUIC connection reports a datagram size");
            let payload_len = path_datagram_cap.saturating_sub(200);
            let payload = vec![0x41u8; payload_len];

            let result = pair.client.send(&payload).await;
            assert!(
                !matches!(
                    result,
                    Err(MultiHopError::Send(quinn::SendDatagramError::TooLarge))
                ),
                "a full-size payload right after a PQ rekey must not be dropped as \
                 oversized; the epoch bootstrap must never ride a DATA frame, got {result:?}"
            );
        }

        #[tokio::test]
        async fn max_inner_payload_v2_reflects_the_data_frame_not_the_setup_bound() {
            // Once the ML-KEM ciphertext is decoupled onto its own empty-payload
            // bootstrap ping, a `/v2` DATA frame never carries `pq_ct`, so the
            // advertised inner-payload budget must reflect the small data-frame
            // overhead, not the ~1.1 KB setup-frame bound. A deployer sizes the
            // tunnel MTU from this value, so reserving the pq_ct space here
            // silently starves every `/v2` session of ~1088 bytes of payload.
            let pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x78; 16]))
                    .await;
            let path = pair
                .client
                .max_datagram_size()
                .expect("an established QUIC connection reports a datagram size");
            let budget = pair.client.max_inner_payload();
            assert!(
                budget >= path.saturating_sub(128),
                "a /v2 session's max_inner_payload ({budget}) must sit within a small \
                 data-frame overhead of the path MTU ({path}), not be starved by the \
                 1088-byte pq_ct that steady-state data frames no longer carry"
            );

            // The advertised budget must also be genuinely sendable in one
            // datagram: guards the fix from over-correcting past the true cap.
            let payload = vec![0x41u8; budget];
            let result = pair.client.send(&payload).await;
            assert!(
                !matches!(
                    result,
                    Err(MultiHopError::Send(quinn::SendDatagramError::TooLarge))
                ),
                "a payload sized to max_inner_payload must fit in one datagram, got {result:?}"
            );
        }

        #[tokio::test]
        async fn should_rekey_true_only_at_or_past_the_frame_count_threshold_pq() {
            let mut pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x71; 16]))
                    .await;
            Arc::get_mut(&mut pair.client)
                .expect("sole owner before any clone")
                .set_rekey_policy(RekeyPolicy {
                    max_frames: 5,
                    max_age: Duration::from_secs(3600),
                });
            assert!(
                !pair.client.should_rekey(4),
                "below the frame threshold must not rekey"
            );
            assert!(
                pair.client.should_rekey(5),
                "at the frame threshold must rekey"
            );
            assert!(
                pair.client.should_rekey(6),
                "past the frame threshold must rekey"
            );
        }

        #[tokio::test]
        async fn should_rekey_true_once_the_age_threshold_elapses_pq() {
            let mut pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x72; 16]))
                    .await;
            Arc::get_mut(&mut pair.client)
                .expect("sole owner before any clone")
                .set_rekey_policy(RekeyPolicy {
                    max_frames: u64::MAX,
                    max_age: Duration::from_millis(20),
                });
            assert!(
                !pair.client.should_rekey(0),
                "a fresh session under the age threshold must not rekey"
            );
            tokio::time::sleep(Duration::from_millis(60)).await;
            assert!(
                pair.client.should_rekey(0),
                "past the age threshold must rekey regardless of frame count"
            );
        }

        /// Reads and decodes the next raw `/v2` datagram the client sent,
        /// with the same 2 s bound every other loopback test in this module
        /// uses.
        async fn recv_v2_frame(exit_conn: &Connection) -> WarrenMultihopFrameV2 {
            let wire = tokio::time::timeout(Duration::from_secs(2), exit_conn.read_datagram())
                .await
                .expect("must not time out")
                .expect("datagram");
            decode_frame_v2(&wire).expect("decode v2 frame")
        }

        #[tokio::test]
        async fn rekey_round_trip_new_epoch_frame_decrypts_in_both_directions_pq() {
            let mut pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x73; 16]))
                    .await;

            // Epoch 0 was never acked (no `setup_over_stream` in this raw
            // datagram-only harness): the first `send` bootstraps it with its
            // own dedicated ping (empty payload, carries pq_ct) BEFORE the
            // actual DATA frame, so the caller's payload itself never needs
            // to carry pq_ct even on the very first packet.
            pair.client
                .send(b"\x45pre-rekey")
                .await
                .expect("send epoch 0");
            let ping0 = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(ping0.epoch, 0);
            assert!(
                !ping0.pq_ct.is_empty(),
                "the epoch-0 bootstrap ping must carry pq_ct"
            );
            assert!(
                pair.exit_session
                    .open(&ping0)
                    .expect("exit opens the bootstrap ping")
                    .is_empty(),
                "the bootstrap ping payload is empty"
            );
            let frame0 = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(frame0.epoch, 0);
            assert!(
                frame0.pq_ct.is_empty(),
                "a DATA frame must never carry pq_ct, even unacked"
            );
            assert_eq!(
                pair.exit_session
                    .open(&frame0)
                    .expect("exit opens epoch-0 frame"),
                b"\x45pre-rekey"
            );

            let new_epoch = pair.client.rekey().expect("rekey must succeed");
            assert_eq!(new_epoch, 1, "the first rekey must move epoch 0 -> 1");

            // `rekey()` immediately emits the new epoch's own bootstrap ping,
            // decoupled from any caller send.
            let ping1 = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(ping1.epoch, new_epoch);
            assert!(
                !ping1.pq_ct.is_empty(),
                "the rekey bootstrap ping must carry pq_ct"
            );

            // First post-rekey DATA frame: still unacked, but the doctrine
            // overlap keeps epoch 0 alive, so it rides there with NO pq_ct
            // instead of oversizing the new (not yet established) epoch.
            pair.client
                .send(b"\x45post-rekey")
                .await
                .expect("send epoch 1");
            let frame1 = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(
                frame1.epoch, 0,
                "an unacked rekey's DATA frames keep riding the OLD, \
                 already-established epoch"
            );
            assert!(
                frame1.pq_ct.is_empty(),
                "a DATA frame must never carry pq_ct"
            );
            assert_eq!(
                pair.exit_session
                    .open(&frame1)
                    .expect("the OLD exit session still opens it"),
                b"\x45post-rekey"
            );

            // Downlink round-trip: the exit establishes its receiver context
            // for the new epoch from the bootstrap ping's
            // `(encapsulated_key, pq_ct)`; mirror that, then confirm the
            // client's own `recv()` (gated on the SAME new epoch) opens it
            // AND flips the resend-until-ack flag.
            pair.rebuild_exit_session_for_current_epoch();
            let reply = pair
                .exit_session
                .seal_response(b"\x45reply-epoch-1", new_epoch, 0)
                .expect("seal_response");
            let reply_wire = encode_frame_v2(&reply).expect("encode_frame_v2");
            pair.exit_conn
                .send_datagram(bytes::Bytes::from(reply_wire))
                .expect("send_datagram");
            let recovered = tokio::time::timeout(Duration::from_secs(2), pair.client.recv())
                .await
                .expect("must not time out")
                .expect("recv must decrypt the new-epoch reply");
            assert_eq!(recovered, b"\x45reply-epoch-1");

            // Acked now: the NEXT forward frame moves to the new epoch, and
            // still carries no pq_ct.
            pair.client
                .send(b"\x45steady-state")
                .await
                .expect("send steady-state frame");
            let frame2 = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(frame2.epoch, 1);
            assert!(
                frame2.pq_ct.is_empty(),
                "an acked epoch's steady-state frames must not carry pq_ct"
            );
            assert_eq!(
                pair.exit_session
                    .open(&frame2)
                    .expect("the new exit session opens the steady-state frame"),
                b"\x45steady-state"
            );
        }

        #[tokio::test]
        async fn resend_until_ack_state_machine_stops_pinging_after_ack() {
            // Focused unit test for the resend-until-ack policy, decoupled
            // from the full rekey round trip above: after `rekey()`, DATA
            // frames must never carry `pq_ct` (old epoch while unacked, new
            // epoch after ack); only the dedicated bootstrap ping does, and
            // it must stop being resent once a reverse frame on the new
            // epoch is observed via `recv()`/`decode_and_open_reply`.
            let mut pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x74; 16]))
                    .await;
            let new_epoch = pair.client.rekey().expect("rekey must succeed");

            let ping = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(ping.epoch, new_epoch);
            assert!(
                !ping.pq_ct.is_empty(),
                "the bootstrap ping must carry pq_ct"
            );

            // While unacked, DATA frames ride the OLD epoch with no pq_ct,
            // and (rate-limited well past this loop's duration) the ping is
            // not resent.
            for _ in 0..3 {
                pair.client
                    .send(b"\x45unacked")
                    .await
                    .expect("send before ack");
                let frame = recv_v2_frame(&pair.exit_conn).await;
                assert_eq!(frame.epoch, 0, "DATA frames stay on the old epoch");
                assert!(
                    frame.pq_ct.is_empty(),
                    "a DATA frame must never carry pq_ct"
                );
            }

            // Ack: the exit answers on the new epoch.
            pair.rebuild_exit_session_for_current_epoch();
            let reply = pair
                .exit_session
                .seal_response(b"\x45ack", new_epoch, 0)
                .expect("seal_response");
            let reply_wire = encode_frame_v2(&reply).expect("encode_frame_v2");
            pair.exit_conn
                .send_datagram(bytes::Bytes::from(reply_wire))
                .expect("send_datagram");
            tokio::time::timeout(Duration::from_secs(2), pair.client.recv())
                .await
                .expect("must not time out")
                .expect("recv must decrypt the ack");

            // Every subsequent frame moves to the new epoch and still never
            // carries pq_ct.
            for _ in 0..3 {
                pair.client
                    .send(b"\x45steady")
                    .await
                    .expect("send after ack");
                let frame = recv_v2_frame(&pair.exit_conn).await;
                assert_eq!(frame.epoch, new_epoch);
                assert!(
                    frame.pq_ct.is_empty(),
                    "frames after the ack must not carry pq_ct"
                );
            }
        }

        #[tokio::test]
        async fn pq_setup_ping_is_resent_after_the_rate_limit_interval() {
            // Covers the "re-emit it (rate-limited) while the epoch stays
            // unacked" half of the bootstrap design: a `send_packet` call
            // long after the last ping must trigger another one, ahead of
            // the caller's own DATA frame.
            let pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x76; 16]))
                    .await;
            let new_epoch = pair.client.rekey().expect("rekey must succeed");

            let first_ping = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(first_ping.epoch, new_epoch);

            tokio::time::sleep(PQ_SETUP_PING_RESEND_INTERVAL + Duration::from_millis(50)).await;
            pair.client
                .send(b"\x45after-the-interval")
                .await
                .expect("send after the resend interval");

            let resent_ping = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(resent_ping.epoch, new_epoch);
            assert!(
                !resent_ping.pq_ct.is_empty(),
                "the resent ping must still carry pq_ct"
            );

            let data = recv_v2_frame(&pair.exit_conn).await;
            assert!(
                data.pq_ct.is_empty(),
                "the caller's own DATA frame must never carry pq_ct"
            );
        }

        #[tokio::test]
        async fn epoch_zero_over_setup_stream_counts_as_acked_from_the_start() {
            // Pins the "ALSO" invariant: epoch 0's setup rides the RELIABLE
            // stream, so a successful `setup_over_stream` leaves the session
            // acked immediately, without needing to separately observe a
            // reverse datagram first.
            let pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x77; 16]))
                    .await;

            let server_task = pair.spawn_setup_stream_server();

            pair.client
                .setup_over_stream(None, false, false)
                .await
                .expect("setup_over_stream must succeed");
            server_task.await.expect("server task");

            // No `recv()` was ever called to observe a reverse datagram: if
            // the session were still unacked, this DATA frame would ride the
            // (non-existent) pending old epoch or drop under the fallback.
            // Acked-from-the-start means it seals under the current epoch
            // with no pq_ct, straight away.
            pair.client
                .send(b"\x45first-data-after-setup")
                .await
                .expect("send after setup_over_stream");
            let frame = recv_v2_frame(&pair.exit_conn).await;
            assert_eq!(frame.epoch, 0);
            assert!(
                frame.pq_ct.is_empty(),
                "epoch 0 must count as acked right after setup_over_stream, \
                 with no separate bootstrap ping needed"
            );
        }

        #[tokio::test]
        async fn setup_over_stream_populates_the_ip_assignment_pq() {
            // The bug this guards: a `/v2` (PQ X-Wing) setup must capture the
            // exit's IP allocation into `assignment()` exactly like `/v1`, or a
            // consumer that needs the tunnel IP (and `.expect()`s it) panics.
            let pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x79; 16]))
                    .await;
            assert!(
                pair.client.assignment().is_none(),
                "no assignment before the setup exchange"
            );

            let server_task = pair.spawn_setup_stream_server();
            pair.client
                .setup_over_stream(None, false, false)
                .await
                .expect("setup_over_stream must succeed");
            server_task.await.expect("server task");

            let assignment = pair.client.assignment().expect(
                "a /v2 setup reply carrying IpAssign must populate assignment(), not stay None",
            );
            // The exact allocation the loopback exit assigned in
            // `spawn_setup_stream_server`.
            assert_eq!(assignment.ipv4, [10, 88, 0, 2]);
            assert_eq!(assignment.prefix_len, 24);
            assert_eq!(assignment.gateway_ipv4, [10, 88, 0, 1]);
            assert_eq!(
                pair.client.assigned_ipv4(),
                Some(std::net::Ipv4Addr::new(10, 88, 0, 2))
            );
        }

        #[tokio::test]
        async fn a_policy_refusal_leaves_the_ip_assignment_unset_pq() {
            // A `Rejected` setup reply is best-effort: the round trip still
            // returns the opened plaintext, but `assignment()` stays `None`
            // rather than panicking, mirroring `/v1`.
            let pair =
                crate::test_support::spawn_loopback_multihop_pq(ExitId::from_bytes([0x7a; 16]))
                    .await;
            let server_task = pair.spawn_setup_stream_server_with_reply(
                warrenguard_multihop::WarrenControlMessage::Rejected,
            );
            pair.client
                .setup_over_stream(None, false, false)
                .await
                .expect("setup_over_stream returns the opened plaintext even on a refusal");
            server_task.await.expect("server task");

            assert!(
                pair.client.assignment().is_none(),
                "a Rejected setup reply must leave assignment() at None, never panic"
            );
        }
    }
}
