//! Multihop termination on the exit side.
//!
//! When `warren-exit` runs with `--multihop`, each QUIC datagram it
//! receives is a [`WarrenMultihopFrame`] sealed by a [`ClientSession`]
//! on the user's laptop, forwarded transparently through a
//! `warren-relay`, and delivered to the exit's QUIC server. The exit
//! must:
//!
//! 1. Decode the cleartext header (`exit_id`, `epoch`, `seq`,
//!    `encapsulated_key`).
//! 2. Drive an [`ExitSession`] keyed on `encapsulated_key` (one per
//!    rekey epoch on a given physical QUIC connection).
//! 3. AEAD-open the ciphertext using the per-packet exporter key
//!    (cf. `warren-multihop`'s session module docs).
//! 4. Process the recovered IP packet: [`serve_multihop_echo`] seals the
//!    plaintext straight back to the client through the
//!    reverse-direction HPKE export info (end-to-end loopback tests
//!    without a TUN), while [`serve_multihop_with_tun`] bridges it onto
//!    the exit TUN device (the production path).
//!
//! Privacy contract: no per-client identifier is logged from this
//! module. The only structured fields emitted are session counters and
//! the local bind address.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use parking_lot::Mutex;
use quinn::{Connection, DatagramClass, Endpoint, SendDatagramError, SendStream, VarInt};
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::watch;
use warrenguard_daita::daita::{DaitaEvent, DaitaState};
use warrenguard_multihop::{
    EncapsulatedKeyBytes, ExitId, ExitSession, MULTIHOP_FRAME_MAX_OVERHEAD, MultihopError,
    ReplayWindow, WARREN_MH_DRAINING, WARREN_MH_REJECTED, WarrenControlMessage,
    WarrenKemPrivateKey, WarrenKemPublicKey, WarrenMultihopFrame, decode_frame, encode_control,
    encode_frame, test_support::pubkey_to_bytes,
};
#[cfg(feature = "pq-hpke")]
use warrenguard_multihop::{
    MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD, PqExitSession, WarrenMultihopFrameV2,
    XWingRecipientSecretKey, decode_frame_v2, encode_frame_v2,
};
use warrenguard_pump::{DAITA_DUMMY_FIRST_BYTE, is_daita_dummy};
use warrenguard_server::tun_dispatch::source_ip_matches;
use warrenguard_server::{AllowlistHandle, SessionTokenAdmitter};
use warrenguard_transport_core::PacketDevice;
use warrenguard_transport_core::{build_frag_needed, clamp_syn_mss, is_tcp_syn};
use warrenguard_wire::WarrenPubkey;

use crate::ip_pool::{ConnId, IpAllocator, IpAllocatorV6, SessionIntent, SessionIntentV6};

/// Retain anti-replay windows for at most this many recent epochs. Rekeys are
/// infrequent, so a handful covers every in-flight frame around an epoch
/// boundary while bounding memory against a client that forces many rekeys.
const REPLAY_EPOCHS_KEPT: usize = 4;

/// Per-epoch anti-replay tracker for the exit receive path.
///
/// A multi-hop frame is authenticated by [`ExitSession::open`] with a
/// deterministic per-`(epoch, seq)` key, so a cryptographically blind or
/// compromised relay can replay a captured sealed frame on a fresh connection
/// and the exit would decrypt and re-inject it onto the internet. This tracks
/// accepted `(epoch, seq)` pairs in a sliding [`ReplayWindow`] per epoch and
/// rejects duplicates before the plaintext reaches the TUN. The number of
/// retained epochs is bounded ([`REPLAY_EPOCHS_KEPT`]).
#[derive(Debug, Default)]
struct EpochReplayWindows {
    windows: std::collections::HashMap<u32, ReplayWindow>,
}

impl EpochReplayWindows {
    /// Record `(epoch, seq)`; returns `Err(MultihopError::Replay)` if it was
    /// already seen, or has fallen below the active window for its epoch.
    fn check_and_record(&mut self, seq: u64, epoch: u32) -> Result<(), MultihopError> {
        self.windows
            .entry(epoch)
            .or_default()
            .check_and_record(seq, epoch)?;
        // Bound memory: keep only the most recent epochs. Evicting the oldest
        // epoch means an ancient replay (>= REPLAY_EPOCHS_KEPT rekeys old) could
        // be re-accepted, which is harmless: the client has long moved on.
        while self.windows.len() > REPLAY_EPOCHS_KEPT {
            if let Some(&oldest) = self.windows.keys().min() {
                self.windows.remove(&oldest);
            } else {
                break;
            }
        }
        Ok(())
    }
}

/// IP-nego configuration carried alongside each accepted
/// connection. Holds the host IP that was popped off the
/// [`crate::ip_pool::IpAllocator`] for this connection plus the subnet
/// parameters that the [`WarrenControlMessage::IpAssign`] needs.
///
/// `None` ⇒ IP negotiation disabled for this binary (legacy behaviour:
/// the client falls back to the hardcoded `10.66.0.2/24`). `Some` ⇒ the
/// rx loop emits exactly one `IpAssign` after the session is open, then
/// forwards regular traffic.
#[derive(Debug, Clone, Copy)]
struct IpAssignSpec {
    assigned: Ipv4Addr,
    gateway: Ipv4Addr,
    prefix_len: u8,
    /// Dual-stack: the IPv6 allocated for this conn, set only when the
    /// client asked for v6 (`IpRequest { wants_ipv6: true }`) AND the exit
    /// has a v6 allocator. `None` keeps the conn IPv4-only; the *presence*
    /// of `ipv6` in the reply is the capability echo, so a client that
    /// asked for v6 but got `None` surfaces the gap instead of silently
    /// degrading.
    assigned_v6: Option<Ipv6Addr>,
    gateway_v6: Option<Ipv6Addr>,
    prefix_len_v6: u8,
}

impl IpAssignSpec {
    /// `daita_spec` is injected here rather than stored on the spec: the
    /// spec stays `Copy` (a `DaitaConfig` is not), and the grant is decided
    /// where the reply is built, from the client's `wants_daita` and the
    /// machine this connection actually runs.
    fn into_control_message(
        self,
        daita_spec: Option<warrenguard_wire::DaitaConfig>,
    ) -> WarrenControlMessage {
        WarrenControlMessage::IpAssign {
            ipv4: self.assigned.octets(),
            prefix_len: self.prefix_len,
            gateway_ipv4: self.gateway.octets(),
            ipv6: self.assigned_v6.map(|a| a.octets()),
            prefix_len_v6: self.prefix_len_v6,
            gateway_ipv6: self.gateway_v6.map(|g| g.octets()),
            daita_spec,
        }
    }
}

/// Lazy allocation helper, called inside the rx-side loop on the FIRST
/// successfully-opened plaintext. `sticky_pubkey` is the value the sticky
/// allocator keys on across reconnects: the client's account pubkey for a v6
/// `IpRequest`, or the admitted token serial (pubkey-shaped) for a v7
/// `IpRequestV7`; `None` = a regular IP packet as the first frame (no hint).
/// `wants_ipv6` requests a dual-stack v6 allocation. `prefer_ipv4` is the
/// request's raw session-placement hint (see [`SessionIntent`]): it decides
/// whether a same-key request joins the session holding an address or gets
/// a session-fresh one; hint-less requests keep the historical sharing.
///
/// Returns `None` when the pool is exhausted **and** no sticky binding
/// could be reused. The caller then emits an
/// [`WarrenControlMessage::IpExhausted`] and closes the connection.
fn allocate_on_first_frame(
    ip_allocator: &Option<Arc<Mutex<IpAllocator>>>,
    ip_allocator_v6: &Option<Arc<Mutex<IpAllocatorV6>>>,
    conn_id: ConnId,
    sticky_pubkey: Option<[u8; 32]>,
    wants_ipv6: bool,
    prefer_ipv4: Option<[u8; 4]>,
) -> Option<IpAssignSpec> {
    let alloc = ip_allocator.as_ref()?;
    let pubkey = sticky_pubkey;
    let intent = SessionIntent::from_prefer_ipv4(prefer_ipv4);
    let mut guard = alloc.lock();
    let assigned = match pubkey {
        Some(pk) => guard.allocate_for_pubkey_with_intent(conn_id, pk, intent)?,
        None => guard.allocate(conn_id)?,
    };
    let spec_gateway = guard.gateway();
    let spec_prefix = guard.prefix_len();
    // Same-key siblings sharing the assigned v4 (the session this
    // connection joined); they anchor the v6 placement so both address
    // families land on the same session.
    let siblings: Vec<ConnId> = guard
        .conns_holding(assigned)
        .into_iter()
        .filter(|&c| c != conn_id)
        .collect();
    drop(guard);

    // Allocate an IPv6 only when the client asked for it AND the exit runs
    // a v6 allocator. A v6 allocation failure (practically unreachable on a
    // /64) degrades to v4-only rather than failing the whole conn - the
    // client's firewall keeps native v6 blocked, so this is leak-safe, and
    // the `None` reply surfaces the gap on the client.
    let (assigned_v6, gateway_v6, prefix_len_v6) = if wants_ipv6 {
        match ip_allocator_v6.as_ref() {
            Some(alloc6) => {
                let mut guard6 = alloc6.lock();
                let v6 = match pubkey {
                    Some(pk) => {
                        // The wire carries no v6 hint: project the v4
                        // placement. A joined session shares its siblings'
                        // interface ID; an independent one gets its own.
                        let intent6 = match intent {
                            SessionIntent::Legacy => SessionIntentV6::Legacy,
                            _ if !siblings.is_empty() => SessionIntentV6::Join(&siblings),
                            _ => SessionIntentV6::Fresh,
                        };
                        guard6.allocate_for_pubkey_with_intent(conn_id, pk, intent6)
                    }
                    None => guard6.allocate(conn_id),
                };
                match v6 {
                    Some(addr) => (Some(addr), Some(guard6.gateway()), 64),
                    None => (None, None, 0),
                }
            }
            None => (None, None, 0),
        }
    } else {
        (None, None, 0)
    };

    Some(IpAssignSpec {
        assigned,
        gateway: spec_gateway,
        prefix_len: spec_prefix,
        assigned_v6,
        gateway_v6,
        prefix_len_v6,
    })
}

/// H1 exit-side authorization: decide whether a multi-hop client may be
/// granted a tunnel IP, given the exit allowlist, the account pubkey
/// asserted in its setup control message, and the Ed25519 proof of
/// possession (PoP) covering this session's HPKE `encapsulated_key`.
///
/// In permissive/bench mode (`allowlist == None`) every client is admitted.
/// In strict mode the client must assert an
/// allowlisted account pubkey via the `IpRequest` `client_pubkey` field
/// AND prove possession of its private key: `pop_sig` must be a valid
/// signature by `client_pubkey` over
/// `warrenguard_multihop::pop_signing_message(exit_id, encapsulated_key)`.
///
/// SECURITY NOTE: the exit's TLS peer is the relay, not the client, so
/// without the PoP the pubkey would be self-asserted - and account pubkeys
/// are not secret (allowlist snapshots, API headers). The PoP binds the
/// assertion to this session: `encapsulated_key` is client-chosen per
/// session (cross-session replay impossible) and intra-session replay of
/// the setup frame is rejected by the session-scoped anti-replay window.
/// The signature is verified BEFORE the allowlist lookup so a forged
/// assertion never reaches the authorization data. Do NOT relax the
/// `pop_sig` requirement in strict mode - it is what turns this gate from
/// a declaration into an authentication.
fn allowlist_admits(
    allowlist: Option<&AllowlistHandle>,
    control_msg: Option<&WarrenControlMessage>,
    exit_id: &ExitId,
    encapsulated_key: &EncapsulatedKeyBytes,
) -> bool {
    let Some(allowlist) = allowlist else {
        return true;
    };
    let (asserted, pop_sig) = match control_msg {
        Some(WarrenControlMessage::IpRequest {
            client_pubkey,
            pop_sig,
            ..
        }) => (*client_pubkey, *pop_sig),
        _ => (None, None),
    };
    let (Some(pubkey), Some(sig)) = (asserted, pop_sig) else {
        // Strict mode: no pubkey or no possession proof = no egress.
        return false;
    };
    if !warrenguard_multihop::verify_pop(&pubkey, exit_id, encapsulated_key, &sig) {
        return false;
    }
    allowlist.is_allowed_at(
        &WarrenPubkey::from_bytes(pubkey),
        warrenguard_config::unix_now(),
    )
}

/// Upper bound on a single multi-hop setup-stream message
/// (`read_to_end` cap). Mirror of
/// `warrenguard_relay::MAX_MULTIHOP_SETUP_FRAME_BYTES` and the client-side
/// constant. The setup frame is one HPKE-sealed `WarrenMultihopFrame`
/// of a few hundred bytes; 64 KiB bounds the memory a hostile dialer
/// can force the exit to buffer on the setup stream.
const MAX_MULTIHOP_SETUP_FRAME_BYTES: usize = 64 * 1024;

/// How long a client setup will wait for the FIRST allowlist sync after a
/// cold start before the gate is evaluated anyway (see the call site in
/// [`process_setup_frame`]). Comfortably under the client's QUIC idle
/// timeout (the client `read_to_end`s the setup reply with no shorter
/// deadline of its own) and the refresh loop's first poll fires
/// immediately at boot, so the real wait is normally sub-second; this only
/// caps the pathological "backend down at boot with no disk cache" case.
const ALLOWLIST_FIRST_SYNC_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Bounded wait for the peer to acknowledge the sealed rejection reply
/// before the connection is closed: `Connection::close` drops stream
/// data still in flight, which would strand the detail.
const REJECT_REPLY_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// Seal `detail` to the client over the setup stream, wait (bounded) for
/// delivery, then close the relay-facing connection with the single
/// opaque policy-rejection code and EMPTY reason bytes.
///
/// Anti-oracle invariant: the exit's TLS peer on this connection is the
/// RELAY, hostile by threat model. Every policy rejection MUST produce
/// the identical close (code [`WARREN_MH_REJECTED`], no reason bytes) so
/// the relay cannot learn the client's subscription status; the cause
/// detail travels HPKE-sealed to the client only. Do not reintroduce
/// per-cause close codes or ASCII reasons on this branch.
async fn reply_sealed_detail_then_close(
    send: &mut SendStream,
    term: &SetupTermination,
    epoch: u32,
    reverse_seq: &AtomicU64,
    conn: &Connection,
    detail: &WarrenControlMessage,
) {
    if let Ok(plaintext) = encode_control(detail)
        && let Some(bytes) = term.seal_reply(
            &plaintext,
            epoch,
            reverse_seq.fetch_add(1, Ordering::AcqRel),
        )
        && send.write_all(&bytes).await.is_ok()
        && send.finish().is_ok()
    {
        // `stopped()` after `finish()` resolves once the peer has acked
        // all stream data (quinn 0.11 contract); without it the close
        // below could drop the sealed detail from flight. Bounded so a
        // peer that never acks cannot hold the rejected connection open.
        let _ = tokio::time::timeout(REJECT_REPLY_ACK_TIMEOUT, send.stopped()).await;
    }
    conn.close(quinn::VarInt::from_u32(WARREN_MH_REJECTED), &[]);
}

/// Per-connection state established during the reliable setup-stream
/// phase and handed to the datagram pump. By the time the pump runs the
/// HPKE context, the allocated IP, and the downlink route are all
/// already installed, so the datagram path only ever sees DATA frames.
struct ConnSetup {
    /// HPKE session derived from the setup frame's `encapsulated_key`.
    session: Arc<ExitSession>,
    /// Epoch of the setup frame (the pump installs `(session, epoch)`
    /// into the shared `current` slot before pumping).
    epoch: u32,
    /// IP allocated for this connection (when ip-nego is on), already
    /// announced to the client over the setup stream as an `IpAssign`.
    /// `None` when the exit runs without an allocator (legacy single
    /// client, bootstrap IP).
    assigned_ip: Option<Ipv4Addr>,
    /// Multi-hop `/v2` dual-stack: the IPv6 allocated for this conn,
    /// announced in the same setup-stream `IpAssign`. `None` when the
    /// client is v4-only or the exit has no v6 allocator. Read by the
    /// conn handler to unregister the v6 downlink route on close.
    assigned_ip_v6: Option<Ipv6Addr>,
    /// RAII registration in the live-session registry. Held here so it
    /// drops (and unregisters) exactly when the connection handler ends,
    /// whatever the exit path. `None` when no registry is wired or the
    /// client asserted no account pubkey (permissive mode). Read only via
    /// its `Drop`.
    #[allow(dead_code)]
    revocation_guard: Option<SessionGuard>,
    /// Whether the client's `IpRequest` asked for DAITA. The exit only
    /// drives its per-conn machines for a client that negotiated them:
    /// an un-negotiated peer cannot use the 0xFF dummies (legacy pumps
    /// pay a kernel-rejected TUN write per dummy) and unsolicited cover
    /// traffic blinds rx-based liveness watchdogs (2026-07-15 incident).
    wants_daita: bool,
}

/// Post-quantum (`/v2`) counterpart of [`ConnSetup`]: the established
/// [`PqExitSession`] plus the same per-connection state, handed to the PQ
/// datagram pump. Separate from [`ConnSetup`] because the two sessions are
/// distinct types sealing distinct wire frames.
#[cfg(feature = "pq-hpke")]
struct ConnSetupPq {
    session: Arc<PqExitSession>,
    epoch: u32,
    assigned_ip: Option<Ipv4Addr>,
    assigned_ip_v6: Option<Ipv6Addr>,
    #[allow(dead_code)]
    revocation_guard: Option<SessionGuard>,
}

/// Which datapath a completed setup selected. A `/v1` connection runs the
/// existing classical pump; a `/v2` connection runs the PQ pump. Homogeneous
/// per connection: the client picks one seal for the whole session.
enum SetupOutcome {
    V1(ConnSetup),
    #[cfg(feature = "pq-hpke")]
    V2(ConnSetupPq),
}

/// PQ setup material threaded through the setup path. Present only when the exit
/// was built with `pq-hpke` AND an X-Wing secret was attached
/// ([`ExitTerminateCtx::with_xwing_secret`]); absent means classical-only, so a
/// `/v2` frame is dropped rather than terminated.
#[cfg(feature = "pq-hpke")]
#[derive(Clone)]
pub(crate) struct PqSetup {
    cache: Arc<PqSessionCache>,
    secret: Arc<XWingRecipientSecretKey>,
}

/// Crypto wrapper unifying setup-frame handling across `/v1` and `/v2` so the
/// admission/allocation/registry core in [`process_setup_frame`] stays a single
/// copy. Holds the decoded setup frame, the established termination session, and
/// the session-scoped anti-replay window.
enum SetupTermination {
    V1 {
        session: Arc<ExitSession>,
        frame: WarrenMultihopFrame,
        replay: Arc<Mutex<EpochReplayWindows>>,
    },
    #[cfg(feature = "pq-hpke")]
    V2 {
        session: Arc<PqExitSession>,
        frame: WarrenMultihopFrameV2,
        replay: Arc<Mutex<EpochReplayWindows>>,
    },
}

impl SetupTermination {
    fn encapsulated_key(&self) -> EncapsulatedKeyBytes {
        match self {
            Self::V1 { frame, .. } => frame.encapsulated_key,
            #[cfg(feature = "pq-hpke")]
            Self::V2 { frame, .. } => frame.encapsulated_key,
        }
    }

    fn epoch(&self) -> u32 {
        match self {
            Self::V1 { frame, .. } => frame.epoch,
            #[cfg(feature = "pq-hpke")]
            Self::V2 { frame, .. } => frame.epoch,
        }
    }

    fn seq(&self) -> u64 {
        match self {
            Self::V1 { frame, .. } => frame.seq,
            #[cfg(feature = "pq-hpke")]
            Self::V2 { frame, .. } => frame.seq,
        }
    }

    fn replay(&self) -> &Arc<Mutex<EpochReplayWindows>> {
        match self {
            Self::V1 { replay, .. } => replay,
            #[cfg(feature = "pq-hpke")]
            Self::V2 { replay, .. } => replay,
        }
    }

    /// Open (decrypt) the setup frame with the established session.
    fn open(&self) -> Result<Vec<u8>, MultihopError> {
        match self {
            Self::V1 { session, frame, .. } => session.open(frame),
            #[cfg(feature = "pq-hpke")]
            Self::V2 { session, frame, .. } => session.open(frame),
        }
    }

    /// Seal a reply plaintext into the encoded reverse frame bytes.
    fn seal_reply(&self, plaintext: &[u8], epoch: u32, seq: u64) -> Option<Vec<u8>> {
        match self {
            Self::V1 { session, .. } => session
                .seal_response(plaintext, epoch, seq)
                .ok()
                .and_then(|f| encode_frame(&f).ok()),
            #[cfg(feature = "pq-hpke")]
            Self::V2 { session, .. } => session
                .seal_response(plaintext, epoch, seq)
                .ok()
                .and_then(|f| encode_frame_v2(&f).ok()),
        }
    }

    fn into_outcome(
        self,
        assigned_ip: Option<Ipv4Addr>,
        assigned_ip_v6: Option<Ipv6Addr>,
        revocation_guard: Option<SessionGuard>,
        wants_daita: bool,
    ) -> SetupOutcome {
        match self {
            Self::V1 { session, frame, .. } => SetupOutcome::V1(ConnSetup {
                session,
                epoch: frame.epoch,
                assigned_ip,
                assigned_ip_v6,
                revocation_guard,
                wants_daita,
            }),
            #[cfg(feature = "pq-hpke")]
            Self::V2 { session, frame, .. } => SetupOutcome::V2(ConnSetupPq {
                session,
                epoch: frame.epoch,
                assigned_ip,
                assigned_ip_v6,
                revocation_guard,
            }),
        }
    }
}

/// Decode the setup frame, select `/v1` vs `/v2` by its version byte, and build
/// the matching termination session (classical from the `SessionCache`, PQ by
/// X-Wing-decapsulating the setup frame's `pq_ct`). Returns `None` (drop) on a
/// decode/exit_id/build failure, or on a `/v2` frame when the exit is not
/// PQ-capable.
fn build_setup_termination(
    bytes: &[u8],
    exit_id: ExitId,
    privkey: &Arc<WarrenKemPrivateKey>,
    cache: &Arc<SessionCache>,
    #[cfg(feature = "pq-hpke")] pq: Option<&PqSetup>,
) -> Option<SetupTermination> {
    #[cfg(feature = "pq-hpke")]
    if bytes.first() == Some(&warrenguard_multihop::WARREN_HPKE_VERSION_V2) {
        // A `/v2` frame with no PQ material configured is dropped: this exit did
        // not publish an ML-KEM key, so no honest client sends it one.
        let pq = pq?;
        let frame = decode_frame_v2(bytes).ok()?;
        if frame.exit_id != exit_id {
            tracing::debug!("multihop: v2 setup frame exit_id mismatch");
            return None;
        }
        if frame.pq_ct.is_empty() {
            // A setup frame MUST carry the ML-KEM ciphertext to establish the
            // session; a first frame without it cannot bootstrap PQ.
            tracing::debug!("multihop: v2 setup frame missing pq_ct");
            return None;
        }
        let handle = pq
            .cache
            .establish_or_get(&frame.encapsulated_key, &frame.pq_ct, exit_id, &pq.secret)
            .ok()?;
        return Some(SetupTermination::V2 {
            session: handle.session,
            frame,
            replay: handle.replay_windows,
        });
    }
    let frame = decode_frame(bytes).ok()?;
    if frame.exit_id != exit_id {
        tracing::debug!("multihop: setup frame exit_id mismatch");
        return None;
    }
    let handle = cache
        .get_or_insert(&frame.encapsulated_key, || {
            ExitSession::new(privkey, &frame.encapsulated_key, exit_id)
        })
        .ok()?;
    Some(SetupTermination::V1 {
        session: handle.session,
        frame,
        replay: handle.replay_windows,
    })
}

/// Source of the setup-stream bytes for [`process_setup_frame`].
///
/// - [`SetupSource::AcceptFromConn`]: the standalone exit listener
///   accepts the client→exit bidi stream itself.
/// - [`SetupSource::PreRead`]: the unified `:443` dispatcher has already
///   accepted the bidi stream and read the frame (to peek the `exit_id`
///   for routing), so it hands the send half + verbatim bytes straight
///   through. A second `accept_bi` on the same stream is impossible, so
///   this variant skips the read entirely.
pub enum SetupSource {
    /// The standalone exit listener accepts the bidi stream itself.
    AcceptFromConn,
    /// The unified `:443` dispatcher has already accepted the stream and
    /// read the setup frame; it hands the pieces straight through.
    PreRead {
        /// Send half of the already-accepted client→exit bidi stream.
        send: SendStream,
        /// Verbatim setup-frame bytes the dispatcher already read.
        frame_bytes: Vec<u8>,
    },
}

/// Run the exit-side setup-stream phase: accept the client→exit bidi
/// stream (shuttled by the relay), read the setup frame, then delegate
/// to [`process_setup_frame`]. Used by the standalone exit listener; the
/// unified dispatcher calls [`process_setup_frame`] directly with the
/// stream it already accepted (see [`SetupSource::PreRead`]).
///
/// Returns `None` (after closing/resetting as appropriate) on any
/// stream, decode, exit_id, replay, or HPKE failure; the caller then
/// abandons the connection without starting the datagram pump.
#[allow(clippy::too_many_arguments)]
async fn accept_setup_stream(
    conn: &Connection,
    privkey: &Arc<WarrenKemPrivateKey>,
    exit_id: ExitId,
    cache: &Arc<SessionCache>,
    ip_allocator: &Option<Arc<Mutex<IpAllocator>>>,
    ip_allocator_v6: &Option<Arc<Mutex<IpAllocatorV6>>>,
    conn_id: ConnId,
    router: &Option<Arc<MultihopTunRouter>>,
    down_tx: &Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    reverse_seq: &AtomicU64,
    allowlist: Option<&AllowlistHandle>,
    session_registry: Option<&Arc<MultihopSessionRegistry>>,
    token_admitter: Option<&Arc<dyn SessionTokenAdmitter>>,
    offered_daita: Option<&warrenguard_wire::DaitaConfig>,
    #[cfg(feature = "pq-hpke")] pq: Option<&PqSetup>,
) -> Option<SetupOutcome> {
    let (send, mut recv) = match conn.accept_bi().await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!(error = %e, "multihop: client never opened the setup stream");
            return None;
        }
    };
    let bytes = match recv.read_to_end(MAX_MULTIHOP_SETUP_FRAME_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "multihop: setup stream read failed");
            return None;
        }
    };
    process_setup_frame(
        send,
        bytes,
        conn,
        privkey,
        exit_id,
        cache,
        ip_allocator,
        ip_allocator_v6,
        conn_id,
        router,
        down_tx,
        reverse_seq,
        allowlist,
        session_registry,
        token_admitter,
        offered_daita,
        #[cfg(feature = "pq-hpke")]
        pq,
    )
    .await
}

/// Decode an already-read setup frame, derive the HPKE session, allocate
/// the IP, register the downlink route, and write the sealed `IpAssign`
/// reply back on `send`.
///
/// The setup frame's `(epoch, seq)` is recorded in the session-scoped
/// anti-replay window (held in the `SessionCache` entry) so a later DATA
/// datagram, on this or any other connection sharing the same HPKE
/// session, cannot replay it. On pool exhaustion the helper writes an
/// `IpExhausted` reply and returns `None` so the caller closes the
/// connection.
///
/// Returns `None` (after closing/resetting as appropriate) on any
/// decode, exit_id, replay, or HPKE failure; the caller then abandons
/// the connection without starting the datagram pump.
#[allow(clippy::too_many_arguments)]
async fn process_setup_frame(
    mut send: SendStream,
    bytes: Vec<u8>,
    conn: &Connection,
    privkey: &Arc<WarrenKemPrivateKey>,
    exit_id: ExitId,
    cache: &Arc<SessionCache>,
    ip_allocator: &Option<Arc<Mutex<IpAllocator>>>,
    ip_allocator_v6: &Option<Arc<Mutex<IpAllocatorV6>>>,
    conn_id: ConnId,
    router: &Option<Arc<MultihopTunRouter>>,
    down_tx: &Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    reverse_seq: &AtomicU64,
    allowlist: Option<&AllowlistHandle>,
    session_registry: Option<&Arc<MultihopSessionRegistry>>,
    token_admitter: Option<&Arc<dyn SessionTokenAdmitter>>,
    offered_daita: Option<&warrenguard_wire::DaitaConfig>,
    #[cfg(feature = "pq-hpke")] pq: Option<&PqSetup>,
) -> Option<SetupOutcome> {
    let term = build_setup_termination(
        &bytes,
        exit_id,
        privkey,
        cache,
        #[cfg(feature = "pq-hpke")]
        pq,
    )?;
    let epoch = term.epoch();
    let encapsulated_key = term.encapsulated_key();
    let plaintext = match term.open() {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "multihop: setup frame HPKE open failed");
            return None;
        }
    };
    // Record the setup (epoch, seq) in the session-scoped window so a
    // DATA datagram on this or any other connection sharing this session
    // cannot replay it.
    if term
        .replay()
        .lock()
        .check_and_record(term.seq(), epoch)
        .is_err()
    {
        tracing::debug!("multihop: setup frame failed anti-replay");
        return None;
    }
    let control_msg = warrenguard_multihop::try_decode_control(&plaintext)
        .ok()
        .flatten();

    // Cold-start grace (deploy / reboot / fresh immutable host with no
    // disk cache): the in-memory allowlist is empty until the refresh
    // loop's first poll lands. Hard-rejecting every client in that window
    // closes their connection with NotAllowlisted, which the client treats
    // as a definitive per-attempt refusal and answers with a reconnect
    // storm (observed after an exit update while a client was connected).
    // Instead, hold this setup briefly for the first sync, then evaluate
    // the gate normally. Bounded, so a backend that never answers still
    // fails closed after the grace. Once the exit has synced once, this
    // returns instantly (steady state pays nothing).
    if let Some(al) = allowlist
        && al.last_success_unix_secs() == 0
        && !al.wait_for_first_sync(ALLOWLIST_FIRST_SYNC_GRACE).await
    {
        tracing::warn!(
            "multihop: allowlist not yet synced after grace; evaluating client \
             against the current (empty) allowlist"
        );
    }

    // H1: authorize the client and resolve the sticky-allocation key BEFORE
    // any allocation work. Two admission arms:
    //  - v7 `IpRequestV7`: verify a Privacy Pass token OFFLINE and spend its
    //    serial via the injected `SessionTokenAdmitter`. The exit never learns
    //    the wallet; the anonymous serial (pubkey-shaped) becomes the sticky
    //    key. A v7-incapable exit (no admitter) rejects.
    //  - v6 `IpRequest`: the existing allowlist + proof-of-possession gate,
    //    keyed on the asserted account pubkey (behaviour unchanged).
    // A rejected client gets the sealed detail + an opaque close, so the
    // relay cannot distinguish rejection causes.
    let sticky_pubkey: Option<[u8; 32]>;
    let token_serial: Option<[u8; 32]>;
    let (wants_ipv6, wants_daita): (bool, bool);
    let prefer_ipv4: Option<[u8; 4]>;
    (
        sticky_pubkey,
        wants_ipv6,
        wants_daita,
        token_serial,
        prefer_ipv4,
    ) = match control_msg.as_ref() {
        Some(WarrenControlMessage::IpRequestV7 {
            session_tokens,
            wants_ipv6,
            wants_daita,
            prefer_ipv4,
            ..
        }) => {
            let admitted = match token_admitter {
                Some(admitter) => admitter.admit(session_tokens).await,
                // No admitter configured => this exit is not v7-capable.
                None => warrenguard_server::TokenAdmission::Reject,
            };
            match admitted {
                warrenguard_server::TokenAdmission::Admit { serial } => (
                    Some(serial),
                    *wants_ipv6,
                    *wants_daita,
                    Some(serial),
                    *prefer_ipv4,
                ),
                _ => {
                    tracing::warn!(
                        "multihop: v7 setup rejected - token invalid/denied; sealed detail + opaque close"
                    );
                    reply_sealed_detail_then_close(
                        &mut send,
                        &term,
                        epoch,
                        reverse_seq,
                        conn,
                        &WarrenControlMessage::Rejected,
                    )
                    .await;
                    return None;
                }
            }
        }
        other => {
            if !allowlist_admits(allowlist, other, &exit_id, &encapsulated_key) {
                tracing::warn!(
                    "multihop: setup rejected - client not authorized; sealed detail + opaque close"
                );
                reply_sealed_detail_then_close(
                    &mut send,
                    &term,
                    epoch,
                    reverse_seq,
                    conn,
                    &WarrenControlMessage::Rejected,
                )
                .await;
                return None;
            }
            let pk = match other {
                Some(WarrenControlMessage::IpRequest {
                    client_pubkey,
                    wants_ipv6,
                    wants_daita,
                    prefer_ipv4,
                    ..
                }) => (*client_pubkey, *wants_ipv6, *wants_daita, *prefer_ipv4),
                _ => (None, false, false, None),
            };
            (pk.0, pk.1, pk.2, None, pk.3)
        }
    };
    // Register this admitted connection in the live-session registry so a
    // mid-session revocation (allowlist removal / CRL) can force-close it
    // (see `MultihopSessionRegistry`). Only meaningful in strict mode
    // where the client asserted an account pubkey; permissive mode has no
    // pubkey to key on and no revocation to enforce.
    //
    // The guard is built immediately (RAII) so every early-return below
    // also unregisters. After registering we RE-CHECK the gate: a
    // revocation broadcast that fired between `allowlist_admits` above and
    // `register` here would have found no connection to close. Because
    // `apply_delta`/`apply_crl_revocations` mutate the allowlist BEFORE
    // broadcasting, `is_allowed_at` already reflects the removal, so this
    // recheck closes the TOCTOU window: a pubkey revoked during setup is
    // refused here even if its broadcast slipped past the registry.
    let revocation_guard = match (
        session_registry,
        sticky_pubkey.map(WarrenPubkey::from_bytes),
    ) {
        (Some(registry), Some(pubkey)) => {
            registry.register(pubkey, conn_id, conn.clone());
            let guard = SessionGuard {
                registry: Arc::clone(registry),
                pubkey,
                conn_id,
            };
            // TOCTOU allowlist recheck applies ONLY to the v6 wallet path: a
            // v7 sticky key is an anonymous token serial, never an allowlist
            // entry, so an `is_allowed_at` on it would spuriously reject. v7
            // authorization already happened at token spend above.
            if token_serial.is_none()
                && let Some(al) = allowlist
                && !al.is_allowed_at(&pubkey, warrenguard_config::unix_now())
            {
                tracing::warn!(
                    "multihop: setup rejected - pubkey revoked during setup (TOCTOU recheck)"
                );
                // `guard` drops here -> unregister; close the connection
                // we just registered so it does not linger.
                conn.close(quinn::VarInt::from_u32(WARREN_MH_REJECTED), &[]);
                return None;
            }
            Some(guard)
        }
        _ => None,
    };

    // The setup reply is sealed and written on the same bidi stream the
    // relay shuttles back to the client, instead of a reverse datagram.
    let mut assigned_ip = None;
    let mut assigned_ip_v6 = None;
    let reply_plaintext = match allocate_on_first_frame(
        ip_allocator,
        ip_allocator_v6,
        conn_id,
        sticky_pubkey,
        wants_ipv6,
        prefer_ipv4,
    ) {
        Some(spec) => {
            if let (Some(router), Some(tx)) = (router, down_tx) {
                router.register(spec.assigned, tx.clone());
                assigned_ip = Some(spec.assigned);
                if let (Some(registry), Some(guard)) = (session_registry, revocation_guard.as_ref())
                {
                    registry.record_assigned_ipv4(spec.assigned, guard.pubkey);
                }
                // Dual-stack `/v2`: also register the v6 downlink route so
                // the single TUN reader fans out v6 reply packets to this
                // conn by destination address.
                if let Some(v6) = spec.assigned_v6 {
                    router.register_v6(v6, tx.clone());
                    assigned_ip_v6 = Some(v6);
                }
            }
            // DAITA capability echo: grant the machine THIS connection runs
            // only when the client asked for it. A client that did not ask
            // is never pushed a spec; a client that asked against an unarmed
            // exit reads the honest `None` ("the defense is not running")
            // instead of believing itself protected.
            let granted_daita = if wants_daita {
                offered_daita.cloned()
            } else {
                None
            };
            match encode_control(&spec.into_control_message(granted_daita)) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "ip-nego: encode IpAssign for setup reply failed");
                    return None;
                }
            }
        }
        None if ip_allocator.is_some() => {
            // Pool exhausted: sealed IpExhausted detail, then the same
            // opaque close every policy rejection uses (anti-oracle).
            tracing::warn!("ip-nego: pool exhausted at setup; sealed detail + opaque close");
            reply_sealed_detail_then_close(
                &mut send,
                &term,
                epoch,
                reverse_seq,
                conn,
                &WarrenControlMessage::IpExhausted,
            )
            .await;
            return None;
        }
        // No allocator (legacy single client): reply with an empty
        // IpExhausted-free path is not applicable. Send a benign reply so
        // the client's reliable setup round-trip still completes: re-seal
        // the client's own setup plaintext as the reply. The client's
        // setup_over_stream then decodes a non-IpAssign reply and keeps
        // its bootstrap IP.
        None => match encode_control(&WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
            wants_daita: false,
        }) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "multihop: encode no-alloc setup reply failed");
                return None;
            }
        },
    };

    let seq = reverse_seq.fetch_add(1, Ordering::AcqRel);
    let reply_bytes = match term.seal_reply(&reply_plaintext, epoch, seq) {
        Some(b) => b,
        None => {
            tracing::warn!("multihop: seal/encode setup reply failed");
            return None;
        }
    };
    if let Err(e) = send.write_all(&reply_bytes).await {
        tracing::debug!(error = %e, "multihop: write setup reply failed");
        return None;
    }
    if let Err(e) = send.finish() {
        tracing::debug!(error = %e, "multihop: finish setup reply stream failed");
        return None;
    }
    if let Some(ip) = assigned_ip {
        // `ip` is the ephemeral exit-internal pool address (10.66.0.x),
        // not a client identifier, so it is benign to log. The v6 address
        // is omitted; the `dual_stack` flag is enough for ops.
        tracing::info!(
            assigned = %ip,
            dual_stack = assigned_ip_v6.is_some(),
            "ip-nego: IpAssign sent over setup stream"
        );
    }

    Some(term.into_outcome(assigned_ip, assigned_ip_v6, revocation_guard, wants_daita))
}

/// Run the setup-stream phase from either source: accept the bidi
/// stream from `conn`, or reuse the stream the unified dispatcher
/// already accepted and read.
#[allow(clippy::too_many_arguments)]
async fn run_setup(
    source: SetupSource,
    conn: &Connection,
    privkey: &Arc<WarrenKemPrivateKey>,
    exit_id: ExitId,
    cache: &Arc<SessionCache>,
    ip_allocator: &Option<Arc<Mutex<IpAllocator>>>,
    ip_allocator_v6: &Option<Arc<Mutex<IpAllocatorV6>>>,
    conn_id: ConnId,
    router: &Option<Arc<MultihopTunRouter>>,
    down_tx: &Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    reverse_seq: &AtomicU64,
    allowlist: Option<&AllowlistHandle>,
    session_registry: Option<&Arc<MultihopSessionRegistry>>,
    token_admitter: Option<&Arc<dyn SessionTokenAdmitter>>,
    offered_daita: Option<&warrenguard_wire::DaitaConfig>,
    #[cfg(feature = "pq-hpke")] pq: Option<&PqSetup>,
) -> Option<SetupOutcome> {
    match source {
        SetupSource::AcceptFromConn => {
            accept_setup_stream(
                conn,
                privkey,
                exit_id,
                cache,
                ip_allocator,
                ip_allocator_v6,
                conn_id,
                router,
                down_tx,
                reverse_seq,
                allowlist,
                session_registry,
                token_admitter,
                offered_daita,
                #[cfg(feature = "pq-hpke")]
                pq,
            )
            .await
        }
        SetupSource::PreRead { send, frame_bytes } => {
            process_setup_frame(
                send,
                frame_bytes,
                conn,
                privkey,
                exit_id,
                cache,
                ip_allocator,
                ip_allocator_v6,
                conn_id,
                router,
                down_tx,
                reverse_seq,
                allowlist,
                session_registry,
                token_admitter,
                offered_daita,
                #[cfg(feature = "pq-hpke")]
                pq,
            )
            .await
        }
    }
}

/// Doctrine 2-5 s overlap window after a client rekey, enforced
/// symmetrically on the exit-side session cache. After this TTL the
/// cached entry for an old encapsulated key is dropped so the cache
/// does not grow unboundedly across thousands of rekeys on a long
/// connection. Cf. `docs/19-WARREN-MULTIHOP-DESIGN.md` § 11.6 and
/// `warren_multihop_doctrine_v1` memory.
const SESSION_CACHE_TTL: Duration = Duration::from_secs(5);

/// HKDF info string binding the X25519 multihop IKM derivation to the
/// `/v1` PKI namespace. Freezing this string is required so two exits
/// holding the same Ed25519 mnemonic also share the same X25519 HPKE
/// recipient pubkey across restarts.
const X25519_DERIVATION_INFO: &[u8] = b"warren/exit/multihop-x25519/v1";

/// Errors raised by the multihop exit termination path.
#[derive(Debug, Error)]
pub enum MultihopExitError {
    /// The IKM file was shorter than the required 32 bytes.
    #[error("IKM file too short: expected 32 bytes, got {got}")]
    IkmTooShort {
        /// Bytes actually present in the IKM source.
        got: usize,
    },
    /// `quinn::Endpoint::accept` returned `None` (endpoint was closed).
    #[error("endpoint closed")]
    EndpointClosed,
    /// Underlying I/O failure (TUN or QUIC).
    #[error("multihop I/O error: {0}")]
    Io(String),
}

/// Derive the long-lived X25519 multihop keypair from a 32-byte IKM via
/// HKDF-SHA256 with a fixed `/v1` info tag.
///
/// The output of `HKDF-Expand(salt=None, ikm, info=X25519_DERIVATION_INFO, 32)`
/// is fed as IKM to
/// [`warrenguard_multihop::test_support::derive_exit_keypair`], which then
/// runs RFC 9180's `DeriveKeyPair` to produce the X25519 secret/public
/// pair. This pipeline gives a stable pubkey for as long as the
/// upstream 32-byte input does not change.
///
/// # Errors
///
/// Returns [`MultihopExitError::IkmTooShort`] if `ikm` has fewer than 32
/// bytes.
pub fn derive_x25519_keypair(
    ikm: &[u8],
) -> Result<(WarrenKemPrivateKey, WarrenKemPublicKey), MultihopExitError> {
    if ikm.len() < 32 {
        return Err(MultihopExitError::IkmTooShort { got: ikm.len() });
    }
    let mut expanded = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(None, ikm);
    hk.expand(X25519_DERIVATION_INFO, &mut expanded)
        .expect("HKDF-Expand 32 bytes always succeeds with sha256");
    let (priv_key, pub_key) = warrenguard_multihop::test_support::derive_exit_keypair(&expanded);
    Ok((priv_key, pub_key))
}

/// Derive the 32-byte X25519 IKM from an Ed25519 signing key.
///
/// Used when an operator runs `warren-exit --multihop` without
/// supplying a dedicated `--multihop-x25519-ikm` file: the X25519
/// material is then deterministically bound to the existing Ed25519
/// identity, so the multihop pubkey rotates exactly when the exit
/// rotates its Ed25519 identity (cf. `provision-warren-exit.sh
/// --ephemeral-identity`).
#[must_use]
pub fn derive_x25519_ikm_from_ed25519(signing_key: &SigningKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &signing_key.to_bytes());
    let mut ikm = [0u8; 32];
    hk.expand(X25519_DERIVATION_INFO, &mut ikm)
        .expect("HKDF-Expand 32 bytes always succeeds with sha256");
    ikm
}

/// HKDF info tag for deriving the exit's ML-KEM-768 keygen IKM from its Ed25519
/// identity. DISTINCT from [`X25519_DERIVATION_INFO`] so the ML-KEM IKM and the
/// X25519 IKM never coincide. Frozen: changing it rotates every exit's published
/// ML-KEM key (old signed descriptors and in-flight PQ sessions would break).
#[cfg(feature = "pq-hpke")]
const MLKEM768_DERIVATION_INFO: &[u8] = b"warren/exit/multihop-mlkem768/v1";

/// Derive the 32-byte ML-KEM-768 keygen IKM from an Ed25519 signing key, the
/// post-quantum sibling of [`derive_x25519_ikm_from_ed25519`]. Domain-separated
/// so the exit's ML-KEM key is bound to (and rotates with) the same identity as
/// its X25519 multihop key, with no separately persisted secret.
#[cfg(feature = "pq-hpke")]
#[must_use]
pub fn derive_mlkem768_ikm_from_ed25519(signing_key: &SigningKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &signing_key.to_bytes());
    let mut ikm = [0u8; 32];
    hk.expand(MLKEM768_DERIVATION_INFO, &mut ikm)
        .expect("HKDF-Expand 32 bytes always succeeds with sha256");
    ikm
}

/// Derive the exit's X-Wing recipient keypair from its Ed25519 identity: the
/// X25519 half REUSES the existing multihop key (so the combiner's `pk_X` equals
/// the published descriptor key) and the ML-KEM half is derived from the
/// identity-bound IKM. Returns the secret (holds the decapsulation key for the
/// `/v2` datapath) and the 1184-byte ML-KEM encapsulation key to sign and
/// publish in `exit_mlkem768_pubkey`.
///
/// # Errors
///
/// Propagates [`MultihopExitError::IkmTooShort`] from [`derive_x25519_keypair`]
/// (not reachable here: the derived IKM is always 32 bytes).
#[cfg(feature = "pq-hpke")]
pub fn derive_exit_xwing_from_identity(
    signing_key: &SigningKey,
) -> Result<(warrenguard_multihop::XWingRecipientSecretKey, Vec<u8>), MultihopExitError> {
    let x25519_ikm = derive_x25519_ikm_from_ed25519(signing_key);
    let (x_privkey, _x_pubkey) = derive_x25519_keypair(&x25519_ikm)?;
    let mlkem_ikm = derive_mlkem768_ikm_from_ed25519(signing_key);
    let (secret, public) =
        warrenguard_multihop::derive_exit_xwing_recipient(&x_privkey, &mlkem_ikm);
    Ok((secret, public.mlkem768_ek_bytes()))
}

/// Cache of `ExitSession`s keyed by encapsulated key, shared across all
/// QUIC connections served by one exit. The cache lets a single physical
/// QUIC connection drive multiple sequential rekey epochs and lets the
/// same client reconnect on top of an existing HPKE setup without
/// repaying the KEM ECDH on every QUIC handshake.
///
/// Entries are kept alive for [`SESSION_CACHE_TTL`] after their last
/// access. On every `get_or_insert`, the cache lazily evicts expired
/// entries. This bounds memory at "active sessions in the last 5 s",
/// which on a heavy client comes out to two (current + just-rekeyed
/// old), and on an idle client comes out to one.
/// Generous cap on NEW HPKE session derivations per second across the
/// whole exit: a DoS backstop. Each cache miss runs an X25519 KEM decap,
/// and an unauthenticated peer can otherwise drive one decap per frame by
/// rotating `encapsulated_key`. Set far above any legitimate connect/rekey
/// rate so it only bites a flood; established sessions (cache hits) and the
/// per-connection setup gate (allowlist) are unaffected. The burst lets a
/// reconnect storm through while still bounding sustained CPU.
const SESSION_CREATE_RATE_PER_SEC: f64 = 500.0;
const SESSION_CREATE_BURST: f64 = 1000.0;

/// Minimal token bucket for the session-creation DoS backstop. Refills
/// continuously at `rate_per_sec`, capped at `capacity`.
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rate_per_sec: f64,
    capacity: f64,
}

impl TokenBucket {
    fn new(rate_per_sec: f64, capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
            rate_per_sec,
            capacity,
        }
    }

    /// Try to consume one token. Returns `false` (caller drops the work)
    /// when the bucket is empty.
    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct SessionCacheState {
    map: HashMap<EncapsulatedKeyBytes, SessionCacheEntry>,
    /// Rate limiter on NEW session derivations (decaps). Kept under the
    /// same lock as the map so a miss is gated atomically with the build.
    create_bucket: TokenBucket,
}

struct SessionCache {
    inner: Mutex<SessionCacheState>,
    ttl: Duration,
}

struct SessionCacheEntry {
    session: Arc<ExitSession>,
    /// Anti-replay window shared by every QUIC connection that drives
    /// this HPKE session (a hostile relay can open a fresh connection
    /// and replay captured frames; legitimately bonded connections also
    /// share one monotonic seq). Scoping it to the cache entry rather
    /// than to a connection is what closes the cross-connection replay:
    /// a `(epoch, seq)` accepted on any connection is rejected on all
    /// others sharing the same `encapsulated_key`.
    ///
    /// Lifetime caveat: the window dies with the cache entry, which the
    /// lazy sweep reclaims [`SESSION_CACHE_TTL`] after the last frame.
    /// Within that 5 s residue a deterministic post-TTL reconstruction
    /// (a cache miss rebuilds a byte-identical [`ExitSession`]) would
    /// get a fresh window and could re-accept an ancient replay. The TTL
    /// bounds that residue to the doctrine rekey-overlap window; a frame
    /// older than that is harmless (the client has long moved on).
    replay_windows: Arc<Mutex<EpochReplayWindows>>,
    last_seen_at: Instant,
}

/// Handle returned by [`SessionCache::get_or_insert`]: the HPKE session
/// plus the anti-replay window shared across every connection driving
/// that session. The two are looked up together so the replay check is
/// always performed against the session-scoped window, never a
/// connection-local one.
struct SessionHandle {
    session: Arc<ExitSession>,
    replay_windows: Arc<Mutex<EpochReplayWindows>>,
}

impl SessionCache {
    fn new() -> Self {
        Self::with_ttl(SESSION_CACHE_TTL)
    }

    fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(SessionCacheState {
                map: HashMap::new(),
                create_bucket: TokenBucket::new(
                    SESSION_CREATE_RATE_PER_SEC,
                    SESSION_CREATE_BURST,
                    Instant::now(),
                ),
            }),
            ttl,
        }
    }

    /// Get or insert a session keyed by `encapsulated_key`. Sweeps
    /// expired entries before the lookup and refreshes `last_seen_at`
    /// on every hit so a steady stream of traffic for one session
    /// keeps it indefinitely while a paused session is reclaimed
    /// after [`Self::ttl`].
    ///
    /// A cache MISS additionally consumes a token from the per-second
    /// session-creation budget before running `build` (the HPKE decap);
    /// when the budget is exhausted the frame is dropped with
    /// [`MultihopError::SessionCreateRateLimited`] instead of burning CPU.
    fn get_or_insert(
        &self,
        encapsulated_key: &EncapsulatedKeyBytes,
        build: impl FnOnce() -> Result<ExitSession, warrenguard_multihop::MultihopError>,
    ) -> Result<SessionHandle, warrenguard_multihop::MultihopError> {
        let mut guard = self.inner.lock();
        let now = Instant::now();
        let ttl = self.ttl;
        guard
            .map
            .retain(|_, entry| now.duration_since(entry.last_seen_at) < ttl);
        if let Some(existing) = guard.map.get_mut(encapsulated_key) {
            existing.last_seen_at = now;
            return Ok(SessionHandle {
                session: existing.session.clone(),
                replay_windows: existing.replay_windows.clone(),
            });
        }
        if !guard.create_bucket.try_take(now) {
            return Err(warrenguard_multihop::MultihopError::SessionCreateRateLimited);
        }
        let new_session = Arc::new(build()?);
        let replay_windows = Arc::new(Mutex::new(EpochReplayWindows::default()));
        guard.map.insert(
            *encapsulated_key,
            SessionCacheEntry {
                session: new_session.clone(),
                replay_windows: replay_windows.clone(),
                last_seen_at: now,
            },
        );
        Ok(SessionHandle {
            session: new_session,
            replay_windows,
        })
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.lock().map.len()
    }
}

/// Post-quantum (`/v2` X-Wing) analogue of [`SessionCache`], keyed by the same
/// 32-byte `encapsulated_key` (`ct_X`) so the shared cross-connection anti-replay
/// window semantics are identical. The one structural difference is load-bearing:
/// a [`PqExitSession`] can be BUILT only from a setup/rekey frame (which carries
/// the 1088-byte `pq_ct` to decapsulate); a steady-state DATA frame carries an
/// empty `pq_ct`, so it can only LOOK UP an already-established session, never
/// rebuild one. Hence [`Self::establish_or_get`] (setup/rekey) and [`Self::get`]
/// (data) are split, unlike the classical rebuild-on-miss `get_or_insert`.
#[cfg(feature = "pq-hpke")]
struct PqSessionCacheEntry {
    session: Arc<PqExitSession>,
    replay_windows: Arc<Mutex<EpochReplayWindows>>,
    last_seen_at: Instant,
}

#[cfg(feature = "pq-hpke")]
struct PqSessionCacheState {
    map: HashMap<EncapsulatedKeyBytes, PqSessionCacheEntry>,
    create_bucket: TokenBucket,
}

#[cfg(feature = "pq-hpke")]
pub(crate) struct PqSessionCache {
    inner: Mutex<PqSessionCacheState>,
    ttl: Duration,
}

#[cfg(feature = "pq-hpke")]
struct PqSessionHandle {
    session: Arc<PqExitSession>,
    replay_windows: Arc<Mutex<EpochReplayWindows>>,
}

#[cfg(feature = "pq-hpke")]
impl PqSessionCache {
    fn new() -> Self {
        Self::with_ttl(SESSION_CACHE_TTL)
    }

    fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(PqSessionCacheState {
                map: HashMap::new(),
                create_bucket: TokenBucket::new(
                    SESSION_CREATE_RATE_PER_SEC,
                    SESSION_CREATE_BURST,
                    Instant::now(),
                ),
            }),
            ttl,
        }
    }

    /// Establish (setup/rekey frame, `pq_ct` present) or return the cached PQ
    /// session for `encapsulated_key`. A cache miss runs one X-Wing decapsulation
    /// (gated by the shared DoS budget, since decap is the expensive step an
    /// unauthenticated peer could otherwise drive by rotating `encapsulated_key`).
    ///
    /// # Errors
    ///
    /// - [`MultihopError::SessionCreateRateLimited`] if the create budget is spent.
    /// - Propagates [`PqExitSession::new`] decapsulation failures.
    fn establish_or_get(
        &self,
        encapsulated_key: &EncapsulatedKeyBytes,
        pq_ct: &[u8],
        exit_id: ExitId,
        secret: &XWingRecipientSecretKey,
    ) -> Result<PqSessionHandle, MultihopError> {
        let mut guard = self.inner.lock();
        let now = Instant::now();
        let ttl = self.ttl;
        guard
            .map
            .retain(|_, entry| now.duration_since(entry.last_seen_at) < ttl);
        if let Some(existing) = guard.map.get_mut(encapsulated_key) {
            existing.last_seen_at = now;
            return Ok(PqSessionHandle {
                session: existing.session.clone(),
                replay_windows: existing.replay_windows.clone(),
            });
        }
        if !guard.create_bucket.try_take(now) {
            return Err(MultihopError::SessionCreateRateLimited);
        }
        let session = Arc::new(PqExitSession::new(
            secret,
            encapsulated_key,
            pq_ct,
            exit_id,
        )?);
        let replay_windows = Arc::new(Mutex::new(EpochReplayWindows::default()));
        guard.map.insert(
            *encapsulated_key,
            PqSessionCacheEntry {
                session: session.clone(),
                replay_windows: replay_windows.clone(),
                last_seen_at: now,
            },
        );
        Ok(PqSessionHandle {
            session,
            replay_windows,
        })
    }

    /// Look up an already-established PQ session (steady-state DATA frame, empty
    /// `pq_ct`). A miss returns `None`: the frame is dropped, since the session
    /// cannot be rebuilt without the `pq_ct` only a setup/rekey frame carries.
    fn get(&self, encapsulated_key: &EncapsulatedKeyBytes) -> Option<PqSessionHandle> {
        let mut guard = self.inner.lock();
        let now = Instant::now();
        let ttl = self.ttl;
        guard
            .map
            .retain(|_, entry| now.duration_since(entry.last_seen_at) < ttl);
        let existing = guard.map.get_mut(encapsulated_key)?;
        existing.last_seen_at = now;
        Some(PqSessionHandle {
            session: existing.session.clone(),
            replay_windows: existing.replay_windows.clone(),
        })
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.lock().map.len()
    }
}

/// Drive the multihop accept loop on `endpoint`, echoing every sealed
/// payload back to the client through the reverse-direction HPKE
/// exporter.
///
/// This is the loopback / bench variant: no TUN, no SNAT, no upstream
/// traffic. It exists so the multihop pipeline can be exercised
/// end-to-end with iperf3 over the QUIC tunnel without requiring root
/// or a Linux kernel TUN device. The production TUN-bridged variant is
/// [`serve_multihop_with_tun`].
///
/// The function returns when `endpoint.accept()` yields `None` (i.e. the
/// endpoint has been closed) or when an unrecoverable error is raised
/// at the per-connection level. Per-datagram crypto failures are
/// counted in tracing logs but do not break the loop, mirroring the
/// behaviour of the existing `warren-relay` accept path.
///
/// # Errors
///
/// - [`MultihopExitError::EndpointClosed`] if `accept()` returns `None`.
pub async fn serve_multihop_echo(
    endpoint: Endpoint,
    exit_x25519_privkey: WarrenKemPrivateKey,
    exit_id: ExitId,
) -> Result<(), MultihopExitError> {
    let cache = Arc::new(SessionCache::new());
    let privkey = Arc::new(exit_x25519_privkey);

    while let Some(incoming) = endpoint.accept().await {
        let cache = cache.clone();
        let privkey = privkey.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "multihop incoming handshake failed");
                    return;
                }
            };
            serve_one_connection_echo(conn, privkey, exit_id, cache).await;
        });
    }
    Err(MultihopExitError::EndpointClosed)
}

async fn serve_one_connection_echo(
    conn: Connection,
    privkey: Arc<WarrenKemPrivateKey>,
    exit_id: ExitId,
    cache: Arc<SessionCache>,
) {
    let mut reverse_seq = 0u64;
    loop {
        let datagram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(_) => return,
        };
        let frame = match decode_frame(&datagram) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if frame.exit_id != exit_id {
            continue;
        }
        let session = match cache.get_or_insert(&frame.encapsulated_key, || {
            ExitSession::new(&privkey, &frame.encapsulated_key, exit_id)
        }) {
            Ok(h) => h.session,
            Err(_) => continue,
        };
        let plaintext = match session.open(&frame) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let response = match session.seal_response(&plaintext, frame.epoch, reverse_seq) {
            Ok(r) => r,
            Err(_) => continue,
        };
        reverse_seq = reverse_seq.saturating_add(1);
        let bytes = match encode_frame(&response) {
            Ok(b) => b,
            Err(_) => continue,
        };
        match conn.send_datagram(bytes.into()) {
            Ok(()) => {}
            // Transient PMTU dip: drop the echo, keep serving.
            Err(SendDatagramError::TooLarge) => {}
            Err(_) => return,
        }
    }
}

/// Shared slot holding the latest installed `(ExitSession, epoch)` for
/// a connection. Mutated by the RX pump on each accepted frame, read
/// by the TX pump before each reverse seal.
type SharedCurrentSession = Arc<Mutex<Option<(Arc<ExitSession>, u32)>>>;

/// Post-quantum counterpart of [`SharedCurrentSession`] (`/v2` X-Wing session).
#[cfg(feature = "pq-hpke")]
type SharedPqCurrentSession = Arc<Mutex<Option<(Arc<PqExitSession>, u32)>>>;

/// A drain advisory broadcast to every live multi-hop connection on this
/// exit when the backend marks the exit for maintenance (the heartbeat
/// `drain` directive). ADR 36 "smooth exit maintenance": the soft,
/// HPKE-sealed signal that lets each client make-before-break onto another
/// exit BEFORE the hard `deadline_unix_secs` close. Process-wide: one
/// `watch::Sender` in the exit feeds every per-connection drain emitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainAdvisory {
    /// Unix seconds after which a still-attached connection is hard-closed
    /// with [`WARREN_MH_DRAINING`] as a backstop. Carried verbatim to the
    /// client so it can schedule its own jittered migration before then.
    pub deadline_unix_secs: u64,
    /// Opaque reason carried verbatim to the client (0 = scheduled
    /// maintenance). Never a destination hint (anti-herding, ADR 36 §7).
    pub reason_code: u8,
}

/// How often each connection re-seals and re-sends its soft `ExitDraining`
/// advisory until the deadline. QUIC datagrams are unreliable, so a single
/// emit can be lost; re-emitting every few seconds bounds the worst-case
/// notice the client loses to one interval. A control message is tiny, so
/// the bandwidth cost is negligible even across a full exit's fleet.
const DRAIN_REEMIT_INTERVAL: Duration = Duration::from_secs(3);

/// Current wall-clock as unix seconds, saturating to 0 before the epoch
/// (never in practice). Used to compare against an absolute drain deadline.
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Spawn the per-connection drain emitter (ADR 36 soft in-band signal).
///
/// It parks on `drain_rx` until the exit publishes a [`DrainAdvisory`]
/// (`None` -> `Some`), then seals an [`WarrenControlMessage::ExitDraining`]
/// with this connection's CURRENT session (so it rides any rekey
/// transparently, like the DAITA timer) and emits it as a downlink
/// datagram, re-emitting every [`DRAIN_REEMIT_INTERVAL`] until the
/// deadline. At the deadline it hard-closes the connection with
/// [`WARREN_MH_DRAINING`] as a backstop for any client that did not
/// migrate. If the advisory is withdrawn before the deadline (operator
/// `undrain`, `Some` -> `None`) the emitter returns WITHOUT closing, so a
/// cancelled maintenance never tears a tunnel down.
///
/// Returns `None` when no `drain_rx` is wired (bench/test/standalone
/// entry points), so callers can skip the abort bookkeeping.
fn spawn_drain_emitter(
    drain_rx: Option<watch::Receiver<Option<DrainAdvisory>>>,
    current: SharedCurrentSession,
    reverse_seq: Arc<AtomicU64>,
    conn: Connection,
) -> Option<tokio::task::JoinHandle<()>> {
    let mut drain_rx = drain_rx?;
    Some(tokio::spawn(async move {
        let encode_adv = |adv: DrainAdvisory| {
            encode_control(&WarrenControlMessage::ExitDraining {
                deadline_unix_secs: adv.deadline_unix_secs,
                reason_code: adv.reason_code,
            })
        };
        // Park until an advisory is published. `borrow_and_update` marks
        // the current value seen so the next `changed()` only fires on a
        // genuine transition. A connection that arrives mid-drain reads
        // `Some` immediately and emits right away.
        let mut advisory = loop {
            if let Some(adv) = *drain_rx.borrow_and_update() {
                break adv;
            }
            if drain_rx.changed().await.is_err() {
                return; // exit shutting down: sender dropped.
            }
        };
        let mut plaintext = match encode_adv(advisory) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "drain: failed to encode ExitDraining; no soft signal");
                return;
            }
        };
        loop {
            // Seal with the connection's latest session (rotates on rekey).
            if let Some((session, epoch)) = current.lock().clone() {
                let seq = reverse_seq.fetch_add(1, Ordering::AcqRel);
                match session.seal_response(&plaintext, epoch, seq) {
                    Ok(frame) => match encode_frame(&frame) {
                        Ok(bytes) => {
                            // Best-effort: a transient PMTU dip can make even
                            // a tiny control frame momentarily TooLarge; the
                            // next re-emit retries. A hard send error means
                            // the conn is gone, so stop.
                            match conn.send_datagram(bytes.into()) {
                                Ok(()) | Err(SendDatagramError::TooLarge) => {}
                                Err(_) => return,
                            }
                        }
                        Err(e) => tracing::trace!(error = %e, "drain: encode_frame failed"),
                    },
                    Err(e) => tracing::trace!(error = %e, "drain: seal_response failed"),
                }
            }
            let now = unix_now_secs();
            if now >= advisory.deadline_unix_secs {
                break;
            }
            let remaining = Duration::from_secs(advisory.deadline_unix_secs - now);
            let nap = DRAIN_REEMIT_INTERVAL.min(remaining);
            tokio::select! {
                _ = tokio::time::sleep(nap) => {}
                // Operator withdrew or RE-PUBLISHED the drain: re-read.
                changed = drain_rx.changed() => {
                    if changed.is_err() {
                        return; // sender dropped (exit shutdown).
                    }
                    match *drain_rx.borrow_and_update() {
                        // Undrain (cancelled maintenance): do NOT hard-close.
                        None => return,
                        // Re-publish with a changed deadline/reason (e.g. the
                        // operator EXTENDS the window): re-arm on the new
                        // advisory so the hard-close honours the latest
                        // deadline and the next emit carries it, instead of
                        // closing at the stale one.
                        Some(new_adv) if new_adv != advisory => {
                            advisory = new_adv;
                            match encode_adv(advisory) {
                                Ok(p) => plaintext = p,
                                Err(e) => {
                                    tracing::warn!(error = %e, "drain: re-encode failed");
                                    return;
                                }
                            }
                        }
                        // Same advisory republished: keep going unchanged.
                        Some(_) => {}
                    }
                }
            }
        }
        // Deadline reached: backstop hard-close. The client should already
        // have migrated off the soft advisory; this only catches stragglers.
        conn.close(VarInt::from_u32(WARREN_MH_DRAINING), &[]);
    }))
}

/// Routes exit-TUN downlink packets to the owning multi-hop connection
/// by inner destination IPv4.
///
/// Replaces the broken model where every connection's TX task competed
/// on a shared `tun.recv()`: the kernel hands each TUN packet to exactly
/// one reader, so with more than one connection a downlink packet went
/// to a random TX task and was sealed for the wrong client's HPKE
/// session - only the first connection ever worked. A single reader
/// task ([`pump_multihop_tun_router`]) instead parses each packet's
/// destination IPv4 and forwards it to that connection's bounded
/// channel; the per-connection TX task then seals and sends as before.
///
/// Only used when the exit allocates inner IPs (ip-nego on). The legacy
/// no-allocator path keeps reading the TUN directly (single client).
/// Bound on each connection's downlink channel. Full ⇒ the router drops
/// (TCP retransmits); sized for a burst without unbounded memory growth.
const DOWNLINK_CHANNEL_BOUND: usize = 1024;

/// Upper bound on bonded downlink channels per assigned IP. Generous
/// vs the client-side bonding cap (8): the overlap window of a sticky
/// reconnect can briefly hold both the dying and the fresh generation.
const MAX_SENDERS_PER_IP: usize = 16;

/// Cap on the per-IP learned-flow table (canonical 5-tuple -> owning
/// downlink sender). Bounds memory when many short flows churn under one
/// sticky IP; at the cap one existing entry is evicted and that flow falls
/// back to the 5-tuple hash until its next uplink packet re-learns the
/// owner. A normal client holds far fewer than this.
const FLOW_TABLE_CAP_PER_IP: usize = 8192;

/// Give up on a connection's RX pump only after this many consecutive
/// TUN write failures. A single transient write error (kernel queue
/// pressure under a burst) used to kill the RX task, which cascaded
/// into a zombie connection: pumps dead, QUIC alive, every flow pinned
/// to it blackholed both ways (2026-06-11 incident, 8-flow collapse).
const MAX_CONSECUTIVE_TUN_WRITE_ERRORS: u32 = 10_000;

/// Delay after a sticky-IP takeover before the stale-predecessor re-check
/// runs. Long enough that a predecessor still serving traffic has advanced
/// its inbound counter (one uplink packet, sub-RTT in practice), short
/// enough to re-pin a dead predecessor's re-used flows in ~2s instead of
/// the ~80s QUIC idle timeout that black-holed a fast single-hop ->
/// multihop reconnect (client kept the same sticky inner IP, so its flows
/// stayed pinned to the just-closed connection's downlink channel).
const TAKEOVER_STALE_RECHECK: Duration = Duration::from_millis(2000);

/// One downlink channel of an assigned IP's fan-out, plus an optional
/// liveness handle. `activity` is a monotonic count of inbound datagrams
/// the owning connection's RX pump has read from its peer; the pump bumps
/// it lock-free on the hot path. It stays frozen the moment that peer goes
/// silent, which is how a takeover re-check tells a dead sticky-reconnect
/// predecessor (client abandoned it, no more uplink) from a live owner
/// still serving traffic. `None` until the pump attaches it (and on the
/// plain channels the unit tests register).
struct Downlink {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    activity: Option<Arc<AtomicU64>>,
}

/// One assigned IP's downlink fan-out: every live connection of the
/// owning client (bonded multi-connection sessions register one channel
/// each, all under the same sticky IP). Flows are pinned to one channel
/// by 5-tuple hash so per-flow ordering is preserved; non-TCP/UDP
/// packets fall back to round-robin.
struct RouteSlot<A> {
    senders: Vec<Downlink>,
    rr: std::sync::atomic::AtomicUsize,
    /// Learned flow ownership: canonical 5-tuple -> the bonded connection
    /// (downlink sender) whose uplink carried that flow. The downlink
    /// prefers this over the 5-tuple hash so two independent sessions
    /// sharing one sticky IP never receive each other's return packets.
    flows: HashMap<u64, tokio::sync::mpsc::Sender<Vec<u8>>>,
    _addr: std::marker::PhantomData<A>,
}

impl<A> RouteSlot<A> {
    fn new(tx: tokio::sync::mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            senders: vec![Downlink { tx, activity: None }],
            rr: std::sync::atomic::AtomicUsize::new(0),
            flows: HashMap::new(),
            _addr: std::marker::PhantomData,
        }
    }

    /// Records (from the uplink) that `key`'s flow is owned by `tx`.
    /// First-writer-wins: the first connection to carry a flow owns its
    /// downlink and keeps it, so a client that spreads one flow's uplink
    /// across several bonded connections still gets its reply on a single
    /// channel (no reordering). A departed owner is purged by
    /// [`RouteTable::unregister_if_owner`], which lets the flow be
    /// re-learned. Bounded by [`FLOW_TABLE_CAP_PER_IP`]: at the cap one
    /// existing entry is evicted (that flow then falls back to the hash
    /// until re-learned).
    fn note_flow(&mut self, key: u64, tx: &tokio::sync::mpsc::Sender<Vec<u8>>) {
        if self.flows.contains_key(&key) {
            return;
        }
        if self.flows.len() >= FLOW_TABLE_CAP_PER_IP
            && let Some(&victim) = self.flows.keys().next()
        {
            self.flows.remove(&victim);
        }
        self.flows.insert(key, tx.clone());
    }
}

/// A predecessor route captured for the sticky-IP takeover re-check: its
/// downlink channel, its inbound-activity counter, and that counter's value
/// at snapshot time. The re-check evicts it iff the counter has not moved.
type PredecessorSnapshot = (tokio::sync::mpsc::Sender<Vec<u8>>, Arc<AtomicU64>, u64);

/// Address-generic route table shared by the IPv4 and IPv6 maps.
struct RouteTable<A: std::hash::Hash + Eq + Copy>(Mutex<HashMap<A, RouteSlot<A>>>);

impl<A: std::hash::Hash + Eq + Copy> Default for RouteTable<A> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<A: std::hash::Hash + Eq + Copy> RouteTable<A> {
    /// Adds `tx` to the slot for `ip`, creating the slot when absent.
    /// A channel already present (same sender) is not duplicated. At
    /// capacity the OLDEST channel is evicted: on a sticky takeover the
    /// stale generation's channels are the oldest, so the semantics
    /// degrade to the historical replace-on-reconnect behavior.
    fn register(&self, ip: A, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
        let mut routes = self.0.lock();
        let slot = routes
            .entry(ip)
            .or_insert_with(|| RouteSlot::new(tx.clone()));
        if slot.senders.iter().any(|s| s.tx.same_channel(&tx)) {
            return;
        }
        if slot.senders.len() >= MAX_SENDERS_PER_IP {
            slot.senders.remove(0);
        }
        slot.senders.push(Downlink { tx, activity: None });
        tracing::info!(
            senders = slot.senders.len(),
            "multihop: bonded downlink route registered"
        );
    }

    /// Attaches an inbound-activity counter to `tx`'s route entry under
    /// `ip`, so a later takeover re-check can judge that connection's
    /// liveness. No-op if the slot or the channel is already gone.
    fn attach_liveness(
        &self,
        ip: A,
        tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
        activity: Arc<AtomicU64>,
    ) {
        let mut routes = self.0.lock();
        if let Some(slot) = routes.get_mut(&ip)
            && let Some(d) = slot.senders.iter_mut().find(|d| d.tx.same_channel(tx))
        {
            d.activity = Some(activity);
        }
    }

    /// Snapshots the OTHER liveness-tracked channels sharing `ip` with
    /// `newcomer` (i.e. the predecessors a sticky-IP takeover just landed
    /// on top of), each paired with its current inbound-activity reading.
    /// A later [`Self::evict_stale_predecessors`] compares against these to
    /// drop only the ones whose peer stayed silent. Empty when `newcomer`
    /// is the sole owner (no takeover). Channels with no liveness handle
    /// are excluded: their liveness is unknown, so they are never evicted.
    fn snapshot_predecessors(
        &self,
        ip: A,
        newcomer: &tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Vec<PredecessorSnapshot> {
        let routes = self.0.lock();
        let Some(slot) = routes.get(&ip) else {
            return Vec::new();
        };
        slot.senders
            .iter()
            .filter(|d| !d.tx.same_channel(newcomer))
            .filter_map(|d| {
                d.activity
                    .as_ref()
                    .map(|a| (d.tx.clone(), a.clone(), a.load(Ordering::Relaxed)))
            })
            .collect()
    }

    /// Drops every predecessor from `snapshot` whose inbound-activity
    /// counter has NOT advanced since the snapshot: a frozen counter means
    /// the peer went silent (a dead sticky-reconnect predecessor), so its
    /// channel and learned flows are removed and the re-used flows re-pin
    /// to a live sender on the next downlink packet instead of black-holing
    /// until the QUIC idle timeout. A predecessor still serving traffic has
    /// advanced its counter and is left untouched (first-writer-wins owner
    /// preference is preserved for a genuinely live owner). Returns how many
    /// were evicted.
    fn evict_stale_predecessors(&self, ip: A, snapshot: &[PredecessorSnapshot]) -> usize {
        let mut evicted = 0;
        for (tx, activity, seen) in snapshot {
            if activity.load(Ordering::Relaxed) == *seen {
                self.unregister_if_owner(ip, tx);
                evicted += 1;
            }
        }
        evicted
    }

    /// Removes ONLY `owner`'s channel from `ip`'s slot (and the slot
    /// itself once empty). A dying connection must not tear down the
    /// channels of its bonded siblings, nor of a same-pubkey successor
    /// that took the address over.
    fn unregister_if_owner(&self, ip: A, owner: &tokio::sync::mpsc::Sender<Vec<u8>>) {
        let mut routes = self.0.lock();
        if let Some(slot) = routes.get_mut(&ip) {
            slot.senders.retain(|s| !s.tx.same_channel(owner));
            // Drop any learned flow pointing at the departed channel so a
            // stale owner can never be re-selected on the downlink.
            slot.flows.retain(|_, s| !s.same_channel(owner));
            if slot.senders.is_empty() {
                routes.remove(&ip);
            }
        }
    }

    /// Learns (from an uplink packet) that `key`'s flow is owned by
    /// `owner` under `ip`. No-op if the slot is gone (connection closed).
    fn note_flow(&self, ip: A, key: u64, owner: &tokio::sync::mpsc::Sender<Vec<u8>>) {
        let mut routes = self.0.lock();
        if let Some(slot) = routes.get_mut(&ip) {
            slot.note_flow(key, owner);
        }
    }

    /// Snapshot of the addresses with at least one live downlink route.
    /// These are the tunnel IPs that currently hold a multi-hop session;
    /// the NAT-PMP orphan reaper diffs them against the allocator's active
    /// internal IPs to find departed clients.
    fn snapshot_keys(&self) -> Vec<A> {
        self.0.lock().keys().copied().collect()
    }

    /// Picks the channel for `pkt` and try-sends. Selection order: the
    /// flow's learned owner (recorded from the uplink, so a session only
    /// ever gets its own return traffic even when several sessions share
    /// one sticky IP), else the 5-tuple hash (per-flow ordering for a
    /// single bonded client), else round-robin. A `Closed` channel is
    /// pruned in place and the packet is retried on the survivors; a
    /// `Full` channel drops the packet (TCP retransmits).
    fn dispatch(&self, ip: A, pkt: &[u8]) {
        let flow_key = canonical_flow_key(pkt);
        loop {
            let tx = {
                let routes = self.0.lock();
                let Some(slot) = routes.get(&ip) else {
                    return;
                };
                let n = slot.senders.len();
                if n == 0 {
                    return;
                }
                // Prefer the flow's learned owner, but only while it is
                // still a live sender under this IP; otherwise fall back to
                // the hash so a departed owner never black-holes the flow.
                let owned = flow_key
                    .and_then(|k| slot.flows.get(&k))
                    .filter(|owner| slot.senders.iter().any(|s| s.tx.same_channel(owner)))
                    .cloned();
                match owned {
                    Some(owner) => owner,
                    None => {
                        let idx = match warrenguard_transport_core::flow_hash_5tuple(pkt) {
                            Some(h) => (h as usize) % n,
                            None => slot.rr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % n,
                        };
                        slot.senders[idx].tx.clone()
                    }
                }
            };
            match tx.try_send(pkt.to_vec()) {
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    self.unregister_if_owner(ip, &tx);
                    // Retry on the remaining channels (the loop exits via
                    // the `return` above once the slot is empty).
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Drop (TCP retransmits), but keep the loss visible: a
                    // sustained Full means this connection's tx task is not
                    // draining and every flow pinned to it stalls silently.
                    static FULL_DROPS: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
                    let n = FULL_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if n.is_multiple_of(5_000) {
                        tracing::warn!(
                            total_drops = n + 1,
                            "multihop: downlink channel full, dropping (rate-limited log)"
                        );
                    }
                    return;
                }
                Ok(()) => return,
            }
        }
    }
}

#[derive(Default)]
struct MultihopTunRouter {
    routes: RouteTable<Ipv4Addr>,
    /// Multi-hop `/v2` dual-stack: per-connection downlink channels keyed
    /// on the assigned IPv6. Same one-reader-fans-out model as `routes`;
    /// a single TUN reader dispatches each downlink packet to the owning
    /// connection(s) by destination address, IPv4 or IPv6.
    routes_v6: RouteTable<Ipv6Addr>,
}

impl MultihopTunRouter {
    /// Registers a downlink channel for `ip` (bonded connections of the
    /// same client stack up under one slot; see [`RouteTable::register`]).
    fn register(&self, ip: Ipv4Addr, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
        self.routes.register(ip, tx);
    }

    /// Removes the downlink route for `ip` ONLY where it points at
    /// `owner`'s channel. See [`RouteTable::unregister_if_owner`].
    fn unregister_if_owner(&self, ip: Ipv4Addr, owner: &tokio::sync::mpsc::Sender<Vec<u8>>) {
        self.routes.unregister_if_owner(ip, owner);
    }

    /// Tunnel IPv4s that currently hold a live downlink route (i.e. an
    /// active multi-hop session). Source of truth for the NAT-PMP orphan
    /// reaper in multi-hop mode.
    fn active_ipv4s(&self) -> std::collections::HashSet<Ipv4Addr> {
        self.routes.snapshot_keys().into_iter().collect()
    }

    /// `/v2` dual-stack mirror of [`Self::unregister_if_owner`].
    fn unregister_v6_if_owner(&self, ip: Ipv6Addr, owner: &tokio::sync::mpsc::Sender<Vec<u8>>) {
        self.routes_v6.unregister_if_owner(ip, owner);
    }

    /// `/v2` dual-stack: register a downlink channel for an assigned
    /// IPv6 (same stacking semantics as [`Self::register`]).
    fn register_v6(&self, ip: Ipv6Addr, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
        self.routes_v6.register(ip, tx);
    }

    /// Attach a connection's inbound-activity counter to its downlink
    /// route(s) (see [`RouteTable::attach_liveness`]).
    fn attach_liveness(
        &self,
        ip: Ipv4Addr,
        tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
        activity: Arc<AtomicU64>,
    ) {
        self.routes.attach_liveness(ip, tx, activity);
    }

    /// `/v2` dual-stack mirror of [`Self::attach_liveness`].
    fn attach_liveness_v6(
        &self,
        ip: Ipv6Addr,
        tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
        activity: Arc<AtomicU64>,
    ) {
        self.routes_v6.attach_liveness(ip, tx, activity);
    }

    /// Snapshot the predecessors a sticky-IP takeover landed on (see
    /// [`RouteTable::snapshot_predecessors`]).
    fn snapshot_predecessors(
        &self,
        ip: Ipv4Addr,
        newcomer: &tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Vec<PredecessorSnapshot> {
        self.routes.snapshot_predecessors(ip, newcomer)
    }

    /// `/v2` dual-stack mirror of [`Self::snapshot_predecessors`].
    fn snapshot_predecessors_v6(
        &self,
        ip: Ipv6Addr,
        newcomer: &tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Vec<PredecessorSnapshot> {
        self.routes_v6.snapshot_predecessors(ip, newcomer)
    }

    /// Evict the predecessors whose peer went silent (see
    /// [`RouteTable::evict_stale_predecessors`]).
    fn evict_stale_predecessors(&self, ip: Ipv4Addr, snapshot: &[PredecessorSnapshot]) -> usize {
        self.routes.evict_stale_predecessors(ip, snapshot)
    }

    /// `/v2` dual-stack mirror of [`Self::evict_stale_predecessors`].
    fn evict_stale_predecessors_v6(&self, ip: Ipv6Addr, snapshot: &[PredecessorSnapshot]) -> usize {
        self.routes_v6.evict_stale_predecessors(ip, snapshot)
    }

    /// Routes one inner packet to a connection owning its destination
    /// address. Handles both IPv4 and IPv6 inner packets (multi-hop
    /// `/v2` dual-stack). Drops silently when there is no route, the
    /// packet is neither v4 nor v6, or the channel is full (TCP
    /// retransmits); prunes channels whose receiver is gone.
    fn dispatch(&self, pkt: &[u8]) {
        match pkt.first().map(|b| b >> 4) {
            Some(6) => {
                if let Some(dst) = dst_ipv6(pkt) {
                    self.routes_v6.dispatch(dst, pkt);
                }
            }
            _ => {
                if let Some(dst) = dst_ipv4(pkt) {
                    self.routes.dispatch(dst, pkt);
                }
            }
        }
    }

    /// Learn, from an uplink packet, which bonded connection (`owner`) owns
    /// its flow, keyed on the client's own source IP (the slot the downlink
    /// reply targets). MUST be called only AFTER the anti-spoof gate has
    /// proven the source IP is this connection's allocation, so one client
    /// can never plant a flow owner under another client's IP.
    fn note_uplink(&self, pkt: &[u8], owner: &tokio::sync::mpsc::Sender<Vec<u8>>) {
        let Some(key) = canonical_flow_key(pkt) else {
            return;
        };
        match pkt.first().map(|b| b >> 4) {
            Some(6) => {
                if let Some(src) = src_ipv6(pkt) {
                    self.routes_v6.note_flow(src, key, owner);
                }
            }
            _ => {
                if let Some(src) = src_ipv4(pkt) {
                    self.routes.note_flow(src, key, owner);
                }
            }
        }
    }
}

/// Extracts the destination IPv4 from a raw inner IP packet, or `None`
/// when the packet is too short or not IPv4.
fn dst_ipv4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

/// Extracts the destination IPv6 from a raw inner IP packet, or `None`
/// when the packet is too short or not IPv6. The IPv6 header is fixed at
/// 40 bytes with the destination address in the last 16 (offset 24..40).
fn dst_ipv6(pkt: &[u8]) -> Option<Ipv6Addr> {
    if pkt.len() < 40 || (pkt[0] >> 4) != 6 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&pkt[24..40]);
    Some(Ipv6Addr::from(octets))
}

/// Extracts the source IPv4 from a raw inner IP packet (offset 12..16), or
/// `None` when too short or not IPv4. On the uplink the source is the
/// client's own allocated address (the anti-spoof gate has already proven
/// it), which is the slot key the downlink uses as destination.
fn src_ipv4(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// Extracts the source IPv6 from a raw inner IP packet (offset 8..24), or
/// `None` when too short or not IPv6.
fn src_ipv6(pkt: &[u8]) -> Option<Ipv6Addr> {
    if pkt.len() < 40 || (pkt[0] >> 4) != 6 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&pkt[8..24]);
    Some(Ipv6Addr::from(octets))
}

/// Direction-agnostic hash of an inner packet's flow, so an uplink packet
/// (src=client, dst=peer) and its downlink reply (src=peer, dst=client)
/// map to the SAME key. It hashes `(proto, min(endpoint), max(endpoint))`
/// where an endpoint is `(ip, port)`, ordering the two endpoints so the
/// direction drops out. Returns `None` for non-TCP/UDP or malformed
/// packets (the caller then falls back to the plain 5-tuple hash).
///
/// This is the key under which the exit learns, from the uplink, which
/// bonded connection owns a flow, so the downlink returns to the same
/// session instead of being split by a blind hash across every session
/// that happens to share one sticky IP.
fn canonical_flow_key(pkt: &[u8]) -> Option<u64> {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let first = *pkt.first()?;
    let mut h: u64 = FNV_OFFSET;
    let mut feed = |bytes: &[u8]| {
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
    };
    match first >> 4 {
        4 => {
            if pkt.len() < 24 {
                return None;
            }
            let ihl = (first & 0x0f) as usize * 4;
            if ihl < 20 || pkt.len() < ihl + 4 {
                return None;
            }
            let proto = pkt[9];
            if proto != 6 && proto != 17 {
                return None;
            }
            let mut a = [0u8; 6];
            a[..4].copy_from_slice(&pkt[12..16]);
            a[4..].copy_from_slice(&pkt[ihl..ihl + 2]);
            let mut b = [0u8; 6];
            b[..4].copy_from_slice(&pkt[16..20]);
            b[4..].copy_from_slice(&pkt[ihl + 2..ihl + 4]);
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            feed(&[proto]);
            feed(&lo);
            feed(&hi);
            Some(h)
        }
        6 => {
            if pkt.len() < 44 {
                return None;
            }
            let next = pkt[6];
            if next != 6 && next != 17 {
                return None;
            }
            let mut a = [0u8; 18];
            a[..16].copy_from_slice(&pkt[8..24]);
            a[16..].copy_from_slice(&pkt[40..42]);
            let mut b = [0u8; 18];
            b[..16].copy_from_slice(&pkt[24..40]);
            b[16..].copy_from_slice(&pkt[42..44]);
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            feed(&[next]);
            feed(&lo);
            feed(&hi);
            Some(h)
        }
        _ => None,
    }
}

/// Single TUN reader: forwards each downlink packet to the owning
/// connection's channel via [`MultihopTunRouter::dispatch`].
///
/// MUST survive transient TUN read errors (EINTR/ENOBUFS bursts under
/// high PPS): this task is the downlink for EVERY client of the exit,
/// and the 2026-06-11 incident showed that exiting on the first error
/// blackholes all connected users silently (QUIC stays alive, so
/// clients keep a dead "Connected" until the service is restarted).
/// Only a long unbroken error streak (TUN truly gone) ends the task.
async fn pump_multihop_tun_router<T: PacketDevice>(tun: T, router: Arc<MultihopTunRouter>) {
    const MAX_CONSECUTIVE_TUN_ERRORS: u32 = 10_000;
    let mut consecutive_errors: u32 = 0;
    loop {
        match tun.recv().await {
            Ok(pkt) => {
                consecutive_errors = 0;
                router.dispatch(&pkt);
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors == 1 || consecutive_errors.is_multiple_of(1_000) {
                    tracing::warn!(
                        error = %e,
                        consecutive_errors,
                        "multihop TUN reader: transient read error, retrying"
                    );
                }
                if consecutive_errors >= MAX_CONSECUTIVE_TUN_ERRORS {
                    tracing::error!(
                        "multihop TUN reader: TUN permanently unreadable, downlink stops                          (exit needs a restart)"
                    );
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
    }
}

/// Reads the next downlink packet for a connection's TX task: from the
/// router channel when ip-nego is on (per-IP routed by the single TUN
/// reader), else directly from the shared TUN (legacy single-client).
/// Returns `None` when the source is exhausted (channel senders all
/// dropped, or TUN error) so the caller's TX loop exits.
async fn next_downlink<T: PacketDevice>(
    down_rx: &mut Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    tun: &T,
) -> Option<Vec<u8>> {
    match down_rx {
        Some(rx) => rx.recv().await,
        None => tun.recv().await.ok(),
    }
}

/// Process-wide count of downlink packets tail-dropped by the over-read
/// backpressure gate. Kept observable (rate-limited log) so the early-drop
/// volume can be A/B-compared against the fork's CoDel `dropped_overflow`
/// stat when tuning `WARREN_EXIT_OVERREAD_GATE`.
static OVERREAD_GATE_DROPS: AtomicU64 = AtomicU64::new(0);

/// Fallback MTU when the peer has not yet advertised a datagram frame size
/// (`max_datagram_size()` is `None`): the Warren tunnel floor.
const OVERREAD_GATE_FALLBACK_MTU: usize = 1280;

/// Exit downlink over-read backpressure: `true` when this packet must be
/// tail-dropped because `conn`'s datagram send buffer is within `gate_mtus`
/// MTUs of full.
///
/// With N multi-queue TUN readers feeding one client's single QUIC connection,
/// the aggregate read rate can far exceed the connection's BBR-limited drain
/// rate. The excess piles into the datagram send buffer until the fork's CoDel
/// head-drops (and `send_datagram`'s overflow drops) the OLDEST in-flight
/// datagrams, which is exactly what the inner TCP is waiting to ACK, spiking
/// its retransmits. Dropping the NEWEST packet at the reader keeps the standing
/// queue shallow, so inner-TCP RTT and loss recovery stay fast.
///
/// `datagram_send_buffer_space()` is relative to the LIVE (BDP-adaptive) buffer
/// limit, so a small MTU-multiple low-water stays correct as fork.11 shrinks
/// the buffer toward the path BDP (no fixed-16-MiB constant). `gate_mtus == 0`
/// disables the gate; when the buffer has room it is a no-op, so the gate can
/// only ever reduce occupancy.
fn overread_gate_should_drop(conn: &Connection, gate_mtus: usize) -> bool {
    if gate_mtus == 0 {
        return false;
    }
    let mtu = conn
        .max_datagram_size()
        .unwrap_or(OVERREAD_GATE_FALLBACK_MTU);
    if !overread_should_drop(conn.datagram_send_buffer_space(), mtu, gate_mtus) {
        return false;
    }
    let n = OVERREAD_GATE_DROPS.fetch_add(1, Ordering::Relaxed);
    if n.is_multiple_of(50_000) {
        tracing::debug!(
            total_drops = n + 1,
            "exit downlink over-read gate: tail-drop (rate-limited log)"
        );
    }
    true
}

/// Pure over-read decision: drop when fewer than `gate_mtus` MTUs of buffer
/// `space` remain. `gate_mtus == 0` disables the gate. The threshold scales
/// with `mtu` (the connection's live datagram size), so it stays relative to
/// the BDP-adaptive buffer rather than a fixed byte constant. Split out from
/// the connection read so the boundary/relative-keying logic is unit-testable
/// without a live QUIC connection.
fn overread_should_drop(space: usize, mtu: usize, gate_mtus: usize) -> bool {
    if gate_mtus == 0 {
        return false;
    }
    space < gate_mtus.saturating_mul(mtu)
}

/// Multi-hop termination with TUN bridge.
///
/// Variant of [`serve_multihop_echo`] that forwards opened plaintext
/// IP packets onto a local TUN device instead of echoing them back.
/// Each accepted connection drives a bidirectional pump:
///
/// - **RX (client -> exit -> TUN)**: `Quinn::read_datagram` -> `decode_frame`
///   -> [`SessionCache`] lookup -> [`ExitSession::open`] -> `tun.send`.
/// - **TX (TUN -> exit -> client)**: a single TUN reader
///   ([`pump_multihop_tun_router`]) routes each packet to the owning
///   connection by destination IPv4, which then seals it with its
///   latest [`ExitSession::seal_response`] (a rekey replaces the sealing
///   context atomically) -> `encode_frame` -> `Quinn::send_datagram`.
///   When ip-nego is off (no allocator) the single client reads the TUN
///   directly.
///
/// The reverse-direction seq counter is connection-local and resets
/// to zero per connection. The client-side anti-replay window
/// observes the exit's counter via the per-epoch `ReplayWindow` slot
/// (cf. the client `multi_hop::MultiHopClient` doctrine overlap
/// state).
///
/// # Errors
///
/// - [`MultihopExitError::EndpointClosed`] when the underlying
///   `endpoint.accept()` returns `None`.
pub async fn serve_multihop_with_tun<T>(
    endpoint: Endpoint,
    exit_x25519_privkey: WarrenKemPrivateKey,
    exit_id: ExitId,
    tun: T,
) -> Result<(), MultihopExitError>
where
    T: PacketDevice + Clone,
{
    serve_multihop_with_tun_and_daita(
        endpoint,
        exit_x25519_privkey,
        exit_id,
        tun,
        None,
        None,
        None,
        None,
    )
    .await
}

/// DAITA-aware variant of [`serve_multihop_with_tun`].
///
/// When `daita_config` is `Some(cfg)` and the config is enabled,
/// every accepted multi-hop connection builds a fresh
/// [`DaitaState`] from that config and runs a third "padding timer"
/// task alongside the standard rx + tx pumps. The timer drives the
/// maybenot framework over the per-conn [`DaitaState`] and emits
/// DAITA dummies on the reverse direction when the per-machine
/// action timer expires.
///
/// `None` / disabled config = strict alias of
/// [`serve_multihop_with_tun`] (zero overhead, no extra tasks).
///
/// This entry point runs one FIXED config for every connection (each conn
/// still gets an independent [`DaitaState`] instance: separate maybenot
/// timers + RNG), which is what tests and pinned ops investigations need.
/// The production dispatcher instead arms a curated pool on the shared
/// ctx ([`ExitTerminateCtx::with_daita_pool`]) so every connection samples
/// its own machine. Either way, a `wants_daita` client is granted the spec
/// this connection actually runs, via `IpAssign.daita_spec`.
///
/// # Errors
///
/// See [`serve_multihop_with_tun`].
#[allow(clippy::too_many_arguments)]
pub async fn serve_multihop_with_tun_and_daita<T>(
    endpoint: Endpoint,
    exit_x25519_privkey: WarrenKemPrivateKey,
    exit_id: ExitId,
    tun: T,
    daita_config: Option<warrenguard_wire::DaitaConfig>,
    daita_machine_name: Option<String>,
    ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
    ip_allocator_v6: Option<Arc<Mutex<IpAllocatorV6>>>,
) -> Result<(), MultihopExitError>
where
    T: PacketDevice + Clone,
{
    let ctx = ExitTerminateCtx::new(
        exit_x25519_privkey,
        exit_id,
        tun,
        daita_config,
        daita_machine_name,
        ip_allocator,
        ip_allocator_v6,
        // Standalone-listener entry point (tests / legacy single-tenant):
        // no allowlist, every client admitted. The production unified
        // dispatcher passes a real allowlist via `ExitTerminateCtx::new`
        // in `run_multihop_mode`.
        None,
    );
    while let Some(incoming) = endpoint.accept().await {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "multihop incoming handshake failed");
                    return;
                }
            };
            terminate_connection(conn, SetupSource::AcceptFromConn, ctx).await;
        });
    }
    Err(MultihopExitError::EndpointClosed)
}

/// Per-connection datapath counters for node telemetry (doc 52 §4.2),
/// read from `quinn::Connection::stats()` in production. The byte and
/// packet fields are cumulative for the connection's lifetime; `rtt_us`
/// is the current smoothed RTT. Node-level aggregation (summing across
/// connections, never surfacing a per-client identifier, invariant I2)
/// happens in the exit telemetry sampler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnDatapathStats {
    /// Bytes sent on the wire (all QUIC traffic over UDP), cumulative.
    pub bytes_tx: u64,
    /// Bytes received on the wire, cumulative.
    pub bytes_rx: u64,
    /// UDP datagrams sent, cumulative.
    pub datagrams_tx: u64,
    /// UDP datagrams received, cumulative.
    pub datagrams_rx: u64,
    /// Packets QUIC declared lost, cumulative.
    pub lost_packets: u64,
    /// Congestion events, cumulative.
    pub congestion_events: u64,
    /// Current smoothed RTT in microseconds (a gauge, not cumulative).
    pub rtt_us: u32,
}

/// A connection that can be force-closed on revocation. Implemented for
/// the real `quinn::Connection` in production; the test suite supplies a
/// fake that records closes, so the registry's bookkeeping can be tested
/// without a live QUIC handshake. `pub` only because it appears as a
/// bound on [`MultihopSessionRegistry`]; not part of the intended API.
pub trait ClosableConn: Send + Sync + 'static {
    /// Close the connection with the opaque multi-hop policy-rejection
    /// code (the same one every setup-time rejection uses, so a relay
    /// observing the close learns nothing about the client's status).
    fn close_rejected(&self);

    /// Live datapath counters for node telemetry, or `None` for a
    /// connection type that does not track them (test fakes). Default
    /// `None` so existing impls compile unchanged.
    fn datapath_stats(&self) -> Option<ConnDatapathStats> {
        None
    }

    /// The immediate QUIC peer's outer socket address (5-tuple source), or
    /// `None` for a connection type that does not expose one (test fakes).
    /// Feeds the Port Fail defense-in-depth guard's connected-real-IP set via
    /// [`MultihopSessionRegistry::snapshot_ipv4_sources_excluding`]. Default
    /// `None` so existing impls compile unchanged.
    fn remote_address(&self) -> Option<std::net::SocketAddr> {
        None
    }
}

impl ClosableConn for Connection {
    fn close_rejected(&self) {
        self.close(quinn::VarInt::from_u32(WARREN_MH_REJECTED), &[]);
    }

    fn remote_address(&self) -> Option<std::net::SocketAddr> {
        // Inherent `quinn::Connection::remote_address` (not this trait method).
        Some(quinn::Connection::remote_address(self))
    }

    fn datapath_stats(&self) -> Option<ConnDatapathStats> {
        let s = self.stats();
        Some(ConnDatapathStats {
            bytes_tx: s.udp_tx.bytes,
            bytes_rx: s.udp_rx.bytes,
            datagrams_tx: s.udp_tx.datagrams,
            datagrams_rx: s.udp_rx.datagrams,
            lost_packets: s.path.lost_packets,
            congestion_events: s.path.congestion_events,
            rtt_us: u32::try_from(s.path.rtt.as_micros()).unwrap_or(u32::MAX),
        })
    }
}

/// How long a departed client's tunnel-IP attribution is retained past its last
/// connection. It must outlast the orphan reaper's worst-case reclaim of the
/// NAT-PMP lease that same client leaves behind on this exit (cf.
/// `warren-exit::natpmp_orphan_reaper`: grace 30s + check interval 10s), so the
/// lingering lease is still attributed to its real owner instead of flipping to
/// `unknown` on the old exit for the window right after a change. Bounded, so
/// client churn cannot grow the map without end.
const DEPARTED_ATTRIBUTION_RETENTION: Duration = Duration::from_secs(60);

/// One tunnel-IP attribution entry for the admin port-forward view.
struct Ipv4Owner {
    pubkey: WarrenPubkey,
    /// `None` while the client has a live session. `Some(deadline)` once its
    /// last connection has left: the entry stays resolvable until `deadline`
    /// (see [`DEPARTED_ATTRIBUTION_RETENTION`]) so the orphan lease it leaves
    /// behind keeps its real owner until the reaper sweeps it.
    departed_deadline: Option<Instant>,
}

/// Registry of live multi-hop connections keyed by the account pubkey
/// that was admitted at setup.
///
/// Why this exists: the exit allowlist gate (`allowlist_admits`) runs
/// ONCE, at setup. Without this registry a pubkey that is de-allowlisted
/// or CRL-revoked mid-session keeps its tunnel until the client happens
/// to reconnect, an egress window bounded only by the client. The
/// refresh/CRL loops already broadcast the revoked pubkeys on the
/// `AllowlistHandle` revocation channel; this registry is what lets the
/// dispatcher act on that broadcast and force-close the in-flight
/// connection, bounding revocation latency to one poll interval.
///
/// A bonded client opens several QUIC connections under one pubkey, so a
/// pubkey maps to a set of `(conn_id, conn)`; a revocation closes them
/// all. Generic over [`ClosableConn`] (defaulting to the real
/// `quinn::Connection`) purely for unit-testability.
pub struct MultihopSessionRegistry<C: ClosableConn = Connection> {
    live: Mutex<HashMap<WarrenPubkey, HashMap<ConnId, C>>>,
    /// Reverse map `assigned tunnel IPv4 -> owning account`, recorded at setup
    /// once the IP is allocated. Lets `port_forward_sync` attribute each NAT-PMP
    /// allocation (keyed by internal tunnel IP) to the owning subscriber in the
    /// admin view instead of showing `unknown`. A bonded client's connections
    /// share one sticky IP, so this holds one entry per client; a departed
    /// client's entry is tombstoned (not dropped) until its lease can no longer
    /// linger (see [`Ipv4Owner::departed_deadline`]).
    ipv4_to_pubkey: Mutex<HashMap<Ipv4Addr, Ipv4Owner>>,
}

impl<C: ClosableConn> Default for MultihopSessionRegistry<C> {
    fn default() -> Self {
        Self {
            live: Mutex::new(HashMap::new()),
            ipv4_to_pubkey: Mutex::new(HashMap::new()),
        }
    }
}

impl<C: ClosableConn> MultihopSessionRegistry<C> {
    /// Build a shared, empty registry.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a live connection admitted under `pubkey`. Called once per
    /// connection, right after the setup gate admits it. Re-registering
    /// the same `(pubkey, conn_id)` overwrites the previous handle (a
    /// sticky reconnect reusing the stable id), which is harmless.
    fn register(&self, pubkey: WarrenPubkey, conn_id: ConnId, conn: C) {
        self.live
            .lock()
            .entry(pubkey)
            .or_default()
            .insert(conn_id, conn);
    }

    /// Remove one connection from the registry (called from the RAII
    /// [`SessionGuard`] when the handler ends). Idempotent.
    fn unregister(&self, pubkey: &WarrenPubkey, conn_id: ConnId) {
        let mut guard = self.live.lock();
        if let Some(conns) = guard.get_mut(pubkey) {
            conns.remove(&conn_id);
            if conns.is_empty() {
                guard.remove(pubkey);
                drop(guard);
                self.tombstone_attribution(pubkey, Instant::now());
            }
        }
    }

    /// Record the `(assigned tunnel IPv4 -> owning account)` pair, called once
    /// the IP is allocated at setup. Bonded connections share one sticky IP, so
    /// re-recording the same pair is a harmless overwrite; a reconnect on the
    /// same IP also revives a tombstoned entry (back to a live session).
    fn record_assigned_ipv4(&self, ipv4: Ipv4Addr, pubkey: WarrenPubkey) {
        self.ipv4_to_pubkey.lock().insert(
            ipv4,
            Ipv4Owner {
                pubkey,
                departed_deadline: None,
            },
        );
    }

    /// Mark every still-live entry owned by `pubkey` as departed at `now`, so it
    /// stays resolvable for [`DEPARTED_ATTRIBUTION_RETENTION`] before a snapshot
    /// reaps it. A graceful disconnect (exit change) leaves an orphan NAT-PMP
    /// lease the reaper reclaims later, unlike a `terminate` revoke which tears
    /// the lease down at once and so clears attribution immediately.
    fn tombstone_attribution(&self, pubkey: &WarrenPubkey, now: Instant) {
        let deadline = now + DEPARTED_ATTRIBUTION_RETENTION;
        for owner in self.ipv4_to_pubkey.lock().values_mut() {
            if &owner.pubkey == pubkey && owner.departed_deadline.is_none() {
                owner.departed_deadline = Some(deadline);
            }
        }
    }

    /// Snapshot of `tunnel IPv4 -> 64-char pubkey hex`, consumed by
    /// `port_forward_sync` to attribute NAT-PMP allocations to the owning
    /// subscriber in the admin view. Admin-only surface (behind admin auth).
    #[must_use]
    pub fn snapshot_ipv4_to_pubkey_hex(&self) -> HashMap<Ipv4Addr, String> {
        self.snapshot_ipv4_to_pubkey_hex_at(Instant::now())
    }

    /// `now`-injected core of [`snapshot_ipv4_to_pubkey_hex`]: lazily drops
    /// tombstoned entries whose retention has elapsed, then returns the rest.
    fn snapshot_ipv4_to_pubkey_hex_at(&self, now: Instant) -> HashMap<Ipv4Addr, String> {
        let mut map = self.ipv4_to_pubkey.lock();
        map.retain(|_, owner| owner.departed_deadline.is_none_or(|d| now < d));
        map.iter()
            .map(|(ip, owner)| (*ip, owner.pubkey.to_hex()))
            .collect()
    }

    /// Force-close every live connection admitted under `pubkey`.
    /// Returns the number of connections closed. Idempotent: a pubkey
    /// with no live connection returns 0. The entry is removed under the
    /// lock first, then the closes happen outside it, so a concurrent
    /// `unregister` from a closing handler cannot deadlock or double-act.
    #[must_use]
    pub fn terminate(&self, pubkey: &WarrenPubkey) -> usize {
        let conns = self.live.lock().remove(pubkey).unwrap_or_default();
        self.ipv4_to_pubkey
            .lock()
            .retain(|_, owner| &owner.pubkey != pubkey);
        let n = conns.len();
        for (_id, conn) in conns {
            conn.close_rejected();
        }
        n
    }

    /// Number of distinct client pubkeys with at least one live
    /// connection (ADR 36 §6: the multi-hop "clients remaining" gauge an
    /// operator watches drain to 0). A bonded client opens several
    /// connections under one pubkey but counts once. Aggregate count only,
    /// never a per-client identifier (no-log safe).
    #[must_use]
    pub fn live_client_count(&self) -> usize {
        self.live.lock().len()
    }

    /// Per-connection datapath stats for the telemetry sampler (doc 52
    /// §4.2), keyed by each connection's stable id so the sampler can
    /// accumulate monotonic node totals across reconnects. One entry per
    /// live connection that reports stats (a test fake without stats is
    /// skipped). No pubkey leaves this method: it returns opaque
    /// connection ids only, so node-level aggregation stays I2-safe.
    #[must_use]
    pub fn datapath_stats(&self) -> Vec<(ConnId, ConnDatapathStats)>
    where
        C: Clone,
    {
        // Snapshot the connection handles (a cheap Arc bump for the real
        // `quinn::Connection`) under the lock, then query each stat OUTSIDE
        // it: `Connection::stats()` contends with the per-connection IO
        // driver, so holding `live` across all of them would periodically
        // stall the hot register/unregister/terminate path on a busy exit.
        let handles: Vec<(ConnId, C)> = {
            let guard = self.live.lock();
            guard
                .values()
                .flat_map(|conns| conns.iter().map(|(id, conn)| (*id, conn.clone())))
                .collect()
        };
        handles
            .into_iter()
            .filter_map(|(id, conn)| conn.datapath_stats().map(|stats| (id, stats)))
            .collect()
    }

    /// Connected-subscriber real source IPv4s for the Port Fail defense-in-depth
    /// guard (doc 76), EXCLUDING every address in `exclude`.
    ///
    /// A 1-hop client's connection carries its real source IP (what the guard
    /// must drop when it hits another subscriber's forwarded port). A 2-hop
    /// exit-leg instead carries a Warren relay's IP; under Warren's mono-IP
    /// invariant that equals the relay's advertised fleet endpoint, so passing
    /// the fleet endpoint IPs as `exclude` keeps relay IPs out of the set. This
    /// is load-bearing: a relay IP in the drop set would blackhole forwarded-port
    /// access for EVERY client behind that relay (doc 76 section 2). A native-v6
    /// peer is skipped (the guard set is v4-only). The connection handles are
    /// snapshotted under the lock, then read outside it, mirroring
    /// [`Self::datapath_stats`].
    #[must_use]
    pub fn snapshot_ipv4_sources_excluding(
        &self,
        exclude: &std::collections::BTreeSet<Ipv4Addr>,
    ) -> std::collections::BTreeSet<Ipv4Addr>
    where
        C: Clone,
    {
        let handles: Vec<C> = {
            let guard = self.live.lock();
            guard
                .values()
                .flat_map(|conns| conns.values().cloned())
                .collect()
        };
        handles
            .iter()
            .filter_map(|c| c.remote_address())
            .filter_map(ipv4_source_of)
            .filter(|ip| !exclude.contains(ip))
            .collect()
    }
}

/// Extract the IPv4 source of a peer socket address for the Port Fail guard:
/// a native v4 address as-is, a v4-mapped v6 address unmapped to its v4 form,
/// and a genuine v6 address skipped (`None`). Shares the `ipv4_source_of`
/// keying used by the exit's Port-Fail guard set.
#[must_use]
fn ipv4_source_of(addr: std::net::SocketAddr) -> Option<Ipv4Addr> {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// RAII guard that removes a connection from the [`MultihopSessionRegistry`]
/// when dropped. Carried in [`ConnSetup`] so the deregistration is tied to
/// the connection handler's lifetime: every exit path (normal close, early
/// return on a pump failure, or a panic unwind) unregisters exactly once,
/// with no manual cleanup call to forget.
struct SessionGuard {
    registry: Arc<MultihopSessionRegistry>,
    pubkey: WarrenPubkey,
    conn_id: ConnId,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.registry.unregister(&self.pubkey, self.conn_id);
    }
}

/// How an exit chooses the DAITA machine for each connection it terminates.
///
/// The curated pool must be sampled per connection: the spread of defenses an
/// observer sees across an exit's clients is the reason the pool exists, and one
/// machine shared by every client collapses that spread to a single behaviour.
/// The production path therefore carries the pool ([`Self::Pool`]), not a
/// config. [`Self::Fixed`] is the deterministic variant the datapath tests and a
/// pinned ops investigation need.
#[derive(Clone)]
pub enum DaitaSource {
    /// DAITA off: every connection runs the plain pump at zero overhead.
    Off,
    /// One config for every connection.
    Fixed {
        /// The single machine configuration every connection runs.
        config: warrenguard_wire::DaitaConfig,
        /// Machine family name, surfaced in the per-connection close log.
        name: Option<String>,
    },
    /// Sample the curated pool independently for every connection. `pinned`
    /// holds one family steady (the `--daita-machine` ops lever) while still
    /// re-materialising its machine per connection.
    Pool {
        /// The curated machine pool, sampled once per accepted connection.
        pool: warrenguard_daita::DaitaPool,
        /// When set, hold this one family steady across connections.
        pinned: Option<String>,
    },
}

impl DaitaSource {
    /// Sample `pool` for every connection, optionally pinning one family.
    ///
    /// Returns `None` when the pool is empty, or when `pinned` names an entry
    /// the pool does not carry: an operator typo must fail the exit loudly, not
    /// boot it with DAITA silently off.
    #[must_use]
    pub fn pool(pool: warrenguard_daita::DaitaPool, pinned: Option<String>) -> Option<Self> {
        if pool.is_empty() {
            return None;
        }
        if let Some(name) = pinned.as_deref() {
            // Probe once at construction so the failure surfaces at boot rather
            // than on the first client that happens to connect.
            pool.pick_named_os(name)?;
        }
        Some(Self::Pool { pool, pinned })
    }

    /// One fixed config for every connection.
    #[must_use]
    pub fn fixed(config: warrenguard_wire::DaitaConfig, name: Option<String>) -> Self {
        Self::Fixed { config, name }
    }

    /// Build this connection's [`DaitaPick`]: the exit-side padding state,
    /// the machine name to log, and the wire config to advertise in the
    /// `IpAssign` grant. All three come from the SAME draw, so the spec the
    /// client is told to drive is exactly the machine padding the exit's
    /// downlink.
    ///
    /// A failure to materialise the picked machine degrades that single
    /// connection to the plain pump rather than dropping the client; the
    /// pick then carries no config, so the exit never advertises a defense
    /// it is not running.
    #[must_use]
    pub fn pick_for_connection(&self) -> DaitaPick {
        let (config, name) = match self {
            Self::Off => return DaitaPick::disabled(),
            Self::Fixed { config, name } => (config.clone(), name.clone()),
            Self::Pool { pool, pinned } => match pinned.as_deref() {
                Some(name) => match pool.pick_named_os(name) {
                    Some(cfg) => (cfg, Some(name.to_owned())),
                    None => return DaitaPick::disabled(),
                },
                None => match pool.pick_with_name_os() {
                    Some((name, cfg)) => (cfg, Some(name.to_owned())),
                    None => return DaitaPick::disabled(),
                },
            },
        };
        if !config.is_enabled() {
            return DaitaPick::disabled();
        }
        match DaitaState::from_config(&config, Instant::now()) {
            Ok(state) => DaitaPick {
                state,
                name,
                config: Some(config),
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to build DaitaState; this connection runs without DAITA");
                DaitaPick::disabled()
            }
        }
    }
}

/// One connection's DAITA draw. `config` is `Some` exactly when `state` is
/// an enabled machine: the two are inseparable so the exit can only ever
/// advertise (`IpAssign.daita_spec`) the defense it actually drives on its
/// downlink.
pub struct DaitaPick {
    /// Exit-side padding state for this connection's pump.
    pub state: DaitaState,
    /// Machine family name, surfaced in the per-connection close log.
    pub name: Option<String>,
    /// The wire spec to grant a `wants_daita` client, `None` when this
    /// connection runs no machine.
    pub config: Option<warrenguard_wire::DaitaConfig>,
}

impl DaitaPick {
    fn disabled() -> Self {
        Self {
            state: DaitaState::disabled(),
            name: None,
            config: None,
        }
    }
}

/// Shared per-listener state for exit-side multi-hop termination, cloned
/// into each accepted connection. Lets the standalone exit listener and
/// the unified `:443` dispatcher run the identical termination path
/// (build per-conn `DaitaState`, run setup + datagram pump, release IP)
/// without duplicating that body.
#[derive(Clone)]
pub struct ExitTerminateCtx<T: PacketDevice + Clone> {
    cache: Arc<SessionCache>,
    privkey: Arc<WarrenKemPrivateKey>,
    exit_id: ExitId,
    tun: T,
    daita: Arc<DaitaSource>,
    ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
    /// Multi-hop `/v2` dual-stack: the IPv6 pool allocator. `None` keeps
    /// the exit IPv4-only (a v2 client then gets `ipv6: None` back and
    /// stays v4-only, firewall keeps native v6 blocked - no leak).
    ip_allocator_v6: Option<Arc<Mutex<IpAllocatorV6>>>,
    router: Option<Arc<MultihopTunRouter>>,
    /// TUN queues connections write their uplink onto. One entry (the primary
    /// `tun`) in the single-queue default; N entries when the deployer opens an
    /// `IFF_MULTI_QUEUE` TUN and calls [`Self::with_extra_tun_queues`]. Each
    /// accepted connection is pinned round-robin to one queue via
    /// [`Self::pick_uplink_tun`], so N connections write to N distinct kernel
    /// fds in parallel instead of contending on one. `Arc` so the per-connection
    /// ctx clone is a refcount bump, not a Vec copy.
    uplink_queues: Arc<Vec<T>>,
    /// Round-robin cursor over `uplink_queues`, shared across the per-connection
    /// ctx clones (hence `Arc`) so connections spread across the queues instead
    /// of every clone starting at 0 and piling onto queue 0.
    next_uplink: Arc<std::sync::atomic::AtomicUsize>,
    /// Exit allowlist gate. `Some` in strict mode (warren-api configured):
    /// a client must assert an allowlisted account pubkey before it is
    /// granted a tunnel IP. `None` in permissive/bench mode admits any
    /// client.
    allowlist: Option<AllowlistHandle>,
    /// Live-session registry for mid-session revocation teardown. `Some`
    /// only in the production dispatcher (set via
    /// [`ExitTerminateCtx::with_session_registry`]); when `None` a
    /// revoked pubkey is merely denied at its next setup (no force-close
    /// of the in-flight connection). Bench/test entry points leave it
    /// `None`.
    session_registry: Option<Arc<MultihopSessionRegistry>>,
    /// Exit-wide drain watch (ADR 36 soft maintenance signal). `Some` only
    /// when the production dispatcher wires it via
    /// [`ExitTerminateCtx::with_drain_rx`]; bench/test/standalone entry
    /// points leave it `None` (no drain emission). Each terminated
    /// connection clones the receiver and parks on it.
    drain_rx: Option<watch::Receiver<Option<DrainAdvisory>>>,
    /// v7 anonymous session-token admitter (doc 64). `Some` only when the
    /// production dispatcher wires it via [`ExitTerminateCtx::with_token_admitter`]:
    /// a client presenting an [`warrenguard_multihop::WarrenControlMessage::IpRequestV7`]
    /// is then admitted by verifying + spending a token offline (the exit never
    /// learns the wallet). `None` refuses v7 (the exit stays wallet-authenticated).
    token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,
    /// Post-quantum (`/v2` X-Wing) session cache. Always built when the crate is
    /// compiled with `pq-hpke`; it only ever holds entries once an X-Wing secret
    /// is also attached (see `xwing_secret`).
    #[cfg(feature = "pq-hpke")]
    pq_cache: Arc<PqSessionCache>,
    /// The exit's long-lived X-Wing recipient SECRET, derived from its identity
    /// ([`derive_exit_xwing_from_identity`]). `Some` makes the exit PQ-capable:
    /// it can decapsulate `/v2` setup frames. `None` (the default) drops `/v2`
    /// frames, so a classical-only exit is unchanged.
    #[cfg(feature = "pq-hpke")]
    xwing_secret: Option<Arc<XWingRecipientSecretKey>>,
}

impl<T: PacketDevice + Clone> ExitTerminateCtx<T> {
    /// Build the shared termination state. When an allocator is present,
    /// spawns the single TUN -> per-IP downlink router pump (the same
    /// one-reader-fans-out model the standalone listener used).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit_x25519_privkey: WarrenKemPrivateKey,
        exit_id: ExitId,
        tun: T,
        daita_config: Option<warrenguard_wire::DaitaConfig>,
        daita_machine_name: Option<String>,
        ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
        ip_allocator_v6: Option<Arc<Mutex<IpAllocatorV6>>>,
        allowlist: Option<AllowlistHandle>,
    ) -> Self {
        let router = ip_allocator
            .as_ref()
            .map(|_| Arc::new(MultihopTunRouter::default()));
        if let Some(router) = router.clone() {
            tokio::spawn(pump_multihop_tun_router(tun.clone(), router));
        }
        Self {
            cache: Arc::new(SessionCache::new()),
            privkey: Arc::new(exit_x25519_privkey),
            exit_id,
            uplink_queues: Arc::new(vec![tun.clone()]),
            next_uplink: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            tun,
            daita: Arc::new(match daita_config {
                Some(config) if config.is_enabled() => {
                    DaitaSource::fixed(config, daita_machine_name)
                }
                _ => DaitaSource::Off,
            }),
            ip_allocator,
            ip_allocator_v6,
            router,
            allowlist,
            session_registry: None,
            drain_rx: None,
            token_admitter: None,
            #[cfg(feature = "pq-hpke")]
            pq_cache: Arc::new(PqSessionCache::new()),
            #[cfg(feature = "pq-hpke")]
            xwing_secret: None,
        }
    }

    /// Attach `extra` `IFF_MULTI_QUEUE` TUN queues (beyond the primary passed to
    /// [`Self::new`]) so the exit runs one downlink reader task per queue and
    /// spreads per-connection uplink writes across all queues. Wired by the
    /// deployer from `warrenguard_config::knobs::exit_tun_queues()`: it opens N
    /// queues with `RealTun::create_multi_queue_named`, keeps queue 0 as the
    /// `new` primary, and hands the rest here.
    ///
    /// A downlink router reader is spawned for each extra queue ONLY when an IP
    /// allocator is configured (the router exists), matching `new`'s primary
    /// reader; the no-allocator legacy path stays single-queue. Passing an empty
    /// `extra` is a no-op, so the single-queue default is byte-identical.
    #[must_use]
    pub fn with_extra_tun_queues(mut self, extra: Vec<T>) -> Self {
        if extra.is_empty() {
            return self;
        }
        if let Some(router) = self.router.clone() {
            for q in &extra {
                tokio::spawn(pump_multihop_tun_router(q.clone(), router.clone()));
            }
        }
        let mut queues = Vec::with_capacity(self.uplink_queues.len() + extra.len());
        queues.extend(self.uplink_queues.iter().cloned());
        queues.extend(extra);
        self.uplink_queues = Arc::new(queues);
        self
    }

    /// The TUN queue this connection writes its uplink onto: round-robin across
    /// the opened queues so N connections spread over N kernel fds. Collapses to
    /// the single primary `tun` when only one queue is open (the default), so
    /// the single-queue path picks exactly the historic handle.
    fn pick_uplink_tun(&self) -> T {
        let n = self.uplink_queues.len();
        if n <= 1 {
            return self.tun.clone();
        }
        let i = self
            .next_uplink
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % n;
        self.uplink_queues[i].clone()
    }

    /// Number of TUN queues this ctx fans out over (1 = single-queue default).
    #[must_use]
    pub fn tun_queue_count(&self) -> usize {
        self.uplink_queues.len()
    }

    /// Sample the curated DAITA pool independently for every connection this
    /// ctx terminates (the production path).
    ///
    /// Returns `None` when the pool is empty or `pinned` names an entry the
    /// pool does not carry, so the caller fails the exit at boot instead of
    /// serving with DAITA quietly off.
    #[must_use]
    pub fn with_daita_pool(
        mut self,
        pool: warrenguard_daita::DaitaPool,
        pinned: Option<String>,
    ) -> Option<Self> {
        self.daita = Arc::new(DaitaSource::pool(pool, pinned)?);
        Some(self)
    }

    /// This connection's DAITA draw (padding state, log name, and the spec
    /// to grant a `wants_daita` client). Called once per accepted
    /// connection, so a pool-backed ctx hands each client an independently
    /// sampled machine.
    #[must_use]
    pub fn daita_for_connection(&self) -> DaitaPick {
        self.daita.pick_for_connection()
    }

    /// Attach the exit's X-Wing recipient SECRET (from
    /// [`derive_exit_xwing_from_identity`]) so this exit terminates post-quantum
    /// `/v2` connections. Builder (like [`Self::with_session_registry`]) so the
    /// existing `new(...)` call sites keep the classical-only `None` default.
    #[cfg(feature = "pq-hpke")]
    #[must_use]
    pub fn with_xwing_secret(mut self, secret: Arc<XWingRecipientSecretKey>) -> Self {
        self.xwing_secret = Some(secret);
        self
    }

    /// The PQ setup material to thread into the setup path, or `None` when this
    /// exit is classical-only (no X-Wing secret attached).
    #[cfg(feature = "pq-hpke")]
    fn pq_setup(&self) -> Option<PqSetup> {
        self.xwing_secret.as_ref().map(|secret| PqSetup {
            cache: self.pq_cache.clone(),
            secret: secret.clone(),
        })
    }

    /// Attach a [`SessionTokenAdmitter`] so this exit admits v7 anonymous
    /// session-token clients ([`warrenguard_multihop::WarrenControlMessage::IpRequestV7`]).
    /// Injected by the exit binary (it owns the control-plane API client the
    /// admitter spends serials against); `None` keeps the exit v6-only.
    #[must_use]
    pub fn with_token_admitter(mut self, admitter: Option<Arc<dyn SessionTokenAdmitter>>) -> Self {
        self.token_admitter = admitter;
        self
    }

    /// Attach a [`MultihopSessionRegistry`] so a mid-session revocation
    /// (allowlist removal or CRL) force-closes this client's in-flight
    /// connection instead of waiting for its next reconnect. The
    /// dispatcher spawns the matching revocation consumer that calls
    /// [`MultihopSessionRegistry::terminate`]. Builder rather than a
    /// `new` argument so the many existing `new(...)` call sites (tests,
    /// bench, single-tenant listener) stay unchanged and keep the `None`
    /// default.
    #[must_use]
    pub fn with_session_registry(mut self, registry: Arc<MultihopSessionRegistry>) -> Self {
        self.session_registry = Some(registry);
        self
    }

    /// Attach the exit-wide drain watch (ADR 36). When the operator marks
    /// this exit for maintenance, the backend heartbeat publishes a
    /// [`DrainAdvisory`] on the matching `watch::Sender`; every per-conn
    /// handler then emits the soft ExitDraining signal and hard-closes at
    /// the deadline. Builder (like [`Self::with_session_registry`]) so the
    /// bench/test/standalone `new(...)` call sites keep the `None` default.
    #[must_use]
    pub fn with_drain_rx(mut self, drain_rx: watch::Receiver<Option<DrainAdvisory>>) -> Self {
        self.drain_rx = Some(drain_rx);
        self
    }

    /// This listener's own `exit_id`. The unified dispatcher compares it
    /// against each frame's cleartext routing tag to decide
    /// terminate-locally vs forward.
    pub fn exit_id(&self) -> ExitId {
        self.exit_id
    }

    /// Read-only handle over this dispatcher's live tunnel IPv4s, for the
    /// NAT-PMP orphan reaper to diff against the allocator. `None` when no
    /// per-IP router is wired (no ip-nego / bench echo path). Cheap to clone
    /// (shares the router `Arc`); call before moving `self` into the serve
    /// loop, which never returns until shutdown.
    #[must_use]
    pub fn active_tunnel_ipv4s(&self) -> Option<ActiveTunnelIpv4s> {
        self.router.clone().map(ActiveTunnelIpv4s)
    }
}

/// Cloneable, read-only view of the multi-hop dispatcher's live tunnel IPv4s
/// (the keys of its downlink [`RouteTable`]). Decouples the NAT-PMP orphan
/// reaper from the private router type while keeping the snapshot a cheap
/// lock-and-copy.
#[derive(Clone)]
pub struct ActiveTunnelIpv4s(Arc<MultihopTunRouter>);

impl ActiveTunnelIpv4s {
    /// Snapshot of the tunnel IPv4s that currently hold a live session.
    #[must_use]
    pub fn snapshot(&self) -> std::collections::HashSet<Ipv4Addr> {
        self.0.active_ipv4s()
    }
}

/// Terminate one accepted connection locally: build its per-conn
/// `DaitaState`, run the setup phase from `source`, pump datagrams, then
/// release the allocated IP. Shared by the standalone exit listener
/// (`source = AcceptFromConn`) and the unified `:443` dispatcher
/// (`source = PreRead`, when `frame.exit_id == self`).
pub async fn terminate_connection<T>(
    conn: Connection,
    source: SetupSource,
    ctx: ExitTerminateCtx<T>,
) where
    T: PacketDevice + Clone,
{
    // Drain admission gate (ADR 36 §5.5 fail-fast): while the exit is
    // drained, refuse NEW connections outright with the same frozen close
    // code the deadline hard-close uses, so a client reconnecting to a
    // draining exit fails fast and re-selects another exit instead of
    // landing "connected with no egress". Established sessions are NOT
    // touched here: their drain emitter handles the soft signal and the
    // deadline backstop.
    if ctx
        .drain_rx
        .as_ref()
        .is_some_and(|rx| rx.borrow().is_some())
    {
        conn.close(VarInt::from_u32(WARREN_MH_DRAINING), &[]);
        return;
    }
    // Defer allocation into the pump so the first decoded plaintext may
    // carry an `IpRequest` with a client pubkey (sticky reservations
    // across reconnects). The parent owns `conn_id` and calls
    // `release(conn_id)` after the handler joins; release is idempotent
    // on unknown conn ids, so the unconditional call is safe even when
    // allocation never happened.
    let conn_id: ConnId = conn.stable_id() as ConnId;
    // Two clients of the same exit must not share one maybenot machine.
    let daita_pick = ctx.daita_for_connection();
    serve_one_connection_with_tun_and_daita(
        conn,
        ctx.privkey.clone(),
        ctx.exit_id,
        ctx.cache.clone(),
        // Round-robin the connection onto one of the opened TUN queues so its
        // uplink writes parallelize across kernel fds (single-queue = the
        // primary `tun`, byte-identical to before).
        ctx.pick_uplink_tun(),
        daita_pick,
        ctx.ip_allocator.clone(),
        ctx.ip_allocator_v6.clone(),
        conn_id,
        ctx.router.clone(),
        source,
        ctx.allowlist.clone(),
        ctx.session_registry.clone(),
        ctx.drain_rx.clone(),
        ctx.token_admitter.clone(),
        #[cfg(feature = "pq-hpke")]
        ctx.pq_setup(),
    )
    .await;
    if let Some(alloc) = ctx.ip_allocator.as_ref() {
        alloc.lock().release(conn_id);
    }
    // `/v2` dual-stack: release the v6 lease too so its interface ID
    // returns to the recycle queue (and the sticky binding survives for
    // a reconnect of the same pubkey).
    if let Some(alloc6) = ctx.ip_allocator_v6.as_ref() {
        alloc6.lock().release(conn_id);
    }
}

/// This node's live inner-packet budget for one multihop connection: its
/// current QUIC datagram budget minus the wire overhead of the frame format
/// this session speaks ([`MULTIHOP_FRAME_MAX_OVERHEAD`] for `/v1` sessions,
/// [`pq_inner_budget`]'s data-frame overhead under `pq-hpke`). Saturates
/// instead of wrapping when the path MTU cannot even carry the frame overhead,
/// and falls back to `u16::MAX` (no clamp) before the connection has negotiated
/// a size.
fn inner_budget(max_datagram_size: Option<usize>, frame_overhead: usize) -> u16 {
    u16::try_from(
        max_datagram_size
            .unwrap_or(usize::from(u16::MAX))
            .saturating_sub(frame_overhead),
    )
    .unwrap_or(u16::MAX)
}

/// The `/v2` (pq-hpke) inner-packet budget for a live datagram size. A `/v2`
/// DATA frame carries an EMPTY `pq_ct` (the 1088-byte ML-KEM ciphertext rides
/// only the dedicated bootstrap frame, see [`PqExitSession::seal_response`]), so
/// the budget subtracts [`MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD`], matching the
/// client's `max_inner_payload`. Subtracting the ~1 KB-larger setup bound
/// starved a 1452-byte path to a ~240-byte budget, so every real downlink packet
/// exceeded it and was reflected as frag-needed rather than sealed: a silent
/// data black-hole while the tunnel stayed Connected.
#[cfg(feature = "pq-hpke")]
fn pq_inner_budget(max_datagram_size: Option<usize>) -> u16 {
    inner_budget(max_datagram_size, MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD)
}

/// Rewrites the MSS option of a SYN/SYN-ACK down to `budget`, logging the
/// change. A no-op, silently, when [`clamp_syn_mss`] finds the packet
/// already fits or carries no MSS option.
fn clamp_mss_logged(packet: &mut [u8], budget: u16) {
    if let Some((old, new)) = clamp_syn_mss(packet, budget) {
        tracing::debug!(
            old,
            new,
            budget,
            "exit clamped inner TCP MSS to node budget"
        );
    }
}

/// Uplink SYN clamp (client -> exit -> TUN). The [`is_tcp_syn`] pre-filter
/// means the live-budget lookup (a `Connection` state read) is only paid on
/// the rare packets that could actually be rewritten, not on every uplink
/// packet. The MSS a peer announces governs the segments the OTHER side
/// will emit back through this node, so clamping it here caps what any
/// origin server ever sends down through this exit's own transmit budget,
/// healing pre-existing clients with no app update since the clamp lives
/// entirely on the exit (2026-07-15 SNCF incident: a reduced-MTU underlay
/// silently blackholed full-MSS downlink segments while the tunnel stayed
/// Connected).
fn clamp_uplink_syn(packet: &mut [u8], conn: &Connection, frame_overhead: usize) {
    if !is_tcp_syn(packet) {
        return;
    }
    clamp_mss_logged(
        packet,
        inner_budget(conn.max_datagram_size(), frame_overhead),
    );
}

/// Downlink adaptation (TUN -> exit -> client) of a packet about to be
/// sealed, given the live `budget` ([`inner_budget`]). Clamps an outgoing
/// SYN-ACK's MSS the same way as [`clamp_uplink_syn`] (always small enough
/// afterward on its own: a SYN carries no payload). Any other packet that
/// still exceeds `budget` cannot be sealed/sent as-is: `Some` is the RFC
/// 1191/4443 fragmentation-needed reply to reflect into the TUN so the
/// origin server's own PMTUD shrinks its segments within one RTT instead of
/// the exit dropping them silently forever; `None` means seal and send
/// unchanged.
fn adapt_inner_for_budget(packet: &mut [u8], budget: u16) -> Option<Vec<u8>> {
    if is_tcp_syn(packet) {
        clamp_mss_logged(packet, budget);
        return None;
    }
    if packet.len() <= usize::from(budget) {
        return None;
    }
    build_frag_needed(
        packet,
        budget,
        warrenguard_config::TUNNEL_GATEWAY_IP,
        warrenguard_config::TUNNEL_GATEWAY_IPV6,
    )
}

/// Attach this connection's inbound-activity counter to its freshly
/// registered downlink route(s), and if it took over an inner IP already
/// held by other connection(s) (a sticky reconnect or a same-pubkey
/// collision), arm a one-shot re-check that evicts any predecessor whose
/// peer has since gone silent.
///
/// Why a re-check and not an immediate eviction: a genuinely live
/// same-pubkey session (two devices on one wallet, both active) shares the
/// same sticky IP and must keep serving; only a predecessor whose client
/// stopped feeding it is dead. Advancing inbound activity is what tells
/// them apart. The check runs off the datapath (spawned, once per
/// takeover) so the per-packet fast path pays nothing. A connection
/// serving no traffic at all for the whole window owns no active flow and
/// so black-holes nothing; it is the concurrent same-pubkey-collision case
/// (decision pending), not the single-user reconnect this fixes.
fn arm_takeover_recheck(
    router: &Option<Arc<MultihopTunRouter>>,
    down_tx: &Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    assigned_ip: Option<Ipv4Addr>,
    assigned_ip_v6: Option<Ipv6Addr>,
    activity: &Arc<AtomicU64>,
) {
    let (Some(router), Some(tx)) = (router.as_ref(), down_tx.as_ref()) else {
        return;
    };
    let mut predecessors_v4 = Vec::new();
    let mut predecessors_v6 = Vec::new();
    if let Some(ip) = assigned_ip {
        router.attach_liveness(ip, tx, activity.clone());
        predecessors_v4 = router.snapshot_predecessors(ip, tx);
    }
    if let Some(ip6) = assigned_ip_v6 {
        router.attach_liveness_v6(ip6, tx, activity.clone());
        predecessors_v6 = router.snapshot_predecessors_v6(ip6, tx);
    }
    if predecessors_v4.is_empty() && predecessors_v6.is_empty() {
        return;
    }
    // Make the takeover visible for the next investigator: counts only, no
    // address or pubkey (the exit's no-log discipline). The 2026-07-16
    // black-hole was silent precisely because this collision left no trace.
    tracing::info!(
        v4 = predecessors_v4.len(),
        v6 = predecessors_v6.len(),
        "multihop: sticky-IP takeover, existing downlink owner(s) present; stale re-check armed"
    );
    let router = router.clone();
    tokio::spawn(async move {
        tokio::time::sleep(TAKEOVER_STALE_RECHECK).await;
        let mut evicted = 0;
        if let Some(ip) = assigned_ip {
            evicted += router.evict_stale_predecessors(ip, &predecessors_v4);
        }
        if let Some(ip6) = assigned_ip_v6 {
            evicted += router.evict_stale_predecessors_v6(ip6, &predecessors_v6);
        }
        if evicted > 0 {
            tracing::info!(
                evicted,
                "multihop: evicted stale downlink predecessor(s) after sticky-IP takeover (peer went silent)"
            );
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn serve_one_connection_with_tun<T>(
    conn: Connection,
    privkey: Arc<WarrenKemPrivateKey>,
    exit_id: ExitId,
    cache: Arc<SessionCache>,
    tun: T,
    ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
    ip_allocator_v6: Option<Arc<Mutex<IpAllocatorV6>>>,
    conn_id: ConnId,
    router: Option<Arc<MultihopTunRouter>>,
    setup_source: SetupSource,
    allowlist: Option<AllowlistHandle>,
    session_registry: Option<Arc<MultihopSessionRegistry>>,
    drain_rx: Option<watch::Receiver<Option<DrainAdvisory>>>,
    token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,
    #[cfg(feature = "pq-hpke")] pq: Option<PqSetup>,
) where
    T: PacketDevice + Clone,
{
    // Latest installed sealing context shared between the RX task
    // (which installs it on every accepted frame) and the TX task
    // (which uses it to seal reverse frames). On a rekey the
    // exit-side SessionCache returns a fresh entry for the new
    // encapsulated_key; the slot is then atomically swapped here so
    // the reverse path picks the new sealing context on the next
    // outbound TUN packet.
    let current: SharedCurrentSession = Arc::new(Mutex::new(None));
    let reverse_seq = Arc::new(AtomicU64::new(0));

    // Downlink routing (see the DAITA variant + `MultihopTunRouter`):
    // channel-fed per-IP when ip-nego is on, direct `tun.recv()` else.
    let (down_tx, down_rx) = if router.is_some() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(DOWNLINK_CHANNEL_BOUND);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Reliable setup phase: derive HPKE, allocate the IP, register the
    // route, and reply with the sealed IpAssign over the bidi stream
    // BEFORE any DATA datagram is pumped. A setup failure abandons the
    // connection (the datagram pump never starts). The anti-replay window
    // is session-scoped (held in the SessionCache entry), not local to
    // this connection, so a frame replayed on a fresh connection sharing
    // this HPKE session is rejected.
    let setup = match run_setup(
        setup_source,
        &conn,
        &privkey,
        exit_id,
        &cache,
        &ip_allocator,
        &ip_allocator_v6,
        conn_id,
        &router,
        &down_tx,
        &reverse_seq,
        allowlist.as_ref(),
        session_registry.as_ref(),
        token_admitter.as_ref(),
        // Plain pump: this connection runs no machine, so there is nothing
        // to offer a wants_daita client (the reply honestly reads None).
        None,
        #[cfg(feature = "pq-hpke")]
        pq.as_ref(),
    )
    .await
    {
        Some(o) => o,
        None => return,
    };
    // When compiled without `pq-hpke`, `SetupOutcome` has only the `V1` variant,
    // so this reads as a single-arm destructure; the `V2` arm exists only under
    // the feature.
    #[allow(clippy::infallible_destructuring_match)]
    let setup = match setup {
        SetupOutcome::V1(s) => s,
        // A `/v2` connection runs the dedicated post-quantum pump; the classical
        // pump below is byte-identical to before.
        #[cfg(feature = "pq-hpke")]
        SetupOutcome::V2(pq_setup) => {
            if let Some(pq) = pq {
                serve_pq_datagram_pump(conn, exit_id, tun, pq_setup, router, down_tx, down_rx, pq)
                    .await;
            }
            return;
        }
    };
    let assigned_ip: Arc<Mutex<Option<Ipv4Addr>>> = Arc::new(Mutex::new(setup.assigned_ip));
    let assigned_ip_v6: Arc<Mutex<Option<Ipv6Addr>>> = Arc::new(Mutex::new(setup.assigned_ip_v6));
    *current.lock() = Some((setup.session.clone(), setup.epoch));

    // Inbound-activity counter bumped by the RX task below; feeds the
    // sticky-IP takeover re-check so a dead predecessor's re-used flows
    // re-pin to this live connection in bounded time.
    let rx_activity = Arc::new(AtomicU64::new(0));
    arm_takeover_recheck(
        &router,
        &down_tx,
        setup.assigned_ip,
        setup.assigned_ip_v6,
        &rx_activity,
    );

    // ADR 36 soft drain signal: park on the exit-wide drain watch and, when
    // the exit is marked for maintenance, seal+emit ExitDraining on this
    // connection, hard-closing at the deadline. Spawned BEFORE the Arcs are
    // moved into the pump tasks below (this variant has no timer task, so
    // `current`/`reverse_seq` are moved, not cloned).
    let drain_task =
        spawn_drain_emitter(drain_rx, current.clone(), reverse_seq.clone(), conn.clone());

    // Transport path probe (Lever 1a): the unified prod dispatcher
    // terminates clients HERE, so the multihop path needs its own probe
    // spawn for observability parity.
    drop(warrenguard_transport_core::spawn_path_probe(
        "exit-mh",
        vec![conn.clone()],
        None,
    ));

    let conn_rx = conn.clone();
    let tun_rx = tun.clone();
    let cache_rx = cache.clone();
    let privkey_rx = privkey.clone();
    let current_rx = current.clone();
    // For learning per-flow downlink ownership from the uplink (both `None`
    // on the legacy no-allocator path, where routing is direct `tun.recv`).
    let router_rx = router.clone();
    let down_tx_rx = down_tx.clone();
    // Anti-spoof gate inputs: fixed for the connection's lifetime (the
    // allocation happens once, during setup). `None` only on the legacy
    // no-allocator path (single client, bootstrap IP) where no expected
    // address exists to compare against.
    let spoof_gate_v4 = setup.assigned_ip;
    let spoof_gate_v6 = setup.assigned_ip_v6;
    let rx_activity_rx = rx_activity.clone();
    let rx_task = tokio::spawn(async move {
        let mut tun_write_errors: u32 = 0;
        let mut spoofed_drops: u64 = 0;
        // See the DAITA variant: lock-free memo so the router lock is taken
        // only on a flow's first uplink packet, not on its bulk data.
        let mut noted_flows: HashSet<u64> = HashSet::new();
        loop {
            let datagram = match conn_rx.read_datagram().await {
                Ok(d) => d,
                Err(_) => return,
            };
            // One lock-free bump per inbound datagram: a live peer keeps
            // this advancing, a dead predecessor freezes it (takeover check).
            rx_activity_rx.fetch_add(1, Ordering::Relaxed);
            let frame = match decode_frame(&datagram) {
                Ok(f) => f,
                Err(_) => continue,
            };
            if frame.exit_id != exit_id {
                continue;
            }
            let handle = match cache_rx.get_or_insert(&frame.encapsulated_key, || {
                ExitSession::new(&privkey_rx, &frame.encapsulated_key, exit_id)
            }) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let session = handle.session;
            // Capture the Copy scalars used after the open (anti-replay seq/epoch
            // and the epoch slot) before the zero-copy open consumes the frame.
            let (frame_seq, frame_epoch) = (frame.seq, frame.epoch);
            let mut plaintext = match session.open_owned(frame) {
                Ok(p) => p,
                Err(_) => continue,
            };
            // Anti-replay before the frame can reach the TUN: a
            // blind/compromised relay must not be able to replay a
            // captured sealed frame. The window is shared across every
            // connection driving this HPKE session (cf. SessionCache), so
            // a replay on a fresh connection is rejected too.
            if handle
                .replay_windows
                .lock()
                .check_and_record(frame_seq, frame_epoch)
                .is_err()
            {
                continue;
            }
            *current_rx.lock() = Some((session.clone(), frame_epoch));
            // The setup round-trip is reliable, so a DATA datagram is
            // normally a real IP packet. A stray control frame (e.g. a
            // client still retrying an IpRequest on the legacy datagram
            // path) is dropped rather than re-forwarded: the setup
            // stream already delivered the IpAssign.
            if warrenguard_multihop::try_decode_control(&plaintext)
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            // Anti-spoof: the decrypted packet's inner source IP must be
            // the address allocated to this connection. The counter (not the
            // address) is logged.
            if let Some(expected_v4) = spoof_gate_v4
                && !source_ip_matches(&plaintext, expected_v4, spoof_gate_v6)
            {
                spoofed_drops += 1;
                if spoofed_drops == 1 || spoofed_drops.is_multiple_of(10_000) {
                    tracing::warn!(
                        spoofed_drops,
                        "rx_task: dropped packet with spoofed inner source IP"
                    );
                }
                continue;
            }
            // Anti-spoof passed: safe to record this flow's downlink owner
            // for the reverse path. First packet of each flow only (memoized).
            if let (Some(router), Some(owner)) = (&router_rx, &down_tx_rx)
                && let Some(fk) = canonical_flow_key(&plaintext)
            {
                if noted_flows.len() >= FLOW_TABLE_CAP_PER_IP {
                    noted_flows.clear();
                }
                if noted_flows.insert(fk) {
                    router.note_uplink(&plaintext, owner);
                }
            }
            // Cap the MSS any SYN announces to the exit's own downlink
            // budget before it reaches the TUN: see `clamp_uplink_syn`.
            clamp_uplink_syn(&mut plaintext, &conn_rx, MULTIHOP_FRAME_MAX_OVERHEAD);
            match tun_rx.send(&plaintext).await {
                Ok(()) => tun_write_errors = 0,
                Err(e) => {
                    tun_write_errors += 1;
                    if tun_write_errors == 1 || tun_write_errors.is_multiple_of(1_000) {
                        tracing::warn!(
                            error = %e,
                            consecutive = tun_write_errors,
                            "rx_task: transient TUN write error, dropping packet"
                        );
                    }
                    if tun_write_errors >= MAX_CONSECUTIVE_TUN_WRITE_ERRORS {
                        return;
                    }
                }
            }
        }
    });

    let conn_tx = conn.clone();
    let tun_tx = tun;
    let mut down_rx_tx = down_rx;
    let current_tx = current;
    let reverse_seq_tx = reverse_seq;
    let tx_task = tokio::spawn(async move {
        let mut mtu_reflected = 0u64;
        loop {
            let mut packet = match next_downlink(&mut down_rx_tx, &tun_tx).await {
                Some(p) => p,
                None => return,
            };
            // Over-read backpressure: drop the newest packet BEFORE sealing when
            // the client's connection buffer is near full (see the gate helper).
            if overread_gate_should_drop(
                &conn_tx,
                warrenguard_config::knobs::exit_overread_gate_mtus(),
            ) {
                continue;
            }
            let (session, epoch) = match current_tx.lock().clone() {
                Some(v) => v,
                None => continue,
            };
            // Reject/clamp before sealing: see `adapt_inner_for_budget`.
            let budget = inner_budget(conn_tx.max_datagram_size(), MULTIHOP_FRAME_MAX_OVERHEAD);
            if let Some(ptb) = adapt_inner_for_budget(&mut packet, budget) {
                mtu_reflected += 1;
                if mtu_reflected == 1 || mtu_reflected.is_multiple_of(64) {
                    tracing::warn!(
                        mtu_reflected,
                        budget,
                        "tx_task: packet exceeds downlink budget, reflecting frag-needed instead of sealing"
                    );
                }
                if let Err(e) = tun_tx.send(&ptb).await {
                    tracing::trace!(error = %e, "tx_task: frag-needed reflection tun write failed");
                }
                continue;
            }
            let seq = reverse_seq_tx.fetch_add(1, Ordering::AcqRel);
            // Classify while the plaintext is still readable: the sealed
            // frame is opaque to quinn, so the inner ECN/flow key must
            // travel with the datagram.
            let class = DatagramClass::of_inner_ip_packet(&packet);
            let frame = match session.seal_response_owned(packet, epoch, seq) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let bytes = match encode_frame(&frame) {
                Ok(b) => b,
                Err(_) => continue,
            };
            match conn_tx.send_datagram_classified(bytes.into(), class) {
                Ok(()) => {}
                // Transient PMTU dip under loss: drop, never die (see
                // the DAITA tx_task below for the full rationale).
                Err(SendDatagramError::TooLarge) => {}
                Err(_) => return,
            }
        }
    });

    // On conn close, rx_task returns first (Quinn `read_datagram`
    // errors). Without this abort the tx_task's downlink source would
    // never return, leaking the spawn forever and blocking the
    // allocator's `release(conn_id)` in the parent. Abort both
    // side-tasks once rx exits; this is safe because reverse-direction
    // packets after conn close cannot land.
    let _ = rx_task.await;
    tx_task.abort();
    let _ = tx_task.await;
    // The drain emitter may still be parked on the watch (no drain ever
    // came) or sleeping between re-emits; abort AND join it so a deadline
    // hard-close in flight settles before the pump's own close, keeping the
    // client-visible close code deterministic (WARREN_MH_DRAINING wins).
    if let Some(t) = drain_task {
        t.abort();
        let _ = t.await;
    }
    // Owner-checked: a same-pubkey takeover may have re-pointed this
    // address at a successor connection's channel already.
    if let (Some(router), Some(ip), Some(own_tx)) = (&router, *assigned_ip.lock(), &down_tx) {
        router.unregister_if_owner(ip, own_tx);
        if let Some(ip6) = *assigned_ip_v6.lock() {
            router.unregister_v6_if_owner(ip6, own_tx);
        }
    }
    // Pumps gone: close the QUIC connection so the client's bundle
    // observes the death and redials. Without this, detached observers
    // (the path probe holds a `Connection` clone) keep the session
    // alive and every flow pinned to it blackholes silently.
    conn.close(quinn::VarInt::from_u32(0), b"exit pumps ended");
}

/// Post-quantum (`/v2`) datagram pump: the X-Wing counterpart of the RX/TX tasks
/// in [`serve_one_connection_with_tun`]. The setup phase already ran (over the
/// reliable stream, in [`process_setup_frame`]), so this only pumps DATA and
/// rekey datagrams. Anti-spoof, per-flow downlink routing and TUN writes are
/// identical to the classical path; only the seal/open and the
/// establish-from-`pq_ct` cache discipline differ. DAITA cover and the
/// soft-drain emitter are not wired on the PQ path yet.
#[cfg(feature = "pq-hpke")]
#[allow(clippy::too_many_arguments)]
async fn serve_pq_datagram_pump<T>(
    conn: Connection,
    exit_id: ExitId,
    tun: T,
    setup: ConnSetupPq,
    router: Option<Arc<MultihopTunRouter>>,
    down_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    down_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    pq: PqSetup,
) where
    T: PacketDevice + Clone,
{
    let current: SharedPqCurrentSession =
        Arc::new(Mutex::new(Some((setup.session.clone(), setup.epoch))));
    let reverse_seq = Arc::new(AtomicU64::new(0));
    let spoof_gate_v4 = setup.assigned_ip;
    let spoof_gate_v6 = setup.assigned_ip_v6;

    // Inbound-activity counter for the sticky-IP takeover re-check (see the
    // classical pump). Registration already happened in `run_setup`; here we
    // attach the counter and arm the re-check for the `/v2` path too.
    let rx_activity = Arc::new(AtomicU64::new(0));
    arm_takeover_recheck(
        &router,
        &down_tx,
        setup.assigned_ip,
        setup.assigned_ip_v6,
        &rx_activity,
    );

    drop(warrenguard_transport_core::spawn_path_probe(
        "exit-mh-pq",
        vec![conn.clone()],
        None,
    ));

    let conn_rx = conn.clone();
    let tun_rx = tun.clone();
    let current_rx = current.clone();
    let router_rx = router.clone();
    let down_tx_rx = down_tx.clone();
    let pq_rx = pq.clone();
    let rx_activity_rx = rx_activity.clone();
    let rx_task = tokio::spawn(async move {
        let mut tun_write_errors: u32 = 0;
        let mut spoofed_drops: u64 = 0;
        let mut noted_flows: HashSet<u64> = HashSet::new();
        loop {
            let datagram = match conn_rx.read_datagram().await {
                Ok(d) => d,
                Err(_) => return,
            };
            rx_activity_rx.fetch_add(1, Ordering::Relaxed);
            let frame = match decode_frame_v2(&datagram) {
                Ok(f) => f,
                Err(_) => continue,
            };
            if frame.exit_id != exit_id {
                continue;
            }
            // A rekey/setup datagram carries `pq_ct`: (re)establish the epoch's
            // session by decapsulating it. A steady-state DATA datagram (empty
            // `pq_ct`) can only LOOK UP an already-established session; a miss is
            // dropped, since it cannot be rebuilt without the ML-KEM ciphertext.
            let handle = if frame.pq_ct.is_empty() {
                match pq_rx.cache.get(&frame.encapsulated_key) {
                    Some(h) => h,
                    None => continue,
                }
            } else {
                match pq_rx.cache.establish_or_get(
                    &frame.encapsulated_key,
                    &frame.pq_ct,
                    exit_id,
                    &pq_rx.secret,
                ) {
                    Ok(h) => h,
                    Err(_) => continue,
                }
            };
            let session = handle.session;
            let (frame_seq, frame_epoch) = (frame.seq, frame.epoch);
            let mut plaintext = match session.open(&frame) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if handle
                .replay_windows
                .lock()
                .check_and_record(frame_seq, frame_epoch)
                .is_err()
            {
                continue;
            }
            *current_rx.lock() = Some((session.clone(), frame_epoch));
            if warrenguard_multihop::try_decode_control(&plaintext)
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            if let Some(expected_v4) = spoof_gate_v4
                && !source_ip_matches(&plaintext, expected_v4, spoof_gate_v6)
            {
                spoofed_drops += 1;
                if spoofed_drops == 1 || spoofed_drops.is_multiple_of(10_000) {
                    tracing::warn!(
                        spoofed_drops,
                        "pq rx_task: dropped packet with spoofed inner source IP"
                    );
                }
                continue;
            }
            if let (Some(router), Some(owner)) = (&router_rx, &down_tx_rx)
                && let Some(fk) = canonical_flow_key(&plaintext)
            {
                if noted_flows.len() >= FLOW_TABLE_CAP_PER_IP {
                    noted_flows.clear();
                }
                if noted_flows.insert(fk) {
                    router.note_uplink(&plaintext, owner);
                }
            }
            // Cap the MSS any SYN announces to the exit's own downlink
            // budget before it reaches the TUN: see `clamp_uplink_syn`.
            clamp_uplink_syn(
                &mut plaintext,
                &conn_rx,
                MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD,
            );
            match tun_rx.send(&plaintext).await {
                Ok(()) => tun_write_errors = 0,
                Err(e) => {
                    tun_write_errors += 1;
                    if tun_write_errors == 1 || tun_write_errors.is_multiple_of(1_000) {
                        tracing::warn!(
                            error = %e,
                            consecutive = tun_write_errors,
                            "pq rx_task: transient TUN write error, dropping packet"
                        );
                    }
                    if tun_write_errors >= MAX_CONSECUTIVE_TUN_WRITE_ERRORS {
                        return;
                    }
                }
            }
        }
    });

    let conn_tx = conn.clone();
    let tun_tx = tun;
    let mut down_rx_tx = down_rx;
    let current_tx = current;
    let reverse_seq_tx = reverse_seq;
    let tx_task = tokio::spawn(async move {
        let mut mtu_reflected = 0u64;
        loop {
            let mut packet = match next_downlink(&mut down_rx_tx, &tun_tx).await {
                Some(p) => p,
                None => return,
            };
            // Over-read backpressure: drop the newest packet BEFORE sealing when
            // the client's connection buffer is near full (see the gate helper).
            if overread_gate_should_drop(
                &conn_tx,
                warrenguard_config::knobs::exit_overread_gate_mtus(),
            ) {
                continue;
            }
            let (session, epoch) = match current_tx.lock().clone() {
                Some(v) => v,
                None => continue,
            };
            // Reject/clamp before sealing: see `adapt_inner_for_budget`.
            let budget = pq_inner_budget(conn_tx.max_datagram_size());
            if let Some(ptb) = adapt_inner_for_budget(&mut packet, budget) {
                mtu_reflected += 1;
                if mtu_reflected == 1 || mtu_reflected.is_multiple_of(64) {
                    tracing::warn!(
                        mtu_reflected,
                        budget,
                        "pq tx_task: packet exceeds downlink budget, reflecting frag-needed instead of sealing"
                    );
                }
                if let Err(e) = tun_tx.send(&ptb).await {
                    tracing::trace!(error = %e, "pq tx_task: frag-needed reflection tun write failed");
                }
                continue;
            }
            let seq = reverse_seq_tx.fetch_add(1, Ordering::AcqRel);
            // Same plaintext-side classification as the v1 tx_task above.
            let class = DatagramClass::of_inner_ip_packet(&packet);
            let frame = match session.seal_response(&packet, epoch, seq) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let bytes = match encode_frame_v2(&frame) {
                Ok(b) => b,
                Err(_) => continue,
            };
            match conn_tx.send_datagram_classified(bytes.into(), class) {
                Ok(()) => {}
                Err(SendDatagramError::TooLarge) => {}
                Err(_) => return,
            }
        }
    });

    let _ = rx_task.await;
    tx_task.abort();
    let _ = tx_task.await;
    if let (Some(router), Some(ip), Some(own_tx)) = (&router, setup.assigned_ip, &down_tx) {
        router.unregister_if_owner(ip, own_tx);
        if let Some(ip6) = setup.assigned_ip_v6 {
            router.unregister_v6_if_owner(ip6, own_tx);
        }
    }
    conn.close(quinn::VarInt::from_u32(0), b"exit pq pumps ended");
}

/// DAITA-aware variant of [`serve_one_connection_with_tun`].
///
/// When the passed [`DaitaState`] is disabled, this is a strict alias
/// of [`serve_one_connection_with_tun`] (zero overhead). When enabled,
/// it runs the same RX + TX pumps **plus** a "padding timer" task that
/// drives the per-conn maybenot framework over the shared
/// [`DaitaState`] and emits DAITA dummies on the reverse direction
/// whenever the action timer expires.
///
/// Maybenot event firing matches the doctrine `DaitaEvent` contract:
/// - RX (client -> exit -> TUN): `TunnelRecv` always; `PaddingRecv`
///   if the opened payload is a 0xFF dummy (filtered before TUN); else
///   `NormalRecv` after a successful `tun.send`.
/// - TX (TUN -> exit -> client): `NormalSent` + `TunnelSent` BEFORE
///   the seal so the framework observes the egress packet timing
///   regardless of QUIC backpressure.
/// - Timer: `PaddingSent { machine } + TunnelSent` after a dummy is
///   actually sealed and queued for transmission.
///
/// Lock model: `Arc<parking_lot::Mutex<DaitaState>>` shared across the
/// three tasks (same pattern as
/// `warrenguard_pump::pump_multi_bidirectional_with_daita`).
#[allow(clippy::too_many_arguments)]
async fn serve_one_connection_with_tun_and_daita<T>(
    conn: Connection,
    privkey: Arc<WarrenKemPrivateKey>,
    exit_id: ExitId,
    cache: Arc<SessionCache>,
    tun: T,
    daita_pick: DaitaPick,
    ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
    ip_allocator_v6: Option<Arc<Mutex<IpAllocatorV6>>>,
    conn_id: ConnId,
    router: Option<Arc<MultihopTunRouter>>,
    setup_source: SetupSource,
    allowlist: Option<AllowlistHandle>,
    session_registry: Option<Arc<MultihopSessionRegistry>>,
    drain_rx: Option<watch::Receiver<Option<DrainAdvisory>>>,
    token_admitter: Option<Arc<dyn SessionTokenAdmitter>>,
    #[cfg(feature = "pq-hpke")] pq: Option<PqSetup>,
) where
    T: PacketDevice + Clone,
{
    let DaitaPick {
        state,
        name: daita_machine_name,
        config: daita_config,
    } = daita_pick;
    if !state.is_enabled() {
        serve_one_connection_with_tun(
            conn,
            privkey,
            exit_id,
            cache,
            tun,
            ip_allocator,
            ip_allocator_v6,
            conn_id,
            router,
            setup_source,
            allowlist,
            session_registry,
            drain_rx,
            token_admitter,
            #[cfg(feature = "pq-hpke")]
            pq,
        )
        .await;
        return;
    }

    let daita = Arc::new(Mutex::new(state));
    // Clone for the end-of-connection metrics snapshot.
    // Logged after `join!` so ops can compare per-conn DAITA emission
    // counters against the client-side counterpart.
    let daita_for_metrics = daita.clone();
    let conn_start = Instant::now();
    let current: SharedCurrentSession = Arc::new(Mutex::new(None));
    let reverse_seq = Arc::new(AtomicU64::new(0));
    // Notify the timer task whenever RX or TX fires events into the
    // shared `DaitaState`. Without this, the timer would park for
    // hours on the placeholder `next_timer = now + 3600s` it reads
    // before any event is fired, and never observe the newly-scheduled
    // action timers. `tokio::sync::Notify` consolidates wake-ups: if
    // many events fire in quick succession the timer wakes once and
    // re-reads `next_timer` against the now-up-to-date state.
    let state_changed = Arc::new(tokio::sync::Notify::new());

    // Downlink routing: when a router is present, the TX task reads its
    // bounded channel (fed by the single TUN reader keyed on the
    // client's allocated IPv4) instead of competing on `tun.recv()`.
    // `assigned_ip` is set by the RX task on allocation and read by the
    // parent to unregister the route on connection close.
    let (down_tx, down_rx) = if router.is_some() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(DOWNLINK_CHANNEL_BOUND);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Reliable setup phase (same as the non-DAITA path): derive HPKE,
    // allocate the IP, register the route, and reply with the sealed
    // IpAssign over the bidi stream before any DATA datagram is pumped.
    // The anti-replay window is session-scoped (held in the SessionCache
    // entry), so a frame replayed on a fresh connection sharing this HPKE
    // session is rejected.
    let setup = match run_setup(
        setup_source,
        &conn,
        &privkey,
        exit_id,
        &cache,
        &ip_allocator,
        &ip_allocator_v6,
        conn_id,
        &router,
        &down_tx,
        &reverse_seq,
        allowlist.as_ref(),
        session_registry.as_ref(),
        token_admitter.as_ref(),
        // Offer this connection's own machine: the grant in the IpAssign is
        // the exact spec padding this exit's downlink, so client and exit
        // drive the same defense, one per direction.
        daita_config.as_ref(),
        #[cfg(feature = "pq-hpke")]
        pq.as_ref(),
    )
    .await
    {
        Some(o) => o,
        None => return,
    };
    // When compiled without `pq-hpke`, `SetupOutcome` has only the `V1` variant,
    // so this reads as a single-arm destructure; the `V2` arm exists only under
    // the feature.
    #[allow(clippy::infallible_destructuring_match)]
    let setup = match setup {
        SetupOutcome::V1(s) => s,
        // A `/v2` connection runs the post-quantum pump (no DAITA padding on the
        // PQ path yet; a DAITA-enabled exit that also published an ML-KEM key is
        // out of scope for the first cut and simply terminates PQ without cover).
        #[cfg(feature = "pq-hpke")]
        SetupOutcome::V2(pq_setup) => {
            if let Some(pq) = pq {
                serve_pq_datagram_pump(conn, exit_id, tun, pq_setup, router, down_tx, down_rx, pq)
                    .await;
            }
            return;
        }
    };
    if !setup.wants_daita {
        // The IpAssign echo already read `daita_spec: None` for this client;
        // driving the machines anyway would rain 0xFF dummies on a peer that
        // never negotiated the defense (see `ConnSetup::wants_daita`), so the
        // connection runs with the shared state disarmed.
        *daita.lock() = DaitaState::disabled();
    }
    let assigned_ip: Arc<Mutex<Option<Ipv4Addr>>> = Arc::new(Mutex::new(setup.assigned_ip));
    let assigned_ip_v6: Arc<Mutex<Option<Ipv6Addr>>> = Arc::new(Mutex::new(setup.assigned_ip_v6));
    *current.lock() = Some((setup.session.clone(), setup.epoch));

    // Inbound-activity counter for the sticky-IP takeover re-check (DAITA
    // variant); the RX task bumps it via its own `datagrams` counter below.
    let rx_activity = Arc::new(AtomicU64::new(0));
    arm_takeover_recheck(
        &router,
        &down_tx,
        setup.assigned_ip,
        setup.assigned_ip_v6,
        &rx_activity,
    );

    // ADR 36 soft drain signal (DAITA variant): same emitter as the
    // non-DAITA path. `current`/`reverse_seq` are Arc-cloned here because
    // the timer task also keeps a handle, so plain clones are correct.
    let drain_task =
        spawn_drain_emitter(drain_rx, current.clone(), reverse_seq.clone(), conn.clone());

    // Transport path probe: same observability-parity rationale as the
    // non-DAITA variant (prod terminates clients on this path).
    drop(warrenguard_transport_core::spawn_path_probe(
        "exit-mh",
        vec![conn.clone()],
        None,
    ));

    let conn_rx = conn.clone();
    let tun_rx = tun.clone();
    let cache_rx = cache.clone();
    let privkey_rx = privkey.clone();
    let current_rx = current.clone();
    let daita_rx = daita.clone();
    let state_changed_rx = state_changed.clone();
    // For learning per-flow downlink ownership from the uplink (both `None`
    // on the legacy no-allocator path, where routing is direct `tun.recv`).
    let router_rx = router.clone();
    let down_tx_rx = down_tx.clone();
    // Anti-spoof gate inputs: fixed for the connection's lifetime (the
    // allocation happens once, during setup). `None` only on the legacy
    // no-allocator path (single client, bootstrap IP) where no expected
    // address exists to compare against.
    let spoof_gate_v4 = setup.assigned_ip;
    let spoof_gate_v6 = setup.assigned_ip_v6;
    let rx_activity_rx = rx_activity.clone();
    // Counters for periodic observability. Surfaces silent drop paths
    // (decode/exit_id/session.open) and the dummy-vs-real split so a
    // "0 real packets reach TUN under DAITA" scenario can be diagnosed
    // from production logs without per-packet log spam.
    let rx_task = tokio::spawn(async move {
        let mut datagrams = 0u64;
        let mut decode_errs = 0u64;
        let mut exit_id_mismatches = 0u64;
        let mut session_errs = 0u64;
        let mut open_errs = 0u64;
        let mut dummies = 0u64;
        let mut to_tun = 0u64;
        // Defensive forward-compat dispatch on the `0xC0` marker:
        // ignores late or unknown control frames on the datagram path
        // (the IpAssign already travelled over the reliable setup
        // stream).
        let mut control_ok = 0u64;
        let mut control_errs = 0u64;
        let mut last_report = Instant::now();
        let mut replays = 0u64;
        let mut spoofed_drops = 0u64;
        let mut tun_write_errors: u32 = 0;
        // Lock-free per-connection memo of flows already announced to the
        // router: the downlink owner is set once (first-writer-wins), so we
        // only take the router lock on a flow's FIRST uplink packet, never
        // on the bulk data that follows. Cleared coarsely at the cap.
        let mut noted_flows: HashSet<u64> = HashSet::new();
        loop {
            let datagram = match conn_rx.read_datagram().await {
                Ok(d) => d,
                Err(_) => return,
            };
            datagrams += 1;
            // One lock-free bump per inbound datagram, feeding the sticky-IP
            // takeover re-check (dead predecessor => this stays frozen).
            rx_activity_rx.fetch_add(1, Ordering::Relaxed);
            let frame = match decode_frame(&datagram) {
                Ok(f) => f,
                Err(_) => {
                    decode_errs += 1;
                    continue;
                }
            };
            if frame.exit_id != exit_id {
                exit_id_mismatches += 1;
                continue;
            }
            let handle = match cache_rx.get_or_insert(&frame.encapsulated_key, || {
                ExitSession::new(&privkey_rx, &frame.encapsulated_key, exit_id)
            }) {
                Ok(h) => h,
                Err(_) => {
                    session_errs += 1;
                    continue;
                }
            };
            let session = handle.session;
            // Capture the Copy scalars used after the open (anti-replay seq/epoch
            // and the epoch slot) before the zero-copy open consumes the frame.
            let (frame_seq, frame_epoch) = (frame.seq, frame.epoch);
            let mut plaintext = match session.open_owned(frame) {
                Ok(p) => p,
                Err(_) => {
                    open_errs += 1;
                    continue;
                }
            };
            // Anti-replay: reject a frame whose (epoch, seq) was already
            // accepted, before it can reach the TUN / the open internet. A blind
            // or compromised relay can re-send a captured sealed frame; without
            // this, `ExitSession::open` re-derives the identical per-packet key
            // and the exit would re-inject the inner IP packet. The window is
            // shared across every connection driving this HPKE session (cf.
            // SessionCache), so a replay on a fresh connection is rejected too.
            if handle
                .replay_windows
                .lock()
                .check_and_record(frame_seq, frame_epoch)
                .is_err()
            {
                replays += 1;
                continue;
            }
            *current_rx.lock() = Some((session.clone(), frame_epoch));
            // DAITA: TunnelRecv fires for every received frame
            // (real or dummy), then either PaddingRecv (drop before
            // TUN) or NormalRecv (after successful tun.send). Each
            // fire_events potentially schedules a new action timer
            // so we wake the timer task to re-read `next_timer`.
            daita_rx
                .lock()
                .fire_events(&[DaitaEvent::TunnelRecv], Instant::now());
            state_changed_rx.notify_one();
            // Control message dispatch precedes the DAITA dummy filter
            // and the IP forward path. The IpAssign already travelled
            // over the reliable setup stream, so a control frame on the
            // datagram path (a stray legacy IpRequest retry, an unknown
            // future control message) is simply dropped here.
            let control_msg = match warrenguard_multihop::try_decode_control(&plaintext) {
                Ok(Some(msg)) => {
                    control_ok += 1;
                    Some(msg)
                }
                Ok(None) => None,
                Err(e) => {
                    control_errs += 1;
                    tracing::debug!(error = %e, "rx_task control-message decode failed; dropping frame");
                    continue;
                }
            };
            if control_msg.is_some() {
                tracing::debug!(
                    "rx_task observed a control message on the datagram path; dropping (setup already done over stream)"
                );
                continue;
            }
            if is_daita_dummy(&plaintext) {
                dummies += 1;
                daita_rx
                    .lock()
                    .fire_events(&[DaitaEvent::PaddingRecv], Instant::now());
                state_changed_rx.notify_one();
            } else if let Some(expected_v4) = spoof_gate_v4
                && !source_ip_matches(&plaintext, expected_v4, spoof_gate_v6)
            {
                // Anti-spoof: the decrypted packet's inner source IP must
                // be the address allocated to this connection. The counter
                // (not the address) is logged.
                spoofed_drops += 1;
                if spoofed_drops == 1 || spoofed_drops.is_multiple_of(10_000) {
                    tracing::warn!(
                        spoofed_drops,
                        "rx_task: dropped packet with spoofed inner source IP"
                    );
                }
            } else {
                // Anti-spoof passed: the inner source IP is this
                // connection's allocation, so it is safe to record this
                // flow's downlink owner for the reverse path. Only the first
                // packet of each flow takes the router lock (memoized here).
                if let (Some(router), Some(owner)) = (&router_rx, &down_tx_rx)
                    && let Some(fk) = canonical_flow_key(&plaintext)
                {
                    if noted_flows.len() >= FLOW_TABLE_CAP_PER_IP {
                        noted_flows.clear();
                    }
                    if noted_flows.insert(fk) {
                        router.note_uplink(&plaintext, owner);
                    }
                }
                // Cap the MSS any SYN announces to the exit's own downlink
                // budget before it reaches the TUN: see `clamp_uplink_syn`.
                clamp_uplink_syn(&mut plaintext, &conn_rx, MULTIHOP_FRAME_MAX_OVERHEAD);
                match tun_rx.send(&plaintext).await {
                    Ok(()) => {
                        tun_write_errors = 0;
                        to_tun += 1;
                        daita_rx
                            .lock()
                            .fire_events(&[DaitaEvent::NormalRecv], Instant::now());
                        state_changed_rx.notify_one();
                    }
                    Err(e) => {
                        tun_write_errors += 1;
                        if tun_write_errors == 1 || tun_write_errors.is_multiple_of(1_000) {
                            tracing::warn!(
                                error = %e,
                                consecutive = tun_write_errors,
                                "rx_task: transient TUN write error, dropping packet"
                            );
                        }
                        if tun_write_errors >= MAX_CONSECUTIVE_TUN_WRITE_ERRORS {
                            return;
                        }
                    }
                }
            }
            // Periodic structured report every 5 s so the bench harness
            // can correlate per-conn behaviour against the wire trace.
            if last_report.elapsed() >= Duration::from_secs(5) {
                tracing::debug!(
                    datagrams,
                    decode_errs,
                    exit_id_mismatches,
                    session_errs,
                    open_errs,
                    dummies,
                    control_ok,
                    control_errs,
                    to_tun,
                    replays,
                    spoofed_drops,
                    "rx_task report"
                );
                last_report = Instant::now();
            }
        }
    });

    let conn_tx = conn.clone();
    let tun_tx = tun;
    let mut down_rx_tx = down_rx;
    let current_tx = current.clone();
    let reverse_seq_tx = reverse_seq.clone();
    let daita_tx = daita.clone();
    let state_changed_tx = state_changed.clone();
    let tx_task = tokio::spawn(async move {
        let mut from_tun = 0u64;
        let mut no_session = 0u64;
        let mut seal_errs = 0u64;
        let mut encode_errs = 0u64;
        let mut too_large = 0u64;
        let mut mtu_reflected = 0u64;
        let mut sent = 0u64;
        let mut last_report = Instant::now();
        loop {
            // Downlink source: the router channel (per-IP routed) when
            // ip-nego is on, else the shared TUN directly (single client).
            let mut packet = match next_downlink(&mut down_rx_tx, &tun_tx).await {
                Some(p) => p,
                None => return,
            };
            from_tun += 1;
            // Over-read backpressure: drop the newest packet BEFORE sealing (and
            // before the DAITA uplink-sent event, which must only fire for a
            // packet that actually egresses) when the client's connection buffer
            // is near full. See the gate helper.
            if overread_gate_should_drop(
                &conn_tx,
                warrenguard_config::knobs::exit_overread_gate_mtus(),
            ) {
                continue;
            }
            let (session, epoch) = match current_tx.lock().clone() {
                Some(v) => v,
                None => {
                    no_session += 1;
                    continue;
                }
            };
            // Reject/clamp before sealing: see `adapt_inner_for_budget`. Done
            // before the DAITA uplink-sent event, which must only fire for a
            // packet that actually proceeds to seal+send.
            let budget = inner_budget(conn_tx.max_datagram_size(), MULTIHOP_FRAME_MAX_OVERHEAD);
            if let Some(ptb) = adapt_inner_for_budget(&mut packet, budget) {
                mtu_reflected += 1;
                if mtu_reflected == 1 || mtu_reflected.is_multiple_of(64) {
                    tracing::warn!(
                        mtu_reflected,
                        budget,
                        "tx_task: packet exceeds downlink budget, reflecting frag-needed instead of sealing"
                    );
                }
                if let Err(e) = tun_tx.send(&ptb).await {
                    tracing::trace!(error = %e, "tx_task: frag-needed reflection tun write failed");
                }
                continue;
            }
            let seq = reverse_seq_tx.fetch_add(1, Ordering::AcqRel);
            // DAITA: the uplink event sequence BEFORE the seal so the
            // framework observes the egress timing independent of any QUIC
            // backpressure in send_datagram. Notify the timer task because
            // the new events may have scheduled a SendPadding action timer.
            daita_tx.lock().on_real_uplink_sent(Instant::now());
            state_changed_tx.notify_one();
            // Same plaintext-side classification as the non-DAITA tx_task.
            let class = DatagramClass::of_inner_ip_packet(&packet);
            let frame = match session.seal_response_owned(packet, epoch, seq) {
                Ok(f) => f,
                Err(_) => {
                    seal_errs += 1;
                    continue;
                }
            };
            let bytes = match encode_frame(&frame) {
                Ok(b) => b,
                Err(_) => {
                    encode_errs += 1;
                    continue;
                }
            };
            match conn_tx.send_datagram_classified(bytes.into(), class) {
                Ok(()) => sent += 1,
                // Transient: Quinn's black-hole detector can lower the
                // path-MTU estimate under a loss burst, making an
                // already-sealed frame "too large" for a moment. Drop
                // the packet (TCP retransmits); exiting here used to
                // permanently mute this connection's downlink while
                // QUIC stayed alive, collapsing every bonded flow onto
                // the last surviving sender (2026-06-11 incident).
                Err(SendDatagramError::TooLarge) => {
                    too_large += 1;
                    if too_large == 1 || too_large.is_multiple_of(5_000) {
                        tracing::warn!(
                            too_large,
                            "tx_task: datagram too large for current path MTU, dropped"
                        );
                    }
                }
                // Connection gone (or datagrams disabled by the peer):
                // nothing further can ever be sent on this conn.
                Err(_) => return,
            }
            if last_report.elapsed() >= Duration::from_secs(5) {
                tracing::debug!(
                    from_tun,
                    no_session,
                    seal_errs,
                    encode_errs,
                    too_large,
                    mtu_reflected,
                    sent,
                    "tx_task report"
                );
                last_report = Instant::now();
            }
        }
    });

    // Timer task: wakes on next per-machine action timer, drains
    // expired ones, seals one dummy per machine via the current
    // ExitSession (rotates on rekey transparently) and emits it on
    // the reverse direction with a 0xFF marker. Receiver-side
    // `is_daita_dummy` then drops it before reaching the TUN.
    //
    // Wakes early on `state_changed` (RX/TX fired events that may
    // have scheduled a closer action timer): without this, the timer
    // would sleep on the 3600 s placeholder it read before any event
    // fired and the maybenot machine would never produce dummies in
    // practice.
    let current_timer = current;
    let reverse_seq_timer = reverse_seq;
    let daita_timer = daita;
    let conn_timer = conn.clone();
    let state_changed_timer = state_changed;
    let timer_task = tokio::spawn(async move {
        loop {
            let next_timer = daita_timer.lock().sleep_deadline(Instant::now());
            let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(next_timer));
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => {}
                _ = state_changed_timer.notified() => {
                    // State changed: re-read next_timer on the next
                    // loop iteration. Do NOT drain expired here
                    // since the placeholder timer may not have
                    // fired yet.
                    continue;
                }
            }
            let fired = {
                let mut st = daita_timer.lock();
                st.drain_expired(Instant::now())
            };
            if fired.is_empty() {
                continue;
            }
            let (session, epoch) = match current_timer.lock().clone() {
                Some(v) => v,
                None => continue,
            };
            // Dummy plaintext size accounting for HPKE + wire format
            // overhead (~96 B: 12 nonce + 16 AEAD tag + ~68 wire header
            // fields). Capping plaintext below the negotiated Quinn
            // `max_datagram_size` prevents `send_datagram` returning
            // `TooLarge` and silently killing the timer task. On
            // loopback the negotiated max is ~1200 B; in production
            // cross-DC with TUN MTU 1280 the value scales with the
            // path MTU.
            let max_plaintext = conn_timer
                .max_datagram_size()
                .unwrap_or(1200)
                .saturating_sub(96)
                .min(1184);
            for machine in fired {
                let dummy = vec![DAITA_DUMMY_FIRST_BYTE; max_plaintext];
                let seq = reverse_seq_timer.fetch_add(1, Ordering::AcqRel);
                let frame = match session.seal_response_owned(dummy, epoch, seq) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::trace!(error = %e, "daita dummy seal failed");
                        continue;
                    }
                };
                let bytes = match encode_frame(&frame) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::trace!(error = %e, "daita dummy encode failed");
                        continue;
                    }
                };
                match conn_timer.send_datagram(bytes.into()) {
                    Ok(()) => {}
                    // Transient PMTU dip: skip this dummy, keep the
                    // DAITA timer alive (a dead timer silently disables
                    // the defense for the rest of the session).
                    Err(SendDatagramError::TooLarge) => continue,
                    Err(_) => return,
                }
                daita_timer.lock().on_dummy_sent(machine, Instant::now());
            }
        }
    });

    // On conn close, rx_task returns first (Quinn `read_datagram`
    // errors). Without this abort path the tx_task's `tun.recv()` and
    // the timer_task's `sleep_until + Notify` would both hang forever,
    // leaking the spawn task and blocking the allocator's
    // `release(conn_id)` in the parent.
    let _ = rx_task.await;
    tx_task.abort();
    timer_task.abort();
    // Abort AND join the drain emitter (see the non-DAITA variant): a
    // deadline hard-close in flight settles before the pump's own close so
    // the client-visible code stays deterministic.
    if let Some(t) = drain_task {
        t.abort();
        let _ = t.await;
    }
    let _ = tx_task.await;
    let _ = timer_task.await;
    // Drop this connection's downlink route so the single TUN reader
    // stops sending its reply packets to a dead channel (and a sticky
    // reconnect re-registers cleanly). Owner-checked: a same-pubkey
    // takeover may have re-pointed the address at a successor already.
    if let (Some(router), Some(ip), Some(own_tx)) = (&router, *assigned_ip.lock(), &down_tx) {
        router.unregister_if_owner(ip, own_tx);
        if let Some(ip6) = *assigned_ip_v6.lock() {
            router.unregister_v6_if_owner(ip6, own_tx);
        }
    }
    // Pumps gone: close the QUIC connection so the client's bundle
    // observes the death and redials (see the non-DAITA variant).
    conn.close(quinn::VarInt::from_u32(0), b"exit pumps ended");
    // Per-connection DAITA snapshot. Logged on close so
    // each multi-hop conn produces one final summary line containing
    // its emission profile + lifetime; ops can aggregate across conns
    // off-line without parsing the 5 s in-flight rx/tx reports.
    // `machine` field threaded from `warren-exit::main`
    // so the close log mirrors the client-side counterpart (one
    // grep on the machine label correlates both ends of the path).
    // Read the LIVE state, not the pre-setup pick: a client that never
    // negotiated DAITA had its machines disarmed after setup and must
    // close with `machines_count=0`, not the sampled pool's count.
    let (metrics, machines_count) = {
        let st = daita_for_metrics.lock();
        (st.metrics(), st.machines_count())
    };
    let conn_secs = conn_start.elapsed().as_secs();
    tracing::info!(
        machine = %daita_machine_name.as_deref().unwrap_or("<none>"),
        machines_count,
        padding_fired = metrics.padding_fired,
        blocking_begins = metrics.blocking_begins,
        blocking_ends = metrics.blocking_ends,
        conn_secs,
        "multi-hop connection closed; DAITA per-conn metrics snapshot"
    );
}

/// Format the X25519 multihop pubkey as 64 lowercase hex chars on a
/// single line. Mirror of the format expected by the
/// `warren-exit-sign-descriptor` helper bin so an operator can pipe one
/// into the other without manual conversion.
#[must_use]
pub fn format_x25519_pubkey_hex(pub_key: &WarrenKemPublicKey) -> String {
    hex::encode(pubkey_to_bytes(pub_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Downlink over-read backpressure gate ----

    /// The gate is a kill-switchable safety, not a hard-coded behaviour: with
    /// `gate_mtus == 0` it must NEVER drop, even when the send buffer is empty.
    #[test]
    fn overread_gate_disabled_never_drops() {
        assert!(
            !overread_should_drop(0, 1280, 0),
            "disabled gate must pass a full buffer"
        );
        assert!(!overread_should_drop(1_000_000, 1280, 0));
    }

    /// The gate's whole purpose: when the connection's datagram send buffer has
    /// less than `gate_mtus` MTUs of room, the NEW packet is tail-dropped before
    /// it can deepen the standing queue into the CoDel oldest-first head-drop.
    #[test]
    fn overread_gate_drops_when_buffer_near_full() {
        // 1 KiB of room left, 4-MTU (5120 B) low-water at a 1280 B MTU: drop.
        assert!(overread_should_drop(1024, 1280, 4));
        // No room at all: drop.
        assert!(overread_should_drop(0, 1280, 4));
    }

    /// Symmetric to the drop case: with plenty of room the gate is a no-op, so
    /// the datapath is unchanged whenever the connection is draining normally.
    #[test]
    fn overread_gate_passes_when_space_available() {
        assert!(!overread_should_drop(100_000, 1280, 4));
        // Exactly at the low-water is enough room (strict `<`): the boundary
        // packet passes, so the gate never fires one MTU too early.
        assert!(
            !overread_should_drop(4 * 1280, 1280, 4),
            "at the low-water, pass"
        );
        // One byte under the low-water fires.
        assert!(
            overread_should_drop(4 * 1280 - 1, 1280, 4),
            "just under the low-water, drop"
        );
    }

    /// Relative keying (the property that lets the gate survive fork.11's
    /// BDP-adaptive buffer without a fixed 16-MiB constant): the SAME `gate_mtus`
    /// yields a threshold that scales with the connection's live MTU. With the
    /// same 5000 B of room, a 1000 B MTU (threshold 4000) passes but a 2000 B
    /// MTU (threshold 8000) drops.
    #[test]
    fn overread_gate_threshold_is_relative_to_mtu() {
        assert!(!overread_should_drop(5000, 1000, 4), "5000 >= 4*1000, pass");
        assert!(overread_should_drop(5000, 2000, 4), "5000 < 4*2000, drop");
    }

    // ---- Multi-queue exit TUN wiring ----

    /// The single-queue default (no extra queues) must be exactly today's
    /// behaviour: one queue, and `pick_uplink_tun` hands out the primary
    /// without ever spinning the round-robin cursor.
    #[tokio::test]
    async fn exit_ctx_defaults_to_a_single_tun_queue() {
        let (priv_key, _pub) = derive_x25519_keypair(&[3u8; 32]).expect("32-byte ikm");
        let ctx = ExitTerminateCtx::new(
            priv_key,
            ExitId::from_bytes([1u8; 16]),
            warrenguard_transport_core::FakeTun::new(),
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            ctx.tun_queue_count(),
            1,
            "default exit opens exactly one TUN queue"
        );
        for _ in 0..5 {
            let _ = ctx.pick_uplink_tun();
        }
        assert_eq!(
            ctx.next_uplink.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "single-queue pick must short-circuit to the primary, never spinning the cursor"
        );
    }

    /// Opting into N queues constructs an N-wide fan-out and round-robins the
    /// per-connection uplink across them (the cursor advances once per pick).
    #[tokio::test]
    async fn exit_ctx_multi_queue_constructs_n_queues_and_round_robins() {
        let (priv_key, _pub) = derive_x25519_keypair(&[4u8; 32]).expect("32-byte ikm");
        let ctx = ExitTerminateCtx::new(
            priv_key,
            ExitId::from_bytes([2u8; 16]),
            warrenguard_transport_core::FakeTun::new(),
            None,
            None,
            None,
            None,
            None,
        )
        .with_extra_tun_queues(vec![
            warrenguard_transport_core::FakeTun::new(),
            warrenguard_transport_core::FakeTun::new(),
        ]);
        assert_eq!(ctx.tun_queue_count(), 3, "primary + 2 extra = 3 queues");
        for _ in 0..3 {
            let _ = ctx.pick_uplink_tun();
        }
        assert_eq!(
            ctx.next_uplink.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "each multi-queue pick advances the round-robin cursor once"
        );
    }

    /// An empty extra-queue list is a no-op: a deployer that resolved
    /// `queues == 1` leaves the single-queue default untouched.
    #[tokio::test]
    async fn exit_ctx_with_empty_extra_queues_stays_single() {
        let (priv_key, _pub) = derive_x25519_keypair(&[5u8; 32]).expect("32-byte ikm");
        let ctx = ExitTerminateCtx::new(
            priv_key,
            ExitId::from_bytes([3u8; 16]),
            warrenguard_transport_core::FakeTun::new(),
            None,
            None,
            None,
            None,
            None,
        )
        .with_extra_tun_queues(vec![]);
        assert_eq!(
            ctx.tun_queue_count(),
            1,
            "empty extra queues keep the single-queue default"
        );
    }

    // ---- DAITA machine selection (per connection, not per process) ----

    /// Different connections of the same exit must run different defenses: that
    /// spread of behaviours is the whole point of sampling a pool rather than
    /// shipping one machine. 200 draws over a 5-entry uniform pool land on a
    /// single name with probability 5 * (1/5)^200, so one distinct name here
    /// means the pick is not happening per connection.
    #[test]
    fn pool_source_varies_the_machine_across_connections() {
        let source = DaitaSource::pool(warrenguard_daita::DaitaPool::default_pool(), None)
            .expect("default pool is non-empty");
        let names: std::collections::HashSet<String> = (0..200)
            .filter_map(|_| source.pick_for_connection().name)
            .collect();
        assert!(
            names.len() >= 2,
            "200 connections to one exit MUST sample more than one curated machine; \
             a single name means the machine is picked per process, not per connection. Got: {names:?}"
        );
    }

    /// `--daita-machine <name>` is an ops lever to hold one family steady while
    /// investigating. It must keep pinning that family even though the pick now
    /// happens per connection.
    #[test]
    fn pinned_pool_source_always_returns_the_pinned_family() {
        let source = DaitaSource::pool(
            warrenguard_daita::DaitaPool::default_pool(),
            Some("tamaraw".to_owned()),
        )
        .expect("tamaraw is a curated entry");
        for _ in 0..20 {
            let pick = source.pick_for_connection();
            assert_eq!(pick.name.as_deref(), Some("tamaraw"));
            assert!(
                pick.state.is_enabled(),
                "a pinned pool entry MUST yield DAITA on"
            );
            assert!(
                pick.config.is_some(),
                "an enabled pick MUST carry the spec to grant a wants_daita client"
            );
        }
    }

    /// An unknown pinned name is an operator typo that would otherwise boot an
    /// exit with DAITA silently off. Fail closed at construction instead.
    #[test]
    fn pool_source_rejects_an_unknown_pinned_machine() {
        assert!(
            DaitaSource::pool(
                warrenguard_daita::DaitaPool::default_pool(),
                Some("does-not-exist".to_owned()),
            )
            .is_none(),
            "an unknown --daita-machine MUST be refused, never silently disable DAITA"
        );
    }

    /// The deterministic path the integration tests rely on: one fixed config,
    /// identical for every connection.
    #[test]
    fn fixed_source_returns_the_same_machine_for_every_connection() {
        let cfg = warrenguard_daita::DaitaPool::default_pool()
            .pick_named_os("tamaraw")
            .expect("curated pool carries tamaraw");
        let source = DaitaSource::fixed(cfg.clone(), Some("tamaraw".to_owned()));
        for _ in 0..5 {
            let pick = source.pick_for_connection();
            assert_eq!(pick.name.as_deref(), Some("tamaraw"));
            assert!(pick.state.is_enabled());
            assert_eq!(
                pick.config.as_ref(),
                Some(&cfg),
                "the advertisable spec MUST be the very config the state runs"
            );
        }
    }

    #[test]
    fn off_source_yields_a_disabled_state() {
        let pick = DaitaSource::Off.pick_for_connection();
        assert!(
            !pick.state.is_enabled(),
            "DAITA off MUST run the plain pump at zero overhead"
        );
        assert!(pick.name.is_none());
        assert!(
            pick.config.is_none(),
            "a disabled pick MUST NOT carry a spec the exit would falsely advertise"
        );
    }

    /// The production dispatcher builds ONE `ExitTerminateCtx` and clones it
    /// into every accepted connection, so the per-connection pick has to live
    /// on the shared ctx itself. This drives the real production type: a ctx
    /// carrying the pool must hand out a fresh machine on each call, which is
    /// exactly what a pre-picked config on the shared ctx could not do.
    #[tokio::test]
    async fn exit_ctx_with_a_pool_picks_a_fresh_machine_for_every_connection() {
        let (priv_key, _pub) = derive_x25519_keypair(&[7u8; 32]).expect("32-byte ikm");
        let ctx = ExitTerminateCtx::new(
            priv_key,
            ExitId::from_bytes([9u8; 16]),
            warrenguard_transport_core::FakeTun::new(),
            None,
            None,
            None,
            None,
            None,
        )
        .with_daita_pool(warrenguard_daita::DaitaPool::default_pool(), None)
        .expect("default pool is non-empty");

        let names: std::collections::HashSet<String> = (0..200)
            .filter_map(|_| ctx.daita_for_connection().name)
            .collect();
        assert!(
            names.len() >= 2,
            "every connection terminated by one exit process MUST get an independently \
             sampled machine; got a single name across 200 connections: {names:?}"
        );
    }

    // ---- MultihopSessionRegistry (mid-session revocation teardown) ----

    /// Fake connection that records how many times it was force-closed,
    /// so the registry's bookkeeping can be tested without a live QUIC
    /// handshake. Optionally carries datapath stats to exercise
    /// [`MultihopSessionRegistry::datapath_stats`].
    #[derive(Clone)]
    struct FakeConn {
        closes: Arc<std::sync::atomic::AtomicUsize>,
        stats: Option<ConnDatapathStats>,
        remote: Option<std::net::SocketAddr>,
    }

    impl FakeConn {
        fn new() -> Self {
            Self {
                closes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                stats: None,
                remote: None,
            }
        }
        fn with_stats(stats: ConnDatapathStats) -> Self {
            Self {
                closes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                stats: Some(stats),
                remote: None,
            }
        }
        fn with_remote(addr: &str) -> Self {
            Self {
                closes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                stats: None,
                remote: Some(addr.parse().expect("test socket addr parses")),
            }
        }
        fn closes(&self) -> usize {
            self.closes.load(Ordering::Acquire)
        }
    }

    impl ClosableConn for FakeConn {
        fn close_rejected(&self) {
            self.closes.fetch_add(1, Ordering::AcqRel);
        }
        fn datapath_stats(&self) -> Option<ConnDatapathStats> {
            self.stats
        }
        fn remote_address(&self) -> Option<std::net::SocketAddr> {
            self.remote
        }
    }

    #[test]
    fn snapshot_ipv4_sources_includes_direct_client_and_unmaps_v4_mapped() {
        // A 1-hop client's connection carries its real v4 source; a v4-mapped-v6
        // peer is unmapped to its v4 form. Both must appear in the guard set.
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        registry.register(reg_pk(1), 1, FakeConn::with_remote("203.0.113.7:51000"));
        registry.register(
            reg_pk(2),
            2,
            FakeConn::with_remote("[::ffff:198.51.100.9]:41000"),
        );

        let got = registry.snapshot_ipv4_sources_excluding(&std::collections::BTreeSet::new());

        assert_eq!(
            got,
            [
                Ipv4Addr::new(198, 51, 100, 9),
                Ipv4Addr::new(203, 0, 113, 7),
            ]
            .into_iter()
            .collect(),
            "direct client v4 and unmapped v4-mapped-v6 sources must both be in the set"
        );
    }

    #[test]
    fn snapshot_ipv4_sources_excludes_fleet_relay_ips() {
        // The crux: a 2-hop exit-leg's source is a Warren relay's (fleet
        // endpoint) IP. Passing it in `exclude` MUST keep it out of the drop
        // set, else every client behind that relay loses forwarded-port access.
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        let relay_ip = Ipv4Addr::new(192, 0, 2, 50);
        registry.register(reg_pk(1), 1, FakeConn::with_remote("203.0.113.7:51000")); // direct
        registry.register(reg_pk(2), 2, FakeConn::with_remote("192.0.2.50:44000")); // relay leg

        let exclude: std::collections::BTreeSet<Ipv4Addr> = [relay_ip].into_iter().collect();
        let got = registry.snapshot_ipv4_sources_excluding(&exclude);

        assert_eq!(
            got,
            [Ipv4Addr::new(203, 0, 113, 7)].into_iter().collect(),
            "the relay/fleet endpoint IP must be excluded; only the direct client remains"
        );
    }

    #[test]
    fn snapshot_ipv4_sources_skips_native_v6_and_addressless_conns() {
        // A genuine v6 peer is not representable in the v4-only guard set, and a
        // connection that exposes no address (a fake, or a not-yet-connected
        // handle) contributes nothing. Neither may crash or pollute the set.
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        registry.register(reg_pk(1), 1, FakeConn::with_remote("[2001:db8::1]:51000"));
        registry.register(reg_pk(2), 2, FakeConn::new()); // no address

        let got = registry.snapshot_ipv4_sources_excluding(&std::collections::BTreeSet::new());

        assert!(
            got.is_empty(),
            "a native-v6 peer and an addressless conn must yield an empty v4 set, got {got:?}"
        );
    }

    #[test]
    fn datapath_stats_returns_one_entry_per_reporting_conn() {
        // The sampler needs per-connection cumulative counters keyed by
        // stable id; a connection type that reports no stats is skipped.
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        let pk = reg_pk(1);
        let s0 = ConnDatapathStats {
            bytes_tx: 1000,
            bytes_rx: 500,
            datagrams_tx: 10,
            datagrams_rx: 8,
            lost_packets: 2,
            congestion_events: 1,
            rtt_us: 20_000,
        };
        let s1 = ConnDatapathStats {
            bytes_tx: 300,
            bytes_rx: 200,
            datagrams_tx: 4,
            datagrams_rx: 3,
            lost_packets: 0,
            congestion_events: 0,
            rtt_us: 40_000,
        };
        registry.register(pk, 100, FakeConn::with_stats(s0));
        registry.register(pk, 101, FakeConn::with_stats(s1));
        // A conn without stats must not appear in the aggregate.
        registry.register(reg_pk(2), 200, FakeConn::new());

        let mut stats = registry.datapath_stats();
        stats.sort_by_key(|(id, _)| *id);
        assert_eq!(stats.len(), 2, "only stats-reporting conns are returned");
        assert_eq!(stats[0], (100, s0));
        assert_eq!(stats[1], (101, s1));
    }

    fn reg_pk(seed: u8) -> WarrenPubkey {
        WarrenPubkey::from_bytes([seed; 32])
    }

    #[test]
    fn registry_terminate_closes_all_bonded_conns_of_a_pubkey() {
        // A bonded client registers several connections under one pubkey;
        // a single revocation must close every one of them and report the
        // count.
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        let pk = reg_pk(1);
        let c0 = FakeConn::new();
        let c1 = FakeConn::new();
        registry.register(pk, 100, c0.clone());
        registry.register(pk, 101, c1.clone());
        assert_eq!(registry.live_client_count(), 1);

        let closed = registry.terminate(&pk);

        assert_eq!(closed, 2, "both bonded conns closed");
        assert_eq!(c0.closes(), 1);
        assert_eq!(c1.closes(), 1);
        assert_eq!(registry.live_client_count(), 0, "entry removed once empty");
    }

    #[test]
    fn registry_terminate_only_touches_the_revoked_pubkey() {
        // A revocation for one pubkey must not close another subscriber's
        // live connection.
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        let victim = FakeConn::new();
        let bystander = FakeConn::new();
        registry.register(reg_pk(1), 100, victim.clone());
        registry.register(reg_pk(2), 200, bystander.clone());

        let closed = registry.terminate(&reg_pk(1));

        assert_eq!(closed, 1);
        assert_eq!(victim.closes(), 1);
        assert_eq!(bystander.closes(), 0, "other pubkey untouched");
        assert_eq!(registry.live_client_count(), 1);
    }

    #[test]
    fn registry_terminate_unknown_pubkey_is_a_noop() {
        // Idempotency: revoking a pubkey with no live session (already
        // disconnected, or never connected) closes nothing and never
        // panics.
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        registry.register(reg_pk(1), 100, FakeConn::new());

        assert_eq!(registry.terminate(&reg_pk(99)), 0);
        assert_eq!(registry.terminate(&reg_pk(1)), 1);
        assert_eq!(
            registry.terminate(&reg_pk(1)),
            0,
            "second terminate is a no-op"
        );
    }

    #[test]
    fn registry_keeps_departed_attribution_until_retention_then_drops_it() {
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        registry.register(reg_pk(1), 100, FakeConn::new());
        let ip = Ipv4Addr::new(10, 66, 0, 5);
        registry.record_assigned_ipv4(ip, reg_pk(1));

        let t0 = Instant::now();
        assert_eq!(
            registry.snapshot_ipv4_to_pubkey_hex_at(t0).get(&ip),
            Some(&reg_pk(1).to_hex()),
            "a live client's tunnel IPv4 resolves to its account pubkey hex"
        );

        registry.unregister(&reg_pk(1), 100);

        // The orphan lease the client leaves on the old exit lingers until the
        // reaper sweeps it, so the attribution must outlive the session and not
        // flip to `unknown`.
        assert_eq!(
            registry.snapshot_ipv4_to_pubkey_hex_at(t0).get(&ip),
            Some(&reg_pk(1).to_hex()),
            "attribution survives the post-departure dying window"
        );
        assert!(
            registry
                .snapshot_ipv4_to_pubkey_hex_at(
                    t0 + DEPARTED_ATTRIBUTION_RETENTION + Duration::from_secs(1)
                )
                .is_empty(),
            "attribution is dropped once the retention window elapses"
        );
    }

    #[test]
    fn registry_reconnect_revives_departed_attribution() {
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        let ip = Ipv4Addr::new(10, 66, 0, 5);
        registry.register(reg_pk(1), 100, FakeConn::new());
        registry.record_assigned_ipv4(ip, reg_pk(1));
        registry.unregister(&reg_pk(1), 100);

        registry.register(reg_pk(1), 101, FakeConn::new());
        registry.record_assigned_ipv4(ip, reg_pk(1));

        assert_eq!(
            registry
                .snapshot_ipv4_to_pubkey_hex_at(
                    Instant::now() + DEPARTED_ATTRIBUTION_RETENTION + Duration::from_secs(5)
                )
                .get(&ip),
            Some(&reg_pk(1).to_hex()),
            "a reconnect on the same IP clears the tombstone and keeps the client named"
        );
    }

    #[test]
    fn registry_terminate_clears_the_ipv4_attribution() {
        let registry: MultihopSessionRegistry<FakeConn> = MultihopSessionRegistry::default();
        registry.register(reg_pk(1), 100, FakeConn::new());
        registry.record_assigned_ipv4(Ipv4Addr::new(10, 66, 0, 9), reg_pk(1));

        let _ = registry.terminate(&reg_pk(1));

        assert!(
            registry.snapshot_ipv4_to_pubkey_hex().is_empty(),
            "a revoked/terminated client's attribution must be cleared"
        );
    }

    #[test]
    fn session_guard_unregisters_one_conn_without_closing_siblings() {
        // The RAII guard removes exactly its own connection on drop; a
        // bonded sibling stays live and is NOT force-closed (a clean
        // disconnect is not a revocation).
        let registry: Arc<MultihopSessionRegistry<FakeConn>> =
            Arc::new(MultihopSessionRegistry::default());
        let a = FakeConn::new();
        let b = FakeConn::new();
        registry.register(reg_pk(1), 100, a.clone());
        registry.register(reg_pk(1), 101, b.clone());

        // The real SessionGuard cannot be built here (it is hardcoded to
        // the Connection-typed registry), so exercise the `unregister` its
        // Drop calls. The e2e test covers the guard's Drop end-to-end.
        registry.unregister(&reg_pk(1), 100);

        assert_eq!(a.closes(), 0, "unregister must not close the conn");
        assert_eq!(b.closes(), 0);
        assert_eq!(
            registry.live_client_count(),
            1,
            "sibling keeps the entry alive"
        );

        let closed = registry.terminate(&reg_pk(1));
        assert_eq!(closed, 1, "only the still-registered sibling remains");
        assert_eq!(b.closes(), 1);
    }

    /// Build a fresh `ExitSession` whose `encapsulated_key` matches
    /// `wanted_encap` if possible (otherwise just produces a valid
    /// session at whatever encap key OsRng landed on). Used by the
    /// SessionCache tests to populate entries without dragging in
    /// rand_chacha as a test dep.
    fn build_session_for_cache_test() -> Result<ExitSession, warrenguard_multihop::MultihopError> {
        let (priv_k, pub_k) =
            warrenguard_multihop::test_support::derive_exit_keypair(&[0x33u8; 32]);
        let exit_id = warrenguard_multihop::ExitId::from_bytes([0xCC; 16]);
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let client = warrenguard_multihop::ClientSession::new(&pub_k, exit_id, &mut rng)
            .expect("client session setup");
        warrenguard_multihop::ExitSession::new(&priv_k, &client.encapsulated_key(), exit_id)
    }

    #[cfg(feature = "pq-hpke")]
    #[test]
    fn pq_session_cache_establishes_from_setup_then_serves_data_lookups() {
        let (secret, public) = warrenguard_multihop::XWingRecipientSecretKey::derive_deterministic(
            &[7u8; 32],
            &[9u8; 32],
            &[11u8; 32],
        );
        let exit_id = ExitId::from_bytes([0x3c; 16]);
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let client = warrenguard_multihop::PqClientSession::new(&public, exit_id, &mut rng)
            .expect("client session setup");
        let ek = client.encapsulated_key();
        let cache = PqSessionCache::new();

        // A DATA-frame lookup before any setup MISSES: a PQ session cannot be
        // rebuilt without the setup frame's ML-KEM ciphertext.
        assert!(cache.get(&ek).is_none(), "no session before setup");

        // A setup frame (pq_ct present) establishes the session.
        let h1 = cache
            .establish_or_get(&ek, client.pq_ct(), exit_id, &secret)
            .expect("establish from setup");
        assert_eq!(cache.entry_count(), 1);

        // A steady-state DATA lookup now hits and shares the same anti-replay
        // window (so a replay accepted on one connection is rejected on all).
        let h2 = cache.get(&ek).expect("data lookup hits after setup");
        assert!(Arc::ptr_eq(&h1.replay_windows, &h2.replay_windows));

        // The established exit session opens a frame the client sealed to it.
        let frame = client.seal(b"pq data", 0, 1).expect("client seals data");
        assert_eq!(h2.session.open(&frame).expect("exit opens"), b"pq data");
    }

    #[test]
    fn session_cache_evicts_entries_after_ttl() {
        // ARRANGE: cache with a 50 ms TTL so the test runs fast.
        let cache = SessionCache::with_ttl(Duration::from_millis(50));
        let encap_a: EncapsulatedKeyBytes = [0x01; 32];
        let encap_b: EncapsulatedKeyBytes = [0x02; 32];

        // ACT: insert two distinct entries (the session value itself
        // is irrelevant for the eviction check; the cache keys on
        // encap bytes).
        cache
            .get_or_insert(&encap_a, build_session_for_cache_test)
            .expect("insert A");
        cache
            .get_or_insert(&encap_b, build_session_for_cache_test)
            .expect("insert B");
        assert_eq!(cache.entry_count(), 2, "both entries should be present");

        std::thread::sleep(Duration::from_millis(80));

        // A fresh lookup triggers the lazy sweep and inserts a new C
        // entry. A and B should be evicted as expired.
        let encap_c: EncapsulatedKeyBytes = [0x03; 32];
        cache
            .get_or_insert(&encap_c, build_session_for_cache_test)
            .expect("insert C");

        // ASSERT: only C remains.
        assert_eq!(
            cache.entry_count(),
            1,
            "expired entries A and B must be reclaimed by the lazy sweep"
        );
    }

    #[test]
    fn session_cache_hit_refreshes_last_seen_at() {
        // ARRANGE: short TTL, one entry installed.
        let cache = SessionCache::with_ttl(Duration::from_millis(40));
        let encap: EncapsulatedKeyBytes = [0x11; 32];
        cache
            .get_or_insert(&encap, build_session_for_cache_test)
            .expect("initial insert");

        // ACT: touch the entry every 20 ms for 120 ms total. Each touch
        // resets last_seen_at, so the entry must survive.
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(20));
            cache
                .get_or_insert(&encap, build_session_for_cache_test)
                .expect("refresh");
        }

        // ASSERT.
        assert_eq!(
            cache.entry_count(),
            1,
            "a touched entry must not be evicted while traffic keeps flowing"
        );
    }

    #[test]
    fn derive_x25519_ikm_from_ed25519_is_deterministic() {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let a = derive_x25519_ikm_from_ed25519(&key);
        let b = derive_x25519_ikm_from_ed25519(&key);
        assert_eq!(a, b);
        assert_ne!(
            a, [0u8; 32],
            "HKDF output must not be all zero (would indicate a no-op)"
        );
    }

    #[test]
    fn derive_x25519_ikm_from_ed25519_differs_per_input_key() {
        let a = derive_x25519_ikm_from_ed25519(&SigningKey::from_bytes(&[0x01; 32]));
        let b = derive_x25519_ikm_from_ed25519(&SigningKey::from_bytes(&[0x02; 32]));
        assert_ne!(a, b);
    }

    #[test]
    fn derive_x25519_keypair_rejects_short_ikm() {
        // `WarrenKemPrivateKey` does not derive `Debug` (intentional:
        // hpke's `PrivateKey` opts out so secret bytes never land in
        // panic messages or log lines). That rules out `expect_err`,
        // which requires `Debug` on the `Ok` variant; use an explicit
        // match instead.
        match derive_x25519_keypair(&[0u8; 4]) {
            Err(MultihopExitError::IkmTooShort { got }) => assert_eq!(got, 4),
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("short IKM must be rejected"),
        }
    }

    #[test]
    fn derive_x25519_keypair_is_deterministic_under_a_fixed_ikm() {
        let ikm = [0x77u8; 32];
        let (pub_a, pub_b) = match (derive_x25519_keypair(&ikm), derive_x25519_keypair(&ikm)) {
            (Ok((_, a)), Ok((_, b))) => (a, b),
            _ => panic!("derive_x25519_keypair must succeed on a 32-byte IKM"),
        };
        assert_eq!(
            pubkey_to_bytes(&pub_a),
            pubkey_to_bytes(&pub_b),
            "the same IKM must produce the same X25519 pubkey; otherwise the exit's published \
             multihop pubkey would rotate at every process restart and the operational signature \
             would silently break"
        );
    }

    #[cfg(feature = "pq-hpke")]
    #[test]
    fn exit_xwing_derivation_is_identity_bound_and_matches_published_x25519() {
        let signing = SigningKey::from_bytes(&[0x42; 32]);
        // Deterministic: the same identity publishes the same ML-KEM key on every boot.
        let (secret, ek1) = derive_exit_xwing_from_identity(&signing).expect("derive");
        let (_secret2, ek2) = derive_exit_xwing_from_identity(&signing).expect("derive again");
        assert_eq!(ek1, ek2, "same identity must publish the same ML-KEM key");
        assert_eq!(
            ek1.len(),
            1184,
            "ML-KEM-768 encapsulation key is 1184 bytes"
        );

        // The X-Wing pk_X MUST equal the exit's published multihop X25519 pubkey:
        // a client seals to the descriptor key and the exit decapsulates with this
        // secret, so a mismatch would bind different pk_X and the two hybrid secrets
        // would never agree.
        let x25519_ikm = derive_x25519_ikm_from_ed25519(&signing);
        let (_priv, x_pub) = derive_x25519_keypair(&x25519_ikm).expect("x25519 keypair");
        assert_eq!(
            secret.x25519_pubkey(),
            pubkey_to_bytes(&x_pub),
            "X-Wing pk_X must equal the exit's published multihop X25519 pubkey"
        );

        // A distinct identity derives a distinct ML-KEM key.
        let other = SigningKey::from_bytes(&[0x43; 32]);
        let (_s3, ek3) = derive_exit_xwing_from_identity(&other).expect("derive other");
        assert_ne!(
            ek1, ek3,
            "distinct identities must publish distinct ML-KEM keys"
        );
    }

    #[test]
    fn format_x25519_pubkey_hex_emits_64_lowercase_chars() {
        let pub_key = match derive_x25519_keypair(&[0x5Au8; 32]) {
            Ok((_, pk)) => pk,
            Err(e) => panic!("derive failed: {e:?}"),
        };
        let hex_str = format_x25519_pubkey_hex(&pub_key);
        assert_eq!(hex_str.len(), 64);
        assert!(
            hex_str
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "expected lowercase hex, got {hex_str}"
        );
    }

    #[test]
    fn session_cache_shares_one_replay_window_across_lookups() {
        // The cross-connection replay defense: two separate `get_or_insert`
        // calls for the SAME encapsulated_key (simulating two QUIC
        // connections sharing one HPKE session) must hand back the SAME
        // anti-replay window, so a seq recorded via the first lookup is
        // rejected via the second.
        let cache = SessionCache::new();
        let encap: EncapsulatedKeyBytes = [0x21; 32];

        // "Connection 1" records (epoch=0, seq=7).
        let h1 = cache
            .get_or_insert(&encap, build_session_for_cache_test)
            .expect("first lookup builds the session");
        assert!(
            h1.replay_windows.lock().check_and_record(7, 0).is_ok(),
            "the first occurrence of (epoch=0, seq=7) is accepted"
        );

        // "Connection 2" (fresh lookup, cache hit) replays the same seq.
        let h2 = cache
            .get_or_insert(&encap, build_session_for_cache_test)
            .expect("second lookup hits the cache");
        assert!(
            h2.replay_windows.lock().check_and_record(7, 0).is_err(),
            "a replay of (epoch=0, seq=7) on a second connection sharing the \
             session must be rejected by the shared window"
        );
    }

    #[test]
    fn session_cache_distinct_keys_have_independent_replay_windows() {
        // A different encapsulated_key is a different HPKE session and
        // must get its own window: the same seq under another key is NOT
        // a replay.
        let cache = SessionCache::new();
        let encap_a: EncapsulatedKeyBytes = [0x31; 32];
        let encap_b: EncapsulatedKeyBytes = [0x32; 32];

        let ha = cache
            .get_or_insert(&encap_a, build_session_for_cache_test)
            .expect("insert A");
        assert!(ha.replay_windows.lock().check_and_record(3, 0).is_ok());

        let hb = cache
            .get_or_insert(&encap_b, build_session_for_cache_test)
            .expect("insert B");
        assert!(
            hb.replay_windows.lock().check_and_record(3, 0).is_ok(),
            "the same seq under a different encapsulated_key is a distinct \
             session, not a replay"
        );
    }

    #[test]
    fn epoch_replay_windows_rejects_duplicate_seq_in_same_epoch() {
        let mut w = EpochReplayWindows::default();
        assert!(w.check_and_record(1, 0).is_ok(), "first frame accepted");
        assert!(w.check_and_record(2, 0).is_ok(), "next seq accepted");
        assert!(
            w.check_and_record(1, 0).is_err(),
            "a replay of (seq=1, epoch=0) must be rejected before reaching the TUN"
        );
    }

    #[test]
    fn epoch_replay_windows_are_independent_per_epoch() {
        let mut w = EpochReplayWindows::default();
        assert!(w.check_and_record(5, 0).is_ok());
        // The same seq under a different epoch is a distinct (epoch, seq).
        assert!(w.check_and_record(5, 1).is_ok());
        // But a replay within epoch 1 is still rejected.
        assert!(w.check_and_record(5, 1).is_err());
    }

    #[test]
    fn epoch_replay_windows_bounds_retained_epochs() {
        let mut w = EpochReplayWindows::default();
        for epoch in 0..(REPLAY_EPOCHS_KEPT as u32 + 3) {
            assert!(w.check_and_record(1, epoch).is_ok());
        }
        assert!(
            w.windows.len() <= REPLAY_EPOCHS_KEPT,
            "retained epoch windows must stay bounded under a rekey flood"
        );
    }

    /// Builds a minimal IPv4 packet (20-byte header) with the given dst.
    fn ipv4_packet_to(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn dst_ipv4_parses_v4_and_rejects_non_v4() {
        let pkt = ipv4_packet_to(Ipv4Addr::new(10, 66, 0, 7));
        assert_eq!(dst_ipv4(&pkt), Some(Ipv4Addr::new(10, 66, 0, 7)));
        assert_eq!(dst_ipv4(&[0x60u8; 40]), None, "IPv6 must not parse as v4");
        assert_eq!(dst_ipv4(&[0x45u8; 10]), None, "too short must be None");
    }

    #[tokio::test]
    async fn router_dispatches_each_packet_to_the_owning_ip() {
        // The core regression: two connections, each keyed by its own
        // allocated IPv4, must each receive ONLY their own reply packets
        // (the old shared-`tun.recv()` model sent each packet to a random
        // connection regardless of destination).
        let router = MultihopTunRouter::default();
        let ip_a = Ipv4Addr::new(10, 66, 0, 2);
        let ip_b = Ipv4Addr::new(10, 66, 0, 3);
        let (tx_a, mut rx_a) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register(ip_a, tx_a);
        router.register(ip_b, tx_b);

        router.dispatch(&ipv4_packet_to(ip_a));
        router.dispatch(&ipv4_packet_to(ip_b));
        router.dispatch(&ipv4_packet_to(Ipv4Addr::new(10, 66, 0, 99))); // no route -> dropped

        assert_eq!(dst_ipv4(&rx_a.try_recv().unwrap()), Some(ip_a));
        assert!(rx_a.try_recv().is_err(), "A must get exactly its packet");
        assert_eq!(dst_ipv4(&rx_b.try_recv().unwrap()), Some(ip_b));
        assert!(rx_b.try_recv().is_err(), "B must get exactly its packet");
    }

    #[tokio::test]
    async fn router_prunes_route_when_receiver_dropped() {
        let router = MultihopTunRouter::default();
        let ip = Ipv4Addr::new(10, 66, 0, 5);
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register(ip, tx);
        drop(rx); // connection gone
        router.dispatch(&ipv4_packet_to(ip));
        assert!(
            router.routes.0.lock().get(&ip).is_none(),
            "a closed-receiver route must be pruned on dispatch"
        );
    }

    /// Builds a minimal IPv4 TCP packet (20B header + 4B ports) so the
    /// 5-tuple flow hash applies, with a controllable source port.
    fn ipv4_tcp_packet(dst: Ipv4Addr, src_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45;
        p[9] = 6; // TCP
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&src_port.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p
    }

    #[tokio::test]
    async fn router_bonded_slot_pins_flows_and_survives_sibling_unregister() {
        // Bonded multi-connection client: two channels under ONE IP.
        // Every packet of a given flow must land on the same channel
        // (per-flow ordering), and unregistering one channel must leave
        // the sibling serving the address.
        let router = MultihopTunRouter::default();
        let ip = Ipv4Addr::new(10, 66, 0, 7);
        let (tx_a, mut rx_a) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        router.register(ip, tx_a.clone());
        router.register(ip, tx_b.clone());
        // Duplicate registration of the same channel must not stack.
        router.register(ip, tx_b.clone());
        assert_eq!(router.routes.0.lock().get(&ip).unwrap().senders.len(), 2);

        // 32 flows: each flow's 4 packets stay on one channel, and with
        // FNV over 32 distinct ports both channels get work.
        for port in 0..32u16 {
            for _ in 0..4 {
                router.dispatch(&ipv4_tcp_packet(ip, 40_000 + port));
            }
        }
        let drain = |rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>| {
            let mut by_port: HashMap<u16, usize> = HashMap::new();
            while let Ok(p) = rx.try_recv() {
                let port = u16::from_be_bytes([p[20], p[21]]);
                *by_port.entry(port).or_default() += 1;
            }
            by_port
        };
        let a_ports = drain(&mut rx_a);
        let b_ports = drain(&mut rx_b);
        assert!(
            !a_ports.is_empty() && !b_ports.is_empty(),
            "both channels must carry flows"
        );
        for (port, count) in a_ports.iter().chain(b_ports.iter()) {
            assert_eq!(
                *count, 4,
                "flow {port} split across channels (ordering broken)"
            );
        }
        assert!(
            a_ports.keys().all(|p| !b_ports.contains_key(p)),
            "a flow must be pinned to exactly one channel"
        );

        // Sibling unregister keeps the other channel serving the IP.
        router.unregister_if_owner(ip, &tx_a);
        assert_eq!(router.routes.0.lock().get(&ip).unwrap().senders.len(), 1);
        router.dispatch(&ipv4_tcp_packet(ip, 50_000));
        assert!(
            rx_b.try_recv().is_ok(),
            "survivor must receive after sibling unregister"
        );
        router.unregister_if_owner(ip, &tx_b);
        assert!(
            router.routes.0.lock().get(&ip).is_none(),
            "empty slot must be removed"
        );
    }

    /// Builds a minimal IPv4 TCP packet with explicit src/dst IP and ports,
    /// so uplink and its downlink reply can be constructed as mirror images.
    fn ipv4_tcp_full(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45;
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src_ip.octets());
        p[16..20].copy_from_slice(&dst_ip.octets());
        p[20..22].copy_from_slice(&src_port.to_be_bytes());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p
    }

    #[test]
    fn canonical_flow_key_is_direction_agnostic() {
        let client = Ipv4Addr::new(10, 66, 0, 7);
        let peer = Ipv4Addr::new(93, 184, 216, 34);
        // Uplink (client -> peer) and its downlink reply (peer -> client)
        // are mirror images; they MUST hash to the same flow key.
        let up = ipv4_tcp_full(client, peer, 51000, 443);
        let down = ipv4_tcp_full(peer, client, 443, 51000);
        assert_eq!(
            canonical_flow_key(&up),
            canonical_flow_key(&down),
            "reverse directions of one flow must share a key"
        );
        // A different flow (other client port) must differ.
        let other = ipv4_tcp_full(client, peer, 51001, 443);
        assert_ne!(canonical_flow_key(&up), canonical_flow_key(&other));
        // Non-TCP/UDP yields None (caller falls back to the plain hash).
        let mut icmp = up.clone();
        icmp[9] = 1;
        assert_eq!(canonical_flow_key(&icmp), None);
    }

    // ---- reduced-MTU inner-packet adaptation (2026-07-15 SNCF incident) ----

    /// Minimal IPv4 TCP SYN carrying one MSS option, enough for
    /// `clamp_syn_mss` to locate and rewrite it. Checksums are irrelevant
    /// here: `adapt_inner_for_budget` never reads them, and the incremental
    /// checksum maintenance itself is already vector-tested in
    /// `warrenguard_transport_core`.
    fn syn_packet(mss: u16) -> Vec<u8> {
        let mut p = vec![0u8; 44];
        p[0] = 0x45; // version 4, IHL 20
        p[9] = 6; // proto TCP
        let t = 20;
        p[t + 12] = 6 << 4; // data offset: 24 bytes (20 base + 4-byte MSS option)
        p[t + 13] = 0x02; // SYN
        p[t + 20] = 2; // MSS option kind
        p[t + 21] = 4; // MSS option length
        p[t + 22..t + 24].copy_from_slice(&mss.to_be_bytes());
        p
    }

    #[test]
    fn adapt_inner_for_budget_clamps_a_syn_and_sends_it() {
        let mut pkt = syn_packet(1460);
        assert_eq!(
            adapt_inner_for_budget(&mut pkt, 200),
            None,
            "a clamped SYN is sent, never reflected"
        );
        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert!(
            mss < 1460,
            "MSS option must have been lowered to fit the budget"
        );
    }

    #[test]
    fn adapt_inner_for_budget_leaves_a_fitting_non_syn_packet_untouched() {
        let mut pkt = ipv4_tcp_full(
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(10, 66, 0, 7),
            443,
            51000,
        );
        let original = pkt.clone();
        assert_eq!(adapt_inner_for_budget(&mut pkt, u16::MAX), None);
        assert_eq!(
            pkt, original,
            "a fitting non-SYN packet must stay untouched"
        );
    }

    #[test]
    fn adapt_inner_for_budget_reflects_frag_needed_for_an_oversized_non_syn_packet() {
        let mut pkt = vec![0u8; 1300];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP: irrelevant to the too-large path
        pkt[12..16].copy_from_slice(&[93, 184, 216, 34]);
        let icmp =
            adapt_inner_for_budget(&mut pkt, 1200).expect("oversized packet must be reflected");
        assert_eq!(icmp[0] >> 4, 4);
        assert_eq!(icmp[9], 1, "ICMP");
        assert_eq!(icmp[20], 3, "destination unreachable");
        assert_eq!(icmp[21], 4, "fragmentation needed");
        assert_eq!(
            u16::from_be_bytes([icmp[26], icmp[27]]),
            1200,
            "next-hop MTU echoes the live budget"
        );
    }

    #[test]
    fn adapt_inner_for_budget_returns_none_when_the_packet_already_fits() {
        let mut pkt = vec![0u8; 100];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[93, 184, 216, 34]);
        assert_eq!(adapt_inner_for_budget(&mut pkt, 100), None);
    }

    #[test]
    fn inner_budget_subtracts_the_frame_overhead_from_the_live_datagram_size() {
        assert_eq!(inner_budget(Some(1300), 83), 1217);
    }

    #[test]
    fn inner_budget_saturates_instead_of_underflowing_when_overhead_exceeds_the_datagram() {
        assert_eq!(inner_budget(Some(50), 83), 0);
    }

    #[test]
    fn inner_budget_defaults_to_u16_max_before_the_connection_negotiates_a_size() {
        assert_eq!(inner_budget(None, 83), u16::MAX - 83);
    }

    #[cfg(feature = "pq-hpke")]
    #[test]
    fn pq_inner_budget_sizes_from_the_data_frame_not_the_setup_bound() {
        // A /v2 DATA frame carries an empty pq_ct, so the exit's downlink budget
        // must subtract the small data-frame overhead, not the ~1174-byte setup
        // bound (which held the 1088-byte ML-KEM ciphertext). The setup bound
        // starved a 1452-byte path to a ~240-byte budget, so every real downlink
        // packet was reflected as frag-needed instead of sealed: a silent data
        // black-hole while the tunnel stayed Connected.
        assert_eq!(
            pq_inner_budget(Some(1452)),
            inner_budget(Some(1452), MULTIHOP_FRAME_V2_DATA_MAX_OVERHEAD)
        );
        assert!(
            pq_inner_budget(Some(1452)) > 1000,
            "the /v2 downlink budget must not be starved by the ~1 KB setup bound"
        );
    }

    #[tokio::test]
    async fn downlink_follows_the_uplink_owner_not_the_hash() {
        // The shared-wallet collision fix: two INDEPENDENT sessions of one
        // account share a single sticky IP (two senders under one slot). A
        // flow's downlink must return to the SAME session its uplink used,
        // never to the sibling. To distinguish owner-routing from the old
        // hash-routing, we deliberately make the owner the channel the hash
        // would NOT have picked: success then proves the owner was followed.
        let router = MultihopTunRouter::default();
        let ip = Ipv4Addr::new(10, 66, 0, 7);
        let peer = Ipv4Addr::new(93, 184, 216, 34);
        let (tx_a, mut rx_a) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register(ip, tx_a.clone()); // senders[0]
        router.register(ip, tx_b.clone()); // senders[1]

        let uplink = ipv4_tcp_full(ip, peer, 51000, 443);
        let downlink = ipv4_tcp_full(peer, ip, 443, 51000);
        // The channel a blind 5-tuple hash would have chosen for the reply.
        let hash_idx = (warrenguard_transport_core::flow_hash_5tuple(&downlink).expect("tcp hashes")
            as usize)
            % 2;

        if hash_idx == 0 {
            // Hash would pick A; make B the flow's uplink owner.
            router.note_uplink(&uplink, &tx_b);
            router.dispatch(&downlink);
            assert!(
                rx_b.try_recv().is_ok(),
                "reply must follow owner B, not hash A"
            );
            assert!(
                rx_a.try_recv().is_err(),
                "hash-picked A must NOT receive it"
            );
        } else {
            // Hash would pick B; make A the flow's uplink owner.
            router.note_uplink(&uplink, &tx_a);
            router.dispatch(&downlink);
            assert!(
                rx_a.try_recv().is_ok(),
                "reply must follow owner A, not hash B"
            );
            assert!(
                rx_b.try_recv().is_err(),
                "hash-picked B must NOT receive it"
            );
        }
    }

    #[tokio::test]
    async fn sessions_on_distinct_ips_never_cross_deliver_even_with_identical_ports() {
        // The structural per-session ownership: each live session of one
        // wallet now holds its OWN inner IP, so the downlink route key (the
        // destination address) identifies exactly one session, even in the
        // shape no flow demux can split on a SHARED IP: both sessions using
        // identical inner ports to the same peer (identical 5-tuples
        // collapse in the kernel NAT; ICMP has no ports and fans out
        // round-robin).
        let router = MultihopTunRouter::default();
        let ip_a = Ipv4Addr::new(10, 66, 0, 7);
        let ip_b = Ipv4Addr::new(10, 66, 0, 8);
        let peer = Ipv4Addr::new(1, 1, 1, 1);
        let (tx_a, mut rx_a) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register(ip_a, tx_a.clone());
        router.register(ip_b, tx_b.clone());

        let down_a = ipv4_tcp_full(peer, ip_a, 443, 51000);
        let down_b = ipv4_tcp_full(peer, ip_b, 443, 51000);
        router.dispatch(&down_a);
        router.dispatch(&down_b);
        assert_eq!(
            rx_a.try_recv().expect("session A gets its reply"),
            down_a,
            "session A must receive exactly its own downlink"
        );
        assert_eq!(
            rx_b.try_recv().expect("session B gets its reply"),
            down_b,
            "session B must receive exactly its own downlink"
        );
        assert!(rx_a.try_recv().is_err(), "no cross-delivery to A");
        assert!(rx_b.try_recv().is_err(), "no cross-delivery to B");
    }

    #[tokio::test]
    async fn downlink_falls_back_to_hash_when_owner_departed() {
        // If the flow's learned owner has left (its channel pruned), the
        // downlink must fall back to the hash over the survivors instead of
        // black-holing the flow.
        let router = MultihopTunRouter::default();
        let ip = Ipv4Addr::new(10, 66, 0, 8);
        let peer = Ipv4Addr::new(1, 1, 1, 1);
        let (tx_a, rx_a) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register(ip, tx_a.clone());
        router.register(ip, tx_b.clone());

        let uplink = ipv4_tcp_full(ip, peer, 40000, 443);
        let downlink = ipv4_tcp_full(peer, ip, 443, 40000);
        router.note_uplink(&uplink, &tx_a);
        // A leaves: receiver dropped then channel unregistered.
        drop(rx_a);
        router.unregister_if_owner(ip, &tx_a);

        router.dispatch(&downlink);
        assert!(
            rx_b.try_recv().is_ok(),
            "with the owner gone the flow must fall back to the survivor"
        );
    }

    #[tokio::test]
    async fn stale_predecessor_is_evicted_and_flow_repins_to_live_successor() {
        // The 2026-07-16 incident shape: a fast single-hop -> multihop
        // reconnect keeps the SAME sticky inner IP, so the client's
        // established flow stays owned (first-writer-wins) by the just-closed
        // connection's downlink channel. That predecessor's QUIC leg is dead
        // but its mpsc channel is still OPEN (its TX task drains it into the
        // dying leg), so `try_send` returns Ok and the reply black-holes with
        // no `Closed` to trigger a re-route. The takeover re-check must catch
        // the frozen predecessor and re-pin the flow to the live successor.
        let router = MultihopTunRouter::default();
        let ip = Ipv4Addr::new(10, 66, 0, 166);
        let peer = Ipv4Addr::new(93, 184, 216, 34);
        // Predecessor: channel stays open (rx kept), so dispatch to it is Ok.
        let (tx_pred, mut rx_pred) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_succ, mut rx_succ) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let act_pred = Arc::new(AtomicU64::new(7)); // frozen from here on
        let act_succ = Arc::new(AtomicU64::new(0));

        router.register(ip, tx_pred.clone());
        router.attach_liveness(ip, &tx_pred, act_pred.clone());
        // The client's established flow was learned to the predecessor.
        let uplink = ipv4_tcp_full(ip, peer, 51000, 443);
        let downlink = ipv4_tcp_full(peer, ip, 443, 51000);
        router.note_uplink(&uplink, &tx_pred);

        // Successor takes over the same sticky IP.
        router.register(ip, tx_succ.clone());
        let snapshot = {
            router.attach_liveness(ip, &tx_succ, act_succ.clone());
            router.snapshot_predecessors(ip, &tx_succ)
        };
        assert_eq!(
            snapshot.len(),
            1,
            "the predecessor must be seen as a takeover"
        );

        // Before the re-check: the reply black-holes into the dead-but-open
        // predecessor, exactly as in production.
        router.dispatch(&downlink);
        assert!(
            rx_pred.try_recv().is_ok(),
            "pre-fix: reply goes to the dead predecessor's open channel"
        );
        assert!(
            rx_succ.try_recv().is_err(),
            "pre-fix: the live successor receives nothing"
        );

        // The successor is alive (its RX task advanced its counter); the
        // predecessor stayed silent (frozen). The re-check evicts it.
        act_succ.fetch_add(3, Ordering::Relaxed);
        let evicted = router.evict_stale_predecessors(ip, &snapshot);
        assert_eq!(evicted, 1, "the frozen predecessor must be evicted");

        // Now the re-used flow re-pins to the sole live sender.
        router.dispatch(&downlink);
        assert!(
            rx_succ.try_recv().is_ok(),
            "post-fix: the reply must reach the live successor"
        );
        assert!(
            rx_pred.try_recv().is_err(),
            "post-fix: nothing more may reach the evicted predecessor"
        );
        assert_eq!(
            router.routes.0.lock().get(&ip).unwrap().senders.len(),
            1,
            "the stale predecessor's channel must be gone"
        );
    }

    #[tokio::test]
    async fn live_predecessor_is_never_evicted_on_takeover() {
        // A genuinely live same-pubkey owner (two active devices on one
        // wallet share the sticky IP) must keep its route and its owned flow:
        // its inbound-activity counter advances, so the takeover re-check
        // leaves it untouched (first-writer-wins preserved for a live owner).
        let router = MultihopTunRouter::default();
        let ip = Ipv4Addr::new(10, 66, 0, 200);
        let peer = Ipv4Addr::new(1, 1, 1, 1);
        let (tx_live, mut rx_live) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_new, mut rx_new) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let act_live = Arc::new(AtomicU64::new(100));
        let act_new = Arc::new(AtomicU64::new(0));

        router.register(ip, tx_live.clone());
        router.attach_liveness(ip, &tx_live, act_live.clone());
        let uplink = ipv4_tcp_full(ip, peer, 40000, 443);
        let downlink = ipv4_tcp_full(peer, ip, 443, 40000);
        router.note_uplink(&uplink, &tx_live);

        router.register(ip, tx_new.clone());
        router.attach_liveness(ip, &tx_new, act_new.clone());
        let snapshot = router.snapshot_predecessors(ip, &tx_new);
        assert_eq!(snapshot.len(), 1);

        // The incumbent keeps serving traffic during the window.
        act_live.fetch_add(5, Ordering::Relaxed);
        let evicted = router.evict_stale_predecessors(ip, &snapshot);
        assert_eq!(evicted, 0, "a live owner must never be evicted");
        assert_eq!(
            router.routes.0.lock().get(&ip).unwrap().senders.len(),
            2,
            "both channels must remain registered"
        );

        // Its owned flow still returns to it, not the newcomer.
        router.dispatch(&downlink);
        assert!(rx_live.try_recv().is_ok(), "the live owner keeps its flow");
        assert!(
            rx_new.try_recv().is_err(),
            "the newcomer must not steal the live owner's reply"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn arm_takeover_recheck_evicts_dead_predecessor_after_the_window() {
        // End-to-end of the armed path: `arm_takeover_recheck` attaches the
        // successor's liveness, detects the takeover, and after
        // `TAKEOVER_STALE_RECHECK` evicts the frozen predecessor so its flow
        // re-pins. Time is paused so the 2s window is deterministic.
        let router = Arc::new(MultihopTunRouter::default());
        let ip = Ipv4Addr::new(10, 66, 0, 166);
        let peer = Ipv4Addr::new(93, 184, 216, 34);
        let (tx_pred, mut rx_pred) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_succ, mut rx_succ) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let act_pred = Arc::new(AtomicU64::new(1)); // frozen
        let downlink = ipv4_tcp_full(peer, ip, 443, 51000);
        let uplink = ipv4_tcp_full(ip, peer, 51000, 443);

        router.register(ip, tx_pred.clone());
        router.attach_liveness(ip, &tx_pred, act_pred);
        router.note_uplink(&uplink, &tx_pred);

        // Successor registers, then arms the re-check (its own live counter).
        router.register(ip, tx_succ.clone());
        let succ_activity = Arc::new(AtomicU64::new(9));
        arm_takeover_recheck(
            &Some(router.clone()),
            &Some(tx_succ.clone()),
            Some(ip),
            None,
            &succ_activity,
        );
        // Let the spawned re-check task run up to its sleep so its timer is
        // registered before we advance the (paused) clock.
        tokio::task::yield_now().await;

        // Before the window elapses nothing is evicted: the flow still
        // black-holes into the predecessor.
        router.dispatch(&downlink);
        assert!(
            rx_pred.try_recv().is_ok(),
            "still owned by predecessor pre-window"
        );
        assert!(rx_succ.try_recv().is_err());

        // Advance past the window and let the spawned re-check run. Yield a
        // few times so the current-thread runtime polls the woken task.
        tokio::time::advance(TAKEOVER_STALE_RECHECK + Duration::from_millis(1)).await;
        for _ in 0..16 {
            if router.routes.0.lock().get(&ip).unwrap().senders.len() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(
            router.routes.0.lock().get(&ip).unwrap().senders.len(),
            1,
            "the stale predecessor must have been evicted by the armed re-check"
        );
        router.dispatch(&downlink);
        assert!(
            rx_succ.try_recv().is_ok(),
            "after the window the flow must re-pin to the live successor"
        );
    }

    /// A transient TUN read error must NOT kill the single TUN reader:
    /// it is the downlink of every connected client (2026-06-11 prod
    /// incident: first EINTR-class error under ~800 Mbps load silently
    /// blackholed the whole exit until a service restart).
    #[derive(Clone)]
    struct FlakyTun {
        inner: warrenguard_transport_core::FakeTun,
        errors_left: Arc<std::sync::atomic::AtomicU32>,
    }

    impl warrenguard_transport_core::PacketDevice for FlakyTun {
        async fn recv(&self) -> std::io::Result<Vec<u8>> {
            let left = &self.errors_left;
            if left
                .fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |n| n.checked_sub(1),
                )
                .is_ok()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "transient flaky read",
                ));
            }
            self.inner.recv().await
        }

        async fn send(&self, packet: &[u8]) -> std::io::Result<()> {
            self.inner.send(packet).await
        }

        fn try_recv(&self) -> std::io::Result<Option<Vec<u8>>> {
            self.inner.try_recv()
        }
    }

    #[tokio::test]
    async fn tun_router_pump_survives_transient_read_errors() {
        let router = Arc::new(MultihopTunRouter::default());
        let ip = Ipv4Addr::new(10, 66, 0, 11);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register(ip, tx);

        let tun = FlakyTun {
            inner: warrenguard_transport_core::FakeTun::new(),
            errors_left: Arc::new(std::sync::atomic::AtomicU32::new(3)),
        };
        tun.inner.inject_inbound(ipv4_packet_to(ip));
        let pump = tokio::spawn(pump_multihop_tun_router(tun.clone(), router));

        // The pump must absorb the 3 injected errors (3 x 5 ms pauses)
        // and still deliver the packet that follows them.
        let pkt = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("packet must arrive despite transient TUN errors")
            .expect("channel open");
        assert_eq!(dst_ipv4(&pkt), Some(ip));
        pump.abort();
    }

    #[tokio::test]
    async fn router_bonded_slot_retries_on_closed_sibling() {
        // One of two bonded channels dies (receiver dropped): dispatch
        // must prune it and deliver the packet via the survivor instead
        // of dropping it.
        let router = MultihopTunRouter::default();
        let ip = Ipv4Addr::new(10, 66, 0, 9);
        let (tx_dead, rx_dead) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx_live, mut rx_live) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register(ip, tx_dead);
        router.register(ip, tx_live);
        drop(rx_dead);
        // Send across many flows: whichever hash to the dead channel
        // must be retried onto the survivor.
        for port in 0..8u16 {
            router.dispatch(&ipv4_tcp_packet(ip, 41_000 + port));
        }
        let mut received = 0;
        while rx_live.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, 8, "every packet must reach the survivor");
        assert_eq!(
            router.routes.0.lock().get(&ip).unwrap().senders.len(),
            1,
            "dead channel must be pruned"
        );
    }

    // ---- H2: session-creation (HPKE decap) rate-limit backstop ----

    #[test]
    fn token_bucket_limits_then_refills() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(10.0, 2.0, t0);
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0), "third take with no refill must be denied");
        // After 1s at 10 tokens/s the bucket refills back to its capacity (2).
        let t1 = t0 + Duration::from_secs(1);
        assert!(b.try_take(t1));
        assert!(b.try_take(t1));
        assert!(!b.try_take(t1), "capacity caps the refill");
    }

    // ---- H1: exit allowlist gate ----

    fn allowlist_with(pubkeys: &[[u8; 32]]) -> AllowlistHandle {
        use std::collections::HashSet;
        let (handle, _rx) = AllowlistHandle::new();
        let set: HashSet<WarrenPubkey> = pubkeys
            .iter()
            .map(|b| WarrenPubkey::from_bytes(*b))
            .collect();
        handle.apply_snapshot(warrenguard_server::AllowlistSnapshot::from_legacy_set(
            1,
            set,
            warrenguard_config::unix_now(),
        ));
        handle
    }

    fn ip_request_pop(
        client_pubkey: Option<[u8; 32]>,
        pop_sig: Option<warrenguard_multihop::PopSignature>,
    ) -> WarrenControlMessage {
        WarrenControlMessage::IpRequest {
            wants_daita: false,
            prefer_ipv4: None,
            client_pubkey,
            wants_ipv6: false,
            pop_sig,
        }
    }

    const GATE_EXIT_ID: [u8; 16] = [0xAA; 16];
    const GATE_ENCAP: EncapsulatedKeyBytes = [0x5C; 32];

    #[test]
    fn allowlist_admits_permissive_mode_admits_everyone() {
        // No allowlist (bench / single-tenant) admits any client, even one
        // that asserts no pubkey and carries no PoP.
        let exit_id = ExitId::from_bytes(GATE_EXIT_ID);
        assert!(allowlist_admits(
            None,
            Some(&ip_request_pop(None, None)),
            &exit_id,
            &GATE_ENCAP
        ));
        assert!(allowlist_admits(None, None, &exit_id, &GATE_ENCAP));
    }

    #[test]
    fn allowlist_admits_strict_mode_requires_listed_pubkey_and_valid_pop() {
        // Security gate: strict mode admits ONLY an allowlisted pubkey
        // whose proof of possession verifies over this session's
        // (exit_id, encapsulated_key). Anything weaker reopens the
        // self-asserted-pubkey hole (anyone knowing an allowlisted
        // pubkey would get egress through the relay).
        let exit_id = ExitId::from_bytes(GATE_EXIT_ID);
        let account = SigningKey::from_bytes(&[0x11; 32]);
        let account_pubkey = account.verifying_key().to_bytes();
        let handle = allowlist_with(&[account_pubkey]);
        let valid_pop = warrenguard_multihop::sign_pop(&account, &exit_id, &GATE_ENCAP);

        assert!(
            allowlist_admits(
                Some(&handle),
                Some(&ip_request_pop(Some(account_pubkey), Some(valid_pop))),
                &exit_id,
                &GATE_ENCAP
            ),
            "an allowlisted pubkey with a valid PoP is admitted in strict mode"
        );
        assert!(
            !allowlist_admits(
                Some(&handle),
                Some(&ip_request_pop(Some(account_pubkey), None)),
                &exit_id,
                &GATE_ENCAP
            ),
            "an allowlisted pubkey WITHOUT a PoP is rejected (self-assertion is not authentication)"
        );
        let attacker = SigningKey::from_bytes(&[0x66; 32]);
        let forged_pop = warrenguard_multihop::sign_pop(&attacker, &exit_id, &GATE_ENCAP);
        assert!(
            !allowlist_admits(
                Some(&handle),
                Some(&ip_request_pop(Some(account_pubkey), Some(forged_pop))),
                &exit_id,
                &GATE_ENCAP
            ),
            "a PoP signed by a different key is rejected"
        );
        let other_encap: EncapsulatedKeyBytes = [0x5D; 32];
        assert!(
            !allowlist_admits(
                Some(&handle),
                Some(&ip_request_pop(Some(account_pubkey), Some(valid_pop))),
                &exit_id,
                &other_encap
            ),
            "a PoP replayed under a different session encapsulated_key is rejected"
        );
        let unlisted = SigningKey::from_bytes(&[0x22; 32]);
        let unlisted_pop = warrenguard_multihop::sign_pop(&unlisted, &exit_id, &GATE_ENCAP);
        assert!(
            !allowlist_admits(
                Some(&handle),
                Some(&ip_request_pop(
                    Some(unlisted.verifying_key().to_bytes()),
                    Some(unlisted_pop)
                )),
                &exit_id,
                &GATE_ENCAP
            ),
            "a valid PoP for a pubkey absent from the allowlist is rejected"
        );
        assert!(
            !allowlist_admits(
                Some(&handle),
                Some(&ip_request_pop(None, None)),
                &exit_id,
                &GATE_ENCAP
            ),
            "a client asserting no pubkey is rejected in strict mode"
        );
        assert!(
            !allowlist_admits(Some(&handle), None, &exit_id, &GATE_ENCAP),
            "a client with no control message is rejected in strict mode"
        );
    }

    // ---- Dual-stack negotiation gating ----

    fn v4_alloc() -> Option<Arc<Mutex<IpAllocator>>> {
        Some(Arc::new(Mutex::new(
            IpAllocator::new(Ipv4Addr::new(10, 66, 0, 0), 24, Ipv4Addr::new(10, 66, 0, 1))
                .expect("/24 v4 pool builds"),
        )))
    }

    fn v6_alloc() -> Option<Arc<Mutex<IpAllocatorV6>>> {
        Some(Arc::new(Mutex::new(IpAllocatorV6::new(Ipv6Addr::new(
            0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 0,
        )))))
    }

    #[test]
    fn wants_ipv6_against_v6_capable_exit_grants_a_dual_stack_ip_assign() {
        let spec =
            allocate_on_first_frame(&v4_alloc(), &v6_alloc(), 1, Some([0x11; 32]), true, None)
                .expect("allocation succeeds");
        assert!(
            spec.assigned_v6.is_some(),
            "wants_ipv6 against a v6-capable exit must allocate a v6"
        );
        match spec.into_control_message(None) {
            WarrenControlMessage::IpAssign {
                ipv6,
                gateway_ipv6,
                prefix_len_v6,
                ..
            } => {
                assert!(ipv6.is_some(), "IpAssign must carry the granted v6");
                assert_eq!(
                    gateway_ipv6,
                    Some(Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 1).octets()),
                    "gateway must be fdcc:f:1::1"
                );
                assert_eq!(prefix_len_v6, 64);
            }
            other => panic!("expected IpAssign, got {other:?}"),
        }
    }

    #[test]
    fn wants_ipv6_against_a_v4_only_exit_echoes_ipv6_none_not_silent() {
        // The capability echo: the client asked for v6 but the exit has no
        // v6 allocator -> the reply's `ipv6` is `None` (which the client
        // surfaces), the conn stays v4-only, and that is leak-safe.
        let no_v6: Option<Arc<Mutex<IpAllocatorV6>>> = None;
        let spec = allocate_on_first_frame(&v4_alloc(), &no_v6, 1, Some([0x11; 32]), true, None)
            .expect("v4 still allocates");
        assert!(spec.assigned_v6.is_none(), "no v6 allocator -> no v6");
        match spec.into_control_message(None) {
            WarrenControlMessage::IpAssign { ipv6, .. } => {
                assert!(
                    ipv6.is_none(),
                    "an unservable v6 request must echo ipv6: None"
                );
            }
            other => panic!("expected IpAssign, got {other:?}"),
        }
    }

    #[test]
    fn no_wants_ipv6_never_triggers_a_v6_allocation() {
        // A v4-only request must NOT get a v6 even on a v6-capable exit: no
        // silent upgrade.
        let spec =
            allocate_on_first_frame(&v4_alloc(), &v6_alloc(), 1, Some([0x11; 32]), false, None)
                .expect("v4 allocates");
        assert!(
            spec.assigned_v6.is_none(),
            "a request with wants_ipv6=false must never allocate a v6"
        );
        match spec.into_control_message(None) {
            WarrenControlMessage::IpAssign { ipv6, .. } => assert!(ipv6.is_none()),
            other => panic!("expected IpAssign, got {other:?}"),
        }
    }

    // ---- Session-placement hints (two-live-sessions collision) ----

    #[test]
    fn fresh_hint_places_concurrent_same_key_sessions_on_distinct_ips_v4_and_v6() {
        // Two INDEPENDENT sessions of one wallet: the second declares
        // itself session-fresh (prefer_ipv4 = 0.0.0.0) and must get its own
        // v4 AND v6, so the downlink route keys never span two sessions.
        let v4 = v4_alloc();
        let v6 = v6_alloc();
        let s1 =
            allocate_on_first_frame(&v4, &v6, 1, Some([0x11; 32]), true, None).expect("session 1");
        let s2 = allocate_on_first_frame(&v4, &v6, 2, Some([0x11; 32]), true, Some([0, 0, 0, 0]))
            .expect("session 2");
        assert_ne!(s2.assigned, s1.assigned, "v4 must be session-fresh");
        assert!(s1.assigned_v6.is_some() && s2.assigned_v6.is_some());
        assert_ne!(s2.assigned_v6, s1.assigned_v6, "v6 must be session-fresh");
    }

    #[test]
    fn join_hint_lands_on_the_named_sessions_ip_v4_and_v6() {
        // A bonded secondary names its session's v4; the v6 must follow the
        // JOINED session's interface ID (sibling projection), not the
        // wallet's sticky binding, which points at session 1.
        let v4 = v4_alloc();
        let v6 = v6_alloc();
        let s1 =
            allocate_on_first_frame(&v4, &v6, 1, Some([0x11; 32]), true, None).expect("session 1");
        let s2 = allocate_on_first_frame(&v4, &v6, 2, Some([0x11; 32]), true, Some([0, 0, 0, 0]))
            .expect("session 2");
        let joined = allocate_on_first_frame(
            &v4,
            &v6,
            3,
            Some([0x11; 32]),
            true,
            Some(s2.assigned.octets()),
        )
        .expect("session 2 secondary");
        assert_eq!(joined.assigned, s2.assigned);
        assert_eq!(
            joined.assigned_v6, s2.assigned_v6,
            "the v6 must follow the joined session, not the sticky binding"
        );
        assert_ne!(joined.assigned_v6, s1.assigned_v6);
    }

    /// Builds a minimal IPv6 packet (40-byte header) with the given dst.
    fn ipv6_packet_to(dst: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60; // version 6
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn dst_ipv6_parses_v6_and_rejects_non_v6() {
        let addr = Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 7);
        assert_eq!(dst_ipv6(&ipv6_packet_to(addr)), Some(addr));
        assert_eq!(
            dst_ipv6(&[0x45u8; 40]),
            None,
            "IPv4 must not parse as v6 even at 40 bytes"
        );
        assert_eq!(dst_ipv6(&[0x60u8; 20]), None, "too short must be None");
    }

    #[tokio::test]
    async fn router_dispatches_v6_and_v4_to_their_own_owners() {
        // Dual-stack regression: a v4 and a v6 route coexist; each family
        // dispatches only to its owner, and a v6 packet must never land in
        // a v4 channel (or vice-versa).
        let router = MultihopTunRouter::default();
        let ip4 = Ipv4Addr::new(10, 66, 0, 2);
        let ip6 = Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 2);
        let (tx4, mut rx4) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let (tx6, mut rx6) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register(ip4, tx4);
        router.register_v6(ip6, tx6);

        router.dispatch(&ipv4_packet_to(ip4));
        router.dispatch(&ipv6_packet_to(ip6));
        router.dispatch(&ipv6_packet_to(Ipv6Addr::new(
            0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 99,
        ))); // no route

        assert_eq!(dst_ipv4(&rx4.try_recv().unwrap()), Some(ip4));
        assert!(rx4.try_recv().is_err(), "v4 owner gets exactly its packet");
        assert_eq!(dst_ipv6(&rx6.try_recv().unwrap()), Some(ip6));
        assert!(rx6.try_recv().is_err(), "v6 owner gets exactly its packet");
    }

    #[tokio::test]
    async fn router_prunes_v6_route_when_receiver_dropped() {
        let router = MultihopTunRouter::default();
        let ip = Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 5);
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        router.register_v6(ip, tx);
        drop(rx);
        router.dispatch(&ipv6_packet_to(ip));
        assert!(
            router.routes_v6.0.lock().get(&ip).is_none(),
            "a closed-receiver v6 route must be pruned on dispatch"
        );
    }

    // ---- Anti-oracle close + sealed rejection detail ----

    use warrenguard_multihop::{ClientSession, try_decode_control};

    const ANTI_ORACLE_EXIT_IKM: [u8; 32] = [0x77; 32];
    const ANTI_ORACLE_EXIT_ID: [u8; 16] = [0xAB; 16];

    struct TerminatingExit {
        addr: std::net::SocketAddr,
        sni: String,
        exit_pub: WarrenKemPublicKey,
        _endpoint: Endpoint,
        accept_task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TerminatingExit {
        fn drop(&mut self) {
            self.accept_task.abort();
        }
    }

    /// Spawn a real exit-side termination loop (the production
    /// `terminate_connection` path) with the given allowlist/allocator.
    fn spawn_terminating_exit(
        allowlist: Option<AllowlistHandle>,
        ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
    ) -> TerminatingExit {
        let exit_key = SigningKey::from_bytes(&[0x42; 32]);
        let provider = warrenguard_tls::default_crypto_provider();
        let server_cfg = warrenguard_tls::make_server_config(
            &exit_key,
            provider,
            &[warrenguard_config::ALPN_H3],
        )
        .expect("server config builds");
        let endpoint = Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into())
            .expect("server endpoint binds");
        let addr = endpoint.local_addr().expect("local addr");
        let (privkey, exit_pub) =
            derive_x25519_keypair(&ANTI_ORACLE_EXIT_IKM).expect("x25519 keypair derives");
        let exit_id = ExitId::from_bytes(ANTI_ORACLE_EXIT_ID);
        let ctx = ExitTerminateCtx::new(
            privkey,
            exit_id,
            warrenguard_transport_core::FakeTun::new(),
            None,
            None,
            ip_allocator,
            None,
            allowlist,
        );
        let listen = endpoint.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = listen.accept().await {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        terminate_connection(conn, SetupSource::AcceptFromConn, ctx).await;
                    }
                });
            }
        });
        let sni = warrenguard_tls::name::encode(WarrenPubkey::from_bytes(
            *exit_key.verifying_key().as_bytes(),
        ));
        TerminatingExit {
            addr,
            sni,
            exit_pub,
            _endpoint: endpoint,
            accept_task,
        }
    }

    /// Dial the exit, run the setup-stream round-trip with `request`, and
    /// return the sealed control reply (if any arrived) plus the
    /// connection's close error as observed by the peer (`None` when the
    /// exit kept the connection open, i.e. the client was admitted).
    /// Fake v7 admitter: admits (or denies) any presented token, returning a
    /// serial derived from the token bytes. No network; exercises the
    /// exit-side v7 admission branch in `process_setup_frame`.
    struct FakeMhAdmitter {
        deny: bool,
    }

    impl SessionTokenAdmitter for FakeMhAdmitter {
        fn admit<'a>(
            &'a self,
            tokens: &'a [warrenguard_wire::SessionToken],
        ) -> warrenguard_server::BoxFuture<'a, warrenguard_server::TokenAdmission> {
            Box::pin(async move {
                if self.deny {
                    return warrenguard_server::TokenAdmission::Denied;
                }
                match tokens.first() {
                    Some(t) => {
                        let mut serial = [0u8; 32];
                        serial.copy_from_slice(&t.0[..32]);
                        warrenguard_server::TokenAdmission::Admit { serial }
                    }
                    None => warrenguard_server::TokenAdmission::Reject,
                }
            })
        }

        fn renew_live<'a>(
            &'a self,
            _live: &'a [[u8; 32]],
        ) -> warrenguard_server::BoxFuture<'a, ()> {
            Box::pin(async {})
        }
    }

    fn spawn_terminating_exit_v7(
        ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
        admitter: Arc<dyn SessionTokenAdmitter>,
    ) -> TerminatingExit {
        let exit_key = SigningKey::from_bytes(&[0x42; 32]);
        let provider = warrenguard_tls::default_crypto_provider();
        let server_cfg = warrenguard_tls::make_server_config(
            &exit_key,
            provider,
            &[warrenguard_config::ALPN_H3],
        )
        .expect("server config builds");
        let endpoint = Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into())
            .expect("server endpoint binds");
        let addr = endpoint.local_addr().expect("local addr");
        let (privkey, exit_pub) =
            derive_x25519_keypair(&ANTI_ORACLE_EXIT_IKM).expect("x25519 keypair derives");
        let exit_id = ExitId::from_bytes(ANTI_ORACLE_EXIT_ID);
        // Strict allowlist mode (Some) would reject v6, but v7 admission is
        // gated by the token, not the allowlist: pass an allowlist to prove
        // the v7 path bypasses it.
        let ctx = ExitTerminateCtx::new(
            privkey,
            exit_id,
            warrenguard_transport_core::FakeTun::new(),
            None,
            None,
            ip_allocator,
            None,
            Some(allowlist_with(&[[0x99; 32]])),
        )
        .with_token_admitter(Some(admitter));
        let listen = endpoint.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = listen.accept().await {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        terminate_connection(conn, SetupSource::AcceptFromConn, ctx).await;
                    }
                });
            }
        });
        let sni = warrenguard_tls::name::encode(WarrenPubkey::from_bytes(
            *exit_key.verifying_key().as_bytes(),
        ));
        TerminatingExit {
            addr,
            sni,
            exit_pub,
            _endpoint: endpoint,
            accept_task,
        }
    }

    fn a_session_token(fill: u8) -> warrenguard_wire::SessionToken {
        warrenguard_wire::SessionToken([fill; warrenguard_wire::SESSION_TOKEN_LEN])
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn v7_ip_request_with_a_valid_token_is_admitted_bypassing_the_allowlist() {
        let admitter = Arc::new(FakeMhAdmitter { deny: false }) as Arc<dyn SessionTokenAdmitter>;
        let exit = spawn_terminating_exit_v7(v4_alloc(), admitter);
        let (detail, _close) = client_setup_roundtrip(&exit, |s| {
            s.build_ip_request_v7(vec![a_session_token(0xAB)], None, false, false)
        })
        .await;
        match detail {
            Some(WarrenControlMessage::IpAssign { ipv4, .. }) => {
                assert_eq!(
                    ipv4[0], 10,
                    "a v7-admitted client must get a 10.66 tunnel IP"
                );
                assert_eq!(ipv4[1], 66);
            }
            other => panic!("expected an IpAssign for a valid v7 token, got {other:?}"),
        }
    }

    /// A v7 admitter that performs the REAL offline blind-RSA verification
    /// (RFC 9578) against a fixed test issuer, exactly as a production exit's
    /// admitter does before spending the serial. Proves the exit admits a
    /// genuinely-valid Privacy Pass token, not just a fake stub.
    struct RealVerifyAdmitter {
        issuer: warrenguard_token::IssuerPublicKey,
    }
    impl SessionTokenAdmitter for RealVerifyAdmitter {
        fn admit<'a>(
            &'a self,
            tokens: &'a [warrenguard_wire::SessionToken],
        ) -> warrenguard_server::BoxFuture<'a, warrenguard_server::TokenAdmission> {
            Box::pin(async move {
                for t in tokens {
                    if let Ok(token) = warrenguard_token::Token::parse(&t.0)
                        && self.issuer.verify_token(&token).is_ok()
                    {
                        return warrenguard_server::TokenAdmission::Admit {
                            serial: *token.serial().as_bytes(),
                        };
                    }
                }
                warrenguard_server::TokenAdmission::Reject
            })
        }
        fn renew_live<'a>(
            &'a self,
            _live: &'a [[u8; 32]],
        ) -> warrenguard_server::BoxFuture<'a, ()> {
            Box::pin(async {})
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn v7_ip_request_with_a_real_blind_rsa_token_is_admitted() {
        use rand_v10::SeedableRng;
        // Fixed test issuer (no live API / wallet): mint a real token the SAME
        // way the TS EdgeConnect client does (blind -> sign -> finalize), then
        // prove the REAL exit termination admits it and assigns a tunnel IP.
        let mut rng = rand_v10::rngs::StdRng::seed_from_u64(0xED9E_5EED);
        let sk = warrenguard_token::IssuerSecretKey::generate(&mut rng).expect("issuer key");
        let pk = sk.public_key();
        let challenge = warrenguard_token::TokenChallenge::for_epoch(
            "issuer.warren.test",
            "warren/token/epoch",
            7,
        )
        .expect("challenge");
        let (req, state) = pk.blind_token(&mut rng, &challenge).expect("blind");
        let blind_sig = sk.blind_sign(&req).expect("blind sign");
        let token = pk.finalize_token(state, &blind_sig).expect("finalize");
        let session_token = warrenguard_wire::SessionToken(token.serialize());

        let admitter = Arc::new(RealVerifyAdmitter { issuer: pk }) as Arc<dyn SessionTokenAdmitter>;
        let exit = spawn_terminating_exit_v7(v4_alloc(), admitter);
        let (detail, _close) = client_setup_roundtrip(&exit, |s| {
            s.build_ip_request_v7(vec![session_token], None, false, false)
        })
        .await;
        match detail {
            Some(WarrenControlMessage::IpAssign { ipv4, .. }) => {
                assert_eq!(
                    ipv4[0], 10,
                    "a real-token v7 client must get a 10.66 tunnel IP"
                );
                assert_eq!(ipv4[1], 66);
            }
            other => panic!("expected an IpAssign for a real blind-RSA token, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn v7_ip_request_with_a_denied_token_is_rejected() {
        let admitter = Arc::new(FakeMhAdmitter { deny: true }) as Arc<dyn SessionTokenAdmitter>;
        let exit = spawn_terminating_exit_v7(v4_alloc(), admitter);
        let (detail, _close) = client_setup_roundtrip(&exit, |s| {
            s.build_ip_request_v7(vec![a_session_token(0x11)], None, false, false)
        })
        .await;
        assert!(
            matches!(detail, Some(WarrenControlMessage::Rejected)),
            "a denied v7 token must yield a sealed Rejected, got {detail:?}"
        );
    }

    async fn client_setup_roundtrip(
        exit: &TerminatingExit,
        build_request: impl FnOnce(&ClientSession) -> WarrenControlMessage,
    ) -> (Option<WarrenControlMessage>, Option<quinn::ConnectionError>) {
        let provider = warrenguard_tls::default_crypto_provider();
        let cfg = warrenguard_tls::make_client_config(provider, &[warrenguard_config::ALPN_H3])
            .expect("client config builds");
        let mut endpoint =
            Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
        endpoint.set_default_client_config(cfg);
        let conn = endpoint
            .connect(exit.addr, &exit.sni)
            .expect("connect")
            .await
            .expect("handshake");
        let exit_id = ExitId::from_bytes(ANTI_ORACLE_EXIT_ID);
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let session = ClientSession::new(&exit.exit_pub, exit_id, &mut rng).expect("HPKE setup");
        let request = build_request(&session);
        let plaintext = encode_control(&request).expect("encode request");
        let frame = session.seal(&plaintext, 0, 0).expect("seal setup frame");
        let bytes = encode_frame(&frame).expect("encode setup frame");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(&bytes).await.expect("write setup");
        let _ = send.finish();
        let detail = match tokio::time::timeout(
            Duration::from_secs(5),
            recv.read_to_end(MAX_MULTIHOP_SETUP_FRAME_BYTES),
        )
        .await
        {
            Ok(Ok(reply)) if !reply.is_empty() => decode_frame(&reply)
                .ok()
                .and_then(|f| session.open_response(&f).ok())
                .and_then(|p| try_decode_control(&p).ok().flatten()),
            _ => None,
        };
        let close = tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .ok();
        (detail, close)
    }

    /// An admitted client whose QUIC connection is deliberately kept
    /// alive, so several concurrent sessions can coexist on one exit.
    struct LiveClient {
        _endpoint: Endpoint,
        _conn: quinn::Connection,
    }

    /// Like [`client_setup_roundtrip`] but expects admission and keeps the
    /// connection (and its allocation) alive for the caller.
    async fn client_setup_admitted(
        exit: &TerminatingExit,
        request: WarrenControlMessage,
    ) -> (LiveClient, [u8; 4]) {
        let provider = warrenguard_tls::default_crypto_provider();
        let cfg = warrenguard_tls::make_client_config(provider, &[warrenguard_config::ALPN_H3])
            .expect("client config builds");
        let mut endpoint =
            Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
        endpoint.set_default_client_config(cfg);
        let conn = endpoint
            .connect(exit.addr, &exit.sni)
            .expect("connect")
            .await
            .expect("handshake");
        let exit_id = ExitId::from_bytes(ANTI_ORACLE_EXIT_ID);
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let session = ClientSession::new(&exit.exit_pub, exit_id, &mut rng).expect("HPKE setup");
        let plaintext = encode_control(&request).expect("encode request");
        let frame = session.seal(&plaintext, 0, 0).expect("seal setup frame");
        let bytes = encode_frame(&frame).expect("encode setup frame");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(&bytes).await.expect("write setup");
        let _ = send.finish();
        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            recv.read_to_end(MAX_MULTIHOP_SETUP_FRAME_BYTES),
        )
        .await
        .expect("setup reply within deadline")
        .expect("setup reply readable");
        let detail = decode_frame(&reply)
            .ok()
            .and_then(|f| session.open_response(&f).ok())
            .and_then(|p| try_decode_control(&p).ok().flatten());
        match detail {
            Some(WarrenControlMessage::IpAssign { ipv4, .. }) => (
                LiveClient {
                    _endpoint: endpoint,
                    _conn: conn,
                },
                ipv4,
            ),
            other => panic!("expected an IpAssign, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_session_fresh_hint_isolates_concurrent_same_wallet_sessions() {
        // End-to-end through the real termination loop: one wallet, several
        // LIVE connections. A hint-capable second session gets its own
        // inner IP, its joining secondary lands on it, and a hint-less
        // (deployed) client still shares the incumbent's sticky IP.
        let exit = spawn_terminating_exit(None, v4_alloc());
        let wallet = [0x5A; 32];
        let ip_request = |prefer_ipv4| WarrenControlMessage::IpRequest {
            prefer_ipv4,
            client_pubkey: Some(wallet),
            wants_ipv6: false,
            pop_sig: None,
            wants_daita: false,
        };
        let (_c1, ip1) = client_setup_admitted(&exit, ip_request(None)).await;
        let (_c2, ip2) = client_setup_admitted(&exit, ip_request(Some([0, 0, 0, 0]))).await;
        assert_ne!(
            ip2, ip1,
            "a session-fresh second session must not share the incumbent's live IP"
        );
        let (_c3, ip3) = client_setup_admitted(&exit, ip_request(Some(ip2))).await;
        assert_eq!(
            ip3, ip2,
            "a joining connection lands on the session it names"
        );
        let (_c4, ip4) = client_setup_admitted(&exit, ip_request(None)).await;
        assert_eq!(
            ip4, ip1,
            "a hint-less (deployed) client keeps the historical sharing with the sticky incumbent"
        );
    }

    #[cfg(feature = "pq-hpke")]
    struct TerminatingExitPq {
        addr: std::net::SocketAddr,
        sni: String,
        exit_x25519_pub: [u8; 32],
        mlkem_ek: Vec<u8>,
        _endpoint: Endpoint,
        accept_task: tokio::task::JoinHandle<()>,
    }

    #[cfg(feature = "pq-hpke")]
    impl Drop for TerminatingExitPq {
        fn drop(&mut self) {
            self.accept_task.abort();
        }
    }

    /// Spawn a real PQ-capable exit termination loop (identity-bound X-Wing
    /// recipient attached), returning the descriptor material a client needs to
    /// seal a `/v2` setup frame to it.
    #[cfg(feature = "pq-hpke")]
    fn spawn_terminating_exit_pq(
        allowlist: Option<AllowlistHandle>,
        ip_allocator: Option<Arc<Mutex<IpAllocator>>>,
    ) -> TerminatingExitPq {
        let exit_key = SigningKey::from_bytes(&[0x42; 32]);
        let provider = warrenguard_tls::default_crypto_provider();
        let server_cfg = warrenguard_tls::make_server_config(
            &exit_key,
            provider,
            &[warrenguard_config::ALPN_H3],
        )
        .expect("server config builds");
        let endpoint = Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into())
            .expect("server endpoint binds");
        let addr = endpoint.local_addr().expect("local addr");
        // Identity-bound: the published x25519 pubkey and the X-Wing secret's
        // x25519 half derive from the SAME identity, so the client sealing to the
        // descriptor and the exit decapsulating agree on the hybrid secret.
        let x25519_ikm = derive_x25519_ikm_from_ed25519(&exit_key);
        let (privkey, exit_pub) = derive_x25519_keypair(&x25519_ikm).expect("x25519 keypair");
        let (xwing_secret, mlkem_ek) =
            derive_exit_xwing_from_identity(&exit_key).expect("xwing derive");
        let exit_id = ExitId::from_bytes(ANTI_ORACLE_EXIT_ID);
        let ctx = ExitTerminateCtx::new(
            privkey,
            exit_id,
            warrenguard_transport_core::FakeTun::new(),
            None,
            None,
            ip_allocator,
            None,
            allowlist,
        )
        .with_xwing_secret(Arc::new(xwing_secret));
        let listen = endpoint.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = listen.accept().await {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        terminate_connection(conn, SetupSource::AcceptFromConn, ctx).await;
                    }
                });
            }
        });
        let sni = warrenguard_tls::name::encode(WarrenPubkey::from_bytes(
            *exit_key.verifying_key().as_bytes(),
        ));
        TerminatingExitPq {
            addr,
            sni,
            exit_x25519_pub: pubkey_to_bytes(&exit_pub),
            mlkem_ek,
            _endpoint: endpoint,
            accept_task,
        }
    }

    /// Drive a real [`warrenguard_multihop::PqClientSession`] through the exit's
    /// setup-stream round-trip with `request`, returning the sealed control reply
    /// the client opens (the full `/v2` handshake through the production exit
    /// termination loop: decapsulate, admit, allocate, seal reply).
    #[cfg(feature = "pq-hpke")]
    async fn client_setup_roundtrip_pq(
        exit: &TerminatingExitPq,
        request: WarrenControlMessage,
    ) -> Option<WarrenControlMessage> {
        let provider = warrenguard_tls::default_crypto_provider();
        let cfg = warrenguard_tls::make_client_config(provider, &[warrenguard_config::ALPN_H3])
            .expect("client config builds");
        let mut endpoint =
            Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint binds");
        endpoint.set_default_client_config(cfg);
        let conn = endpoint
            .connect(exit.addr, &exit.sni)
            .expect("connect")
            .await
            .expect("handshake");
        let exit_id = ExitId::from_bytes(ANTI_ORACLE_EXIT_ID);
        let recipient = warrenguard_multihop::XWingRecipientPublicKey::from_descriptor_bytes(
            &exit.mlkem_ek,
            &exit.exit_x25519_pub,
        )
        .expect("recipient builds");
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let session = warrenguard_multihop::PqClientSession::new(&recipient, exit_id, &mut rng)
            .expect("PQ client session");
        let plaintext = encode_control(&request).expect("encode request");
        let frame = session.seal_setup(&plaintext, 0, 0).expect("seal v2 setup");
        let bytes = warrenguard_multihop::encode_frame_v2(&frame).expect("encode v2 setup");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(&bytes).await.expect("write setup");
        let _ = send.finish();
        match tokio::time::timeout(
            Duration::from_secs(5),
            recv.read_to_end(MAX_MULTIHOP_SETUP_FRAME_BYTES),
        )
        .await
        {
            Ok(Ok(reply)) if !reply.is_empty() => warrenguard_multihop::decode_frame_v2(&reply)
                .ok()
                .and_then(|f| session.open_response(&f).ok())
                .and_then(|p| try_decode_control(&p).ok().flatten()),
            _ => None,
        }
    }

    /// Full `/v2` X-Wing handshake through the real exit termination loop: a
    /// permissive exit with an allocator must decapsulate the client's PQ setup
    /// frame, admit it, and seal an `IpAssign` the client opens.
    #[cfg(feature = "pq-hpke")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pq_setup_roundtrip_admits_and_seals_the_ip_assign_reply() {
        let exit = spawn_terminating_exit_pq(None, v4_alloc());
        let request = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
            wants_daita: false,
        };
        let detail = client_setup_roundtrip_pq(&exit, request).await;
        match detail {
            Some(WarrenControlMessage::IpAssign { ipv4, .. }) => {
                assert_eq!(ipv4[0], 10, "assigned an exit-pool 10.x address");
            }
            other => panic!("expected a sealed IpAssign reply, got {other:?}"),
        }
    }

    fn expect_app_close(err: &quinn::ConnectionError) -> (u64, Vec<u8>) {
        match err {
            quinn::ConnectionError::ApplicationClosed(ac) => {
                (u64::from(ac.error_code), ac.reason.to_vec())
            }
            other => panic!("expected an application close, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn policy_rejections_share_one_opaque_close_and_seal_the_detail() {
        // Path A: strict allowlist, the client asserts an unlisted pubkey.
        let exit_a = spawn_terminating_exit(Some(allowlist_with(&[[0x11; 32]])), v4_alloc());
        let req_a = WarrenControlMessage::IpRequest {
            wants_daita: false,
            prefer_ipv4: None,
            client_pubkey: Some([0x22; 32]),
            wants_ipv6: false,
            pop_sig: None,
        };
        let (detail_a, close_a) = client_setup_roundtrip(&exit_a, |_| req_a.clone()).await;

        // Path B: permissive allowlist, but the IP pool is exhausted
        // (a /30 has exactly one host slot, consumed up-front).
        let alloc = Arc::new(Mutex::new(
            IpAllocator::new(Ipv4Addr::new(10, 66, 0, 0), 30, Ipv4Addr::new(10, 66, 0, 1))
                .expect("/30 pool builds"),
        ));
        assert!(
            alloc.lock().allocate(424_242).is_some(),
            "the single /30 host slot must be consumable up-front"
        );
        let exit_b = spawn_terminating_exit(None, Some(alloc));
        let req_b = WarrenControlMessage::IpRequest {
            wants_daita: false,
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
        };
        let (detail_b, close_b) = client_setup_roundtrip(&exit_b, |_| req_b.clone()).await;

        // The CLIENT learns the cause through the HPKE-sealed reply.
        assert_eq!(
            detail_a,
            Some(WarrenControlMessage::Rejected),
            "not-allowlisted: the sealed Rejected detail must reach the client before the close"
        );
        assert_eq!(
            detail_b,
            Some(WarrenControlMessage::IpExhausted),
            "pool-exhausted: the sealed IpExhausted detail must reach the client before the close"
        );

        // The RELAY (the exit's TLS peer) must observe one identical,
        // opaque close for every policy rejection: same code, empty
        // reason bytes. Distinct codes or ASCII reasons would leak the
        // client's subscription status to a hostile relay.
        let close_a = close_a.expect("the exit must close the not-allowlisted connection promptly");
        let close_b = close_b.expect("the exit must close the pool-exhausted connection promptly");
        let (code_a, reason_a) = expect_app_close(&close_a);
        let (code_b, reason_b) = expect_app_close(&close_b);
        assert_eq!(
            code_a, code_b,
            "ANTI-ORACLE: rejection causes must share one opaque close code"
        );
        assert_eq!(
            code_a,
            u64::from(WARREN_MH_REJECTED),
            "the shared close code must be the frozen WARREN_MH_REJECTED value"
        );
        assert!(
            reason_a.is_empty() && reason_b.is_empty(),
            "ANTI-ORACLE: close reason bytes must be empty on the relay-facing branch"
        );
    }

    // ---- Proof of possession (strict allowlist mode) ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn strict_mode_requires_a_valid_pop_and_an_allowlisted_pubkey() {
        let account = SigningKey::from_bytes(&[0x11; 32]);
        let account_pubkey = account.verifying_key().to_bytes();
        let exit_id = ExitId::from_bytes(ANTI_ORACLE_EXIT_ID);

        let ip_request = |client_pubkey, pop_sig| WarrenControlMessage::IpRequest {
            wants_daita: false,
            prefer_ipv4: None,
            client_pubkey,
            wants_ipv6: false,
            pop_sig,
        };

        // 1) Allowlisted pubkey WITHOUT a PoP: rejected. Account pubkeys
        //    are not secret (allowlist snapshots, API headers); admitting
        //    a bare assertion hands egress to anyone who knows one.
        let exit = spawn_terminating_exit(Some(allowlist_with(&[account_pubkey])), v4_alloc());
        let (detail, _) =
            client_setup_roundtrip(&exit, |_| ip_request(Some(account_pubkey), None)).await;
        assert_eq!(
            detail,
            Some(WarrenControlMessage::Rejected),
            "SECURITY: an allowlisted pubkey without a proof of possession must be rejected"
        );

        // 2) Allowlisted pubkey with a PoP signed by the WRONG key:
        //    rejected (the literal impersonation attack).
        let attacker = SigningKey::from_bytes(&[0x66; 32]);
        let exit = spawn_terminating_exit(Some(allowlist_with(&[account_pubkey])), v4_alloc());
        let (detail, _) = client_setup_roundtrip(&exit, |session| {
            let sig =
                warrenguard_multihop::sign_pop(&attacker, &exit_id, &session.encapsulated_key());
            ip_request(Some(account_pubkey), Some(sig))
        })
        .await;
        assert_eq!(
            detail,
            Some(WarrenControlMessage::Rejected),
            "SECURITY: a PoP signed by a key other than the asserted pubkey must be rejected"
        );

        // 3) Valid PoP but the pubkey is NOT allowlisted: still rejected
        //    (possession does not replace the subscription gate).
        let exit = spawn_terminating_exit(Some(allowlist_with(&[[0x99; 32]])), v4_alloc());
        let (detail, _) = client_setup_roundtrip(&exit, |session| {
            let sig =
                warrenguard_multihop::sign_pop(&account, &exit_id, &session.encapsulated_key());
            ip_request(Some(account_pubkey), Some(sig))
        })
        .await;
        assert_eq!(
            detail,
            Some(WarrenControlMessage::Rejected),
            "a valid PoP for a non-allowlisted pubkey must still be rejected"
        );

        // 4) Valid PoP + allowlisted pubkey: admitted (IpAssign).
        let exit = spawn_terminating_exit(Some(allowlist_with(&[account_pubkey])), v4_alloc());
        let (detail, _) = client_setup_roundtrip(&exit, |session| {
            let sig =
                warrenguard_multihop::sign_pop(&account, &exit_id, &session.encapsulated_key());
            ip_request(Some(account_pubkey), Some(sig))
        })
        .await;
        assert!(
            matches!(detail, Some(WarrenControlMessage::IpAssign { .. })),
            "a valid PoP for an allowlisted pubkey must be admitted, got {detail:?}"
        );
    }
}
