//! Async HTTP/3 WebTransport edge server on the warren-quinn transport.
//!
//! This is the datapath half of workstream D: it takes the pure classifier in
//! [`warrenguard_edge`] and drives a real browser WebTransport-over-HTTP/3
//! handshake on a dedicated quinn endpoint, so a zero-install browser can open
//! a Warren multi-hop entry.
//!
//! # Why a dedicated endpoint (not the production `:443` dispatcher)
//!
//! The production exit endpoint runs the no-pad multi-hop transport profile,
//! which sets `max_concurrent_uni_streams = 0`: it refuses peer-initiated
//! unidirectional streams. A conformant HTTP/3 browser MUST open uni streams
//! (its control stream and the two QPACK streams), so it cannot handshake
//! against that endpoint at all. The edge therefore binds its own endpoint with
//! a browser-compatible transport config ([`edge_transport_config`]): uni + bidi
//! streams allowed and QUIC datagrams enabled (WebTransport rides on them). The
//! endpoint still serves the same X.509 cover certificate on ALPN `h3`, so it is
//! wire-indistinguishable from an ordinary HTTP/3 server.
//!
//! # Handshake performed by [`serve_edge_session`]
//!
//! 1. open the server control uni-stream and write our SETTINGS (WebTransport
//!    capable, `QPACK_MAX_TABLE_CAPACITY = 0`) via
//!    [`warrenguard_edge::control_stream_prelude`];
//! 2. read the client's control-stream SETTINGS and confirm it advertises
//!    WebTransport;
//! 3. accept the client's bidi CONNECT stream, read its HEADERS frame, and
//!    classify it with [`warrenguard_edge::classify_request_stream`];
//! 4. on a WebTransport extended-CONNECT, gate on the Privacy Pass token and, if
//!    admitted, write the `:status 200` accept
//!    ([`warrenguard_edge::webtransport_accept_response`]).
//!
//! After step 4 the WebTransport session is established. Pumping that session as
//! a multi-hop entry (reading the Warren frames the browser tunnels inside it
//! and forwarding to the exit) is the next datapath increment and is not done
//! here; this layer is validated end-to-end over real QUIC by the crate's
//! integration test.

mod pump;

pub use pump::{PumpError, PumpSummary, pump_multihop_entry};

use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint, Incoming, RecvStream, VarInt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use warrenguard_edge::{
    EdgeRequest, classify_request_stream, control_stream_prelude, encode_varint, parse_settings,
    read_frame, read_uni_stream_type, webtransport_accept_response,
};
use warrenguard_token::{IssuerPublicKey, Token};

/// QPACK encoder stream type (RFC 9204 section 4.2).
const QPACK_STREAM_ENCODER: u64 = 0x02;
/// QPACK decoder stream type (RFC 9204 section 4.2).
const QPACK_STREAM_DECODER: u64 = 0x03;

/// Upper bound on the bytes read while looking for a single complete HTTP/3
/// frame on a stream (the control-stream SETTINGS and the request HEADERS are
/// both small). Bounds the memory a hostile peer can force us to buffer before
/// the frame is either complete or rejected.
const MAX_FRAME_SCAN_BYTES: usize = 16 * 1024;

// Edge ingress rate-limit budgets, sized to absorb a legitimate reconnect
// burst (a mobile handover, a page reload storm) while bounding the
// worst-case pre-auth accept cost a hostile ingress could force: the QUIC
// handshake is paid before any application-level admission runs, so these
// three layers (per-IP rate, per-IP concurrency, global in-flight) are the
// only thing standing between an accepted `Incoming` and unbounded resource
// use. Shared by every accept loop in this crate via [`EdgeAdmissionControl`].
const MAX_INFLIGHT_SESSIONS: usize = 1024;
const PER_IP_SESSION_BURST: u32 = 32;
const PER_IP_SESSION_REFILL: Duration = Duration::from_millis(100);
const PER_IP_MAX_CONCURRENT: u32 = 64;
const IP_LIMITER_GC_INTERVAL: Duration = Duration::from_secs(60);
const IP_LIMITER_IDLE_EVICT: Duration = Duration::from_secs(300);

/// IPv6 collapses to its /64 so an attacker cannot evade the bucket by rotating
/// through the 2^64 addresses of one delegation.
fn rate_limit_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(v4) => std::net::IpAddr::V4(v4),
        std::net::IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

/// Caps the number of CONCURRENT admitted edge sessions per rate-limit key.
///
/// The per-IP token bucket bounds how FAST an IP opens sessions; the global
/// semaphore bounds the TOTAL. Neither stops one IP from slowly accumulating
/// long-lived sessions until it alone approaches the global cap. This closes that
/// gap: a guard is held for each session's lifetime and released on drop, so the
/// count reflects live sessions, not a rate. The map evicts a key when its count
/// reaches zero, so it self-bounds without a GC task.
#[derive(Clone)]
struct PerIpConcurrency {
    map: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>>,
    max: u32,
}

/// Decrements the per-IP live-session count for its key when dropped (RAII), so a
/// session that ends for ANY reason (clean close, error, panic) frees its slot.
struct PerIpGuard {
    map: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>>,
    key: std::net::IpAddr,
}

impl PerIpConcurrency {
    fn new(max: u32) -> Self {
        Self {
            map: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max,
        }
    }

    /// Reserves a live-session slot for `key`, or `None` if it is already at
    /// `max`. The returned guard frees the slot on drop. Reads before inserting so
    /// a refused key never leaves a zero-count entry behind.
    fn try_acquire(&self, key: std::net::IpAddr) -> Option<PerIpGuard> {
        let mut map = self.map.lock().ok()?;
        let count = map.get(&key).copied().unwrap_or(0);
        if count >= self.max {
            return None;
        }
        map.insert(key, count + 1);
        Some(PerIpGuard {
            map: self.map.clone(),
            key,
        })
    }
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let Ok(mut map) = self.map.lock() else {
            return;
        };
        let Some(count) = map.get_mut(&self.key) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(&self.key);
        }
    }
}

/// The pre-auth admission-control layers shared by every accept loop in this
/// crate: QUIC address validation, a per-IP new-session token bucket, a
/// per-IP live-concurrency cap, and a global in-flight semaphore. Terminating
/// a QUIC handshake costs CPU before any application-level check (the token
/// gate, the exit dial) can run, so a `pub` accept loop that skips this is a
/// pre-auth DoS surface regardless of what it does afterward. Constructing
/// one and spawning its GC task once per listener, then routing every
/// accepted connection through [`EdgeAdmissionControl::admit`], is the only
/// sanctioned way for an accept loop in this crate to accept a connection.
#[derive(Clone)]
struct EdgeAdmissionControl {
    conn_limit: Arc<tokio::sync::Semaphore>,
    ip_limiter: Arc<warrenguard_ratelimit::ConnectionRateLimiter<std::net::IpAddr>>,
    per_ip_conc: PerIpConcurrency,
}

/// Held for the lifetime of one admitted session; releases the global permit
/// and the per-IP concurrency slot on drop, from any exit path (clean close,
/// error, panic).
struct EdgeSessionGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _ip_conc: PerIpGuard,
}

/// The outcome of [`EdgeAdmissionControl::admit`] for one accepted `Incoming`.
enum EdgeAdmission {
    /// The source address was not yet QUIC-validated; a Retry was already
    /// sent, and the caller must `continue` its accept loop without spawning
    /// anything.
    Retry,
    /// Admission was refused (per-IP rate, per-IP concurrency, or the global
    /// cap); `incoming.refuse()` was already called.
    Refused,
    /// Admitted: the caller may proceed with `(*incoming).await`, holding the
    /// guard for the session's lifetime. Boxed: `Incoming` is far larger than
    /// the other two variants and clippy flags the size gap otherwise.
    Admitted(Box<Incoming>, EdgeSessionGuard),
}

impl EdgeAdmissionControl {
    /// Builds the shared admission state and spawns its periodic GC task
    /// (idle per-IP bucket eviction), cancelled by `shutdown`.
    fn new(shutdown: &CancellationToken) -> Self {
        let this = Self {
            conn_limit: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_SESSIONS)),
            ip_limiter: Arc::new(warrenguard_ratelimit::ConnectionRateLimiter::new(
                PER_IP_SESSION_BURST,
                PER_IP_SESSION_REFILL,
            )),
            per_ip_conc: PerIpConcurrency::new(PER_IP_MAX_CONCURRENT),
        };
        let ip_limiter = this.ip_limiter.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(IP_LIMITER_GC_INTERVAL);
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = tick.tick() => {
                        ip_limiter.retain_active(IP_LIMITER_IDLE_EVICT, std::time::Instant::now());
                    }
                }
            }
        });
        this
    }

    /// Applies QUIC address validation, then the three admission layers, to
    /// one accepted `Incoming`. See [`EdgeAdmission`] for the caller
    /// contract: on `Retry` or `Refused` the caller must `continue` its
    /// accept loop without touching `incoming` further (this method already
    /// consumed it via `retry()`/`refuse()`).
    fn admit(&self, incoming: Incoming) -> EdgeAdmission {
        // Force QUIC address validation BEFORE any per-IP or global admission
        // state is touched: an unvalidated source has not proved it can
        // receive traffic at its claimed address, so a spoofed-source flood
        // could otherwise consume the per-IP token bucket, the per-IP
        // concurrency map, and the global semaphore for addresses that never
        // round-trip. `retry()` only fails if `incoming` already carries a
        // token from a prior retry, which cannot happen here since
        // `remote_address_validated()` is false; a fallible result is handled
        // defensively by dropping the attempt (its `Drop` impl refuses it).
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            return EdgeAdmission::Retry;
        }
        let ip_key = rate_limit_key(incoming.remote_address().ip());
        // Refuse fast (the client fails over) rather than drop, in this
        // order: new-session RATE (token bucket), then per-IP CONCURRENT live
        // sessions, then the global in-flight cap.
        if !self.ip_limiter.try_acquire(&ip_key) {
            incoming.refuse();
            return EdgeAdmission::Refused;
        }
        let Some(ip_conc) = self.per_ip_conc.try_acquire(ip_key) else {
            incoming.refuse();
            return EdgeAdmission::Refused;
        };
        let Ok(permit) = self.conn_limit.clone().try_acquire_owned() else {
            incoming.refuse();
            return EdgeAdmission::Refused;
        };
        EdgeAdmission::Admitted(
            Box::new(incoming),
            EdgeSessionGuard {
                _permit: permit,
                _ip_conc: ip_conc,
            },
        )
    }
}

/// Errors from running the edge handshake. Coarse and value-free (no peer bytes,
/// no token material) so they are safe to log.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EdgeServerError {
    /// A QUIC stream operation failed (peer reset, connection lost).
    #[error("QUIC stream error")]
    Stream,
    /// The peer's HTTP/3 bytes were malformed or a frame never completed within
    /// the scan bound.
    #[error("malformed HTTP/3 from peer")]
    MalformedHttp3,
    /// The client did not open a control stream advertising WebTransport.
    #[error("peer is not a WebTransport client")]
    NotWebTransport,
    /// The pre-pump handshake (from the QUIC accept through the CONNECT
    /// stream being classified) did not complete within the setup deadline.
    /// The connection is closed before this is returned, so any per-IP or
    /// global admission slot the caller holds for the session is freed.
    #[error("edge handshake did not complete within the setup deadline")]
    HandshakeTimeout,
}

/// The result of a completed edge handshake attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeOutcome {
    /// A WebTransport session was accepted (the `:status 200` was written). The
    /// session is now ready to carry the tunnelled Warren circuit.
    Admitted {
        /// The `:authority` the browser dialed.
        authority: String,
        /// The `:path` the browser requested.
        path: String,
    },
    /// The peer spoke HTTP/3 but not a WebTransport CONNECT, or presented no
    /// admissible token: no session was opened.
    Rejected,
}

/// The token-admission seam is the exit's canonical [`SessionTokenAdmitter`]
/// (protocol v7), reused verbatim so a browser edge session is admitted
/// through the exact same verify-offline-then-spend-the-serial path as a native
/// v7 client: the deployer plugs in its own `SessionTokenAdmitter` implementation
/// (typically an issuer directory plus a per-serial lease backed by its own API)
/// with zero divergence. The edge serializes the Privacy Pass token the browser
/// presented into a [`SessionToken`] and hands it to [`SessionTokenAdmitter::admit`].
pub use warrenguard_server::{SessionTokenAdmitter, TokenAdmission};
use warrenguard_wire::SessionToken;

/// A [`SessionTokenAdmitter`] that admits a session iff the browser presented a
/// token whose authenticator verifies against `issuer` (RFC 9578 blind-RSA). It
/// performs the OFFLINE cryptographic check ONLY, with no per-serial lease, so
/// it does NOT prevent double-spend: it is for local/dev validation and tests,
/// never a production exit. Production uses the API-backed admitter.
pub struct OfflineTokenGate {
    /// The issuer public key the token must verify against.
    pub issuer: IssuerPublicKey,
}

impl SessionTokenAdmitter for OfflineTokenGate {
    fn admit<'a>(
        &'a self,
        tokens: &'a [SessionToken],
    ) -> warrenguard_server::BoxFuture<'a, TokenAdmission> {
        Box::pin(async move {
            for st in tokens {
                let Ok(token) = Token::parse(&st.0) else {
                    continue;
                };
                if self.issuer.verify_token(&token).is_ok() {
                    return TokenAdmission::Admit {
                        serial: *token.serial().as_bytes(),
                    };
                }
            }
            TokenAdmission::Reject
        })
    }

    fn renew_live<'a>(
        &'a self,
        _live: &'a [[u8; warrenguard_server::TOKEN_SERIAL_LEN]],
    ) -> warrenguard_server::BoxFuture<'a, ()> {
        // Offline-only gate: no lease is held, so there is nothing to renew.
        Box::pin(async {})
    }
}

/// A browser-compatible QUIC transport config for the edge endpoint: peer uni
/// and bidi streams allowed (an HTTP/3 client needs them) and QUIC datagrams
/// enabled (WebTransport data rides on them). Deliberately NOT the Warren
/// multi-hop profile, which forbids peer uni streams.
#[must_use]
pub fn edge_transport_config() -> Arc<quinn::TransportConfig> {
    let mut cfg = quinn::TransportConfig::default();
    cfg.max_concurrent_uni_streams(VarInt::from_u32(16))
        .max_concurrent_bidi_streams(VarInt::from_u32(16))
        .datagram_receive_buffer_size(Some(64 * 1024))
        .datagram_send_buffer_size(64 * 1024)
        .max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("30s is a valid idle timeout"),
        ))
        .keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(cfg)
}

/// Runs the edge accept loop until `shutdown` is cancelled or the endpoint
/// closes. Each accepted connection is handled by [`serve_edge_session`] on its
/// own task; a session error is logged (value-free) and dropped, never
/// propagated, so one bad peer cannot stop the listener.
///
/// This composition gates admission at the edge itself (the token check runs
/// in [`serve_edge_session`], no exit dial), a distinct deployment shape from
/// [`run_edge_entry_listener`]'s blind bridge. Every accepted connection still
/// runs through the same pre-auth [`EdgeAdmissionControl`] as that loop (QUIC
/// address validation, per-IP rate, per-IP concurrency, global in-flight cap):
/// a `pub` accept loop with no admission control is a pre-auth DoS surface
/// regardless of what it does with an accepted connection afterward.
pub async fn run_edge_listener<A: SessionTokenAdmitter + ?Sized + 'static>(
    endpoint: Endpoint,
    gate: Arc<A>,
    shutdown: CancellationToken,
) {
    let admission = EdgeAdmissionControl::new(&shutdown);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            maybe_incoming = endpoint.accept() => {
                let Some(incoming) = maybe_incoming else { break; };
                let (incoming, guard) = match admission.admit(incoming) {
                    EdgeAdmission::Retry | EdgeAdmission::Refused => continue,
                    EdgeAdmission::Admitted(incoming, guard) => (incoming, guard),
                };
                let gate = gate.clone();
                tokio::spawn(async move {
                    // Held for the session's lifetime; freed on drop (any exit
                    // path: clean close, error, panic).
                    let _guard = guard;
                    match (*incoming).await {
                        Ok(conn) => match serve_edge_session(&conn, gate).await {
                            Ok(EdgeOutcome::Admitted { .. }) => {
                                // Hold the connection open: the WebTransport
                                // session lives on it. (The multi-hop entry pump
                                // that consumes it is the next increment.) Drop
                                // it only when the peer leaves, so the accept
                                // 200 and any session bytes flush.
                                conn.closed().await;
                            }
                            Ok(EdgeOutcome::Rejected) => {}
                            Err(e) => {
                                tracing::debug!(error = %e, "edge: session ended with error");
                            }
                        },
                        Err(_) => {
                            tracing::debug!("edge: handshake failed");
                        }
                    }
                });
            }
        }
    }
    endpoint.wait_idle().await;
}

/// Runs the edge accept loop as a FUNCTIONAL multi-hop entry: each admitted
/// browser WebTransport session is pumped to the exit `dial_exit` resolves (see
/// [`serve_edge_entry`] / [`pump_multihop_entry`]), rather than merely held open
/// like [`run_edge_listener`]. `dial_exit` is cloned per connection, so it must
/// be cheap to clone (capture `Arc`s, not owned state).
///
/// This is what a production exit mounts on its dedicated edge port: the same
/// X.509 cover endpoint, a BLIND bridge ([`serve_edge_entry`]) whose sessions
/// are admitted end-to-end at the exit via the tunnelled v7 tokens. See
/// [`EdgeAdmissionControl`] for the pre-auth admission layers this loop shares
/// with [`run_edge_listener`].
pub async fn run_edge_entry_listener<D, Fut>(
    endpoint: Endpoint,
    dial_exit: D,
    shutdown: CancellationToken,
) where
    D: Fn(warrenguard_multihop::ExitId) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Connection, PumpError>> + Send,
{
    let admission = EdgeAdmissionControl::new(&shutdown);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            maybe_incoming = endpoint.accept() => {
                let Some(incoming) = maybe_incoming else { break; };
                let (incoming, guard) = match admission.admit(incoming) {
                    EdgeAdmission::Retry | EdgeAdmission::Refused => continue,
                    EdgeAdmission::Admitted(incoming, guard) => (incoming, guard),
                };
                let dial_exit = dial_exit.clone();
                tokio::spawn(async move {
                    // Held for the session's lifetime; freed on drop when the
                    // session ends for any reason (close, error, panic).
                    let _guard = guard;
                    match (*incoming).await {
                        Ok(conn) => {
                            if let Err(e) = serve_edge_entry(&conn, dial_exit).await {
                                tracing::debug!(error = %e, "edge: entry session ended with error");
                            }
                        }
                        Err(_) => tracing::debug!("edge: handshake failed"),
                    }
                });
            }
        }
    }
    endpoint.wait_idle().await;
}

/// Drives one browser WebTransport handshake to completion. See the module docs
/// for the four steps. On success writes the `:status 200` accept and returns
/// [`EdgeOutcome::Admitted`]; a non-WebTransport or token-rejected peer gets
/// [`EdgeOutcome::Rejected`] and the connection is left to close.
///
/// # Errors
/// [`EdgeServerError`] on a QUIC stream failure, malformed HTTP/3, or a peer
/// that never opened a WebTransport-advertising control stream.
pub async fn serve_edge_session<A: SessionTokenAdmitter + ?Sized>(
    conn: &Connection,
    gate: Arc<A>,
) -> Result<EdgeOutcome, EdgeServerError> {
    serve_edge_session_inner(conn, gate, pump::SETUP_DEADLINE).await
}

/// Test-only entry point for [`serve_edge_session`] with an injectable
/// handshake deadline, so a slowloris regression test can observe the
/// deadline firing without waiting out the real [`pump::SETUP_DEADLINE`].
/// Not part of the crate's production surface; production code must call
/// [`serve_edge_session`].
#[doc(hidden)]
pub async fn serve_edge_session_with_deadline<A: SessionTokenAdmitter + ?Sized>(
    conn: &Connection,
    gate: Arc<A>,
    handshake_deadline: Duration,
) -> Result<EdgeOutcome, EdgeServerError> {
    serve_edge_session_inner(conn, gate, handshake_deadline).await
}

async fn serve_edge_session_inner<A: SessionTokenAdmitter + ?Sized>(
    conn: &Connection,
    gate: Arc<A>,
    handshake_deadline: Duration,
) -> Result<EdgeOutcome, EdgeServerError> {
    match run_handshake_bounded(conn, handshake_deadline).await? {
        Handshake::WebTransport {
            authority,
            path,
            token,
            mut send,
            recv,
        } => {
            // Gate on the browser's Privacy Pass token via the canonical
            // verify-offline-then-spend path. No token -> empty slice -> reject.
            let tokens: Vec<SessionToken> = token
                .as_ref()
                .map(|t| SessionToken(t.serialize()))
                .into_iter()
                .collect();
            if !matches!(gate.admit(&tokens).await, TokenAdmission::Admit { .. }) {
                conn.close(VarInt::from_u32(0), b"");
                return Ok(EdgeOutcome::Rejected);
            }
            send.write_all(&webtransport_accept_response())
                .await
                .map_err(|_| EdgeServerError::Stream)?;
            // The CONNECT bidi stream IS the WebTransport session: it must stay
            // open for the session's lifetime. Dropping (and thus resetting) it
            // here would tear the session down the instant it is accepted, which
            // a browser reports as ERR_QUIC_PROTOCOL_ERROR. Hold both halves on a
            // task until the connection closes. Use [`serve_edge_entry`] instead
            // to pump the accepted session as a multi-hop entry.
            let hold_conn = conn.clone();
            tokio::spawn(async move {
                let _hold_session_stream = (send, recv);
                hold_conn.closed().await;
            });
            Ok(EdgeOutcome::Admitted { authority, path })
        }
        Handshake::Rejected => Ok(EdgeOutcome::Rejected),
    }
}

/// Drives the browser handshake and pumps the accepted WebTransport session as a
/// Warren multi-hop entry: the browser tunnels a `WarrenMultihopFrame` setup and
/// DATA datagrams inside the session, forwarded to the exit `dial_exit` resolves
/// (see [`pump_multihop_entry`]).
///
/// This is a BLIND BRIDGE: it admits any valid WebTransport extended-CONNECT
/// without an ingress token check, exactly as the native Warren relay is blind.
/// A browser cannot set the CONNECT `Authorization` header, so admission is
/// necessarily end-to-end at the exit, which verifies-and-spends the v7 session
/// tokens the browser tunnels inside the `SetupV7` (the exit's
/// `SessionTokenAdmitter`, wired on `ExitTerminateCtx`). Ingress DoS protection
/// is a separate rate-limiting concern, not a token gate here.
///
/// Returns [`EdgeOutcome::Admitted`] once the pump ends (the session closed);
/// [`EdgeOutcome::Rejected`] if the peer was not a WebTransport CONNECT. A pump
/// error is logged value-free and folded into the admitted outcome.
///
/// # Errors
/// [`EdgeServerError`] on a handshake stream failure, malformed HTTP/3, or a
/// peer that never advertised WebTransport.
pub async fn serve_edge_entry<F, Fut>(
    conn: &Connection,
    dial_exit: F,
) -> Result<EdgeOutcome, EdgeServerError>
where
    F: FnOnce(warrenguard_multihop::ExitId) -> Fut,
    Fut: std::future::Future<Output = Result<Connection, PumpError>>,
{
    match run_handshake_bounded(conn, pump::SETUP_DEADLINE).await? {
        Handshake::WebTransport {
            authority,
            path,
            token: _,
            mut send,
            recv,
        } => {
            // Blind bridge: accept the WebTransport session unconditionally; the
            // exit admits the tunnelled v7 tokens end-to-end.
            send.write_all(&webtransport_accept_response())
                .await
                .map_err(|_| EdgeServerError::Stream)?;
            // The pump has its own internal SETUP_DEADLINE for ITS setup-stream
            // + exit-dial + shuttle phase, then runs the long-lived DATA pump
            // unbounded: no further bound is applied here.
            if let Err(e) = pump_multihop_entry(conn, send, recv, dial_exit).await {
                tracing::debug!(error = %e, "edge: multi-hop entry pump ended with error");
            }
            Ok(EdgeOutcome::Admitted { authority, path })
        }
        Handshake::Rejected => Ok(EdgeOutcome::Rejected),
    }
}

/// The classification of a browser WebTransport handshake performed by
/// [`run_handshake`]: it hands back the still-open CONNECT stream halves and the
/// presented Privacy Pass token (if any) so the caller decides admission and
/// whether to write the `:status 200`, hold the session, or pump it as a
/// multi-hop entry. `run_handshake` deliberately does NOT gate or write the 200.
enum Handshake {
    WebTransport {
        authority: String,
        path: String,
        // Boxed: a `Token` is far larger than the `Rejected` variant, and
        // clippy flags the size gap otherwise.
        token: Option<Box<Token>>,
        send: quinn::SendStream,
        recv: RecvStream,
    },
    Rejected,
}

/// Runs [`run_handshake`] under `deadline`: bounds the WHOLE pre-pump phase,
/// from right after the QUIC accept through the WebTransport CONNECT stream
/// being classified.
///
/// Without this bound, a client that completes the QUIC/TLS handshake and the
/// control-stream SETTINGS but never opens its CONNECT stream (or stalls
/// reading it) hangs forever at `conn.accept_bi()` / the HEADERS read inside
/// `run_handshake`: only the control-stream SETTINGS wait had its own short
/// bound, nothing bounded the CONNECT stream itself. Worse,
/// [`edge_transport_config`]'s `keep_alive_interval(10s)` keeps such a
/// connection alive indefinitely from the server's own side, so a slowloris
/// client can pin the caller's per-IP concurrency guard and global semaphore
/// permit ([`run_edge_entry_listener`]) forever. On timeout the connection is
/// explicitly closed so those RAII guards release.
async fn run_handshake_bounded(
    conn: &Connection,
    deadline: Duration,
) -> Result<Handshake, EdgeServerError> {
    match tokio::time::timeout(deadline, run_handshake(conn)).await {
        Ok(result) => result,
        Err(_) => {
            conn.close(VarInt::from_u32(0), b"");
            Err(EdgeServerError::HandshakeTimeout)
        }
    }
}

/// Runs steps 1-3 of the browser WebTransport-over-HTTP/3 handshake (see the
/// module docs) and classifies the request stream. On a WebTransport
/// extended-CONNECT it returns the CONNECT stream halves + the presented token
/// WITHOUT writing the `:status 200` and WITHOUT gating: the caller
/// ([`serve_edge_session`] gates on the token; [`serve_edge_entry`] is a blind
/// bridge that admits end-to-end at the exit) decides. Callers must go through
/// [`run_handshake_bounded`], never call this directly, so the pre-pump phase
/// is always bounded (fix for the slowloris gap: an unbounded `run_handshake`
/// combined with the edge endpoint's long keep-alive lets a stalling client
/// pin a session slot forever).
async fn run_handshake(conn: &Connection) -> Result<Handshake, EdgeServerError> {
    // Step 1: speak first, exactly as a real HTTP/3 server does. Our SETTINGS
    // advertise WebTransport and pin QPACK_MAX_TABLE_CAPACITY = 0. The control
    // stream stays open for the connection lifetime (never finished).
    let mut server_control = conn.open_uni().await.map_err(|_| EdgeServerError::Stream)?;
    server_control
        .write_all(&control_stream_prelude())
        .await
        .map_err(|_| EdgeServerError::Stream)?;
    // A conformant HTTP/3 client (a browser) expects the server to open its
    // QPACK encoder (type 0x02) and decoder (type 0x03) unidirectional streams
    // too (RFC 9204 section 4.2); some clients will not proceed to the request
    // until they exist. We use only the static table, so they carry just the
    // stream-type byte and stay open (empty) for the connection.
    let mut qpack_encoder = conn.open_uni().await.map_err(|_| EdgeServerError::Stream)?;
    qpack_encoder
        .write_all(&encode_varint(QPACK_STREAM_ENCODER))
        .await
        .map_err(|_| EdgeServerError::Stream)?;
    let mut qpack_decoder = conn.open_uni().await.map_err(|_| EdgeServerError::Stream)?;
    qpack_decoder
        .write_all(&encode_varint(QPACK_STREAM_DECODER))
        .await
        .map_err(|_| EdgeServerError::Stream)?;
    tracing::debug!("edge: server control + QPACK streams sent, awaiting client control stream");

    // Step 2: accept and DRAIN the client's unidirectional streams for the
    // connection lifetime, and read the control stream's SETTINGS. The control
    // and QPACK encoder/decoder streams are "critical" (RFC 9114 section 6.2):
    // resetting or closing one is an H3_CLOSED_CRITICAL_STREAM connection error,
    // which a browser reacts to by aborting the whole connection. So these
    // streams must be kept open and drained, never dropped mid-stream. The
    // acceptor runs on its own task (owning a connection handle and the server
    // control stream) so the streams stay alive after this function returns.
    let (settings_tx, mut settings_rx) = mpsc::channel::<bool>(1);
    {
        let uni_conn = conn.clone();
        tokio::spawn(async move {
            // Keep the server's control + QPACK streams open for the connection.
            let _hold = (server_control, qpack_encoder, qpack_decoder);
            while let Ok(recv) = uni_conn.accept_uni().await {
                tokio::spawn(drain_client_uni(recv, settings_tx.clone()));
            }
        });
    }

    // Confirm the client advertises WebTransport on its control stream.
    let supports = tokio::time::timeout(Duration::from_secs(5), settings_rx.recv())
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
    if !supports {
        conn.close(VarInt::from_u32(0), b"");
        return Err(EdgeServerError::NotWebTransport);
    }
    tracing::debug!("edge: client advertises WebTransport, awaiting CONNECT stream");

    // Step 3: the request arrives on a client-initiated bidi stream (the CONNECT
    // stream), which the browser keeps OPEN for the session, so we read just its
    // leading HEADERS frame rather than to the stream's finish.
    let (send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|_| EdgeServerError::Stream)?;
    tracing::debug!("edge: CONNECT bidi stream accepted, reading HEADERS frame");
    let request_bytes = read_one_frame(&mut recv).await?;
    tracing::debug!(bytes = request_bytes.len(), "edge: HEADERS frame read");

    match classify_request_stream(&request_bytes).map_err(|_| EdgeServerError::MalformedHttp3)? {
        EdgeRequest::WebTransport(wt) => Ok(Handshake::WebTransport {
            authority: wt.authority,
            path: wt.path,
            token: wt.token.map(Box::new),
            send,
            recv,
        }),
        EdgeRequest::OtherHttp3 => {
            conn.close(VarInt::from_u32(0), b"");
            Ok(Handshake::Rejected)
        }
    }
}

/// Drains one client-initiated unidirectional stream to end of stream, never
/// resetting it (a reset of a critical HTTP/3 stream aborts the connection). If
/// it is the HTTP/3 control stream, its SETTINGS frame is parsed and whether the
/// client advertises WebTransport is sent once on `settings_tx`. Bytes are
/// otherwise discarded; the read loop only exists to keep the stream open for
/// the connection's lifetime.
async fn drain_client_uni(mut recv: RecvStream, settings_tx: mpsc::Sender<bool>) {
    let mut header = Vec::new();
    let mut settled = false; // true once the type (and SETTINGS, if control) is resolved
    let mut scratch = [0u8; 4096];
    // Read until end of stream (or reset). We never reset from our side: a reset
    // of a critical stream would abort the whole HTTP/3 connection.
    while let Ok(Some(n)) = recv.read(&mut scratch).await {
        if settled {
            continue; // discard; we only keep reading to hold the stream open
        }
        // Accumulate only until the type (+ SETTINGS for control) is known,
        // bounded so a hostile peer cannot grow this buffer.
        if header.len() < MAX_FRAME_SCAN_BYTES {
            header.extend_from_slice(&scratch[..n]);
        }
        settled = try_resolve_control_settings(&header, &settings_tx);
    }
}

/// Inspects the accumulated leading bytes of a uni stream. Returns `true` once
/// the stream is resolved: either it is not the control stream (nothing to do)
/// or it is and its SETTINGS have been parsed and reported on `settings_tx`.
/// Returns `false` while still waiting for more bytes to complete the type or
/// the SETTINGS frame.
fn try_resolve_control_settings(header: &[u8], settings_tx: &mpsc::Sender<bool>) -> bool {
    let Some((ty, after_ty)) = read_uni_stream_type(header) else {
        return false; // type varint not complete yet
    };
    if ty != warrenguard_edge::STREAM_CONTROL {
        return true; // QPACK or other stream: resolved, keep draining
    }
    match read_frame(after_ty) {
        Some((frame, _)) => {
            let advertises = parse_settings(frame.payload).client_advertises_webtransport();
            let _ = settings_tx.try_send(advertises);
            true
        }
        None => false, // control stream, SETTINGS frame not complete yet
    }
}

/// Reads one complete HTTP/3 frame from `recv`, blocking (bounded) until the
/// frame is whole. Extra bytes past the first frame stay unread in the stream.
async fn read_one_frame(recv: &mut RecvStream) -> Result<Vec<u8>, EdgeServerError> {
    let mut buf = Vec::new();
    loop {
        if read_frame(&buf).is_some() {
            return Ok(buf);
        }
        if !read_more(recv, &mut buf).await? {
            return Err(EdgeServerError::MalformedHttp3); // stream ended mid-frame
        }
    }
}

/// Appends the next chunk from `recv` to `buf`. Returns `false` at end of
/// stream. Errors if the peer resets or the scan bound is exceeded.
async fn read_more(recv: &mut RecvStream, buf: &mut Vec<u8>) -> Result<bool, EdgeServerError> {
    if buf.len() >= MAX_FRAME_SCAN_BYTES {
        return Err(EdgeServerError::MalformedHttp3);
    }
    let mut chunk = [0u8; 2048];
    match recv.read(&mut chunk).await {
        Ok(Some(n)) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(_) => Err(EdgeServerError::Stream),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_key_collapses_ipv6_within_a_64_but_keeps_ipv4_identity() {
        // Two addresses that only differ in their interface identifier (the
        // low 64 bits) share one /64 delegation and must collapse to the same
        // key, otherwise an attacker rotating through the 2^64 addresses of
        // one delegation evades the per-IP budget entirely.
        let a: std::net::IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:1234:5678:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(
            rate_limit_key(a),
            rate_limit_key(b),
            "addresses within the same /64 must collapse to the same key"
        );

        // A different /64 (network bits differ) must NOT collapse to the
        // same key: that would let one delegation exhaust another's budget.
        let c: std::net::IpAddr = "2001:db8:1234:5679::1".parse().unwrap();
        assert_ne!(
            rate_limit_key(a),
            rate_limit_key(c),
            "a different /64 must produce a different key"
        );

        // IPv4 has no /64 collapsing: the key is the address itself.
        let v4: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(
            rate_limit_key(v4),
            v4,
            "IPv4 must stay identity (no octet collapsing)"
        );
    }

    #[test]
    fn per_ip_guard_releases_exactly_this_attempts_slot_when_the_global_cap_then_refuses() {
        // Mirrors the accept loop's acquisition order in
        // `run_edge_entry_listener`: the per-IP CONCURRENT slot is taken
        // first, then the global in-flight cap is checked; a refusal at the
        // global step must release only the slot THIS attempt just took,
        // restoring the count to what it was before the attempt (not to
        // zero), so other live sessions for the same IP are undisturbed.
        let per_ip_conc = PerIpConcurrency::new(4);
        let ip: std::net::IpAddr = "203.0.113.50".parse().unwrap();

        // One already-live session for this IP, unrelated to the attempt
        // under test.
        let _existing = per_ip_conc
            .try_acquire(ip)
            .expect("existing session admitted");
        let prior_count = per_ip_conc.map.lock().unwrap().get(&ip).copied().unwrap();
        assert_eq!(prior_count, 1);

        let attempt_guard = per_ip_conc
            .try_acquire(ip)
            .expect("this attempt is admitted per-IP");
        assert_eq!(per_ip_conc.map.lock().unwrap().get(&ip).copied(), Some(2));

        // An exhausted global semaphore, exactly like `MAX_INFLIGHT_SESSIONS`
        // being full: `try_acquire` refuses without blocking.
        let global = tokio::sync::Semaphore::new(0);
        let refused = global.try_acquire().is_err();
        assert!(refused, "the global semaphore must be exhausted here");
        if refused {
            drop(attempt_guard);
        }

        assert_eq!(
            per_ip_conc.map.lock().unwrap().get(&ip).copied(),
            Some(prior_count),
            "a refusal at the global step must release exactly this attempt's per-IP slot"
        );
    }

    #[test]
    fn per_ip_concurrency_caps_live_sessions_and_frees_on_drop() {
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let c = PerIpConcurrency::new(2);
        let g1 = c.try_acquire(ip).expect("1st admitted");
        let _g2 = c.try_acquire(ip).expect("2nd admitted");
        assert!(c.try_acquire(ip).is_none(), "3rd over the cap is refused");
        drop(g1);
        let _g3 = c.try_acquire(ip).expect("a freed slot admits again");

        // A distinct rate-limit key has its own independent budget.
        let other: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        let _o1 = c.try_acquire(other).expect("distinct key admitted");
        let _o2 = c.try_acquire(other).expect("distinct key admitted");
        assert!(
            c.try_acquire(other).is_none(),
            "distinct key has its own cap"
        );
    }

    #[test]
    fn per_ip_concurrency_evicts_a_key_when_its_last_session_ends() {
        let ip: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let c = PerIpConcurrency::new(4);
        {
            let _g = c.try_acquire(ip).expect("admitted");
            assert_eq!(c.map.lock().unwrap().len(), 1);
        }
        // Dropping the last guard removes the key, so the map self-bounds under
        // churn without a GC task.
        assert!(
            c.map.lock().unwrap().is_empty(),
            "an empty key must be evicted"
        );
    }
}
