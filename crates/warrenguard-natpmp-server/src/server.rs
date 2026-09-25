//! Server-side NAT-PMP UDP loop.
//!
//! - Binds a `UdpSocket` on `bind_addr` (`0.0.0.0:5351` in prod,
//!   random port in tests).
//! - For every received datagram:
//!   1. Verifies that `src_ip` is in the tunnel pool
//!      (`10.66.0.0/16`). Otherwise → `NotAuthorized` response.
//!   2. Parses the `Request`. On parse error, responds with an
//!      appropriate RFC error code (`UnsupportedVersion`,
//!      `UnsupportedOpcode`).
//!   3. Dispatches:
//!      - `ExternalAddress` → returns the configured `external_ip`.
//!      - `Map { lifetime=0 }` → `release_by_client` on the
//!        backend's underlying allocator (RFC §3.3.2).
//!      - `Map { lifetime>0 }` → the deployer's [`CredentialAuthority`], when
//!        one is wired, decides on the presented credential (or on its
//!        absence) whether the request is served; a refusal answers
//!        `NotAuthorized`. Then `backend.allocate(...)`, and a granted
//!        credential is told the mapping it now holds.
//! - Datagrams are handled in separate tasks, concurrent with each other
//!   and bounded by [`MAX_IN_FLIGHT_REQUESTS`], so one slow request does
//!   not immobilize the service for the others.
//! - Every deployer-facing await in the dispatch (credential
//!   presentation, `allocate`, `release_by_client`) is bounded by the
//!   server's `request_timeout` (default [`DEFAULT_REQUEST_TIMEOUT`], see
//!   [`Server::with_request_timeout`]). Past that bound the request is
//!   refused fail-closed with `NetworkFailure`: no allocation is served on
//!   a credential the authority never verified, and no `Success` is
//!   reported for a release that did not complete.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use crate::protocol::{
    MAP_REQUEST_LEN, MAX_CREDENTIAL_LEN, MapProto, NATPMP_VERSION, ParseError, RateLimitInfo,
    Request, Response, ResultCode, credential_trailer, parse_request, serialize_response,
};
use crate::{Allocation, PortForwardingBackend, Proto};

/// Bound applied to every deployer-facing await in the dispatch: the
/// credential authority's `present`, the backend's `allocate`, and the
/// backend's `release_by_client`.
///
/// Past it the request is refused fail-closed with
/// [`ResultCode::NetworkFailure`] rather than held open: an authority that
/// never answers must not hand out an unverified allocation, and a release
/// that never completed must not be reported as a `Success`. Overridable per
/// server with [`Server::with_request_timeout`].
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of datagrams handled concurrently.
///
/// [`Server::run`] spawns one task per received datagram and stops receiving
/// while this many are outstanding, so a burst of requests that each wait on
/// a slow deployer call applies backpressure instead of growing tasks (and
/// their frames) without bound.
pub const MAX_IN_FLIGHT_REQUESTS: usize = 64;

// A timed-out allocation must finish its compensating release before another
// request can refresh the same mapping and receive a port that cleanup removes.
const MAX_BACKEND_OPERATIONS: usize = 1;

/// Checks that `ip` is in the Warren tunnel pool (`10.66.0.0/16`).
fn in_tunnel_pool(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 && o[1] == 66
}

/// Converts `MapProto` (wire) into `Proto` (allocator). Bijection.
fn proto_from_wire(p: MapProto) -> Proto {
    match p {
        MapProto::Tcp => Proto::Tcp,
        MapProto::Udp => Proto::Udp,
    }
}

/// Converts `Proto` (allocator) into `MapProto` (wire). Bijection.
fn proto_to_wire(p: Proto) -> MapProto {
    match p {
        Proto::Tcp => MapProto::Tcp,
        Proto::Udp => MapProto::Udp,
    }
}

/// Source-IP authorization filter. Returns `true` iff the client is
/// allowed to talk to the server.
pub type SourceFilter = Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync>;

/// What a [`CredentialAuthority`] decided about a presented credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialVerdict {
    /// Serve the request, within whatever budget the deployer answers through
    /// [`crate::allocator::PortBudget`] (the configured quota when it answers
    /// nothing). This is also the verdict for a credential the deployer could
    /// not check for a reason of its own, such as an outage, when it prefers
    /// the constant quota to a refusal.
    Grant,
    /// Refuse the request with RFC 6886 result code 2 (`NotAuthorized`). No
    /// allocation is attempted.
    Refuse,
}

/// Receives the credential a client presented with its Map request, before
/// the request is served, and decides whether it is served.
///
/// The engine carries the bytes and forms no opinion about them: a deployer
/// verifies them, spends them if that is what they are, decides whether they
/// admit the request and what budget they buy (see
/// [`crate::allocator::PortBudget`]). Presentation is awaited, so an authority
/// that has to reach the network holds the request while it does; keep it
/// quick, and answer rather than hang.
///
/// Only a Map request that creates or renews a mapping is gated. A delete
/// (lifetime 0) buys nothing and is always served, so a client can take down
/// a forward it no longer wants whatever it holds.
pub trait CredentialAuthority: Send + Sync {
    /// Hand `credential`, as presented by `client_ip`, to the deployer, and
    /// return whether the request it came with is served.
    fn present<'a>(
        &'a self,
        client_ip: Ipv4Addr,
        credential: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = CredentialVerdict> + Send + 'a>>;

    /// Whether a Map request that presents no credential at all is refused
    /// (`NotAuthorized`) rather than served on the configured quota. Such a
    /// request never reaches [`Self::present`], so a deployer can still tell
    /// "claimed nothing" from "claimed something I could not verify". Defaults
    /// to `false`, the behaviour of every deployer that predates it.
    fn requires_credential(&self) -> bool {
        false
    }

    /// `credential` was granted and now holds `allocation`: one call per
    /// successful Map request that presented one, renewals included, so both
    /// legs of a TCP+UDP pair each report their own slot of the same port.
    ///
    /// This is how a deployer binds what it knows about a credential to a
    /// port. Dropping that binding with the mapping is the job of
    /// [`crate::allocator::ReleaseObserver`] and of the allocations the
    /// deployer's own takes return. Called once the allocation is live, while
    /// the server still holds its backend slot, so no release of that mapping
    /// can run before it; a request that times out afterwards is rolled back
    /// through the backend's release, which the observer hears. It runs on the
    /// request path, so it must not block.
    fn on_granted(&self, credential: &[u8], allocation: &Allocation) {
        let _ = (credential, allocation);
    }
}

/// RFC 6886 NAT-PMP server - UDP listening loop.
///
/// Generic over `B: PortForwardingBackend` to allow monomorphization:
/// `Server<StubBackend>` for POC/dev on macOS,
/// `Server<NftablesBackend<ShellNftExecutor>>` for Linux prod. The
/// RPITIT used on the trait prevents `Box<dyn>`, but we do not need
/// it as long as the backend choice happens at construction time.
pub struct Server<B> {
    socket: Arc<UdpSocket>,
    backend: Arc<B>,
    public_ip: Ipv4Addr,
    epoch: Instant,
    auth_filter: SourceFilter,
    /// Where a presented credential goes. `None` (the default) means the
    /// deployer gates nothing on one, and any trailer is ignored.
    credential_authority: Option<Arc<dyn CredentialAuthority>>,
    /// Wall-clock bound on every deployer-facing response in `dispatch`.
    /// Defaults to [`DEFAULT_REQUEST_TIMEOUT`].
    request_timeout: Duration,
    backend_slots: Arc<tokio::sync::Semaphore>,
}

impl<B: PortForwardingBackend + 'static> Server<B> {
    /// Binds a NAT-PMP server on `addr` with the Warren default
    /// filter (source IP must be in the tunnel pool
    /// `10.66.0.0/16`).
    ///
    /// # Errors
    ///
    /// UDP bind error (port already in use, permission denied, ...).
    pub async fn bind(addr: SocketAddr, backend: Arc<B>, public_ip: Ipv4Addr) -> Result<Self> {
        Self::bind_with_filter(addr, backend, public_ip, Arc::new(in_tunnel_pool)).await
    }

    /// Variant with a custom filter. Used by integration tests to
    /// authorize off-pool sources (typically 127.0.0.1).
    ///
    /// # Errors
    ///
    /// See [`Self::bind`].
    pub async fn bind_with_filter(
        addr: SocketAddr,
        backend: Arc<B>,
        public_ip: Ipv4Addr,
        auth_filter: SourceFilter,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("failed to bind UDP NAT-PMP server on {addr}"))?;
        Ok(Self {
            socket: Arc::new(socket),
            backend,
            public_ip,
            epoch: Instant::now(),
            auth_filter,
            credential_authority: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            backend_slots: Arc::new(tokio::sync::Semaphore::new(MAX_BACKEND_OPERATIONS)),
        })
    }

    /// Send every presented credential to `authority` before the request it
    /// came with is served. Without one, a credential trailer is ignored and
    /// every client gets the configured budget.
    #[must_use]
    pub fn with_credential_authority(mut self, authority: Arc<dyn CredentialAuthority>) -> Self {
        self.credential_authority = Some(authority);
        self
    }

    /// Bounds the response wait for credential presentation, allocation and
    /// release by `timeout`. A backend operation already in progress retains
    /// its bounded worker slot until it finishes; an allocation completed
    /// after the response deadline is released before that slot is freed.
    ///
    /// A deployer call that exceeds the bound is refused fail-closed with
    /// [`ResultCode::NetworkFailure`]. Defaults to
    /// [`DEFAULT_REQUEST_TIMEOUT`]; tests shorten it to exercise the
    /// expiry paths without waiting out the production bound.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Local address actually bound (resolved port when `:0` was
    /// passed).
    ///
    /// # Errors
    ///
    /// OS error if the socket is in an invalid state.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Infinite listen loop: receive, spawn, respond. Returns on a
    /// fatal socket error (rare).
    ///
    /// Each datagram is handed to its own task, so a request blocked on a
    /// deployer call no longer immobilizes the service for the others. At
    /// most [`MAX_IN_FLIGHT_REQUESTS`] requests are handled concurrently:
    /// while that many are outstanding the loop stops receiving, which
    /// applies backpressure rather than growing tasks without bound.
    ///
    /// # Errors
    ///
    /// Non-recoverable `recv_from` error, or the in-flight semaphore found
    /// closed (a bug: nothing closes it).
    pub async fn run(self) -> Result<()> {
        // Must hold the largest frame a client can legitimately send: an RFC
        // Map request plus a full credential trailer. Sized short, a
        // credential is silently truncated away and the deployer never sees
        // what the client presented.
        let mut buf = [0u8; MAP_REQUEST_LEN + 4 + MAX_CREDENTIAL_LEN];
        let server = Arc::new(self);
        let in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_REQUESTS));
        loop {
            let res = server.socket.recv_from(&mut buf).await;
            let (n, src) = match res {
                Ok(v) => v,
                Err(e) => {
                    // Transient errors (EINTR, EAGAIN under load,
                    // kernel buffer overflow) must not kill the
                    // server. Retry on those. Only structural errors
                    // (socket closed, permanent OS resource
                    // exhaustion) propagate.
                    use std::io::ErrorKind;
                    match e.kind() {
                        ErrorKind::Interrupted | ErrorKind::WouldBlock => {
                            continue;
                        }
                        _ => {
                            return Err(e).context("recv_from failed");
                        }
                    }
                }
            };
            // `buf` is reused by the next `recv_from` while the spawned task
            // still reads this datagram, so the frame has to be owned by the
            // task. One allocation per datagram is the price of handling
            // requests independently of one another.
            let frame = buf[..n].to_vec();
            // Backpressure: a permit is taken before the task is spawned, so
            // the receive loop parks here while `MAX_IN_FLIGHT_REQUESTS`
            // requests are still running.
            let permit = Arc::clone(&in_flight)
                .acquire_owned()
                .await
                .context("NAT-PMP in-flight request semaphore closed")?;
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                // Held for the whole request; dropping it on task exit frees
                // the slot for the next datagram.
                let _permit = permit;
                server.handle_one(&frame, src).await;
            });
        }
    }

    /// Processes a single datagram. Split out from `run` so tests can
    /// step through one frame at a time.
    pub async fn handle_one(&self, frame: &[u8], src: SocketAddr) {
        let response = self.dispatch(frame, src).await;
        let bytes = serialize_response(&response);
        if let Err(e) = self.socket.send_to(&bytes, src).await {
            // No-log: never log the client's tunnel-inner source address (it is
            // a per-session correlation handle). The IO error alone is enough
            // to diagnose a socket-level send failure.
            tracing::warn!(error = %e, "send_to NAT-PMP response failed");
        }
    }

    /// Builds the response for one datagram.
    ///
    /// Every deployer-facing response here is bounded by
    /// [`Self::request_timeout`] and fails closed with
    /// [`ResultCode::NetworkFailure`] on expiry. Called by `handle_one`,
    /// itself either driven by the per-datagram task `run` spawns or
    /// directly by a test.
    async fn dispatch(&self, frame: &[u8], src: SocketAddr) -> Response {
        let epoch_secs = self.epoch_secs();
        // Source IP scoping: refuse anything not authorized by the
        // injected filter.
        let src_v4 = match src.ip() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => {
                // NAT-PMP is IPv4-only by spec - an IPv6 client is
                // off-tunnel or misconfigured.
                return error_response(frame, ResultCode::NotAuthorized, epoch_secs);
            }
        };
        if !(self.auth_filter)(src_v4) {
            return error_response(frame, ResultCode::NotAuthorized, epoch_secs);
        }

        let req = match parse_request(frame) {
            Ok(r) => r,
            Err(ParseError::UnsupportedVersion(_)) => {
                return error_response(frame, ResultCode::UnsupportedVersion, epoch_secs);
            }
            Err(ParseError::UnsupportedOpcode(_) | ParseError::TooShort { .. }) => {
                return error_response(frame, ResultCode::UnsupportedOpcode, epoch_secs);
            }
        };

        match req {
            Request::ExternalAddress => Response::ExternalAddress {
                result_code: ResultCode::Success,
                epoch_secs,
                external_ip: self.public_ip,
            },
            Request::Map {
                proto,
                internal_port,
                lifetime_secs: 0,
                ..
            } => {
                // RFC §3.3.2: delete-mapping. On success, respond Success
                // with lifetime=0, whether or not a mapping existed -
                // the client is just told that nothing is mapped now.
                // Bounded: a release that never completed must not be
                // reported as done, because a client that believes its
                // mapping is gone while it still stands is worse off than
                // one told the release failed.
                let Ok(Ok(permit)) = tokio::time::timeout(
                    self.request_timeout,
                    self.backend_slots.clone().acquire_owned(),
                )
                .await
                else {
                    return error_response(frame, ResultCode::NetworkFailure, epoch_secs);
                };
                let backend = Arc::clone(&self.backend);
                let (tx, rx) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let _permit = permit;
                    let released = backend
                        .release_by_client(src_v4, internal_port, proto_from_wire(proto))
                        .await;
                    let _ = tx.send(released);
                });
                match tokio::time::timeout(self.request_timeout, rx).await {
                    Ok(Ok(Ok(_released))) => Response::Map {
                        proto,
                        result_code: ResultCode::Success,
                        epoch_secs,
                        internal_port,
                        external_port: internal_port,
                        lifetime_secs: 0,
                        // Release ack: no budget hint needed.
                        rate_limit: None,
                    },
                    Ok(Ok(Err(_))) | Ok(Err(_)) | Err(_) => {
                        // No-log: never log the client's tunnel-inner address.
                        tracing::warn!("natpmp release failed or timed out");
                        error_response(frame, ResultCode::NetworkFailure, epoch_secs)
                    }
                }
            }
            Request::Map {
                proto,
                internal_port,
                suggested_external_port,
                lifetime_secs,
            } => {
                // Before serving: hand the deployer whatever the client
                // presented, so it decides whether the request is served and
                // the budget this allocation is measured against is the one
                // the credential bought. A client that presented nothing
                // reaches `present` not at all, which is how a deployer tells
                // "claimed nothing" from "claimed something I could not
                // verify"; whether claiming nothing is enough is its
                // `requires_credential` answer.
                let authority = self.credential_authority.as_ref();
                let mut granted_credential = None;
                if let Some(authority) = authority {
                    let refused = || {
                        map_failure_response(
                            proto,
                            internal_port,
                            &crate::NatPmpError::NotAuthorized(src_v4),
                            epoch_secs,
                        )
                    };
                    match credential_trailer(frame) {
                        Some(credential) => {
                            // Bounded, and fail closed: an authority that does
                            // not answer has not verified the credential, so
                            // the allocation is refused rather than served
                            // unverified.
                            match tokio::time::timeout(
                                self.request_timeout,
                                authority.present(src_v4, credential),
                            )
                            .await
                            {
                                Ok(CredentialVerdict::Grant) => {
                                    granted_credential = Some(credential);
                                }
                                Ok(CredentialVerdict::Refuse) => return refused(),
                                Err(_) => {
                                    // No-log: never log the client's
                                    // tunnel-inner address.
                                    tracing::warn!(
                                        "natpmp credential authority timed out; refusing the map request"
                                    );
                                    return error_response(
                                        frame,
                                        ResultCode::NetworkFailure,
                                        epoch_secs,
                                    );
                                }
                            }
                        }
                        None if authority.requires_credential() => return refused(),
                        None => {}
                    }
                }
                // Defense in depth: clamp
                // the wire-supplied lifetime to RFC 6886 §3.3 bounds
                // before crossing the backend trait boundary. The
                // Allocator inside `nftables.rs` / `stub_backend.rs`
                // also clamps via `clamp_lifetime`, but pinning the
                // bound here keeps the contract explicit for every
                // future backend.
                let clamped_secs = lifetime_secs.clamp(
                    warrenguard_config::NATPMP_LIFETIME_MIN_SECS,
                    warrenguard_config::NATPMP_LIFETIME_MAX_SECS,
                );
                let lifetime = std::time::Duration::from_secs(u64::from(clamped_secs));
                // The client's suggested external port (RFC 6886 §3.3)
                // is forwarded as-is; the allocator decides whether it
                // can honour it. `0` = no preference.
                //
                // Bounded: a backend that does not return within the
                // request timeout is reported as a network failure rather
                // than holding the request (and its in-flight slot) open.
                let Ok(Ok(permit)) = tokio::time::timeout(
                    self.request_timeout,
                    self.backend_slots.clone().acquire_owned(),
                )
                .await
                else {
                    return error_response(frame, ResultCode::NetworkFailure, epoch_secs);
                };
                let backend = Arc::clone(&self.backend);
                let binding = granted_credential
                    .zip(authority)
                    .map(|(credential, authority)| (credential.to_vec(), Arc::clone(authority)));
                let (tx, rx) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let _permit = permit;
                    let result = backend
                        .allocate(
                            src_v4,
                            proto_from_wire(proto),
                            internal_port,
                            suggested_external_port,
                            lifetime,
                        )
                        .await;
                    // Bound while the backend slot is still held, so no other
                    // release can run between the grant and the binding: a
                    // client delete racing its own request would otherwise be
                    // reported first and leave the binding behind it. A
                    // rollback below goes through the backend's release, which
                    // the release observer hears like any other.
                    if let (Ok(alloc), Some((credential, authority))) = (&result, &binding) {
                        authority.on_granted(credential, alloc);
                    }
                    if let Err(Ok(alloc)) = tx.send(result) {
                        // The requester timed out while the backend was in flight.
                        // Keep the slot until the unacknowledged mapping is gone.
                        if backend.release(&alloc).await.is_err() {
                            tracing::error!(
                                "timed-out NAT-PMP allocation could not be rolled back"
                            );
                        }
                    }
                });
                match tokio::time::timeout(self.request_timeout, rx).await {
                    Ok(Ok(Ok(alloc))) => {
                        // Attach the post-allocation rate-limit budget so
                        // the client/UI can warn before the next ban.
                        let rate_limit = self.backend.rate_limit_status(src_v4);
                        map_success_response(&alloc, internal_port, epoch_secs, Some(rate_limit))
                    }
                    Ok(Ok(Err(e))) => map_failure_response(proto, internal_port, &e, epoch_secs),
                    Ok(Err(_)) | Err(_) => {
                        // No-log: never log the client's tunnel-inner address.
                        tracing::warn!(
                            "natpmp backend allocate timed out; refusing the map request"
                        );
                        map_failure_response(
                            proto,
                            internal_port,
                            &crate::NatPmpError::Backend("allocate timed out".to_string()),
                            epoch_secs,
                        )
                    }
                }
            }
        }
    }

    fn epoch_secs(&self) -> u32 {
        u32::try_from(self.epoch.elapsed().as_secs()).unwrap_or(u32::MAX)
    }
}

fn map_success_response(
    alloc: &Allocation,
    internal_port: u16,
    epoch_secs: u32,
    rate_limit: Option<RateLimitInfo>,
) -> Response {
    let lifetime_secs = u32::try_from(
        alloc
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_secs(),
    )
    .unwrap_or(u32::MAX);
    Response::Map {
        proto: proto_to_wire(alloc.proto),
        result_code: ResultCode::Success,
        epoch_secs,
        internal_port,
        external_port: alloc.external_port,
        lifetime_secs,
        rate_limit,
    }
}

fn map_failure_response(
    proto: MapProto,
    internal_port: u16,
    err: &crate::NatPmpError,
    epoch_secs: u32,
) -> Response {
    // The rate-limit case gets a dedicated result code plus the
    // retry-after trailer so the UI can show a countdown; the other
    // out-of-resources cases (pool exhausted, per-client quota) stay
    // generic with no trailer.
    let (result_code, rate_limit) = match err {
        crate::NatPmpError::RateLimited {
            retry_after_secs, ..
        } => (
            ResultCode::RateLimited,
            Some(RateLimitInfo {
                attempts_remaining: 0,
                window_reset_secs: *retry_after_secs,
            }),
        ),
        crate::NatPmpError::Exhausted | crate::NatPmpError::QuotaExceeded(_) => {
            (ResultCode::OutOfResources, None)
        }
        crate::NatPmpError::SuggestedPortInUse(external_port) => {
            // The one refusal an operator cannot reconstruct after the fact:
            // it leaves no trace in the allocator, in the backend rules, or
            // in the reaper's accounting, and a support report describes it
            // only as "port in use". The port is the exit's own resource; the
            // requester stays out of the record.
            tracing::info!(
                external_port,
                "natpmp refused a suggested port already held on this exit"
            );
            (ResultCode::SuggestedPortUnavailable, None)
        }
        crate::NatPmpError::NotAuthorized(_) => (ResultCode::NotAuthorized, None),
        crate::NatPmpError::Backend(_) => (ResultCode::NetworkFailure, None),
    };
    Response::Map {
        proto,
        result_code,
        epoch_secs,
        internal_port,
        external_port: 0,
        lifetime_secs: 0,
        rate_limit,
    }
}

/// Builds the "least wrong" error response when parsing fails.
/// Without a reliable opcode we respond as an `ExternalAddress`
/// (response opcode 0x80) - the client will see `result_code != 0`
/// and abort.
fn error_response(frame: &[u8], result_code: ResultCode, epoch_secs: u32) -> Response {
    // If we have at least an opcode and it is map-like, mirror the
    // protocol so the client can intelligently ignore the response.
    if frame.len() >= 2 && frame[0] == NATPMP_VERSION {
        match frame[1] {
            1 => {
                return Response::Map {
                    proto: MapProto::Udp,
                    result_code,
                    epoch_secs,
                    internal_port: 0,
                    external_port: 0,
                    lifetime_secs: 0,
                    rate_limit: None,
                };
            }
            2 => {
                return Response::Map {
                    proto: MapProto::Tcp,
                    result_code,
                    epoch_secs,
                    internal_port: 0,
                    external_port: 0,
                    lifetime_secs: 0,
                    rate_limit: None,
                };
            }
            _ => {}
        }
    }
    Response::ExternalAddress {
        result_code,
        epoch_secs,
        external_ip: Ipv4Addr::UNSPECIFIED,
    }
}
