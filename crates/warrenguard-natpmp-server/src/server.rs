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
//!      - `Map { lifetime>0 }` → `backend.allocate(...)`.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use crate::protocol::{
    MAP_REQUEST_LEN, MAX_CREDENTIAL_LEN, MapProto, NATPMP_VERSION, ParseError, RateLimitInfo,
    Request, Response, ResultCode, credential_trailer, parse_request, serialize_response,
};
use crate::{Allocation, PortForwardingBackend, Proto};

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

/// Receives the credential a client presented with its Map request, before
/// the request is served.
///
/// The engine carries the bytes and forms no opinion about them: a deployer
/// verifies them, spends them if that is what they are, and decides what
/// budget they buy (see [`crate::allocator::PortBudget`]). Presentation is
/// awaited, so an authority that has to reach the network holds the request
/// while it does; keep it quick, and answer rather than hang.
pub trait CredentialAuthority: Send + Sync {
    /// Hand `credential`, as presented by `client_ip`, to the deployer.
    fn present<'a>(
        &'a self,
        client_ip: Ipv4Addr,
        credential: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
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

    /// Local address actually bound (resolved port when `:0` was
    /// passed).
    ///
    /// # Errors
    ///
    /// OS error if the socket is in an invalid state.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Infinite listen loop: receive, dispatch, respond. Returns on a
    /// fatal socket error (rare).
    ///
    /// # Errors
    ///
    /// Non-recoverable `recv_from` or `send_to` error.
    pub async fn run(self) -> Result<()> {
        // Must hold the largest frame a client can legitimately send: an RFC
        // Map request plus a full credential trailer. Sized short, a
        // credential is silently truncated away and the deployer never sees
        // what the client presented.
        let mut buf = [0u8; MAP_REQUEST_LEN + 4 + MAX_CREDENTIAL_LEN];
        loop {
            let res = self.socket.recv_from(&mut buf).await;
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
            self.handle_one(&buf[..n], src).await;
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
                // RFC §3.3.2: delete-mapping. Always respond Success
                // with lifetime=0, whether or not a mapping existed -
                // the client is just told that nothing is mapped now.
                self.backend
                    .release_by_client(src_v4, internal_port, proto_from_wire(proto))
                    .await;
                Response::Map {
                    proto,
                    result_code: ResultCode::Success,
                    epoch_secs,
                    internal_port,
                    external_port: internal_port,
                    lifetime_secs: 0,
                    // Release ack: no budget hint needed.
                    rate_limit: None,
                }
            }
            Request::Map {
                proto,
                internal_port,
                suggested_external_port,
                lifetime_secs,
            } => {
                // Before serving: hand the deployer whatever the client
                // presented, so the budget this allocation is measured
                // against is the one the credential bought. A client that
                // presented nothing reaches the authority not at all, which is
                // how a deployer tells "claimed nothing" from "claimed
                // something I could not verify".
                if let (Some(authority), Some(credential)) = (
                    self.credential_authority.as_ref(),
                    credential_trailer(frame),
                ) {
                    authority.present(src_v4, credential).await;
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
                match self
                    .backend
                    .allocate(
                        src_v4,
                        proto_from_wire(proto),
                        internal_port,
                        suggested_external_port,
                        lifetime,
                    )
                    .await
                {
                    Ok(alloc) => {
                        // Attach the post-allocation rate-limit budget so
                        // the client/UI can warn before the next ban.
                        let rate_limit = self.backend.rate_limit_status(src_v4);
                        map_success_response(&alloc, internal_port, epoch_secs, Some(rate_limit))
                    }
                    Err(e) => map_failure_response(proto, internal_port, &e, epoch_secs),
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
