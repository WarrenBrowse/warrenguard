//! NAT-PMP client used by the Warren daemon.
//!
//! Requests a port mapping from the Warren exit through NAT-PMP
//! (RFC 6886) on UDP/5351 of the tunnel gateway (`10.66.0.1:5351` by
//! default).
//!
//! ## Architecture
//!
//! - [`request_map`]: sends a `Request::Map`, waits for the
//!   `Response::Map`, returns a [`NatPmpMapping`]. Exponential backoff
//!   retries follow RFC §3.1 (see "Retry RFC §3.1" below).
//! - [`NatPmpClientError`]: `Io`, `Timeout`, `Parse`,
//!   `Server(ResultCode)`.
//!
//! ## Retry RFC §3.1
//!
//! [`request_map`] applies RFC 6886 §3.1 exponential backoff: initial
//! timeout `250ms`, doubled on each retry, capped at
//! [`DEFAULT_MAX_ATTEMPTS`] attempts (5 = ~7.75s total). RFC mandates 9
//! attempts (~128s) - Warren caps at 5 for an interactive POC.
//!
//! To override the retry count (tests, slow environments), use
//! [`request_map_with_retries`].
//!
//! ## Automatic renewal
//!
//! See [`refresh::spawn_refresh_loop`] for a long-running task that
//! sends the initial `request_map`, then re-issues it every
//! `lifetime / 2` (RFC 6886 §3.7) and emits events on a caller-supplied
//! channel.

#![warn(missing_docs)]

pub mod refresh;

pub use refresh::{
    CredentialProvider, ForwardProtos, NatPmpEvent, NatPmpFailureReason, RefreshLoopConfig,
    RefreshLoopHandle, SuggestionKind, spawn_refresh_loop, spawn_refresh_loop_from_addr,
    spawn_refresh_loop_protos_from_addr, spawn_refresh_loop_with,
};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use warrenguard_natpmp_protocol::{
    MapProto, ParseError, RateLimitInfo, Request, Response, ResultCode, parse_response,
    serialize_request,
};

// Re-export so daemon-side consumers can name the rate-limit budget
// without a transitive dependency on `warren-natpmp-protocol`.
pub use warrenguard_natpmp_protocol::RateLimitInfo as RateLimitBudget;

// Re-export `MapProto` so consumers do not need a transitive dep on
// `warren-natpmp-protocol` just to name a protocol variant.
pub use warrenguard_natpmp_protocol::MapProto as MapProtocol;

/// Successful client-side NAT-PMP mapping. Lifetime must be renewed
/// before `epoch_secs + lifetime_secs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatPmpMapping {
    /// TCP or UDP (echoed from the request).
    pub proto: MapProto,
    /// Internal port on the client side (tunnel side, e.g.
    /// `10.66.x.y:internal_port`).
    pub internal_port: u16,
    /// Allocated external port - reachable from the Internet on the
    /// exit's public IP. May differ from the request's
    /// `suggested_external_port`.
    pub external_port: u16,
    /// Granted lifetime, in seconds. May be < the requested one.
    pub lifetime_secs: u32,
    /// Daemon epoch (RFC §3.6) used to detect server restarts.
    pub epoch_secs: u32,
    /// Per-source rate-limit budget reported by the exit on this
    /// response (Warren trailer). `None` if the server did not include
    /// the trailer (RFC-only / pre-trailer exit). Surfaced to the UI so
    /// it can warn before the next ban.
    pub rate_limit: Option<RateLimitInfo>,
}

/// Client-side NAT-PMP errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NatPmpClientError {
    /// UDP socket I/O error (bind, connect, send, recv).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// No response after exhausting retries (default 5 attempts =
    /// ~7.75s with RFC §3.1 exponential backoff).
    #[error("timeout waiting for NAT-PMP response")]
    Timeout,

    /// Server response is malformed (wrong opcode, incompatible
    /// version, frame too short, ...).
    #[error("invalid response: {0}")]
    Parse(#[from] ParseError),

    /// Server replied with a non-Success `result_code`.
    #[error("server returned error: {0:?}")]
    Server(ResultCode),

    /// Server rejected the request with the Warren `RateLimited` code:
    /// the per-source allocation rate limit fired. Carries the
    /// retry-after delay (from the response trailer) so the caller can
    /// wait the exact time before retrying and the UI can show a
    /// countdown. Distinct from [`Self::Server`] so the refresh loop can
    /// treat it as recoverable-after-delay rather than terminal.
    #[error("rate limited by exit; retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds to wait before a rate-limit slot frees.
        retry_after_secs: u16,
    },

    /// Server replied with an unexpected opcode (Map requested,
    /// ExternalAddress received, or vice-versa).
    #[error("unexpected response opcode (expected map mapping)")]
    UnexpectedOpcode,
}

/// Default address of the Warren exit NAT-PMP server: tunnel gateway
/// `10.66.0.1` on the RFC 6886 standard port 5351.
#[must_use]
pub fn default_server_addr() -> SocketAddr {
    SocketAddr::from((warrenguard_config::TUNNEL_GATEWAY_IP, 5351))
}

/// Default maximum number of RFC §3.1 attempts. RFC recommends 9
/// (~128s total with doubling) - Warren POC caps at 5 (~7.75s) to
/// avoid blocking the user too long when the server has no NAT-PMP
/// service.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Initial timeout before retry, RFC §3.1 ("client should give up
/// receiving the response after 250ms"). Doubled on each retry.
pub const INITIAL_TIMEOUT_MS: u64 = 250;

/// Requests a port mapping from the exit with RFC §3.1 exponential
/// backoff retries (5 attempts by default, ~7.75s total timeout).
///
/// `lifetime_secs == 0` sends a *delete-mapping* (RFC §3.3.2): the
/// server releases the corresponding allocation and the response also
/// has `lifetime_secs == 0`.
///
/// # Errors
///
/// - [`NatPmpClientError::Io`]: socket bind/connect/send/recv failed.
/// - [`NatPmpClientError::Timeout`]: retries exhausted without
///   response.
/// - [`NatPmpClientError::Parse`]: response is not a valid frame.
/// - [`NatPmpClientError::Server`]: `result_code != Success` on the
///   server (typically `OutOfResources` if the pool is empty,
///   `NotAuthorized` if the source IP is not in the tunnel CIDR).
/// - [`NatPmpClientError::UnexpectedOpcode`]: received an
///   `ExternalAddress` response instead of a `Map` (buggy server or
///   MITM).
pub async fn request_map(
    server: SocketAddr,
    proto: MapProto,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
) -> Result<NatPmpMapping, NatPmpClientError> {
    request_map_with_retries(
        server,
        proto,
        internal_port,
        suggested_external_port,
        lifetime_secs,
        DEFAULT_MAX_ATTEMPTS,
    )
    .await
}

/// Variant of [`request_map`] binding the client UDP socket to a
/// specific local IP. Useful when the host has multiple network
/// interfaces (e.g. an Android VPN client whose tunnel is layered
/// over the default mobile-data interface) and the request MUST
/// egress through a specific one. Without a bound local IP the
/// kernel routes via the default interface, which on Android means
/// the NAT-PMP request bypasses the tunnel entirely and the exit's
/// NAT-PMP server never sees it.
///
/// **Use this on Android VPN clients** with `bind_addr = the
/// tunnel inner IPv4 (e.g. `10.66.0.2`)`. Desktop daemons that
/// already route the default route through the tunnel can keep
/// [`request_map`].
///
/// # Errors
///
/// See [`request_map`].
pub async fn request_map_from_addr(
    server: SocketAddr,
    proto: MapProto,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    bind_addr: Option<IpAddr>,
) -> Result<NatPmpMapping, NatPmpClientError> {
    request_map_with_retries_from_addr(
        server,
        proto,
        internal_port,
        suggested_external_port,
        lifetime_secs,
        DEFAULT_MAX_ATTEMPTS,
        bind_addr,
    )
    .await
}

/// Variant of [`request_map`] exposing the maximum number of
/// attempts. Useful for tests wanting a short timeout or for slow
/// environments needing more than the default 5 attempts.
///
/// Algorithm: at most `max_attempts` iterations, timeout doubling on
/// each retry starting from [`INITIAL_TIMEOUT_MS`] (250ms). Typical
/// total duration for `max_attempts=5`: 250 + 500 + 1000 + 2000 +
/// 4000 = 7.75s.
///
/// **No retry on server errors**: if the server replies with
/// `result_code != Success`, the error is propagated immediately
/// (retrying will not change a valid response). Same for `Parse` and
/// `UnexpectedOpcode`. Only `Timeout` triggers a retry.
///
/// # Errors
///
/// See [`request_map`].
///
/// # Panics
///
/// If `max_attempts == 0` (caller bug - a client that waits for no
/// response makes no sense).
pub async fn request_map_with_retries(
    server: SocketAddr,
    proto: MapProto,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    max_attempts: u32,
) -> Result<NatPmpMapping, NatPmpClientError> {
    request_map_with_retries_from_addr(
        server,
        proto,
        internal_port,
        suggested_external_port,
        lifetime_secs,
        max_attempts,
        None,
    )
    .await
}

/// Full-knobs variant: `request_map_with_retries` + a
/// `bind_addr` override. `None` = let the OS pick (UNSPECIFIED v4/v6,
/// kernel routes via default interface). `Some(ip)` = bind the source
/// IP explicitly so the egress interface is forced.
///
/// # Errors
///
/// See [`request_map`].
///
/// # Panics
///
/// If `max_attempts == 0`.
pub async fn request_map_with_retries_from_addr(
    server: SocketAddr,
    proto: MapProto,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    max_attempts: u32,
    bind_addr: Option<IpAddr>,
) -> Result<NatPmpMapping, NatPmpClientError> {
    request_map_with_credential(
        server,
        proto,
        internal_port,
        suggested_external_port,
        lifetime_secs,
        max_attempts,
        bind_addr,
        None,
    )
    .await
}

/// [`request_map_with_retries_from_addr`] presenting `credential` with the
/// request, for a deployer whose server gates the port budget on one.
///
/// The credential rides a trailer after the RFC frame, so a server that does
/// not know about it answers exactly as it would have without one. Too long a
/// credential ([`warrenguard_natpmp_protocol::MAX_CREDENTIAL_LEN`]) is dropped
/// rather than failing the request: a mapping is worth more than the budget it
/// would have bought.
///
/// # Errors
///
/// See [`request_map_with_retries_from_addr`].
///
/// # Panics
///
/// If `max_attempts` is zero.
#[expect(clippy::too_many_arguments)]
pub async fn request_map_with_credential(
    server: SocketAddr,
    proto: MapProto,
    internal_port: u16,
    suggested_external_port: u16,
    lifetime_secs: u32,
    max_attempts: u32,
    bind_addr: Option<IpAddr>,
    credential: Option<&[u8]>,
) -> Result<NatPmpMapping, NatPmpClientError> {
    assert!(max_attempts >= 1, "max_attempts must be ≥ 1");

    let bind_socket_addr: SocketAddr = match bind_addr {
        Some(ip) => SocketAddr::from((ip, 0)),
        None => match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
        },
    };
    let sock = UdpSocket::bind(bind_socket_addr).await?;
    sock.connect(server).await?;

    let req = Request::Map {
        proto,
        internal_port,
        suggested_external_port,
        lifetime_secs,
    };
    let mut req_bytes = serialize_request(&req);
    if let Some(credential) = credential
        && let Err(e) =
            warrenguard_natpmp_protocol::append_credential_trailer(&mut req_bytes, credential)
    {
        tracing::debug!(error = %e, "credential not presented with the mapping request");
    }

    let mut timeout_ms = INITIAL_TIMEOUT_MS;
    for attempt in 1..=max_attempts {
        // RFC §3.1: re-send the same request on each attempt
        // (idempotent server-side thanks to internal conntrack for Map
        // requests).
        sock.send(&req_bytes).await?;
        tracing::debug!(
            ?server,
            ?proto,
            attempt,
            max_attempts,
            timeout_ms,
            "NAT-PMP map request sent"
        );

        let mut buf = [0u8; 64];
        let recv_fut = sock.recv(&mut buf);
        let n = match tokio::time::timeout(Duration::from_millis(timeout_ms), recv_fut).await {
            Ok(res) => res?,
            Err(_) => {
                // Timeout on this attempt - RFC says to double the
                // timeout and retry. If attempts are exhausted, return
                // a final Timeout to the caller.
                if attempt >= max_attempts {
                    tracing::warn!(
                        max_attempts,
                        "NAT-PMP request giving up after exhausted retries"
                    );
                    return Err(NatPmpClientError::Timeout);
                }
                tracing::debug!(attempt, "NAT-PMP timeout, retrying with doubled backoff");
                timeout_ms = timeout_ms.saturating_mul(2);
                continue;
            }
        };

        // Response received - no retry, return directly.
        return match parse_response(&buf[..n])? {
            Response::Map {
                proto,
                result_code: ResultCode::Success,
                internal_port,
                external_port,
                lifetime_secs,
                epoch_secs,
                rate_limit,
            } => Ok(NatPmpMapping {
                proto,
                internal_port,
                external_port,
                lifetime_secs,
                epoch_secs,
                rate_limit,
            }),
            // Rate-limit rejection carries the retry-after in the trailer
            // (window_reset_secs). Distinct error so the refresh loop can
            // wait then retry instead of giving up.
            Response::Map {
                result_code: ResultCode::RateLimited,
                rate_limit,
                ..
            } => Err(NatPmpClientError::RateLimited {
                retry_after_secs: rate_limit.map_or(0, |info| info.window_reset_secs),
            }),
            Response::Map { result_code, .. } => Err(NatPmpClientError::Server(result_code)),
            Response::ExternalAddress { .. } => Err(NatPmpClientError::UnexpectedOpcode),
        };
    }

    // The loop returns from every branch: Ok(...), Err(Server/Parse),
    // or Err(Timeout) on the last iteration when exhausted.
    // `unreachable!` catches a logic bug if a future path is added that
    // exits the loop without returning.
    unreachable!("request_map_with_retries loop must return inside its body")
}

#[cfg(test)]
mod tests {
    use super::*;
    use warrenguard_natpmp_protocol::{Response as ServerResponse, serialize_response};

    /// Spawns a tiny one-shot UDP stub server that replies once with
    /// the provided `Response::Map`. Returns the bound address for the
    /// client to target.
    async fn spawn_one_shot_stub(reply: ServerResponse) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = sock.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (n, peer) = sock.recv_from(&mut buf).await.expect("recv stub");
            // Request bytes are not validated here (dedicated tests
            // cover that) - just reply to exercise the client.
            let _ = n;
            sock.send_to(&serialize_response(&reply), peer)
                .await
                .expect("send stub");
        });
        addr
    }

    #[tokio::test]
    async fn request_map_success_returns_mapping() {
        let stub = spawn_one_shot_stub(ServerResponse::Map {
            proto: MapProto::Udp,
            result_code: ResultCode::Success,
            epoch_secs: 12345,
            internal_port: 22,
            external_port: 49152,
            lifetime_secs: 3600,
            rate_limit: None,
        })
        .await;

        let mapping = request_map(stub, MapProto::Udp, 22, 0, 3600)
            .await
            .expect("client got mapping");

        assert_eq!(mapping.proto, MapProto::Udp);
        assert_eq!(mapping.internal_port, 22);
        assert_eq!(mapping.external_port, 49152);
        assert_eq!(mapping.lifetime_secs, 3600);
        assert_eq!(mapping.epoch_secs, 12345);
    }

    #[tokio::test]
    async fn request_map_from_addr_binds_to_supplied_local_ip() {
        // Spawn a stub that captures the client's source address +
        // echoes back a Success mapping. We then assert that the source
        // IP equals the explicit `bind_addr` we passed.
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_addr = server_sock.local_addr().expect("addr");
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::channel::<SocketAddr>(1);
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (_, peer) = server_sock.recv_from(&mut buf).await.expect("recv");
            // Tell the test where the client bound, then reply.
            let _ = peer_tx.send(peer).await;
            let reply = ServerResponse::Map {
                proto: MapProto::Udp,
                result_code: ResultCode::Success,
                epoch_secs: 1,
                internal_port: 22,
                external_port: 49152,
                lifetime_secs: 60,
                rate_limit: None,
            };
            server_sock
                .send_to(&serialize_response(&reply), peer)
                .await
                .expect("send");
        });

        // Force the bind addr to 127.0.0.1 explicitly; we should observe
        // it as the source IP on the server side.
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mapping = request_map_from_addr(server_addr, MapProto::Udp, 22, 0, 60, Some(bind_addr))
            .await
            .expect("client got mapping");
        assert_eq!(mapping.external_port, 49152);

        let observed_peer = peer_rx.recv().await.expect("peer addr captured");
        assert_eq!(
            observed_peer.ip(),
            bind_addr,
            "source IP must match bind_addr"
        );
    }

    #[tokio::test]
    async fn request_map_propagates_server_out_of_resources() {
        let stub = spawn_one_shot_stub(ServerResponse::Map {
            proto: MapProto::Tcp,
            result_code: ResultCode::OutOfResources,
            epoch_secs: 0,
            internal_port: 80,
            external_port: 0,
            lifetime_secs: 0,
            rate_limit: None,
        })
        .await;

        let err = request_map(stub, MapProto::Tcp, 80, 0, 60)
            .await
            .expect_err("server returned error code");
        match err {
            NatPmpClientError::Server(ResultCode::OutOfResources) => {}
            other => panic!("expected Server(OutOfResources), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_map_maps_rate_limited_code_to_retry_after_error() {
        // The exit's RateLimited code (7) plus the trailer's
        // window_reset_secs must surface as a typed RateLimited error so
        // the refresh loop can wait the exact retry-after.
        let stub = spawn_one_shot_stub(ServerResponse::Map {
            proto: MapProto::Udp,
            result_code: ResultCode::RateLimited,
            epoch_secs: 0,
            internal_port: 22,
            external_port: 0,
            lifetime_secs: 0,
            rate_limit: Some(RateLimitInfo {
                attempts_remaining: 0,
                window_reset_secs: 47,
            }),
        })
        .await;

        let err = request_map(stub, MapProto::Udp, 22, 0, 60)
            .await
            .expect_err("rate-limited must be an error");
        match err {
            NatPmpClientError::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, 47);
            }
            other => panic!("expected RateLimited {{ retry_after_secs: 47 }}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_map_surfaces_rate_limit_budget_on_success() {
        // A successful map carries the per-source budget so the UI can
        // warn before the next ban.
        let stub = spawn_one_shot_stub(ServerResponse::Map {
            proto: MapProto::Udp,
            result_code: ResultCode::Success,
            epoch_secs: 1,
            internal_port: 22,
            external_port: 49152,
            lifetime_secs: 3600,
            rate_limit: Some(RateLimitInfo {
                attempts_remaining: 2,
                window_reset_secs: 31,
            }),
        })
        .await;

        let mapping = request_map(stub, MapProto::Udp, 22, 0, 3600)
            .await
            .expect("mapping");
        let budget = mapping.rate_limit.expect("budget present");
        assert_eq!(budget.attempts_remaining, 2);
        assert_eq!(budget.window_reset_secs, 31);
    }

    #[tokio::test]
    async fn request_map_rejects_external_address_response() {
        // If the server replies with an ExternalAddress when a Map was
        // requested, the client must signal a clear error (not silently
        // confuse the two).
        let stub = spawn_one_shot_stub(ServerResponse::ExternalAddress {
            result_code: ResultCode::Success,
            epoch_secs: 0,
            external_ip: Ipv4Addr::new(1, 2, 3, 4),
        })
        .await;

        let err = request_map(stub, MapProto::Udp, 22, 0, 60)
            .await
            .expect_err("opcode mismatch");
        assert!(matches!(err, NatPmpClientError::UnexpectedOpcode));
    }

    #[tokio::test]
    async fn request_map_with_retries_times_out_after_one_attempt() {
        // Bind a socket that is never served. With max_attempts=1, the
        // total timeout = INITIAL_TIMEOUT_MS = 250ms.
        let server_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = server_sock.local_addr().expect("addr");
        std::mem::forget(server_sock);

        let start = std::time::Instant::now();
        let err = request_map_with_retries(server_addr, MapProto::Udp, 12345, 0, 60, 1)
            .await
            .expect_err("must timeout after the single attempt");
        let elapsed = start.elapsed();
        assert!(matches!(err, NatPmpClientError::Timeout));
        // Generous margin: 250ms timeout + scheduler latency.
        assert!(
            elapsed < Duration::from_millis(800),
            "single-attempt timeout took too long: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn request_map_recovers_after_packet_loss() {
        // Stub that ignores the first 2 requests then replies to the
        // 3rd. The retry-enabled client must recover the mapping.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let counter = Arc::new(AtomicU32::new(0));
        let counter_for_stub = counter.clone();

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = sock.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let (_, peer) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let attempt = counter_for_stub.fetch_add(1, Ordering::SeqCst) + 1;
                if attempt < 3 {
                    // Drop the first 2 requests to simulate packet loss.
                    continue;
                }
                let resp = serialize_response(&ServerResponse::Map {
                    proto: MapProto::Udp,
                    result_code: ResultCode::Success,
                    epoch_secs: 0,
                    internal_port: 22,
                    external_port: 49152,
                    lifetime_secs: 3600,
                    rate_limit: None,
                });
                let _ = sock.send_to(&resp, peer).await;
                return;
            }
        });

        // With max_attempts=5 and drops on 1+2, at least 3 attempts are
        // needed. Must converge in < 1s (250ms + 500ms + retry).
        let mapping = request_map_with_retries(addr, MapProto::Udp, 22, 0, 3600, 5)
            .await
            .expect("retry should have succeeded after packet loss");
        assert_eq!(mapping.external_port, 49152);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            3,
            "client must have tried exactly 3 times (drops 1+2, success on 3)"
        );
    }

    #[tokio::test]
    async fn request_map_with_retries_no_retry_on_server_error() {
        // If the server replies with an error on the 1st attempt, the
        // client must not retry (the response is valid, just negative).
        let stub = spawn_one_shot_stub(ServerResponse::Map {
            proto: MapProto::Udp,
            result_code: ResultCode::OutOfResources,
            epoch_secs: 0,
            internal_port: 22,
            external_port: 0,
            lifetime_secs: 0,
            rate_limit: None,
        })
        .await;
        let start = std::time::Instant::now();
        let err = request_map_with_retries(stub, MapProto::Udp, 22, 0, 3600, 5)
            .await
            .expect_err("server error must propagate without retry");
        let elapsed = start.elapsed();
        assert!(matches!(
            err,
            NatPmpClientError::Server(ResultCode::OutOfResources)
        ));
        assert!(
            elapsed < Duration::from_millis(500),
            "server error must propagate immediately without retry: {elapsed:?}"
        );
    }

    #[test]
    #[should_panic(expected = "max_attempts must be ≥ 1")]
    fn request_map_with_retries_zero_attempts_panics() {
        // Test must run inside a tokio runtime to avoid block_on issues.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let _ = request_map_with_retries(
                "127.0.0.1:1".parse().unwrap(),
                MapProto::Udp,
                22,
                0,
                60,
                0,
            )
            .await;
        });
    }

    #[tokio::test]
    async fn request_map_parse_error_on_garbage_response() {
        // Server returns 4 random bytes (frame too short).
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = sock.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (_, peer) = sock.recv_from(&mut buf).await.expect("recv");
            sock.send_to(&[0xAA, 0xBB, 0xCC, 0xDD], peer)
                .await
                .expect("send garbage");
        });

        let err = request_map(addr, MapProto::Udp, 22, 0, 60)
            .await
            .expect_err("garbage response");
        assert!(matches!(err, NatPmpClientError::Parse(_)));
    }

    #[test]
    fn default_server_addr_is_tunnel_gateway_5351() {
        let addr = default_server_addr();
        assert_eq!(addr.port(), 5351, "RFC 6886 standard port");
        assert_eq!(addr.ip(), warrenguard_config::TUNNEL_GATEWAY_IP);
    }
}
