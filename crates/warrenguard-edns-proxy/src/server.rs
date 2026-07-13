//! The Encrypted DNS proxy server.
//!
//! Accepts TCP connections from Warren clients, removes the XOR
//! obfuscation (if any), and forwards the recovered byte stream to a fixed
//! upstream - the Warren API. The client speaks TLS to the API end-to-end
//! through this relay; the proxy never terminates TLS and learns nothing
//! about the payload beyond the obfuscation layer it strips.
//!
//! Hardening (this is a public-facing forwarder): a global connection cap
//! (semaphore) bounds concurrency, an upstream-connect timeout and a
//! per-direction idle timeout reap stalled/slow-loris connections, and the
//! accept loop honours a [`CancellationToken`] for graceful shutdown.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::concurrency::PerIpConcurrency;
use crate::config::ObfuscationConfig;
use crate::ratelimit::{IpRateLimiter, PerIpLimit};
use crate::xor::XorObfuscator;

/// Default ceiling on concurrent client connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
/// Default timeout for establishing the upstream TCP connection.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default per-direction idle timeout: a connection with no bytes in either
/// direction for this long is dropped (slow-loris / dead-peer defence).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Default sustained per-IP new-connection rate (connections/second/key).
/// Generous on purpose: many legitimate users share a CGNAT IPv4.
pub const DEFAULT_PER_IP_PER_SECOND: u32 = 15;
/// Default per-IP connection burst allowance.
pub const DEFAULT_PER_IP_BURST: u32 = 60;

/// Default cap on concurrently active relay sessions per source IP. Matches
/// the analogous `PER_IP_MAX_CONCURRENT` in the sibling
/// `warrenguard-edge-server` ingress: generous enough for a CGNAT IPv4 shared
/// by many simultaneous legitimate users, while keeping any single source
/// well under [`DEFAULT_MAX_CONNECTIONS`] (so it cannot alone starve the
/// proxy for everyone else).
pub const DEFAULT_PER_IP_MAX_CONCURRENT: u32 = 64;

/// How often expired rate-limiter keys are reclaimed. Kept short so the
/// limiter's key map cannot accumulate distinct source IPs for long between
/// reclamations (memory-exhaustion defence; see [`crate::ratelimit`]).
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// errno values (identical on Linux and macOS) for the `accept()` failures
/// that would otherwise busy-spin: while the resource stays exhausted the next
/// `accept()` returns the same error instantly.
const EMFILE: i32 = 24; // per-process open-file limit reached
const ENFILE: i32 = 23; // system-wide open-file limit reached
const ENOMEM: i32 = 12; // kernel out of memory

/// Backoff applied after a resource-exhaustion `accept()` error so the loop
/// yields the CPU and cannot flood the journal while fds/memory recover.
const ACCEPT_EXHAUSTION_BACKOFF: Duration = Duration::from_millis(100);

/// Returns the backoff to apply after an `accept()` error, or `None` to retry
/// immediately.
///
/// Only resource-exhaustion errors (`EMFILE`/`ENFILE`/`ENOMEM`) warrant a
/// pause: they persist, so an immediate retry returns the same error at once
/// and pegs a CPU core while flooding the log. Other errors (e.g. a peer that
/// reset the connection before `accept()` completed) are one-offs and are
/// retried without delay.
fn accept_error_backoff(err: &io::Error) -> Option<Duration> {
    match err.raw_os_error() {
        Some(EMFILE | ENFILE | ENOMEM) => Some(ACCEPT_EXHAUSTION_BACKOFF),
        _ => None,
    }
}

/// Hard ceiling on tracked rate-limiter keys. Once reached, new keys are
/// refused (fail-closed) until the next reclamation, bounding memory under a
/// flood of distinct source IPs. ~100 bytes/key → well under ~100 MiB.
const MAX_TRACKED_KEYS: usize = 1_000_000;

/// Read/write buffer size per direction. XOR is per-byte and stream-continuous,
/// so this only affects syscall batching, never the wire format.
const RELAY_BUFFER_SIZE: usize = 64 * 1024;

/// Runtime configuration for a [`ProxyServer`].
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Upstream `host:port` every recovered stream is forwarded to.
    pub upstream: String,
    /// XOR obfuscation this proxy strips, or `None` for a plain proxy.
    pub obfuscation: Option<ObfuscationConfig>,
    /// Maximum number of concurrent client connections.
    pub max_connections: usize,
    /// Timeout for establishing the upstream TCP connection.
    pub connect_timeout: Duration,
    /// Per-direction idle timeout before a connection is dropped.
    pub idle_timeout: Duration,
    /// Per-source-IP connection rate limit, or `None` to disable.
    pub per_ip_limit: Option<PerIpLimit>,
    /// Per-source-IP cap on concurrently active relay sessions, or `None` to
    /// disable. See [`crate::concurrency::PerIpConcurrency`] for the
    /// rationale: bounds a single IP's *standing* session count, which
    /// `per_ip_limit` (new-connection rate) does not.
    pub per_ip_max_concurrent: Option<u32>,
}

impl ServerConfig {
    /// Build a config with the default hardening limits.
    #[must_use]
    pub fn new(upstream: String, obfuscation: Option<ObfuscationConfig>) -> Self {
        Self {
            upstream,
            obfuscation,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            per_ip_limit: Some(PerIpLimit {
                // Defaults are non-zero, so the unwraps never fire.
                per_second: NonZeroU32::new(DEFAULT_PER_IP_PER_SECOND).unwrap(),
                burst: NonZeroU32::new(DEFAULT_PER_IP_BURST).unwrap(),
            }),
            per_ip_max_concurrent: Some(DEFAULT_PER_IP_MAX_CONCURRENT),
        }
    }
}

/// Cumulative server counters, exported via the binary's `/metrics` endpoint.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Connections accepted and dispatched to a relay task.
    pub accepted: AtomicU64,
    /// Relay tasks that have finished (cleanly or with error).
    pub completed: AtomicU64,
    /// Connections dropped at accept time because the cap was reached.
    pub rejected_at_capacity: AtomicU64,
    /// Connections dropped at accept time by the per-IP rate limiter.
    pub rejected_rate_limited: AtomicU64,
    /// Connections dropped at accept time because the source IP already has
    /// [`DEFAULT_PER_IP_MAX_CONCURRENT`] (or the configured override) relay
    /// sessions active.
    pub rejected_per_ip_concurrency: AtomicU64,
    /// Failures (or timeouts) connecting to the upstream.
    pub upstream_connect_failures: AtomicU64,
}

impl Metrics {
    /// Connections currently being relayed (`accepted - completed`).
    #[must_use]
    pub fn active(&self) -> u64 {
        self.accepted
            .load(Ordering::Relaxed)
            .saturating_sub(self.completed.load(Ordering::Relaxed))
    }
}

/// A bound Encrypted DNS proxy server.
pub struct ProxyServer {
    listener: TcpListener,
    config: Arc<ServerConfig>,
    semaphore: Arc<Semaphore>,
    rate_limiter: Option<Arc<IpRateLimiter>>,
    per_ip_conc: Option<Arc<PerIpConcurrency>>,
    metrics: Arc<Metrics>,
}

impl ProxyServer {
    /// Bind the listener without yet accepting connections.
    ///
    /// # Errors
    /// Returns an error if the listen address cannot be bound.
    pub async fn bind(listen: SocketAddr, config: ServerConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(listen).await?;
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        let rate_limiter = config
            .per_ip_limit
            .map(|limit| Arc::new(IpRateLimiter::new(limit, MAX_TRACKED_KEYS)));
        let per_ip_conc = config
            .per_ip_max_concurrent
            .map(|max| Arc::new(PerIpConcurrency::new(max)));
        Ok(Self {
            listener,
            config: Arc::new(config),
            semaphore,
            rate_limiter,
            per_ip_conc,
            metrics: Arc::new(Metrics::default()),
        })
    }

    /// The actual local address the listener is bound to.
    ///
    /// # Errors
    /// Returns an error if the underlying socket address cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Shared metrics handle (for a `/metrics` endpoint).
    #[must_use]
    pub fn metrics(&self) -> Arc<Metrics> {
        self.metrics.clone()
    }

    /// Accept connections until `cancel` fires, spawning a relay task per
    /// connection (bounded by the per-IP rate limit and the connection cap).
    pub async fn run(self, cancel: CancellationToken) {
        self.spawn_rate_limit_cleanup(cancel.clone());
        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    tracing::info!("shutdown requested, no longer accepting connections");
                    break;
                }
                result = self.listener.accept() => match result {
                    Ok((client, peer)) => self.accept(client, peer.ip()),
                    Err(error) => {
                        if let Some(backoff) = accept_error_backoff(&error) {
                            // Resource exhaustion (out of fds/memory): the next
                            // accept() would fail identically and instantly, so
                            // pause to avoid pegging a CPU core and flooding the
                            // journal until the resource recovers.
                            tracing::warn!(%error, "accept failed (resource exhaustion); backing off");
                            tokio::time::sleep(backoff).await;
                        } else {
                            tracing::warn!(%error, "accept failed");
                        }
                    }
                },
            }
        }
    }

    /// Periodically reclaim expired rate-limiter keys to bound memory.
    fn spawn_rate_limit_cleanup(&self, cancel: CancellationToken) {
        let Some(limiter) = self.rate_limiter.clone() else {
            return;
        };
        tokio::spawn(async move {
            // `interval_at` so the first tick is one full interval out, rather
            // than firing immediately at startup on an empty map.
            let start = tokio::time::Instant::now() + RATE_LIMIT_CLEANUP_INTERVAL;
            let mut interval = tokio::time::interval_at(start, RATE_LIMIT_CLEANUP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    _ = interval.tick() => limiter.cleanup(),
                }
            }
        });
    }

    /// Apply the per-IP rate limit, then hand off to [`Self::dispatch`].
    ///
    /// Peer addresses are deliberately NOT logged: this is a
    /// censorship-circumvention service, and the set of connecting source IPs
    /// is exactly the data that would deanonymize at-risk users. Aggregate
    /// counts live in [`Metrics`] instead.
    fn accept(&self, client: TcpStream, peer_ip: std::net::IpAddr) {
        if let Some(limiter) = &self.rate_limiter
            && !limiter.check(peer_ip)
        {
            self.metrics
                .rejected_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            // `client` dropped here, closing the connection.
            return;
        }
        self.dispatch(client, peer_ip);
    }

    /// Reserve a per-IP concurrency slot and a connection permit, then spawn
    /// the relay task, or drop the connection if either is exhausted.
    fn dispatch(&self, client: TcpStream, peer_ip: std::net::IpAddr) {
        // Checked before the global semaphore (cheaper to refuse a single
        // over-quota source than to burn a slot from the shared pool on it).
        let ip_conc_guard = match &self.per_ip_conc {
            Some(conc) => match conc.try_acquire(peer_ip) {
                Some(guard) => Some(guard),
                None => {
                    self.metrics
                        .rejected_per_ip_concurrency
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
            },
            None => None,
        };

        let Ok(permit) = Arc::clone(&self.semaphore).try_acquire_owned() else {
            self.metrics
                .rejected_at_capacity
                .fetch_add(1, Ordering::Relaxed);
            return;
        };

        self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
        let config = Arc::clone(&self.config);
        let metrics = Arc::clone(&self.metrics);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(client, &config, &metrics).await {
                // No peer address: errors are logged by kind only, not by source.
                tracing::debug!(%error, "connection ended with error");
            }
            metrics.completed.fetch_add(1, Ordering::Relaxed);
            // Both released here: the semaphore permit frees a slot for a new
            // connection anywhere, the per-IP guard frees this source's slot.
            drop(permit);
            drop(ip_conc_guard);
        });
    }
}

/// Relay a single client connection to the upstream, stripping obfuscation.
async fn handle_connection(
    client: TcpStream,
    config: &ServerConfig,
    metrics: &Metrics,
) -> io::Result<()> {
    let server =
        match tokio::time::timeout(config.connect_timeout, TcpStream::connect(&config.upstream))
            .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                metrics
                    .upstream_connect_failures
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(upstream = %config.upstream, %error, "upstream connect failed");
                return Err(error);
            }
            Err(_) => {
                metrics
                    .upstream_connect_failures
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(upstream = %config.upstream, "upstream connect timed out");
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upstream connect timeout",
                ));
            }
        };

    // Latency matters on the relay path; disable Nagle on both legs.
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);

    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();

    // One fresh obfuscator per direction, mirroring the client's two
    // independent obfuscators. XOR is symmetric, so the same operation both
    // recovers (client -> upstream) and re-applies (upstream -> client).
    let to_upstream = config.obfuscation.map(|o| o.create_obfuscator());
    let to_client = config.obfuscation.map(|o| o.create_obfuscator());

    let (up, down) = tokio::join!(
        pump(to_upstream, client_read, server_write, config.idle_timeout),
        pump(to_client, server_read, client_write, config.idle_timeout),
    );
    // Surface the first error so the caller can log it and metrics stay honest.
    up.and(down)
}

/// Copy `source` to `sink`, XOR-transforming each chunk if obfuscated, with an
/// idle timeout that bounds how long a read may stall.
async fn pump(
    mut obfuscator: Option<XorObfuscator>,
    mut source: impl AsyncRead + Unpin,
    mut sink: impl AsyncWrite + Unpin,
    idle_timeout: Duration,
) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
    loop {
        let n = match tokio::time::timeout(idle_timeout, source.read(&mut buf)).await {
            Ok(result) => result?,
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout")),
        };
        if n == 0 {
            break;
        }
        let chunk = &mut buf[..n];
        if let Some(obfuscator) = &mut obfuscator {
            obfuscator.obfuscate(chunk);
        }
        sink.write_all(chunk).await?;
    }
    // Propagate the half-close so the peer observes EOF on this direction.
    let _ = sink.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ObfuscationConfig;
    use crate::xor::{XorKey, XorObfuscator};
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    #[test]
    fn accept_backoff_pauses_on_resource_exhaustion() {
        // EMFILE/ENFILE/ENOMEM persist, so retrying instantly busy-spins a CPU
        // core and floods the log. Each must yield a backoff.
        for errno in [EMFILE, ENFILE, ENOMEM] {
            let err = io::Error::from_raw_os_error(errno);
            assert_eq!(
                accept_error_backoff(&err),
                Some(ACCEPT_EXHAUSTION_BACKOFF),
                "errno {errno} is a resource-exhaustion accept() error and must back off"
            );
        }
    }

    #[test]
    fn accept_backoff_retries_immediately_on_one_off_errors() {
        // EPERM (1) is the same on Linux and macOS and is not an exhaustion
        // error; a non-OS error has no raw errno. Both retry without delay.
        assert_eq!(accept_error_backoff(&io::Error::from_raw_os_error(1)), None);
        assert_eq!(accept_error_backoff(&io::Error::other("synthetic")), None);
    }

    /// Spawn a TCP echo server, return its address.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    async fn start(echo: SocketAddr, obf: Option<ObfuscationConfig>) -> (SocketAddr, Arc<Metrics>) {
        let server = ProxyServer::bind(
            (Ipv4Addr::LOCALHOST, 0).into(),
            ServerConfig::new(echo.to_string(), obf),
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        let metrics = server.metrics();
        tokio::spawn(server.run(CancellationToken::new()));
        (addr, metrics)
    }

    /// End-to-end: a client obfuscating exactly like the upstream client sends bytes
    /// through the proxy; the echo upstream must receive plaintext and the
    /// client must read back its original payload.
    #[tokio::test]
    async fn relays_and_deobfuscates_xor_stream() {
        let echo = spawn_echo().await;
        let obf = ObfuscationConfig::XorV2(XorKey::try_from([0xff, 0x04, 0x02, 0, 0, 0]).unwrap());
        let (proxy_addr, _metrics) = start(echo, Some(obf)).await;

        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        let mut client_write = XorObfuscator::new(match obf {
            ObfuscationConfig::XorV2(k) => k,
        });
        let mut client_read = XorObfuscator::new(match obf {
            ObfuscationConfig::XorV2(k) => k,
        });

        for _ in 0..4 {
            let original: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
            let mut wire = original.clone();
            client_write.obfuscate(&mut wire);
            conn.write_all(&wire).await.unwrap();

            let mut back = vec![0u8; original.len()];
            conn.read_exact(&mut back).await.unwrap();
            client_read.obfuscate(&mut back);
            assert_eq!(original, back);
        }
    }

    /// Plain (no obfuscation) proxies must pass bytes through untouched.
    #[tokio::test]
    async fn relays_plain_stream() {
        let echo = spawn_echo().await;
        let (proxy_addr, _metrics) = start(echo, None).await;

        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        let payload = b"hello warren";
        conn.write_all(payload).await.unwrap();
        let mut back = vec![0u8; payload.len()];
        conn.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, payload);
    }

    /// At capacity, additional connections are dropped and counted.
    #[tokio::test]
    async fn rejects_connections_over_capacity() {
        // Upstream that accepts but never echoes, so connections stay open.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                if let Ok((sock, _)) = listener.accept().await {
                    held.push(sock); // keep alive, never read/close
                }
            }
        });

        let mut config = ServerConfig::new(upstream.to_string(), None);
        config.max_connections = 1;
        let server = ProxyServer::bind((Ipv4Addr::LOCALHOST, 0).into(), config)
            .await
            .unwrap();
        let proxy_addr = server.local_addr().unwrap();
        let metrics = server.metrics();
        tokio::spawn(server.run(CancellationToken::new()));

        // First connection occupies the single permit.
        let _c1 = TcpStream::connect(proxy_addr).await.unwrap();
        // Give the server a moment to accept and occupy the permit.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Second connection: TCP connect succeeds, but the server drops it
        // immediately for lack of a permit.
        let mut c2 = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 1];
        // The dropped connection sees EOF (read returns 0).
        let n = tokio::time::timeout(Duration::from_secs(2), c2.read(&mut buf))
            .await
            .expect("read should not hang")
            .unwrap();
        assert_eq!(n, 0, "over-capacity connection should be closed");
        assert_eq!(metrics.rejected_at_capacity.load(Ordering::Relaxed), 1);
    }

    /// A single source IP cannot accumulate more than `per_ip_max_concurrent`
    /// standing relay sessions, even though it is well under the global cap
    /// and the churn rate limiter (disabled here to isolate the concurrency
    /// cap specifically).
    #[tokio::test]
    async fn rejects_third_concurrent_connection_from_the_same_ip() {
        // Upstream that accepts but never echoes, so connections stay open.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                if let Ok((sock, _)) = listener.accept().await {
                    held.push(sock); // keep alive, never read/close
                }
            }
        });

        let mut config = ServerConfig::new(upstream.to_string(), None);
        config.max_connections = 10; // well above the per-IP cap under test
        config.per_ip_limit = None; // isolate: churn limiter must not interfere
        config.per_ip_max_concurrent = Some(2);
        let server = ProxyServer::bind((Ipv4Addr::LOCALHOST, 0).into(), config)
            .await
            .unwrap();
        let proxy_addr = server.local_addr().unwrap();
        let metrics = server.metrics();
        tokio::spawn(server.run(CancellationToken::new()));

        // Both loopback connections share the same source IP (127.0.0.1), so
        // the 1st and 2nd occupy the per-IP cap of 2.
        let _c1 = TcpStream::connect(proxy_addr).await.unwrap();
        let _c2 = TcpStream::connect(proxy_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3rd from the same IP: TCP connect succeeds, but the server drops it
        // for lack of a per-IP concurrency slot (global cap is nowhere near
        // reached).
        let mut c3 = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), c3.read(&mut buf))
            .await
            .expect("read should not hang")
            .unwrap();
        assert_eq!(n, 0, "over-per-IP-cap connection should be closed");
        assert_eq!(
            metrics.rejected_per_ip_concurrency.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.rejected_at_capacity.load(Ordering::Relaxed),
            0,
            "must be refused by the per-IP cap, not the (much higher) global cap"
        );
    }

    /// Closing a connection frees its source IP's concurrency slot for a
    /// subsequent connection.
    #[tokio::test]
    async fn per_ip_concurrency_slot_is_freed_when_the_connection_closes() {
        let echo = spawn_echo().await;
        let mut config = ServerConfig::new(echo.to_string(), None);
        config.per_ip_limit = None;
        config.per_ip_max_concurrent = Some(1);
        let server = ProxyServer::bind((Ipv4Addr::LOCALHOST, 0).into(), config)
            .await
            .unwrap();
        let proxy_addr = server.local_addr().unwrap();
        let metrics = server.metrics();
        tokio::spawn(server.run(CancellationToken::new()));

        let c1 = TcpStream::connect(proxy_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(c1);
        // Give the relay task a moment to observe the close and drop its guard.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A fresh connection from the same IP must be admitted now that the
        // first session's slot was freed.
        let mut c2 = TcpStream::connect(proxy_addr).await.unwrap();
        let payload = b"still admitted";
        c2.write_all(payload).await.unwrap();
        let mut back = vec![0u8; payload.len()];
        c2.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, payload);
        assert_eq!(
            metrics.rejected_per_ip_concurrency.load(Ordering::Relaxed),
            0
        );
    }

    /// An idle connection (no bytes flowing) is reaped after the idle timeout.
    #[tokio::test(start_paused = true)]
    async fn idle_connection_is_reaped() {
        let echo = spawn_echo().await;
        let mut config = ServerConfig::new(echo.to_string(), None);
        config.idle_timeout = Duration::from_secs(5);
        let server = ProxyServer::bind((Ipv4Addr::LOCALHOST, 0).into(), config)
            .await
            .unwrap();
        let proxy_addr = server.local_addr().unwrap();
        tokio::spawn(server.run(CancellationToken::new()));

        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        // Never send anything; advance virtual time past the idle timeout.
        tokio::time::sleep(Duration::from_secs(10)).await;

        // The proxy should have dropped the connection: read returns EOF.
        let mut buf = [0u8; 1];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "idle connection should be reaped");
    }
}
