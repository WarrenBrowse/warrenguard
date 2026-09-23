//! Bounded, concurrent request handling.
//!
//! Two properties the UDP loop must hold, both end-to-end on real sockets:
//!
//! - a deployer call that never returns (`CredentialAuthority::present`)
//!   is refused fail-closed after `request_timeout`, instead of holding the
//!   request (and, before the requests were isolated, the whole service)
//!   open forever;
//! - a request hanging on that same call does not delay a different client,
//!   because `run` handles each datagram in its own task.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use warrenguard_natpmp_protocol::{
    MapProto, Request, append_credential_trailer, serialize_request,
};
use warrenguard_natpmp_server::server::{CredentialAuthority, Server, SourceFilter};
use warrenguard_natpmp_server::stub_backend::StubBackend;
use warrenguard_natpmp_server::{Allocation, NatPmpError, PortForwardingBackend, Proto};

const FAKE_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);
/// RFC 6886 result code 3, `NetworkFailure`.
const NETWORK_FAILURE: u16 = 3;
/// RFC 6886 result code 0, `Success`.
const SUCCESS: u16 = 0;

/// An authority that never answers, whatever is presented.
struct AlwaysPending;

impl CredentialAuthority for AlwaysPending {
    fn present<'a>(
        &'a self,
        _client_ip: Ipv4Addr,
        _credential: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(std::future::pending::<()>())
    }
}

/// An authority that hangs only on the `SLOW` marker credential and answers
/// immediately otherwise. Signals each hang so a test can wait until the slow
/// request really is parked inside `present`.
struct SlowMarkerAuthority {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
}

impl CredentialAuthority for SlowMarkerAuthority {
    fn present<'a>(
        &'a self,
        _client_ip: Ipv4Addr,
        credential: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        let entered = self.entered.clone();
        let slow = credential == b"SLOW";
        Box::pin(async move {
            if slow {
                let _ = entered.send(());
                std::future::pending::<()>().await;
            }
        })
    }
}

/// Binds a server on loopback only, with `authority` and `request_timeout`.
async fn spawn_server(
    authority: Arc<dyn CredentialAuthority>,
    request_timeout: Duration,
) -> SocketAddr {
    // 127.0.0.1 only: the test's client sockets are loopback sockets.
    let loopback_only: SourceFilter = Arc::new(|ip: Ipv4Addr| ip.is_loopback());
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().expect("static addr"),
        Arc::new(StubBackend::new()),
        FAKE_PUBLIC_IP,
        loopback_only,
    )
    .await
    .expect("bind server")
    .with_credential_authority(authority)
    .with_request_timeout(request_timeout);
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    addr
}

/// A valid RFC 6886 Map request, optionally carrying `credential`.
fn map_request(credential: &[u8]) -> Vec<u8> {
    let mut frame = serialize_request(&Request::Map {
        proto: MapProto::Tcp,
        internal_port: 8080,
        suggested_external_port: 0,
        lifetime_secs: 600,
    });
    append_credential_trailer(&mut frame, credential).expect("credential fits the trailer");
    frame
}

/// RFC 6886 result code of a response frame.
fn result_code(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[2], response[3]])
}

async fn bind_client() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.expect("bind client")
}

#[tokio::test]
async fn hanging_credential_authority_is_refused_not_awaited_forever() {
    // 50 ms bound: the point is that the request comes back at all, and that
    // it comes back refused rather than granted.
    let server = spawn_server(Arc::new(AlwaysPending), Duration::from_millis(50)).await;
    let client = bind_client().await;
    let frame = map_request(b"an-unverifiable-credential");
    client.send_to(&frame, server).await.expect("send_to");

    let mut buf = [0u8; 64];
    let started = Instant::now();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("a bounded authority must answer well before 2 s")
        .expect("recv_from");
    let elapsed = started.elapsed();

    assert_eq!(
        result_code(&buf[..n]),
        NETWORK_FAILURE,
        "a credential the authority never verified must be refused, not granted"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "the response took {elapsed:?}, past the 2 s ceiling"
    );
}

#[tokio::test]
async fn a_hanging_request_does_not_block_another_client() {
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let authority: Arc<dyn CredentialAuthority> = Arc::new(SlowMarkerAuthority {
        entered: entered_tx,
    });
    // 10 s bound: far past the test's own deadline, so the slow request is
    // still in flight when the assertions run.
    let server = spawn_server(authority, Duration::from_secs(10)).await;

    let slow_client = bind_client().await;
    slow_client
        .send_to(&map_request(b"SLOW"), server)
        .await
        .expect("send the slow request");

    // Wait until the slow request is parked inside `present` before sending
    // the normal one: otherwise the normal request could be answered first
    // simply by arriving first, and the test would prove nothing.
    tokio::time::timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .expect("the slow request must reach the authority")
        .expect("authority entry signal");

    let normal_client = bind_client().await;
    normal_client
        .send_to(&map_request(b"FAST"), server)
        .await
        .expect("send the normal request");

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(
        Duration::from_millis(500),
        normal_client.recv_from(&mut buf),
    )
    .await
    .expect("the second client must be served while the first request still hangs")
    .expect("recv_from");

    assert_eq!(
        result_code(&buf[..n]),
        SUCCESS,
        "the unimpeded client must get its mapping"
    );
    assert!(
        slow_client.try_recv(&mut buf).is_err(),
        "the slow request must still be in flight, not already answered"
    );
}

struct DelayedBackend {
    inner: StubBackend,
    allocated: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    fail_release: std::sync::atomic::AtomicBool,
    delay_allocations: std::sync::atomic::AtomicBool,
}

impl DelayedBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: StubBackend::new(),
            allocated: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
            fail_release: std::sync::atomic::AtomicBool::new(false),
            delay_allocations: std::sync::atomic::AtomicBool::new(true),
        })
    }
}

impl PortForwardingBackend for DelayedBackend {
    async fn allocate(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested_external_port: u16,
        lifetime: Duration,
    ) -> Result<Allocation, NatPmpError> {
        let allocation = self
            .inner
            .allocate(
                client_ip,
                proto,
                internal_port,
                suggested_external_port,
                lifetime,
            )
            .await?;
        if self
            .delay_allocations
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.allocated.notify_one();
            self.resume.notified().await;
        }
        Ok(allocation)
    }

    async fn release(&self, allocation: &Allocation) -> Result<(), NatPmpError> {
        self.inner.release(allocation).await
    }

    async fn release_by_client(
        &self,
        client_ip: Ipv4Addr,
        internal_port: u16,
        proto: Proto,
    ) -> Result<bool, NatPmpError> {
        if self.fail_release.load(std::sync::atomic::Ordering::Acquire) {
            return Err(NatPmpError::Backend("simulated delete failure".to_string()));
        }
        self.inner
            .release_by_client(client_ip, internal_port, proto)
            .await
    }

    fn rate_limit_status(
        &self,
        client_ip: Ipv4Addr,
    ) -> warrenguard_natpmp_server::protocol::RateLimitInfo {
        self.inner.rate_limit_status(client_ip)
    }

    async fn restore(&self, entries: Vec<Allocation>) -> Vec<Allocation> {
        self.inner.restore(entries).await
    }
}

#[tokio::test]
async fn a_timed_out_allocation_is_rolled_back_after_backend_completion() {
    let backend = DelayedBackend::new();
    let loopback_only: SourceFilter = Arc::new(|ip: Ipv4Addr| ip.is_loopback());
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().expect("static addr"),
        backend.clone(),
        FAKE_PUBLIC_IP,
        loopback_only,
    )
    .await
    .expect("bind server")
    .with_request_timeout(Duration::from_millis(50));
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    let client = bind_client().await;
    client
        .send_to(&map_request(b""), addr)
        .await
        .expect("send_to");
    backend.allocated.notified().await;

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("bounded response")
        .expect("recv_from");
    assert_eq!(result_code(&buf[..n]), NETWORK_FAILURE);
    backend.resume.notify_one();

    tokio::time::timeout(Duration::from_secs(2), async {
        while backend.inner.allocator().active_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed-out mapping must be removed");
}

#[tokio::test]
async fn a_failed_backend_delete_returns_network_failure() {
    let backend = DelayedBackend::new();
    backend
        .fail_release
        .store(true, std::sync::atomic::Ordering::Release);
    let loopback_only: SourceFilter = Arc::new(|ip: Ipv4Addr| ip.is_loopback());
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().expect("static addr"),
        backend.clone(),
        FAKE_PUBLIC_IP,
        loopback_only,
    )
    .await
    .expect("bind server");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    backend
        .inner
        .allocate(
            Ipv4Addr::LOCALHOST,
            Proto::Tcp,
            8080,
            0,
            Duration::from_secs(600),
        )
        .await
        .expect("preexisting mapping");
    let client = bind_client().await;
    let frame = serialize_request(&Request::Map {
        proto: MapProto::Tcp,
        internal_port: 8080,
        suggested_external_port: 0,
        lifetime_secs: 0,
    });
    client.send_to(&frame, addr).await.expect("send_to");

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .expect("bounded response")
        .expect("recv_from");
    assert_eq!(result_code(&buf[..n]), NETWORK_FAILURE);
    assert_eq!(backend.inner.allocator().active_count(), 1);
}

#[tokio::test]
async fn a_later_map_waits_for_timed_out_allocation_cleanup() {
    let backend = DelayedBackend::new();
    let loopback_only: SourceFilter = Arc::new(|ip: Ipv4Addr| ip.is_loopback());
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().expect("static addr"),
        backend.clone(),
        FAKE_PUBLIC_IP,
        loopback_only,
    )
    .await
    .expect("bind server")
    .with_request_timeout(Duration::from_millis(250));
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    let first = bind_client().await;
    first
        .send_to(&map_request(b""), addr)
        .await
        .expect("first send");
    backend.allocated.notified().await;

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), first.recv_from(&mut buf))
        .await
        .expect("first response")
        .expect("recv_from");
    assert_eq!(result_code(&buf[..n]), NETWORK_FAILURE);

    backend
        .delay_allocations
        .store(false, std::sync::atomic::Ordering::Release);
    let second = bind_client().await;
    second
        .send_to(&map_request(b""), addr)
        .await
        .expect("second send");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), second.recv_from(&mut buf))
            .await
            .is_err(),
        "the second map must wait while cleanup still owns the backend slot"
    );
    backend.resume.notify_one();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), second.recv_from(&mut buf))
        .await
        .expect("second response")
        .expect("recv_from");
    assert_eq!(result_code(&buf[..n]), SUCCESS);
    assert_eq!(backend.inner.allocator().active_count(), 1);
}
