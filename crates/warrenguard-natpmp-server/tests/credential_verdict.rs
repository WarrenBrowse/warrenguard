//! The credential authority decides, and learns what its credential bought.
//!
//! End to end over the real UDP loop: a deployer can refuse a Map request on
//! what the client presented, or on the absence of anything presented, and is
//! told which port each granted credential ended up holding, so it can later
//! find the credential bound to a port. The engine still reads nothing into
//! the bytes.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use warrenguard_natpmp_protocol::{
    MapProto, Request, append_credential_trailer, serialize_request,
};
use warrenguard_natpmp_server::allocator::Allocator;
use warrenguard_natpmp_server::server::{
    CredentialAuthority, CredentialVerdict, Server, SourceFilter,
};
use warrenguard_natpmp_server::stub_backend::StubBackend;
use warrenguard_natpmp_server::{Allocation, Proto};

const TIMEOUT: Duration = Duration::from_secs(5);
const FAKE_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);
const SUCCESS: u16 = 0;
/// RFC 6886 result code 2.
const NOT_AUTHORIZED: u16 = 2;
const CREDENTIAL: &[u8] = b"an opaque entitlement envelope";

/// Answers every presentation with one verdict, and records what it bound.
struct Authority {
    verdict: CredentialVerdict,
    required: bool,
    bound: Mutex<Vec<(Vec<u8>, Allocation)>>,
}

impl Authority {
    fn new(verdict: CredentialVerdict, required: bool) -> Arc<Self> {
        Arc::new(Self {
            verdict,
            required,
            bound: Mutex::new(Vec::new()),
        })
    }

    fn bound(&self) -> Vec<(Vec<u8>, Allocation)> {
        self.bound.lock().expect("authority lock").clone()
    }
}

impl CredentialAuthority for Authority {
    fn present<'a>(
        &'a self,
        _client_ip: Ipv4Addr,
        _credential: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = CredentialVerdict> + Send + 'a>> {
        let verdict = self.verdict;
        Box::pin(async move { verdict })
    }

    fn requires_credential(&self) -> bool {
        self.required
    }

    fn on_granted(&self, credential: &[u8], allocation: &Allocation) {
        self.bound
            .lock()
            .expect("authority lock")
            .push((credential.to_vec(), allocation.clone()));
    }
}

async fn spawn_server(authority: Arc<Authority>, allocator: Arc<Allocator>) -> SocketAddr {
    let permissive: SourceFilter = Arc::new(|_| true);
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().expect("static addr"),
        Arc::new(StubBackend::with_allocator(allocator)),
        FAKE_PUBLIC_IP,
        permissive,
    )
    .await
    .expect("bind server")
    .with_credential_authority(authority);
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    addr
}

fn map_request(
    proto: MapProto,
    suggested: u16,
    lifetime_secs: u32,
    credential: Option<&[u8]>,
) -> Vec<u8> {
    let mut frame = serialize_request(&Request::Map {
        proto,
        internal_port: 8080,
        suggested_external_port: suggested,
        lifetime_secs,
    });
    if let Some(credential) = credential {
        append_credential_trailer(&mut frame, credential).expect("credential fits");
    }
    frame
}

/// Sends `frame` from `client` and returns `(result_code, external_port)`.
async fn round_trip(client: &UdpSocket, server: SocketAddr, frame: &[u8]) -> (u16, u16) {
    client.send_to(frame, server).await.expect("send");
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("response before timeout")
        .expect("recv");
    assert!(n >= 16, "short map response: {n} bytes");
    (
        u16::from_be_bytes([buf[2], buf[3]]),
        u16::from_be_bytes([buf[10], buf[11]]),
    )
}

async fn client() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.expect("bind client")
}

#[tokio::test]
async fn a_required_credential_that_is_absent_is_refused_not_authorized() {
    let allocator = Arc::new(Allocator::new());
    let authority = Authority::new(CredentialVerdict::Grant, true);
    let server = spawn_server(Arc::clone(&authority), Arc::clone(&allocator)).await;

    let (code, port) = round_trip(
        &client().await,
        server,
        &map_request(MapProto::Tcp, 0, 600, None),
    )
    .await;

    assert_eq!(code, NOT_AUTHORIZED);
    assert_eq!(port, 0);
    assert_eq!(
        allocator.active_count(),
        0,
        "a refused request must not reach the allocator"
    );
    assert!(authority.bound().is_empty());
}

#[tokio::test]
async fn a_refused_credential_is_refused_not_authorized() {
    let allocator = Arc::new(Allocator::new());
    let authority = Authority::new(CredentialVerdict::Refuse, true);
    let server = spawn_server(Arc::clone(&authority), Arc::clone(&allocator)).await;

    let (code, _) = round_trip(
        &client().await,
        server,
        &map_request(MapProto::Tcp, 0, 600, Some(CREDENTIAL)),
    )
    .await;

    assert_eq!(code, NOT_AUTHORIZED);
    assert_eq!(allocator.active_count(), 0);
    assert!(authority.bound().is_empty());
}

#[tokio::test]
async fn a_granted_credential_learns_the_port_it_bought() {
    let allocator = Arc::new(Allocator::new());
    let authority = Authority::new(CredentialVerdict::Grant, true);
    let server = spawn_server(Arc::clone(&authority), allocator).await;

    let (code, port) = round_trip(
        &client().await,
        server,
        &map_request(MapProto::Udp, 0, 600, Some(CREDENTIAL)),
    )
    .await;

    assert_eq!(code, SUCCESS);
    let bound = authority.bound();
    assert_eq!(bound.len(), 1, "{bound:?}");
    let (credential, allocation) = &bound[0];
    assert_eq!(credential.as_slice(), CREDENTIAL);
    assert_eq!(allocation.external_port, port, "bound to the port granted");
    assert_eq!(allocation.proto, Proto::Udp);
    assert_eq!(allocation.internal_ip, Ipv4Addr::LOCALHOST);
}

#[tokio::test]
async fn both_legs_of_a_pair_bind_one_credential_to_one_port() {
    let allocator = Arc::new(Allocator::new());
    let authority = Authority::new(CredentialVerdict::Grant, true);
    let server = spawn_server(Arc::clone(&authority), allocator).await;
    let client = client().await;

    let (_, tcp_port) = round_trip(
        &client,
        server,
        &map_request(MapProto::Tcp, 0, 600, Some(CREDENTIAL)),
    )
    .await;
    let (code, udp_port) = round_trip(
        &client,
        server,
        &map_request(MapProto::Udp, tcp_port, 600, Some(CREDENTIAL)),
    )
    .await;

    assert_eq!(code, SUCCESS);
    assert_eq!(udp_port, tcp_port);
    let bound: Vec<(u16, Proto)> = authority
        .bound()
        .iter()
        .map(|(credential, a)| {
            assert_eq!(credential.as_slice(), CREDENTIAL);
            (a.external_port, a.proto)
        })
        .collect();
    assert_eq!(bound, vec![(tcp_port, Proto::Tcp), (tcp_port, Proto::Udp)]);
}

#[tokio::test]
async fn an_optional_authority_still_serves_a_client_that_presents_nothing() {
    // Every deployment that predates the requirement keeps its behaviour: no
    // credential, the configured quota, and nothing to bind.
    let allocator = Arc::new(Allocator::new());
    let authority = Authority::new(CredentialVerdict::Refuse, false);
    let server = spawn_server(Arc::clone(&authority), Arc::clone(&allocator)).await;

    let (code, _) = round_trip(
        &client().await,
        server,
        &map_request(MapProto::Tcp, 0, 600, None),
    )
    .await;

    assert_eq!(code, SUCCESS);
    assert_eq!(allocator.active_count(), 1);
    assert!(
        authority.bound().is_empty(),
        "nothing presented, nothing bound"
    );
}

#[tokio::test]
async fn a_client_may_always_delete_its_mapping_without_a_credential() {
    // A delete buys nothing, and refusing it would leave a client unable to
    // take down a forward it no longer wants.
    let allocator = Arc::new(Allocator::new());
    let authority = Authority::new(CredentialVerdict::Grant, true);
    let server = spawn_server(Arc::clone(&authority), Arc::clone(&allocator)).await;
    let client = client().await;
    let (granted, _) = round_trip(
        &client,
        server,
        &map_request(MapProto::Tcp, 0, 600, Some(CREDENTIAL)),
    )
    .await;
    assert_eq!(granted, SUCCESS);

    let (code, _) = round_trip(&client, server, &map_request(MapProto::Tcp, 0, 0, None)).await;

    assert_eq!(code, SUCCESS);
    assert_eq!(allocator.active_count(), 0);
}

#[tokio::test]
async fn an_abuse_quarantine_keeps_the_former_tenant_off_its_port_until_it_lifts() {
    let allocator = Arc::new(Allocator::new());
    let authority = Authority::new(CredentialVerdict::Grant, true);
    let server = spawn_server(Arc::clone(&authority), Arc::clone(&allocator)).await;
    let client = client().await;
    let pinned = map_request(MapProto::Tcp, 50000, 600, Some(CREDENTIAL));
    let (code, port) = round_trip(&client, server, &pinned).await;
    assert_eq!((code, port), (SUCCESS, 50000));

    // What the deployer's abuse path does: find the binding, then revoke.
    let revoked = allocator.revoke_for_abuse(50000, Duration::from_millis(300));
    assert_eq!(revoked.len(), 1);
    assert!(revoked[0].held_since <= std::time::Instant::now());
    assert!(
        authority
            .bound()
            .iter()
            .any(|(c, a)| c.as_slice() == CREDENTIAL && a.external_port == 50000),
        "the credential that bought the revoked port is still findable by port"
    );

    let (code, during) = round_trip(&client, server, &pinned).await;
    assert_eq!(code, SUCCESS, "the renewal is served, elsewhere");
    assert_ne!(
        during, 50000,
        "the pinned renewal must not get the port back"
    );

    tokio::time::sleep(Duration::from_millis(400)).await;
    let (code, after) = round_trip(&client, server, &pinned).await;
    assert_eq!((code, after), (SUCCESS, 50000), "the quarantine lifts");
}
