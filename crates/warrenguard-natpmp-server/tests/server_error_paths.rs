//! Server UDP error-path tests not covered by `e2e_natpmp.rs`.
//!
//! Covers:
//! - UDP variant of `proto_{from,to}_wire` conversions.
//! - Refusal of an IPv6 source.
//! - Truncated frames (`ParseError::TooShort`).
//! - `map_failure_response` with a backend that fails (`Exhausted`).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use warrenguard_natpmp_server::allocator::Allocator;
use warrenguard_natpmp_server::server::{Server, SourceFilter};
use warrenguard_natpmp_server::stub_backend::StubBackend;

const TIMEOUT: Duration = Duration::from_secs(2);
const FAKE_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);

async fn spawn_test_server() -> (SocketAddr, Arc<StubBackend>) {
    let backend = Arc::new(StubBackend::new());
    let permissive: SourceFilter = Arc::new(|_| true);
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().unwrap(),
        Arc::clone(&backend),
        FAKE_PUBLIC_IP,
        permissive,
    )
    .await
    .expect("bind server");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    (addr, backend)
}

async fn roundtrip(server_addr: SocketAddr, frame: &[u8]) -> Vec<u8> {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    client.send_to(frame, server_addr).await.expect("send_to");
    // 64 bytes: successful / rate-limited Map responses carry the
    // optional 4-byte Warren rate-limit trailer (20 bytes total).
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("response before timeout")
        .expect("recv_from");
    buf[..n].to_vec()
}

#[tokio::test]
async fn udp_mapping_roundtrip_exercises_proto_conversions() {
    // Coverage: `proto_from_wire(MapProto::Udp)` +
    // `proto_to_wire(Proto::Udp)`.
    let (server_addr, backend) = spawn_test_server().await;

    // UDP map frame: opcode=1, internal=49152, suggested=0,
    // lifetime=600.
    let frame = [
        0x00, 0x01, // version=0, opcode=1 UDP
        0x00, 0x00, // reserved
        0xC0, 0x00, // internal port 49152
        0x00, 0x00, // suggested 0
        0x00, 0x00, 0x02, 0x58, // lifetime 600
    ];
    let resp = roundtrip(server_addr, &frame).await;

    assert_eq!(resp[1], 0x81, "opcode 1 UDP | response bit (0x81)");
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        0,
        "Success expected"
    );
    assert_eq!(backend.allocator().active_count(), 1);
}

#[tokio::test]
async fn server_rejects_ipv6_source() {
    // Coverage: the `IpAddr::V6` branch in `dispatch`. We bind the
    // server on dual-stack IPv6 (::1) so the client can reach it
    // from [::1].
    let backend = Arc::new(StubBackend::new());
    let permissive: SourceFilter = Arc::new(|_| true);
    let server = Server::bind_with_filter(
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)),
        Arc::clone(&backend),
        FAKE_PUBLIC_IP,
        permissive,
    )
    .await
    .expect("bind server v6");
    let server_addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());

    // Client bound on IPv6 → the source seen by the server is ::1.
    let client = UdpSocket::bind("[::1]:0").await.expect("bind client v6");
    client
        .send_to(&[0x00, 0x00], server_addr)
        .await
        .expect("send_to v6");

    let mut buf = [0u8; 16];
    let (n, _) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("timeout")
        .expect("recv");
    let resp = &buf[..n];

    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        2, // NotAuthorized
        "IPv6 source must be rejected NotAuthorized (NAT-PMP is IPv4-only per RFC §3)"
    );
}

#[tokio::test]
async fn server_responds_unsupported_opcode_for_unknown_opcode() {
    // Coverage: the `ParseError::UnsupportedOpcode` branch in
    // `dispatch`.
    let (server_addr, _) = spawn_test_server().await;
    // Opcode 7 = unknown (RFC defines only 0/1/2).
    let resp = roundtrip(server_addr, &[0x00, 0x07]).await;
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        5, // UnsupportedOpcode
        "unknown opcode must be rejected UnsupportedOpcode"
    );
}

#[tokio::test]
async fn server_responds_unsupported_opcode_for_truncated_map_frame() {
    // Coverage: the `ParseError::TooShort` branch in `dispatch`. A
    // map frame (opcode=1) with only 6 bytes instead of 12 must be
    // rejected. The code maps this error to `UnsupportedOpcode`.
    let (server_addr, _) = spawn_test_server().await;
    let resp = roundtrip(server_addr, &[0x00, 0x01, 0x00, 0x00, 0xC0, 0x00]).await;
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        5, // UnsupportedOpcode (default for other parsing errors)
        "truncated frame must return a non-Success error code"
    );
}

#[tokio::test]
async fn server_returns_out_of_resources_when_pool_exhausted() {
    // Coverage: `map_failure_response` with `Exhausted`.
    // Strategy: build a `StubBackend` with an Allocator on a tiny
    // range (a single port), consume it, then ask for a second
    // allocation, which must fail in the allocator and therefore
    // trigger map_failure_response.
    use warrenguard_natpmp_server::PortForwardingBackend;
    use warrenguard_natpmp_server::Proto;

    let allocator = Arc::new(Allocator::with_config(
        (50000, 50000), // a single port
        Duration::from_secs(60),
        100, // generous rate limit
        Duration::from_secs(60),
    ));
    let backend = Arc::new(StubBackend::with_allocator(Arc::clone(&allocator)));
    // Pre-consume the unique port.
    let _kept = backend
        .allocate(
            Ipv4Addr::new(127, 0, 0, 1),
            Proto::Tcp,
            0,
            0,
            Duration::from_secs(60),
        )
        .await
        .expect("alloc 1 must succeed");
    assert_eq!(backend.allocator().active_count(), 1);

    let permissive: SourceFilter = Arc::new(|_| true);
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().unwrap(),
        Arc::clone(&backend),
        FAKE_PUBLIC_IP,
        permissive,
    )
    .await
    .expect("bind server");
    let server_addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());

    // Map TCP request → pool exhausted, must respond OutOfResources.
    let frame = [
        0x00, 0x02, // TCP
        0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, // ports
        0x00, 0x00, 0x02, 0x58, // lifetime 600
    ];
    let resp = roundtrip(server_addr, &frame).await;
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        4, // OutOfResources
        "exhausted pool must return OutOfResources, got code = {}",
        u16::from_be_bytes([resp[2], resp[3]])
    );
}
