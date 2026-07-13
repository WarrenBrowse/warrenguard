//! End-to-end test of the full RFC 6886 UDP loop.
//!
//! Spawns an in-process `Server` on `127.0.0.1:<random>` with a
//! filter that accepts any source IP (to test without a real
//! tunnel), sends raw frames, and verifies responses byte by byte.
//! Does not depend on crab_nat (its hardcoded port 5351 is
//! incompatible with random ports).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use warrenguard_natpmp_server::server::{Server, SourceFilter};
use warrenguard_natpmp_server::stub_backend::StubBackend;

const TIMEOUT: Duration = Duration::from_secs(2);
const FAKE_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);

/// Spawns a server with a permissive filter (tests).
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

/// Sends `frame` to the server and reads the response, with a
/// timeout.
async fn roundtrip(server_addr: SocketAddr, frame: &[u8]) -> Vec<u8> {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    client.send_to(frame, server_addr).await.expect("send_to");
    // 64 bytes: a successful / rate-limited Map response carries the
    // optional 4-byte Warren rate-limit trailer (20 bytes total); a
    // 16-byte buffer would silently truncate it.
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("response before timeout")
        .expect("recv_from");
    buf[..n].to_vec()
}

// ---------------------------------------------------------------------------
// ExternalAddress opcode returns the configured public IP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_responds_to_external_address_request() {
    let (server_addr, _backend) = spawn_test_server().await;
    let resp = roundtrip(server_addr, &[0x00, 0x00]).await;

    assert_eq!(resp.len(), 12, "ExternalAddress response = 12 bytes");
    assert_eq!(resp[0], 0, "version");
    assert_eq!(resp[1], 0x80, "opcode 0 | response bit");
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        0,
        "result code = Success"
    );
    let external_ip = Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11]);
    assert_eq!(
        external_ip, FAKE_PUBLIC_IP,
        "must return the configured public IP"
    );
}

// ---------------------------------------------------------------------------
// Map TCP nominal roundtrip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_allocates_tcp_mapping_and_returns_external_port() {
    let (server_addr, backend) = spawn_test_server().await;

    // Map TCP frame, internal=49200, suggested=0, lifetime=600.
    let frame = [
        0x00, 0x02, 0x00, 0x00, 0xC0, 0x30, 0x00, 0x00, 0x00, 0x00, 0x02, 0x58,
    ];
    let resp = roundtrip(server_addr, &frame).await;

    assert_eq!(
        resp.len(),
        20,
        "successful Map response = 16 RFC bytes + 4-byte Warren rate-limit trailer"
    );
    // Trailer: after a fresh allocation the per-source budget still has
    // headroom (default 5/min), so attempts_remaining > 0.
    assert!(
        resp[16] > 0,
        "attempts_remaining should be non-zero after the first map, got {}",
        resp[16]
    );
    assert_eq!(resp[0], 0);
    assert_eq!(resp[1], 0x82, "opcode 2 TCP | response bit");
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        0,
        "Success expected, got result code = {}",
        u16::from_be_bytes([resp[2], resp[3]])
    );
    let internal_port = u16::from_be_bytes([resp[8], resp[9]]);
    let external_port = u16::from_be_bytes([resp[10], resp[11]]);
    let lifetime = u32::from_be_bytes([resp[12], resp[13], resp[14], resp[15]]);
    assert_eq!(internal_port, 49200, "internal port must be echoed");
    assert!(
        (49152..=65535).contains(&external_port),
        "external port {external_port} out of range"
    );
    assert!(
        (60..=3600).contains(&lifetime),
        "lifetime {lifetime} outside clamp [60..3600]"
    );
    assert_eq!(backend.allocator().active_count(), 1);
}

#[tokio::test]
async fn server_honors_suggested_external_port_end_to_end() {
    // Regression guard for the bug where the server dropped the
    // client's suggested external port (destructured it away with
    // `..`) and the backends hardcoded `suggested = 0`. A free,
    // in-range suggestion must now come back verbatim through the
    // real UDP server → backend → allocator path.
    let (server_addr, backend) = spawn_test_server().await;

    // Map TCP, internal=49200 (0xC030), suggested=50000 (0xC350),
    // lifetime=600 (0x0258). Bytes 6..8 carry the suggested port.
    let frame = [
        0x00, 0x02, 0x00, 0x00, 0xC0, 0x30, 0xC3, 0x50, 0x00, 0x00, 0x02, 0x58,
    ];
    let resp = roundtrip(server_addr, &frame).await;

    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        0,
        "Success expected, got result code = {}",
        u16::from_be_bytes([resp[2], resp[3]])
    );
    let external_port = u16::from_be_bytes([resp[10], resp[11]]);
    assert_eq!(
        external_port, 50000,
        "the free, in-range suggested port must be honoured end-to-end"
    );
    assert_eq!(backend.allocator().active_count(), 1);
}

#[tokio::test]
async fn server_rejects_taken_suggested_port_with_suggested_port_unavailable() {
    // Strict honour-or-error, end-to-end on the wire: once a port is
    // held, an explicit request for that SAME port that cannot refresh
    // it (a different (internal_port, proto) tuple) must come back as
    // `ResultCode::SuggestedPortUnavailable` (6), NOT a silently
    // substituted random port. Exercises server → backend → allocator
    // → wire, complementing the allocator-level unit tests.
    let (server_addr, backend) = spawn_test_server().await;

    // 1. Map TCP internal=49200 (0xC030), suggested=50000 (0xC350) → granted.
    let map1 = [
        0x00, 0x02, 0x00, 0x00, 0xC0, 0x30, 0xC3, 0x50, 0x00, 0x00, 0x02, 0x58,
    ];
    let resp1 = roundtrip(server_addr, &map1).await;
    assert_eq!(
        u16::from_be_bytes([resp1[2], resp1[3]]),
        0,
        "first map of a free port must succeed"
    );
    assert_eq!(u16::from_be_bytes([resp1[10], resp1[11]]), 50000);

    // 2. Same client, DIFFERENT internal port 8080 (0x1F90), same
    //    suggested=50000 → not a refresh of the held mapping, port is
    //    taken → strict rejection.
    let map2 = [
        0x00, 0x02, 0x00, 0x00, 0x1F, 0x90, 0xC3, 0x50, 0x00, 0x00, 0x02, 0x58,
    ];
    let resp2 = roundtrip(server_addr, &map2).await;
    assert_eq!(
        u16::from_be_bytes([resp2[2], resp2[3]]),
        6,
        "a taken suggested port must return ResultCode::SuggestedPortUnavailable (6), not a substitute"
    );
    // No new mapping was created and no port substituted.
    assert_eq!(
        u16::from_be_bytes([resp2[10], resp2[11]]),
        0,
        "no port granted on rejection"
    );
    assert_eq!(
        backend.allocator().active_count(),
        1,
        "the rejection must not create or replace a mapping"
    );
}

// ---------------------------------------------------------------------------
// delete-mapping (lifetime=0, RFC §3.3.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_deletes_mapping_on_lifetime_zero() {
    let (server_addr, backend) = spawn_test_server().await;

    // 1. Allocate (TCP, internal=49200, lifetime=600).
    let alloc_frame = [
        0x00, 0x02, 0x00, 0x00, 0xC0, 0x30, 0x00, 0x00, 0x00, 0x00, 0x02, 0x58,
    ];
    let _resp1 = roundtrip(server_addr, &alloc_frame).await;
    assert_eq!(backend.allocator().active_count(), 1);

    // 2. Delete request: RFC §3.3.2 - send the original
    // `internal_port` (49200), NOT the external_port. The server
    // does the internal lookup to find the mapping and free it.
    let mut delete_frame = [0u8; 12];
    delete_frame[0] = 0;
    delete_frame[1] = 0x02; // TCP
    delete_frame[4..6].copy_from_slice(&49200u16.to_be_bytes()); // internal_port
    // bytes 6-7 suggested = 0, bytes 8-11 lifetime = 0
    let resp2 = roundtrip(server_addr, &delete_frame).await;

    assert_eq!(resp2[0], 0);
    assert_eq!(resp2[1], 0x82, "opcode TCP | response");
    assert_eq!(
        u16::from_be_bytes([resp2[2], resp2[3]]),
        0,
        "delete must reply Success"
    );
    let lifetime = u32::from_be_bytes([resp2[12], resp2[13], resp2[14], resp2[15]]);
    assert_eq!(lifetime, 0, "echoed lifetime = 0 confirms deletion");
    assert_eq!(
        backend.allocator().active_count(),
        0,
        "the mapping must actually be freed"
    );
}

// ---------------------------------------------------------------------------
// Source IP scoping: reject sources outside the pool
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_rejects_source_outside_tunnel_pool() {
    // Use the *default* `bind` (pool 10.66.0.0/16) so a request from
    // 127.0.0.1 must be refused with NotAuthorized.
    let backend = Arc::new(StubBackend::new());
    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::clone(&backend),
        FAKE_PUBLIC_IP,
    )
    .await
    .expect("bind server");
    let server_addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());

    let resp = roundtrip(server_addr, &[0x00, 0x00]).await;
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        2, // NotAuthorized
        "loopback source outside the 10.66.0.0/16 pool must be NotAuthorized"
    );
    assert_eq!(backend.allocator().active_count(), 0);
}

// ---------------------------------------------------------------------------
// UnsupportedVersion on frames with version != 0
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_responds_unsupported_version_for_non_zero_version() {
    let (server_addr, _backend) = spawn_test_server().await;
    // version=1 (PCP) - Warren only does NAT-PMP v0.
    let resp = roundtrip(server_addr, &[0x01, 0x00]).await;
    assert_eq!(
        u16::from_be_bytes([resp[2], resp[3]]),
        1, // UnsupportedVersion
        "version=1 must be rejected"
    );
}
