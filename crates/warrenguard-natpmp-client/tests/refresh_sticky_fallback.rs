//! Refresh-loop behavior when an explicit suggested port is taken.
//!
//! A STICKY suggestion (a previously-granted port carried over so the
//! public port follows the client, e.g. across an exit maintenance
//! migration) is a best-effort preference: on the exit's strict
//! `SuggestedPortUnavailable` rejection the loop must downgrade to a
//! server-picked port and keep the rule alive. A PINNED suggestion (the
//! user chose the port) keeps the strict honour-or-error contract: the
//! loop surfaces `Failed(SuggestedPortInUse)` and stops.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use warrenguard_natpmp_client::{NatPmpEvent, NatPmpFailureReason, spawn_refresh_loop_from_addr};
use warrenguard_natpmp_protocol::MapProto;
use warrenguard_natpmp_server::server::{Server, SourceFilter};
use warrenguard_natpmp_server::stub_backend::StubBackend;

const TIMEOUT: Duration = Duration::from_secs(5);
const FAKE_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);

async fn spawn_test_server() -> SocketAddr {
    let backend = Arc::new(StubBackend::new());
    let permissive: SourceFilter = Arc::new(|_| true);
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().unwrap(),
        backend,
        FAKE_PUBLIC_IP,
        permissive,
    )
    .await
    .expect("bind server");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    addr
}

/// Occupies external port 50000 from this host (internal port 49200),
/// so a later request for 50000 with a DIFFERENT internal port is a
/// strict conflict (same source IP, different tuple).
async fn occupy_port_50000(server_addr: SocketAddr) {
    let map = [
        0x00, 0x02, 0x00, 0x00, 0xC0, 0x30, 0xC3, 0x50, 0x00, 0x00, 0x02, 0x58,
    ];
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    client.send_to(&map, server_addr).await.expect("send");
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("response")
        .expect("recv");
    assert!(n >= 12, "short response");
    assert_eq!(
        u16::from_be_bytes([buf[2], buf[3]]),
        0,
        "pre-occupation map must succeed"
    );
}

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NatPmpEvent>) -> NatPmpEvent {
    tokio::time::timeout(TIMEOUT, rx.recv())
        .await
        .expect("event before timeout")
        .expect("channel open")
}

#[tokio::test]
async fn sticky_suggestion_downgrades_to_server_pick_on_conflict() {
    let server_addr = spawn_test_server().await;
    occupy_port_50000(server_addr).await;

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handle = spawn_refresh_loop_from_addr(
        server_addr,
        MapProto::Tcp,
        8080,
        50000,
        600,
        warrenguard_natpmp_client::SuggestionKind::Sticky,
        tx,
        None,
    );

    match next_event(&mut rx).await {
        NatPmpEvent::Mapped { external_port, .. } => {
            assert_ne!(external_port, 0, "a real port must be granted");
            assert_ne!(
                external_port, 50000,
                "the conflicting sticky port cannot be granted"
            );
        }
        other => panic!("expected Mapped after sticky downgrade, got {other:?}"),
    }
    handle.cancel();
}

#[tokio::test]
async fn pinned_suggestion_fails_permanently_on_conflict() {
    let server_addr = spawn_test_server().await;
    occupy_port_50000(server_addr).await;

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handle = spawn_refresh_loop_from_addr(
        server_addr,
        MapProto::Tcp,
        8080,
        50000,
        600,
        warrenguard_natpmp_client::SuggestionKind::Pinned,
        tx,
        None,
    );

    match next_event(&mut rx).await {
        NatPmpEvent::Failed { reason, .. } => {
            assert_eq!(reason, NatPmpFailureReason::SuggestedPortInUse);
        }
        other => panic!("expected Failed(SuggestedPortInUse), got {other:?}"),
    }
    handle.cancel();
}
