//! Refresh-loop behavior when an explicit suggested port is taken.
//!
//! A STICKY suggestion (a previously-granted port carried over so the
//! public port follows the client, e.g. across an exit maintenance
//! migration) is a best-effort preference: on the exit's strict
//! `SuggestedPortUnavailable` rejection the loop must downgrade to a
//! server-picked port and keep the rule alive. A PINNED suggestion (the
//! user chose the port) keeps the strict honour-or-error contract: it is
//! never substituted, and the loop re-requests it across the window in
//! which the holder may release it before surfacing the refusal.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use warrenguard_natpmp_client::{NatPmpEvent, spawn_refresh_loop_from_addr};
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
    map_round_trip(server_addr, &map, "pre-occupation map").await;
}

/// Releases the mapping [`occupy_port_50000`] took, the way a departing
/// holder does: RFC 6886 §3.3.2 Map with lifetime 0 on the same
/// (source, internal port, proto) tuple.
async fn release_port_50000(server_addr: SocketAddr) {
    let release = [
        0x00, 0x02, 0x00, 0x00, 0xC0, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    map_round_trip(server_addr, &release, "release").await;
}

async fn map_round_trip(server_addr: SocketAddr, request: &[u8], what: &str) {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    client.send_to(request, server_addr).await.expect("send");
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("response")
        .expect("recv");
    assert!(n >= 12, "short response to {what}");
    assert_eq!(
        u16::from_be_bytes([buf[2], buf[3]]),
        0,
        "{what} must succeed"
    );
}

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NatPmpEvent>) -> NatPmpEvent {
    tokio::time::timeout(TIMEOUT, rx.recv())
        .await
        .expect("event before timeout")
        .expect("channel open")
}

/// A presented credential must reach the server as a trailer on the very
/// request it belongs to, and must never change how that request is read.
#[tokio::test]
async fn a_credential_rides_the_mapping_request_it_belongs_to() {
    use warrenguard_natpmp_protocol::credential_trailer;

    let seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = sock.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            sink.lock().expect("sink").push(buf[..n].to_vec());
            // Answer Success so the caller completes rather than retrying.
            let resp = [
                0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x1F, 0x90, 0xC3, 0x50, 0x00, 0x00,
                0x02, 0x58,
            ];
            let _ = sock.send_to(&resp, peer).await;
        }
    });

    let credential = vec![0x7Eu8; 354];
    warrenguard_natpmp_client::request_map_with_credential(
        addr,
        MapProto::Tcp,
        8080,
        50000,
        600,
        1,
        None,
        Some(&credential),
    )
    .await
    .expect("mapping granted");

    let frames = seen.lock().expect("sink").clone();
    assert_eq!(frames.len(), 1, "expected one request: {frames:?}");
    assert_eq!(credential_trailer(&frames[0]), Some(credential.as_slice()));
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

/// The commonest holder of a user-pinned port is the client's own previous
/// session, whose mapping the exit drops shortly after it departs. The loop
/// must still be asking for the port when that happens.
#[tokio::test]
async fn pinned_suggestion_reclaims_its_port_once_the_holder_releases() {
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
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        release_port_50000(server_addr).await;
    });

    match next_event(&mut rx).await {
        NatPmpEvent::Mapped { external_port, .. } => {
            assert_eq!(
                external_port, 50000,
                "the pinned port must be granted once its holder let it go"
            );
        }
        other => panic!("expected Mapped on the pinned port, got {other:?}"),
    }
    handle.cancel();
}

/// Honour-or-error: while the conflict lasts the loop reports nothing. A
/// `Mapped` on any other port would be the silent substitution the strict
/// contract forbids, and an immediate `Failed` would strand a rule whose
/// port is about to come back.
#[tokio::test]
async fn pinned_suggestion_is_never_substituted_while_the_conflict_lasts() {
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

    let observed = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        observed.is_err(),
        "expected no event while the pinned port stays taken, got {observed:?}"
    );
    handle.cancel();
    match next_event(&mut rx).await {
        NatPmpEvent::Cancelled => {}
        other => panic!("expected Cancelled after cancel, got {other:?}"),
    }
}
