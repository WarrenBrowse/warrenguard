//! End-to-end validation of the dual-proto (TCP+UDP) pair against the
//! REAL NAT-PMP server and its REAL allocator, over UDP loopback: the
//! whole chain the unit stubs cannot vouch for (client pair sequencing
//! + server-side client-level port ownership + companion-slot grant).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use warrenguard_natpmp_client::{
    ForwardProtos, NatPmpEvent, NatPmpFailureReason, SuggestionKind,
    spawn_refresh_loop_protos_from_addr,
};
use warrenguard_natpmp_server::Proto;
use warrenguard_natpmp_server::server::{Server, SourceFilter};
use warrenguard_natpmp_server::stub_backend::StubBackend;

const TIMEOUT: Duration = Duration::from_secs(3);
const FAKE_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);

async fn spawn_real_server() -> (SocketAddr, Arc<StubBackend>) {
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

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NatPmpEvent>) -> NatPmpEvent {
    tokio::time::timeout(TIMEOUT, rx.recv())
        .await
        .expect("event before timeout")
        .expect("channel open")
}

#[tokio::test]
async fn dual_pair_maps_both_slots_of_one_port_on_the_real_allocator() {
    let (server, backend) = spawn_real_server().await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handle = spawn_refresh_loop_protos_from_addr(
        server,
        ForwardProtos::Both,
        27015,
        0,
        60,
        SuggestionKind::Pinned,
        tx,
        None,
    );

    let ev = next_event(&mut rx).await;
    let NatPmpEvent::Mapped { external_port, .. } = ev else {
        panic!("expected Mapped for the pair, got {ev:?}");
    };

    let active = backend.allocator().snapshot_active();
    assert_eq!(active.len(), 2, "one allocator entry per leg: {active:?}");
    assert!(
        active
            .iter()
            .all(|a| a.external_port == external_port && a.internal_port == 27015),
        "both legs must share the granted port: {active:?}"
    );
    let mut protos: Vec<Proto> = active.iter().map(|a| a.proto).collect();
    protos.sort_by_key(|p| *p == Proto::Udp);
    assert_eq!(protos, vec![Proto::Tcp, Proto::Udp]);

    // Releasing the handle frees BOTH slots on the exit.
    handle.release().await;
    assert_eq!(
        backend.allocator().active_count(),
        0,
        "release must free both legs"
    );
}

#[tokio::test]
async fn dual_pair_pinned_on_a_foreign_port_fails_whole_and_leaves_owner_intact() {
    let (server, backend) = spawn_real_server().await;
    // Another client already owns the pinned port through its UDP slot.
    let other = Ipv4Addr::new(10, 66, 0, 99);
    let taken = backend
        .allocator()
        .allocate(other, Proto::Udp, 5000, 50000, 600)
        .expect("foreign owner");
    assert_eq!(taken.external_port, 50000);

    let (tx, mut rx) = mpsc::unbounded_channel();
    let handle = spawn_refresh_loop_protos_from_addr(
        server,
        ForwardProtos::Both,
        27015,
        50000,
        60,
        SuggestionKind::Pinned,
        tx,
        None,
    );

    let ev = next_event(&mut rx).await;
    assert!(
        matches!(
            ev,
            NatPmpEvent::Failed {
                reason: NatPmpFailureReason::SuggestedPortInUse,
                ..
            }
        ),
        "the pair must fail as a unit on a foreign pinned port, got {ev:?}"
    );

    let active = backend.allocator().snapshot_active();
    assert_eq!(
        active.len(),
        1,
        "the foreign owner's mapping must survive untouched: {active:?}"
    );
    assert_eq!(active[0].internal_ip, other);
    let _ = handle;
}
