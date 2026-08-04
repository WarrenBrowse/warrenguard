//! The refresh loop presents a credential on every request it makes.
//!
//! A port entitlement buys one forwarded port (internal warren-core doc 99), and the
//! exit spends it on presentation. Two properties the loop owes that design:
//! every leg of a cycle carries the SAME credential (a TCP+UDP pair is one
//! port, so it must not read as two), and a credential that has rotated
//! reaches the next renewal (an entitlement is valid for its own epoch only,
//! so a mapping outliving one epoch has to present the next one).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use warrenguard_natpmp_client::{
    ForwardProtos, NatPmpEvent, RefreshLoopConfig, SuggestionKind, spawn_refresh_loop_with,
};
use warrenguard_natpmp_protocol::credential_trailer;

const TIMEOUT: Duration = Duration::from_secs(5);

/// Records every request and answers Success, echoing the request's opcode so
/// a dual-proto cycle sees a matching response on each leg. `lifetime_secs`
/// drives the loop's renewal delay (`lifetime / 2`, floored at 1 s).
async fn stub_server(seen: Arc<Mutex<Vec<Vec<u8>>>>, lifetime_secs: u32) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = sock.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let frame = buf[..n].to_vec();
            let op = frame.get(1).copied().unwrap_or(1);
            let internal = [frame[4], frame[5]];
            seen.lock().expect("sink").push(frame);
            let lt = lifetime_secs.to_be_bytes();
            let resp = [
                0x00,
                0x80 | op,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x2A,
                internal[0],
                internal[1],
                0xC3,
                0x50,
                lt[0],
                lt[1],
                lt[2],
                lt[3],
            ];
            let _ = sock.send_to(&resp, peer).await;
        }
    });
    addr
}

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NatPmpEvent>) -> NatPmpEvent {
    tokio::time::timeout(TIMEOUT, rx.recv())
        .await
        .expect("event before timeout")
        .expect("channel open")
}

#[tokio::test]
async fn every_leg_of_a_cycle_presents_the_same_credential() {
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let addr = stub_server(Arc::clone(&seen), 600).await;

    let credential = vec![0x5Au8; 300];
    let handed = credential.clone();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handle = spawn_refresh_loop_with(
        RefreshLoopConfig {
            server: addr,
            protos: ForwardProtos::Both,
            internal_port: 8080,
            suggested_external_port: 50000,
            lifetime_secs: 600,
            suggestion: SuggestionKind::Pinned,
            bind_addr: None,
            credential: Some(Arc::new(move || Some(handed.clone()))),
        },
        tx,
    );

    assert!(matches!(
        next_event(&mut rx).await,
        NatPmpEvent::Mapped { .. }
    ));
    handle.cancel();

    let frames = seen.lock().expect("sink").clone();
    assert_eq!(frames.len(), 2, "a Both cycle is two requests: {frames:?}");
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(
            credential_trailer(frame),
            Some(credential.as_slice()),
            "leg {i} presented no credential, or the wrong one",
        );
    }
}

#[tokio::test]
async fn a_rotated_credential_reaches_the_next_renewal() {
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    // lifetime 2 s => the loop renews after 1 s, so the rotation is observable
    // without a long test.
    let addr = stub_server(Arc::clone(&seen), 2).await;

    let calls = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&calls);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handle = spawn_refresh_loop_with(
        RefreshLoopConfig {
            server: addr,
            protos: ForwardProtos::Tcp,
            internal_port: 8080,
            suggested_external_port: 50000,
            lifetime_secs: 600,
            suggestion: SuggestionKind::Pinned,
            bind_addr: None,
            credential: Some(Arc::new(move || {
                let mut n = counter.lock().expect("counter");
                *n += 1;
                Some(vec![u8::try_from(*n).expect("small"); 8])
            })),
        },
        tx,
    );

    assert!(matches!(
        next_event(&mut rx).await,
        NatPmpEvent::Mapped { .. }
    ));
    assert!(matches!(
        next_event(&mut rx).await,
        NatPmpEvent::Renewed { .. }
    ));
    handle.cancel();

    let frames = seen.lock().expect("sink").clone();
    assert!(frames.len() >= 2, "expected a renewal: {frames:?}");
    assert_eq!(credential_trailer(&frames[0]), Some([1u8; 8].as_slice()));
    assert_eq!(
        credential_trailer(&frames[1]),
        Some([2u8; 8].as_slice()),
        "the renewal re-used the first credential instead of asking again",
    );
}

#[tokio::test]
async fn no_provider_means_no_trailer() {
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let addr = stub_server(Arc::clone(&seen), 600).await;

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut handle = spawn_refresh_loop_with(
        RefreshLoopConfig {
            server: addr,
            protos: ForwardProtos::Tcp,
            internal_port: 8080,
            suggested_external_port: 50000,
            lifetime_secs: 600,
            suggestion: SuggestionKind::Pinned,
            bind_addr: None,
            credential: None,
        },
        tx,
    );
    assert!(matches!(
        next_event(&mut rx).await,
        NatPmpEvent::Mapped { .. }
    ));
    handle.cancel();

    let frames = seen.lock().expect("sink").clone();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].len(), 12, "an RFC request and nothing else");
    assert_eq!(credential_trailer(&frames[0]), None);
}
