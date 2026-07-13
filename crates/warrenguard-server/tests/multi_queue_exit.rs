//! Multi-queue exit datapath: the exit runs one TUN downlink reader per
//! kernel queue and spreads per-connection uplink writes across queues, so
//! the single-TUN-queue serialization point that `SO_REUSEPORT` endpoint
//! sharding leaves in place is removed.
//!
//! Engine-only over loopback with in-memory `FakeTun` queues: proves the
//! fan-out ORCHESTRATION (N reader tasks, one per queue, all delivering to
//! the client) without a real kernel TUN. The throughput win from real
//! `IFF_MULTI_QUEUE` queues is validated on a multi-core cloud exit, not
//! here.

use std::net::Ipv4Addr;
use std::time::Duration;

use warrenguard_server::ExitListener;
use warrenguard_transport::ClientTunnel;
use warrenguard_transport_core::packet_device::FakeTun;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A minimal 40-byte IPv4/TCP packet from the exit gateway to `dst`, tagged
/// by `src_port` so two packets are distinguishable on arrival.
fn ipv4_downlink(dst: Ipv4Addr, src_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45; // IPv4, IHL 5
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[10, 66, 0, 1]); // src = gateway
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
    pkt
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downlink_reads_from_every_queue_and_delivers_to_the_client() {
    // Two distinct TUN queues back the exit. A packet injected into EACH
    // queue, destined to the client's tunnel IP, must reach the client. If
    // only the first queue had a reader task, the packet injected into the
    // second queue would never be dispatched and the client would receive
    // only one datagram: the assertion on receiving BOTH is what proves one
    // reader per queue.
    let q0 = FakeTun::new();
    let q1 = FakeTun::new();

    let exit = ExitListener::bind_localhost().await.expect("bind exit");
    let exit_addr = exit.bound_addr();
    let queues = vec![q0.clone(), q1.clone()];
    let _exit = tokio::spawn(async move {
        let _ = exit.accept_forever_with_tun_queues(queues).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let node_key = warrenguard_identity::derive_node_key(&[0x51u8; 32]);
    let client = ClientTunnel::with_signing_key(&node_key);
    let session = tokio::time::timeout(TEST_TIMEOUT, client.connect(exit_addr))
        .await
        .expect("connect must not time out")
        .expect("handshake must succeed against the multi-queue exit");

    let assigned = session.assigned_ipv4();
    assert_eq!(assigned.octets()[0], 10, "tunnel IP from the pool");

    // Let the exit register this connection in the dispatch table (it
    // happens in the accept task right after the handshake the client just
    // observed complete).
    tokio::time::sleep(Duration::from_millis(200)).await;

    let pkt_q0 = ipv4_downlink(assigned, 1111);
    let pkt_q1 = ipv4_downlink(assigned, 2222);
    q0.inject_inbound(pkt_q0.clone());
    q1.inject_inbound(pkt_q1.clone());

    // Collect two downlink datagrams; each carries the full IP packet the
    // dispatcher read off its queue.
    let mut received = Vec::new();
    for _ in 0..2 {
        let dg = tokio::time::timeout(TEST_TIMEOUT, session.read_datagram())
            .await
            .expect("a downlink datagram must arrive from each queue")
            .expect("datagram read must not error");
        received.push(dg.to_vec());
    }

    assert!(
        received.contains(&pkt_q0),
        "the packet injected into queue 0 must be delivered"
    );
    assert!(
        received.contains(&pkt_q1),
        "the packet injected into queue 1 must be delivered (proves queue 1 has its own reader)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_queue_list_is_rejected() {
    // A caller must pass at least one queue: an empty Vec is a bug, not a
    // silently idle exit that accepts connections with no downlink.
    let exit = ExitListener::bind_localhost().await.expect("bind exit");
    let res = exit
        .accept_forever_with_tun_queues(Vec::<FakeTun>::new())
        .await;
    assert!(
        res.is_err(),
        "accept_forever_with_tun_queues must reject an empty queue list"
    );
}
