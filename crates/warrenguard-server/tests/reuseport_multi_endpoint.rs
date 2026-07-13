//! SO_REUSEPORT multi-endpoint exit datapath: several UDP sockets share the
//! one listen port so the kernel load-balances inbound QUIC flows across N
//! independent `quinn::Endpoint` drivers (one per core), breaking the
//! single-endpoint recv serialization that caps single-tunnel throughput.
//!
//! These are engine-only tests (no Warren backend): they prove the socket
//! layer (N sockets, one shared port) and that a real client still handshakes
//! and round-trips a datagram when the exit is sharded. The throughput win
//! itself is validated on a real multi-core exit (see the bench report), not
//! here.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use warrenguard_server::{ExitBindOpts, ExitListener};
use warrenguard_transport::ClientTunnel;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn localhost_v4_ephemeral() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

#[tokio::test]
async fn multi_endpoint_bind_shares_a_single_listen_port_across_n_sockets() {
    let opts = ExitBindOpts {
        datapath_sockets: 4,
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts(localhost_v4_ephemeral(), opts)
        .await
        .expect("multi-endpoint exit must bind");

    // N independent datapath sockets exist...
    assert_eq!(
        exit.datapath_socket_count(),
        4,
        "requested 4 datapath sockets, all must be bound"
    );

    // ...and SO_REUSEPORT means every one of them shares the SAME port (the
    // kernel 4-tuple-hashes inbound flows across them). A different port per
    // socket would mean the reuseport group never formed.
    let addrs = exit.local_socket_addrs();
    assert_eq!(addrs.len(), 4, "one local addr per datapath socket");
    let port = addrs[0].port();
    assert_ne!(port, 0, "an ephemeral port must have been resolved");
    assert!(
        addrs.iter().all(|a| a.port() == port),
        "all datapath sockets must share one listen port, got {addrs:?}"
    );
}

#[tokio::test]
async fn sharded_exit_still_handshakes_and_round_trips_a_datagram() {
    // A 3-socket exit must remain functionally a single exit from the client's
    // point of view: it dials the one shared port, the kernel routes its flow
    // to whichever endpoint owns that 4-tuple, and the handshake + datagram
    // echo work exactly as on a single-socket exit.
    let opts = ExitBindOpts {
        datapath_sockets: 3,
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts(localhost_v4_ephemeral(), opts)
        .await
        .expect("sharded exit must bind");
    let exit_addr = exit.bound_addr();

    let response = b"warrenguard-reuseport-pong".to_vec();
    let response_for_exit = response.clone();
    let exit_task =
        tokio::spawn(async move { exit.echo_one_datagram_with(response_for_exit).await });

    let node_key = warrenguard_identity::derive_node_key(&[0x22u8; 32]);
    let client = ClientTunnel::with_signing_key(&node_key);
    let session = tokio::time::timeout(TEST_TIMEOUT, client.connect(exit_addr))
        .await
        .expect("connect must not time out")
        .expect("the sharded exit must complete the handshake");

    let assigned = session.assigned_ipv4();
    assert_eq!(assigned.octets()[0], 10, "tunnel IP from the pool");
    assert_eq!(assigned.octets()[1], 66, "tunnel IP from the pool");

    session
        .send_datagram(b"warrenguard-reuseport-ping".to_vec())
        .expect("send a datagram through the sharded tunnel");
    let echoed = tokio::time::timeout(TEST_TIMEOUT, session.read_datagram())
        .await
        .expect("recv must not time out")
        .expect("the sharded exit must echo the datagram back");
    assert_eq!(
        echoed.as_ref(),
        &response[..],
        "the sharded tunnel must carry the payload byte-for-byte"
    );

    tokio::time::timeout(TEST_TIMEOUT, exit_task)
        .await
        .expect("exit task must finish")
        .expect("exit task must not panic")
        .expect("exit echo must succeed");
}

#[tokio::test]
async fn default_bind_opts_keep_a_single_datapath_socket() {
    // Back-compat guard: the engine default is exactly one socket, so nothing
    // changes for existing deployers/tests until they opt into sharding.
    let exit = ExitListener::bind_localhost()
        .await
        .expect("default exit must bind");
    assert_eq!(
        exit.datapath_socket_count(),
        1,
        "the default datapath must remain a single socket"
    );
}
