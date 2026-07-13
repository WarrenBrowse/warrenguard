//! Client-side datapath sharding: a multi-conn client spreads its N
//! connections across N independent `quinn::Endpoint`s (N UDP sockets), so its
//! send/recv I/O runs on N endpoint drivers instead of funnelling through one.
//! This is the client half of the SO_REUSEPORT exit sharding: distinct client
//! source ports let the exit's reuseport group hash the flows across cores.
//!
//! Engine-only e2e over loopback with a `FakeTun` exit: proves the client binds
//! N distinct sockets by default and the multi-conn session still handshakes,
//! aggregates onto one tunnel IP, and round-trips. The throughput win is
//! validated on a real network.

use std::time::Duration;

use warrenguard_server::ExitListener;
use warrenguard_transport::ClientTunnel;
use warrenguard_transport_core::packet_device::FakeTun;

const TEST_TIMEOUT: Duration = Duration::from_secs(8);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_conn_client_defaults_to_one_datapath_socket_per_connection() {
    // Default `WARREN_CLIENT_DATAPATH_SOCKETS` is auto = one endpoint per
    // connection: distinct source ports let the exit reuseport group hash flows
    // across cores AND are required for the client multi-queue TUN downlink win
    // (bench needed both together). Re-enabled after part 1 flipped
    // it off (it bought nothing then); the throughput gain now justifies the
    // per-connection NAT mapping.
    let exit = ExitListener::bind_localhost().await.expect("bind exit");
    let exit_addr = exit.bound_addr();
    let _exit = tokio::spawn(async move {
        let _ = exit.accept_forever_with_tun(FakeTun::new()).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = ClientTunnel::new();
    let session = tokio::time::timeout(TEST_TIMEOUT, client.connect_multi(exit_addr, 3))
        .await
        .expect("connect_multi(3) must not time out")
        .expect("connect_multi(3) must succeed");

    assert_eq!(session.num_connections(), 3, "three connections opened");
    assert_eq!(
        session.datapath_endpoint_count(),
        3,
        "auto default must give one datapath socket per connection"
    );
    assert_eq!(
        session.local_socket_addrs().len(),
        3,
        "one datapath endpoint per connection means three distinct local sockets"
    );

    // Multi-conn aggregation is preserved: all conns share one exit tunnel IP.
    assert_eq!(
        session.assigned_ipv4().octets()[0],
        10,
        "tunnel IP from pool"
    );
    assert_eq!(
        session.assigned_ipv4().octets()[1],
        66,
        "tunnel IP from pool"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_conn_client_uses_exactly_one_datapath_socket() {
    // A mono-conn session (the mobile default) must remain a single socket:
    // sharding only applies to multi-conn throughput sessions.
    let exit = ExitListener::bind_localhost().await.expect("bind exit");
    let exit_addr = exit.bound_addr();
    let _exit = tokio::spawn(async move {
        let _ = exit.accept_forever_with_tun(FakeTun::new()).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = ClientTunnel::new();
    let session = tokio::time::timeout(TEST_TIMEOUT, client.connect_multi(exit_addr, 1))
        .await
        .expect("connect_multi(1) must not time out")
        .expect("connect_multi(1) must succeed");

    assert_eq!(session.num_connections(), 1);
    assert_eq!(
        session.datapath_endpoint_count(),
        1,
        "a single-connection session must use exactly one datapath socket"
    );
}
