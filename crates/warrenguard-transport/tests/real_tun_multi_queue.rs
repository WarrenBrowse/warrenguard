//! Real-device multi-queue TUN tests (`IFF_MULTI_QUEUE`).
//!
//! These create an actual kernel TUN, so they need `CAP_NET_ADMIN` /
//! root and a Linux host with multi-queue support. They are `#[ignore]`
//! by default and run manually on a real exit:
//!
//! ```sh
//! sudo -E cargo test -p warrenguard-transport --test real_tun_multi_queue -- --ignored --nocapture
//! ```
//!
//! The datapath throughput win these queues unlock is validated
//! separately by a cloud bench.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;

use warrenguard_transport::RealTun;

#[tokio::test]
#[ignore = "needs root + a real Linux TUN with IFF_MULTI_QUEUE"]
async fn multi_queue_opens_n_independent_queues_on_one_interface() {
    // Four queues on one interface: the kernel must accept the primary
    // (IFF_MULTI_QUEUE) plus three try_clone'd fds, all named the same.
    let queues = RealTun::create_multi_queue_named(
        "wgmq0",
        Ipv4Addr::new(10, 66, 0, 1),
        16,
        None,
        0,
        1280,
        true, // offload: every cloned queue must stay offload-capable
        4,
    )
    .await
    .expect("create 4 multi-queue TUN queues (needs root)");

    assert_eq!(queues.len(), 4, "requested 4 queues, must open exactly 4");
    for q in &queues {
        assert_eq!(q.name(), "wgmq0", "every queue attaches to one interface");
        assert!(q.is_offloaded(), "each cloned queue keeps offload enabled");
    }
}

#[tokio::test]
#[ignore = "needs root + a real Linux TUN"]
async fn single_queue_request_returns_exactly_one() {
    // queues = 1 is the historic single-queue path: no IFF_MULTI_QUEUE,
    // exactly one handle, regardless of platform capability.
    let queues = RealTun::create_multi_queue_named(
        "wgmq1",
        Ipv4Addr::new(10, 66, 0, 1),
        16,
        None,
        0,
        1280,
        true,
        1,
    )
    .await
    .expect("create single-queue TUN (needs root)");

    assert_eq!(queues.len(), 1, "a single-queue request yields one handle");
}
