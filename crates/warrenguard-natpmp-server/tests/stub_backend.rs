//! `StubBackend` implements `PortForwardingBackend` and delegates
//! to the internal allocator.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use warrenguard_natpmp_server::allocator::Allocator;
use warrenguard_natpmp_server::stub_backend::StubBackend;
use warrenguard_natpmp_server::{PortForwardingBackend, Proto};

#[tokio::test]
async fn stub_allocate_returns_allocation_for_client_ip() {
    let backend = StubBackend::new();
    let client = Ipv4Addr::new(10, 66, 0, 7);
    let alloc = backend
        .allocate(client, Proto::Tcp, 0, 0, Duration::from_secs(600))
        .await
        .expect("nominal alloc");
    assert_eq!(alloc.internal_ip, client);
    assert_eq!(alloc.proto, Proto::Tcp);
    assert!(
        (49152..=65535).contains(&alloc.external_port),
        "port {} out of range",
        alloc.external_port
    );
}

#[tokio::test]
async fn stub_consecutive_allocs_yield_distinct_ports() {
    // This test passes `suggested=0` (no preference) → the allocator
    // picks at random. 4 consecutive allocations (under the 5/min
    // rate-limit) must yield distinct ports. With a single shared
    // allocator we expect 4 distinct active ports.
    //
    // Quota disabled here: this test exercises port rotation, not
    // the per-client cap (which has its own dedicated tests in
    // `tests/allocator.rs`).
    let allocator = Arc::new(Allocator::with_config(
        (49152, 65535),
        Duration::from_secs(300),
        100, // generous rate limit
        Duration::from_secs(60),
    ));
    let backend = StubBackend::with_allocator(allocator);
    let client = Ipv4Addr::new(10, 66, 0, 7);
    let mut ports = Vec::with_capacity(4);
    for i in 0..4u16 {
        // Distinct internal ports so each is a separate mapping. A
        // re-MAP of the SAME (client, internal_port, proto) tuple is
        // now a refresh (RFC 6886 §3.3) that replaces rather than
        // stacks; to exercise 4 PARALLEL mappings the internal ports
        // must differ.
        let a = backend
            .allocate(client, Proto::Tcp, 8000 + i, 0, Duration::from_secs(600))
            .await
            .expect("alloc ok");
        ports.push(a.external_port);
    }
    let unique: std::collections::HashSet<_> = ports.iter().collect();
    assert_eq!(
        unique.len(),
        ports.len(),
        "expected random rotation, ports = {ports:?}"
    );
    assert_eq!(
        backend.allocator().active_count(),
        4,
        "the 4 mappings must be active in parallel"
    );
}

#[tokio::test]
async fn stub_release_clears_active_count() {
    let backend = StubBackend::new();
    let client = Ipv4Addr::new(10, 66, 0, 7);
    let alloc = backend
        .allocate(client, Proto::Udp, 0, 0, Duration::from_secs(600))
        .await
        .expect("alloc");
    assert_eq!(backend.allocator().active_count(), 1);

    backend.release(&alloc).await.expect("release");
    assert_eq!(backend.allocator().active_count(), 0);
}
