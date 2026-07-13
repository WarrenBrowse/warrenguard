//! `PortForwardingBackend::release_by_client` is exposed on the
//! public trait so the `Server` can release by (client_ip, port,
//! proto) without knowing the concrete backend impl.
//!
//! Verified on both existing impls (StubBackend, NftablesBackend
//! with a mock executor) to ensure the trait extension was not
//! missed on either side.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use warrenguard_natpmp_server::nftables::{NftExecutor, NftablesBackend};
use warrenguard_natpmp_server::stub_backend::StubBackend;
use warrenguard_natpmp_server::{PortForwardingBackend, Proto};

const ALICE: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 7);
const BOB: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 99);

/// No-op recorder for NftablesBackend tests.
struct NoopExec(Mutex<Vec<String>>);
impl NoopExec {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Vec::new())))
    }
}
impl NftExecutor for NoopExec {
    fn run_script(&self, s: &str) -> impl std::future::Future<Output = Result<(), String>> + Send {
        self.0.lock().push(s.to_string());
        async { Ok(()) }
    }
}

#[tokio::test]
async fn stub_backend_implements_release_by_client_via_trait() {
    let backend = StubBackend::new();
    let internal_port = 8080;
    let _alloc = backend
        .allocate(
            ALICE,
            Proto::Tcp,
            internal_port,
            0,
            Duration::from_secs(600),
        )
        .await
        .expect("alloc");

    // Trait call (RFC §3.3.2: pass internal_port, not external).
    let released: bool =
        PortForwardingBackend::release_by_client(&backend, ALICE, internal_port, Proto::Tcp).await;
    assert!(released, "Stub must release a mapping it allocated");
    assert_eq!(backend.allocator().active_count(), 0);
}

#[tokio::test]
async fn nftables_backend_implements_release_by_client_via_trait() {
    let runner = NoopExec::new();
    let backend = NftablesBackend::new(Arc::clone(&runner))
        .await
        .expect("setup");
    let internal_port = 8080;
    let _alloc = backend
        .allocate(
            ALICE,
            Proto::Udp,
            internal_port,
            0,
            Duration::from_secs(600),
        )
        .await
        .expect("alloc");

    let released =
        PortForwardingBackend::release_by_client(&backend, ALICE, internal_port, Proto::Udp).await;
    assert!(released, "Nftables must release a mapping it allocated");
    assert_eq!(backend.allocator().active_count(), 0);

    // The nftables backend must also have emitted a delete element
    // script.
    let scripts = runner.0.lock().clone();
    assert!(
        scripts.iter().any(|s| s.contains("delete element")),
        "release_by_client must emit a delete script, got {scripts:?}"
    );
}

#[tokio::test]
async fn release_by_client_rejects_other_clients_request_via_trait() {
    // Security: Bob cannot release Alice's port through the trait,
    // regardless of the concrete backend.
    let backend = StubBackend::new();
    let internal_port = 8080;
    let _alloc = backend
        .allocate(
            ALICE,
            Proto::Tcp,
            internal_port,
            0,
            Duration::from_secs(600),
        )
        .await
        .expect("alice alloc");

    let released =
        PortForwardingBackend::release_by_client(&backend, BOB, internal_port, Proto::Tcp).await;
    assert!(!released, "Bob must not be able to release Alice's port");
    assert_eq!(backend.allocator().active_count(), 1);
}
