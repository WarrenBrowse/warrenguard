//! Integration tests for [`ExitConnPool`].
//!
//! The relay-side pool opens (and caches) the second-hop QUIC
//! connection. The tests spin up a fake exit endpoint on loopback so
//! the pool dials a real Warren-TLS RPK handshake.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use quinn::{Endpoint, VarInt};
use warrenguard_config::ALPN_H3;
use warrenguard_multihop::ExitId;
use warrenguard_relay::{
    ExitConnPool, ExitDescriptorSigned, ExitPoolError, exit_descriptor_signing_payload,
};
use warrenguard_tls::{default_crypto_provider, make_server_config};

fn det_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_bytes(k: &SigningKey) -> [u8; 32] {
    *k.verifying_key().as_bytes()
}

fn signed_descriptor_for(
    op: &SigningKey,
    exit_id: ExitId,
    exit_ed25519_pubkey: [u8; 32],
    endpoint: SocketAddr,
) -> ExitDescriptorSigned {
    let x25519 = [0x11; 32];
    let payload = exit_descriptor_signing_payload(exit_id, &x25519);
    let sig = op.sign(&payload);
    ExitDescriptorSigned {
        exit_id,
        exit_ed25519_pubkey,
        exit_x25519_multihop_pubkey: x25519,
        endpoint: Some(endpoint),
        cover_domain: None,
        signature: sig.to_bytes(),
        dns_disabled: false,
        exit_mlkem768_pubkey: None,
    }
}

/// Spawns a fake exit Quinn server bound on loopback. The accept loop
/// is held inside the returned struct so dropping it cleanly aborts
/// the background task even when a test panics.
struct FakeExit {
    addr: SocketAddr,
    _endpoint: Endpoint,
    accept_handle: tokio::task::JoinHandle<()>,
}

impl Drop for FakeExit {
    fn drop(&mut self) {
        self.accept_handle.abort();
    }
}

fn spawn_fake_exit(exit_key: &SigningKey) -> FakeExit {
    let provider = default_crypto_provider();
    let server_cfg =
        make_server_config(exit_key, provider, &[ALPN_H3]).expect("server config builds");
    let endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("fake exit binds");
    let addr = endpoint.local_addr().expect("local_addr");
    let listen_endpoint = endpoint.clone();
    let accept_handle = tokio::spawn(async move {
        // Hold every accepted connection alive until its remote side
        // closes. Collecting handles ensures the inner spawned tasks
        // are not orphaned across tests.
        let mut tasks = Vec::new();
        while let Some(incoming) = listen_endpoint.accept().await {
            tasks.push(tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        // Keep the connection alive until natural
                        // close on the remote side.
                        let _ = conn.closed().await;
                    }
                    Err(_e) => {
                        // Test-side will surface the handshake failure
                        // via its own assertions.
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    });
    FakeExit {
        addr,
        _endpoint: endpoint,
        accept_handle,
    }
}

fn build_pool() -> ExitConnPool {
    ExitConnPool::new((Ipv4Addr::LOCALHOST, 0).into()).expect("pool binds on loopback")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_creates_connection_on_first_use() {
    let op = det_signing_key(0x42);
    let exit_key = det_signing_key(0x55);
    let exit = spawn_fake_exit(&exit_key);

    let descriptor = signed_descriptor_for(
        &op,
        ExitId::from_bytes([0xAA; 16]),
        pubkey_bytes(&exit_key),
        exit.addr,
    );

    let pool = build_pool();
    assert_eq!(pool.cached_entry_count(), 0);

    let conn = pool
        .get_or_create(&descriptor)
        .await
        .expect("first get_or_create dials and succeeds");
    assert!(
        conn.close_reason().is_none(),
        "fresh connection must be alive"
    );
    assert_eq!(pool.cached_entry_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_reuses_alive_connection_on_second_lookup() {
    let op = det_signing_key(0x42);
    let exit_key = det_signing_key(0x55);
    let exit = spawn_fake_exit(&exit_key);

    let descriptor = signed_descriptor_for(
        &op,
        ExitId::from_bytes([0xAA; 16]),
        pubkey_bytes(&exit_key),
        exit.addr,
    );

    let pool = build_pool();

    let first = pool.get_or_create(&descriptor).await.expect("first dial");
    let second = pool
        .get_or_create(&descriptor)
        .await
        .expect("second lookup hits cache");

    // Pointer equality: the pool must return the same Arc on cache hit.
    assert!(
        Arc::ptr_eq(&first, &second),
        "cache hit must return the same Arc<Connection>"
    );
    assert_eq!(pool.cached_entry_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_recreates_connection_after_remote_close() {
    let op = det_signing_key(0x42);
    let exit_key = det_signing_key(0x55);
    let exit = spawn_fake_exit(&exit_key);

    let descriptor = signed_descriptor_for(
        &op,
        ExitId::from_bytes([0xAA; 16]),
        pubkey_bytes(&exit_key),
        exit.addr,
    );

    let pool = build_pool();

    let first = pool.get_or_create(&descriptor).await.expect("first dial");
    // Force-close the connection from the client side.
    first.close(VarInt::from_u32(0), b"test close");
    // Wait until the close has propagated to `close_reason()`.
    let _ = tokio::time::timeout(Duration::from_secs(2), first.closed()).await;

    let second = pool
        .get_or_create(&descriptor)
        .await
        .expect("post-close dial");
    assert!(
        !Arc::ptr_eq(&first, &second),
        "stale entry must be replaced after remote close"
    );
    assert!(second.close_reason().is_none(), "fresh second is alive");
    assert_eq!(pool.cached_entry_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_rejects_exit_with_wrong_rpk_at_handshake() {
    let op = det_signing_key(0x42);
    let real_exit_key = det_signing_key(0x55);
    let _fake_exit_key = det_signing_key(0x66);
    let exit = spawn_fake_exit(&real_exit_key);

    // Descriptor advertises the *wrong* RPK: relay pins
    // _fake_exit_key but the server presents real_exit_key. The
    // warren-tls SNI-vs-RPK verifier must reject this.
    let descriptor = signed_descriptor_for(
        &op,
        ExitId::from_bytes([0xAA; 16]),
        pubkey_bytes(&_fake_exit_key),
        exit.addr,
    );

    let pool = build_pool();

    let err = pool
        .get_or_create(&descriptor)
        .await
        .expect_err("RPK mismatch must reject");
    assert!(
        matches!(err, ExitPoolError::Handshake(_)),
        "expected Handshake error, got {err:?}"
    );
    assert_eq!(
        pool.cached_entry_count(),
        0,
        "failed dial must not pollute the cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_rejects_a_redacted_descriptor_with_no_endpoint() {
    // The client-facing directory redacts `endpoint` (censorship
    // minimization, cf. `ExitDescriptorSigned::endpoint` docs). A relay must
    // never be handed such a descriptor, but if it is, the pool must fail
    // closed with `MissingEndpoint` rather than panicking or silently
    // dialing nowhere.
    let op = det_signing_key(0x42);
    let exit_key = det_signing_key(0x55);
    let descriptor = ExitDescriptorSigned {
        endpoint: None,
        ..signed_descriptor_for(
            &op,
            ExitId::from_bytes([0xCC; 16]),
            pubkey_bytes(&exit_key),
            "10.0.0.1:443".parse().expect("static addr parses"),
        )
    };

    let pool = build_pool();
    let err = pool
        .get_or_create(&descriptor)
        .await
        .expect_err("a redacted (endpoint = None) descriptor must reject");
    assert!(
        matches!(err, ExitPoolError::MissingEndpoint),
        "expected MissingEndpoint, got {err:?}"
    );
    assert_eq!(
        pool.cached_entry_count(),
        0,
        "a failed dial must not pollute the cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn is_cached_reports_hit_after_get_or_create_and_false_before() {
    let op = det_signing_key(0x42);
    let exit_key = det_signing_key(0x55);
    let exit = spawn_fake_exit(&exit_key);
    let exit_id = ExitId::from_bytes([0xAA; 16]);

    let descriptor = signed_descriptor_for(&op, exit_id, pubkey_bytes(&exit_key), exit.addr);

    let pool = build_pool();
    assert!(
        !pool.is_cached(&exit_id),
        "an empty pool must report no cached entry"
    );

    pool.get_or_create(&descriptor).await.expect("first dial");
    assert!(
        pool.is_cached(&exit_id),
        "is_cached must report true immediately after get_or_create populated the cache"
    );
    assert!(
        !pool.is_cached(&ExitId::from_bytes([0xFF; 16])),
        "is_cached must not report true for a different, never-dialed exit_id"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_concurrent_get_or_create_yields_a_single_connection() {
    let op = det_signing_key(0x42);
    let exit_key = det_signing_key(0x55);
    let exit = spawn_fake_exit(&exit_key);

    let descriptor = signed_descriptor_for(
        &op,
        ExitId::from_bytes([0xAA; 16]),
        pubkey_bytes(&exit_key),
        exit.addr,
    );

    let pool = Arc::new(build_pool());

    // Fire ten concurrent get_or_create calls. Even if some races
    // lose, the final cache must hold a single live entry. This
    // exercises the double-checked-insert path in the pool.
    let mut handles = Vec::with_capacity(10);
    for _ in 0..10 {
        let p = pool.clone();
        let d = descriptor.clone();
        handles.push(tokio::spawn(async move { p.get_or_create(&d).await }));
    }
    for h in handles {
        h.await
            .expect("task did not panic")
            .expect("each call completes");
    }
    assert_eq!(
        pool.cached_entry_count(),
        1,
        "pool must converge to a single cached entry"
    );
}
