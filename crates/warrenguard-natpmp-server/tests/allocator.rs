//! Allocator tests - port-forwarding pool with abuse mitigations.
//!
//! Each test injects its own `Instant` through `allocate_at` /
//! `release_at` to simulate time passing without blocking the test
//! runtime.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use warrenguard_natpmp_server::allocator::Allocator;
use warrenguard_natpmp_server::{NatPmpError, Proto};

const ALICE: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 42);
const BOB: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 99);
/// A second live session of ALICE's tenant: the exit places it on its own
/// inner address, so the allocator sees two "clients" for one subscriber.
const ALICE_SECOND_SESSION: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 43);

// ---------------------------------------------------------------------------
// Nominal allocation
// ---------------------------------------------------------------------------

#[test]
fn allocate_returns_port_in_range() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 0, 0, 600, now)
        .expect("nominal alloc");
    assert!(
        (49152..=65535).contains(&a.external_port),
        "port {} outside IANA ephemeral range",
        a.external_port
    );
    assert_eq!(a.internal_ip, ALICE);
    assert_eq!(a.proto, Proto::Tcp);
    assert_eq!(alloc.active_count(), 1);
}

#[test]
fn allocate_honors_suggested_port_when_free() {
    let alloc = Allocator::new();
    let a = alloc
        .allocate_at(ALICE, Proto::Udp, 0, 49200, 600, Instant::now())
        .expect("alloc with suggested");
    assert_eq!(
        a.external_port, 49200,
        "the suggested port must be honored when free"
    );
}

#[test]
fn refresh_keeps_same_external_port_without_explicit_suggestion() {
    // RFC 6886 refresh semantics: re-MAPping the same (client,
    // internal_port, proto) tuple with no explicit suggestion must
    // renew the SAME external port, not rotate to a fresh random one.
    // Rotating on every ~30 min renewal would silently break any
    // long-lived self-hosted service behind the mapping.
    let alloc = Allocator::new();
    let now = Instant::now();
    // 1 h lifetime, refreshed at the half-life (the real client
    // cadence) - i.e. while the mapping is still active, before the
    // lazy expiry sweep would reclaim it.
    let first = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 0, 3600, now)
        .expect("first alloc");
    let refreshed = alloc
        .allocate_at(
            ALICE,
            Proto::Tcp,
            8080,
            0,
            3600,
            now + Duration::from_secs(1800),
        )
        .expect("refresh");
    assert_eq!(
        refreshed.external_port, first.external_port,
        "a refresh with no explicit suggestion must keep the same external port"
    );
    assert_eq!(
        alloc.active_count(),
        1,
        "a refresh must replace the mapping, not stack a second one"
    );
}

#[test]
fn refresh_moves_to_a_new_explicit_suggestion() {
    // If the client changes its mind and supplies a new (free,
    // in-range) suggestion on refresh, the explicit suggestion wins
    // over the previously-held port.
    let alloc = Allocator::new();
    let now = Instant::now();
    let first = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 0, 600, now)
        .expect("first alloc");
    let moved = alloc
        .allocate_at(
            ALICE,
            Proto::Tcp,
            8080,
            50_123,
            600,
            now + Duration::from_secs(60),
        )
        .expect("refresh with new suggestion");
    assert_eq!(moved.external_port, 50_123);
    assert_ne!(moved.external_port, first.external_port);
    assert_eq!(alloc.active_count(), 1);
}

#[test]
fn two_concurrent_allocations_yield_different_ports() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 0, 0, 600, now)
        .expect("alloc 1");
    let b = alloc
        .allocate_at(BOB, Proto::Tcp, 0, 0, 600, now)
        .expect("alloc 2");
    assert_ne!(
        a.external_port, b.external_port,
        "two distinct clients must get distinct ports"
    );
}

// ---------------------------------------------------------------------------
// 5 min cooldown after release
// ---------------------------------------------------------------------------

#[test]
fn released_port_is_in_cooldown_for_300s() {
    // Short cooldown (3s) so the test does not actually sleep - we
    // simulate via the injected Instant.
    let alloc = Allocator::with_config(
        (50000, 50000), // minimal range: a single available port
        Duration::from_secs(3),
        100, // generous rate limit so it does not interfere
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    // Alice grabs port 50000.
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 0, 0, 600, t0)
        .expect("alice alloc");
    assert_eq!(a.external_port, 50000);

    // Alice releases.
    alloc.release_at(&a, t0 + Duration::from_secs(1));

    // Bob (different client) asks immediately: must fail with
    // Exhausted (port in cooldown, and it is the only one in range).
    let res = alloc.allocate_at(BOB, Proto::Tcp, 0, 0, 600, t0 + Duration::from_secs(2));
    assert!(
        matches!(res, Err(NatPmpError::Exhausted)),
        "port in cooldown must be unavailable, got {res:?}"
    );

    // After cooldown expiry (>3s after release), Bob can have it.
    let bob_later = alloc
        .allocate_at(BOB, Proto::Tcp, 0, 0, 600, t0 + Duration::from_secs(10))
        .expect("after cooldown, Bob can take the port");
    assert_eq!(bob_later.external_port, 50000);
}

// ---------------------------------------------------------------------------
// Anti-predictable-rotation: a port does not return to its previous owner
// ---------------------------------------------------------------------------

#[test]
fn port_does_not_return_to_same_user_back_to_back() {
    // 2 ports in the range. Alice grabs one, releases it, asks again
    // immediately: she must receive the OTHER port, not her previous.
    let alloc = Allocator::with_config(
        (50000, 50001),
        Duration::from_secs(3600), // long cooldown to exercise anti-rotation
        100,
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    let first = alloc
        .allocate_at(ALICE, Proto::Tcp, 0, 0, 600, t0)
        .expect("alloc 1");
    let alice_first_port = first.external_port;

    alloc.release_at(&first, t0 + Duration::from_secs(1));

    let second = alloc
        .allocate_at(ALICE, Proto::Tcp, 0, 0, 600, t0 + Duration::from_secs(2))
        .expect("alloc 2");
    assert_ne!(
        second.external_port, alice_first_port,
        "Alice must not get her former port immediately back (anti-rotation)"
    );
}

// ---------------------------------------------------------------------------
// Explicit suggestion: strict honour-or-error + owner reclaim
// ---------------------------------------------------------------------------

#[test]
fn owner_reclaims_its_own_pinned_port_within_cooldown() {
    // Regression for "I pin a port, the live port-change releases then
    // re-requests it, and I get a RANDOM port until the next renewal":
    // an EXPLICIT suggestion for the client's OWN just-released port
    // must be honoured immediately, bypassing that client's own
    // post-release cooldown. The cooldown only guards against OTHER
    // clients inheriting the port - never the owner asking for it back.
    let alloc = Allocator::with_config(
        (50000, 50005),
        Duration::from_secs(3600), // long cooldown, to prove the bypass
        100,
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    let first = alloc
        .allocate_at(ALICE, Proto::Udp, 0, 50000, 600, t0)
        .expect("alloc pinned 50000");
    assert_eq!(first.external_port, 50000);

    alloc.release_at(&first, t0 + Duration::from_secs(1));

    // Re-pin the SAME port well within the (1 h) cooldown window.
    let again = alloc
        .allocate_at(
            ALICE,
            Proto::Udp,
            0,
            50000,
            600,
            t0 + Duration::from_secs(2),
        )
        .expect("owner must reclaim its own pinned port immediately");
    assert_eq!(
        again.external_port, 50000,
        "owner must get its explicitly-requested port back, not a substitute"
    );
}

#[test]
fn explicit_suggestion_held_by_another_client_is_rejected_strictly() {
    // Strict honour-or-error: if the pinned port is genuinely held by a
    // DIFFERENT client, the request fails with SuggestedPortInUse (so
    // the UI can say "port already in use") rather than silently
    // substituting a random port.
    let alloc = Allocator::new();
    let now = Instant::now();

    let a = alloc
        .allocate_at(ALICE, Proto::Udp, 0, 50000, 600, now)
        .expect("Alice pins 50000");
    assert_eq!(a.external_port, 50000);

    let err = alloc
        .allocate_at(BOB, Proto::Udp, 0, 50000, 600, now)
        .expect_err("Bob must not silently get a substitute for Alice's active port");
    assert!(
        matches!(err, NatPmpError::SuggestedPortInUse(50000)),
        "expected SuggestedPortInUse(50000), got {err:?}"
    );
}

#[test]
fn follow_conflict_rejects_and_preserves_holders_mapping() {
    // Port-follow conflict across an exit change. Client X (ALICE)
    // currently holds external port P on this exit. A different client Y
    // (BOB) tries to follow the same pinned port P here. The strict
    // honour-or-error pre-check runs BEFORE any state mutation, so it
    // must reject Y with SuggestedPortInUse(P) AND leave X's live
    // mapping byte-for-byte untouched (X keeps forwarding). A regression
    // that silently substituted a port for Y, or evicted X's mapping
    // while serving Y, would break the holder. The existing
    // strict-rejection test only checks the error; this one pins the
    // "holder survives" invariant the follow feature depends on.
    let alloc = Allocator::new();
    let now = Instant::now();

    let held = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 50000, 600, now)
        .expect("Alice pins 50000");
    assert_eq!(held.external_port, 50000);

    let err = alloc
        .allocate_at(BOB, Proto::Tcp, 9090, 50000, 600, now)
        .expect_err("Bob must be rejected, not granted a substitute for Alice's held port");
    assert!(
        matches!(err, NatPmpError::SuggestedPortInUse(50000)),
        "expected SuggestedPortInUse(50000), got {err:?}"
    );

    assert_eq!(
        alloc.active_count(),
        1,
        "a rejected follow conflict must neither add nor drop a mapping"
    );
    let still = alloc.snapshot_active();
    assert_eq!(still.len(), 1, "exactly Alice's mapping must remain");
    assert_eq!(
        still[0], held,
        "Alice's mapping must be left intact (same port, owner, internal_port, proto, expiry) after Bob's rejected follow"
    );
}

#[test]
fn explicit_suggestion_in_cooldown_for_another_client_is_rejected_strictly() {
    // After Alice releases a port it enters cooldown. A DIFFERENT client
    // that pins that exact port within the cooldown must be rejected
    // (privacy: Bob must not inherit residual inbound traffic to Alice's
    // old port) - strictly, not silently reassigned to a random port.
    let alloc = Allocator::with_config(
        (50000, 50005),
        Duration::from_secs(3600),
        100,
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    let a = alloc
        .allocate_at(ALICE, Proto::Udp, 0, 50000, 600, t0)
        .expect("Alice pins 50000");
    alloc.release_at(&a, t0 + Duration::from_secs(1));

    let err = alloc
        .allocate_at(BOB, Proto::Udp, 0, 50000, 600, t0 + Duration::from_secs(2))
        .expect_err("Bob must not grab Alice's cooled-down port");
    assert!(
        matches!(err, NatPmpError::SuggestedPortInUse(50000)),
        "expected SuggestedPortInUse(50000), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Rate limit 5/min/source
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_blocks_after_threshold() {
    let alloc = Allocator::with_config(
        (50000, 60000), // large enough to never be Exhausted
        Duration::from_secs(60),
        3, // max 3 in the window
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    // 3 successful allocations of DISTINCT internal ports (each a NEW
    // allocation - refreshes of the same tuple are exempt from the rate
    // limit, so they would not count here).
    for i in 0..3 {
        alloc
            .allocate_at(
                ALICE,
                Proto::Tcp,
                1 + i as u16,
                0,
                600,
                t0 + Duration::from_secs(i),
            )
            .unwrap_or_else(|e| panic!("alloc {i} must succeed, got {e}"));
    }

    // 4th NEW allocation must be rate-limited.
    let res = alloc.allocate_at(ALICE, Proto::Tcp, 4, 0, 600, t0 + Duration::from_secs(3));
    assert!(
        matches!(res, Err(NatPmpError::RateLimited { .. })),
        "4th alloc inside the window must be rate-limited, got {res:?}"
    );

    // Bob (different IP) is not affected.
    alloc
        .allocate_at(BOB, Proto::Tcp, 1, 0, 600, t0 + Duration::from_secs(3))
        .expect("rate limit is per source IP, not global");
}

/// A mapping whose `lifetime` has expired must be automatically
/// recycled by the next `allocate_at`. Otherwise the pool ends in
/// guaranteed exhaustion in prod (clients that crash without sending
/// a delete-mapping).
#[test]
fn expired_allocation_is_recycled_on_next_allocate() {
    // Single-port pool. Alice allocates with lifetime=60s.
    let alloc = Allocator::with_config(
        (50000, 50000),
        Duration::from_secs(1), // short cooldown so it does not mask
        100,
        Duration::from_secs(60),
    );
    let t0 = Instant::now();
    let _a = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 0, 60, t0)
        .expect("alloc 1");
    assert_eq!(alloc.active_count(), 1);

    // Bob tries immediately → Exhausted (port taken, lifetime not
    // expired).
    let res = alloc.allocate_at(BOB, Proto::Tcp, 9090, 0, 60, t0 + Duration::from_secs(5));
    assert!(matches!(res, Err(NatPmpError::Exhausted)));

    // Bob tries after expiry (60s + cooldown 1s + margin) → must OK.
    let bob_alloc = alloc
        .allocate_at(BOB, Proto::Tcp, 9090, 0, 60, t0 + Duration::from_secs(120))
        .expect("post-expiry, Bob must be able to take the port");
    assert_eq!(bob_alloc.external_port, 50000);
    assert_eq!(alloc.active_count(), 1, "old mapping must be evicted");
}

/// An `Exhausted` failure must NOT consume a slot in the rate-limit
/// window - otherwise a transient full-pool situation becomes a
/// permanent `RateLimited` (self-reinforcing DoS).
#[test]
fn exhausted_does_not_consume_rate_limit_slot() {
    // Tiny pool: 2 ports max → easy to exhaust.
    let alloc = Allocator::with_config(
        (50000, 50001), // 2 ports
        Duration::from_secs(60),
        3, // max rate limit = 3
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    // Alice consumes both ports → full pool. This consumes 2
    // rate-limit slots on Alice's side (successful allocs increment
    // the log). NOTE: the two allocations use DISTINCT internal
    // ports (8080, 8081) so each is a separate mapping - a re-MAP of
    // the SAME (ip, internal_port, proto) tuple is now a refresh
    // (RFC 6886 §3.3) that would replace rather than stack, and the
    // pool would not fill. The allocator here is built with the
    // default (unlimited) quota via `with_config`, so two distinct
    // tuples from Alice are allowed.
    alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 0, 600, t0)
        .expect("alloc 1 OK");
    alloc
        .allocate_at(ALICE, Proto::Tcp, 8081, 0, 600, t0 + Duration::from_secs(1))
        .expect("alloc 2 OK");

    // Bob tries 5 times → all Exhausted (full pool). With the old
    // bug that consumed the rate-limit at pre-increment time, Bob's
    // 4th attempt would flip to `RateLimited` (rate_limit_max=3).
    // With the fix, all 5 always return Exhausted (full pool) and
    // never burn Bob's window.
    for i in 0..5 {
        let res = alloc.allocate_at(BOB, Proto::Tcp, 0, 0, 600, t0 + Duration::from_secs(2 + i));
        assert!(
            matches!(res, Err(NatPmpError::Exhausted)),
            "attempt {i} must be Exhausted (full pool), got {res:?}"
        );
    }
}

#[test]
fn rate_limit_window_slides_correctly() {
    let alloc = Allocator::with_config(
        (50000, 60000),
        Duration::from_secs(60),
        2, // max 2
        Duration::from_secs(10),
    );
    let t0 = Instant::now();

    // Distinct internal ports = NEW allocations (refreshes are exempt).
    alloc.allocate_at(ALICE, Proto::Tcp, 1, 0, 600, t0).unwrap();
    alloc
        .allocate_at(ALICE, Proto::Tcp, 2, 0, 600, t0 + Duration::from_secs(1))
        .unwrap();

    // 3rd NEW allocation immediately: rate-limited.
    let res = alloc.allocate_at(ALICE, Proto::Tcp, 3, 0, 600, t0 + Duration::from_secs(2));
    assert!(matches!(res, Err(NatPmpError::RateLimited { .. })));

    // After the window (>10s past the old entries), Alice gets her
    // budget back.
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4, 0, 600, t0 + Duration::from_secs(15))
        .expect("past the window, must succeed again");
}

// ---------------------------------------------------------------------------
// Lifetime clamp [60..3600] (RFC 6886 §3.3)
// ---------------------------------------------------------------------------

#[test]
fn lifetime_below_min_is_clamped_up() {
    // Asking for 10s must be clamped up to 60s minimum.
    let alloc = Allocator::new();
    let t0 = Instant::now();
    let a = alloc.allocate_at(ALICE, Proto::Tcp, 0, 0, 10, t0).unwrap();
    let elapsed = a.expires_at.saturating_duration_since(t0);
    assert!(
        elapsed >= Duration::from_secs(60),
        "lifetime 10s must be clamped >= 60s, got {elapsed:?}"
    );
}

#[test]
fn lifetime_above_max_is_clamped_down() {
    // Asking for 10000s must be clamped down to 3600s.
    let alloc = Allocator::new();
    let t0 = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 0, 0, 10_000, t0)
        .unwrap();
    let elapsed = a.expires_at.saturating_duration_since(t0);
    assert!(
        elapsed <= Duration::from_secs(3600),
        "lifetime 10000s must be clamped <= 3600s, got {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// lifetime=0 semantics: the caller (server) must call release. The
// allocator does not treat lifetime=0 specially; server.rs dispatches
// (cf. RFC §3.3.2). The allocator only guarantees that release is
// idempotent and that releasing an unknown port erases nothing.
// ---------------------------------------------------------------------------

#[test]
fn release_unknown_port_is_noop() {
    let alloc = Allocator::new();
    let fake_alloc = warrenguard_natpmp_server::Allocation {
        external_port: 12345,
        internal_ip: ALICE,
        internal_port: 12345,
        proto: Proto::Tcp,
        expires_at: Instant::now() + Duration::from_secs(60),
    };
    // Must not panic and must not increase active_count.
    alloc.release_at(&fake_alloc, Instant::now());
    assert_eq!(alloc.active_count(), 0);
}

#[test]
fn release_by_client_finds_and_frees_active_mapping() {
    // RFC §3.3.2: a Map request with lifetime=0 deletes the mapping
    // for (client, internal_port, proto). The client sends its
    // `internal_port` (= what it bound on its socket); the server
    // does the internal lookup to recover the external_port and
    // release the mapping.
    let alloc = Allocator::new();
    let t0 = Instant::now();
    let internal_port = 8080;
    let _a = alloc
        .allocate_at(ALICE, Proto::Tcp, internal_port, 0, 600, t0)
        .unwrap();
    assert_eq!(alloc.active_count(), 1);

    let released = alloc.release_by_client_at(
        ALICE,
        internal_port,
        Proto::Tcp,
        t0 + Duration::from_secs(1),
    );
    assert!(
        released.is_some(),
        "release_by_client must find and free the mapping"
    );
    assert_eq!(alloc.active_count(), 0);
}

#[test]
fn release_by_client_rejects_other_clients_request() {
    // Security: Bob must not be able to release Alice's port just by
    // sending a delete request with the right internal_port. Auth is
    // by (client_ip, internal_port) - not by internal_port alone.
    let alloc = Allocator::new();
    let t0 = Instant::now();
    let internal_port = 8080;
    let _a = alloc
        .allocate_at(ALICE, Proto::Tcp, internal_port, 0, 600, t0)
        .unwrap();

    let released =
        alloc.release_by_client_at(BOB, internal_port, Proto::Tcp, t0 + Duration::from_secs(1));
    assert!(
        released.is_none(),
        "Bob must not be able to release Alice's port"
    );
    assert_eq!(alloc.active_count(), 1, "Alice's mapping must remain");
}

#[test]
fn release_by_client_proto_specific() {
    // A TCP and a UDP mapping on the same internal_port (theoretical)
    // are distinct. release_by_client only frees the exact protocol.
    let alloc = Allocator::new();
    let t0 = Instant::now();
    let internal_port = 8080;
    let _a = alloc
        .allocate_at(ALICE, Proto::Tcp, internal_port, 0, 600, t0)
        .unwrap();

    let released = alloc.release_by_client_at(
        ALICE,
        internal_port,
        Proto::Udp,
        t0 + Duration::from_secs(1),
    );
    assert!(
        released.is_none(),
        "UDP release must not free a TCP mapping"
    );
    assert_eq!(alloc.active_count(), 1);
}

#[test]
fn release_decrements_active_count() {
    let alloc = Allocator::new();
    let t0 = Instant::now();
    let a = alloc.allocate_at(ALICE, Proto::Tcp, 0, 0, 600, t0).unwrap();
    assert_eq!(alloc.active_count(), 1);
    alloc.release_at(&a, t0 + Duration::from_secs(1));
    assert_eq!(alloc.active_count(), 0);
}

// ---------------------------------------------------------------------------
// Internal map sweeps (cooldown_until, last_user_per_port,
// rate_limit_log) after expiry. Without sweeping, sustained load
// produces a memory leak: entries stay forever even past their
// deadline.
// ---------------------------------------------------------------------------

#[test]
fn cooldown_until_is_purged_after_expiry_on_next_allocate() {
    // 100ms cooldown to force fast expiry.
    let alloc = Allocator::with_config(
        (49152, 49160),
        Duration::from_millis(100),
        100, // generous rate-limit so it does not interfere
        Duration::from_secs(60),
    );
    let now = Instant::now();

    // Alloc + release on 5 ports → 5 entries in cooldown_until.
    let allocs: Vec<_> = (0..5)
        .map(|i| {
            alloc
                .allocate_at(ALICE, Proto::Tcp, 1000 + i, 0, 600, now)
                .expect("alloc")
        })
        .collect();
    for a in &allocs {
        alloc.release_at(a, now);
    }
    assert_eq!(
        alloc.cooldown_count(),
        5,
        "5 released ports must be in cooldown"
    );

    // Advance time past expiry.
    let later = now + Duration::from_millis(200);
    let _ = alloc
        .allocate_at(BOB, Proto::Tcp, 2000, 0, 600, later)
        .expect("alloc post-expiry");

    assert_eq!(
        alloc.cooldown_count(),
        0,
        "cooldown_until must purge expired entries on allocate_at"
    );
}

#[test]
fn last_user_per_port_is_purged_after_expiry_on_next_allocate() {
    let alloc = Allocator::with_config(
        (49152, 49160),
        Duration::from_millis(100),
        100,
        Duration::from_secs(60),
    );
    let now = Instant::now();

    let allocs: Vec<_> = (0..5)
        .map(|i| {
            alloc
                .allocate_at(ALICE, Proto::Tcp, 1000 + i, 0, 600, now)
                .expect("alloc")
        })
        .collect();
    for a in &allocs {
        alloc.release_at(a, now);
    }
    assert_eq!(alloc.last_user_count(), 5);

    let later = now + Duration::from_millis(200);
    let _ = alloc
        .allocate_at(BOB, Proto::Tcp, 2000, 0, 600, later)
        .expect("alloc post-expiry");

    assert_eq!(
        alloc.last_user_count(),
        0,
        "last_user_per_port must purge expired entries on allocate_at"
    );
}

// ---------------------------------------------------------------------------
// pick_port partial random sampling + linear fallback.
// Earlier behavior: 32 KB Vec<u16> + full Fisher-Yates per allocation.
// Current: 256 alloc-free random draws, linear fallback only when the
// pool is near-full.
// ---------------------------------------------------------------------------

#[test]
fn pick_port_finds_last_free_port_in_full_range_via_linear_fallback() {
    // Tiny range so a "near-full" pool is trivial to set up; the test
    // exercises the path where random draws hit only occupied ports
    // and the linear fallback finds the one free port.
    let alloc = Allocator::with_config(
        (60000, 60004), // 5 ports: 60000..=60004
        Duration::from_millis(1),
        100, // disable rate limit for this test
        Duration::from_secs(60),
    );
    let now = Instant::now();

    // Occupy 60000..=60003 explicitly via successive suggested ports.
    for sug in 60000..=60003 {
        alloc
            .allocate_at(ALICE, Proto::Tcp, 1000 + (sug - 60000), sug, 600, now)
            .expect("alloc suggested");
    }
    assert_eq!(alloc.active_count(), 4);

    // Request without `suggested` → must find 60004 (the only free
    // one) whether or not the 256 random draws touched it. The
    // fallback guarantees we never miss an existing free port.
    let a = alloc
        .allocate_at(BOB, Proto::Tcp, 2000, 0, 600, now)
        .expect("must find the remaining port via linear fallback");
    assert_eq!(a.external_port, 60004);
}

#[test]
fn pick_port_returns_exhausted_when_full_pool() {
    // 3-port pool, all occupied → Exhausted returned, no hang.
    let alloc = Allocator::with_config(
        (60000, 60002),
        Duration::from_millis(1),
        100,
        Duration::from_secs(60),
    );
    let now = Instant::now();

    for sug in 60000..=60002 {
        alloc
            .allocate_at(ALICE, Proto::Tcp, 1000 + (sug - 60000), sug, 600, now)
            .expect("alloc suggested");
    }
    assert_eq!(alloc.active_count(), 3);

    let r = alloc.allocate_at(BOB, Proto::Tcp, 2000, 0, 600, now);
    assert!(
        matches!(r, Err(NatPmpError::Exhausted)),
        "must return Exhausted when all ports are active"
    );
}

#[test]
fn rate_limit_log_purges_clients_outside_window_on_next_allocate() {
    // Short rate-limit window to force entry expiry.
    let alloc = Allocator::with_config(
        (49152, 49200),
        Duration::from_secs(300),
        5,
        Duration::from_millis(100),
    );
    let now = Instant::now();

    // 3 distinct clients each make 1 request → 3 entries in
    // rate_limit_log.
    let charlie_old = Ipv4Addr::new(10, 66, 0, 7);
    for ip in [ALICE, BOB, charlie_old] {
        alloc
            .allocate_at(ip, Proto::Tcp, 1000, 0, 600, now)
            .expect("alloc");
    }
    assert_eq!(alloc.rate_limit_clients_tracked(), 3);

    // Advance time past the window.
    let later = now + Duration::from_millis(200);

    // A 4th, independent client makes a request. This allocation
    // must trigger the sweep of every entry whose timestamps are
    // outside the window (Alice, Bob, charlie_old → their logs
    // become empty).
    let dave = Ipv4Addr::new(10, 66, 0, 200);
    alloc
        .allocate_at(dave, Proto::Tcp, 1000, 0, 600, later)
        .expect("alloc");

    assert_eq!(
        alloc.rate_limit_clients_tracked(),
        1,
        "rate_limit_log must purge clients whose timestamps are all outside the window"
    );
}

// ---------------------------------------------------------------------------
// Snapshot of active mappings (consumed by the Exit -> API sync push)
// ---------------------------------------------------------------------------

#[test]
fn snapshot_active_is_empty_when_no_allocation() {
    let alloc = Allocator::new();
    assert!(
        alloc.snapshot_active().is_empty(),
        "fresh allocator must expose an empty snapshot"
    );
}

#[test]
fn snapshot_active_reflects_every_live_allocation() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let a1 = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice tcp");
    let a2 = alloc
        .allocate_at(BOB, Proto::Udp, 5151, 0, 600, now)
        .expect("bob udp");

    let mut snap = alloc.snapshot_active();
    snap.sort_by_key(|a| a.external_port);
    let mut expected = vec![a1, a2];
    expected.sort_by_key(|a| a.external_port);
    assert_eq!(
        snap, expected,
        "snapshot must mirror every active mapping verbatim"
    );
}

#[test]
fn snapshot_active_drops_expired_mappings_after_next_allocate() {
    // Lazy-sweep contract: expired mappings are removed by the next
    // `allocate_at` call, NOT by `snapshot_active` itself. The
    // snapshot is a pure read.
    let alloc = Allocator::new();
    let now = Instant::now();
    let _ = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 60, now)
        .expect("alice tcp");
    assert_eq!(
        alloc.snapshot_active().len(),
        1,
        "snapshot is a pure read; it does not sweep expired entries"
    );

    let after_expiry = now + Duration::from_secs(120);
    let _ = alloc
        .allocate_at(BOB, Proto::Tcp, 4243, 0, 60, after_expiry)
        .expect("bob tcp after expiry sweeps alice");
    let snap = alloc.snapshot_active();
    assert_eq!(snap.len(), 1, "alice's expired mapping must be swept");
    assert_eq!(snap[0].internal_ip, BOB);
}

#[test]
fn snapshot_active_decrements_after_release() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice tcp");
    alloc.release_at(&a, now + Duration::from_secs(1));
    assert!(
        alloc.snapshot_active().is_empty(),
        "released mapping must no longer appear in the snapshot"
    );
}

// ---------------------------------------------------------------------------
// Per-client quota (defensive against pool exhaustion by a single user)
// ---------------------------------------------------------------------------

#[test]
fn over_quota_alloc_is_rejected_with_quota_exceeded_not_partial() {
    // Once the per-client quota is full, the next distinct-port
    // allocation MUST be refused with `QuotaExceeded` (NOT `RateLimited`,
    // NOT a silent re-attribution of an existing slot) and must not leave
    // a partial entry behind.
    use warrenguard_natpmp_server::allocator::AllocatorConfig;
    let quota = AllocatorConfig::warren_default().quota_per_client;
    let alloc = Allocator::new();
    let now = Instant::now();
    for i in 0..quota {
        alloc
            .allocate_at(
                ALICE,
                Proto::Tcp,
                4242 + u16::try_from(i).unwrap(),
                0,
                600,
                now,
            )
            .expect("alloc within quota");
    }
    let res = alloc.allocate_at(ALICE, Proto::Udp, 9000, 0, 600, now);
    assert!(
        matches!(res, Err(NatPmpError::QuotaExceeded(ip)) if ip == ALICE),
        "over-quota alloc must hit the per-client quota, got {res:?}"
    );
    assert_eq!(
        alloc.active_count(),
        quota,
        "the failed alloc must not leave a partial entry behind"
    );
}

/// The quota counts a tunnel address, and one tenant can hold several of
/// them at once (the exit places each of its live sessions on its own inner
/// address). Without a way to tell the allocator which addresses are the same
/// tenant, the budget is per session, so opening sessions multiplies it. The
/// deployer supplies that grouping; the allocator never learns who the tenant
/// is, only which addresses answer for one.
#[test]
fn quota_is_shared_by_every_address_of_one_tenant() {
    use std::sync::Arc;
    use warrenguard_natpmp_server::allocator::{AllocatorConfig, QuotaPeers};

    struct SameTenant;
    impl QuotaPeers for SameTenant {
        fn peer_addresses(&self, client_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
            // Keyed on the argument, so an implementation that grouped by
            // anything other than the requesting address fails this test.
            if client_ip == ALICE || client_ip == ALICE_SECOND_SESSION {
                vec![ALICE, ALICE_SECOND_SESSION]
            } else {
                vec![client_ip]
            }
        }
    }

    let quota = AllocatorConfig::warren_default().quota_per_client;
    let alloc = Allocator::new();
    assert!(
        alloc.set_quota_peers(Arc::new(SameTenant)),
        "the first wiring must be accepted"
    );
    let now = Instant::now();
    for i in 0..quota {
        alloc
            .allocate_at(
                ALICE,
                Proto::Tcp,
                4242 + u16::try_from(i).unwrap(),
                0,
                600,
                now,
            )
            .expect("alloc within quota");
    }

    let res = alloc.allocate_at(ALICE_SECOND_SESSION, Proto::Tcp, 9000, 0, 600, now);

    assert!(
        matches!(res, Err(NatPmpError::QuotaExceeded(ip)) if ip == ALICE_SECOND_SESSION),
        "a second session of the same tenant must not get a fresh budget, got {res:?}"
    );
}

/// A deployer that sells port budgets per subscriber needs the cap to come
/// from what the client presented, not from one number baked into the
/// allocator. What it does not answer for keeps the configured default, which
/// is what makes an unverifiable credential degrade instead of refusing.
#[test]
fn a_client_budget_overrides_the_configured_quota() {
    use std::sync::Arc;
    use warrenguard_natpmp_server::allocator::PortBudget;

    struct OnePortForAlice;
    impl PortBudget for OnePortForAlice {
        fn budget_for(&self, client_ip: Ipv4Addr) -> Option<usize> {
            (client_ip == ALICE).then_some(1)
        }
    }

    let alloc = Allocator::new();
    assert!(alloc.set_port_budget(Arc::new(OnePortForAlice)));
    let now = Instant::now();

    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("first port is within the granted budget");
    let second = alloc.allocate_at(ALICE, Proto::Tcp, 4243, 0, 600, now);

    assert!(
        matches!(second, Err(NatPmpError::QuotaExceeded(ip)) if ip == ALICE),
        "a budget of one must refuse the second port, got {second:?}"
    );
    assert!(
        alloc
            .allocate_at(BOB, Proto::Tcp, 5252, 0, 600, now)
            .is_ok(),
        "an address the authority does not answer for keeps the default quota"
    );
}

/// Wiring the grouping twice would let a later caller widen every budget by
/// answering with a narrower group, so only the first one counts.
#[test]
fn quota_grouping_refuses_to_be_rewired() {
    use std::sync::Arc;
    use warrenguard_natpmp_server::allocator::QuotaPeers;

    struct Alone;
    impl QuotaPeers for Alone {
        fn peer_addresses(&self, client_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
            vec![client_ip]
        }
    }

    let alloc = Allocator::new();
    assert!(alloc.set_quota_peers(Arc::new(Alone)));
    assert!(
        !alloc.set_quota_peers(Arc::new(Alone)),
        "a second wiring must be refused, not silently applied"
    );
}

/// The grouping never merges two tenants: an address the oracle does not
/// name keeps its own budget.
#[test]
fn quota_grouping_leaves_a_different_tenant_alone() {
    use std::sync::Arc;
    use warrenguard_natpmp_server::allocator::{AllocatorConfig, QuotaPeers};

    struct AliceSessions;
    impl QuotaPeers for AliceSessions {
        fn peer_addresses(&self, client_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
            if client_ip == BOB {
                vec![BOB]
            } else {
                vec![ALICE, ALICE_SECOND_SESSION]
            }
        }
    }

    let quota = AllocatorConfig::warren_default().quota_per_client;
    let alloc = Allocator::new();
    alloc.set_quota_peers(Arc::new(AliceSessions));
    let now = Instant::now();
    for i in 0..quota {
        alloc
            .allocate_at(
                ALICE,
                Proto::Tcp,
                4242 + u16::try_from(i).unwrap(),
                0,
                600,
                now,
            )
            .expect("alloc within quota");
    }

    assert!(
        alloc
            .allocate_at(BOB, Proto::Tcp, 9000, 0, 600, now)
            .is_ok(),
        "another tenant must keep its own budget while alice is at quota"
    );
}

#[test]
fn quota_is_per_client_not_global() {
    // Two distinct clients must each be able to allocate their own
    // single port without colliding on the per-client quota.
    let alloc = Allocator::new();
    let now = Instant::now();
    let _ = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice");
    let bob = alloc.allocate_at(BOB, Proto::Tcp, 5252, 0, 600, now);
    assert!(
        bob.is_ok(),
        "bob's allocation must succeed even though alice is at quota"
    );
}

#[test]
fn quota_decrements_after_release_so_client_can_realloc() {
    // Quota is a count of *active* allocations, so releasing the
    // current one must free a slot for the same client to take a
    // new one (typically after a port rotation).
    let alloc = Allocator::new();
    let now = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("first alloc");
    alloc.release_at(&a, now + Duration::from_secs(1));
    // Allocate again past the cooldown horizon so the port itself
    // is reusable; the quota check is independent of the cooldown.
    let later = now + Duration::from_secs(600);
    let res = alloc.allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, later);
    assert!(
        res.is_ok(),
        "after release, the client must regain a quota slot"
    );
}

#[test]
fn remap_same_tuple_refreshes_instead_of_hitting_quota() {
    // RFC 6886 §3.3 refresh + orphan self-heal: a MAP for the SAME
    // (client_ip, internal_port, proto) the client already holds must
    // be treated as a refresh - succeed and replace - NOT refused by
    // the per-client quota of 1. This is the path that unblocks a
    // client whose tunnel dropped mid-mapping and reconnected with the
    // same deterministic tunnel IP (the orphan from the previous
    // session would otherwise hold the only quota slot until its lease
    // expires, ~1 h).
    let alloc = Allocator::new(); // default quota = 1
    let now = Instant::now();

    let first = alloc
        .allocate_at(ALICE, Proto::Udp, 0, 0, 600, now)
        .expect("first alloc");
    assert_eq!(alloc.active_count(), 1);

    // Same tuple (ALICE, internal_port=0, Udp) again - must SUCCEED
    // (refresh), not QuotaExceeded.
    let second = alloc
        .allocate_at(ALICE, Proto::Udp, 0, 0, 600, now + Duration::from_secs(1))
        .expect("re-MAP of the same tuple must refresh, not hit quota");
    assert_eq!(
        alloc.active_count(),
        1,
        "refresh must replace the old mapping, not stack a second"
    );
    // The refreshed mapping is a fresh allocation (its external port
    // may differ from the first - the client could have changed its
    // suggested port; here suggested=0 so the server re-picks).
    let _ = (first.external_port, second.external_port);
}

#[test]
fn remap_same_tuple_honors_new_suggested_port() {
    // A refresh may carry a different suggested external port; the
    // server must drop the old mapping and honor the new suggestion
    // (when free). Exercises the "change preferred port live" UX.
    let alloc = Allocator::new();
    let now = Instant::now();

    let first = alloc
        .allocate_at(ALICE, Proto::Udp, 0, 49500, 600, now)
        .expect("first alloc with suggested 49500");
    assert_eq!(first.external_port, 49500);

    // Refresh with a different suggested port.
    let second = alloc
        .allocate_at(
            ALICE,
            Proto::Udp,
            0,
            49600,
            600,
            now + Duration::from_secs(1),
        )
        .expect("refresh with new suggested port");
    assert_eq!(
        second.external_port, 49600,
        "refresh must honor the new suggested port"
    );
    assert_eq!(alloc.active_count(), 1, "still exactly one mapping");
}

#[test]
fn quota_can_be_widened_via_config() {
    // The default is 1 port/client; tests that need more can build
    // the allocator with a custom quota. This is also how a future
    // subscription-tier gate will let paying users have more
    // simultaneous port forwards.
    use std::time::Duration;
    use warrenguard_natpmp_server::allocator::AllocatorConfig;
    let alloc = Allocator::from_config(AllocatorConfig {
        range: (49152, 65535),
        cooldown: Duration::from_secs(300),
        rate_limit_max: 5,
        rate_limit_window: Duration::from_secs(60),
        quota_per_client: 3,
    });
    let now = Instant::now();
    for i in 0..3 {
        alloc
            .allocate_at(ALICE, Proto::Tcp, 4000 + i, 0, 600, now)
            .expect("under quota");
    }
    let res = alloc.allocate_at(ALICE, Proto::Tcp, 4003, 0, 600, now);
    assert!(
        matches!(res, Err(NatPmpError::QuotaExceeded(_))),
        "the 4th alloc must hit the configured quota of 3, got {res:?}"
    );
}

// ---------------------------------------------------------------------------
// Eviction propagation: the allowlist refresher tells the exit which
// pubkeys lost their subscription; the allocator must release their ports.
// ---------------------------------------------------------------------------

#[test]
fn take_active_for_ip_returns_every_alloc_owned_by_the_client() {
    use warrenguard_natpmp_server::allocator::AllocatorConfig;
    let alloc = Allocator::from_config(AllocatorConfig {
        range: (49152, 65535),
        cooldown: Duration::from_secs(300),
        rate_limit_max: 100,
        rate_limit_window: Duration::from_secs(60),
        quota_per_client: 4,
    });
    let now = Instant::now();
    let _ = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice tcp");
    let _ = alloc
        .allocate_at(ALICE, Proto::Udp, 4243, 0, 600, now)
        .expect("alice udp");
    let _ = alloc
        .allocate_at(BOB, Proto::Tcp, 5252, 0, 600, now)
        .expect("bob tcp");
    assert_eq!(alloc.active_count(), 3);

    let removed = alloc.take_active_for_ip(ALICE);
    assert_eq!(removed.len(), 2, "both alice mappings must be returned");
    assert!(removed.iter().all(|a| a.internal_ip == ALICE));
    assert_eq!(
        alloc.active_count(),
        1,
        "only bob's mapping remains in the active pool"
    );
}

#[test]
fn take_active_for_ip_is_noop_when_client_has_no_alloc() {
    let alloc = Allocator::new();
    let removed = alloc.take_active_for_ip(ALICE);
    assert!(removed.is_empty());
    assert_eq!(alloc.active_count(), 0);
}

#[test]
fn take_active_for_ip_puts_freed_ports_into_cooldown() {
    // Same invariant as the regular release path: the freed port
    // is not eligible for an immediate reallocation. Otherwise an
    // attacker could self-trigger an eviction to short-circuit the
    // rotation policy.
    let alloc = Allocator::new();
    let now = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice");
    let removed = alloc.take_active_for_ip(ALICE);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].external_port, a.external_port);
    assert_eq!(
        alloc.cooldown_count(),
        1,
        "the freed port must enter cooldown so the rotation policy holds"
    );
}

// ---------------------------------------------------------------------------
// Counters: monotonic AtomicU64 tally exposed via Allocator::metrics()
// for future Prometheus scraping. The numbers must move on the events the
// /metrics view will reference (allocations, releases, evictions, errors).
// ---------------------------------------------------------------------------

#[test]
fn metrics_count_successful_allocations() {
    let alloc = Allocator::new();
    let now = Instant::now();
    assert_eq!(alloc.metrics().allocations_total, 0);
    let _ = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice");
    let _ = alloc
        .allocate_at(BOB, Proto::Udp, 5252, 0, 600, now)
        .expect("bob");
    assert_eq!(alloc.metrics().allocations_total, 2);
}

#[test]
fn metrics_count_releases_only_when_a_mapping_was_present() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice");
    alloc.release_at(&a, now + Duration::from_secs(1));
    assert_eq!(alloc.metrics().releases_total, 1);

    // Releasing the same allocation again is a no-op (no entry in
    // the active map), so the counter must NOT move - otherwise the
    // metric would lie about the actual nftables churn.
    alloc.release_at(&a, now + Duration::from_secs(2));
    assert_eq!(alloc.metrics().releases_total, 1);
}

#[test]
fn metrics_count_evictions_through_take_active_for_ip() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let _ = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice");
    let removed = alloc.take_active_for_ip(ALICE);
    assert_eq!(removed.len(), 1);
    let m = alloc.metrics();
    assert_eq!(m.evictions_total, 1, "one allocation evicted");
    // Evictions also bump releases_total because the cooldown +
    // last_user_per_port bookkeeping is the same path; the admin
    // panel can compute "active churn" as
    // releases_total - evictions_total to separate organic releases
    // from forced ones.
    assert_eq!(m.releases_total, 1);
}

#[test]
fn metrics_count_quota_exceeded_failures() {
    use warrenguard_natpmp_server::allocator::AllocatorConfig;
    let quota = AllocatorConfig::warren_default().quota_per_client;
    let alloc = Allocator::new();
    let now = Instant::now();
    for i in 0..quota {
        alloc
            .allocate_at(
                ALICE,
                Proto::Tcp,
                4242 + u16::try_from(i).unwrap(),
                0,
                600,
                now,
            )
            .expect("alloc within quota");
    }
    let _ = alloc
        .allocate_at(ALICE, Proto::Udp, 9000, 0, 600, now)
        .expect_err("over quota");
    assert_eq!(alloc.metrics().quota_exceeded_total, 1);
    assert_eq!(
        alloc.metrics().allocations_total,
        u64::try_from(quota).unwrap(),
        "failed alloc does not count toward allocations_total"
    );
}

#[test]
fn metrics_count_rate_limited_failures() {
    let alloc = Allocator::with_config(
        (49152, 65535),
        Duration::from_secs(300),
        1, // rate_limit_max = 1 to hit the cap on the second alloc
        Duration::from_secs(60),
    );
    let now = Instant::now();
    let _ = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("first ok");
    let _ = alloc
        .allocate_at(ALICE, Proto::Udp, 4243, 0, 600, now)
        .expect_err("rate limit kicks in");
    assert_eq!(alloc.metrics().rate_limited_total, 1);
}

#[test]
fn metrics_count_exhausted_failures() {
    let alloc = Allocator::with_config(
        (50000, 50000), // pool of size 1
        Duration::from_secs(300),
        100,
        Duration::from_secs(60),
    );
    let now = Instant::now();
    let _ = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("first port consumed");
    let _ = alloc
        .allocate_at(BOB, Proto::Tcp, 5252, 0, 600, now)
        .expect_err("pool exhausted");
    assert_eq!(alloc.metrics().exhausted_total, 1);
}

// ---------------------------------------------------------------------------
// Admin revoke propagation: the API tells the exit which ports to drop
// via the sync response; the exit calls `take_active_for_port` and pushes
// the result into the cleanup worker.
// ---------------------------------------------------------------------------

#[test]
fn take_active_for_port_returns_and_removes_the_mapping() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 600, now)
        .expect("alice");
    let port = a.external_port;
    let removed = alloc.take_active_for_port(port);
    assert_eq!(removed, vec![a]);
    assert_eq!(alloc.active_count(), 0);
    assert_eq!(
        alloc.cooldown_count(),
        1,
        "the freed port must enter cooldown"
    );
    let m = alloc.metrics();
    assert_eq!(m.releases_total, 1);
    assert_eq!(
        m.evictions_total, 1,
        "an admin-driven take counts as a forced eviction in the metrics"
    );
}

#[test]
fn take_active_for_port_returns_none_for_unknown_port() {
    let alloc = Allocator::new();
    assert!(alloc.take_active_for_port(49999).is_empty());
    assert_eq!(alloc.metrics().releases_total, 0);
    assert_eq!(alloc.metrics().evictions_total, 0);
}

// ---------------------------------------------------------------------------
// allocate_collecting: every removed `active` entry must be surfaced so the
// backend can tear down the matching nftables element. An unsurfaced
// removal is an allocator<->nftables desync that leaks ghost DNAT rules for
// expired and port-changed mappings (one client ends up holding several UDP
// DNAT elements under a quota of one).
// ---------------------------------------------------------------------------

#[test]
fn allocate_collecting_reports_no_evictions_for_a_fresh_mapping() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let outcome = alloc.allocate_at_collecting(ALICE, Proto::Tcp, 8080, 0, 600, now);
    assert!(
        outcome.evicted.is_empty(),
        "a brand-new mapping evicts nothing, got {:?}",
        outcome.evicted
    );
    assert_eq!(outcome.result.expect("fresh map").internal_ip, ALICE);
}

#[test]
fn allocate_collecting_surfaces_expired_entry_as_evicted() {
    // Alice maps with a 60s lifetime, then Bob allocates well past
    // expiry. The lazy sweep drops Alice's record; the outcome must
    // surface it so the backend deletes the matching DNAT element
    // instead of leaking it (the expiry leg of the desync).
    let alloc = Allocator::new();
    let t0 = Instant::now();
    let alice = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 0, 60, t0)
        .expect("alice");
    let outcome =
        alloc.allocate_at_collecting(BOB, Proto::Tcp, 9090, 0, 60, t0 + Duration::from_secs(120));
    assert!(outcome.result.is_ok(), "bob after alice expired");
    assert_eq!(
        outcome.evicted.len(),
        1,
        "alice's expired mapping must be surfaced exactly once"
    );
    assert_eq!(outcome.evicted[0].external_port, alice.external_port);
    assert_eq!(outcome.evicted[0].internal_ip, ALICE);
}

#[test]
fn allocate_collecting_surfaces_port_change_refresh_as_evicted() {
    // The live bug: a refresh that moves to a new suggested external
    // port abandons the old port. The old port MUST be reported so its
    // ghost DNAT element gets deleted; otherwise the kernel keeps
    // forwarding the old port to the client forever.
    let alloc = Allocator::new();
    let now = Instant::now();
    let first = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 50_111, 600, now)
        .expect("first map");
    assert_eq!(first.external_port, 50_111);
    let outcome = alloc.allocate_at_collecting(
        ALICE,
        Proto::Tcp,
        8080,
        50_222,
        600,
        now + Duration::from_secs(60),
    );
    assert_eq!(
        outcome.result.expect("refresh moves port").external_port,
        50_222
    );
    assert_eq!(
        outcome.evicted.len(),
        1,
        "the surrendered old port must be surfaced as evicted"
    );
    assert_eq!(
        outcome.evicted[0].external_port, 50_111,
        "the reclaimed stale-tuple port (the live-bug ghost) must be in evicted"
    );
    assert_eq!(
        alloc.active_count(),
        1,
        "a refresh replaces the mapping, it does not stack"
    );
}

#[test]
fn allocate_collecting_surfaces_same_port_refresh_for_idempotent_teardown() {
    // A refresh that keeps the same external port still surfaces the
    // reclaimed entry. The backend then deletes-then-re-adds the same
    // element, which keeps the kernel map authoritative and avoids an
    // "add element on existing key" failure on every renewal.
    let alloc = Allocator::new();
    let now = Instant::now();
    let first = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 50_111, 600, now)
        .expect("first map");
    let outcome = alloc.allocate_at_collecting(
        ALICE,
        Proto::Tcp,
        8080,
        0,
        600,
        now + Duration::from_secs(300),
    );
    assert_eq!(
        outcome.result.expect("refresh same port").external_port,
        first.external_port
    );
    assert_eq!(outcome.evicted.len(), 1);
    assert_eq!(outcome.evicted[0].external_port, first.external_port);
}

#[test]
fn evicted_is_surfaced_even_when_the_call_is_rate_limited() {
    // Robustness regression: the lazy expiry sweep runs at the TOP of
    // every allocate, BEFORE the rate-limit gate. A call that is
    // rate-limited AFTER it swept an expired mapping must STILL surface
    // that mapping in `evicted`, so the backend tears down its DNAT
    // element. The earlier `Result<AllocateOutcome, _>` shape dropped
    // `evicted` on the error return and re-leaked the ghost rule on
    // exactly this path.
    let alloc = Allocator::with_config(
        (50000, 60000),
        Duration::from_secs(300), // cooldown (irrelevant here)
        1,                        // rate limit: 1 request per window
        // window long enough that t0's slot is still counted at t0+90,
        // while the 60s-min-clamped mapping has already expired.
        Duration::from_secs(3600),
    );
    let t0 = Instant::now();

    // Alice maps (consumes the single rate slot at t0). Lifetime is
    // clamped up to the 60s minimum.
    let alice = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 0, 1, t0)
        .expect("alice maps");

    // t0+90s: Alice's mapping has expired (the sweep reaps it), but her
    // rate slot at t0 is still inside the 3600s window → this call is
    // RateLimited.
    let outcome =
        alloc.allocate_at_collecting(ALICE, Proto::Tcp, 8080, 0, 1, t0 + Duration::from_secs(90));

    assert!(
        matches!(outcome.result, Err(NatPmpError::RateLimited { .. })),
        "expected RateLimited, got {:?}",
        outcome.result
    );
    assert_eq!(
        outcome.evicted.len(),
        1,
        "the expired mapping swept before the rate-limit gate must still be surfaced for teardown"
    );
    assert_eq!(outcome.evicted[0].external_port, alice.external_port);
}

// ---------------------------------------------------------------------------
// Rate-limit budget surfaced to the UI (retry-after + remaining slots)
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_status_counts_down_then_rate_limited_carries_retry_after() {
    // Tight config: 3 allocations per 60s window. After 3 successful
    // maps the budget is exhausted and the 4th must report a retry-after
    // close to the full window (the oldest slot was taken at t0).
    let alloc = Allocator::with_config(
        (50000, 60000),
        Duration::from_secs(300),
        3,
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    // Fresh client: full budget, no window to wait on.
    let s0 = alloc.rate_limit_status_at(ALICE, t0);
    assert_eq!(s0.attempts_remaining, 3);
    assert_eq!(s0.window_reset_secs, 0);

    // Three maps on three distinct internal ports consume all rate
    // slots. `with_config` leaves the per-client quota unbounded, so the
    // gate exercised here is purely the rate limit.
    for (i, port) in [8001u16, 8002, 8003].into_iter().enumerate() {
        alloc
            .allocate_at(
                ALICE,
                Proto::Tcp,
                port,
                0,
                600,
                t0 + Duration::from_secs(i as u64),
            )
            .unwrap_or_else(|e| panic!("map {port} should succeed: {e:?}"));
    }

    // Budget now exhausted within the window.
    let s3 = alloc.rate_limit_status_at(ALICE, t0 + Duration::from_secs(3));
    assert_eq!(s3.attempts_remaining, 0);
    // Oldest slot taken at t0; at t0+3 it frees in ~57s.
    assert!(
        (55..=60).contains(&s3.window_reset_secs),
        "window_reset should be ~57s, got {}",
        s3.window_reset_secs
    );

    // The 4th allocation is rate-limited and carries the retry-after.
    let outcome =
        alloc.allocate_at_collecting(ALICE, Proto::Tcp, 8004, 0, 600, t0 + Duration::from_secs(3));
    match outcome.result {
        Err(NatPmpError::RateLimited {
            retry_after_secs, ..
        }) => assert!(
            (55..=60).contains(&retry_after_secs),
            "retry_after ~57s expected, got {retry_after_secs}"
        ),
        other => panic!("expected RateLimited with retry-after, got {other:?}"),
    }

    // Past the window (last slot taken at t0+2, window 60s), the budget
    // fully resets once even the newest slot has aged out.
    let s_after = alloc.rate_limit_status_at(ALICE, t0 + Duration::from_secs(63));
    assert_eq!(s_after.attempts_remaining, 3);
    assert_eq!(s_after.window_reset_secs, 0);
}

// ---------------------------------------------------------------------------
// Multi-port: several simultaneous forwards per client
// ---------------------------------------------------------------------------

#[test]
fn shipped_config_allows_quota_ports_per_client_then_rejects() {
    // Multi-port contract: the SHIPPED allocator must let ONE client
    // hold up to `quota_per_client` simultaneous mappings (distinct
    // internal ports) and refuse the one past the quota. The initial
    // burst must also fit under the rate limit (rate_limit_max >= quota),
    // otherwise multi-port setup would rate-limit itself.
    use warrenguard_natpmp_server::allocator::AllocatorConfig;
    let quota = AllocatorConfig::warren_default().quota_per_client;
    assert!(
        quota >= 2,
        "multi-port requires a quota of at least 2 (got {quota})"
    );

    let alloc = Allocator::new();
    let now = Instant::now();
    for i in 0..quota {
        let internal = 1000 + u16::try_from(i).unwrap();
        alloc
            .allocate_at(ALICE, Proto::Tcp, internal, 0, 600, now)
            .unwrap_or_else(|e| panic!("allocation #{i} within quota must succeed: {e:?}"));
    }
    assert_eq!(
        alloc.active_count(),
        quota,
        "all quota ports must be active"
    );

    let over = alloc.allocate_at(ALICE, Proto::Tcp, 9999, 0, 600, now);
    assert!(
        matches!(over, Err(NatPmpError::QuotaExceeded(_))),
        "the (quota+1)-th simultaneous mapping must be refused, got {over:?}"
    );
}

#[test]
fn refresh_is_exempt_from_rate_limit() {
    // Renewals (same (client, internal_port, proto) tuple) must NOT
    // consume rate-limit budget. Otherwise N held ports renewing would
    // exhaust the per-source limit and the daemon could not keep them
    // alive. Only genuinely-NEW allocations / port changes count.
    use warrenguard_natpmp_server::allocator::AllocatorConfig;
    let cfg = AllocatorConfig {
        rate_limit_max: 2,
        ..AllocatorConfig::warren_default()
    };
    let alloc = Allocator::from_config(cfg);
    let now = Instant::now();

    // One NEW port, then refresh it many times - every refresh must pass
    // even though the rate-limit budget is only 2.
    alloc
        .allocate_at(ALICE, Proto::Udp, 1000, 0, 3600, now)
        .expect("first new port A");
    for n in 0..5 {
        alloc
            .allocate_at(ALICE, Proto::Udp, 1000, 0, 3600, now)
            .unwrap_or_else(|e| panic!("refresh #{n} of A must never be rate-limited: {e:?}"));
    }

    // A genuinely-NEW second port consumes the 2nd (last) slot.
    alloc
        .allocate_at(ALICE, Proto::Udp, 2000, 0, 3600, now)
        .expect("2nd NEW port still within rate limit");
    // A third NEW port in the same window exceeds it.
    let third = alloc.allocate_at(ALICE, Proto::Udp, 3000, 0, 3600, now);
    assert!(
        matches!(third, Err(NatPmpError::RateLimited { .. })),
        "the 3rd NEW allocation in the window must be rate-limited, got {third:?}"
    );
}

// ---------------------------------------------------------------------------
// The suggested-port occupancy oracle is rate-limited
// ---------------------------------------------------------------------------

#[test]
fn probing_another_clients_port_is_rate_limited() {
    // A non-owner's rejected explicit suggestion ("is this port taken?")
    // must count against its per-source rate limit. Otherwise a malicious
    // subscribed client can enumerate the whole live allocation table at
    // UDP line rate for free (occupancy oracle), then target other tenants'
    // forwarded ports.
    let alloc = Allocator::with_config(
        (50000, 50010),
        Duration::from_secs(300),
        3, // small rate-limit budget so the test is cheap
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    // Alice holds 50000.
    alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 50000, 600, t0)
        .expect("alice holds 50000");

    // Bob probes Alice's port. Each rejected probe burns one of Bob's slots.
    for i in 0..3 {
        let res = alloc.allocate_at(
            BOB,
            Proto::Tcp,
            9000,
            50000,
            600,
            t0 + Duration::from_millis(i),
        );
        assert!(
            matches!(res, Err(NatPmpError::SuggestedPortInUse(50000))),
            "probe {i} should be rejected as in-use, got {res:?}"
        );
    }
    // The 4th probe within the window is throttled rather than answered with
    // the oracle-leaking in-use-vs-free distinction.
    let throttled = alloc.allocate_at(
        BOB,
        Proto::Tcp,
        9000,
        50000,
        600,
        t0 + Duration::from_millis(4),
    );
    assert!(
        matches!(throttled, Err(NatPmpError::RateLimited { .. })),
        "the oracle must be rate-limited after the budget, got {throttled:?}"
    );
}

// ---------------------------------------------------------------------------
// A lazily-expired lease still arms the anti-inheritance cooldown
// ---------------------------------------------------------------------------

#[test]
fn lazily_expired_port_is_in_cooldown_for_a_different_client() {
    // A client that crashes without sending delete-mapping leaves a lease
    // that EXPIRES rather than being explicitly released. That expiry must
    // still arm the cooldown, or a DIFFERENT client could grab the exact
    // port the instant it lapses and inherit residual inbound traffic - the
    // precise case the cooldown exists to prevent.
    let alloc = Allocator::with_config(
        (50000, 50000), // single port in range
        Duration::from_secs(300),
        100, // generous rate limit so it does not interfere
        Duration::from_secs(60),
    );
    let t0 = Instant::now();

    // Alice grabs 50000 with the minimum 60s lease, then never refreshes.
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 0, 0, 60, t0)
        .expect("alice alloc");
    assert_eq!(a.external_port, 50000);

    // 61s later the lease has lazily expired. Bob asks: the sweep frees the
    // port but the cooldown must still block him.
    let bob = alloc.allocate_at(BOB, Proto::Tcp, 0, 0, 600, t0 + Duration::from_secs(61));
    assert!(
        matches!(bob, Err(NatPmpError::Exhausted)),
        "a lazily-expired port must be in cooldown for a different client, got {bob:?}"
    );

    // The OWNER may still reclaim her own expired port immediately via an
    // explicit suggestion (cooldown guards only against OTHER clients).
    let alice_reclaim = alloc
        .allocate_at(
            ALICE,
            Proto::Tcp,
            0,
            50000,
            600,
            t0 + Duration::from_secs(62),
        )
        .expect("owner reclaims her own expired port");
    assert_eq!(alice_reclaim.external_port, 50000);
}

// ---------------------------------------------------------------------------
// Restore (persistence across a process restart, doc: exit hot-swap)
// ---------------------------------------------------------------------------

#[test]
fn restore_reinstates_saved_mappings() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 8080, 50000, 600, now)
        .expect("alloc");

    // Simulate the process restart: a fresh allocator, fed the snapshot.
    let fresh = Allocator::new();
    let reinstated = fresh.restore_at(vec![a.clone()], now);
    assert_eq!(reinstated.len(), 1);
    assert_eq!(fresh.active_count(), 1);

    // The restored port keeps its owner: another client asking for it
    // is refused (strict honour-or-error), exactly as before the restart.
    let err = fresh
        .allocate_at(BOB, Proto::Tcp, 9000, 50000, 600, now)
        .expect_err("port must still be held");
    assert!(matches!(err, NatPmpError::SuggestedPortInUse(50000)));

    // The owner's refresh still works (same tuple, no quota charge).
    let refreshed = fresh
        .allocate_at(ALICE, Proto::Tcp, 8080, 50000, 600, now)
        .expect("owner refresh");
    assert_eq!(refreshed.external_port, 50000);
}

#[test]
fn restore_skips_expired_and_conflicting_entries() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let live = alloc
        .allocate_at(ALICE, Proto::Udp, 1000, 50001, 600, now)
        .expect("live");
    let expired = alloc
        .allocate_at(ALICE, Proto::Udp, 2000, 50002, 60, now)
        .expect("soon expired");

    let fresh = Allocator::new();
    // A third party grabbed 50001 before the restore ran: first-wins.
    fresh
        .allocate_at(BOB, Proto::Udp, 3000, 50001, 600, now)
        .expect("bob wins the race");

    let later = now + Duration::from_secs(120);
    let reinstated = fresh.restore_at(vec![live, expired], later);
    assert!(
        reinstated.is_empty(),
        "conflicting + expired entries must both be skipped, got {reinstated:?}"
    );
    assert_eq!(fresh.active_count(), 1, "only bob's mapping remains");
}

// ---------------------------------------------------------------------------
// Dual-proto: TCP + UDP simultaneously on the same external port
// ---------------------------------------------------------------------------

#[test]
fn owner_maps_both_protos_on_the_same_port() {
    let alloc = Allocator::new();
    let now = Instant::now();
    let udp = alloc
        .allocate_at(ALICE, Proto::Udp, 4242, 50000, 600, now)
        .expect("udp leg");
    assert_eq!(udp.external_port, 50000);
    let tcp = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 50000, 600, now)
        .expect("tcp companion on the port this client already owns");
    assert_eq!(tcp.external_port, 50000);
    assert_eq!(alloc.active_count(), 2, "one entry per proto");
}

#[test]
fn other_client_cannot_take_the_free_proto_of_an_owned_port() {
    // Port ownership is client-level: a port live-mapped by Alice in UDP
    // must never be grantable to Bob in TCP, or two tenants would share
    // one public port number across protocols.
    let alloc = Allocator::new();
    let now = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Udp, 4242, 50000, 600, now)
        .expect("alice udp");
    let err = alloc
        .allocate_at(BOB, Proto::Tcp, 4242, 50000, 600, now)
        .expect_err("bob must not obtain the tcp slot of alice's port");
    assert!(matches!(err, NatPmpError::SuggestedPortInUse(50000)));
}

#[test]
fn random_pick_never_lands_on_the_free_proto_of_an_owned_port() {
    // Single-port pool: alice owns the only port in UDP. Bob's
    // no-preference TCP request must exhaust rather than share it.
    let alloc = Allocator::with_config(
        (50000, 50000),
        Duration::from_secs(300),
        100,
        Duration::from_secs(60),
    );
    let now = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Udp, 0, 0, 600, now)
        .expect("alice udp");
    let err = alloc
        .allocate_at(BOB, Proto::Tcp, 0, 0, 600, now)
        .expect_err("the only port is owned by alice");
    assert!(matches!(err, NatPmpError::Exhausted));
}

#[test]
fn companion_proto_does_not_consume_quota() {
    use warrenguard_natpmp_server::allocator::AllocatorConfig;
    let alloc = Allocator::from_config(AllocatorConfig {
        range: (49152, 65535),
        cooldown: Duration::from_secs(300),
        rate_limit_max: 100,
        rate_limit_window: Duration::from_secs(60),
        quota_per_client: 1,
    });
    let now = Instant::now();
    let udp = alloc
        .allocate_at(ALICE, Proto::Udp, 4242, 50000, 600, now)
        .expect("first port");
    // Same port number, other proto: not a new port, must pass the
    // 1-port quota.
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, udp.external_port, 600, now)
        .expect("companion proto is quota-free");
    // A second port number is over quota.
    let err = alloc
        .allocate_at(ALICE, Proto::Udp, 5353, 0, 600, now)
        .expect_err("second port number exceeds the quota");
    assert!(matches!(err, NatPmpError::QuotaExceeded(ip) if ip == ALICE));
}

#[test]
fn quota_counts_port_numbers_not_entries() {
    use warrenguard_natpmp_server::allocator::AllocatorConfig;
    let alloc = Allocator::from_config(AllocatorConfig {
        range: (49152, 65535),
        cooldown: Duration::from_secs(300),
        rate_limit_max: 100,
        rate_limit_window: Duration::from_secs(60),
        quota_per_client: 2,
    });
    let now = Instant::now();
    for port in [50000u16, 50001] {
        alloc
            .allocate_at(ALICE, Proto::Udp, port, port, 600, now)
            .expect("udp leg");
        alloc
            .allocate_at(ALICE, Proto::Tcp, port, port, 600, now)
            .expect("tcp leg");
    }
    assert_eq!(alloc.active_count(), 4, "2 ports x 2 protos");
    let err = alloc
        .allocate_at(ALICE, Proto::Udp, 6000, 0, 600, now)
        .expect_err("third port number exceeds the 2-port quota");
    assert!(matches!(err, NatPmpError::QuotaExceeded(_)));
}

#[test]
fn companion_proto_is_exempt_from_rate_limit() {
    // The rate limit throttles NEW port acquisition; adding the other
    // proto on a port the client already owns acquires nothing.
    let alloc = Allocator::with_config(
        (49152, 65535),
        Duration::from_secs(300),
        1,
        Duration::from_secs(60),
    );
    let now = Instant::now();
    let udp = alloc
        .allocate_at(ALICE, Proto::Udp, 4242, 0, 600, now)
        .expect("consumes the only rate-limit slot");
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, udp.external_port, 600, now)
        .expect("companion proto must not be rate limited");
    let err = alloc
        .allocate_at(ALICE, Proto::Udp, 5353, 0, 600, now)
        .expect_err("a new port acquisition is rate limited");
    assert!(matches!(err, NatPmpError::RateLimited { .. }));
}

#[test]
fn releasing_one_proto_keeps_the_other_live_and_the_port_owned() {
    let alloc = Allocator::new();
    let now = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Udp, 4242, 50000, 600, now)
        .expect("udp");
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 50000, 600, now)
        .expect("tcp");
    let released = alloc.release_by_client_at(ALICE, 4242, Proto::Udp, now);
    assert!(released.is_some(), "udp leg found and released");
    assert_eq!(alloc.active_count(), 1, "tcp leg survives");
    // The port stays alice's: bob cannot grab the freed udp slot.
    let err = alloc
        .allocate_at(BOB, Proto::Udp, 4242, 50000, 600, now)
        .expect_err("port still owned by alice through the live tcp leg");
    assert!(matches!(err, NatPmpError::SuggestedPortInUse(50000)));
    // Alice may re-add the udp leg immediately.
    alloc
        .allocate_at(ALICE, Proto::Udp, 4242, 50000, 600, now)
        .expect("owner re-adds the released proto");
}

#[test]
fn take_active_for_port_removes_both_protos() {
    // Admin revoke-by-port kills the whole port, both legs at once.
    let alloc = Allocator::new();
    let now = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Udp, 4242, 50000, 600, now)
        .expect("udp");
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 50000, 600, now)
        .expect("tcp");
    let taken = alloc.take_active_for_port_at(50000, now);
    assert_eq!(taken.len(), 2, "both legs drained: {taken:?}");
    assert_eq!(alloc.active_count(), 0);
}

#[test]
fn restore_reinstates_a_dual_proto_pair() {
    // Hot-swap persistence: a pair saved before the restart must come
    // back whole, not first-wins-by-port.
    let alloc = Allocator::new();
    let now = Instant::now();
    let udp = alloc
        .allocate_at(ALICE, Proto::Udp, 4242, 50000, 600, now)
        .expect("udp");
    let tcp = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 50000, 600, now)
        .expect("tcp");
    let fresh = Allocator::new();
    let reinstated = fresh.restore_at(vec![udp, tcp], now);
    assert_eq!(reinstated.len(), 2, "both legs reinstated: {reinstated:?}");
    assert_eq!(fresh.active_count(), 2);
}

#[test]
fn lazily_expired_port_rejects_foreign_suggestion_during_cooldown() {
    // The random-pick path already honours the expiry cooldown; the
    // explicit-suggestion path must too, or a different client could
    // inherit residual inbound traffic the instant a lease lapses.
    let alloc = Allocator::new();
    let t0 = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 0, 50000, 60, t0)
        .expect("alice lease");
    assert_eq!(a.external_port, 50000);
    let err = alloc
        .allocate_at(BOB, Proto::Tcp, 0, 50000, 600, t0 + Duration::from_secs(61))
        .expect_err("bob must not inherit the just-expired port by suggestion");
    assert!(matches!(err, NatPmpError::SuggestedPortInUse(50000)));
}

// ---------------------------------------------------------------------------
// Reclaiming a pinned port from the tenant's own departed address
// ---------------------------------------------------------------------------

/// Groups ALICE's two session addresses, the way the exit's session registry
/// answers for one account.
struct AliceTenant;

impl warrenguard_natpmp_server::allocator::QuotaPeers for AliceTenant {
    fn peer_addresses(&self, client_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
        if client_ip == ALICE || client_ip == ALICE_SECOND_SESSION {
            vec![ALICE, ALICE_SECOND_SESSION]
        } else {
            vec![client_ip]
        }
    }
}

/// The live-session view the exit already computes for the orphan reaper.
struct SessionsOn(Vec<Ipv4Addr>);

impl warrenguard_natpmp_server::allocator::LiveSessions for SessionsOn {
    fn has_live_session(&self, client_ip: Ipv4Addr) -> bool {
        self.0.contains(&client_ip)
    }
}

/// A reconnect lands the client on a new inner address while its pinned port
/// is still held by the address the dead session left behind. Refusing that
/// left the forward down for up to nine minutes with no way back
/// (2026-07-30, measured again on 2026-08-15). The predecessor holds no live
/// session, so the port comes back to the same payer, and its stale mapping
/// is handed to the caller for backend teardown.
#[test]
fn a_pinned_port_is_reclaimed_from_the_tenants_own_departed_address() {
    use std::sync::Arc;

    let alloc = Allocator::new();
    assert!(alloc.set_quota_peers(Arc::new(AliceTenant)));
    assert!(alloc.set_live_sessions(Arc::new(SessionsOn(vec![ALICE_SECOND_SESSION]))));
    let now = Instant::now();
    let dead = alloc
        .allocate_at(ALICE, Proto::Tcp, 52419, 52419, 600, now)
        .expect("the first session pins its port");

    let outcome =
        alloc.allocate_at_collecting(ALICE_SECOND_SESSION, Proto::Tcp, 52419, 52419, 600, now);

    let granted = outcome.result.expect("the tenant takes its own port back");
    assert_eq!(granted.external_port, 52419);
    assert_eq!(granted.internal_ip, ALICE_SECOND_SESSION);
    assert!(
        outcome.evicted.contains(&dead),
        "the predecessor's mapping must be surfaced so its DNAT rule is deleted"
    );
    assert_eq!(
        alloc.active_count(),
        1,
        "the port must not end up owned by two addresses at once"
    );
}

/// Both proto slots of one port belong to one address, so a takeover that
/// left the companion leg on the dead predecessor would split the port
/// between two owners and leave a DNAT rule pointing at a gone address.
#[test]
fn reclaiming_a_pinned_port_takes_over_the_companion_proto_too() {
    use std::sync::Arc;

    let alloc = Allocator::new();
    assert!(alloc.set_quota_peers(Arc::new(AliceTenant)));
    assert!(alloc.set_live_sessions(Arc::new(SessionsOn(vec![ALICE_SECOND_SESSION]))));
    let now = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Tcp, 52419, 52419, 600, now)
        .expect("the first session pins tcp");
    let dead_udp = alloc
        .allocate_at(ALICE, Proto::Udp, 52419, 52419, 600, now)
        .expect("the first session pins udp");

    let outcome =
        alloc.allocate_at_collecting(ALICE_SECOND_SESSION, Proto::Tcp, 52419, 52419, 600, now);

    outcome.result.expect("the tenant takes its own port back");
    assert!(
        outcome.evicted.contains(&dead_udp),
        "the companion leg must be torn down with the port it belongs to"
    );
    assert_eq!(alloc.active_count(), 1, "only the new tcp leg stays live");
}

/// The objection that killed identity-keyed ownership in 2026-07-30: two live
/// devices of one wallet must not steal each other's port. The exemption is
/// gated on the holder having no live session, so a live holder is still
/// refused whoever it is.
#[test]
fn a_pinned_port_held_by_a_live_session_of_the_same_tenant_stays_refused() {
    use std::sync::Arc;

    let alloc = Allocator::new();
    assert!(alloc.set_quota_peers(Arc::new(AliceTenant)));
    assert!(alloc.set_live_sessions(Arc::new(SessionsOn(vec![ALICE, ALICE_SECOND_SESSION]))));
    let now = Instant::now();
    let held = alloc
        .allocate_at(ALICE, Proto::Tcp, 52419, 52419, 600, now)
        .expect("the first device pins its port");

    let res = alloc.allocate_at(ALICE_SECOND_SESSION, Proto::Tcp, 52419, 52419, 600, now);

    assert!(
        matches!(res, Err(NatPmpError::SuggestedPortInUse(p)) if p == 52419),
        "a live holder keeps its port, same tenant or not, got {res:?}"
    );
    assert_eq!(
        alloc.snapshot_active(),
        vec![held],
        "the refusal must leave the holder's mapping untouched"
    );
}

/// The grouping never merges two tenants: a stranger's port stays refused
/// even once the stranger is gone, which is the whole point of the per-port
/// ownership check.
#[test]
fn a_pinned_port_held_by_a_departed_stranger_stays_refused() {
    use std::sync::Arc;

    let alloc = Allocator::new();
    assert!(alloc.set_quota_peers(Arc::new(AliceTenant)));
    assert!(alloc.set_live_sessions(Arc::new(SessionsOn(vec![ALICE]))));
    let now = Instant::now();
    alloc
        .allocate_at(BOB, Proto::Tcp, 52419, 52419, 600, now)
        .expect("bob pins the port first");

    let res = alloc.allocate_at(ALICE, Proto::Tcp, 52419, 52419, 600, now);

    assert!(
        matches!(res, Err(NatPmpError::SuggestedPortInUse(p)) if p == 52419),
        "another tenant's port is never grantable, dead holder or not, got {res:?}"
    );
}

/// The post-release cooldown exists to keep a port away from a DIFFERENT
/// client while residual inbound traffic may still arrive. The tenant's own
/// next address is not a different client, so the port its predecessor just
/// released is pinnable straight away, with no live-session view needed:
/// nobody holds the port at all.
#[test]
fn the_post_release_cooldown_does_not_block_the_tenants_own_next_address() {
    use std::sync::Arc;

    let alloc = Allocator::new();
    assert!(alloc.set_quota_peers(Arc::new(AliceTenant)));
    let now = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Tcp, 52419, 52419, 600, now)
        .expect("the first session pins its port");
    alloc
        .release_by_client_at(ALICE, 52419, Proto::Tcp, now)
        .expect("the first session releases it");

    let granted = alloc
        .allocate_at(
            ALICE_SECOND_SESSION,
            Proto::Tcp,
            52419,
            52419,
            600,
            now + Duration::from_secs(60),
        )
        .expect("the same payer pins the port it just released");

    assert_eq!(granted.external_port, 52419);
    assert_eq!(granted.internal_ip, ALICE_SECOND_SESSION);
}
