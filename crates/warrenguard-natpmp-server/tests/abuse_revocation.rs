//! Abuse revocation: a reported port is taken off its tenant and held out of
//! reach for a quarantine that nothing bypasses, the tenant's own reclaim of a
//! port it just lost included.
//!
//! The ordinary cooldown a release arms is deliberately lifted for the same
//! tenant, so a payer that reconnects keeps its pinned forward. That is the
//! wrong answer for a port an operator closed after an abuse report: the
//! pinned client re-requests it at its next renewal and would get it straight
//! back. Every test drives the clock through the `_at` entry points.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use warrenguard_natpmp_server::allocator::{Allocator, QuotaPeers, ReleaseObserver};
use warrenguard_natpmp_server::{Allocation, NatPmpError, Proto};

const ALICE: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 42);
const ALICE_SECOND_SESSION: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 43);
const BOB: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 99);
const PINNED: u16 = 50000;
const QUARANTINE: Duration = Duration::from_secs(48 * 3600);

/// Groups ALICE's two sessions into one tenant, which is what arms the
/// tenant-reclaim bypass the quarantine has to defeat.
struct AliceTenant;

impl QuotaPeers for AliceTenant {
    fn peer_addresses(&self, client_ip: Ipv4Addr) -> Vec<Ipv4Addr> {
        if client_ip == ALICE || client_ip == ALICE_SECOND_SESSION {
            vec![ALICE, ALICE_SECOND_SESSION]
        } else {
            vec![client_ip]
        }
    }
}

/// A small range, a short cooldown and a loose rate limit, so every refusal
/// below is the quarantine's and nothing else's.
fn allocator() -> Allocator {
    let alloc = Allocator::with_config(
        (PINNED, PINNED + 9),
        Duration::from_secs(300),
        1000,
        Duration::from_secs(60),
    );
    assert!(alloc.set_quota_peers(Arc::new(AliceTenant)));
    alloc
}

/// ALICE holds `PINNED` over TCP and UDP, the way a client forwards one port.
fn pin_pair(alloc: &Allocator, now: Instant) {
    for proto in [Proto::Tcp, Proto::Udp] {
        let a = alloc
            .allocate_at(ALICE, proto, 4242, PINNED, 3600, now)
            .expect("pinned leg");
        assert_eq!(a.external_port, PINNED);
    }
}

#[test]
fn abuse_revoke_takes_both_legs_of_the_port_and_returns_them() {
    let alloc = allocator();
    let t0 = Instant::now();
    pin_pair(&alloc, t0);

    let revoked = alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0);

    let mut protos: Vec<Proto> = revoked.iter().map(|a| a.proto).collect();
    protos.sort_by_key(|p| matches!(p, Proto::Udp));
    assert_eq!(protos, vec![Proto::Tcp, Proto::Udp], "{revoked:?}");
    assert!(
        revoked
            .iter()
            .all(|a| a.external_port == PINNED && a.internal_ip == ALICE),
        "the caller tears down exactly what held the port: {revoked:?}"
    );
    assert_eq!(alloc.active_count(), 0);
    assert_eq!(alloc.metrics().abuse_revocations_total, 1);
}

#[test]
fn a_plain_revoke_still_lets_the_tenant_reclaim_its_port() {
    // The baseline the quarantine exists to change: after an ordinary
    // take-by-port, the tenant's explicit suggestion bypasses its own
    // cooldown. If this ever stops holding, the test below proves nothing.
    let alloc = allocator();
    let t0 = Instant::now();
    pin_pair(&alloc, t0);
    alloc.take_active_for_port_at(PINNED, t0);

    let back = alloc
        .allocate_at(
            ALICE_SECOND_SESSION,
            Proto::Tcp,
            4242,
            PINNED,
            3600,
            t0 + Duration::from_secs(1),
        )
        .expect("reclaim after a plain revoke");

    assert_eq!(back.external_port, PINNED);
}

#[test]
fn the_quarantine_refuses_the_tenant_reclaim_and_hands_out_another_port() {
    let alloc = allocator();
    let t0 = Instant::now();
    pin_pair(&alloc, t0);
    alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0);

    for (client, at) in [
        (ALICE, t0 + Duration::from_secs(1)),
        (ALICE_SECOND_SESSION, t0 + Duration::from_secs(600)),
        (ALICE, t0 + QUARANTINE - Duration::from_secs(1)),
    ] {
        let got = alloc
            .allocate_at(client, Proto::Tcp, 4242, PINNED, 3600, at)
            .expect("a quarantined suggestion reads as no preference");
        assert_ne!(
            got.external_port, PINNED,
            "the reported port must stay out of the former tenant's reach"
        );
        alloc.release_at(&got, at);
    }
}

#[test]
fn a_pinned_refresh_after_an_abuse_revoke_does_not_get_the_port_back() {
    // The failure doc 105 names: the pinned client's next renewal re-presents
    // the same tuple and the same suggestion, and got its reported port back
    // inside the ordinary cooldown.
    let alloc = allocator();
    let t0 = Instant::now();
    pin_pair(&alloc, t0);
    alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0);

    let renewal = t0 + Duration::from_secs(1800);
    let pinned = alloc
        .allocate_at(ALICE, Proto::Udp, 4242, PINNED, 3600, renewal)
        .expect("renewal is served");
    let unpinned = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, 0, 3600, renewal)
        .expect("renewal without a suggestion is served");

    assert_ne!(pinned.external_port, PINNED);
    assert_ne!(unpinned.external_port, PINNED);
}

#[test]
fn nobody_else_gets_the_port_during_the_quarantine_either() {
    let alloc = Allocator::with_config(
        (PINNED, PINNED),
        Duration::from_secs(1),
        1000,
        Duration::from_secs(60),
    );
    let t0 = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, PINNED, 3600, t0)
        .expect("pinned");
    alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0);

    let during = alloc.allocate_at(BOB, Proto::Tcp, 80, 0, 3600, t0 + Duration::from_secs(10));

    assert!(
        matches!(during, Err(NatPmpError::Exhausted)),
        "a one-port pool with its port quarantined has nothing to give: {during:?}"
    );
}

#[test]
fn the_quarantine_lifts_once_it_has_run_and_the_tenant_may_pin_again() {
    let alloc = allocator();
    let t0 = Instant::now();
    pin_pair(&alloc, t0);
    alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0);

    let after = alloc
        .allocate_at(
            ALICE,
            Proto::Tcp,
            4242,
            PINNED,
            3600,
            t0 + QUARANTINE + Duration::from_secs(1),
        )
        .expect("served after the quarantine");

    assert_eq!(after.external_port, PINNED);
}

#[test]
fn an_abuse_revoke_on_a_free_port_still_quarantines_it() {
    // A report can land after the mapping lapsed on its own. The port was
    // still reported, and the tenant that lapsed must not walk back onto it.
    let alloc = allocator();
    let t0 = Instant::now();

    let revoked = alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0);
    let got = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, PINNED, 3600, t0)
        .expect("served elsewhere");

    assert!(revoked.is_empty());
    assert_ne!(got.external_port, PINNED);
    assert_eq!(
        alloc.metrics().abuse_revocations_total,
        0,
        "nothing was taken, so nothing was revoked"
    );
}

#[test]
fn a_second_report_never_shortens_a_running_quarantine() {
    let alloc = allocator();
    let t0 = Instant::now();
    alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0);
    alloc.revoke_for_abuse_at(PINNED, Duration::from_secs(1), t0);

    let got = alloc
        .allocate_at(
            ALICE,
            Proto::Tcp,
            4242,
            PINNED,
            3600,
            t0 + Duration::from_secs(3600),
        )
        .expect("served elsewhere");

    assert_ne!(got.external_port, PINNED);
}

#[test]
fn expired_quarantines_are_purged() {
    let alloc = allocator();
    let t0 = Instant::now();
    alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0);
    assert_eq!(alloc.abuse_quarantine_count(), 1);

    alloc
        .allocate_at(BOB, Proto::Tcp, 80, 0, 3600, t0 + QUARANTINE)
        .expect("any allocation trims the side maps");

    assert_eq!(
        alloc.abuse_quarantine_count(),
        0,
        "the quarantine map must not grow with every report ever filed"
    );
}

// ---------------------------------------------------------------------------
// Release observer: a deployer that binds something to a port has to learn
// when the port goes, whichever path took it.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Recorder(Mutex<Vec<Allocation>>);

impl Recorder {
    fn ports(&self) -> Vec<(u16, Proto)> {
        self.0
            .lock()
            .expect("recorder")
            .iter()
            .map(|a| (a.external_port, a.proto))
            .collect()
    }
}

impl ReleaseObserver for Recorder {
    fn released(&self, allocations: &[Allocation]) {
        self.0
            .lock()
            .expect("recorder")
            .extend_from_slice(allocations);
    }
}

fn observed() -> (Allocator, Arc<Recorder>) {
    let alloc = allocator();
    let recorder = Arc::new(Recorder::default());
    assert!(alloc.set_release_observer(recorder.clone()));
    (alloc, recorder)
}

#[test]
fn a_client_release_is_reported() {
    let (alloc, seen) = observed();
    let t0 = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Udp, 4242, PINNED, 3600, t0)
        .expect("alloc");

    alloc.release_by_client_at(ALICE, 4242, Proto::Udp, t0);

    assert_eq!(seen.ports(), vec![(PINNED, Proto::Udp)]);
}

#[test]
fn a_release_through_the_backend_path_is_reported() {
    let (alloc, seen) = observed();
    let t0 = Instant::now();
    let a = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, PINNED, 3600, t0)
        .expect("alloc");

    alloc.release_at(&a, t0);
    alloc.release_at(&a, t0);

    assert_eq!(
        seen.ports(),
        vec![(PINNED, Proto::Tcp)],
        "a release that removed nothing reports nothing"
    );
}

#[test]
fn a_lapsed_mapping_is_reported_when_the_sweep_drops_it() {
    let (alloc, seen) = observed();
    let t0 = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, PINNED, 60, t0)
        .expect("short lease");

    alloc
        .allocate_at(BOB, Proto::Tcp, 80, 0, 3600, t0 + Duration::from_secs(120))
        .expect("next request sweeps");

    assert_eq!(seen.ports(), vec![(PINNED, Proto::Tcp)]);
}

#[test]
fn a_refresh_that_moves_the_port_reports_the_old_one() {
    let (alloc, seen) = observed();
    let t0 = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, PINNED, 3600, t0)
        .expect("alloc");

    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, PINNED + 1, 3600, t0)
        .expect("port change");

    assert_eq!(seen.ports(), vec![(PINNED, Proto::Tcp)]);
}

#[test]
fn a_refresh_on_the_same_port_reports_nothing() {
    // The mapping never stops existing, so a deployer must not drop what it
    // bound to it: an abuse report landing between the two halves of a
    // renewal would otherwise find the port unattributed.
    let (alloc, seen) = observed();
    let t0 = Instant::now();
    alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, PINNED, 3600, t0)
        .expect("alloc");

    alloc
        .allocate_at(
            ALICE,
            Proto::Tcp,
            4242,
            PINNED,
            3600,
            t0 + Duration::from_secs(1800),
        )
        .expect("renewal");
    alloc
        .allocate_at(
            ALICE,
            Proto::Tcp,
            4242,
            0,
            3600,
            t0 + Duration::from_secs(3600),
        )
        .expect("renewal without a suggestion");

    assert!(seen.ports().is_empty(), "{:?}", seen.ports());
}

#[test]
fn what_the_deployer_takes_itself_is_returned_rather_than_reported() {
    // The deployer that revokes a port for abuse reads what it bound to that
    // port from the allocations handed back. Reporting them through the
    // observer first would have it drop the binding before it could read it.
    let (alloc, seen) = observed();
    let t0 = Instant::now();
    pin_pair(&alloc, t0);
    alloc
        .allocate_at(BOB, Proto::Tcp, 80, PINNED + 5, 3600, t0)
        .expect("bob");
    alloc
        .allocate_at(BOB, Proto::Tcp, 81, PINNED + 6, 3600, t0)
        .expect("bob");

    assert_eq!(alloc.revoke_for_abuse_at(PINNED, QUARANTINE, t0).len(), 2);
    assert_eq!(alloc.take_active_for_port_at(PINNED + 5, t0).len(), 1);
    assert_eq!(alloc.take_active_for_ip_at(BOB, t0).len(), 1);

    assert!(seen.ports().is_empty(), "{:?}", seen.ports());
}

#[test]
fn the_release_observer_refuses_to_be_rewired() {
    let (alloc, _seen) = observed();

    assert!(
        !alloc.set_release_observer(Arc::new(Recorder::default())),
        "a second wiring would silently orphan every binding the first one holds"
    );
}

#[test]
fn an_unbounded_quarantine_is_capped_rather_than_overflowing_the_clock() {
    let alloc = allocator();
    let t0 = Instant::now();

    alloc.revoke_for_abuse_at(PINNED, Duration::MAX, t0);
    let got = alloc
        .allocate_at(ALICE, Proto::Tcp, 4242, PINNED, 3600, t0 + QUARANTINE)
        .expect("served elsewhere");

    assert_ne!(got.external_port, PINNED);
}
