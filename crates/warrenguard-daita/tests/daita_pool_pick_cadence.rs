//! Validate that Tamaraw fires at its documented cadence when the
//! surrounding state has fresh traffic events.
//!
//! A cloud bench observed `sent_padding=4 over 25 s` for the
//! multi-hop client uplink, which is two orders of magnitude below the
//! documented Tamaraw rate (p = 5 ms → ~200 pkt/s). Two hypotheses :
//!   1. the random pool pick landed on a non-Tamaraw entry (FRONT or
//!      InterspaceServer), which have different - and lower - emit
//!      cadences by design;
//!   2. maybenot's Tamaraw `p` parameter is in a different unit than
//!      microseconds.
//!
//! This test pins the machine choice to Tamaraw, drives the framework
//! with synthetic TunnelSent/TunnelRecv events for one second of
//! simulated time, and asserts that `drain_expired` returns the
//! expected order of magnitude of SendPadding actions. If maybenot
//! changes the `p` unit semantics in a future version this regression
//! gate will fail loudly.

use std::time::{Duration, Instant};

use maybenot_machines::{StaticMachine, get_machine};
use rand_v9::SeedableRng;
use warrenguard_daita::daita::{DaitaConfig, DaitaConfigExt, DaitaEvent, DaitaState};

/// There was a Tamaraw cadence regression caused by Warren's
/// `DaitaState::apply_action` collapsing `BlockOutgoing` and
/// `SendPadding` into the same per-machine action timer without
/// firing the `BlockingBegin` event that Tamaraw's state machine
/// requires to transition out of its block state. The fix extended
/// `MachineTimers` with an `action_kind` discriminator and fired
/// `BlockingBegin` / `BlockingEnd` events directly from
/// `drain_expired` so the framework always sees the state machine's
/// expected event sequence.
///
/// Independent finding: maybenot's `Tamaraw { p }` parameter is in
/// `s/packet`, so the historical Warren value `p = 5_000.0` was 5000
/// seconds per padding (= ~83 minutes between dummies, effectively a
/// disabled defense). The corrected value `p = 0.005` is what the
/// curated pool ships; this test pins it explicitly so the assertion
/// is independent of pool-pick RNG.
#[test]
fn tamaraw_fires_padding_at_expected_cadence() {
    let mut rng = rand_v9::rngs::StdRng::seed_from_u64(0xCADE);
    let machines = get_machine(
        &[StaticMachine::Tamaraw {
            // `p` is "s/packet" per maybenot's own doc.
            // 0.005 = 5 ms/packet = 200 pkt/s constant-rate. This
            // value is also what `DaitaPool::default_pool` ships.
            p: 0.005,
            // 1 s of no-normal-packet stops the machine; the test
            // drives an event every 10 ms so this is never reached.
            stop_window: 1_000_000.0,
        }],
        &mut rng,
    );
    let cfg = DaitaConfig::from_machines(&machines, 0.5, 0.0);
    assert!(cfg.is_enabled(), "Tamaraw config builds");

    let start = Instant::now();
    let mut state = DaitaState::from_config(&cfg, start).expect("DaitaState builds");

    // Kick the machine into the padding state with a single
    // NormalSent (state 0 -> 1 -> BlockingBegin -> 2). Then simulate
    // 1 s of *idle* tunnel time with a tight 1 ms drain loop, mimicking
    // the production pump (`run_uplink_with_daita`) which calls
    // `drain_expired` on every timer wake-up and re-fires
    // `PaddingSent + TunnelSent` after the dummy is actually emitted
    // - exactly what re-arms Tamaraw's constant-rate padding.
    //
    // Tamaraw's `replace=true` SendPadding semantics mean any
    // intervening `TunnelSent` *resets* the padding timer to 5 ms
    // in the future. Driving TunnelSent at 10 ms cadence in the
    // pre-fix version of this test starved the timer and made the
    // assertion fall to 0/1 actions; the fix is to mirror the real
    // pump (PaddingSent feedback only fires after the dummy is
    // actually transmitted).
    state.fire_events(&[DaitaEvent::NormalSent], start);
    let drain_step = Duration::from_micros(500);
    let mut fired_count = 0usize;
    let mut now = start;
    let deadline = start + Duration::from_secs(1);
    while now < deadline {
        now += drain_step;
        let fired = state.drain_expired(now);
        for machine in &fired {
            // The pump-side production code fires
            // `PaddingSent + TunnelSent` after the dummy hits the
            // wire. Mirror it here so the action timer re-arms and
            // Tamaraw produces the documented constant-rate cadence.
            state.fire_events(
                &[
                    DaitaEvent::PaddingSent { machine: *machine },
                    DaitaEvent::TunnelSent,
                ],
                now,
            );
        }
        fired_count += fired.len();
    }

    // Expected: p = 5 ms in maybenot's microsecond-Duration unit → 1 s
    // of simulated time should yield ~200 SendPadding actions. Allow a
    // generous lower bound (50) so the test is not flaky on scheduler
    // jitter and an upper bound (400) so a unit-change regression
    // (e.g. p = 5 µs interpreted as 5 ms) fires the assertion too.
    assert!(
        fired_count >= 50,
        "Tamaraw must fire at least 50 SendPadding actions in 1s of simulated traffic, got {fired_count} (p=5000 cadence regression)"
    );
    assert!(
        fired_count <= 400,
        "Tamaraw must NOT fire more than 400 SendPadding actions in 1s (got {fired_count}: maybenot unit change?)"
    );

    // `DaitaState::metrics()` exposes the same counters that the drain
    // loop saw. `padding_fired` should track the
    // local `fired_count` minus the single `BlockingBegin` drain
    // (Tamaraw's state-1 BlockOutgoing action fires once with
    // timeout=0 before the SendPadding loop takes over). The
    // assertion below allows that off-by-one without binding the
    // test to the exact internal kind dispatch.
    let metrics = state.metrics();
    assert_eq!(
        metrics.blocking_begins, 1,
        "Tamaraw must fire exactly one BlockingBegin in its session lifetime (state 1 → 2 transition); got {}",
        metrics.blocking_begins
    );
    assert!(
        metrics.padding_fired + metrics.blocking_begins == fired_count as u64,
        "DaitaMetrics::padding_fired + blocking_begins must match local fired_count (metrics={metrics:?}, fired_count={fired_count})"
    );
    // Tamaraw's BlockOutgoing duration is MAX_SAMPLED_BLOCK_DURATION
    // (~1 day in microseconds), so within a 1 s simulated window
    // `block_end_at` cannot have elapsed yet → no BlockingEnd.
    assert_eq!(
        metrics.blocking_ends, 0,
        "Tamaraw block must NOT end within a 1s window (MAX_SAMPLED_BLOCK_DURATION is ~1 day); got {}",
        metrics.blocking_ends
    );
}

#[test]
fn pool_pick_with_name_returns_consistent_entry() {
    use warrenguard_daita::DaitaPool;
    let pool = DaitaPool::default_pool();
    let names: std::collections::HashSet<&'static str> = pool.entry_names().into_iter().collect();
    assert!(
        names.contains("tamaraw"),
        "pool must contain tamaraw as a named entry"
    );

    let mut rng = rand_v9::rngs::StdRng::seed_from_u64(0xCAFE);
    let picked = pool.pick_with_name(&mut rng).expect("non-empty pool picks");
    assert!(
        names.contains(picked.0),
        "pick_with_name returned a name ({}) not in the curated list {:?}",
        picked.0,
        names
    );
}
