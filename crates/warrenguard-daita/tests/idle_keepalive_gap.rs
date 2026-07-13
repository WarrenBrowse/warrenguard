//! Characterization of DAITA idle behavior vs the keep-alive tell.
//!
//! During pure application idle the only wire activity is the
//! quinn keep-alive PING (a 30-byte metronome every ~5s). DAITA is the
//! natural place to mask it. This test drives EACH curated machine in
//! isolation through a long idle window, replicating the production pump
//! exactly: after each emitted dummy it fires `PaddingSent + TunnelSent`
//! (`DaitaState::on_dummy_sent`), never `NormalSent`. It measures how
//! much padding each machine emits well past its stop/inactivity window,
//! i.e. whether it covers idle (and thus drowns the keep-alive beacon)
//! or goes silent (leaving the tell exposed).
//!
//! The exit picks ONE machine uniformly at random, so idle masking is
//! per-machine and probabilistic. This test pins the measured behavior
//! of the whole curated pool so any change to the pool, the machine
//! specs, or the pump self-feed that alters idle coverage fails loudly.

use std::time::{Duration, Instant};

use rand_v9::SeedableRng;
use warrenguard_daita::DaitaPool;
use warrenguard_daita::daita::{DaitaEvent, DaitaState};

/// Drives one curated machine through `NormalSent` (last real packet)
/// then sustained idle, returning (early_count, late_count) padding
/// actions. `early` = first 1s (machine still warm), `late` = 3s..30s
/// (sustained idle, past every curated stop_window).
fn idle_padding_counts(name: &str) -> (usize, usize) {
    let mut rng = rand_v9::rngs::StdRng::seed_from_u64(0xA1DE);
    let cfg = DaitaPool::default_pool()
        .pick_named(name, &mut rng)
        .unwrap_or_else(|| panic!("curated pool must contain {name}"));
    if !cfg.is_enabled() {
        return (0, 0);
    }
    let start = Instant::now();
    let mut state = DaitaState::from_config(&cfg, start).expect("DaitaState builds");
    // A real last packet fires NormalSent + TunnelSent, exactly as the
    // pump's `on_real_uplink_sent`. Use the faithful sequence so each
    // machine is kicked the way production kicks it.
    state.fire_events(&[DaitaEvent::NormalSent, DaitaEvent::TunnelSent], start);

    let drain_step = Duration::from_micros(500);
    let early_end = start + Duration::from_secs(1);
    let late_start = start + Duration::from_secs(3);
    let deadline = start + Duration::from_secs(30);

    let (mut early, mut late) = (0usize, 0usize);
    let mut now = start;
    while now < deadline {
        now += drain_step;
        let fired = state.drain_expired(now);
        for machine in &fired {
            // Production pump idle self-feed: PaddingSent + TunnelSent.
            state.on_dummy_sent(*machine, now);
        }
        if now < early_end {
            early += fired.len();
        } else if now >= late_start {
            late += fired.len();
        }
    }
    (early, late)
}

#[test]
fn curated_pool_idle_coverage_is_pinned() {
    let names = DaitaPool::default_pool().entry_names();
    let mut counts = std::collections::BTreeMap::new();
    for name in &names {
        let (early, late) = idle_padding_counts(name);
        println!("machine={name:<18} early(0-1s)={early:<6} late(3-30s idle)={late}");
        counts.insert(*name, (early, late));
    }
    let covers_idle: Vec<&str> = counts
        .iter()
        .filter(|(_, (_, late))| *late > 0)
        .map(|(n, _)| *n)
        .collect();
    let silent_idle: Vec<&str> = counts
        .iter()
        .filter(|(_, (_, late))| *late == 0)
        .map(|(n, _)| *n)
        .collect();
    println!("covers idle (masks keep-alive): {covers_idle:?}");
    println!("silent during idle (tell exposed): {silent_idle:?}");

    // Verified behavior (locked). The constant-rate machines self-sustain
    // through idle because the pump's dummy self-feed fires TunnelSent,
    // which holds their stop/inactivity window open indefinitely:
    //   - tamaraw  : heavy constant-rate cover (~200 pkt/s), masks the tell
    //   - netflow  : a weak trickle (~1 dummy / few seconds), barely better
    //                than the keep-alive beacon it would replace
    //   - front / interspace_server / scrambler_server: SILENT past their
    //     window, so the keep-alive tell stays fully exposed.
    // DAITA is off by default and the exit rolls 1-of-5 at random, so
    // idle masking is conditional (~off-by-default; ~2/5 when on), never a
    // baseline obfuscation property. Closing the gap as a baseline needs
    // the follow-up (idle-cover machine or always-on idle filler).
    assert_eq!(
        covers_idle,
        vec!["netflow", "tamaraw"],
        "exactly tamaraw (heavy) and netflow (trickle) self-sustain through \
         idle; the others go silent. A change here moves idle keep-alive \
         masking and must update this test. counts={counts:?}"
    );
    assert!(
        counts["tamaraw"].1 > 1000,
        "tamaraw must give heavy constant-rate idle cover, got {}",
        counts["tamaraw"].1
    );
    assert!(
        (1..=100).contains(&counts["netflow"].1),
        "netflow must give only a weak idle trickle, got {}",
        counts["netflow"].1
    );
}
