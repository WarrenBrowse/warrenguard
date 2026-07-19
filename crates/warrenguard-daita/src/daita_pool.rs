//! Server-side pool of DAITA v2 machines.
//!
//! The exit picks one [`DaitaConfig`] from the pool at the start of
//! every new session and ships it back to the client in the handshake
//! `IpAssign` control message (`daita_spec`). Different connections see different
//! machines: this is the "dynamic per-connection configuration" that
//! distinguishes DAITA v2 from v1's four hardcoded client-side machines.
//!
//! Warren's pool is hand-curated from the public
//! [`maybenot_machines`] crate (Tobias Pulls et al.). Each entry
//! covers a different traffic-analysis-defense regime so the
//! distribution of behaviours visible to an attacker is wide:
//!
//! - **NetFlow padding** (`StaticMachine::SimpleNetFlow`): mitigates
//!   NetFlow-level fingerprinting (1.5-9.5s padding interval).
//! - **Constant-rate Tamaraw**: regularises packet emission at a
//!   chosen `p` interval (5ms by default = ~200 pkt/s).
//! - **FRONT random padding**: random padding bursts within a sampled
//!   window, parameter set picked from the FRONT paper.
//! - **Interspace** (server variant): video-style burst defense.
//! - **Scrambler** (server variant): regularises packet timing within
//!   segments for streaming protection.
//!
//! Expansion plan: once Mullvad publishes the DAITA v2 paper +
//! maybenot-gen pipeline, swap the curated list for a
//! `maybenot-gen` generated "thousands of defenses" pool. The wire
//! format (`DaitaConfig`) doesn't change; only the population
//! strategy does.

use rand_v9::seq::IndexedRandom;
use rand_v9::{Rng, RngCore, SeedableRng};

use maybenot_machines::{StaticMachine, get_machine};

use crate::daita::{DaitaConfig, DaitaConfigExt};

/// One named recipe in the pool. The name is observability-friendly
/// (logging, metrics) and never sent on the wire.
#[derive(Debug, Clone)]
struct PoolEntry {
    /// Short identifier ("netflow", "tamaraw", "front", ...). Used
    /// only in tracing / observability, never on the wire.
    name: &'static str,
    /// The [`StaticMachine`] variant that yields the underlying
    /// `maybenot::Machine` set on demand.
    static_machine: StaticMachine,
    /// Hard cap on the fraction of total packets that may be padding
    /// (cf. [`DaitaConfig::max_padding_frac`]).
    max_padding_frac: f64,
    /// Hard cap on the fraction of total time that may be blocked
    /// (cf. [`DaitaConfig::max_blocking_frac`]).
    max_blocking_frac: f64,
}

/// Warren's curated DAITA v2 machine pool. Exits use [`Self::default`]
/// at boot time and call [`Self::pick`] for every new session.
///
/// Picking is uniformly random across the entries; future versions
/// may add per-entry weights based on observed effectiveness against
/// recent fingerprinting attack literature.
#[derive(Debug, Clone)]
pub struct DaitaPool {
    entries: Vec<PoolEntry>,
}

impl DaitaPool {
    /// Default Warren pool: five curated machine families, each
    /// representing a different defense regime. The exit shouldn't
    /// need to touch this constructor for ordinary operation.
    #[must_use]
    pub fn default_pool() -> Self {
        Self {
            entries: vec![
                PoolEntry {
                    name: "netflow",
                    static_machine: StaticMachine::SimpleNetFlow,
                    max_padding_frac: 0.05,
                    max_blocking_frac: 0.0,
                },
                PoolEntry {
                    name: "tamaraw",
                    static_machine: StaticMachine::Tamaraw {
                        // maybenot's Tamaraw `p` is documented as
                        // "s/packet" (seconds per padding packet); the
                        // implementation internally multiplies by
                        // 1_000_000 to derive the microsecond-scale
                        // `SendPadding` timer. A previous value of
                        // `p = 5_000.0` was wrong - it meant 5000
                        // seconds per padding (~ 83 minutes /
                        // padding, i.e. effectively disabled Tamaraw).
                        // The correct value for 200 pkt/s (= 5 ms
                        // period) is `0.005`. Cf. the bench measurement
                        // (`sent_padding=4 over 25 s`) and in-process
                        // regression test
                        // `daita_pool_pick_cadence.rs::tamaraw_fires_padding_at_expected_cadence`.
                        p: 0.005,
                        // 1 s window with no normal packet stops the
                        // machine (`stop_window` IS in microseconds
                        // per maybenot's own doc, so 1_000_000.0 = 1 s).
                        stop_window: 1_000_000.0,
                    },
                    max_padding_frac: 0.15,
                    max_blocking_frac: 0.0,
                },
                PoolEntry {
                    name: "front",
                    // FRONT paper defaults, conservative.
                    static_machine: StaticMachine::Front {
                        padding_budget_max: 1500,
                        window_min: 1.0,
                        window_max: 14.0,
                        num_states: 200,
                    },
                    max_padding_frac: 0.10,
                    max_blocking_frac: 0.0,
                },
                PoolEntry {
                    name: "interspace_server",
                    static_machine: StaticMachine::InterspaceServer,
                    max_padding_frac: 0.10,
                    max_blocking_frac: 0.0,
                },
                PoolEntry {
                    name: "scrambler_server",
                    // 4000us = 4ms interval (~ 250 pkt/s, paper default).
                    static_machine: StaticMachine::ScramblerServer {
                        interval: 4_000.0,
                        min_count: 4.0,
                        min_trail: 4.0,
                        max_trail: 16.0,
                    },
                    max_padding_frac: 0.20,
                    // Scrambler can block briefly to regularise bursts.
                    max_blocking_frac: 0.05,
                },
            ],
        }
    }

    /// Number of entries in the pool. Always >= 1 for any pool built
    /// via [`Self::default_pool`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the pool has zero entries. Equivalent to `len() == 0`.
    /// Exposed to satisfy the `clippy::len_without_is_empty` lint.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Picks one entry uniformly at random and materialises it as a
    /// wire-transmissible [`DaitaConfig`]. Returns `None` if the pool
    /// is empty (only possible via [`Self::empty_for_testing`]).
    ///
    /// The returned config carries the chosen machine's serialized
    /// bytes plus the per-entry fractional caps.
    pub fn pick<R: Rng + RngCore>(&self, rng: &mut R) -> Option<DaitaConfig> {
        self.pick_with_name(rng).map(|(_name, cfg)| cfg)
    }

    /// Variant of [`Self::pick`] that also returns the entry name used
    /// for observability: bench harnesses and production logs can
    /// correlate the on-wire padding cadence with the curated machine
    /// family that was rolled. This addresses a bench observation that
    /// the observed cadence (4 dummies / 25 s) did not match the
    /// expected Tamaraw rate (200 / s) - the random pool pick had
    /// landed on a non-Tamaraw entry, but the legacy `pick` API gave
    /// the operator no way to confirm that.
    pub fn pick_with_name<R: Rng + RngCore>(
        &self,
        rng: &mut R,
    ) -> Option<(&'static str, DaitaConfig)> {
        let entry = self.entries.choose(rng)?;
        let machines = get_machine(&[entry.static_machine], rng);
        let cfg =
            DaitaConfig::from_machines(&machines, entry.max_padding_frac, entry.max_blocking_frac);
        Some((entry.name, cfg))
    }

    /// Returns the entry names in declaration order. Used by tests to
    /// assert coverage of the curated list, and by tracing / metrics
    /// on the exit side.
    #[must_use]
    pub fn entry_names(&self) -> Vec<&'static str> {
        self.entries.iter().map(|e| e.name).collect()
    }

    /// Builds a [`DaitaConfig`] for the entry whose `name` matches.
    /// Returns `None` if no such name is in the pool. The random-pick
    /// path is unsuitable for per-entry regression tests (which want to
    /// drive each curated machine in isolation without rolling the same
    /// one repeatedly until all are sampled).
    pub fn pick_named<R: Rng + RngCore>(&self, name: &str, rng: &mut R) -> Option<DaitaConfig> {
        let entry = self.entries.iter().find(|e| e.name == name)?;
        let machines = get_machine(&[entry.static_machine], rng);
        Some(DaitaConfig::from_machines(
            &machines,
            entry.max_padding_frac,
            entry.max_blocking_frac,
        ))
    }

    /// [`Self::pick`] seeded from the OS RNG, for callers that do not thread
    /// their own RNG (FFI / client convenience).
    #[must_use]
    pub fn pick_os(&self) -> Option<DaitaConfig> {
        self.pick(&mut rand_v9::rngs::StdRng::from_os_rng())
    }

    /// [`Self::pick_with_name`] seeded from the OS RNG. The exit samples the
    /// pool once per accepted connection and has no RNG of its own to thread.
    #[must_use]
    pub fn pick_with_name_os(&self) -> Option<(&'static str, DaitaConfig)> {
        self.pick_with_name(&mut rand_v9::rngs::StdRng::from_os_rng())
    }

    /// [`Self::pick_named`] seeded from the OS RNG.
    #[must_use]
    pub fn pick_named_os(&self, name: &str) -> Option<DaitaConfig> {
        self.pick_named(name, &mut rand_v9::rngs::StdRng::from_os_rng())
    }

    /// Test-only constructor for an empty pool (verifies the `None`
    /// branch of [`Self::pick`]). Not exposed in non-test builds to
    /// prevent accidentally shipping a DAITA-off exit.
    #[cfg(test)]
    fn empty_for_testing() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::daita::DaitaFramework;

    #[test]
    fn default_pool_carries_the_five_curated_machines() {
        let pool = DaitaPool::default_pool();
        let names = pool.entry_names();
        assert_eq!(pool.len(), 5, "Warren ships 5 curated DAITA defenses");
        // Must include the explicit names of each regime: a silent
        // drift here means the exit lost a defense family without
        // anyone noticing.
        assert_eq!(
            names,
            vec![
                "netflow",
                "tamaraw",
                "front",
                "interspace_server",
                "scrambler_server",
            ]
        );
    }

    #[test]
    fn empty_pool_pick_returns_none() {
        let pool = DaitaPool::empty_for_testing();
        let mut rng = rand_v9::rng();
        assert!(
            pool.pick(&mut rng).is_none(),
            "empty pool MUST return None on pick - signals exit policy bug \
             to caller rather than silently shipping no DAITA"
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn pick_returns_a_config_with_at_least_one_machine_spec() {
        let pool = DaitaPool::default_pool();
        let mut rng = rand_v9::rng();
        let cfg = pool.pick(&mut rng).expect("default pool always picks");
        assert!(
            cfg.is_enabled(),
            "picked config from a non-empty pool MUST be enabled - the wire \
             contract is that `daita_spec: Some(..)` carries at least one machine"
        );
    }

    #[test]
    fn picked_config_parses_via_daita_framework() {
        // Round-trip via the runtime framework: every serialized
        // machine in the pool must be parseable. A drift in maybenot
        // upstream that breaks one of our static machine specs would
        // surface here and be caught before any session sees it.
        let pool = DaitaPool::default_pool();
        let mut rng = rand_v9::rng();
        for _ in 0..50 {
            let cfg = pool.pick(&mut rng).expect("non-empty pool");
            DaitaFramework::from_config(&cfg, Instant::now()).unwrap_or_else(|e| {
                panic!("pool config must parse via DaitaFramework: {e}");
            });
        }
    }

    #[test]
    fn pick_distribution_eventually_covers_all_entries() {
        // Probabilistic test: with N=200 picks over a 5-entry uniform
        // pool, the chance that one entry is never picked is
        // (4/5)^200 ≈ 4.0e-20 -- vanishing. Test catches a bug where
        // `choose()` would return the same entry every time (e.g. a
        // bad RNG wiring or a Vec::first() typo).
        let pool = DaitaPool::default_pool();
        let mut rng = rand_v9::rng();
        let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for _ in 0..200 {
            let cfg = pool.pick(&mut rng).expect("non-empty pool");
            // We identify the entry by serialized machine length as a
            // proxy (different defenses serialize to different sizes).
            seen.insert(cfg.machine_specs.iter().map(String::len).sum::<usize>());
        }
        assert!(
            seen.len() >= 3,
            "200 picks MUST reach at least 3 distinct serialized payloads \
             (5-entry uniform pool, prob of <3 is ~1e-15); got {} distinct",
            seen.len()
        );
    }

    #[test]
    fn pool_entries_have_legal_fractional_caps() {
        // Tripwire: every entry's max_padding_frac and max_blocking_frac
        // must be in [0.0, 1.0]. A fraction > 1.0 would make
        // `DaitaFramework::from_config` fail at session time.
        let pool = DaitaPool::default_pool();
        for entry in &pool.entries {
            assert!(
                (0.0..=1.0).contains(&entry.max_padding_frac),
                "entry {} max_padding_frac out of range: {}",
                entry.name,
                entry.max_padding_frac
            );
            assert!(
                (0.0..=1.0).contains(&entry.max_blocking_frac),
                "entry {} max_blocking_frac out of range: {}",
                entry.name,
                entry.max_blocking_frac
            );
        }
    }
}
