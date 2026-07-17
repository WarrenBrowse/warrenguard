//! In-tunnel egress liveness probe.
//!
//! RX-silence detection (the supervisor's dead-path watch) only sees the QUIC
//! transport: an exit that is drained or half-swapped during a fleet rollout
//! keeps ACKing keep-alives, so the session never looks dead while the exit
//! forwards NOTHING and the UI shows "Connected" with zero actual internet.
//! This probe closes that gap by exercising the datapath end to end: a periodic
//! DNS query THROUGH the tunnel to the exit-provided resolver (the tunnel
//! gateway, the same server the system DNS uses while connected). Any answer
//! proves the exit decapsulates, forwards and can reach its upstream; the
//! gateway address is only routable via the tunnel, so the probe can never leak
//! outside it.
//!
//! Escalation is debounced: [`EgressProbeConfig::failure_threshold`] consecutive
//! failures publish an "egress dead" verdict; one success clears it. A rollout
//! hot-swap blip (~1-2 s) never reaches the threshold. While the caller reports
//! no published session the probe is skipped entirely (the RX-silence machinery
//! owns that case) and the failure count resets.
//!
//! On a dead verdict the probe does not just banner. When a drain advisory is
//! active it prefers the drain reactor's gap-free migration hook; otherwise it
//! escalates a full reconnect through the caller's escalation channel (the same
//! path RX-silence uses): a live QUIC session over an exit that forwards nothing
//! is a dead path the RX-silence guards cannot see, so banner-and-wait would
//! leave the user offline until the exit self-healed. A faster startup cadence
//! probes until the first success so a circuit that is dead from connect is
//! caught in ~20 s instead of ~75 s.
//!
//! This is the reusable engine home for that behavior. The scheduler
//! [`run_egress_probe`] is transport-agnostic: a consumer implements
//! [`EgressProbeIo`] over its own tunnel (the SDK userland proxy, the desktop
//! daemon, the FRB client), supplying a way to send/receive the probe datagram
//! and an escalation callback. TUN-routed consumers can reuse
//! [`probe_gateway_dns`] verbatim for the datapath probe.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Disable knob: `WARREN_EGRESS_PROBE=0` turns the probe off.
pub const EGRESS_PROBE_ENV: &str = "WARREN_EGRESS_PROBE";
/// Steady-state probe cadence in seconds (jittered +/-15% per tick).
pub const EGRESS_PROBE_INTERVAL_ENV: &str = "WARREN_EGRESS_PROBE_INTERVAL_SECS";
/// Faster cadence used until the first probe proves the circuit forwards.
pub const EGRESS_PROBE_STARTUP_ENV: &str = "WARREN_EGRESS_PROBE_STARTUP_SECS";
/// Consecutive failures before the egress-dead verdict.
pub const EGRESS_PROBE_FAILURES_ENV: &str = "WARREN_EGRESS_PROBE_FAILURES";

const DEFAULT_INTERVAL: Duration = Duration::from_secs(25);
const INTERVAL_RANGE_SECS: std::ops::RangeInclusive<u64> = 5..=600;
/// Until the first success, probe on this shorter cadence: a circuit that never
/// forwards from connect is then detected and reconnected in ~20 s instead of a
/// full steady interval.
const DEFAULT_STARTUP_INTERVAL: Duration = Duration::from_secs(3);
const STARTUP_RANGE_SECS: std::ops::RangeInclusive<u64> = 1..=60;
const DEFAULT_FAILURE_THRESHOLD: u32 = 3;
const FAILURE_RANGE: std::ops::RangeInclusive<u32> = 1..=10;

/// Exit-provided in-tunnel resolver: the fleet-invariant tunnel gateway
/// ([`warrenguard_config::TUNNEL_GATEWAY_IP`]), the same address the system DNS
/// points at while connected, port 53.
const GATEWAY_DNS: SocketAddr =
    SocketAddr::new(IpAddr::V4(warrenguard_config::TUNNEL_GATEWAY_IP), 53);

/// Name resolved by the probe. Warren infrastructure, queried against Warren's
/// own exit resolver, so no third party learns anything. Exported so external
/// probe drivers (the SDK userland prober) query the same name rather than
/// re-declaring it.
pub const PROBE_QNAME: &str = "warrenbrowse.com";

/// Overall wait for an answer within one probe (two sends inside). Exported
/// for external probe drivers, like [`PROBE_QNAME`].
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
/// Retransmit offset of the second datagram inside one probe, so a single lost
/// UDP packet does not count as an egress failure.
const PROBE_RETRANSMIT: Duration = Duration::from_secs(2);

/// Resolved probe settings (env knobs applied once at tunnel start).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressProbeConfig {
    /// `false` when `WARREN_EGRESS_PROBE=0` disables the probe entirely.
    pub enabled: bool,
    /// Steady-state cadence, used once the first probe has proven the circuit.
    pub interval: Duration,
    /// Faster startup cadence, used until the first successful probe.
    pub startup_interval: Duration,
    /// Consecutive failures before the egress-dead verdict fires.
    pub failure_threshold: u32,
}

impl EgressProbeConfig {
    /// Resolves the config from the `WARREN_EGRESS_PROBE*` environment knobs.
    #[must_use]
    pub fn from_env() -> Self {
        Self::resolve(
            std::env::var(EGRESS_PROBE_ENV).ok().as_deref(),
            std::env::var(EGRESS_PROBE_INTERVAL_ENV).ok().as_deref(),
            std::env::var(EGRESS_PROBE_STARTUP_ENV).ok().as_deref(),
            std::env::var(EGRESS_PROBE_FAILURES_ENV).ok().as_deref(),
        )
    }

    /// Pure resolution so the knob semantics are unit-testable: invalid or
    /// out-of-range values warn and keep the default (never clamp silently, so a
    /// typo cannot change the cadence unnoticed).
    #[must_use]
    pub fn resolve(
        enable: Option<&str>,
        interval: Option<&str>,
        startup: Option<&str>,
        failures: Option<&str>,
    ) -> Self {
        let enabled = enable.map(str::trim) != Some("0");
        let interval = match interval.map(|raw| raw.trim().parse::<u64>()) {
            None => DEFAULT_INTERVAL,
            Some(Ok(secs)) if INTERVAL_RANGE_SECS.contains(&secs) => Duration::from_secs(secs),
            Some(_) => {
                tracing::warn!(
                    "ignoring invalid {EGRESS_PROBE_INTERVAL_ENV} \
                     (expected integer in {INTERVAL_RANGE_SECS:?})"
                );
                DEFAULT_INTERVAL
            }
        };
        let startup_interval = match startup.map(|raw| raw.trim().parse::<u64>()) {
            None => DEFAULT_STARTUP_INTERVAL,
            Some(Ok(secs)) if STARTUP_RANGE_SECS.contains(&secs) => Duration::from_secs(secs),
            Some(_) => {
                tracing::warn!(
                    "ignoring invalid {EGRESS_PROBE_STARTUP_ENV} \
                     (expected integer in {STARTUP_RANGE_SECS:?})"
                );
                DEFAULT_STARTUP_INTERVAL
            }
        };
        // The startup cadence is a fast-detect head start, never slower than
        // steady state: clamp it down if a misconfig inverts them.
        let startup_interval = startup_interval.min(interval);
        let failure_threshold = match failures.map(|raw| raw.trim().parse::<u32>()) {
            None => DEFAULT_FAILURE_THRESHOLD,
            Some(Ok(n)) if FAILURE_RANGE.contains(&n) => n,
            Some(_) => {
                tracing::warn!(
                    "ignoring invalid {EGRESS_PROBE_FAILURES_ENV} \
                     (expected integer in {FAILURE_RANGE:?})"
                );
                DEFAULT_FAILURE_THRESHOLD
            }
        };
        Self {
            enabled,
            interval,
            startup_interval,
            failure_threshold,
        }
    }
}

/// Jittered tick delay: `interval * (0.85 + 0.3 * fraction)` with `fraction`
/// uniform in `[0, 1)`, so a fleet of clients never probes in lockstep.
#[must_use]
pub fn jittered(interval: Duration, fraction: f64) -> Duration {
    interval.mul_f64(0.85 + 0.3 * fraction.clamp(0.0, 1.0))
}

/// Builds a minimal RFC 1035 query: header (RD set) + one A/IN question for
/// `qname`.
#[must_use]
pub fn build_dns_query(txid: u16, qname: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(17 + qname.len() + 1);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&[
        0x01, 0x00, // flags: RD
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
    ]);
    for label in qname.split('.').filter(|l| !l.is_empty()) {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    pkt
}

/// `true` when `buf` is a DNS response to our `txid`. Any response (even
/// SERVFAIL) proves the round trip through the exit, which is all the liveness
/// probe needs; the RCODE is irrelevant.
#[must_use]
pub fn is_matching_response(buf: &[u8], txid: u16) -> bool {
    buf.len() >= 12 && buf[0..2] == txid.to_be_bytes() && buf[2] & 0x80 != 0
}

/// IO surface consumed by [`run_egress_probe`]; a consumer implements it over
/// its own tunnel and the scheduler owns the escalation logic.
///
/// The async methods are declared with an explicit `impl Future` return (not
/// `async fn`) so this public trait is free of the `async_fn_in_trait`
/// caveat; an implementor may still write `async fn` for each.
pub trait EgressProbeIo {
    /// Waits for the next probe tick. `settled` is `false` until the first probe
    /// has succeeded, selecting the faster startup cadence. A `false` return =
    /// teardown, so the loop exits.
    fn next_tick(&mut self, settled: bool) -> impl Future<Output = bool> + Send;
    /// `true` while the supervisor has a live published session (always `true`
    /// on single-hop, which has no supervisor).
    fn session_present(&mut self) -> bool;
    /// One end-to-end probe through the tunnel. `true` = egress alive.
    fn probe(&mut self) -> impl Future<Output = bool> + Send;
    /// Publishes the verdict to the consumer (edge-triggered only).
    fn publish(&mut self, egress_dead: bool);
    /// `true` while a drain advisory is active on this tunnel.
    fn drain_active(&mut self) -> bool;
    /// Attempts the gap-free drain migration off the current exit. `true` =
    /// migration dispatched.
    fn try_migrate(&mut self) -> impl Future<Output = bool> + Send;
    /// Escalates a full tunnel reconnect (via the consumer's shared reconnect
    /// channel, the same path RX-silence uses). Called when the exit is not
    /// forwarding but no gap-free drain migration took it: the state machine
    /// leaves Connected and redials onto a fresh circuit.
    fn escalate_reconnect(&mut self, msg: String);
}

/// Probe scheduler: counts consecutive failures while a session is published,
/// publishes the egress-dead verdict at the threshold, clears it on the first
/// success. Never probes without a session (the RX-silence machinery owns that
/// case).
///
/// On a dead verdict the probe does not just banner: a drained exit is migrated
/// gap-free when possible, and otherwise (or if the migration hook declines) a
/// full reconnect is escalated. A live QUIC session over an exit that forwards
/// nothing is a dead path the RX-silence guard cannot see; banner-and-wait left
/// the user offline until the exit self-healed.
pub async fn run_egress_probe<I: EgressProbeIo>(io: &mut I, failure_threshold: u32) {
    let mut consecutive_failures: u32 = 0;
    let mut dead = false;
    let mut settled = false;
    loop {
        if !io.next_tick(settled).await {
            return;
        }
        if !io.session_present() {
            // A redial in flight: failures across it would conflate two
            // different exits (a failover may land elsewhere).
            consecutive_failures = 0;
            continue;
        }
        if io.probe().await {
            settled = true;
            consecutive_failures = 0;
            if dead {
                dead = false;
                io.publish(false);
            }
        } else {
            consecutive_failures = consecutive_failures.saturating_add(1);
            if !dead && consecutive_failures >= failure_threshold {
                dead = true;
                io.publish(true);
                // Under an active drain the exit is deliberately going away:
                // prefer the gap-free migration path.
                let migrated = io.drain_active() && io.try_migrate().await;
                if migrated {
                    tracing::info!(
                        "egress probe: exit not forwarding while draining; \
                         gap-free migration dispatched"
                    );
                } else {
                    // No drain, or the migration hook declined: the only
                    // remaining recovery is a full reconnect. Escalate and stop
                    // probing (this tunnel instance is tearing down).
                    io.escalate_reconnect(format!(
                        "exit not forwarding ({consecutive_failures} consecutive in-tunnel \
                         egress probes failed) while the QUIC session is alive; leaving \
                         Connected to reconnect onto a fresh circuit"
                    ));
                    return;
                }
            }
        }
    }
}

/// One in-tunnel DNS round trip to the exit resolver, for TUN-routed consumers.
/// Two datagrams spaced [`PROBE_RETRANSMIT`], overall deadline [`PROBE_TIMEOUT`].
/// Local socket errors (bind/send) are inconclusive, not egress-dead: they
/// report success so a host-side hiccup never raises the banner.
///
/// This is the datapath probe a consumer whose tunnel is a real OS TUN plugs
/// into [`EgressProbeIo::probe`]. A userland-proxy datapath, where the gateway
/// is not OS-routable, supplies its own probe over its session instead.
pub async fn probe_gateway_dns() -> bool {
    let sock = match tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("egress probe: local socket bind failed (inconclusive): {e}");
            return true;
        }
    };
    if let Err(e) = sock.connect(GATEWAY_DNS).await {
        tracing::warn!("egress probe: connect failed (inconclusive): {e}");
        return true;
    }
    let txid = rand::random::<u16>();
    let query = build_dns_query(txid, PROBE_QNAME);
    if sock.send(&query).await.is_err() {
        // Send failures are routing/firewall races during teardown, not an exit
        // verdict.
        return true;
    }
    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let retransmit = tokio::time::sleep(PROBE_RETRANSMIT);
    tokio::pin!(retransmit);
    let mut retransmitted = false;
    loop {
        tokio::select! {
            () = &mut retransmit, if !retransmitted => {
                retransmitted = true;
                let _ = sock.send(&query).await;
            }
            recv = sock.recv(&mut buf) => {
                match recv {
                    Ok(n) if is_matching_response(&buf[..n], txid) => return true,
                    Ok(_) => {} // unrelated datagram, keep reading
                    Err(_) => return false,
                }
            }
            () = tokio::time::sleep_until(deadline) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    // --- config knobs -----------------------------------------------

    #[test]
    fn config_defaults_when_env_unset() {
        let cfg = EgressProbeConfig::resolve(None, None, None, None);
        assert!(cfg.enabled, "probe is on by default");
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
        assert_eq!(cfg.startup_interval, DEFAULT_STARTUP_INTERVAL);
        assert_eq!(cfg.failure_threshold, DEFAULT_FAILURE_THRESHOLD);
    }

    #[test]
    fn config_disable_knob_and_overrides() {
        assert!(!EgressProbeConfig::resolve(Some("0"), None, None, None).enabled);
        assert!(EgressProbeConfig::resolve(Some("1"), None, None, None).enabled);
        let cfg = EgressProbeConfig::resolve(None, Some("30"), Some("5"), Some("2"));
        assert_eq!(cfg.interval, Duration::from_secs(30));
        assert_eq!(cfg.startup_interval, Duration::from_secs(5));
        assert_eq!(cfg.failure_threshold, 2);
    }

    #[test]
    fn config_rejects_out_of_range_values() {
        // Invalid values must warn + keep the default, never clamp: a typo
        // cannot silently change the probe cadence.
        let cfg = EgressProbeConfig::resolve(None, Some("1"), Some("0"), Some("0"));
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
        assert_eq!(cfg.startup_interval, DEFAULT_STARTUP_INTERVAL);
        assert_eq!(cfg.failure_threshold, DEFAULT_FAILURE_THRESHOLD);
        let cfg = EgressProbeConfig::resolve(None, Some("abc"), Some("xyz"), Some("99"));
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
        assert_eq!(cfg.startup_interval, DEFAULT_STARTUP_INTERVAL);
        assert_eq!(cfg.failure_threshold, DEFAULT_FAILURE_THRESHOLD);
    }

    #[test]
    fn startup_interval_never_exceeds_steady_interval() {
        // A startup cadence slower than steady state would defeat its
        // fast-detect purpose: clamp it down.
        let cfg = EgressProbeConfig::resolve(None, Some("10"), Some("30"), None);
        assert_eq!(cfg.interval, Duration::from_secs(10));
        assert_eq!(cfg.startup_interval, Duration::from_secs(10));
    }

    #[test]
    fn jitter_spreads_within_15_percent() {
        let base = Duration::from_secs(20);
        assert_eq!(jittered(base, 0.0), Duration::from_secs(17));
        assert_eq!(jittered(base, 0.5), Duration::from_secs(20));
        assert_eq!(jittered(base, 1.0), Duration::from_secs(23));
    }

    // --- DNS packet building / matching ------------------------------

    #[test]
    fn dns_query_encodes_header_and_question() {
        let pkt = build_dns_query(0xABCD, "warrenbrowse.com");
        assert_eq!(&pkt[0..2], &[0xAB, 0xCD], "txid big-endian");
        assert_eq!(&pkt[2..4], &[0x01, 0x00], "RD flag only");
        assert_eq!(&pkt[4..6], &[0x00, 0x01], "one question");
        // Question: 12"warrenbrowse" 3"com" 0, A, IN.
        let mut expected_q = vec![12u8];
        expected_q.extend_from_slice(b"warrenbrowse");
        expected_q.push(3);
        expected_q.extend_from_slice(b"com");
        expected_q.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(&pkt[12..], expected_q.as_slice());
    }

    #[test]
    fn response_matching_requires_txid_and_qr_bit() {
        let mut resp = build_dns_query(0x1234, "warrenbrowse.com");
        assert!(
            !is_matching_response(&resp, 0x1234),
            "a query echo (QR=0) is not a response"
        );
        resp[2] |= 0x80;
        assert!(is_matching_response(&resp, 0x1234));
        assert!(
            !is_matching_response(&resp, 0x9999),
            "txid mismatch must not match (stray datagram)"
        );
        assert!(!is_matching_response(&[0x12, 0x34, 0x80], 0x1234), "runt");
    }

    // --- scheduler ----------------------------------------------------

    /// Scripted mock: one entry per tick.
    struct MockIo {
        /// Per tick: `None` = no session (skip), `Some(ok)` = probe result.
        script: VecDeque<Option<bool>>,
        published: Vec<bool>,
        drain_active: bool,
        migrate_succeeds: bool,
        migrate_attempts: u32,
        /// `settled` flags observed at each `next_tick` (cadence proof).
        settled_seen: Vec<bool>,
        /// Reconnect escalations (the fix): the messages passed.
        reconnects: Vec<String>,
    }

    impl MockIo {
        fn scripted(script: impl IntoIterator<Item = Option<bool>>) -> Self {
            Self {
                script: script.into_iter().collect(),
                published: Vec::new(),
                drain_active: false,
                migrate_succeeds: false,
                migrate_attempts: 0,
                settled_seen: Vec::new(),
                reconnects: Vec::new(),
            }
        }
    }

    impl EgressProbeIo for MockIo {
        async fn next_tick(&mut self, settled: bool) -> bool {
            self.settled_seen.push(settled);
            !self.script.is_empty()
        }
        fn session_present(&mut self) -> bool {
            // A skipped tick (no session) consumes its script entry here, since
            // the scheduler `continue`s without calling probe().
            if self
                .script
                .front()
                .expect("tick gated by next_tick")
                .is_some()
            {
                true
            } else {
                self.script.pop_front();
                false
            }
        }
        async fn probe(&mut self) -> bool {
            self.script
                .pop_front()
                .flatten()
                .expect("probe only runs with a session")
        }
        fn publish(&mut self, egress_dead: bool) {
            self.published.push(egress_dead);
        }
        fn drain_active(&mut self) -> bool {
            self.drain_active
        }
        async fn try_migrate(&mut self) -> bool {
            self.migrate_attempts += 1;
            self.migrate_succeeds
        }
        fn escalate_reconnect(&mut self, msg: String) {
            self.reconnects.push(msg);
        }
    }

    #[tokio::test]
    async fn verdict_fires_after_threshold_consecutive_failures_only() {
        // Two failures under threshold 3: nothing published (a rollout hot-swap
        // blip must not flap the UI), and no reconnect.
        let mut io = MockIo::scripted([Some(false), Some(false), Some(true)]);
        run_egress_probe(&mut io, 3).await;
        assert!(
            io.published.is_empty(),
            "sub-threshold failures must never publish: {:?}",
            io.published
        );
        assert!(
            io.reconnects.is_empty(),
            "sub-threshold failures never reconnect"
        );

        // Three consecutive failures: exactly one dead verdict, then a reconnect
        // (no drain advisory in this mock).
        let mut io = MockIo::scripted([Some(false), Some(false), Some(false)]);
        run_egress_probe(&mut io, 3).await;
        assert_eq!(
            io.published,
            vec![true],
            "threshold reached publishes exactly one dead verdict"
        );
        assert_eq!(
            io.reconnects.len(),
            1,
            "a dead exit with no gap-free migration must escalate one reconnect"
        );
    }

    #[tokio::test]
    async fn success_after_gapfree_migration_clears_the_dead_verdict() {
        // Under a drain the loop keeps probing after the gap-free migration, so a
        // later success still clears the verdict; the full reconnect is reserved
        // for the no-migration case.
        let mut io = MockIo::scripted([Some(false), Some(false), Some(true)]);
        io.drain_active = true;
        io.migrate_succeeds = true;
        run_egress_probe(&mut io, 2).await;
        assert_eq!(
            io.published,
            vec![true, false],
            "one success after the gap-free migration must clear the verdict"
        );
        assert!(
            io.reconnects.is_empty(),
            "a successful gap-free migration must not also force a full reconnect"
        );
    }

    #[tokio::test]
    async fn success_resets_the_consecutive_failure_count() {
        // fail, fail, ok, fail, fail: never 3 consecutive => no verdict.
        let mut io = MockIo::scripted([
            Some(false),
            Some(false),
            Some(true),
            Some(false),
            Some(false),
        ]);
        run_egress_probe(&mut io, 3).await;
        assert!(
            io.published.is_empty(),
            "non-consecutive failures must not accumulate: {:?}",
            io.published
        );
    }

    #[tokio::test]
    async fn no_session_ticks_never_probe_and_reset_the_count() {
        // Two failures, then a redial window (no session), then two more
        // failures: the count must restart, so threshold 3 never fires.
        let mut io = MockIo::scripted([Some(false), Some(false), None, Some(false), Some(false)]);
        run_egress_probe(&mut io, 3).await;
        assert!(
            io.published.is_empty(),
            "a redial gap must reset the failure count (the new session may be a \
             different exit): {:?}",
            io.published
        );
    }

    #[tokio::test]
    async fn teardown_exits_without_publishing() {
        let mut io = MockIo::scripted([]);
        run_egress_probe(&mut io, 1).await;
        assert!(io.published.is_empty());
    }

    #[tokio::test]
    async fn drain_active_verdict_prefers_the_migration_hook() {
        let mut io = MockIo::scripted([Some(false), Some(false)]);
        io.drain_active = true;
        io.migrate_succeeds = true;
        run_egress_probe(&mut io, 2).await;
        assert_eq!(io.published, vec![true], "verdict still published");
        assert_eq!(
            io.migrate_attempts, 1,
            "an egress-dead verdict under an active drain must trigger the \
             gap-free migration path"
        );
        assert!(
            io.reconnects.is_empty(),
            "a successful gap-free migration replaces the full reconnect"
        );
    }

    #[tokio::test]
    async fn drain_migration_decline_escalates_a_reconnect() {
        // Drain active but the gap-free hook declines (no eligible peer): the
        // only remaining recovery is a full reconnect.
        let mut io = MockIo::scripted([Some(false), Some(false)]);
        io.drain_active = true;
        io.migrate_succeeds = false;
        run_egress_probe(&mut io, 2).await;
        assert_eq!(io.published, vec![true]);
        assert_eq!(io.migrate_attempts, 1, "the gap-free hook is tried first");
        assert_eq!(
            io.reconnects.len(),
            1,
            "when the migration hook declines, fall back to a full reconnect"
        );
    }

    #[tokio::test]
    async fn egress_dead_without_drain_escalates_a_reconnect() {
        // QUIC alive, exit forwards nothing, no drain advisory. The probe must
        // escalate a reconnect, not just banner and wait for the exit to
        // self-heal.
        let mut io = MockIo::scripted([Some(false)]);
        run_egress_probe(&mut io, 1).await;
        assert_eq!(io.published, vec![true]);
        assert_eq!(
            io.migrate_attempts, 0,
            "no drain advisory: never attempt gap-free migration"
        );
        assert_eq!(
            io.reconnects.len(),
            1,
            "a non-forwarding exit with a live QUIC session must trigger a full reconnect"
        );
    }

    #[tokio::test]
    async fn startup_cadence_is_used_until_the_first_success() {
        // `next_tick` sees settled=false until a probe succeeds, then true: the
        // scheduler drives the fast startup cadence only while the circuit is
        // unproven. High threshold so it never escalates.
        let mut io = MockIo::scripted([Some(false), Some(false), Some(true), Some(true)]);
        run_egress_probe(&mut io, 10).await;
        assert_eq!(
            io.settled_seen,
            vec![false, false, false, true, true],
            "settled flips to true only after the first successful probe"
        );
    }

    #[test]
    fn gateway_probe_targets_the_config_tunnel_gateway_on_port_53() {
        // The probe target must be the fleet-invariant tunnel gateway from the
        // shared config, not a hardcoded literal that could drift.
        assert_eq!(
            GATEWAY_DNS,
            SocketAddr::new(IpAddr::V4(warrenguard_config::TUNNEL_GATEWAY_IP), 53)
        );
    }
}
