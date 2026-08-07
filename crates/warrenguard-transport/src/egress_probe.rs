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
//! leave the user offline until the exit self-healed.
//!
//! Two cadences, and which one applies is the whole timing design. A circuit
//! that has answered and has nothing pending is polled on
//! [`EgressProbeConfig::interval`]; a circuit that is unproven (dead from
//! connect, or fresh out of a redial) or already carrying a failure is polled on
//! the much faster [`EgressProbeConfig::startup_interval`], because in both
//! cases the next probe decides something. The verdict still needs the same
//! consecutive failures, so the evidence is unchanged and only the waiting
//! between the probes is gone. Against the shipped defaults, with the timings
//! justified on [`PROBE_TIMEOUT`] from a measurement on the beta network, that
//! bounds the user's time on a silently dead tunnel at ~11 s from connect and
//! ~39 s from a mid-session death. The scheduler tests assert both numbers in
//! wall-clock terms.
//!
//! What that fast confirmation cadence cost, until it was measured: the three
//! "consecutive" probes all fall inside the same ~9 s, so ANY 8.5 s stall was
//! enough to convict an exit that was forwarding perfectly well, and the
//! conviction costs the user every request in flight (a redial is a fresh QUIC
//! epoch). The window cannot simply be widened back: that trades the detection
//! time this module exists to keep short. The evidence is qualified instead.
//! Before convicting, the scheduler consults [`TransportEvidence`]: this whole
//! module is about an exit that ACKs keep-alives and forwards nothing, so while
//! the peer has ACKed nothing at all the premise does not hold, the path is the
//! suspect, and the QUIC idle timeout owns that death. See
//! `a_path_stall_never_convicts_the_exit_however_long_it_lasts`.
//!
//! Both ends of that trade were then measured on a live circuit (2026-08-02,
//! Android over two hops). An exit that forwards nothing is convicted 10.2 to
//! 11.3 s after the session comes up. A datapath outage on a proven circuit
//! costs one failed probe, then confirmations ~3.6 s apart: a 6 s outage clears
//! on the third probe with no verdict and the loop returns to the steady
//! cadence, while an outage that persists is convicted 9.6 s after the first
//! probe that noticed it.
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
/// Faster cadence for a circuit that is unproven or carrying a failure.
pub const EGRESS_PROBE_STARTUP_ENV: &str = "WARREN_EGRESS_PROBE_STARTUP_SECS";
/// Consecutive failures before the egress-dead verdict.
pub const EGRESS_PROBE_FAILURES_ENV: &str = "WARREN_EGRESS_PROBE_FAILURES";

const DEFAULT_INTERVAL: Duration = Duration::from_secs(25);
const INTERVAL_RANGE_SECS: std::ops::RangeInclusive<u64> = 5..=600;
/// Cadence for a circuit that is unproven or under suspicion. Deliberately not
/// tighter than a second: back-to-back retries would spend the whole conviction
/// budget inside one bad moment, whereas a second between them lets a transient
/// (a route being installed, a radio waking) clear on its own. It also keeps the
/// first probe of a session behind the TUN coming up, so a local routing error
/// cannot be mistaken for an answer.
const DEFAULT_STARTUP_INTERVAL: Duration = Duration::from_secs(1);
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

/// Overall wait for an answer within one probe. Exported for external probe
/// drivers, like [`PROBE_QNAME`].
///
/// Measured over a two-hop circuit from an Android client to a European exit
/// (2026-08-02): 536 in-tunnel DNS round trips over 7 minutes on one stable
/// session, p50 368 ms, p95 574 ms, p99 737 ms, max 1186 ms, and one datagram
/// lost outright. 2.5 s is 2.1x the worst round trip that measurement saw and
/// 3.4x its p99, so the deadline absorbs a far worse link than the one it was
/// measured on. Three probes have to spend it in full before an exit is
/// convicted, which makes it the dominant term in the detection time: every
/// 100 ms here is 300 ms of a user staring at a tunnel that carries nothing.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);
/// Offsets, from the start of one probe, at which that probe sends its query.
///
/// Retransmitting inside the probe is what keeps a shorter deadline safe: a lost
/// datagram costs a retransmit, never a failed probe. The offsets are spaced by
/// roughly the measured p99 round trip and the last one still leaves 1.1 s, so
/// every datagram in the schedule can genuinely be answered before the deadline
/// (`every_probe_datagram_can_still_be_answered_inside_the_deadline`). Only a
/// failing probe ever sends more than the first: a healthy circuit answers in
/// ~370 ms and returns.
///
/// Exported for the same reason as [`PROBE_QNAME`] and [`PROBE_TIMEOUT`]: an
/// external probe driver MUST follow this schedule, not just the deadline. The
/// three constants were sized together, and [`PROBE_TIMEOUT`] is only safe
/// because a lost datagram is retransmitted twice inside it. A driver that
/// sends once and waits out the deadline has no retransmit at all, so one lost
/// datagram is a failed probe, and three of those convict a healthy exit.
pub const PROBE_SENDS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(700),
    Duration::from_millis(1400),
];

/// Resolved probe settings (env knobs applied once at tunnel start).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressProbeConfig {
    /// `false` when `WARREN_EGRESS_PROBE=0` disables the probe entirely.
    pub enabled: bool,
    /// Steady-state cadence, for a proven circuit with no failure pending.
    pub interval: Duration,
    /// Faster cadence, for a circuit that is unproven or under suspicion.
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

/// What one probe established about the exit's egress.
///
/// The third case is the one that matters: a probe that never reached the wire
/// (a socket that would not bind, a datapath torn down under it) has observed
/// NOTHING about the exit. It is host-side evidence, not exit evidence, and the
/// scheduler must not spend it either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// A matching answer came back through the tunnel: the exit decapsulates,
    /// forwards, and reached its upstream.
    Alive,
    /// Every datagram in [`PROBE_SENDS`] went out and none was answered within
    /// [`PROBE_TIMEOUT`]. Evidence against the exit.
    Dead,
    /// The probe could not be carried out at all. No evidence either way.
    Inconclusive,
}

/// What the transport saw while the in-tunnel probe was failing.
///
/// This module's entire premise is an exit that ACKs keep-alives and forwards
/// nothing, so a conviction is only meaningful while the transport underneath is
/// actually carrying traffic. When it is not, the unanswered query says nothing
/// about the exit: the path stopped carrying anything, a redial goes over that
/// same path, and the QUIC idle timeout already owns that death.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportEvidence {
    /// The peer kept acknowledging what we sent. Only the peer can ACK what it
    /// received, so the path is live and an unanswered in-tunnel query is
    /// evidence against the EXIT.
    Progressing,
    /// Nothing came back from the peer either, not even an ACK of our
    /// keep-alives. The path is the suspect, not the exit.
    Silent,
    /// The consumer does not report it. Kept distinct from `Progressing` so a
    /// reader can tell "the transport was fine" from "nobody looked".
    Unknown,
}

/// IO surface consumed by [`run_egress_probe`]; a consumer implements it over
/// its own tunnel and the scheduler owns the escalation logic.
///
/// The async methods are declared with an explicit `impl Future` return (not
/// `async fn`) so this public trait is free of the `async_fn_in_trait`
/// caveat; an implementor may still write `async fn` for each.
pub trait EgressProbeIo {
    /// Waits for the next probe tick. `steady` is `true` only for a circuit that
    /// has answered and has no failure pending; an unproven or suspect circuit
    /// passes `false` and takes the faster cadence. A `false` return = teardown,
    /// so the loop exits.
    fn next_tick(&mut self, steady: bool) -> impl Future<Output = bool> + Send;
    /// `true` while the supervisor has a live published session (always `true`
    /// for an unsupervised pump, which has no supervisor).
    fn session_present(&mut self) -> bool;
    /// One end-to-end probe through the tunnel.
    fn probe(&mut self) -> impl Future<Output = ProbeOutcome> + Send;
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
    /// What the transport carried since the current failure streak began, read
    /// once at the threshold. Defaults to [`TransportEvidence::Unknown`], which
    /// keeps a consumer that has not wired it on the pre-existing behaviour.
    fn transport_evidence(&mut self) -> TransportEvidence {
        TransportEvidence::Unknown
    }
    /// Marks the start of a failure streak, so the next
    /// [`Self::transport_evidence`] answers about THIS streak and not about the
    /// whole session.
    fn mark_streak_start(&mut self) {}
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
    let mut proven = false;
    loop {
        // The steady cadence is for a circuit that is both proven and quiet.
        // Confirming a suspicion on it would spend two more steady intervals
        // deciding, so a pending failure takes the fast cadence too: the
        // evidence required is unchanged (the same consecutive probes), only the
        // waiting between them is gone.
        let steady = proven && consecutive_failures == 0;
        if !io.next_tick(steady).await {
            return;
        }
        if !io.session_present() {
            // A redial in flight: failures across it would conflate two
            // different exits (a failover may land elsewhere), and for the same
            // reason the circuit that comes back is unproven until it answers.
            consecutive_failures = 0;
            proven = false;
            continue;
        }
        let outcome = io.probe().await;
        // A probe that never reached the wire is host-side evidence, not exit
        // evidence: it neither proves the circuit nor counts against it, so the
        // scheduler carries its state across untouched. Spending it either way
        // is a real failure mode in both directions: read as a success it
        // launders away accumulated failures and marks a never-answered circuit
        // proven (dropping it onto the slow cadence), and read as a failure a
        // host hiccup convicts a healthy exit.
        if outcome == ProbeOutcome::Inconclusive {
            continue;
        }
        if outcome == ProbeOutcome::Alive {
            proven = true;
            consecutive_failures = 0;
            if dead {
                dead = false;
                io.publish(false);
            }
        } else {
            if consecutive_failures == 0 {
                io.mark_streak_start();
            }
            consecutive_failures = consecutive_failures.saturating_add(1);
            // A conviction is only meaningful while the transport underneath is
            // carrying traffic, because that is the whole condition this probe
            // exists to catch: an exit that ACKs and forwards nothing. When the
            // peer has ACKed nothing since the streak began, the path stopped
            // carrying anything and the exit is not the suspect. Convicting
            // anyway costs the user every request in flight (the redial is a
            // fresh QUIC epoch) and cannot help, since the redial rides the same
            // path. The QUIC idle timeout owns that death instead.
            //
            // The failures are KEPT, not reset: if the path comes back and the
            // exit is still silent, the very next probe convicts it.
            if !dead
                && consecutive_failures >= failure_threshold
                && io.transport_evidence() == TransportEvidence::Silent
            {
                tracing::debug!(
                    "egress probe: {consecutive_failures} failed probes, but the \
                     transport carried nothing over them; the path is the \
                     suspect, not the exit"
                );
                continue;
            }
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
/// Datagrams at the [`PROBE_SENDS`] offsets, overall deadline [`PROBE_TIMEOUT`].
/// Local socket errors (bind/send) never reached the exit, so they report
/// [`ProbeOutcome::Inconclusive`] and the scheduler spends them neither way.
///
/// This is the datapath probe a consumer whose tunnel is a real OS TUN plugs
/// into [`EgressProbeIo::probe`]. A userland-proxy datapath, where the gateway
/// is not OS-routable, supplies its own probe over its session instead.
pub async fn probe_gateway_dns() -> ProbeOutcome {
    let sock = match tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("egress probe: local socket bind failed (inconclusive): {e}");
            return ProbeOutcome::Inconclusive;
        }
    };
    if let Err(e) = sock.connect(GATEWAY_DNS).await {
        tracing::warn!("egress probe: connect failed (inconclusive): {e}");
        return ProbeOutcome::Inconclusive;
    }
    let txid = rand::random::<u16>();
    let query = build_dns_query(txid, PROBE_QNAME);
    let started = tokio::time::Instant::now();
    if sock.send(&query).await.is_err() {
        // Send failures are routing/firewall races during teardown, not an exit
        // verdict.
        return ProbeOutcome::Inconclusive;
    }
    let mut buf = [0u8; 512];
    let deadline = started + PROBE_TIMEOUT;
    // The first offset was just sent; the rest are retransmits still to come.
    let mut retransmits = PROBE_SENDS.iter().skip(1).map(|offset| started + *offset);
    let mut next_send = retransmits.next();
    loop {
        // Absolute instants, so re-arming the timer on every loop turn (the
        // stray-datagram path) never shifts the schedule.
        let wake = next_send.unwrap_or(deadline).min(deadline);
        tokio::select! {
            recv = sock.recv(&mut buf) => {
                match recv {
                    Ok(n) if is_matching_response(&buf[..n], txid) => return ProbeOutcome::Alive,
                    Ok(_) => {} // unrelated datagram, keep reading
                    Err(_) => return ProbeOutcome::Dead,
                }
            }
            () = tokio::time::sleep_until(wake) => {
                if wake >= deadline {
                    return ProbeOutcome::Dead;
                }
                let _ = sock.send(&query).await;
                next_send = retransmits.next();
            }
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
        /// Per tick: `None` = no session (skip), `Some(o)` = probe outcome.
        script: VecDeque<Option<ProbeOutcome>>,
        published: Vec<bool>,
        drain_active: bool,
        migrate_succeeds: bool,
        migrate_attempts: u32,
        /// `steady` flags observed at each `next_tick` (cadence proof).
        steady_seen: Vec<bool>,
        /// Reconnect escalations (the fix): the messages passed.
        reconnects: Vec<String>,
    }

    impl MockIo {
        /// Answered/unanswered script, for the cases that predate the tri-state
        /// outcome and read better as a plain yes/no.
        fn scripted(script: impl IntoIterator<Item = Option<bool>>) -> Self {
            Self::scripted_outcomes(script.into_iter().map(|tick| {
                tick.map(|ok| {
                    if ok {
                        ProbeOutcome::Alive
                    } else {
                        ProbeOutcome::Dead
                    }
                })
            }))
        }

        fn scripted_outcomes(script: impl IntoIterator<Item = Option<ProbeOutcome>>) -> Self {
            Self {
                script: script.into_iter().collect(),
                published: Vec::new(),
                drain_active: false,
                migrate_succeeds: false,
                migrate_attempts: 0,
                steady_seen: Vec::new(),
                reconnects: Vec::new(),
            }
        }
    }

    impl EgressProbeIo for MockIo {
        async fn next_tick(&mut self, steady: bool) -> bool {
            self.steady_seen.push(steady);
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
        async fn probe(&mut self) -> ProbeOutcome {
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
    async fn an_inconclusive_probe_does_not_clear_accumulated_failure_evidence() {
        // A probe that never reached the wire observed nothing about the exit,
        // so it must not launder away the failures on either side of it. Read
        // as a success it would, and an exit that forwards nothing could then
        // stay convicted-free forever behind a host that hiccups periodically.
        let mut io = MockIo::scripted_outcomes([
            Some(ProbeOutcome::Dead),
            Some(ProbeOutcome::Dead),
            Some(ProbeOutcome::Inconclusive),
            Some(ProbeOutcome::Dead),
        ]);
        run_egress_probe(&mut io, 3).await;
        assert_eq!(
            io.published,
            vec![true],
            "three failed probes must convict the exit even with an inconclusive \
             probe among them"
        );
    }

    #[tokio::test]
    async fn an_inconclusive_probe_never_proves_the_circuit() {
        // `proven` is what drops the probe onto the slow steady cadence. A
        // circuit that has never answered must stay on the fast one, or a
        // tunnel dead from connect behind a failing local socket is polled
        // every steady interval instead of every startup interval.
        let mut io = MockIo::scripted_outcomes([
            Some(ProbeOutcome::Inconclusive),
            Some(ProbeOutcome::Inconclusive),
            Some(ProbeOutcome::Alive),
        ]);
        run_egress_probe(&mut io, 3).await;
        // Three probe ticks then the teardown tick, which is the first to see
        // the circuit proven.
        assert_eq!(
            io.steady_seen,
            vec![false, false, false, true],
            "only an answered probe proves the circuit and earns the steady cadence"
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
        // An unproven circuit takes the fast cadence however many probes it
        // costs, and only the first success buys the steady one. High threshold
        // so it never escalates.
        let mut io = MockIo::scripted([Some(false), Some(false), Some(true), Some(true)]);
        run_egress_probe(&mut io, 10).await;
        assert_eq!(
            io.steady_seen,
            vec![false, false, false, true, true],
            "the steady cadence starts only after the first successful probe"
        );
    }

    // --- schedule timing ----------------------------------------------
    //
    // The bounds below are the point of the whole module: how long a user sits
    // on a tunnel that carries nothing, and how much healthy turbulence it takes
    // to tear a working tunnel down. They are asserted in WALL-CLOCK terms over
    // tokio's paused clock, against the shipped defaults, so a constant edited
    // without thinking moves a test rather than only a number.

    /// Round trip a healthy probe takes in the model below.
    ///
    /// The measured p99 of the in-tunnel DNS round trip on the beta network
    /// (see [`PROBE_TIMEOUT`] for the sample). Modelling the p99 rather than the
    /// median keeps every bound below pessimistic.
    const MODEL_RTT: Duration = Duration::from_millis(750);

    /// Worst-case jitter draw, so an asserted bound is a true upper bound.
    const WORST_JITTER: f64 = 1.0;

    /// Datagrams one probe sends, at these offsets from its start.
    fn probe_send_offsets() -> Vec<Duration> {
        PROBE_SENDS.to_vec()
    }

    /// Scheduler mock that spends real (simulated) time: `next_tick` sleeps the
    /// jittered cadence the shipped defaults produce and `probe` consumes the
    /// real deadline when nothing answers. A test can then assert on elapsed
    /// time rather than on tick counts.
    struct TimedIo {
        /// Window, from loop start, during which the exit forwards nothing
        /// while the transport underneath keeps carrying traffic. This is the
        /// condition the probe exists to catch.
        dead: std::ops::Range<Duration>,
        /// Window during which NOTHING crosses the path: the probe gets no
        /// answer and the peer ACKs nothing either. A residential stall.
        stalled: std::ops::Range<Duration>,
        /// Where the current failure streak began, so the evidence answers
        /// about that streak rather than about the whole run.
        streak_start: Option<Duration>,
        /// Every `lose_every`-th probe loses all of its datagrams, modelling
        /// isolated packet loss on an otherwise healthy circuit.
        lose_every: usize,
        probes: usize,
        started: tokio::time::Instant,
        stop_after: Duration,
        escalated_at: Option<Duration>,
        published: Vec<bool>,
        fast_ticks: usize,
        steady_ticks: usize,
    }

    impl TimedIo {
        fn new(dead: std::ops::Range<Duration>, stop_after: Duration) -> Self {
            Self {
                dead,
                stalled: Duration::MAX..Duration::MAX,
                streak_start: None,
                lose_every: 0,
                probes: 0,
                started: tokio::time::Instant::now(),
                stop_after,
                escalated_at: None,
                published: Vec::new(),
                fast_ticks: 0,
                steady_ticks: 0,
            }
        }

        fn healthy(stop_after: Duration) -> Self {
            Self::new(Duration::MAX..Duration::MAX, stop_after)
        }

        /// A path that carries nothing at all over `stalled`, with a perfectly
        /// healthy exit behind it.
        fn stalling(stalled: std::ops::Range<Duration>, stop_after: Duration) -> Self {
            let mut io = Self::new(Duration::MAX..Duration::MAX, stop_after);
            io.stalled = stalled;
            io
        }

        /// `true` when the path carries nothing at any point of `[from, to]`.
        fn stalled_over(&self, from: Duration, to: Duration) -> bool {
            from < self.stalled.end && to >= self.stalled.start
        }

        fn elapsed(&self) -> Duration {
            self.started.elapsed()
        }

        /// `true` when the exit forwards nothing at any point of `[from, to]`.
        fn dead_over(&self, from: Duration, to: Duration) -> bool {
            from < self.dead.end && to >= self.dead.start
        }
    }

    impl EgressProbeIo for TimedIo {
        async fn next_tick(&mut self, steady: bool) -> bool {
            if self.elapsed() >= self.stop_after {
                return false;
            }
            let base = if steady {
                self.steady_ticks += 1;
                DEFAULT_INTERVAL
            } else {
                self.fast_ticks += 1;
                DEFAULT_STARTUP_INTERVAL
            };
            tokio::time::sleep(jittered(base, WORST_JITTER)).await;
            true
        }

        fn session_present(&mut self) -> bool {
            true
        }

        async fn probe(&mut self) -> ProbeOutcome {
            self.probes += 1;
            let start = self.elapsed();
            let lost = self.lose_every > 0 && self.probes % self.lose_every == 0;
            if !lost {
                for offset in probe_send_offsets() {
                    let sent = start + offset;
                    let answered = offset + MODEL_RTT;
                    if answered <= PROBE_TIMEOUT
                        && !self.dead_over(sent, sent + MODEL_RTT)
                        && !self.stalled_over(sent, sent + MODEL_RTT)
                    {
                        tokio::time::sleep(answered).await;
                        return ProbeOutcome::Alive;
                    }
                }
            }
            tokio::time::sleep(PROBE_TIMEOUT).await;
            ProbeOutcome::Dead
        }

        fn publish(&mut self, egress_dead: bool) {
            self.published.push(egress_dead);
        }

        fn drain_active(&mut self) -> bool {
            false
        }

        async fn try_migrate(&mut self) -> bool {
            false
        }

        fn escalate_reconnect(&mut self, _msg: String) {
            self.escalated_at = Some(self.elapsed());
        }

        fn mark_streak_start(&mut self) {
            self.streak_start = Some(self.elapsed());
        }

        /// ACKs stop arriving exactly while the path carries nothing; a dead
        /// EXIT behind a live path keeps ACKing our keep-alives.
        fn transport_evidence(&mut self) -> TransportEvidence {
            let from = self.streak_start.unwrap_or_else(|| self.elapsed());
            if self.stalled_over(from, self.elapsed()) {
                TransportEvidence::Silent
            } else {
                TransportEvidence::Progressing
            }
        }
    }

    /// A circuit that never forwards from connect is the cheapest case to
    /// convict: nothing has ever crossed it, so no success has to be explained
    /// away. The user must not sit in front of "You are protected" over a dead
    /// tunnel for the length of a steady cadence.
    #[tokio::test(start_paused = true)]
    async fn a_circuit_dead_from_connect_is_convicted_within_twelve_seconds() {
        let mut io = TimedIo::new(Duration::ZERO..Duration::MAX, Duration::from_secs(300));
        run_egress_probe(&mut io, DEFAULT_FAILURE_THRESHOLD).await;
        let convicted = io.escalated_at.expect("a dead circuit must escalate");
        assert!(
            convicted <= Duration::from_secs(12),
            "a circuit dead from connect must be convicted within 12 s, took {convicted:?}"
        );
        assert_eq!(io.published, vec![true]);
    }

    /// An exit that stops forwarding mid-session must not be confirmed on the
    /// steady cadence: the first failure is a suspicion, and confirming it takes
    /// the fast cadence, so the whole verdict lands inside one steady interval
    /// of the death instead of three.
    #[tokio::test(start_paused = true)]
    async fn a_circuit_that_dies_mid_session_is_convicted_within_forty_seconds() {
        // 61 s falls just after a probe has answered, which is the worst place
        // for the exit to die: a whole steady interval passes before anything
        // suspects it. The lower bound below keeps the test on that worst case
        // instead of silently drifting onto a lucky phase.
        let death = Duration::from_secs(61);
        let mut io = TimedIo::new(death..Duration::MAX, Duration::from_secs(600));
        run_egress_probe(&mut io, DEFAULT_FAILURE_THRESHOLD).await;
        let convicted = io.escalated_at.expect("a dead exit must escalate");
        let after_death = convicted.saturating_sub(death);
        assert!(
            after_death >= Duration::from_secs(30),
            "this bound is about a death that wastes a full steady interval; \
             {after_death:?} means the death no longer lands there"
        );
        assert!(
            after_death <= Duration::from_secs(40),
            "an exit that stops forwarding must be convicted within 40 s of the \
             death, took {after_death:?}"
        );
    }

    /// The other half of the trade: a verdict tears a working tunnel down, so a
    /// turbulence burst shorter than the conviction window must never reach it.
    /// Eight seconds of total silence is well past anything the measurement
    /// behind [`PROBE_TIMEOUT`] saw, and a 6 s outage was confirmed on a live
    /// circuit to cost two failed probes and then clear.
    #[tokio::test(start_paused = true)]
    async fn a_stall_shorter_than_the_conviction_window_never_convicts() {
        let stall = Duration::from_secs(30)..Duration::from_secs(38);
        let mut io = TimedIo::new(stall, Duration::from_secs(300));
        run_egress_probe(&mut io, DEFAULT_FAILURE_THRESHOLD).await;
        assert!(
            io.escalated_at.is_none(),
            "an 8 s stall must never tear the tunnel down"
        );
        assert!(
            io.published.is_empty(),
            "an 8 s stall must not even banner: {:?}",
            io.published
        );
    }

    /// A path stall must never be blamed on the EXIT, however long it lasts.
    ///
    /// This module convicts an exit that ACKs keep-alives and forwards nothing.
    /// While the path itself carries nothing, that premise does not hold: the
    /// unanswered query says nothing about the exit, the redial the conviction
    /// triggers goes over the same dead path, and the QUIC idle timeout already
    /// owns that death. What the conviction does cost is certain: a reconnect is
    /// a fresh QUIC epoch, so every request in flight through the tunnel dies
    /// with the old one.
    ///
    /// Measured before the fix: 8.5 s of silence was enough, at the worst
    /// alignment, because a pending failure drops the cadence to one second and
    /// the three "consecutive" probes then all fall inside the SAME bad moment.
    /// A residential path stalls that long routinely.
    #[tokio::test(start_paused = true)]
    async fn a_path_stall_never_convicts_the_exit_however_long_it_lasts() {
        // Swept over both the length of the stall and where it falls relative
        // to the cadence: a real stall starts whenever it wants, and the old
        // budget was only reachable at one alignment.
        for silence_s in [3u64, 8, 9, 12, 20, 45, 90] {
            let silence = Duration::from_secs(silence_s);
            for offset_ms in (0..30_000).step_by(500) {
                let start = Duration::from_secs(120) + Duration::from_millis(offset_ms as u64);
                let mut io =
                    TimedIo::stalling(start..start + silence, start + Duration::from_secs(120));
                run_egress_probe(&mut io, DEFAULT_FAILURE_THRESHOLD).await;
                assert!(
                    io.escalated_at.is_none(),
                    "a {silence_s} s path stall starting at +{offset_ms} ms tore \
                     the tunnel down, killing every request in flight, over a \
                     path that was carrying nothing for the exit to be blamed for"
                );
            }
        }
    }

    /// The other side of the same coin, and the reason the probe exists: when
    /// the path IS carrying traffic (the peer keeps ACKing) and the exit still
    /// answers nothing, that is evidence against the exit and it must still be
    /// convicted as fast as it ever was.
    #[tokio::test(start_paused = true)]
    async fn an_exit_that_forwards_nothing_behind_a_live_path_is_still_convicted() {
        let dead_from = Duration::from_secs(120);
        let mut io = TimedIo::new(
            dead_from..Duration::MAX,
            dead_from + Duration::from_secs(120),
        );
        run_egress_probe(&mut io, DEFAULT_FAILURE_THRESHOLD).await;
        let at = io
            .escalated_at
            .expect("an exit forwarding nothing over a live path must be convicted");
        assert!(
            at - dead_from <= Duration::from_secs(40),
            "conviction of a genuinely dead exit must not regress: took {:?}",
            at - dead_from
        );
    }

    /// A healthy circuit that loses the odd probe must never be convicted, and
    /// each isolated failure must cost exactly one fast confirmation tick before
    /// the loop settles back onto the steady cadence.
    #[tokio::test(start_paused = true)]
    async fn an_occasional_lost_probe_never_convicts_and_returns_to_the_steady_cadence() {
        let mut io = TimedIo::healthy(Duration::from_secs(3600));
        io.lose_every = 5;
        run_egress_probe(&mut io, DEFAULT_FAILURE_THRESHOLD).await;
        assert!(
            io.published.is_empty() && io.escalated_at.is_none(),
            "isolated losses must never convict: {:?}",
            io.published
        );
        let lost = io.probes / io.lose_every;
        assert_eq!(
            io.fast_ticks,
            1 + lost,
            "the fast cadence must be used once at startup and once per pending \
             failure, never beyond it"
        );
        assert!(
            io.steady_ticks > 100,
            "a healthy circuit must spend its life on the steady cadence"
        );
    }

    /// A redial may land on a different exit, so the new circuit is unproven:
    /// it must be re-proven on the fast cadence, exactly like the first one.
    #[tokio::test]
    async fn a_redial_reproves_the_new_circuit_on_the_fast_cadence() {
        let mut io = MockIo::scripted([Some(true), None, Some(true)]);
        run_egress_probe(&mut io, 3).await;
        assert_eq!(
            io.steady_seen,
            vec![false, true, false, true],
            "the tick after a redial must drop back to the fast cadence, and the \
             one after the new circuit answers must return to the steady one"
        );
    }

    /// The deadline has to leave the last retransmit room to be answered, or the
    /// extra datagram buys nothing. The budget is the measured p99 of the
    /// in-tunnel round trip (see [`MODEL_RTT`]).
    #[test]
    fn every_probe_datagram_can_still_be_answered_inside_the_deadline() {
        for offset in probe_send_offsets() {
            assert!(
                offset + MODEL_RTT <= PROBE_TIMEOUT,
                "a datagram sent at {offset:?} cannot be answered within \
                 {PROBE_TIMEOUT:?} at the measured p99 round trip"
            );
        }
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
