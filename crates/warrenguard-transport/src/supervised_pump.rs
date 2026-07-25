//! TUN <-> multi-hop pump driven by a [`MultiHopSupervisor`] watch
//! channel.
//!
//! The four pump bodies below ([`run_uplink`], [`run_uplink_with_daita`],
//! [`run_downlink`], [`run_downlink_with_daita`]) are the production pump
//! bodies a deployer's TUN-mode client binary drives. They live in the
//! library so the crate's own `live_pump_tests` module (bottom of this
//! file) can exercise the disconnect / reconnect behaviour against a real
//! (setup-stream-free) loopback session and a
//! [`warrenguard_transport_core::FakeTun`] without pulling in OS
//! privileges.
//!
//! ## Semantics during reconnect
//!
//! - **Uplink (TUN -> multi-hop)**: when the supervisor publishes
//!   `None` on the watch channel, [`run_uplink`] drops outbound packets
//!   it reads from the TUN. The host's killswitch and routing guards
//!   stay installed throughout the reconnect window, so a packet that
//!   tries to escape via the original physical default route is blocked
//!   off-tunnel.
//! - **Downlink (multi-hop -> TUN)**: [`run_downlink`] parks on the
//!   watch channel during reconnect rather than busy-looping on a dying
//!   `Connection::read_datagram`. The pump resumes the next iteration
//!   once the supervisor publishes a fresh `Some(client)`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use parking_lot::Mutex as PlMutex;
use warrenguard_daita::DaitaState;
use warrenguard_multihop::WarrenControlMessage;
use warrenguard_pump::{TunIoTolerance, is_daita_dummy, record_uplink_too_large_drop};
use warrenguard_transport_core::{
    PacketDevice, clamp_downlink_syn, clamp_uplink_syn, is_tcp_syn, uplink_frag_needed,
};

use crate::bundle::MultiHopBundle;
use crate::multihop::MultiHopError;
use crate::supervisor::ClientWatch;

pub use crate::{IpAssignChannel, IpAssignSpec};
// The advisory type moved to `drain_policy` (the single drain-reaction home);
// re-exported here so pump-side consumers keep their import path.
pub use crate::drain_policy::ExitDrainAdvisory;

/// `tokio::sync::watch` channel the downlink pump uses to publish an
/// [`ExitDrainAdvisory`] to the orchestrator (ADR 36), mirroring
/// [`IpAssignChannel`]. The pump writes; the orchestrator subscribes and,
/// on an advisory, proactively migrates the user to another exit
/// (make-before-break) before the draining exit hard-closes at the
/// deadline. The draining exit is never named as a *destination* on the
/// wire, so the orchestrator re-selects from its signed relay list: a
/// hostile exit can only make a client leave, never steer it.
#[derive(Clone)]
pub struct ExitDrainingChannel {
    sender: Arc<tokio::sync::watch::Sender<Option<ExitDrainAdvisory>>>,
}

impl Default for ExitDrainingChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitDrainingChannel {
    /// Construct an empty channel ready to be shared via `clone()`.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _initial) = tokio::sync::watch::channel(None);
        Self {
            sender: Arc::new(sender),
        }
    }

    /// Publish a fresh advisory to every active subscriber (latest wins).
    pub fn publish(&self, adv: ExitDrainAdvisory) {
        let _ = self.sender.send_replace(Some(adv));
    }

    /// Subscribe to subsequent drain advisories.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<ExitDrainAdvisory>> {
        self.sender.subscribe()
    }
}

/// Route a decoded downlink control message to its consumer channel.
/// `IpAssign` -> `ip_assign_channel`; `ExitDraining` -> `exit_draining_channel`;
/// anything else (or a missing channel) is logged and dropped. Shared by
/// both downlink pumps so the dispatch policy lives in one place. A `0xC0`
/// control plaintext is never an IP packet nor a DAITA dummy, so the
/// caller routes here before the IP-forward path.
fn dispatch_control_message(
    msg: &WarrenControlMessage,
    ip_assign_channel: Option<&IpAssignChannel>,
    exit_draining_channel: Option<&ExitDrainingChannel>,
) {
    if let Some(spec) = IpAssignSpec::from_control(msg) {
        if let Some(ch) = ip_assign_channel {
            tracing::info!(
                assigned = %spec.assigned,
                gateway = %spec.gateway,
                prefix_len = spec.prefix_len,
                "downlink received IpAssign; publishing on the IpAssignChannel"
            );
            ch.publish(spec);
        } else {
            tracing::debug!("downlink received IpAssign with no consumer; dropping");
        }
    } else if let Some(adv) = ExitDrainAdvisory::from_control(msg) {
        if let Some(ch) = exit_draining_channel {
            tracing::warn!(
                deadline_unix_secs = adv.deadline_unix_secs,
                reason_code = adv.reason_code,
                "downlink received ExitDraining; publishing migrate advisory (make-before-break)"
            );
            ch.publish(adv);
        } else {
            tracing::debug!("downlink received ExitDraining with no consumer; dropping");
        }
    } else {
        // No-log: print only the variant discriminant, never the message body
        // (an `IpRequest`/`IpRequestV7` carries a client pubkey + PoP or
        // anonymous session tokens; both are uplink-only and unreachable here,
        // but this dispatch is shared code).
        let variant = match msg {
            WarrenControlMessage::IpRequest { .. } => "IpRequest",
            WarrenControlMessage::IpRequestV7 { .. } => "IpRequestV7",
            WarrenControlMessage::IpAssign { .. } => "IpAssign",
            WarrenControlMessage::IpExhausted => "IpExhausted",
            WarrenControlMessage::Rejected => "Rejected",
            WarrenControlMessage::RejectedBanned { .. } => "RejectedBanned",
            WarrenControlMessage::ExitDraining { .. } => "ExitDraining",
        };
        tracing::debug!(
            variant,
            "downlink observed a control message with no consumer; dropping"
        );
    }
}

/// Shared per-session [`DaitaState`] handle threaded between the
/// uplink and downlink pumps. `parking_lot::Mutex` keeps
/// the critical section short (no `.await` while holding the lock);
/// both pumps acquire briefly to fire events and to read the next
/// timer instant.
pub type DaitaShared = Arc<PlMutex<DaitaState>>;

/// Minimal mutation surface of a TUN device that [`run_reassign_loop`]
/// needs. Seam so the loop is testable with a recording fake (no TUN
/// privileges); the production impl is [`crate::RealTun`].
pub trait ReassignableTun: Send + Sync + 'static {
    /// Interface name (feeds the Linux v6 split-route install).
    fn name(&self) -> &str;

    /// Replace the interface's IPv4 address.
    ///
    /// # Errors
    ///
    /// OS error from the underlying netlink / ioctl call.
    fn reassign_ipv4(&self, addr: Ipv4Addr, prefix_len: u8) -> std::io::Result<()>;

    /// Add or replace an IPv6 address on the interface.
    ///
    /// # Errors
    ///
    /// OS error from the underlying netlink / ioctl call.
    fn reassign_ipv6(&self, addr: Ipv6Addr, prefix_len: u8) -> std::io::Result<()>;

    /// Remove an IPv6 address from the interface.
    ///
    /// # Errors
    ///
    /// OS error from the underlying netlink / ioctl call.
    fn remove_ipv6(&self, addr: Ipv6Addr) -> std::io::Result<()>;
}

// Gated exactly like `crate::RealTun` itself (warrenguard-transport/src/lib.rs):
// RealTun does not exist on android/ios, where reassignment is driven by the
// platform host (Swift IpAssign callback on iOS), not `run_reassign_loop`.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl ReassignableTun for crate::RealTun {
    fn name(&self) -> &str {
        crate::RealTun::name(self)
    }
    fn reassign_ipv4(&self, addr: Ipv4Addr, prefix_len: u8) -> std::io::Result<()> {
        crate::RealTun::reassign_ipv4(self, addr, prefix_len)
    }
    fn reassign_ipv6(&self, addr: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
        crate::RealTun::reassign_ipv6(self, addr, prefix_len)
    }
    fn remove_ipv6(&self, addr: Ipv6Addr) -> std::io::Result<()> {
        crate::RealTun::remove_ipv6(self, addr)
    }
}

/// Knobs for [`run_reassign_loop`], shared by a product client's
/// `--multi-hop --use-tun` path and the multihop TUN test-client
/// binary (the loop used to be duplicated ~110 lines in each).
#[derive(Debug, Clone)]
pub struct ReassignLoopConfig {
    /// IPv4 the TUN was bootstrapped with; an `IpAssign` matching it is
    /// a no-op.
    pub bootstrap_ipv4: Ipv4Addr,
    /// Apply exit-allocated IPv6 assignments (dual-stack opt-in).
    pub enable_ipv6: bool,
    /// Install the Linux `::/1` + `8000::/1` split route on the first
    /// v6 assignment and hold it for the loop's lifetime (production
    /// behavior). Tests pass `false`: the install shells out to `ip`
    /// and needs `CAP_NET_ADMIN`. No-op off Linux.
    pub install_v6_split_route: bool,
    /// Optional external stop signal. The loop also exits when every
    /// [`IpAssignChannel`] sender is gone, or when its task is aborted.
    pub stop: Option<Arc<tokio::sync::Notify>>,
}

/// Long-lived reassign loop. Subscribes to the [`IpAssignChannel`] and
/// reassigns the TUN on every change that differs from the
/// currently-installed addressing. Survives supervisor reconnects: a
/// first session that times out before its `IpAssign` lands still gets
/// the next attempt's address. Logs a one-shot warning after 30 s
/// without any `IpAssign` so ops can tell "exit without ip-nego" from
/// "everything fine but bootstrap matches", and keeps listening
/// regardless.
pub async fn run_reassign_loop<T: ReassignableTun>(
    tun: T,
    channel: IpAssignChannel,
    cfg: ReassignLoopConfig,
) {
    let mut rx = channel.subscribe();
    let mut current_ipv4 = cfg.bootstrap_ipv4;
    // Track the live v6 so a sticky reconnect to the same address is a
    // no-op and a changed address removes the old binding first.
    let mut current_ipv6: Option<Ipv6Addr> = None;
    // The v6 split route is installed once, on the first v6
    // assignment, and held until the loop ends (drop restores the
    // host). Linux-only; the firewall keeps v6 leak-safe elsewhere.
    #[cfg(target_os = "linux")]
    let mut v6_route_guard: Option<
        warrenguard_route_split::default_route_split::DefaultRouteSplitV6Guard,
    > = None;
    let mut first_wait_logged = false;
    let warn_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        // Pick up any value published before we subscribed (or one
        // cached from a previous iteration).
        let cached = *rx.borrow_and_update();
        if let Some(spec) = cached {
            if spec.assigned == current_ipv4 {
                tracing::debug!(
                    assigned = %spec.assigned,
                    "IpAssign matches the current TUN IPv4; no reassign needed"
                );
            } else {
                match tun.reassign_ipv4(spec.assigned, spec.prefix_len) {
                    Ok(()) => {
                        tracing::info!(
                            old = %current_ipv4,
                            assigned = %spec.assigned,
                            prefix_len = spec.prefix_len,
                            gateway = %spec.gateway,
                            "TUN reassigned to exit-allocated address"
                        );
                        current_ipv4 = spec.assigned;
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            assigned = %spec.assigned,
                            prefix_len = spec.prefix_len,
                            "reassign_ipv4 failed; TUN keeps its current IP"
                        );
                    }
                }
            }
            // Dual-stack: apply the exit-allocated v6 (only when the
            // client asked for it and the exit answered with one).
            if cfg.enable_ipv6
                && let Some(v6) = spec.assigned_v6
                && current_ipv6 != Some(v6)
            {
                if let Some(old) = current_ipv6 {
                    let _ = tun.remove_ipv6(old);
                }
                match tun.reassign_ipv6(v6, spec.prefix_len_v6) {
                    Ok(()) => {
                        // no-log (INV-3): never log the per-session
                        // client v6 itself.
                        tracing::info!(
                            prefix_len_v6 = spec.prefix_len_v6,
                            "TUN reassigned to exit-allocated IPv6 (dual-stack)"
                        );
                        current_ipv6 = Some(v6);
                        #[cfg(target_os = "linux")]
                        if cfg.install_v6_split_route && v6_route_guard.is_none() {
                            match warrenguard_route_split::default_route_split::DefaultRouteSplitV6Guard::install(
                                None,
                                tun.name(),
                                None,
                            )
                            .await
                            {
                                Ok(guard) => {
                                    tracing::info!(
                                        tun = tun.name(),
                                        "installed ::/1 + 8000::/1 v6 split route"
                                    );
                                    v6_route_guard = Some(guard);
                                }
                                Err(e) => tracing::error!(
                                    error = %e,
                                    "v6 split-route install failed; v6 stays on the \
                                     physical default route"
                                ),
                            }
                        }
                    }
                    Err(e) => tracing::error!(
                        error = %e,
                        prefix_len_v6 = spec.prefix_len_v6,
                        "reassign_ipv6 failed; TUN keeps its current v6"
                    ),
                }
            }
        }
        // Park on the next channel change. The warn arm is one-shot.
        let stop_wait = async {
            match cfg.stop.as_ref() {
                Some(stop) => stop.notified().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            res = rx.changed() => {
                if res.is_err() {
                    // Every sender dropped - orchestrator shutting down.
                    tracing::debug!("IpAssignChannel senders dropped; reassign loop exiting");
                    return;
                }
            }
            _ = tokio::time::sleep_until(warn_deadline), if !first_wait_logged => {
                tracing::warn!(
                    bootstrap = %cfg.bootstrap_ipv4,
                    "no IpAssign received within 30 s; TUN keeps the bootstrap \
                     address (exit may run without --multihop-subnet). The \
                     reassign loop keeps listening."
                );
                first_wait_logged = true;
            }
            () = stop_wait => {
                tracing::debug!("reassign loop stop requested");
                return;
            }
        }
    }
}

/// Rewrites the MSS option of a SYN/SYN-ACK crossing this pump down to the
/// bundle's live inner-packet budget (no-op whenever everything already
/// fits). The MSS a peer announces governs segments that must later fit
/// this tunnel's datagrams, so clamping at both pump directions keeps
/// end-to-end TCP flowing on reduced-MTU underlays (train/satellite
/// backhauls, nested tunnels) instead of black-holing full-size segments
/// while the tunnel looks Connected. The per-leg policy (uplink margined,
/// downlink exact) is single-homed in
/// [`warrenguard_transport_core::inner_mtu`], shared with the userland TUN
/// pump so budget fixes land once.
fn clamp_uplink_to_budget(client: &MultiHopBundle, pkt: &mut [u8]) {
    if !is_tcp_syn(pkt) {
        return;
    }
    let budget = u16::try_from(client.max_inner_payload()).unwrap_or(u16::MAX);
    if let Some((old, new)) = clamp_uplink_syn(pkt, budget) {
        tracing::debug!(old, new, budget, "clamped inner TCP MSS to tunnel budget");
    }
}

fn clamp_downlink_to_budget(client: &MultiHopBundle, pkt: &mut [u8]) {
    if !is_tcp_syn(pkt) {
        return;
    }
    let budget = u16::try_from(client.max_inner_payload()).unwrap_or(u16::MAX);
    if let Some((old, new)) = clamp_downlink_syn(pkt, budget) {
        tracing::debug!(old, new, budget, "clamped inner TCP MSS to tunnel budget");
    }
}

/// Reflects a dropped too-large uplink packet back into the TUN as ICMP
/// Fragmentation-Needed / Packet-Too-Big from the tunnel gateway, so the
/// local stack's PMTUD converges per-destination instead of black-holing
/// non-TCP flows (inner QUIC, UDP) that the MSS clamp cannot cover.
async fn reflect_frag_needed<T: PacketDevice>(tun: &T, client: &MultiHopBundle, dropped: &[u8]) {
    let eff = u16::try_from(client.max_inner_payload()).unwrap_or(u16::MAX);
    if let Some(ptb) = uplink_frag_needed(dropped, eff)
        && let Err(e) = tun.send(&ptb).await
    {
        tracing::trace!(error = %e, "frag-needed reflection tun write failed");
    }
}

/// Uplink pump: read IP packets from `tun` and seal them as multi-hop
/// frames using the latest [`crate::multihop::MultiHopClient`] the
/// supervisor publishes on `rx`. Drops packets during reconnect windows
/// so the killswitch invariant holds.
///
/// # Errors
///
/// Propagates a fatal `tun.recv` error (device closed, EIO). Transient
/// multi-hop errors (PMTU race, in-flight send on a closed connection)
/// are logged at trace/debug level and tolerated.
pub async fn run_uplink<T: PacketDevice>(rx: ClientWatch, tun: T) -> Result<()> {
    let mut tun_io = TunIoTolerance::new("uplink tun recv");
    loop {
        let mut packet = match tun.recv().await {
            Ok(p) => {
                tun_io.ok();
                p
            }
            Err(e) => {
                tun_io.tolerate(&e).await.context("tun recv failed")?;
                continue;
            }
        };
        let Some(client) = rx.borrow().clone() else {
            // Mid-reconnect: drop the packet. The killswitch + routing
            // guards prevent off-tunnel leakage; the pump simply skips
            // the egress.
            tracing::trace!(
                pkt = packet.len(),
                "dropping packet: multi-hop session reconnecting"
            );
            continue;
        };
        clamp_uplink_to_budget(&client, &mut packet);
        match client.send(&packet).await {
            Ok(()) => {}
            Err(MultiHopError::Send(quinn::SendDatagramError::TooLarge)) => {
                record_uplink_too_large_drop(packet.len(), client.max_datagram_size());
                reflect_frag_needed(&tun, &client, &packet).await;
            }
            Err(MultiHopError::Send(_)) | Err(MultiHopError::Recv(_)) => {
                tracing::debug!("uplink send on dying connection, supervisor will reconnect");
                drop(client);
            }
            Err(e) => {
                tracing::trace!(error = %e, "uplink send transient error");
            }
        }
    }
}

/// DAITA-aware variant of [`run_uplink`].
///
/// Identical to the regular uplink pump but with three hooks into a
/// shared [`DaitaState`]:
///
/// 1. Every successful `client.send(packet)` fires
///    `NormalSent` + `TunnelSent` so the framework's machines can
///    count packet activity.
/// 2. A `tokio::select!` arm wakes on the next per-machine action
///    timer expiry (via `DaitaState::next_timer`). On wake the pump
///    drains expired timers and emits one
///    `MultiHopClient::send_daita_padding()` per machine - each
///    padding frame is sealed by HPKE so the relay sees only
///    ciphertext, and the receiver-side filter (`is_daita_dummy`)
///    drops the dummy at the exit's TUN gateway.
/// 3. On reconnect (supervisor publishes `None`) the timer arm
///    remains armed; once the client returns, queued timers fire as
///    usual without state loss.
///
/// # Errors
///
/// Same as [`run_uplink`].
pub async fn run_uplink_with_daita<T: PacketDevice>(
    rx: ClientWatch,
    tun: T,
    daita: DaitaShared,
    state_changed: Arc<tokio::sync::Notify>,
) -> Result<()> {
    // Rate-limited per-task counters so a bench harness can correlate
    // the silent drop paths (mid-reconnect / TooLarge / dying-conn)
    // against the wire trace. Resets after each 5 s report.
    let mut from_tun = 0u64;
    let mut no_session = 0u64;
    let mut sent_real = 0u64;
    let mut sent_padding = 0u64;
    let mut padding_failed = 0u64;
    let mut too_large = 0u64;
    let mut dying = 0u64;
    let mut last_report = Instant::now();
    let mut tun_io = TunIoTolerance::new("uplink tun recv");
    loop {
        // Arm a sleep on the next action timer (or 1h placeholder
        // when no timer is armed, same pattern as
        // `pump_bidirectional_with_daita`). The `state_changed`
        // notify arm is the cross-task wake-up: when the
        // downlink pump fires Recv events that schedule a closer
        // action timer, it notifies and this select returns early to
        // re-read `next_timer`. Without this the uplink-owned timer
        // would park on the 1 h placeholder until the next uplink
        // packet, missing the downlink-scheduled padding cadence.
        let next_timer = daita.lock().sleep_deadline(Instant::now());
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(next_timer));
        tokio::pin!(sleep);

        tokio::select! {
            res = tun.recv() => {
                let packet = match res {
                    Ok(p) => {
                        tun_io.ok();
                        p
                    }
                    Err(e) => {
                        tun_io.tolerate(&e).await.context("tun recv failed")?;
                        continue;
                    }
                };
                from_tun += 1;
                let Some(client) = rx.borrow().clone() else {
                    no_session += 1;
                    tracing::trace!(
                        pkt = packet.len(),
                        "dropping packet: multi-hop session reconnecting"
                    );
                    continue;
                };
                let mut packet = packet;
                clamp_uplink_to_budget(&client, &mut packet);
                match client.send(&packet).await {
                    Ok(()) => {
                        sent_real += 1;
                        daita.lock().on_real_uplink_sent(Instant::now());
                        state_changed.notify_one();
                    }
                    Err(MultiHopError::Send(quinn::SendDatagramError::TooLarge)) => {
                        too_large += 1;
                        record_uplink_too_large_drop(packet.len(), client.max_datagram_size());
                        reflect_frag_needed(&tun, &client, &packet).await;
                    }
                    Err(MultiHopError::Send(_)) | Err(MultiHopError::Recv(_)) => {
                        dying += 1;
                        tracing::debug!(
                            "uplink send on dying connection, supervisor will reconnect"
                        );
                        drop(client);
                    }
                    Err(e) => {
                        tracing::trace!(error = %e, "uplink send transient error");
                    }
                }
            }
            _ = &mut sleep => {
                let fired = {
                    let mut st = daita.lock();
                    st.drain_expired(Instant::now())
                };
                if fired.is_empty() {
                    continue;
                }
                let Some(client) = rx.borrow().clone() else {
                    continue;
                };
                for machine in fired {
                    match client.send_daita_padding().await {
                        Ok(_) => {
                            sent_padding += 1;
                            daita.lock().on_dummy_sent(machine, Instant::now());
                            state_changed.notify_one();
                        }
                        Err(e) => {
                            padding_failed += 1;
                            tracing::trace!(error = %e, "daita padding emit failed");
                        }
                    }
                }
            }
            _ = state_changed.notified() => {
                continue;
            }
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            tracing::debug!(
                from_tun,
                no_session,
                sent_real,
                sent_padding,
                padding_failed,
                too_large,
                dying,
                "uplink_with_daita report"
            );
            last_report = Instant::now();
        }
    }
}

/// Downlink pump: drain decoded plaintexts from the active multi-hop
/// session and write them onto `tun`. Parks on the watch channel when
/// the supervisor publishes `None` so the recv future is not racing
/// against a freshly-installed connection.
///
/// # Errors
///
/// `Err` only when the supervisor's watch channel terminates (binary
/// shutting down) or when `tun.send` returns an unrecoverable OS error.
pub async fn run_downlink<T: PacketDevice>(
    mut rx: ClientWatch,
    tun: T,
    exit_draining_channel: Option<ExitDrainingChannel>,
) -> Result<()> {
    let mut tun_io = TunIoTolerance::new("downlink tun send");
    loop {
        let maybe = rx.borrow().clone();
        let Some(client) = maybe else {
            if rx.changed().await.is_err() {
                return Err(anyhow!("supervisor watch closed; downlink shutting down"));
            }
            continue;
        };
        tokio::select! {
            res = client.recv() => {
                match res {
                    Ok(payload) => {
                        // A 0xC0 plaintext is a Warren control frame, never an
                        // IP packet: intercept `ExitDraining` (ADR 36 drain
                        // advisory) before the TUN-forward path so the daemon's
                        // make-before-break reactor sees it. This non-DAITA
                        // pump is the default multi-hop downlink, so
                        // without this branch the advisory would be written to
                        // the TUN as junk and kernel-dropped. Non-control
                        // payloads fall through to the TUN unchanged.
                        match warrenguard_multihop::try_decode_control(&payload) {
                            Ok(Some(msg)) => {
                                dispatch_control_message(
                                    &msg,
                                    None,
                                    exit_draining_channel.as_ref(),
                                );
                                continue;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                // A 0xC0-marked but malformed control frame is
                                // not an IP packet (0xC0 is an invalid IP first
                                // byte); drop it rather than forward junk to the
                                // TUN, matching `run_downlink_with_daita`.
                                tracing::trace!(error = %e, "downlink control decode error");
                                continue;
                            }
                        }
                        // An armed exit pads its downlink with 0xFF dummies for
                        // every connection, not only DAITA-negotiated ones. On
                        // this plain pump each dummy written to the TUN is a
                        // kernel-rejected write ("IP version 15") that costs the
                        // 1 ms tolerance backoff, stalling real downlink packets
                        // behind it.
                        if is_daita_dummy(&payload) {
                            continue;
                        }
                        let mut payload = payload;
                        clamp_downlink_to_budget(&client, &mut payload);
                        match tun.send(&payload).await {
                            Ok(()) => {
                                tun_io.ok();
                                client.note_real_downlink();
                            }
                            Err(e) => {
                                tun_io
                                    .tolerate(&e)
                                    .await
                                    .context("tun send failed")?;
                            }
                        }
                    }
                    Err(MultiHopError::Recv(_)) => {
                        tracing::debug!(
                            "downlink recv on dying connection, waiting for supervisor to swap"
                        );
                        if rx.changed().await.is_err() {
                            return Err(anyhow!("supervisor watch closed; downlink shutting down"));
                        }
                    }
                    Err(e) => {
                        tracing::trace!(error = %e, "downlink recv transient error");
                    }
                }
            }
            res = rx.changed() => {
                if res.is_err() {
                    return Err(anyhow!("supervisor watch closed; downlink shutting down"));
                }
            }
        }
    }
}

/// DAITA-aware variant of [`run_downlink`].
///
/// After HPKE-opening each reverse-direction frame, the pump checks
/// the cleartext's first-nibble via [`is_daita_dummy`]:
///
/// - **IP packet** (nibble 4 or 6): forwarded to the TUN as usual,
///   and the framework receives `TunnelRecv` + `NormalRecv`.
/// - **Dummy** (anything else, in practice nibble 0xF): dropped at
///   the pump (never written to the TUN where the kernel would
///   discard it anyway), and the framework receives
///   `TunnelRecv` + `PaddingRecv`.
///
/// The cleartext check is correct on the multi-hop side because the
/// dummy marker lives in the **plaintext** carried inside the HPKE
/// envelope; the relay only sees ciphertext and cannot distinguish
/// padding from real IP packets.
///
/// # Errors
///
/// Same as [`run_downlink`].
pub async fn run_downlink_with_daita<T: PacketDevice>(
    mut rx: ClientWatch,
    tun: T,
    daita: DaitaShared,
    state_changed: Arc<tokio::sync::Notify>,
    ip_assign_channel: Option<IpAssignChannel>,
    exit_draining_channel: Option<ExitDrainingChannel>,
) -> Result<()> {
    // Rate-limited counters so the bench harness can see exactly where
    // downlink frames go (filtered as dummies vs forwarded to TUN).
    let mut recvd = 0u64;
    let mut dummies = 0u64;
    let mut to_tun = 0u64;
    // Control-message dispatch counters. The exit can send IpAssign
    // (setup) and ExitDraining (mid-session drain advisory, ADR 36);
    // both are intercepted before the IP forwarding path and routed to
    // their consumer channels by `dispatch_control_message`.
    let mut control_ok = 0u64;
    let mut control_errs = 0u64;
    let mut last_report = Instant::now();
    let mut tun_io = TunIoTolerance::new("downlink tun send");
    loop {
        let maybe = rx.borrow().clone();
        let Some(client) = maybe else {
            if rx.changed().await.is_err() {
                return Err(anyhow!("supervisor watch closed; downlink shutting down"));
            }
            continue;
        };
        tokio::select! {
            res = client.recv() => {
                match res {
                    Ok(payload) => {
                        recvd += 1;
                        // Control message dispatch precedes the
                        // DAITA dummy + IP forward paths. A 0xC0
                        // plaintext is never an IP packet, never a
                        // DAITA dummy, so the check order is
                        // control > daita > ip. `dispatch_control_message`
                        // routes IpAssign and ExitDraining to their
                        // consumer channels; any other variant (or a
                        // missing channel) is logged and dropped.
                        match warrenguard_multihop::try_decode_control(&payload) {
                            Ok(Some(msg)) => {
                                control_ok += 1;
                                dispatch_control_message(
                                    &msg,
                                    ip_assign_channel.as_ref(),
                                    exit_draining_channel.as_ref(),
                                );
                                continue;
                            }
                            Ok(None) => {}
                            Err(e) => {
                                control_errs += 1;
                                tracing::debug!(
                                    error = %e,
                                    "downlink control-message decode failed; dropping frame"
                                );
                                continue;
                            }
                        }
                        // One Instant::now() per payload, and one Mutex lock:
                        // TunnelRecv must fire before the kind-specific event
                        // per the maybenot specification, both in a single
                        // critical section.
                        let now = Instant::now();
                        let dummy = is_daita_dummy(&payload);
                        if dummy {
                            dummies += 1;
                            // Drop the dummy; the receiver TUN would discard it
                            // anyway as a malformed IP packet.
                        } else {
                            let mut payload = payload;
                            clamp_downlink_to_budget(&client, &mut payload);
                            match tun.send(&payload).await {
                                Ok(()) => {
                                    tun_io.ok();
                                    to_tun += 1;
                                    client.note_real_downlink();
                                }
                                Err(e) => {
                                    tun_io
                                        .tolerate(&e)
                                        .await
                                        .context("tun send failed")?;
                                }
                            }
                        }
                        // Shared downlink event sequence (TunnelRecv before the
                        // kind-specific event) for real and dummy; single lock.
                        daita.lock().on_downlink_received(dummy, now);
                        state_changed.notify_one();
                        if last_report.elapsed() >= Duration::from_secs(5) {
                            tracing::debug!(
                                recvd,
                                dummies,
                                to_tun,
                                control_ok,
                                control_errs,
                                "downlink_with_daita report"
                            );
                            last_report = Instant::now();
                        }
                    }
                    Err(MultiHopError::Recv(_)) => {
                        tracing::debug!(
                            "downlink recv on dying connection, waiting for supervisor to swap"
                        );
                        if rx.changed().await.is_err() {
                            return Err(anyhow!("supervisor watch closed; downlink shutting down"));
                        }
                    }
                    Err(e) => {
                        tracing::trace!(error = %e, "downlink recv transient error");
                    }
                }
            }
            res = rx.changed() => {
                if res.is_err() {
                    return Err(anyhow!("supervisor watch closed; downlink shutting down"));
                }
            }
        }
    }
}

/// Idle-cover emitter for the multi-hop supervised datapath.
///
/// The mono-conn pump ([`warrenguard_pump::pump_bidirectional_with_idle_cover`])
/// runs cover inline in its single select loop, but the multi-hop pump is
/// split into independent uplink/downlink tasks over a session that the
/// supervisor swaps on reconnect. This task is the cover home for that shape:
/// it follows the live [`crate::bundle::MultiHopBundle`] on the watch channel
/// and drives the SAME [`warrenguard_pump::idle_cover::IdleCover`] scheduler,
/// so the jittered interval + varied size are byte-identical to the mono-conn
/// footprint. It sends each dummy through [`MultiHopBundle::send_cover_traffic`]
/// (sealed by HPKE, dropped at the exit by `is_daita_dummy`), and the exit's
/// own downlink dummies are already filtered by [`run_downlink`].
///
/// Caller contract (mirrors the mono-conn pump): the multi-hop client
/// transport config MUST disable the keep-alive PING
/// (`warren_transport_config_client_multihop_with_idle_cover(.., true)` /
/// the obfuscation profile's idle-cover variant), or the fixed 5s beacon this
/// replaces still fires alongside cover.
///
/// # Errors
///
/// Returns `Ok(())` when the supervisor's watch channel closes (shutdown). A
/// transient cover-send failure (dying connection, PMTU race) is logged at
/// trace and tolerated; the supervisor redials.
pub async fn run_idle_cover(rx: ClientWatch) -> Result<()> {
    run_idle_cover_interval(
        rx,
        warrenguard_pump::idle_cover::IDLE_COVER_MIN_INTERVAL,
        warrenguard_pump::idle_cover::IDLE_COVER_MAX_INTERVAL,
    )
    .await
}

/// Test/tuning seam behind [`run_idle_cover`]: identical wiring with an
/// explicit jittered interval range instead of the fixed production 10-20s
/// bounds, so an integration test can drive the real reconnect-following loop
/// with a short interval instead of waiting ~35s.
///
/// # Errors
///
/// Same as [`run_idle_cover`].
pub async fn run_idle_cover_interval(
    mut rx: ClientWatch,
    min_interval: Duration,
    max_interval: Duration,
) -> Result<()> {
    use warrenguard_pump::idle_cover::IdleCover;

    // Created lazily on the first live bundle (it needs the path budget to seed
    // the size cap) and then kept across reconnects so the jitter/size cadence
    // stays continuous through a make-before-break swap; a `None` on the watch
    // (mid-reconnect gap) drops it so the next bundle re-seeds to its own MTU.
    let mut cover: Option<IdleCover> = None;
    // Last real-traffic totals seen: cover stays silent while user traffic
    // flows, mirroring the mono-conn pump's `note_activity` but sampled at each
    // jittered deadline (the split tasks own the packet loops, this task only
    // watches the bundle's cumulative real-traffic counters).
    let mut last_totals: Option<(u64, u64)> = None;
    loop {
        let Some(bundle) = rx.borrow().clone() else {
            cover = None;
            last_totals = None;
            if rx.changed().await.is_err() {
                return Ok(());
            }
            continue;
        };
        if cover.is_none() {
            cover = Some(IdleCover::with_interval(
                // Per-bundle local seed (never on the wire) so two concurrent
                // tunnels do not share a cover schedule.
                Arc::as_ptr(&bundle) as usize as u64,
                Instant::now(),
                Some(bundle.max_inner_payload()),
                min_interval,
                max_interval,
            ));
            // Baseline the silencing counter so the first idle deadline emits
            // (rather than being mistaken for activity against a `None`).
            last_totals = Some(bundle.real_traffic_totals());
        }
        let sched = cover.as_mut().expect("scheduler seeded above");
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(sched.deadline()));
        tokio::pin!(sleep);
        tokio::select! {
            () = &mut sleep => {
                let now = Instant::now();
                let totals = bundle.real_traffic_totals();
                if last_totals != Some(totals) {
                    // Real traffic advanced during this interval: silence cover
                    // and re-arm, exactly like note_activity on the mono pump.
                    last_totals = Some(totals);
                    cover
                        .as_mut()
                        .expect("scheduler seeded above")
                        .note_activity(now);
                    continue;
                }
                let size = cover.as_mut().expect("scheduler seeded above").fire_size(now);
                // A dummy is one discriminator byte plus padding; clamp to the
                // live path budget so a PMTU shrink since seeding does not make
                // every dummy a TooLarge drop.
                let padding_len = size
                    .saturating_sub(1)
                    .min(bundle.max_inner_payload().saturating_sub(1));
                if let Err(e) = bundle.send_cover_traffic(padding_len) {
                    tracing::trace!(error = %e, "idle cover send transient error");
                }
            }
            res = rx.changed() => {
                if res.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_assign_v4_only_reads_back_without_v6() {
        let msg = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 42],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        let spec = IpAssignSpec::from_control(&msg).expect("IpAssign must yield Some");
        assert_eq!(spec.assigned, Ipv4Addr::new(10, 66, 0, 42));
        assert_eq!(spec.prefix_len, 24);
        assert_eq!(spec.gateway, Ipv4Addr::new(10, 66, 0, 1));
        assert!(
            spec.assigned_v6.is_none(),
            "ipv6 None = v6 not granted -> client stays v4-only (the capability gap)"
        );
    }

    #[test]
    fn ip_assign_dual_stack_reads_back_the_v6() {
        let msg = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 42],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: Some(Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 2).octets()),
            prefix_len_v6: 64,
            gateway_ipv6: Some(Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 1).octets()),
            daita_spec: None,
        };
        let spec = IpAssignSpec::from_control(&msg).expect("IpAssign must yield Some");
        assert_eq!(
            spec.assigned_v6,
            Some(Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 2)),
            "v6 granted -> present (the capability echo)"
        );
        assert_eq!(spec.prefix_len_v6, 64);
        assert_eq!(
            spec.gateway_v6,
            Some(Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn ip_assign_spec_from_control_other_variants_yield_none() {
        let req = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
            wants_daita: false,
        };
        assert!(IpAssignSpec::from_control(&req).is_none());
        let ex = WarrenControlMessage::IpExhausted;
        assert!(IpAssignSpec::from_control(&ex).is_none());
    }

    #[test]
    fn exit_draining_advisory_reads_back_deadline_and_reason() {
        // ADR 36: a mid-session ExitDraining decodes into the advisory the
        // orchestrator acts on (migrate before the deadline).
        let msg = WarrenControlMessage::ExitDraining {
            deadline_unix_secs: 1_700_000_120,
            reason_code: 3,
        };
        let adv = ExitDrainAdvisory::from_control(&msg).expect("ExitDraining must yield Some");
        assert_eq!(adv.deadline_unix_secs, 1_700_000_120);
        assert_eq!(adv.reason_code, 3);
    }

    #[test]
    fn exit_draining_advisory_other_variants_yield_none() {
        // Only ExitDraining maps to an advisory; an IpAssign must not.
        let assign = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 7],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        assert!(ExitDrainAdvisory::from_control(&assign).is_none());
        assert!(ExitDrainAdvisory::from_control(&WarrenControlMessage::Rejected).is_none());
    }

    #[test]
    fn exit_draining_channel_publishes_latest_advisory() {
        // The channel surfaces the advisory to a subscriber (latest wins),
        // the seam the orchestrator uses to trigger make-before-break.
        let ch = ExitDrainingChannel::new();
        let mut rx = ch.subscribe();
        assert!(rx.borrow_and_update().is_none(), "starts empty");
        ch.publish(ExitDrainAdvisory {
            deadline_unix_secs: 42,
            reason_code: 0,
        });
        let got = rx.borrow_and_update().expect("advisory published");
        assert_eq!(got.deadline_unix_secs, 42);
    }

    // ----------------------------------------------------------------
    // run_reassign_loop (mock ReassignableTun)
    // ----------------------------------------------------------------

    #[derive(Debug, Clone, Default)]
    struct FakeReassignTun {
        calls: Arc<std::sync::Mutex<Vec<String>>>,
        /// Acked on every `record()`, so `wait_for_calls` can await a real
        /// signal from the fake instead of polling on a fixed real-time
        /// sleep (slow and, at 10 ms against a 2 s deadline, flaky under
        /// load: an event landing just past the poll window would falsely
        /// time out).
        recorded: Arc<tokio::sync::Notify>,
    }

    impl FakeReassignTun {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("mutex").clone()
        }
        fn record(&self, call: String) {
            self.calls.lock().expect("mutex").push(call);
            self.recorded.notify_one();
        }
    }

    impl ReassignableTun for FakeReassignTun {
        fn name(&self) -> &str {
            "faketun0"
        }
        fn reassign_ipv4(&self, addr: Ipv4Addr, prefix_len: u8) -> std::io::Result<()> {
            self.record(format!("v4 {addr}/{prefix_len}"));
            Ok(())
        }
        fn reassign_ipv6(&self, addr: Ipv6Addr, prefix_len: u8) -> std::io::Result<()> {
            self.record(format!("v6 {addr}/{prefix_len}"));
            Ok(())
        }
        fn remove_ipv6(&self, addr: Ipv6Addr) -> std::io::Result<()> {
            self.record(format!("del-v6 {addr}"));
            Ok(())
        }
    }

    fn spec_v4(a: u8) -> IpAssignSpec {
        IpAssignSpec {
            assigned: Ipv4Addr::new(10, 66, 0, a),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            assigned_v6: None,
            prefix_len_v6: 0,
            gateway_v6: None,
        }
    }

    fn test_cfg(stop: Arc<tokio::sync::Notify>) -> ReassignLoopConfig {
        ReassignLoopConfig {
            bootstrap_ipv4: Ipv4Addr::new(10, 66, 0, 99),
            enable_ipv6: true,
            // The split-route install shells out to `ip` and needs
            // CAP_NET_ADMIN: never in tests.
            install_v6_split_route: false,
            stop: Some(stop),
        }
    }

    async fn wait_for_calls(tun: &FakeReassignTun, expected: &[&str]) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                // Check BEFORE arming the wait: a `record()` between the
                // previous iteration's check and this one still lands the
                // notify permit (`Notify::notify_one` retains a permit for
                // the next `notified()` call when nobody is currently
                // waiting), so this never misses a fast double-record.
                if tun.calls() == expected {
                    return;
                }
                tun.recorded.notified().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected:?}, got {:?}", tun.calls()));
    }

    #[tokio::test]
    async fn reassign_loop_applies_a_published_ipv4() {
        let tun = FakeReassignTun::default();
        let channel = IpAssignChannel::new();
        let stop = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(run_reassign_loop(
            tun.clone(),
            channel.clone(),
            test_cfg(stop.clone()),
        ));

        channel.publish(spec_v4(7));
        wait_for_calls(&tun, &["v4 10.66.0.7/24"]).await;

        stop.notify_waiters();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("loop must exit on stop")
            .expect("loop task must not panic");
    }

    #[tokio::test(start_paused = true)]
    async fn reassign_loop_skips_an_assign_matching_the_bootstrap() {
        let tun = FakeReassignTun::default();
        let channel = IpAssignChannel::new();
        let stop = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(run_reassign_loop(
            tun.clone(),
            channel.clone(),
            test_cfg(stop.clone()),
        ));

        channel.publish(spec_v4(99)); // == bootstrap_ipv4
        // Virtual-clock jump (not a real sleep) well past any scheduling
        // latency the loop could need to process the publish: proving
        // absence costs no wall-clock time and cannot false-pass just
        // because a slow CI runner missed a fixed real-time window.
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(
            tun.calls().is_empty(),
            "an IpAssign equal to the bootstrap must not touch the TUN, got {:?}",
            tun.calls()
        );

        stop.notify_waiters();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("loop must exit on stop")
            .expect("loop task must not panic");
    }

    #[tokio::test]
    async fn reassign_loop_replaces_an_old_ipv6_on_change() {
        let tun = FakeReassignTun::default();
        let channel = IpAssignChannel::new();
        let stop = Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(run_reassign_loop(
            tun.clone(),
            channel.clone(),
            test_cfg(stop.clone()),
        ));

        let v6_a = Ipv6Addr::new(0xfdcc, 0xf, 0x1, 0, 0, 0, 0, 2);
        let v6_b = Ipv6Addr::new(0xfdcc, 0xf, 0x1, 0, 0, 0, 0, 3);
        let mut first = spec_v4(7);
        first.assigned_v6 = Some(v6_a);
        first.prefix_len_v6 = 64;
        channel.publish(first);
        wait_for_calls(&tun, &["v4 10.66.0.7/24", &format!("v6 {v6_a}/64")]).await;

        let mut second = first;
        second.assigned_v6 = Some(v6_b);
        channel.publish(second);
        wait_for_calls(
            &tun,
            &[
                "v4 10.66.0.7/24",
                &format!("v6 {v6_a}/64"),
                &format!("del-v6 {v6_a}"),
                &format!("v6 {v6_b}/64"),
            ],
        )
        .await;

        stop.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn reassign_loop_ignores_a_granted_v6_when_v6_is_disabled() {
        let tun = FakeReassignTun::default();
        let channel = IpAssignChannel::new();
        let stop = Arc::new(tokio::sync::Notify::new());
        let mut cfg = test_cfg(stop.clone());
        cfg.enable_ipv6 = false;
        let task = tokio::spawn(run_reassign_loop(tun.clone(), channel.clone(), cfg));

        let mut spec = spec_v4(7);
        spec.assigned_v6 = Some(Ipv6Addr::new(0xfdcc, 0xf, 0x1, 0, 0, 0, 0, 2));
        spec.prefix_len_v6 = 64;
        channel.publish(spec);
        wait_for_calls(&tun, &["v4 10.66.0.7/24"]).await;
        // No extra settle-sleep needed: `run_reassign_loop` evaluates the
        // `cfg.enable_ipv6` gate synchronously, in the same poll and with
        // no `.await` in between, right after the v4 reassignment. By the
        // time `wait_for_calls` observes the v4 record, the v6 gate for
        // this iteration has therefore already run to completion.
        assert_eq!(
            tun.calls(),
            vec!["v4 10.66.0.7/24"],
            "with enable_ipv6=false the granted v6 must not be applied \
             (native v6 stays under the killswitch)"
        );

        stop.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn ip_assign_channel_publish_then_subscribe_returns_value() {
        let channel = IpAssignChannel::new();
        let spec = IpAssignSpec {
            assigned: Ipv4Addr::new(10, 66, 0, 7),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            assigned_v6: None,
            prefix_len_v6: 0,
            gateway_v6: None,
        };
        channel.publish(spec);
        // Subscribing AFTER publish still surfaces the latest cached
        // value through `borrow_and_update`. This is what the
        // orchestrator's reassign task does on its first iteration.
        let mut rx = channel.subscribe();
        let cached = *rx.borrow_and_update();
        assert_eq!(cached, Some(spec));
    }

    #[tokio::test]
    async fn ip_assign_channel_changed_blocks_until_publish() {
        let channel = IpAssignChannel::new();
        let mut rx = channel.subscribe();
        assert!(rx.borrow().is_none(), "fresh channel starts empty");
        let writer_channel = channel.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            writer_channel.publish(IpAssignSpec {
                assigned: Ipv4Addr::new(10, 66, 0, 3),
                prefix_len: 24,
                gateway: Ipv4Addr::new(10, 66, 0, 1),
                assigned_v6: None,
                prefix_len_v6: 0,
                gateway_v6: None,
            });
        });
        tokio::time::timeout(Duration::from_millis(200), rx.changed())
            .await
            .expect("must not time out")
            .expect("publisher must be alive");
        let got = (*rx.borrow_and_update()).expect("spec must be set");
        assert_eq!(got.assigned, Ipv4Addr::new(10, 66, 0, 3));
        writer.await.expect("writer task");
    }

    #[tokio::test]
    async fn ip_assign_channel_latest_publish_wins() {
        // The channel collapses to "latest value
        // wins" so a burst of reconnects from the supervisor only
        // surfaces the most recent IpAssign to the reassign task.
        let channel = IpAssignChannel::new();
        let first = IpAssignSpec {
            assigned: Ipv4Addr::new(10, 66, 0, 5),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            assigned_v6: None,
            prefix_len_v6: 0,
            gateway_v6: None,
        };
        let second = IpAssignSpec {
            assigned: Ipv4Addr::new(10, 66, 0, 99),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            assigned_v6: None,
            prefix_len_v6: 0,
            gateway_v6: None,
        };
        channel.publish(first);
        channel.publish(second);
        let mut rx = channel.subscribe();
        let got = (*rx.borrow_and_update()).expect("spec must be set");
        assert_eq!(got, second, "second publish overwrites first");
    }

    #[tokio::test]
    async fn ip_assign_channel_multiple_subscribers_see_publish() {
        // Each subscriber gets its own receiver but they share the
        // same broadcast underneath: a single publish wakes them all.
        let channel = IpAssignChannel::new();
        let mut rx_a = channel.subscribe();
        let mut rx_b = channel.subscribe();
        let spec = IpAssignSpec {
            assigned: Ipv4Addr::new(10, 66, 0, 8),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 66, 0, 1),
            assigned_v6: None,
            prefix_len_v6: 0,
            gateway_v6: None,
        };
        channel.publish(spec);
        tokio::time::timeout(Duration::from_millis(100), rx_a.changed())
            .await
            .expect("rx_a not timeout")
            .expect("rx_a alive");
        tokio::time::timeout(Duration::from_millis(100), rx_b.changed())
            .await
            .expect("rx_b not timeout")
            .expect("rx_b alive");
        assert_eq!(*rx_a.borrow_and_update(), Some(spec));
        assert_eq!(*rx_b.borrow_and_update(), Some(spec));
    }
}

/// Live loopback tests for the four production pump bodies
/// ([`run_uplink`], [`run_uplink_with_daita`], [`run_downlink`],
/// [`run_downlink_with_daita`]) against a real (but setup-stream-free)
/// [`crate::multihop::MultiHopClient`] session
/// ([`crate::test_support::spawn_loopback_multihop`]) and a
/// [`warrenguard_transport_core::FakeTun`]. These pin the reconnect-window
/// drop invariant (the killswitch/no-leak contract), the downlink control-
/// message interception, and the DAITA dummy filter - the exact gaps a
/// deleted-code check must turn red.
#[cfg(test)]
mod live_pump_tests {
    use std::time::Duration;

    use bytes::Bytes;
    use warrenguard_multihop::{ExitId, encode_control, encode_frame};

    use super::*;
    use crate::bundle::MultiHopBundle;
    use crate::test_support::spawn_loopback_multihop;

    const RECV_TIMEOUT: Duration = Duration::from_millis(500);
    const ABSENCE_WINDOW: Duration = Duration::from_millis(150);

    /// Seals `payload` as a reverse-direction (exit -> client) frame using
    /// the loopback pair's matching `ExitSession`, then sends it as a raw
    /// QUIC datagram on the exit-side connection - exactly what a real
    /// exit's downlink write does, minus the setup-stream bootstrap.
    async fn exit_send_datagram(
        pair: &crate::test_support::LoopbackMultiHop,
        seq: u64,
        payload: Vec<u8>,
    ) {
        let frame = pair
            .exit_session
            .seal_response(&payload, 0, seq)
            .expect("seal_response");
        let wire = encode_frame(&frame).expect("encode_frame");
        pair.exit_conn
            .send_datagram(Bytes::from(wire))
            .expect("send_datagram");
    }

    /// Polls `tun.take_outbound()` until it is non-empty or `RECV_TIMEOUT`
    /// elapses.
    async fn wait_for_outbound(tun: &warrenguard_transport_core::FakeTun) -> Vec<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + RECV_TIMEOUT;
        loop {
            let out = tun.take_outbound();
            if !out.is_empty() {
                return out;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for a packet on the TUN outbound queue"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // ------------------------------------------------------------------
    // run_uplink: reconnect-window drop invariant (B6, security-critical)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_uplink_forwards_then_drops_during_reconnect_then_resumes() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x11; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle.clone()));
        let tun = warrenguard_transport_core::FakeTun::new();

        let task = tokio::spawn(run_uplink(rx, tun.clone()));

        // Connected: a packet must flow to the exit as a sealed frame.
        tun.inject_inbound(vec![0x45, 0, 0, 20, 1, 2, 3, 4]);
        let first = tokio::time::timeout(RECV_TIMEOUT, pair.exit_conn.read_datagram())
            .await
            .expect("must not time out while connected")
            .expect("datagram");
        assert!(!first.is_empty(), "the first packet must reach the exit");

        // The supervisor publishes None on a mid-session disconnect: the
        // pump must drain the TUN read (so the queue does not back up)
        // but MUST NOT reach the multi-hop session - a leak here would
        // put plaintext on the wire during the exact window the client's
        // UI still shows "connected". A stale "last known client" cache
        // would defeat this: the guard must re-read the watch every time.
        tx.send(None).expect("watch has a receiver");
        tun.inject_inbound(vec![0x45, 0, 0, 20, 5, 6, 7, 8]);
        tokio::time::sleep(ABSENCE_WINDOW).await;
        let got =
            tokio::time::timeout(Duration::from_millis(50), pair.exit_conn.read_datagram()).await;
        assert!(
            got.is_err(),
            "a packet read during the reconnect window must never reach the exit"
        );

        // Once the supervisor republishes the (possibly new) session,
        // forwarding must resume immediately.
        tx.send(Some(bundle)).expect("watch has a receiver");
        tun.inject_inbound(vec![0x45, 0, 0, 20, 9, 9, 9, 9]);
        let resumed = tokio::time::timeout(RECV_TIMEOUT, pair.exit_conn.read_datagram())
            .await
            .expect("must not time out once the session is live again")
            .expect("datagram");
        assert!(
            !resumed.is_empty(),
            "forwarding must resume once live again"
        );

        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn run_uplink_with_daita_forwards_then_drops_during_reconnect_then_resumes() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x12; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle.clone()));
        let tun = warrenguard_transport_core::FakeTun::new();
        let daita: DaitaShared = Arc::new(PlMutex::new(DaitaState::disabled()));
        let state_changed = Arc::new(tokio::sync::Notify::new());

        let task = tokio::spawn(run_uplink_with_daita(rx, tun.clone(), daita, state_changed));

        tun.inject_inbound(vec![0x45, 0, 0, 20, 1, 1, 1, 1]);
        let first = tokio::time::timeout(RECV_TIMEOUT, pair.exit_conn.read_datagram())
            .await
            .expect("must not time out while connected")
            .expect("datagram");
        assert!(!first.is_empty(), "the first packet must reach the exit");

        tx.send(None).expect("watch has a receiver");
        tun.inject_inbound(vec![0x45, 0, 0, 20, 9, 9, 9, 9]);
        tokio::time::sleep(ABSENCE_WINDOW).await;
        let got =
            tokio::time::timeout(Duration::from_millis(50), pair.exit_conn.read_datagram()).await;
        assert!(
            got.is_err(),
            "the DAITA-aware uplink must also drop mid-reconnect, never seal-and-send"
        );

        tx.send(Some(bundle)).expect("watch has a receiver");
        tun.inject_inbound(vec![0x45, 0, 0, 20, 2, 2, 2, 2]);
        let resumed = tokio::time::timeout(RECV_TIMEOUT, pair.exit_conn.read_datagram())
            .await
            .expect("must not time out once the session is live again")
            .expect("datagram");
        assert!(
            !resumed.is_empty(),
            "forwarding must resume once live again"
        );

        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    // ------------------------------------------------------------------
    // run_idle_cover: multi-hop cover emitter (ADR-0006)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_idle_cover_emits_hpke_sealed_dummies_the_exit_drops() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x31; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle));

        // Short interval so cover fires inside the test window (the production
        // path is 10-20s); the seam drives the exact same reconnect-following
        // loop, just re-timed.
        let task = tokio::spawn(run_idle_cover_interval(
            rx,
            Duration::from_millis(20),
            Duration::from_millis(40),
        ));

        // While nothing else flows, the emitter must send a cover dummy. The
        // exit reads it as an ordinary forward frame; opened, it is a 0xFF
        // dummy a real exit drops (`is_daita_dummy`), NOT a real IP packet, and
        // NOT a fixed-size 5s beacon. Sealed by HPKE, so the relay only sees
        // ciphertext.
        let wire = tokio::time::timeout(RECV_TIMEOUT, pair.exit_conn.read_datagram())
            .await
            .expect("idle cover must emit a dummy within a few short intervals")
            .expect("datagram");
        let frame = warrenguard_multihop::decode_frame(&wire).expect("decode_frame");
        let plaintext = pair
            .exit_session
            .open(&frame)
            .expect("exit opens the sealed cover frame");
        assert!(
            warrenguard_pump::is_daita_dummy(&plaintext),
            "idle cover must seal a 0xFF-marked dummy the exit drops, not a real packet"
        );

        // Closing the watch (supervisor shutdown) must return the task cleanly.
        drop(tx);
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("cover task must return promptly when the watch closes")
            .expect("cover task must not panic");
        assert!(
            result.is_ok(),
            "a closed watch is a clean shutdown, not an error"
        );
    }

    #[tokio::test]
    async fn run_idle_cover_stays_silent_while_real_traffic_flows() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x32; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        // Simulate a steadily-used tunnel: the pumps advance the real-traffic
        // counters the emitter samples. It must then skip cover, exactly like
        // `note_activity` silences the mono-conn pump under load.
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle.clone()));
        let task = tokio::spawn(run_idle_cover_interval(
            rx,
            Duration::from_millis(20),
            Duration::from_millis(40),
        ));

        // Advance the real-uplink counter every 8ms (well under the 20ms min
        // interval) for the whole check window, so every jittered deadline sees
        // fresh activity. The bumper runs CONCURRENTLY with the exit read: cover
        // must stay silent throughout, not merely resume once traffic stops.
        let bumper_bundle = bundle.clone();
        let stop_bumping = Arc::new(tokio::sync::Notify::new());
        let stop2 = stop_bumping.clone();
        let bumper = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = stop2.notified() => break,
                    () = tokio::time::sleep(Duration::from_millis(8)) => {
                        bumper_bundle.note_real_uplink();
                    }
                }
            }
        });

        // No cover frame must reach the exit over a window spanning several max
        // intervals while traffic flows.
        let got =
            tokio::time::timeout(Duration::from_millis(200), pair.exit_conn.read_datagram()).await;
        assert!(
            got.is_err(),
            "cover must stay silent while the tunnel carries real traffic"
        );

        stop_bumping.notify_one();
        let _ = bumper.await;
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    // ------------------------------------------------------------------
    // run_downlink: control-message interception + watch-closed shutdown
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_downlink_intercepts_exit_draining_before_tun_forward() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x21; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle));
        let tun = warrenguard_transport_core::FakeTun::new();
        let draining = ExitDrainingChannel::new();
        let mut draining_rx = draining.subscribe();

        let task = tokio::spawn(run_downlink(rx, tun.clone(), Some(draining)));

        let control = encode_control(&WarrenControlMessage::ExitDraining {
            deadline_unix_secs: 1_800_000_000,
            reason_code: 7,
        })
        .expect("encode_control");
        exit_send_datagram(&pair, 0, control).await;

        let adv = tokio::time::timeout(RECV_TIMEOUT, draining_rx.changed())
            .await
            .expect("must not time out")
            .map(|()| *draining_rx.borrow_and_update())
            .expect("advisory published")
            .expect("Some advisory");
        assert_eq!(adv.deadline_unix_secs, 1_800_000_000);
        assert_eq!(adv.reason_code, 7);

        // The control frame must never be handed to the TUN: a raw 0xC0
        // plaintext is not a valid IP packet and the doc comment on
        // `run_downlink` is explicit that this would otherwise be written
        // as junk.
        tokio::time::sleep(ABSENCE_WINDOW).await;
        assert!(
            tun.take_outbound().is_empty(),
            "a control message must never be forwarded to the TUN"
        );

        // A normal packet sent right after must still flow to the TUN
        // (the interception must not wedge the loop).
        exit_send_datagram(&pair, 1, vec![0x45, 0, 0, 20, 1, 1, 1, 1]).await;
        let out = wait_for_outbound(&tun).await;
        assert_eq!(out, vec![vec![0x45, 0, 0, 20, 1, 1, 1, 1]]);

        // Clean, deterministic shutdown: dropping the sender resolves the
        // `rx.changed()` arm of the inner select with Err, unblocking the
        // task without relying on the QUIC connection's own teardown.
        drop(tx);
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("must shut down promptly once the watch closes")
            .expect("task must not panic");
        assert!(
            result.is_err(),
            "closing the watch mid-serve must surface as Err"
        );
    }

    #[tokio::test]
    async fn run_downlink_drops_daita_dummies_before_tun() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x22; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle.clone()));
        let tun = warrenguard_transport_core::FakeTun::new();

        let task = tokio::spawn(run_downlink(rx, tun.clone(), None));

        // An exit runs its DAITA machines whenever the operator arms them,
        // so a client on the PLAIN pump still receives 0xFF dummies. They
        // must be dropped here: written to the TUN the kernel rejects each
        // one ("IP version 15") and the tolerance path stalls the pump
        // 1 ms per dummy.
        exit_send_datagram(&pair, 0, vec![0xFF; 64]).await;
        tokio::time::sleep(ABSENCE_WINDOW).await;
        assert!(
            tun.take_outbound().is_empty(),
            "a DAITA dummy must never be forwarded to the TUN by the plain pump"
        );
        assert_eq!(
            bundle.real_traffic_totals().1,
            0,
            "a dummy must not count as real downlink for the liveness watches"
        );

        exit_send_datagram(&pair, 1, vec![0x45, 0, 0, 20, 3, 3, 3, 3]).await;
        let out = wait_for_outbound(&tun).await;
        assert_eq!(out, vec![vec![0x45, 0, 0, 20, 3, 3, 3, 3]]);
        assert_eq!(
            bundle.real_traffic_totals().1,
            1,
            "a forwarded IP packet must count as real downlink"
        );

        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn dead_datapath_escalation_judges_real_downlink_not_quinn_frames() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x24; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle.clone()));
        let tun = warrenguard_transport_core::FakeTun::new();
        let task = tokio::spawn(run_downlink(rx, tun.clone(), None));

        // The failure shape: a dead uplink under an armed exit still
        // RECEIVES dummies, so quinn's datagram counter climbs on a session
        // that carried zero real downlink. If the escalation judged that
        // counter it would reset on every close and the "datapath dead"
        // fatal could never fire.
        exit_send_datagram(&pair, 0, vec![0xFF; 64]).await;
        tokio::time::sleep(ABSENCE_WINDOW).await;
        let quinn_frames: u64 = bundle
            .clients()
            .iter()
            .map(|c| c.quinn_stats().frame_rx.datagram)
            .sum();
        assert!(
            quinn_frames > 0,
            "the dummy must be visible to quinn (that is the trap)"
        );
        assert_eq!(
            crate::supervisor::session_escalation_downlink(&bundle),
            0,
            "a dummy-only session must count as a zero-downlink dead window"
        );

        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    }

    #[tokio::test]
    async fn real_uplink_accounting_counts_sends_but_never_padding() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x23; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);

        bundle
            .send(&[0x45, 0, 0, 20, 1, 1, 1, 1])
            .await
            .expect("send");
        assert_eq!(bundle.real_traffic_totals().0, 1);

        // DAITA padding must stay invisible to the liveness accounting: an
        // idle DAITA session pads continuously and would otherwise look
        // like one-way app traffic, forcing spurious redials.
        bundle.send_daita_padding().await.expect("padding");
        assert_eq!(
            bundle.real_traffic_totals().0,
            1,
            "padding must not count as real uplink"
        );
    }

    #[tokio::test]
    async fn run_downlink_returns_err_once_watch_closes_while_reconnecting() {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let tun = warrenguard_transport_core::FakeTun::new();

        let task = tokio::spawn(run_downlink(rx, tun, None));

        // While mid-reconnect (None) the pump must park on the watch
        // channel rather than return - give it a moment to prove it has
        // not already exited on its own.
        tokio::time::sleep(ABSENCE_WINDOW).await;
        assert!(
            !task.is_finished(),
            "must park on the watch, not busy-return"
        );

        drop(tx);
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("must return promptly once the watch closes")
            .expect("task must not panic");
        assert!(
            result.is_err(),
            "a closed supervisor watch during a reconnect window must surface as Err"
        );
    }

    // ------------------------------------------------------------------
    // run_downlink_with_daita: dummy filter + control dispatch + shutdown
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_downlink_with_daita_filters_dummy_and_forwards_real_packet() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x31; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle));
        let tun = warrenguard_transport_core::FakeTun::new();
        let daita: DaitaShared = Arc::new(PlMutex::new(DaitaState::disabled()));
        let state_changed = Arc::new(tokio::sync::Notify::new());

        let task = tokio::spawn(run_downlink_with_daita(
            rx,
            tun.clone(),
            daita,
            state_changed,
            None,
            None,
        ));

        // A DAITA dummy (first byte 0xFF) must never reach the TUN: the
        // kernel would reject it as a malformed IP packet.
        exit_send_datagram(&pair, 0, vec![warrenguard_pump::DAITA_DUMMY_FIRST_BYTE; 32]).await;
        tokio::time::sleep(ABSENCE_WINDOW).await;
        assert!(
            tun.take_outbound().is_empty(),
            "a DAITA dummy must be dropped, not forwarded to the TUN"
        );

        // A real IP-shaped packet sent right after must flow through.
        exit_send_datagram(&pair, 1, vec![0x45, 0, 0, 20, 7, 7, 7, 7]).await;
        let out = wait_for_outbound(&tun).await;
        assert_eq!(out, vec![vec![0x45, 0, 0, 20, 7, 7, 7, 7]]);

        drop(tx);
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("must shut down promptly once the watch closes")
            .expect("task must not panic");
        assert!(
            result.is_err(),
            "closing the watch mid-serve must surface as Err"
        );
    }

    #[tokio::test]
    async fn run_downlink_with_daita_dispatches_ip_assign_and_never_forwards_it() {
        let pair = spawn_loopback_multihop(ExitId::from_bytes([0x32; 16])).await;
        let bundle = MultiHopBundle::new(vec![pair.client.clone()]);
        let (tx, rx) = tokio::sync::watch::channel(Some(bundle));
        let tun = warrenguard_transport_core::FakeTun::new();
        let daita: DaitaShared = Arc::new(PlMutex::new(DaitaState::disabled()));
        let state_changed = Arc::new(tokio::sync::Notify::new());
        let ip_assign = IpAssignChannel::new();
        let mut ip_assign_rx = ip_assign.subscribe();

        let task = tokio::spawn(run_downlink_with_daita(
            rx,
            tun.clone(),
            daita,
            state_changed,
            Some(ip_assign),
            None,
        ));

        let control = encode_control(&WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 9],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        })
        .expect("encode_control");
        exit_send_datagram(&pair, 0, control).await;

        let spec = tokio::time::timeout(RECV_TIMEOUT, ip_assign_rx.changed())
            .await
            .expect("must not time out")
            .map(|()| *ip_assign_rx.borrow_and_update())
            .expect("IpAssign published")
            .expect("Some spec");
        assert_eq!(spec.assigned, std::net::Ipv4Addr::new(10, 66, 0, 9));

        tokio::time::sleep(ABSENCE_WINDOW).await;
        assert!(
            tun.take_outbound().is_empty(),
            "an IpAssign control message must never be forwarded to the TUN"
        );

        drop(tx);
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("must shut down promptly once the watch closes")
            .expect("task must not panic");
        assert!(
            result.is_err(),
            "closing the watch mid-serve must surface as Err"
        );
    }

    #[tokio::test]
    async fn run_downlink_with_daita_returns_err_once_watch_closes_while_reconnecting() {
        let (tx, rx) = tokio::sync::watch::channel(None);
        let tun = warrenguard_transport_core::FakeTun::new();
        let daita: DaitaShared = Arc::new(PlMutex::new(DaitaState::disabled()));
        let state_changed = Arc::new(tokio::sync::Notify::new());

        let task = tokio::spawn(run_downlink_with_daita(
            rx,
            tun,
            daita,
            state_changed,
            None,
            None,
        ));

        tokio::time::sleep(ABSENCE_WINDOW).await;
        assert!(
            !task.is_finished(),
            "must park on the watch, not busy-return"
        );

        drop(tx);
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("must return promptly once the watch closes")
            .expect("task must not panic");
        assert!(
            result.is_err(),
            "a closed supervisor watch during a reconnect window must surface as Err"
        );
    }
}
