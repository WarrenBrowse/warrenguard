//! Local network-path change detection: the single home of the "the host moved
//! to another network" signal (Wi-Fi to Ethernet handover, DHCP renumbering,
//! tethering flips).
//!
//! A tunnel session survives such a move only by redialing from the new local
//! address; without a watcher the loss is discovered indirectly (idle timeout,
//! dead-path escalation), minutes after the user already has a working new
//! network. This module detects the move cheaply and portably: it polls the
//! kernel's own routing decision (the local source address a fresh socket
//! toward the exit would bind to) and reports when that decision changes to a
//! live path. The reaction is the consumer's redial machinery (the supervisor's
//! forced reconnect, the proxy supervisor's epoch end); this module never
//! touches a socket that carries traffic.
//!
//! No packet is ever sent: a `connect()` on an unconnected UDP socket only
//! runs the kernel route lookup, so polling is side-effect free and needs no
//! privileges.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// How often the preferred-path probe polls. A handover therefore heals within
/// about this interval plus one redial, matching the production app's watcher
/// reaction time, while an idle poll is a single route lookup (no I/O).
pub const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Default probe destination when the consumer has no better anchor (the relay
/// address it dials is better when at hand). Only the kernel route lookup uses
/// it; no packet is ever sent to this address. Any stable global unicast
/// address selects the same default route.
pub const PROBE_ANCHOR: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// A detected move of the preferred local path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathChange {
    /// The preferred local source before the move (`None` = the host had no
    /// route, so this change is a connectivity recovery).
    pub previous: Option<IpAddr>,
    /// The live local source address the kernel now prefers.
    pub current: IpAddr,
}

/// The local source address the kernel would use right now for a fresh socket
/// toward `dest`, or `None` when no route exists (host offline). This is the
/// kernel's own routing decision, not an interface enumeration, so it is what
/// a redial would actually bind.
#[must_use]
pub fn preferred_source_ip(dest: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if dest.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind).ok()?;
    // The port is irrelevant: connect() on UDP is a local route lookup, no
    // packet leaves the host.
    socket.connect(SocketAddr::new(dest, 443)).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// Polls `probe` every `interval` and resolves on the first change of the
/// preferred path TO a live one: a different source address, or a route
/// appearing after none. Losing the route entirely does not resolve (there is
/// nothing to redial onto; session death is the dead-path watchers' job), but
/// it is remembered so the later recovery fires even onto the same address.
pub async fn wait_for_path_change(
    mut probe: impl FnMut() -> Option<IpAddr>,
    interval: Duration,
) -> PathChange {
    let mut last = probe();
    loop {
        tokio::time::sleep(interval).await;
        let now = probe();
        match now {
            Some(current) if last != Some(current) => {
                return PathChange {
                    previous: last,
                    current,
                };
            }
            _ => last = now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    const A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const B: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

    /// A probe that replays a fixed sequence, then repeats its last value.
    fn scripted(seq: Vec<Option<IpAddr>>) -> impl FnMut() -> Option<IpAddr> {
        let mut i = 0;
        move || {
            let v = seq[i.min(seq.len() - 1)];
            i += 1;
            v
        }
    }

    #[test]
    fn preferred_source_for_loopback_is_loopback() {
        // The kernel routes loopback destinations through the loopback
        // interface on every OS, so this pins the probe's mechanics without
        // depending on the machine's real interfaces.
        let source = preferred_source_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            source,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "a loopback destination must select the loopback source"
        );
    }

    /// Bounds a watcher future so a regression that stops firing FAILS the
    /// test instead of wedging it (paused time turns an unresolved watcher
    /// into a busy loop).
    async fn expect_fires(fut: impl Future<Output = PathChange>) -> PathChange {
        tokio::time::timeout(Duration::from_secs(600), fut)
            .await
            .expect("the watcher must fire for this sequence")
    }

    #[tokio::test(start_paused = true)]
    async fn fires_when_the_preferred_source_moves() {
        let change = expect_fires(wait_for_path_change(
            scripted(vec![Some(A), Some(A), Some(B)]),
            POLL_INTERVAL,
        ))
        .await;
        assert_eq!(
            change,
            PathChange {
                previous: Some(A),
                current: B,
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_after_loss_fires_even_onto_the_same_address() {
        let change = expect_fires(wait_for_path_change(
            scripted(vec![Some(A), None, None, Some(A)]),
            POLL_INTERVAL,
        ))
        .await;
        assert_eq!(
            change,
            PathChange {
                previous: None,
                current: A,
            },
            "a route reappearing is a migration trigger: the redial backoff may \
             otherwise sleep through the recovery"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn loss_alone_or_a_steady_path_never_fires() {
        for seq in [vec![Some(A)], vec![Some(A), None]] {
            let waited = tokio::time::timeout(
                Duration::from_secs(600),
                wait_for_path_change(scripted(seq), POLL_INTERVAL),
            )
            .await;
            assert!(
                waited.is_err(),
                "no live new path means nothing to migrate to, so no event"
            );
        }
    }
}
