//! IPv4/IPv6 assignment channel and spec decoded from the exit's
//! `WarrenControlMessage::IpAssign` on the multi-hop downlink.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use warrenguard_multihop::WarrenControlMessage;

/// `tokio::sync::watch` channel the downlink pump
/// uses to publish each observed `IpAssign` control message to the
/// orchestrator. Cloneable: the downlink pump holds one handle (writer),
/// the orchestrator's reassign task holds a `Receiver` subscribed via
/// [`IpAssignChannel::subscribe`].
///
/// v1.1 design (vs the AE.3 v1 one-shot Notify):
///
/// - **Multi-update** : every fresh QUIC connection makes the exit emit
///   a new `IpAssign`. The downlink pump publishes each one onto the
///   channel ; the reassign task's `Receiver::changed()` loop wakes for
///   each and reassigns the TUN if the IPv4 changed.
/// - **Survives supervisor reconnects** : the reassign task never exits
///   on a single timeout, it keeps listening for the next IpAssign so a
///   slow first session (e.g. DAITA handshake) eventually triggers the
///   reassign once the supervisor's later attempt succeeds.
/// - **Backpressure-free** : watch channel collapses to "latest value
///   wins", so a burst of reconnects only triggers one reassign per
///   distinct IPv4 (changes are dedup'd by the reassign task's `current
///   != new` check, not by the channel).
#[derive(Clone)]
pub struct IpAssignChannel {
    sender: Arc<tokio::sync::watch::Sender<Option<IpAssignSpec>>>,
}

impl Default for IpAssignChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl IpAssignChannel {
    /// Construct an empty channel ready to be shared via `clone()`.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _initial_receiver) = tokio::sync::watch::channel(None);
        Self {
            sender: Arc::new(sender),
        }
    }

    /// Publish a fresh [`IpAssignSpec`] to every active subscriber. The
    /// watch channel keeps only the latest value, so a slow consumer
    /// always sees the most recent `IpAssign`.
    pub fn publish(&self, spec: IpAssignSpec) {
        let _ = self.sender.send_replace(Some(spec));
    }

    /// Subscribe to subsequent `IpAssign` publications. The returned
    /// receiver starts with the latest cached value (could be `None` if
    /// no publish happened yet); calling `borrow_and_update` on it
    /// before the first `changed().await` lets the caller pick up a
    /// spec already published before subscription.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<IpAssignSpec>> {
        self.sender.subscribe()
    }
}

/// IPv4 assignment received from the exit. Mirror of the exit-side
/// `IpAssignSpec` (private there). Copy + Eq so
/// the orchestrator can compare assignments across reconnects and
/// decide whether the TUN actually needs a reassign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAssignSpec {
    /// IPv4 address allocated by the exit.
    pub assigned: Ipv4Addr,
    /// Subnet prefix length.
    pub prefix_len: u8,
    /// Gateway IPv4 (exit-side TUN host).
    pub gateway: Ipv4Addr,
    /// The IPv6 the exit allocated, present only when it actually granted a
    /// dual-stack v6 (the `IpAssign.ipv6` field). `None` keeps the client
    /// IPv4-only (firewall keeps native v6 blocked, so no leak); its absence
    /// when the client requested v6 IS the capability gap the supervisor
    /// surfaces.
    pub assigned_v6: Option<Ipv6Addr>,
    /// IPv6 subnet prefix length (e.g. 64). Meaningful only when
    /// `assigned_v6` is `Some`.
    pub prefix_len_v6: u8,
    /// IPv6 gateway (`fdcc:f:1::1`), present iff `assigned_v6` is.
    pub gateway_v6: Option<Ipv6Addr>,
}

impl IpAssignSpec {
    /// Build from a [`WarrenControlMessage::IpAssign`]. Returns `None` for
    /// any other variant. The presence of `ipv6` is the exit's capability
    /// echo (v6 granted iff `assigned_v6.is_some()`).
    #[must_use]
    pub fn from_control(msg: &WarrenControlMessage) -> Option<Self> {
        match msg {
            WarrenControlMessage::IpAssign {
                ipv4,
                prefix_len,
                gateway_ipv4,
                ipv6,
                prefix_len_v6,
                gateway_ipv6,
            } => Some(Self {
                assigned: Ipv4Addr::from(*ipv4),
                prefix_len: *prefix_len,
                gateway: Ipv4Addr::from(*gateway_ipv4),
                assigned_v6: ipv6.map(Ipv6Addr::from),
                prefix_len_v6: *prefix_len_v6,
                gateway_v6: gateway_ipv6.map(Ipv6Addr::from),
            }),
            _ => None,
        }
    }
}
