//! Multi-conn QUIC on the client side: N parallel Quinn connections to
//! the same exit, signed by the **same** Ed25519 identity (so the same
//! `WarrenPubkey` as seen by the exit). The exit aggregates these N
//! conns under a single session (cf. `ExitListener` server-side).
//!
//! **Perf rationale**: the Warren tunnel bottleneck is not the pump CPU
//! but the internal serialization of a `quinn::Connection` (per-Connection
//! Quinn mutex). Distributing packets over N Connections gives N distinct
//! mutexes, exploitable by the multi-threaded tokio scheduler on N cores.
//!
//! **Dispatch**: sticky 5-tuple hash for TCP/UDP, atomic round-robin
//! fallback (ICMP, ARP, malformed packet). Packets from the same TCP flow
//! stay on the same `Connection` -> BBR cwnd converges per-flow rather
//! than mixing on cross-conn reorder.
//!
//! **Hash function**: FNV-1a 64-bit (deterministic, simple, sufficient
//! to distribute N flows across N conns). Not SipHash because we don't
//! need adversarial collision resistance, a malicious client could at
//! worst steer one of their flows onto the same conn as their other
//! flows, which only degrades their own performance.
//!
//! **API**: symmetric to [`ClientSession`] but over N conns. See
//! [`warrenguard_pump::pump_multi_bidirectional`] for the TUN <-> N datagrams pump.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use quinn::{Connection, Endpoint};

use warrenguard_transport_core::error::{Result, TunnelError};
use warrenguard_transport_core::flow_hash::flow_hash_5tuple;

/// Multi-connection client session. Aggregates N active Quinn
/// `Connection`s to a single exit + their shared configuration (IP, MTU).
pub struct MultiSession {
    /// Underlying Quinn endpoints (one UDP socket each). Kept alive for the
    /// session duration: drop = all connections die in cascade. Length 1 is
    /// the historic single-socket session; length N spreads the connections
    /// across N endpoint drivers so the client datapath I/O is not serialized
    /// through one socket. Every connection references whichever endpoint it
    /// was dialed on.
    _endpoints: Vec<Endpoint>,
    /// The N active connections. All are dialed by the same client
    /// identity. Ordered by protocol `connection_index` (0 = primary).
    conns: Arc<Vec<Connection>>,
    /// Atomic counter for [`Self::send_datagram`]'s round-robin fallback.
    round_robin: AtomicUsize,
    /// Tunnel IPv4 assigned by the exit in the primary's SetupAck.
    /// All connections of this session share the same exit-side IP
    /// (per-Ed25519-identity aggregation).
    assigned_ipv4: std::net::Ipv4Addr,
    /// Optional tunnel IPv6, shared by the N conns.
    assigned_ipv6: Option<std::net::Ipv6Addr>,
    /// Negotiated MTU, identical for the N conns of the session.
    assigned_max_mtu: u16,
    /// DAITA spec from the primary's SetupAck, shared across
    /// every conn of the session (the exit guarantees the secondaries'
    /// SetupAck carries the same spec via the multi-conn sharing in
    /// the exit session attribution). `None` when DAITA was not
    /// negotiated (client opt-out or exit pool unset).
    daita_spec: Option<warrenguard_wire::DaitaConfig>,
}

/// Pure dispatch decision shared by [`MultiSession::dispatch_idx`] and
/// unit-tested directly (no live `Connection` needed): sticky 5-tuple hash
/// for TCP/UDP, atomic round-robin fallback otherwise. Extracted so the
/// sticky-vs-round-robin branch and the modulo-by-width logic are testable
/// in isolation from the QUIC session construction.
fn dispatch_idx_pure(n: usize, pkt: &[u8], round_robin: &AtomicUsize) -> usize {
    match flow_hash_5tuple(pkt) {
        Some(h) => (h as usize) % n,
        None => round_robin.fetch_add(1, Ordering::Relaxed) % n,
    }
}

impl MultiSession {
    /// Build a `MultiSession` from components already resolved by
    /// [`crate::ClientTunnel::connect_multi`]. Not exposed publicly:
    /// only created by `ClientTunnel`.
    pub(crate) fn new(
        endpoints: Vec<Endpoint>,
        conns: Vec<Connection>,
        assigned_ipv4: std::net::Ipv4Addr,
        assigned_ipv6: Option<std::net::Ipv6Addr>,
        assigned_max_mtu: u16,
        daita_spec: Option<warrenguard_wire::DaitaConfig>,
    ) -> Result<Self> {
        if conns.is_empty() {
            return Err(TunnelError::MultiSessionEmpty(
                "MultiSession needs at least one Connection",
            ));
        }
        if endpoints.is_empty() {
            return Err(TunnelError::MultiSessionEmpty(
                "MultiSession needs at least one Endpoint",
            ));
        }
        Ok(Self {
            _endpoints: endpoints,
            conns: Arc::new(conns),
            round_robin: AtomicUsize::new(0),
            assigned_ipv4,
            assigned_ipv6,
            assigned_max_mtu,
            daita_spec,
        })
    }

    /// Number of active connections in this session.
    #[must_use]
    pub fn num_connections(&self) -> usize {
        self.conns.len()
    }

    /// Number of distinct client datapath endpoints (UDP sockets) this session
    /// spreads its connections across. `1` for a single-socket session; up to
    /// `num_connections()` when fully sharded. See
    /// `WARREN_CLIENT_DATAPATH_SOCKETS`.
    #[must_use]
    pub fn datapath_endpoint_count(&self) -> usize {
        self._endpoints.len()
    }

    /// Local `SocketAddr` of every client datapath endpoint. With sharding each
    /// is a distinct ephemeral port, which is what lets the exit's reuseport
    /// group hash the connections across cores. For observability/tests.
    #[must_use]
    pub fn local_socket_addrs(&self) -> Vec<std::net::SocketAddr> {
        self._endpoints
            .iter()
            .filter_map(|e| e.local_addr().ok())
            .collect()
    }

    /// Tunnel IPv4 assigned by the exit (shared across the N conns).
    #[must_use]
    pub fn assigned_ipv4(&self) -> std::net::Ipv4Addr {
        self.assigned_ipv4
    }

    /// Optional tunnel IPv6 (shared across the N conns).
    #[must_use]
    pub fn assigned_ipv6(&self) -> Option<std::net::Ipv6Addr> {
        self.assigned_ipv6
    }

    /// MTU negotiated by the exit (shared across the N conns).
    #[must_use]
    pub fn assigned_max_mtu(&self) -> u16 {
        self.assigned_max_mtu
    }

    /// DAITA spec negotiated with the exit during the primary's
    /// handshake. Shared across the N conns by exit-side aggregation.
    /// Returns `None` when DAITA was not negotiated.
    #[must_use]
    pub fn daita_spec(&self) -> Option<&warrenguard_wire::DaitaConfig> {
        self.daita_spec.as_ref()
    }

    /// Returns a copy of the N `Connection`s (cheap Arc-clone) - useful
    /// for pumps spawning N tasks.
    #[must_use]
    pub fn clone_connections(&self) -> Vec<Connection> {
        (*self.conns).clone()
    }

    /// Selects the target `Connection` for this IP packet.
    ///
    /// Strategy:
    /// 1. If the packet is IPv4/v6 + TCP/UDP, hash the 5-tuple
    ///    (proto, src/dst IP, src/dst port) with FNV-1a -> sticky idx.
    /// 2. Otherwise (ICMP, ARP, truncated packet), atomic round-robin
    ///    fallback for load balancing.
    ///
    /// The sticky hash guarantees packets of the same TCP flow land on
    /// the same Quinn `Connection` -> BBR cwnd consistent per-flow.
    ///
    /// `pub(crate)` so [`warrenguard_pump::pump_multi_bidirectional`] can dispatch
    /// in the parallel variant where the dispatcher task pushes onto N
    /// per-conn channels.
    pub(crate) fn dispatch_idx(&self, pkt: &[u8]) -> usize {
        dispatch_idx_pure(self.conns.len(), pkt, &self.round_robin)
    }

    /// Send a QUIC datagram, selecting the `Connection` via sticky
    /// 5-tuple hash (TCP/UDP) or round-robin (other protocols).
    ///
    /// # Errors
    ///
    /// Datagram too large for the path MTU, or the selected connection
    /// is closed.
    pub fn send_datagram(&self, payload: Vec<u8>) -> Result<()> {
        let idx = self.dispatch_idx(&payload);
        self.conns[idx]
            .send_datagram(Bytes::from(payload))
            .map_err(|source| TunnelError::QuicSendDatagram {
                context: format!("conn[{idx}]").into(),
                source,
            })
    }

    /// Zero-copy variant of [`Self::send_datagram`]: dispatches on the borrowed
    /// payload, then forwards the `Bytes` handle unchanged so a pooled buffer
    /// recycles on drop.
    ///
    /// # Errors
    /// Datagram too large for the path MTU, or the selected connection closed.
    pub fn send_datagram_bytes(&self, payload: Bytes) -> Result<()> {
        let idx = self.dispatch_idx(&payload);
        self.conns[idx]
            .send_datagram(payload)
            .map_err(|source| TunnelError::QuicSendDatagram {
                context: format!("conn[{idx}]").into(),
                source,
            })
    }
}

impl warrenguard_pump::MultiConnSession for MultiSession {
    fn clone_connections(&self) -> Vec<Connection> {
        self.clone_connections()
    }

    fn send_datagram(&self, payload: Vec<u8>) -> Result<()> {
        self.send_datagram(payload)
    }

    fn send_datagram_bytes(&self, payload: Bytes) -> Result<()> {
        self.send_datagram_bytes(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesize a minimal IPv4/TCP-or-UDP packet, mirroring
    /// `warrenguard_transport_core::flow_hash`'s own test helper (kept in
    /// sync manually; the two modules must not import from each other).
    fn make_ipv4_tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version 4 + IHL 5
        pkt[9] = 6; // proto TCP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    /// A packet `flow_hash_5tuple` cannot key (proto = ICMP): forces the
    /// round-robin fallback branch of `dispatch_idx_pure`.
    fn make_icmp_packet() -> Vec<u8> {
        let mut pkt = make_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
        pkt[9] = 1; // proto ICMP
        pkt
    }

    #[test]
    fn dispatch_idx_pure_is_sticky_for_the_same_tcp_flow() {
        let rr = AtomicUsize::new(0);
        let pkt = make_ipv4_tcp([10, 0, 0, 1], [192, 168, 1, 1], 1234, 80);
        let first = dispatch_idx_pure(4, &pkt, &rr);
        let second = dispatch_idx_pure(4, &pkt, &rr);
        assert_eq!(
            first, second,
            "the same 5-tuple must always dispatch to the same index"
        );
        assert!(first < 4, "index must be within [0, n)");
        // Stickiness must not consume the round-robin counter (only the
        // non-hashable fallback path does).
        assert_eq!(rr.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dispatch_idx_pure_round_robins_for_non_tcp_udp_packets() {
        let rr = AtomicUsize::new(0);
        let pkt = make_icmp_packet();
        let indices: Vec<usize> = (0..5).map(|_| dispatch_idx_pure(3, &pkt, &rr)).collect();
        assert_eq!(
            indices,
            vec![0, 1, 2, 0, 1],
            "a non-TCP/UDP packet must round-robin across the N connections"
        );
    }

    #[test]
    fn new_rejects_an_empty_connection_list() {
        // No live Endpoint/Connection needed: the empty-conns check runs
        // before either vec is touched.
        let result = MultiSession::new(
            vec![],
            vec![],
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            None,
            1280,
            None,
        );
        match result {
            Err(err) => assert!(
                matches!(err, TunnelError::MultiSessionEmpty(_)),
                "expected MultiSessionEmpty, got {err:?}"
            ),
            Ok(_) => panic!("an empty conns list must be rejected"),
        }
    }

    #[tokio::test]
    async fn new_rejects_an_empty_endpoint_list_even_with_a_live_connection() {
        let pair = crate::test_support::spawn_loopback_conn_pair().await;
        let result = MultiSession::new(
            vec![],
            vec![pair.client_conn],
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            None,
            1280,
            None,
        );
        match result {
            Err(err) => assert!(
                matches!(err, TunnelError::MultiSessionEmpty(_)),
                "expected MultiSessionEmpty, got {err:?}"
            ),
            Ok(_) => panic!("an empty endpoints list must be rejected"),
        }
    }

    #[tokio::test]
    async fn send_datagram_after_close_surfaces_a_quic_send_datagram_error() {
        let pair = crate::test_support::spawn_loopback_conn_pair().await;
        pair.client_conn
            .close(quinn::VarInt::from_u32(0), b"closing for the test");
        // Give the close a moment to actually land on the connection state
        // before the send is attempted. Also confirms the peer (server)
        // side observes the same close, not just the local handle.
        tokio::time::timeout(std::time::Duration::from_secs(2), pair.client_conn.closed())
            .await
            .expect("close must be observed promptly on the local handle");
        tokio::time::timeout(std::time::Duration::from_secs(2), pair.server_conn.closed())
            .await
            .expect("the peer must observe the close too");

        let session = MultiSession::new(
            vec![pair.client_ep],
            vec![pair.client_conn],
            std::net::Ipv4Addr::new(10, 0, 0, 2),
            None,
            1280,
            None,
        )
        .expect("a single closed connection is still non-empty");

        let err = session
            .send_datagram(vec![0x45, 0, 0, 20])
            .expect_err("sending on a closed connection must fail");
        assert!(
            matches!(err, TunnelError::QuicSendDatagram { .. }),
            "expected QuicSendDatagram, got {err:?}"
        );
    }
}
