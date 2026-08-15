//! Shared data-plane primitives for the WarrenGuard tunnel, consumed by both
//! the client transport and the server: the error type, the `/v1` protocol
//! close codes, the [`PacketDevice`] trait, the datagram buffer pool, the QUIC
//! transport-config tuning (which carries the quinn-fork knobs), the
//! per-connection metrics, the path probe and the 5-tuple flow hash.

pub mod buffer_pool;
pub mod client_metrics;
pub mod constants;
pub mod error;
pub mod flow_hash;
pub mod icmp_probe;
pub mod inner_mtu;
pub mod ip_parse;
pub mod packet_device;
pub mod path_probe;
pub mod transport_config;

pub use client_metrics::{ClientMetrics, ClientMetricsSnapshot, MetricsRegistry};
pub use error::{Result, TunnelError};
pub use flow_hash::flow_hash_5tuple;
pub use inner_mtu::{
    CARRIER_MAX_INNER_MTU, PROXY_BUDGET_MARGIN, QUIC_SAFE_INNER_MTU, build_frag_needed,
    carrier_capped_inner_mtu, clamp_downlink_syn, clamp_syn_mss, clamp_uplink_syn, effective_mss,
    icmpv6_pseudo_sum, incremental_checksum_update, internet_checksum, is_tcp_syn,
    uplink_frag_needed,
};
pub use ip_parse::{
    SpoofRefusal, classify_source, extract_dst_ipv4, extract_dst_ipv6, extract_src_ipv4,
    extract_src_ipv6, source_ip_matches,
};
pub use packet_device::{FakeTun, PacketDevice};
pub use path_probe::{PATH_PROBE_INTERVAL, PathProbeDelta, spawn_path_probe};
pub use transport_config::{
    warren_transport_config_client, warren_transport_config_client_full,
    warren_transport_config_client_multihop_with_gso,
    warren_transport_config_client_multihop_with_idle_cover,
    warren_transport_config_client_with_gso, warren_transport_config_client_with_idle_cover,
    warren_transport_config_exit, warren_transport_config_exit_full,
    warren_transport_config_exit_multihop_with_gso, warren_transport_config_exit_with_gso,
    warren_transport_config_relay_inbound, warren_transport_config_relay_inbound_multihop_with_gso,
    warren_transport_config_relay_inbound_with_gso, warren_transport_config_relay_outbound,
    warren_transport_config_relay_outbound_multihop_with_gso,
    warren_transport_config_relay_outbound_with_gso,
};
pub use warrenguard_wire::{FatalCause, Retryability};
