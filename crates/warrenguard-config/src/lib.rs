//! Generic VPN-over-QUIC constants for the WarrenGuard engine: ALPN, HKDF
//! contexts, tunnel MTU and IP-pool sizing, NAT-PMP and QUIC tuning, plus the
//! env-knob registry. Carries no Warren-product specifics (domain, API URL,
//! pinned keys, policy) - those live in the deployer's own configuration.
//!
//! Anything fixed by the design docs that should only change with an explicit
//! version bump (`/v1` to `/v2`) belongs here.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

pub mod knobs;

/// ALPN negotiated by Warren clients.
///
/// `h3` is the IETF HTTP/3 identifier (RFC 9114). Emitting it on the
/// wire makes a Warren handshake indistinguishable from a casual
/// HTTP/3 dial at the ALPN layer (one of the wire-fingerprint
/// invariants).
///
/// The byte value is fixed by the IETF; mutating it breaks the
/// mimicry guarantee. Routing between exit and (future) relay
/// hops is carried by an opaque type byte in the first applicative
/// DATAGRAM, never via a Warren-specific ALPN.
pub const ALPN_H3: &[u8] = b"h3";

/// HKDF salt for deriving the Warren key from the BIP39 seed.
///
/// **Never modify without bumping the version.** Any mutation breaks
/// derivation of every existing identity.
pub const HKDF_SALT_IDENTITY_V1: &[u8] = b"warren/identity/v1";

/// HKDF info for the Warren tunnel key.
pub const HKDF_INFO_NODEKEY: &[u8] = b"vpn-node-key";

/// Initial UDP payload size targeted by every Warren Quinn endpoint
/// (`TransportConfig::initial_mtu`).
///
/// **1280, not 1350**: a 1350 value
/// derives from `1500 - 50 B QUIC/AEAD overhead`, which is fine on the
/// open Internet but trips a PMTU black-hole on a cross-DC cloud
/// backbone between two datacenters when the obfuscation pad layout
/// (`initial_datagram_min_size = 1500`) forces the ServerHello-bearing
/// Initial datagram above the path-MTU floor. The blackhole manifests
/// as a stalled multi-hop handshake even though the ClientHello
/// arrives intact. RFC 9000
/// guarantees 1200 B end-to-end and most backbones tolerate 1280 B
/// without fragmentation. DPLPMTUD probes upward from 1280 once the
/// handshake is established, so steady-state throughput is unchanged.
pub const TUNNEL_INITIAL_MTU: u16 = 1280;

/// Minimum MTU (DPLPMTUD will not go below this).
pub const TUNNEL_MIN_MTU: u16 = 1200;

/// Minimum size every padded QUIC Initial datagram is inflated to
/// (`initial_datagram_min_size`). 1200 fits nested/reduced-MTU paths where 1280
/// black-holes, is the RFC 9000 floor every major stack pads to, and matches
/// current browser Initials, so it is mimicry-neutral. Kept distinct from
/// [`TUNNEL_INITIAL_MTU`] (the DPLPMTUD start MTU): the pad must never exceed the
/// Initial MTU, and coupling the two is exactly the drift this constant removes.
pub const PADDED_INITIAL_MIN_SIZE: u16 = 1200;

/// IPv4 address of the TUN gateway on the exit side.
///
/// This is the IP the client uses as a "virtual router" behind the
/// tunnel: the NAT-PMP daemon on the exit listens on this address, and
/// the warren-natpmp-client uses it as the destination of its raw
/// RFC 6886 UDP requests.
pub const TUNNEL_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

/// Network address of the tunnel IP pool.
pub const TUNNEL_POOL_NETWORK: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 0);

/// CIDR prefix of the pool.
pub const TUNNEL_POOL_PREFIX: u8 = 16;

/// Textual CIDR representation of the pool (for logs / nftables).
pub const TUNNEL_POOL_CIDR: &str = "10.66.0.0/16";

// --- IPv6 dual-stack ---
//
// ULA pool RFC 4193 `fdcc:f:1::/64` chosen for:
// - `fd00::/8` = randomly-assigned ULA, not routable on the Internet
// - `fdcc:f:1::` visually mirrors `10.66.0.0/16` IPv4 (cc/f → 0xcc → "warren-decimal")
// - `/64` standard IPv6 subnet
//
// The IPv6 exit gateway is `fdcc:f:1::1`. Clients receive `fdcc:f:1::2`,
// `::3`, etc. through the same allocator sequence as v4. NAT v6 on the
// exit uses `nftables ip6 nat masquerade` (the v6 equivalent of
// MASQUERADE) to route v6 traffic to the public Internet via the
// cloud exit host's IPv6.

/// Tunnel pool IPv6 gateway.
pub const TUNNEL_GATEWAY_IPV6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 1);

/// Tunnel pool IPv6 network address.
pub const TUNNEL_POOL_NETWORK_V6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 0);

/// IPv6 pool CIDR prefix (/64 standard).
pub const TUNNEL_POOL_PREFIX_V6: u8 = 64;

/// Textual IPv6 CIDR representation (for logs / nftables ip6).
pub const TUNNEL_POOL_CIDR_V6: &str = "fdcc:f:1::/64";

/// Lower bound of the external port range allocated by
/// `warren-natpmp-server`. Matches IANA's standard ephemeral range.
pub const NATPMP_EXTERNAL_PORT_MIN: u16 = 49152;

/// Upper bound of the external port range allocated by
/// `warren-natpmp-server`.
pub const NATPMP_EXTERNAL_PORT_MAX: u16 = 65535;

/// Fleet-wide UDP port for the EdgeConnect browser tier, so a client reaches
/// every edge without per-node config. This is a frozen deployer contract, not
/// something this crate binds itself: no in-repo code opens a listener on it
/// (the edge-server crate's bind functions take a caller-supplied address), so
/// both a deployer's edge binary and its client/SDK are expected to use this
/// constant verbatim as the default bind/dial target. Changing it is a
/// wire-incompatible break across every already-deployed edge and client.
/// MUST stay below [`NATPMP_EXTERNAL_PORT_MIN`] (asserted at compile time
/// below): a port in the NAT-PMP range could collide with a user's forwarded
/// port on the same exit.
pub const WARREN_EDGE_PORT: u16 = 8443;

// Compile-time invariant guards: the EdgeConnect port must never fall in
// NAT-PMP's user port-forward range (else a user's forwarded port could
// collide with the edge listener on the same exit), and must not clash with
// the `:443` cover / `:53` DNS ports. Module scope (not inside a `#[test]`
// body) so the guarantee holds at compile time for every build, not only
// when the test happens to run.
const _: () = assert!(WARREN_EDGE_PORT < NATPMP_EXTERNAL_PORT_MIN);
const _: () = assert!(WARREN_EDGE_PORT != 443);
const _: () = assert!(WARREN_EDGE_PORT != 53);
const _: () = assert!(WARREN_EDGE_PORT != 0);

/// Cooldown before a freed port can be reused.
pub const NATPMP_PORT_COOLDOWN_SECS: u64 = 300;

/// Maximum NAT-PMP allocation lifetime (1 hour, RFC 6886).
pub const NATPMP_LIFETIME_MAX_SECS: u32 = 3600;

/// Minimum NAT-PMP allocation lifetime (RFC 6886 §3.3).
pub const NATPMP_LIFETIME_MIN_SECS: u32 = 60;

/// Maximum number of concurrent NAT-PMP port-forward allocations
/// per client tunnel IP. With the current tunnel model (one IPv4
/// assigned per pubkey for the lifetime of the session), this caps
/// the per-pubkey port-forward budget at the same value.
///
/// Set to 5 to support the multi-port use case (a torrent client with
/// its web UI, a game server with a query port, several self-hosted
/// services at once) while keeping abuse bounded: the external-port
/// pool is 16384 wide (`NATPMP_EXTERNAL_PORT_MIN..=MAX`), so even at
/// this quota a single exit serves ~3200 clients before pool pressure,
/// and a malicious client can never hold more than 5. If/when a paid
/// quota tier is wired through the subscription gate, make this
/// per-tier; until then 5 is the flat ceiling for everyone.
pub const NATPMP_QUOTA_PER_CLIENT_IP: usize = 5;

/// Maximum number of NEW NAT-PMP allocations (or port changes) a single
/// source may make per [`NATPMP_RATE_LIMIT_WINDOW_SECS`] sliding window.
/// Must be `>= NATPMP_QUOTA_PER_CLIENT_IP` so a client can stand up its
/// full set of forwards in one burst without rate-limiting itself; the
/// surplus is churn headroom. Refreshes/renewals of an EXISTING mapping
/// do NOT count against this (see the allocator), so holding N ports
/// alive is free regardless of lifetime.
pub const NATPMP_RATE_LIMIT_MAX_PER_WINDOW: usize = 12;

/// Sliding-window length (seconds) for [`NATPMP_RATE_LIMIT_MAX_PER_WINDOW`].
pub const NATPMP_RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Hard upper bound on the time the exit-side handshake (accept the
/// connection, then the sealed setup round-trip over the reliable
/// stream) may take, per accept iteration. Without this cap, a
/// slow-loris client that completes the QUIC handshake but never sends
/// its setup request would hold a tokio task alive until Quinn's own
/// idle timeout (multiple minutes). Honest clients complete a Warren
/// handshake in single-digit milliseconds even across continents, so
/// 30 s is a generous ceiling.
pub const WARREN_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Current Unix epoch seconds, saturating to 0 on a misconfigured
/// system clock (pre-epoch). Centralised so every Warren crate uses
/// the same clock semantics - preventing the kind of subtle drift a
/// mix of `i64`/`u64`/`as_secs()` patterns can introduce.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Same as [`unix_now`] but returns `i64` for callers that persist
/// timestamps as signed integers (a common constraint of SQL `INTEGER`
/// columns and several JSON schemas). Saturates at `i64::MAX` if the
/// system clock somehow reports a timestamp past year 292_277_026_596
/// (impossible in practice).
#[must_use]
pub fn unix_now_i64() -> i64 {
    i64::try_from(unix_now()).unwrap_or(i64::MAX)
}

// ---- No-log helpers --------------------------------------------------

/// Number of characters retained when truncating an identifier for
/// logs. 8 chars is enough to grep for a specific event across a
/// journal but far short of being reversible into the full identifier.
///
/// For an SS58-style base58 pubkey the first 8 chars (address prefix
/// plus a few discriminating base58 chars) disambiguate without
/// revealing the underlying key - the checksum and the remaining
/// payload stay hidden, so the full 32 raw bytes cannot be
/// reconstructed. For an opaque single-use token the space is also
/// orders of magnitude larger than 2^32. (Deployments that prefer a
/// head+tail `xx…yy` form for pubkeys can layer their own helper; this
/// generic one stays dependency-free for non-pubkey ids.)
pub const LOG_PREFIX_LEN: usize = 8;

/// Truncate `s` to the first [`LOG_PREFIX_LEN`] characters. If the
/// input is shorter, it is returned unchanged. The result is a
/// borrow, so no allocation happens on the hot path.
///
/// Use this on every `tracing::*` site that would otherwise
/// interpolate a pubkey, a single-use token, or any identifier that
/// would let a journal reader bypass the no-log contract:
/// - re-correlate users by pubkey (privacy violation),
/// - steal a single-use payment or provisioning token from the
///   journal and redeem it against the deployer's backend while it
///   is still valid (financial fraud).
#[must_use]
pub fn log_prefix(s: &str) -> &str {
    // `s.get(..n)` returns None if `n` falls mid codepoint. Callers
    // pass hex / ASCII opaque ids in practice, so this is byte
    // equivalent, but the safe API protects against future callers
    // that pass UTF-8.
    s.get(..LOG_PREFIX_LEN).unwrap_or(s)
}

/// Errors returned by [`parse_loopback_bind`]. Callers can match on
/// the variant to distinguish a syntactically invalid bind (always a
/// bug) from a non-loopback bind (potentially a deliberate ops choice
/// behind an opt-in flag).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoopbackBindError {
    /// The bind string did not parse as a `SocketAddr`.
    #[error("invalid bind address {0:?}: {1}")]
    Parse(String, std::net::AddrParseError),
    /// The bind parsed but resolved to a non-loopback IP.
    #[error("bind must be a loopback address (got {0}); Caddy is the only public surface")]
    NotLoopback(String),
}

/// Parse `bind` as a `SocketAddr` and require its IP to be loopback.
///
/// A reusable guard for any deployer binary that exposes a local-only
/// endpoint (metrics, admin, a debug socket) behind its own reverse proxy:
/// it defends against misconfigurations like `bind = "0.0.0.0:8080"` that
/// would expose that endpoint directly to the Internet.
///
/// # Errors
///
/// - [`LoopbackBindError::Parse`] if `bind` does not parse as a
///   `SocketAddr`.
/// - [`LoopbackBindError::NotLoopback`] if the resolved IP is not
///   loopback.
pub fn parse_loopback_bind(bind: &str) -> Result<SocketAddr, LoopbackBindError> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| LoopbackBindError::Parse(bind.to_owned(), e))?;
    if !addr.ip().is_loopback() {
        return Err(LoopbackBindError::NotLoopback(bind.to_owned()));
    }
    Ok(addr)
}

// ---------------------------------------------------------------------------
// Quinn `TransportConfig` tuning.
//
// All values are calibrated for a consumer fibre VPN use case at
// 1 Gbps with 30-80 ms RTT typical (FR ↔ NL/RO/SE). On a faster fibre
// or higher RTT, scale `QUIC_STREAM_RECV_WINDOW` proportionally.
// ---------------------------------------------------------------------------

/// Per-stream QUIC receive window, in bytes. Sized for the
/// bandwidth × delay product: 1 Gbps × 50 ms ≈ 6.25 MB.
///
/// Too small → throughput limited by the window.
/// Too large → excessive RAM consumption on the receiver.
pub const QUIC_STREAM_RECV_WINDOW: u32 = 6_250_000;

/// Global receive window (= upper bound on the sum of
/// stream_recv_window). On the Warren client side we open ~5 streams
/// (control + RPC), hence 5×.
pub const QUIC_RECV_WINDOW: u32 = 5 * QUIC_STREAM_RECV_WINDOW;

/// Send window (max unacknowledged volume). Must be ≥ `QUIC_RECV_WINDOW`
/// otherwise the sender is bottlenecked before the receiver.
pub const QUIC_SEND_WINDOW: u64 = QUIC_RECV_WINDOW as u64;

/// Datagram **receive** buffer (bytes). Application datagrams that the
/// peer sent but the local application has not consumed yet are held
/// here; if the buffer fills, the oldest datagrams are dropped. Quinn's
/// default is `1.25 MB` (= the default `STREAM_RWND` derived from a
/// hardcoded `12.5 Mbps × 100 ms` assumption) which is dramatically
/// under-sized for the Warren target of 1+ Gbps.
///
/// Sizing: 1 Gbps with MTU 1280 ≈ 97 700 datagrams/s. Absorbing a
/// 80 ms pump-side jitter event takes 7 800 datagrams ≈ 10 MB. We
/// round up to a comfortable `8 MiB` to leave headroom for occasional
/// 2 Gbps bursts before MTU discovery raises the per-datagram size.
pub const QUIC_DATAGRAM_RECV_BUFFER: usize = 8 * 1024 * 1024;

/// Datagram **send** buffer (bytes). Outbound datagrams that have been
/// handed to Quinn but not yet pushed to the UDP socket. Quinn's
/// default of `1 MB` is the working set for ~ 10 ms backpressure at
/// 1 Gbps; we raise to `4 MiB` (~ 40 ms at 1 Gbps) so a brief NIC
/// stall doesn't cascade into dropped datagrams on the transport
/// pump side.
pub const QUIC_DATAGRAM_SEND_BUFFER: usize = 4 * 1024 * 1024;

/// Datagram **send** buffer for the SERVER-side configs (exit, exit
/// multihop inbound, relay inbound): 16 MiB.
///
/// The instrumented WAN bench (path probe, 54 ms) proved the
/// downlink "tunnel loss" the inner TCP
/// collapses on is born exactly here: during the congestion
/// controller's ramp/probe phases the app-to-wire deficit reached
/// ~9.6 MiB, so the 4 MiB buffer overflowed and silently dropped
/// (exit `app_tx` vs `dg_tx` gap matched iperf3 receiver loss 1:1,
/// with ZERO path loss). 16 MiB absorbs the full ramp: measured 0%
/// loss at 300 Mbps offered (was 2.6%), TCP x4 490 -> 818 Mbps,
/// TCP x32 575 -> 1230 Mbps combined with exit-side GSO.
///
/// Tradeoff: when a flow saturates past the path rate the full buffer
/// adds up to ~190 ms of queueing latency at 680 Mbps before the
/// oldest-drop kicks in (vs ~47 ms at 4 MiB). For the Warren bulk
/// download profile that beats loss by far; latency-sensitive inner
/// flows only pay it while the tunnel is saturated.
///
/// The CLIENT side keeps [`QUIC_DATAGRAM_SEND_BUFFER`] (4 MiB): its
/// uplink producer is the inner TCP itself, which ramps WITH the
/// outer cwnd, so the client buffer never filled in any bench run
/// (min observed free: 4 193 024 of 4 194 304 bytes) and the smaller
/// cap matters on memory-constrained mobile targets.
pub const QUIC_DATAGRAM_SEND_BUFFER_EXIT: usize = 16 * 1024 * 1024;

// Compile-time invariant guards for the WAN bench findings:
// the exit-side send buffer must absorb the measured ~9.6 MiB ramp
// deficit and must stay strictly larger than the client default
// (which is kept small for mobile memory budgets).
const _: () = assert!(QUIC_DATAGRAM_SEND_BUFFER_EXIT >= 10 * 1024 * 1024);
const _: () = assert!(QUIC_DATAGRAM_SEND_BUFFER_EXIT > QUIC_DATAGRAM_SEND_BUFFER);

/// QUIC connection idle timeout, in seconds.
/// Too short: spurious disconnects on slow / mobile networks.
/// Too long: future leaks when the peer goes down.
///
/// Bumped from 60s to 180s after an instrumented re-bench (tcpdump
/// 3.2 GB cross-DC) showed three distinct stalls reproducing the same
/// pattern: a backbone blip of
/// 50s+ on the relay-to-exit leg fires `max_idle_timeout` on C2 (the
/// relay-exit hop), because the blind relay forwarder does not
/// propagate QUIC PING frames from C1 (the client-relay hop). The
/// 180s budget keeps `keep_alive_interval(20s)` at a comfortable 1/9
/// ratio (9 PINGs before idle close) and absorbs blips up to ~120s,
/// the observed worst-case on a cross-DC cloud backbone
/// (23.5ms RTT baseline).
pub const QUIC_MAX_IDLE_TIMEOUT_SECS: u64 = 180;

/// QUIC keep-alive interval, in seconds.
///
/// Period of inactivity after which Quinn emits a PING frame to keep
/// the connection alive. Must be strictly lower than
/// `QUIC_MAX_IDLE_TIMEOUT_SECS` on both peers, with enough margin to
/// absorb one missed PING (factor of 2 safety).
///
/// Without keep-alive, a Quinn `Connection` silently dies after
/// `max_idle_timeout` of silence on any active path. Under NAT
/// (especially CGNAT, mapping expiry ~30 s), the mapping vanishes
/// and the next reply from the peer is dropped, breaking long-running
/// flows. The exit-side then logs
/// `pump session ended error=read_datagram failed`.
///
/// 20 s sits below the typical 30 s CGNAT UDP mapping while still
/// being a fraction of the 60 s idle, keeping overhead negligible.
pub const QUIC_KEEP_ALIVE_INTERVAL_SECS: u64 = 20;

/// Max bidirectional streams a client can open *against* an exit. An
/// exit therefore accepts 100 streams per session. RAM cap = 100 × 6.25
/// MB = 625 MB peak per client.
pub const QUIC_MAX_CONCURRENT_BIDI_STREAMS_EXIT: u32 = 100;

/// Max bidirectional streams an exit can open *against* a client. On
/// the client side we only expect one control stream + 1-2 RPC.
pub const QUIC_MAX_CONCURRENT_BIDI_STREAMS_CLIENT: u32 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_h3_is_stable() {
        // ALPN negotiated by Warren clients is the IETF h3
        // identifier (RFC 9114). Two bytes exactly. Mutating this
        // breaks the wire-level h3 mimicry; bump to `h3-NN` (draft
        // suffix) only if Chrome stable ever shifts away from `h3`.
        assert_eq!(ALPN_H3, b"h3");
        assert_eq!(ALPN_H3.len(), 2);
    }

    #[test]
    fn hkdf_salt_is_stable() {
        // Mutation = breaks every deployed identity.
        assert_eq!(HKDF_SALT_IDENTITY_V1, b"warren/identity/v1");
    }

    #[test]
    fn hkdf_info_nodekey_is_stable() {
        // Same for the HKDF info: it feeds the Ed25519 derivation.
        assert_eq!(HKDF_INFO_NODEKEY, b"vpn-node-key");
    }

    // ---- Numeric invariants ----

    #[test]
    fn natpmp_port_range_is_sane() {
        const _: () = assert!(NATPMP_EXTERNAL_PORT_MIN < NATPMP_EXTERNAL_PORT_MAX);
        const _: () = assert!(NATPMP_EXTERNAL_PORT_MIN >= 49152);
    }

    #[test]
    fn natpmp_lifetime_range_is_sane() {
        // RFC 6886 §3.3: lifetime min < max, and max ≤ 1h.
        const _: () = assert!(NATPMP_LIFETIME_MIN_SECS < NATPMP_LIFETIME_MAX_SECS);
        const _: () = assert!(NATPMP_LIFETIME_MAX_SECS == 3600);
    }

    #[test]
    fn natpmp_cooldown_is_at_least_5_min() {
        // Minimum 5 min so an attacker cannot guess a rotation and
        // re-grab a freed port. Compile-time check: lowering the const
        // breaks the build.
        const _: () = assert!(NATPMP_PORT_COOLDOWN_SECS >= 300);
    }

    #[test]
    fn tunnel_mtu_min_lt_initial() {
        // DPLPMTUD starts at initial and may probe down towards min.
        // Need min < initial otherwise DPLPMTUD cannot adapt.
        const _: () = assert!(TUNNEL_MIN_MTU < TUNNEL_INITIAL_MTU);
    }

    #[test]
    fn padded_initial_never_exceeds_the_initial_mtu() {
        // A pad target larger than the Initial MTU stalls the handshake
        // (the datagram overflows the path and is dropped).
        const _: () = assert!(PADDED_INITIAL_MIN_SIZE <= TUNNEL_INITIAL_MTU);
    }

    #[test]
    fn tunnel_mtu_initial_leaves_room_for_overhead() {
        // UDP+QUIC+AEAD overhead is ~50 bytes on Ethernet 1500.
        // Initial MTU 1280 + 50 = 1330 <= 1500 => no IP
        // fragmentation. Compile-time check: bumping initial above
        // 1450 would break the build.
        const ETHERNET_MTU: u16 = 1500;
        const QUIC_AEAD_OVERHEAD: u16 = 50;
        const _: () = assert!(TUNNEL_INITIAL_MTU + QUIC_AEAD_OVERHEAD <= ETHERNET_MTU);
    }

    // ---- Tunnel topology invariants ----

    #[test]
    fn tunnel_gateway_is_in_pool() {
        let g = TUNNEL_GATEWAY_IP.octets();
        let n = TUNNEL_POOL_NETWORK.octets();
        // /16 pool: only the first two octets must match.
        assert_eq!(g[0], n[0]);
        assert_eq!(g[1], n[1]);
    }

    #[test]
    fn tunnel_pool_prefix_matches_pool_network() {
        // Pool is /16 ⇒ the last two octets of TUNNEL_POOL_NETWORK
        // must be zero (otherwise the CIDR is malformed).
        const _: () = assert!(TUNNEL_POOL_PREFIX == 16);
        let n = TUNNEL_POOL_NETWORK.octets();
        assert_eq!(n[2], 0);
        assert_eq!(n[3], 0);
    }

    #[test]
    fn tunnel_pool_cidr_string_matches_typed_constants() {
        // The textual representation (used for logs and nftables) must
        // match the typed constants - otherwise we get silent drift
        // between code and firewall rules.
        let expected = format!(
            "{}.{}.{}.{}/{}",
            TUNNEL_POOL_NETWORK.octets()[0],
            TUNNEL_POOL_NETWORK.octets()[1],
            TUNNEL_POOL_NETWORK.octets()[2],
            TUNNEL_POOL_NETWORK.octets()[3],
            TUNNEL_POOL_PREFIX,
        );
        assert_eq!(TUNNEL_POOL_CIDR, expected);
    }

    #[test]
    fn unix_now_is_strictly_positive_after_2024() {
        // Sanity: we are running after the start of 2024
        // (epoch 1_704_067_200). If `unix_now` returns 0, the system
        // clock or the function are broken - this test catches it
        // either way.
        assert!(
            unix_now() > 1_704_067_200,
            "unix_now must reflect a post-2024 wall clock"
        );
    }

    #[test]
    fn unix_now_is_monotonic_within_a_second() {
        // Two consecutive calls must observe the same or a later
        // second. Defends against the helper accidentally returning
        // a stale cached value.
        let a = unix_now();
        let b = unix_now();
        assert!(b >= a, "unix_now must be monotonic (got {a} then {b})");
    }

    #[test]
    fn log_prefix_truncates_long_string() {
        let pubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(log_prefix(pubkey), "01234567");
    }

    #[test]
    fn log_prefix_returns_short_string_unchanged() {
        // Defense: never panic, never out-of-bounds. A short input
        // (already non-leaky) is returned as-is.
        assert_eq!(log_prefix("abc"), "abc");
        assert_eq!(log_prefix(""), "");
    }

    #[test]
    fn log_prefix_returns_exactly_eight_chars_when_longer() {
        // Anchor: any change to LOG_PREFIX_LEN is a deliberate
        // policy change and breaks this assertion.
        let s = "abcdefghijklmnop";
        assert_eq!(log_prefix(s).len(), LOG_PREFIX_LEN);
    }

    #[test]
    fn log_prefix_handles_multibyte_codepoint_boundary() {
        // Pathological input: 7 ASCII bytes then a 4-byte codepoint
        // crossing the prefix boundary. `s.get(..8)` returns None
        // (mid-codepoint), so we fall back to the full string. No
        // panic.
        let s = "abcdefg\u{1F600}";
        let prefix = log_prefix(s);
        assert!(s.starts_with(prefix));
    }

    #[test]
    fn parse_loopback_bind_accepts_ipv4_loopback() {
        let addr = parse_loopback_bind("127.0.0.1:8080").expect("loopback v4");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn parse_loopback_bind_accepts_ipv6_loopback() {
        let addr = parse_loopback_bind("[::1]:8080").expect("loopback v6");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn parse_loopback_bind_rejects_unspecified_v4() {
        let err = parse_loopback_bind("0.0.0.0:8080").expect_err("0.0.0.0 must reject");
        assert!(matches!(err, LoopbackBindError::NotLoopback(_)));
    }

    #[test]
    fn parse_loopback_bind_rejects_unspecified_v6() {
        let err = parse_loopback_bind("[::]:8080").expect_err("[::] must reject");
        assert!(matches!(err, LoopbackBindError::NotLoopback(_)));
    }

    #[test]
    fn parse_loopback_bind_rejects_public_address() {
        let err = parse_loopback_bind("203.0.113.42:8080").expect_err("public IP must reject");
        assert!(matches!(err, LoopbackBindError::NotLoopback(_)));
    }

    #[test]
    fn parse_loopback_bind_rejects_unparseable_input() {
        let err = parse_loopback_bind("not_a_socket_addr").expect_err("garbage rejected");
        assert!(matches!(err, LoopbackBindError::Parse(_, _)));
    }

    #[test]
    fn loopback_bind_error_distinguishes_parse_from_not_loopback() {
        // Anti-conflation: callers (e.g. an `--allow-public-bind` flag)
        // need to allow NotLoopback while still rejecting Parse errors.
        // Verify the variants are matchable.
        let parse_err = parse_loopback_bind("garbage").unwrap_err();
        let not_loopback_err = parse_loopback_bind("203.0.113.42:8080").unwrap_err();
        assert!(matches!(parse_err, LoopbackBindError::Parse(_, _)));
        assert!(matches!(
            not_loopback_err,
            LoopbackBindError::NotLoopback(_)
        ));
    }

    // ---- Quinn tuning: sanity on TransportConfig windows ----

    #[test]
    fn quic_stream_recv_window_matches_bandwidth_delay_product() {
        // Window = bandwidth × delay. Warren targets 1 Gbps × 50 ms RTT
        // FR↔NL → 6.25 MB per stream.
        // 1_000_000_000 bits/s × 0.050 s / 8 = 6 250 000 bytes.
        const _: () = assert!(QUIC_STREAM_RECV_WINDOW == 6_250_000);
    }

    #[test]
    fn quic_recv_window_covers_5_streams() {
        // RECV_WINDOW must be ≥ 5 × STREAM_RECV_WINDOW.
        const _: () = assert!(QUIC_RECV_WINDOW >= 5 * QUIC_STREAM_RECV_WINDOW);
    }

    #[test]
    fn quic_send_window_at_least_recv_window() {
        // send_window ≥ receive_window, otherwise the sender is
        // bottlenecked by its own window before the receiver.
        const _: () = assert!(QUIC_SEND_WINDOW >= QUIC_RECV_WINDOW as u64);
    }

    #[test]
    fn quic_max_idle_timeout_is_warren_default() {
        // Warren default = 180 seconds. Bumped from 60s to absorb
        // cross-DC cloud backbone blips up to ~120s without tripping
        // `max_idle_timeout` on the blind-forwarded relay-to-exit hop
        // (where QUIC PING frames from the client-to-relay hop do not
        // propagate). Cf. const docstring.
        const _: () = assert!(QUIC_MAX_IDLE_TIMEOUT_SECS == 180);
    }

    /// Regression: the legacy 60s idle timeout const must NOT be
    /// re-introduced. It shadowed `QUIC_MAX_IDLE_TIMEOUT_SECS = 180`
    /// without being consumed, which is a landmine: a future developer
    /// searching for "idle timeout" would have hit the dead 60s value
    /// and quietly regressed to the cross-DC stall behaviour.
    /// Source-level scan, kept here next to the canonical const so the
    /// contract is obvious. Pattern obfuscated by `concat!` so the test
    /// itself does not self-match.
    #[test]
    fn no_legacy_tunnel_idle_timeout_const_re_introduced() {
        let src = include_str!("lib.rs");
        let code_only: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let forbidden = concat!("TUNNEL", "_IDLE_TIMEOUT_SECS");
        assert!(
            !code_only.contains(forbidden),
            "the legacy {forbidden} const is the dead shadow of \
             QUIC_MAX_IDLE_TIMEOUT_SECS. \
             If you need a tunnel-level idle timeout, use \
             QUIC_MAX_IDLE_TIMEOUT_SECS (= 180) directly."
        );
    }

    #[test]
    fn quic_concurrent_streams_bounded() {
        // 100 streams per client on the exit side (plenty for tunnel +
        // RPC), 10 on the client side. Both limits exposed separately.
        const _: () = assert!(QUIC_MAX_CONCURRENT_BIDI_STREAMS_EXIT == 100);
        const _: () = assert!(QUIC_MAX_CONCURRENT_BIDI_STREAMS_CLIENT == 10);
    }
}
