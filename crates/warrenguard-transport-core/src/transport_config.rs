//! Quinn `TransportConfig` tuned for Warren.
//!
//! Centralizes the transport tuning levers:
//! - **BBR** congestion controller (vs default CUBIC).
//! - **MTU 1280** initial with DPLPMTUD probing upward.
//!   (Lowered from 1350 to defeat the cross-DC PMTU blackhole that
//!   stalled the server-side obfuscation mirror; cf.
//!   `warrenguard_config::TUNNEL_INITIAL_MTU` docstring.)
//! - **Receive windows** sized for BDP 1 Gbps × 50 ms RTT.
//! - **Idle timeout** 180 s. (Bumped from 60 s to absorb
//!   cross-DC backbone blips that fire `max_idle_timeout` on the
//!   blind-forwarded relay-to-exit hop; cf.
//!   `warrenguard_config::QUIC_MAX_IDLE_TIMEOUT_SECS` docstring.)
//! - **Stream limits** differ between client (10) and exit (100).
//!
//! Linux-only levers (UDP GSO/GRO, sendmmsg/recvmmsg) are automatic via
//! `quinn-udp` and need no `TransportConfig` configuration, except
//! **`enable_segmentation_offload(false)`** for cloud KVM/virtio NICs
//! that don't support hardware UDP segmentation
//! (`tx-udp-segmentation: off [fixed]` via `ethtool -k`). Without this
//! toggle, quinn-udp tries UDP_SEGMENT on the first packet, gets EIO, halts
//! and falls back, but logs a noisy WARN and loses a few packets during
//! the transition. With `--no-gso` on the client/exit binary, the attempt
//! is skipped entirely.

use std::sync::Arc;
use std::time::Duration;

use quinn::TransportConfig;
use quinn::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use quinn::{IdleTimeout, MtuDiscoveryConfig, VarInt};
use warrenguard_config::{
    QUIC_DATAGRAM_RECV_BUFFER, QUIC_DATAGRAM_SEND_BUFFER, QUIC_DATAGRAM_SEND_BUFFER_EXIT,
    QUIC_KEEP_ALIVE_INTERVAL_SECS, QUIC_MAX_CONCURRENT_BIDI_STREAMS_CLIENT,
    QUIC_MAX_CONCURRENT_BIDI_STREAMS_EXIT, QUIC_MAX_IDLE_TIMEOUT_SECS, QUIC_RECV_WINDOW,
    QUIC_SEND_WINDOW, QUIC_STREAM_RECV_WINDOW, TUNNEL_INITIAL_MTU, TUNNEL_MIN_MTU,
};

/// Common base for the client + exit transport configs. Applies BBR,
/// MTU, windows, idle timeout, keep-alive. Returns by value: the caller
/// then plugs the stream-limit setters and wraps in `Arc` before
/// handing the result to `ClientConfig::transport_config` or
/// `ServerConfig::transport_config`.
///
/// When `enable_gso == false`, disables UDP segmentation offload upfront
/// (useful on KVM/virtio NICs that lack hardware `UDP_SEGMENT`
/// support, otherwise quinn-udp tries, gets `EIO`, halts and falls back).
/// Congestion-controller selection for the A/B bench knobs. BBR stays
/// the production default; the env overrides exist so a real-WAN A/B
/// (BBR vs Cubic, initial-window sweep) does not require a rebuild per
/// hypothesis. All three choices are upstream-tested controllers that
/// stay loss-responsive; the knob can NOT select anything antisocial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CcKind {
    Bbr,
    Cubic,
    NewReno,
}

/// Maps the `WARREN_CC` override string to a controller kind. Unknown
/// names fall back to the production default (BBR) so a typo can never
/// degrade a production deployment into an untested configuration. The
/// raw env read is owned by `warrenguard_config::knobs`; this stays pure for
/// the enum-mapping tests.
fn parse_cc_kind(cc: Option<&str>) -> CcKind {
    match cc.map(str::to_ascii_lowercase).as_deref() {
        Some("cubic") => CcKind::Cubic,
        Some("newreno") => CcKind::NewReno,
        Some("bbr") | None => CcKind::Bbr,
        Some(other) => {
            tracing::warn!(value = other, "unknown WARREN_CC, keeping BBR");
            CcKind::Bbr
        }
    }
}

fn apply_congestion_controller(cfg: &mut TransportConfig) {
    let cc_env = warrenguard_config::knobs::cc_choice();
    let win = warrenguard_config::knobs::initial_window();
    let kind = parse_cc_kind(cc_env);
    if cc_env.is_some() || win.is_some() {
        tracing::info!(?kind, initial_window = ?win, "transport CC override active");
    }
    match kind {
        CcKind::Bbr => {
            let mut bbr = BbrConfig::default();
            if let Some(w) = win {
                bbr.initial_window(w);
            }
            cfg.congestion_controller_factory(Arc::new(bbr));
        }
        CcKind::Cubic => {
            let mut cubic = CubicConfig::default();
            if let Some(w) = win {
                cubic.initial_window(w);
            }
            cfg.congestion_controller_factory(Arc::new(cubic));
        }
        CcKind::NewReno => {
            let mut nr = NewRenoConfig::default();
            if let Some(w) = win {
                nr.initial_window(w);
            }
            cfg.congestion_controller_factory(Arc::new(nr));
        }
    }
}

/// Datagram send-buffer size: `WARREN_DG_SEND_BUF` (bytes) overrides the
/// production default for A/B benching. The instrumented run
/// proved the buffer is the exact birthplace of the "tunnel loss" the
/// inner TCP collapses on (exit app_tx vs wire dg_tx gap matched iperf
/// loss 1:1 during the BBR ramp), so its sizing is a first-class lever:
/// client side defaults to `QUIC_DATAGRAM_SEND_BUFFER` (4 MiB), the
/// server-side configs pass `QUIC_DATAGRAM_SEND_BUFFER_EXIT` (16 MiB).
/// Parsing / clamp (`> 0`, capped at 64 MiB) lives in the central knob
/// registry (`warrenguard_config::knobs`).
fn datagram_send_buffer_size(default: usize) -> usize {
    warrenguard_config::knobs::datagram_send_buffer(default)
}

fn warren_transport_config_base_with_pad(enable_gso: bool, pad_to_mtu: bool) -> TransportConfig {
    let mut cfg = TransportConfig::default();
    apply_congestion_controller(&mut cfg);
    cfg.initial_mtu(TUNNEL_INITIAL_MTU)
        .min_mtu(TUNNEL_MIN_MTU)
        .mtu_discovery_config(Some(MtuDiscoveryConfig::default()))
        .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECV_WINDOW))
        .receive_window(VarInt::from_u32(QUIC_RECV_WINDOW))
        .send_window(QUIC_SEND_WINDOW)
        // Explicit datagram buffers, defaults
        // are dramatically under-sized for the 1+ Gbps target.
        .datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECV_BUFFER))
        .datagram_send_buffer_size(datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER))
        .enable_segmentation_offload(enable_gso)
        // Keep the QUIC spin bit (RFC 9312 section 3.2) at a
        // constant 0 on every short header. The spin bit is a passive
        // RTT signal that an on-path observer can use to fingerprint
        // Warren tunnels or correlate them with the user's outer
        // traffic; opting out of `allow_spin` is the IETF-blessed way
        // to disable it.
        .allow_spin(false)
        .max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(QUIC_MAX_IDLE_TIMEOUT_SECS))
                .expect("idle timeout fits in VarInt"),
        ))
        // Keep-alive PINGs maintain the connection across NAT mapping
        // expiry and brief packet loss on a single path. Without this,
        // a quinn `Connection` dies silently after `max_idle_timeout` of
        // silence and the exit logs `pump session ended
        // error=read_datagram failed`.
        .keep_alive_interval(Some(Duration::from_secs(QUIC_KEEP_ALIVE_INTERVAL_SECS)))
        .pad_to_mtu(pad_to_mtu);
    cfg
}

fn warren_transport_config_base(enable_gso: bool) -> TransportConfig {
    warren_transport_config_base_with_pad(enable_gso, false)
}

/// Client-side keep-alive cadence. More aggressive than the shared
/// `QUIC_KEEP_ALIVE_INTERVAL_SECS` (20 s): a healthy session then never
/// goes more than ~5 s without an ACK-eliciting exchange, which is what
/// makes the short client idle timeout below safe.
const CLIENT_KEEP_ALIVE_INTERVAL_SECS: u64 = 5;

/// Client-side dead-peer detection bound - and, per RFC 9000 § 10.1,
/// the EFFECTIVE idle timeout of the whole connection: each endpoint
/// applies `min(its own limit, the peer's advertised limit)`, verified
/// in the vendored quinn-proto (`negotiate_max_idle_timeout` =
/// `cmp::min`, evaluated on BOTH endpoints). So the server's tolerant
/// 180 s `QUIC_MAX_IDLE_TIMEOUT_SECS` does NOT survive on connections
/// dialed with this config: the exit closes the session after 25 s of
/// silence exactly like the client does. There is no "server keeps its
/// mobile tolerance" asymmetry - configuring one is wire-impossible.
///
/// Assumed tradeoff, valid for desktop:
/// - GAIN: fast dead-exit detection. With 5 s keep-alives a healthy
///   session never goes ~25 s silent, and the live kill-the-exit test
///   measured a 38 s blackout with the shared 180 s values
///   vs ~25 s capped here; the supervisor then redials in ~30 ms.
/// - COST: any real >25 s radio silence (mobile doze suppressing
///   keep-alives, long suspend) closes the session on BOTH ends and
///   forces a redial on wake.
///
/// Re-decide before a mobile client ships: either keep 25 s and
/// accept redial-on-wake, or raise the client idle timeout back up and
/// lean on the uplink dead-path watch (`WARREN_UPLINK_DEADPATH`)
/// for fast dead-exit detection instead. Changing the
/// value requires a real-network bench, which is why this constant is
/// documented rather than retuned.
const CLIENT_MAX_IDLE_TIMEOUT_SECS: u64 = 25;

/// Applies the aggressive client-side dead-peer detection knobs
/// (see [`CLIENT_KEEP_ALIVE_INTERVAL_SECS`] /
/// [`CLIENT_MAX_IDLE_TIMEOUT_SECS`]).
///
/// When `idle_cover` is true, the fixed keep-alive
/// PING is DISABLED: the idle cover pump
/// (`warrenguard_pump::pump_bidirectional_with_idle_cover`) refreshes the
/// NAT mapping and resets the idle timeout with jittered, size-varied
/// dummies instead, removing the keep-alive beacon. The 25s idle timeout
/// still detects a dead exit (cover datagrams stop being acknowledged).
/// The caller MUST run the cover pump when this is set, or the
/// connection has no liveness mechanism beyond the idle timeout.
fn apply_client_liveness(cfg: &mut TransportConfig, idle_cover: bool) {
    let keep_alive = if idle_cover {
        None
    } else {
        Some(Duration::from_secs(CLIENT_KEEP_ALIVE_INTERVAL_SECS))
    };
    cfg.keep_alive_interval(keep_alive).max_idle_timeout(Some(
        IdleTimeout::try_from(Duration::from_secs(CLIENT_MAX_IDLE_TIMEOUT_SECS))
            .expect("idle timeout fits in VarInt"),
    ));
}

/// Warren **client** `TransportConfig`, GSO enabled (default).
///
/// Returned wrapped in `Arc` so the caller can plug it directly into
/// `quinn::ClientConfig::transport_config` without an extra allocation.
#[must_use]
pub fn warren_transport_config_client() -> Arc<TransportConfig> {
    warren_transport_config_client_with_gso(true)
}

/// Variant of the client transport config with explicit GSO toggle.
/// Pass `false` on KVM/virtio NICs.
#[must_use]
pub fn warren_transport_config_client_with_gso(enable_gso: bool) -> Arc<TransportConfig> {
    warren_transport_config_client_full(enable_gso, false, false)
}

/// Client transport config for idle cover. When
/// `idle_cover` is true the keep-alive PING is disabled; the caller MUST
/// run `warrenguard_pump::pump_bidirectional_with_idle_cover` so cover
/// traffic provides NAT refresh and liveness. With `idle_cover` false
/// this is identical to [`warren_transport_config_client_with_gso`].
#[must_use]
pub fn warren_transport_config_client_with_idle_cover(
    enable_gso: bool,
    idle_cover: bool,
) -> Arc<TransportConfig> {
    warren_transport_config_client_full(enable_gso, false, idle_cover)
}

/// Full-option client transport config with GSO, pad_to_mtu and
/// idle-cover (keep-alive-disabled) toggles.
#[must_use]
pub fn warren_transport_config_client_full(
    enable_gso: bool,
    pad_to_mtu: bool,
    idle_cover: bool,
) -> Arc<TransportConfig> {
    warren_transport_config_client_full_with_mtu(
        enable_gso,
        pad_to_mtu,
        idle_cover,
        warrenguard_config::knobs::client_initial_mtu(),
    )
}

/// [`warren_transport_config_client_full`] with an explicit outer QUIC
/// `initial_mtu`. Lowering it below the default fits the handshake and datagrams
/// through a reduced path (a client nested inside a full-tunnel system VPN);
/// DPLPMTUD then probes upward from there. The Initial pad tracks `initial_mtu`
/// so it never exceeds it (a pad larger than the initial MTU stalls the
/// handshake, cf. the base-config docstring). The public entry reads the
/// [`warrenguard_config::knobs::client_initial_mtu`] knob; this seam keeps the
/// clamp testable without touching the process environment.
fn warren_transport_config_client_full_with_mtu(
    enable_gso: bool,
    pad_to_mtu: bool,
    idle_cover: bool,
    initial_mtu: u16,
) -> Arc<TransportConfig> {
    let mut cfg = warren_transport_config_base_with_pad(enable_gso, pad_to_mtu);
    apply_client_liveness(&mut cfg, idle_cover);
    cfg.initial_mtu(initial_mtu)
        .max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS_CLIENT))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        // Force the TLS ClientHello to span 2 Initial
        // QUIC packets in 2 UDP datagrams (obfuscation baseline).
        //
        // - `initial_crypto_first_fragment_size(Some(64))` caps the
        //   very first CRYPTO chunk to 64 bytes, which lands inside
        //   the ClientHello header (legacy version + random + early
        //   session-id bytes). Every TLS extension - including SNI -
        //   then lives in the *second* Initial packet, which Quinn
        //   emits in a separate UDP datagram once the first one is
        //   padded near the path MTU. A passive observer parsing
        //   either datagram in isolation cannot reconstruct the SNI
        //   extension (GFW SNI extractor, USENIX Security 2025).
        // - `initial_datagram_min_size(1280)` pads both Initial
        //   datagrams to the conservative RFC 9000 path-MTU floor
        //   (= `TUNNEL_INITIAL_MTU`). This was dropped from
        //   the historical 1500 B Chrome H/3 mimicry value after
        //   the loopback bench proved that combining
        //   `initial_datagram_min_size(1500)` with
        //   `initial_mtu(1280)` stalls the server side: Quinn's
        //   coalesce path cannot emit a full 1500 B target into a
        //   single 1280 B datagram, and the warren_force_finish
        //   path interacts badly with the server's TLS handshake
        //   state machine. With `1280 = initial_mtu`, each Initial
        //   is padded to a full path-MTU datagram and the chunk cap
        //   still produces the 2-datagram split that defeats the
        //   GFW SNI extractor (invariant I3).
        //
        //   The pad tracks `initial_mtu` (not the literal 1280): a client
        //   nested inside a full-tunnel system VPN lowers the floor, and the
        //   pad must follow or the padded ClientHello overflows the reduced
        //   path and is dropped (the same pad-vs-MTU stall, one layer out).
        .initial_crypto_first_fragment_size(Some(64))
        .initial_datagram_min_size(initial_mtu);
    Arc::new(cfg)
}

/// Warren **exit** `TransportConfig`: up to 100 concurrent streams (a single
/// client may open up to 100 streams on this session).
///
/// Mirrors the client-side obfuscation knobs
/// (`initial_crypto_first_fragment_size` + `initial_datagram_min_size`)
/// on the server side too, so the wire profile is symmetric: a
/// passive observer sees the ServerHello-bearing Initial coalesce
/// over ≥ 2 padded UDP datagrams, same as the ClientHello, defeating
/// the asymmetry that a stateful DPI could otherwise fingerprint.
/// Both knobs fire server-side since the fork bump to
/// `0.11.13-warren.2` (the historical `self.side.is_client()` guard
/// on the chunk-cap site was dropped; cf. `quinn_fork_patch.rs`).
/// The pad target is `1280 = TUNNEL_INITIAL_MTU` so a server Initial
/// never has to coalesce a 1500 B pad target into a 1280 B datagram
/// (a loopback bench traced a handshake stall to that
/// asymmetric pad-vs-mtu interaction).
#[must_use]
pub fn warren_transport_config_exit() -> Arc<TransportConfig> {
    warren_transport_config_exit_with_gso(true)
}

/// Variant of the exit transport config with explicit GSO toggle.
#[must_use]
pub fn warren_transport_config_exit_with_gso(enable_gso: bool) -> Arc<TransportConfig> {
    warren_transport_config_exit_full(enable_gso, false)
}

/// Full-option exit transport config with GSO and pad_to_mtu toggles.
#[must_use]
pub fn warren_transport_config_exit_full(
    enable_gso: bool,
    pad_to_mtu: bool,
) -> Arc<TransportConfig> {
    let mut cfg = warren_transport_config_base_with_pad(enable_gso, pad_to_mtu);
    cfg.datagram_send_buffer_size(datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_EXIT))
        .max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS_EXIT))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        // Server-side mirror of the client pad knobs. See the
        // module-level doc.
        .initial_crypto_first_fragment_size(Some(64))
        .initial_datagram_min_size(1280);
    Arc::new(cfg)
}

/// Warren **exit multi-hop inbound** `TransportConfig`: the config the
/// exit's `--multihop` termination listener serves to incoming dialers
/// (the relay-to-exit leg, and a direct 1-hop client).
///
/// Identical to [`warren_transport_config_exit`] **except the
/// Initial-padding knobs are omitted** - for the same reason
/// [`warren_transport_config_client_multihop_with_gso`] and
/// [`warren_transport_config_relay_outbound_multihop_with_gso`] omit
/// them: the multi-hop dial chain does not pre-negotiate the padded
/// frame size, and padding the ServerHello to 1280 B makes the
/// handshake stall whenever the path MTU dips below ~1308 B - which it
/// does on a long intercontinental relay-to-exit hop (e.g. DE↔SG),
/// where the padded ServerHello datagram is silently dropped and the
/// handshake never completes. The exit listener kept the padding by
/// oversight while the two dialer profiles already dropped it.
#[must_use]
pub fn warren_transport_config_exit_multihop_with_gso(enable_gso: bool) -> Arc<TransportConfig> {
    let mut cfg = warren_transport_config_base(enable_gso);
    cfg.datagram_send_buffer_size(datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_EXIT))
        .max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS_EXIT))
        .max_concurrent_uni_streams(VarInt::from_u32(0));
    Arc::new(cfg)
}

/// Warren **relay inbound** `TransportConfig`: served to incoming Warren
/// clients dialing the relay.
///
/// Mirrors the exit-side profile (BBR, MTU 1280, idle, spin bit off,
/// 100 concurrent bidi streams) **including the obfuscation-baseline
/// Initial-padding knobs**. Those knobs were once reverted after the
/// cross-DC bench stalled with the 1500 B pad-vs-1350 B MTU
/// asymmetry. The bidirectional mirror is unlocked by
/// (a) lowering `TUNNEL_INITIAL_MTU` to 1280, (b) lowering the pad
/// target to match (`initial_datagram_min_size = 1280`, no longer the
/// historical Chrome 1500 B figure), and (c) bumping the quinn-fork
/// to `0.11.13-warren.2` so the chunk-cap site fires server-side
/// too. The resulting wire pattern is 2 padded Initials of ~1280 B
/// each, which satisfies obfuscation invariant I3 (≥ 2 datagrams) and
/// defeats the GFW SNI extractor while staying well inside any
/// path-MTU floor.
#[must_use]
pub fn warren_transport_config_relay_inbound() -> Arc<TransportConfig> {
    warren_transport_config_relay_inbound_with_gso(true)
}

/// Variant of [`warren_transport_config_relay_inbound`] with explicit
/// GSO toggle. Pass `false` on KVM/virtio NICs.
#[must_use]
pub fn warren_transport_config_relay_inbound_with_gso(enable_gso: bool) -> Arc<TransportConfig> {
    let mut cfg = warren_transport_config_base(enable_gso);
    cfg.datagram_send_buffer_size(datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_EXIT))
        .max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS_EXIT))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        // Server-side mirror of the client pad knobs. See
        // `warren_transport_config_exit` doc.
        .initial_crypto_first_fragment_size(Some(64))
        .initial_datagram_min_size(1280);
    Arc::new(cfg)
}

/// Warren **multi-hop relay inbound** `TransportConfig`: identical to
/// [`warren_transport_config_relay_inbound_with_gso`] **except the
/// Initial-padding knobs** (`initial_crypto_first_fragment_size` +
/// `initial_datagram_min_size`) are **omitted**.
///
/// The non-multihop relay inbound profile pads the ServerHello to
/// 1280 B. On the multi-hop dial chain the client side
/// ([`warren_transport_config_client_multihop_with_gso`]) drops those
/// knobs, so the relay listener must drop them too: an asymmetric
/// pad-vs-MTU pairing stalls the handshake whenever the path MTU dips
/// below ~1308 B, which the relay-facing client leg can hit on a real
/// network path. Mirror of the exit-side
/// [`warren_transport_config_exit_multihop_with_gso`] reasoning.
#[must_use]
pub fn warren_transport_config_relay_inbound_multihop_with_gso(
    enable_gso: bool,
) -> Arc<TransportConfig> {
    let mut cfg = warren_transport_config_base(enable_gso);
    cfg.datagram_send_buffer_size(datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER_EXIT))
        .max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS_EXIT))
        .max_concurrent_uni_streams(VarInt::from_u32(0));
    Arc::new(cfg)
}

/// Warren **relay outbound** `TransportConfig`: used by the relay when
/// dialing an exit's QUIC server. Mirrors the client-side profile
/// (stream limits, Initial padding) so the wire signature of the
/// relay-to-exit dial is also Chrome-like.
#[must_use]
pub fn warren_transport_config_relay_outbound() -> Arc<TransportConfig> {
    warren_transport_config_relay_outbound_with_gso(true)
}

/// Variant of [`warren_transport_config_relay_outbound`] with explicit
/// GSO toggle.
#[must_use]
pub fn warren_transport_config_relay_outbound_with_gso(enable_gso: bool) -> Arc<TransportConfig> {
    let mut cfg = warren_transport_config_base(enable_gso);
    cfg.max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS_CLIENT))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .initial_crypto_first_fragment_size(Some(64))
        .initial_datagram_min_size(1280);
    Arc::new(cfg)
}

/// Warren **multi-hop client** `TransportConfig`: the idle-cover-off form of
/// [`warren_transport_config_client_multihop_with_idle_cover`]. It carries the
/// Initial-padding knobs (`initial_datagram_min_size` + 64 B first CRYPTO chunk)
/// on the GFW-facing client-to-relay leg;
/// see that function's doc for why the SNI-split is safe here while the inbound
/// and relay-outbound multi-hop profiles must stay no-pad.
#[must_use]
pub fn warren_transport_config_client_multihop_with_gso(enable_gso: bool) -> Arc<TransportConfig> {
    warren_transport_config_client_multihop_with_idle_cover(enable_gso, false)
}

/// Multi-hop client config (client to relay hop, C1) with idle-cover
/// support. When `idle_cover` is true the keep-alive
/// PING on the client-to-relay connection is disabled; the caller MUST
/// run `warrenguard_pump::pump_bidirectional_with_idle_cover` on that
/// connection so cover provides NAT refresh and liveness. The relay to
/// exit hop (C2) is a separate connection with its own server-side
/// keep-alive and is unaffected. With `idle_cover` false this is
/// identical to [`warren_transport_config_client_multihop_with_gso`].
///
/// Unlike every other multi-hop profile, this one DOES carry the
/// Initial-padding knobs (`initial_crypto_first_fragment_size(64)` +
/// `initial_datagram_min_size(1280)`). The client-to-relay leg (C1) is the
/// ONLY hop a GFW-class censor observes - the relay and exit sit outside
/// the censored region - so the SNI-split that defeats the QUIC SNI
/// extractor (USENIX Security 2025) must apply here. The multi-hop
/// stall risk is a SERVER-side problem: padding the *ServerHello*
/// to 1280 B is dropped on a low-PMTU intercontinental relay-to-exit
/// hop, which is why the inbound and relay-outbound multi-hop
/// profiles stay no-pad. The CLIENT padding its own ClientHello to 1280 B
/// is the exact mechanism
/// [`warren_transport_config_client_with_gso`] ships on the client-to-relay leg, and
/// the C1 first hop (user ISP to relay) is the same class of path as a
/// direct client-to-exit dial, so it carries no extra stall risk. The
/// relay answers C1 with an unpadded ServerHello (its inbound profile),
/// which never overflows a low-PMTU path.
#[must_use]
pub fn warren_transport_config_client_multihop_with_idle_cover(
    enable_gso: bool,
    idle_cover: bool,
) -> Arc<TransportConfig> {
    warren_transport_config_client_multihop_with_mtu(
        enable_gso,
        idle_cover,
        warrenguard_config::knobs::client_initial_mtu(),
    )
}

/// [`warren_transport_config_client_multihop_with_idle_cover`] with an explicit
/// outer QUIC `initial_mtu` for the GFW-facing client-to-relay leg. Same
/// nested-path rationale as [`warren_transport_config_client_full_with_mtu`]:
/// lowering the floor fits a reduced path and the Initial pad tracks it. The
/// public entry reads the [`warrenguard_config::knobs::client_initial_mtu`]
/// knob; this seam keeps the clamp testable without the process environment.
fn warren_transport_config_client_multihop_with_mtu(
    enable_gso: bool,
    idle_cover: bool,
    initial_mtu: u16,
) -> Arc<TransportConfig> {
    let mut cfg = warren_transport_config_base(enable_gso);
    apply_client_liveness(&mut cfg, idle_cover);
    cfg.initial_mtu(initial_mtu)
        .max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS_CLIENT))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        // SNI-split on the GFW-facing client->relay leg. See the doc above
        // for why this is safe on the multi-hop client while the inbound
        // and relay-outbound multi-hop profiles must stay no-pad. The pad
        // tracks `initial_mtu` so a nested-path client's lowered floor does not
        // leave an oversized ClientHello that the reduced path drops.
        .initial_crypto_first_fragment_size(Some(64))
        .initial_datagram_min_size(initial_mtu);
    Arc::new(cfg)
}

/// Warren **multi-hop relay outbound** `TransportConfig`: identical
/// to [`warren_transport_config_relay_outbound_with_gso`] except the
/// Initial-padding knobs are **omitted**, for the same reason
/// as [`warren_transport_config_client_multihop_with_gso`].
#[must_use]
pub fn warren_transport_config_relay_outbound_multihop_with_gso(
    enable_gso: bool,
) -> Arc<TransportConfig> {
    let mut cfg = warren_transport_config_base(enable_gso);
    cfg.max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS_CLIENT))
        .max_concurrent_uni_streams(VarInt::from_u32(0));
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_lowers_initial_mtu_and_pad_together_for_a_nested_path() {
        // A client nested inside a full-tunnel system VPN sees a reduced path
        // MTU. The outer QUIC floor must drop below the nested cap AND the
        // Initial pad must drop with it: a pad larger than initial_mtu stalls the
        // handshake (the 1500-vs-1280 class the base docstring warns about), so a
        // handshake padded to 1280 on a 1200 floor would itself be dropped.
        let cfg = warren_transport_config_client_full_with_mtu(true, false, false, 1200);
        let rendered = format!("{cfg:?}");
        assert!(
            rendered.contains("initial_mtu: 1200"),
            "outer QUIC floor must drop to the nested-safe MTU, got: {rendered}"
        );
        assert!(
            rendered.contains("initial_datagram_min_size: 1200"),
            "the Initial pad must track the lowered MTU, never exceed it, got: {rendered}"
        );
    }

    #[test]
    fn client_config_keeps_the_full_mtu_and_pad_by_default() {
        // A healthy path pays nothing: the default is the full 1280 floor and pad.
        let cfg =
            warren_transport_config_client_full_with_mtu(true, false, false, TUNNEL_INITIAL_MTU);
        let rendered = format!("{cfg:?}");
        assert!(
            rendered.contains("initial_mtu: 1280"),
            "default must keep the full outer MTU, got: {rendered}"
        );
        assert!(
            rendered.contains("initial_datagram_min_size: 1280"),
            "default must keep the full Initial pad, got: {rendered}"
        );
    }

    #[test]
    fn multihop_client_config_lowers_initial_mtu_and_pad_together_for_a_nested_path() {
        let cfg = warren_transport_config_client_multihop_with_mtu(true, false, 1200);
        let rendered = format!("{cfg:?}");
        assert!(
            rendered.contains("initial_mtu: 1200"),
            "multihop client outer QUIC floor must drop for a nested path, got: {rendered}"
        );
        assert!(
            rendered.contains("initial_datagram_min_size: 1200"),
            "multihop Initial pad must track the lowered MTU, got: {rendered}"
        );
    }

    #[test]
    fn cc_kind_defaults_to_bbr_without_env() {
        assert_eq!(
            parse_cc_kind(None),
            CcKind::Bbr,
            "production default must stay BBR"
        );
    }

    #[test]
    fn cc_kind_selects_cubic_and_newreno_case_insensitive() {
        assert_eq!(parse_cc_kind(Some("cubic")), CcKind::Cubic);
        assert_eq!(parse_cc_kind(Some("CUBIC")), CcKind::Cubic);
        assert_eq!(parse_cc_kind(Some("newreno")), CcKind::NewReno);
        assert_eq!(parse_cc_kind(Some("bbr")), CcKind::Bbr);
    }

    #[test]
    fn cc_kind_unknown_name_falls_back_to_bbr() {
        // A typo in the env var must never silently select an untested
        // controller; it keeps the production default. The initial-window
        // parsing / clamp moved to `warrenguard_config::knobs` and is covered
        // by that crate's `parse_positive_u64_opt` tests.
        assert_eq!(parse_cc_kind(Some("vegas")), CcKind::Bbr);
    }

    // The exit-vs-client send-buffer sizing invariants are enforced at
    // compile time next to the const definitions in `warren-config`
    // (`const _: () = assert!(...)` guards).
}
