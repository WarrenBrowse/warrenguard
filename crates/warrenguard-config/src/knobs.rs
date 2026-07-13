//! Central registry of Warren tuning knobs (`WARREN_*` environment
//! variables that tune the data plane / transport).
//!
//! Before this module, ~8 tuning knobs were parsed ad-hoc at each call
//! site with inconsistent error semantics (some warned, some silently
//! ignored, some re-read the env on every config construction). This
//! module unifies them:
//!
//! * **Typed parsers** with **uniform error semantics**: an invalid or
//!   unparsable value never panics and never degrades a production
//!   deployment into an untested state. It falls back to the documented
//!   default and emits a single `tracing::warn!`.
//! * **Read once** at first access via [`std::sync::OnceLock`], so a
//!   knob has the same value for the whole process lifetime. (The few
//!   knobs that historically re-read the env on every config build are
//!   now read-once. This is observable only if some code changed the
//!   env between two builds in the same process, which never happens in
//!   production. See `docs/35-ENV-KNOBS.md`.)
//! * A single optional [`log_effective_overrides`] call logs the knobs
//!   that were actually overridden (never the defaults, never a secret).
//!
//! Only **tuning** knobs live here. Infrastructure variables (database
//! URLs, bind addresses, pubkey pins, enrollment tokens) and clap
//! `#[arg(env = ...)]` flags are NOT registered here: they have their
//! own validation at the binary boundary and are not data-plane levers.
//! See the "Not tuning knobs" section of `docs/35-ENV-KNOBS.md`.
//!
//! # Adding a knob
//!
//! 1. Add a `KnobMeta` entry to [`REGISTRY`].
//! 2. Add a typed accessor function that reads it once via `OnceLock`.
//! 3. Document it in `docs/35-ENV-KNOBS.md` (the
//!    `registry_matches_doc` test enforces this).

/// Static metadata for one tuning knob. Drives the anti-drift doc test
/// and the effective-override log.
#[derive(Debug, Clone, Copy)]
pub struct KnobMeta {
    /// Environment variable name, e.g. `"WARREN_CC"`.
    pub name: &'static str,
    /// Declared value type for the doc table (`"bool"`, `"u64"`, ...).
    pub kind: &'static str,
    /// Human-readable default for the doc table.
    pub default: &'static str,
    /// Human-readable clamp / validation for the doc table.
    pub clamp: &'static str,
    /// One-line effect description for the doc table.
    pub effect: &'static str,
    /// Owning crate / source path for the doc table.
    pub home: &'static str,
}

/// The full set of tuning knobs. The single source of truth: the
/// `docs/35-ENV-KNOBS.md` table is kept in sync by `registry_matches_doc`.
pub const REGISTRY: &[KnobMeta] = &[
    KnobMeta {
        name: "WARREN_CC",
        kind: "enum {bbr,cubic,newreno}",
        default: "bbr",
        clamp: "unknown name -> warn + bbr",
        effect: "QUIC congestion controller (A/B bench lever)",
        home: "warrenguard-transport-core/src/transport_config.rs",
    },
    KnobMeta {
        name: "WARREN_INITIAL_WINDOW",
        kind: "u64",
        default: "controller default",
        clamp: "must be > 0, else warn + ignore",
        effect: "congestion-controller initial window (bytes)",
        home: "warrenguard-transport-core/src/transport_config.rs",
    },
    KnobMeta {
        name: "WARREN_DG_SEND_BUF",
        kind: "usize (bytes)",
        default: "per-side default (client 4 MiB / exit 16 MiB)",
        clamp: "must be > 0, capped at 64 MiB",
        effect: "QUIC datagram send-buffer cap per connection",
        home: "warrenguard-transport-core/src/transport_config.rs",
    },
    KnobMeta {
        name: "WARREN_UPLINK_BATCH_MAX",
        kind: "usize",
        default: "1",
        clamp: "must be >= 1, capped at 1024",
        effect: "max TUN reads drained per uplink datagram batch",
        home: "warrenguard-pump/src/lib.rs",
    },
    KnobMeta {
        name: "WARREN_PATH_PROBE",
        kind: "bool",
        default: "on",
        clamp: "\"0\" disables, anything else enables",
        effect: "per-connection throughput/RTT probe logging",
        home: "warrenguard-transport-core/src/path_probe.rs",
    },
    KnobMeta {
        name: "WARREN_DEAD_PATH_SECS",
        kind: "u64 (seconds)",
        default: "15",
        clamp: "0 disables the watch; unparsable -> default",
        effect: "RX-silence window before the client redials",
        home: "warrenguard-transport/src/supervisor.rs",
    },
    KnobMeta {
        name: "WARREN_APP_DOWNLINK_DEAD_SECS",
        kind: "u64 (seconds)",
        default: "15",
        clamp: "0 disables the watch; unparsable -> default",
        effect: "one-way-traffic window (app datagrams up, none back) before the client redials",
        home: "warrenguard-transport/src/supervisor.rs",
    },
    KnobMeta {
        name: "WARREN_UPLINK_DEADPATH",
        kind: "bool",
        default: "off",
        clamp: "\"1\"/\"true\" enables, else off",
        effect: "enable the uplink-only dead-path watch",
        home: "warrenguard-transport/src/supervisor.rs",
    },
    KnobMeta {
        name: "WARREN_WORKER_THREADS",
        kind: "usize",
        default: "2",
        clamp: "must be >= 1; unparsable -> default",
        effect: "client tokio runtime worker-thread count",
        home: "warrenguard-config/src/knobs.rs (resolver only; deployer-wired, see docs/35-ENV-KNOBS.md)",
    },
    KnobMeta {
        name: "WARREN_IDLE_COVER",
        kind: "bool",
        default: "off",
        clamp: "\"1\"/\"true\" enables, else off",
        effect: "emit jittered, size-varied idle cover datagrams to mask the keep-alive beacon",
        home: "warrenguard-pump/src/idle_cover.rs",
    },
    KnobMeta {
        name: "WARREN_HS_RATE_BURST",
        kind: "u32",
        default: "512",
        clamp: "min 1; unparsable -> default",
        effect: "per-source-IP handshake token-bucket burst (CGNAT reconnect-wave allowance)",
        home: "warrenguard-config/src/knobs.rs (resolver only; deployer-wired, see docs/35-ENV-KNOBS.md)",
    },
    KnobMeta {
        name: "WARREN_HS_RATE_PER_SEC",
        kind: "u32",
        default: "256",
        clamp: "0 disables the per-IP limit; unparsable -> default",
        effect: "per-source-IP handshake token-bucket sustained refill rate (handshakes/s)",
        home: "warrenguard-config/src/knobs.rs (resolver only; deployer-wired, see docs/35-ENV-KNOBS.md)",
    },
    KnobMeta {
        name: "WARREN_EXIT_DATAPATH_SOCKETS",
        kind: "usize",
        default: "0 (auto = core count)",
        clamp: "0/unset -> host parallelism; clamped to [1, 32]",
        effect: "SO_REUSEPORT datapath sockets: shard the QUIC recv across N endpoint drivers to break the single-endpoint throughput ceiling",
        home: "warrenguard-config/src/knobs.rs (resolver only; deployer-wired, see docs/35-ENV-KNOBS.md)",
    },
    KnobMeta {
        name: "WARREN_CLIENT_DATAPATH_SOCKETS",
        kind: "usize",
        default: "auto (one endpoint per connection)",
        clamp: "unset/0 -> one per conn; else N; clamped to [1, num_conns]",
        effect: "client datapath UDP sockets/endpoints a multi-conn session spreads its connections across; auto = one source port per connection (distinct ports let the exit reuseport hash flows across cores and are required for the client multi-queue TUN downlink win, bench); 1 keeps a single NAT mapping",
        home: "warrenguard-transport/src/client.rs (connect_multi)",
    },
    KnobMeta {
        name: "WARREN_EXIT_TUN_QUEUES",
        kind: "usize",
        default: "1 (single queue, off)",
        clamp: "unset/0/garbage -> 1; else N; clamped to [1, 32]",
        effect: "multi-queue TUN (IFF_MULTI_QUEUE, Linux only): N kernel TUN queues, N downlink reader tasks + per-connection uplink writes spread round-robin across queues, to break the single-TUN-queue throughput ceiling that endpoint sharding alone cannot",
        home: "warrenguard-config/src/knobs.rs (resolver only; deployer-wired, see docs/35-ENV-KNOBS.md)",
    },
    KnobMeta {
        name: "WARREN_CLIENT_TUN_QUEUES",
        kind: "usize",
        default: "auto (min(cores, num_conns))",
        clamp: "unset/0 -> auto; else N; clamped to [1, 32]",
        effect: "client multi-queue TUN (IFF_MULTI_QUEUE, Linux only): N kernel TUN queues so a multi-conn session runs N uplink reader tasks + N downlink writers on distinct fds; auto opens min(cores, connections) queues (mono-conn stays single-queue). Breaks the single client-TUN-task chokepoint (bench: +64% downlink with client sockets)",
        home: "warrenguard-config/src/knobs.rs (resolver only; deployer-wired, see docs/35-ENV-KNOBS.md)",
    },
    KnobMeta {
        name: "WARREN_DAITA",
        kind: "bool",
        default: "off",
        clamp: "\"1\"/\"true\" enables, else off",
        effect: "request the DAITA traffic-analysis defense (Maybenot padding/dummies); mutually exclusive with idle cover (DAITA supersedes it)",
        home: "warrenguard-daita + warrenguard-pump (pump_*_with_daita)",
    },
];

// ---------------------------------------------------------------------
// Pure parser helpers. These take the raw `Option<&str>` (as returned
// by `std::env::var(...).ok()`) so they are fully testable without
// touching the process-global environment. Every accessor below routes
// through one of these, guaranteeing one error semantics for all knobs.
// ---------------------------------------------------------------------

/// Parses a boolean knob whose presence with `"1"` or `"true"`
/// (case-insensitive) means `true`. Any other value, or absence, yields
/// `default`. Never warns: a "1/true or off" knob has no invalid value.
#[must_use]
pub fn parse_bool_flag(raw: Option<&str>, default: bool) -> bool {
    match raw {
        Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        None => default,
    }
}

/// Parses a "disabled only by an explicit sentinel" boolean: the knob is
/// `true` (enabled) unless the value exactly equals `off_value`.
/// Used by `WARREN_PATH_PROBE` (`"0"` disables, default on).
#[must_use]
pub fn parse_enabled_unless(raw: Option<&str>, off_value: &str) -> bool {
    raw != Some(off_value)
}

/// Parses a `u64` knob. Unparsable values warn and fall back to
/// `default`. `name` is used only for the warning.
#[must_use]
pub fn parse_u64_or_default(name: &str, raw: Option<&str>, default: u64) -> u64 {
    match raw {
        None => default,
        Some(s) => match s.parse::<u64>() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(knob = name, value = s, "unparsable u64, using default");
                default
            }
        },
    }
}

/// Parses an optional positive `u64` knob. Absent or `<= 0` or
/// unparsable yields `None` (caller keeps its own default). Unparsable
/// non-empty values warn. Used by `WARREN_INITIAL_WINDOW`.
#[must_use]
pub fn parse_positive_u64_opt(name: &str, raw: Option<&str>) -> Option<u64> {
    match raw {
        None => None,
        Some(s) => match s.parse::<u64>() {
            Ok(v) if v > 0 => Some(v),
            Ok(_) => None,
            Err(_) => {
                tracing::warn!(knob = name, value = s, "unparsable u64, ignoring");
                None
            }
        },
    }
}

/// Parses a `usize` knob with an inclusive lower bound `min` and an
/// inclusive upper clamp `max`. Below `min`, unparsable, or absent
/// yields `default`. Above `max` is clamped down to `max`. Used by
/// `WARREN_UPLINK_BATCH_MAX` and `WARREN_WORKER_THREADS`.
#[must_use]
pub fn parse_usize_clamped(raw: Option<&str>, min: usize, max: usize, default: usize) -> usize {
    raw.and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= min)
        .map(|n| n.min(max))
        .unwrap_or(default)
}

/// Parses a positive `usize` byte-size knob clamped at `max`. Absent,
/// unparsable, or `0` yields `default`. Above `max` is clamped down.
/// Used by `WARREN_DG_SEND_BUF`.
#[must_use]
pub fn parse_positive_usize_clamped(raw: Option<&str>, max: usize, default: usize) -> usize {
    raw.and_then(|s| s.parse::<usize>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(max))
        .unwrap_or(default)
}

// ---------------------------------------------------------------------
// Typed accessors. Each reads its env var exactly once (OnceLock) and
// delegates to a pure helper above. These are the only sanctioned way
// for the rest of the workspace to read a tuning knob.
// ---------------------------------------------------------------------

/// Congestion controller selected by `WARREN_CC` (lower-cased name).
/// `None` => not set; the caller keeps BBR. The raw string is returned
/// so the transport crate can map it to its own `CcKind` without this crate
/// depending on quinn.
#[must_use]
pub fn cc_choice() -> Option<&'static str> {
    static CACHE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| std::env::var("WARREN_CC").ok())
        .as_deref()
}

/// `WARREN_INITIAL_WINDOW`: optional positive congestion-controller
/// initial window (bytes). `None` keeps the controller default.
#[must_use]
pub fn initial_window() -> Option<u64> {
    static CACHE: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_positive_u64_opt(
            "WARREN_INITIAL_WINDOW",
            std::env::var("WARREN_INITIAL_WINDOW").ok().as_deref(),
        )
    })
}

/// `WARREN_DG_SEND_BUF`: QUIC datagram send-buffer size in bytes, capped
/// at 64 MiB. `default` is the per-side production value the caller
/// passes (client 4 MiB / exit 16 MiB).
#[must_use]
pub fn datagram_send_buffer(default: usize) -> usize {
    const MAX_DG_SEND_BUF: usize = 64 * 1024 * 1024;
    static CACHE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    // Cache only the parsed override (independent of the caller's
    // default); apply the default at the boundary so both client and
    // exit defaults resolve correctly from one cached read.
    let override_val = *CACHE.get_or_init(|| {
        std::env::var("WARREN_DG_SEND_BUF")
            .ok()
            .as_deref()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .map(|v| v.min(MAX_DG_SEND_BUF))
    });
    override_val.unwrap_or(default)
}

/// `WARREN_UPLINK_BATCH_MAX`: max TUN reads drained per uplink batch.
/// Clamped to `[1, 1024]`, default `1`.
#[must_use]
pub fn uplink_batch_max() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_usize_clamped(
            std::env::var("WARREN_UPLINK_BATCH_MAX").ok().as_deref(),
            1,
            1024,
            1,
        )
    })
}

/// `WARREN_PATH_PROBE`: per-connection probe logging. On by default,
/// `"0"` disables.
#[must_use]
pub fn path_probe_enabled() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_enabled_unless(std::env::var("WARREN_PATH_PROBE").ok().as_deref(), "0")
    })
}

/// `WARREN_DEAD_PATH_SECS`: RX-silence window in seconds before the
/// client redials. Default `15`; `0` disables the watch.
#[must_use]
pub fn dead_path_secs() -> u64 {
    static CACHE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_u64_or_default(
            "WARREN_DEAD_PATH_SECS",
            std::env::var("WARREN_DEAD_PATH_SECS").ok().as_deref(),
            15,
        )
    })
}

/// `WARREN_APP_DOWNLINK_DEAD_SECS`: window in seconds during which the client
/// keeps sending application datagrams while not one application datagram
/// comes back, before it redials. Complements `WARREN_DEAD_PATH_SECS`, which
/// only sees transport-level RX silence: a relay that ACKs uplink packets but
/// forwards nothing keeps that watch blind while the tunnel carries zero
/// traffic (observed 2026-07-12). Default `15`; `0` disables the watch.
#[must_use]
pub fn app_downlink_dead_secs() -> u64 {
    static CACHE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_u64_or_default(
            "WARREN_APP_DOWNLINK_DEAD_SECS",
            std::env::var("WARREN_APP_DOWNLINK_DEAD_SECS")
                .ok()
                .as_deref(),
            15,
        )
    })
}

/// `WARREN_UPLINK_DEADPATH`: enable the uplink-only dead-path watch.
/// Off by default; `"1"`/`"true"` enables.
#[must_use]
pub fn uplink_deadpath_enabled() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_bool_flag(
            std::env::var("WARREN_UPLINK_DEADPATH").ok().as_deref(),
            false,
        )
    })
}

/// `WARREN_IDLE_COVER`: enable idle cover traffic. Off
/// by default; `"1"`/`"true"` enables. When on, the client pump emits a
/// jittered, size-varied dummy datagram during idle and the fixed
/// client keep-alive PING is disabled (the dummy refreshes the NAT
/// mapping and the 25s idle timeout still detects a dead exit), removing
/// the fixed keep-alive beacon. Requires the runtime to run
/// `warrenguard_pump::pump_bidirectional_with_idle_cover` together with a
/// client transport config built via
/// `warren_transport_config_client_with_idle_cover(.., true)`; enabling
/// this knob without both leaves the connection with no keep-alive.
#[must_use]
pub fn idle_cover_enabled() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE
        .get_or_init(|| parse_bool_flag(std::env::var("WARREN_IDLE_COVER").ok().as_deref(), false))
}

/// `WARREN_DAITA`: request the DAITA traffic-analysis defense. Off by
/// default; `"1"`/`"true"` enables. When on, the client advertises
/// `Setup::daita_support` so the exit assigns a per-session Maybenot machine
/// config (padding + dummy datagrams, bidirectional) applied by the
/// `pump_*_with_daita` variants. DAITA and idle cover are mutually exclusive
/// covers: DAITA already emits `0xFF` cover datagrams that mask the idle
/// keep-alive, so idle cover is suppressed whenever DAITA is requested (see
/// [`cover_defenses`]). Off keeps the default path byte-identical.
#[must_use]
pub fn daita_requested() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| parse_bool_flag(std::env::var("WARREN_DAITA").ok().as_deref(), false))
}

/// The two traffic-analysis cover defenses, resolved together so the
/// mutually-exclusive-cover invariant lives in ONE place instead of being
/// re-derived (and mis-derived) at each call site.
///
/// `daita` and `idle_cover` are NEVER both true: DAITA emits its own `0xFF`
/// cover substrate that already masks the idle keep-alive, so turning DAITA on
/// suppresses idle cover. This is the structural guard against the foot-gun the
/// traffic-analysis plan calls out (a Stealth session left with no liveness cover
/// because the two flips disagreed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverDefenses {
    /// DAITA (Maybenot) padding + dummy defense is requested.
    pub daita: bool,
    /// Jittered idle cover replaces the keep-alive beacon. Only ever true when
    /// `daita` is false.
    pub idle_cover: bool,
}

/// Resolve the coupled cover-defense decision from the `WARREN_DAITA` and
/// `WARREN_IDLE_COVER` knobs, enforcing the mutual exclusion (DAITA supersedes
/// idle cover). This is the single source of truth for "what covers are on".
#[must_use]
pub fn cover_defenses() -> CoverDefenses {
    resolve_cover_defenses(daita_requested(), idle_cover_enabled())
}

/// Pure resolution of the mutual-exclusion rule, split out so it is testable
/// without touching the process-global (OnceLock-cached) env accessors.
#[must_use]
pub fn resolve_cover_defenses(daita: bool, idle_cover_knob: bool) -> CoverDefenses {
    CoverDefenses {
        daita,
        idle_cover: idle_cover_knob && !daita,
    }
}

/// `WARREN_WORKER_THREADS`: client tokio runtime worker-thread count.
/// At least `1`, default `2`.
///
/// This resolver has no in-repo caller: no engine crate builds a tokio
/// `Runtime` (they run inside whatever runtime the caller provides). A
/// deployer's own binary calls this resolver and passes the result to its
/// `tokio::runtime::Builder::worker_threads`. See the "Deployer-wired knobs"
/// section of `docs/35-ENV-KNOBS.md`.
#[must_use]
pub fn worker_threads() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_usize_clamped(
            std::env::var("WARREN_WORKER_THREADS").ok().as_deref(),
            1,
            usize::MAX,
            2,
        )
    })
}

/// `WARREN_HS_RATE_BURST`: per-source-IP handshake token-bucket burst
/// capacity. At least `1`, default `512`. Generous by design: it is only
/// the per-IP fairness layer, not the aggregate cost ceiling (that is the
/// global concurrent-handshake semaphore), so it must absorb CGNAT
/// reconnect waves rather than throttle them.
///
/// This resolver has no in-repo caller: `ExitBindOpts::default()` is
/// deliberately a fixed value for back-compat (see
/// `exit::tests::exit_bind_opts_default_handshake_rate_limit_is_the_fixed_engine_default`
/// in `warrenguard-server`). A deployer's own exit binary calls this
/// resolver and builds its own `HandshakeRateLimit` to make the knob live.
/// See the "Deployer-wired knobs" section of `docs/35-ENV-KNOBS.md`.
#[must_use]
pub fn handshake_rate_burst() -> u32 {
    static CACHE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        u32::try_from(parse_usize_clamped(
            std::env::var("WARREN_HS_RATE_BURST").ok().as_deref(),
            1,
            u32::MAX as usize,
            512,
        ))
        .unwrap_or(512)
    })
}

/// `WARREN_HS_RATE_PER_SEC`: per-source-IP handshake token-bucket sustained
/// refill rate (handshakes/second). Default `256`; `0` disables the per-IP
/// limit entirely (the global concurrent-handshake semaphore still applies).
///
/// Has no in-repo caller for the same reason as [`handshake_rate_burst`]: a
/// deployer's own exit binary is expected to call this resolver and act on
/// it. See the "Deployer-wired knobs" section of `docs/35-ENV-KNOBS.md`.
#[must_use]
pub fn handshake_rate_per_sec() -> u32 {
    static CACHE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        u32::try_from(parse_usize_clamped(
            std::env::var("WARREN_HS_RATE_PER_SEC").ok().as_deref(),
            0,
            u32::MAX as usize,
            256,
        ))
        .unwrap_or(256)
    })
}

/// Upper bound on datapath sockets: beyond one per core there is no recv
/// parallelism to gain, and each socket costs an endpoint driver task. 32
/// covers the largest exits we deploy with headroom.
const MAX_DATAPATH_SOCKETS: usize = 32;

/// Resolves the raw `WARREN_EXIT_DATAPATH_SOCKETS` value against the host core
/// count: `0` (unset/auto) means one socket per core, an explicit value is
/// taken as-is; both are clamped to `[1, MAX_DATAPATH_SOCKETS]`. Pure so the
/// auto/explicit/clamp behaviour is testable without touching the environment
/// or the real core count.
fn resolve_datapath_sockets(raw: usize, cores: usize) -> usize {
    let n = if raw == 0 { cores } else { raw };
    n.clamp(1, MAX_DATAPATH_SOCKETS)
}

/// `WARREN_EXIT_DATAPATH_SOCKETS`: number of `SO_REUSEPORT` datapath sockets
/// the exit binds (see `warrenguard_server::ExitBindOpts::datapath_sockets`).
/// `0`/unset = auto = the host's available parallelism (core count); an
/// explicit `N` is honoured. Both are clamped to `[1, 32]`. This shards the
/// QUIC recv across cores, the lever that breaks the single-endpoint
/// throughput ceiling.
///
/// This resolver has no in-repo caller: `ExitBindOpts::default()` deliberately
/// stays a single socket for back-compat (see
/// `reuseport_multi_endpoint::default_bind_opts_keep_a_single_datapath_socket`
/// in `warrenguard-server`). A deployer's own exit binary calls this
/// resolver and sets `ExitBindOpts::datapath_sockets` explicitly to opt into
/// sharding. See the "Deployer-wired knobs" section of `docs/35-ENV-KNOBS.md`.
#[must_use]
pub fn exit_datapath_sockets() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        let raw = parse_usize_clamped(
            std::env::var("WARREN_EXIT_DATAPATH_SOCKETS")
                .ok()
                .as_deref(),
            0,
            MAX_DATAPATH_SOCKETS,
            0,
        );
        let cores = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        resolve_datapath_sockets(raw, cores)
    })
}

/// Resolves the raw `WARREN_CLIENT_DATAPATH_SOCKETS` value against a session's
/// connection count: `0` (unset/auto) gives one endpoint per connection, an
/// explicit value is honoured; both are clamped to `[1, num_conns]` (there is
/// no gain from more endpoints than connections). Pure for testability.
fn resolve_client_datapath_sockets(raw: usize, num_conns: usize) -> usize {
    let conns = num_conns.max(1);
    let n = if raw == 0 { conns } else { raw };
    n.clamp(1, conns)
}

/// `WARREN_CLIENT_DATAPATH_SOCKETS`: number of client datapath UDP
/// sockets/endpoints a multi-conn session spreads its connections across (see
/// `connect_multi`). **Unset defaults to auto** = one endpoint per connection:
/// distinct source ports let the exit's `SO_REUSEPORT` group hash flows across
/// cores AND are required for the client multi-queue TUN downlink win (the
/// bench needed both together for the full +64 %: multi-queue alone
/// gave +20 %). Re-enabled alongside `WARREN_CLIENT_TUN_QUEUES` (it was off in
/// part 1 when it bought nothing and cost 8x NAT mappings; the throughput gain
/// now justifies the footprint). An explicit `N` is honoured; `1` keeps a single
/// socket. Resolved against the connection count by
/// [`resolve_client_datapath_sockets`].
#[must_use]
pub fn client_datapath_sockets_raw() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_usize_clamped(
            std::env::var("WARREN_CLIENT_DATAPATH_SOCKETS")
                .ok()
                .as_deref(),
            0,
            MAX_DATAPATH_SOCKETS,
            0,
        )
    })
}

/// Effective client datapath endpoint count for a session of `num_conns`
/// connections, applying the `WARREN_CLIENT_DATAPATH_SOCKETS` knob.
#[must_use]
pub fn client_datapath_sockets(num_conns: usize) -> usize {
    resolve_client_datapath_sockets(client_datapath_sockets_raw(), num_conns)
}

/// Upper bound on TUN queues. Beyond ~one queue per core the per-queue reader
/// tasks stop adding read parallelism and each queue costs a kernel fd + task;
/// 32 matches the largest dedicated-vCPU boxes we bench/deploy with
/// headroom.
const MAX_TUN_QUEUES: usize = 32;

/// `WARREN_EXIT_TUN_QUEUES`: number of `IFF_MULTI_QUEUE` TUN queues the exit
/// opens (Linux only). **Unset defaults to `1`** (a single queue = the historic
/// single-reader/single-writer TUN path): multi-queue is opt-in because it is a
/// brand-new, Linux-only datapath change validated on real exits before it
/// becomes a default. An explicit `N` opens N kernel queues; the exit then runs
/// one downlink reader task per queue and spreads per-connection uplink writes
/// round-robin across them, removing the single-TUN-queue serialization point
/// that `SO_REUSEPORT` endpoint sharding alone leaves in place. Clamped to
/// `[1, 32]`. On non-Linux the requested count is silently capped to what the
/// platform can create (one queue).
///
/// This resolver has no in-repo caller: `ExitListener::accept_forever_with_tun_queues`
/// takes an already-opened `Vec<T>` of TUN queues, and opening N platform TUN
/// fds is device code the engine does not own. A deployer's own binary calls
/// this resolver, opens that many queues, and hands the `Vec` to
/// `accept_forever_with_tun_queues`. See the "Deployer-wired knobs" section of
/// `docs/35-ENV-KNOBS.md`.
#[must_use]
pub fn exit_tun_queues() -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        parse_usize_clamped(
            std::env::var("WARREN_EXIT_TUN_QUEUES").ok().as_deref(),
            1,
            MAX_TUN_QUEUES,
            1,
        )
    })
}

/// Resolves the raw `WARREN_CLIENT_TUN_QUEUES` value against the host core count
/// and the session's connection count: `0` (unset/auto) opens
/// `min(cores, num_conns)` queues (one per core up to one per connection, so a
/// mono-conn session stays single-queue and an N-conn session on an N-core host
/// gets N), an explicit value is honoured; both are clamped to
/// `[1, MAX_TUN_QUEUES]`. Pure for testability. Non-Linux collapses to one queue
/// in `RealTun` regardless.
fn resolve_client_tun_queues(raw: usize, cores: usize, num_conns: usize) -> usize {
    let cap = num_conns.max(1);
    let n = if raw == 0 { cores.min(cap) } else { raw };
    n.clamp(1, MAX_TUN_QUEUES)
}

/// `WARREN_CLIENT_TUN_QUEUES`: number of `IFF_MULTI_QUEUE` TUN queues the client
/// opens (Linux only), so a multi-conn session runs N uplink reader tasks and N
/// downlink writers on distinct fds. This breaks the single client-TUN-task
/// chokepoint the real-exit bench localised as the single-client throughput wall
/// (+64 % downlink; exit-side sharding and multi-queue left it
/// untouched). **Unset defaults to auto** = `min(cores, num_conns)`: a mono-conn
/// session stays single-queue (no change), an N-conn session parallelises up to
/// the core count. An explicit `N` is honoured; `1` disables. Clamped to
/// `[1, 32]`; non-Linux caps to one queue in `RealTun`.
///
/// This resolver has no in-repo caller: `pump_multi_bidirectional_queues` takes
/// an already-opened `Vec<T>` of TUN queues, and opening N platform TUN fds is
/// device code the engine does not own. A deployer's own client binary calls
/// this resolver, opens that many queues, and hands the `Vec` to the pump. See
/// the "Deployer-wired knobs" section of `docs/35-ENV-KNOBS.md`.
#[must_use]
pub fn client_tun_queues(num_conns: usize) -> usize {
    static CACHE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let raw = *CACHE.get_or_init(|| {
        parse_usize_clamped(
            std::env::var("WARREN_CLIENT_TUN_QUEUES").ok().as_deref(),
            0,
            MAX_TUN_QUEUES,
            0,
        )
    });
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    resolve_client_tun_queues(raw, cores, num_conns)
}

/// Logs every knob in [`REGISTRY`] that is currently set in the
/// environment to a non-empty value. Logs the value as-is: every
/// registered knob is a tuning lever, never a secret. Defaults are not
/// logged (only real overrides).
///
/// Has no in-repo caller: this is a boot-time convenience the deployer's own
/// binary is expected to call once, early in `main`, if it wants the active
/// overrides in its startup log; it is a no-op when no knob is overridden.
pub fn log_effective_overrides() {
    for meta in REGISTRY {
        if let Ok(v) = std::env::var(meta.name)
            && !v.is_empty()
        {
            tracing::info!(knob = meta.name, value = %v, "tuning knob override active");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daita_supersedes_idle_cover_when_both_requested() {
        // The load-bearing invariant: DAITA and idle cover are never both on.
        // DAITA already emits its own cover substrate, so idle cover is
        // suppressed whenever DAITA is requested.
        let both = resolve_cover_defenses(true, true);
        assert!(both.daita, "DAITA stays on when requested");
        assert!(
            !both.idle_cover,
            "idle cover MUST be suppressed while DAITA is on (mutually exclusive covers)"
        );
    }

    #[test]
    fn idle_cover_runs_only_when_daita_is_off() {
        assert_eq!(
            resolve_cover_defenses(false, true),
            CoverDefenses {
                daita: false,
                idle_cover: true
            },
            "with DAITA off, the idle-cover knob decides idle cover"
        );
        assert_eq!(
            resolve_cover_defenses(false, false),
            CoverDefenses {
                daita: false,
                idle_cover: false
            },
            "neither cover on when both knobs are off (default path)"
        );
    }

    #[test]
    fn bool_flag_recognizes_one_and_true_case_insensitively() {
        assert!(parse_bool_flag(Some("1"), false));
        assert!(parse_bool_flag(Some("true"), false));
        assert!(parse_bool_flag(Some("TRUE"), false));
        assert!(parse_bool_flag(Some("True"), false));
    }

    #[test]
    fn bool_flag_rejects_other_values_to_false_when_default_false() {
        assert!(!parse_bool_flag(Some("0"), false));
        assert!(!parse_bool_flag(Some("yes"), false));
        assert!(!parse_bool_flag(Some(""), false));
    }

    #[test]
    fn bool_flag_uses_default_when_absent() {
        assert!(!parse_bool_flag(None, false));
        assert!(parse_bool_flag(None, true));
    }

    #[test]
    fn enabled_unless_off_value_only_off_disables() {
        assert!(!parse_enabled_unless(Some("0"), "0"));
        assert!(parse_enabled_unless(Some("1"), "0"));
        assert!(parse_enabled_unless(Some("anything"), "0"));
        // Absent keeps the on default.
        assert!(parse_enabled_unless(None, "0"));
    }

    #[test]
    fn u64_or_default_parses_and_falls_back() {
        assert_eq!(parse_u64_or_default("X", Some("42"), 15), 42);
        assert_eq!(parse_u64_or_default("X", Some("0"), 15), 0);
        assert_eq!(parse_u64_or_default("X", None, 15), 15);
    }

    #[test]
    fn datapath_sockets_auto_follows_core_count_and_clamps() {
        // 0 = auto: one socket per core.
        assert_eq!(resolve_datapath_sockets(0, 8), 8);
        assert_eq!(resolve_datapath_sockets(0, 1), 1);
        // Auto never yields zero even on a (impossible) zero-core report.
        assert_eq!(resolve_datapath_sockets(0, 0), 1);
        // Auto is capped so a huge machine does not spawn absurd endpoints.
        assert_eq!(resolve_datapath_sockets(0, 128), MAX_DATAPATH_SOCKETS);
    }

    #[test]
    fn datapath_sockets_explicit_value_overrides_cores_but_is_clamped() {
        // An explicit count ignores the core count.
        assert_eq!(resolve_datapath_sockets(4, 8), 4);
        assert_eq!(resolve_datapath_sockets(16, 2), 16);
        // Explicit is clamped to the same [1, MAX] range.
        assert_eq!(resolve_datapath_sockets(1, 8), 1);
        assert_eq!(resolve_datapath_sockets(999, 8), MAX_DATAPATH_SOCKETS);
    }

    #[test]
    fn client_datapath_sockets_auto_is_one_endpoint_per_conn() {
        // 0 = auto: one endpoint per connection.
        assert_eq!(resolve_client_datapath_sockets(0, 8), 8);
        assert_eq!(resolve_client_datapath_sockets(0, 1), 1);
        // A single-conn client always resolves to exactly one endpoint.
        assert_eq!(resolve_client_datapath_sockets(0, 0), 1);
    }

    #[test]
    fn client_tun_queues_auto_is_min_cores_and_conns() {
        // Auto (raw 0): one queue per core, capped at one per connection.
        assert_eq!(resolve_client_tun_queues(0, 8, 8), 8);
        assert_eq!(
            resolve_client_tun_queues(0, 4, 8),
            4,
            "fewer cores than conns"
        );
        assert_eq!(
            resolve_client_tun_queues(0, 8, 2),
            2,
            "fewer conns than cores"
        );
        // A mono-conn session stays single-queue under auto (no multi-queue).
        assert_eq!(resolve_client_tun_queues(0, 8, 1), 1);
        // Degenerate zero-conn report never yields zero queues.
        assert_eq!(resolve_client_tun_queues(0, 8, 0), 1);
    }

    #[test]
    fn client_tun_queues_explicit_overrides_auto_but_is_clamped() {
        // An explicit count ignores cores/conns (an operator override).
        assert_eq!(resolve_client_tun_queues(4, 8, 8), 4);
        assert_eq!(resolve_client_tun_queues(1, 8, 8), 1, "explicit 1 disables");
        // Clamped to [1, MAX_TUN_QUEUES].
        assert_eq!(resolve_client_tun_queues(999, 8, 8), MAX_TUN_QUEUES);
    }

    #[test]
    fn client_datapath_sockets_explicit_is_clamped_to_conn_count() {
        // Fewer endpoints than conns: conns share endpoints round-robin.
        assert_eq!(resolve_client_datapath_sockets(2, 8), 2);
        // Never more endpoints than connections (no gain past one-per-conn).
        assert_eq!(resolve_client_datapath_sockets(16, 4), 4);
        assert_eq!(resolve_client_datapath_sockets(1, 8), 1);
    }

    #[test]
    fn u64_or_default_uses_default_on_garbage_without_panic() {
        assert_eq!(parse_u64_or_default("X", Some("not-a-number"), 15), 15);
        assert_eq!(parse_u64_or_default("X", Some("-5"), 15), 15);
        assert_eq!(parse_u64_or_default("X", Some(""), 15), 15);
    }

    #[test]
    fn positive_u64_opt_requires_strictly_positive() {
        assert_eq!(parse_positive_u64_opt("X", Some("100")), Some(100));
        assert_eq!(parse_positive_u64_opt("X", Some("0")), None);
        assert_eq!(parse_positive_u64_opt("X", None), None);
    }

    #[test]
    fn positive_u64_opt_ignores_garbage_without_panic() {
        assert_eq!(parse_positive_u64_opt("X", Some("abc")), None);
        assert_eq!(parse_positive_u64_opt("X", Some("-1")), None);
    }

    #[test]
    fn usize_clamped_honors_min_max_and_default() {
        // Within range: kept as-is.
        assert_eq!(parse_usize_clamped(Some("4"), 1, 1024, 1), 4);
        // Below min: default.
        assert_eq!(parse_usize_clamped(Some("0"), 1, 1024, 1), 1);
        // Above max: clamped to max.
        assert_eq!(parse_usize_clamped(Some("99999"), 1, 1024, 1), 1024);
        // Exactly at the bounds.
        assert_eq!(parse_usize_clamped(Some("1"), 1, 1024, 1), 1);
        assert_eq!(parse_usize_clamped(Some("1024"), 1, 1024, 1), 1024);
        // Absent / garbage: default.
        assert_eq!(parse_usize_clamped(None, 1, 1024, 7), 7);
        assert_eq!(parse_usize_clamped(Some("nope"), 1, 1024, 7), 7);
    }

    #[test]
    fn positive_usize_clamped_caps_and_rejects_zero() {
        let max = 64 * 1024 * 1024;
        assert_eq!(
            parse_positive_usize_clamped(Some("8388608"), max, 4096),
            8_388_608
        );
        // Zero -> default.
        assert_eq!(parse_positive_usize_clamped(Some("0"), max, 4096), 4096);
        // Over cap -> clamped to max.
        assert_eq!(
            parse_positive_usize_clamped(Some("999999999"), max, 4096),
            max
        );
        // Absent / garbage -> default.
        assert_eq!(parse_positive_usize_clamped(None, max, 4096), 4096);
        assert_eq!(parse_positive_usize_clamped(Some("x"), max, 4096), 4096);
    }

    #[test]
    fn registry_names_are_unique() {
        let mut names: Vec<&str> = REGISTRY.iter().map(|k| k.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate knob name in REGISTRY");
    }

    #[test]
    fn registry_names_are_warren_prefixed() {
        for k in REGISTRY {
            assert!(
                k.name.starts_with("WARREN_"),
                "knob {} must be WARREN_ prefixed",
                k.name
            );
        }
    }
}
