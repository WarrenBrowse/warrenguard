# 35 - Environment knobs (`WARREN_*` tuning variables)

Warren's data-plane and transport behaviour can be tuned at runtime
through a small set of `WARREN_*` environment variables. Historically
each one was parsed ad-hoc at its call site with inconsistent error
semantics. They are now centralized in the registry module
[`crates/warrenguard-config/src/knobs.rs`](../crates/warrenguard-config/src/knobs.rs).

The registry is the single source of truth. This document is kept in
sync with it by the `registry_matches_doc` test in `warrenguard-config`: every
knob in `REGISTRY` must appear in the table below, or the test fails.

## Semantics (uniform across all knobs)

- Each knob is **read once** at first access (via `OnceLock`) and keeps
  that value for the whole process lifetime. Setting or changing a knob
  after the process has read it has no effect.
- An **invalid / unparsable value never panics** and never degrades a
  production deployment into an untested configuration: the knob falls
  back to its documented default and emits a single `tracing::warn!`.
- `knobs::log_effective_overrides()` has no in-repo caller: it is a
  boot-time convenience a deployer's own binary can call once, early in
  `main`, to log every knob that was actually overridden (defaults are
  never logged; every registered knob is a tuning lever, never a secret).
- Every knob in `REGISTRY` falls into one of two categories, split into the
  two tables below:
  - **Tuning knobs**: an engine crate reads the resolver itself (the `home`
    column names the call site), so setting the environment variable on any
    binary that links that crate changes its behaviour with zero extra code.
  - **Deployer-wired knobs**: the registry and the typed resolver live here,
    but no engine crate calls the resolver. Either the effect they tune
    (opening N platform TUN queues, sizing a tokio `Runtime`) is inherently
    something only the deployer's own binary can do (it owns the TUN device
    code / builds the runtime, not this crate), or the value feeds an engine
    `Default` impl that existing deployers/tests rely on staying fixed (see
    e.g. `ExitBindOpts::default()`), so the knob is wired by the deployer
    explicitly overriding that field instead. Setting the environment
    variable alone is a silent no-op until the deployer's binary calls the
    resolver and acts on the result; see the column for exactly where.

> Note on read-once: three transport knobs (`WARREN_CC`,
> `WARREN_INITIAL_WINDOW`, `WARREN_DG_SEND_BUF`) were previously re-read
> on every transport-config construction. They are now read once. This
> is observable only if some code changed the env between two config
> builds inside the same process, which never happens in production
> (knobs are set before launch). Defaults and clamps are unchanged.

## Tuning knobs

| Variable | Type | Default | Clamp / validation | Effect | Home |
|---|---|---|---|---|---|
| `WARREN_CC` | enum {bbr,cubic,newreno} | bbr | unknown name -> warn + bbr | QUIC congestion controller (A/B bench lever) | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_INITIAL_WINDOW` | u64 | 32 packets (~IW10-class) | must be > 0, else warn + ignore | congestion-controller initial window (bytes) | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_DG_SEND_BUF` | usize (bytes) | per-side default (client 4 MiB / exit 16 MiB) | must be > 0, capped at 64 MiB | QUIC datagram send-buffer cap per connection | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_DG_AQM` | bool | on | "0"/"false"/"no"/"off" disables, else on | CoDel AQM on the QUIC datagram send queue (bounds queue latency on slow last miles) | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_DG_AQM_TARGET_MS` | u64 (ms) | 15 | clamped to [1, 1000]; unparsable -> default | AQM sojourn-time target: queue latency persistently above it starts head-dropping | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_DG_AQM_INTERVAL_MS` | u64 (ms) | 100 | clamped to [10, 10000]; unparsable -> default | AQM grace window before the first drop and base period of the drop-rate ramp | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_DG_FQ_QUEUES` | usize | 1024 | clamped to [1, 65536]; unparsable -> default | flow-queue count of the datagram send AQM (FQ-CoDel per-flow fairness); 1 = single shared queue (plain CoDel fallback) | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_DG_BDP_BUF` | bool | on | "0"/"false"/"no"/"off" disables, else on | BDP-adaptive datagram send-buffer sizing (shrinks the fixed 4/16 MiB cap toward the path's measured BDP) | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_DG_BDP_MULT` | u64 | 4 | clamped to [1, 64]; unparsable -> default | adaptive send-buffer size as a multiple of the smoothed BDP estimate | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_DG_BDP_FLOOR` | usize (bytes) | 1048576 (1 MiB) | clamped to [16384, 64 MiB]; unparsable -> default | lower bound of the adaptive send buffer (ramp-up and tiny-BDP guard) | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_EXIT_OVERREAD_GATE` | usize (MTUs) | 4 (on) | 0 disables; clamped to [0, 64]; unparsable/absent -> default | exit downlink over-read backpressure: tail-drop a NEW downlink packet when the destination connection's datagram send buffer has less than N MTUs of space left (relative to the BDP-adaptive limit), so N multi-queue TUN readers cannot over-fill the buffer into the CoDel oldest-first head-drop zone that spikes inner-TCP retransmits | warrenguard-multihop-server/src/multihop.rs (downlink tx_task) |
| `WARREN_UPLINK_BATCH_MAX` | usize | 1 | must be >= 1, capped at 1024 | max TUN reads drained per uplink datagram batch | warrenguard-pump/src/lib.rs |
| `WARREN_PATH_PROBE` | bool | on | "0" disables, anything else enables | per-connection throughput/RTT probe logging | warrenguard-transport-core/src/path_probe.rs |
| `WARREN_DEAD_PATH_SECS` | u64 (seconds) | 15 | 0 disables the watch; unparsable -> default | RX-silence window before the client redials | warrenguard-transport/src/supervisor.rs |
| `WARREN_APP_DOWNLINK_DEAD_SECS` | u64 (seconds) | 15 | 0 disables the watch; unparsable -> default | one-way-traffic window (app datagrams up, none back) before the client redials | warrenguard-transport/src/supervisor.rs |
| `WARREN_UPLINK_DEADPATH` | bool | off | "1"/"true" enables, else off | enable the uplink-only dead-path watch | warrenguard-transport/src/supervisor.rs |
| `WARREN_IDLE_COVER` | bool | on | "0"/"false"/"no"/"off" disables, else on | emit jittered, size-varied idle cover datagrams to mask the keep-alive beacon | warrenguard-pump/src/idle_cover.rs |
| `WARREN_DAITA` | bool | off | "1"/"true" enables, else off | request the DAITA traffic-analysis defense (Maybenot padding/dummies); mutually exclusive with idle cover (DAITA supersedes it) | warrenguard-daita + warrenguard-pump (pump_*_with_daita) |
| `WARREN_CLIENT_DATAPATH_SOCKETS` | usize | auto (one endpoint per connection) | unset/0 -> one per conn; else N; clamped to [1, num_conns] | client datapath UDP sockets/endpoints a multi-conn session spreads its connections across; auto = one source port per connection (distinct ports let the exit reuseport hash flows across cores and are required for the client multi-queue TUN downlink win, bench); 1 keeps a single NAT mapping | warrenguard-transport/src/client.rs (connect_multi) |
| `WARREN_TUNNEL_INITIAL_MTU` | u16 | 1280 (TUNNEL_INITIAL_MTU) | clamped to [1200, 1280]; unparsable/absent -> default | client outer QUIC initial MTU + Initial-pad size; a client nested inside a full-tunnel system VPN lowers it below the nested cap so the data plane does not black-hole (quinn's DPLPMTUD only probes upward, never below its floor) | warrenguard-transport-core/src/transport_config.rs |
| `WARREN_MULTIHOP_CONNS` | usize | 0 (deployer-configured n_connections) | unset/0/garbage -> deployer value; else clamped to [1, 8] | bonded QUIC connections per multi-hop session (overrides the deployer's `SupervisorConfig::n_connections` for A/B rollouts without a rebuild); N sessions under one identity share one inner IP, flows shard sticky per 5-tuple | warrenguard-transport/src/supervisor.rs |
| `WARREN_ENABLE_TCP_FALLBACK` | bool | on | "0"/"false"/"no"/"off" disables, else on | arm the TLS-over-TCP fallback carrier when the exit advertises it and carries a cover domain; fail-closed (disabled keeps the plain UDP dial and never opens :443/tcp) | warrenguard-transport/src/multihop.rs (dial_relay) |
| `WARREN_TCP_FALLBACK_RACE_MS` | u64 (ms) | 400 | clamped to [100, 5000]; unparsable/absent -> default | head start the UDP handshake gets before the armed TCP carrier is dialled in parallel; first successful handshake wins (the 5s UDP deadline is the overall guard) | warrenguard-transport/src/multihop.rs (dial_relay_with_carrier) |

## Deployer-wired knobs

These knobs are registered in `REGISTRY` and have a typed resolver in
`knobs.rs`, exactly like the tuning knobs above, but **no engine crate calls
that resolver**. This is by design, not an oversight: each one tunes something
only the deployer's own binary can decide (open N platform TUN device queues,
build a tokio `Runtime`, or override an `ExitBindOpts` field that must
otherwise stay at a fixed back-compat-safe default) because the engine code
that would consume the value either is generic over an already-constructed
input it does not build itself, or is a `Default` impl that existing
deployers/tests rely on staying unchanged. Setting the environment variable
alone is a **silent no-op** until the deployer's binary calls the resolver
below and acts on the result.

| Variable | Type | Default | Clamp / validation | Effect | Resolver (call it yourself) |
|---|---|---|---|---|---|
| `WARREN_WORKER_THREADS` | usize | 2 | must be >= 1; unparsable -> default | client tokio runtime worker-thread count | `knobs::worker_threads()` -> pass to `tokio::runtime::Builder::worker_threads` |
| `WARREN_HS_RATE_BURST` | u32 | 512 | min 1; unparsable -> default | per-source-IP handshake token-bucket burst (CGNAT reconnect-wave allowance) | `knobs::handshake_rate_burst()` -> build `ExitBindOpts { handshake_rate_limit: Some(HandshakeRateLimit::new(..)), .. }` |
| `WARREN_HS_RATE_PER_SEC` | u32 | 256 | 0 disables the per-IP limit; unparsable -> default | per-source-IP handshake token-bucket sustained refill rate (handshakes/s) | `knobs::handshake_rate_per_sec()` -> same as above; `0` means pass `handshake_rate_limit: None` |
| `WARREN_EXIT_DATAPATH_SOCKETS` | usize | 0 (auto = core count) | 0/unset -> host parallelism; clamped to [1, 32] | SO_REUSEPORT datapath sockets: shard the QUIC recv across N endpoint drivers to break the single-endpoint throughput ceiling | `knobs::exit_datapath_sockets()` -> set `ExitBindOpts::datapath_sockets` explicitly (the engine `Default` stays a single socket for back-compat) |
| `WARREN_EXIT_TUN_QUEUES` | usize | 1 (single queue, off) | unset/0/garbage -> 1; else N; clamped to [1, 32] | multi-queue TUN (IFF_MULTI_QUEUE, Linux only): N kernel TUN queues, N downlink reader tasks + per-connection uplink writes spread round-robin across queues, to break the single-TUN-queue throughput ceiling that endpoint sharding alone cannot | `knobs::exit_tun_queues()` -> `RealTun::create_multi_queue_named` opens that many queues; keep queue 0 as the `ExitTerminateCtx::new` primary and pass the rest to `ExitTerminateCtx::with_extra_tun_queues` |
| `WARREN_CLIENT_TUN_QUEUES` | usize | auto (min(cores, num_conns)) | unset/0 -> auto; else N; clamped to [1, 32] | client multi-queue TUN (IFF_MULTI_QUEUE, Linux only): N kernel TUN queues so a multi-conn session runs N uplink reader tasks + N downlink writers on distinct fds; auto opens min(cores, connections) (mono-conn stays single-queue). Breaks the single client-TUN-task chokepoint (bench: +64% downlink with client sockets) | `knobs::client_tun_queues(num_conns)` -> open that many TUN queues, pass the `Vec` to `pump_multi_bidirectional_queues` |

## Not tuning knobs

Not every `WARREN_*` variable is a data-plane tuning lever. A consumer binary
(an exit, a client, or a control-plane service built on the engine) defines its
own `WARREN_*` clap arguments, trust pins, and secrets, validated at that
binary's boundary and documented by the consumer, not here. Only the registry
above is an engine tuning surface; anything a consumer adds outside it is
intentionally not in this table, and secret-bearing values must never be logged.

The engine's own build-metadata variables (`WARREN_GIT_SHA`, `WARREN_RELEASE`,
`WARREN_BUILD_TIME`) are stamped at build time by `warrenguard-buildinfo`, not
read at runtime.

## Adding a tuning knob

1. Add a `KnobMeta` entry to `REGISTRY` in `knobs.rs`.
2. Add a typed accessor that reads it once via `OnceLock` and delegates
   to a pure parser helper.
3. Add a row to the "Tuning knobs" table above (the `registry_matches_doc`
   test enforces this).
