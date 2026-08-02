# ADR-0006: The keep-alive PING as a passive traffic-analysis tell

Status: accepted (the tell is recorded and characterized; mitigation B2-lite is
IMPLEMENTED as an opt-in engine capability behind `WARREN_IDLE_COVER`, off by
default. Turning it on by default remains gated on a real-network bench.)
Date: 2026-06-24
Related: ADR-0002 (active-probing threat model), ADR-0004 (QUIC fingerprint
parity), ADR-0005 (decoy feasibility / RPK tell), ADR-0001 (why QUIC)

## Context

ADR-0002, ADR-0004 and ADR-0005 analyze fingerprints in the HANDSHAKE: the
mutual-TLS CertificateRequest (fixed), the JA4Q transport-parameter profile, and
the RPK cert-type ClientHello extension. All of those are observable in the first
few packets of a flow.

This ADR records a different and previously undocumented class: a tell on the
ESTABLISHED connection, in the time and size domain rather than the byte-content
domain. WarrenGuard keeps every tunnel alive with QUIC PING frames at a fixed
sub-30s cadence. That cadence, and the size of the resulting packets, do not match
the HTTP/3 disguise the obfuscation baseline (ADR-0002) builds in the handshake.
The handshake says "I am a browser talking to an h3 server"; the idle keep-alive
says "I am a long-lived tunnel".

This is on record because no prior ADR mentions packet timing or the keep-alive
interval as a fingerprint vector, and the obfuscation invariant test
(`crates/warrenguard-transport-core/tests/m40_obfuscation_invariants.rs`) only
locks handshake-shaped knobs (ALPN, spin bit, Initial split). The keep-alive
cadence is unguarded against this concern.

## What the engine does today (verified in code)

Two configurations, both below the 30s the QUIC operational guidance treats as the
floor for idle keep-alives:

- Base (exit and relay): `QUIC_KEEP_ALIVE_INTERVAL_SECS = 20` /
  `QUIC_MAX_IDLE_TIMEOUT_SECS = 180`
  (`crates/warrenguard-config/src/lib.rs:357,376`), applied at
  `crates/warrenguard-transport-core/src/transport_config.rs:144,154`.
- Client override (more aggressive): `CLIENT_KEEP_ALIVE_INTERVAL_SECS = 5` /
  `CLIENT_MAX_IDLE_TIMEOUT_SECS = 25`
  (`crates/warrenguard-transport-core/src/transport_config.rs:167,194`), applied at
  the same file 200-201.

Mechanism, in the warren-quinn fork (the `WarrenBrowse/warren-quinn` git-dep):

- The keep-alive timer is strictly periodic: `reset_keep_alive` sets it to
  `now + keep_alive_interval`, with zero jitter
  (`quinn-proto/src/connection/mod.rs:1987` in the warren-quinn fork).
- It is re-armed ONLY when an authenticated packet is RECEIVED
  (`on_packet_authenticated`, same file 1920), never on send. So during genuine
  receive-idle the PING fires on the dot every interval; during active two-way
  traffic the incoming packets keep resetting the timer and no PING is emitted.
  The tell therefore appears precisely in the idle gaps of a real session, not
  during active browsing.
- The PING packet is NOT padded. `poll_transmit` writes a bare one-byte PING frame
  (`quinn-proto/src/connection/mod.rs:3180` in the warren-quinn fork), so the keep-alive
  is a QUIC short-header packet carrying a PING (and possibly a piggybacked ACK)
  plus the 16-byte AEAD tag: a few tens of bytes. `initial_datagram_min_size(1280)`
  only pads Initials, not 1-RTT keep-alives.

Net observable for an on-path passive observer, during any idle stretch of an
`h3`-ALPN flow: a tiny client datagram every 5.000s (or 20s server-to-relay),
each answered by a tiny ACK. Fixed period, fixed small size, indefinitely, and the
connection never closes.

Measured, not asserted: a loopback client<->exit connection with the production
client config, left idle and sampled via quinn `Connection::stats()`
(`crates/warrenguard-relay/tests/measure_keepalive_signature.rs`), emits a
steady-state keep-alive packet of exactly 30 bytes every 5.01s (mean inter-PING
gap over 6 steady-state samples; the cadence is a flat metronome, not a
distribution). 30 bytes is the QUIC short-header packet carrying a single PING
frame plus the AEAD tag, with no padding. This is the worst case for the tell: on
loopback the period has no network jitter at all.

## Why this diverges from the HTTP/3 disguise

A real browser does not behave this way on an idle h3 connection:

- The QUIC operational guidance states that sending keep-alive PINGs more often
  than every 30s over long idle periods causes excessive traffic and power use, and
  recommends against intervals shorter than ~30s; the idle timeout in force is the
  minimum the two peers advertise. WarrenGuard's 5s (client) and 20s (base) are
  both under that floor. Source: "Applicability of the QUIC Transport Protocol",
  IETF QUIC WG ops draft
  (https://quicwg.org/ops-drafts/draft-ietf-quic-applicability.html).
- Browsers pool idle h3 connections and let them lapse on the negotiated idle
  timeout rather than PING-ing them alive forever; keep-alive is the exception
  (an in-flight request), not the steady state. quic-go documents keep-alive as an
  opt-in that pings at half the idle-timeout period, not a default sub-30s beacon.
  Source: quic-go connection docs (https://quic-go.net/docs/quic/connection/).
- Concretely, Chromium uses a ~30s QUIC idle timeout (chosen for NAT) and, when it
  does keep a connection warm, PINGs at ~15s and ONLY while requests/responses are
  outstanding; a truly idle pooled connection is allowed to lapse. Warren's
  perpetual 5s (client) / 20s (base) beacon is both more frequent than Chrome's 15s
  AND present exactly where Chrome is silent. Sources: Chromium proto-quic threads
  on idle timeout and PING
  (https://groups.google.com/a/chromium.org/g/proto-quic/c/cWoQxBMopR0); RFC 9114
  guidance to prefer letting idle connections time out
  (https://httpwg.org/specs/rfc9114.html).
- HTTP/3 even forbids the `Keep-Alive` header; persistence at the app layer is not
  expressed the way Warren expresses it at the transport layer. Source: MDN,
  Keep-Alive header (https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Keep-Alive).

So an adversary that does per-flow timing analysis sees an h3-shaped handshake
followed by a metronome that no browser runs. It is a stable, low-false-positive
signal that this is a tunnel, orthogonal to everything ADR-0002/0004/0005 cover.

## Threat-model placement (calibrated severity)

This is a PASSIVE tell, but unlike ADR-0005's passive ClientHello tell it is NOT
readable from a single datagram. It requires per-5-tuple stateful timing analysis
sustained over an idle period. That is more expensive than the GFW's documented
bulk pipeline (first-datagram SNI extraction, entropy/prefix classification;
ADR-0002), and closer in cost to the JA4Q residual of ADR-0004: within reach of a
TARGETED or research-grade traffic-analysis adversary, not obviously something run
at line rate against all flows today. It should be treated like the JA4Q residual:
real, documented, mitigated when a matching adversary is in scope, not a
fire-drill.

The severity is also bounded by the fact that the keep-alive cannot simply be
removed. It is load-bearing for correctness:

- NAT/CGNAT UDP mappings expire near 30s; without traffic the mapping vanishes and
  the next reply from the peer is dropped (`warrenguard-config/src/lib.rs:359-376`).
- The blind relay does not forward client PINGs onto the relay-to-exit hop, so that
  hop needs its own keep-alive against backbone blips up to ~120s; the 180s idle
  budget exists for exactly this
  (`warrenguard-config/src/lib.rs:343-356`).
- Removing the `.keep_alive_interval(...)` call reintroduces a ~15-minute tunnel
  death cycle, which is why it is pinned by a source-level guard test
  (`crates/warrenguard-transport-core/src/transport_config.rs:179`) and a 90s relay
  idle test (`crates/warrenguard-relay/tests/keep_alive_idle_90s.rs`).

The one part that is NOT correctness-driven is the client's aggressive 5s value:
that exists for fast dead-exit detection (a UX/liveness choice), not for NAT, which
only needs the ~20s base. The 5s value is both the worst offender for the tell (the
shortest, most regular period) and the most separable from the necessity argument.
The `CLIENT_MAX_IDLE_TIMEOUT_SECS` doc comment
(`crates/warrenguard-transport-core/src/transport_config.rs`) names a substitute
dead-exit detector, the uplink dead-path watch (`WARREN_UPLINK_DEADPATH`). The
watch is implemented in the multi-hop supervisor (`uplink_dead_watch` in
`crates/warrenguard-transport/src/supervisor.rs`, wired into the supervisor's
serve select, reading `warrenguard_config::knobs::uplink_deadpath_enabled()`),
opt-in and off by default. So Option C is engine-local: relax the client
keep-alive and lean on the in-engine watch for dead-exit detection, gated on a
real-network bench before any default changes.

## DAITA already provides the cover-traffic substrate, but does not cover idle (verified)

The cover-traffic mechanism Option B was assumed to need from scratch ALREADY
EXISTS in the engine: DAITA (`warrenguard-daita`, a maybenot v2 wrapper) plus its
pump integration (`pump_bidirectional_with_daita`). Specifically:

- The filler/discriminator Option B called for is already there: dummy datagrams
  carry first byte `0xFF` (`DAITA_DUMMY_FIRST_BYTE`), distinct from the IPv4/IPv6
  nibbles 4/6, and the receiver drops them before the TUN via `is_daita_dummy`
  (`crates/warrenguard-pump/src/lib.rs`). No new wire format is needed.
- Dummies are full-MTU (1280B), so the SIZE axis is already handled when DAITA
  emits; padding cadence is driven by maybenot machines.

Two facts make this NOT a solution to the idle tell as it stands:

1. DAITA is OFF by default and strictly opt-in. The client sets `daita_support:
   false` (`crates/warrenguard-transport/src/client.rs`) and the exit ships
   `daita_pool: None` (`crates/warrenguard-server/src/exit/mod.rs`); a default
   session runs `DaitaState::disabled()` on both ends. There is no `WARREN_DAITA`
   knob. So for the default connection the idle tell is fully exposed.
2. Even when DAITA is on, idle coverage is per-machine and the exit rolls 1-of-5
   uniformly. Measured in `crates/warrenguard-daita/tests/idle_keepalive_gap.rs`
   (drives each curated machine through 30s of sustained idle with the exact pump
   self-feed `PaddingSent + TunnelSent`):

   | curated machine | padding in 3-30s idle | idle keep-alive tell |
   | --- | --- | --- |
   | tamaraw | ~5400 (heavy, ~200 pkt/s) | masked |
   | netflow | ~6 (a weak trickle, ~1 / few s) | barely better than the beacon |
   | front | 0 (bursts early, then silent) | exposed |
   | interspace_server | 0 | exposed |
   | scrambler_server | 0 | exposed |

   The constant-rate machines self-sustain through idle because the pump's dummy
   self-feed fires `TunnelSent`, which holds their stop/inactivity window open
   indefinitely (so DAITA does not fall silent shortly after traffic stops, for
   tamaraw/netflow). So idle masking, when DAITA is on at all, is roughly 2/5 by
   the random roll, and only tamaraw masks it well, at a heavy constant-rate cost.

Net: the substrate for Option B is built and is the architecturally correct home,
but masking the idle tell as a BASELINE property (the always-on posture of the
ADR-0002 obfuscation invariants) is not achieved by DAITA today. Closing it means
either (B1) a curated idle-cover machine with a long/no stop window that the pool
can roll, plus turning DAITA on by default, or (B2) an always-on, DAITA-independent
idle filler in the pump. Both change wire behavior for real connections and carry
bandwidth/battery cost, so both are product decisions gated on a real-network
bench.

## Options, with cost

| Option | What it does | Removes timing tell | Removes size tell | Keeps NAT/backbone | Where it lives | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| 0. Document status quo | Record the tell, change nothing | No | No | Yes | here | Honest baseline; insufficient if a timing adversary is in scope |
| A. Jitter the keep-alive in the fork | New `keep_alive_jitter` TransportConfig field; `reset_keep_alive` becomes `now + interval + rand(0..jitter)` (`connection/mod.rs:1987`), bounded by `(interval+jitter)*2 <= idle` | Partial (defeats naive periodicity) | No (PING still tiny/unpadded) | Yes | warren-quinn fork (a separate repo; landed there and the tag bumped here, not in this repo) | Timing-only; out-of-band patch |
| B1. Curated idle-cover DAITA machine | Add a maybenot machine with a long/no stop window so an enabled DAITA session keeps full-MTU cover through idle; turn DAITA on by default | Yes (when rolled) | Yes (1280B dummies) | Yes | here (`daita_pool.rs`) + product (default-on) | Substrate exists; correct home; cost = bandwidth/battery + real-net bench + product call |
| B2. Idle filler in the pump (B2-lite) | DAITA-independent: when neither direction carried a real packet for a jittered 10-20s, emit a jittered, size-varied `0xFF` dummy (dropped by `is_daita_dummy`); client keep-alive disabled so the dummy REPLACES the beacon | Yes | Yes | Yes (refreshes NAT) | here (`warrenguard-pump` + `-transport-core`) | IMPLEMENTED opt-in (`WARREN_IDLE_COVER`); no new wire format; default-on gated on real-net bench |
| C. Relax the 5s client value | Raise client keep-alive toward the ~20s NAT floor and move dead-exit detection to the uplink dead-path watch (implemented in the engine supervisor, opt-in `WARREN_UPLINK_DEADPATH`) | Reduces (less frequent, still periodic) | No | Yes (at the NAT floor) | here (supervisor + transport-core) | Engine-local now that the watch exists; still bench-gated |

Observations that drive the recommendation:

- Option A corrects only the TIME axis (the PING stays tiny/unpadded) and the patch
  lives in the separate warren-quinn fork repo, so it is not a clean in-repo
  deliverable. De-ranked.
- The cover-traffic substrate B assumed it had to build ALREADY EXISTS (DAITA: the
  `0xFF` discriminator, receiver-side drop, full-MTU dummies). So there is no
  wire-format work. The real choice is WHERE to drive idle cover: inside DAITA (B1,
  only helps enabled sessions) or always-on in the pump (B2, helps the default
  path). B2 is the only one that makes idle masking a BASELINE property matching the
  always-on obfuscation invariants.
- Option C is engine-local now that the uplink dead-path watch is implemented
  in the supervisor (opt-in); it can reduce the beacon frequency but cannot
  remove it.

## Decision

1. Record the keep-alive cadence as a known passive traffic-analysis tell, in the
   time and size domain, not an oversight. Any future change to
   `keep_alive_interval` / `max_idle_timeout` or to the keep-alive packet shape is a
   censorship-posture change and must reference this ADR.
2. Ship B2-lite as an OPT-IN capability (`WARREN_IDLE_COVER`, off by default), so
   the default path is byte-identical and nothing changes for current deployments,
   while the mechanism exists, is tested end-to-end, and is ready for the bench.
   Turning it ON BY DEFAULT changes real-connection behavior (bandwidth/battery) and
   stays gated on a real-network bench (the shared real-network validation rule)
   plus a product call. This matches the ADR-0004 posture for the default while still advancing the
   fix.
3. The engine-local, no-regression work that IS done now: pin the verified
   behavior. `crates/warrenguard-relay/tests/measure_keepalive_signature.rs`
   measures the tell (30B / 5.01s); `crates/warrenguard-daita/tests/idle_keepalive_gap.rs`
   pins which curated machines cover idle. These lock the baseline so any future fix
   is provably a change and no regression slips in silently.
4. When a mitigation is pursued, the recommended order is now B2 then B1: B2 (pump
   idle filler) closes the tell on the DEFAULT path and is engine-local with no new
   wire format; B1 (idle-cover DAITA machine + default-on) layers richer
   per-session defense for DAITA users. C is a complementary engine task (relax the
   5s beacon, leaning on the in-engine uplink dead-path watch once it is
   real-network validated). Any mitigation MUST keep the NAT/backbone
   guarantees and MUST NOT regress the ADR-0002 obfuscation invariants or the
   keep-alive guard tests cited above; a new invariant test should lock the chosen
   idle behavior.

## Open questions for the continuing investigation

- OPEN: real-network jitter on the 5.01s period (needs a real-net capture; the
  size tell and the existence of the beacon are unchanged by jitter, so this is
  refinement, not blocking).
- OPEN (product/threat): is per-flow timing analysis in scope for the target
  markets (like JA4Q, deferred until a matching adversary), and is the
  bandwidth/battery cost of always-on idle cover (B2) acceptable for mobile.

## When to revisit

- A deployed tunnel is confirmed classified or blocked via flow-timing/keep-alive
  analysis (then B2 for the default path, B1 for DAITA users).
- The in-engine uplink dead-path watch (opt-in `WARREN_UPLINK_DEADPATH`) is
  validated on a real network: then fold Option C in (relax the 5s beacon toward
  the NAT floor) once liveness no longer depends on it.
- DAITA is turned on by default for any reason: then B1 (an idle-cover machine) is
  nearly free to add to the curated pool, and idle masking ships with it for DAITA
  sessions.

## Realized changes (B2-lite, opt-in)

Shipped behind `WARREN_IDLE_COVER` (off by default; the default path is unchanged):

- Knob `WARREN_IDLE_COVER` (`crates/warrenguard-config/src/knobs.rs`, doc row in
  `docs/35-ENV-KNOBS.md`, enforced by `registry_matches_doc`).
- `IdleCover` scheduler (`crates/warrenguard-pump/src/idle_cover.rs`): a pure,
  deterministic (splitmix64, no new dep) state machine that emits a `0xFF` dummy at
  a jittered 10-20s interval and a varied size in `[64, min(max_datagram, 1280)]`.
  `note_activity` pushes the deadline out on every real packet, so cover is silent
  under traffic (zero overhead) and only fills genuine idle. Unit-tested for
  interval/size bounds, variation on both axes, activity reset, and small-MTU clamp.
- `pump_bidirectional_with_idle_cover` (mono) and
  `pump_multi_bidirectional_with_idle_cover` (multi-conn), both in
  `crates/warrenguard-pump/src/lib.rs`. Each reuses the existing DAITA `0xFF`
  discriminator, so the exit drops cover via `is_daita_dummy` with NO new wire format
  and NO server-side change. The multi-conn variant gives EACH connection its own
  `IdleCover` (every connection is a distinct 5-tuple / NAT mapping / idle timeout,
  so per-connection cover is required; a session-wide scheduler would let an idle
  secondary expire while a sticky flow keeps the primary busy).
- Client configs with the keep-alive PING disabled when cover is active, so the
  dummy REPLACES the beacon (refreshes NAT, resets the idle timeout) rather than
  coexisting with it: `warren_transport_config_client_with_idle_cover(.., true)`
  (single-hop) and `warren_transport_config_client_multihop_with_idle_cover(.., true)`
  (multi-hop client to relay, C1). The 25s idle timeout still detects a dead exit.
- End-to-end proofs (ignored, ~35s each):
  `crates/warrenguard-pump/tests/idle_cover_loopback.rs` (mono) and
  `crates/warrenguard-pump/tests/idle_cover_multi_loopback.rs` (2-conn): with cover
  on, `frame_tx.ping` stays at the handshake baseline (no 5s beacon) on EVERY
  connection while `frame_tx.datagram` grows (cover emitted), and the connections
  survive on cover alone.

Cost/benefit: the cover budget is ~1 dummy / 10-20s per connection (tens of
bytes/s), comparable to the keep-alive beacon it replaces, NOT the ~200 pkt/s of
constant-rate cover (tamaraw). It removes the trivial fixed-metronome signature on
both axes; it does NOT make a persistent tunnel indistinguishable from a browser
(browsers close idle connections, a VPN cannot), which is an inherent ceiling, not
a B2-lite gap.

### Activation (consumer side) and the bench gate (NOT in this repo)

The engine builds the client config but the consuming runtime (invisible from
this engine by self-containment) runs the client pump. So turning B2-lite on is
a coordinated consumer change, deliberately NOT wired here to avoid a foot-gun
(the engine config disables keep-alive; if the runtime then ran the plain pump
the connection would have no liveness). Precise handoff:

1. Read `warrenguard_config::knobs::idle_cover_enabled()` once at session setup.
2. If true, build the client config with the idle-cover variant
   (`warren_transport_config_client_with_idle_cover` / `..._multihop_with_idle_cover`,
   `idle_cover = true`) AND run the matching cover pump
   (`pump_bidirectional_with_idle_cover` for `ClientSession` /
   `pump_multi_bidirectional_with_idle_cover` for `MultiSession`). Both sides MUST
   flip together; never one without the other.
3. Before enabling by default, run a real-network bench (the shared
   real-network validation rule; needs a live exit): confirm (a) no spurious disconnects on
   real mobile/CGNAT paths over a long idle (the 10-20s cover stays under the NAT
   expiry), (b) the field inter-dummy distribution is non-periodic (jitter survives
   real scheduling), and (c) the battery/data cost is acceptable for mobile. Only
   then consider default-on.

Still open after this ADR: the consumer wiring + bench above (needs a live
exit); turning it on by default; and Option C (relax the 5s beacon), gated on
real-network validation of the in-engine uplink dead-path watch. The
exit/relay server-side keep-alive (20s) is
unchanged and is a weaker concern (server behavior, not the censored client).

Consumer wiring has since shipped downstream (default-OFF): the engine exposes
`ClientTunnel::with_idle_cover(bool)`, and the consuming daemon derives one
bool from `idle_cover_enabled() && !daita_requested` (idle cover and DAITA are
mutually exclusive covers) that drives BOTH the config and the pump choice, so
the config/pump foot-gun is structurally impossible. Turning
`WARREN_IDLE_COVER` on by default remains gated on the real-network bench
(a/b/c above); the default path stays byte-identical until then.

## Consequences

- The keep-alive cadence joins JA4Q (ADR-0004) and the RPK ClientHello extension
  (ADR-0005) on the record of known, unmitigated-by-design residuals, with its
  severity calibrated as a targeted/research-grade passive timing tell rather than
  a bulk-pipeline one.
- The obfuscation invariant set is now known to be incomplete in the time/size
  domain: `m40_obfuscation_invariants.rs` locks handshake shape only. If a
  mitigation lands, a matching invariant test should lock the new behavior.
- The keep-alive remains load-bearing for NAT and backbone resilience; this ADR
  does not weaken that and does not remove the guard tests. It only opens the
  question of making the cadence and packet shape less browser-anomalous.
- DAITA is documented as the cover-traffic substrate (the `0xFF` discriminator and
  full-MTU dummies are reused by any idle-filler work), but its idle coverage is now
  on record as conditional (off by default; ~2/5 curated machines when on), pinned
  by `idle_keepalive_gap.rs`. Changing the curated pool or the pump self-feed in a
  way that alters idle coverage will fail that test.
- The `WARREN_UPLINK_DEADPATH` knob gates the uplink dead-path watch implemented
  in the engine's multi-hop supervisor (`uplink_dead_watch`,
  `crates/warrenguard-transport/src/supervisor.rs`), opt-in and off by default.
  Relaxing the keep-alive for liveness (Option C) can lean on it once it is
  validated on a real network.
