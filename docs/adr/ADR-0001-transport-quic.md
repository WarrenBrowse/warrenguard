# ADR-0001: QUIC as the transport, not raw UDP or a WireGuard-style data plane

Status: accepted (retroactive; documents a decision already embodied in the code)
Date: 2026-06-21

## Context

WarrenGuard is described as a "generic VPN-over-QUIC engine" (README.md:3,
CLAUDE.md). The transport choice (QUIC, via a pinned quinn fork) is the single
most load-bearing architectural decision in the repo, yet until this ADR it was
never written down: the rationale was scattered across code comments and test
invariants. Two design notes the code points at,
`docs/20-WARREN-OBFUSCATION-DESIGN.md` (referenced at
`crates/warrenguard-transport-core/src/transport_config.rs:260`) and
`docs/29-QUIC-MOBILITY-DESIGN.md` (referenced at the relay), are NOT present in
this repository. They live in a private doc set that was not carried over when
the engine was extracted. This ADR is meant to be the self-contained, in-repo
record so a future contributor does not "optimize" the transport in a way that
silently breaks the property that actually justifies it.

The honest framing matters here: on raw throughput and CPU cost, QUIC is a
WORSE transport for a VPN than an in-kernel WireGuard-style data plane. The
decision is justified by one property, censorship resistance through traffic
mimicry, and that property is decisive for the Warren product. If that property
were not a first-class requirement, this decision would not hold.

## Decision

Carry the tunnel over QUIC:

- A TLS 1.3 handshake with raw public keys (RFC 7250), identity-bound, no PKI
  (README.md:12, `crates/warrenguard-tls/src/lib.rs`).
- IP packets carried one-to-one over QUIC DATAGRAM frames (RFC 9221), unreliable
  and unordered, not over reliable streams. Streams are used only for the
  `Setup`/`SetupAck` handshake (README.md:13,
  `crates/warrenguard-wire/src/lib.rs`).
- The wire profile is deliberately shaped to look like IETF HTTP/3.

## Why QUIC (the forces that actually decide it)

### 1. Traffic mimicry / censorship resistance (the decisive reason)

The whole obfuscation profile is built on the assumption that the transport is
QUIC and is trying to pass as ordinary HTTP/3 web traffic. This is not optional
or feature-gated; it is baked into the base transport config and locked by
tests:

- ALPN is `h3` "to mimic IETF HTTP/3 on the wire"
  (`crates/warrenguard-tls/src/lib.rs`). The exit advertises **only** `h3`,
  never a Warren-custom protocol id: an exit that accepted the historical
  `warren/exit/1` ALPN would answer an active probe in a way no public HTTP/3
  server does, a wire-visible tell. Enforced by
  `crates/warrenguard-server/tests/exit_alpn_h3_only.rs`.
- The TLS ClientHello is forced to span two Initial QUIC packets in two UDP
  datagrams: `initial_crypto_first_fragment_size(Some(64))` caps the first CRYPTO
  chunk so the SNI extension lands in the second Initial, and
  `initial_datagram_min_size(1280)` pads both Initials. A passive observer parsing
  either datagram in isolation cannot reconstruct the SNI (GFW SNI extractor,
  USENIX Security 2025). See
  `crates/warrenguard-transport-core/src/transport_config.rs:233-262`, mirrored
  server-side at lines 266-281.

No raw-UDP or WireGuard-style design gives this for free. WireGuard's handshake
has a recognizable fixed-size signature and is routinely blocked by DPI in
censored networks. Masquerading as HTTP/3, the single most common encrypted
transport on the open web, is the property QUIC buys, and it is the reason the
engine exists in this shape.

### 2. Unreliable datagram semantics without rolling our own crypto transport

RFC 9221 datagrams give UDP-like loss/reorder tolerance (no head-of-line
blocking, no TCP-over-TCP meltdown) inside an authenticated, encrypted,
congestion-controlled session. We get TLS 1.3, mutual RPK authentication, and a
modern congestion controller (BBR default) without designing a bespoke crypto
handshake.

### 3. DAITA traffic-analysis defense depends on independent datagrams

DAITA dummy packets and padding ride the datagram pump as independent units
(README.md:15). This requires the unreliable-datagram model; it does not compose
with a reliable, ordered stream.

### 4. Connection migration for mobility

QUIC connection migration is the intended mechanism for WiFi/cellular handover
(referenced design note `docs/29-QUIC-MOBILITY-DESIGN.md`, not in this repo;
the relay accepts client-facing address migration). Migration is deliberately
DISABLED on the exit (`server_cfg.migration(false)`,
`crates/warrenguard-tls/src/lib.rs:167,203`) to deny an attacker a
PATH_CHALLENGE timing-correlation primitive, so this benefit is currently scoped
to the relay hop, not the exit.

## What this costs (do not pretend otherwise)

These are real, code-visible downsides of choosing QUIC. They are accepted
because property 1 outweighs them, not because they do not exist.

- Userspace per-packet cost and a single-connection throughput ceiling. A
  single `quinn::Connection` serializes internally; to break that ceiling the
  client opens up to `MAX_CONNECTIONS_PER_SESSION = 32` parallel QUIC
  connections to the same exit (`crates/warrenguard-config/src/lib.rs:406`,
  rationale at `crates/warrenguard-wire/src/lib.rs:19-22`, throughput evidence
  in the buffer-sizing comment at `crates/warrenguard-config/src/lib.rs:321`).
  An in-kernel WireGuard data plane reaches multi-gigabit on a single tunnel
  without this. The N-connection fan-out is a workaround for a QUIC cost, not a
  feature we would want for its own sake.
- A maintained quinn fork. GSO transmit constants, the obfuscation knobs,
  socket-buffer sizing, and an Apple fast datapath all live in a pinned fork,
  the standalone `WarrenBrowse/warren-quinn` repo consumed as a git dependency
  pinned by tag in the root `Cargo.toml`. The hard anti-depatch guard is the
  E0599 compile error the fork-only knobs raise in
  `crates/warrenguard-transport-core/src/transport_config.rs`. This is permanent
  maintenance debt a raw-UDP transport would not carry.
- 0-RTT is disabled on both sides (`Resumption::disabled()` and
  `send_tls13_tickets = 0`, `crates/warrenguard-tls/src/lib.rs:114,154`), so the
  oft-cited QUIC handshake-latency advantage is intentionally given up (replay
  risk on VPN auth is unacceptable). QUIC is not chosen here for fast handshakes.

## Alternatives considered

- Raw UDP + Noise (WireGuard-style): leaner, faster, kernel-space possible.
  Rejected: recognizable DPI signature, blocked in censored networks, and no
  obfuscation story without rebuilding one from scratch. Loses property 1.
- DTLS: UDP plus crypto with none of QUIC's ecosystem, no standardized
  migration, no mimicry story. No advantage over QUIC here.
- TCP/TLS: head-of-line blocking and TCP-over-TCP. Disqualified for a VPN data
  plane.
- MASQUE (RFC 9298 CONNECT-UDP over HTTP/3): effectively the standardized form
  of what we do. A genuine alternative, but it constrains control over the
  Initial-packet obfuscation knobs that property 1 relies on. Raw QUIC plus
  datagrams was kept for that control.

## When this decision stops being justified

Revisit this ADR (do not just tweak the transport) if any of these change:

- Censorship resistance / traffic mimicry is dropped or downgraded from a
  first-class requirement. Without property 1, an in-kernel WireGuard-style data
  plane very likely wins on throughput, CPU, and maintenance burden, and the
  quinn fork plus the 32-connection fan-out stop paying for themselves.
- HTTP/3 stops being a plausible cover protocol on the target networks (for
  example, widespread blocking of UDP/443 or of QUIC itself). Then the cover has
  to move (to TCP-based mimicry, domain fronting, a pluggable transport), and
  QUIC may no longer be the right base.
- The single-connection throughput ceiling is lifted upstream in quinn such that
  the 32-connection fan-out is no longer needed. That would remove one of the
  main costs and strengthen, not weaken, this decision; record it here.

## Consequences

- The obfuscation invariants (`h3` ALPN, two-datagram Initial split, padded
  first datagram, spin bit off) are load-bearing, not cosmetic. Changing them is
  a transport-security change, not a tuning change. They are guarded by
  `crates/warrenguard-transport-core/tests/m40_obfuscation_invariants.rs` and the
  fork patch test; keep it that way.
- Performance work on the data plane is constrained to working within QUIC
  (batching, GSO/GRO, multi-connection, buffer sizing), not around it.
- The missing private design notes (`docs/20-*`, `docs/29-*`) should either be
  ported into this repo or this ADR should absorb their load-bearing content, so
  the engine stays self-contained as CLAUDE.md section 1 requires.
