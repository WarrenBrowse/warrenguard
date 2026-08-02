# ADR-0004: QUIC / HTTP-3 fingerprint parity (uTLS-for-QUIC)

Status: proposed (audit and feasibility record; NOT implemented; documents a
known residual and why closing it is research-grade)
Date: 2026-06-23
Related: ADR-0002 (active-probing threat model, option-2 residual), ADR-0001

## Context

ADR-0002 named a second residual against a sophisticated adversary: even with the
mutual-TLS tell removed, the QUIC transport parameters and (where present) the
HTTP/3 SETTINGS frame can be fingerprinted against real browsers (JA4/QUIC), and
WarrenGuard's stack does not match a browser byte-for-byte. This ADR audits that
gap and records why closing it is not a session-sized task.

## What gets fingerprinted, and who is exposed

JA4 explicitly covers QUIC and HTTP/3, keying on ALPN, the TLS ClientHello shape,
and QUIC transport parameters (https://blog.cloudflare.com/ja4-signals/). The
exposed party here is mostly the CLIENT: the client dials, so its QUIC Initial /
ClientHello (extension list and order, GREASE values, supported groups, QUIC
transport-parameter set and order) is what a passive observer fingerprints. A
real browser (Chrome/Firefox/Safari) has a specific, well-known JA4Q; quinn +
rustls emit their OWN distinct fingerprint. A censor maintaining a "known good
browser JA4Q" allowlist could therefore flag Warren traffic as "QUIC, but not a
browser", independently of the SNI-split and the mutual-TLS fix.

What WarrenGuard already controls (and pins via tests): ALPN = `h3`, SNI split
across two Initials, spin bit off, padded first datagram. What it does NOT
control: the exact TLS extension order, GREASE placement, QUIC transport-
parameter order/values, and h3 SETTINGS, relative to a target browser.

## Why this is research-grade

- uTLS is Go-only. The reference tool for ClientHello mimicry,
  `refraction-networking/utls`, is a fork of Go's TLS stack
  (https://github.com/refraction-networking/utls). There is no mature
  equivalent for the Rust + rustls + quinn stack that emits a chosen browser's
  QUIC ClientHello byte-for-byte.
- Rust fingerprint-control tools target a different stack and role. `wreq`
  offers JA3/JA4/HTTP2 fingerprint control for an HTTP CLIENT
  (https://github.com/0x676e67/wreq), built on its own TLS backend for scraping
  mimicry; it is not a server-side QUIC data-plane on the quinn fork, and adopting
  it would mean abandoning the warren-quinn fork and its obfuscation knobs (see
  ADR-0001), a far larger change than this residual warrants.
- rustls / quinn do not expose byte-level ClientHello / transport-parameter
  shaping intended to impersonate a specific browser build. Achieving parity
  would mean carrying invasive patches in the quinn fork and chasing a moving
  target (browsers change their fingerprint across releases). That is a research
  project, not a bug fix.

## Decision

Do not attempt browser fingerprint parity in this change. Record the residual and
the audit. Treat ALPN/SNI-split/spin-bit (already pinned) as the realistic
passive-mimicry surface for now.

If/when this becomes a launch blocker for a JA4Q-allowlisting adversary, evaluate,
in order of cost:

1. Align the few transport parameters we already control toward a common,
   non-suspicious profile (documented, measured against a packet capture). Cheap,
   partial.
2. Mimic a widely-deployed QUIC LIBRARY fingerprint (e.g. a popular CDN/edge
   stack) rather than a browser, if that blends better for server-to-server
   shaped deployments. Medium.
3. A uTLS-equivalent for the quinn fork: invasive ClientHello / TP shaping with a
   browser fingerprint database. Research-grade; only if the threat is confirmed
   and funded.

## When to revisit

- Evidence that a target adversary blocks on QUIC/JA4Q (browser-vs-library)
  rather than only on SNI.
- A mature Rust uTLS-for-QUIC appears (track the utls / wreq ecosystems).

## Consequences

- The residual stands: a JA4Q-allowlisting censor can in principle distinguish
  Warren's quinn fingerprint from a browser's. The SNI-split and mutual-TLS fixes
  do not address this layer; they are orthogonal and remain necessary.
- Any future fingerprint shaping must not regress the ADR-0002 obfuscation
  invariants (guarded by
  `crates/warrenguard-transport-core/tests/m40_obfuscation_invariants.rs` and the
  fork-patch test).
