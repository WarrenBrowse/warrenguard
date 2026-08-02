# ADR-0007: Total-obfuscation roadmap

Status: D1 accepted, D2 direction set (2026-07-05); Option A implementation
scope open pending JA4Q instrumentation.

Supersedes nothing. Consolidates the residual tells recorded in ADR-0002
(active probing), ADR-0004 (QUIC fingerprint parity), and ADR-0006 (keepalive
traffic-analysis tell) into one plan, and sets the acceptance bar.

## Goal and its honest bound

The stated product goal is that no observer can betray the tunnel's nature.
That goal is only meaningful once parameterised by an adversary, because
"undetectable to everyone" is not achievable by any VPN, including this one:

- Undetectable (the observer cannot tell it is a tunnel even with full
  analysis) is bounded by information theory once real traffic flows. A
  sustained high-volume flow cannot be shaped to look like reading a web page
  without either enormous padding overhead or capping throughput to browsing
  levels. No deployed system (Tor pluggable transports included) claims
  undetectability against a global passive adversary running per-flow ML while
  carrying real payload.
- Unblockable (the observer may suspect but cannot block without unacceptable
  collateral) is achievable and is the workhorse of QUIC-based circumvention:
  if the flow sits inside the anonymity set of "QUIC traffic the censor will
  not block wholesale", blocking it means blocking mainstream HTTP/3.

### Acceptance bar (proposed)

Indistinguishable from a genuine HTTP/3 flow to a mainstream service, against a
passive + active-probing + fingerprinting DPI adversary; and unblockable via
collateral damage against a fingerprint-allowlisting adversary. Explicitly NOT
"undetectable to a global ML adversary while carrying torrent-scale volume":
that is out of scope as unachievable, and pretending otherwise would make the
bar un-shippable. Traffic-analysis resistance for the browsing threat model is
provided by DAITA; its interaction with throughput is governed by the profile
scheme in ADR-0008.

## Tell inventory and disposition

1. Keepalive metronome (ADR-0006). Fixed sub-30s zero-jitter QUIC PING marks a
   long-lived tunnel in idle gaps. Mitigation (jittered, size-varied idle
   cover) is implemented behind `WARREN_IDLE_COVER`, off by default pending a
   real-network bench. Disposition: bench, then flip default-on for
   censored-network profiles.

2. Active-probe close-code oracle (ADR-0002/0003). Without a configured
   decoy, a prober that completes TLS and sends garbage used to receive the
   greppable application close code `0x57415252` ("WARR"). Disposition: CLOSED.
   The exit now closes any unauthenticated / undecodable peer (including a
   version mismatch) with the standard `H3_GENERAL_PROTOCOL_ERROR` and an empty
   reason, indistinguishable from a real h3 endpoint; a default decoy seam
   remains a deployer option for an even richer cover response.

3. QUIC/TLS fingerprint non-parity (ADR-0004, the hard one). quinn+rustls emit
   a ClientHello (cipher list, extension order, GREASE) and QUIC transport
   parameters (values and encoding order) that do not match a browser. A
   JA4Q-allowlisting censor blocks the flow regardless of SNI. Parity is
   research-grade and unimplemented. Disposition: see decision below.

4. Traffic shape of high-volume flows. Volume, duration and burst signature of
   a full browsing or torrenting tunnel do not resemble one page fetch. This is
   the DAITA frontier and cannot be made "total" without throughput cost;
   handled per-profile in ADR-0008, not here.

5. Custom-ALPN active-probe tell. The exit used to accept the legacy
   `warren/exit/1` ALPN alongside `h3`, so a prober offering it got an
   acceptance no public HTTP/3 server gives. Disposition: CLOSED. The exit
   advertises only `h3` (enforced by
   `crates/warrenguard-server/tests/exit_alpn_h3_only.rs`).

## Decision

- D1 (accepted 2026-07-05). Adopt the acceptance bar above: unblockable, and
  undetectable to a realistic DPI + active-probing + fingerprinting adversary.
  Literal "undetectable to a global ML adversary while carrying real volume" is
  out of scope as unachievable.

- D2 (direction set). Split obfuscation into two families with different
  treatment:
  - Protocol and fingerprint obfuscation (look like HTTP/3, JA4Q parity, the
    active-probe decoy, and never emitting an engine-specific close code to an
    unauthenticated peer) costs approximately no throughput, so it applies to
    every user in every profile, always on. This is the "no compromise"
    surface.
    - Sure wins to ship first: a default-on decoy with a real cover response,
      and closing the probe-oracle close code.
    - Fingerprint parity (the hard item): instrument before building. The
      `warrenguard-ja4` crate + the `ja4_fingerprint` tls test (wired into
      fingerprint-nightly) decrypt a captured engine Initial per RFC 9001 and pin
      BOTH client shapes: the RPK/dev path `q13d0312h3_55b375c5d22e_28e663e2d6d5`
      and the production cover-domain (WebPKI) path
      `q13d0311h3_55b375c5d22e_387675cfb458`. Both already match a browser on the
      cipher hash; the production path additionally drops the RPK
      `server_certificate_type` tell (11 vs 12 extensions). The residual gap is
      JA4_c (the extension set + sig-algs) and the extension count.
    - Decision (2026-07-05): DEFER the byte-exact-parity fork. There is no clean
      path. Stock rustls 0.23 exposes no public API to add, remove, reorder or
      GREASE ClientHello extensions (the set is a closed struct;
      status_request / extended_master_secret / psk_key_exchange_modes are emitted
      unconditionally), and the quinn fork hands ClientHello construction entirely
      to rustls. craftls, the only Rust uTLS-equivalent, tracks rustls 0.22 with
      no QUIC support. Parity therefore requires self-forking rustls, the engine's
      TLS layer: a security-critical, perpetual-maintenance commitment (track
      rustls CVEs AND browser-fingerprint drift). Against the realistic adversary
      (a denylist censor blocking known-VPN fingerprints) Warren's generic rustls
      fingerprint is not itself a tell; an allowlist censor (browser-JA4-only) is
      rare and high-collateral. Ship the certain wins instead (the probe-oracle
      close code and the `warren/exit/1` ALPN tell are both closed) and keep the
      nightly JA4 as the drift tripwire. Revisit the fork only if a real
      allowlist-censor threat appears, or if rustls upstreams a ClientHello
      customization API (rustls #1932).
  - Traffic-analysis defenses (DAITA padding and timing, jittered idle cover)
    cost throughput and are Stealth-profile only (ADR-0008). idle cover flips
    default-on for the Stealth profile after its real-network bench.

- D3 (unchanged). A future versioned-Setup must not emit a distinguishable
  version-mismatch signal to an unauthenticated peer; undecodable input always
  routes to the decoy.

## Consequences

- The parity fork is deferred, not rejected: if a real allowlist-censor threat
  forces it, it is a standing maintenance cost (rustls CVEs + browser-fingerprint
  drift), not a one-off. That perpetual cost is precisely why it stays gated
  behind a concrete threat rather than shipped speculatively.
- Default-on defenses cost throughput; the profile scheme in ADR-0008 keeps
  that cost off the performance audience.
- Docs must state the enabled-vs-default gap plainly (done in README and
  SECURITY.md); a naive deployer must not believe the bare default is stealthy.

## Remaining scope to size

- The JA4 gap is now quantified (both client fingerprints pinned in
  `ja4_fingerprint`). If the parity fork is later triggered, size it then: pick
  the target browser/CDN profile, and scope the rustls patch (extension set +
  GREASE + sig-algs to match JA4_c). Not started, gated per the decision above.
- idle-cover default-on for the Stealth profile (tell 1) still awaits its
  real-network bench.
