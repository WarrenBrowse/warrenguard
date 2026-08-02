# ADR-0003: Active-probe decoy / HTTP/3 co-tenancy (option 3)

Status: partially implemented (the engine SEAM `UnauthenticatedHandler` is
shipped on branch `feat/inband-setup-auth`; the DECOY itself - a real HTTP/3
site / reverse proxy - is deliberately left to the deployer and not shipped, and
the default behavior remains the ADR-0002 clean close)
Date: 2026-06-23
Related: ADR-0002 (active-probing threat model, option 3), ADR-0001 (why QUIC)

## Context

ADR-0002 shipped option 2: the exit no longer requests a TLS client certificate
(the CertificateRequest tell is gone) and authenticates clients in-band. It
recorded one residual against a GFW-class ACTIVE prober: after the QUIC + TLS
handshake completes (which now looks exactly like an ordinary server-auth-only
HTTP/3 endpoint), a prober that speaks real HTTP/3 and sends a request gets a
non-website answer, because the exit does not speak HTTP/3. Today, on a
connection that does not deliver a valid Warren `Setup`, the exit closes cleanly
(no proxy-distinctive application signaling). That is strictly better than the
old CertificateRequest tell, but it is not a served web page.

This ADR is the design and feasibility record for closing that residual (option
3: real HTTP/3 decoy co-tenancy). It is deliberately NOT implemented yet; the
reasoning is below.

## What "done" would look like

A prober that completes the handshake and issues a genuine HTTP/3 GET receives a
plausible web response (a real site), indistinguishable from a normal HTTP/3
server, while authenticated Warren clients use the `Setup`-stream tunnel on the
same endpoint. This is the QUIC-native analogue of Trojan's "fall back to a real
backend" and REALITY's "forward the probe to the real site" (see ADR-0002
sources).

## Why this is hard in QUIC (and not a session-sized task)

1. No mid-flight hand-off. A QUIC connection is cryptographically bound to THIS
   server from the Initial packet onward (the TLS keys derive from this server's
   handshake). Unlike a TCP byte-proxy, the exit cannot transparently forward an
   already-established QUIC connection to a third-party real HTTP/3 site. A
   convincing fallback must therefore be served locally: the exit itself has to
   speak enough HTTP/3 to answer like a website.

2. The HTTP/3 stack on the quinn fork is experimental. The reusable option is
   `h3` + `h3-quinn` (hyperium), which the project itself still labels
   "experimental ... there may still be bugs, and the API could change"
   (https://github.com/hyperium/h3, https://lib.rs/crates/h3-quinn). Pulling an
   experimental dependency into a security data-plane engine, for a speculative
   threat, is not a change to make casually, and a half-built h3 responder that
   answers incorrectly is MORE fingerprintable than a clean close, not less.

3. Policy belongs to the deployer. Per ADR-0001 and CLAUDE.md the engine carries
   no product policy. WHICH site to serve as a decoy, and whether to co-tenant a
   real web app, is a deployment decision, not an engine default.

## Proposed design (engine seam, not a bundled web server)

Keep the engine policy-free by exposing an extension seam instead of bundling an
HTTP/3 server:

- Add an optional `UnauthenticatedHandler` hook on the exit: when a connection
  completes the handshake but fails to deliver a valid, authenticated `Setup`
  (bad/absent frame, or `verify_channel_binding` fails), the exit, instead of
  closing, hands the live `quinn::Connection` to the handler if one is
  configured. With no handler configured (the default, and the only behavior
  today) it closes cleanly as now.
- A deployer that wants active-probe resistance plugs a handler that speaks
  HTTP/3 (via `h3-quinn`) and serves a real site or reverse-proxies a local web
  backend. That code, and its experimental dependency, live in the deployer's
  own codebase, not in the engine.

This is bounded, testable (the seam itself: "unauthenticated connection is
routed to the handler, authenticated is not"), and keeps the experimental h3
dependency out of the engine until it stabilizes.

Sketch (illustrative, not final):

```rust
pub trait UnauthenticatedHandler: Send + Sync {
    // Called with a live, handshake-complete connection that did not present a
    // valid authenticated Setup. The handler owns the connection from here.
    fn handle(&self, conn: quinn::Connection);
}
// Exit config gains: unauthenticated_handler: Option<Arc<dyn UnauthenticatedHandler>>
```

## Decision

Ship the engine SEAM now; leave the DECOY to the deployer.

Implemented in this change:
- `warrenguard_server::UnauthenticatedHandler` (trait) and
  `ExitBindOpts::unauthenticated_handler`. When set, a connection that completes
  the handshake but fails to present a valid, channel-bound `Setup` (decode
  failure, channel-binding export failure, or auth-proof verification failure) is
  handed to the handler instead of being closed. Routing lives in
  `reject_unauthenticated`, called from both exit handshake paths
  (`handshake_from_incoming`, `handshake_only`). Authorization denials (valid
  auth, allowlist/device-cap rejected) are NOT routed there. The accept loop
  treats the hand-off as the quiet `TunnelError::DivertedToDecoy` outcome.
  Covered by `tests/unauthenticated_decoy_seam.rs`.

Deliberately NOT implemented (deployer-side, gated):
- The decoy handler itself (a real HTTP/3 responder / reverse proxy) and its
  experimental `h3`/`h3-quinn` dependency. With no handler configured (the
  default) the exit keeps the ADR-0002 clean close. Build the decoy in the
  product when (a) a GFW-class active prober is confirmed
  against deployed exits, or (b) `h3`/`h3-quinn` reach a stable release.

Rationale: the seam is bounded, stable and engine-appropriate (no policy, no
HTTP/3 dependency); the decoy is policy + an experimental dependency, so it stays
out of the engine.

## When to revisit

- A deployed exit is confirmed fingerprinted/blocked via active HTTP/3 probing.
- `h3` / `h3-quinn` ship a stable (1.0-class) release.
- NOTE (ADR-0005): a third gate applies. The exit authenticates itself via RPK
  (RFC 7250), so a generic active prober's handshake aborts at certificate
  negotiation, BEFORE this seam is reached. The decoy is therefore unreachable by
  the intended adversary until the exit can complete a normal X.509 handshake
  (an engine "v6" change). Sequence that prerequisite before building the decoy.
- The product decides active-probe resistance is a launch requirement for a
  censored market; then implement the seam first (cheap, engine-appropriate) and
  the decoy handler in the product.

## Consequences

- Until then, the active-probe residual stands as documented in ADR-0002: a real
  HTTP/3 probe gets a clean close, not a served page.
- The seam, if added, must not change the authenticated path or its tests, and
  must keep the engine free of a bundled web server / policy.
