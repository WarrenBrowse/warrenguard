# ADR-0002: Active-probing threat model and the mutual-TLS tell

Status: accepted and implemented (GFW-class active prober is IN scope; option 2
shipped on branch `feat/inband-setup-auth`: protocol bumped to v5, the exit
requests no client certificate, and the client authenticates in-band)
Date: 2026-06-22
Related: ADR-0001 (why QUIC)

## Context

ADR-0001 established that QUIC is justified here for one reason: censorship
resistance through traffic mimicry (passing as IETF HTTP/3). That ADR named, but
did not analyze, a residual weakness: active probing. This ADR does the analysis,
sourced to both the code and the public censorship-research literature, and lays
out the mitigation options with honest cost estimates so the deployer can decide
whether active-probing resistance is in scope.

Two layers of adversary must be kept distinct, because WarrenGuard's posture is
very different at each:

- Passive DPI: an on-path observer reading packets. Cannot decrypt the QUIC
  handshake beyond the Initial packets.
- Active probing: the censor opens its own connections to a suspected server to
  confirm it is a proxy, then blocks the IP/port. This is the regime that broke
  Shadowsocks and that the Great Firewall of China (GFW) runs at scale.

## What the GFW actually does (sourced)

- Passive, fully-encrypted-traffic detection: the GFW blocks by default and
  exempts traffic that looks like a known protocol (TLS/HTTP byte prefixes,
  printable-ASCII ratios, bit-entropy outside ~3.4 to 4.6 per byte). Random or
  uniformly-encrypted payloads are the worst case. Source: Wu et al., "How the
  Great Firewall of China Detects and Blocks Fully Encrypted Traffic", USENIX
  Security 2023 (https://gfw.report/publications/usenixsecurity23/en/).
- QUIC SNI censorship: since 2024-04-07 the GFW decrypts QUIC Initial packets at
  scale and blocks by SNI against a dedicated blocklist. As of 2025-01 it parses
  only the first UDP datagram of a 5-tuple flow not seen in the last 60 s, and it
  does NOT reassemble a ClientHello split across multiple UDP datagrams or across
  multiple QUIC CRYPTO frames in one datagram. Recommended circumvention: split
  the SNI across CRYPTO frames, or precede the Initial with a random-payload UDP
  datagram. quic-go v0.52.0 (2025-05) shipped SNI-slicing. Source: Zohaib et al.,
  "Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of
  China", USENIX Security 2025
  (https://gfw.report/publications/usenixsecurity25/en/).
- Active probing: passive detection and active probing run in parallel but
  independently; over 99% of blocks never involved a prior probe, but the probe
  path is what confirms and durably blocks proxy servers. Source: Alice et al.,
  "How China Detects and Blocks Shadowsocks"
  (https://gfw.report/blog/gfw_shadowsocks/).

Takeaway: WarrenGuard's passive posture is sound and matches current research
(see next section). Its exposure is on the active-probing path.

## What WarrenGuard already gets right (passive)

The obfuscation baseline is, in effect, an implementation of the USENIX Security
2025 circumvention:

- `initial_crypto_first_fragment_size(Some(64))` caps the first CRYPTO chunk so
  the SNI extension lands in a second Initial, and `initial_datagram_min_size(1280)`
  pads so that second Initial lands in a second UDP datagram
  (`crates/warrenguard-transport-core/src/transport_config.rs:233-262`, mirrored
  server-side at 266-281). This is exactly "split the ClientHello across CRYPTO
  frames AND across UDP datagrams", which defeats the GFW's first-datagram-only
  QUIC SNI extractor as documented in 2025.
- ALPN `h3` and a high-entropy-but-QUIC-shaped wire profile keep the flow inside
  the "looks like HTTP/3" exemption rather than the "fully encrypted" block class.

Note on ECH (correcting a tempting shortcut): ECH is NOT a strictly better
substitute here. ECH bootstraps its key from a DNS HTTPS record, and China and
Iran neutralize ECH precisely by censoring encrypted DNS; Russia censors
ClientHello carrying an ECH extension outright. Source: Niere et al., "Encrypted
Client Hello in Censorship Circumvention", PETS/FOCI 2025
(https://petsymposium.org/foci/2025/foci-2025-0016.pdf). WarrenGuard's
SNI-splitting has no DNS dependency, so for the China/Iran environment it is a
more robust passive choice than ECH, not a worse one.

## The vulnerability: a mutual-TLS tell exposed only to active probes

The exit demands mutual TLS client authentication, and this is the fingerprint.
Verified in code:

- `make_server_config` installs a mandatory client-certificate verifier:
  `.with_client_cert_verifier(client_verifier)` with
  `client_verifier = Arc::new(ClientCertificateVerifier)`
  (`crates/warrenguard-tls/src/lib.rs:145-151`).
- `ClientCertificateVerifier::offer_client_auth()` returns `true`, so the exit
  emits a TLS CertificateRequest, and `client_auth_mandatory()` is left at its
  trait default of `true` (not overridden), so a client presenting no
  certificate aborts the handshake
  (`crates/warrenguard-tls/src/verifier.rs:123-182`).

Two consequences matter for the threat model:

1. The mutual-auth requirement is invisible to a PASSIVE observer. In QUIC the
   CertificateRequest, Certificate, and CertificateVerify travel in Handshake
   packets encrypted under keys derived from the ephemeral key exchange, not the
   publicly-derivable Initial keys. A passive DPI box cannot see that this
   endpoint wants a client cert.
2. It is fully visible to an ACTIVE prober. A censor that completes a real
   HTTP/3 dial to the exit observes that this "website" demands a client
   certificate (or aborts the handshake when none is sent). Public HTTP/3 web
   servers essentially never request client certificates. This is an anomalous,
   stable, low-false-positive fingerprint of "not a real website".

A second, subtler point about authorization: the TLS verifier does NOT check the
client pubkey against any roster. `verify_client_cert` accepts any single
well-formed RPK (it only rejects non-empty intermediates) and
`verify_tls13_signature` only proves possession of the matching private key
(`crates/warrenguard-tls/src/verifier.rs:130-169`). Subscriber/roster
authorization happens at the application layer after the handshake, via
`peer_pubkey` (`crates/warrenguard-tls/src/lib.rs:220-224`) and the server's
authorizer. So a prober that generates a throwaway Ed25519 key completes the TLS
handshake and is rejected only at the app layer, with proxy-shaped timing and
teardown rather than a website response. Either way (no cert, or throwaway cert),
the prober gets a non-website answer. The CertificateRequest is the cleanest tell.

## Why this is hard to fix in QUIC specifically

The proven mitigations come from the TCP/TLS proxy world and do not transplant
cleanly onto QUIC:

- Trojan: completes a normal TLS handshake for everyone, authenticates in-band
  in the first encrypted application bytes (a password), and on failure proxies
  the connection to a real backend web server so a prober sees a genuine site.
  Sources: VPN-obfuscation survey
  (https://b.vpn.how/en/pages/vpn-obfuscation-in-2026-disguising-as-https-pluggable-transports-and-real-world-circumvention-cases.html);
  TrojanProbe (Sci. of Computer Programming / ScienceDirect S0167404824004528)
  shows even Trojan is fingerprintable by crafted HTTP probes if the fallback is
  imperfect, so the fallback must be a real site, not a stub.
- REALITY (Xray/XTLS): needs no owned domain or certificate; it borrows a real
  third-party site's TLS handshake (uTLS browser fingerprint, re-signed with an
  ephemeral X25519 key the real client can verify) and, on an unrecognized
  probe, forwards the probe to the genuine target site and drops. Sources:
  REALITY.ENG.md
  (https://github.com/XTLS/Xray-examples/blob/main/VLESS-TCP-XTLS-Vision-REALITY/REALITY.ENG.md);
  source analysis (https://objshadow.pages.dev/en/posts/how-reality-works/).

Both are TCP/TLS by construction (REALITY "sits between proxy protocols and TCP
connections"). The REALITY trick of forwarding an unrecognized probe to the real
target is trivial over TCP (transparent byte proxy) but not over QUIC: a QUIC
connection is cryptographically bound to THIS server from the Initial onward, so
you cannot hand a mid-flight QUIC handshake off to a third-party QUIC server.
A realistic QUIC fallback therefore means serving genuine HTTP/3 yourself on the
same endpoint, which pulls in a real h3 stack (the MASQUE co-tenancy path from
ADR-0001). There is no mature QUIC-REALITY.

Residual fingerprint beyond the CertificateRequest: even with in-band auth, a
sophisticated prober can fingerprint the QUIC transport parameters and HTTP/3
SETTINGS frame against real browsers (JA4/QUIC), so full mimicry would also need
a uTLS-for-QUIC equivalent. Source: HTTP/3 QUIC fingerprinting overview
(https://scrapfly.io/blog/posts/http2-http3-fingerprinting-guide).

## Options, with cost

1. Do nothing; declare active probing out of scope. Cost: zero. Valid if the
   target adversary is a commercial/ISP DPI box, not a GFW-class active prober.
   Most deployments are in this class. The passive posture already covers them.

2. Remove the CertificateRequest tell (Trojan-style in-band auth). Set
   `offer_client_auth(false)`, complete the handshake like a normal h3 server,
   and move client identity + proof-of-possession into the existing `Setup`
   frame (sign a server-provided challenge). On an invalid/absent `Setup`, fall
   back. Cost: medium. It re-architects how session identity is established
   (today `peer_pubkey` reads it from the TLS layer; it would move in-band),
   touches `warrenguard-tls`, `warrenguard-wire`, and `warrenguard-server`, and
   needs new frozen-vector tests. It removes the cleanest tell but not the QUIC
   transport-parameter fingerprint, and the "fall back" still needs option 3 to
   be convincing against a prober that sends a real h3 request.

3. Real HTTP/3 decoy co-tenancy (MASQUE-adjacent). Serve a genuine site on `/`
   and tunnel only for authenticated requests on the same h3 connection. Cost:
   high, and gated on the immature Rust ecosystem documented in the MASQUE
   analysis (no production CONNECT-IP on quinn; `h3`/`h3-datagram` experimental).
   Strongest active-probing resistance; only worth it for a confirmed GFW-class
   threat model.

## Decision

A GFW-class active prober IS in scope. Option 2 is selected: remove the
CertificateRequest tell and move client authentication in-band into the existing
`Setup` frame, channel-bound against the QUIC/TLS session to stay replay-safe.
Option 3 (real h3 decoy co-tenancy) remains a documented phase-2 follow-up; it is
NOT in this change. Option 1 (do nothing) is rejected.

This is implemented on branch `feat/inband-setup-auth`.

## Implementation design (option 2)

### Authentication construction (channel-bound proof of possession)

The TLS layer stops authenticating the client. The client proves possession of
its Ed25519 identity key in-band, bound to the unique QUIC session so a captured
`Setup` cannot be replayed onto another connection:

- Channel binding value: `cb = QUIC_export_keying_material(label, 32)` where
  `label = b"warrenguard in-band client auth v1"`. quinn exposes
  `Connection::export_keying_material`; both peers derive the same 32 bytes from
  the TLS key schedule, and an on-path observer cannot (it never sees the master
  secret). This replaces the old TLS CertificateVerify transcript binding.
- The client signs a domain-separated message
  `CLIENT_AUTH_CONTEXT_V1 || cb || device_id` (context
  `b"warrenguard/inband-auth/v1"`, then the 32-byte `cb`, then the 16-byte
  `Setup::device_id`) with its Ed25519 identity key, and sends
  `(client_pubkey, auth_sig)` in `Setup`.
- The exit recomputes `cb`, rebuilds the same message with `setup.device_id`,
  verifies `auth_sig` against `client_pubkey`, and only then runs the existing
  `Authorizer::is_allowed(client_pubkey)` gate. A failed verification is treated
  as an unauthenticated connection (see fallback).

`cb` is sound channel binding: a different exit has a different `cb`, so a relayed
or recorded proof fails. `client_pubkey` is implicitly bound (the signature is
verified under it). The `device_id` is folded in as DEFENSE IN DEPTH: it binds
the authenticated identity to the `device_id` the exit keys its session and
device-cap on, so the proof is self-contained and does not rely on the transport
for that field's integrity. This is redundant on the single-hop path (QUIC's AEAD
already protects `device_id` end-to-end and the channel binding already defeats a
terminating intermediary), but it is cheap (zero perf: Ed25519 hashes the message,
and 26+32+16 bytes still fit one SHA-512 block) and future-proofs the proof if the
topology ever changes. The context prefix keeps an in-band-auth signature from
being confused with the same key's multi-hop PoP signature. The signed-message
layout is frozen by `auth::tests::signing_message_layout_is_frozen`.

### TLS layer changes (`warrenguard-tls`)

- `make_server_config` / `make_server_config_with_rotation`: replace
  `.with_client_cert_verifier(ClientCertificateVerifier)` with
  `.with_no_client_auth()`. No CertificateRequest is emitted; the exit now looks
  exactly like an ordinary server-auth-only HTTP/3 endpoint. This is the actual
  removal of the active-probing tell.
- `make_client_config`: stop presenting a client RPK certificate.
- New helpers: `channel_binding(conn) -> [u8; 32]` (export keying material with
  the Warren label), `sign_channel_binding(key, cb) -> [u8; 64]`, and
  `verify_channel_binding(pubkey, cb, sig) -> bool`. `peer_pubkey` /
  `pubkey_from_certs` and `ClientCertificateVerifier` are removed (client RPK is
  no longer a TLS concept). Server cert verification (client verifies the exit
  via SNI-pinned pubkey) is UNCHANGED.

### Wire changes (`warrenguard-wire`)

- Bump `PROTOCOL_VERSION` 4 -> 5.
- Add `Setup::client_pubkey: [u8; 32]` and `Setup::auth_sig: [u8; 64]`.
- `decode_setup` keeps strict trailing-byte and version checks. Add a frozen
  wire-format vector test for v5 (fixed dummy pubkey/sig bytes lock the layout,
  not a live crypto op, matching the existing v4 vector style).

### Server changes (`warrenguard-server`)

- In `handshake_from_incoming` and `handshake_only`: replace
  `warrenguard_tls::peer_pubkey(&conn)` with: read `Setup`, then
  `verify_channel_binding(setup.client_pubkey, channel_binding(&conn), setup.auth_sig)`.
  On failure, close without proxy-distinctive signaling (the handshake already
  completed like a website; we add no extra tell). `SessionKey` stays
  `(client_pubkey, device_id)`; only the pubkey source moves from TLS to in-band.
- `Authorizer` trait and `is_allowed` are unchanged in shape.

### Out of scope for this change (recorded, not done)

- Real h3 decoy fallback on auth failure (option 3). Until then, a prober that
  completes the handshake sees a normal-looking close, which is strictly better
  than the old CertificateRequest tell but not a served web page.
- QUIC transport-parameter / h3 SETTINGS fingerprint parity (uTLS-for-QUIC).
- Rollout interop between v4 (mutual-TLS) and v5 (in-band) clients. The engine
  switches cleanly and bumps the version; staged rollout is a deployer concern.

### Relay / multihop

Unaffected: the relay performs no client auth (stateless client-facing side) and
multihop already conveys client identity out of the exit's TLS peer. To verify,
not assume: the implementation must confirm `export_keying_material` on a
multihop exit binds to the client-terminated session and not the relay hop before
this lands.

## Consequences

- The mutual-TLS CertificateRequest is now documented as a known active-probing
  tell, not an oversight. Any change to `offer_client_auth` /
  `ClientCertificateVerifier` is a censorship-posture change and must reference
  this ADR.
- The passive obfuscation knobs (SNI split, padded Initials) are validated
  against USENIX Security 2025 and must not regress; they are guarded by
  `crates/warrenguard-transport-core/tests/m40_obfuscation_invariants.rs` and the
  fork-patch test.
- The SNI suffix `.exits.warrenbrowse.com` is a single point of failure if the
  GFW ever reassembles split Initials: it becomes a trivially blockable domain.
  This is acceptable only while the split holds; the suffix is already a
  deployer-overridable default (README.md:59-63).
- ECH is recorded as NOT a drop-in upgrade for the China/Iran environment due to
  its encrypted-DNS bootstrap dependency.

## Realized changes (as shipped)

Breaking changes a consumer must absorb when adopting v5:

- Wire: `Setup` gains `client_pubkey: [u8; 32]` and `auth_sig: AuthSig([u8; 64])`;
  `PROTOCOL_VERSION` is 5. v4 and v5 do not interoperate (postcard with
  `deny_unknown_fields`). New builder `Setup::with_auth(client_pubkey, auth_sig)`.
- TLS public API: `make_client_config(crypto_provider, alpns)` no longer takes a
  client `SigningKey` (the client is anonymous at TLS). `make_server_config` now
  uses `with_no_client_auth()`. `peer_pubkey` / `pubkey_from_certs` /
  `ClientCertificateVerifier` are removed. New: `channel_binding`,
  `sign_client_auth`, `verify_client_auth` (module `warrenguard_tls::auth`,
  exporter label `b"warrenguard in-band client auth v1"`, signed-message context
  `b"warrenguard/inband-auth/v1"`; the proof binds `cb` and `device_id`).
- Relay: `ExitConnPool::new` / `new_with_warren_obfuscation` / `new_default` drop
  the `client_signing_key` parameter (the relay is anonymous toward the exit at
  the TLS layer; client identity travels via the multi-hop PoP, unchanged).
- Error: `TunnelError::TlsPubkeyExtract` is replaced by `ChannelBindingExport`
  and `InbandAuthFailed`.

Follow-ups, each now with its own record:

- Real-h3 decoy fallback on auth failure (option 3): the engine SEAM is now
  shipped (ADR-0003) - `UnauthenticatedHandler` + `ExitBindOpts`, routing an
  unauthenticated connection to a deployer-provided handler. The decoy itself (a
  real HTTP/3 site, with the experimental `h3` dependency) is left to the
  deployer. With no handler configured (default) the exit still closes cleanly on
  auth failure: no proxy-distinctive signaling, strictly better than the old
  CertificateRequest tell, but not a served web page.
- QUIC / h3 fingerprint parity (uTLS-for-QUIC): audited in ADR-0004, research-
  grade (no Rust uTLS-for-QUIC exists), left as a documented residual.
- v4<->v5 rollout: deliberately lockstep, NOT interoperable. Re-admitting v4 on a
  v5 exit would either re-introduce the mutual-TLS tell or admit an
  unauthenticated peer, so it is rejected by design. Pinned by the wire test
  `previous_protocol_v4_is_rejected_no_interop`; staged deployment (drain v4,
  then enable v5) is the deployer's operational concern.
