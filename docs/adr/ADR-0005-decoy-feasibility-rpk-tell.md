# ADR-0005: Active-probe decoy feasibility, and the RPK upstream tell

Status: accepted (feasibility and audit record; the decoy is NOT implemented and
remains deployer territory, cf. ADR-0003). Its engine-side prerequisite, the v6
X.509 migration described below, has since SHIPPED (protocol v6; see the code and
`docs/30-GFW-ACTIVATION-GUIDE.md`).
Date: 2026-06-23
Related: ADR-0003 (active-probe decoy seam), ADR-0002 (active-probing threat
model), ADR-0004 (QUIC fingerprint parity), ADR-0001 (why QUIC)

## Context

ADR-0003 shipped the engine SEAM (`UnauthenticatedHandler` +
`ExitBindOpts::unauthenticated_handler`) and deferred the DECOY itself (a real
HTTP/3 responder) to the deployer (warren-core), gated on two triggers: a
confirmed GFW-class active prober against deployed exits, OR `h3`/`h3-quinn`
reaching a stable release.

This ADR is the deeper feasibility study of the decoy itself, requested before
any warren-core work. It evaluates usefulness, security, performance,
non-regression, and side effects. It records a decisive finding that ADR-0003 did
not surface: as the engine authenticates the exit today, the decoy is
unreachable by the exact adversary it is meant to fool, so it cannot be
"undetectable" without a prerequisite engine change. The decoy is therefore
gated on a THIRD condition, documented here.

## Decisive finding: the exit's RPK identity is an active-probe tell upstream of the seam

The exit authenticates itself with TLS 1.3 Raw Public Keys (RFC 7250), not X.509.
Verified in code:

- `crates/warrenguard-tls/src/resolver.rs:100,113`: both server cert resolvers
  return `only_raw_public_keys() -> true`. The exit holds no X.509 certificate;
  its end-entity "cert" is the raw Ed25519 SPKI.
- `crates/warrenguard-tls/src/lib.rs:5-8`: "no PKI, no X.509 chain, and no trust
  anchor list; the client verifies the exit's pubkey against the SNI it dialed".

Consequence on the active-probing path:

A GFW-class prober dials the exit with an ordinary HTTP/3 client (Chrome, curl,
quiche). Its ClientHello does NOT carry the `server_certificate_type`
extension, so per RFC 7250 it expects X.509. The exit has no X.509 to present and
accepts only RPK, so the TLS handshake aborts at certificate negotiation, BEFORE
HTTP/3, BEFORE the `Setup` frame, BEFORE the `UnauthenticatedHandler` seam is ever
reached. rustls's cert-type negotiation in mixed cases is itself imperfect and
emits a distinctive `UnsolicitedCertificateTypeExtension` / handshake_failure
(rustls#2257, https://github.com/rustls/rustls/issues/2257), so the abort is not
only certain but fingerprintable.

The seam fires only after a fully completed handshake (the exit calls
`incoming.await`, then `accept_bi`, then `read_to_end` on the Setup stream; all of
this presupposes a successful RPK handshake). Therefore the decoy is visible ONLY
to a peer that already speaks the full Warren RPK handshake: a real but
mis-authenticating Warren client, or a targeted adversary who has reverse
engineered Warren enough to offer the RPK cert-type extension. Against the generic
prober the decoy is meant to defeat, the connection is already dead one layer
earlier. A decoy installed on the current stack would buy a false sense of
protection.

## Secondary finding: a passive ClientHello tell, orthogonal to the SNI split

The QUIC ClientHello travels in Initial packets, protected only by keys derived
from the public connection ID, so it is passively readable. The GFW already
decrypts QUIC Initials at scale for SNI (ADR-0002). The Warren CLIENT offers
`server_certificate_type=RawPublicKey` in that ClientHello, which no browser
sends. This is a passive, browser-anomalous fingerprint that is INDEPENDENT of
the SNI and therefore NOT mitigated by the SNI split. It is crisper than the
"extension order" residual of ADR-0004: a single present/absent extension,
trivial to match. ECH would hide it, but ADR-0002 rejected ECH for the
China/Iran environment (encrypted-DNS bootstrap dependency).

## Ecosystem state (ADR-0003 trigger b, re-checked 2026-06)

`h3` is at 0.0.7 and `h3-quinn` at 0.0.8; the project README still labels the
stack "still very experimental ... there may still be bugs, and the API could
change" (https://github.com/hyperium/h3,
https://github.com/hyperium/h3/releases). Pulling it into a security data plane
remains the risk ADR-0003 declined. Trigger (b) is NOT met.

## Options, with cost

| Option | What it does | Useful vs. a generic active prober | Cost | Verdict |
| --- | --- | --- | --- | --- |
| A. Decoy on the current seam (RPK kept) | Serves an h3 site to peers that complete the RPK handshake but present no valid `Setup` | No: the generic prober fails at TLS before the seam | Medium (experimental h3) | Misleading; rejected |
| B. REALITY-grade decoy | The exit completes a real X.509 handshake with anyone, serves a real h3 site to non-Warren peers, tunnels for Warren peers | Yes | High, multi-phase, engine-first | The only path that meets the goal |
| C. Documented status quo | Clean close on unauthenticated connections (already shipped) | N/A (a close is not a served page, but is >= the old CertificateRequest tell) | Zero | Recommended until a trigger fires |

The load-bearing point: "undetectable" requires Option B, and Option B is NOT a
warren-core task first. It is an engine change first. While the exit proves its
identity only through RPK-via-SNI, the decoy is unreachable by the intended
adversary.

## The staged plan for Option B (recorded, not executed)

Dependency order. Each stage is a precondition for the next.

### Stage 0: triggers (non-code)
Do not implement until (a) a deployed exit is confirmed fingerprinted by active
HTTP/3 probing, OR (b) `h3` ships a stable release. Neither is met today.

### Stage 1: engine "v6", move the exit identity off the TLS layer (symmetric to what v5 did for the client)
- The exit presents a real X.509 certificate (real domain + ACME) to every
  client, and proves its Warren identity in-band only: it signs the QUIC channel
  binding (RFC 5705) with its Ed25519 key in `SetupAck`. The client's
  `ServerCertificateVerifier` stops checking the RPK SPKI and verifies the in-band
  proof instead. SNI stops being `pubkey.exits.warrenbrowse.com` and becomes a
  plausible domain.
- Security: replaces RPK server auth with an Ed25519 signature over the channel
  binding, the exact v5 pattern already audited and `verify_strict`. No loss of
  guarantee; an MITM holding a valid X.509 cert still cannot forge the exit's
  signature. Gain: the ClientHello becomes browser-shaped, removing passive tell
  #2.
- Performance: +1 Ed25519 sign / +1 verify per handshake (negligible, already the
  case client-side in v5). Zero data-plane impact.
- Non-regression: this is a v5 -> v6 wire break (lockstep, no interop, like v5),
  so it needs cross-repo re-pin and v6 golden vectors, exactly like the v5
  migration. `make_server_config` must do cert-type-conditional resolution (RPK if
  the client offers the extension during transition, X.509 otherwise), and
  rustls#2257 shows that mixed path is buggy, so strict TDD plus an e2e test with
  a real non-Warren h3 client is mandatory.
- Side effect / true cost: requires a real PKI on the exits (ACME, rotation, TLS
  private-key storage), the very thing the "no PKI" design avoided.

### Stage 2: the decoy itself, in warren-core, behind the seam
- Plug-in point: `warren-exit/src/main.rs` (`unauthenticated_handler: None` today)
  becomes `Some(Arc::new(DecoyHandler::new(cfg)))`. The seam is already correct:
  live connection, completed handshake, `h3` ALPN already negotiated, accept loop
  treats `DivertedToDecoy` as a non-error.
- Critical constraint: the engine has ALREADY consumed the client's first bidi
  stream (`accept_bi` + `read_to_end` of the invalid Setup) before the handler
  receives the connection. The decoy cannot replay that stream; it must accept the
  SUBSEQUENT streams (h3 opens its control stream and new request streams anyway).
  Validate in TDD that `h3_quinn::Connection::new(conn)` works on a connection
  whose stream 0 is already finished/reset. This is the decoy's #1 technical risk
  and must be proven before anything else.
- Undetectability (TrojanProbe lesson, ADR-0002): the served site must be a REAL
  site consistent with the cert domain (Stage 1), not a stub; an imperfect h3
  responder is more fingerprintable than a clean close. Either reverse-proxy a
  local web backend or serve substantial static content; headers, timing, and
  error behaviour must match a real server.
- Security / no leak: the handler must never log the source IP (CLAUDE.md), never
  reuse tunnel state, and be strictly resource-bounded (a prober can open many
  decoy connections, so a dedicated semaphore + timeout + memory cap, or it
  becomes a DoS vector that the current clean close does not have). `handle()` must
  not block the accept loop; spawn immediately (the trait contract requires it).
- Performance / tunnel non-regression: zero by construction. The seam fires only
  on the `reject_unauthenticated` branch, never on the authenticated path, and the
  `None` handler stays zero-cost. This is the only part that is already safe today.

### Stage 3: fingerprint parity (ADR-0004)
Even after B, the JA4Q quinn-vs-browser profile (transport params, extension
order) remains. Research-grade, no Rust uTLS-for-QUIC exists. Out of scope unless
a JA4Q-blocking adversary is proven. Unchanged.

## Decision

1. Do not implement the decoy now. No ADR-0003 trigger is met, `h3` is still
   0.0.x, and, decisively, the decoy is unreachable by the intended adversary
   until Stage 1 (moving the exit identity off RPK) is done. Building it first
   would deliver Option A: a false sense of protection.
2. Record a THIRD gate on the decoy, beyond ADR-0003's two: the exit must first
   complete a normal X.509 handshake with an arbitrary client (Stage 1 / a v6
   engine change), or the decoy is invisible to a generic active prober.
3. The only no-regret decoy work available today is a disabled `DecoyHandler`
   skeleton behind the seam, purely to validate the Stage 2 #1 risk (h3 over a
   consumed stream 0) in TDD, without activating it and without adding any
   dependency on the tunnel path. Defer even this until there is intent to pursue
   Option B.

## When to revisit

- A deployed exit is confirmed fingerprinted or blocked via active HTTP/3 probing
  (then Stage 1 first, Stage 2 second).
- `h3` / `h3-quinn` ship a stable release.
- The product decides active-probe resistance is a launch requirement for a
  censored market; then schedule the v6 exit-identity change (Stage 1) as the
  prerequisite, not the decoy.

## Consequences

- The active-probe residual stands as in ADR-0002/0003: an active prober gets a
  clean close (or, with a generic client, a TLS abort at RPK negotiation), not a
  served page. This is strictly better than the old CertificateRequest tell but is
  not website mimicry.
- A new passive residual is now on record: the client's
  `server_certificate_type=RawPublicKey` ClientHello extension is a
  browser-anomalous fingerprint not covered by the SNI split. Closing it is part
  of Stage 1, not a standalone fix.
- Any future move to implement the decoy MUST sequence Stage 1 (engine) before
  Stage 2 (warren-core), and MUST NOT regress the ADR-0002 obfuscation invariants
  (guarded by `crates/warrenguard-transport-core/tests/m40_obfuscation_invariants.rs`
  and the fork-patch test) or the authenticated handshake path and its tests.

## Stage 1 ACTIVATION (2026-06-24): decisions, shipped foundation, execution plan

Stage 1 was triggered by a product decision (D0 = a censored market is a
near-term target; see warren-core `docs/adr/ADR-0001` register). Two sub-decisions
were taken (poka):

- **Cover domain / SNI**: a single **neutral Warren-owned domain with a wildcard
  cert** (`*.<neutral-domain>`, name TBD by poka for branding/opsec). Replaces the
  self-identifying `<pubkey>.exits.warrenbrowse.com`. The exit pubkey moves
  entirely out of the SNI; the client learns the expected exit pubkey from the
  signed roster and uses it only to verify the in-band proof.
- **Cert issuance**: **DNS-01 wildcard, issued centrally and pushed** to the
  exits (no per-exit HTTP-01: the NL aadeploy appliance, Alpine/musl/s6 with no
  scp/sudo, makes per-exit ACME impractical).

### Foundation SHIPPED (decision-free, additive, no wire/version change)

warrenguard `4191801`: `warrenguard_tls::auth::{sign_server_auth,
verify_server_auth, server_auth_signing_message, SERVER_AUTH_CONTEXT_V1}`. The
exit signs the QUIC channel binding (RFC 5705) under
`warrenguard/inband-server-auth/v1`; the client verifies against the expected
roster pubkey. Mirrors the audited v5 client auth (`verify_strict`, frozen
vector, fails closed). This defeats an MITM holding a valid-but-different X.509
cert: it controls the channel binding but cannot forge the exit's Ed25519 proof.
6 TDD tests in `crates/warrenguard-tls/src/auth.rs`.

### The v6 migration (SHIPPED, protocol v6) - lockstep, no interop, like v5

Landed complete as the 5 steps below (`PROTOCOL_VERSION = 6`,
`SetupAck::exit_auth_sig`, the WebPKI client verifier + X.509 exit resolver, and
`sign`/`verify_server_auth`). Deploy stays coordinated (drain v5 exits, deploy
v6); the prod wildcard cert is the remaining DEPLOY prerequisite, not a BUILD one.

1. **Wire (warrenguard-wire)**: `SetupAck` gains `exit_auth_sig: [u8; 64]`; bump
   `PROTOCOL_VERSION` 5 -> 6; frozen v6 vector; `previous_v5_is_rejected_no_interop`.
2. **Exit handshake (warrenguard-server)**: after the TLS handshake, compute the
   channel binding and `sign_server_auth(exit_identity, cb)` into `SetupAck`.
3. **Client handshake (warrenguard-transport)**: read `exit_auth_sig`, recompute
   cb, `verify_server_auth(expected_exit_pubkey, cb, sig)`; reject on failure.
4. **TLS (warrenguard-tls)**, the security-critical part, **MCP rust-docs
   verification mandatory (CLAUDE.md §5)**: exit resolver presents an **X.509**
   cert (loaded from the pushed wildcard) instead of RPK; client verifier checks
   a normal cert chain for the cover domain (drop `only_raw_public_keys`, drop the
   SNI-pinned-RPK check). Mind rustls#2257 (mixed cert-type path is buggy);
   strict TDD + an **e2e with a real non-Warren h3 client** that must complete the
   TLS handshake (proving the exit looks like an ordinary website).
5. **SNI/dial (warrenguard-transport + warren-core warren-exit + warren-app
   talpid)**: client dials the cover-domain SNI (config), no pubkey in SNI; exit
   loads cert path + cover domain from config; expected exit pubkey flows from the
   roster to the in-band verifier.

### Infra prerequisite (poka, critical path, blocks DEPLOY not BUILD)

The neutral domain + DNS-01 wildcard cert + a push mechanism to all exits (incl.
the NL appliance via its existing channel) must exist before a v6 exit can serve
X.509. The engine v6 BUILD can proceed against test certs; only the prod DEPLOY
needs the real cert. This is the true critical path for the user-facing payoff
(closing R3 SNI + R4 RPK tell).

### TLS implementation spec (as shipped, grounded in pinned rustls 0.23.40)

Grounded in the pinned TLS code (`crates/warrenguard-tls/src/{lib,resolver,
verifier}.rs`). Records the API contract the v6 X.509 handshake implements:

- **Exit (server), today**: `ServerConfig::builder_with_provider(p)
  .with_protocol_versions(TLS13).with_no_client_auth().with_cert_resolver(rpk)`
  where `rpk: ResolvesServerCert` returns a `CertifiedKey` whose end-entity is the
  Ed25519 SPKI and `only_raw_public_keys() -> true`
  (`resolver.rs`). **v6 change**: serve the real wildcard chain instead, i.e.
  build a `CertifiedKey` from the LE cert chain + its private key
  (`provider.key_provider.load_private_key(..)`, typically ECDSA P-256) and use
  `with_single_cert(chain, key)` (or a resolver with `only_raw_public_keys ->
  false`). The exit's Ed25519 identity leaves TLS entirely; it is used ONLY for
  `auth::sign_server_auth(cb)` into `SetupAck`.
- **Client, today**: `ClientConfig::builder_with_provider(p)
  .with_protocol_versions(TLS13).dangerous()
  .with_custom_certificate_verifier(ServerCertificateVerifier)` which decodes the
  exit pubkey FROM THE SNI and checks the RPK SPKI + `CertificateVerify` via
  `verify_tls13_signature_with_raw_key`, with `SUPPORTED_SIG_ALGS` restricted to
  Ed25519 (`verifier.rs`). **v6 change**: drop the custom verifier; use the
  standard `WebPkiServerVerifier` over a Mozilla `RootCertStore`
  (`.with_root_certificates(roots).with_no_client_auth()`) so the client validates
  the exit's real chain for the cover domain exactly like a browser. The Ed25519
  `SUPPORTED_SIG_ALGS` restriction is dropped (WebPki uses the provider's algs,
  needed for the ECDSA/RSA LE cert). The Warren-identity check moves OUT of TLS to
  `auth::verify_server_auth(expected_exit_pubkey, cb, setupack.exit_auth_sig)`.
- **SNI**: client dials `ServerName::DnsName(<cover-domain>)` (config), not
  `<pubkey>.exits.warrenbrowse.com`. The `name::{encode,decode}` SNI<->pubkey
  codec is no longer on the dial path (kept only if needed elsewhere).
- **Client API**: `ClientTunnel` must receive the EXPECTED exit pubkey (from the
  signed roster) to verify the in-band proof, since it is no longer in the SNI.
  New builder, e.g. `with_expected_exit_pubkey(WarrenPubkey)`.

KEY FINDING (de-risks the migration): going **pure** X.509 lockstep (the client
stops offering `server_certificate_type=RawPublicKey` entirely, no mixed
RPK/X.509 cert-type negotiation) **sidesteps rustls#2257**, whose bug is only in
the MIXED cert-type path. ADR-0003/ADR-0005 flagged #2257 as a risk; the lockstep
no-interop design removes it. This also removes passive tell #2 (the
browser-anomalous RPK ClientHello extension) cleanly.

Tests: a loopback handshake where a STANDARD quinn+rustls (WebPki) client
completes the X.509 handshake to the exit is the e2e "looks like a real website"
proof; plus the in-band proof verifies; plus an MITM presenting a different valid
cert is rejected by `verify_server_auth`. Needs a test cert (add `rcgen`
dev-dep, or a checked-in fixture).
