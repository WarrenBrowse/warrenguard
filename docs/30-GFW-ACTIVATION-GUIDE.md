# GFW activation guide (wg-0005)

How a deployer turns on the full anti-censorship posture of the WarrenGuard
engine, what is on by default, and which switches are deliberately gated.

This is an operational guide, not a design record. The rationale lives in the
ADRs it references.

## What is ON by default (no action required)

These ship enabled in the engine and need no deployer flag:

- **SNI-split on every GFW-facing leg.** The client pads its first Initial to
  1280 B and caps the first CRYPTO chunk to 64 B, so the ClientHello SNI lands
  in a second UDP datagram that the GFW QUIC SNI extractor (USENIX Security
  2025) does not reassemble. Applied on the single-hop client
  (`warren_transport_config_client_*`) and, since wg-0005 Lot E, on the
  multi-hop client->relay leg (`warren_transport_config_client_multihop_*`),
  which is the only hop a GFW-class censor observes. The relay->exit and
  inbound multi-hop profiles stay no-pad on purpose (a padded ServerHello is
  dropped on a low-PMTU intercontinental hop). See ADR-0002.
- **h3 ALPN, spin bit 0, UDP/443.** The flow stays in the "looks like HTTP/3"
  exemption class rather than the "fully encrypted" block class (USENIX
  Security 2023). See ADR-0004.
- **No CertificateRequest tell.** Since protocol v5 the exit requests no client
  certificate; the client authenticates in-band over the QUIC channel binding.
  See ADR-0002.

## v6 X.509 cover-domain mode (opt-in, recommended for GFW)

By default the exit authenticates via a raw Ed25519 public key encoded in the
SNI (`<pubkey>.exits.warrenbrowse.com`). That SNI is self-identifying and the
RawPublicKey ClientHello extension is browser-anomalous (ADR-0005). v6 swaps
both for an ordinary X.509 handshake against a plausible cover domain; the
Warren identity is proven in-band in `SetupAck::exit_auth_sig`. This is the
mode to run behind the GFW.

It is opt-in because it requires a real certificate. To activate:

### Exit side

Provide a PEM certificate chain + key (an ACME `fullchain.pem` /
`privkey.pem`, or a self-hosted CA leaf):

- Reference CLI: `warrenguard serve --tls-cert fullchain.pem --tls-key privkey.pem`
  (or `WARREN_TLS_CERT` / `WARREN_TLS_KEY`).
- Library: set `ExitBindOpts::tls_certificate = Some((chain_der, key_der))`.
  Load PEM with `warrenguard_tls::load_cert_chain_pem` /
  `load_private_key_pem`.

When set, the exit presents the cert and looks like an ordinary HTTPS/h3
server to a generic active prober.

**Caveat for multi-hop / dual-role exits.** `ExitBindOpts::tls_certificate`
configures the single-hop exit listener. A consumer that runs a separate
unified multi-hop / dual-role QUIC endpoint (its own `quinn::Endpoint`) must
wire the X.509 server config into THAT endpoint too, or it will keep presenting
the RPK cert while the roster advertises a cover domain, and X.509 clients fail
the WebPKI handshake. The consumer should not advertise a cover domain for an
exit whose client-facing endpoint still serves RPK.

### Client side

Dial the cover domain as SNI and validate the chain via WebPKI:

- Public-ACME cert: `ClientTunnel::with_x509_webpki(cover_domain)` (validates
  against the bundled Mozilla roots, `warrenguard_tls::mozilla_root_store`).
- Self-hosted CA: `ClientTunnel::with_x509(roots_der, cover_domain)`.
- Reference CLI: `warrenguard connect --cover-domain cover.example.com [--ca ca.pem]`.

The expected exit identity is taken from the dialed target's pubkey (the signed
roster), so a MITM holding a valid cert for the cover domain still cannot forge
the in-band proof.

### Cover-domain rotation (wg-0005 Lot C)

One exit can serve several cover domains at once, so a deployer rotates the
cover domain (serve the old and the new name during the migration window)
without a redeploy, and a single blocked domain never strands the exit:

- `ExitBindOpts::tls_certificates_by_sni: Vec<(domain, chain_der, key_der)>`
  routes each declared domain to its own cert; `tls_certificate` is the default
  for any other or absent SNI.

**Policy is a backend concern.** The engine provides the mechanism (serve N
cover domains, dial a given one); which domains to use and when to rotate is
the control-plane's job (CLAUDE.md: no product policy in the engine). For a
serious GFW deployment, use rotating / per-deployment cover domains rather than
the `.exits.warrenbrowse.com` default, which is a single blockable suffix.

## Gated switches (do not flip blindly)

These close real residual tells but are gated on validation that this engine
checkout cannot perform on its own:

- **Default-on `WARREN_IDLE_COVER` for censored profiles** (ADR-0006). The keep-alive metronome
  (periodic unpadded PING) is a traffic-analysis tell. The idle-cover pump
  removes it, but turning it on by default is gated on a real-network bench
  (cost measurement, `WARREN_MNEMONIC` against the test backend). Until then it
  stays opt-in via the `WARREN_IDLE_COVER` knob.
- **v6 X.509 as the consumer default.** Flipping production to X.509 is a
  cross-repo + infra step, not an engine default (the engine cannot default to
  X.509 without a cert to present): it needs a neutral domain + DNS-01 wildcard
  cert pushed to every exit, and the consumers (`warren-exit`, `warren-app` /
  SDK) wiring `tls_certificate` / `with_x509_webpki` unconditionally. See
  ADR-0005 Stage 1.

## Not yet built (tracked residuals)

- **Real HTTP/3 decoy on auth failure** (ADR-0005 Stage 2). The engine seam is
  shipped (`ExitBindOpts::unauthenticated_handler`); the decoy itself is a
  backend concern, gated on a stable `h3` crate. Default behaviour is a clean
  close.
- **JA4Q / QUIC transport-parameter + h3 SETTINGS fingerprint parity**
  (ADR-0004). No uTLS-for-QUIC exists in Rust; documented residual.

## Cross-repo integration status (wg-0005 Lot F)

The engine APIs above are consumed by the sibling repos (not part of this repo).
Verified against this engine checkout:

- **Exit (`warren-core` / `warren-exit`): DONE.** Single-cover-domain X.509 is
  wired end to end: `--tls-cert` / `--tls-key` (env `WARREN_TLS_CERT` /
  `WARREN_TLS_KEY`) load a PEM pair into `ExitBindOpts::tls_certificate`
  (`warren-core/crates/warren-exit/src/main.rs:201-213, 688-694`).
  `warren-exit` compiles cleanly against the new engine, including the
  `tls_certificates_by_sni` field (`main.rs:698`, left empty: the multi-cover
  CLI surface is a deferred warren-core task; the engine mechanism is ready).
- **Exit cover-domain rotation: DONE.** `warren-exit` takes repeatable
  `--tls-cert-sni <domain>=<cert.pem>=<key.pem>` (in addition to the default
  `--tls-cert`), so one exit serves the old and the new cover domain at once
  during a migration (engine `tls_certificates_by_sni`).
- **App (`warren-app` / `talpid-warren-tunnel`): DONE (per-exit via roster +
  shared-env fallback).** The tunnel dials the per-exit `cover_domain` from the
  signed roster automatically and validates the chain via the Mozilla roots
  (`talpid-warren-tunnel/src/lib.rs`, `resolve_cover_domain` -> `with_x509_webpki`).
  `WARREN_COVER_DOMAIN`, when set, is the fallback for exits whose roster entry
  carries no domain; no domain anywhere keeps RPK. Build with warren-app's own
  toolchain (it pins newer Rust than the engine MSRV 1.89 via the Mullvad/talpid
  crates).

This matches the ADR-0005 Stage 1 design: a single neutral Warren-owned cover
domain (one wildcard cert pushed to every exit), configured on the client. A
rotation is: deploy the new cert on the exits with `--tls-cert-sni` so they
serve old + new, flip `WARREN_COVER_DOMAIN` on clients, retire the old.

Because it is lockstep (a v6 X.509 exit and an RPK client do not interoperate),
roll out by enabling X.509 on the exits while still serving RPK is NOT possible
on one listener; stage by exit pool, or keep both an RPK exit pool and an X.509
exit pool during the transition.

### Per-exit cover domains via the signed roster (DONE, signed-list v8)

The single shared cover domain is one blockable suffix. Per-exit distinct
domains (stronger against targeted blocking) reach the client through the
**signed exit roster** so they cannot be spoofed. This shipped as signed-list
v8: the roster carries an optional per-node `cover_domain`, and the client dials
it automatically (no env needed), preferring it over `WARREN_COVER_DOMAIN`.

End-to-end path, all live:
- Exit declares its domain: `warren-exit --cover-domain <exit-id>.cover.example.com`
  (env `WARREN_COVER_DOMAIN`), sent in `RegisterExitRequest`.
- warren-api signs it into the roster (`SIGNED_VERSION = 8`, `JsonNode.cover_domain`).
- The SDK / daemon resolve it onto the dial target
  (`warren-relay-selector` threads `cover_domain` onto `WarrenExitAddr`;
  `warren-discovery` does the same for the Rust SDK `Relay`).
- `talpid-warren-tunnel` dials the per-exit domain via WebPKI; the
  `WARREN_COVER_DOMAIN` env remains the fallback for exits whose roster entry
  carries none.

Lockstep: v7 and v8 rosters do not interoperate; roll the roster bump out
alongside the clients that understand it. The Rust SDK's own (RPK-only)
transport refuses an X.509 exit with `SdkError::CoverDomainUnsupported` rather
than mis-dialing; the production client is `warren-app` via the engine transport.

## Production operations (continuous deployment)

This section is the operational runbook for running v6 X.509 in production:
why a real certificate and per-exit cover domains are needed, and how the
certificate + rotation lifecycle runs hands-off. The engine ships the
mechanisms; the pipeline below is the control-plane's responsibility.

### Why a real (ACME) certificate is required

In RPK mode the exit "proves who it is" by presenting its raw Ed25519 key as the
SNI/cert. No real website does that, so it is a tell. X.509 mode requires the
exit to present a certificate a browser would accept, i.e. one signed by a public
CA (Let's Encrypt) for a domain you actually own. Such a certificate cannot be
forged; it must be obtained via ACME. The client validates against the Mozilla
root program, so without a real public-CA certificate the handshake is rejected.
A wildcard (`*.cover.example.com`) lets the whole exit fleet share one
certificate instead of one per machine.

### Why per-exit cover domains (the signed-roster step)

A single shared cover domain is one blockable string: once the censor learns
`cover.example.com` is Warren, it blocklists that SNI and the entire fleet dies
at once (every exit presents it). Per-exit distinct domains mean blocking one
name kills one exit, not the fleet, and domains can be rotated continuously. The
domain must reach the client through the signed roster so it cannot be spoofed.

### The certificate pipeline (automated, hands-off after setup)

1. Own an innocuous domain whose DNS provider exposes an API (Cloudflare, OVH,
   ...). Store an API token in the control-plane secret store.
2. Run a cert-manager service (lego / certbot / acme.sh / caddy) that performs
   ACME **DNS-01** for `*.cover.example.com` (DNS-01 is mandatory for
   wildcards: it proves domain control by setting a TXT record via the API).
3. It obtains a 90-day wildcard certificate and auto-renews at ~60 days. No
   human action after the initial setup.
4. The cert + key are pushed to every exit over the existing config/secret
   channel; each exit loads them via `--tls-cert` and hot-reloads on renewal.
5. Each exit registers its cover domain (e.g. `<exit-id>.cover.example.com`,
   covered by the wildcard) with warren-api; the API signs it into the roster.

### Zero-downtime rotation choreography

To move off `*.cover.example.com` (scheduled, or in response to a block):

1. The cert-manager obtains a wildcard for a NEW base domain `*.veil.other.com`.
2. Push it to the exits, which now serve BOTH names: `--tls-cert` (old default)
   plus `--tls-cert-sni veil.other.com=<cert>=<key>` (the engine SNI resolver).
3. warren-api updates the signed roster to advertise the new per-exit domain.
   New clients dial the new name; clients still on a cached roster keep dialing
   the old name, which the exit still serves. No connection is dropped.
4. After the roster-refresh window, drop the old `--tls-cert-sni` entry.

This is driven entirely by a roster field plus an exit cert push; no app release
is involved. The rotation can be scheduled (cron) or triggered by a monitor that
detects a domain being blocked from inside the censored region.

### Lockstep handling during the RPK -> X.509 migration

A v6 X.509 exit and an RPK client do not interoperate. Do not flip one listener
in place. Run two exit pools (RPK and X.509) and let the signed roster route
each client to the pool matching its mode, draining the RPK pool as clients
update.

### Robustness / friction summary

- One wildcard covers the whole fleet; auto-renew (60-day) means certs never
  expire unattended.
- Rotation is a roster field + a cert push, both automatable end to end.
- The signed roster makes remote domain steering tamper-proof.
- No single point of blocking once per-exit domains are live.
- The one recurring manual cost is maintaining a stock of innocuous domains
  (registrar + DNS API), which rotation consumes over time.

### What is NOT yet built for this pipeline

The signed-roster `cover_domain` field (v8), the exit->warren-api registration
of its cover domain, and the per-exit client dial are all DONE (see above). What
remains is purely deployment/control-plane, in no repo here:

- The ACME cert-manager (DNS-01 wildcard) + the push of cert/key to the exits.
- The block-detection monitor that triggers a cover-domain rotation.
- The stock of innocuous base domains the rotation consumes.

## One-line posture summary

Behind the GFW: run v6 X.509 with rotating cover domains and enable
`WARREN_IDLE_COVER`. The SNI-split that defeats today's QUIC SNI censor is
already on by default, but treat the cover domain as revocable, not permanent:
the split protects against the GFW as it behaves today, not as it may behave
after it learns to reassemble split Initials.
