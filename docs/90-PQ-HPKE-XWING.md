# X-Wing hybrid post-quantum multihop HPKE seal (`/v2`)

Status: implemented behind the `pq-hpke` cargo feature, **OFF by default**,
awaiting real-exit validation before any client enables it. Additive: the
classical X25519 `/v1` seal is untouched and stays the production default.

## What this adds

A hybrid post-quantum KEM in the client-to-exit HPKE layer
(`warrenguard-multihop`), so a harvest-now-decrypt-later adversary who later
builds a quantum computer cannot recover past tunnel payloads. The hybrid is
**X-Wing** (draft-connolly-cfrg-xwing-kem): X25519 + ML-KEM-768, combined with
the exact X-Wing SHA3-256 combiner, never a XOR of the component secrets.

Hybrid, not replacement: security is at least that of the classical X25519 path
even if ML-KEM is later broken, because the combiner binds both shared secrets.

## The combiner (security-critical, frozen)

```
ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
XWingLabel = 5c 2e 2f 2f 5e 5c   (the 6 bytes "\.//^\", hashed LAST)
```

- `ss_M` (32) ML-KEM-768 shared secret, `ss_X` (32) X25519 raw DH output,
  `ct_X` (32) X25519 ephemeral public, `pk_X` (32) recipient static X25519
  public. Label last.
- X-Wing ciphertext = `ct_M (1088) || ct_X (32)` = 1120 bytes.

Implementation: `crates/warrenguard-multihop/src/xwing.rs`
(`xwing_combiner`, `xwing_encapsulate`, `xwing_decapsulate`). Component crypto:
`ml-kem` 0.2 (FIPS 203), `x25519-dalek` 2, `sha3` 0.10; all optional, gated by
`pq-hpke`.

Deployment note: X-Wing's native keygen derives both component keys from one
seed. Warren instead uses INDEPENDENT component keys, the exit's existing
long-lived `exit_x25519_multihop_pubkey` as `pk_X` and a separately generated
ML-KEM-768 key. Only the security-critical combiner + KEM ops are shared with
X-Wing; the single-seed keygen is a storage convenience the protocol does not
need, and the X-Wing security argument holds for independent component keys.

## Wire `/v2` (versioned, `/v1` frozen and unchanged)

- Frame: `WarrenMultihopFrameV2` (`wire_format_v2.rs`), version byte `0x02`.
  Same fields as `/v1` plus ONE: `pq_ct` (the ML-KEM ciphertext `ct_M`). The
  classical `encapsulated_key` field keeps its 32-byte position and role (it
  carries `ct_X`), so that portion of the wire is byte-shaped identically to
  `/v1`. A `/v1` decoder rejects `0x02`; a `/v2` decoder rejects `0x01`.
- Session: `PqClientSession` / `PqExitSession` (`pq_session.rs`) mirror the
  classical sessions one-for-one (forward/reverse direction tags, rekey overlap
  window, caller-owned anti-replay seq). Key schedule is HKDF-SHA256 over the
  X-Wing shared secret (salt `WARREN_PQ_HPKE_SALT_V2`, per-packet info prefixed
  by `WARREN_PQ_HPKE_AAD_V2`), then ChaCha20-Poly1305 with an all-zero nonce
  (safe: unique key per `(epoch, seq)`). Domain-separated from `/v1`.
- Descriptor: `ExitDescriptorSigned` gains an optional
  `exit_mlkem768_pubkey: Option<Vec<u8>>` (1184 B), covered by a NEW signing
  context `WARREN_PKI_OPERATIONAL_EXIT_PQ_V1` over
  `context || exit_id || x25519 || dns_disabled_byte || mlkem768_ek`
  (`exit_descriptor_signing_payload_pq`, `verify_exit_descriptor_pq`). The field
  is skipped when `None`, so a classical descriptor serializes byte-identically.

## Negotiation and anti-downgrade

`negotiate_pq(op_pubkey, descriptor, require_pq)`:

- Decision is driven ONLY by the operational signature over the ML-KEM key
  (`verify_exit_descriptor_pq`), never by an unauthenticated wire bit. A
  middlebox that strips the ML-KEM key from the descriptor invalidates the
  signature.
- Descriptor carries a valid signed ML-KEM key -> `Available` (use the hybrid
  seal, set the `PQ_HPKE` wire feature bit, `warrenguard_wire::features::PQ_HPKE`
  = `1 << 4`).
- No valid signed ML-KEM key and `require_pq` -> `Err(PqDowngrade)`: the dial is
  REFUSED (a required-PQ client is never silently downgraded to classical).
- No valid signed ML-KEM key and not `require_pq` -> `ClassicalFallback`.

## No new steady-state tell

`pq_ct` (1088 B) is required only on the setup / rekey frame that establishes an
epoch. On steady-state data frames it is empty: the ML-KEM ciphertext is not
re-sent per datagram (the receiver holds the epoch session), so data-plane frame
size matches `/v1` plus the postcard length prefix, and `encapsulated_key`
(`ct_X`, 32 B) is still carried every frame exactly as `/v1` does.

## Tests, KATs, golden vectors

- KATs (`tests/xwing_kat.rs`, `--features pq-hpke`):
  - `official_xwing_draft_vectors`: replays the 3 official
    draft-connolly-cfrg-xwing-kem vectors
    (`tests/xwing_test_vectors.json`, from
    `dconnolly/draft-connolly-cfrg-xwing-kem/spec/test-vectors.json`) end-to-end
    through the production combiner + KEM: keygen -> encaps -> decaps, asserting
    `pk`, `ct`, `ss` byte-for-byte.
  - `combiner_matches_independent_sha3_256`: the combiner byte layout is
    cross-checked against Python `hashlib.sha3_256` values (catches a
    label-first / XOR / reordered transcript mistake).
- Frozen engine vectors (`tests/pq_hpke_vectors_v2.rs` +
  `tests/pq_hpke_vectors_v2.json`, generated by
  `examples/gen_pq_hpke_vectors_v2.rs`): forward setup frame, reverse reply
  frame, and the signed PQ descriptor, all pinned byte-for-byte.
- Session + descriptor unit tests: round-trip, cross-direction rejection, tamper
  rejection, exit-id mismatch, rekey overlap, anti-downgrade, context
  separation, JSON byte-compat.
- Shared `warren-vectors` (for the six SDKs): `xwing_kem.json`,
  `pq_hpke_seal_v2.json`, `multihop_frame_v2.json`.

Secret hygiene: `XWingSharedSecret` and the ML-KEM decapsulation key are
zeroize-on-drop; per-packet keys and the encaps randomness are zeroized after
use; no secret-bearing type derives `Debug`.

## The relay is version-agnostic: it routes and loads `/v2` (and PQ)

The relay (`crates/warrenguard-relay`) never decrypts the HPKE payload and
never reads the richer attestations `/v2` or PQ add (the `dns_disabled` bit,
the ML-KEM key); it only needs the cleartext `exit_id` and proof that the
operational key vouches for an exit pool entry. Neither of those needs are
version-specific, so the relay stays blind on purpose:

- **Descriptor loading**: `RelayConfig::validate` verifies each exit
  descriptor with a version-agnostic cascade (`verify_exit_descriptor_pq`,
  then `verify_exit_descriptor_v2`, then the legacy `verify_exit_descriptor`
  `/v1` context). A pool can therefore mix `/v1`, `/v2`, and PQ-signed
  entries during a rolling fleet upgrade instead of requiring every
  descriptor to be re-signed under one context at once.
- **Setup-frame dispatch**: `session::read_dispatch_frame` and
  `read_dispatch_frame_or_unauth` decode the routing `exit_id` by trying
  `/v1` (`WarrenMultihopFrame`) first, then `/v2`
  (`WarrenMultihopFrameV2`, the post-quantum X-Wing seal) on `/v1` decode
  failure. Both frames carry `exit_id` at the same wire position, and each
  decoder's version-byte check rejects the other's frame, so the cascade
  cannot misroute a `/v1` frame as `/v2` or vice versa.

This holds end to end: `tests/exit_id_extraction.rs` and
`tests/multihop_v2_e2e.rs` drive a real `RelayServer` with a `/v2` PQ setup
frame and assert it routes to the matching exit exactly like a `/v1` frame
would. The `WarrenMultihopFrameV2` type, its decoder, and the PQ session code
above are fully implemented and tested in `warrenguard-multihop`, and the
relay's routing and descriptor-loading of `/v2` is wired up to match.

## Live validation (GATED, operator-run, not yet executed)

Prerequisite: a test exit that publishes a `/v2` PQ descriptor (a signed
`exit_mlkem768_pubkey`) and runs a `pq-hpke`-enabled build.

1. Build a `pq-hpke` client and exit. Point the client at the test exit with
   `require_pq` set.
2. Confirm negotiation: the client verifies the signed ML-KEM key
   (`negotiate_pq` -> `Available`), sets `PQ_HPKE`, and the setup exchange
   completes over the `/v2` hybrid seal. Confirm a `require_pq` client REFUSES a
   classical-only descriptor (`PqDowngrade`).
3. Datapath: push real traffic; confirm no plaintext regression and that
   steady-state data frames carry an empty `pq_ct` (no per-packet ML-KEM bloat).
4. No new tell: re-pin the QUIC/TLS JA4 of the PQ session and diff against the
   classical baseline. Expectation: UNCHANGED, since PQ_HPKE lives in the HPKE
   payload inside the tunnel, not the TLS handshake (post-quantum key exchange
   at the TLS layer is a separate, independent concern). The only size delta is
   the one-time larger setup frame (ML-KEM ct); verify the data-plane frame-size
   distribution is unchanged.
5. Record the bench and the JA4 diff before flipping any default.

