# warrenguard-multihop

Warren multi-hop wire format and HPKE-based payload encryption (RFC 9180).

This crate implements the Warren v1 multi-hop primitive: client-to-exit
end-to-end authenticated encryption over a relay that is cryptographically
blind to the payload. It is the data-plane layer of the two-relayed
QUIC + HPKE multi-hop design.

## Cryptographic suite

- KEM: `DHKEM(X25519, HKDF-SHA256)` (RFC 9180 ID `0x0020`)
- KDF: `HKDF-SHA256` (ID `0x0001`)
- AEAD: `ChaCha20Poly1305` (ID `0x0003`)
- HPKE mode: `mode_base` (`0x00`)

Multi-message sessions: one HPKE setup per `(client, exit)` pair
amortizes the X25519 ECDH cost across the whole session. Per-packet
symmetric keys are derived via `AeadCtxS::export(epoch || seq, 32 B)`
and used with a fixed all-zero `ChaCha20Poly1305` nonce. The pattern is
unreliable-transport-friendly (QUIC datagram reorder / drop tolerant)
and mirrors how QUIC itself derives per-packet keys internally.

## Frozen `/v1` contract, the `/v2` hybrid suite, and the control layer

All `WARREN_*_V1` constants and the wire layout of `WarrenMultihopFrame`
are immutable. The frozen test vectors in `tests/hpke_vectors_v1.rs` (and
the binary fixture `tests/hpke_vector_max_ciphertext.bin`) detect any
drift. Breaking changes rotate the version instead of mutating `/v1`:
the post-quantum `/v2` suite (X-Wing hybrid KEM, `wire_format_v2` /
`pq_session`, gated behind the `pq-hpke` feature) already coexists with
`/v1` this way, negotiated per session and pinned by its own vectors.
The control-message codec on top has its own version line (currently
v3, DAITA echo) pinned by `vectors/control.json`.

Regenerate the vectors with:

```sh
./scripts/dev/cargo-test-nofw.sh run -p warrenguard-multihop --example gen_hpke_vectors_v1
```

## Scope and non-scope

In scope (this crate):
- Wire format frame + `/v1` constants.
- `ClientSession::seal` / `ExitSession::open` HPKE multi-message API.
- `ReplayWindow` (RFC 6479 sliding 1024-bit bitmap).
- `ClientSession::rekey` HPKE context rotation.

Out of scope (implemented elsewhere):
- The relay that forwards payload-blind frames: `warrenguard-relay`.
- Client multi-hop integration, which lives in the downstream client.
- Mini-PKI signature path (root -> operational -> exit X25519 pubkey).
  The PKI context constants (`WARREN_PKI_*_V1`) are defined here because
  they are versioned contracts that must be frozen together with the
  wire format; the signing/verifying code itself lives downstream.
