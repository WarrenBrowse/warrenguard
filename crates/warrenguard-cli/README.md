# warrenguard

A reference CLI that drives the **WarrenGuard engine** as a generic
VPN-over-QUIC tool, with no Warren backend in the path. It exists to show that
the engine crates (`warrenguard-*`) are a self-contained building block a
third-party deployer can use directly, the way WireGuard's `wg`/`wg-quick` use
the kernel module.

The engine layering guarantees this: the `engine_direction` conformance
invariant fails CI if any `warrenguard-*` crate ever depends on a Warren backend
crate, and this CLI pulls the identity layer with `default-features = false`, so
there is not even a BIP39 dependency. Keys are raw 32-byte seeds.

## Quickstart (3 commands)

Every seed and key in this document is a throwaway documentation example; never
reuse one in a real deployment.

```sh
# 1. Generate a node key on each side. Keep the seed secret; share the public key.
$ warrenguard keygen
seed       399963691b81c92648bc094ce4f7369cd3962a41b431c45e0fcc1e4389cabf25
public key ed25519:FejfKsU2bIyOb138pztV6D9A4VMSlxLT+TVe3Fa/Qa4=

# 2. Run a server (an "exit"). It admits any peer that completes the handshake
#    (AllowAll). Pass --seed for a stable identity; omit it for an ephemeral one.
$ warrenguard serve --listen 0.0.0.0:443 --seed <server-seed-hex>
public key ed25519:quAYOzBGqUu49nZ9lZ2xJDWvI7iZH1dHWbvqws1Hw+E=
listening  0.0.0.0:443
policy     AllowAll (any handshaking peer is admitted)

# 3. Connect a client, pinning the server's public key (like a WireGuard peer).
$ warrenguard connect \
      --server-key ed25519:quAYOzBGqUu49nZ9lZ2xJDWvI7iZH1dHWbvqws1Hw+E= \
      --server-addr 203.0.113.10:443
connected
tunnel ipv4 10.66.0.2
```

The client completes the raw-public-key TLS 1.3 handshake over QUIC, the server
allocates it a tunnel IP from the `10.66.0.0/16` pool, and the datagram plane is
ready (RFC 9221). `--server-key` is the WireGuard `PublicKey=` analog;
`--server-addr` is the `Endpoint`.

## What this is (and is not)

- **Is**: a minimal, honest demonstration that the engine stands alone: keygen,
  a generic `AllowAll` server, and a raw-key client, end-to-end.
- **Is not** (yet): the full product surface. TOML peer-list config and a
  privileged `--tun` mode that actually moves OS traffic are deliberate
  extensions on top of this core. The Warren product adds its
  account/subscription policy by implementing the engine's admission in its
  private backend, never by patching the engine.

## Closed roster (`--peer`)

`serve` is open (`AllowAll`) by default. Pass `--peer <ed25519:base64>` one or
more times to admit only those peer keys, the way a WireGuard peer lists its
counterparties; every other handshake is refused before any tunnel IP is
assigned:

```sh
$ warrenguard serve --listen 0.0.0.0:443 \
      --peer ed25519:LSHxsGZCVoFppR8Sji5yVNNzEriCBLsRma7DBVZMSWg= \
      --peer ed25519:quAYOzBGqUu49nZ9lZ2xJDWvI7iZH1dHWbvqws1Hw+E=
public key ed25519:Djh/3Tqk9hNYnJf7gPvHRYww7en0TFYavww/UJqw82k=
listening  0.0.0.0:443
policy     StaticAllowlist (2 authorized peer(s))
```

A single malformed `--peer` value fails the whole invocation (fail-closed: a
typo must never silently widen admission). The roster is static, with no TTL and
no live revocation, so it is the right fit for a small self-hosted deployment;
the Warren product instead drives a subscription-backed, revocable allowlist
through the same engine gate.

## Subcommands

| Command | What it does |
|---|---|
| `keygen` | Print a fresh node key: a 32-byte seed (secret) and its `ed25519:<base64>` public key. |
| `serve --listen <addr> [--seed <hex>] [--peer <ed25519:..>]... [--tls-cert <path> --tls-key <path>]` | Bind an exit and serve until interrupted. Open by default; `--peer` (repeatable) enforces a closed static roster. `--tls-cert`/`--tls-key` switch the exit to v6 X.509 mode (present a real cert instead of the RPK). |
| `connect --server-key <ed25519:..> --server-addr <addr> [--seed <hex>] [--cover-domain <host>] [--ca <path>]` | Dial a key-pinned server and print the allocated tunnel IP. `--cover-domain`/`--ca` switch the client to v6 X.509 mode (validate the exit's real cert for the cover domain instead of the RPK). |
