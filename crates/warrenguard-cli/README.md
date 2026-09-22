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

## What this is (and is not)

- **Is**: a minimal, honest demonstration that the engine stands alone: keygen,
  an exit that terminates the multi-hop datapath, and a forwarder through the
  HTTP/3 proxy ingress.
- **Is not**: the full product surface, and in particular it is **not** an
  admission control. `serve` admits every peer that completes the handshake: no
  allowlist, no token, no revocation. A deployer puts its own admission in
  front of the engine (the Warren product implements it in its private
  backend); nothing in this repository can turn `serve` into a closed exit.
  Attaching the tunnel to the host network stack and the OS killswitch are
  likewise deployer-side, not CLI-side.

## Quickstart

Every seed and key in this document is a throwaway documentation example; never
reuse one in a real deployment.

```sh
# 1. Generate a node key. Keep the seed secret; share the public key.
$ warrenguard keygen
seed       399963691b81c92648bc094ce4f7369cd3962a41b431c45e0fcc1e4389cabf25
public key ed25519:FejfKsU2bIyOb138pztV6D9A4VMSlxLT+TVe3Fa/Qa4=

# 2. Keep the seed in a file only its owner can read.
$ printf '%s\n' "$SEED_HEX" > /etc/warrenguard/exit.seed && chmod 600 /etc/warrenguard/exit.seed

# 3. Run an exit. It binds loopback by default, and it admits every peer that
#    completes the handshake.
$ warrenguard serve --seed-file /etc/warrenguard/exit.seed \
      --multihop-exit-id aabbccddeeff00112233445566778899
multihop exit-id  aabbccddeeff00112233445566778899
multihop pubkey   1f2e...d067
public key        ed25519:FejfKsU2bIyOb138pztV6D9A4VMSlxLT+TVe3Fa/Qa4=
listening         127.0.0.1:443
```

The printed block is what a client pins: the exit id, the X25519 multi-hop
pubkey derived from the identity, the Ed25519 raw public key, and the bind
address. The identity must be stable across restarts, which is why `serve`
requires a seed and refuses to invent an ephemeral one.

## The exit is open, so exposure is explicit

`serve` has no allowlist and no token admission. Anyone who can reach the bound
port and complete the handshake can use the exit, so the address it binds is the
only thing standing between a test exit and an open relay.

- The default bind is `127.0.0.1:443`, which is not reachable from off the host.
- Any non-loopback `--listen` is refused unless `--allow-open-exit` is also
  passed. That flag is an acknowledgement of network exposure, not a security
  control: it does not restrict who may use the exit.

```sh
# Refused: a wildcard bind with no admission control behind it.
$ warrenguard serve --listen 0.0.0.0:443 --seed-file /etc/warrenguard/exit.seed \
      --multihop-exit-id aabbccddeeff00112233445566778899
refusing to serve an open exit on 0.0.0.0:443: ...

# Accepted: the operator has said, on purpose, that this exit is public.
$ warrenguard serve --listen 0.0.0.0:443 --allow-open-exit \
      --seed-file /etc/warrenguard/exit.seed \
      --multihop-exit-id aabbccddeeff00112233445566778899
```

A deployer that wants a closed exit terminates this datapath behind its own
admission layer; it does not get one from this flag.

## Secrets never belong in the arguments

A value passed in the process arguments is readable by every local account
through `ps`, and by most supervisors' inspection surfaces. Both secrets this
CLI takes therefore also have a file form:

| Secret | Preferred | Legacy (still accepted, warns) |
|---|---|---|
| Node seed | `serve --seed-file <FILE>` | `serve --seed <HEX>` |
| Proxy credential | `masque-forward --credential-file <FILE>` | `masque-forward --credential <TOKEN>` |

The file form:

- accepts exactly what `keygen` prints (the seed file holds 64 hex characters;
  surrounding whitespace is ignored) or the raw token for the credential;
- refuses a regular file that group or others can read or write, so
  `chmod 600 <FILE>` is required; the error names the fix;
- is also satisfied by an inherited descriptor, `--seed-file /dev/fd/3` (or
  `/proc/self/fd/3` on Linux), which keeps the secret off disk entirely. A
  descriptor has no mode of its own, so no mode check applies to it;
- keeps the secret in buffers that are zeroized on drop, and never renders one
  through `Debug`, an error message or a log line (a malformed seed is reported
  by shape, never by content).

### Migrating off the argument forms

Both flags still work and warn on every use, so an existing command line keeps
running while it is migrated:

```sh
# before
warrenguard serve --seed "$SEED_HEX" --multihop-exit-id "$EXIT_ID"
# after
install -m 600 /dev/null /etc/warrenguard/exit.seed
printf '%s\n' "$SEED_HEX" > /etc/warrenguard/exit.seed
warrenguard serve --seed-file /etc/warrenguard/exit.seed --multihop-exit-id "$EXIT_ID"
```

Passing both forms at once is an error rather than a silent preference for one
of them.

## Subcommands

| Command | What it does |
|---|---|
| `keygen` | Print a fresh node key: a 32-byte seed (secret) and its `ed25519:<base64>` public key. |
| `serve --multihop-exit-id <32-hex> (--seed-file <FILE> \| --seed <HEX>) [--listen <addr>] [--allow-open-exit] [--multihop-subnet <CIDR>] [--multihop-gateway <IP>] [--multihop-x25519-ikm <FILE>]` | Bind an exit, print the identity a client pins, and serve until interrupted. Loopback by default; a non-loopback bind needs `--allow-open-exit`. |
| `masque-forward --proxy <host:port> (--credential-file <FILE> \| --credential <TOKEN>) [--proxy-addr <ip:port>] [--tcp <local=host:port>]... [--udp <local=host:port>]... [--ca <FILE>]` | Forward local TCP and UDP through an HTTP/3 proxy ingress, the way a browser handed that proxy does. |

`--multihop-x25519-ikm <FILE>` holds a raw 32-byte key and is held to the same
permission rule as the other secret files.
