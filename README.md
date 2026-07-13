# WarrenGuard

A generic **VPN-over-QUIC engine**: the data-plane building block behind the
[Warren](https://warrenbrowse.com) VPN, carved out to stand on its own. Like
WireGuard's kernel module, it is the reusable primitive; a deployer brings their
own control-plane (admission, accounting, discovery) on top.

Licensed **AGPL-3.0-or-later**.

## What it is

- A raw-public-key (RFC 7250) TLS 1.3 handshake over QUIC: the exit identity is
  SNI-pinned; the client authenticates in-band (no TLS client certificate, to
  avoid an active-probing tell).
- An RFC 9221 datagram tunnel plane (`10.66.0.0/16`), single- and multi-hop.
- HPKE-sealed multi-hop sessions (a blind relay between client and exit).
- DAITA traffic-analysis defenses tied to the QUIC datagram pump.
- Cross-OS TUN, NAT-PMP port-forwarding, an OS killswitch, an eDNS proxy.
- The Warren obfuscation profile (Initial-packet split, padded first datagram).

## Prerequisites

- **Rust 1.89** (pinned by `rust-toolchain.toml`; rustup installs it
  automatically). The toolchain file pre-declares the `x86_64-unknown-linux-gnu`
  and `aarch64-apple-darwin` targets; on any other host add yours with
  `rustup target add <triple>`.
- **git + SSH access to GitHub** on the first build: the quinn fork is a
  published git dependency (`WarrenBrowse/warren-quinn`) that cargo fetches over
  SSH.

It depends on a pinned **quinn fork** (GSO transmit constants, the obfuscation
knobs, socket-buffer sizing, an Apple fast datapath), published as the
standalone `warren-quinn` repo and consumed as a git dependency pinned by tag in
the root `Cargo.toml` (the crates are renamed `warren-quinn`/`-proto`/`-udp` but
keep the lib names `quinn`/`quinn_proto`/`quinn_udp`, so `use quinn` is
unchanged). Nothing to reassemble: cargo fetches it on the first build.

```sh
cargo build --workspace
```

## Reference CLI

`warrenguard` (crate `warrenguard-cli`) drives the engine as a standalone tool,
no backend in the path:

```sh
warrenguard keygen                         # node key (seed + ed25519 pubkey)
warrenguard serve --listen 0.0.0.0:443     # open exit (AllowAll)
warrenguard serve --peer ed25519:<b64> ... # closed static roster
warrenguard connect --server-key ed25519:<b64> --server-addr host:443
```

The CLI covers the handshake and the tunnel session: it is enough to stand up an
exit and to prove a client can reach it. It deliberately stops there, and does
**not** attach the tunnel to the host's network stack.

Anything that mutates privileged system state stays out of the reference CLI and
is wired by the deployer's own binary, which owns the elevation model and the
teardown policy:

| Engine crate | Exercised by the CLI | Wired by the deployer |
|---|---|---|
| wire, identity, tls, transport, pump, server, relay, multihop | yes | |
| `warrenguard-tun-device` (TUN interface) | | yes |
| `warrenguard-route-split` (default-route split) | | yes |
| `warrenguard-killswitch-os` (OS firewall killswitch) | | yes |
| `warrenguard-daita` (traffic-analysis defenses) | | yes (opt-in) |
| `warrenguard-natpmp-client` (port forwarding) | | yes |

## Layout

- `crates/warrenguard-*`: the engine crates (wire, identity, multihop, daita,
  tls, transport, pump, server, relay, tun, natpmp, killswitch, eDNS, ...).
- The QUIC fork lives in its own repo, `WarrenBrowse/warren-quinn`, pinned by
  tag as a git dependency in the root `Cargo.toml` (no vendored tree here).

## Genericity

The engine carries no product policy. Warren-specific defaults a deployer
overrides (not bugs): the obfuscation SNI suffix, the eDNS default upstream, and
"subscription"-worded auth-rejection strings. The Warren product adds its
account/subscription admission by implementing the engine's authorizer in its
own backend, never by patching the engine.
