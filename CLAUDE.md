# warrenguard: rules for Claude Code

WarrenGuard is a **generic VPN-over-QUIC engine** (AGPL-3.0): the reusable
data-plane primitive behind the Warren VPN, with no product or control-plane
logic. A deployer consumes it as a sibling path-dep (a private backend, a client
SDK, an app) and brings their own control-plane on top; those consumers live
outside this repo and MUST stay invisible to it.

> Shared Warren rules (single source of truth: WarrenBrowse/warren-workspace).
> They resolve when this repo is checked out inside the workspace (mani sync);
> cloned standalone, the imports just warn harmlessly. Never restate one of them
> here: import it, and keep this file to what is specific to the engine.
@../shared/rules/00-conventions.md
@../shared/rules/10-tdd.md
@../shared/rules/20-errors-secrets.md
@../shared/rules/30-git-commits.md
@../shared/rules/40-wire-vectors.md

## 1. Self-containment (load-bearing)

- **No crate here may depend on anything outside this repo.** No path-dep into a
  consumer repo. The engine depends only on other `warrenguard-*` crates, the
  warren-quinn fork git-dep, and crates.io. The standalone CI build (no sibling
  checkout present) is the enforcement.
- No product policy in the engine. Warren-flavoured defaults a generic deployer
  overrides (documented, not bugs): the obfuscation SNI suffix
  `.exits.warrenbrowse.com`, the eDNS default upstream, and "subscription"-worded
  auth-rejection strings.

## 2. TDD specifics (in addition to the shared rule)

No wire-format change (postcard, crypto encoding, ALPN, HKDF) without a frozen
vector test. The `vectors/` submodule is the corpus; see the shared wire-vectors
rule for what may and may not change there.

## 3. The quinn fork

The QUIC stack is a thin published fork, `warren-quinn`
(`WarrenBrowse/warren-quinn`), consumed as a git-dep pinned by tag in the root
`Cargo.toml` (`quinn = { git, tag, package = "warren-quinn" }`; the lib names stay
`quinn`/`quinn_proto`/`quinn_udp` so `use quinn` is unchanged).

It carries the GSO transmit constants, the Initial-fragmentation knobs
(`initial_datagram_min_size` / `initial_crypto_first_fragment_size`),
socket-buffer sizing, and the Apple fast datapath. No vendored tree, no
`[patch.crates-io]`, no setup script.

The hard anti-depatch guard is the E0599 compile error from the fork-only knobs in
`crates/warrenguard-transport-core/src/transport_config.rs`. Bumping the fork means
pushing a new tag on `warren-quinn` and bumping the `tag` here.

## 4. Code style specifics

- Edition 2024, MSRV 1.89 (pinned by `rust-toolchain.toml`).
- `#![forbid(unsafe_code)]` everywhere except three crates that downgrade to `deny`
  with per-block documented `# Safety`: the privileged TUN FFI in
  `warrenguard-tun-device`, the Win32 IP Helper FFI in `warrenguard-winroute`, and
  the `setsockopt` FFI in `warrenguard-socket-bypass`. Strict `[workspace.lints]`;
  never relax `clippy::correctness`.
- No `unwrap()`/`expect()` without a documented `# Panics` invariant. No
  `format!()` in hot paths. No stringly-typed APIs; newtypes for validated data.

## 5. Verify before commit

```bash
./scripts/dev/cargo-test-nofw.sh fmt --all -- --check
./scripts/dev/cargo-test-nofw.sh clippy --workspace --all-targets --all-features -- -D warnings
./scripts/dev/cargo-test-nofw.sh test -p <crate>
```

On macOS, **ALWAYS** go through `./scripts/dev/cargo-test-nofw.sh` for
test/run/bench: Quinn binds UDP and pops the Application Firewall on every fresh
test-binary hash. Prefer `-p <crate>` over `--workspace`. The Warren plugin's Bash
hook refuses a bare `cargo test` here, so this is enforced, not just documented.

## 6. Fleet-facing builds

A binary built from this engine and shipped to an exit needs `--features pq-hpke`
(off by default; a no-pq build silently refuses every /v2 post-quantum client).
The full build, hot-swap and persist procedure is the `warren-exit-fleet` skill.
