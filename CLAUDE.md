# CLAUDE.md - WarrenGuard engine rules

> Read automatically each Claude session in this repo. Binding for all
> contributions.

WarrenGuard is a **generic VPN-over-QUIC engine** (AGPL-3.0): the reusable
data-plane primitive behind the Warren VPN, with no product/control-plane logic.
A deployer consumes it as a sibling path-dep (a private backend, a client SDK,
an app) and brings their own control-plane on top; those consumers live outside
this repo and MUST stay invisible to it.

## Conventions (binding)

These apply to every contribution and stay in force even when this repo is
worked on standalone.

- **English only** in code, comments, identifiers, commit messages, and PRs.
- **Never the em-dash or en-dash** (U+2014 / U+2013) in authored text: use a
  comma, colon, period, or hyphen, or restructure. Fix a stray one when you
  touch the file.
- **Comments explain the non-obvious why**, not the what: an invariant, a subtle
  reason, or a warning that stops a future contributor reintroducing a known
  bug. No step narration, no restating the next line, no tombstones of old
  behavior.
- **No phase/ticket/audit markers** in source (`Phase X`, `R1.x`,
  `AUDIT-YYYY-MM-DD`, `Session N`). Tracking lives in git history, not the code.
- **TDD is mandatory**: RED, GREEN, REFACTOR. One failing test first, the
  minimum code to pass, then clean up. Every public function and every
  documented error path has a direct test. No hollow tests (one that passes even
  if the code under test is deleted). Mocks only at system boundaries (network,
  disk, clock, RNG); test the real logic. Data-plane changes are validated
  against a real network, not just fakes, before being claimed to work.
- **Typed errors, never stringly-typed**: `thiserror` with `#[non_exhaustive]`
  public enums and `#[source]`; newtypes for validated data and identifiers.
- **No-log discipline** (load-bearing for a privacy product): never put a
  pubkey, address, source IP, nonce, seed, or other identity material in a log
  or error in clear; redact to a short prefix if genuinely needed. Map internal
  errors at the boundary.
- **Zeroize secrets on drop** (seeds, signing keys, mnemonics); never derive
  `Debug` on a secret-bearing type (render only the public handle).
- **Conventional Commits, subject line only** (no body, no `Co-Authored-By`).
  Never run destructive git (`stash`, `checkout .`, `restore .`, `reset --hard`,
  `clean`); inspect history with `log` / `show` / `diff` instead.
- **Golden vectors are the wire contract**: every frozen format (identity, SS58,
  request signing, handshake frames, the signed relay list, the multihop frame)
  is pinned by a file under `vectors/` and replayed by any reimplementation.
  Never edit a vector to make a test pass; fix the code. Changing a vector means
  bumping the schema version.

## 1. Self-containment (load-bearing)

- **No crate here may depend on anything outside this repo.** No path-dep into a
  consumer repo. The engine depends only on other `warrenguard-*` crates + the
  warren-quinn fork git-dep + crates.io. The standalone CI build (no sibling
  checkout present) is the enforcement.
- No product policy in the engine. Warren-flavoured defaults a generic deployer
  overrides (documented, not bugs): the obfuscation SNI suffix
  `.exits.warrenbrowse.com`, the eDNS default upstream, and "subscription"-worded
  auth-rejection strings.

## 2. TDD specifics (in addition to the Conventions above)

Every functional change to Rust code follows RED -> GREEN -> REFACTOR (see the
Conventions above). Engine-specific: no wire-format change (postcard, crypto
encoding, ALPN, HKDF) without a frozen vector test.

## 3. quinn fork

The QUIC stack is a thin published fork, `warren-quinn`
(`WarrenBrowse/warren-quinn`), consumed as a git-dep pinned by tag in the root
`Cargo.toml` (`quinn = { git, tag, package = "warren-quinn" }`; the lib names
stay `quinn`/`quinn_proto`/`quinn_udp` so `use quinn` is unchanged). It carries
the GSO transmit constants, the Initial-fragmentation knobs
(`initial_datagram_min_size` / `initial_crypto_first_fragment_size`),
socket-buffer sizing, and the Apple fast datapath. No vendored tree, no
`[patch.crates-io]`, no setup script. The hard anti-depatch guard is the E0599
compile error from the fork-only knobs in
`warrenguard-transport-core/src/transport_config.rs`. Bumping the fork = push a
new tag on `warren-quinn` and bump the `tag` here.

## 4. Code style specifics

- Edition 2024, MSRV 1.89 (pinned by `rust-toolchain.toml`).
- `#![forbid(unsafe_code)]` everywhere except three crates that downgrade to
  `deny` with per-block documented `# Safety`: the privileged TUN FFI in
  `warrenguard-tun-device`, the Win32 IP Helper FFI in `warrenguard-winroute`,
  and the `setsockopt` FFI in `warrenguard-socket-bypass`. Strict
  `[workspace.lints]`; never relax `clippy::correctness`.
- No `unwrap()`/`expect()` without a documented `# Panics` invariant. No
  `format!()` in hot paths. No stringly-typed APIs; newtypes for validated data.

## 5. Verify before commit

```bash
./scripts/dev/cargo-test-nofw.sh fmt --all -- --check
./scripts/dev/cargo-test-nofw.sh clippy --workspace --all-targets --all-features -- -D warnings
./scripts/dev/cargo-test-nofw.sh test -p <crate>
```

On macOS, ALWAYS go through `./scripts/dev/cargo-test-nofw.sh` for
test/run/bench (Quinn binds UDP and pops the Application Firewall on every fresh
test-binary hash). Prefer `-p <crate>` over `--workspace`.
