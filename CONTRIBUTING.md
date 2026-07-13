# Contributing to WarrenGuard

WarrenGuard is the data-plane engine of a privacy VPN. A defect here can leak a
user's traffic or identity, so the bar for contributions is deliberately high.
Thank you for reading this before opening a pull request.

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability. Follow
[SECURITY.md](SECURITY.md) and report privately to security@warrenbrowse.com.

## Scope of this repository

The engine is a **generic VPN-over-QUIC primitive** with no product or
control-plane logic. A deployer brings their own admission, accounting and
discovery on top, by implementing the engine's traits in their own code.

Contributions that add product policy to the engine will be declined. If you
need a hook the engine does not expose, propose the hook, not the policy.

A small number of Warren-flavoured defaults exist and are documented as such
(the obfuscation SNI suffix, the eDNS default upstream, and the wording of some
auth-rejection strings). They are overridable by a deployer, and they are not
bugs.

## Ground rules

- **English only** in code, comments, identifiers, commit messages and pull
  requests.
- **No em-dash or en-dash** (U+2014 / U+2013) in authored text. Use a comma,
  colon, period or hyphen, or restructure the sentence.
- **Comments explain the non-obvious why**: an invariant, a subtle reason, or a
  warning that stops a future contributor reintroducing a known bug. Not step
  narration, not a restatement of the next line, not a record of what the code
  used to do.
- **No ticket, phase or audit markers** in source. Tracking belongs in git
  history.

## Test-driven development is mandatory

Red, green, refactor. One failing test first, the minimum code to make it pass,
then clean up.

- Every public function and every documented error path has a direct test.
- **No hollow tests.** A test that still passes when the code under test is
  deleted has negative value: it grants confidence it has not earned. If you are
  unsure, delete the code locally, watch the test go red, and restore it.
- Mocks only at system boundaries (network, disk, clock, RNG). Test the real
  logic.
- Anything that parses attacker-controlled bytes before authentication needs a
  no-panic property test alongside its unit tests.
- Data-plane changes are validated against a real network, not only against
  fakes, before they are claimed to work.

## Golden vectors are the wire contract

Every frozen format (identity, request signing, handshake frames, the signed
relay list, the multihop frame) is pinned by a file under `vectors/` and can be
replayed by any reimplementation.

**Never edit a vector to make a test pass.** Fix the code. Changing a vector
means changing the wire format, which requires bumping the schema version.

## Errors, secrets and logs

- **Typed errors, never stringly-typed**: `thiserror`, `#[non_exhaustive]` on
  public enums, `#[source]` for chaining. Newtypes for validated data.
- **No-log discipline** (this is load-bearing for a privacy product): never put
  a pubkey, address, source IP, nonce, seed or other identity material into a
  log or an error in clear. Redact to a short prefix if it is genuinely needed.
- **Zeroize secrets on drop** (seeds, signing keys, mnemonics). Never derive
  `Debug` on a secret-bearing type: render only the public handle.

## Unsafe code

`#![forbid(unsafe_code)]` is the default. Three crates downgrade it to `deny`
because they wrap OS FFI: `warrenguard-tun-device`, `warrenguard-winroute` and
`warrenguard-socket-bypass`. In those, every `unsafe` block carries a `// SAFETY:`
comment stating the invariant that makes it sound. A block without one will not
be merged.

## Before you open a pull request

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

On macOS, run these through `./scripts/dev/cargo-test-nofw.sh` instead: Quinn
binds a UDP socket, so a fresh test binary otherwise triggers the Application
Firewall prompt on every run.

Some tests are gated behind features or `#[ignore]` (they need root, a real TUN,
or a long wall-clock wait). If you touch the code they cover, run them.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), **subject line
only**: no body, no trailers.

```
fix(pump): drop oversize uplink datagrams instead of panicking
```

## Licence

WarrenGuard is AGPL-3.0-or-later. By contributing, you agree that your
contribution is licensed under the same terms.
