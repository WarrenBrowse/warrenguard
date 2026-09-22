# Killswitch policy per platform, and exit-operation safety

Status: Linux and macOS paths unit-tested behaviourally through their command
seams; the Windows policy, its read-back verification and its rollback are
driven against a model of the documented Windows Firewall precedence on every
host, and the `cfg(target_os = "windows")` code is type-checked with
`cargo check -p warrenguard-killswitch-os --target x86_64-pc-windows-msvc`. No
Windows host and no privileged pf host were available to this change, so the
host behaviour itself is operator-gated (see "What is verified where").

The engine exposes the killswitch as `warrenguard-killswitch-os`. The deployer's
own binary wires it (see the crate table in the root `README.md`); this document
is what that wiring has to respect.

## Windows: why the profile default is not a killswitch

Windows Firewall's rule precedence, as documented by Microsoft in
[Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules):

1. an explicitly defined allow rule takes precedence over the default block
   setting;
2. an explicit block rule takes precedence over any conflicting allow rule;
3. more specific rules take precedence over less specific ones, except when an
   explicit block rule is involved. Outbound rules follow the same order, and
   the platform offers no administrator-assigned weighting.

`Set-NetFirewallProfile -DefaultOutboundAction Block` only changes the *default*,
so it stops traffic that matches no rule. Every pre-existing explicit Allow rule
(a user clicking Allow on the firewall prompt, a vendor installer's rule, a
Group Policy exception) still matches its traffic and lets it leave the physical
interface. An engine that announced a killswitch on the strength of the default
alone was therefore announcing a protection it did not have.

The policy the engine installs instead, in order:

1. enable all three profiles (`Domain`, `Private`, `Public`);
2. set `DefaultOutboundAction Block` on all three;
3. create ONE explicit outbound `Block` rule matching everything, which is what
   outranks the pre-existing Allow rules;
4. create the exceptions as `Allow` rules carrying
   `-OverrideBlockRules True`, the documented outbound "allow bypass rule"
   (`New-NetFirewallRule`), so they outrank step 3's block. Loopback, the tunnel
   interface, UDP to each exit scoped to the daemon's own executable with
   `-Program` (the Port Fail / TunnelCrack ServerIP closure), and the optional
   LAN and DHCP ranges.

Two consequences a deployer must plan for:

- **All three profiles must be effectively enabled.** The install reads them
  from the active store (`-PolicyStore ActiveStore`, the resultant set), turns
  the firewall on, then reads the effective state back. A Group Policy that
  forces the firewall off cannot be overridden from the local store, so the
  install refuses with an explicit error instead of reporting success. If the
  deployer's service treats "killswitch install failed" as non-fatal, that
  decision is a leak; treat it as fatal.
- **A failed install rolls back.** The captured local profile settings
  (`Enabled` and `DefaultOutboundAction`) are restored and every
  `warren-killswitch-*` rule is removed, so a failure never leaves the host
  blocked without a guard, and never leaves a half-applied policy behind.

The exit-UDP exception is scoped to the daemon's executable path, so it must be
the path of the process that owns the carrier socket; a supervisor that relaunches
the daemon from a different path invalidates the scope and the tunnel will not
connect (fail-closed, not a leak).

## macOS: states are part of the policy

Loading pf rules does not affect connections that already exist. pf keeps a
state table and consults it before it re-evaluates the ruleset, so a connection
opened before the install (by macOS's default `pass all`, for instance) keeps
flowing off-tunnel past the new block until its state entry is gone.

The install therefore purges the state table after the rules are loaded: every
state that is not loopback-to-loopback is killed, the table is re-read, and the
install FAILS if any bypass state survived. Preserving loopback-only states is
deliberate (they are same-host IPC and cannot leak); a state on any other
address is a connection that leaves the host and is the leak the purge exists to
close. A failure of the purge, or of the anchor flush that precedes the rule
load, is fatal: a host that is still carrying off-tunnel traffic must not be
reported as protected.

An operator with root can confirm the purge by hand: with a physical connection
open, `sudo pfctl -s states` before the install and again after it must show the
non-loopback entries gone while the tunnel and the carrier remain.

## Linux: unchanged

The nftables table `inet warrenguard_killswitch_os` uses an `output` chain with
`policy drop` plus explicit accept rules (loopback, the TUN, UDP to the exits or
the daemon's marked socket, optional LAN and DHCP). `nft -f -` applies it
atomically, so a failed install commits nothing.

## Exit and CLI safety

The reference CLI (`warrenguard`, crate `warrenguard-cli`) admits every peer that
completes the handshake: it has no allowlist and no token admission. It
therefore binds loopback by default, and any non-loopback `--listen` requires
`--allow-open-exit`. Both secrets (the node seed, the HTTP/3 proxy credential)
are taken from a protected file (`--seed-file`, `--credential-file`, `chmod
600`, or an inherited descriptor through `/dev/fd/N`), with the legacy
argument forms kept only for compatibility; see
`crates/warrenguard-cli/README.md` for the migration.

## What is verified where

| Claim | Evidence |
|---|---|
| Windows policy: the block rule outranks pre-existing allow rules, exceptions survive it, the carrier stays scoped to the daemon | Model-driven install tests in `src/windows.rs` (documented precedence), with mutation-checked RED for each property |
| Windows: the install is not reported done unless the active policy confirms it | `check_effective_state` unit tests plus lifecycle tests against a policy that keeps a profile off or drops the override flag |
| Windows: partial failure and rollback | Lifecycle test with an injected command failure, asserting no rule of ours survives and the captured settings return |
| Windows host behaviour, PowerShell command acceptance | NOT verified here. Run `scripts/windows/killswitch-policy-smoke.ps1` on a throwaway Windows host; it reproduces the pre-existing-allow leak, then confirms the explicit block rule and the `-OverrideBlockRules` exception, and restores the host. |
| macOS: the anchor-block bypass through pre-existing states | Purge lifecycle tests plus the pure state predicate, mutation-checked |
| macOS host behaviour, `/dev/pf` purge | NOT verified here (no root). The manual `pfctl -s states` procedure above is the check. |
| CLI: a reachable open exit is refused without the explicit flag; a secret file with group or other access is refused; no secret reaches a `Debug` rendering or an error | Unit tests in `crates/warrenguard-cli` (RED proven by mutation for each guard) |
