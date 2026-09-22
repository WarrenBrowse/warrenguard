# Killswitch policy per platform, and exit-operation safety

Status: Linux and macOS paths unit-tested behaviourally through their command
seams, with mutation-checked RED for every security property; the Windows policy,
its read-back verification and its rollback are driven against a model of the
documented Windows Firewall precedence on every host, and the
`cfg(target_os = "windows")` code is type-checked and linted with
`cargo check -p warrenguard-killswitch-os --target x86_64-pc-windows-msvc`. No
Windows host and no privileged pf host were available to this change, so the host
behaviour itself is operator-gated (see "What is verified where").

The engine exposes the killswitch as `warrenguard-killswitch-os`. The deployer's
own binary wires it (see the crate table in the root `README.md`); this document
is what that wiring has to respect.

## Windows: why the profile default is not enough

Windows Firewall's rule precedence, as documented by Microsoft in
[Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules):

1. an explicitly defined allow rule takes precedence over the default block
   setting;
2. an explicit block rule takes precedence over any conflicting allow rule;
3. more specific rules take precedence over less specific ones, except when an
   explicit block rule is involved.

Outbound rules follow the same order, and the platform offers no
administrator-assigned weighting. `Set-NetFirewallProfile` states the same thing
for the setting itself: "Block: Blocks outbound network traffic that does not
match an outbound rule."

`Set-NetFirewallProfile -DefaultOutboundAction Block` only changes the *default*,
so it stops traffic that matches no rule. Every pre-existing explicit Allow rule
(a user accepting the firewall prompt, a vendor installer's rule, a Group Policy
exception) still matched its traffic and kept its egress: an engine that
announced a killswitch on the strength of the default alone announced a
protection it did not have.

## Windows: the policy the engine installs

1. Remove every `warren-killswitch-*` rule, including the leftovers of a session
   that ended without its teardown.
2. Enable all three profiles (`Domain`, `Private`, `Public`).
3. Set `DefaultOutboundAction Block` on all three.
4. Disable every OTHER enabled outbound allow rule, recording each rule name so
   the teardown re-enables exactly those. This is what closes the hole the
   default leaves, and it leaves a categorical property behind: after the
   install, the only enabled outbound allow rules are the engine's.
5. Create the exceptions as ordinary Allow rules: loopback, the tunnel interface,
   UDP to each exit scoped to the daemon's own executable with `-Program` (the
   Port Fail / TunnelCrack ServerIP closure), and the optional LAN and DHCP
   ranges.

### Why not one Block rule with exceptions

The compact alternative is a single explicit Block-everything rule plus
exceptions, since an explicit block rule outranks every conflicting allow rule.
That shape needs `-OverrideBlockRules` on the exceptions, and Microsoft's
documentation of that parameter is self-contradictory for outbound traffic: it
states the traffic "must be authenticated by using a separate IPsec rule", then
carves out outbound rules on Windows 7 and later ("no accounts are required").
The engine has no IPsec story and no Windows host in CI, so a policy whose tunnel
survival depends on which reading holds is not one it can ship as verified. The
mechanism above needs neither IPsec nor the override: its exceptions are
precedence rule 1, which is unambiguous.

### What a deployer must plan for

- **All three profiles must be effectively enabled.** The install reads them from
  the active store (`-PolicyStore ActiveStore`, the resultant set, Group Policy
  included), turns the firewall on, then reads the effective state back. A Group
  Policy that forces the firewall off, or that sets `AllowLocalFirewallRules` to
  False (which makes every local rule, the engine's included, inert), cannot be
  overridden locally, so the install refuses with an explicit error.
- **A pre-existing allow rule the local store may not disable fails the
  install.** That is the correct outcome: the policy cannot be established on
  that host, so the engine must not announce it.
- **A failed install rolls back.** The captured profile settings (`Enabled` and
  `DefaultOutboundAction`) are restored, the disabled rules are re-enabled, and
  every `warren-killswitch-*` rule is removed, so a failure never leaves the host
  blocked without a guard and never leaves a half-applied policy behind.
- **The exit-UDP exception is scoped to the daemon's executable path.** It must
  be the path of the process that owns the carrier socket; a supervisor that
  relaunches the daemon from another path invalidates the scope and the tunnel
  will not connect (fail-closed, not a leak).
- **A rule created after the install is a leak until the install runs again.**
  The policy is complete at the moment it is verified, but a later allow rule (a
  user answering a firewall prompt, a software installer, a Group Policy refresh)
  is not neutralised. The install is idempotent and re-asserts the whole policy,
  so re-run it after installing software or joining a managed network. Closing
  that window is what a native WFP binding (an own sub-layer with hard-permit
  filters) buys, and it is the documented follow-up.

## macOS: states are part of the policy

Loading pf rules does not affect connections that already exist. pf keeps a
state table and consults it before it re-evaluates the ruleset, so a connection
opened before the install (by macOS's default `pass all`, for instance) keeps
flowing off-tunnel past the new block until its state entry is gone.

The install therefore purges the state table after the rules are loaded. The
decision is taken against the policy the install just loaded, not against "any
state that is not loopback":

- a state is PRESERVED when the anchor passes its flow, judged from what a state
  entry carries (the protocol, the remote address, the remote port): the exit
  carrier, a LAN range under `allow_lan`, the DHCP ports under `allow_dhcp`;
- loopback-to-loopback states are preserved as local IPC;
- every other state is killed, because it is a connection that would egress
  off-tunnel without an exception.

The table is then re-read and the install FAILS if a bypass state survived. This
distinction matters in both directions: killing the carrier's own state drops the
tunnel's transport, and a carrier that reconnected before the confirmation read
would make an install fail and strip its rules, which is a self-inflicted outage
rather than a protection. A failure of the purge, or of the anchor flush that
precedes the rule load, is fatal: a host still carrying off-tunnel traffic must
not be reported as protected.

An operator with root can confirm the purge by hand: with a physical connection
open, `sudo pfctl -s states` before the install and again after it must show the
entries that are neither loopback nor the exit carrier gone, while the carrier and
any state the policy passes may remain.

## Linux: unchanged

The nftables table `inet warrenguard_killswitch_os` uses an `output` chain with
`policy drop` plus explicit accept rules (loopback, the TUN, UDP to the exits or
the daemon's marked socket, optional LAN and DHCP). `nft -f -` applies it
atomically, so a failed install commits nothing.

## Exit and CLI safety

The reference CLI (`warrenguard`, crate `warrenguard-cli`) admits every peer that
completes the handshake: it has no allowlist and no token admission. It therefore
binds loopback by default, and any non-loopback `--listen` requires
`--allow-open-exit`. Both secrets (the node seed, the HTTP/3 proxy credential) are
taken from a protected file (`--seed-file`, `--credential-file`, `chmod 600`, or
an inherited descriptor through `/dev/fd/N`), with the legacy argument forms kept
only for compatibility; see `crates/warrenguard-cli/README.md` for the migration.

## What is verified where

| Claim | Evidence |
|---|---|
| Windows: a pre-existing allow rule cannot keep its egress; the tunnel, the carrier and the optional LAN and DHCP flows still pass | Model-driven install tests in `src/windows.rs` (documented precedence, including the block-beats-allow rule the policy deliberately does not use), with mutation-checked RED for each property |
| Windows: the install is not reported done unless the active policy confirms it | `check_effective_state` unit tests (profiles enabled, default block, local rules honoured, rule conditions, no leftover rule of ours, no foreign enabled allow rule) plus lifecycle tests against a policy that keeps a profile off, ignores local rules, pins an allow rule, or leaves a leftover |
| Windows: partial failure and rollback | Lifecycle test with an injected command failure, asserting no rule of ours survives, the operator's rules are re-enabled and the captured settings return |
| Windows: the generated commands and the four read-back queries | Golden tests pinning the exact text, so the surface a non-Windows reviewer inspects cannot drift silently |
| Windows host behaviour, cmdlet and property behaviour | NOT verified here. Run `scripts/windows/killswitch-policy-smoke.ps1` on a throwaway Windows host: it reproduces the leak, confirms the disable step and the plain-allow exception, checks that `-Program`, `-Protocol`, `-RemotePort`, `-RemoteAddress` and `-InterfaceAlias` read back, and checks the categorical foreign-allow query |
| macOS: the anchor-block bypass through pre-existing states, without killing the flows the policy passes | Purge lifecycle tests, the pure permitted-flow predicate and the wiring test that the set handed to the purge follows `KillswitchOpts`, all mutation-checked |
| macOS host behaviour, `/dev/pf` purge | NOT verified here (no root). The manual `pfctl -s states` procedure above is the check. |
| CLI: a reachable open exit is refused without the explicit flag; a secret file with group or other access is refused; no secret reaches a `Debug` rendering or an error | Unit tests in `crates/warrenguard-cli` (RED proven by mutation for each guard) |
