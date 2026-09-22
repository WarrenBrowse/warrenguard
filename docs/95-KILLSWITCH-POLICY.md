# Killswitch policy per platform, and exit-operation safety

Status: Linux and macOS paths unit-tested behaviourally through their command
seams, with mutation-checked RED for every security property; the Windows policy,
its read-back verification, its guard and its rollback are driven against a model
of the documented Windows Firewall precedence on every host, and the
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

Two consequences drive the policy:

- `Set-NetFirewallProfile -DefaultOutboundAction Block` only changes the
  *default*, so it stops traffic that matches no rule. Every pre-existing explicit
  Allow rule (a user accepting the firewall prompt, a vendor installer's rule, a
  Group Policy exception) kept its egress, which is why an install that only
  flipped the default announced a protection it did not have.
- A policy made of that default plus our own exceptions is established once and
  then decays: an allow rule created later, during the same session, reopens the
  egress for as long as the tunnel is up. Only an explicit Block rule prevents
  that, because rule 2 outranks allow rules that do not exist yet.

## Windows: the policy the engine installs

1. Remove every `warren-killswitch-*` rule, including the leftovers of a session
   that ended without its teardown.
2. Enable all three profiles (`Domain`, `Private`, `Public`).
3. Set `DefaultOutboundAction Block` on all three.
4. Create ONE explicit outbound Block rule. It is what keeps the policy binding
   for the whole session: an allow rule added later loses to it.
5. Create the exceptions as Allow rules carrying `-OverrideBlockRules True`, the
   documented outbound "allow bypass rule", so that they outrank that block:
   loopback, the tunnel interface, UDP to each exit scoped to the daemon's own
   executable with `-Program` (the Port Fail / TunnelCrack ServerIP closure), and
   the optional LAN and DHCP ranges.
6. Disable every OTHER enabled outbound allow rule, recording each name so the
   teardown re-enables exactly those. This is defence in depth, and it is what
   makes the verified property categorical: after the install the only enabled
   outbound allow rules are the engine's.

The install ends with a read-back of the active store, and only then is it
reported as done: all three profiles enabled, all three blocking by default,
local rules not disabled by policy, the block rule present with the right action
and WITHOUT the override, every exception present and enabled with the expected
action, the override flag and its conditions (program, protocol, remote address,
remote port, interface), no rule of the engine's that this install did not create,
and no enabled outbound allow rule outside the engine's. A failure restores the
captured profile settings, re-enables the rules it disabled, removes its own
rules, and returns the error.

### The one question a non-Windows host cannot settle

Step 5 rests on `-OverrideBlockRules`. Microsoft documents it as an outbound
"allow bypass rule" from Windows 7 on ("matching traffic is permitted through this
rule even if other matching rules would block the traffic"), and the Windows
Filtering Platform mechanism behind it is the hard permit ("The traffic can be
blocked at another sub-layer only by a callout Veto"). The same page states
earlier, about the general case, that such traffic "must be authenticated by
using a separate IPsec rule". This engine has no IPsec story and no Windows host
in CI, so:

- if the outbound carve-out holds, the exceptions work and step 4 keeps the
  policy binding for the session;
- if it does not hold on some build, the exceptions lose to step 4's block rule,
  so the tunnel and the carrier are blocked: a dead tunnel, visible immediately.
  Step 6 still stops every OTHER application, so the failure mode is an outage,
  never an exposure.

Shipping the Windows killswitch therefore REQUIRES
`scripts/windows/killswitch-policy-smoke.ps1` to pass on the fleet's Windows
build: it decides the question with real traffic, and its fourth step confirms
that an allow rule created after the install no longer opens the egress. Re-run it
after any change to the rule set.

### What else a deployer must plan for

- A Group Policy that forces the firewall off, that sets
  `AllowLocalFirewallRules` to False (which makes every local rule, the engine's
  included, inert), or that owns an enabled outbound allow rule the local store
  may not disable: each one fails the install rather than announce a protection
  that is not there. Treat that failure as fatal in the service that wires this.
- The exit-UDP exception is scoped to the daemon's executable path, and it must
  be the path of the process that owns the carrier socket. A supervisor that
  relaunches the daemon from another path invalidates the scope and the tunnel
  will not connect (fail-closed, not a leak).
- The guard stays armed until a teardown has actually completed, and it is armed
  BEFORE the first mutation. A cancelled install, a cancelled or failed uninstall,
  and a rollback that only partly applied are all cases where `Drop` (which cannot
  await, so it uses a bounded synchronous path) still re-enables the operator's
  rules and restores the captured profile settings. A rollback that completed
  cleanly disarms the guard, since there is then nothing left to restore.

## macOS: states are part of the policy

Loading pf rules does not affect connections that already exist. pf keeps a state
table and consults it before it re-evaluates the ruleset, so a connection opened
before the install (by macOS's default `pass all`, for instance) keeps flowing
off-tunnel past the new block until its state entry is gone.

The install therefore purges the state table after the rules are loaded. The
decision is taken against the policy the install just loaded, not against "any
state that is not loopback":

- a state is PRESERVED when the anchor passes its flow, judged from what a state
  entry carries (the protocol, the remote address, the remote port): the exit
  carrier, a LAN range under `allow_lan`, the DHCP ports under `allow_dhcp`;
- loopback-to-loopback states are preserved as local IPC;
- every other state is killed, because it is a connection that would egress
  off-tunnel without an exception.

An interface-scoped pass is deliberately NOT permission: the exit carrier is
scoped to `phys_iface` when the caller named the physical egress, `pfctl::State`
exposes no interface name, and pf answers an existing state without re-evaluating
the ruleset. A state that cannot be shown to match the scoped rule is killed
rather than preserved, and the cost is one re-established carrier connection. The
rule is the same in both directions: killing the carrier's state unconditionally
would drop the tunnel's own transport for no confidentiality gain, and preserving
an unattributable state would leave a flow the scoped rule refuses.

The two decisions differ on purpose, and the difference is what keeps an install
from failing on its own transport:

- the PURGE kills every state whose flow it cannot prove the policy passes, so an
  unattributable interface-scoped flow does not survive it;
- the CONFIRMATION read fails only on a surviving state that NO pass rule covers.
  Once the purge has completed, a state matching a pass rule can only have been
  created by a rule that passed its first packet, and the only rules that pass
  those flows are the anchor's own, interface scope included. Failing on an
  unattributable survivor instead would fail the install every time the transport
  recreated its state between the kill and the read, and the rollback would then
  remove the blocking rules.

A failure of the purge, or of the anchor flush that precedes the rule load, is
fatal: a host still carrying off-tunnel traffic must not be reported as protected.

An operator with root can confirm the purge by hand: with a physical connection
open, `sudo pfctl -s states` before the install and again after it must show the
entries that are neither loopback nor a passed flow gone, while the carrier (with
an unscoped carrier pass) and any state the policy passes may remain.

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
| Windows: a pre-existing allow rule cannot keep its egress; the tunnel, the carrier and the optional LAN and DHCP flows still pass | Model-driven install tests in `src/windows.rs` (documented precedence, including the bypass rule and the block-beats-allow rule), with mutation-checked RED for each property |
| Windows: the policy keeps holding for the whole session | A test that adds an allow rule AFTER the install and asserts the traffic stays blocked, with the block-rule removal mutation making it fail |
| Windows: the install is not reported done unless the active policy confirms it | `check_effective_state` unit tests (profiles enabled, default block, local rules honoured, override flag present on exceptions and absent on the block rule, rule conditions, no leftover rule of ours, no foreign enabled allow rule) plus lifecycle tests against a policy that keeps a profile off, ignores local rules, pins an allow rule, leaves a leftover, or drops the override flag |
| Windows: partial failure and cancellation roll back | Lifecycle test with an injected command failure, and guard tests for a completed, a failed and a cancelled uninstall plus a CANCELLED install (the last three assert the synchronous `Drop` teardown still restores the operator's rules and the captured profiles, which the install path gets by arming the guard before its first mutation) |
| Windows: the generated commands and the four read-back queries | Golden tests pinning the exact text, so the surface a non-Windows reviewer inspects cannot drift silently |
| Windows host behaviour, cmdlet and property behaviour, and the `-OverrideBlockRules` reading | NOT verified here. Run `scripts/windows/killswitch-policy-smoke.ps1` on a throwaway Windows host: it reproduces the leak, confirms the block rule, confirms the override exception, confirms that a rule created later cannot reopen the egress, checks the read-back filters, and checks the categorical foreign-allow query |
| macOS: the anchor-block bypass through pre-existing states, without killing the flows the policy passes, and without failing on a state the transport recreates mid-install | Purge lifecycle tests, the pure permitted-flow predicate (the interface-scoping refusal on the purge side, the recreation tolerance on the confirmation side) and the wiring test that the set handed to the purge follows `KillswitchOpts`, all mutation-checked |
| macOS host behaviour, `/dev/pf` purge | NOT verified here (no root). The manual `pfctl -s states` procedure above is the check. |
| CLI: a reachable open exit is refused without the explicit flag; a secret file with group or other access is refused; no secret reaches a `Debug` rendering or an error | Unit tests in `crates/warrenguard-cli` (RED proven by mutation for each guard) |
