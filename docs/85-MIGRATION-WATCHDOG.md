# Migration watchdog: the contract a client surface implements

Status: single home in `warrenguard-transport::migration_watchdog`, consumed by
five client surfaces. The decision loop, its timings and the rebind API live
here; a surface supplies only its platform IO.

This document is the integration guide. The loop itself is documented in the
module's own rustdoc, which stays authoritative on behaviour; what follows is
what a new surface has to get right, and why each rule exists.

## What the watchdog is for

The primary path needs no code at all. The QUIC socket is wildcard-bound and
the relay accepts migration, so after a default-route change the next packet
leaves through the new interface and the relay revalidates the path in about
one round trip. The watchdog exists to VERIFY that this happened and to fall
back when it did not, in three layers:

1. Establish the escape the fresh socket will need, rebind, probe the tunnel
   for `MIGRATION_TIMEOUT`.
2. No answer: force a reconnect, which redials from a fresh socket under the
   consumer's own supervisor backoff. TUN, routes, firewall and the consumer's
   state machine are untouched.
3. Still no live session after `ESCALATE_TIMEOUT`: hand the failure to the
   consumer's fail-closed machinery.

A change that leaves no IPv4 default route parks instead of verifying, because
there is nothing to migrate onto yet. The park owns the window until the route
returns, until the event source closes, or until the escalation backstop
expires.

## Implementing `MigrationIo`

Nine methods, one of which has a default. Each is a seam onto something only
the surface knows.

| Method | What the surface supplies |
|---|---|
| `next_route_event` | Its default-route change source. **Must be cancel-safe.** |
| `has_v4_default_route` | Whether a usable v4 default exists right now |
| `nudge_bypass` | Re-point a connect-time escape, or nothing |
| `session_can_migrate` | `false` when the session rides the TLS-over-TCP carrier |
| `ensure_route_escape` | Install the escape the rebind will need, and CONFIRM it |
| `rebind_endpoint` | Swap the QUIC endpoint onto a fresh socket |
| `reclaim_escape` | Optional. Take a leak-free escape back after a migration |
| `send_probe` / `rx_sample` | Liveness probe and its observation |
| `force_reconnect` / `escalate` | The two fallback rungs |

### Rules that are not negotiable

**Cancel-safety of `next_route_event`.** The burst coalescer and the park both
drop a pending call and issue a fresh one. An implementation that consumed an
event on drop would lose the very change it watches for, and the session would
sit on a dead path until the escalation backstop.

**No escape, no rebind.** `ensure_route_escape` returning `false` means the
cycle redials instead of handing quinn a socket with nothing keeping it off the
tunnel it carries. Never return `true` optimistically: an unescaped carrier
self-nests, every send returns `Ok`, and no counter in the transport notices.

**Wait for the escape, do not merely request it.** Route installation is
asynchronous on some platforms, and an escape merely requested loses the race
against QUIC's own path-validation window. The boolean return exists to force
the wait.

**Never reapply a per-socket bind that the platform cannot honour.** On macOS
multi-interface hosts an `IP_BOUND_IF`-bound socket loses all egress the instant
the default swaps onto the TUN. That is why the macOS surfaces carry a
destination-keyed escape across a rebind rather than re-binding the fresh
socket. See `80-PORTFAIL-SOCKET-BYPASS.md`.

**Build the socket through the engine.** `MultiHopClient::rebind_wildcard`
takes a `RebindPolicy` (`Plain`, `Bypass(SocketBypass)`, `Protect`), matches the
socket family to the live local address, applies the policy BEFORE quinn can
send anything on the fresh socket, and fails closed if the policy cannot be
installed. A surface that builds its own socket has to remember all of that; one
that calls `rebind_wildcard` cannot forget it.

**`session_can_migrate` must be honest about the carrier.** A session riding the
TLS-over-TCP fallback has no UDP socket to swap. Rebinding it is meaningless and
the recovery path is a full redial, so the cycle skips both the rebind and the
probe window.

### `reclaim_escape`, and why it has a default

Some surfaces prefer a leak-free per-socket escape (a bind or `protect`) but
cannot carry it across a rebind, so they degrade to a destination-keyed route
first. That route is an exception another host application can take to reach the
relay IP off-tunnel. `reclaim_escape` is called once, only on the path that
confirmed the migration, so such a surface can try to close the exception again
on the network it just moved onto.

Doing nothing is always correct, hence the empty default body: the escape
installed before the rebind is live and proven by the revalidated path. The
engine does not know what a platform escape is; it only knows when it is safe to
try one.

It is deliberately NOT called on the other exits. A redial rebuilds the escape
from the connect path, and reclaiming there would race that rebuild on a path
nothing has proven. A park that ends still without a v4 route never rebound, so
it never degraded anything.

## Per-surface bindings today

| Surface | Route events | Escape across the rebind |
|---|---|---|
| Desktop app | platform route manager (per OS) | macOS: degrade to the destination-keyed route. Windows: re-resolve and reapply the interface bypass. Linux: fwmark, nothing to do |
| iOS | the system path monitor | the extension's own sockets are auto-exempt |
| Android | the connectivity network callback | `RebindPolicy::Protect` (`VpnService.protect`) |
| Rust SDK, proxy path | the engine's preferred-path probe | nothing captures host routes |
| Rust SDK, TUN path | the same probe | macOS: carrier host route. Linux: fwmark |

The route-event source differs because privilege differs: a daemon subscribes to
the OS, an unprivileged SDK polls the kernel's routing decision. Both satisfy the
same contract.

## What a new surface must validate

Unit tests over a scripted `MigrationIo` are necessary and not sufficient. The
loop is pure and every branch is testable with paused time, but two classes of
defect are structurally invisible to them:

- **Whole-loop defects.** A cycle test drives one cycle; it cannot see a loop
  that stops being woken. A real flap (route lost, then returned) found exactly
  that: the park consumed the return event, and nothing woke the watchdog
  afterwards. The session survived only because the local address came back
  identical.
- **Platform IO defects.** Whether a bind actually egresses, whether `protect`
  actually routed the fd, whether a route install actually took: none of it is
  observable from a mock.

So a new surface is not done until a real network change has been driven against
a real exit, with the tunnel IP observed UNCHANGED across it. An unchanged
tunnel IP is the strong evidence: it proves the session migrated rather than
redialed, because a redial would have replayed the exit's address allocation.

For any fail-closed counter-test (does anything leak during the switch?), prove
it by capture on the attachment network. A log written by the device cannot
prove the absence of a leak.
