# Socket-level tunnel bypass (Port Fail / TunnelCrack ServerIP closure)

Status: engine plan + socket applier landed and unit-tested; live rooted
validation and the consumer wiring of the bypass value are operator-gated (see
the last section).

## The attack

A full-tunnel VPN steers every destination into its TUN device with the classic
`0.0.0.0/1` + `128.0.0.0/1` split (and `::/1` + `8000::/1` for v6). Its own QUIC
carrier socket to the exit must NOT be steered there, or the tunnel would route
its own packets into itself. The historical desktop escape was a destination
route to the exit:

- Datapath A (`warrenguard-tun-core` plan + `warrenguard-tun-device` applier):
  `ip route replace <exit>/32 via <gw>` (Linux), `route add -host <exit> <gw>`
  (macOS), plus a killswitch accept for `ip daddr <exit>` UDP.
- Datapath B (`warrenguard-route-split` + `warrenguard-winroute`): an
  `ip rule to <exit>/32 lookup main pref 50` (Linux), a `route add -host <exit>`
  (macOS), a `CreateIpForwardEntry2 <exit>/32` (Windows), plus a killswitch
  accept for the exit address.

That destination route is correct for the carrier, but it also lets ANY
application flow to the exit IP leave the tunnel in the clear. An adversary who
can make a target's app connect to the exit IP (QUIC/HTTP3 UDP 443, WebRTC, an
`<img>` to the exit, ...) observes the packet egress on the physical link with
the real source IP. That is the Port Fail deanonymisation, and the same root
cause as TunnelCrack's ServerIP leak. The killswitch did not stop it: its
accept was keyed on the same destination, so it explicitly permitted the leak.

Mobile is unaffected (iOS auto-exempts the NE provider's own sockets; Android
uses `VpnService.protect`), and the userland proxy datapath is unaffected (it is
loopback-mediated, with no OS tunnel installed). Only the desktop TUN datapaths
were exposed.

## The fix: key the escape on the SOCKET, not the destination

This is the WireGuard fwmark model and exactly TunnelCrack's recommendation:
"everything in the tunnel except the VPN app's own traffic". The datapath's own
carrier socket is marked/bound so only IT leaves the tunnel; the exit IP is no
longer special-cased in routing or in the killswitch, so the split-default
captures it into the tunnel like any other destination.

`SocketBypass` (`warrenguard-tun-core::plan`) is the per-OS mechanism, applied to
the freshly bound UDP socket before its first send by
`warrenguard-socket-bypass::apply` (fail-closed: if the mark/bind fails, the
endpoint bind fails and nothing egresses, mirroring the Android `protect` path):

| OS      | Mechanism                               | Escapes the `/1` split because           |
| ------- | --------------------------------------- | ---------------------------------------- |
| Linux   | `SO_MARK = WARREN_TUNNEL_FWMARK`        | paired `ip rule fwmark <m> lookup main`  |
| macOS   | `IP_BOUND_IF` / `IPV6_BOUND_IF`         | forces egress interface over the route   |
| Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF`     | forces egress interface over the route   |
| Android | `VpnService.protect` (unchanged)        | JNI callback in the transport layer      |

`WARREN_TUNNEL_FWMARK = 0x77617272` is the single source of truth, shared by the
routing rule, the killswitch accept and the socket mark on Linux.

### Routing changes

- **Datapath A Linux** now installs the `/1` halves in a dedicated table
  (`TUN_ROUTE_TABLE = 100`, matching datapath B) and adds
  `ip rule add fwmark 0x77617272 lookup main pref 50` + `ip rule add lookup 100
  pref 51` (and the `ip -6` equivalents). The marked socket falls through to
  `main`'s physical default; everything else goes to table 100 -> tun. No
  `<exit>/32` route is emitted.
- **Datapath A macOS** installs only the two `/1` interface routes; the socket's
  `IP_BOUND_IF` handles the escape. No `route add -host`.
- **Datapath B Linux** (`build_install_commands`) drops the `to <exit>/32 lookup
  main` rule and installs `build_tunnel_socket_fwmark_rule("add")` at the same
  priority. v6 gets `build_tunnel_socket_fwmark_rule_v6`.
- **Datapath B macOS** (`default_route_split_macos`) drops the `route add -host
  <exit>` (v4 and v6); the socket's `IP_BOUND_IF` handles the escape.
- **Datapath B Windows** (`warrenguard-winroute`): `plan_install_v4` no longer
  emits the `/32` host route. `RouteSpec` lost its gateway target entirely, so
  the crate can no longer even construct a destination-based route (the
  vulnerability class is closed at the type level). `discover_physical_ifindex()`
  is exposed to feed `SocketBypass::UnicastIf`.

### Killswitch changes

Fail-closed (policy drop / `block out all`) is preserved everywhere; only the
exit exception is re-scoped.

- **Datapath A** (`warrenguard-tun-core::plan::KillswitchPlan`): the nftables
  accept is `meta mark 0x77617272 accept` instead of `ip daddr <exit> udp`. The
  macOS pf accept is scoped `on <phys_iface>` (the interface the socket binds to)
  instead of matching the exit on any interface.
- **Datapath B** (`warrenguard-killswitch-os`): `KillswitchOpts` gained
  `socket_mark: Option<u32>` (Linux `meta mark` accept, omitting the per-exit
  `ip daddr` rules) and `phys_iface: Option<String>` (macOS pf interface scope).
  When both are `None` the legacy destination behaviour is kept for back-compat.

The `meta mark` accept (Linux) is genuinely socket-scoped: only the daemon's
`SO_MARK`ed socket passes. The macOS interface-scoped accept closes the Port Fail
vector (a normal app dialing the exit is routed to utun, never to the physical
output), with one documented residual below. Windows WFP still uses a
`-RemoteAddress <exit>` allow; true app-id scoping
(`FWPM_CONDITION_ALE_APP_ID`) is the follow-up (see below).

## Why this closes the attack

After the change, an application flow to `<exit_ip>` matches the `/1` split and
is routed INTO the tunnel (encrypted, egressing the TUN), exactly like a flow to
any other address. It never reaches the physical output in the clear. The only
thing on the physical link to the exit is the daemon's own marked/bound socket,
and the killswitch permits only that (by mark on Linux, by bound interface on
macOS). Covered by unit tests asserting: the routing plan contains no
`<exit>/32` and no host route; the Linux plan carries the fwmark rule in a
dedicated table (v4 + v6); the killswitch accepts the mark and NOT the exit
daddr; fail-closed is preserved; and the socket applier really performs the
`IP_BOUND_IF`/`IPV6_BOUND_IF` syscall (validated unprivileged against `lo0`).

## Residuals and operator-gated items

- **macOS process scoping.** pf cannot match a socket mark. The accept is scoped
  to the physical interface, which closes the Port Fail vector, but a hostile app
  that deliberately `IP_BOUND_IF`s its OWN socket to the physical interface and
  dials the exit would still be passed. The robust fix is a dedicated egress
  group and a pf `group <gid>` match; that needs a daemon change and is deferred.
- **Windows killswitch app-id.** The WFP allow is still destination-based. With
  the `/32` route removed and `IP_UNICAST_IF` binding the carrier, the leak of
  normal app traffic is closed by routing; tightening the killswitch to the
  daemon app-id (`-Program` / `FWPM_CONDITION_ALE_APP_ID`) needs a Windows host
  to validate and is deferred.
- **Consumer wiring of the bypass value.** The engine exposes
  `ClientTunnel::with_socket_bypass`, a `socket_bypass` field on
  `MultiHopClient::connect*` and `SupervisorConfig`, and
  `discover_physical_ifindex()` (Windows) / the physical ifindex discovery a
  macOS consumer needs. A privileged TUN consumer MUST set the bypass to
  `Fwmark(WARREN_TUNNEL_FWMARK)` (Linux) or `BoundIf(ifindex)` /
  `UnicastIf(ifindex)` (macOS/Windows) AND set `KillswitchOpts.socket_mark` /
  `phys_iface`. Without the socket bypass set, the routing/killswitch no longer
  have the destination escape, so the carrier would be captured: the two must be
  wired together (this is intentional fail-closed coupling).
- **Live rooted validation.** The plan/command layer and the macOS
  `IP_BOUND_IF` syscall are unit-validated. An end-to-end rooted run against a
  real exit (confirm app traffic to `<exit>` is captured in-tunnel while the
  carrier egresses physically, killswitch still fail-closed, routing restored on
  stop) is pending an operator with a live exit. No production rollout is
  required for this change.
