# ADR-0008: Performance and the two audiences

Status: Proposed (launches a workstream; decisions below await sign-off)

## Context

The engine serves two audiences that want opposing things on one axis:

- Censored users: obfuscation first, throughput second. Willing to pay the
  cost of DAITA, idle cover, and the active-probe decoy.
- P2P / high-volume (torrent) users: throughput first. Their real adversary is
  not a nation-state doing per-flow analysis; it is the copyright monitor in
  the swarm (who sees the exit IP, defeated by IP substitution) and an ISP that
  throttles detectable VPN or torrent traffic. They need raw throughput, port
  forwarding (NAT-PMP, already in the engine), no DNS/IPv6 leak (killswitch,
  already in the engine), and enough protocol obfuscation to avoid ISP
  throttling; they do not need traffic-analysis defenses.

These pull apart because hiding a high-volume flow's shape (DAITA) and
maximising its throughput are information-theoretically opposed: you cannot make
sustained multi-hundred-Mbps look like reading a news site without capping the
rate or paying large padding overhead.

Separately, the engine pays the intrinsic cost of a userspace QUIC data plane
versus in-kernel WireGuard, and the standing wish is to close that gap.

## WireGuard gap: anatomy

- Kernel datapath. WireGuard (Linux) encrypts in-kernel with no per-packet
  syscall or copy to userspace. The engine reads the TUN fd, crypts in
  userspace, and sends on a UDP socket, crossing the kernel boundary each way.
  This is the dominant cost.
- Framing and crypto. QUIC adds packet-number encryption, header protection,
  ACK machinery, and an outer congestion controller that WireGuard does not
  have (WireGuard leaves congestion to the inner flow).
- These costs are the price of the HTTP/3 mimicry that is the entire reason for
  choosing QUIC (ADR-0001). They are not a defect to be removed; they are a gap
  to be narrowed without giving up packet-level control.

## Kernel-land is the wrong bet here

The recurring hope is "move QUIC/TLS into the kernel to match WireGuard". This
is the wrong lever for this product:

- There is no mainline, cross-platform, production kernel QUIC. Client reach is
  macOS / Windows / iOS / Android; a Linux-only, exit-side kernel QUIC does
  nothing for client throughput, which is where the browsing and torrent
  experience is felt.
- kTLS offloads TLS-over-TCP records; QUIC does its own packet-level crypto, so
  kTLS does not apply to a QUIC data plane.
- Most important: a kernel QUIC implementation exposes a fixed fingerprint the
  application cannot shape. That directly fights ADR-0007's fingerprint-parity
  goal, which needs fine userspace control of the Initial packet, ClientHello,
  and transport parameters. Kernel QUIC and obfuscation control are in tension.

## The right gap-closers (userspace, keep packet control)

- GSO / GRO batching: already in the fork and pump. Keep.
- AF_XDP on exits: kernel-bypass to userspace at near line rate, the production
  answer for a high-throughput userspace data plane, and it preserves full
  packet control (unlike kernel QUIC). This is the main exit-side lever.
- Multiqueue TUN (`IFF_MULTI_QUEUE`) + per-core pumps: parallelise a busy exit
  across cores; the current pump is largely single-threaded per tunnel.
- Crypto: evaluate `aws-lc-rs` (VAES/AES-NI) versus the current `ring` backend
  on modern exit hardware; AES-GCM throughput is a measurable win on x86-64.
- io_uring for socket I/O on Linux exits.
- Client-side allocation fixes already identified: pool the DAITA / idle-cover
  receive path (it allocates and zero-fills 2 KiB per packet today), and cut
  the multihop per-packet copies. These matter most on the privacy paths and on
  constrained client devices.

The 32-connection fan-out that works around quinn's single-connection CPU
ceiling is the pragmatic present. The principled replacement is real multipath
QUIC, which is why the `MULTIPATH` feature bit is reserved, not deleted: it is
the home for that work when the fork gains multipath.

## Resolution: one datapath, named profiles

Do not ship two data planes (a WireGuard "fast" tier alongside QUIC). A second,
DPI-trivial protocol would be throttled by exactly the ISPs the torrent
audience wants to evade, and it would double the attack surface and abandon the
obfuscation moat. Instead expose named profiles over the single QUIC datapath:

- Stealth (censored networks): DAITA on, idle cover on, decoy on, throughput
  capped by the defenses. The ADR-0007 bar applies.
- Performance / P2P (torrent, uncensored ISP): DAITA off, protocol and
  fingerprint obfuscation kept (to dodge ISP VPN/torrent throttling), multi-conn
  maxed, NAT-PMP port forwarding on, leak protection on. No traffic-analysis
  defenses, because that audience's adversary does not do traffic analysis.

Only the throughput-expensive traffic-analysis defenses are profile-gated; the
protocol and fingerprint obfuscation of ADR-0007 stays on in both profiles, so
Performance still looks like HTTP/3 and still evades ISP throttling. DAITA is
already off by default today, so Performance is the de-facto current default;
the profile scheme only names it and adds an opt-in Stealth preset on top. The
engine already has the knobs (DAITA toggle, idle-cover toggle, multi-conn,
NAT-PMP); this is presets and honest docs, not new datapaths.

## Decision

- One QUIC datapath; reject a WireGuard fast tier and reject kernel QUIC for the
  client.
- Close the WireGuard gap with AF_XDP + multiqueue TUN + crypto-backend
  evaluation on exits, and the allocation fixes on clients; sequence and bench
  each.
- Ship Stealth and Performance profiles; keep `MULTIPATH` reserved for real
  multipath QUIC.

## Consequences

DAITA is already off by default, so the Performance profile is the de-facto
current behavior, now named and paired with an opt-in Stealth preset. No
imposition on any user (cf. the Resolution above).
