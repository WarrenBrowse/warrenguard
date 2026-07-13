# Security Policy

WarrenGuard is the data-plane engine behind a privacy VPN. Vulnerabilities in
the handshake, the crypto, the no-log discipline, and the censorship-resistance
surface are treated as high priority.

## Reporting a vulnerability

Report privately to **security@warrenbrowse.com**. Do not open a public issue
for a suspected vulnerability.

Include the affected crate and version (or commit), a description of the issue,
and a proof of concept if you have one. If you need encryption, send a first
plaintext mail asking for a key.

Expect an acknowledgement within 72 hours and a proposed disclosure timeline.
Coordinated disclosure is supported and reporters are credited on request.

## Scope

In scope: the engine crates in this repository (handshake, wire formats,
identity and crypto, server admission, killswitch, relay and multihop, eDNS
proxy).

Out of scope: a deployer's own control-plane (admission, accounting,
discovery), which is not part of this engine; and resource exhaustion caused by
a deployer misconfiguration of a documented tuning knob.

## Default posture is not the hardened posture

Several censorship-resistance defenses (idle cover traffic, the active-probe
decoy, X.509 cover-domain mode) are opt-in and off by default. A deployer
targeting a censored network must enable them. Report gaps against the enabled
configuration, and note which defenses were on.
