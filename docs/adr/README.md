# WarrenGuard ADRs: the engine and obfuscation decisions

Eight records covering the transport choice, the active-probing threat model and
the obfuscation roadmap. They lived at `warren-workspace/warrenguard-docs/` (a
private Warren repo) until 2026-08-02, which is why nothing in this repo
referenced them; the workspace holds no product content, so they belong here.

| ADR | subject |
|---|---|
| 0001 | transport: QUIC |
| 0002 | active-probing threat model |
| 0003 | active-probe decoy |
| 0004 | QUIC fingerprint parity |
| 0005 | decoy feasibility, the RPK tell |
| 0006 | keepalive traffic-analysis tell |
| 0007 | total obfuscation roadmap |
| 0008 | performance and positioning |

**There are two ADR series in Warren and their numbers collide.** This one is the
engine's. The other is `warren-core/docs/adr/`, in the private backend repo
(0001 to 0006: GFW posture, exit IP diversity, dataplane transport fallback,
X.509 multihop dispatcher, DNS content-blocking resolver, anonymous session
credentials). A bare "ADR-0004" is
therefore ambiguous: always write `warrenguard ADR-0004` or `warren-core
ADR-0004`.
