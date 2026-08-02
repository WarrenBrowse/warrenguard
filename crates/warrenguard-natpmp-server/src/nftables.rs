//! Linux nftables backend for `warrenguard-natpmp-server` - DNAT injection
//! via `nft -f -` shell-out.
//!
//! ## Strategy
//!
//! Rather than dynamic rules, Warren uses **nftables maps**
//! (`type inet_service : ipv4_addr . inet_service`). Benefits:
//! - One static rule per protocol, never modified → no handle
//!   tracking, no `nft list` parsing (fragile and race-prone).
//! - O(1) atomic element add/remove.
//! - State queryable via `nft list map inet warren natpmp_tcp_dnat`.
//!
//! Available since nftables 1.0.0 (Debian 12+).
//!
//! ## Setup-time structure
//!
//! ```nft
//! destroy table inet warren
//! add table inet warren
//! add map inet warren natpmp_tcp_dnat { type inet_service : ipv4_addr . inet_service ; }
//! add map inet warren natpmp_udp_dnat { type inet_service : ipv4_addr . inet_service ; }
//! add chain inet warren prerouting_natpmp { type nat hook prerouting priority dstnat ; }
//! add rule inet warren prerouting_natpmp tcp dport @natpmp_tcp_dnat dnat ip to tcp dport map @natpmp_tcp_dnat
//! add rule inet warren prerouting_natpmp udp dport @natpmp_udp_dnat dnat ip to udp dport map @natpmp_udp_dnat
//! ```
//!
//! ## Per-allocation
//!
//! ```nft
//! add element inet warren natpmp_tcp_dnat { 49180 : 10.66.0.7 . 49180 }
//! delete element inet warren natpmp_tcp_dnat { 49180 }
//! ```

use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::allocator::Allocator;
use crate::{Allocation, NatPmpError, PortForwardingBackend, Proto};

/// Default Warren table name - shared across the module.
pub const DEFAULT_TABLE: &str = "warren";
/// Default chain name.
pub const DEFAULT_CHAIN: &str = "prerouting_natpmp";

/// nftables map name for TCP mappings. Hardcoded - changes with the
/// schema.
const MAP_TCP: &str = "natpmp_tcp_dnat";
/// nftables map name for UDP mappings.
const MAP_UDP: &str = "natpmp_udp_dnat";

fn map_name(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => MAP_TCP,
        Proto::Udp => MAP_UDP,
    }
}

/// Generates the nft setup script: idempotent reset + create table +
/// maps + chain + rules.
///
/// **Idempotent reset**: `add table` (no-op if it exists, creates
/// otherwise) → `delete table` (definitely exists after the add) →
/// `add table` (recreates empty). This replaces `destroy table`,
/// which is rejected by the Debian 12 build of nftables 1.0.6 (the
/// keyword exists upstream since 1.0.0 but the Debian parser rejects
/// it - verified on `Linux 6.1.0-41-amd64`, `nftables v1.0.6 Lester
/// Gooch #5`).
///
/// **Map-based DNAT**: the rule uses `meta l4proto {tcp|udp} dnat ip
/// to tcp|udp dport map @<map>`. The matcher `tcp dport @<map>` on a
/// set/map is rejected by the Debian 12 parser (`Could not process
/// rule: Invalid argument`) - same root cause as the `destroy` case.
/// The `meta l4proto` pattern is semantically equivalent (the rule
/// only DNATs packets whose destination port is present in the map,
/// by construction of `dport map @<map>`) and accepted everywhere
/// since nftables 0.9.x.
///
/// `table` is typically `"warren"`, `chain` `"prerouting_natpmp"`.
///
/// `pfwd_daddr` scopes the DNAT to a dedicated forwarded-port IP (Port
/// Fail parade, Perfect Privacy 2015): when `Some(ip)`, each DNAT rule
/// only fires for packets whose destination address is `ip`, so forwarded
/// ports live on an address that is NOT the QUIC ingress endpoint and NOT
/// in the client's off-tunnel route-split bypass. A co-tenant probing the
/// forwarded port therefore transits the tunnel instead of leaking its
/// real IP off-tunnel. `None` keeps the legacy behaviour (DNAT on any
/// destination), used only for single-IP dev where separation is off.
#[must_use]
pub fn render_setup_script(table: &str, chain: &str, pfwd_daddr: Option<Ipv4Addr>) -> String {
    let daddr_match = pfwd_daddr
        .map(|ip| format!("ip daddr {ip} "))
        .unwrap_or_default();
    format!(
        "add table inet {table}\n\
         delete table inet {table}\n\
         add table inet {table}\n\
         add map inet {table} {MAP_TCP} {{ type inet_service : ipv4_addr . inet_service ; }}\n\
         add map inet {table} {MAP_UDP} {{ type inet_service : ipv4_addr . inet_service ; }}\n\
         add chain inet {table} {chain} {{ type nat hook prerouting priority dstnat ; }}\n\
         add rule inet {table} {chain} {daddr_match}meta l4proto tcp dnat ip to tcp dport map @{MAP_TCP}\n\
         add rule inet {table} {chain} {daddr_match}meta l4proto udp dnat ip to udp dport map @{MAP_UDP}\n"
    )
}

/// Default chain name for the Port Fail defense-in-depth guard.
pub const DEFAULT_PORTFAIL_GUARD_CHAIN: &str = "warren_portfail_guard";
/// Default set name holding the real (outer, 5-tuple) IPv4 of every
/// currently-connected subscriber.
pub const DEFAULT_CLIENT_REAL_IPS_SET: &str = "warren_client_real_ips";

/// Renders the setup for the Port Fail defense-in-depth guard (a companion to
/// the client-side route-split fix, protecting old clients during the
/// transition).
///
/// The guard drops packets whose SOURCE is the real IPv4 of a
/// currently-connected subscriber when they land on a forwarded port owned by
/// someone else. This is the server-side parade to the PIA / Perfect Privacy
/// "Port Fail" deanonymization: a co-tenant lured into probing another
/// subscriber's forwarded port on the exit IP would, on an old client whose
/// route-split is not yet narrowed to the ingress `/32`, leak its real address
/// off-tunnel. Dropping such packets on the exit closes that window.
///
/// It is deliberately NOT a "tunneled vs untunneled" filter: only the real IPs
/// of connected subscribers are in `set_name`, so a public Internet peer
/// (never in the set) reaches the forwarded port untouched and port forwarding
/// stays unrestricted.
///
/// Placement: a `filter` chain on the `forward` hook at priority `-10`, i.e.
/// AFTER prerouting DNAT (`dstnat`, -100) and BEFORE the default forward filter
/// (0). By the forward hook a forwarded-port packet has its destination
/// rewritten to the owner's inner pool IP, so matching `ip daddr <pool_cidr>`
/// selects exactly the forwarded-port traffic without needing a separate
/// port set (which the Debian nft parser rejects as a `dport @set` matcher).
///
/// Established flows are exempt, and that exemption is what keeps the match
/// narrow enough to be correct. `ip daddr <pool_cidr>` does NOT select only
/// forwarded-port traffic: it is equally the destination of the RETURN leg of
/// any connection the subscriber itself opened. So a subscriber reaching a
/// service hosted at its own public address (a home server, or anything behind
/// the same CGNAT address) would have every reply dropped, with the exit
/// forwarding the SYN, the far end answering, and the SYN-ACK never reaching
/// the tunnel. Port Fail is an unsolicited probe, which conntrack sees as
/// `new`, so exempting `established,related` costs the defence nothing.
///
/// Remaining, genuinely rare false positive: a connected subscriber opening a
/// NEW connection to a forwarded port on THIS exit from its own real IP
/// off-tunnel is still dropped. That one is not a deanonymization (the owner
/// already knows its own IP), only a reachability quirk.
#[must_use]
pub fn render_portfail_guard_setup(
    table: &str,
    guard_chain: &str,
    set_name: &str,
    pool_cidr: &str,
) -> String {
    format!(
        "add set inet {table} {set_name} {{ type ipv4_addr ; }}\n\
         add chain inet {table} {guard_chain} {{ type filter hook forward priority -10 ; policy accept ; }}\n\
         add rule inet {table} {guard_chain} ct state established,related accept\n\
         add rule inet {table} {guard_chain} ip saddr @{set_name} ip daddr {pool_cidr} drop\n"
    )
}

/// Default chain name for the optional same-exit-peer hairpin SNAT.
pub const DEFAULT_HAIRPIN_SNAT_CHAIN: &str = "warren_hairpin_snat";

/// Renders the optional hairpin SNAT (Layer 3 hygiene, off by default).
///
/// When a same-exit peer (inner pool IP `10.66.x`) reaches another
/// subscriber's forwarded port, the DNAT sends its packet BACK out the tunnel
/// to the owner, keeping the peer's inner `10.66.x` source (the egress
/// masquerade is `oifname != tun`, so it does not cover the hairpin path). This
/// masquerades that inner source to the tunnel gateway so the port owner does
/// not learn the peer's inner pool IP.
///
/// It is scoped to `ip saddr <pool_cidr> oifname "<tun_name>"`, so it fires
/// ONLY for hairpinned pool-internal sources: a PUBLIC Internet peer (not in
/// the pool) reaching the forwarded port keeps its real source IP, preserving
/// the port-forwarding feature untouched.
///
/// The gain is marginal (the `10.66.x` address is ephemeral and
/// non-identifying), which is why this is off by default and behind an opt-in
/// flag rather than always installed.
#[must_use]
pub fn render_hairpin_snat_setup(
    table: &str,
    chain: &str,
    pool_cidr: &str,
    tun_name: &str,
) -> String {
    format!(
        "add chain inet {table} {chain} {{ type nat hook postrouting priority srcnat ; policy accept ; }}\n\
         add rule inet {table} {chain} ip saddr {pool_cidr} oifname \"{tun_name}\" masquerade\n"
    )
}

/// Renders the atomic script that replaces the connected-subscriber real-IP
/// set membership: `flush set` then one `add element` per IP. Applied via a
/// single `nft -f -`, so the swap is atomic (no window where a stale IP is
/// dropped or a new one is missed). An empty `ips` yields just the flush,
/// which empties the set so the guard drops nothing (fail-open when there is
/// nothing to protect).
#[must_use]
pub fn render_sync_client_ips(table: &str, set_name: &str, ips: &[Ipv4Addr]) -> String {
    let mut out = format!("flush set inet {table} {set_name}\n");
    for ip in ips {
        out.push_str(&format!("add element inet {table} {set_name} {{ {ip} }}\n"));
    }
    out
}

/// Generates the nft command to insert a mapping `external_port →
/// internal_ip:internal_port` for protocol `proto`.
#[must_use]
pub fn render_add_element(
    table: &str,
    proto: Proto,
    external_port: u16,
    internal_ip: Ipv4Addr,
    internal_port: u16,
) -> String {
    let m = map_name(proto);
    format!("add element inet {table} {m} {{ {external_port} : {internal_ip} . {internal_port} }}")
}

/// Generates the nft command to remove a mapping by external port +
/// proto.
#[must_use]
pub fn render_delete_element(table: &str, proto: Proto, external_port: u16) -> String {
    let m = map_name(proto);
    format!("delete element inet {table} {m} {{ {external_port} }}")
}

/// nft script execution abstraction. Production implements it as a
/// shell-out to `nft -f -` (see [`ShellNftExecutor`],
/// `cfg(target_os = "linux")`). Tests provide a mock that captures
/// the scripts.
pub trait NftExecutor: Send + Sync {
    /// Executes `script` (multi-line). Returns `Err(stderr)` on
    /// failure.
    fn run_script(&self, script: &str) -> impl Future<Output = Result<(), String>> + Send;
}

/// Port-forwarding backend that injects DNAT rules via nftables.
///
/// The internal `Allocator` handles abuse mitigations (cooldown,
/// anti-rotation, rate limit). This layer just orchestrates the nft
/// commands that translate each allocation into a kernel mapping.
///
/// `E` (the nft executor) stays generic to preserve monomorphization:
/// `NftablesBackend<ShellNftExecutor>` in Linux prod,
/// `NftablesBackend<Recorder>` in tests. The trait's RPITIT prevents
/// `Box<dyn NftExecutor>`, which is fine here.
pub struct NftablesBackend<E> {
    allocator: Arc<Allocator>,
    runner: Arc<E>,
    table: String,
    chain: String,
    portfail_guard: Option<PortFailGuard>,
}

/// Configuration for the optional Port Fail defense-in-depth guard (see
/// [`render_portfail_guard_setup`]). Off unless the exit deliberately enables
/// it during the client-migration transition.
#[derive(Debug, Clone)]
pub struct PortFailGuard {
    /// Name of the guard's `filter`/`forward` chain.
    pub chain: String,
    /// Name of the set holding connected subscribers' real IPv4s.
    pub set: String,
    /// Inner tunnel pool CIDR (e.g. `10.66.0.0/16`): a forwarded-port packet
    /// has its destination rewritten into this range by the DNAT, so matching
    /// it selects exactly the forwarded-port traffic post-DNAT.
    pub pool_cidr: String,
}

impl PortFailGuard {
    /// Guard with the default chain/set names and the given inner pool CIDR.
    #[must_use]
    pub fn new(pool_cidr: impl Into<String>) -> Self {
        Self {
            chain: DEFAULT_PORTFAIL_GUARD_CHAIN.to_string(),
            set: DEFAULT_CLIENT_REAL_IPS_SET.to_string(),
            pool_cidr: pool_cidr.into(),
        }
    }
}

/// Configuration for the optional same-exit-peer hairpin SNAT (see
/// [`render_hairpin_snat_setup`]). Off by default (marginal gain).
#[derive(Debug, Clone)]
pub struct HairpinSnat {
    /// Name of the hairpin postrouting/srcnat chain.
    pub chain: String,
    /// Inner tunnel pool CIDR whose hairpinned sources are masked.
    pub pool_cidr: String,
    /// Tunnel interface name (the hairpin is `oifname "<tun>"`).
    pub tun_name: String,
}

impl HairpinSnat {
    /// Hairpin SNAT with the default chain name and the given pool CIDR + tun.
    #[must_use]
    pub fn new(pool_cidr: impl Into<String>, tun_name: impl Into<String>) -> Self {
        Self {
            chain: DEFAULT_HAIRPIN_SNAT_CHAIN.to_string(),
            pool_cidr: pool_cidr.into(),
            tun_name: tun_name.into(),
        }
    }
}

impl<E: NftExecutor + 'static> NftablesBackend<E> {
    /// Builds a backend with the given runner, executing the setup
    /// script (destroy + create table/maps/chain/rules) immediately.
    /// DNAT is unscoped (any destination); prefer [`Self::with_pfwd_ip`]
    /// in production to pin forwarded ports to a dedicated egress IP.
    ///
    /// # Errors
    ///
    /// Returns [`NatPmpError::Backend`] if `nft` fails (kernel
    /// without nat support, missing permissions, invalid syntax,
    /// ...).
    pub async fn new(runner: Arc<E>) -> Result<Self, NatPmpError> {
        Self::with_names(runner, DEFAULT_TABLE, DEFAULT_CHAIN, None, None, None).await
    }

    /// Builds a backend whose DNAT is scoped to `pfwd_ip` (optional dual-IP
    /// hardening): forwarded ports only answer on the dedicated
    /// forwarded-port address, never the QUIC ingress endpoint.
    ///
    /// # Errors
    ///
    /// See [`Self::new`].
    pub async fn with_pfwd_ip(
        runner: Arc<E>,
        pfwd_ip: Option<Ipv4Addr>,
    ) -> Result<Self, NatPmpError> {
        Self::with_names(runner, DEFAULT_TABLE, DEFAULT_CHAIN, pfwd_ip, None, None).await
    }

    /// Builds a backend with the optional DNAT scope AND the optional Port
    /// Fail defense-in-depth guard (connected-subscriber real-IP drop). The
    /// guard set + chain + rule are installed as part of the same atomic
    /// setup script.
    ///
    /// # Errors
    ///
    /// See [`Self::new`].
    pub async fn with_pfwd_ip_and_guard(
        runner: Arc<E>,
        pfwd_ip: Option<Ipv4Addr>,
        portfail_guard: Option<PortFailGuard>,
    ) -> Result<Self, NatPmpError> {
        Self::with_names(
            runner,
            DEFAULT_TABLE,
            DEFAULT_CHAIN,
            pfwd_ip,
            portfail_guard,
            None,
        )
        .await
    }

    /// Builds a backend with the optional DNAT scope, the optional Port Fail
    /// guard, AND the optional same-exit-peer hairpin SNAT. All are installed
    /// in one atomic setup script.
    ///
    /// # Errors
    ///
    /// See [`Self::new`].
    pub async fn with_options(
        runner: Arc<E>,
        pfwd_ip: Option<Ipv4Addr>,
        portfail_guard: Option<PortFailGuard>,
        hairpin_snat: Option<HairpinSnat>,
    ) -> Result<Self, NatPmpError> {
        Self::with_names(
            runner,
            DEFAULT_TABLE,
            DEFAULT_CHAIN,
            pfwd_ip,
            portfail_guard,
            hairpin_snat,
        )
        .await
    }

    /// Variant with custom table/chain names (useful to colocate
    /// several warren-* on the same host, e.g. dev + prod), an
    /// optional forwarded-port destination scope, the optional Port Fail
    /// defense-in-depth guard, and the optional hairpin SNAT.
    ///
    /// # Errors
    ///
    /// See [`Self::new`].
    pub async fn with_names(
        runner: Arc<E>,
        table: &str,
        chain: &str,
        pfwd_ip: Option<Ipv4Addr>,
        portfail_guard: Option<PortFailGuard>,
        hairpin_snat: Option<HairpinSnat>,
    ) -> Result<Self, NatPmpError> {
        let mut setup = render_setup_script(table, chain, pfwd_ip);
        // Append the optional guard/hairpin to the SAME script so the table
        // reset in render_setup_script and these extra chains apply atomically:
        // a separate second call could observe the table between the two.
        if let Some(guard) = portfail_guard.as_ref() {
            setup.push_str(&render_portfail_guard_setup(
                table,
                &guard.chain,
                &guard.set,
                &guard.pool_cidr,
            ));
        }
        // The hairpin SNAT is fully applied at setup (no runtime sync needed,
        // unlike the guard's dynamic set), so it is consumed here, not stored.
        if let Some(hairpin) = hairpin_snat.as_ref() {
            setup.push_str(&render_hairpin_snat_setup(
                table,
                &hairpin.chain,
                &hairpin.pool_cidr,
                &hairpin.tun_name,
            ));
        }
        runner
            .run_script(&setup)
            .await
            .map_err(NatPmpError::Backend)?;
        Ok(Self {
            allocator: Arc::new(Allocator::new()),
            runner,
            table: table.to_string(),
            chain: chain.to_string(),
            portfail_guard,
        })
    }

    /// Replaces the Port Fail guard's connected-subscriber real-IP set with
    /// `ips` (flush + re-add, atomic). A no-op returning `Ok(())` when the
    /// guard is not configured, so the caller's periodic maintainer can call
    /// it unconditionally.
    ///
    /// # Errors
    ///
    /// Returns [`NatPmpError::Backend`] if the `nft` sync fails.
    pub async fn sync_portfail_guard_ips(&self, ips: &[Ipv4Addr]) -> Result<(), NatPmpError> {
        let Some(guard) = self.portfail_guard.as_ref() else {
            return Ok(());
        };
        let script = render_sync_client_ips(&self.table, &guard.set, ips);
        self.runner
            .run_script(&script)
            .await
            .map_err(NatPmpError::Backend)
    }

    /// Access to the internal allocator (useful for metrics and
    /// tests).
    #[must_use]
    pub fn allocator(&self) -> &Arc<Allocator> {
        &self.allocator
    }

    /// Currently used table name. Useful for operators inspecting via
    /// `nft list table inet <name>`.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Chain name.
    #[must_use]
    pub fn chain(&self) -> &str {
        &self.chain
    }

    /// Allocate with an injectable `now`, so a caller (tests, future
    /// ops tooling) can drive the allocator's lazy expiry sweep
    /// deterministically and observe that the matching nftables
    /// elements are torn down. Production goes through the
    /// [`PortForwardingBackend::allocate`] trait method, which pins
    /// `now` to `Instant::now()`. Both share [`Self::allocate_at`]'s
    /// body via this method.
    ///
    /// # Errors
    ///
    /// See [`NatPmpError`]. A failed `add element` rolls the new
    /// allocation back in the allocator; failed teardown of evicted
    /// elements is logged but does not fail the allocation (the entry
    /// is gone from the allocator regardless).
    pub fn allocate_at(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested_external_port: u16,
        lifetime: Duration,
        now: Instant,
    ) -> impl Future<Output = Result<Allocation, NatPmpError>> + Send {
        let allocator = Arc::clone(&self.allocator);
        let runner = Arc::clone(&self.runner);
        let table = self.table.clone();
        let lifetime_secs = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
        async move {
            // 1. Reserve a port in the Allocator (abuse mitigations
            // applied). `allocate_at_collecting` also surfaces every
            // entry it removed as a side effect: expired mappings
            // swept lazily, and a stale same-tuple mapping reclaimed on
            // refresh (e.g. the client changed its suggested external
            // port). Those removals must be mirrored into the kernel or
            // their DNAT element leaks - the desync this fixes.
            let outcome = allocator.allocate_at_collecting(
                client_ip,
                proto,
                internal_port,
                suggested_external_port,
                lifetime_secs,
                now,
            );

            // 2. Tear down the nft element of every evicted mapping
            // FIRST and UNCONDITIONALLY - before surfacing the
            // allocation result below, so a `RateLimited` /
            // `QuotaExceeded` / `Exhausted` failure cannot skip it. The
            // allocator has already removed these entries from `active`,
            // so any path that drops them without a kernel delete leaks
            // their DNAT element (the desync `evicted` exists to fix).
            // Ordering vs. the add (step 3) also matters: a refresh that
            // keeps the same external port surfaces that port as
            // evicted, so delete-then-add leaves the (possibly
            // re-targeted) element correct; add-then-delete would wipe
            // the freshly added element. A delete failure is logged but
            // not fatal: the allocator already dropped the entry, and a
            // residual kernel element is reclaimed on the next allocate
            // that reuses the port.
            for ev in &outcome.evicted {
                let del = render_delete_element(&table, ev.proto, ev.external_port);
                if let Err(stderr) = runner.run_script(&del).await {
                    tracing::warn!(
                        error = %stderr,
                        external_port = ev.external_port,
                        "nft delete element for evicted mapping failed; DNAT rule may linger"
                    );
                }
            }

            // Evicted entries are now torn down on every path. Surface
            // the allocation result; on failure we return here, having
            // already cleaned up the kernel state above.
            let alloc = outcome.result?;

            // 3. Inject the nftables rule for the new allocation. If
            // injection fails, roll back the Allocator to avoid leaking
            // a phantom mapping that nothing routes to.
            //
            // A client that does not bind a specific local port sends
            // `internal_port == 0`. DNAT-ing to port 0 is a black hole,
            // so we forward to the allocated external port instead
            // (public E → client:E, the intuitive "same port on your
            // device" model). The stored allocation keeps
            // `internal_port == 0` untouched so the RFC 6886 refresh
            // key `(client_ip, internal_port, proto)` stays stable.
            let dnat_port = if alloc.internal_port == 0 {
                alloc.external_port
            } else {
                alloc.internal_port
            };
            let script = render_add_element(
                &table,
                proto,
                alloc.external_port,
                alloc.internal_ip,
                dnat_port,
            );
            if let Err(stderr) = runner.run_script(&script).await {
                allocator.release(&alloc);
                return Err(NatPmpError::Backend(stderr));
            }
            Ok(alloc)
        }
    }
}

impl<E: NftExecutor + 'static> PortForwardingBackend for NftablesBackend<E> {
    fn allocate(
        &self,
        client_ip: Ipv4Addr,
        proto: Proto,
        internal_port: u16,
        suggested_external_port: u16,
        lifetime: Duration,
    ) -> impl Future<Output = Result<Allocation, NatPmpError>> + Send {
        self.allocate_at(
            client_ip,
            proto,
            internal_port,
            suggested_external_port,
            lifetime,
            Instant::now(),
        )
    }

    fn release(&self, alloc: &Allocation) -> impl Future<Output = Result<(), NatPmpError>> + Send {
        let allocator = Arc::clone(&self.allocator);
        let runner = Arc::clone(&self.runner);
        let table = self.table.clone();
        let alloc = alloc.clone();
        async move {
            // The allocator is idempotent best-effort on release -
            // call nft first (its error is the most interesting one
            // to log), then release in the allocator even on nft
            // failure so the pool is not blocked.
            let script = render_delete_element(&table, alloc.proto, alloc.external_port);
            let nft_res = runner.run_script(&script).await;
            allocator.release(&alloc);
            nft_res.map_err(NatPmpError::Backend)
        }
    }

    fn release_by_client(
        &self,
        client_ip: Ipv4Addr,
        internal_port: u16,
        proto: Proto,
    ) -> impl Future<Output = bool> + Send {
        let allocator = Arc::clone(&self.allocator);
        let runner = Arc::clone(&self.runner);
        let table = self.table.clone();
        async move {
            // 1. Lookup + release in the Allocator by (client_ip,
            // internal_port, proto). Recover the real `external_port`
            // for the delete script.
            let Some(alloc) = allocator.release_by_client(client_ip, internal_port, proto) else {
                return false;
            };
            // 2. Emit the delete element for the resolved
            // external_port. The error is logged but we return `true`
            // (the RAM pool is freed; a kernel drift will be cleaned
            // up on the next setup or reload).
            let script = render_delete_element(&table, proto, alloc.external_port);
            if let Err(stderr) = runner.run_script(&script).await {
                tracing::warn!(
                    error = %stderr,
                    external_port = alloc.external_port,
                    "nft delete element failed"
                );
            }
            true
        }
    }

    fn rate_limit_status(&self, client_ip: Ipv4Addr) -> crate::protocol::RateLimitInfo {
        self.allocator.rate_limit_status(client_ip)
    }

    fn restore(&self, entries: Vec<Allocation>) -> impl Future<Output = Vec<Allocation>> + Send {
        let allocator = Arc::clone(&self.allocator);
        let runner = Arc::clone(&self.runner);
        let table = self.table.clone();
        async move {
            let mut live = Vec::new();
            for alloc in allocator.restore(entries) {
                // Same port-0 forwarding fallback as `allocate_at`: the
                // stored entry keeps `internal_port == 0` untouched, the
                // kernel rule targets the external port.
                let dnat_port = if alloc.internal_port == 0 {
                    alloc.external_port
                } else {
                    alloc.internal_port
                };
                let script = render_add_element(
                    &table,
                    alloc.proto,
                    alloc.external_port,
                    alloc.internal_ip,
                    dnat_port,
                );
                if let Err(stderr) = runner.run_script(&script).await {
                    // Drop only this slot, WITHOUT arming a cooldown:
                    // nothing routes to it, so the owner's fresh
                    // re-request must be able to grab it back at once,
                    // and the pair's other leg (restored separately)
                    // must not be collaterally evicted.
                    allocator.take_active_for_slot(alloc.external_port, alloc.proto);
                    tracing::warn!(
                        error = %stderr,
                        external_port = alloc.external_port,
                        "nft add element failed on restore; entry dropped"
                    );
                    continue;
                }
                live.push(alloc);
            }
            live
        }
    }
}

/// Real `NftExecutor`: shell-out to `nft -f -` via `tokio::process`.
/// Linux-only (on macOS / other targets, tests use a mock and prod
/// code does not compile when `target_os != linux`).
#[cfg(target_os = "linux")]
pub struct ShellNftExecutor;

#[cfg(target_os = "linux")]
impl ShellNftExecutor {
    /// Builds an executor; consumes no resources until the first
    /// `run_script` call.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
impl Default for ShellNftExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl NftExecutor for ShellNftExecutor {
    fn run_script(&self, script: &str) -> impl Future<Output = Result<(), String>> + Send {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;
        let script_owned = script.to_string();
        async move {
            let mut child = Command::new("nft")
                .arg("-f")
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("failed to spawn nft: {e}"))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(script_owned.as_bytes())
                    .await
                    .map_err(|e| format!("failed to write nft stdin: {e}"))?;
                drop(stdin);
            }
            let output = child
                .wait_with_output()
                .await
                .map_err(|e| format!("failed to wait for nft: {e}"))?;
            if output.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                Err(format!(
                    "nft exited with {}: {}",
                    output.status,
                    stderr.trim()
                ))
            }
        }
    }
}
