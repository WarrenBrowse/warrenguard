//! IPv4 pool allocator for multi-hop client IP negotiation.
//!
//! Each multi-hop connection accepted by the exit gets a unique IPv4
//! from a configurable subnet (default `10.66.0.0/24`), so multiple
//! clients can share one exit-side TUN without colliding on the
//! gateway. See `.planning/session-aa-multi-hop-ip-nego-design.md`
//! for the end-to-end protocol context.
//!
//! Allocation lifecycle :
//!
//! 1. A fresh QUIC connection arrives.
//! 2. The exit pump assigns a `ConnId` (any caller-chosen u64 unique to
//!    the connection - Quinn's `ConnectionId` mapped to u64 works) and
//!    calls [`IpAllocator::allocate`].
//! 3. The returned `Ipv4Addr` is sealed as an `IpAssign` control
//!    message and sent back to the client.
//! 4. On connection close, [`IpAllocator::release`] returns the address
//!    to the free set. Allocation draws a RANDOM free host (not arrival
//!    order) so the inner IP is never a positional function of a stable
//!    client identifier (Mullvad cross-exit egress-fingerprint lesson).
//!
//! The allocator is **not** thread-safe. Wrap in `Arc<Mutex<_>>` for
//! shared access across the multi-conn spawn loop.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Minimal SplitMix64 PRNG used ONLY to pick which free host a fresh
/// session lands on. It is not cryptographic: the value it protects is a
/// tunnel-internal position that is masqueraded away before egress (never
/// visible to a destination), so the requirement is "no stable-identifier
/// -derived ordering", not unpredictability. Seeded from OS entropy at
/// construction (`os_seed`), so two exits draw independently and no
/// position is a function of arrival order or of any client identifier.
/// A deterministic seed constructor exists for tests only.
#[derive(Debug)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish index in `0..n`. Caller guarantees `n > 0`.
    fn bounded(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// Draw a seed from the OS RNG. Falls back to a coarse time-based seed if
/// the OS entropy source is unavailable, which must never panic here: a
/// weaker seed only degrades position spreading, it does not break
/// correctness or leak an identifier.
fn os_seed() -> u64 {
    use rand_core::{OsRng, TryRngCore};
    let mut rng = OsRng;
    rng.try_next_u64().unwrap_or_else(|_| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678_9ABC_DEF0)
            ^ 0x9E37_79B9_7F4A_7C15
    })
}

/// Caller-supplied unique identifier for a multi-hop connection. The
/// allocator keys its `used` map on this so multiple `allocate` calls
/// for the same connection are idempotent (return the same IP).
pub type ConnId = u64;

/// Session-placement intent a client declares through the (pre-existing)
/// `prefer_ipv4` field of its `IpRequest`/`IpRequestV7`. The downlink route
/// table keys ownership on the assigned inner IP, so two LIVE sessions of
/// one wallet sharing an IP steal each other's return packets whenever
/// their inner flows collide (identical 5-tuples collapse in the kernel
/// NAT, ICMP fans out round-robin). The intent lets the allocator place
/// each SESSION on its own IP while bonded connections of one session
/// still share theirs.
///
/// Hint-capable clients send `0.0.0.0` on a session's first connection and
/// the session's assigned IP on every later one (bonded secondaries,
/// overlap or fast reconnects). Deployed hint-less clients decode to
/// [`Self::Legacy`] and keep the historical semantics untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionIntent {
    /// No hint on the wire: historical same-pubkey sharing (deployed
    /// clients, bonded or not). Behavior byte-for-byte unchanged.
    Legacy,
    /// `prefer_ipv4 = 0.0.0.0`: an independent session start. Never
    /// co-housed on an IP a live session of the same key holds; still
    /// granted the sticky IP when that IP is free.
    Fresh,
    /// `prefer_ipv4 = <addr>`: this connection belongs to the session
    /// holding `<addr>`. Shared only when `<addr>` is held by (or sticky
    /// for) the SAME authenticated key, so a hint can never land a client
    /// on another identity's address.
    Join(Ipv4Addr),
}

impl SessionIntent {
    /// Derives the intent from the raw wire hint. `0.0.0.0` is the
    /// "session-fresh" sentinel: it is never an allocatable host, so no
    /// legal join target is shadowed.
    #[must_use]
    pub fn from_prefer_ipv4(hint: Option<[u8; 4]>) -> Self {
        match hint {
            None => Self::Legacy,
            Some([0, 0, 0, 0]) => Self::Fresh,
            Some(addr) => Self::Join(Ipv4Addr::from(addr)),
        }
    }
}

/// [`SessionIntent`] projected for the IPv6 allocator. The wire carries no
/// v6 hint; the caller derives this from the v4 placement decision:
/// `Join` names the sibling connections that share the session's v4, so
/// the v6 allocation joins the same session's interface ID.
#[derive(Debug, Clone, Copy)]
pub enum SessionIntentV6<'a> {
    /// Hint-less request: historical same-pubkey sharing.
    Legacy,
    /// Independent session start: never co-housed on a live-held offset.
    Fresh,
    /// Share the interface ID held by these same-key sibling connections.
    Join(&'a [ConnId]),
}

/// Errors returned by [`IpAllocator::new`].
#[derive(Debug, thiserror::Error)]
pub enum IpPoolError {
    /// Prefix length is outside the IPv4 range (1..=32).
    #[error("invalid IPv4 prefix length {prefix_len} (expected 1..=32)")]
    InvalidPrefix {
        /// Prefix length passed by the caller.
        prefix_len: u8,
    },
    /// Subnet has no usable host beyond the gateway (e.g. `/31` or `/32`).
    #[error(
        "subnet {network}/{prefix_len} has no usable host beyond gateway {gateway} (subnet capacity {capacity})"
    )]
    NoUsableHosts {
        /// Subnet network address derived from `network_ipv4 & netmask`.
        network: Ipv4Addr,
        /// Prefix length passed by the caller.
        prefix_len: u8,
        /// Gateway address passed by the caller.
        gateway: Ipv4Addr,
        /// Host count in the subnet excluding network + broadcast.
        capacity: u32,
    },
    /// Gateway does not belong to the supplied subnet.
    #[error("gateway {gateway} is not inside subnet {network}/{prefix_len}")]
    GatewayOutsideSubnet {
        /// Subnet network address.
        network: Ipv4Addr,
        /// Subnet prefix length.
        prefix_len: u8,
        /// Gateway address that violated the subnet bound.
        gateway: Ipv4Addr,
    },
}

/// IPv4 pool with allocate / release semantics and RANDOM free-host
/// selection. See the module docs for the wider IP-negotiation flow.
///
/// A fresh, non-sticky allocation draws a uniformly random free host from
/// an OS-seeded PRNG, not the lowest free host in arrival order. The old
/// FIFO ordering made the assigned inner IP a deterministic function of
/// arrival order (a weak positional signal, and one design change away
/// from the Mullvad cross-exit egress fingerprint). Random selection
/// removes it and costs nothing on a small subnet. The inner IP is
/// masqueraded away before egress, so it is never destination-visible;
/// this hardening keeps it from becoming a stable-identifier position.
///
/// The optional `sticky` map records the most recent
/// IP each client pubkey received, so [`IpAllocator::allocate_for_pubkey`]
/// can serve a sticky address across reconnects. Stickiness is
/// best-effort : if the previously-allocated IP has been recycled to
/// another client in the meantime, the keyed allocate falls back to a
/// fresh pop from `free`. The map is in-memory only and resets at
/// process restart, which keeps the privacy property (no on-disk
/// per-client identifier).
///
/// The sticky map is **self-cleaning** : when a
/// fresh allocate (path 3 in [`Self::allocate_for_pubkey`]) recycles
/// an address that was sticky-bound to a *different* pubkey, the stale
/// binding is evicted. This maintains the invariant `sticky.len() ≤
/// pool.capacity()` - each in-use IP has at most one sticky owner - so
/// memory cannot grow beyond the subnet size regardless of how many
/// distinct pubkeys ever connect. A malicious client rotating its
/// Ed25519 signing key on every reconnect therefore cannot inflate the
/// exit's RSS unboundedly (for a /24 the worst case is ≈ 25 KB).
#[derive(Debug)]
pub struct IpAllocator {
    network: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    /// Free hosts in no meaningful order: allocation swap-removes a random
    /// index, release pushes back. Order carries no information by design.
    free: Vec<Ipv4Addr>,
    rng: SplitMix64,
    used: HashMap<ConnId, Ipv4Addr>,
    sticky: HashMap<[u8; 32], Ipv4Addr>,
    /// Pubkey that authenticated each live allocation (absent for the
    /// legacy no-pubkey `allocate` path). Required by the same-pubkey
    /// takeover in [`Self::allocate_for_pubkey`]: an address may only
    /// be transferred between two connections of the SAME identity.
    owners: HashMap<ConnId, [u8; 32]>,
}

impl IpAllocator {
    /// Build a pool covering every host of `network_ipv4 / prefix_len`
    /// except `gateway` (which the exit-side TUN already owns).
    ///
    /// The network and broadcast addresses are also excluded.
    ///
    /// # Errors
    ///
    /// See [`IpPoolError`].
    pub fn new(
        network_ipv4: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    ) -> Result<Self, IpPoolError> {
        Self::with_seed(network_ipv4, prefix_len, gateway, os_seed())
    }

    /// Build a pool with an explicit PRNG seed. Tests use this to drive the
    /// random free-host selection deterministically; production goes
    /// through [`Self::new`], which seeds from OS entropy.
    ///
    /// # Errors
    ///
    /// See [`IpPoolError`].
    pub fn with_seed(
        network_ipv4: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        seed: u64,
    ) -> Result<Self, IpPoolError> {
        if prefix_len == 0 || prefix_len > 32 {
            return Err(IpPoolError::InvalidPrefix { prefix_len });
        }
        let host_bits = 32 - u32::from(prefix_len);
        let netmask: u32 = if host_bits == 32 {
            0
        } else {
            u32::MAX << host_bits
        };
        let network_u32 = u32::from(network_ipv4) & netmask;
        let network = Ipv4Addr::from(network_u32);
        let broadcast_u32 = network_u32 | !netmask;

        // /31 has 2 addresses (RFC 3021 point-to-point) - but with a
        // dedicated gateway we still need at least 1 free host, which
        // requires the subnet to have at least 3 host slots total
        // (network + gateway + 1). /30 is the smallest workable prefix
        // when network + broadcast are reserved.
        let subnet_capacity = if host_bits >= 31 {
            // /1 .. /0 are absurd but allowed by the prefix range; cap
            // saturating to avoid integer overflow on /0.
            u32::MAX
        } else {
            (1u32 << host_bits).saturating_sub(2)
        };
        if (u32::from(gateway) & netmask) != network_u32 {
            return Err(IpPoolError::GatewayOutsideSubnet {
                network,
                prefix_len,
                gateway,
            });
        }
        if subnet_capacity == 0 {
            return Err(IpPoolError::NoUsableHosts {
                network,
                prefix_len,
                gateway,
                capacity: subnet_capacity,
            });
        }
        // Build the free set : iterate every host in the subnet, exclude
        // network + broadcast + gateway. Order is irrelevant because
        // allocation draws a RANDOM index (anti-correlation): the assigned
        // host must not be a function of arrival order.
        let mut free = Vec::new();
        for host in (network_u32 + 1)..broadcast_u32 {
            let addr = Ipv4Addr::from(host);
            if addr == gateway {
                continue;
            }
            free.push(addr);
        }
        if free.is_empty() {
            return Err(IpPoolError::NoUsableHosts {
                network,
                prefix_len,
                gateway,
                capacity: subnet_capacity,
            });
        }
        Ok(Self {
            network,
            prefix_len,
            gateway,
            free,
            rng: SplitMix64::new(seed),
            used: HashMap::new(),
            sticky: HashMap::new(),
            owners: HashMap::new(),
        })
    }

    /// Remove and return a uniformly random free host, or `None` when the
    /// pool is exhausted. O(1): swap-remove at a random index.
    fn pop_random(&mut self) -> Option<Ipv4Addr> {
        if self.free.is_empty() {
            return None;
        }
        let idx = self.rng.bounded(self.free.len());
        Some(self.free.swap_remove(idx))
    }

    /// Allocate an IPv4 for `conn`. Idempotent : if `conn` is already
    /// in the `used` map, returns the same address without consuming a
    /// fresh entry. Returns `None` when the pool is exhausted.
    pub fn allocate(&mut self, conn: ConnId) -> Option<Ipv4Addr> {
        if let Some(addr) = self.used.get(&conn).copied() {
            return Some(addr);
        }
        let addr = self.pop_random()?;
        self.used.insert(conn, addr);
        Some(addr)
    }

    /// Allocate an IPv4 keyed on the client's
    /// Ed25519 pubkey so reconnects from the same identity land on the
    /// same address (best-effort). Hint-less wire requests resolve here
    /// ([`SessionIntent::Legacy`]): the historical same-pubkey sharing
    /// semantics, byte-for-byte, so every deployed client is unaffected.
    ///
    /// Resolution order :
    /// 1. Already allocated for this `conn` ? Return the same address
    ///    (idempotent, mirrors [`Self::allocate`]).
    /// 2. Sticky binding for `pubkey` exists AND the bound address is
    ///    still in the `free` queue ? Remove it from `free`, install
    ///    in `used`, return it.
    /// 3. Otherwise fall back to a fresh FIFO pop, install the new
    ///    binding so the next reconnect attempts stickiness.
    ///
    /// Returns `None` only on full exhaustion (no sticky address
    /// available AND `free` queue is empty).
    pub fn allocate_for_pubkey(&mut self, conn: ConnId, pubkey: [u8; 32]) -> Option<Ipv4Addr> {
        self.allocate_for_pubkey_with_intent(conn, pubkey, SessionIntent::Legacy)
    }

    /// Connections currently holding `ip` (bonded siblings of one session
    /// after per-session allocation). Feeds the v6 allocator's
    /// [`SessionIntentV6::Join`] so a joining connection shares its
    /// siblings' interface ID, and lets tests observe sharing directly.
    #[must_use]
    pub fn conns_holding(&self, ip: Ipv4Addr) -> Vec<ConnId> {
        self.used
            .iter()
            .filter_map(|(&c, &a)| (a == ip).then_some(c))
            .collect()
    }

    /// True when `ip` is live-held by at least one connection whose
    /// authenticated owner is `pubkey`.
    fn held_by_pubkey(&self, ip: Ipv4Addr, pubkey: &[u8; 32]) -> bool {
        self.used
            .iter()
            .any(|(c, &a)| a == ip && self.owners.get(c) == Some(pubkey))
    }

    /// [`Self::allocate_for_pubkey`] with an explicit session-placement
    /// intent (see [`SessionIntent`]). This is where the two-live-sessions
    /// downlink collision is structurally closed: a [`SessionIntent::Fresh`]
    /// request never lands on an inner IP that another live session of the
    /// same key holds, so the downlink route key (the inner IP) identifies
    /// exactly one session.
    pub fn allocate_for_pubkey_with_intent(
        &mut self,
        conn: ConnId,
        pubkey: [u8; 32],
        intent: SessionIntent,
    ) -> Option<Ipv4Addr> {
        if let Some(addr) = self.used.get(&conn).copied() {
            return Some(addr);
        }
        if let SessionIntent::Join(target) = intent {
            // Owner-gated join: the hint names an address, only the
            // authenticated key of its current holders authorizes it
            // (bonded secondary, overlap or fast reconnect of that session).
            if self.held_by_pubkey(target, &pubkey) {
                self.used.insert(conn, target);
                self.owners.insert(conn, pubkey);
                return Some(target);
            }
            // Clean-close reconnect: the remembered address is free and
            // still sticky-bound to this wallet.
            if self.sticky.get(&pubkey) == Some(&target)
                && let Some(pos) = self.free.iter().position(|&a| a == target)
            {
                self.free.swap_remove(pos);
                self.used.insert(conn, target);
                self.owners.insert(conn, pubkey);
                return Some(target);
            }
            // Stale or foreign target: degrade to Fresh below. Never to
            // legacy sharing (a mis-aimed join must not co-house sessions)
            // and never to another key's address (no targeted squatting of
            // a departed client's address and its NAT-PMP window).
        }
        if let Some(preferred) = self.sticky.get(&pubkey).copied() {
            if let Some(pos) = self.free.iter().position(|&a| a == preferred) {
                self.free.swap_remove(pos);
                self.used.insert(conn, preferred);
                self.owners.insert(conn, pubkey);
                return Some(preferred);
            }
            // Same-pubkey SHARING, hint-less requests only: the sticky
            // address is still held by one or more connections of this same
            // identity. For a deployed client that cannot declare intent
            // this covers two cases that must both keep the SAME inner IP:
            //   * bonded multi-connection sessions (N connections of one
            //     identity dialed together, all needing the same IP so
            //     the exit can fan its TUN downlink across them);
            //   * a reconnect that raced the old session's teardown
            //     (force_reconnect redials within ~50 ms).
            // One identity = one tunnel IP, but that tunnel may ride
            // several connections: the address is SHARED (a new `used`
            // entry is added, the existing holders are left intact)
            // rather than taken over. The IP only returns to `free` once
            // the LAST holder releases (refcounted in `release`). Never
            // evict the prior holder here: each secondary would kick its
            // sibling out of `used`, and the first release would push the
            // still-shared IP back to `free` where it could be re-handed to
            // a different pubkey.
            // A Fresh (or degraded Join) intent skips this: an independent
            // session gets its own address so the downlink route key never
            // spans two live sessions.
            if matches!(intent, SessionIntent::Legacy) && self.held_by_pubkey(preferred, &pubkey) {
                self.used.insert(conn, preferred);
                self.owners.insert(conn, pubkey);
                return Some(preferred);
            }
        }
        let addr = self.pop_random()?;
        self.used.insert(conn, addr);
        self.owners.insert(conn, pubkey);
        // Self-cleaning: when recycling an
        // address that another pubkey previously held a sticky binding
        // for, drop the stale binding so the sticky map never holds
        // more than one owner per IP. The scan is O(sticky.len()) but
        // sticky.len() ≤ pool.capacity() by induction, so it runs in
        // a few hundred ops for a /24. The `stale_owner != pubkey`
        // guard is defensive - within this branch we never reach a
        // stale entry pointing at us (path 2 above would have caught
        // it), but the explicit check rules out any future refactor
        // accidentally evicting our own fresh insert.
        let stale_owner = self
            .sticky
            .iter()
            .find_map(|(k, &ip)| if ip == addr { Some(*k) } else { None });
        if let Some(stale) = stale_owner
            && stale != pubkey
        {
            self.sticky.remove(&stale);
        }
        // Binding-move guard: a session-fresh allocation forced by a LIVE
        // incumbent must not steal the wallet's sticky binding, else a later
        // hint-less reconnect of the incumbent would land on this new
        // session's address and recreate the collision.
        let incumbent_live = self
            .sticky
            .get(&pubkey)
            .is_some_and(|&ip| self.held_by_pubkey(ip, &pubkey));
        if !incumbent_live {
            self.sticky.insert(pubkey, addr);
        }
        Some(addr)
    }

    /// Release a previously-allocated address. Idempotent on unknown
    /// `conn`. Released IPs go back to the free set; the next allocate
    /// draws a random host, so a freshly-reconnected client does not
    /// deterministically land on the exact same address.
    pub fn release(&mut self, conn: ConnId) {
        if let Some(addr) = self.used.remove(&conn) {
            // Refcounted: only return the address to the free pool when
            // NO other connection still holds it. Bonded multi-connection
            // sessions (and a reconnect overlapping its predecessor)
            // share one inner IP across several `used` entries; pushing
            // it to `free` while a sibling still uses it would let the
            // allocator re-hand it to a DIFFERENT identity = collision.
            if !self.used.values().any(|&held| held == addr) {
                self.free.push(addr);
            }
        }
        self.owners.remove(&conn);
    }

    /// Number of host slots currently available for allocation. Useful
    /// for ops dashboards and exhaustion warnings.
    #[must_use]
    pub fn free_count(&self) -> usize {
        self.free.len()
    }

    /// Number of host slots currently held by live connections.
    #[must_use]
    pub fn used_count(&self) -> usize {
        self.used.len()
    }

    /// Number of sticky pubkey bindings currently
    /// recorded. Useful for an ops dashboard "how many recent clients
    /// would land on their previous IP if they reconnected now" and as
    /// a regression gate on the self-cleaning invariant (the value MUST
    /// stay ≤ subnet host capacity).
    #[must_use]
    pub fn sticky_count(&self) -> usize {
        self.sticky.len()
    }

    /// Network address (e.g. `10.66.0.0` for `10.66.0.0/24`).
    #[must_use]
    pub fn network(&self) -> Ipv4Addr {
        self.network
    }

    /// Subnet prefix length.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Gateway address (exit-side TUN host).
    #[must_use]
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }
}

/// Multi-hop IPv6 pool allocator over a `/64` ULA prefix (default
/// `fdcc:f:1::/64`, RFC 4193). Companion to [`IpAllocator`] for the
/// dual-stack multi-hop control `/v2` (cf. `docs/31-MULTIHOP-IPV6-V2-DESIGN.md`).
///
/// A `/64` carries 2^64 host slots, so - unlike the v4 allocator - the
/// free hosts are **not** enumerated into a queue. A fresh offset is a
/// RANDOM interface ID drawn from an OS-seeded PRNG (never a monotonic
/// counter: arrival order must not be a positional signal, same
/// anti-correlation rationale as the v4 allocator), avoiding the reserved
/// offsets `0` (network) and `1` (gateway) and any live one. A `recycled`
/// set reuses offsets returned by [`Self::release`] first to keep the
/// address space from wandering unboundedly.
///
/// The sticky-by-pubkey semantics mirror [`IpAllocator::allocate_for_pubkey`]
/// exactly: a reconnecting identity lands on its previous interface ID as
/// long as that offset is still recycled (not held by another live conn),
/// and the sticky map self-cleans so its size stays bounded by the count
/// of in-use offsets - never by the number of distinct pubkeys ever seen.
///
/// INV-4 (anti-correlation, cf. `docs/30`): the address is allocated by
/// the exit, **never** derived from the client key. Stickiness is keyed
/// on the pubkey only in volatile memory and resets at process restart,
/// so it leaves no on-disk per-client identifier.
#[derive(Debug)]
pub struct IpAllocatorV6 {
    /// `/64` network prefix; the low 64 bits are zeroed.
    network: Ipv6Addr,
    /// Gateway address (network offset `1`), owned by the exit-side TUN.
    gateway: Ipv6Addr,
    rng: SplitMix64,
    /// Offsets returned by `release`, reused before drawing a fresh one.
    recycled: Vec<u64>,
    used: HashMap<ConnId, u64>,
    sticky: HashMap<[u8; 32], u64>,
    /// Pubkey behind each live allocation; same-pubkey takeover guard,
    /// mirrors [`IpAllocator::owners`].
    owners: HashMap<ConnId, [u8; 32]>,
}

impl IpAllocatorV6 {
    /// Build a `/64` pool from `network_ipv6`. The low 64 bits of
    /// `network_ipv6` are masked off, so passing any address inside the
    /// prefix (e.g. the gateway) normalises to the canonical network.
    /// The gateway is fixed at offset `1` (`<prefix>::1`).
    #[must_use]
    pub fn new(network_ipv6: Ipv6Addr) -> Self {
        Self::with_seed(network_ipv6, os_seed())
    }

    /// Build a `/64` pool with an explicit PRNG seed. Tests use this to
    /// drive random offset selection deterministically; production goes
    /// through [`Self::new`], which seeds from OS entropy.
    #[must_use]
    pub fn with_seed(network_ipv6: Ipv6Addr, seed: u64) -> Self {
        // Mask the low 64 bits (interface ID) to the canonical network.
        let net_u128 = u128::from(network_ipv6) & (u128::MAX << 64);
        let network = Ipv6Addr::from(net_u128);
        let gateway = Ipv6Addr::from(net_u128 | 1);
        Self {
            network,
            gateway,
            rng: SplitMix64::new(seed),
            recycled: Vec::new(),
            used: HashMap::new(),
            sticky: HashMap::new(),
            owners: HashMap::new(),
        }
    }

    /// Compose the full address for an interface-ID `offset` inside the
    /// pool prefix.
    fn addr_of(&self, offset: u64) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.network) | u128::from(offset))
    }

    /// Mint or recycle an interface-ID offset. Prefers a recycled offset
    /// (drawn at random) to bound wandering, else draws a fresh RANDOM
    /// offset avoiding the reserved low ids (`0`, `1`) and any live one.
    /// Returns `None` only after an astronomically improbable run of
    /// collisions - a `/64` is never exhausted in any real deployment.
    fn pop_offset(&mut self) -> Option<u64> {
        if !self.recycled.is_empty() {
            let idx = self.rng.bounded(self.recycled.len());
            return Some(self.recycled.swap_remove(idx));
        }
        for _ in 0..64 {
            let offset = self.rng.next_u64();
            if offset < 2 {
                continue;
            }
            if self.used.values().any(|&o| o == offset) {
                continue;
            }
            return Some(offset);
        }
        None
    }

    /// Allocate an IPv6 for `conn`. Idempotent on a known `ConnId`
    /// (returns the same address without consuming a fresh offset).
    pub fn allocate(&mut self, conn: ConnId) -> Option<Ipv6Addr> {
        if let Some(&offset) = self.used.get(&conn) {
            return Some(self.addr_of(offset));
        }
        let offset = self.pop_offset()?;
        self.used.insert(conn, offset);
        Some(self.addr_of(offset))
    }

    /// Allocate an IPv6 keyed on the client's Ed25519 pubkey so
    /// reconnects from the same identity land on the same interface ID
    /// (best-effort). Mirrors [`IpAllocator::allocate_for_pubkey`]:
    ///
    /// 1. Already allocated for this `conn` ? Return the same address.
    /// 2. Sticky offset for `pubkey` still recycled (not live) ? Reuse it.
    /// 3. Otherwise mint a fresh offset, evict any stale sticky owner of
    ///    that recycled offset, and record the new binding.
    pub fn allocate_for_pubkey(&mut self, conn: ConnId, pubkey: [u8; 32]) -> Option<Ipv6Addr> {
        self.allocate_for_pubkey_with_intent(conn, pubkey, SessionIntentV6::Legacy)
    }

    /// [`Self::allocate_for_pubkey`] with an explicit session-placement
    /// intent, mirror of [`IpAllocator::allocate_for_pubkey_with_intent`]
    /// (see [`SessionIntentV6`] for how the caller projects the v4
    /// decision onto the v6 pool).
    pub fn allocate_for_pubkey_with_intent(
        &mut self,
        conn: ConnId,
        pubkey: [u8; 32],
        intent: SessionIntentV6<'_>,
    ) -> Option<Ipv6Addr> {
        if let Some(&offset) = self.used.get(&conn) {
            return Some(self.addr_of(offset));
        }
        if let SessionIntentV6::Join(siblings) = intent {
            // Owner-gated join, mirror of the v4 allocator: share the
            // interface ID a same-key sibling connection holds. A sibling
            // owned by another key is never joined; no usable sibling
            // degrades to Fresh below.
            let shared = siblings.iter().find_map(|c| {
                (self.owners.get(c) == Some(&pubkey))
                    .then(|| self.used.get(c).copied())
                    .flatten()
            });
            if let Some(offset) = shared {
                self.used.insert(conn, offset);
                self.owners.insert(conn, pubkey);
                return Some(self.addr_of(offset));
            }
        }
        if let Some(&preferred) = self.sticky.get(&pubkey) {
            if let Some(pos) = self.recycled.iter().position(|&o| o == preferred) {
                self.recycled.swap_remove(pos);
                self.used.insert(conn, preferred);
                self.owners.insert(conn, pubkey);
                return Some(self.addr_of(preferred));
            }
            // Same-pubkey SHARING, hint-less requests only, mirror of the
            // v4 allocator: bonded multi-connection sessions (and a
            // reconnect overlapping its predecessor) of one identity share
            // a single interface ID across several `used` entries. The
            // offset only returns to the recycle queue once the LAST holder
            // releases. Never evict the prior holder here, it breaks bonding
            // exactly as in the v4 allocator. A Fresh (or degraded Join)
            // intent skips this so an independent session gets its own
            // interface ID.
            if matches!(intent, SessionIntentV6::Legacy) && self.held_by_pubkey(preferred, &pubkey)
            {
                self.used.insert(conn, preferred);
                self.owners.insert(conn, pubkey);
                return Some(self.addr_of(preferred));
            }
        }
        let offset = self.pop_offset()?;
        self.used.insert(conn, offset);
        self.owners.insert(conn, pubkey);
        // Self-cleaning (mirror of the v4 allocator): if the minted
        // offset was sticky-bound to a *different* pubkey, drop that
        // stale binding so `sticky.len()` never exceeds the count of
        // distinct in-use offsets. A client rotating its signing key on
        // every reconnect therefore cannot inflate the exit's RSS.
        let stale_owner = self
            .sticky
            .iter()
            .find_map(|(k, &o)| if o == offset { Some(*k) } else { None });
        if let Some(stale) = stale_owner
            && stale != pubkey
        {
            self.sticky.remove(&stale);
        }
        // Binding-move guard, mirror of the v4 allocator: never steal the
        // sticky binding from a live incumbent session.
        let incumbent_live = self
            .sticky
            .get(&pubkey)
            .is_some_and(|&o| self.held_by_pubkey(o, &pubkey));
        if !incumbent_live {
            self.sticky.insert(pubkey, offset);
        }
        Some(self.addr_of(offset))
    }

    /// True when `offset` is live-held by at least one connection whose
    /// authenticated owner is `pubkey`.
    fn held_by_pubkey(&self, offset: u64, pubkey: &[u8; 32]) -> bool {
        self.used
            .iter()
            .any(|(c, &o)| o == offset && self.owners.get(c) == Some(pubkey))
    }

    /// Release a previously-allocated address. Idempotent on unknown
    /// `conn`. The freed interface ID returns to the recycle set (a fresh
    /// allocate draws from it at random, so a reconnect does not
    /// deterministically reuse it), and the sticky binding is
    /// intentionally kept alive for a future reconnect of the same pubkey.
    pub fn release(&mut self, conn: ConnId) {
        if let Some(offset) = self.used.remove(&conn) {
            // Refcounted (mirror of the v4 allocator): only recycle the
            // interface ID once no other connection still holds it, so a
            // bonded sibling sharing the offset never has it recycled out
            // from under it.
            if !self.used.values().any(|&held| held == offset) {
                self.recycled.push(offset);
            }
        }
        self.owners.remove(&conn);
    }

    /// Number of interface IDs currently held by live connections.
    #[must_use]
    pub fn used_count(&self) -> usize {
        self.used.len()
    }

    /// Number of released-but-not-reissued interface IDs queued for
    /// reuse. Unlike the v4 `free_count`, this is *not* the pool
    /// capacity (a `/64` is effectively unbounded) - only the recycle
    /// backlog.
    #[must_use]
    pub fn recycled_count(&self) -> usize {
        self.recycled.len()
    }

    /// Number of sticky pubkey bindings currently recorded. Regression
    /// gate on the self-cleaning invariant (MUST stay ≤ the count of
    /// distinct in-use interface IDs).
    #[must_use]
    pub fn sticky_count(&self) -> usize {
        self.sticky.len()
    }

    /// `/64` network address (low 64 bits zeroed).
    #[must_use]
    pub fn network(&self) -> Ipv6Addr {
        self.network
    }

    /// Gateway address (exit-side TUN host, `<prefix>::1`).
    #[must_use]
    pub fn gateway(&self) -> Ipv6Addr {
        self.gateway
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 0);
    const GW: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

    #[test]
    fn allocate_returns_distinct_addresses() {
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let a = pool.allocate(1).expect("first allocate");
        let b = pool.allocate(2).expect("second allocate");
        assert_ne!(a, b);
        assert_ne!(a, GW);
        assert_ne!(b, GW);
    }

    #[test]
    fn fresh_allocation_is_not_fifo_lowest_host_sequence() {
        // Anti-correlation (Mullvad exit-fingerprint lesson): a fresh,
        // non-sticky allocation must NOT be a deterministic function of
        // arrival order. The old FIFO handed out the lowest free host
        // first (.2, .3, .4, ...), a weak but real positional signal.
        // Selection is now an OS-seeded random draw, so the first N
        // addresses are not the ascending prefix of the pool.
        let mut pool = IpAllocator::with_seed(NET, 24, GW, 0x1234_5678).expect("/24 pool builds");
        let got: Vec<Ipv4Addr> = (0..6)
            .map(|c| pool.allocate(c).expect("allocate"))
            .collect();
        let ascending: Vec<Ipv4Addr> = (2..8).map(|h| Ipv4Addr::new(10, 66, 0, h)).collect();
        assert_ne!(
            got, ascending,
            "fresh allocations must not be the FIFO ascending lowest-host sequence"
        );
        // Still a valid permutation of pool hosts: all distinct, none the gateway.
        let mut sorted = got.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), got.len(), "addresses must be distinct");
        assert!(!got.contains(&GW), "gateway must never be handed out");
    }

    #[test]
    fn selection_never_consults_the_client_identifier() {
        // Guardrail for the latent egress-pool trap: the address a session
        // lands on must be independent of any stable client identifier. Two
        // identically-seeded pools handed two WILDLY different pubkeys on a
        // first (non-sticky) allocate return the SAME address, proving the
        // draw is the RNG state alone and never a function of the pubkey.
        let mut a = IpAllocator::with_seed(NET, 24, GW, 0xABCD_EF01).expect("pool a");
        let mut b = IpAllocator::with_seed(NET, 24, GW, 0xABCD_EF01).expect("pool b");
        let ip_a = a.allocate_for_pubkey(1, [0x00; 32]).expect("alloc a");
        let ip_b = b.allocate_for_pubkey(1, [0xFF; 32]).expect("alloc b");
        assert_eq!(
            ip_a, ip_b,
            "the allocated address must depend on RNG state only, never on the pubkey"
        );
    }

    #[test]
    fn draining_the_pool_yields_every_host_exactly_once() {
        // The random-pick refactor must remain a faithful allocator: a full
        // drain still covers every usable host exactly once (no gaps, no
        // duplicates, gateway excluded), so randomness never loses capacity.
        let mut pool = IpAllocator::with_seed(NET, 24, GW, 0x9999).expect("/24 pool builds");
        let capacity = pool.free_count();
        let mut seen = std::collections::HashSet::new();
        for c in 0..capacity as u64 {
            let ip = pool.allocate(c).expect("allocate within capacity");
            assert!(seen.insert(ip), "every host handed out at most once: {ip}");
            assert_ne!(ip, GW);
        }
        assert!(
            pool.allocate(9999).is_none(),
            "pool exhausted after full drain"
        );
        assert_eq!(seen.len(), capacity, "the drain covered the whole pool");
    }

    #[test]
    fn allocate_skips_gateway() {
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        for _ in 0..pool.free_count() {
            let addr = pool.allocate(rand_dummy_id()).expect("allocate");
            assert_ne!(
                addr, GW,
                "allocator must never hand out the gateway address"
            );
        }
    }

    #[test]
    fn idempotent_allocate_for_same_conn() {
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let first = pool.allocate(7).expect("first allocate");
        let second = pool.allocate(7).expect("second allocate same conn");
        assert_eq!(
            first, second,
            "allocate is idempotent on a known ConnId - same address"
        );
        assert_eq!(pool.used_count(), 1, "same conn must not double-consume");
    }

    #[test]
    fn release_returns_address_to_pool() {
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let initial_free = pool.free_count();
        let _addr = pool.allocate(1).expect("allocate");
        assert_eq!(pool.free_count(), initial_free - 1);
        pool.release(1);
        assert_eq!(
            pool.free_count(),
            initial_free,
            "release must return the address"
        );
        assert_eq!(pool.used_count(), 0);
    }

    #[test]
    fn release_unknown_conn_is_noop() {
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let initial_free = pool.free_count();
        pool.release(999); // never allocated
        assert_eq!(pool.free_count(), initial_free);
    }

    #[test]
    fn exhaustion_returns_none() {
        // /29 = 8 addresses, network + broadcast reserved, gateway
        // reserved, so 5 usable hosts.
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let mut pool = IpAllocator::new(net, 29, gw).expect("/29 pool builds");
        assert_eq!(pool.free_count(), 5);
        for i in 0..5 {
            assert!(pool.allocate(i).is_some(), "allocate #{i} succeeds");
        }
        assert!(pool.allocate(99).is_none(), "exhausted pool returns None");
        assert_eq!(pool.free_count(), 0);
    }

    #[test]
    fn release_then_reallocate_serves_fresh_conn() {
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let mut pool = IpAllocator::new(net, 29, gw).expect("/29 pool builds");
        for i in 0..5 {
            pool.allocate(i).expect("initial allocate");
        }
        assert!(pool.allocate(99).is_none(), "exhausted");
        pool.release(2);
        let revived = pool.allocate(99).expect("freed slot now serves new conn");
        // FIFO: the released addr goes to the tail, so the new allocate
        // pops from the head. Whatever address the new conn lands on,
        // it must not collide with any still-held conn.
        for held in 0..5 {
            if held == 2 {
                continue;
            }
            let prev = pool.allocate(held).expect("re-query idempotent");
            assert_ne!(prev, revived, "fresh allocation must not alias a held one");
        }
    }

    #[test]
    fn gateway_outside_subnet_rejected() {
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw_outside = Ipv4Addr::new(192, 168, 1, 1);
        let err = IpAllocator::new(net, 24, gw_outside).expect_err("must reject");
        assert!(matches!(err, IpPoolError::GatewayOutsideSubnet { .. }));
    }

    #[test]
    fn invalid_prefix_rejected() {
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let err = IpAllocator::new(net, 0, gw).expect_err("must reject /0");
        assert!(matches!(err, IpPoolError::InvalidPrefix { prefix_len: 0 }));
        let err = IpAllocator::new(net, 33, gw).expect_err("must reject /33");
        assert!(matches!(err, IpPoolError::InvalidPrefix { prefix_len: 33 }));
    }

    #[test]
    fn slash_30_has_one_usable_host_after_gateway() {
        // /30 = 4 addresses : network + broadcast reserved + gateway =
        // exactly 1 host slot.
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let mut pool = IpAllocator::new(net, 30, gw).expect("/30 pool builds");
        assert_eq!(pool.free_count(), 1);
        let addr = pool.allocate(1).expect("single allocate");
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 2));
        assert!(pool.allocate(2).is_none(), "second allocate exhausts");
    }

    #[test]
    fn network_normalised_from_host_bits() {
        // Caller passes a host bit set ; constructor should normalise
        // to the canonical network address (low bits zeroed).
        let inside = Ipv4Addr::new(10, 0, 0, 42);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let pool = IpAllocator::new(inside, 24, gw).expect("constructor tolerates host bits");
        assert_eq!(pool.network(), Ipv4Addr::new(10, 0, 0, 0));
    }

    #[test]
    fn allocate_for_pubkey_first_call_installs_sticky_binding() {
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x11u8; 32];
        let first = pool
            .allocate_for_pubkey(1, pubkey)
            .expect("first sticky allocate");
        assert_eq!(pool.used_count(), 1);
        // Same pubkey, fresh conn after release - must still resolve
        // to the same address as long as it remains in the pool.
        pool.release(1);
        assert_eq!(pool.used_count(), 0);
        let second = pool
            .allocate_for_pubkey(2, pubkey)
            .expect("sticky allocate post-release");
        assert_eq!(
            first, second,
            "pubkey-keyed allocator must hand out the same address across reconnects"
        );
    }

    #[test]
    fn allocate_for_pubkey_distinct_pubkeys_get_distinct_addresses() {
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let a = pool
            .allocate_for_pubkey(1, [0x11; 32])
            .expect("pubkey A allocate");
        let b = pool
            .allocate_for_pubkey(2, [0x22; 32])
            .expect("pubkey B allocate");
        assert_ne!(
            a, b,
            "two distinct pubkeys must end up on distinct addresses"
        );
        assert_eq!(pool.used_count(), 2);
    }

    #[test]
    fn allocate_for_pubkey_falls_back_when_sticky_ip_is_taken() {
        // /30 = exactly one usable host. Allocate it for pubkey A,
        // release it back, allocate again under pubkey B (which grabs
        // the sole free address), then reconnect with pubkey A : the
        // sticky preference points at an address that pubkey B now
        // holds, so the allocator must report exhaustion (None) rather
        // than aliasing.
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let mut pool = IpAllocator::new(net, 30, gw).expect("/30 pool builds");
        let pubkey_a = [0xAA; 32];
        let pubkey_b = [0xBB; 32];
        let a_first = pool
            .allocate_for_pubkey(1, pubkey_a)
            .expect("pubkey A first allocate");
        pool.release(1);
        let b_first = pool
            .allocate_for_pubkey(2, pubkey_b)
            .expect("pubkey B grabs the freed slot");
        assert_eq!(
            a_first, b_first,
            "after release pubkey B may legitimately reuse the same address"
        );
        // pubkey A reconnects - sticky says the address it had, but
        // pubkey B holds it now. No other slot is free, so None.
        let a_reconnect = pool.allocate_for_pubkey(3, pubkey_a);
        assert!(
            a_reconnect.is_none(),
            "pubkey A must NOT alias an address currently held by another conn"
        );
    }

    #[test]
    fn allocate_for_pubkey_same_pubkey_shares_addr_with_previous_conn() {
        // Two connections of the SAME identity overlap (migration-watchdog
        // force_reconnect racing teardown, OR bonded multi-connection
        // sessions): they SHARE one inner IP. The address only returns to
        // the free pool once the LAST holder releases - releasing one
        // while the other still holds it must NOT free it (else it could
        // be re-handed to a different identity = collision).
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0xAA; 32];
        let first = pool.allocate_for_pubkey(1, pubkey).expect("first allocate");
        // No release: conn 1 is still alive when conn 2 dials.
        let second = pool
            .allocate_for_pubkey(2, pubkey)
            .expect("second allocate");
        assert_eq!(first, second, "same pubkey must share one address");
        assert_eq!(pool.used_count(), 2, "both conns hold the shared address");
        let free_before = pool.free_count();
        pool.release(1);
        assert_eq!(
            pool.free_count(),
            free_before,
            "releasing one holder must NOT free the still-shared address"
        );
        assert_eq!(pool.used_count(), 1, "the other holder keeps the address");
        pool.release(2);
        assert_eq!(
            pool.free_count(),
            free_before + 1,
            "the address returns to free only after the last holder releases"
        );
    }

    #[test]
    fn allocate_for_pubkey_bonded_fan_shares_one_ip_across_n_conns() {
        // Bonded session: 8 connections of one identity dialed together
        // must all land on the SAME inner IP and the pool must consume
        // exactly one host slot.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x5A; 32];
        let free0 = pool.free_count();
        let primary = pool.allocate_for_pubkey(1, pubkey).expect("primary");
        for conn in 2..=8 {
            let ip = pool
                .allocate_for_pubkey(conn, pubkey)
                .expect("bonded secondary");
            assert_eq!(ip, primary, "every bonded conn shares the primary IP");
        }
        assert_eq!(pool.used_count(), 8, "8 holders of one IP");
        assert_eq!(pool.free_count(), free0 - 1, "exactly one slot consumed");
        // Tear the bundle down; the IP comes back exactly once.
        for conn in 1..=8 {
            pool.release(conn);
        }
        assert_eq!(
            pool.free_count(),
            free0,
            "slot returns once, no double-free"
        );
        assert_eq!(pool.used_count(), 0);
    }

    #[test]
    fn allocate_for_pubkey_takeover_never_steals_from_another_pubkey() {
        // /30 = one usable host. Pubkey B holds it (live). A's stale
        // sticky binding (if any) must not let A steal B's address.
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let mut pool = IpAllocator::new(net, 30, gw).expect("/30 pool builds");
        let addr = pool
            .allocate_for_pubkey(1, [0xBB; 32])
            .expect("B allocates");
        let res = pool.allocate_for_pubkey(2, [0xAA; 32]);
        assert!(res.is_none(), "A must not steal {addr} from live pubkey B");
        assert_eq!(pool.used_count(), 1);
    }

    #[test]
    fn v6_allocate_for_pubkey_same_pubkey_takes_over_offset_held_by_previous_conn() {
        let mut pool = IpAllocatorV6::new("fdcc:f:1::".parse().unwrap());
        let pubkey = [0xCC; 32];
        let first = pool.allocate_for_pubkey(1, pubkey).expect("first allocate");
        let second = pool
            .allocate_for_pubkey(2, pubkey)
            .expect("second allocate");
        assert_eq!(first, second, "same pubkey must share its v6");
        assert_eq!(pool.used_count(), 2, "both conns hold the shared v6");
        pool.release(1);
        assert_eq!(pool.used_count(), 1, "the other holder keeps the v6");
        // The shared offset must NOT be recycled while conn 2 holds it:
        // another pubkey must still get a different v6.
        let third = pool.allocate_for_pubkey(3, [0xDD; 32]).expect("fresh conn");
        assert_ne!(third, first, "another pubkey must get a different v6");
    }

    #[test]
    fn allocate_for_pubkey_idempotent_on_same_conn() {
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x33; 32];
        let first = pool.allocate_for_pubkey(7, pubkey).expect("first allocate");
        let second = pool
            .allocate_for_pubkey(7, pubkey)
            .expect("second allocate same conn");
        assert_eq!(first, second);
        assert_eq!(pool.used_count(), 1);
    }

    #[test]
    fn release_keeps_sticky_binding_alive_for_future_reconnect() {
        // The release path returns the address to the FIFO tail but
        // does NOT clear the sticky map - that is precisely the v1.3
        // contract : sticky bindings persist across release/realloc
        // cycles for the lifetime of the process.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x55; 32];
        let allocated = pool
            .allocate_for_pubkey(1, pubkey)
            .expect("initial allocate");
        let initial_free = pool.free_count();
        pool.release(1);
        assert_eq!(
            pool.free_count(),
            initial_free + 1,
            "address returned to free"
        );
        // Burn through all other addresses so the FIFO order pushes
        // our previously-bound IP to a deep position. The sticky
        // lookup must still find it.
        let mut burned = Vec::new();
        for i in 100u64..200 {
            if let Some(ip) = pool.allocate(i) {
                if ip != allocated {
                    burned.push(i);
                } else {
                    // We hit the sticky address via unkeyed allocate
                    // (which can happen on a /24 with many free
                    // slots). Release it back so the sticky lookup
                    // below has something to find.
                    pool.release(i);
                    break;
                }
            } else {
                break;
            }
        }
        let revived = pool
            .allocate_for_pubkey(999, pubkey)
            .expect("sticky binding still resolves");
        assert_eq!(
            revived, allocated,
            "sticky binding survives an unrelated burst of unkeyed allocate/release"
        );
        // Cleanup so the test does not leak state across the
        // assertions above.
        for i in burned {
            pool.release(i);
        }
    }

    #[test]
    fn sticky_map_self_cleans_when_addresses_are_recycled_to_other_pubkeys() {
        // /29 = 5 usable host slots. Allocate for 5 distinct pubkeys,
        // release every conn, then allocate for 5 NEW distinct pubkeys.
        // Each fresh allocate must evict the stale binding before
        // installing the new one, so sticky.len() stays bounded by
        // pool capacity (5) instead of growing to 10.
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let mut pool = IpAllocator::new(net, 29, gw).expect("/29 pool builds");
        let capacity = pool.free_count();
        assert_eq!(capacity, 5);

        // First wave : 5 distinct pubkeys take all 5 slots.
        for i in 0u8..5 {
            let mut pubkey = [0u8; 32];
            pubkey[0] = i;
            pool.allocate_for_pubkey(u64::from(i), pubkey)
                .expect("first-wave allocate");
        }
        assert_eq!(pool.sticky_count(), 5);
        assert_eq!(pool.used_count(), 5);
        assert_eq!(pool.free_count(), 0);

        // Release all 5.
        for i in 0u8..5 {
            pool.release(u64::from(i));
        }
        assert_eq!(pool.used_count(), 0);
        assert_eq!(pool.free_count(), 5);
        // Sticky map still has all 5 bindings (no release in path).
        assert_eq!(pool.sticky_count(), 5);

        // Second wave : 5 DIFFERENT pubkeys take the same 5 slots.
        // Each fresh allocate must evict the stale binding for the
        // recycled address.
        for i in 0u8..5 {
            let mut pubkey = [0u8; 32];
            pubkey[0] = 100 + i;
            pool.allocate_for_pubkey(100u64 + u64::from(i), pubkey)
                .expect("second-wave allocate");
        }

        assert_eq!(
            pool.sticky_count(),
            capacity,
            "self-cleaning invariant : sticky.len() must stay ≤ pool capacity (5), not grow to 10"
        );
    }

    #[test]
    fn sticky_eviction_does_not_remove_same_pubkey_entry() {
        // Defensive : if a fresh allocate happens to recycle an
        // address that was sticky-bound to the SAME pubkey (edge case
        // where path 2 missed for some reason - currently
        // unreachable but the guard rules out a future refactor
        // wiping the binding by mistake), we MUST keep the binding
        // after re-inserting.
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 0, 0, 1);
        let mut pool = IpAllocator::new(net, 30, gw).expect("/30 pool builds");
        let pubkey = [0x77u8; 32];
        // Inject a sticky entry pointing at the only usable address
        // WITHOUT going through the allocate path (simulates a
        // post-refactor invariant violation).
        let only_addr = Ipv4Addr::new(10, 0, 0, 2);
        pool.sticky.insert(pubkey, only_addr);
        // Now allocate for the same pubkey - path 2 catches the
        // sticky-in-free case, but as a paranoid follow-up we re-run
        // a release + allocate cycle to ensure the binding survives.
        let got = pool
            .allocate_for_pubkey(1, pubkey)
            .expect("path 2 returns the sticky address");
        assert_eq!(got, only_addr);
        assert_eq!(pool.sticky_count(), 1);
        pool.release(1);
        let got2 = pool
            .allocate_for_pubkey(2, pubkey)
            .expect("second cycle path 2 returns the sticky address");
        assert_eq!(got2, only_addr);
        assert_eq!(
            pool.sticky_count(),
            1,
            "same-pubkey reconnect must not evict its own binding"
        );
    }

    /// Just spits out a fresh id each call. The local rand_dummy_id
    /// avoids pulling in the rand crate for a single test.
    fn rand_dummy_id() -> ConnId {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(1);
        N.fetch_add(1, Ordering::Relaxed)
    }

    // ---- IPv6 allocator (multi-hop /v2) ----

    const NET6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 0);
    const GW6: Ipv6Addr = Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0, 0, 0, 1);

    #[test]
    fn v6_new_normalises_network_and_pins_gateway_at_offset_one() {
        // Pass an address with host bits set - the constructor must mask
        // the low 64 bits to the canonical /64 network and put the
        // gateway at <prefix>::1.
        let inside = Ipv6Addr::new(0xfdcc, 0x000f, 0x0001, 0, 0xdead, 0xbeef, 0, 0x42);
        let pool = IpAllocatorV6::new(inside);
        assert_eq!(pool.network(), NET6, "low 64 bits must be zeroed");
        assert_eq!(pool.gateway(), GW6, "gateway is <prefix>::1");
    }

    #[test]
    fn v6_allocate_returns_distinct_addresses_skipping_reserved_offsets() {
        let mut pool = IpAllocatorV6::new(NET6);
        let a = pool.allocate(1).expect("first v6 allocate");
        let b = pool.allocate(2).expect("second v6 allocate");
        assert_ne!(a, b, "distinct connections get distinct addresses");
        // Offsets are drawn at random (anti-correlation), but 0 (network)
        // and 1 (gateway) stay reserved and are never handed out.
        for got in [a, b] {
            assert_ne!(got, pool.network(), "network address is reserved");
            assert_ne!(got, pool.gateway(), "gateway address is reserved");
            assert!(
                u128::from(got) & (u128::MAX >> 64) >= 2,
                "interface id must skip the reserved low offsets"
            );
        }
    }

    #[test]
    fn v6_idempotent_allocate_for_same_conn() {
        let mut pool = IpAllocatorV6::new(NET6);
        let first = pool.allocate(7).expect("first");
        let second = pool.allocate(7).expect("same conn");
        assert_eq!(first, second, "allocate is idempotent on a known ConnId");
        assert_eq!(pool.used_count(), 1, "same conn must not double-consume");
    }

    #[test]
    fn v6_release_recycles_offset_before_advancing_counter() {
        let mut pool = IpAllocatorV6::new(NET6);
        let a = pool.allocate(1).expect("allocate"); // offset 2
        pool.allocate(2).expect("allocate"); // offset 3
        assert_eq!(pool.recycled_count(), 0);
        pool.release(1);
        assert_eq!(pool.recycled_count(), 1, "freed offset queued for reuse");
        assert_eq!(pool.used_count(), 1);
        // A fresh conn must reuse the recycled offset (2), not mint a new
        // one (4), keeping the address space dense.
        let revived = pool.allocate(3).expect("reuse recycled");
        assert_eq!(
            revived, a,
            "recycled offset reissued before counter advance"
        );
        assert_eq!(pool.recycled_count(), 0);
    }

    #[test]
    fn v6_release_unknown_conn_is_noop() {
        let mut pool = IpAllocatorV6::new(NET6);
        pool.release(999);
        assert_eq!(pool.recycled_count(), 0);
        assert_eq!(pool.used_count(), 0);
    }

    #[test]
    fn v6_allocate_for_pubkey_is_sticky_across_reconnect() {
        let mut pool = IpAllocatorV6::new(NET6);
        let pubkey = [0x11u8; 32];
        let first = pool
            .allocate_for_pubkey(1, pubkey)
            .expect("first sticky allocate");
        pool.release(1);
        let second = pool
            .allocate_for_pubkey(2, pubkey)
            .expect("sticky allocate post-release");
        assert_eq!(
            first, second,
            "same pubkey must land on the same interface ID across reconnects"
        );
    }

    #[test]
    fn v6_allocate_for_pubkey_distinct_pubkeys_get_distinct_addresses() {
        let mut pool = IpAllocatorV6::new(NET6);
        let a = pool.allocate_for_pubkey(1, [0x11; 32]).expect("pubkey A");
        let b = pool.allocate_for_pubkey(2, [0x22; 32]).expect("pubkey B");
        assert_ne!(a, b, "distinct pubkeys get distinct addresses");
        assert_eq!(pool.used_count(), 2);
    }

    #[test]
    fn v6_sticky_falls_back_when_offset_is_held_by_another_conn() {
        // pubkey A takes offset 2, releases it; pubkey B then grabs the
        // recycled offset 2; pubkey A reconnects -> its sticky offset is
        // live under B, so A must get a FRESH offset (no aliasing).
        let mut pool = IpAllocatorV6::new(NET6);
        let pubkey_a = [0xAA; 32];
        let pubkey_b = [0xBB; 32];
        let a_first = pool.allocate_for_pubkey(1, pubkey_a).expect("A first");
        pool.release(1);
        let b_first = pool.allocate_for_pubkey(2, pubkey_b).expect("B reuses");
        assert_eq!(
            a_first, b_first,
            "B legitimately reuses the recycled offset"
        );
        let a_reconnect = pool
            .allocate_for_pubkey(3, pubkey_a)
            .expect("A gets a fresh offset, never None on a /64");
        assert_ne!(
            a_reconnect, a_first,
            "A must NOT alias an interface ID currently held by B"
        );
    }

    #[test]
    fn v6_sticky_map_self_cleans_when_offsets_are_recycled_to_other_pubkeys() {
        // Wave 1: 4 pubkeys take offsets 2..=5. Release all. Wave 2: 4
        // DIFFERENT pubkeys reuse the same recycled offsets. The sticky
        // map must evict the stale owners, staying bounded by the in-use
        // offset count (4) instead of growing to 8.
        let mut pool = IpAllocatorV6::new(NET6);
        for i in 0u8..4 {
            let mut pk = [0u8; 32];
            pk[0] = i;
            pool.allocate_for_pubkey(u64::from(i), pk)
                .expect("wave-1 allocate");
        }
        assert_eq!(pool.sticky_count(), 4);
        for i in 0u8..4 {
            pool.release(u64::from(i));
        }
        assert_eq!(pool.recycled_count(), 4);
        assert_eq!(pool.sticky_count(), 4, "release keeps sticky bindings");

        for i in 0u8..4 {
            let mut pk = [0u8; 32];
            pk[0] = 100 + i;
            pool.allocate_for_pubkey(100u64 + u64::from(i), pk)
                .expect("wave-2 allocate");
        }
        assert_eq!(
            pool.sticky_count(),
            4,
            "self-cleaning: sticky.len() bounded by in-use offsets (4), not grown to 8"
        );
    }

    // ---- Per-session placement intents (two-live-sessions collision) ----

    #[test]
    fn session_intent_derives_from_the_wire_hint() {
        assert_eq!(SessionIntent::from_prefer_ipv4(None), SessionIntent::Legacy);
        assert_eq!(
            SessionIntent::from_prefer_ipv4(Some([0, 0, 0, 0])),
            SessionIntent::Fresh
        );
        assert_eq!(
            SessionIntent::from_prefer_ipv4(Some([10, 66, 0, 7])),
            SessionIntent::Join(Ipv4Addr::new(10, 66, 0, 7))
        );
    }

    #[test]
    fn fresh_intent_never_shares_an_ip_a_live_session_of_the_same_key_holds() {
        // THE two-live-sessions hole: an independent second session of one
        // wallet declared Fresh must get its OWN inner IP, never be
        // co-housed on the incumbent's (downlink routes key on the IP).
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x5A; 32];
        let incumbent = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        let second = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntent::Fresh)
            .expect("session 2");
        assert_ne!(
            second, incumbent,
            "a Fresh session must never share the incumbent's live IP"
        );
        assert_eq!(pool.used_count(), 2);
    }

    #[test]
    fn fresh_intent_grants_the_sticky_ip_when_it_is_free() {
        // Single-session sticky UX unchanged: no live holder, the wallet's
        // previous address is served.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x5A; 32];
        let first = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        pool.release(1);
        let reconnect = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntent::Fresh)
            .expect("reconnect");
        assert_eq!(reconnect, first, "sticky reconnect must keep its address");
    }

    #[test]
    fn fresh_intent_leaves_the_sticky_binding_with_the_incumbent_session() {
        // If the session-fresh allocation moved the wallet's sticky binding,
        // a later hint-less reconnect would land ON TOP of the new session
        // and recreate the collision. The binding must stay with the
        // incumbent's address.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x5A; 32];
        let incumbent = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        let second = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntent::Fresh)
            .expect("session 2");
        pool.release(1);
        let legacy_reconnect = pool.allocate_for_pubkey(3, pubkey).expect("reconnect");
        assert_eq!(
            legacy_reconnect, incumbent,
            "the sticky binding must stay with the incumbent session's address"
        );
        assert_ne!(legacy_reconnect, second);
    }

    #[test]
    fn join_intent_shares_the_target_ip_held_by_the_same_key() {
        // Bonded secondary / overlap reconnect: joining the session that
        // holds the target address.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x5A; 32];
        let primary = pool.allocate_for_pubkey(1, pubkey).expect("primary");
        let secondary = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntent::Join(primary))
            .expect("secondary");
        assert_eq!(secondary, primary, "a bond join shares the session IP");
        assert_eq!(pool.conns_holding(primary).len(), 2);
    }

    #[test]
    fn join_intent_targets_the_named_session_not_the_sticky_binding() {
        // Two live sessions of one wallet: a secondary joining session 2
        // must land on session 2's IP even though the sticky binding points
        // at session 1.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x5A; 32];
        let s1 = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        let s2 = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntent::Fresh)
            .expect("session 2");
        let joined = pool
            .allocate_for_pubkey_with_intent(3, pubkey, SessionIntent::Join(s2))
            .expect("session 2 secondary");
        assert_eq!(joined, s2, "the join must target the NAMED session's IP");
        assert_ne!(joined, s1);
    }

    #[test]
    fn join_intent_never_grants_an_ip_held_by_another_key() {
        // Anti-hijack: a hint names an address, it never authorizes one.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let victim = pool.allocate_for_pubkey(1, [0xAA; 32]).expect("victim");
        let attacker = pool
            .allocate_for_pubkey_with_intent(2, [0xBB; 32], SessionIntent::Join(victim))
            .expect("attacker still gets an address");
        assert_ne!(
            attacker, victim,
            "a join hint must never land on another identity's address"
        );
    }

    #[test]
    fn join_intent_recovers_the_sticky_ip_after_a_clean_close() {
        // Client-remembered reconnect: the session's previous IP is free
        // and still sticky-bound to this wallet, so the join recovers it.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x5A; 32];
        let first = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        pool.release(1);
        let reconnect = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntent::Join(first))
            .expect("reconnect");
        assert_eq!(reconnect, first);
    }

    #[test]
    fn join_intent_with_a_free_unbound_target_falls_back_to_a_fresh_ip() {
        // A free address NOT sticky-bound to this wallet must not be
        // grantable on demand (no targeted squatting of just-departed
        // clients' addresses and their NAT-PMP windows).
        let mut pool = IpAllocator::with_seed(NET, 24, GW, 0x7777).expect("/24 pool builds");
        let other = pool.allocate_for_pubkey(1, [0xAA; 32]).expect("other");
        pool.release(1);
        // The sticky binding for [0xAA] still points at `other`.
        let requester = pool
            .allocate_for_pubkey_with_intent(2, [0xBB; 32], SessionIntent::Join(other))
            .expect("requester");
        assert_ne!(
            requester, other,
            "a foreign-bound free address must not be joinable"
        );
    }

    #[test]
    fn join_intent_with_a_stale_target_falls_back_to_a_session_fresh_ip() {
        // The join target vanished (exit restart, pool churn): the request
        // degrades to Fresh, i.e. it still never lands on the incumbent's
        // live IP.
        let mut pool = IpAllocator::new(NET, 24, GW).expect("/24 pool builds");
        let pubkey = [0x5A; 32];
        let incumbent = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        let bogus = Ipv4Addr::new(10, 66, 0, 250);
        let got = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntent::Join(bogus))
            .expect("fallback");
        assert_ne!(
            got, incumbent,
            "a stale join must degrade to Fresh, not to legacy sharing"
        );
    }

    #[test]
    fn v6_fresh_intent_never_shares_a_live_held_interface_id() {
        let mut pool = IpAllocatorV6::new(NET6);
        let pubkey = [0x5A; 32];
        let incumbent = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        let second = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntentV6::Fresh)
            .expect("session 2");
        assert_ne!(
            second, incumbent,
            "a Fresh session must get its own interface ID"
        );
    }

    #[test]
    fn v6_join_intent_shares_the_sibling_connections_interface_id() {
        let mut pool = IpAllocatorV6::new(NET6);
        let pubkey = [0x5A; 32];
        let s1 = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        let s2 = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntentV6::Fresh)
            .expect("session 2");
        let joined = pool
            .allocate_for_pubkey_with_intent(3, pubkey, SessionIntentV6::Join(&[2]))
            .expect("session 2 secondary");
        assert_eq!(joined, s2, "the join must share the sibling's offset");
        assert_ne!(joined, s1);
    }

    #[test]
    fn v6_join_intent_ignores_siblings_owned_by_another_key() {
        // Anti-hijack mirror: sibling conn ids come from the v4 decision,
        // but the owner check still guards the share.
        let mut pool = IpAllocatorV6::new(NET6);
        let victim = pool.allocate_for_pubkey(1, [0xAA; 32]).expect("victim");
        let got = pool
            .allocate_for_pubkey_with_intent(2, [0xBB; 32], SessionIntentV6::Join(&[1]))
            .expect("fallback");
        assert_ne!(got, victim, "a foreign sibling must never be joined");
    }

    #[test]
    fn v6_fresh_intent_leaves_the_sticky_binding_with_the_incumbent() {
        let mut pool = IpAllocatorV6::new(NET6);
        let pubkey = [0x5A; 32];
        let incumbent = pool.allocate_for_pubkey(1, pubkey).expect("session 1");
        let second = pool
            .allocate_for_pubkey_with_intent(2, pubkey, SessionIntentV6::Fresh)
            .expect("session 2");
        pool.release(1);
        let legacy_reconnect = pool.allocate_for_pubkey(3, pubkey).expect("reconnect");
        assert_eq!(
            legacy_reconnect, incumbent,
            "the v6 sticky binding must stay with the incumbent session"
        );
        assert_ne!(legacy_reconnect, second);
    }
}
