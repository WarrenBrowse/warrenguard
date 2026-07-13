//! `PacketDevice` implementation over a real OS-level TUN via `tun-rs`.
//!
//! - macOS: uses `utun*` (auto-numbered).
//! - Linux: `/dev/net/tun` (the name can be enforced).
//!
//! Requires `CAP_NET_ADMIN` (Linux) or root (macOS) for creation. Tests
//! are marked `#[ignore]`; they should be run manually with
//! `sudo -E cargo test ...` (cf. `tests/real_tun.rs`).
//!
//! ## TUN GSO/GRO offload (Linux)
//!
//! On Linux we can enable `IFF_VNET_HDR` via
//! `tun-rs::DeviceBuilder::offload(true)`. This authorizes:
//! - **`recv_multiple`**: the kernel coalesces N small IP packets into
//!   a single large chunk prefixed with a `virtio_net_hdr`, then
//!   tun-rs splits in userspace -> 1 syscall for N packets (vs N
//!   syscalls before).
//! - **`send_multiple`**: symmetric, write-side batching via `GROTable`.
//!   `PacketDevice::send_batch` delegates to `tun-rs::send_multiple`
//!   which coalesces same-flow packets into a single `writev` call.
//!
//! The **read** path (`recv_multiple`) reduces uplink CPU. The **write**
//! path (`send_multiple`, via `send_batch`) reduces downlink CPU.
//! Individual `send()` calls still prepend a zero `virtio_net_hdr`
//! for backward compatibility with callers that don't use `send_batch`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tun_rs::{AsyncDevice, DeviceBuilder};

#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use warrenguard_transport_core::PacketDevice;

/// Default MTU at the TUN level.
///
/// **1280 chosen**: `TUNNEL_INITIAL_MTU = 1350` on the Quinn side, but
/// `Connection::max_datagram_size()` may be < 1350 depending on the
/// path-MTU discovered dynamically (DPLPMTUD). If we set the TUN to
/// 1350, `pump_tun_to_quic` receives 1350-byte IP packets and tries to
/// send them as QUIC datagrams, which can be rejected
/// ("datagram too large") until DPLPMTUD has raised the PMTU. 1280
/// (RFC 8200 IPv6 minimum, widely supported) guarantees that
/// `max_datagram_size() >= 1280` always - no initial drop.
///
/// The cost is ~5 % overhead vs 1350. Acceptable for stability; a
/// client may override via a future `--tun-mtu` flag.
const DEFAULT_TUN_MTU: u16 = 1280;

/// Number of TUN queues actually opened for a `requested` count.
///
/// `IFF_MULTI_QUEUE` is a Linux-only kernel feature, so every other
/// platform collapses to a single queue regardless of the request; on
/// Linux the request is honoured (floored at 1). This is the single place
/// that decides platform capability, so the multi-queue constructor and
/// its callers agree on the returned queue count.
#[must_use]
const fn planned_queue_count(requested: usize) -> usize {
    #[cfg(target_os = "linux")]
    {
        if requested < 1 { 1 } else { requested }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = requested;
        1
    }
}

/// Shared state for `recv_multiple` (Linux + offload). Maintains
/// persistent scratch buffers between calls (otherwise 256+ KB of
/// allocations per recv_batch - costly).
#[cfg(target_os = "linux")]
struct RecvBatchState {
    /// Monolithic buffer for the virtio_net_hdr-prefixed chunk (up to
    /// 64 KiB of coalesced TCP/UDP GSO).
    original: Vec<u8>,
    /// Output slots for the split packets (up to `IDEAL_BATCH_SIZE`).
    bufs: Vec<Vec<u8>>,
    /// Effective sizes written by recv_multiple into each `bufs[i]`.
    sizes: Vec<usize>,
}

#[cfg(target_os = "linux")]
impl RecvBatchState {
    fn new(batch_size: usize) -> Self {
        Self {
            original: vec![0u8; VIRTIO_NET_HDR_LEN + 65535],
            bufs: (0..batch_size).map(|_| vec![0u8; 1500]).collect(),
            sizes: vec![0; batch_size],
        }
    }
}

/// Shared state for `send_multiple` (Linux + offload). Maintains the
/// `GROTable` and reusable scratch buffers between calls.
#[cfg(target_os = "linux")]
struct SendBatchState {
    gro_table: GROTable,
}

/// Async-tokio wrapper around `tun-rs::AsyncDevice`. Implements
/// [`PacketDevice`] to plug Warren pumps onto a real OS TUN.
///
/// `Clone` shares the same underlying device (Arc) - useful for
/// `pump_bidirectional`, which needs a copy for each direction.
#[derive(Clone)]
pub struct RealTun {
    device: Arc<AsyncDevice>,
    name: String,
    /// TUN mode: Plain or Offloaded(state) on Linux. The Offloaded state
    /// holds the reusable scratch buffers for `recv_multiple`.
    mode: TunMode,
}

#[derive(Clone)]
enum TunMode {
    /// Standard TUN without IFF_VNET_HDR. Historic Warren path.
    Plain,
    /// Linux TUN with offload(true) -> IFF_VNET_HDR + recv_multiple/send.
    /// The recv/send_batch states are mutex-protected to amortize
    /// scratch allocations between calls (single concurrent reader/writer
    /// on the kernel TUN side).
    #[cfg(target_os = "linux")]
    Offloaded {
        recv_state: Arc<tokio::sync::Mutex<RecvBatchState>>,
        send_state: Arc<tokio::sync::Mutex<SendBatchState>>,
    },
}

impl RealTun {
    /// Create a minimal TUN for tests. On macOS, `utun*` is
    /// auto-numbered. On Linux, we suggest a name but the kernel may
    /// rotate.
    ///
    /// Default IP: `10.66.0.99/16`. For distinct configurations
    /// (e.g. local client vs exit), use [`Self::create_with_ipv4`].
    ///
    /// # Errors
    ///
    /// EPERM if the process is not root / lacks capabilities.
    pub async fn create_for_test() -> std::io::Result<Self> {
        Self::create_with_ipv4(Ipv4Addr::new(10, 66, 0, 99), 16).await
    }

    /// Create a TUN with an explicit MTU (override of the 1280 default).
    /// Useful for setups where the effective path MTU is below the
    /// Warren default - typically when the client is itself behind a
    /// VPN (Mullvad, etc.) that lowers the effective PMTU.
    ///
    /// Guard: MTU < 576 = invalid IPv4. MTU > 1500 = above standard
    /// Ethernet, will likely fragment somewhere.
    ///
    /// # Errors
    ///
    /// See [`Self::create_with_ipv4`].
    pub async fn create_with_ipv4_mtu(
        addr: Ipv4Addr,
        prefix: u8,
        mtu: u16,
    ) -> std::io::Result<Self> {
        Self::create_internal(None, addr, prefix, None, 0, mtu, false, false).await
    }

    /// **Linux only** - Create a TUN with offload (IFF_VNET_HDR) to
    /// enable batched `recv_multiple`. On macOS / non-Linux, falls
    /// back to the standard non-offload path (`offload` is ignored).
    ///
    /// Enabling offload coalesces N RX packets into 1 syscall ->
    /// reduced client uplink CPU. Only the read path is offloaded for
    /// now; the write path keeps a single `send()` with a zero-prefixed
    /// virtio_net_hdr.
    ///
    /// # Errors
    ///
    /// EPERM if not privileged. EOPNOTSUPP if the kernel does not
    /// support IFF_VNET_HDR (very old kernel < 2.6.32).
    pub async fn create_with_ipv4_mtu_offload(
        addr: Ipv4Addr,
        prefix: u8,
        mtu: u16,
        offload: bool,
    ) -> std::io::Result<Self> {
        Self::create_internal(None, addr, prefix, None, 0, mtu, offload, false).await
    }

    /// Create a dual-stack IPv4 + IPv6 TUN with optional offload.
    /// `addr_v6 = None` -> v4-only mode (back-compat). `addr_v6 = Some(ip6)`
    /// -> also assigns the IPv6 to the TUN with `prefix_v6` (typically
    /// 128 for host-specific on the client side, 64 on the gateway exit).
    ///
    /// # Errors
    ///
    /// See [`Self::create_with_ipv4_mtu_offload`].
    pub async fn create_with_ipv4_ipv6_offload(
        addr_v4: Ipv4Addr,
        prefix_v4: u8,
        addr_v6: Option<Ipv6Addr>,
        prefix_v6: u8,
        mtu: u16,
        offload: bool,
    ) -> std::io::Result<Self> {
        Self::create_internal(
            None, addr_v4, prefix_v4, addr_v6, prefix_v6, mtu, offload, false,
        )
        .await
    }

    /// Variant of [`Self::create_with_ipv4_ipv6_offload`] that
    /// explicitly forces the TUN interface name via
    /// `DeviceBuilder::name()`. Without it, the Linux kernel ignores
    /// the suggested name and auto-increments (`tun0`, `tun1`...),
    /// breaking nftables rules hardcoded on `warren0` in the cloud-init.
    ///
    /// On macOS, `utun*` naming remains constrained by the system; the
    /// flag is attempted but the OS may still impose an auto name. On
    /// Linux, the name is respected as long as it is <= 15 chars and
    /// not already in use.
    ///
    /// # Errors
    ///
    /// See [`Self::create_with_ipv4_ipv6_offload`]. Plus EBUSY if the
    /// name is already taken by another interface.
    pub async fn create_with_ipv4_ipv6_offload_named(
        name: &str,
        addr_v4: Ipv4Addr,
        prefix_v4: u8,
        addr_v6: Option<Ipv6Addr>,
        prefix_v6: u8,
        mtu: u16,
        offload: bool,
    ) -> std::io::Result<Self> {
        Self::create_internal(
            Some(name),
            addr_v4,
            prefix_v4,
            addr_v6,
            prefix_v6,
            mtu,
            offload,
            false,
        )
        .await
    }

    /// **Linux only** multi-queue TUN: opens `queues` independent kernel
    /// queues (`IFF_MULTI_QUEUE`) on ONE named interface, returning one
    /// [`RealTun`] per queue. Each returned handle owns its own kernel fd
    /// and (in offload mode) its own `recv`/`send` scratch state, so N
    /// downlink reader tasks and N uplink writers run without contending
    /// on a single TUN queue: the serialization point `SO_REUSEPORT`
    /// endpoint sharding cannot remove.
    ///
    /// The returned Vec length is authoritative, **not** the requested
    /// count: `queues <= 1`, and every non-Linux platform (where
    /// `IFF_MULTI_QUEUE` does not exist), yield exactly one queue. Callers
    /// must size their reader/writer fan-out from `vec.len()`.
    ///
    /// # Errors
    ///
    /// See [`Self::create_with_ipv4_ipv6_offload_named`]. Plus any error
    /// from `AsyncDevice::try_clone` when attaching an extra queue (e.g.
    /// the kernel refusing a new multi-queue fd).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_multi_queue_named(
        name: &str,
        addr_v4: Ipv4Addr,
        prefix_v4: u8,
        addr_v6: Option<Ipv6Addr>,
        prefix_v6: u8,
        mtu: u16,
        offload: bool,
        queues: usize,
    ) -> std::io::Result<Vec<Self>> {
        let planned = planned_queue_count(queues);

        // Single-queue path: the historic device, no IFF_MULTI_QUEUE. This
        // is also the only path compiled on non-Linux (planned == 1).
        if planned <= 1 {
            let single = Self::create_internal(
                Some(name),
                addr_v4,
                prefix_v4,
                addr_v6,
                prefix_v6,
                mtu,
                offload,
                false,
            )
            .await?;
            return Ok(vec![single]);
        }

        #[cfg(target_os = "linux")]
        {
            // Queue 0 carries IFF_MULTI_QUEUE so try_clone can attach the
            // rest to the same interface. try_clone preserves the
            // vnet_hdr/offload setup on each new fd (tun-rs re-applies the
            // TCP/UDP offloads), so every queue is offload-capable.
            let primary = Self::create_internal(
                Some(name),
                addr_v4,
                prefix_v4,
                addr_v6,
                prefix_v6,
                mtu,
                offload,
                true,
            )
            .await?;
            let base = primary.device.clone();
            let iface = primary.name.clone();
            let mut tuns = Vec::with_capacity(planned);
            tuns.push(primary);
            for _ in 1..planned {
                let cloned = base.try_clone().map_err(std::io::Error::other)?;
                tuns.push(Self::from_queue_device(cloned, iface.clone(), offload));
            }
            Ok(tuns)
        }
        // Unreachable on non-Linux: planned is always 1 there, handled above.
        #[cfg(not(target_os = "linux"))]
        {
            unreachable!("planned_queue_count is 1 on non-Linux platforms")
        }
    }

    /// Wraps an extra queue fd (from `AsyncDevice::try_clone`) into a
    /// `RealTun` with its own offload scratch state. Linux-only: only the
    /// multi-queue path creates cloned queues.
    #[cfg(target_os = "linux")]
    fn from_queue_device(device: AsyncDevice, name: String, offload: bool) -> Self {
        let mode = if offload {
            TunMode::Offloaded {
                recv_state: Arc::new(tokio::sync::Mutex::new(RecvBatchState::new(
                    IDEAL_BATCH_SIZE,
                ))),
                send_state: Arc::new(tokio::sync::Mutex::new(SendBatchState {
                    gro_table: GROTable::default(),
                })),
            }
        } else {
            TunMode::Plain
        };
        Self {
            device: Arc::new(device),
            name,
            mode,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_internal(
        name: Option<&str>,
        addr: Ipv4Addr,
        prefix: u8,
        addr_v6: Option<Ipv6Addr>,
        prefix_v6: u8,
        mtu: u16,
        offload: bool,
        multi_queue: bool,
    ) -> std::io::Result<Self> {
        let addr_str = addr.to_string();
        let mut builder = DeviceBuilder::new()
            .ipv4(addr_str.as_str(), prefix, None)
            .mtu(mtu);
        if let Some(n) = name {
            builder = builder.name(n);
        }
        if let Some(v6) = addr_v6 {
            builder = builder.ipv6(v6, prefix_v6);
        }

        // The `offload` and `multi_queue` APIs are gated
        // `#[cfg(target_os = "linux")]` on the tun-rs side. On macOS both
        // flags are silently ignored (single Plain queue).
        #[cfg(target_os = "linux")]
        let builder = if offload {
            builder.offload(true)
        } else {
            builder
        };
        // IFF_MULTI_QUEUE must be set on the *first* queue so subsequent
        // `AsyncDevice::try_clone()` calls can attach further queues to the
        // same interface; without it try_clone returns EOPNOTSUPP.
        #[cfg(target_os = "linux")]
        let builder = if multi_queue {
            builder.multi_queue(true)
        } else {
            builder
        };
        #[cfg(not(target_os = "linux"))]
        let _ = (offload, multi_queue); // unused outside Linux

        let device = builder.build_async().map_err(std::io::Error::other)?;
        let name = device.name().map_err(std::io::Error::other)?;

        let mode = {
            #[cfg(target_os = "linux")]
            {
                if offload {
                    TunMode::Offloaded {
                        recv_state: Arc::new(tokio::sync::Mutex::new(RecvBatchState::new(
                            IDEAL_BATCH_SIZE,
                        ))),
                        send_state: Arc::new(tokio::sync::Mutex::new(SendBatchState {
                            gro_table: GROTable::default(),
                        })),
                    }
                } else {
                    TunMode::Plain
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                TunMode::Plain
            }
        };

        Ok(Self {
            device: Arc::new(device),
            name,
            mode,
        })
    }

    /// Create a TUN with a custom local IP and CIDR prefix. Lets us
    /// have distinct IPs per binary locally.
    ///
    /// # Errors
    ///
    /// EPERM without privileges, EADDRNOTAVAIL if the IP is already
    /// used by another interface.
    pub async fn create_with_ipv4(addr: Ipv4Addr, prefix: u8) -> std::io::Result<Self> {
        Self::create_internal(None, addr, prefix, None, 0, DEFAULT_TUN_MTU, false, false).await
    }

    /// Name of the TUN interface as seen by the OS (e.g. `utun7`, `tun0`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Atomically replace the TUN's IPv4 assignment.
    ///
    /// Used by the multi-hop client to reconfigure the TUN after the
    /// exit has answered an `IpAssign` control message. The
    /// underlying `tun-rs::set_network_address` call removes every
    /// existing IPv4 binding on the interface before adding the new
    /// one, so the swap is atomic from the kernel's perspective.
    ///
    /// The TUN handle itself is unchanged - `recv` / `send` continue
    /// to operate on the same file descriptor; only the kernel's IP
    /// binding is rewritten. Existing TCP sessions bound to the old
    /// IP will see their address disappear (expected; the multi-hop
    /// session is the only consumer of this method).
    ///
    /// # Errors
    ///
    /// EPERM without privileges. EINVAL on a malformed prefix length
    /// (`> 32`). EADDRNOTAVAIL if the IP is already used by another
    /// interface (Linux strict mode).
    pub fn reassign_ipv4(&self, addr: Ipv4Addr, prefix: u8) -> std::io::Result<()> {
        self.device
            .set_network_address(addr, prefix, None)
            .map_err(std::io::Error::other)
    }

    /// Multi-hop `/v2` dual-stack - add the exit-allocated IPv6 to the
    /// TUN after an `IpAssign` control message.
    ///
    /// Unlike [`Self::reassign_ipv4`] (whose `set_network_address`
    /// removes every prior v4 binding), `tun-rs` has no
    /// remove-all-then-set for v6, so this only *adds* `addr`. Callers
    /// that reassign across a changing assignment must first drop the old
    /// address with [`Self::remove_ipv6`]; the multi-hop reassign loop
    /// does exactly that. Re-adding an already-present address is a
    /// no-op-or-EEXIST, which the loop's change-detection avoids.
    ///
    /// # Errors
    ///
    /// EPERM without privileges. EINVAL on a malformed prefix length
    /// (`> 128`). EEXIST if `addr` is already bound to the interface.
    pub fn reassign_ipv6(&self, addr: Ipv6Addr, prefix: u8) -> std::io::Result<()> {
        self.device
            .add_address_v6(addr, prefix)
            .map_err(std::io::Error::other)
    }

    /// Multi-hop `/v2` dual-stack - remove a previously-added IPv6 from
    /// the TUN (companion to [`Self::reassign_ipv6`]). Used by the
    /// reassign loop to drop the prior assignment before adding a fresh
    /// one so the interface never carries two tunnel v6 addresses at once.
    ///
    /// # Errors
    ///
    /// EPERM without privileges. EADDRNOTAVAIL when `addr` is not bound.
    pub fn remove_ipv6(&self, addr: Ipv6Addr) -> std::io::Result<()> {
        self.device
            .remove_address(std::net::IpAddr::V6(addr))
            .map_err(std::io::Error::other)
    }

    /// True if the TUN is in offload mode (Linux + IFF_VNET_HDR).
    /// Allows the pump to log or diagnose.
    #[must_use]
    pub fn is_offloaded(&self) -> bool {
        match &self.mode {
            TunMode::Plain => false,
            #[cfg(target_os = "linux")]
            TunMode::Offloaded { .. } => true,
        }
    }

    /// Internal method that calls `tun-rs::recv_multiple` directly
    /// (Linux + offload only). Factored outside the trait to avoid
    /// async opaque-type inference cycles between `recv` and
    /// `recv_batch` (the compiler cannot prove the absence of a cycle
    /// when recv() delegates to recv_batch through the trait).
    #[cfg(target_os = "linux")]
    async fn recv_multiple_into(
        &self,
        state: &Arc<tokio::sync::Mutex<RecvBatchState>>,
        max: usize,
        out: &mut Vec<Vec<u8>>,
    ) -> std::io::Result<usize> {
        let mut state = state.lock().await;
        let batch_cap = state.bufs.len().min(max).max(1);
        let RecvBatchState {
            original,
            bufs,
            sizes,
        } = &mut *state;
        let n = match self
            .device
            .recv_multiple(original, &mut bufs[..batch_cap], &mut sizes[..batch_cap], 0)
            .await
        {
            Ok(n) => n,
            Err(e) if e.to_string().contains("ErrTooManySegments") => {
                // Matches wireguard-go behavior (device/send.go:300): drop
                // the oversized GSO packet and continue. The raw packet was
                // already consumed from the kernel TUN fd by the read()
                // inside recv_multiple, so we cannot retry the split - TCP
                // retransmission will recover.
                tracing::warn!("dropped oversized GSO packet from TUN (ErrTooManySegments)");
                return Ok(0);
            }
            Err(e) => return Err(e),
        };
        for i in 0..n {
            let len = sizes[i];
            let mut pkt = Vec::with_capacity(len);
            pkt.extend_from_slice(&bufs[i][..len]);
            out.push(pkt);
        }
        Ok(n)
    }
}

impl PacketDevice for RealTun {
    async fn recv(&self) -> std::io::Result<Vec<u8>> {
        match &self.mode {
            TunMode::Plain => {
                // Historic path: single direct recv.
                let mut buf = vec![0u8; 2048];
                let n = self.device.recv(&mut buf).await?;
                buf.truncate(n);
                Ok(buf)
            }
            #[cfg(target_os = "linux")]
            TunMode::Offloaded { recv_state, .. } => {
                // Offload mode: must go through recv_multiple so tun-rs
                // strips the virtio_net_hdr automatically. We call the
                // inherent method directly (avoids the async opaque
                // type inference cycle via the trait).
                //
                // With max=1, any GSO packet (> 1 segment) triggers
                // ErrTooManySegments which recv_multiple_into converts
                // to Ok(0). Retry until we get a non-GSO packet. Lost
                // GSO packets are recovered by TCP retransmission.
                loop {
                    let mut out = Vec::with_capacity(1);
                    self.recv_multiple_into(recv_state, 1, &mut out).await?;
                    if let Some(pkt) = out.pop() {
                        return Ok(pkt);
                    }
                }
            }
        }
    }

    async fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        match &self.mode {
            TunMode::Plain => {
                let written = self.device.send(packet).await?;
                if written != packet.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!(
                            "short write on TUN: wanted {} got {}",
                            packet.len(),
                            written
                        ),
                    ));
                }
                Ok(())
            }
            #[cfg(target_os = "linux")]
            TunMode::Offloaded { .. } => {
                // In offload mode, the kernel expects a virtio_net_hdr
                // (12 bytes) prefix on every write. All-zero =
                // gso_type=NONE -> treated as a single packet without
                // offload kernel-side. For batched writes, use
                // `send_batch` which delegates to `send_multiple` +
                // `GROTable` for flow-coalesced writes.
                let mut buf = Vec::with_capacity(VIRTIO_NET_HDR_LEN + packet.len());
                buf.resize(VIRTIO_NET_HDR_LEN, 0);
                buf.extend_from_slice(packet);
                let written = self.device.send(&buf).await?;
                if written != buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!(
                            "short write on TUN (offload): wanted {} got {}",
                            buf.len(),
                            written
                        ),
                    ));
                }
                Ok(())
            }
        }
    }

    fn try_recv(&self) -> std::io::Result<Option<Vec<u8>>> {
        // try_recv in offload mode is not trivial: it would need a
        // try_recv_multiple on the tun-rs side (not exposed). For now
        // we return None - the caller (app-level batching pump) falls
        // through to the default recv_batch + drain path.
        match &self.mode {
            TunMode::Plain => {
                let mut buf = vec![0u8; 2048];
                match self.device.try_recv(&mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        Ok(Some(buf))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                    Err(e) => Err(e),
                }
            }
            #[cfg(target_os = "linux")]
            TunMode::Offloaded { .. } => {
                // In offload mode, application-level batching is made
                // obsolete by recv_multiple which already amortizes at
                // the syscall. try_recv = no-op signalling "nothing to
                // drain in addition".
                Ok(None)
            }
        }
    }

    async fn recv_batch(&self, max: usize, out: &mut Vec<Vec<u8>>) -> std::io::Result<usize> {
        // Precondition: callers must pass `max >= 1` (caller bug
        // otherwise). `max` is only used in the Linux Offloaded path
        // below, but the assertion covers both paths for API
        // stability.
        debug_assert!(max >= 1, "recv_batch max must be >= 1");
        let _ = max;
        match &self.mode {
            TunMode::Plain => {
                // Default fallback: single direct recv, push 1 packet.
                // We avoid calling self.recv() to not create a cycle in
                // the async opaque-type inference (the compiler cannot
                // prove the absence of recursion when traversing the
                // trait both ways).
                let mut buf = vec![0u8; 2048];
                let n = self.device.recv(&mut buf).await?;
                buf.truncate(n);
                out.push(buf);
                Ok(1)
            }
            #[cfg(target_os = "linux")]
            TunMode::Offloaded { recv_state, .. } => {
                self.recv_multiple_into(recv_state, max, out).await
            }
        }
    }

    async fn recv_batch_into(&self, bufs: &mut [Vec<u8>]) -> std::io::Result<usize> {
        if bufs.is_empty() {
            return Ok(0);
        }
        match &self.mode {
            TunMode::Plain => {
                let buf = &mut bufs[0];
                if buf.capacity() < 2048 {
                    buf.reserve(2048 - buf.len());
                }
                buf.resize(2048, 0);
                let n = self.device.recv(buf).await?;
                buf.truncate(n);
                Ok(1)
            }
            #[cfg(target_os = "linux")]
            TunMode::Offloaded { recv_state, .. } => {
                let mut state = recv_state.lock().await;
                let batch_cap = state.bufs.len().min(bufs.len()).max(1);
                let RecvBatchState {
                    original,
                    bufs: scratch,
                    sizes,
                } = &mut *state;
                let n = match self
                    .device
                    .recv_multiple(
                        original,
                        &mut scratch[..batch_cap],
                        &mut sizes[..batch_cap],
                        0,
                    )
                    .await
                {
                    Ok(n) => n,
                    Err(e) if e.to_string().contains("ErrTooManySegments") => {
                        tracing::warn!(
                            "dropped oversized GSO packet from TUN (ErrTooManySegments)"
                        );
                        return Ok(0);
                    }
                    Err(e) => return Err(e),
                };
                let count = n.min(bufs.len());
                for i in 0..count {
                    let len = sizes[i];
                    bufs[i].clear();
                    bufs[i].extend_from_slice(&scratch[i][..len]);
                }
                Ok(count)
            }
        }
    }

    async fn send_batch(&self, packets: &mut Vec<Vec<u8>>) -> std::io::Result<usize> {
        match &self.mode {
            TunMode::Plain => {
                let count = packets.len();
                for pkt in packets.iter() {
                    self.send(pkt).await?;
                }
                Ok(count)
            }
            #[cfg(target_os = "linux")]
            TunMode::Offloaded { send_state, .. } => {
                if packets.is_empty() {
                    return Ok(0);
                }
                let mut state = send_state.lock().await;
                let mut bufs: Vec<Vec<u8>> = packets
                    .drain(..)
                    .map(|pkt| {
                        let mut buf = Vec::with_capacity(VIRTIO_NET_HDR_LEN + pkt.len());
                        buf.resize(VIRTIO_NET_HDR_LEN, 0);
                        buf.extend_from_slice(&pkt);
                        buf
                    })
                    .collect();
                let n = self
                    .device
                    .send_multiple(&mut state.gro_table, &mut bufs, VIRTIO_NET_HDR_LEN)
                    .await?;
                Ok(n)
            }
        }
    }

    async fn send_batch_bytes(&self, packets: &mut Vec<bytes::Bytes>) -> std::io::Result<usize> {
        match &self.mode {
            TunMode::Plain => {
                // Plain mode: one send() per packet, same cost as the
                // Vec<Vec<u8>> variant but avoids the per-packet .to_vec().
                let count = packets.len();
                for pkt in packets.iter() {
                    self.send(pkt.as_ref()).await?;
                }
                Ok(count)
            }
            #[cfg(target_os = "linux")]
            TunMode::Offloaded { send_state, .. } => {
                // Offload mode: build virtio_net_hdr-prefixed bufs from
                // the Bytes slices (one copy here is unavoidable for the
                // kernel API), then dispatch via send_multiple + GROTable.
                // This is cheaper than the caller doing .to_vec() first
                // because the intermediate Vec<Vec<u8>> step is removed
                // from the caller's hot path.
                if packets.is_empty() {
                    return Ok(0);
                }
                let mut state = send_state.lock().await;
                let mut bufs: Vec<Vec<u8>> = packets
                    .drain(..)
                    .map(|pkt| {
                        let mut buf = Vec::with_capacity(VIRTIO_NET_HDR_LEN + pkt.len());
                        buf.resize(VIRTIO_NET_HDR_LEN, 0);
                        buf.extend_from_slice(&pkt);
                        buf
                    })
                    .collect();
                let n = self
                    .device
                    .send_multiple(&mut state.gro_table, &mut bufs, VIRTIO_NET_HDR_LEN)
                    .await?;
                Ok(n)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::planned_queue_count;

    #[test]
    fn queue_plan_never_below_one() {
        // A zero or one request is always exactly one queue, on every
        // platform: the single-queue historic path.
        assert_eq!(planned_queue_count(0), 1);
        assert_eq!(planned_queue_count(1), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn queue_plan_honours_request_on_linux() {
        // Linux has IFF_MULTI_QUEUE: N is honoured verbatim.
        assert_eq!(planned_queue_count(2), 2);
        assert_eq!(planned_queue_count(8), 8);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn queue_plan_collapses_to_single_off_linux() {
        // No IFF_MULTI_QUEUE off Linux: any request collapses to one
        // queue, so the constructor never attempts a doomed try_clone.
        assert_eq!(planned_queue_count(8), 1);
        assert_eq!(planned_queue_count(16), 1);
    }
}
