//! Accept loop and test helpers for [`super::ExitListener`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::session::{SESSION_IDLE_TTL, release_connection_and_maybe_session, sweep_idle_sessions};
use super::{ExitListener, HandshakeRateLimiter, SessionKey};
use warrenguard_transport_core::error::{Result, TunnelError};

impl ExitListener {
    /// Infinite loop: accepts incoming connections and **spawns** a
    /// bidirectional pump per connection so as not to block the accept
    /// loop.
    ///
    /// **Why spawn?** The previous design called `pump_bidirectional`
    /// directly inside the loop, which blocked until the connection
    /// closed. Consequence: with a multi-conn client, the primary
    /// connection blocked the loop and the second connection from the
    /// same client timed out at handshake. Spawning per conn = N
    /// independent pumps run concurrently, sharing the TUN (thread-safe
    /// for write on the `tun-rs` side).
    ///
    /// For multi-conn sessions (cf. `connect_multi` on the client),
    /// each conn from the same Ed25519 identity gets its own pump,
    /// the per-identity aggregation in `attribute_session` guarantees
    /// they share the same tunnel IP, so all traffic ends up on the
    /// right TUN.
    ///
    /// # Errors
    ///
    /// A handshake error is *logged* and the loop continues. A pump
    /// error in a spawned task is also logged but does not affect the
    /// other sessions.
    ///
    /// # Lifetime invariant
    ///
    /// `self` is consumed and lives in this future's stack frame. The
    /// spawned pumps hold `Connection` clones that depend on the
    /// `Endpoint` owned by `self`. **If the caller wraps this future in
    /// a `tokio::select!` with another branch that may terminate (e.g.
    /// ctrl-c), dropping `self` will kill all active pumps**.
    ///
    /// Correct caller pattern: use `tokio::spawn` for the entire future
    /// + `JoinHandle` for explicit shutdown, rather than `select!` which
    ///   drops the future on a race.
    pub async fn accept_forever_with_tun<T>(self, tun: T) -> Result<()>
    where
        T: warrenguard_transport_core::PacketDevice + Clone + Send + 'static,
    {
        self.accept_forever_with_tun_queues(vec![tun]).await
    }

    /// Multi-queue variant of [`Self::accept_forever_with_tun`]: takes N
    /// TUN queues (one per `IFF_MULTI_QUEUE` kernel queue) instead of one
    /// device, and removes the single-TUN-queue serialization point that
    /// `SO_REUSEPORT` endpoint sharding leaves in place:
    ///
    /// - **Downlink** (exit -> client): one `pump_tun_downlink` reader task
    ///   per queue, all dispatching into the shared routing table. N kernel
    ///   queues read in parallel instead of one.
    /// - **Uplink** (client -> exit): each accepted connection's QUIC->TUN
    ///   pump is pinned to a queue chosen round-robin, so per-connection
    ///   writes spread across the N queues rather than serializing on one fd.
    ///
    /// `queues` must be non-empty; a single-element Vec is exactly the old
    /// single-queue behaviour (what [`Self::accept_forever_with_tun`]
    /// passes). The caller sizes the Vec from the count `RealTun` actually
    /// opened (see `RealTun::create_multi_queue_named`), which may be less
    /// than requested on platforms without multi-queue support.
    ///
    /// # Errors
    ///
    /// See [`Self::accept_forever_with_tun`]. Additionally returns
    /// [`TunnelError::Internal`] if `queues` is empty (caller bug).
    pub async fn accept_forever_with_tun_queues<T>(self, queues: Vec<T>) -> Result<()>
    where
        T: warrenguard_transport_core::PacketDevice + Clone + Send + 'static,
    {
        if queues.is_empty() {
            return Err(TunnelError::Internal(
                "accept_forever_with_tun_queues needs at least one TUN queue".into(),
            ));
        }

        let handshake_semaphore =
            Arc::new(tokio::sync::Semaphore::new(self.max_concurrent_handshakes));

        let rate_limiter = self
            .handshake_rate_limit
            .map(|cfg| Arc::new(HandshakeRateLimiter::new(cfg)));

        let mut rl_gc_interval = tokio::time::interval(Duration::from_secs(60));
        rl_gc_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let dispatch_table = Arc::new(
            crate::tun_dispatch::TunDownlinkTable::new()
                .with_downlink_limiter(self.rate_limiter_downlink.clone()),
        );

        // One TUN reader task per queue: each reads its own kernel queue and
        // dispatches to the correct QUIC connection by destination IP through
        // the shared routing table. With one queue this is the historic
        // single-reader downlink; with N queues the kernel fans inbound
        // packets across the queues and N readers drain them in parallel.
        let mut downlink_readers = tokio::task::JoinSet::new();
        for queue in &queues {
            let tun_for_dispatch = queue.clone();
            let table_for_dispatch = dispatch_table.clone();
            downlink_readers.spawn(async move {
                if let Err(e) =
                    crate::tun_dispatch::pump_tun_downlink(tun_for_dispatch, table_for_dispatch)
                        .await
                {
                    tracing::warn!(error = %e, "TUN downlink dispatcher ended");
                }
            });
        }

        // Round-robin cursor assigning each new connection's uplink
        // (QUIC->TUN) pump to a queue, so per-connection writes spread across
        // the N kernel queues instead of contending on one fd.
        let uplink_queue_cursor = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let sessions = self.sessions.clone();
        let allocator = self.allocator.clone();
        let allocator_v6 = self.allocator_v6.clone();
        let state_persister = self.state_persister.clone();
        let local_pubkey = self.local_pubkey;
        let signing_key = self.signing_key.clone();
        let allowlist = self.allowlist.clone();
        let daita_pool = self.daita_pool.clone();
        let active_conns = self.active_conns.clone();
        let uplink_global = self.rate_limiter_uplink.clone();
        let metrics_reg = self.metrics_registry.clone();
        let device_cap = self.device_cap_enforcer.clone();
        let token_admitter = self.token_admitter.clone();
        let unauthenticated_handler = self.unauthenticated_handler.clone();
        let drain_rx = self.drain_rx.clone();

        // First-seen-idle timestamps for the GC session sweep (crash
        // net); see `sweep_idle_sessions`.
        let mut idle_since: HashMap<SessionKey, Instant> = HashMap::new();

        loop {
            let incoming = tokio::select! {
                accepted = self.accept_any() => {
                    match accepted {
                        Some(inc) => inc,
                        None => {
                            tracing::info!("accept_forever_with_tun loop terminated: endpoint closed");
                            return Err(TunnelError::EndpointClosed);
                        }
                    }
                }
                joined = downlink_readers.join_next() => {
                    // A downlink reader task finishing is always abnormal (the
                    // pump loops forever); any queue dying degrades the
                    // downlink for every client, so stop the accept loop as
                    // with the single-reader case. `None` (empty set) cannot
                    // happen: `queues` is non-empty, so at least one reader
                    // was spawned.
                    tracing::error!("a TUN downlink dispatcher died unexpectedly, stopping accept loop");
                    return match joined {
                        Some(Ok(())) => Err(TunnelError::Internal("TUN dispatcher exited".into())),
                        Some(Err(e)) => Err(TunnelError::Internal(format!("TUN dispatcher panicked: {e}"))),
                        None => Err(TunnelError::Internal("TUN dispatcher set empty".into())),
                    };
                }
                _ = rl_gc_interval.tick() => {
                    if let Some(rl) = rate_limiter.as_ref() {
                        rl.gc();
                    }
                    // Lock order: sessions (async) first, then
                    // active_conns - same as the pump-end release, so
                    // the sweep can never interleave with a handshake
                    // that just attributed an IP.
                    let evicted = {
                        let mut sess = sessions.lock().await;
                        let mut conns_map = active_conns.lock();
                        conns_map.retain(|_, conns| {
                            conns.retain(|c| c.close_reason().is_none());
                            !conns.is_empty()
                        });
                        sweep_idle_sessions(
                            &mut sess,
                            &conns_map,
                            &mut idle_since,
                            &allocator,
                            &allocator_v6,
                            Instant::now(),
                            SESSION_IDLE_TTL,
                        )
                    };
                    if evicted > 0 {
                        tracing::info!(evicted, "GC tick evicted idle sessions (crash-path net)");
                        if let Some(p) = state_persister.as_ref() {
                            p.request_save();
                        }
                    }
                    continue;
                }
            };

            // Stateless retry on un-validated remotes.
            if !incoming.remote_address_validated() && incoming.may_retry() {
                match incoming.retry() {
                    Ok(()) => {
                        tracing::debug!("issued stateless retry; continuing accept loop");
                        continue;
                    }
                    Err(_retry_err) => {
                        tracing::debug!("stateless retry could not be issued; dropping");
                        continue;
                    }
                }
            }

            if let Some(rl) = rate_limiter.as_ref() {
                let remote_ip = incoming.remote_address().ip();
                if !rl.check(remote_ip) {
                    tracing::debug!("handshake rate-limited; dropping");
                    incoming.refuse();
                    continue;
                }
            }

            let sem = handshake_semaphore.clone();
            let in_flight = self.max_concurrent_handshakes - sem.available_permits();
            if in_flight > 0 {
                tracing::debug!(in_flight, "handshakes in flight");
            }
            let permit = sem.acquire_owned().await;
            let Ok(permit) = permit else {
                break;
            };

            // Pin this connection's uplink (QUIC->TUN) pump to one queue,
            // round-robin, so writes from concurrent connections land on
            // different kernel queues instead of serializing on a single fd.
            let queue_idx = uplink_queue_cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % queues.len();
            let tun_for_task = queues[queue_idx].clone();
            let sess = sessions.clone();
            let sess_for_daita = sessions.clone();
            let sess_for_cleanup = sessions.clone();
            let alloc = allocator.clone();
            let alloc_v6 = allocator_v6.clone();
            let alloc_for_cleanup = allocator.clone();
            let alloc_v6_for_cleanup = allocator_v6.clone();
            let sf = state_persister.clone();
            let sf_for_cleanup = state_persister.clone();
            let lpk = local_pubkey;
            let skey = signing_key.clone();
            let al = allowlist.clone();
            let dp = daita_pool.clone();
            let ac = active_conns.clone();
            let ac_for_cleanup = active_conns.clone();
            let mr = metrics_reg.clone();
            let ul = uplink_global.clone();
            let dt = dispatch_table.clone();
            let dc = device_cap.clone();
            let ta = token_admitter.clone();
            let uh = unauthenticated_handler.clone();
            let dr = drain_rx.clone();

            tokio::spawn(async move {
                let handshake_result = tokio::time::timeout(
                    Duration::from_secs(warrenguard_config::WARREN_HANDSHAKE_TIMEOUT_SECS),
                    Self::handshake_from_incoming(
                        incoming,
                        sess,
                        alloc,
                        alloc_v6,
                        sf,
                        lpk,
                        skey,
                        al,
                        dp,
                        ac,
                        dc,
                        ta,
                        uh,
                        dr.clone(),
                    ),
                )
                .await;
                // The semaphore bounds concurrent HANDSHAKES only.
                // Holding the permit across the pump would cap live
                // sessions at `max_concurrent_handshakes` and freeze
                // the accept loop once that many clients stay
                // connected.
                drop(permit);

                let (conn, session_key, client_ip, client_ipv6) = match handshake_result {
                    Ok(Ok(c)) => {
                        // No-log: never log the client's real source IP
                        // (CLAUDE.md § 6). Identify the session by the
                        // already-truncated pubkey Debug and the internal
                        // tunnel IP only.
                        tracing::info!(
                            client = ?c.1.0,
                            tunnel_ip = %c.2,
                            "client handshake OK"
                        );
                        c
                    }
                    Ok(Err(TunnelError::DivertedToDecoy)) => {
                        // Expected, not a failure: an unauthenticated
                        // connection was handed to the decoy handler.
                        tracing::debug!("connection diverted to the decoy handler");
                        return;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(
                            timeout_secs = warrenguard_config::WARREN_HANDSHAKE_TIMEOUT_SECS,
                            "handshake exceeded cap; dropping connection"
                        );
                        return;
                    }
                };

                // `client_id` is the bare pubkey used by the metrics
                // registry, dispatch table and pump APIs (all keyed by
                // identity). `session_key` is the full `(pubkey,
                // device_id)` used to look the session up in the map.
                let client_id = session_key.0;

                // Build shared DAITA state (if enabled for this client).
                let daita_spec = {
                    let map = sess_for_daita.lock().await;
                    map.get(&session_key).and_then(|s| s.daita_spec.clone())
                };
                let shared_daita = match daita_spec.as_ref() {
                    Some(cfg) if cfg.is_enabled() => {
                        match warrenguard_daita::daita::DaitaState::from_config(
                            cfg,
                            std::time::Instant::now(),
                        ) {
                            Ok(state) => {
                                Some(Arc::new(crate::tun_dispatch::SharedDaitaState::new(state)))
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "failed to build DaitaState; running without DAITA"
                                );
                                None
                            }
                        }
                    }
                    _ => None,
                };

                let client_metrics = mr.register(client_id);

                // Drain signalling: park on the exit-wide drain watch and,
                // once the exit is marked draining, emit the in-band
                // ExitDraining control datagram until the deadline, then
                // hard-close (see `exit::drain`). `None` when no drain watch
                // is wired.
                let drain_task = super::drain::spawn_drain_emitter(dr, conn.clone());

                // Register in the centralized TUN downlink dispatcher.
                let slot_conns = dt.register(
                    client_ip,
                    client_ipv6,
                    conn.clone(),
                    client_id,
                    shared_daita.clone(),
                    Some(client_metrics.clone()),
                );

                // Per-connection transport probe (self-terminates
                // when the conn closes). The app counters (session-wide,
                // shared per identity) are attached ONLY to the session's
                // first connection: with N probes each diffing the same
                // shared counters, every probe would report the full
                // session-wide app delta against its own single-conn wire
                // count and fake a permanent send-buffer-drop gap.
                let probe_app = (slot_conns <= 1).then(|| client_metrics.clone());
                drop(warrenguard_transport_core::path_probe::spawn_path_probe(
                    "exit",
                    vec![conn.clone()],
                    probe_app,
                ));

                // Per-connection pump: QUIC->TUN direction only.
                // TUN->QUIC is handled by the centralized dispatcher.
                let cm = Some(client_metrics);
                let res = match shared_daita {
                    Some(daita) => {
                        crate::tun_dispatch::pump_quic_to_tun_with_daita(
                            conn.clone(),
                            tun_for_task,
                            daita,
                            ul,
                            client_id,
                            client_ip,
                            client_ipv6,
                            cm,
                        )
                        .await
                    }
                    None => {
                        if let Some(ul_limiter) = ul {
                            warrenguard_pump::pump_quic_to_tun_rate_limited(
                                conn.clone(),
                                tun_for_task,
                                ul_limiter,
                                client_id,
                                client_ip,
                                client_ipv6,
                                cm,
                            )
                            .await
                        } else {
                            warrenguard_pump::pump_quic_to_tun(
                                conn.clone(),
                                tun_for_task,
                                Some((client_ip, client_ipv6)),
                                cm,
                            )
                            .await
                        }
                    }
                };
                if let Err(e) = res {
                    tracing::warn!(error = %e, "pump session ended");
                }

                // The drain emitter may still be parked on the watch (no
                // drain ever came) or sleeping between re-emits; the watch
                // sender outlives every connection, so without this abort
                // the task would leak per closed connection. Join it so a
                // deadline hard-close in flight settles before the cleanup
                // below.
                if let Some(t) = drain_task {
                    t.abort();
                    let _ = t.await;
                }

                // Cleanup: remove this connection from the dispatch table
                // and release its metrics registration (refcounted: the
                // shared entry survives while sibling conns are live).
                dt.unregister(client_ip, client_ipv6, &conn);
                let _ = mr.unregister(&client_id);

                // Last-connection eviction: when no sibling connection
                // of this `(pubkey, device_id)` session remains, the
                // session entry is removed and its tunnel IPs return to
                // the recycling allocators (sticky hint kept so an
                // immediate reconnect prefers the same addresses).
                release_connection_and_maybe_session(
                    &sess_for_cleanup,
                    &ac_for_cleanup,
                    &alloc_for_cleanup,
                    &alloc_v6_for_cleanup,
                    &sf_for_cleanup,
                    session_key,
                    &conn,
                )
                .await;
            });
        }

        downlink_readers.abort_all();
        while downlink_readers.join_next().await.is_some() {}
        Ok(())
    }

    /// Test-only helper: accepts ONE connection + handshake and returns
    /// the `Connection` to the caller. Takes `&self` to avoid dropping
    /// the underlying endpoint (otherwise the `Connection` becomes
    /// orphaned).
    ///
    /// **Internal 30 s timeout**: if the client never connects (test
    /// panicking before `client.connect_multi`, or stuck in another
    /// helper), `endpoint.accept().await` would block forever, leaving
    /// the test binary at 100 % CPU until reboot. Cf. CLAUDE.md § 4
    /// "Orphan post-test processes".
    ///
    /// # Errors
    ///
    /// See [`Self::accept_one`]. Plus an
    /// `accept_one_handshake_for_test timeout` variant if the client
    /// does not connect within 30 s.
    pub async fn accept_one_handshake_for_test(&self) -> Result<quinn::Connection> {
        let (conn, _) = self.handshake_only_retrying().await?;
        Ok(conn)
    }
}
