//! Shared loopback QUIC helpers for this crate's unit tests.
//!
//! Building a protocol-correct fake exit (relay descriptor PKI, TLS RPK
//! dial, HPKE setup-over-stream) is overkill for exercising the pump /
//! bundle / supervisor plumbing: those only need a live
//! [`crate::multihop::MultiHopClient`] wired directly onto an established
//! QUIC connection (skipping [`crate::multihop::MultiHopClient::connect`]'s
//! relay-descriptor verification and dial) plus a matching exit-side
//! [`ExitSession`] so a downlink test can seal frames the client can
//! actually open. `cfg(test)`-only; `pub(crate)` so every test module in
//! this crate can share one implementation instead of four near-duplicates.
//! (Module itself is gated `#[cfg(test)]` at the `mod test_support;`
//! declaration in `lib.rs`.)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use quinn::{Connection, Endpoint};
use warrenguard_multihop::{
    ExitId, ExitSession, RelayDescriptorSigned, WarrenControlMessage, decode_frame, encode_control,
    encode_frame, relay_descriptor_signing_payload, test_support::derive_exit_keypair,
};
#[cfg(feature = "pq-hpke")]
use warrenguard_multihop::{
    PqExitSession, XWingRecipientSecretKey, decode_frame_v2, encode_frame_v2,
};
use warrenguard_wire::WarrenPubkey;

#[cfg(feature = "pq-hpke")]
use crate::multihop::client_pq_setup_material_for_test;
use crate::multihop::{MultiHopClient, client_encapsulated_key_for_test};

/// A loopback multi-hop pair: a real client-side [`MultiHopClient`] plus
/// the raw server-side [`Connection`] and matching [`ExitSession`] needed
/// to drive the exit side of the HPKE session in a test (seal downlink
/// frames, read raw uplink datagrams, or just close the connection to
/// exercise the reader's error path). Endpoints are kept alive on the
/// struct: dropping them tears down the underlying UDP sockets.
pub(crate) struct LoopbackMultiHop {
    pub(crate) client: Arc<MultiHopClient>,
    pub(crate) exit_conn: Connection,
    pub(crate) exit_session: ExitSession,
    exit_id: ExitId,
    exit_priv: warrenguard_multihop::WarrenKemPrivateKey,
    _client_ep: Endpoint,
    _server_ep: Endpoint,
}

impl LoopbackMultiHop {
    /// Rebuilds [`Self::exit_session`] from the client's CURRENT
    /// `encapsulated_key`. A real exit re-derives its receiver context on
    /// seeing a fresh epoch's first frame; call this right after
    /// [`crate::multihop::MultiHopClient::rekey`] so a subsequent
    /// `exit_session.seal_response(..)` produces a downlink frame the
    /// client's NEW epoch can decrypt (exercising the rekey round-trip
    /// rather than only the client-local counter rotation).
    pub(crate) fn rebuild_exit_session_for_current_epoch(&mut self) {
        let encapsulated_key = client_encapsulated_key_for_test(&self.client);
        self.exit_session = ExitSession::new(&self.exit_priv, &encapsulated_key, self.exit_id)
            .expect("exit-side session rebuild after rekey");
    }

    /// Spawns a task that answers exactly one classical (`/v1`)
    /// `setup_over_stream` round trip on `exit_conn`, establishing the
    /// exit-side session from the request frame and replying with a trivial
    /// `IpAssign`. The `/v1` twin of
    /// [`LoopbackMultiHopPq::spawn_setup_stream_server`], for a test that needs
    /// epoch 0 to go through the real reliable-stream admission path.
    pub(crate) fn spawn_setup_stream_server(&self) -> tokio::task::JoinHandle<()> {
        let exit_conn = self.exit_conn.clone();
        let exit_id = self.exit_id;
        tokio::spawn(async move {
            let (mut send, mut recv) = exit_conn.accept_bi().await.expect("accept_bi");
            let bytes = recv
                .read_to_end(crate::multihop::MAX_MULTIHOP_SETUP_FRAME_BYTES)
                .await
                .expect("read request");
            let frame = decode_frame(&bytes).expect("decode v1 setup frame");
            // Same fixed IKM `spawn_loopback_multihop` derives its exit key
            // from: deterministic, so re-deriving here (rather than threading
            // the non-Clone zeroize-on-drop private key through the task)
            // yields the identical key.
            let (exit_priv, _exit_pub) = derive_exit_keypair(&[0x99; 32]);
            let exit_session = ExitSession::new(&exit_priv, &frame.encapsulated_key, exit_id)
                .expect("exit establishes the session from the setup frame");
            let _plaintext = exit_session.open(&frame).expect("exit opens setup frame");
            let reply_msg = WarrenControlMessage::IpAssign {
                ipv4: [10, 66, 0, 2],
                prefix_len: 24,
                gateway_ipv4: [10, 66, 0, 1],
                ipv6: None,
                prefix_len_v6: 0,
                gateway_ipv6: None,
                daita_spec: None,
            };
            let reply_plaintext = encode_control(&reply_msg).expect("encode reply");
            let reply_frame = exit_session
                .seal_response(&reply_plaintext, frame.epoch, frame.seq)
                .expect("seal reply");
            let reply_wire = encode_frame(&reply_frame).expect("encode reply frame");
            send.write_all(&reply_wire).await.expect("write reply");
            let _ = send.finish();
        })
    }
}

/// Bare RPK loopback QUIC bootstrap (no relay-auth proof, no setup-stream
/// exchange, no multi-hop semantics at all): TLS server + client endpoints
/// on a fixed RPK identity, connected. Shared by [`spawn_loopback_multihop`]
/// and its PQ twin [`spawn_loopback_multihop_pq`], which differ only in
/// which HPKE session they build over the resulting connection.
/// `tls_key_seed` fixes the server's RPK identity byte so concurrently
/// running loopback tests never collide on it. `transport_config`, when
/// `Some`, is applied to BOTH endpoints (needed by the PQ variant: Quinn's
/// unconfigured default initial MTU is too small for a `/v2` setup frame's
/// 1088-byte `pq_ct`); `None` keeps Quinn's absolute defaults, matching the
/// classical loopback's behavior before this helper was shared.
async fn bare_rpk_loopback(
    tls_key_seed: u8,
    transport_config: Option<Arc<quinn::TransportConfig>>,
    allow_migration: bool,
) -> (Endpoint, Connection, Connection, Endpoint) {
    let tls_key = SigningKey::from_bytes(&[tls_key_seed; 32]);
    let mut server_cfg = warrenguard_tls::make_server_config(
        &tls_key,
        warrenguard_tls::default_crypto_provider(),
        &[warrenguard_config::ALPN_H3],
    )
    .expect("server cfg");
    if allow_migration {
        // The client's QUIC peer is the RELAY, which re-enables migration on
        // top of the exit-flavoured `make_server_config` default; a server that
        // forbids it discards every packet from a new 4-tuple, close frames
        // included, so a migration test on the default fixture would observe
        // the fixture's policy rather than the client's behaviour.
        server_cfg.migration(true);
    }
    if let Some(cfg) = &transport_config {
        server_cfg.transport_config(cfg.clone());
    }
    let server_ep = Endpoint::server(
        server_cfg,
        "127.0.0.1:0".parse().expect("static addr parses"),
    )
    .expect("server bind");
    let addr = server_ep.local_addr().expect("local addr");

    let server_for_accept = server_ep.clone();
    let accept = tokio::spawn(async move {
        let incoming = server_for_accept.accept().await.expect("incoming");
        incoming.await.expect("server handshake")
    });

    let mut client_cfg = warrenguard_tls::make_client_config(
        warrenguard_tls::default_crypto_provider(),
        &[warrenguard_config::ALPN_H3],
    )
    .expect("client cfg");
    if let Some(cfg) = transport_config {
        client_cfg.transport_config(cfg);
    }
    let mut client_ep =
        Endpoint::client("127.0.0.1:0".parse().expect("static addr parses")).expect("client bind");
    client_ep.set_default_client_config(client_cfg);
    let sni =
        warrenguard_tls::name::encode(WarrenPubkey::from_bytes(tls_key.verifying_key().to_bytes()));
    let client_conn = client_ep
        .connect(addr, &sni)
        .expect("connect builds")
        .await
        .expect("client handshake");

    let exit_conn = accept.await.expect("server accept task");
    (client_ep, client_conn, exit_conn, server_ep)
}

/// Spins up a bare RPK loopback QUIC connection (no relay-auth proof, no
/// setup-stream exchange) and wraps the client side as a
/// [`MultiHopClient`] via [`MultiHopClient::from_established_connection`].
/// The returned [`ExitSession`] is built from the client's own
/// `encapsulated_key`, so `exit_session.seal_response(..)` produces frames
/// `client.recv()` can decrypt, exactly mirroring a real exit's reverse
/// direction without paying for the setup-stream round-trip.
pub(crate) async fn spawn_loopback_multihop(exit_id: ExitId) -> LoopbackMultiHop {
    spawn_loopback_multihop_inner(exit_id, None, false).await
}

/// [`spawn_loopback_multihop`] with a peer that accepts address migration, the
/// way the production relay does: needed by any test that rebinds the client
/// endpoint and then expects the peer to still receive what it sends.
pub(crate) async fn spawn_loopback_multihop_migratable(exit_id: ExitId) -> LoopbackMultiHop {
    spawn_loopback_multihop_inner(exit_id, None, true).await
}

/// [`spawn_loopback_multihop`] with an explicit QUIC transport config on both
/// ends, so a test can drive a specific path MTU (e.g. the Warren multi-hop
/// profile's 1280 initial MTU) rather than quinn's default.
pub(crate) async fn spawn_loopback_multihop_with_transport(
    exit_id: ExitId,
    transport_config: Option<Arc<quinn::TransportConfig>>,
) -> LoopbackMultiHop {
    spawn_loopback_multihop_inner(exit_id, transport_config, false).await
}

async fn spawn_loopback_multihop_inner(
    exit_id: ExitId,
    transport_config: Option<Arc<quinn::TransportConfig>>,
    allow_migration: bool,
) -> LoopbackMultiHop {
    let (client_ep, client_conn, exit_conn, server_ep) =
        bare_rpk_loopback(0x77, transport_config, allow_migration).await;

    let (exit_priv, exit_pub) = derive_exit_keypair(&[0x99; 32]);
    let exit_pub_bytes = warrenguard_multihop::test_support::pubkey_to_bytes(&exit_pub);

    let client = Arc::new(
        MultiHopClient::from_established_connection(
            client_ep.clone(),
            client_conn,
            exit_id,
            &exit_pub_bytes,
            None,
        )
        .expect("client-side HPKE session setup"),
    );

    let encapsulated_key = client_encapsulated_key_for_test(&client);
    let exit_session =
        ExitSession::new(&exit_priv, &encapsulated_key, exit_id).expect("exit-side session setup");

    LoopbackMultiHop {
        client,
        exit_conn,
        exit_session,
        exit_id,
        exit_priv,
        _client_ep: client_ep,
        _server_ep: server_ep,
    }
}

/// PQ (`/v2` X-Wing) twin of [`LoopbackMultiHop`].
#[cfg(feature = "pq-hpke")]
pub(crate) struct LoopbackMultiHopPq {
    pub(crate) client: Arc<MultiHopClient>,
    pub(crate) exit_conn: Connection,
    pub(crate) exit_session: PqExitSession,
    exit_id: ExitId,
    exit_secret: XWingRecipientSecretKey,
    _client_ep: Endpoint,
    _server_ep: Endpoint,
}

#[cfg(feature = "pq-hpke")]
impl LoopbackMultiHopPq {
    /// Rebuilds [`Self::exit_session`] from the client's CURRENT
    /// `(encapsulated_key, pq_ct)`. Mirror of
    /// [`LoopbackMultiHop::rebuild_exit_session_for_current_epoch`] for the
    /// `/v2` session: call right after
    /// [`crate::multihop::MultiHopClient::rekey`] so a subsequent
    /// `exit_session.seal_response(..)` targets the NEW epoch's session
    /// rather than the stale one.
    pub(crate) fn rebuild_exit_session_for_current_epoch(&mut self) {
        let (encapsulated_key, pq_ct) = client_pq_setup_material_for_test(&self.client);
        self.exit_session =
            PqExitSession::new(&self.exit_secret, &encapsulated_key, &pq_ct, self.exit_id)
                .expect("pq exit-side session rebuild after rekey");
    }

    /// Spawns a task that answers exactly one `setup_over_stream` round trip
    /// on `exit_conn`: establishes the exit-side PQ session from the request
    /// frame's `(encapsulated_key, pq_ct)` and replies with a trivial
    /// `IpAssign`. For a test that needs epoch 0 to go through the real
    /// reliable-stream admission path instead of being pre-seeded via
    /// `client_pq_setup_material_for_test`.
    pub(crate) fn spawn_setup_stream_server(&self) -> tokio::task::JoinHandle<()> {
        self.spawn_setup_stream_server_with_reply(WarrenControlMessage::IpAssign {
            ipv4: [10, 88, 0, 2],
            prefix_len: 24,
            gateway_ipv4: [10, 88, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        })
    }

    /// As [`Self::spawn_setup_stream_server`], but the exit replies with an
    /// arbitrary control message (e.g. a `Rejected` refusal) so a test can
    /// exercise the non-`IpAssign` setup-reply paths, where the best-effort
    /// `IpAssignment` capture must leave `assignment()` unset without failing
    /// the round trip.
    pub(crate) fn spawn_setup_stream_server_with_reply(
        &self,
        reply_msg: WarrenControlMessage,
    ) -> tokio::task::JoinHandle<()> {
        let exit_conn = self.exit_conn.clone();
        let exit_id = self.exit_id;
        tokio::spawn(async move {
            let (mut send, mut recv) = exit_conn.accept_bi().await.expect("accept_bi");
            let bytes = recv
                .read_to_end(crate::multihop::MAX_MULTIHOP_SETUP_FRAME_BYTES)
                .await
                .expect("read request");
            let frame = decode_frame_v2(&bytes).expect("decode v2 setup frame");
            // Same fixed seed `spawn_loopback_multihop_pq` derives its exit
            // secret from: deterministic, so re-deriving here (rather than
            // moving or cloning `self.exit_secret`, which does not
            // implement `Clone` by design as a zeroize-on-drop secret)
            // yields the identical key.
            let (exit_secret, _exit_pub) = XWingRecipientSecretKey::derive_deterministic(
                &[0xA1; 32],
                &[0xA2; 32],
                &[0xA3; 32],
            );
            let exit_session =
                PqExitSession::new(&exit_secret, &frame.encapsulated_key, &frame.pq_ct, exit_id)
                    .expect("exit establishes the pq session from the setup frame");
            let _plaintext = exit_session.open(&frame).expect("exit opens setup frame");
            let reply_plaintext = encode_control(&reply_msg).expect("encode reply");
            let reply_frame = exit_session
                .seal_response(&reply_plaintext, frame.epoch, frame.seq)
                .expect("seal reply");
            let reply_wire = encode_frame_v2(&reply_frame).expect("encode reply frame");
            send.write_all(&reply_wire).await.expect("write reply");
            let _ = send.finish();
        })
    }
}

/// PQ (`/v2` X-Wing) twin of [`spawn_loopback_multihop`]: same bare RPK QUIC
/// bootstrap, but the client is built via
/// [`MultiHopClient::from_established_connection_pq`] (`require_pq = true`,
/// so a broken test fixture fails loudly instead of silently falling back to
/// `/v1`) and the exit side is a [`PqExitSession`] derived from a
/// deterministic X-Wing recipient keypair.
#[cfg(feature = "pq-hpke")]
pub(crate) async fn spawn_loopback_multihop_pq(exit_id: ExitId) -> LoopbackMultiHopPq {
    // Quinn's unconfigured default initial MTU cannot fit a `/v2` setup
    // frame (1088-byte `pq_ct`); the multihop client transport config
    // raises it to `TUNNEL_INITIAL_MTU` (1280) with no Initial-padding
    // knobs (irrelevant to a bare loopback), reused on both endpoints since
    // only the MTU floor matters here, not the stream/buffer tuning that
    // differs between the real client and exit profiles.
    let (client_ep, client_conn, exit_conn, server_ep) = bare_rpk_loopback(
        0x78,
        Some(warrenguard_transport_core::warren_transport_config_client_multihop_with_gso(false)),
        false,
    )
    .await;

    let (exit_secret, exit_pub) =
        XWingRecipientSecretKey::derive_deterministic(&[0xA1; 32], &[0xA2; 32], &[0xA3; 32]);
    let mlkem_ek = exit_pub.mlkem768_ek_bytes();
    let exit_x25519_pubkey = *exit_pub.x25519_pubkey();

    let client = Arc::new(
        MultiHopClient::from_established_connection_pq(
            client_ep.clone(),
            client_conn,
            exit_id,
            &exit_x25519_pubkey,
            &mlkem_ek,
            true,
            None,
        )
        .expect("client-side PQ HPKE session setup"),
    );

    let (encapsulated_key, pq_ct) = client_pq_setup_material_for_test(&client);
    let exit_session = PqExitSession::new(&exit_secret, &encapsulated_key, &pq_ct, exit_id)
        .expect("exit-side PQ session setup");

    LoopbackMultiHopPq {
        client,
        exit_conn,
        exit_session,
        exit_id,
        exit_secret,
        _client_ep: client_ep,
        _server_ep: server_ep,
    }
}

/// A loopback fake relay+exit that speaks the real wire protocol
/// [`crate::multihop::MultiHopClient::connect`] expects: a properly-signed
/// [`RelayDescriptorSigned`] pinned by TLS RPK, and the HPKE
/// setup-over-stream round-trip. One process plays both the relay (the TLS
/// identity the client dials) and the exit (the HPKE session the setup
/// frame is addressed to): the supervisor's dial path cannot tell the
/// difference from a real two-hop deployment, since the multi-hop wire
/// protocol is end-to-end between client and exit regardless of what sits
/// in between.
///
/// Drives [`crate::supervisor::MultiHopSupervisor::run`] end-to-end without
/// a live network, so the supervisor's cold-dial, reconnect, and
/// setup-rejection paths get real coverage instead of only the pure
/// `dummy_config`-gated unit tests.
pub(crate) struct FakeMultihopExit {
    pub(crate) relay: Arc<RelayDescriptorSigned>,
    pub(crate) exit_id: ExitId,
    pub(crate) exit_x25519_pubkey: [u8; 32],
    /// Number of connections accepted so far (post TLS handshake), so a
    /// test can assert a redial actually reached the exit again.
    pub(crate) accepted: Arc<AtomicUsize>,
    /// When set, every subsequent setup reply is a sealed `Rejected`
    /// detail instead of an `IpAssign`.
    pub(crate) reject: Arc<AtomicBool>,
    /// When set, every subsequent setup reply is a sealed `RejectedBanned`
    /// detail (takes precedence over `reject`), so a test can drive the
    /// client's ban-vs-not-authorized decode path.
    pub(crate) reject_banned: Arc<AtomicBool>,
    /// Product reason code sealed into the `RejectedBanned` reply when
    /// `reject_banned` is set, so a test can assert the code reaches the
    /// client's `RejectionReason::Banned` intact.
    pub(crate) ban_reason_code: Arc<AtomicU8>,
    _server_ep: Endpoint,
}

const FAKE_EXIT_IKM: [u8; 32] = [0x99; 32];

/// Handles exactly one accepted connection's setup-stream round-trip, then
/// idles reading (and discarding) datagrams until the connection dies so the
/// supervisor's serve loop has a live peer to race against.
async fn serve_one_fake_exit_connection(
    conn: Connection,
    exit_id: ExitId,
    reject: Arc<AtomicBool>,
    reject_banned: Arc<AtomicBool>,
    ban_reason_code: Arc<AtomicU8>,
) {
    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
        return;
    };
    let Ok(bytes) = recv.read_to_end(64 * 1024).await else {
        return;
    };
    let Ok(frame) = decode_frame(&bytes) else {
        return;
    };
    // Deterministic re-derivation instead of threading a `Clone` private
    // key through the task: cheap, and keeps the exit identity anchored to
    // one constant so every connection (including a redial) opens against
    // the same recipient key the client's `exit_x25519_pubkey` pins.
    let (exit_priv, _exit_pub) = derive_exit_keypair(&FAKE_EXIT_IKM);
    let Ok(exit_session) = ExitSession::new(&exit_priv, &frame.encapsulated_key, exit_id) else {
        return;
    };
    if exit_session.open(&frame).is_err() {
        return;
    }
    let reply_msg = if reject_banned.load(Ordering::Relaxed) {
        WarrenControlMessage::RejectedBanned {
            reason_code: ban_reason_code.load(Ordering::Relaxed),
        }
    } else if reject.load(Ordering::Relaxed) {
        WarrenControlMessage::Rejected
    } else {
        WarrenControlMessage::IpAssign {
            ipv4: [10, 77, 0, 2],
            prefix_len: 24,
            gateway_ipv4: [10, 77, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        }
    };
    let Ok(plaintext) = encode_control(&reply_msg) else {
        return;
    };
    let Ok(reply_frame) = exit_session.seal_response(&plaintext, 0, 0) else {
        return;
    };
    let Ok(wire) = encode_frame(&reply_frame) else {
        return;
    };
    if send.write_all(&wire).await.is_err() {
        return;
    }
    let _ = send.finish();

    loop {
        if conn.read_datagram().await.is_err() {
            return;
        }
    }
}

/// Spawns the fake relay+exit and returns the descriptor + control handles
/// a [`crate::supervisor::SupervisorConfig`] plugs straight into.
/// `operational_key` must be the signing counterpart of the
/// `operational_pubkey` the supervisor is configured with, or the relay
/// descriptor fails PKI verification before any dial happens.
pub(crate) fn spawn_fake_multihop_exit(
    operational_key: &SigningKey,
    exit_id: ExitId,
) -> FakeMultihopExit {
    let relay_tls_key = SigningKey::from_bytes(&[0x66; 32]);
    let relay_id = [0xAA; 16];
    let relay_pubkey = relay_tls_key.verifying_key().to_bytes();
    let signature = operational_key
        .sign(&relay_descriptor_signing_payload(&relay_id, &relay_pubkey))
        .to_bytes();

    let server_cfg = warrenguard_tls::make_server_config(
        &relay_tls_key,
        warrenguard_tls::default_crypto_provider(),
        &[warrenguard_config::ALPN_H3],
    )
    .expect("server cfg");
    let server_ep = Endpoint::server(
        server_cfg,
        "127.0.0.1:0".parse().expect("static addr parses"),
    )
    .expect("server bind");
    let addr = server_ep.local_addr().expect("local addr");

    let relay = Arc::new(RelayDescriptorSigned {
        relay_id,
        relay_ed25519_pubkey: relay_pubkey,
        endpoint: addr,
        cover_domain: None,
        tcp_fallback: false,
        signature,
    });

    let (_exit_priv, exit_pub) = derive_exit_keypair(&FAKE_EXIT_IKM);
    let exit_x25519_pubkey = warrenguard_multihop::test_support::pubkey_to_bytes(&exit_pub);

    let accepted = Arc::new(AtomicUsize::new(0));
    let reject = Arc::new(AtomicBool::new(false));
    let reject_banned = Arc::new(AtomicBool::new(false));
    let ban_reason_code = Arc::new(AtomicU8::new(0));

    let accept_loop_ep = server_ep.clone();
    let accept_loop_accepted = accepted.clone();
    let accept_loop_reject = reject.clone();
    let accept_loop_reject_banned = reject_banned.clone();
    let accept_loop_ban_reason_code = ban_reason_code.clone();
    tokio::spawn(async move {
        loop {
            let Some(incoming) = accept_loop_ep.accept().await else {
                return;
            };
            let Ok(conn) = incoming.await else {
                continue;
            };
            accept_loop_accepted.fetch_add(1, Ordering::Relaxed);
            serve_one_fake_exit_connection(
                conn,
                exit_id,
                accept_loop_reject.clone(),
                accept_loop_reject_banned.clone(),
                accept_loop_ban_reason_code.clone(),
            )
            .await;
        }
    });

    FakeMultihopExit {
        relay,
        exit_id,
        exit_x25519_pubkey,
        accepted,
        reject,
        reject_banned,
        ban_reason_code,
        _server_ep: server_ep,
    }
}
