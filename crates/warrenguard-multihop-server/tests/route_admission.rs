//! Route admission by anchor through the real exit termination loop, over
//! loopback QUIC with the real HPKE seals: a v7 main session anchors with an
//! uplink datagram, a route session on another exit is admitted on its
//! locator, refused with its sealed code, or ended when its anchor goes.
//!
//! The policy is a fake control plane holding a real route KEM key: it opens
//! the blobs exactly as the API does, with the exit's own id as the locator's
//! associated data, so a locator sealed for another exit fails for real.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use parking_lot::Mutex;
use quinn::{Connection, Endpoint};
use warrenguard_multihop::{
    ClientSession, ExitId, RouteAnchorSecret, RouteAnchorStatus, RouteKemSecretKey,
    RouteRejectCode, SealedToApi, WARREN_MH_REJECTED, WarrenControlMessage, WarrenKemPublicKey,
    decode_frame, encode_control, encode_frame, seal_route_anchor, seal_route_locator,
    try_decode_control,
};
use warrenguard_multihop_server::ip_pool::IpAllocator;
use warrenguard_multihop_server::multihop::{
    ExitTerminateCtx, MultihopSessionRegistry, SetupSource, derive_x25519_keypair,
    terminate_connection,
};
use warrenguard_server::{
    AnchorVerdict, BoxFuture, RouteAdmission, RouteAdmitter, SessionTokenAdmitter, TokenAdmission,
};
use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken, WarrenPubkey};

const MAX_ROUTES: u16 = 32;

/// The control plane's anchor table, shared by every exit of a test.
#[derive(Default)]
struct Anchors(Mutex<HashMap<[u8; 32], [u8; 32]>>);

/// A fake control plane for one exit: opens with a real route KEM key.
struct FakeApi {
    key: Arc<RouteKemSecretKey>,
    exit_id: ExitId,
    anchors: Arc<Anchors>,
    route_calls: AtomicUsize,
}

impl RouteAdmitter for FakeApi {
    fn admit_route<'a>(&'a self, locator: &'a SealedToApi) -> BoxFuture<'a, RouteAdmission> {
        Box::pin(async move {
            self.route_calls.fetch_add(1, Ordering::AcqRel);
            let Ok(secret) = self.key.open_locator(locator, &self.exit_id) else {
                return RouteAdmission::Refuse(RouteRejectCode::Unspecified);
            };
            let a = secret.anchor_ref();
            if self.anchors.0.lock().contains_key(a.as_bytes()) {
                RouteAdmission::Admit {
                    route_serial: a.route_serial(&self.exit_id),
                }
            } else {
                RouteAdmission::Refuse(RouteRejectCode::AnchorUnknown)
            }
        })
    }

    fn anchor<'a>(
        &'a self,
        lease_serial: &'a [u8; 32],
        sealed_anchor: &'a SealedToApi,
    ) -> BoxFuture<'a, AnchorVerdict> {
        Box::pin(async move {
            match self.key.open_anchor(sealed_anchor, lease_serial) {
                Ok(secret) => {
                    self.anchors
                        .0
                        .lock()
                        .insert(*secret.anchor_ref().as_bytes(), *lease_serial);
                    AnchorVerdict {
                        status: RouteAnchorStatus::Bound,
                        max_routes: MAX_ROUTES,
                    }
                }
                Err(_) => AnchorVerdict::status(RouteAnchorStatus::Refused),
            }
        })
    }
}

/// Admits any token on the serial of its first 32 bytes.
struct FakeTokens;

impl SessionTokenAdmitter for FakeTokens {
    fn admit<'a>(&'a self, tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
        Box::pin(async move {
            let mut serial = [0u8; 32];
            serial.copy_from_slice(&tokens[0].0[..32]);
            TokenAdmission::Admit { serial }
        })
    }

    fn renew_live<'a>(&'a self, _: &'a [[u8; 32]]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

struct Exit {
    addr: std::net::SocketAddr,
    sni: String,
    exit_id: ExitId,
    exit_pub: WarrenKemPublicKey,
    registry: Arc<MultihopSessionRegistry>,
    api: Option<Arc<FakeApi>>,
    _endpoint: Endpoint,
    accept: tokio::task::JoinHandle<()>,
}

impl Drop for Exit {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

fn spawn_exit(
    seed: u8,
    kem: &Arc<RouteKemSecretKey>,
    anchors: &Arc<Anchors>,
    with_policy: bool,
) -> Exit {
    let exit_key = SigningKey::from_bytes(&[seed; 32]);
    let (privkey, exit_pub) = derive_x25519_keypair(&[seed; 32]).expect("x25519 keypair");
    let exit_id = ExitId::from_bytes([seed; 16]);
    let registry = MultihopSessionRegistry::new();
    let api = with_policy.then(|| {
        Arc::new(FakeApi {
            key: Arc::clone(kem),
            exit_id,
            anchors: Arc::clone(anchors),
            route_calls: AtomicUsize::new(0),
        })
    });
    let pool = Arc::new(Mutex::new(
        IpAllocator::new(Ipv4Addr::new(10, 66, 0, 0), 24, Ipv4Addr::new(10, 66, 0, 1))
            .expect("pool"),
    ));
    let ctx = ExitTerminateCtx::new(
        privkey,
        exit_id,
        warrenguard_transport_core::FakeTun::new(),
        None,
        None,
        pool,
        None,
        None,
    )
    .with_session_registry(Arc::clone(&registry))
    .with_token_admitter(Some(Arc::new(FakeTokens)))
    .with_route_admitter(api.clone().map(|a| a as Arc<dyn RouteAdmitter>));
    let provider = warrenguard_tls::default_crypto_provider();
    let server_cfg =
        warrenguard_tls::make_server_config(&exit_key, provider, &[warrenguard_config::ALPN_H3])
            .expect("server config");
    let endpoint =
        Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).expect("server binds");
    let addr = endpoint.local_addr().expect("addr");
    let listen = endpoint.clone();
    let accept = tokio::spawn(async move {
        while let Some(incoming) = listen.accept().await {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    terminate_connection(conn, SetupSource::AcceptFromConn, ctx).await;
                }
            });
        }
    });
    Exit {
        addr,
        sni: warrenguard_tls::name::encode(WarrenPubkey::from_bytes(
            *exit_key.verifying_key().as_bytes(),
        )),
        exit_id,
        exit_pub,
        registry,
        api,
        _endpoint: endpoint,
        accept,
    }
}

/// One client connection with its HPKE session and its next uplink seq.
struct Client {
    _endpoint: Endpoint,
    conn: Connection,
    session: ClientSession,
    seq: u64,
}

impl Client {
    async fn dial(exit: &Exit) -> Self {
        let provider = warrenguard_tls::default_crypto_provider();
        let cfg = warrenguard_tls::make_client_config(provider, &[warrenguard_config::ALPN_H3])
            .expect("client config");
        let mut endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client binds");
        endpoint.set_default_client_config(cfg);
        let conn = endpoint
            .connect(exit.addr, &exit.sni)
            .expect("connect")
            .await
            .expect("handshake");
        let mut rng = rand_core::UnwrapErr(rand_core::OsRng);
        let session = ClientSession::new(&exit.exit_pub, exit.exit_id, &mut rng).expect("hpke");
        Self {
            _endpoint: endpoint,
            conn,
            session,
            seq: 0,
        }
    }

    /// The setup-stream round trip; returns the sealed reply, if any, and
    /// the raw setup frame (for replays).
    async fn setup(
        &mut self,
        request: &WarrenControlMessage,
    ) -> (Option<WarrenControlMessage>, Vec<u8>) {
        let plaintext = encode_control(request).expect("encode");
        let frame = self.session.seal(&plaintext, 0, self.seq).expect("seal");
        self.seq += 1;
        let bytes = encode_frame(&frame).expect("frame");
        (
            setup_with_bytes(&self.conn, &self.session, &bytes).await,
            bytes,
        )
    }

    fn send_control(&mut self, msg: &WarrenControlMessage) {
        let plaintext = encode_control(msg).expect("encode");
        let frame = self.session.seal(&plaintext, 0, self.seq).expect("seal");
        self.seq += 1;
        self.conn
            .send_datagram(encode_frame(&frame).expect("frame").into())
            .expect("datagram");
    }

    /// The next downlink control datagram, skipping anything else.
    async fn next_control(&self) -> Option<WarrenControlMessage> {
        let read = async {
            loop {
                let datagram = self.conn.read_datagram().await.ok()?;
                let Ok(frame) = decode_frame(&datagram) else {
                    continue;
                };
                let Ok(plaintext) = self.session.open_response(&frame) else {
                    continue;
                };
                if let Ok(Some(msg)) = try_decode_control(&plaintext) {
                    return Some(msg);
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .ok()
            .flatten()
    }

    async fn closed_with(&self) -> Option<quinn::ConnectionError> {
        tokio::time::timeout(Duration::from_secs(5), self.conn.closed())
            .await
            .ok()
    }
}

async fn setup_with_bytes(
    conn: &Connection,
    session: &ClientSession,
    bytes: &[u8],
) -> Option<WarrenControlMessage> {
    let (mut send, mut recv) = conn.open_bi().await.ok()?;
    send.write_all(bytes).await.ok()?;
    let _ = send.finish();
    let reply = tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(64 * 1024))
        .await
        .ok()?
        .ok()?;
    let frame = decode_frame(&reply).ok()?;
    try_decode_control(&session.open_response(&frame).ok()?).ok()?
}

fn token(fill: u8) -> SessionToken {
    SessionToken([fill; SESSION_TOKEN_LEN])
}

fn v7_request(fill: u8) -> WarrenControlMessage {
    WarrenControlMessage::IpRequestV7 {
        prefer_ipv4: None,
        wants_ipv6: false,
        session_tokens: vec![token(fill)],
        wants_daita: false,
    }
}

fn route_request(locator: SealedToApi) -> WarrenControlMessage {
    WarrenControlMessage::IpRequestRoute {
        prefer_ipv4: None,
        wants_ipv6: false,
        route_locator: locator,
        wants_daita: false,
    }
}

fn kem() -> Arc<RouteKemSecretKey> {
    Arc::new(RouteKemSecretKey::derive(&[0x71; 32], 1).expect("kem"))
}

/// Dial `main` with a v7 token of `fill` and anchor `secret` on it.
async fn anchored_main(
    main: &Exit,
    kem: &RouteKemSecretKey,
    secret: &RouteAnchorSecret,
    fill: u8,
) -> Client {
    let mut client = Client::dial(main).await;
    let (reply, _) = client.setup(&v7_request(fill)).await;
    assert!(
        matches!(reply, Some(WarrenControlMessage::IpAssign { .. })),
        "{reply:?}"
    );
    let serial = [fill; 32];
    let sealed = seal_route_anchor(kem.public_key(), secret, &serial).expect("seal");
    client.send_control(&WarrenControlMessage::RouteAnchorRequest {
        sealed_anchor: sealed,
        session_token: None,
    });
    assert_eq!(
        client.next_control().await,
        Some(WarrenControlMessage::RouteAnchorAck {
            status: RouteAnchorStatus::Bound.code(),
            max_routes: MAX_ROUTES,
        }),
        "the main exit forwards the anchor and acks bound"
    );
    client
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_main_session_anchors_and_a_route_on_another_exit_is_admitted() {
    let (kem, anchors) = (kem(), Arc::new(Anchors::default()));
    let main = spawn_exit(0x21, &kem, &anchors, true);
    let route_exit = spawn_exit(0x22, &kem, &anchors, true);
    let secret = RouteAnchorSecret::generate();
    let _main = anchored_main(&main, &kem, &secret, 0xA1).await;
    assert_eq!(main.registry.live_anchor_serials(), vec![[0xA1; 32]]);

    let mut route = Client::dial(&route_exit).await;
    let locator = seal_route_locator(kem.public_key(), &secret, &route_exit.exit_id).expect("seal");
    let (reply, _) = route.setup(&route_request(locator)).await;
    assert!(
        matches!(reply, Some(WarrenControlMessage::IpAssign { .. })),
        "an anchored device's route is admitted without a token: {reply:?}"
    );
    let r = *secret
        .anchor_ref()
        .route_serial(&route_exit.exit_id)
        .as_bytes();
    assert_eq!(route_exit.registry.live_route_serials(), vec![r]);
    assert!(route_exit.registry.live_token_serials().is_empty());
    assert_eq!(route_exit.registry.route_locator(&r), Some(locator));
    assert!(
        route.closed_with().await.is_none(),
        "the admitted route stays up"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_with_no_live_anchor_is_refused_with_its_sealed_code() {
    let (kem, anchors) = (kem(), Arc::new(Anchors::default()));
    let route_exit = spawn_exit(0x23, &kem, &anchors, true);
    let secret = RouteAnchorSecret::generate();
    let mut route = Client::dial(&route_exit).await;
    let locator = seal_route_locator(kem.public_key(), &secret, &route_exit.exit_id).expect("seal");
    let (reply, _) = route.setup(&route_request(locator)).await;
    assert_eq!(
        reply,
        Some(WarrenControlMessage::RouteRejected {
            reason_code: RouteRejectCode::AnchorUnknown.code()
        })
    );
    match route.closed_with().await {
        Some(quinn::ConnectionError::ApplicationClosed(close)) => {
            assert_eq!(close.error_code.into_inner(), u64::from(WARREN_MH_REJECTED));
            assert!(
                close.reason.is_empty(),
                "the relay sees the one opaque close"
            );
        }
        other => panic!("a refused route must be closed with the policy code, got {other:?}"),
    }
    assert!(route_exit.registry.live_route_serials().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exit_without_a_route_policy_does_not_offer_routes() {
    let (kem, anchors) = (kem(), Arc::new(Anchors::default()));
    let exit = spawn_exit(0x24, &kem, &anchors, false);
    let secret = RouteAnchorSecret::generate();
    let mut route = Client::dial(&exit).await;
    let locator = seal_route_locator(kem.public_key(), &secret, &exit.exit_id).expect("seal");
    let (reply, _) = route.setup(&route_request(locator)).await;
    assert_eq!(
        reply,
        Some(WarrenControlMessage::RouteRejected {
            reason_code: RouteRejectCode::NotOffered.code()
        })
    );

    // And its main sessions are told they cannot anchor.
    let mut main = Client::dial(&exit).await;
    main.setup(&v7_request(0xB1)).await;
    let sealed = seal_route_anchor(kem.public_key(), &secret, &[0xB1; 32]).expect("seal");
    main.send_control(&WarrenControlMessage::RouteAnchorRequest {
        sealed_anchor: sealed,
        session_token: None,
    });
    assert_eq!(
        main.next_control().await,
        Some(WarrenControlMessage::RouteAnchorAck {
            status: RouteAnchorStatus::NotEligible.code(),
            max_routes: 0,
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_locator_sealed_for_another_exit_is_refused() {
    let (kem, anchors) = (kem(), Arc::new(Anchors::default()));
    let main = spawn_exit(0x25, &kem, &anchors, true);
    let route_exit = spawn_exit(0x26, &kem, &anchors, true);
    let secret = RouteAnchorSecret::generate();
    let _main = anchored_main(&main, &kem, &secret, 0xA5).await;
    // Sealed for the main exit, presented to the route exit: a confused
    // deputy the associated data stops.
    let locator = seal_route_locator(kem.public_key(), &secret, &main.exit_id).expect("seal");
    let mut route = Client::dial(&route_exit).await;
    let (reply, _) = route.setup(&route_request(locator)).await;
    assert_eq!(
        reply,
        Some(WarrenControlMessage::RouteRejected {
            reason_code: RouteRejectCode::Unspecified.code()
        })
    );
    assert!(route_exit.registry.live_route_serials().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_whose_anchor_is_gone_is_told_then_closed() {
    let (kem, anchors) = (kem(), Arc::new(Anchors::default()));
    let main = spawn_exit(0x27, &kem, &anchors, true);
    let route_exit = spawn_exit(0x28, &kem, &anchors, true);
    let secret = RouteAnchorSecret::generate();
    let _main = anchored_main(&main, &kem, &secret, 0xA7).await;
    let mut route = Client::dial(&route_exit).await;
    let locator = seal_route_locator(kem.public_key(), &secret, &route_exit.exit_id).expect("seal");
    route.setup(&route_request(locator)).await;
    let r = *secret
        .anchor_ref()
        .route_serial(&route_exit.exit_id)
        .as_bytes();
    let ended = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&ended);
    route_exit
        .registry
        .set_route_session_end_observer(Box::new(move |serial| sink.lock().push(serial)));

    // The deployer's renewal learned the anchor is gone.
    assert_eq!(
        route_exit
            .registry
            .end_route(&r, warrenguard_multihop::RouteEndReason::AnchorGone),
        1
    );
    assert_eq!(
        route.next_control().await,
        Some(WarrenControlMessage::RouteEnded {
            reason_code: warrenguard_multihop::RouteEndReason::AnchorGone.code()
        }),
        "the client learns why before the close"
    );
    assert!(
        route.closed_with().await.is_some(),
        "then the route is closed"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while ended.lock().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the route end reaches the observer");
    assert_eq!(*ended.lock(), vec![r]);
    assert!(route_exit.registry.live_route_serials().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_route_setup_is_not_admitted_twice() {
    let (kem, anchors) = (kem(), Arc::new(Anchors::default()));
    let main = spawn_exit(0x29, &kem, &anchors, true);
    let route_exit = spawn_exit(0x2A, &kem, &anchors, true);
    let secret = RouteAnchorSecret::generate();
    let _main = anchored_main(&main, &kem, &secret, 0xA9).await;
    let mut route = Client::dial(&route_exit).await;
    let locator = seal_route_locator(kem.public_key(), &secret, &route_exit.exit_id).expect("seal");
    let (reply, frame) = route.setup(&route_request(locator)).await;
    assert!(matches!(reply, Some(WarrenControlMessage::IpAssign { .. })));

    // A relay replays the captured setup frame on a fresh connection.
    let replay = Client::dial(&route_exit).await;
    let replayed = setup_with_bytes(&replay.conn, &route.session, &frame).await;
    assert!(
        replayed.is_none(),
        "a replayed setup gets no answer: {replayed:?}"
    );
    let api = route_exit.api.as_ref().expect("policy");
    assert_eq!(
        api.route_calls.load(Ordering::Acquire),
        1,
        "the anti-replay window stops the replay before the policy"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_anchor_rehomes_when_the_main_session_moves_and_routes_keep_admitting() {
    let (kem, anchors) = (kem(), Arc::new(Anchors::default()));
    let first_main = spawn_exit(0x2B, &kem, &anchors, true);
    let second_main = spawn_exit(0x2C, &kem, &anchors, true);
    let route_exit = spawn_exit(0x2D, &kem, &anchors, true);
    let secret = RouteAnchorSecret::generate();
    let main = anchored_main(&first_main, &kem, &secret, 0xAB).await;
    let mut route = Client::dial(&route_exit).await;
    let locator = seal_route_locator(kem.public_key(), &secret, &route_exit.exit_id).expect("seal");
    route.setup(&route_request(locator)).await;

    // The main session migrates: a new setup on another exit, another
    // serial, the same secret.
    main.conn.close(quinn::VarInt::from_u32(0), b"migrated");
    let _moved = anchored_main(&second_main, &kem, &secret, 0xAC).await;
    assert_eq!(
        anchors.0.lock().get(secret.anchor_ref().as_bytes()),
        Some(&[0xAC; 32]),
        "the anchor now hangs on the new main session"
    );
    assert_eq!(second_main.registry.live_anchor_serials(), vec![[0xAC; 32]]);

    // A route redial after the move is admitted on a fresh locator.
    let mut redial = Client::dial(&route_exit).await;
    let fresh = seal_route_locator(kem.public_key(), &secret, &route_exit.exit_id).expect("seal");
    assert_ne!(fresh, locator, "every dial carries a fresh locator");
    let (reply, _) = redial.setup(&route_request(fresh)).await;
    assert!(matches!(reply, Some(WarrenControlMessage::IpAssign { .. })));
    assert_eq!(
        route_exit.registry.live_route_session_count(),
        1,
        "one route per (anchor, exit)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wallet_session_is_never_eligible_to_anchor() {
    let (kem, anchors) = (kem(), Arc::new(Anchors::default()));
    let exit = spawn_exit(0x2E, &kem, &anchors, true);
    let mut wallet = Client::dial(&exit).await;
    let (reply, _) = wallet
        .setup(&WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: Some([0x5A; 32]),
            wants_ipv6: false,
            pop_sig: None,
            wants_daita: false,
        })
        .await;
    assert!(matches!(reply, Some(WarrenControlMessage::IpAssign { .. })));
    let secret = RouteAnchorSecret::generate();
    let sealed = seal_route_anchor(kem.public_key(), &secret, &[0x5A; 32]).expect("seal");
    wallet.send_control(&WarrenControlMessage::RouteAnchorRequest {
        sealed_anchor: sealed,
        session_token: None,
    });
    assert_eq!(
        wallet.next_control().await,
        Some(WarrenControlMessage::RouteAnchorAck {
            status: RouteAnchorStatus::NotEligible.code(),
            max_routes: 0,
        }),
        "anchoring a wallet session would join a pubkey to its route exits"
    );
    assert!(anchors.0.lock().is_empty());
}
