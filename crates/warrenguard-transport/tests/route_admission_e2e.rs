//! Route admission by anchor end to end: the real client supervisors (a main
//! session that anchors, a route session admitted on it) against the real
//! exit termination loop over loopback QUIC, with a fake control plane that
//! holds a real route KEM key and opens every blob the way the API does.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use parking_lot::Mutex;
use quinn::Endpoint;
use warrenguard_backoff::Backoff;
use warrenguard_multihop::{
    ExitId, RelayDescriptorSigned, RouteAnchorStatus, RouteEndReason, RouteKemSecretKey,
    RouteRejectCode, SealedToApi, relay_descriptor_signing_payload, session_token_serial,
    test_support::pubkey_to_bytes,
};
use warrenguard_multihop_server::ip_pool::IpAllocator;
use warrenguard_multihop_server::multihop::{
    ExitTerminateCtx, MultihopSessionRegistry, SetupSource, derive_x25519_keypair,
    terminate_connection,
};
use warrenguard_server::{
    AnchorVerdict, BoxFuture, RouteAdmission, RouteAdmitter, SessionTokenAdmitter, TokenAdmission,
};
use warrenguard_transport::multihop::MultiHopError;
use warrenguard_transport::route_anchor::{
    AnchorState, RouteAnchorConfig, RouteAnchorHandle, RouteRefusal, RouteSessionAdmission,
};
use warrenguard_transport::supervisor::{
    ClientWatch, MultiHopSupervisor, SessionAdmission, SessionTokenProvider, SupervisorConfig,
};
use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken};

const OPERATIONAL: [u8; 32] = [0x42; 32];

/// The control plane's anchors, shared by every exit of a test.
type Anchors = Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>;

struct FakeApi {
    key: Arc<RouteKemSecretKey>,
    exit_id: ExitId,
    anchors: Anchors,
}

impl RouteAdmitter for FakeApi {
    fn admit_route<'a>(&'a self, locator: &'a SealedToApi) -> BoxFuture<'a, RouteAdmission> {
        Box::pin(async move {
            let Ok(secret) = self.key.open_locator(locator, &self.exit_id) else {
                return RouteAdmission::Refuse(RouteRejectCode::Unspecified);
            };
            let a = secret.anchor_ref();
            if self.anchors.lock().contains_key(a.as_bytes()) {
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
                        .lock()
                        .insert(*secret.anchor_ref().as_bytes(), *lease_serial);
                    AnchorVerdict {
                        status: RouteAnchorStatus::Bound,
                        max_routes: 32,
                    }
                }
                Err(_) => AnchorVerdict::status(RouteAnchorStatus::Refused),
            }
        })
    }
}

/// Admits every token on its real serial, as a verifying exit would.
struct Tokens;

impl SessionTokenAdmitter for Tokens {
    fn admit<'a>(&'a self, tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
        Box::pin(async move {
            TokenAdmission::Admit {
                serial: session_token_serial(&tokens[0]),
            }
        })
    }

    fn renew_live<'a>(&'a self, _: &'a [[u8; 32]]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

struct Exit {
    relay: Arc<RelayDescriptorSigned>,
    exit_id: ExitId,
    exit_pub: [u8; 32],
    registry: Arc<MultihopSessionRegistry>,
    _endpoint: Endpoint,
    accept: tokio::task::JoinHandle<()>,
}

impl Drop for Exit {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// A real one-hop exit: the node the client dials (relay descriptor signed
/// by the operational key, pinned by its TLS key) terminates the session.
fn spawn_exit(seed: u8, kem: &Arc<RouteKemSecretKey>, anchors: &Anchors, policy: bool) -> Exit {
    let tls_key = SigningKey::from_bytes(&[seed; 32]);
    let (privkey, exit_pub) = derive_x25519_keypair(&[seed; 32]).expect("x25519");
    let exit_id = ExitId::from_bytes([seed; 16]);
    let registry = MultihopSessionRegistry::new();
    let route: Option<Arc<dyn RouteAdmitter>> = policy.then(|| {
        Arc::new(FakeApi {
            key: Arc::clone(kem),
            exit_id,
            anchors: Arc::clone(anchors),
        }) as Arc<dyn RouteAdmitter>
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
    .with_token_admitter(Some(Arc::new(Tokens)))
    .with_route_admitter(route);
    let server_cfg = warrenguard_tls::make_server_config(
        &tls_key,
        warrenguard_tls::default_crypto_provider(),
        &[warrenguard_config::ALPN_H3],
    )
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
    let relay_id = [seed; 16];
    let relay_pubkey = tls_key.verifying_key().to_bytes();
    let signature = SigningKey::from_bytes(&OPERATIONAL)
        .sign(&relay_descriptor_signing_payload(&relay_id, &relay_pubkey))
        .to_bytes();
    Exit {
        relay: Arc::new(RelayDescriptorSigned {
            relay_id,
            relay_ed25519_pubkey: relay_pubkey,
            endpoint: addr,
            endpoint_v6: None,
            cover_domain: None,
            tcp_fallback: false,
            signature,
        }),
        exit_id,
        exit_pub: pubkey_to_bytes(&exit_pub),
        registry,
        _endpoint: endpoint,
        accept,
    }
}

fn config(exit: &Exit, tokens: Option<SessionTokenProvider>) -> SupervisorConfig {
    SupervisorConfig {
        relay: Arc::clone(&exit.relay),
        exit_id: exit.exit_id,
        exit_x25519_multihop_pubkey: exit.exit_pub,
        exit_mlkem768_pubkey: None,
        operational_pubkey: SigningKey::from_bytes(&OPERATIONAL).verifying_key(),
        client_signing: SigningKey::from_bytes(&[0x24; 32]),
        bind_addr: "127.0.0.1:0".parse().expect("addr"),
        enable_gso: false,
        use_warren_obfuscation: false,
        socket_bypass: None,
        enable_daita: false,
        idle_cover: false,
        backoff: Backoff::HANDSHAKE,
        on_reconnect: None,
        ip_assign_channel: None,
        wants_ipv6: false,
        n_connections: 1,
        pre_swap_check: None,
        on_overlap_swapped: None,
        on_dial_refused: None,
        on_path_rtt: None,
        session_token_provider: tokens,
    }
}

fn tokens(fills: Vec<u8>) -> SessionTokenProvider {
    let queue = Arc::new(Mutex::new(std::collections::VecDeque::from(fills)));
    Arc::new(move || {
        queue
            .lock()
            .pop_front()
            .map(|fill| vec![SessionToken([fill; SESSION_TOKEN_LEN])])
            .unwrap_or_default()
    })
}

/// Reads every published bundle the way a pump does.
fn spawn_reader(mut rx: ClientWatch) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let current = rx.borrow_and_update().clone();
            if let Some(bundle) = current {
                tokio::select! {
                    _ = async { while bundle.recv().await.is_ok() {} } => {}
                    changed = rx.changed() => if changed.is_err() { return },
                }
            } else if rx.changed().await.is_err() {
                return;
            }
        }
    })
}

async fn wait_state(anchor: &RouteAnchorHandle, want: AnchorState) {
    let mut state = anchor.state();
    tokio::time::timeout(Duration::from_secs(15), async {
        while *state.borrow_and_update() != want {
            state.changed().await.expect("anchor alive");
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the anchor never reached {want:?}"));
}

async fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn kem() -> Arc<RouteKemSecretKey> {
    Arc::new(RouteKemSecretKey::derive(&[0x71; 32], 1).expect("kem"))
}

/// A main supervisor on `exit` anchored with `anchor`.
fn run_main(
    exit: &Exit,
    anchor: &RouteAnchorHandle,
    fills: Vec<u8>,
) -> (
    tokio::task::JoinHandle<Result<(), MultiHopError>>,
    tokio::task::JoinHandle<()>,
    warrenguard_transport::supervisor::SupervisorHandle,
) {
    let (supervisor, rx) = MultiHopSupervisor::new(config(exit, Some(tokens(fills))));
    let supervisor = supervisor.with_route_anchor(anchor.clone());
    let handle = supervisor.handle();
    let reader = spawn_reader(rx);
    (tokio::spawn(supervisor.run()), reader, handle)
}

fn route_supervisor(
    exit: &Exit,
    anchor: &RouteAnchorHandle,
    offered: bool,
) -> (MultiHopSupervisor, ClientWatch) {
    let (supervisor, rx) = MultiHopSupervisor::new(config(exit, None));
    (
        supervisor.with_session_admission(SessionAdmission::Route(RouteSessionAdmission {
            anchor: anchor.clone(),
            exit_offers_routes: offered,
        })),
        rx,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_is_admitted_on_the_main_sessions_anchor_and_ends_with_it() {
    let (kem, anchors): (_, Anchors) = (kem(), Arc::default());
    let main_exit = spawn_exit(0x31, &kem, &anchors, true);
    let route_exit = spawn_exit(0x32, &kem, &anchors, true);
    let anchor = RouteAnchorHandle::new(RouteAnchorConfig {
        kem: kem.public_key().clone(),
    });
    let (main, main_reader, _) = run_main(&main_exit, &anchor, vec![0x11]);
    wait_state(&anchor, AnchorState::Anchored { max_routes: 32 }).await;
    assert_eq!(
        main_exit.registry.live_anchor_serials(),
        vec![session_token_serial(&SessionToken(
            [0x11; SESSION_TOKEN_LEN]
        ))]
    );

    let (route, rx) = route_supervisor(&route_exit, &anchor, true);
    let route_reader = spawn_reader(rx);
    let route_task = tokio::spawn(route.run());
    wait_for("the admitted route session", || {
        route_exit.registry.live_route_session_count() == 1
    })
    .await;
    assert!(
        route_exit.registry.live_token_serials().is_empty(),
        "the route spent no token"
    );

    // The control plane lost the anchor: the route exit's deployer ends it.
    let r = route_exit.registry.live_route_serials()[0];
    assert_eq!(
        route_exit
            .registry
            .end_route(&r, RouteEndReason::AnchorGone),
        1
    );
    let error = tokio::time::timeout(Duration::from_secs(10), route_task)
        .await
        .expect("the route run ends")
        .expect("no panic")
        .expect_err("an ended route is an error for the consumer to act on");
    assert!(
        matches!(
            error,
            MultiHopError::RouteRefused(RouteRefusal::Ended(RouteEndReason::AnchorGone))
        ),
        "got {error:?}"
    );
    main.abort();
    main_reader.abort();
    route_reader.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_at_an_exit_without_route_admission_is_refused_as_not_offered() {
    let (kem, anchors): (_, Anchors) = (kem(), Arc::default());
    let main_exit = spawn_exit(0x33, &kem, &anchors, true);
    let plain_exit = spawn_exit(0x34, &kem, &anchors, false);
    let anchor = RouteAnchorHandle::new(RouteAnchorConfig {
        kem: kem.public_key().clone(),
    });
    let (main, main_reader, _) = run_main(&main_exit, &anchor, vec![0x12]);
    wait_state(&anchor, AnchorState::Anchored { max_routes: 32 }).await;

    let (route, _rx) = route_supervisor(&plain_exit, &anchor, true);
    let error = tokio::time::timeout(Duration::from_secs(10), route.run())
        .await
        .expect("the route run ends")
        .expect_err("refused");
    assert!(
        matches!(
            error,
            MultiHopError::RouteRefused(RouteRefusal::Rejected(RouteRejectCode::NotOffered))
        ),
        "got {error:?}"
    );
    main.abort();
    main_reader.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_anchor_follows_the_main_session_across_a_reconnect() {
    let (kem, anchors): (_, Anchors) = (kem(), Arc::default());
    let main_exit = spawn_exit(0x35, &kem, &anchors, true);
    let route_exit = spawn_exit(0x36, &kem, &anchors, true);
    let anchor = RouteAnchorHandle::new(RouteAnchorConfig {
        kem: kem.public_key().clone(),
    });
    let (main, main_reader, handle) = run_main(&main_exit, &anchor, vec![0x13, 0x14]);
    wait_state(&anchor, AnchorState::Anchored { max_routes: 32 }).await;
    let first = session_token_serial(&SessionToken([0x13; SESSION_TOKEN_LEN]));
    let second = session_token_serial(&SessionToken([0x14; SESSION_TOKEN_LEN]));
    assert_eq!(
        anchors.lock().values().copied().collect::<Vec<_>>(),
        vec![first]
    );

    let (route, rx) = route_supervisor(&route_exit, &anchor, true);
    let route_reader = spawn_reader(rx);
    let route_task = tokio::spawn(route.run());
    wait_for("the admitted route session", || {
        route_exit.registry.live_route_session_count() == 1
    })
    .await;

    // The main session reconnects on a new token: the anchor is re-homed on
    // its serial and the route never noticed.
    assert!(handle.force_reconnect());
    wait_for("the re-homed anchor", || {
        anchors.lock().values().copied().collect::<Vec<_>>() == vec![second]
    })
    .await;
    wait_for("the new main session anchored", || {
        main_exit.registry.live_anchor_serials() == vec![second]
    })
    .await;
    assert_eq!(route_exit.registry.live_route_session_count(), 1);
    assert!(!route_task.is_finished(), "the route session is untouched");
    main.abort();
    main_reader.abort();
    route_task.abort();
    route_reader.abort();
}
