//! End-to-end v7 anonymous session-token handshake over loopback: a real
//! `ClientTunnel` presenting session tokens against a real `ExitListener`
//! wired with a `SessionTokenAdmitter`. Proves the dual-accept datapath:
//! the exit decodes `SetupV7`, admits via the token seam, keys the session by
//! the token serial, and returns a `SetupAckV7` with a 10.66.0.0/16 tunnel IP.
//! No control-plane API in the path (the admitter is faked); the engine crypto
//! and wire codecs are real.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use warrenguard_server::{
    BoxFuture, ExitBindOpts, ExitListener, SessionTokenAdmitter, TokenAdmission,
};
use warrenguard_transport::ClientTunnel;
use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken};

/// Admitter that accepts the first presented token, returning a deterministic
/// serial derived from its bytes, and records that it was consulted.
struct FakeAdmitter {
    consulted: AtomicBool,
    deny: bool,
}

impl SessionTokenAdmitter for FakeAdmitter {
    fn admit<'a>(&'a self, tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
        Box::pin(async move {
            self.consulted.store(true, Ordering::SeqCst);
            if self.deny {
                return TokenAdmission::Denied;
            }
            let Some(first) = tokens.first() else {
                return TokenAdmission::Reject;
            };
            // Deterministic serial: first 32 bytes of the token stand in for
            // SHA256(token_input); the exit only needs a stable 32-byte key.
            let mut serial = [0u8; 32];
            serial.copy_from_slice(&first.0[..32]);
            TokenAdmission::Admit { serial }
        })
    }

    fn renew_live<'a>(&'a self, _live: &'a [[u8; 32]]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

async fn bind_exit_with_admitter(admitter: Arc<FakeAdmitter>) -> ExitListener {
    let opts = ExitBindOpts {
        token_admitter: Some(admitter),
        ..Default::default()
    };
    ExitListener::bind_with_opts(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        opts,
    )
    .await
    .expect("bind exit with token admitter")
}

fn a_token(fill: u8) -> SessionToken {
    SessionToken([fill; SESSION_TOKEN_LEN])
}

#[tokio::test]
async fn v7_client_with_a_token_gets_a_tunnel_ip() {
    let admitter = Arc::new(FakeAdmitter {
        consulted: AtomicBool::new(false),
        deny: false,
    });
    let exit = bind_exit_with_admitter(Arc::clone(&admitter)).await;
    let exit_addr = exit.bound_addr();
    tokio::spawn(exit.accept_one());

    // A v7 client presents a token; no wallet signing key is used for auth.
    let client = ClientTunnel::new().with_session_tokens(vec![a_token(0xAB)]);
    let session = tokio::time::timeout(Duration::from_secs(5), client.connect(exit_addr))
        .await
        .expect("v7 handshake must not time out")
        .expect("the exit must admit a v7 session-token client");

    assert_eq!(
        session.assigned_ipv4().octets()[0],
        10,
        "the exit must assign a 10.66.0.0/16 tunnel IP after a v7 handshake"
    );
    assert_eq!(session.assigned_ipv4().octets()[1], 66);
    assert!(
        admitter.consulted.load(Ordering::SeqCst),
        "the token admitter must have been consulted for the v7 primary"
    );
}

#[tokio::test]
async fn v7_client_is_refused_when_the_serial_is_denied() {
    let admitter = Arc::new(FakeAdmitter {
        consulted: AtomicBool::new(false),
        deny: true,
    });
    let exit = bind_exit_with_admitter(Arc::clone(&admitter)).await;
    let exit_addr = exit.bound_addr();
    tokio::spawn(exit.accept_one());

    let client = ClientTunnel::new().with_session_tokens(vec![a_token(0x11)]);
    let result = tokio::time::timeout(Duration::from_secs(5), client.connect(exit_addr))
        .await
        .expect("handshake must not hang");
    assert!(
        result.is_err(),
        "a denied serial (double-spend) must refuse the v7 session"
    );
}

#[tokio::test]
async fn a_v7_incapable_exit_refuses_a_v7_client() {
    // No admitter configured: the exit must refuse v7 (a v7 client then falls
    // back to v6 or re-selects), never panic or hang.
    let exit = ExitListener::bind_localhost().await.expect("bind exit");
    let exit_addr = exit.bound_addr();
    tokio::spawn(exit.accept_one());

    let client = ClientTunnel::new().with_session_tokens(vec![a_token(0x22)]);
    let result = tokio::time::timeout(Duration::from_secs(5), client.connect(exit_addr))
        .await
        .expect("handshake must not hang");
    assert!(
        result.is_err(),
        "an exit with no token admitter must refuse a v7 client"
    );
}
