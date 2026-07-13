//! Regression guard: `ClientTunnel::handshake()` (the single-hop path that
//! returns the raw `SetupAck`) must stamp the v5 in-band auth proof, exactly
//! like `connect()`. A bug once shipped a zero-auth Setup on this path
//! (`handshake_with_version` built the frame literally and forgot to call
//! `stamp_inband_auth`), so a v5 exit rejected every `handshake()` with
//! `AuthRejected`. This test binds a real exit and asserts the method
//! authenticates. Loopback only.

use std::time::Duration;

use warrenguard_server::ExitListener;
use warrenguard_transport::ClientTunnel;

#[tokio::test]
async fn handshake_method_authenticates_in_band() {
    let exit = ExitListener::bind_localhost().await.expect("bind exit");
    let exit_addr = exit.bound_addr();
    tokio::spawn(exit.accept_one());

    let client = ClientTunnel::new();
    let ack = tokio::time::timeout(Duration::from_secs(5), client.handshake(exit_addr))
        .await
        .expect("handshake must not time out")
        .expect("a v5 exit must accept the in-band-authenticated handshake()");

    assert_eq!(
        ack.tunnel_ipv4[0], 10,
        "the exit must assign a 10.66.0.0/16 tunnel IP after a successful handshake"
    );
    assert_eq!(ack.tunnel_ipv4[1], 66);
}
