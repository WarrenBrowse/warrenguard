//! E4.2 - the WarrenGuard engine as a self-contained generic VPN-over-QUIC
//! building block ("like WireGuard").
//!
//! This e2e stands up a real tunnel from ENGINE CRATES ONLY:
//! - server: [`warrenguard_server::ExitListener`] bound on localhost with an
//!   ephemeral key and `allowlist = None`, i.e. the generic `AllowAll` policy
//!   (every peer that completes the RPK TLS handshake is admitted, like a
//!   WireGuard peer with no extra ACL);
//! - client: [`warrenguard_transport::ClientTunnel`] keyed by a RAW Ed25519 node
//!   key derived from a raw 32-byte seed via [`warrenguard_identity::derive_node_key`]
//!   (no BIP39, no SS58, no Warren account).
//!
//! It then round-trips an opaque datagram through the tunnel. There is ZERO
//! Warren backend crate in this test's dependency tree (the `engine_direction`
//! conformance invariant proves the engine crates themselves never pull one), so
//! a green run here is the standing proof that a third-party deployer can build a
//! working tunnel on the engine alone.

use std::time::Duration;

use warrenguard_server::ExitListener;
use warrenguard_transport::ClientTunnel;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn engine_only_tunnel_admits_a_raw_keypair_client_and_round_trips_a_datagram() {
    // Generic server: ephemeral identity + AllowAll (the bind_localhost default
    // leaves the allowlist unset, which the Authorizer gate treats as AllowAll).
    let exit = ExitListener::bind_localhost()
        .await
        .expect("generic exit must bind on localhost");
    let exit_addr = exit.bound_addr();

    let response = b"warrenguard-pong".to_vec();
    let response_for_exit = response.clone();
    let exit_task =
        tokio::spawn(async move { exit.echo_one_datagram_with(response_for_exit).await });

    // Generic client: a raw node key, no Warren identity layer. This is exactly
    // what a non-Warren deployer would do (raw seed from a config file / KMS).
    let node_key = warrenguard_identity::derive_node_key(&[0x11u8; 32]);
    let client = ClientTunnel::with_signing_key(&node_key);

    let session = tokio::time::timeout(TEST_TIMEOUT, client.connect(exit_addr))
        .await
        .expect("connect must not time out")
        .expect("the generic exit must complete the handshake for a raw-key client");

    // The exit allocated a tunnel IP from its generic pool (10.66.0.0/16), proving
    // the full Setup/IpAssign exchange ran with no Warren account involved.
    let assigned = session.assigned_ipv4();
    assert_eq!(assigned.octets()[0], 10, "tunnel IP from the generic pool");
    assert_eq!(assigned.octets()[1], 66, "tunnel IP from the generic pool");
    assert_ne!(
        assigned,
        std::net::Ipv4Addr::new(10, 66, 0, 1),
        "the client must not be handed the gateway address"
    );

    // Opaque datagram round-trip through the engine datapath.
    session
        .send_datagram(b"warrenguard-ping".to_vec())
        .expect("send a datagram through the engine tunnel");
    let echoed = tokio::time::timeout(TEST_TIMEOUT, session.read_datagram())
        .await
        .expect("recv must not time out")
        .expect("the exit must echo the datagram back through the tunnel");
    assert_eq!(
        echoed.as_ref(),
        &response[..],
        "the engine-only tunnel must carry the payload byte-for-byte"
    );

    tokio::time::timeout(TEST_TIMEOUT, exit_task)
        .await
        .expect("exit task must finish")
        .expect("exit task must not panic")
        .expect("exit echo must succeed");
}
