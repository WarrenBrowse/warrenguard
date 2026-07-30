//! The server hands a presented credential to the deployer, and never
//! invents one.
//!
//! A deployer that gates its port budget on a credential needs the bytes the
//! client presented, keyed to the address that presented them, before the
//! allocation is served. Everything else stays the deployer's business: the
//! engine transports opaque bytes and forms no opinion about them.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use warrenguard_natpmp_protocol::{
    MapProto, Request, append_credential_trailer, serialize_request,
};
use warrenguard_natpmp_server::server::{CredentialAuthority, Server, SourceFilter};
use warrenguard_natpmp_server::stub_backend::StubBackend;

const TIMEOUT: Duration = Duration::from_secs(5);
const FAKE_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 42);

/// Records what the server presented, so a test can assert on it.
#[derive(Default)]
struct RecordingAuthority(Mutex<Vec<(Ipv4Addr, Vec<u8>)>>);

impl RecordingAuthority {
    fn presented(&self) -> Vec<(Ipv4Addr, Vec<u8>)> {
        self.0.lock().expect("recorder lock").clone()
    }
}

impl CredentialAuthority for RecordingAuthority {
    fn present<'a>(
        &'a self,
        client_ip: Ipv4Addr,
        credential: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        let entry = (client_ip, credential.to_vec());
        Box::pin(async move {
            self.0.lock().expect("recorder lock").push(entry);
        })
    }
}

async fn spawn_server(authority: Arc<RecordingAuthority>) -> SocketAddr {
    let permissive: SourceFilter = Arc::new(|_| true);
    let server = Server::bind_with_filter(
        "127.0.0.1:0".parse().expect("static addr"),
        Arc::new(StubBackend::new()),
        FAKE_PUBLIC_IP,
        permissive,
    )
    .await
    .expect("bind server")
    .with_credential_authority(authority);
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.run());
    addr
}

fn map_request() -> Vec<u8> {
    serialize_request(&Request::Map {
        proto: MapProto::Tcp,
        internal_port: 8080,
        suggested_external_port: 0,
        lifetime_secs: 600,
    })
}

async fn round_trip(server: SocketAddr, frame: &[u8]) -> u16 {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
    client.send_to(frame, server).await.expect("send");
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("response before timeout")
        .expect("recv");
    assert!(n >= 12, "short response");
    u16::from_be_bytes([buf[2], buf[3]])
}

#[tokio::test]
async fn a_presented_credential_reaches_the_deployer_with_its_client() {
    let authority = Arc::new(RecordingAuthority::default());
    let server = spawn_server(Arc::clone(&authority)).await;
    let credential = vec![0x5A; 354];
    let mut frame = map_request();
    append_credential_trailer(&mut frame, &credential).expect("credential fits");

    let result_code = round_trip(server, &frame).await;

    assert_eq!(result_code, 0, "the mapping itself must still be granted");
    let presented = authority.presented();
    assert_eq!(
        presented.len(),
        1,
        "expected one presentation: {presented:?}"
    );
    assert_eq!(presented[0].0, Ipv4Addr::LOCALHOST);
    assert_eq!(presented[0].1, credential);
}

#[tokio::test]
async fn a_request_without_a_credential_presents_nothing() {
    // The deployer must be able to tell "presented nothing" from "presented
    // something I could not verify": only the second one is a client claiming
    // a budget it may not have.
    let authority = Arc::new(RecordingAuthority::default());
    let server = spawn_server(Arc::clone(&authority)).await;

    let result_code = round_trip(server, &map_request()).await;

    assert_eq!(result_code, 0, "an uncredentialed client still gets a port");
    assert!(
        authority.presented().is_empty(),
        "the server must not invent a credential"
    );
}
