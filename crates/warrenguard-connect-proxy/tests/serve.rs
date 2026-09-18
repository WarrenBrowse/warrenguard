//! CONNECT ingress behaviour, driven over a real duplex pair with the
//! deployer's three seams stubbed: admission, egress policy and the dialer.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use data_encoding::{BASE64, BASE64URL_NOPAD};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use warrenguard_connect_proxy::{
    Authority, ConnectDialer, ConnectProxyConfig, EgressPolicy, ProxyOutcome, ProxyRefusal,
    serve_connect,
};
use warrenguard_server::{BoxFuture, SessionTokenAdmitter, TOKEN_SERIAL_LEN, TokenAdmission};
use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken};

/// An admitter that answers with a fixed verdict and records what it was asked.
struct StubAdmitter {
    verdict: TokenAdmission,
    calls: AtomicUsize,
    seen: Mutex<Vec<[u8; SESSION_TOKEN_LEN]>>,
}

impl StubAdmitter {
    fn new(verdict: TokenAdmission) -> Self {
        Self {
            verdict,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn admitting() -> Self {
        Self::new(TokenAdmission::Admit {
            serial: [9u8; TOKEN_SERIAL_LEN],
        })
    }
}

impl SessionTokenAdmitter for StubAdmitter {
    fn admit<'a>(&'a self, tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut seen) = self.seen.lock() {
            seen.extend(tokens.iter().map(|t| t.0));
        }
        let verdict = self.verdict.clone();
        Box::pin(async move { verdict })
    }

    fn renew_live<'a>(&'a self, _live: &'a [[u8; TOKEN_SERIAL_LEN]]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// A dialer that hands back one end of a duplex pair, so a test can act as the
/// destination. `refuse` makes every dial fail.
struct StubDialer {
    refuse: bool,
    upstream: Mutex<Option<DuplexStream>>,
    dialed: Mutex<Vec<(String, u16)>>,
}

impl StubDialer {
    fn ready() -> (Self, DuplexStream) {
        let (ours, theirs) = duplex(4096);
        (
            Self {
                refuse: false,
                upstream: Mutex::new(Some(ours)),
                dialed: Mutex::new(Vec::new()),
            },
            theirs,
        )
    }

    fn refusing() -> Self {
        Self {
            refuse: true,
            upstream: Mutex::new(None),
            dialed: Mutex::new(Vec::new()),
        }
    }

    fn dialed(&self) -> Vec<(String, u16)> {
        self.dialed.lock().expect("dialed lock").clone()
    }
}

impl ConnectDialer for StubDialer {
    type Upstream = DuplexStream;

    async fn dial(&self, target: &Authority) -> std::io::Result<Self::Upstream> {
        self.dialed
            .lock()
            .expect("dialed lock")
            .push((target.host().to_owned(), target.port()));
        if self.refuse {
            return Err(std::io::Error::other("refused"));
        }
        self.upstream
            .lock()
            .expect("upstream lock")
            .take()
            .ok_or_else(|| std::io::Error::other("already dialed"))
    }
}

struct AllowAll;
impl EgressPolicy for AllowAll {
    fn permits(&self, _target: &Authority) -> bool {
        true
    }
}

struct DenyAll;
impl EgressPolicy for DenyAll {
    fn permits(&self, _target: &Authority) -> bool {
        false
    }
}

fn credential_header(token: &[u8; SESSION_TOKEN_LEN]) -> String {
    let password = BASE64URL_NOPAD.encode(token);
    let basic = BASE64.encode(format!("warren:{password}").as_bytes());
    format!("Proxy-Authorization: Basic {basic}\r\n")
}

fn connect_request(authority: &str, credential: Option<&str>) -> String {
    format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{}\r\n",
        credential.unwrap_or("")
    )
}

/// Reads whatever the ingress wrote back, until it stops or the buffer fills.
async fn read_response(client: &mut DuplexStream) -> String {
    let mut buf = vec![0u8; 512];
    let n = client.read(&mut buf).await.expect("client read");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
async fn challenges_a_connect_that_carries_no_credential() {
    let (mut client, server) = duplex(4096);
    let admitter = StubAdmitter::admitting();
    let dialer = StubDialer::refusing();

    client
        .write_all(connect_request("example.com:443", None).as_bytes())
        .await
        .expect("write");

    let outcome = serve_connect(
        server,
        &[],
        &ConnectProxyConfig::default(),
        &AllowAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert_eq!(outcome, ProxyOutcome::Refused(ProxyRefusal::Challenged));
    let response = read_response(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 407 "),
        "a browser only asks its extension for credentials after a 407: {response}"
    );
    assert!(response.contains("Proxy-Authenticate: Basic"));
    assert_eq!(
        admitter.calls.load(Ordering::SeqCst),
        0,
        "no credential was presented, so nothing should have been verified"
    );
}

#[tokio::test]
async fn tunnels_bytes_both_ways_once_a_credential_is_admitted() {
    let (mut client, server) = duplex(4096);
    let (dialer, mut destination) = StubDialer::ready();
    let admitter = StubAdmitter::admitting();
    let token = [7u8; SESSION_TOKEN_LEN];

    client
        .write_all(connect_request("example.com:443", Some(&credential_header(&token))).as_bytes())
        .await
        .expect("write");

    let served = tokio::spawn(async move {
        serve_connect(
            server,
            &[],
            &ConnectProxyConfig::default(),
            &AllowAll,
            &admitter,
            &dialer,
        )
        .await
    });

    let response = read_response(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "the browser treats anything but a 200 as a failed tunnel: {response}"
    );

    client.write_all(b"client-to-site").await.expect("uplink");
    let mut seen = [0u8; 14];
    destination
        .read_exact(&mut seen)
        .await
        .expect("uplink read");
    assert_eq!(&seen, b"client-to-site");

    destination.write_all(b"site-to-client").await.expect("dl");
    let mut back = [0u8; 14];
    client.read_exact(&mut back).await.expect("downlink read");
    assert_eq!(&back, b"site-to-client");

    drop(client);
    drop(destination);
    let outcome = served.await.expect("join").expect("served");
    assert!(
        matches!(outcome, ProxyOutcome::Tunnelled { .. }),
        "expected a tunnel, got {outcome:?}"
    );
}

#[tokio::test]
async fn hands_the_admitter_the_token_the_credential_encoded() {
    let (mut client, server) = duplex(4096);
    let (dialer, destination) = StubDialer::ready();
    let admitter = StubAdmitter::admitting();
    let mut token = [0u8; SESSION_TOKEN_LEN];
    token[0] = 0xab;
    token[SESSION_TOKEN_LEN - 1] = 0xcd;

    client
        .write_all(connect_request("example.com:443", Some(&credential_header(&token))).as_bytes())
        .await
        .expect("write");
    let served = tokio::spawn(async move {
        serve_connect(
            server,
            &[],
            &ConnectProxyConfig::default(),
            &AllowAll,
            &admitter,
            &dialer,
        )
        .await
        .map(|outcome| (outcome, admitter))
    });
    let _ = read_response(&mut client).await;
    // Both ends have to go for the bidirectional copy to finish; holding the
    // destination open would hang the join below forever.
    drop(client);
    drop(destination);

    let (_, admitter) = served.await.expect("join").expect("served");
    let seen = admitter.seen.lock().expect("seen lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0], token, "the token must survive the wire encoding");
}

#[tokio::test]
async fn challenges_again_when_the_credential_does_not_verify() {
    let (mut client, server) = duplex(4096);
    let dialer = StubDialer::refusing();
    let admitter = StubAdmitter::new(TokenAdmission::Reject);

    client
        .write_all(
            connect_request(
                "example.com:443",
                Some(&credential_header(&[3u8; SESSION_TOKEN_LEN])),
            )
            .as_bytes(),
        )
        .await
        .expect("write");

    let outcome = serve_connect(
        server,
        &[],
        &ConnectProxyConfig::default(),
        &AllowAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert_eq!(
        outcome,
        ProxyOutcome::Refused(ProxyRefusal::CredentialRejected)
    );
    assert!(
        read_response(&mut client)
            .await
            .starts_with("HTTP/1.1 407 "),
        "an epoch boundary must let the client retry with a fresh token"
    );
    assert!(
        dialer.dialed().is_empty(),
        "a rejected client must not egress"
    );
}

#[tokio::test]
async fn refuses_a_credential_whose_serial_is_already_spent() {
    let (mut client, server) = duplex(4096);
    let dialer = StubDialer::refusing();
    let admitter = StubAdmitter::new(TokenAdmission::Denied);

    client
        .write_all(
            connect_request(
                "example.com:443",
                Some(&credential_header(&[3u8; SESSION_TOKEN_LEN])),
            )
            .as_bytes(),
        )
        .await
        .expect("write");

    let outcome = serve_connect(
        server,
        &[],
        &ConnectProxyConfig::default(),
        &AllowAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert_eq!(
        outcome,
        ProxyOutcome::Refused(ProxyRefusal::CredentialSpent)
    );
    assert!(
        read_response(&mut client)
            .await
            .starts_with("HTTP/1.1 403 ")
    );
    assert!(dialer.dialed().is_empty());
}

#[tokio::test]
async fn refuses_a_denied_destination_before_it_looks_at_the_credential() {
    let (mut client, server) = duplex(4096);
    let dialer = StubDialer::refusing();
    let admitter = StubAdmitter::admitting();

    client
        .write_all(
            connect_request(
                "10.0.0.1:22",
                Some(&credential_header(&[1u8; SESSION_TOKEN_LEN])),
            )
            .as_bytes(),
        )
        .await
        .expect("write");

    let outcome = serve_connect(
        server,
        &[],
        &ConnectProxyConfig::default(),
        &DenyAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert_eq!(outcome, ProxyOutcome::Refused(ProxyRefusal::EgressDenied));
    assert_eq!(
        admitter.calls.load(Ordering::SeqCst),
        0,
        "a destination we will never dial must not spend a token verification"
    );
    assert!(dialer.dialed().is_empty());
}

#[tokio::test]
async fn refuses_a_request_that_is_http_but_not_a_connect() {
    let (mut client, server) = duplex(4096);
    let dialer = StubDialer::refusing();
    let admitter = StubAdmitter::admitting();

    // What a browser sends for a plain-http URL through a proxy.
    client
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write");

    let outcome = serve_connect(
        server,
        &[],
        &ConnectProxyConfig::default(),
        &AllowAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert!(matches!(
        outcome,
        ProxyOutcome::Refused(ProxyRefusal::Head(_))
    ));
    assert!(
        read_response(&mut client)
            .await
            .starts_with("HTTP/1.1 405 ")
    );
}

#[tokio::test]
async fn reports_an_unreachable_upstream_without_opening_the_tunnel() {
    let (mut client, server) = duplex(4096);
    let dialer = StubDialer::refusing();
    let admitter = StubAdmitter::admitting();

    client
        .write_all(
            connect_request(
                "example.com:443",
                Some(&credential_header(&[5u8; SESSION_TOKEN_LEN])),
            )
            .as_bytes(),
        )
        .await
        .expect("write");

    let outcome = serve_connect(
        server,
        &[],
        &ConnectProxyConfig::default(),
        &AllowAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert_eq!(
        outcome,
        ProxyOutcome::Refused(ProxyRefusal::UpstreamUnreachable)
    );
    let response = read_response(&mut client).await;
    assert!(
        !response.starts_with("HTTP/1.1 200 "),
        "a client told 200 would start writing into a tunnel that does not exist"
    );
    assert_eq!(dialer.dialed(), vec![("example.com".to_owned(), 443)]);
}

#[tokio::test]
async fn drops_a_peer_that_never_finishes_its_head() {
    let (mut client, server) = duplex(4096);
    let dialer = StubDialer::refusing();
    let admitter = StubAdmitter::admitting();

    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n")
        .await
        .expect("write");

    let outcome = serve_connect(
        server,
        &[],
        &ConnectProxyConfig {
            head_deadline: Duration::from_millis(50),
        },
        &AllowAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert_eq!(outcome, ProxyOutcome::Refused(ProxyRefusal::Timeout));
}

#[tokio::test]
async fn accepts_a_head_the_caller_already_started_reading() {
    // A shared listener sniffs the first bytes to route the connection here,
    // then hands them over rather than losing them.
    let (mut client, server) = duplex(4096);
    let dialer = StubDialer::refusing();
    let admitter = StubAdmitter::admitting();
    let request = connect_request("example.com:443", None);
    let (prefix, rest) = request.as_bytes().split_at(8);

    client.write_all(rest).await.expect("write");

    let outcome = serve_connect(
        server,
        prefix,
        &ConnectProxyConfig::default(),
        &AllowAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert_eq!(outcome, ProxyOutcome::Refused(ProxyRefusal::Challenged));
}

#[tokio::test]
async fn rejects_a_credential_that_is_not_a_session_token() {
    let (mut client, server) = duplex(4096);
    let dialer = StubDialer::refusing();
    let admitter = StubAdmitter::admitting();
    let basic = BASE64.encode(b"warren:not-a-token");

    client
        .write_all(
            connect_request(
                "example.com:443",
                Some(&format!("Proxy-Authorization: Basic {basic}\r\n")),
            )
            .as_bytes(),
        )
        .await
        .expect("write");

    let outcome = serve_connect(
        server,
        &[],
        &ConnectProxyConfig::default(),
        &AllowAll,
        &admitter,
        &dialer,
    )
    .await
    .expect("served");

    assert_eq!(
        outcome,
        ProxyOutcome::Refused(ProxyRefusal::CredentialRejected)
    );
    assert_eq!(
        admitter.calls.load(Ordering::SeqCst),
        0,
        "a credential of the wrong shape must be refused before any crypto runs"
    );
}
