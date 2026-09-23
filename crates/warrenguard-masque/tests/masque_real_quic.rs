//! The MASQUE ingress over REAL QUIC (warren-quinn) on loopback: a hand-rolled
//! HTTP/3 client does what a browser handed an HTTP/3 proxy does (control
//! stream SETTINGS, CONNECT and CONNECT-UDP request streams, HTTP Datagrams),
//! against [`MasqueIngress::serve_connection`] with the deployer's four seams
//! stubbed. A real transport is the necessary validation for a datapath; the
//! real-browser run against a deployed node is the step this does not cover.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use data_encoding::{BASE64, BASE64URL_NOPAD};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use warrenguard_connect_proxy::{Authority, ConnectDialer, EgressPolicy};
use warrenguard_edge::{
    FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS, SETTINGS_H3_DATAGRAM, STREAM_CONTROL,
    decode_field_section, encode_field_section, encode_frame, encode_masque_datagram,
    encode_varint, read_frame, read_masque_datagram,
};
use warrenguard_masque::{
    ConnectUdpDialer, Http3Handoff, MasqueConfig, MasqueIngress, PendingRequest,
    SessionTokenAdmitter, TokenAdmission,
};
use warrenguard_server::{BoxFuture, TOKEN_SERIAL_LEN};
use warrenguard_wire::{SESSION_TOKEN_LEN, SessionToken};

const COVER: &str = "cover.example.com";

// ---- the deployer's seams, stubbed ------------------------------------------

struct StubAdmitter {
    verdict: TokenAdmission,
    calls: AtomicUsize,
    /// `Some`: the credential is spent by the first verification, which takes
    /// this long to answer; every later verification finds it spent.
    single_use_after: Option<Duration>,
}

impl StubAdmitter {
    fn admitting() -> Arc<Self> {
        Self::with(TokenAdmission::Admit {
            serial: [9u8; TOKEN_SERIAL_LEN],
        })
    }
    fn with(verdict: TokenAdmission) -> Arc<Self> {
        Arc::new(Self {
            verdict,
            calls: AtomicUsize::new(0),
            single_use_after: None,
        })
    }
    fn single_use(verification: Duration) -> Arc<Self> {
        Arc::new(Self {
            verdict: TokenAdmission::Admit {
                serial: [9u8; TOKEN_SERIAL_LEN],
            },
            calls: AtomicUsize::new(0),
            single_use_after: Some(verification),
        })
    }
}

impl SessionTokenAdmitter for StubAdmitter {
    fn admit<'a>(&'a self, _tokens: &'a [SessionToken]) -> BoxFuture<'a, TokenAdmission> {
        let earlier = self.calls.fetch_add(1, Ordering::SeqCst);
        let verdict = self.verdict.clone();
        let single_use_after = self.single_use_after;
        Box::pin(async move {
            let Some(verification) = single_use_after else {
                return verdict;
            };
            tokio::time::sleep(verification).await;
            if earlier == 0 {
                verdict
            } else {
                TokenAdmission::Denied
            }
        })
    }
    fn renew_live<'a>(&'a self, _live: &'a [[u8; TOKEN_SERIAL_LEN]]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

struct Policy(bool);

impl EgressPolicy for Policy {
    fn permits(&self, _target: &Authority) -> bool {
        self.0
    }
}

/// Dials the loopback echo whatever the target names, and remembers what was
/// asked; `None` refuses every dial.
struct Dialer {
    target: Option<SocketAddr>,
    dialed: Mutex<Vec<String>>,
}

impl Dialer {
    fn to(target: SocketAddr) -> Self {
        Self {
            target: Some(target),
            dialed: Mutex::new(Vec::new()),
        }
    }
    fn refusing() -> Self {
        Self {
            target: None,
            dialed: Mutex::new(Vec::new()),
        }
    }
    fn dials(&self) -> usize {
        self.dialed.lock().unwrap().len()
    }
}

impl ConnectDialer for Dialer {
    type Upstream = TcpStream;
    async fn dial(&self, target: &Authority) -> std::io::Result<TcpStream> {
        self.dialed
            .lock()
            .unwrap()
            .push(format!("{}:{}", target.host(), target.port()));
        match self.target {
            Some(addr) => TcpStream::connect(addr).await,
            None => Err(std::io::Error::other("refused")),
        }
    }
}

impl ConnectUdpDialer for Dialer {
    async fn dial(&self, target: &Authority) -> std::io::Result<UdpSocket> {
        self.dialed
            .lock()
            .unwrap()
            .push(format!("{}:{}", target.host(), target.port()));
        match self.target {
            Some(addr) => {
                let socket = UdpSocket::bind("127.0.0.1:0").await?;
                socket.connect(addr).await?;
                Ok(socket)
            }
            None => Err(std::io::Error::other("refused")),
        }
    }
}

type Ingress = MasqueIngress<StubAdmitter, Policy, Arc<Dialer>, Arc<Dialer>>;

// ---- loopback destinations ------------------------------------------------

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

// ---- QUIC endpoints (X.509 cover cert, ALPN h3) ----------------------------

fn mint_cover_cert() -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "masque-test-root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
    let leaf_params = CertificateParams::new(vec![COVER.to_string()]).expect("leaf params");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf sign");
    (
        vec![leaf_cert.der().to_vec()],
        leaf_key.serialize_der(),
        ca_cert.der().to_vec(),
    )
}

/// Spawns an ingress server; every accepted connection is served with an
/// empty handoff (the ingress accepts the peer's streams itself).
fn spawn_server(ingress: Arc<Ingress>) -> (SocketAddr, Vec<u8>) {
    let (chain, key_der, root_der) = mint_cover_cert();
    let endpoint = server_endpoint(chain, key_der);
    let addr = endpoint.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let ingress = ingress.clone();
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    ingress
                        .serve_connection(conn, Http3Handoff::default())
                        .await;
                }
            });
        }
    });
    (addr, root_der)
}

fn server_endpoint(chain: Vec<Vec<u8>>, key_der: Vec<u8>) -> Endpoint {
    use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let chain: Vec<CertificateDer<'static>> = chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let cfg = warrenguard_tls::make_server_config_x509(
        chain,
        key,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("x509 server config");
    Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).expect("server bind")
}

async fn connect(addr: SocketAddr, root_der: &[u8]) -> Connection {
    use quinn::rustls::pki_types::CertificateDer;
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .expect("trust test root");
    let cfg = warrenguard_tls::make_client_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("webpki client config");
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
    endpoint.set_default_client_config(cfg);
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(addr, COVER).expect("connect builds"),
    )
    .await
    .expect("handshake in time")
    .expect("handshake");
    Box::leak(Box::new(endpoint));
    conn
}

// ---- the browser side of HTTP/3 --------------------------------------------

fn field<'a>(name: &'a [u8], value: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    (name, value)
}

fn credential() -> String {
    let token = [7u8; SESSION_TOKEN_LEN];
    let password = BASE64URL_NOPAD.encode(&token);
    format!(
        "Basic {}",
        BASE64.encode(format!("warren:{password}").as_bytes())
    )
}

/// Opens the control stream with SETTINGS; `datagrams` advertises H3_DATAGRAM.
async fn open_control(conn: &Connection, datagrams: bool) -> SendStream {
    let mut settings = Vec::new();
    if datagrams {
        settings.extend_from_slice(&encode_varint(SETTINGS_H3_DATAGRAM));
        settings.extend_from_slice(&encode_varint(1));
    }
    let mut prelude = encode_varint(STREAM_CONTROL);
    prelude.extend_from_slice(&encode_frame(FRAME_SETTINGS, &settings));
    let mut ctrl = conn.open_uni().await.expect("open control");
    ctrl.write_all(&prelude).await.expect("write settings");
    ctrl
}

fn connect_head(authority: &str, credential: Option<&str>) -> Vec<u8> {
    let mut fields = vec![
        field(b":method", b"CONNECT"),
        field(b":authority", authority.as_bytes()),
    ];
    if let Some(c) = credential {
        fields.push(field(b"proxy-authorization", c.as_bytes()));
    }
    encode_frame(FRAME_HEADERS, &encode_field_section(&fields))
}

fn connect_udp_head(path: &str, credential: Option<&str>) -> Vec<u8> {
    let mut fields = vec![
        field(b":method", b"CONNECT"),
        field(b":protocol", b"connect-udp"),
        field(b":scheme", b"https"),
        field(b":authority", COVER.as_bytes()),
        field(b":path", path.as_bytes()),
        field(b"capsule-protocol", b"?1"),
    ];
    if let Some(c) = credential {
        fields.push(field(b"proxy-authorization", c.as_bytes()));
    }
    encode_frame(FRAME_HEADERS, &encode_field_section(&fields))
}

/// A request stream with its head written and the response HEADERS read.
struct Exchange {
    send: SendStream,
    recv: RecvStream,
    status: u16,
    fields: Vec<(String, String)>,
    /// Bytes read past the HEADERS frame (the start of a body or of DATA).
    rest: Vec<u8>,
}

async fn request(conn: &Connection, head: &[u8]) -> Exchange {
    let (mut send, mut recv) = conn.open_bi().await.expect("open request");
    send.write_all(head).await.expect("write head");
    let mut buf = Vec::new();
    let (frame, used) = loop {
        if let Some((frame, used)) = read_frame(&buf) {
            break (frame, used);
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), recv.read(&mut chunk))
            .await
            .expect("response in time")
            .expect("read")
        {
            Some(n) => buf.extend_from_slice(&chunk[..n]),
            None => panic!("stream ended before a response frame"),
        }
    };
    assert_eq!(frame.ty, FRAME_HEADERS, "a response opens with HEADERS");
    let fields: Vec<(String, String)> = decode_field_section(frame.payload)
        .expect("response decodes")
        .into_iter()
        .map(|f| {
            (
                String::from_utf8_lossy(&f.name).into_owned(),
                String::from_utf8_lossy(&f.value).into_owned(),
            )
        })
        .collect();
    let status = fields
        .iter()
        .find(|(n, _)| n == ":status")
        .and_then(|(_, v)| v.parse().ok())
        .expect(":status present");
    let rest = buf[used..].to_vec();
    Exchange {
        send,
        recv,
        status,
        fields,
        rest,
    }
}

/// Reads until the stream holds `want` bytes of DATA payload, and returns them.
async fn read_data(recv: &mut RecvStream, mut buf: Vec<u8>, want: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        while let Some((frame, used)) = read_frame(&buf) {
            if frame.ty == FRAME_DATA {
                out.extend_from_slice(frame.payload);
            }
            buf.drain(..used);
        }
        if out.len() >= want {
            return out;
        }
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), recv.read(&mut chunk))
            .await
            .expect("data in time")
            .expect("read")
        {
            Some(n) => buf.extend_from_slice(&chunk[..n]),
            None => return out,
        }
    }
}

fn ingress(
    admitter: Arc<StubAdmitter>,
    permit: bool,
    dialer: Arc<Dialer>,
    config: MasqueConfig,
) -> Arc<Ingress> {
    Arc::new(MasqueIngress::new(
        admitter,
        Policy(permit),
        dialer.clone(),
        dialer,
        config,
    ))
}

async fn tunnel_config() -> (MasqueConfig, Arc<Dialer>) {
    let echo = tcp_echo().await;
    let config = MasqueConfig {
        other_response: decoy_response(),
        ..MasqueConfig::default()
    };
    (config, Arc::new(Dialer::to(echo)))
}

fn decoy_response() -> Bytes {
    let mut out = warrenguard_edge::encode_response_headers(
        200,
        &[field(b"content-type", b"text/html; charset=utf-8")],
    );
    out.extend_from_slice(&encode_frame(FRAME_DATA, b"<h1>It works!</h1>"));
    Bytes::from(out)
}

// ---- tests -------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_without_a_credential_is_challenged() {
    let (config, dialer) = tunnel_config().await;
    let admitter = StubAdmitter::admitting();
    let (addr, root) = spawn_server(ingress(admitter.clone(), true, dialer.clone(), config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let x = request(&conn, &connect_head("example.com:443", None)).await;

    assert_eq!(x.status, 407);
    let challenge = x
        .fields
        .iter()
        .find(|(n, _)| n == "proxy-authenticate")
        .map(|(_, v)| v.to_lowercase())
        .expect("a challenge names the scheme");
    assert!(challenge.contains("basic realm=\"proxy\""));
    assert_eq!(admitter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(dialer.dials(), 0, "a challenged request dials nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_with_a_verified_credential_tunnels_bytes_both_ways() {
    let (config, dialer) = tunnel_config().await;
    let admitter = StubAdmitter::admitting();
    let (addr, root) = spawn_server(ingress(admitter.clone(), true, dialer.clone(), config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let mut x = request(&conn, &connect_head("example.com:443", Some(&credential()))).await;
    assert_eq!(x.status, 200);
    assert_eq!(
        dialer.dialed.lock().unwrap().as_slice(),
        ["example.com:443"]
    );

    // Two DATA frames, one of them larger than a single transport read, come
    // back through the echo as DATA frames carrying the same bytes.
    let big = vec![0xabu8; 100_000];
    x.send
        .write_all(&encode_frame(FRAME_DATA, b"hello"))
        .await
        .expect("write");
    x.send
        .write_all(&encode_frame(FRAME_DATA, &big))
        .await
        .expect("write");
    let echoed = read_data(&mut x.recv, x.rest, 5 + big.len()).await;
    assert_eq!(&echoed[..5], b"hello");
    assert_eq!(&echoed[5..], big.as_slice());

    // Finishing the request stream half-closes the upstream; the server then
    // finishes its side once the echo closes.
    x.send.finish().expect("finish");
    let tail = read_data(&mut x.recv, Vec::new(), usize::MAX).await;
    assert!(tail.is_empty(), "nothing more after the client finished");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_connect_on_an_admitted_connection_is_not_verified_again() {
    let (config, dialer) = tunnel_config().await;
    let admitter = StubAdmitter::admitting();
    let (addr, root) = spawn_server(ingress(admitter.clone(), true, dialer, config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let first = request(&conn, &connect_head("a.example:443", Some(&credential()))).await;
    let second = request(&conn, &connect_head("b.example:443", Some(&credential()))).await;
    // And one without any credential at all: the admission is the connection's.
    let third = request(&conn, &connect_head("c.example:443", None)).await;

    assert_eq!((first.status, second.status, third.status), (200, 200, 200));
    assert_eq!(
        admitter.calls.load(Ordering::SeqCst),
        1,
        "one verification admits the connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_first_requests_on_one_connection_spend_one_credential() {
    // A browser opens several tunnels at once on a fresh connection, each
    // carrying the same credential. The first verification must admit the
    // connection for all of them: verifying each one spends the token again,
    // and the copies then find it spent.
    let (config, dialer) = tunnel_config().await;
    let admitter = StubAdmitter::single_use(Duration::from_millis(300));
    let (addr, root) = spawn_server(ingress(admitter.clone(), true, dialer, config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;
    let credential = credential();
    let head_a = connect_head("a.example:443", Some(&credential));
    let head_b = connect_head("b.example:443", Some(&credential));

    let (first, second) = tokio::join!(request(&conn, &head_a), request(&conn, &head_b));

    assert_eq!((first.status, second.status), (200, 200));
    assert_eq!(
        admitter.calls.load(Ordering::SeqCst),
        1,
        "one connection spends one credential"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_challenged_connection_admits_on_a_later_verified_credential() {
    let (config, dialer) = tunnel_config().await;
    let admitter = StubAdmitter::admitting();
    let (addr, root) = spawn_server(ingress(admitter.clone(), true, dialer, config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let challenged = request(&conn, &connect_head("a.example:443", None)).await;
    let admitted = request(&conn, &connect_head("b.example:443", Some(&credential()))).await;

    assert_eq!((challenged.status, admitted.status), (407, 200));
    assert_eq!(admitter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_udp_as_first_request_is_challenged_and_dials_nothing() {
    let udp = udp_echo().await;
    let dialer = Arc::new(Dialer::to(udp));
    let admitter = StubAdmitter::admitting();
    let (addr, root) = spawn_server(ingress(
        admitter,
        true,
        dialer.clone(),
        MasqueConfig::default(),
    ));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let x = request(
        &conn,
        &connect_udp_head("/.well-known/masque/udp/example.com/443/", None),
    )
    .await;

    assert_eq!(x.status, 407);
    assert_eq!(dialer.dials(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_udp_after_an_admitted_connect_relays_datagrams() {
    let tcp = tcp_echo().await;
    let udp = udp_echo().await;
    let admitter = StubAdmitter::admitting();
    let ingress = Arc::new(MasqueIngress::new(
        admitter,
        Policy(true),
        Arc::new(Dialer::to(tcp)),
        Arc::new(Dialer::to(udp)),
        MasqueConfig::default(),
    ));
    let (addr, root) = spawn_server(ingress);
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    // The priming CONNECT admits the connection (what the extension does).
    let prime = request(
        &conn,
        &connect_head("prime.example:443", Some(&credential())),
    )
    .await;
    assert_eq!(prime.status, 200);

    let x = request(
        &conn,
        &connect_udp_head("/.well-known/masque/udp/example.com/443/", None),
    )
    .await;
    assert_eq!(x.status, 200);
    assert!(
        x.fields
            .iter()
            .any(|(n, v)| n == "capsule-protocol" && v == "?1"),
        "the 200 confirms the capsule protocol"
    );

    // A UDP payload rides an HTTP Datagram tagged with the stream's quarter id
    // and context 0, and the echo's reply comes back the same way.
    let stream_id = u64::from(x.send.id());
    conn.send_datagram(Bytes::from(encode_masque_datagram(stream_id, b"ping")))
        .expect("send datagram");
    let reply = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .expect("reply in time")
        .expect("datagram");
    let (qsid, context_id, payload) = read_masque_datagram(&reply).expect("well-formed");
    assert_eq!(
        (qsid, context_id, payload),
        (stream_id >> 2, 0, &b"ping"[..])
    );

    // A datagram on a context the ingress never negotiated is dropped, not
    // relayed: the next reply is for the well-formed one that follows it.
    let mut foreign = encode_varint(stream_id >> 2);
    foreign.extend_from_slice(&encode_varint(5));
    foreign.extend_from_slice(b"junk");
    conn.send_datagram(Bytes::from(foreign))
        .expect("send datagram");
    conn.send_datagram(Bytes::from(encode_masque_datagram(stream_id, b"pong")))
        .expect("send datagram");
    let reply = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .expect("reply in time")
        .expect("datagram");
    let (_, _, payload) = read_masque_datagram(&reply).expect("well-formed");
    assert_eq!(payload, b"pong");

    // A DATAGRAM capsule on the request stream is the other way in.
    let mut capsule_payload = encode_varint(0);
    capsule_payload.extend_from_slice(b"via-capsule");
    let capsule = encode_frame(0x00, &capsule_payload);
    let mut send = x.send;
    send.write_all(&encode_frame(FRAME_DATA, &capsule))
        .await
        .expect("write capsule");
    let reply = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .expect("reply in time")
        .expect("datagram");
    let (_, _, payload) = read_masque_datagram(&reply).expect("well-formed");
    assert_eq!(payload, b"via-capsule");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_udp_carrying_its_own_credential_admits_the_connection() {
    let udp = udp_echo().await;
    let admitter = StubAdmitter::admitting();
    let (addr, root) = spawn_server(ingress(
        admitter.clone(),
        true,
        Arc::new(Dialer::to(udp)),
        MasqueConfig::default(),
    ));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let x = request(
        &conn,
        &connect_udp_head(
            "/.well-known/masque/udp/example.com/443/",
            Some(&credential()),
        ),
    )
    .await;

    assert_eq!(x.status, 200);
    assert_eq!(admitter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_udp_carrying_the_credential_in_its_path_admits_a_fresh_connection() {
    // Firefox opens a dedicated HTTP/3 connection for its CONNECT-UDP
    // requests and never sends a header on them: the only credential that
    // connection ever sees is the one the extension put in the template.
    let udp = udp_echo().await;
    let admitter = StubAdmitter::admitting();
    let (addr, root) = spawn_server(ingress(
        admitter.clone(),
        true,
        Arc::new(Dialer::to(udp)),
        MasqueConfig::default(),
    ));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let password = BASE64URL_NOPAD.encode(&[7u8; SESSION_TOKEN_LEN]);
    let x = request(
        &conn,
        &connect_udp_head(
            &format!("/.well-known/masque/udp/example.com/443/?credential={password}"),
            None,
        ),
    )
    .await;
    assert_eq!(x.status, 200);
    assert_eq!(admitter.calls.load(Ordering::SeqCst), 1);

    // The connection is admitted: the next CONNECT-UDP needs nothing at all.
    let again = request(
        &conn,
        &connect_udp_head("/.well-known/masque/udp/example.org/443/", None),
    )
    .await;
    assert_eq!(again.status, 200);
    assert_eq!(admitter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_without_datagram_support_gets_no_udp_tunnel() {
    let udp = udp_echo().await;
    let (addr, root) = spawn_server(ingress(
        StubAdmitter::admitting(),
        true,
        Arc::new(Dialer::to(udp)),
        MasqueConfig::default(),
    ));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, false).await;

    let x = request(
        &conn,
        &connect_udp_head(
            "/.well-known/masque/udp/example.com/443/",
            Some(&credential()),
        ),
    )
    .await;

    assert_eq!(x.status, 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_udp_path_off_the_template_is_a_400() {
    let udp = udp_echo().await;
    let dialer = Arc::new(Dialer::to(udp));
    let (addr, root) = spawn_server(ingress(
        StubAdmitter::admitting(),
        true,
        dialer.clone(),
        MasqueConfig::default(),
    ));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let x = request(
        &conn,
        &connect_udp_head("/masque?h=example.com", Some(&credential())),
    )
    .await;

    assert_eq!(x.status, 400);
    assert_eq!(dialer.dials(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_destination_is_a_403_before_the_credential_is_read() {
    let (config, dialer) = tunnel_config().await;
    let admitter = StubAdmitter::admitting();
    let (addr, root) = spawn_server(ingress(admitter.clone(), false, dialer.clone(), config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let x = request(&conn, &connect_head("10.0.0.1:22", Some(&credential()))).await;

    assert_eq!(x.status, 403);
    assert_eq!(admitter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(dialer.dials(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_credential_is_challenged_and_a_spent_one_refused() {
    let (config, dialer) = tunnel_config().await;
    let (addr, root) = spawn_server(ingress(
        StubAdmitter::with(TokenAdmission::Reject),
        true,
        dialer.clone(),
        config.clone(),
    ));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;
    let x = request(&conn, &connect_head("example.com:443", Some(&credential()))).await;
    assert_eq!(x.status, 407, "a stale credential is re-challenged");

    let (addr, root) = spawn_server(ingress(
        StubAdmitter::with(TokenAdmission::Denied),
        true,
        dialer.clone(),
        config,
    ));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;
    let x = request(&conn, &connect_head("example.com:443", Some(&credential()))).await;
    assert_eq!(x.status, 403, "a spent credential is refused");
    assert_eq!(dialer.dials(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_upstream_is_a_502() {
    let config = MasqueConfig {
        other_response: decoy_response(),
        ..MasqueConfig::default()
    };
    let (addr, root) = spawn_server(ingress(
        StubAdmitter::admitting(),
        true,
        Arc::new(Dialer::refusing()),
        config,
    ));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let x = request(&conn, &connect_head("example.com:443", Some(&credential()))).await;

    assert_eq!(x.status, 502);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_that_is_not_a_proxy_request_gets_the_deployer_response() {
    let (config, dialer) = tunnel_config().await;
    let (addr, root) = spawn_server(ingress(StubAdmitter::admitting(), true, dialer, config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let get = encode_frame(
        FRAME_HEADERS,
        &encode_field_section(&[
            field(b":method", b"GET"),
            field(b":scheme", b"https"),
            field(b":authority", COVER.as_bytes()),
            field(b":path", b"/"),
        ]),
    );
    let mut x = request(&conn, &get).await;

    assert_eq!(x.status, 200);
    let body = read_data(&mut x.recv, x.rest, usize::MAX).await;
    assert_eq!(body, b"<h1>It works!</h1>");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnels_past_the_per_connection_cap_are_refused() {
    let (mut config, dialer) = tunnel_config().await;
    config.max_tunnels_per_connection = 2;
    let (addr, root) = spawn_server(ingress(StubAdmitter::admitting(), true, dialer, config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let first = request(&conn, &connect_head("a.example:443", Some(&credential()))).await;
    let second = request(&conn, &connect_head("b.example:443", None)).await;
    let third = request(&conn, &connect_head("c.example:443", None)).await;
    assert_eq!((first.status, second.status, third.status), (200, 200, 503));

    // Ending a tunnel frees its slot.
    drop(first);
    let mut fourth = None;
    for _ in 0..50 {
        let x = request(&conn, &connect_head("d.example:443", None)).await;
        if x.status == 200 {
            fourth = Some(x);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(fourth.is_some(), "a freed slot admits a new tunnel");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admitted_connection_is_closed_when_its_admission_ends() {
    let (mut config, dialer) = tunnel_config().await;
    config.admission_period = Duration::from_secs(1);
    config.admission_grace = Duration::ZERO;
    let (addr, root) = spawn_server(ingress(StubAdmitter::admitting(), true, dialer, config));
    let conn = connect(addr, &root).await;
    let _ctrl = open_control(&conn, true).await;

    let x = request(&conn, &connect_head("example.com:443", Some(&credential()))).await;
    assert_eq!(x.status, 200);

    // The admission ends at the next one-second boundary: the server closes
    // and the client sees a neutral application close.
    let reason = tokio::time::timeout(Duration::from_secs(3), conn.closed())
        .await
        .expect("the connection is closed at the boundary");
    match reason {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code, VarInt::from_u32(0));
            assert!(close.reason.is_empty(), "no Warren-specific close reason");
        }
        other => panic!("expected an application close, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handed_off_request_read_partly_by_the_dispatcher_is_served() {
    // The deployer's dispatcher accepted the peer's first uni stream and its
    // first request stream, read a few bytes of the latter, then recognised
    // the peer as HTTP/3: the ingress must resume exactly where it stopped.
    let (config, dialer) = tunnel_config().await;
    let ingress = ingress(StubAdmitter::admitting(), true, dialer, config);
    let (chain, key_der, root_der) = mint_cover_cert();
    let endpoint = server_endpoint(chain, key_der);
    let addr = endpoint.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let ingress = ingress.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                let uni = conn.accept_uni().await.expect("first uni");
                let (send, mut recv) = conn.accept_bi().await.expect("first request");
                let mut prefix = [0u8; 3];
                recv.read_exact(&mut prefix).await.expect("three bytes");
                ingress
                    .serve_connection(
                        conn,
                        Http3Handoff {
                            uni: Some(uni),
                            request: Some(PendingRequest {
                                send,
                                recv,
                                bytes: Bytes::copy_from_slice(&prefix),
                            }),
                        },
                    )
                    .await;
            });
        }
    });

    let conn = connect(addr, &root_der).await;
    let _ctrl = open_control(&conn, true).await;
    // Make sure the uni stream is accepted first on the server.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut x = request(&conn, &connect_head("example.com:443", Some(&credential()))).await;
    assert_eq!(x.status, 200);
    x.send
        .write_all(&encode_frame(FRAME_DATA, b"through the handoff"))
        .await
        .expect("write");
    let echoed = read_data(&mut x.recv, x.rest, 19).await;
    assert_eq!(echoed, b"through the handoff");
}

// ---- the crate's own client against the ingress ------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_library_drives_both_tunnel_kinds() {
    use warrenguard_masque::client::{ClientError, MasqueClient};
    let tcp = tcp_echo().await;
    let udp = udp_echo().await;
    let ingress = Arc::new(MasqueIngress::new(
        StubAdmitter::admitting(),
        Policy(true),
        Arc::new(Dialer::to(tcp)),
        Arc::new(Dialer::to(udp)),
        MasqueConfig::default(),
    ));
    let (addr, root) = spawn_server(ingress);
    let client = MasqueClient::open(connect(addr, &root).await)
        .await
        .expect("opens");

    // The challenge surfaces as a typed status with its fields.
    let refused = client
        .connect_tcp("example.com:443", None)
        .await
        .expect_err("challenged");
    match refused {
        ClientError::Status { status, fields } => {
            assert_eq!(status, 407);
            assert!(fields.iter().any(|(n, _)| n == "proxy-authenticate"));
        }
        other => panic!("expected a status, got {other:?}"),
    }

    let credential = credential();
    let mut tcp = client
        .connect_tcp("example.com:443", Some(&credential))
        .await
        .expect("tunnel opens");
    tcp.send(b"round trip").await.expect("send");
    let mut got = Vec::new();
    while got.len() < 10 {
        got.extend_from_slice(&tcp.recv().await.expect("recv").expect("open"));
    }
    assert_eq!(got, b"round trip");

    let mut udp = client
        .connect_udp("2001:db8::1", 53, None)
        .await
        .expect("udp tunnel on the admitted connection");
    // And on a fresh connection, the browser's own shape: the credential in
    // the template's query, nothing in a header.
    let fresh = MasqueClient::open(connect(addr, &root).await)
        .await
        .expect("opens");
    let password = BASE64URL_NOPAD.encode(&[7u8; SESSION_TOKEN_LEN]);
    let mut in_path = fresh
        .connect_udp_with_path_credential("example.com", 443, &password)
        .await
        .expect("admitted by the path credential");
    in_path.send(b"path").expect("send");
    let echoed = tokio::time::timeout(Duration::from_secs(5), in_path.recv())
        .await
        .expect("reply in time")
        .expect("tunnel open");
    assert_eq!(echoed.as_ref(), b"path");
    udp.send(b"dns?").expect("send datagram");
    let reply = tokio::time::timeout(Duration::from_secs(5), udp.recv())
        .await
        .expect("reply in time")
        .expect("tunnel open");
    assert_eq!(reply.as_ref(), b"dns?");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_pump_forwards_a_local_socket_through_the_tunnel() {
    use warrenguard_masque::client::MasqueClient;
    let (config, dialer) = tunnel_config().await;
    let (addr, root) = spawn_server(ingress(StubAdmitter::admitting(), true, dialer, config));
    let client = MasqueClient::open(connect(addr, &root).await)
        .await
        .expect("opens");
    let tunnel = client
        .connect_tcp("example.com:443", Some(&credential()))
        .await
        .expect("tunnel opens");

    // A local duplex stands in for the accepted local socket of a forwarder.
    let (local, mut ours) = tokio::io::duplex(64 * 1024);
    tokio::spawn(tunnel.pump(local));
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let payload = vec![0x5au8; 250_000];
    ours.write_all(&payload).await.expect("write");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), ours.read_exact(&mut echoed))
        .await
        .expect("echo in time")
        .expect("read");
    assert_eq!(echoed, payload);
}
