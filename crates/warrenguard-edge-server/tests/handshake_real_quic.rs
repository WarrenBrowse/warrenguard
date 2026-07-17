//! End-to-end validation of the edge WebTransport handshake over REAL QUIC
//! (warren-quinn) on loopback: a real quinn client performs the browser side of
//! the WebTransport-over-HTTP/3 handshake (control-stream SETTINGS + extended
//! CONNECT with a real Privacy Pass token) against [`run_edge_listener`], and we
//! assert the server admits the session and writes the `:status 200` accept the
//! client can read.
//!
//! This is the "necessary" datapath validation (fakes are not sufficient, but a
//! real-transport in-process test is a real transport): it exercises the actual
//! quinn endpoint setup, the X.509 cover-cert + ALPN `h3` negotiation, real uni
//! and bidi stream handling, the QPACK-decoded classification, real token
//! verification, and the real 200 response. Real-browser (Chrome) validation
//! against a deployed edge endpoint is the remaining step it does not cover.
//!
//! Loopback only.

use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, VarInt};
use tokio_util::sync::CancellationToken;

use warrenguard_edge::{
    FRAME_HEADERS, FRAME_SETTINGS, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM,
    SETTINGS_WT_MAX_SESSIONS, STREAM_CONTROL, encode_frame, encode_varint, read_frame,
};
use warrenguard_edge_server::{
    EdgeOutcome, EdgeServerError, OfflineTokenGate, SessionTokenAdmitter, TokenAdmission,
    edge_transport_config, run_edge_listener, serve_edge_session, serve_edge_session_with_deadline,
};
use warrenguard_token::{IssuerPublicKey, IssuerSecretKey, Token, TokenChallenge, TokenError};
use warrenguard_wire::SessionToken;

// ---- token minting (real blind-RSA issuance) ------------------------------

fn issuer() -> (IssuerSecretKey, IssuerPublicKey) {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xED9E_5EED);
    let sk = IssuerSecretKey::generate(&mut rng).expect("issuer key");
    let pk = sk.public_key();
    (sk, pk)
}

fn mint_token(sk: &IssuerSecretKey, pk: &IssuerPublicKey) -> Token {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x7057_7057);
    let challenge =
        TokenChallenge::for_context("issuer.warren.test", [0x11; 32]).expect("challenge");
    let (req, state) = pk.blind_token(&mut rng, &challenge).expect("blind");
    let blind_sig = sk.blind_sign(&req).expect("blind sign");
    pk.finalize_token(state, &blind_sig).expect("finalize")
}

// ---- QPACK / HTTP/3 client-side request encoding --------------------------

fn base64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..chunk.len() + 1 {
            out.push(A[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

/// QPACK string literal, Huffman bit clear, 7-bit length prefix (with the
/// RFC 7541 continuation for long values like the base64 token).
fn lit_str(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = bytes.len();
    if len < 0x7f {
        out.push(len as u8);
    } else {
        out.push(0x7f);
        let mut rem = len - 0x7f;
        while rem >= 0x80 {
            out.push((rem as u8 & 0x7f) | 0x80);
            rem >>= 7;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(bytes);
    out
}

/// QPACK literal field line with a literal (non-indexed) name.
fn lit_name(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if name.len() < 7 {
        out.push(0x20 | name.len() as u8);
    } else {
        out.push(0x20 | 0x07);
        out.push((name.len() - 7) as u8);
    }
    out.extend_from_slice(name);
    out.extend_from_slice(&lit_str(value));
    out
}

/// The QPACK field section for a WebTransport extended-CONNECT, optionally with
/// an `Authorization: PrivateToken` header carrying `token`.
fn webtransport_field_section(authority: &str, path: &str, token: Option<&Token>) -> Vec<u8> {
    let mut buf = vec![0x00, 0x00]; // encoded field section prefix (RIC=0, Base=0)
    buf.push(0xc0 | 15); // indexed :method CONNECT
    buf.push(0xc0 | 23); // indexed :scheme https
    buf.push(0x50); // :authority via static name ref (index 0)
    buf.extend_from_slice(&lit_str(authority.as_bytes()));
    buf.push(0x51); // :path via static name ref (index 1)
    buf.extend_from_slice(&lit_str(path.as_bytes()));
    buf.extend_from_slice(&lit_name(b":protocol", b"webtransport"));
    if let Some(t) = token {
        let header = format!("PrivateToken token=\"{}\"", base64url(&t.serialize()));
        buf.extend_from_slice(&lit_name(b"authorization", header.as_bytes()));
    }
    buf
}

/// The client's HTTP/3 control-stream bytes: stream type then a SETTINGS frame
/// advertising WebTransport support.
fn client_control_stream() -> Vec<u8> {
    let mut settings = Vec::new();
    for (id, val) in [
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1u64),
        (SETTINGS_H3_DATAGRAM, 1),
        (SETTINGS_WT_MAX_SESSIONS, 1),
    ] {
        settings.extend_from_slice(&encode_varint(id));
        settings.extend_from_slice(&encode_varint(val));
    }
    let mut out = encode_varint(STREAM_CONTROL);
    out.extend_from_slice(&encode_frame(FRAME_SETTINGS, &settings));
    out
}

// ---- QUIC endpoint setup (X.509 cover cert, ALPN h3) ----------------------

fn server_endpoint(chain: Vec<Vec<u8>>, key_der: Vec<u8>) -> Endpoint {
    use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let chain_der: Vec<CertificateDer<'static>> =
        chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let mut server_cfg = warrenguard_tls::make_server_config_x509(
        chain_der,
        key,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("x509 server config");
    server_cfg.transport_config(edge_transport_config());
    Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).expect("server bind")
}

fn client_endpoint(root_der: Vec<u8>) -> Endpoint {
    use quinn::rustls::pki_types::CertificateDer;
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der))
        .expect("trust test root");
    let mut client_cfg = warrenguard_tls::make_client_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("webpki client config");
    client_cfg.transport_config(edge_transport_config());
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
    endpoint.set_default_client_config(client_cfg);
    endpoint
}

/// Mints a self-signed root CA and a leaf for `cover.example.com`. Returns the
/// leaf chain DER, the leaf key DER (PKCS#8), and the root DER (client trust).
fn mint_cover_cert() -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "warren-edge-test-root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let leaf_params =
        CertificateParams::new(vec!["cover.example.com".to_string()]).expect("leaf params");
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

// ---- client side of the handshake -----------------------------------------

async fn read_one_frame_client(recv: &mut RecvStream) -> Vec<u8> {
    let mut buf = Vec::new();
    for _ in 0..64 {
        if read_frame(&buf).is_some() {
            return buf;
        }
        let mut chunk = [0u8; 2048];
        // A rejected session closes the connection; tolerate that and return
        // whatever (possibly nothing) was received rather than panicking.
        match recv.read(&mut chunk).await {
            Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(None) | Err(_) => break,
        }
    }
    buf
}

/// Drives the browser side of the handshake and returns the server's response
/// bytes on the CONNECT stream (a HEADERS frame if admitted, empty if closed).
async fn drive_client(conn: &Connection, token: Option<&Token>) -> Vec<u8> {
    // Open the control stream and send WebTransport-capable SETTINGS. Keep it
    // open (a real HTTP/3 control stream lives for the connection).
    let mut ctrl = conn.open_uni().await.expect("open control uni");
    ctrl.write_all(&client_control_stream())
        .await
        .expect("write client SETTINGS");

    // Open the CONNECT bidi stream and send the extended-CONNECT HEADERS. Do not
    // finish it: the WebTransport session lives on this stream.
    let (mut send, mut recv) = conn.open_bi().await.expect("open connect bidi");
    let field_section = webtransport_field_section("cover.example.com", "/warren", token);
    send.write_all(&encode_frame(FRAME_HEADERS, &field_section))
        .await
        .expect("write CONNECT headers");

    tokio::time::timeout(Duration::from_secs(5), read_one_frame_client(&mut recv))
        .await
        .expect("server response within timeout")
}

// ---- tests ----------------------------------------------------------------

#[tokio::test]
async fn browser_webtransport_handshake_is_admitted_with_a_valid_token() {
    let (sk, pk) = issuer();
    let token = mint_token(&sk, &pk);

    let (chain, key_der, root_der) = mint_cover_cert();
    let server = server_endpoint(chain, key_der);
    let server_addr = server.local_addr().expect("server addr");

    let gate = Arc::new(OfflineTokenGate { issuer: pk });
    let shutdown = CancellationToken::new();
    let listener = tokio::spawn(run_edge_listener(server, gate, shutdown.clone()));

    let client = client_endpoint(root_der);
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .connect(server_addr, "cover.example.com")
            .expect("connect builds"),
    )
    .await
    .expect("handshake must not time out")
    .expect("QUIC + TLS handshake completes over ALPN h3");

    let response = drive_client(&conn, Some(&token)).await;

    // The server admitted the session: it wrote a HEADERS frame carrying the
    // `:status 200` field section (RIC=0, Base=0, static index 25 => 0xD9).
    let (frame, _) = read_frame(&response).expect("server wrote a frame");
    assert_eq!(frame.ty, FRAME_HEADERS, "response must be a HEADERS frame");
    assert_eq!(
        frame.payload,
        &[0x00, 0x00, 0xD9],
        "the accept must be a :status 200 field section"
    );

    // Close the client so the server's held-open session ends and the
    // listener's `wait_idle` can drain.
    conn.close(VarInt::from_u32(0), b"");
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
}

#[tokio::test]
async fn a_webtransport_connect_without_a_token_is_rejected() {
    // Same handshake but the browser presents no token: the offline gate refuses
    // and the server closes without writing a 200.
    let (_sk, pk) = issuer();
    let (chain, key_der, root_der) = mint_cover_cert();
    let server = server_endpoint(chain, key_der);
    let server_addr = server.local_addr().expect("server addr");

    let gate = Arc::new(OfflineTokenGate { issuer: pk });
    let shutdown = CancellationToken::new();
    let listener = tokio::spawn(run_edge_listener(server, gate, shutdown.clone()));

    let client = client_endpoint(root_der);
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .connect(server_addr, "cover.example.com")
            .expect("connect builds"),
    )
    .await
    .expect("handshake must not time out")
    .expect("handshake completes");

    let response = drive_client(&conn, None).await;
    assert!(
        read_frame(&response).is_none(),
        "a tokenless CONNECT must not receive a 200 accept, got {response:?}"
    );

    conn.close(VarInt::from_u32(0), b"");
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
}

#[tokio::test]
async fn offline_gate_admits_a_valid_token_and_refuses_a_forged_one() {
    let (sk, pk) = issuer();
    let token = mint_token(&sk, &pk);
    let gate = OfflineTokenGate { issuer: pk };

    async fn admits(gate: &OfflineTokenGate, t: Option<&Token>) -> bool {
        let tokens: Vec<SessionToken> =
            t.map(|t| SessionToken(t.serialize())).into_iter().collect();
        matches!(gate.admit(&tokens).await, TokenAdmission::Admit { .. })
    }

    assert!(
        admits(&gate, Some(&token)).await,
        "a validly-issued token is admitted"
    );
    assert!(!admits(&gate, None).await, "no token is refused");

    // A token whose authenticator is corrupted must not verify.
    let mut bytes = token.serialize();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    match Token::parse(&bytes) {
        Ok(forged) => assert!(
            !admits(&gate, Some(&forged)).await,
            "a forged token is refused"
        ),
        Err(TokenError::MalformedToken) => {} // parse itself may reject; also fine
        Err(e) => panic!("unexpected parse error: {e:?}"),
    }
}

#[tokio::test]
async fn direct_serve_edge_session_admits_over_loopback() {
    // Exercises `serve_edge_session` directly (not via the accept loop) to keep
    // the unit of behaviour under test explicit.
    let (sk, pk) = issuer();
    let token = mint_token(&sk, &pk);
    let (chain, key_der, root_der) = mint_cover_cert();
    let server = server_endpoint(chain, key_der);
    let server_addr = server.local_addr().expect("addr");

    let gate = Arc::new(OfflineTokenGate { issuer: pk });
    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming");
        let conn = incoming.await.expect("server handshake");
        let outcome = serve_edge_session(&conn, gate).await;
        // Hold the connection open long enough for the client to read the 200
        // before `conn` drops (a real listener holds it for the whole session).
        tokio::time::sleep(Duration::from_millis(300)).await;
        outcome
    });

    let client = client_endpoint(root_der);
    let conn = client
        .connect(server_addr, "cover.example.com")
        .expect("connect builds")
        .await
        .expect("client handshake");
    let response = drive_client(&conn, Some(&token)).await;
    assert!(read_frame(&response).is_some(), "client saw the 200 accept");

    let outcome = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("server task finishes")
        .expect("join")
        .expect("session ok");
    assert_eq!(
        outcome,
        EdgeOutcome::Admitted {
            authority: "cover.example.com".to_string(),
            path: "/warren".to_string(),
        },
    );
}

#[tokio::test]
async fn a_client_that_never_opens_the_connect_stream_is_ended_within_the_setup_deadline() {
    // Slowloris guard: a client that completes the control-stream
    // SETTINGS handshake but never opens the CONNECT bidi stream must not pin
    // the session forever. If `run_handshake` awaited
    // `conn.accept_bi()` with no bound at all, `edge_transport_config`'s
    // 10s keep-alive would keep such a connection alive indefinitely from the
    // server's own side, so nothing would ever end the session on its own.
    //
    // Uses the injectable-deadline test entry point so the test does not have
    // to wait out the real (10s) `pump::SETUP_DEADLINE` to observe it firing.
    let (_sk, pk) = issuer();
    let (chain, key_der, root_der) = mint_cover_cert();
    let server = server_endpoint(chain, key_der);
    let server_addr = server.local_addr().expect("server addr");

    let gate = Arc::new(OfflineTokenGate { issuer: pk });
    let short_deadline = Duration::from_millis(200);
    let accept = tokio::spawn(async move {
        let incoming = server.accept().await.expect("incoming");
        let conn = incoming.await.expect("server handshake");
        serve_edge_session_with_deadline(&conn, gate, short_deadline).await
    });

    let client = client_endpoint(root_der);
    let conn = client
        .connect(server_addr, "cover.example.com")
        .expect("connect builds")
        .await
        .expect("client handshake");

    // Complete the control-stream SETTINGS (so the handshake gets past the
    // WebTransport-advertisement check) but deliberately never open the
    // CONNECT bidi stream.
    let mut ctrl = conn.open_uni().await.expect("open control uni");
    ctrl.write_all(&client_control_stream())
        .await
        .expect("write client SETTINGS");

    // The server must end the session within (a small margin over) the
    // injected deadline, not hang until the QUIC idle timeout.
    let outcome = tokio::time::timeout(short_deadline + Duration::from_secs(2), accept)
        .await
        .expect("the server must end the stalled session within the setup deadline, not hang")
        .expect("join");
    assert!(
        matches!(outcome, Err(EdgeServerError::HandshakeTimeout)),
        "expected a handshake timeout, got {outcome:?}"
    );

    // The server closes the connection on timeout so any per-IP/global
    // admission slot the caller holds for the session is released; the
    // client observes that as its connection closing.
    tokio::time::timeout(Duration::from_secs(2), conn.closed())
        .await
        .expect("client must observe the server closing the stalled connection");
}
