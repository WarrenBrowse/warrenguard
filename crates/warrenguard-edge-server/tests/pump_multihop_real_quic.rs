//! Loopback validation of the multi-hop entry pump over REAL QUIC
//! (warren-quinn): a synthetic browser opens a WebTransport session to the edge
//! and tunnels the Warren circuit inside it (a WebTransport bidi setup stream
//! carrying a real `WarrenMultihopFrame`, then a WebTransport DATA datagram);
//! the edge strips the WebTransport framing, shuttles the setup to a fake exit,
//! and pumps the datagram across, translating the Quarter-Stream-ID prefix in
//! both directions.
//!
//! This is the "necessary" datapath tier (a real in-process transport is a real
//! transport). Real end-to-end validation needs the browser-side Warren
//! WebTransport client (the extension edge-CONNECT tier), which does not exist
//! yet, so the pump is not mounted on a production exit until that closes the
//! loop.
//!
//! Loopback only.

use std::time::Duration;

use bytes::Bytes;
use quinn::{Endpoint, RecvStream, VarInt};

use warrenguard_edge::{
    FRAME_HEADERS, FRAME_SETTINGS, SETTINGS_H3_DATAGRAM, SETTINGS_WT_MAX_SESSIONS, STREAM_CONTROL,
    encode_bidi_stream_header, encode_frame, encode_varint, encode_wt_datagram, read_frame,
    read_wt_datagram, webtransport_accept_response,
};
use warrenguard_edge_server::{
    PumpError, edge_transport_config, pump_multihop_entry, serve_edge_entry,
};
use warrenguard_multihop::{ExitId, WARREN_HPKE_VERSION, WarrenMultihopFrame};

// ---- certs + endpoints ----------------------------------------------------

/// Mints a self-signed root CA and a leaf for `name`. Returns the leaf chain
/// DER, the leaf key DER (PKCS#8), and the root DER (for the dialer's trust).
fn mint_cert(name: &str) -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let mut ca_params = CertificateParams::new(vec![]).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "warren-edge-pump-test-root");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");

    let leaf_params = CertificateParams::new(vec![name.to_string()]).expect("leaf params");
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

fn server_endpoint(chain: Vec<Vec<u8>>, key_der: Vec<u8>) -> Endpoint {
    use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let chain_der: Vec<CertificateDer<'static>> =
        chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let mut cfg = warrenguard_tls::make_server_config_x509(
        chain_der,
        key,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("x509 server config");
    cfg.transport_config(edge_transport_config());
    Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).expect("server bind")
}

fn client_endpoint(root_der: Vec<u8>) -> Endpoint {
    use quinn::rustls::pki_types::CertificateDer;
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der))
        .expect("trust test root");
    let mut cfg = warrenguard_tls::make_client_config_webpki(
        roots,
        warrenguard_tls::default_crypto_provider(),
        &[b"h3"],
    )
    .expect("webpki client config");
    cfg.transport_config(edge_transport_config());
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
    endpoint.set_default_client_config(cfg);
    endpoint
}

// ---- a real (dummy-content) WarrenMultihopFrame ---------------------------

fn setup_frame(exit_id: ExitId) -> Vec<u8> {
    WarrenMultihopFrame {
        version: WARREN_HPKE_VERSION,
        exit_id,
        epoch: 1,
        seq: 0,
        encapsulated_key: [0x22; 32],
        aead_tag: [0x33; 16],
        ciphertext: b"opaque-hpke-ciphertext".to_vec(),
    }
    .encode()
    .expect("encode setup frame")
}

// ---- browser-side HTTP/3 handshake encoding (for the serve_edge_entry test) -

fn lit_str(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![bytes.len() as u8];
    out.extend_from_slice(bytes);
    out
}

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

/// A QPACK field section for a WebTransport extended-CONNECT (no token; the
/// serve_edge_entry test uses an admit-all gate).
fn webtransport_connect_headers(authority: &str, path: &str) -> Vec<u8> {
    let mut buf = vec![0x00, 0x00]; // encoded field section prefix
    buf.push(0xc0 | 15); // indexed :method CONNECT
    buf.push(0xc0 | 23); // indexed :scheme https
    buf.push(0x50); // :authority via static name ref (index 0)
    buf.extend_from_slice(&lit_str(authority.as_bytes()));
    buf.push(0x51); // :path via static name ref (index 1)
    buf.extend_from_slice(&lit_str(path.as_bytes()));
    buf.extend_from_slice(&lit_name(b":protocol", b"webtransport"));
    buf
}

/// The browser's HTTP/3 control-stream bytes: stream type then WebTransport-
/// capable SETTINGS.
fn client_control_stream() -> Vec<u8> {
    let mut settings = Vec::new();
    for (id, val) in [(SETTINGS_H3_DATAGRAM, 1u64), (SETTINGS_WT_MAX_SESSIONS, 1)] {
        settings.extend_from_slice(&encode_varint(id));
        settings.extend_from_slice(&encode_varint(val));
    }
    let mut out = encode_varint(STREAM_CONTROL);
    out.extend_from_slice(&encode_frame(FRAME_SETTINGS, &settings));
    out
}

async fn read_one_frame(recv: &mut RecvStream) -> Vec<u8> {
    let mut buf = Vec::new();
    for _ in 0..64 {
        if read_frame(&buf).is_some() {
            return buf;
        }
        let mut chunk = [0u8; 2048];
        match recv.read(&mut chunk).await {
            Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(None) | Err(_) => break,
        }
    }
    buf
}

// ---- the test -------------------------------------------------------------

#[tokio::test]
async fn pump_bridges_a_webtransport_session_to_the_exit_and_translates_datagrams() {
    let exit_id = ExitId::from_bytes([0xAB; 16]);
    let reply_frame = setup_frame(exit_id); // the exit's canned setup reply
    let dgram_payload = b"warren-data-datagram".to_vec();

    // --- fake exit: accepts the shuttled setup, replies, echoes datagrams ---
    let (exit_chain, exit_key, exit_root) = mint_cert("exit.example.com");
    let exit_server = server_endpoint(exit_chain, exit_key);
    let exit_addr = exit_server.local_addr().expect("exit addr");
    let exit_reply = reply_frame.clone();
    let exit_task = tokio::spawn(async move {
        let conn = exit_server
            .accept()
            .await
            .expect("exit incoming")
            .await
            .expect("exit handshake");
        // Shuttle: read the setup frame the edge forwards, reply with a frame.
        let (mut send, mut recv) = conn.accept_bi().await.expect("exit accept setup bi");
        let got = recv.read_to_end(64 * 1024).await.expect("exit read setup");
        // The exit sees the RAW WarrenMultihopFrame, no WebTransport header.
        assert!(
            WarrenMultihopFrame::decode(&got).is_ok(),
            "exit must receive a clean WarrenMultihopFrame (WT header stripped)"
        );
        send.write_all(&exit_reply).await.expect("exit write reply");
        send.finish().expect("exit finish reply");
        // Echo every DATA datagram back to the edge as a plain QUIC datagram.
        while let Ok(d) = conn.read_datagram().await {
            if conn.send_datagram(d).is_err() {
                break;
            }
        }
    });

    // --- edge: accept the browser, 200, then pump ---------------------------
    let (edge_chain, edge_key, edge_root) = mint_cert("cover.example.com");
    let edge_server = server_endpoint(edge_chain, edge_key);
    let edge_addr = edge_server.local_addr().expect("edge addr");
    let edge_task = tokio::spawn(async move {
        let conn = edge_server
            .accept()
            .await
            .expect("edge incoming")
            .await
            .expect("edge handshake");
        // Accept the CONNECT stream, read the browser's HEADERS, write 200.
        let (mut c_send, mut c_recv) = conn.accept_bi().await.expect("edge accept connect bi");
        let _headers = read_one_frame(&mut c_recv).await;
        c_send
            .write_all(&webtransport_accept_response())
            .await
            .expect("edge write 200");
        // Dial the fake exit for whatever exit_id the frame carries.
        let exit_client = client_endpoint(exit_root);
        let dialer = move |_exit_id: ExitId| {
            let exit_client = exit_client.clone();
            async move {
                exit_client
                    .connect(exit_addr, "exit.example.com")
                    .map_err(|_| PumpError::ExitDial)?
                    .await
                    .map_err(|_| PumpError::ExitDial)
            }
        };
        pump_multihop_entry(&conn, c_send, c_recv, dialer).await
    });

    // --- browser: open the WT session and tunnel a setup frame + a datagram -
    let browser = client_endpoint(edge_root);
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        browser
            .connect(edge_addr, "cover.example.com")
            .expect("connect builds"),
    )
    .await
    .expect("handshake within timeout")
    .expect("browser handshake");

    // CONNECT stream (the WebTransport session). Keep it open.
    let (mut connect_send, mut connect_recv) = conn.open_bi().await.expect("open connect bi");
    let session_id = u64::from(connect_send.id());
    // A minimal WebTransport CONNECT HEADERS frame (content is irrelevant here;
    // the edge task reads one frame then writes 200).
    connect_send
        .write_all(&encode_frame(FRAME_HEADERS, &[0x00, 0x00]))
        .await
        .expect("write connect headers");
    let resp = read_one_frame(&mut connect_recv).await;
    assert!(
        read_frame(&resp).is_some(),
        "browser must read the 200 accept"
    );

    // WebTransport bidi setup stream: WT header + a real WarrenMultihopFrame.
    let (mut setup_send, mut setup_recv) = conn.open_bi().await.expect("open setup bi");
    let mut wt_setup = encode_bidi_stream_header(session_id);
    wt_setup.extend_from_slice(&setup_frame(exit_id));
    setup_send
        .write_all(&wt_setup)
        .await
        .expect("write wt setup");
    setup_send.finish().expect("finish setup send");
    let reply = setup_recv.read_to_end(64 * 1024).await.expect("read reply");
    assert_eq!(
        reply, reply_frame,
        "the browser must receive the exit's setup reply, verbatim, as the WT stream body"
    );

    // DATA: send WebTransport datagrams (qsid-prefixed) until one is echoed.
    let wt_dgram = encode_wt_datagram(session_id, &dgram_payload);
    let mut echoed = None;
    for _ in 0..50 {
        // Datagrams are unreliable; resend until the round-trip echo arrives.
        let _ = conn.send_datagram(Bytes::from(wt_dgram.clone()));
        match tokio::time::timeout(Duration::from_millis(100), conn.read_datagram()).await {
            Ok(Ok(d)) => {
                echoed = Some(d);
                break;
            }
            _ => continue,
        }
    }
    let echoed = echoed.expect("a WebTransport DATA datagram must round-trip through the exit");
    let (qsid, payload) = read_wt_datagram(&echoed).expect("echoed WT datagram parses");
    assert_eq!(
        qsid,
        session_id >> 2,
        "the edge must re-prefix the exit's datagram with our Quarter-Stream-ID"
    );
    assert_eq!(
        payload, dgram_payload,
        "the DATA payload must survive the browser->exit->browser round-trip"
    );

    // Close so the pump's DATA loop ends and both server tasks drain.
    conn.close(VarInt::from_u32(0), b"done");
    let summary = tokio::time::timeout(Duration::from_secs(5), edge_task)
        .await
        .expect("edge task finishes")
        .expect("edge join")
        .expect("pump ok");
    assert!(
        summary.browser_to_exit >= 1,
        "at least one datagram was forwarded browser->exit, got {summary:?}"
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), exit_task).await;
}

/// Spawns a fake exit that accepts the shuttled setup, replies with
/// `reply_frame`, and echoes every DATA datagram. Returns its address, the
/// client-trust root DER for the edge's dialer, and the task handle.
fn spawn_fake_exit(
    reply_frame: Vec<u8>,
) -> (std::net::SocketAddr, Vec<u8>, tokio::task::JoinHandle<()>) {
    let (chain, key, root) = mint_cert("exit.example.com");
    let server = server_endpoint(chain, key);
    let addr = server.local_addr().expect("exit addr");
    let task = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("exit incoming")
            .await
            .expect("exit handshake");
        let (mut send, mut recv) = conn.accept_bi().await.expect("exit accept setup bi");
        let got = recv.read_to_end(64 * 1024).await.expect("exit read setup");
        assert!(
            WarrenMultihopFrame::decode(&got).is_ok(),
            "exit must receive a clean WarrenMultihopFrame (WT header stripped)"
        );
        send.write_all(&reply_frame)
            .await
            .expect("exit write reply");
        send.finish().expect("exit finish reply");
        while let Ok(d) = conn.read_datagram().await {
            if conn.send_datagram(d).is_err() {
                break;
            }
        }
    });
    (addr, root, task)
}

#[tokio::test]
async fn serve_edge_entry_handshakes_then_pumps_the_session_to_the_exit() {
    // The production entry path: the full browser WebTransport-over-HTTP/3
    // handshake (control SETTINGS + extended CONNECT) followed by the multi-hop
    // entry pump, composed by `serve_edge_entry` (a blind bridge), over real QUIC.
    let exit_id = ExitId::from_bytes([0xCD; 16]);
    let reply_frame = setup_frame(exit_id);
    let dgram_payload = b"entry-path-datagram".to_vec();
    let (exit_addr, exit_root, exit_task) = spawn_fake_exit(reply_frame.clone());

    let (edge_chain, edge_key, edge_root) = mint_cert("cover.example.com");
    let edge_server = server_endpoint(edge_chain, edge_key);
    let edge_addr = edge_server.local_addr().expect("edge addr");
    let edge_task = tokio::spawn(async move {
        let conn = edge_server
            .accept()
            .await
            .expect("edge incoming")
            .await
            .expect("edge handshake");
        let exit_client = client_endpoint(exit_root);
        let dialer = move |_exit_id: ExitId| {
            let exit_client = exit_client.clone();
            async move {
                exit_client
                    .connect(exit_addr, "exit.example.com")
                    .map_err(|_| PumpError::ExitDial)?
                    .await
                    .map_err(|_| PumpError::ExitDial)
            }
        };
        serve_edge_entry(&conn, dialer).await
    });

    // --- browser: full HTTP/3 handshake, then tunnel setup + a datagram ------
    let browser = client_endpoint(edge_root);
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        browser
            .connect(edge_addr, "cover.example.com")
            .expect("connect builds"),
    )
    .await
    .expect("handshake within timeout")
    .expect("browser handshake");

    // Control stream with WebTransport-capable SETTINGS. Keep it open.
    let mut ctrl = conn.open_uni().await.expect("open control uni");
    ctrl.write_all(&client_control_stream())
        .await
        .expect("write client SETTINGS");

    // CONNECT stream (the session).
    let (mut connect_send, mut connect_recv) = conn.open_bi().await.expect("open connect bi");
    let session_id = u64::from(connect_send.id());
    connect_send
        .write_all(&encode_frame(
            FRAME_HEADERS,
            &webtransport_connect_headers("cover.example.com", "/warren"),
        ))
        .await
        .expect("write connect headers");
    let resp = read_one_frame(&mut connect_recv).await;
    let (frame, _) = read_frame(&resp).expect("browser reads a frame");
    assert_eq!(
        frame.payload,
        &[0x00, 0x00, 0xD9],
        "the handshake must produce a :status 200 accept"
    );

    // WebTransport bidi setup stream + WarrenMultihopFrame.
    let (mut setup_send, mut setup_recv) = conn.open_bi().await.expect("open setup bi");
    let mut wt_setup = encode_bidi_stream_header(session_id);
    wt_setup.extend_from_slice(&setup_frame(exit_id));
    setup_send
        .write_all(&wt_setup)
        .await
        .expect("write wt setup");
    setup_send.finish().expect("finish setup send");
    let reply = setup_recv.read_to_end(64 * 1024).await.expect("read reply");
    assert_eq!(
        reply, reply_frame,
        "the browser receives the exit's setup reply"
    );

    // DATA round-trip.
    let wt_dgram = encode_wt_datagram(session_id, &dgram_payload);
    let mut echoed = None;
    for _ in 0..50 {
        let _ = conn.send_datagram(Bytes::from(wt_dgram.clone()));
        match tokio::time::timeout(Duration::from_millis(100), conn.read_datagram()).await {
            Ok(Ok(d)) => {
                echoed = Some(d);
                break;
            }
            _ => continue,
        }
    }
    let echoed = echoed.expect("a DATA datagram round-trips through serve_edge_entry");
    let (_qsid, payload) = read_wt_datagram(&echoed).expect("echoed WT datagram parses");
    assert_eq!(
        payload, dgram_payload,
        "DATA survives the entry-path round-trip"
    );

    conn.close(VarInt::from_u32(0), b"done");
    let outcome = tokio::time::timeout(Duration::from_secs(5), edge_task)
        .await
        .expect("edge task finishes")
        .expect("edge join")
        .expect("serve_edge_entry ok");
    assert_eq!(
        outcome,
        warrenguard_edge_server::EdgeOutcome::Admitted {
            authority: "cover.example.com".to_string(),
            path: "/warren".to_string(),
        },
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), exit_task).await;
}

#[tokio::test]
async fn run_edge_entry_listener_pumps_a_browser_session_end_to_end() {
    // The production-shaped path: the accept loop (`run_edge_entry_listener`, a
    // blind bridge) pumps, driven by a real browser handshake, with a
    // self-contained fake exit.
    use tokio_util::sync::CancellationToken;
    use warrenguard_edge_server::run_edge_entry_listener;

    let exit_id = ExitId::from_bytes([0xEE; 16]);
    let reply_frame = setup_frame(exit_id);
    let dgram_payload = b"listener-datagram".to_vec();
    let (exit_addr, exit_root, exit_task) = spawn_fake_exit(reply_frame.clone());

    let (edge_chain, edge_key, edge_root) = mint_cert("cover.example.com");
    let edge_server = server_endpoint(edge_chain, edge_key);
    let edge_addr = edge_server.local_addr().expect("edge addr");
    let shutdown = CancellationToken::new();
    let exit_client = client_endpoint(exit_root);
    let dialer = move |_id: ExitId| {
        let exit_client = exit_client.clone();
        async move {
            exit_client
                .connect(exit_addr, "exit.example.com")
                .map_err(|_| PumpError::ExitDial)?
                .await
                .map_err(|_| PumpError::ExitDial)
        }
    };
    let listener = tokio::spawn(run_edge_entry_listener(
        edge_server,
        dialer,
        shutdown.clone(),
    ));

    let browser = client_endpoint(edge_root);
    let conn = browser
        .connect(edge_addr, "cover.example.com")
        .expect("connect builds")
        .await
        .expect("browser handshake");
    let mut ctrl = conn.open_uni().await.expect("open control uni");
    ctrl.write_all(&client_control_stream())
        .await
        .expect("write SETTINGS");
    let (mut cs, mut cr) = conn.open_bi().await.expect("open connect bi");
    let session_id = u64::from(cs.id());
    cs.write_all(&encode_frame(
        FRAME_HEADERS,
        &webtransport_connect_headers("cover.example.com", "/warren"),
    ))
    .await
    .expect("write headers");
    let resp = read_one_frame(&mut cr).await;
    assert!(read_frame(&resp).is_some(), "browser reads the 200");

    let (mut ss, mut sr) = conn.open_bi().await.expect("open setup bi");
    let mut wt = encode_bidi_stream_header(session_id);
    wt.extend_from_slice(&setup_frame(exit_id));
    ss.write_all(&wt).await.expect("write setup");
    ss.finish().expect("finish setup");
    let reply = sr.read_to_end(64 * 1024).await.expect("read reply");
    assert_eq!(reply, reply_frame, "listener path shuttles the exit reply");

    let wt_dgram = encode_wt_datagram(session_id, &dgram_payload);
    let mut echoed = None;
    for _ in 0..50 {
        let _ = conn.send_datagram(Bytes::from(wt_dgram.clone()));
        if let Ok(Ok(d)) =
            tokio::time::timeout(Duration::from_millis(100), conn.read_datagram()).await
        {
            echoed = Some(d);
            break;
        }
    }
    let echoed = echoed.expect("a datagram round-trips through the listener");
    let (_q, payload) = read_wt_datagram(&echoed).expect("parse");
    assert_eq!(payload, dgram_payload);

    conn.close(VarInt::from_u32(0), b"done");
    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), listener).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), exit_task).await;
}
