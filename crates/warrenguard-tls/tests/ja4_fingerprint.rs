//! Pins the engine client's JA4 QUIC fingerprint(s).
//!
//! Each test drives a real engine client config through a QUIC connect against a
//! non-responding UDP socket, captures the first-flight Initial datagram(s) off
//! the wire, and runs them through `warrenguard-ja4`: this decrypts the Initial
//! exactly as an on-path censor would (keys from the DCID), reassembles the
//! ClientHello, and derives the JA4. A successful decrypt means the AEAD tag
//! verified, which by itself proves the whole decryption pipeline against a real
//! packet.
//!
//! Two fingerprints are pinned because the engine emits two ClientHello shapes,
//! selected by whether the exit advertises a cover domain:
//!   - RPK path (`make_client_config`): a raw-public-key exit (dev, or an exit
//!     with no cover domain). Its verifier requires RPK, so the hello carries
//!     `server_certificate_type` (ext 0x14) and a single ED25519 sig-alg, a shape
//!     no browser sends.
//!   - WebPKI path (`make_client_config_webpki`): the v6 cover-domain X.509 exit,
//!     the **production obfuscation posture**. It drops ext 0x14 and offers the
//!     provider's full sig-alg list, so it is closer to a browser QUIC hello.
//!     This is the fingerprint an on-path censor actually sees against a real
//!     deployment, so it is the one that matters for parity work.
//!
//! Any drift in either emitted ClientHello (a rustls/quinn bump, an ALPN/cipher
//! change) surfaces here so its parity against a browser QUIC JA4 can be
//! re-evaluated before the pin is updated.
//!
//! Note: the engine's Initial-fragmentation obfuscation splits the
//! ClientHello across two packets but does not change its content, so the JA4 is
//! the same whether captured here (default transport config) or in production.

use std::net::Ipv4Addr;
use std::time::Duration;

use warrenguard_config::ALPN_H3;
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, make_client_config_webpki,
    mozilla_root_store, name,
};

/// The RPK-path client JA4 (dev / no-cover-domain exit). `q` = QUIC, `13` =
/// TLS 1.3, `d` = SNI present, `03` cipher suites, `12` extensions, `h3` ALPN,
/// then the truncated SHA-256 over the sorted cipher list and over the sorted
/// extensions + sig-algs.
///
/// The cipher hash `55b375c5d22e` is the universal TLS 1.3 cipher-suite value
/// (0x1301/1302/1303) that browsers also emit: the engine already matches a
/// browser on ciphers, and this equality independently validates the JA4
/// computation against the FoxIO reference. This path additionally carries
/// `server_certificate_type` (0x14) and one ED25519 sig-alg, both browser tells,
/// which is why the cover-domain path below is the one production relies on.
const ENGINE_JA4_RPK: &str = "q13d0312h3_55b375c5d22e_28e663e2d6d5";

/// The WebPKI / cover-domain-path client JA4 (production obfuscation posture).
/// Same universal cipher hash `55b375c5d22e`; the extension set and sig-algs
/// differ from the RPK path (no `server_certificate_type`, the provider's full
/// sig-alg list), so JA4_c and the extension count differ. This is the residual
/// parity gap versus a browser.
const ENGINE_JA4_WEBPKI: &str = "q13d0311h3_55b375c5d22e_387675cfb458";

/// Drives a client config's first-flight Initial to a non-responding socket,
/// captures the datagram(s), and returns the decrypted JA4. A successful decrypt
/// (AEAD tag verify) proves the whole `warrenguard-ja4` pipeline against a real
/// packet. Also asserts the shared JA4_a prefix (QUIC + TLS 1.3 + SNI + h3).
async fn capture_client_ja4(cfg: quinn::ClientConfig) -> String {
    // Non-responding capture socket: the client sends its first-flight Initial
    // here and, getting no reply, retransmits; we only read the first flight.
    let capture = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind capture socket");
    let capture_addr = capture.local_addr().expect("capture addr");

    let mut endpoint =
        quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint");
    endpoint.set_default_client_config(cfg);

    // SNI = the exit pubkey encoded per the engine's naming scheme.
    let server_name = name::encode(WarrenPubkey::from_bytes([7u8; 32]));
    let connecting = endpoint
        .connect(capture_addr, &server_name)
        .expect("connect starts");
    // Drive the connect so the Initial is transmitted; it never completes (no
    // server), so time it out in the background.
    tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(3), connecting).await;
    });

    // Capture the first-flight Initial datagram(s).
    let mut datagrams: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; 2048];
    for _ in 0..4 {
        match tokio::time::timeout(Duration::from_millis(1500), capture.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => datagrams.push(buf[..n].to_vec()),
            _ => break,
        }
    }
    assert!(!datagrams.is_empty(), "captured no Initial datagram");

    let refs: Vec<&[u8]> = datagrams.iter().map(Vec::as_slice).collect();
    let ja4 = warrenguard_ja4::ja4_from_initials(&refs)
        .expect("JA4 from the engine Initial (a successful decrypt proves the pipeline)");

    // End-to-end sanity on the recovered ClientHello, shared by both paths.
    assert!(
        ja4.starts_with("q13d"),
        "expected QUIC + TLS 1.3 + SNI, got {ja4}"
    );
    assert!(
        ja4.contains("h3"),
        "expected the h3 ALPN in JA4_a, got {ja4}"
    );
    ja4
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpk_client_initial_ja4_is_pinned() {
    // The exact engine client crypto config for a raw-public-key exit: h3 ALPN +
    // the RPK handshake. This determines the ClientHello, hence the JA4.
    let cfg = make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client cfg");
    let ja4 = capture_client_ja4(cfg).await;
    // Regression pin. On a rustls/quinn bump this may legitimately change; when
    // it does, re-evaluate the parity gap against the browser target
    // before updating the constant.
    assert_eq!(ja4, ENGINE_JA4_RPK, "RPK-path engine JA4 drifted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webpki_cover_domain_client_initial_ja4_is_pinned() {
    // The production obfuscation config: a cover-domain X.509 exit validated
    // against the Mozilla roots like a browser. Its ClientHello is what an
    // on-path censor sees against a real deployment.
    let cfg =
        make_client_config_webpki(mozilla_root_store(), default_crypto_provider(), &[ALPN_H3])
            .expect("webpki client cfg");
    let ja4 = capture_client_ja4(cfg).await;
    // Regression pin; see the RPK note above. This is the JA4 whose parity gap
    // versus a browser is tracked.
    assert_eq!(ja4, ENGINE_JA4_WEBPKI, "WebPKI-path engine JA4 drifted");
}
