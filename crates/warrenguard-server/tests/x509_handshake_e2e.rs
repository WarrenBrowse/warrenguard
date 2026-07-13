//! v6 X.509 exit mode end-to-end: an exit configured with an X.509 certificate
//! presents it (so the TLS handshake looks like an ordinary HTTPS/h3 server,
//! no RFC 7250 raw public key and no pubkey in the SNI), and a client in
//! X.509 mode validates the chain via WebPKI like a browser, then confirms
//! the Warren identity IN-BAND via the exit's `SetupAck::exit_auth_sig`
//! signature over the channel binding. Loopback only; run via the
//! firewall-disabling wrapper on macOS.
//!
//! Fixtures: a test CA + a leaf for `cover.example.com` (EC P-256, openssl).

use std::time::Duration;

use warrenguard_server::{ExitBindOpts, ExitListener};
use warrenguard_transport::ClientTunnel;

const CA_DER: &[u8] = include_bytes!("fixtures/ca.der");
const LEAF_DER: &[u8] = include_bytes!("fixtures/leaf.der");
const LEAF_KEY_DER: &[u8] = include_bytes!("fixtures/leaf_key.der");

#[tokio::test]
async fn x509_mode_handshake_completes_and_inband_exit_proof_verifies() {
    let opts = ExitBindOpts {
        tls_certificate: Some((vec![LEAF_DER.to_vec()], LEAF_KEY_DER.to_vec())),
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts("127.0.0.1:0".parse().unwrap(), opts)
        .await
        .expect("bind x509-mode exit");
    let exit_addr = exit.bound_addr();
    tokio::spawn(exit.accept_one());

    // Client trusts the test CA and dials the cover domain as SNI (NOT the
    // exit pubkey). The expected exit pubkey still flows via `exit_addr.id`
    // and is checked by the in-band proof, independent of the SNI.
    let client =
        ClientTunnel::new().with_x509(vec![CA_DER.to_vec()], "cover.example.com".to_owned());

    let ack = tokio::time::timeout(Duration::from_secs(5), client.handshake(exit_addr))
        .await
        .expect("handshake must not time out")
        .expect(
            "x509-mode handshake (webpki-valid cert + verified in-band exit proof) must succeed",
        );

    assert_eq!(
        ack.tunnel_ipv4[0], 10,
        "the exit assigns a 10.66.0.0/16 tunnel IP after a successful x509-mode handshake"
    );
    assert_eq!(ack.tunnel_ipv4[1], 66);
}
