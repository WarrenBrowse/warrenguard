//! Behavioural freeze of the CLIENT-side QUIC-Initial obfuscation.
//!
//! `warren_transport_config_client` must pad the first Initial datagram via the
//! fork's `initial_datagram_min_size` knob (1280), the client half of the anti-DPI
//! handshake. A plain UDP "tap" (it never speaks QUIC) captures the client's
//! first emitted datagram and asserts it is padded. This is the missing client
//! counterpart to `server_mirror_initial_pad_loopback.rs`: that one proves the
//! server mirror's padded handshake completes, this one proves the client config
//! actually applies the padding. The knob *presence* in the fork itself is
//! guarded separately by `warrenguard-tls/tests/quinn_fork_patch.rs`; this guards
//! that `warren_transport_config_client` keeps *applying* it, so a refactor of
//! the transport config cannot silently drop the client obfuscation.
//!
//! No root, no live exit, no secret: a loopback UDP socket and a single dial.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use quinn::Endpoint;
use tokio::net::UdpSocket;
use warrenguard_config::ALPN_H3;
use warrenguard_tls::{
    WarrenPubkey, default_crypto_provider, make_client_config, name as tls_name,
};

/// The fork pads the obfuscated client Initial to `initial_datagram_min_size`
/// (1280). The default upstream Initial is the RFC-9000 floor (1200), so a
/// `>= 1280` first datagram is the obfuscation signature.
const OBFUSCATED_MIN_FIRST_DATAGRAM: usize = 1280;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_first_initial_datagram_is_padded_for_obfuscation() {
    // A plain UDP socket that never answers: it only records the size of the
    // first datagram the client emits. The handshake therefore never completes,
    // which is fine: the assertion is on the client's first flight alone.
    let tap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind udp tap");
    let tap_addr: SocketAddr = tap.local_addr().expect("tap addr");

    let mut client_cfg =
        make_client_config(default_crypto_provider(), &[ALPN_H3]).expect("client config");
    // GSO off so the test does not depend on the host kernel supporting
    // UDP_SEGMENT, mirroring server_mirror_initial_pad_loopback.rs.
    client_cfg.transport_config(
        warrenguard_transport_core::warren_transport_config_client_with_gso(false),
    );

    let endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).expect("client endpoint bind");
    // The SNI only needs to be a syntactically valid encoded pubkey; the tap
    // never validates it (it never replies).
    let server_name = tls_name::encode(WarrenPubkey::from_bytes([0x11; 32]));

    // Drive the connect so the endpoint actually emits the Initial flight; it can
    // never resolve (the tap does not answer), we only want the side effect.
    let mut connecting = endpoint
        .connect_with(client_cfg, tap_addr, &server_name)
        .expect("connect setup");
    let driver = tokio::spawn(async move {
        let _ = (&mut connecting).await;
    });

    // Capture the client's first Initial flight: the first datagram (wait up to
    // 5s), then drain the rest of the immediate burst with a short inter-packet
    // window. The 250ms window is far below the initial PTO (~1s), so it captures
    // the burst without folding in a PTO retransmission of the same ClientHello.
    let mut buf = [0u8; 4096];
    let first = tokio::time::timeout(Duration::from_secs(5), tap.recv_from(&mut buf)).await;
    let first_len = first
        .expect("client emitted no Initial datagram within 5s")
        .expect("tap recv_from")
        .0;

    let mut sizes = vec![first_len];
    loop {
        let mut b = [0u8; 4096];
        match tokio::time::timeout(Duration::from_millis(250), tap.recv_from(&mut b)).await {
            Ok(Ok((n, _))) => sizes.push(n),
            _ => break,
        }
    }

    driver.abort();
    endpoint.close(quinn::VarInt::from_u32(0), b"test done");
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;

    // Padding knob (`initial_datagram_min_size`). Empirically: the obfuscated config
    // emits 1280 here, a default quinn config emits 1200 (the RFC floor), so this
    // bound is a real guard, not a tautology.
    assert!(
        first_len >= OBFUSCATED_MIN_FIRST_DATAGRAM,
        "obfuscated client Initial must be padded to >= {OBFUSCATED_MIN_FIRST_DATAGRAM} bytes \
         (initial_datagram_min_size); got {first_len}. warren_transport_config_client lost its \
         Initial-padding knob (client obfuscation regression)."
    );
    // Split knob (`initial_crypto_first_fragment_size(Some(64))`): the ClientHello
    // (which carries the encoded-pubkey SNI) is spread across at least two Initial
    // datagrams so single-packet DPI cannot read it. Empirically: the obfuscated
    // config emits 2 datagrams in the first flight, a default config emits 1 (the
    // small RPK ClientHello fits one Initial), so this is a real guard.
    assert!(
        sizes.len() >= 2,
        "obfuscated client must split the ClientHello across >= 2 Initial datagrams \
         (initial_crypto_first_fragment_size); first flight had {} datagram(s): {sizes:?}. \
         The client crypto-chunk obfuscation regressed.",
        sizes.len()
    );
}
