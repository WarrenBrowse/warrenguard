//! Network-level addressing for a Warren exit.
//!
//! [`WarrenExitAddr`] is the JSON-wire descriptor that an exit
//! binary's `--info-out` writes, that a client's `--info-in`
//! reads, and that provisioning scripts shuttle between
//! machines. Its serde shape is the current Warren exit descriptor
//! contract: the `id` field with 64-char lower-case hex, an `addrs`
//! array, and an externally-tagged transport enum
//! (`{"Ip": "host:port"}`). The integration test
//! `tests/exit_addr_wire_compat.rs` in this crate locks
//! this contract against a captured fixture.
//!
//! The type is intentionally minimal:
//! - [`WarrenTransportAddr`] only exposes the `Ip` variant. Warren is
//!   direct-only (no relay or address-lookup transports), so `Relay` /
//!   `Custom` never appear on the wire in production. The enum is
//!   `#[non_exhaustive]` so future Warren-specific transports can be
//!   added without a breaking change.
//! - All addresses live in one `addrs` BTreeSet, ordered by
//!   `SocketAddr` for deterministic serialization.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::WarrenPubkey;

/// Wire-level addressing record for a Warren exit. See module-level
/// doc for the JSON shape and compatibility notes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WarrenExitAddr {
    /// Ed25519 identity of the exit. Matches the pubkey embedded in
    /// the exit's TLS RPK cert, which the client pins via the SNI and
    /// the warrenguard-tls server-certificate verifier checks at handshake.
    ///
    /// Named `id` so existing client `--info-in` consumers and
    /// provisioning scripts keep parsing the descriptor.
    pub id: WarrenPubkey,
    /// Network paths to reach the exit. Sorted by `SocketAddr` to
    /// keep the wire encoding deterministic across runs.
    pub addrs: BTreeSet<WarrenTransportAddr>,
    /// True when the exit was started with `--no-dns` and therefore
    /// does NOT run the DNS forwarder on `10.66.0.1:53`. The client
    /// uses this flag to refuse boot unless an explicit fallback
    /// DNS (`--push-dns 9.9.9.9` or similar) was passed; without
    /// that, every DNS query falls back to the LAN resolver via the
    /// killswitch hole and leaks user activity off-tunnel. The
    /// `skip_serializing_if = is_false` attribute keeps the on-wire
    /// JSON unchanged from the original descriptor shape when the
    /// exit runs the forwarder (the common case).
    #[serde(default, skip_serializing_if = "is_false")]
    pub dns_disabled: bool,
    /// Cover-domain SNI to dial this exit in v6 X.509 mode: the
    /// hostname on the exit's real certificate that the client validates via
    /// WebPKI and presents as the TLS SNI, instead of pinning the exit's raw
    /// public key. Sourced per-exit from the signed roster so distinct exits
    /// can advertise distinct (rotatable) cover domains. `None` (default, and
    /// skipped from the wire) keeps the RPK-via-SNI handshake. The exit
    /// identity is still verified in-band regardless of this value, so a wrong
    /// or spoofed domain cannot admit a foreign exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_domain: Option<String>,
    /// True when this exit terminates the TCP-over-TLS fallback carrier on
    /// `:443/tcp` (the anti-censorship datapath for networks that block
    /// outbound UDP/QUIC). The client reads this from the signed roster to
    /// decide whether a UDP-handshake timeout is worth retrying over TCP: an
    /// exit that does not advertise it would only refuse the TCP connection, so
    /// the client skips the pointless attempt. Absent/false (the default) is
    /// skipped from the wire, keeping the descriptor JSON byte-equal with the
    /// legacy shape (same additive, backward-compatible pattern as
    /// [`dns_disabled`](Self::dns_disabled) and [`cover_domain`](Self::cover_domain)).
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp_fallback: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(b: &bool) -> bool {
    !*b
}

/// Transport address variant. Externally-tagged so the JSON encoding
/// is `{"Ip": "<host:port>"}`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WarrenTransportAddr {
    /// Plain UDP/QUIC socket address.
    Ip(SocketAddr),
}

impl WarrenExitAddr {
    /// Builds a new exit address with no reachable transports.
    #[must_use]
    pub fn new(id: WarrenPubkey) -> Self {
        Self {
            id,
            addrs: BTreeSet::new(),
            dns_disabled: false,
            cover_domain: None,
            tcp_fallback: false,
        }
    }

    /// Builds an exit address from raw socket addresses, wrapping
    /// each as [`WarrenTransportAddr::Ip`]. Duplicates collapse via
    /// `BTreeSet`.
    #[must_use]
    pub fn from_ip_addrs(id: WarrenPubkey, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        Self {
            id,
            addrs: addrs.into_iter().map(WarrenTransportAddr::Ip).collect(),
            dns_disabled: false,
            cover_domain: None,
            tcp_fallback: false,
        }
    }

    /// Builder-style chain helper (`.new(id).with_ip_addr(a)`).
    #[must_use]
    pub fn with_ip_addr(mut self, addr: SocketAddr) -> Self {
        self.addrs.insert(WarrenTransportAddr::Ip(addr));
        self
    }

    /// Sets the v6 X.509 cover-domain SNI for this exit (from the signed
    /// roster). See the [`cover_domain`](Self::cover_domain) field.
    #[must_use]
    pub fn with_cover_domain(mut self, domain: impl Into<String>) -> Self {
        self.cover_domain = Some(domain.into());
        self
    }

    /// Marks this exit as terminating the TCP-over-TLS fallback carrier. See
    /// the [`tcp_fallback`](Self::tcp_fallback) field.
    #[must_use]
    pub fn with_tcp_fallback(mut self) -> Self {
        self.tcp_fallback = true;
        self
    }

    /// `true` when the exit has no reachable transport.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Returns the `SocketAddr` of every IP transport, skipping any
    /// future non-IP variant. `filter_map` (rather than `map`) is
    /// kept on purpose so a `#[non_exhaustive]` enum can grow extra
    /// variants without breaking callers that only want IP paths.
    #[allow(clippy::unnecessary_filter_map)]
    pub fn ip_addrs(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.addrs.iter().filter_map(|a| match a {
            WarrenTransportAddr::Ip(s) => Some(*s),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;

    const SEED_AB_PUBKEY_BYTES: [u8; 32] = [
        0x21, 0xe9, 0x27, 0x6d, 0xa8, 0x39, 0x5d, 0x56, 0xaf, 0x5c, 0x83, 0xc0, 0x0f, 0xfb, 0x4a,
        0xfb, 0xa7, 0xeb, 0xd3, 0x37, 0x18, 0x9a, 0xee, 0xa9, 0x13, 0x6b, 0xfc, 0x9d, 0x3f, 0xd4,
        0x4f, 0x6b,
    ];

    fn ipv4_socket(d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, d), port))
    }

    fn ipv6_socket(last_octet: u16, port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last_octet),
            port,
            0,
            0,
        ))
    }

    #[test]
    fn new_creates_empty_transport_set() {
        let id = WarrenPubkey::from_bytes([0u8; 32]);
        let addr = WarrenExitAddr::new(id);
        assert!(addr.is_empty());
        assert_eq!(addr.addrs.len(), 0);
        assert_eq!(addr.id, id);
    }

    #[test]
    fn from_ip_addrs_wraps_each_socket_as_transport_ip() {
        let id = WarrenPubkey::from_bytes([0u8; 32]);
        let s1 = ipv4_socket(1, 7000);
        let s2 = ipv4_socket(2, 7000);
        let addr = WarrenExitAddr::from_ip_addrs(id, [s1, s2]);
        assert_eq!(addr.addrs.len(), 2);
        let collected: Vec<SocketAddr> = addr.ip_addrs().collect();
        // BTreeSet sorts by SocketAddr; s1 < s2 by IP, so order is (s1, s2).
        assert_eq!(collected, vec![s1, s2]);
    }

    #[test]
    fn from_ip_addrs_collapses_duplicates() {
        let id = WarrenPubkey::from_bytes([0u8; 32]);
        let s = ipv4_socket(5, 7000);
        let addr = WarrenExitAddr::from_ip_addrs(id, [s, s, s]);
        assert_eq!(addr.addrs.len(), 1, "BTreeSet collapses identical sockets");
    }

    #[test]
    fn ip_addrs_skips_iterating_over_a_non_ip_future_variant() {
        // Compile-time hint: ip_addrs's filter_map must keep working
        // even if a future #[non_exhaustive] variant lands. The match
        // arms must stay exhaustive on `Ip(_)` and skip anything else.
        // Today there is only Ip, so this just exercises the happy
        // path; the structural compile check is in the match body.
        let id = WarrenPubkey::from_bytes([0u8; 32]);
        let addr = WarrenExitAddr::from_ip_addrs(id, [ipv4_socket(9, 7000)]);
        assert_eq!(addr.ip_addrs().count(), 1);
    }

    // ---------------- serde: JSON shape (exit descriptor wire contract) ---------------- //

    /// Locks the JSON output against the exit descriptor wire shape:
    /// `id` field with 64-char lower-case hex, `addrs` array of
    /// `{"Ip":"<socket>"}` entries sorted by SocketAddr. Any drift
    /// here would break client `--info-in` consumers and the
    /// provisioning scripts that consume the same JSON.
    #[test]
    fn json_shape_is_byte_for_byte_stable() {
        let addr = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes(SEED_AB_PUBKEY_BYTES),
            [ipv4_socket(1, 7000)],
        );
        let json = serde_json::to_string(&addr).expect("json serialize");
        assert_eq!(
            json,
            "{\"id\":\"21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b\",\
             \"addrs\":[{\"Ip\":\"10.0.0.1:7000\"}]}"
        );
    }

    #[test]
    fn json_roundtrip_with_dual_stack_v4_and_v6_addrs() {
        let original = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes([0xaa; 32]),
            [ipv4_socket(7, 7000), ipv6_socket(0x42, 7000)],
        );
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: WarrenExitAddr = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, original, "JSON roundtrip preserves id + addrs");
    }

    #[test]
    fn json_deserialize_rejects_missing_id_field() {
        let err = serde_json::from_str::<WarrenExitAddr>("{\"addrs\":[]}")
            .expect_err("missing id must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("id"),
            "error should mention the missing `id` field, got: {msg}"
        );
    }

    #[test]
    fn json_deserialize_rejects_unknown_transport_variant() {
        // Warren disables Relay; a wire shape carrying {"Relay":"..."}
        // must be rejected loud, not silently parsed as empty.
        let bad = "{\"id\":\"21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b\",\
                   \"addrs\":[{\"Relay\":\"https://relay.example/\"}]}";
        let err = serde_json::from_str::<WarrenExitAddr>(bad)
            .expect_err("Relay variant must be rejected: Warren is direct-only");
        let msg = err.to_string();
        assert!(
            msg.to_ascii_lowercase().contains("relay")
                || msg.to_ascii_lowercase().contains("variant"),
            "error should point at the rejected variant, got: {msg}"
        );
    }

    #[test]
    fn json_deserialize_rejects_malformed_socket_addr() {
        let bad = "{\"id\":\"21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b\",\
                   \"addrs\":[{\"Ip\":\"not-a-socket\"}]}";
        let err =
            serde_json::from_str::<WarrenExitAddr>(bad).expect_err("garbage socket addr must fail");
        let msg = err.to_string();
        assert!(
            !msg.contains("`id`"),
            "error must point at the addrs failure, not the id field"
        );
    }

    #[test]
    fn json_empty_addrs_is_valid_and_serializes_as_empty_array() {
        let addr = WarrenExitAddr::new(WarrenPubkey::from_bytes([0xbb; 32]));
        let json = serde_json::to_string(&addr).expect("serialize");
        assert!(
            json.contains("\"addrs\":[]"),
            "empty addrs must serialize as []; got: {json}"
        );
        let parsed: WarrenExitAddr =
            serde_json::from_str(&json).expect("empty addrs must deserialize");
        assert_eq!(parsed, addr);
    }

    // ---------------- serde: postcard (binary, SetupAck wire compat) ---------------- //

    #[test]
    fn postcard_roundtrips_for_dual_nic_exit() {
        // `dns_disabled = true` forces the optional field to be
        // serialized (postcard is a non-self-describing binary format,
        // so `skip_serializing_if = is_false` cannot be roundtripped
        // through postcard for the default case - see the dedicated
        // test below for the contract). The roundtrip property here is
        // what matters: the multi-address shape must survive a wire
        // pass when the field is present.
        let mut original = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes([0xcc; 32]),
            [
                ipv4_socket(10, 7000),
                ipv4_socket(11, 7000),
                ipv4_socket(12, 7000),
            ],
        );
        original.dns_disabled = true;
        // postcard (non-self-describing) cannot round-trip a skipped optional,
        // so every skip_serializing_if field must be present: set cover_domain
        // too (see `postcard_documents_skip_serializing_caveat`).
        original.cover_domain = Some("cover.example.com".to_owned());
        // postcard needs every skip_serializing_if optional present on the wire.
        original.tcp_fallback = true;
        let wire = postcard::to_allocvec(&original).expect("serialize");
        let parsed: WarrenExitAddr = postcard::from_bytes(&wire).expect("deserialize");
        assert_eq!(parsed, original);
    }

    /// Cross-pin: the first 32 wire bytes of a postcard-serialized
    /// `WarrenExitAddr` must be the raw pubkey. This is what makes
    /// `SetupAck.exit_pubkey: WarrenPubkey` byte-equal with a naked
    /// `[u8; 32]` at the wire level.
    #[test]
    fn postcard_pubkey_bytes_appear_raw_at_the_start_of_the_buffer() {
        let pubkey_bytes = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10,
        ];
        let addr = WarrenExitAddr::new(WarrenPubkey::from_bytes(pubkey_bytes));
        let wire = postcard::to_allocvec(&addr).expect("serialize");
        assert_eq!(
            &wire[..32],
            &pubkey_bytes,
            "the first 32 wire bytes must be the raw pubkey (no length prefix), \
             so swapping SetupAck.exit_pubkey to WarrenPubkey is byte-identical"
        );
    }

    #[test]
    fn postcard_roundtrips_empty_addrs_when_dns_disabled_explicit() {
        // Same caveat as above: postcard requires `dns_disabled` to be
        // explicitly set (true here) for the wire to round-trip, since
        // `skip_serializing_if = is_false` produces a wire too short
        // for postcard to decode into the new struct shape. WarrenExitAddr
        // is JSON-only in production (`--info-out` / `--info-in`); this
        // postcard test stays as a defensive contract.
        let mut addr = WarrenExitAddr::new(WarrenPubkey::from_bytes([0u8; 32]));
        addr.dns_disabled = true;
        // All skip_serializing_if optionals must be present for a postcard
        // round-trip (see `postcard_documents_skip_serializing_caveat`).
        addr.cover_domain = Some("cover.example.com".to_owned());
        // postcard needs every skip_serializing_if optional present on the wire.
        addr.tcp_fallback = true;
        let wire = postcard::to_allocvec(&addr).expect("serialize");
        let parsed: WarrenExitAddr = postcard::from_bytes(&wire).expect("deserialize");
        assert_eq!(parsed, addr);
    }

    /// Document the wire-format caveat: in JSON (the production
    /// transport for WarrenExitAddr), the optional `dns_disabled`
    /// field is skipped when false to keep byte-equality with the
    /// original descriptor shape; in postcard (binary, non-self-describing),
    /// this skip means a default-shaped struct cannot roundtrip
    /// because postcard expects all declared fields on the wire.
    /// Callers that need a postcard wire MUST set the field explicitly.
    #[test]
    fn postcard_documents_skip_serializing_caveat() {
        let addr = WarrenExitAddr::new(WarrenPubkey::from_bytes([0u8; 32]));
        assert!(!addr.dns_disabled, "default is false");
        let wire = postcard::to_allocvec(&addr).expect("serialize");
        let res: Result<WarrenExitAddr, _> = postcard::from_bytes(&wire);
        assert!(
            res.is_err(),
            "postcard cannot decode the skipped optional field back; \
             callers using postcard for WarrenExitAddr must set dns_disabled \
             explicitly (or migrate to JSON for full backward compat)"
        );
    }

    // ---------------- dns_disabled ---------------- //

    /// Backward compat: an old JSON descriptor
    /// without the `dns_disabled` field must decode with the field
    /// defaulting to `false` (DNS forwarder is reachable). This keeps
    /// the rolling deploy compatible: a client built after the field
    /// was added can still read a JSON written by an exit built before it.
    #[test]
    fn dns_disabled_defaults_to_false_when_field_absent_from_json() {
        let legacy = "{\"id\":\"21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b\",\
                      \"addrs\":[{\"Ip\":\"10.0.0.1:7000\"}]}";
        let parsed: WarrenExitAddr = serde_json::from_str(legacy).expect("legacy JSON must decode");
        assert!(
            !parsed.dns_disabled,
            "field absent in legacy JSON => dns_disabled defaults to false \
             (exit runs the DNS forwarder, no fallback required client-side)"
        );
    }

    /// Wire stability: when `dns_disabled` is false (the common case),
    /// it MUST be skipped at serialization so the JSON output stays
    /// byte-equal with the original descriptor shape. This is the
    /// property the `json_shape_is_byte_for_byte_stable` test already
    /// locks; we verify here that the skip_serializing attribute is
    /// wired correctly.
    #[test]
    fn dns_disabled_false_does_not_appear_in_serialized_json() {
        let addr = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes(SEED_AB_PUBKEY_BYTES),
            [ipv4_socket(1, 7000)],
        );
        assert!(!addr.dns_disabled);
        let json = serde_json::to_string(&addr).expect("serialize");
        assert!(
            !json.contains("dns_disabled"),
            "dns_disabled=false MUST NOT appear in JSON (skip_serializing_if), \
             so the wire encoding stays byte-equal with the original descriptor shape; \
             got: {json}"
        );
    }

    /// When the exit was started with `--no-dns`, the `WarrenExitAddr`
    /// emitted to `--info-out` MUST carry `dns_disabled: true`. The
    /// client uses this signal to refuse boot unless an explicit
    /// fallback DNS is configured (closes the DNS leak path).
    #[test]
    fn dns_disabled_true_serializes_into_json() {
        let mut addr = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes(SEED_AB_PUBKEY_BYTES),
            [ipv4_socket(1, 7000)],
        );
        addr.dns_disabled = true;
        let json = serde_json::to_string(&addr).expect("serialize");
        assert!(
            json.contains("\"dns_disabled\":true"),
            "dns_disabled=true MUST appear in JSON; got: {json}"
        );
        let roundtrip: WarrenExitAddr =
            serde_json::from_str(&json).expect("dns_disabled=true must roundtrip");
        assert!(roundtrip.dns_disabled);
    }

    // ---------------- cover_domain (v6 X.509 exit mode) ---------------- //

    #[test]
    fn cover_domain_absent_does_not_appear_in_json() {
        // Wire stability: with no cover domain (the RPK default), the field is
        // skipped so the descriptor JSON stays byte-equal with the legacy shape
        // (same property as dns_disabled). This is what keeps
        // `json_shape_is_byte_for_byte_stable` green.
        let addr = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes(SEED_AB_PUBKEY_BYTES),
            [ipv4_socket(1, 7000)],
        );
        assert!(addr.cover_domain.is_none());
        let json = serde_json::to_string(&addr).expect("serialize");
        assert!(
            !json.contains("cover_domain"),
            "cover_domain=None MUST NOT appear in JSON (skip_serializing_if); got: {json}"
        );
    }

    #[test]
    fn cover_domain_present_roundtrips_through_json() {
        let addr = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes(SEED_AB_PUBKEY_BYTES),
            [ipv4_socket(1, 7000)],
        )
        .with_cover_domain("e7f3a.cover.example.com");
        let json = serde_json::to_string(&addr).expect("serialize");
        assert!(
            json.contains("\"cover_domain\":\"e7f3a.cover.example.com\""),
            "a set cover_domain must serialize; got: {json}"
        );
        let parsed: WarrenExitAddr = serde_json::from_str(&json).expect("roundtrip");
        assert_eq!(
            parsed.cover_domain.as_deref(),
            Some("e7f3a.cover.example.com")
        );
        assert_eq!(parsed, addr);
    }

    #[test]
    fn cover_domain_defaults_to_none_when_field_absent_from_json() {
        // Backward compat: a descriptor written before v6 has no cover_domain;
        // it must decode with the field defaulting to None (RPK handshake).
        let legacy = "{\"id\":\"21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b\",\
                      \"addrs\":[{\"Ip\":\"10.0.0.1:7000\"}]}";
        let parsed: WarrenExitAddr = serde_json::from_str(legacy).expect("legacy JSON must decode");
        assert!(parsed.cover_domain.is_none());
    }

    // ---------------- tcp_fallback (TCP-over-TLS carrier capability) ---------------- //

    #[test]
    fn tcp_fallback_absent_does_not_appear_in_json() {
        // Wire stability: an exit that does not terminate the TCP fallback (the
        // default) must not emit the field, so the descriptor JSON stays
        // byte-equal with the legacy shape (same skip-if-false property as
        // dns_disabled). This keeps `json_shape_is_byte_for_byte_stable` green.
        let addr = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes(SEED_AB_PUBKEY_BYTES),
            [ipv4_socket(1, 7000)],
        );
        assert!(!addr.tcp_fallback);
        let json = serde_json::to_string(&addr).expect("serialize");
        assert!(
            !json.contains("tcp_fallback"),
            "tcp_fallback=false MUST NOT appear in JSON (skip_serializing_if); got: {json}"
        );
    }

    #[test]
    fn tcp_fallback_true_serializes_and_roundtrips() {
        let addr = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes(SEED_AB_PUBKEY_BYTES),
            [ipv4_socket(1, 7000)],
        )
        .with_tcp_fallback();
        assert!(addr.tcp_fallback);
        let json = serde_json::to_string(&addr).expect("serialize");
        assert!(
            json.contains("\"tcp_fallback\":true"),
            "a set tcp_fallback must serialize; got: {json}"
        );
        let parsed: WarrenExitAddr = serde_json::from_str(&json).expect("roundtrip");
        assert!(parsed.tcp_fallback);
        assert_eq!(parsed, addr);
    }

    #[test]
    fn tcp_fallback_defaults_to_false_when_field_absent_from_json() {
        // Backward compat: a descriptor written before the capability existed
        // has no tcp_fallback; it must decode with the field defaulting to false
        // (the exit does not advertise the fallback, so the client never tries it).
        let legacy = "{\"id\":\"21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b\",\
                      \"addrs\":[{\"Ip\":\"10.0.0.1:7000\"}]}";
        let parsed: WarrenExitAddr = serde_json::from_str(legacy).expect("legacy JSON must decode");
        assert!(!parsed.tcp_fallback);
    }

    #[test]
    fn dns_disabled_true_postcard_roundtrips() {
        let mut addr = WarrenExitAddr::from_ip_addrs(
            WarrenPubkey::from_bytes([0xdd; 32]),
            [ipv4_socket(8, 7000)],
        );
        addr.dns_disabled = true;
        // All skip_serializing_if optionals must be present for a postcard
        // round-trip (see `postcard_documents_skip_serializing_caveat`).
        addr.cover_domain = Some("cover.example.com".to_owned());
        // postcard needs every skip_serializing_if optional present on the wire.
        addr.tcp_fallback = true;
        let wire = postcard::to_allocvec(&addr).expect("postcard serialize");
        let parsed: WarrenExitAddr = postcard::from_bytes(&wire).expect("postcard deserialize");
        assert!(parsed.dns_disabled);
        assert_eq!(parsed, addr);
    }
}
