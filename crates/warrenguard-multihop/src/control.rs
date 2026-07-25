//! Warren multi-hop control messages.
//!
//! Control messages travel as the **plaintext** carried inside a
//! [`crate::WarrenMultihopFrame`] envelope: the HPKE seal/open layer is
//! transparent to this module. A control plaintext is identified by a
//! reserved first byte ([`CONTROL_FIRST_BYTE`] = `0xC0`) which is
//! distinct from every value the rx-side dispatch already recognises:
//!
//! - `0x40 ..= 0x4F` - IPv4 packet (nibble `4`)
//! - `0x60 ..= 0x6F` - IPv6 packet (nibble `6`)
//! - `0xFF` - DAITA dummy
//!
//! See `.planning/session-aa-multi-hop-ip-nego-design.md` for the
//! end-to-end protocol design. This module owns the wire format **only**.
//!
//! ## Wire layout
//!
//! ```text
//! +--------+--------+--------+----...---+
//! | 0xC0   | 0x03   | payload (postcard-encoded `WarrenControlMessage`)
//! +--------+--------+--------+----...---+
//!   marker  version
//! ```
//!
//! Frozen for `/v3`. Any incompatible change must bump the version byte
//! (see [`CONTROL_VERSION_V3`]) and live in a separate module per the
//! Warren versioning doctrine. The earlier version bytes are retired and a
//! receiver MUST reject them (`UnsupportedVersion`) rather than guess which
//! schema the sender meant. Clients and exits are always redeployed together
//! (pre-production doctrine), so there is no dual-stack decode path: a version
//! mismatch means a stale binary and must fail loudly.

use serde::{Deserialize, Serialize};
use warrenguard_wire::SessionToken;

/// Reserved plaintext first byte that signals a Warren control message.
///
/// Chosen outside every value the rx-side IP / DAITA dispatch already
/// matches (`0x40..=0x4F` for IPv4, `0x60..=0x6F` for IPv6, `0xFF` for
/// DAITA dummies). A single-byte compare is enough to route the
/// plaintext at the rx-side pump.
pub const CONTROL_FIRST_BYTE: u8 = 0xC0;

/// Control protocol version byte. `0x03` for the current layout
/// (proof-of-possession slot on `IpRequest`, sealed `Rejected` reply, and the
/// DAITA capability echo: `wants_daita` on the requests, `daita_spec` on
/// `IpAssign`). A breaking change must bump this value.
///
/// `0x01` and `0x02` are retired and never decoded: a peer speaking either one
/// cannot express whether the traffic-analysis defense is running, and a
/// silently-undefended session is exactly the failure this version exists to
/// make impossible.
pub const CONTROL_VERSION_V3: u8 = 0x03;

/// Errors emitted by [`try_decode_control`] and [`encode_control`].
///
/// Distinct from `MultihopError` because control messages live in the
/// plaintext **after** the HPKE open succeeds, so the rejection paths
/// are different (no replay window, no version-byte aliasing with the
/// frame's HPKE version, etc.).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The plaintext started with [`CONTROL_FIRST_BYTE`] but was shorter
    /// than the 2-byte header (marker + version). Treated as malformed
    /// since a legitimate sender always emits at least these two bytes.
    #[error("control plaintext too short: got {got} bytes, need at least 2 for marker + version")]
    TooShort {
        /// Length of the plaintext that was passed to the decoder.
        got: usize,
    },

    /// The version byte did not match the build's expected value
    /// ([`CONTROL_VERSION_V3`]). Receivers MUST drop the frame and
    /// MAY log a warning so the operator can detect a peer running
    /// an incompatible Warren build.
    #[error("unsupported control version: got 0x{got:02x}, expected 0x{expected:02x}")]
    UnsupportedVersion {
        /// Version byte read from the plaintext (second byte after the
        /// marker).
        got: u8,
        /// Version byte required by this build.
        expected: u8,
    },

    /// The payload decoded to a valid message but was followed by
    /// unexpected trailing bytes. Rejected to keep the wire encoding
    /// unambiguous (one plaintext = exactly one control message).
    #[error("trailing bytes after a valid control message")]
    TrailingBytes,

    /// Postcard decoder rejected the payload (truncation, schema mismatch,
    /// or an over-budget field). Includes the original postcard error
    /// for diagnostics.
    #[error("postcard decode of control payload failed: {0}")]
    Decode(#[from] postcard::Error),
}

/// Ed25519 proof-of-possession signature carried on the wire as 64 raw
/// bytes (no length prefix). Newtype because serde has no built-in
/// `[u8; 64]` impls; the manual impl serialises as a fixed 64-tuple so
/// postcard emits exactly the 64 signature bytes, deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PopSignature(pub [u8; 64]);

impl Serialize for PopSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(64)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for PopSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = PopSignature;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("64 raw Ed25519 signature bytes")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(PopSignature(out))
            }
        }
        deserializer.deserialize_tuple(64, SigVisitor)
    }
}

/// Warren multi-hop control messages exchanged between client and exit
/// over the same HPKE-sealed datagram channel that carries IP packets.
///
/// Single `/v3` format (pre-production: client + exit are always rebuilt
/// and redeployed together, so the message carries every field directly
/// instead of accumulating append-only variants). A future genuine wire
/// break bumps [`CONTROL_VERSION_V3`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WarrenControlMessage {
    /// Client -> exit. Asks the exit to allocate a tunnel IP.
    IpRequest {
        /// Optional client IPv4 preference. `None` = "give me anything".
        /// **Advisory only** - the exit MAY override.
        prefer_ipv4: Option<[u8; 4]>,
        /// 32-byte Ed25519 verifying-key bytes. When `Some`, the exit's
        /// allocator serves a **sticky** IP across reconnects (keyed on the
        /// pubkey) and the allowlist gate authorises the client by it.
        /// `None` = fresh, non-sticky allocation (and, in strict allowlist
        /// mode, rejected). The mapping lives only in the exit's in-memory
        /// allocator - no disk persistence of client identifiers.
        client_pubkey: Option<[u8; 32]>,
        /// `true` ⇒ the client wants a dual-stack IPv6 alongside the IPv4.
        /// The exit MAY still answer with `ipv6: None` in [`Self::IpAssign`]
        /// (it could not serve v6); the client then stays v4-only, the
        /// firewall keeps native v6 blocked (no leak), AND the client
        /// surfaces the gap ("IPv6 unavailable on this exit") rather than
        /// degrading silently. The *presence* of `ipv6` in the reply is the
        /// capability echo - no separate version/bitmask needed.
        wants_ipv6: bool,
        /// Proof of possession of `client_pubkey`'s private key: an
        /// Ed25519 signature over [`crate::pop_signing_message`]
        /// (domain-separated context || exit_id || the session's HPKE
        /// `encapsulated_key`). Required (alongside `client_pubkey`) in
        /// strict allowlist mode; without it a relay that merely KNOWS an
        /// allowlisted pubkey could obtain egress. Freshness comes from
        /// the per-session `encapsulated_key`; intra-session replay is
        /// covered by the session-scoped anti-replay window.
        pop_sig: Option<PopSignature>,
        /// `true` ⇒ the client wants the traffic-analysis defense (DAITA) on
        /// this session. The exit answers with [`Self::IpAssign::daita_spec`]:
        /// `Some(spec)` when it granted the defense (and the client MUST drive
        /// that machine on its uplink), `None` when it could not. Same
        /// capability-echo contract as `wants_ipv6`: a client that asked and
        /// got `None` knows the defense is NOT running and surfaces that,
        /// rather than padding nothing while believing it is protected.
        wants_daita: bool,
    },

    /// Exit -> client. Authoritative IP allocation, sent over the reliable
    /// setup stream. `ipv6` is `Some` **iff** the exit actually granted a
    /// dual-stack v6 - so its presence is the capability echo: a client
    /// that asked for v6 (`wants_ipv6`) but got `ipv6: None` knows the exit
    /// could not serve it and surfaces that instead of silently going
    /// v4-only. `daita_spec` carries the same contract for the
    /// traffic-analysis defense.
    IpAssign {
        /// Allocated host IPv4 address.
        ipv4: [u8; 4],
        /// IPv4 subnet prefix length (e.g. 24 for a `/24`).
        prefix_len: u8,
        /// IPv4 subnet gateway (also the exit-side TUN address).
        gateway_ipv4: [u8; 4],
        /// Allocated host IPv6 (`fdcc:f:1::x`), or `None` when the exit did
        /// not grant v6.
        ipv6: Option<[u8; 16]>,
        /// IPv6 subnet prefix length (e.g. 64). Ignored when `ipv6` is `None`.
        prefix_len_v6: u8,
        /// IPv6 subnet gateway (`fdcc:f:1::1`), or `None` when no v6.
        gateway_ipv6: Option<[u8; 16]>,
        /// The maybenot machine the exit sampled for THIS session, or `None`
        /// when it did not grant the defense (client did not ask, or the exit
        /// runs no pool). `Some` is the exit's commitment that it is driving
        /// the defense on its downlink; the client drives the same spec on its
        /// uplink. Its absence is the honest "DAITA is not running here"
        /// signal, which the client must surface rather than pad nothing.
        daita_spec: Option<warrenguard_wire::DaitaConfig>,
    },

    /// Exit -> client. The pool is exhausted. The client SHOULD terminate
    /// the session and surface the error to the operator.
    IpExhausted,

    /// Exit -> client. The setup was definitively refused by policy
    /// (pubkey not allowlisted, or the proof of possession is missing or
    /// invalid). Sent HPKE-sealed over the setup stream BEFORE the exit
    /// closes the connection, so the CLIENT learns the cause while the
    /// relay (the exit's TLS peer, hostile by model) only observes one
    /// opaque close code with empty reason bytes and cannot distinguish
    /// rejection causes (anti subscription-status oracle).
    Rejected,

    /// Exit -> client, **mid-session**. The exit is being drained for
    /// maintenance (ADR 36): it advises every connected client to migrate
    /// to another exit now, before it hard-closes at the deadline. Unlike
    /// the setup-only variants above, this is sent over the data-plane
    /// (sealed datagram) during the pump phase. It names no destination:
    /// the client re-selects from its signed, roster-authorised relay
    /// list, so a hostile exit cannot use this to herd users onto an
    /// attacker node (it can only make them leave, which it could already
    /// do by closing the connection).
    ExitDraining {
        /// Absolute Unix epoch seconds after which the exit hard-closes
        /// still-connected clients. Absolute (not "grace remaining") so a
        /// periodic re-send carries a stable, idempotent value.
        deadline_unix_secs: u64,
        /// Opaque reason (`0` = maintenance). Carries no per-user
        /// information; surfaced to the operator/telemetry, never logged
        /// against a client identity.
        reason_code: u8,
    },

    /// Client -> exit, **v7 anonymous admission** (Privacy Pass). It
    /// replaces the
    /// [`Self::IpRequest`] `client_pubkey` + `pop_sig` subscription proof with
    /// a stack of Privacy Pass [session tokens](warrenguard_wire::SessionToken)
    /// the exit verifies OFFLINE and spends anonymously, so the exit never
    /// learns the wallet. Appended as a distinct enum variant so the existing
    /// `/v2` layout (and its golden vectors) is byte-for-byte untouched: a
    /// v7-capable exit accepts both, an old exit rejects this variant loudly.
    IpRequestV7 {
        /// Optional client IPv4 preference (advisory), as in [`Self::IpRequest`].
        prefer_ipv4: Option<[u8; 4]>,
        /// `true` ⇒ the client wants a dual-stack IPv6 (same semantics and
        /// capability-echo contract as [`Self::IpRequest::wants_ipv6`]).
        wants_ipv6: bool,
        /// The subscription proof: a non-empty stack of Privacy Pass tokens
        /// (current epoch first, then a lookahead for epoch rollover). The
        /// exit verifies token[0] offline, spends its serial, and keys the
        /// sticky allocation + session registry by that anonymous serial
        /// (pubkey-shaped) instead of a wallet pubkey.
        session_tokens: Vec<SessionToken>,
        /// `true` ⇒ the client wants the traffic-analysis defense (same
        /// capability-echo contract as [`Self::IpRequest::wants_daita`]).
        wants_daita: bool,
    },

    /// Exit -> client. The setup was refused because the account is
    /// explicitly REVOKED (banned): its pubkey is on the exit's signed CRL,
    /// checked before the allowlist. Distinct from [`Self::Rejected`] (no
    /// active subscription / not enrolled, which the user fixes by renewing)
    /// so the client can surface a clear suspension message rather than a
    /// generic "not authorized". Like [`Self::Rejected`] it travels
    /// HPKE-sealed over the setup stream BEFORE the exit's single opaque
    /// close, so the relay (hostile by model) cannot tell a ban from any
    /// other rejection; only the client learns the cause.
    ///
    /// Appended as a distinct enum variant (postcard discriminant 6) so the
    /// existing `/v3` layout and its golden vectors stay byte-for-byte
    /// untouched: a client that predates this variant fails to decode it and
    /// safely falls back to the opaque-close `PolicyRefused` verdict (still
    /// fatal), while an updated client maps it to a suspension state. It
    /// carries no reason detail: the exit's CRL is membership-only (the
    /// human-readable reason never leaves the control-plane API), so the
    /// localized message is derived client-side from the ban state alone.
    RejectedBanned,
}

/// Encode a control message into the wire layout (marker + version +
/// postcard payload). The returned `Vec<u8>` is suitable for sealing
/// inside a [`crate::WarrenMultihopFrame`] as the plaintext.
///
/// # Errors
///
/// Propagates [`ControlError::Decode`] only if postcard fails to encode
/// the message (out-of-memory in practice; bounded fields rule out the
/// usual overflow paths).
pub fn encode_control(msg: &WarrenControlMessage) -> Result<Vec<u8>, ControlError> {
    let payload = postcard::to_stdvec(msg).map_err(ControlError::Decode)?;
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(CONTROL_FIRST_BYTE);
    out.push(CONTROL_VERSION_V3);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Try to decode a plaintext as a control message.
///
/// - `Ok(Some(msg))` - the plaintext starts with [`CONTROL_FIRST_BYTE`]
///   and parses cleanly. Caller should consume it as a control message
///   and NOT forward it to the TUN.
/// - `Ok(None)` - the plaintext does **not** start with the control
///   marker. Caller should fall through to the normal IP-packet
///   dispatch (or the DAITA dummy filter).
/// - `Err(_)` - the plaintext starts with the marker but is malformed
///   (truncation, version mismatch, trailing bytes, or postcard decode
///   failure). Caller SHOULD drop the frame and MAY log a warning.
///
/// # Errors
///
/// See [`ControlError`].
pub fn try_decode_control(plaintext: &[u8]) -> Result<Option<WarrenControlMessage>, ControlError> {
    let Some(&first) = plaintext.first() else {
        return Ok(None);
    };
    if first != CONTROL_FIRST_BYTE {
        return Ok(None);
    }
    if plaintext.len() < 2 {
        return Err(ControlError::TooShort {
            got: plaintext.len(),
        });
    }
    let version = plaintext[1];
    if version != CONTROL_VERSION_V3 {
        return Err(ControlError::UnsupportedVersion {
            got: version,
            expected: CONTROL_VERSION_V3,
        });
    }
    // `take_from_bytes` + explicit rest check rejects trailing bytes after
    // a valid message (anti-ambiguity): one plaintext is exactly one
    // control message.
    let (msg, rest): (WarrenControlMessage, &[u8]) = postcard::take_from_bytes(&plaintext[2..])?;
    if !rest.is_empty() {
        return Err(ControlError::TrailingBytes);
    }
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-impl golden shared with the TS client (`edge.control.test.ts`).
    /// Changing these bytes is a wire break across the sibling SDKs.
    #[test]
    fn ip_assign_v4_only_golden_matches_ts_vector() {
        let msg = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 3],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        let encoded = encode_control(&msg).expect("encode");
        assert_eq!(hex::encode(&encoded), "c003010a420003180a42000100000000");
        // And it round-trips back to the same message.
        assert_eq!(try_decode_control(&encoded).expect("decode"), Some(msg));
    }

    #[test]
    fn round_trip_ip_request_v4_only() {
        let msg = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
            wants_daita: false,
        };
        let encoded = encode_control(&msg).expect("encode");
        assert_eq!(encoded[0], CONTROL_FIRST_BYTE);
        assert_eq!(encoded[1], CONTROL_VERSION_V3);
        let decoded = try_decode_control(&encoded)
            .expect("decode result")
            .expect("control message present");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn round_trip_ip_request_with_pubkey_pop_and_wants_ipv6() {
        for wants_ipv6 in [true, false] {
            let msg = WarrenControlMessage::IpRequest {
                prefer_ipv4: Some([10, 66, 0, 42]),
                client_pubkey: Some([0x42; 32]),
                wants_ipv6,
                pop_sig: Some(PopSignature([0xA5; 64])),
                wants_daita: false,
            };
            let decoded = try_decode_control(&encode_control(&msg).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(
                decoded, msg,
                "IpRequest must round-trip (wants_ipv6={wants_ipv6})"
            );
        }
    }

    #[test]
    fn round_trip_ip_request_v7_with_tokens() {
        for wants_ipv6 in [true, false] {
            let msg = WarrenControlMessage::IpRequestV7 {
                prefer_ipv4: Some([10, 66, 0, 7]),
                wants_ipv6,
                session_tokens: vec![
                    SessionToken([0xAB; warrenguard_wire::SESSION_TOKEN_LEN]),
                    SessionToken([0xCD; warrenguard_wire::SESSION_TOKEN_LEN]),
                ],
                wants_daita: false,
            };
            let decoded = try_decode_control(&encode_control(&msg).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(
                decoded, msg,
                "IpRequestV7 must round-trip (wants_ipv6={wants_ipv6})"
            );
        }
    }

    #[test]
    fn ip_request_v7_wire_layout_is_frozen() {
        // Golden vector: pin the exact bytes so a drift is caught. The v7
        // variant is APPENDED, so it must not disturb the existing layout:
        // the v6 IpRequest keeps enum discriminant 0 (checked below).
        let len = warrenguard_wire::SESSION_TOKEN_LEN;
        let msg = WarrenControlMessage::IpRequestV7 {
            prefer_ipv4: None,
            wants_ipv6: false,
            session_tokens: vec![SessionToken(vec![0xCD; len].try_into().unwrap())],
            wants_daita: false,
        };
        let bytes = encode_control(&msg).unwrap();
        let mut expected = vec![
            CONTROL_FIRST_BYTE, // 0xC0 marker
            CONTROL_VERSION_V3, // 0x03 version
            0x05,               // enum discriminant: 6th variant (IpRequestV7)
            0x00,               // prefer_ipv4: Option None
            0x00,               // wants_ipv6: false
            0x01,               // session_tokens: Vec length = 1
        ];
        expected.extend_from_slice(&vec![0xCD; len]); // token[0] raw bytes
        expected.push(0x00); // wants_daita: false
        assert_eq!(bytes, expected, "v7 IpRequest control layout is frozen");

        // The pre-existing v6 IpRequest MUST still encode at discriminant 0
        // (proves appending the variant did not renumber the others).
        let v6 = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
            wants_daita: false,
        };
        let v6_bytes = encode_control(&v6).unwrap();
        assert_eq!(
            v6_bytes[2], 0x00,
            "v6 IpRequest must keep enum discriminant 0"
        );
    }

    #[test]
    fn round_trip_ip_assign_v4_only_and_dual_stack() {
        // v4-only: the exit did not grant v6 (ipv6 None = the capability echo).
        let v4_only = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 8],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        let decoded = try_decode_control(&encode_control(&v4_only).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(decoded, v4_only, "v4-only IpAssign must round-trip");

        // dual-stack: v6 granted.
        let dual = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 7],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: Some([
                0xfd, 0xcc, 0, 0x0f, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
            ]),
            prefix_len_v6: 64,
            gateway_ipv6: Some([
                0xfd, 0xcc, 0, 0x0f, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]),
            daita_spec: None,
        };
        let decoded = try_decode_control(&encode_control(&dual).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(decoded, dual, "dual-stack IpAssign must round-trip");
    }

    #[test]
    fn round_trip_ip_exhausted_and_rejected() {
        for msg in [
            WarrenControlMessage::IpExhausted,
            WarrenControlMessage::Rejected,
            WarrenControlMessage::RejectedBanned,
        ] {
            let decoded = try_decode_control(&encode_control(&msg).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(decoded, msg);
        }
    }

    // ---- Frozen wire vectors (/v2) ----
    //
    // Every expected byte is a hard literal on purpose: a vector that
    // re-derives its expectation from the constants under test would
    // pass through any drift. Any failure here means the wire layout
    // moved - bump CONTROL_VERSION and freeze new vectors.

    #[test]
    fn ip_request_minimal_wire_layout_is_frozen() {
        let msg = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
            wants_daita: false,
        };
        let encoded = encode_control(&msg).unwrap();
        assert_eq!(
            encoded,
            vec![
                0xC0, // CONTROL_FIRST_BYTE
                0x03, // CONTROL_VERSION_V3
                0x00, // variant tag 0 (IpRequest)
                0x00, // prefer_ipv4 = None
                0x00, // client_pubkey = None
                0x00, // wants_ipv6 = false
                0x00, // pop_sig = None
                0x00, // wants_daita = false
            ],
            "minimal IpRequest wire layout drifted - bump the version byte + freeze a new vector"
        );
    }

    #[test]
    fn ip_request_full_wire_layout_is_frozen() {
        let msg = WarrenControlMessage::IpRequest {
            prefer_ipv4: Some([10, 66, 0, 42]),
            client_pubkey: Some([0x42; 32]),
            wants_ipv6: true,
            pop_sig: Some(PopSignature([0xA5; 64])),
            wants_daita: true,
        };
        let encoded = encode_control(&msg).unwrap();
        let mut expected = vec![
            0xC0, // CONTROL_FIRST_BYTE
            0x03, // CONTROL_VERSION_V3
            0x00, // variant tag 0 (IpRequest)
            0x01, // prefer_ipv4 = Some
            10, 66, 0, 42,   // prefer_ipv4 bytes
            0x01, // client_pubkey = Some
        ];
        expected.extend_from_slice(&[0x42; 32]); // client_pubkey bytes
        expected.push(0x01); // wants_ipv6 = true
        expected.push(0x01); // pop_sig = Some
        expected.extend_from_slice(&[0xA5; 64]); // raw signature, no length prefix
        expected.push(0x01); // wants_daita = true
        assert_eq!(
            encoded, expected,
            "full IpRequest wire layout drifted - bump the version byte + freeze a new vector"
        );
    }

    #[test]
    fn ip_assign_wire_layout_is_frozen() {
        let msg = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 7],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
            daita_spec: None,
        };
        let encoded = encode_control(&msg).unwrap();
        assert_eq!(
            encoded,
            vec![
                0xC0, // CONTROL_FIRST_BYTE
                0x03, // CONTROL_VERSION_V3
                0x01, // variant tag 1 (IpAssign)
                10, 66, 0, 7,  // ipv4
                24, // prefix_len
                10, 66, 0, 1,    // gateway_ipv4
                0x00, // ipv6 = None
                0x00, // prefix_len_v6
                0x00, // gateway_ipv6 = None
                0x00, // daita_spec = None (the exit did not grant the defense)
            ],
            "IpAssign wire layout drifted - bump the version byte + freeze a new vector"
        );
    }

    #[test]
    fn ip_exhausted_wire_layout_is_frozen() {
        let encoded = encode_control(&WarrenControlMessage::IpExhausted).unwrap();
        assert_eq!(
            encoded,
            vec![0xC0, 0x03, 0x02],
            "IpExhausted wire layout drifted - bump the version byte + freeze a new vector"
        );
    }

    #[test]
    fn rejected_wire_layout_is_frozen() {
        let encoded = encode_control(&WarrenControlMessage::Rejected).unwrap();
        assert_eq!(
            encoded,
            vec![0xC0, 0x03, 0x03],
            "Rejected wire layout drifted - bump the version byte + freeze a new vector"
        );
    }

    #[test]
    fn rejected_banned_wire_layout_is_frozen() {
        // Appended variant: discriminant 6, no payload. Freezing the bytes
        // proves the ban rejection did not disturb any earlier variant's
        // layout. A drift here means the wire moved - bump CONTROL_VERSION
        // and freeze a new vector.
        let encoded = encode_control(&WarrenControlMessage::RejectedBanned).unwrap();
        assert_eq!(
            encoded,
            vec![0xC0, 0x03, 0x06],
            "RejectedBanned wire layout drifted - bump the version byte + freeze a new vector"
        );
        // The pre-existing Rejected MUST still encode at discriminant 3
        // (proves appending the ban variant did not renumber the others).
        assert_eq!(
            encode_control(&WarrenControlMessage::Rejected).unwrap()[2],
            0x03,
            "Rejected must keep enum discriminant 3 after appending RejectedBanned"
        );
    }

    #[test]
    fn exit_draining_wire_layout_is_frozen() {
        // ADR 36: variant tag 0x04, then postcard(u64 deadline as varint)
        // + u8 reason. deadline 1_700_000_120, reason 0. The bytes are a
        // hard literal captured from the encoder; a drift here means the
        // wire moved - bump CONTROL_VERSION and freeze a new vector.
        let encoded = encode_control(&WarrenControlMessage::ExitDraining {
            deadline_unix_secs: 1_700_000_120,
            reason_code: 0,
        })
        .unwrap();
        assert_eq!(
            encoded,
            vec![0xC0, 0x03, 0x04, 0xF8, 0xE2, 0xCF, 0xAA, 0x06, 0x00],
            "ExitDraining wire layout drifted - bump the version byte + freeze a new vector"
        );
    }

    #[test]
    fn exit_draining_round_trips() {
        // Behavioural: a mid-session drain advisory survives encode/decode
        // with both fields intact.
        let msg = WarrenControlMessage::ExitDraining {
            deadline_unix_secs: 1_700_000_120,
            reason_code: 7,
        };
        let encoded = encode_control(&msg).unwrap();
        let decoded = try_decode_control(&encoded)
            .expect("decode result")
            .expect("control message present");
        assert_eq!(decoded, msg, "ExitDraining must round-trip exactly");
    }

    // ---- Decoder hygiene ----

    #[test]
    fn non_control_prefix_returns_none() {
        // IPv4 packet (nibble 4), IPv6 packet (nibble 6), DAITA dummy (0xFF):
        // none must be classified as a control message.
        for first in [0x45u8, 0x60, 0xFF] {
            let plaintext = [first, 0x00, 0x00, 0x14];
            assert!(
                try_decode_control(&plaintext)
                    .expect("decode result")
                    .is_none(),
                "first byte 0x{first:02x} must not be classified as control"
            );
        }
    }

    #[test]
    fn unknown_variant_tag_is_a_decode_error_not_a_panic() {
        // A control-marked plaintext whose variant tag is out of range must
        // fail the decode cleanly (never panic, never misread).
        let bogus = [CONTROL_FIRST_BYTE, CONTROL_VERSION_V3, 0x7F, 0x00];
        assert!(matches!(
            try_decode_control(&bogus),
            Err(ControlError::Decode(_))
        ));
    }

    #[test]
    fn trailing_bytes_after_a_valid_message_are_rejected() {
        // One plaintext = exactly one control message. A stale or hostile
        // sender appending bytes after a valid message must be rejected,
        // not silently truncated.
        let mut encoded = encode_control(&WarrenControlMessage::IpExhausted).unwrap();
        encoded.push(0x00);
        assert!(
            matches!(
                try_decode_control(&encoded),
                Err(ControlError::TrailingBytes)
            ),
            "trailing bytes after a valid control message must be a decode error"
        );
    }

    #[test]
    fn retired_version_bytes_are_rejected_loudly() {
        // A stale binary still emits an older version byte. It cannot express
        // whether the traffic-analysis defense is running, so the receiver must
        // surface UnsupportedVersion (loggable) rather than decode an ambiguous
        // schema and leave a session silently undefended.
        for retired in [0x01u8, 0x02] {
            let stale = [CONTROL_FIRST_BYTE, retired, 0x02];
            assert!(
                matches!(
                    try_decode_control(&stale),
                    Err(ControlError::UnsupportedVersion {
                        got,
                        expected: CONTROL_VERSION_V3
                    }) if got == retired
                ),
                "control version 0x{retired:02x} must be refused, not decoded"
            );
        }
    }

    #[test]
    fn too_short_and_unknown_version_are_errors() {
        assert!(matches!(
            try_decode_control(&[CONTROL_FIRST_BYTE]),
            Err(ControlError::TooShort { got: 1 })
        ));
        assert!(matches!(
            try_decode_control(&[CONTROL_FIRST_BYTE, 0x99, 0x00]),
            Err(ControlError::UnsupportedVersion {
                got: 0x99,
                expected: CONTROL_VERSION_V3
            })
        ));
    }
}
