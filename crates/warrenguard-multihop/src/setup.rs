//! High-level multihop setup exchange (client side).
//!
//! Wraps the raw [`ClientSession`](crate::ClientSession) seal/open and the
//! [`WarrenControlMessage`](crate::WarrenControlMessage) codec into the single
//! round-trip a client performs before any traffic flows:
//!
//! 1. The client seals an `IpRequest` (asserting its account pubkey + a proof of
//!    possession over this session's `encapsulated_key`) into the first frame
//!    and sends it on a reliable bidi QUIC stream.
//! 2. The exit replies with a sealed `IpAssign` (or `Rejected` / `IpExhausted`).
//!
//! The transport owns the seq/epoch counters (the setup frame is the first
//! forward frame, `epoch = 0`, `seq = 0`; the first data datagram is `seq = 1`),
//! so they are passed in rather than tracked here. This keeps the crypto layer
//! free of transport state.

use ed25519_dalek::SigningKey;

use crate::control::{ControlError, WarrenControlMessage, encode_control, try_decode_control};
use crate::errors::MultihopError;
use crate::pop::sign_pop;
use crate::session::ClientSession;
use crate::wire_format::WarrenMultihopFrame;

/// The exit's authoritative tunnel-IP allocation, decoded from a sealed
/// `IpAssign` reply. `ipv6` is `Some` iff the exit actually granted dual-stack
/// v6 (the capability echo): a client that asked for v6 but got `None` knows the
/// exit could not serve it and surfaces that instead of going v4-only silently.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IpAssignment {
    /// Allocated host IPv4 address.
    pub ipv4: [u8; 4],
    /// IPv4 subnet prefix length (e.g. 24 for a `/24`).
    pub prefix_len: u8,
    /// IPv4 subnet gateway (also the exit-side TUN address).
    pub gateway_ipv4: [u8; 4],
    /// Allocated host IPv6, or `None` when the exit did not grant v6.
    pub ipv6: Option<[u8; 16]>,
    /// IPv6 subnet prefix length. Meaningless when `ipv6` is `None`.
    pub prefix_len_v6: u8,
    /// IPv6 subnet gateway, or `None` when no v6.
    pub gateway_ipv6: Option<[u8; 16]>,
}

impl IpAssignment {
    /// A loopback placeholder assignment for test harnesses that bypass the real
    /// setup exchange (e.g. the multihop echo exit, which assigns no IP). Never
    /// compiled into a production build.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn placeholder_for_test() -> Self {
        Self {
            ipv4: [127, 0, 0, 2],
            prefix_len: 24,
            gateway_ipv4: [127, 0, 0, 1],
            ipv6: None,
            prefix_len_v6: 0,
            gateway_ipv6: None,
        }
    }
}

/// Failure of the multihop setup exchange.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SetupError {
    /// HPKE seal/open or exit-id/version mismatch on the frame.
    #[error("multihop session error")]
    Session(#[source] MultihopError),
    /// Control-message codec error on the request or reply plaintext.
    #[error("multihop control codec error")]
    Control(#[source] ControlError),
    /// The exit refused the setup by policy (pubkey not allowlisted, or the
    /// proof of possession was missing or invalid). The cause is deliberately
    /// opaque on the wire (anti subscription-status oracle).
    #[error("multihop setup rejected by exit policy")]
    Rejected,
    /// The exit's address pool is exhausted.
    #[error("multihop exit ip pool exhausted")]
    IpExhausted,
    /// The reply was not a control message, or was a control message the client
    /// never expects to receive (e.g. an `IpRequest`).
    #[error("unexpected multihop setup reply")]
    UnexpectedReply,
}

impl From<MultihopError> for SetupError {
    fn from(e: MultihopError) -> Self {
        SetupError::Session(e)
    }
}

impl From<ControlError> for SetupError {
    fn from(e: ControlError) -> Self {
        SetupError::Control(e)
    }
}

impl ClientSession {
    /// Build the `IpRequest` control message for this session.
    ///
    /// When `signing_key` is `Some`, the request asserts its account pubkey and
    /// carries an Ed25519 proof of possession over this session's
    /// `encapsulated_key` (domain-separated and exit-bound), which a strict exit
    /// requires before granting egress. `None` is for permissive/bench exits
    /// only and is rejected by a production exit.
    #[must_use]
    pub fn build_ip_request(
        &self,
        signing_key: Option<&SigningKey>,
        prefer_ipv4: Option<[u8; 4]>,
        wants_ipv6: bool,
    ) -> WarrenControlMessage {
        let exit_id = self.exit_id();
        let encapsulated_key = self.encapsulated_key();
        let (client_pubkey, pop_sig) = match signing_key {
            Some(key) => (
                Some(key.verifying_key().to_bytes()),
                Some(sign_pop(key, &exit_id, &encapsulated_key)),
            ),
            None => (None, None),
        };
        WarrenControlMessage::IpRequest {
            prefer_ipv4,
            client_pubkey,
            wants_ipv6,
            pop_sig,
        }
    }

    /// Seal the setup `IpRequest` into the first forward frame.
    ///
    /// The setup frame is the first forward frame of the session, so the
    /// transport calls this with `epoch = 0`, `seq = 0` and resumes the data
    /// path at `seq = 1`.
    ///
    /// # Errors
    ///
    /// [`SetupError::Control`] if the control message fails to encode,
    /// [`SetupError::Session`] if the HPKE seal fails.
    pub fn seal_setup_request(
        &self,
        signing_key: Option<&SigningKey>,
        prefer_ipv4: Option<[u8; 4]>,
        wants_ipv6: bool,
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrame, SetupError> {
        let msg = self.build_ip_request(signing_key, prefer_ipv4, wants_ipv6);
        let plaintext = encode_control(&msg)?;
        Ok(self.seal(&plaintext, epoch, seq)?)
    }

    /// Build the v7 anonymous [`WarrenControlMessage::IpRequestV7`] for this
    /// session: present `session_tokens` instead of a wallet pubkey + PoP, so
    /// the exit admits the session without learning the account. No
    /// signing key is used and no PoP is produced; the token IS the proof.
    #[must_use]
    pub fn build_ip_request_v7(
        &self,
        session_tokens: Vec<warrenguard_wire::SessionToken>,
        prefer_ipv4: Option<[u8; 4]>,
        wants_ipv6: bool,
    ) -> WarrenControlMessage {
        WarrenControlMessage::IpRequestV7 {
            prefer_ipv4,
            wants_ipv6,
            session_tokens,
        }
    }

    /// Seal a v7 [`WarrenControlMessage::IpRequestV7`] into the first forward
    /// frame (the anonymous-token counterpart of [`Self::seal_setup_request`]).
    ///
    /// # Errors
    ///
    /// [`SetupError::Control`] if the control message fails to encode,
    /// [`SetupError::Session`] if the HPKE seal fails.
    pub fn seal_setup_request_v7(
        &self,
        session_tokens: Vec<warrenguard_wire::SessionToken>,
        prefer_ipv4: Option<[u8; 4]>,
        wants_ipv6: bool,
        epoch: u32,
        seq: u64,
    ) -> Result<WarrenMultihopFrame, SetupError> {
        let msg = self.build_ip_request_v7(session_tokens, prefer_ipv4, wants_ipv6);
        let plaintext = encode_control(&msg)?;
        Ok(self.seal(&plaintext, epoch, seq)?)
    }

    /// Open the exit's sealed setup reply and interpret it.
    ///
    /// # Errors
    ///
    /// [`SetupError::Session`] on an HPKE-open / exit-id / version failure,
    /// [`SetupError::Control`] on a malformed control plaintext,
    /// [`SetupError::Rejected`] / [`SetupError::IpExhausted`] on a policy reply,
    /// [`SetupError::UnexpectedReply`] for any other control variant or a
    /// non-control plaintext.
    pub fn open_setup_reply(
        &self,
        frame: &WarrenMultihopFrame,
    ) -> Result<IpAssignment, SetupError> {
        let plaintext = self.open_response(frame)?;
        match try_decode_control(&plaintext)? {
            Some(WarrenControlMessage::IpAssign {
                ipv4,
                prefix_len,
                gateway_ipv4,
                ipv6,
                prefix_len_v6,
                gateway_ipv6,
            }) => Ok(IpAssignment {
                ipv4,
                prefix_len,
                gateway_ipv4,
                ipv6,
                prefix_len_v6,
                gateway_ipv6,
            }),
            Some(WarrenControlMessage::Rejected) => Err(SetupError::Rejected),
            Some(WarrenControlMessage::IpExhausted) => Err(SetupError::IpExhausted),
            // An IpRequest (client->exit direction), a mid-session
            // ExitDraining advisory (data-plane only, never a setup reply),
            // or a non-control plaintext on the reply path is a protocol
            // violation by the peer. The control enum is exhaustive, so a
            // new variant surfaces here as a compile error rather than
            // being silently swallowed.
            Some(
                WarrenControlMessage::IpRequest { .. }
                | WarrenControlMessage::IpRequestV7 { .. }
                | WarrenControlMessage::ExitDraining { .. },
            )
            | None => Err(SetupError::UnexpectedReply),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pop::verify_pop;
    use crate::session::{ExitId, ExitSession, derive_exit_keypair};
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;

    /// Build a matched client + exit session over the same HPKE encapsulation,
    /// exercising the real engine seal/open on both sides (no hand-rolled HPKE).
    fn pair() -> (ClientSession, ExitSession, SigningKey) {
        let (exit_priv, exit_pub) = derive_exit_keypair(b"warrenguard-setup-test-ikm");
        let exit_id = ExitId::from_bytes([0x3c; 16]);
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let client = ClientSession::new(&exit_pub, exit_id, &mut rng).expect("client session");
        let exit = ExitSession::new(&exit_priv, &client.encapsulated_key(), exit_id)
            .expect("exit session");
        let account = SigningKey::from_bytes(&[0x42; 32]);
        (client, exit, account)
    }

    #[test]
    fn setup_request_carries_a_valid_pop_and_round_trips_to_ip_assign() {
        let (client, exit, account) = pair();

        let request = client
            .seal_setup_request(Some(&account), None, true, 0, 0)
            .expect("seal setup request");
        assert_eq!(request.seq, 0, "setup frame is the first forward frame");
        assert_eq!(request.epoch, 0);

        // Exit side: open the request, decode it, verify the PoP exactly as a
        // strict exit would before consulting the allowlist.
        let plaintext = exit.open(&request).expect("exit opens request");
        let WarrenControlMessage::IpRequest {
            client_pubkey,
            pop_sig,
            wants_ipv6,
            prefer_ipv4,
        } = try_decode_control(&plaintext).unwrap().unwrap()
        else {
            panic!("expected an IpRequest");
        };
        assert!(wants_ipv6);
        assert_eq!(prefer_ipv4, None);
        let pubkey = client_pubkey.expect("pubkey asserted");
        assert_eq!(pubkey, account.verifying_key().to_bytes());
        assert!(
            verify_pop(
                &pubkey,
                &client.exit_id(),
                &client.encapsulated_key(),
                &pop_sig.expect("pop present"),
            ),
            "the proof of possession must verify against the asserted pubkey"
        );

        // Exit grants a dual-stack assignment; the client decodes it.
        let assign = WarrenControlMessage::IpAssign {
            ipv4: [10, 66, 0, 9],
            prefix_len: 24,
            gateway_ipv4: [10, 66, 0, 1],
            ipv6: Some([
                0xfd, 0xcc, 0, 0x0f, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
            ]),
            prefix_len_v6: 64,
            gateway_ipv6: Some([
                0xfd, 0xcc, 0, 0x0f, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]),
        };
        let reply = exit
            .seal_response(&encode_control(&assign).unwrap(), 0, 0)
            .expect("exit seals reply");
        let got = client.open_setup_reply(&reply).expect("open reply");
        assert_eq!(got.ipv4, [10, 66, 0, 9]);
        assert_eq!(got.prefix_len, 24);
        assert_eq!(got.gateway_ipv4, [10, 66, 0, 1]);
        assert_eq!(got.ipv6.unwrap()[15], 0x09);
        assert_eq!(got.prefix_len_v6, 64);
    }

    #[test]
    fn permissive_request_without_identity_omits_pubkey_and_pop() {
        let (client, exit, _account) = pair();
        let request = client
            .seal_setup_request(None, Some([10, 66, 0, 5]), false, 0, 0)
            .unwrap();
        let plaintext = exit.open(&request).unwrap();
        let WarrenControlMessage::IpRequest {
            client_pubkey,
            pop_sig,
            prefer_ipv4,
            wants_ipv6,
        } = try_decode_control(&plaintext).unwrap().unwrap()
        else {
            panic!("expected an IpRequest");
        };
        assert_eq!(client_pubkey, None);
        assert_eq!(pop_sig, None);
        assert_eq!(prefer_ipv4, Some([10, 66, 0, 5]));
        assert!(!wants_ipv6);
    }

    #[test]
    fn rejected_reply_maps_to_rejected_error() {
        let (client, exit, account) = pair();
        let request = client
            .seal_setup_request(Some(&account), None, false, 0, 0)
            .unwrap();
        let _ = exit.open(&request).unwrap();
        let reply = exit
            .seal_response(
                &encode_control(&WarrenControlMessage::Rejected).unwrap(),
                0,
                0,
            )
            .unwrap();
        assert!(matches!(
            client.open_setup_reply(&reply),
            Err(SetupError::Rejected)
        ));
    }

    #[test]
    fn ip_exhausted_reply_maps_to_ip_exhausted_error() {
        let (client, exit, account) = pair();
        let request = client
            .seal_setup_request(Some(&account), None, false, 0, 0)
            .unwrap();
        let _ = exit.open(&request).unwrap();
        let reply = exit
            .seal_response(
                &encode_control(&WarrenControlMessage::IpExhausted).unwrap(),
                0,
                0,
            )
            .unwrap();
        assert!(matches!(
            client.open_setup_reply(&reply),
            Err(SetupError::IpExhausted)
        ));
    }

    #[test]
    fn an_ip_request_on_the_reply_path_is_unexpected() {
        let (client, exit, account) = pair();
        let request = client
            .seal_setup_request(Some(&account), None, false, 0, 0)
            .unwrap();
        let _ = exit.open(&request).unwrap();
        // The exit must never send an IpRequest back; the client rejects it.
        let bogus = WarrenControlMessage::IpRequest {
            prefer_ipv4: None,
            client_pubkey: None,
            wants_ipv6: false,
            pop_sig: None,
        };
        let reply = exit
            .seal_response(&encode_control(&bogus).unwrap(), 0, 0)
            .unwrap();
        assert!(matches!(
            client.open_setup_reply(&reply),
            Err(SetupError::UnexpectedReply)
        ));
    }
}
