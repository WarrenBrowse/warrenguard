//! Anonymous session-token (Privacy Pass) wire primitives.
//!
//! The exit admits an anonymous session by verifying a stack of Privacy Pass
//! [`SessionToken`]s OFFLINE and spending one, so it never sees the wallet. This
//! module holds the token wire type and its size constants; the multi-hop
//! control plane (`warrenguard_multihop`) carries the tokens in its sealed setup
//! exchange, and the exit parses them with `warrenguard_token::Token`.

use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

/// Length of one serialized Privacy Pass session token, matching
/// `warrenguard_token::TOKEN_LEN` (token_input 98 + authenticator 256). The
/// wire crate deliberately does not depend on `warrenguard-token` (layering:
/// wire is the low-level frame codec, it treats a token as an opaque bearer
/// blob), so the constant is duplicated here and pinned equal to the token
/// crate's value by a test in that crate.
pub const SESSION_TOKEN_LEN: usize = 354;

/// Length of the multi-conn attach capability (128-bit, unguessable).
pub const ATTACH_SECRET_LEN: usize = 16;

/// Upper bound on the number of tokens a primary may present in one setup
/// (current epoch + a lookahead so a long session never re-handshakes at an
/// epoch boundary). Bounds the decode allocation from a hostile peer.
pub const MAX_SESSION_TOKENS: usize = 8;

/// One serialized Privacy Pass token, carried as [`SESSION_TOKEN_LEN`] raw
/// bytes with no length prefix. The wire crate does
/// not interpret the bytes; the exit parses them with `warrenguard_token::Token`.
///
/// A bearer credential until spent, so `==` reads every byte whatever the
/// first difference ([`ConstantTimeEq`]).
#[derive(Clone, Copy)]
pub struct SessionToken(pub [u8; SESSION_TOKEN_LEN]);

impl ConstantTimeEq for SessionToken {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SessionToken {}

impl core::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A token is a bearer credential: never render its bytes.
        f.write_str("SessionToken(..)")
    }
}

impl Serialize for SessionToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeTuple;
        let mut tuple = serializer.serialize_tuple(SESSION_TOKEN_LEN)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for SessionToken {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenVisitor;
        impl<'de> serde::de::Visitor<'de> for TokenVisitor {
            type Value = SessionToken;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{SESSION_TOKEN_LEN} raw session-token bytes")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; SESSION_TOKEN_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(SessionToken(out))
            }
        }
        deserializer.deserialize_tuple(SESSION_TOKEN_LEN, TokenVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_postcard_roundtrips_as_fixed_length_raw_bytes() {
        let token = SessionToken([0xCD; SESSION_TOKEN_LEN]);
        let bytes = postcard::to_allocvec(&token).expect("encode");
        // No length prefix: exactly SESSION_TOKEN_LEN raw bytes.
        assert_eq!(bytes.len(), SESSION_TOKEN_LEN);
        assert_eq!(bytes, vec![0xCD; SESSION_TOKEN_LEN]);
        let decoded: SessionToken = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, token, "SessionToken must round-trip byte-for-byte");
    }

    #[test]
    fn session_token_equality_is_constant_time_over_every_byte() {
        use subtle::ConstantTimeEq as _;
        let token = SessionToken([0x5a; SESSION_TOKEN_LEN]);

        assert!(bool::from(
            token.ct_eq(&SessionToken([0x5a; SESSION_TOKEN_LEN]))
        ));
        assert_eq!(token, SessionToken([0x5a; SESSION_TOKEN_LEN]));
        for offset in [0, SESSION_TOKEN_LEN / 2, SESSION_TOKEN_LEN - 1] {
            let mut altered = token;
            altered.0[offset] ^= 1;
            assert!(
                !bool::from(token.ct_eq(&altered)),
                "tokens differing at byte {offset} compared equal"
            );
            assert_ne!(token, altered, "`==` must agree with `ct_eq`");
        }
    }

    #[test]
    fn session_token_debug_never_renders_the_bytes() {
        let token = SessionToken([0x11; SESSION_TOKEN_LEN]);
        assert_eq!(format!("{token:?}"), "SessionToken(..)");
    }
}
