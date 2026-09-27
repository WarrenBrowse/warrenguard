//! Typed token refusal: the reason code of a
//! [`crate::WarrenControlMessage::TokenRejected`].
//!
//! An exit refuses a token for one of two reasons the client acts on
//! differently: the token did not verify (or could not be spent), or it
//! verified and its serial is leased to a live session elsewhere, which is
//! another device of the same wallet. A client refused the second way for
//! every token of its stack holds none of the wallet's device slots.
//!
//! The exit sends the code only to a client that asked for it with
//! [`crate::WarrenControlMessage::IpRequestV7Detailed`]: a client that
//! predates it cannot decode the reply and would present the refused token
//! again instead of the next one.

/// Reason code of a [`crate::WarrenControlMessage::TokenRejected`], a plain
/// `u8` on the wire so a code this build does not know still decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenRejectCode {
    /// `0`: the token did not verify, or the exit could not spend it.
    Unspecified,
    /// `1`: the token verified and its serial is leased to a live session
    /// elsewhere.
    SerialInUse,
    /// A code this build does not know. Read as [`Self::Unspecified`].
    Other(u8),
}

impl TokenRejectCode {
    /// Decode a wire code.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Unspecified,
            1 => Self::SerialInUse,
            other => Self::Other(other),
        }
    }

    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::SerialInUse => 1,
            Self::Other(code) => code,
        }
    }

    /// A stable label for metrics and logs (no identifier).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::SerialInUse => "serial_in_use",
            Self::Other(_) => "other",
        }
    }
}

impl core::fmt::Display for TokenRejectCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_keeps_its_wire_value() {
        for (code, wire) in [
            (TokenRejectCode::Unspecified, 0),
            (TokenRejectCode::SerialInUse, 1),
        ] {
            assert_eq!(code.code(), wire, "{code} moved");
            assert_eq!(TokenRejectCode::from_code(wire), code);
        }
    }

    #[test]
    fn an_unknown_code_decodes_and_encodes_back_unchanged() {
        let code = TokenRejectCode::from_code(42);
        assert_eq!(code, TokenRejectCode::Other(42));
        assert_eq!(code.code(), 42);
        assert_eq!(code.as_str(), "other");
    }
}
