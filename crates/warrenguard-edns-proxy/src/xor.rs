//! XOR-stream obfuscation, byte-for-byte compatible with the Mullvad
//! "XorV2" obfuscator used by the upstream client
//! (`mullvad-encrypted-dns-proxy/src/config/xor.rs`).
//!
//! The obfuscation is a repeating-key XOR keystream applied independently
//! per direction. Because XOR is its own inverse, the same operation both
//! obfuscates (server -> client) and deobfuscates (client -> server); the
//! server simply applies it once on each leg of the relayed connection.

use core::fmt;

use crate::config::Error;

/// A repeating XOR key of 1..=6 bytes.
///
/// The on-wire encoding packs the key into the last 6 bytes of an IPv6
/// address; a `0x00` byte marks a premature end of the key, so the
/// effective key length is 1..=6.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct XorKey {
    data: [u8; 6],
    len: usize,
}

impl XorKey {
    /// Return the active key material. Always has length 1..=6.
    #[must_use]
    pub fn key_data(&self) -> &[u8] {
        &self.data[0..self.len]
    }

    /// Return the full 6-byte representation, zero-padded after the key.
    ///
    /// This is the inverse of [`XorKey::try_from`] and is used by the
    /// AAAA-record encoder to serialize the key back into an IPv6 address.
    #[must_use]
    pub fn to_padded(&self) -> [u8; 6] {
        self.data
    }
}

impl fmt::Debug for XorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for byte in self.key_data() {
            write!(f, "{byte:0>2x}")?;
        }
        Ok(())
    }
}

impl TryFrom<[u8; 6]> for XorKey {
    type Error = Error;

    fn try_from(mut key_bytes: [u8; 6]) -> Result<Self, Self::Error> {
        let key_len = key_bytes
            .iter()
            .position(|b| *b == 0x00)
            .unwrap_or(key_bytes.len());
        if key_len == 0 {
            return Err(Error::EmptyXorKey);
        }

        // Reset bytes after the terminating null to zero so `Eq`/`Hash`
        // ignore trailing garbage. Matches the client implementation.
        key_bytes[key_len..].fill(0);

        Ok(Self {
            data: key_bytes,
            len: key_len,
        })
    }
}

/// Stateful repeating-key XOR obfuscator.
///
/// One instance encodes (or decodes) a single direction of a connection;
/// `key_index` advances across successive buffers, so a fresh obfuscator
/// must be created per direction and per connection.
#[derive(Debug)]
pub struct XorObfuscator {
    key: XorKey,
    key_index: usize,
}

impl XorObfuscator {
    /// Create an obfuscator positioned at the start of the keystream.
    #[must_use]
    pub fn new(key: XorKey) -> Self {
        Self { key, key_index: 0 }
    }

    /// XOR the buffer in place, advancing the keystream position.
    pub fn obfuscate(&mut self, buffer: &mut [u8]) {
        let key_data = self.key.key_data();
        for byte in buffer {
            *byte ^= key_data[self.key_index % key_data.len()];
            self.key_index = (self.key_index + 1) % key_data.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{XorKey, XorObfuscator};

    // Same vector as the upstream Mullvad client test, proving wire-fidelity.
    #[test]
    fn obfuscation_roundtrip_matches_client_vector() {
        const INPUT: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut payload = INPUT.to_vec();

        let xor_key = XorKey::try_from([0xff, 0x04, 0x02, 0x04, 0x00, 0x00]).unwrap();
        let mut enc = XorObfuscator::new(xor_key);
        let mut dec = XorObfuscator::new(xor_key);

        enc.obfuscate(&mut payload);
        assert_eq!(
            payload,
            &[0xfe, 0x06, 0x01, 0x00, 0xfa, 0x02, 0x05, 0x0c, 0xf6, 0x0e]
        );

        dec.obfuscate(&mut payload);
        assert_eq!(INPUT, payload.as_slice());
    }

    #[test]
    fn empty_key_rejected() {
        assert!(XorKey::try_from([0; 6]).is_err());
    }

    #[test]
    fn null_terminates_key() {
        let key = XorKey::try_from([0x01, 0xff, 0x31, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(key.key_data(), &[0x01, 0xff, 0x31]);
        assert_eq!(format!("{key:?}"), "0x01ff31");
    }
}
