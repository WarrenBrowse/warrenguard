//! Proxy configuration encoding/decoding.
//!
//! A proxy configuration is packed into the 16 bytes of an IPv6 address and
//! published as an `AAAA` record, resolved by the client over DoH. This
//! module is byte-for-byte compatible with the parser in the upstream
//! `mullvad-encrypted-dns-proxy` client crate, and additionally
//! provides the inverse [`ProxyConfig::to_ipv6`] encoder (which the client
//! does not need) so operators can generate the records to publish.
//!
//! Wire layout (network byte order, hextets of the IPv6 address):
//! - bytes 0..2  : free prefix, ignored by the parser (conventionally `2001`)
//! - bytes 2..4  : u16 little-endian proxy type (`0x01` Plain, `0x03` `XorV2`)
//! - bytes 4..8  : proxy IPv4 address
//! - bytes 8..10 : u16 little-endian proxy port
//! - bytes 10..16: `XorV2` key (6 bytes, `0x00`-terminated); unused for Plain

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};

use crate::xor::{XorKey, XorObfuscator};

/// Conventional IPv6 prefix used by Mullvad for the published records. The
/// parser ignores these two bytes, but matching the convention keeps the
/// records looking like ordinary global-unicast addresses.
pub const DEFAULT_PREFIX: [u8; 2] = [0x20, 0x01];

/// Errors that can occur while decoding a [`ProxyConfig`] from an IPv6 address.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The proxy type field holds a value this implementation cannot parse.
    #[error("unknown type of proxy: {0:#x}")]
    UnknownProxyType(u16),
    /// The deprecated XorV1 proxy type is not supported.
    #[error("XorV1 proxy types are not supported")]
    XorV1Unsupported,
    /// The encoded port is zero, which is not a valid remote endpoint.
    #[error("port {0} is not valid for a remote endpoint")]
    InvalidPort(u16),
    /// The XOR key material was empty (all zeros).
    #[error("the key material for XOR obfuscation is empty")]
    EmptyXorKey,
}

/// Type discriminant carried in the 2nd hextet (u16 little-endian).
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum ProxyType {
    Plain,
    XorV1,
    XorV2,
}

impl TryFrom<[u8; 2]> for ProxyType {
    type Error = Error;

    fn try_from(bytes: [u8; 2]) -> Result<Self, Self::Error> {
        match u16::from_le_bytes(bytes) {
            0x01 => Ok(Self::Plain),
            0x02 => Ok(Self::XorV1),
            0x03 => Ok(Self::XorV2),
            unknown => Err(Error::UnknownProxyType(unknown)),
        }
    }
}

/// Per-direction obfuscation applied to the relayed stream.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ObfuscationConfig {
    /// Repeating-key XOR keystream ("XorV2").
    XorV2(XorKey),
}

impl ObfuscationConfig {
    /// Create a fresh obfuscator positioned at the start of the keystream.
    #[must_use]
    pub fn create_obfuscator(&self) -> XorObfuscator {
        match self {
            Self::XorV2(key) => XorObfuscator::new(*key),
        }
    }
}

/// A decoded proxy endpoint plus its optional obfuscation.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ProxyConfig {
    /// Public address where the proxy server listens.
    pub addr: SocketAddrV4,
    /// Obfuscation to apply to the relayed stream, if any.
    pub obfuscation: Option<ObfuscationConfig>,
}

impl ProxyConfig {
    /// Encode this configuration into an IPv6 address for publishing as an
    /// `AAAA` record. Inverse of [`TryFrom<Ipv6Addr>`].
    #[must_use]
    pub fn to_ipv6(&self, prefix: [u8; 2]) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets[0..2].copy_from_slice(&prefix);

        let (proxy_type, key_tail): (u16, [u8; 6]) = match &self.obfuscation {
            None => (0x01, [0u8; 6]),
            Some(ObfuscationConfig::XorV2(key)) => (0x03, key.to_padded()),
        };

        octets[2..4].copy_from_slice(&proxy_type.to_le_bytes());
        octets[4..8].copy_from_slice(&self.addr.ip().octets());
        octets[8..10].copy_from_slice(&self.addr.port().to_le_bytes());
        octets[10..16].copy_from_slice(&key_tail);

        Ipv6Addr::from(octets)
    }
}

impl TryFrom<Ipv6Addr> for ProxyConfig {
    type Error = Error;

    fn try_from(ip: Ipv6Addr) -> Result<Self, Self::Error> {
        let data = ip.octets();

        let proxy_type_bytes = <[u8; 2]>::try_from(&data[2..4]).unwrap();
        let payload = <[u8; 12]>::try_from(&data[4..16]).unwrap();

        match ProxyType::try_from(proxy_type_bytes)? {
            ProxyType::Plain => parse_plain(payload),
            ProxyType::XorV1 => Err(Error::XorV1Unsupported),
            ProxyType::XorV2 => parse_xor(payload),
        }
    }
}

fn parse_plain(data: [u8; 12]) -> Result<ProxyConfig, Error> {
    let (ip_bytes, tail) = data.split_first_chunk::<4>().unwrap();
    let (port_bytes, _tail) = tail.split_first_chunk::<2>().unwrap();

    let port = u16::from_le_bytes(*port_bytes);
    if port == 0 {
        return Err(Error::InvalidPort(0));
    }
    Ok(ProxyConfig {
        addr: SocketAddrV4::new(Ipv4Addr::from(*ip_bytes), port),
        obfuscation: None,
    })
}

fn parse_xor(data: [u8; 12]) -> Result<ProxyConfig, Error> {
    let (ip_bytes, tail) = data.split_first_chunk::<4>().unwrap();
    let (port_bytes, key_bytes) = tail.split_first_chunk::<2>().unwrap();
    let key_bytes = <[u8; 6]>::try_from(key_bytes).unwrap();

    let port = u16::from_le_bytes(*port_bytes);
    if port == 0 {
        return Err(Error::InvalidPort(port));
    }
    Ok(ProxyConfig {
        addr: SocketAddrV4::new(Ipv4Addr::from(*ip_bytes), port),
        obfuscation: Some(ObfuscationConfig::XorV2(XorKey::try_from(key_bytes)?)),
    })
}

impl fmt::Display for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.obfuscation {
            None => write!(f, "{} (plain)", self.addr),
            Some(ObfuscationConfig::XorV2(key)) => write!(f, "{} (xorv2 {key:?})", self.addr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the exact vectors from the upstream Mullvad client test
    /// suite, proving the parser is wire-compatible.
    #[test]
    fn decodes_client_xor_vectors() {
        let addr: Ipv6Addr = "2001:300:7f00:1:3905:0102:304:506".parse().unwrap();
        let cfg = ProxyConfig::try_from(addr).unwrap();
        assert_eq!(cfg.addr, "127.0.0.1:1337".parse().unwrap());
        assert_eq!(
            cfg.obfuscation,
            Some(ObfuscationConfig::XorV2(
                XorKey::try_from([1, 2, 3, 4, 5, 6]).unwrap()
            ))
        );
    }

    #[test]
    fn decodes_client_plain_vector() {
        let addr: Ipv6Addr = "2001:100:c0a8:101:bb01::".parse().unwrap();
        let cfg = ProxyConfig::try_from(addr).unwrap();
        assert_eq!(cfg.addr, "192.168.1.1:443".parse().unwrap());
        assert_eq!(cfg.obfuscation, None);
    }

    #[test]
    fn rejects_xorv1() {
        let addr: Ipv6Addr = "2001:200:7f00:1:3905:0102:304:506".parse().unwrap();
        assert_eq!(ProxyConfig::try_from(addr), Err(Error::XorV1Unsupported));
    }

    #[test]
    fn rejects_zero_port() {
        let addr: Ipv6Addr = "2001:100:c0a8:101:0000:404::".parse().unwrap();
        assert_eq!(ProxyConfig::try_from(addr), Err(Error::InvalidPort(0)));
    }

    /// The encoder must reproduce exactly the IPv6 the client expects.
    #[test]
    fn encoder_matches_client_xor_vector() {
        let cfg = ProxyConfig {
            addr: "127.0.0.1:1337".parse().unwrap(),
            obfuscation: Some(ObfuscationConfig::XorV2(
                XorKey::try_from([1, 2, 3, 4, 5, 6]).unwrap(),
            )),
        };
        let expected: Ipv6Addr = "2001:300:7f00:1:3905:0102:304:506".parse().unwrap();
        assert_eq!(cfg.to_ipv6(DEFAULT_PREFIX), expected);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let cases = [
            ProxyConfig {
                addr: "203.0.113.7:443".parse().unwrap(),
                obfuscation: Some(ObfuscationConfig::XorV2(
                    XorKey::try_from([0xab, 0xcd, 0xef, 0, 0, 0]).unwrap(),
                )),
            },
            ProxyConfig {
                addr: "198.51.100.42:8443".parse().unwrap(),
                obfuscation: None,
            },
        ];
        for cfg in cases {
            let encoded = cfg.to_ipv6(DEFAULT_PREFIX);
            assert_eq!(ProxyConfig::try_from(encoded), Ok(cfg));
        }
    }
}
