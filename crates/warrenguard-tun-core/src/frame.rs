//! TUN packet framing: the small per-OS header in front of each IP packet.
//!
//! A kernel TUN device delivers and accepts IP packets. On Linux (and Windows
//! Wintun) the device carries the bare IP packet. On macOS the `utun` device
//! prepends a 4-byte address-family word to every packet. This module isolates
//! that difference so the datapath above it always works with bare IP packets.

/// The address family of an IP packet, derived from its first nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFamily {
    /// IPv4 (first nibble `4`).
    V4,
    /// IPv6 (first nibble `6`).
    V6,
}

impl PacketFamily {
    /// Detects the family from the IP version nibble of `packet`, or `None` if
    /// the packet is empty or carries an unknown version.
    #[must_use]
    pub fn detect(packet: &[u8]) -> Option<Self> {
        match packet.first().map(|b| b >> 4) {
            Some(4) => Some(Self::V4),
            Some(6) => Some(Self::V6),
            _ => None,
        }
    }

    /// The macOS `utun` 4-byte address-family header value for this family.
    ///
    /// The constants are `AF_INET = 2` and (on Darwin) `AF_INET6 = 30`. The kernel
    /// serializes this word in NETWORK byte order (it applies `ntohl`/`htonl`), so
    /// [`Framing`] encodes/decodes it big-endian. A host-order header is rejected
    /// by the kernel and silently breaks the datapath; see
    /// `darwin_utun_header_is_network_byte_order`.
    #[must_use]
    pub const fn darwin_af(self) -> u32 {
        match self {
            Self::V4 => 2,
            Self::V6 => 30,
        }
    }

    /// The family for a macOS `utun` address-family header value, if recognized.
    #[must_use]
    pub const fn from_darwin_af(af: u32) -> Option<Self> {
        match af {
            2 => Some(Self::V4),
            30 => Some(Self::V6),
            _ => None,
        }
    }
}

/// How a TUN device frames packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// Bare IP packet, no header (Linux `/dev/net/tun` without `IFF_NO_PI`
    /// handled separately, Windows Wintun).
    Bare,
    /// macOS `utun`: a 4-byte address-family word (network byte order) precedes
    /// the IP packet.
    DarwinUtun,
}

impl Framing {
    /// The framing the current target OS uses by default.
    #[must_use]
    pub const fn for_target_os() -> Self {
        if cfg!(target_os = "macos") {
            Self::DarwinUtun
        } else {
            Self::Bare
        }
    }

    /// Wraps a bare IP `packet` in this framing for writing to the device.
    /// Returns `None` if the packet has no recognizable IP version (a `DarwinUtun`
    /// frame must name the family; a malformed packet is rejected, not guessed).
    #[must_use]
    pub fn encode(self, packet: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Bare => Some(packet.to_vec()),
            Self::DarwinUtun => {
                let family = PacketFamily::detect(packet)?;
                let mut out = Vec::with_capacity(4 + packet.len());
                out.extend_from_slice(&family.darwin_af().to_be_bytes());
                out.extend_from_slice(packet);
                Some(out)
            }
        }
    }

    /// Strips this framing from a device read, returning the bare IP packet, or
    /// `None` if the frame is too short or carries an unknown family header.
    #[must_use]
    pub fn decode(self, frame: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Bare => Some(frame.to_vec()),
            Self::DarwinUtun => {
                let header: [u8; 4] = frame.get(..4)?.try_into().ok()?;
                PacketFamily::from_darwin_af(u32::from_be_bytes(header))?;
                Some(frame[4..].to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet() -> Vec<u8> {
        // A minimal packet whose first nibble is 4 (IPv4).
        let mut p = vec![0x45u8];
        p.extend_from_slice(&[0u8; 19]);
        p
    }

    fn ipv6_packet() -> Vec<u8> {
        let mut p = vec![0x60u8];
        p.extend_from_slice(&[0u8; 39]);
        p
    }

    #[test]
    fn detects_ip_family_from_the_version_nibble() {
        assert_eq!(PacketFamily::detect(&ipv4_packet()), Some(PacketFamily::V4));
        assert_eq!(PacketFamily::detect(&ipv6_packet()), Some(PacketFamily::V6));
        assert_eq!(PacketFamily::detect(&[]), None);
        assert_eq!(PacketFamily::detect(&[0xF0]), None);
    }

    #[test]
    fn bare_framing_is_an_identity_round_trip() {
        let p = ipv4_packet();
        let framed = Framing::Bare.encode(&p).unwrap();
        assert_eq!(framed, p);
        assert_eq!(Framing::Bare.decode(&framed).unwrap(), p);
    }

    #[test]
    fn darwin_utun_framing_round_trips_both_families() {
        for p in [ipv4_packet(), ipv6_packet()] {
            let framed = Framing::DarwinUtun.encode(&p).unwrap();
            assert_eq!(framed.len(), p.len() + 4, "utun prepends a 4-byte header");
            assert_eq!(Framing::DarwinUtun.decode(&framed).unwrap(), p);
        }
    }

    #[test]
    fn darwin_encode_rejects_a_packet_with_no_ip_version() {
        assert_eq!(Framing::DarwinUtun.encode(&[0xF0, 0x00]), None);
    }

    #[test]
    fn darwin_decode_rejects_a_short_or_unknown_header() {
        assert_eq!(Framing::DarwinUtun.decode(&[0x00, 0x00]), None);
        // Family header 99 is not a recognized address family.
        let mut bad = 99u32.to_be_bytes().to_vec();
        bad.extend_from_slice(&ipv4_packet());
        assert_eq!(Framing::DarwinUtun.decode(&bad), None);
    }

    #[test]
    fn darwin_af_constants_round_trip() {
        for fam in [PacketFamily::V4, PacketFamily::V6] {
            assert_eq!(PacketFamily::from_darwin_af(fam.darwin_af()), Some(fam));
        }
    }

    #[test]
    fn darwin_utun_header_is_network_byte_order() {
        // The macOS utun kernel reads/writes the 4-byte family word with
        // ntohl/htonl, so the wire bytes are big-endian (AF_INET = 2 -> the value
        // lands in the LAST byte). A host-order header is rejected by the kernel,
        // which silently breaks the datapath. Pin the exact on-wire bytes so the
        // contract cannot regress to native order on a little-endian Mac.
        let v4 = Framing::DarwinUtun.encode(&ipv4_packet()).unwrap();
        assert_eq!(&v4[..4], &[0x00, 0x00, 0x00, 0x02], "AF_INET, big-endian");
        let v6 = Framing::DarwinUtun.encode(&ipv6_packet()).unwrap();
        assert_eq!(
            &v6[..4],
            &[0x00, 0x00, 0x00, 0x1e],
            "AF_INET6 (30), big-endian"
        );

        // The kernel delivers reads in the same big-endian framing.
        let mut framed = vec![0x00, 0x00, 0x00, 0x02];
        framed.extend_from_slice(&ipv4_packet());
        assert_eq!(Framing::DarwinUtun.decode(&framed).unwrap(), ipv4_packet());

        // A host-order (little-endian) header must NOT decode: it is exactly the
        // bug that stops packets flowing, so treat it as an unknown family.
        let mut host_order = vec![0x02, 0x00, 0x00, 0x00];
        host_order.extend_from_slice(&ipv4_packet());
        assert_eq!(Framing::DarwinUtun.decode(&host_order), None);
    }
}
