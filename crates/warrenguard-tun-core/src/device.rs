//! The TUN device seam and the framing adapter.
//!
//! A real kernel TUN device does packet-atomic I/O: each read returns exactly one
//! frame, each write submits exactly one frame. [`RawTunDevice`] models that, and
//! [`FramedTun`] layers the per-OS [`Framing`] on top so the
//! datapath above always speaks bare IP packets ([`TunIo`]).
//!
//! This is the safe, always-on half of the seam: the traits and the framing
//! adapter, exercised by tests over an in-memory mock. The actual per-OS device
//! open (`open_tun`) is the privileged half and lives in the
//! `warrenguard-tun-device` crate behind its `experimental-tun` feature, so a
//! userland (no-root) build never pulls it in.

use std::io;

use crate::frame::Framing;

/// Whole-frame, packet-atomic device I/O, as a kernel TUN fd provides.
pub trait RawTunDevice {
    /// Reads the next frame into `buf`, returning its length. `buf` must be at
    /// least MTU + the framing header.
    ///
    /// # Errors
    ///
    /// Propagates the underlying device read error.
    fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Writes one whole `frame` to the device.
    ///
    /// # Errors
    ///
    /// Propagates the underlying device write error.
    fn write_frame(&mut self, frame: &[u8]) -> io::Result<()>;
}

/// The datapath-facing seam: send and receive bare IP packets, framing handled
/// underneath.
pub trait TunIo {
    /// Receives the next bare IP packet from the device.
    ///
    /// # Errors
    ///
    /// A device read error, or [`io::ErrorKind::InvalidData`] if the frame could
    /// not be decoded (a malformed or unknown-family frame).
    fn recv_packet(&mut self) -> io::Result<Vec<u8>>;

    /// Sends one bare IP `packet` to the device.
    ///
    /// # Errors
    ///
    /// A device write error, or [`io::ErrorKind::InvalidData`] if the packet has
    /// no recognizable IP version (so it cannot be framed).
    fn send_packet(&mut self, packet: &[u8]) -> io::Result<()>;
}

/// Adapts a [`RawTunDevice`] to [`TunIo`] by applying the per-OS [`Framing`].
#[derive(Debug)]
pub struct FramedTun<D: RawTunDevice> {
    device: D,
    framing: Framing,
    read_buf: Vec<u8>,
}

impl<D: RawTunDevice> FramedTun<D> {
    /// Wraps `device` with `framing`, sizing the read buffer for `mtu` plus the
    /// 4-byte worst-case header.
    #[must_use]
    pub fn new(device: D, framing: Framing, mtu: u16) -> Self {
        Self {
            device,
            framing,
            read_buf: vec![0u8; mtu as usize + 4],
        }
    }

    /// Consumes the adapter, returning the wrapped device.
    #[must_use]
    pub fn into_inner(self) -> D {
        self.device
    }
}

impl<D: RawTunDevice> TunIo for FramedTun<D> {
    fn recv_packet(&mut self) -> io::Result<Vec<u8>> {
        let n = self.device.read_frame(&mut self.read_buf)?;
        self.framing
            .decode(&self.read_buf[..n])
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "undecodable tun frame"))
    }

    fn send_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let frame = self
            .framing
            .encode(packet)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unframable ip packet"))?;
        self.device.write_frame(&frame)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::PacketFamily;
    use std::collections::VecDeque;

    /// An in-memory packet-atomic device: reads pop queued inbound frames, writes
    /// push onto an outbound queue. Models the TUN fd's framing without a kernel.
    #[derive(Default)]
    struct MockDevice {
        inbound: VecDeque<Vec<u8>>,
        outbound: Vec<Vec<u8>>,
    }

    impl RawTunDevice for MockDevice {
        fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let frame = self
                .inbound
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "no frame"))?;
            buf[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }

        fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
            self.outbound.push(frame.to_vec());
            Ok(())
        }
    }

    fn ipv4_packet() -> Vec<u8> {
        let mut p = vec![0x45u8];
        p.extend_from_slice(&[7u8; 19]);
        p
    }

    #[test]
    fn framed_tun_round_trips_a_packet_over_bare_framing() {
        let mut dev = MockDevice::default();
        dev.inbound.push_back(ipv4_packet());
        let mut tun = FramedTun::new(dev, Framing::Bare, 1280);
        assert_eq!(tun.recv_packet().unwrap(), ipv4_packet());
        tun.send_packet(&ipv4_packet()).unwrap();
        assert_eq!(tun.into_inner().outbound, vec![ipv4_packet()]);
    }

    #[test]
    fn framed_tun_applies_and_strips_the_utun_header() {
        let mut dev = MockDevice::default();
        // An inbound utun frame: 4-byte AF header (network byte order) + packet.
        let mut inbound = PacketFamily::V4.darwin_af().to_be_bytes().to_vec();
        inbound.extend_from_slice(&ipv4_packet());
        dev.inbound.push_back(inbound);

        let mut tun = FramedTun::new(dev, Framing::DarwinUtun, 1280);
        // recv strips the header.
        assert_eq!(tun.recv_packet().unwrap(), ipv4_packet());
        // send prepends it.
        tun.send_packet(&ipv4_packet()).unwrap();
        let out = tun.into_inner().outbound;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), ipv4_packet().len() + 4);
        assert_eq!(&out[0][4..], ipv4_packet().as_slice());
    }

    #[test]
    fn framed_tun_rejects_an_unframable_packet() {
        let dev = MockDevice::default();
        let mut tun = FramedTun::new(dev, Framing::DarwinUtun, 1280);
        let err = tun.send_packet(&[0xF0, 0x00]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn framed_tun_rejects_an_undecodable_inbound_frame() {
        let mut dev = MockDevice::default();
        dev.inbound.push_back(vec![0x00, 0x00]); // too short for a utun header
        let mut tun = FramedTun::new(dev, Framing::DarwinUtun, 1280);
        let err = tun.recv_packet().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
