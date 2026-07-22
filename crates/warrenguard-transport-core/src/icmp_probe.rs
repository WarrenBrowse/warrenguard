//! In-tunnel ICMPv4 echo probes for path-health measurement.
//!
//! The path-health prober sends paired echo requests (one minimum-size,
//! one at the live inner-packet budget) from the session's assigned
//! tunnel IP to the tunnel gateway. The exit-side kernel answers echoes
//! addressed to the gateway natively, so the reply exercises the FULL
//! downlink datapath at the probed size with no exit-side code. The
//! probe id is random per session; the downlink pump intercepts replies
//! carrying it and never writes them to the TUN.
//!
//! Privacy: the payload is all-zero, the sizes are two fixed classes,
//! and both endpoints are tunnel-internal addresses, so a probe carries
//! no user data and no per-user distinguisher beyond the session it
//! already rides in.

use std::net::Ipv4Addr;

use crate::inner_mtu::internet_checksum;

/// IPv4 header (no options) + ICMP echo header.
const IPV4_MIN_HEADER: usize = 20;
const ICMP_ECHO_HEADER: usize = 8;

/// Smallest well-formed probe: headers plus an empty payload would be
/// legal ICMP, but a handful of payload bytes keeps the packet visually
/// ordinary (the classic `ping` default is 56).
pub const MIN_PROBE_LEN: usize = IPV4_MIN_HEADER + ICMP_ECHO_HEADER;

/// Builds an ICMPv4 echo request as a full IP packet of exactly
/// `total_len` bytes (zero-filled payload), or `None` when `total_len`
/// cannot hold the headers or exceeds an IPv4 total length.
#[must_use]
pub fn build_echo_request(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    seq: u16,
    total_len: usize,
) -> Option<Vec<u8>> {
    if total_len < MIN_PROBE_LEN || total_len > usize::from(u16::MAX) {
        return None;
    }
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let ip_ck = internet_checksum(0, &pkt[..IPV4_MIN_HEADER]);
    pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());
    let icmp = IPV4_MIN_HEADER;
    pkt[icmp] = 8;
    pkt[icmp + 4..icmp + 6].copy_from_slice(&id.to_be_bytes());
    pkt[icmp + 6..icmp + 8].copy_from_slice(&seq.to_be_bytes());
    let icmp_ck = internet_checksum(0, &pkt[icmp..]);
    pkt[icmp + 2..icmp + 4].copy_from_slice(&icmp_ck.to_be_bytes());
    Some(pkt)
}

/// Parses `pkt` as an ICMPv4 echo REPLY carrying probe `id`; returns
/// `(seq, total_len)` on a match. Anything else (other protocol, echo
/// request, foreign id, truncated packet) yields `None`, so the caller
/// can use this as the intercept predicate on the hot downlink path.
#[must_use]
pub fn parse_echo_reply(pkt: &[u8], id: u16) -> Option<(u16, usize)> {
    if pkt.len() < MIN_PROBE_LEN || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER || pkt.len() < ihl + ICMP_ECHO_HEADER || pkt[9] != 1 {
        return None;
    }
    // Echo reply, code 0, our probe id.
    if pkt[ihl] != 0 || pkt[ihl + 1] != 0 {
        return None;
    }
    if u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) != id {
        return None;
    }
    let seq = u16::from_be_bytes([pkt[ihl + 6], pkt[ihl + 7]]);
    Some((seq, pkt.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 177);
    const GW: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

    /// Flips an echo request into the reply the gateway kernel would
    /// send back: type 0, swapped addresses, checksums recomputed.
    fn reply_for(req: &[u8]) -> Vec<u8> {
        let mut r = req.to_vec();
        // Swap src/dst.
        let (src, dst): ([u8; 4], [u8; 4]) = (
            r[12..16].try_into().expect("ipv4 src"),
            r[16..20].try_into().expect("ipv4 dst"),
        );
        r[12..16].copy_from_slice(&dst);
        r[16..20].copy_from_slice(&src);
        // Echo reply type + fresh ICMP checksum.
        r[20] = 0;
        r[22] = 0;
        r[23] = 0;
        let ck = {
            let mut sum = 0u32;
            for w in r[20..].chunks(2) {
                let hi = w[0];
                let lo = if w.len() == 2 { w[1] } else { 0 };
                sum += u32::from(u16::from_be_bytes([hi, lo]));
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !(sum as u16)
        };
        r[22..24].copy_from_slice(&ck.to_be_bytes());
        r
    }

    #[test]
    fn build_produces_wellformed_request_of_exact_size() {
        for total in [MIN_PROBE_LEN, 84, 576, 1306] {
            let pkt = build_echo_request(SRC, GW, 0xBEEF, 7, total).expect("builds");
            assert_eq!(pkt.len(), total, "exact requested size");
            assert_eq!(pkt[0], 0x45, "ipv4, no options");
            assert_eq!(pkt[9], 1, "protocol icmp");
            assert_eq!(
                u16::from_be_bytes([pkt[2], pkt[3]]),
                u16::try_from(total).expect("fits"),
                "ip total length"
            );
            assert_eq!(&pkt[12..16], &SRC.octets(), "src is assigned ip");
            assert_eq!(&pkt[16..20], &GW.octets(), "dst is gateway");
            assert_eq!(pkt[20], 8, "echo request");
            assert_eq!(pkt[21], 0, "code 0");
            assert_eq!(u16::from_be_bytes([pkt[24], pkt[25]]), 0xBEEF, "id");
            assert_eq!(u16::from_be_bytes([pkt[26], pkt[27]]), 7, "seq");
            // Both checksums verify (sum-to-zero property).
            assert_eq!(internet_checksum(0, &pkt[..20]), 0, "ip checksum");
            assert_eq!(internet_checksum(0, &pkt[20..]), 0, "icmp checksum");
        }
    }

    #[test]
    fn build_rejects_undersized_and_oversized() {
        assert!(build_echo_request(SRC, GW, 1, 1, MIN_PROBE_LEN - 1).is_none());
        assert!(build_echo_request(SRC, GW, 1, 1, usize::from(u16::MAX) + 1).is_none());
    }

    #[test]
    fn reply_roundtrip_yields_seq_and_len() {
        let req = build_echo_request(SRC, GW, 0xA55A, 42, 1306).expect("builds");
        let reply = reply_for(&req);
        assert_eq!(parse_echo_reply(&reply, 0xA55A), Some((42, 1306)));
    }

    #[test]
    fn parse_rejects_foreign_id_request_type_and_other_protocols() {
        let req = build_echo_request(SRC, GW, 0xA55A, 42, 84).expect("builds");
        let reply = reply_for(&req);
        assert_eq!(parse_echo_reply(&reply, 0x0BAD), None, "foreign id");
        assert_eq!(parse_echo_reply(&req, 0xA55A), None, "request, not reply");
        let mut tcp = reply.clone();
        tcp[9] = 6;
        assert_eq!(parse_echo_reply(&tcp, 0xA55A), None, "non-icmp");
        assert_eq!(parse_echo_reply(&reply[..24], 0xA55A), None, "truncated");
        let mut v6ish = reply;
        v6ish[0] = 0x60;
        assert_eq!(parse_echo_reply(&v6ish, 0xA55A), None, "not ipv4");
    }
}
