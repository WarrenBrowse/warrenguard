//! JA4 fingerprint computation from a parsed ClientHello (FoxIO JA4+ spec).
//!
//! JA4 has three parts joined by `_`:
//! - `a`: `q`/`t` + TLS version + `d`/`i` (SNI) + 2-digit cipher count +
//!   2-digit extension count + first ALPN's first/last char.
//! - `b`: first 12 hex of SHA-256 over the GREASE-filtered cipher suites,
//!   sorted, 4-hex, comma-joined.
//! - `c`: first 12 hex of SHA-256 over the GREASE-filtered extensions (SNI and
//!   ALPN removed), sorted and 4-hex-comma-joined, then `_` and the signature
//!   algorithms in wire order.
//!
//! The absolute agreement of the truncated hashes with FoxIO's `ja4` reference
//! tool is cross-checked by running that tool against a captured Initial;
//! the tests here pin the structure and guard against drift.

use sha2::{Digest, Sha256};

use crate::clienthello::ClientHelloInfo;

/// True for the 16 GREASE code points (RFC 8701): both bytes equal and the low
/// nibble is `0xa`.
pub(crate) fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = v as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

fn version_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

/// First 12 hex chars (6 bytes) of the SHA-256 of `input`.
fn sha12(input: &str) -> String {
    hex::encode(&Sha256::digest(input.as_bytes())[..6])
}

fn hex_csv(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// First and last character of the first ALPN protocol, or `00` if absent.
fn alpn_chars(alpn: &[Vec<u8>]) -> String {
    match alpn.first() {
        Some(v) if !v.is_empty() => {
            format!("{}{}", v[0] as char, v[v.len() - 1] as char)
        }
        _ => "00".to_string(),
    }
}

/// Computes the JA4 QUIC-client fingerprint string from a parsed ClientHello.
#[must_use]
pub fn ja4(ch: &ClientHelloInfo) -> String {
    let ciphers: Vec<u16> = ch
        .cipher_suites
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let exts_all: Vec<u16> = ch
        .extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();

    // Part a: `q` = QUIC (this crate only fingerprints QUIC Initials).
    let ja4_a = format!(
        "q{}{}{:02}{:02}{}",
        version_str(ch.tls_version),
        if ch.has_sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        exts_all.len().min(99),
        alpn_chars(&ch.alpn),
    );

    // Part b: sorted ciphers.
    let mut cs = ciphers;
    cs.sort_unstable();
    let ja4_b = sha12(&hex_csv(&cs));

    // Part c: sorted extensions minus SNI (0x0000) and ALPN (0x0010), then the
    // signature algorithms in wire order.
    let mut exts: Vec<u16> = exts_all
        .into_iter()
        .filter(|&v| v != 0x0000 && v != 0x0010)
        .collect();
    exts.sort_unstable();
    // Signature algorithms in wire order, GREASE removed (the spec ignores
    // GREASE everywhere it appears).
    let sig_algs: Vec<u16> = ch
        .sig_algs
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let ja4_c_input = if sig_algs.is_empty() {
        hex_csv(&exts)
    } else {
        format!("{}_{}", hex_csv(&exts), hex_csv(&sig_algs))
    };
    let ja4_c = sha12(&ja4_c_input);

    format!("{ja4_a}_{ja4_b}_{ja4_c}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientHelloInfo {
        ClientHelloInfo {
            tls_version: 0x0304,
            has_sni: true,
            // Two real ciphers plus a GREASE value that must be dropped.
            cipher_suites: vec![0x0a0a, 0x1301, 0x1302],
            // SNI, ALPN, sig_algs, supported_versions, plus GREASE.
            extensions: vec![0x0a0a, 0x0000, 0x0010, 0x000d, 0x002b],
            alpn: vec![b"h3".to_vec()],
            sig_algs: vec![0x0403, 0x0804],
        }
    }

    #[test]
    fn is_grease_matches_rfc8701_points() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a0b));
        assert!(!is_grease(0x0b0b));
    }

    #[test]
    fn ja4_a_is_hand_verifiable() {
        // q + 13 (TLS1.3) + d (SNI) + 02 ciphers (GREASE dropped) + 04
        // extensions (GREASE dropped, SNI/ALPN still counted) + h3 ALPN.
        assert!(
            ja4(&sample()).starts_with("q13d0204h3_"),
            "got {}",
            ja4(&sample())
        );
    }

    #[test]
    fn ja4_is_deterministic_and_well_shaped() {
        let a = ja4(&sample());
        assert_eq!(a, ja4(&sample()), "must be deterministic");
        // q13d0204h3 (10) + _ + 12 + _ + 12 = 36.
        assert_eq!(a.len(), 36, "unexpected JA4 length: {a}");
        assert_eq!(a.matches('_').count(), 2);
    }

    #[test]
    fn ja4_full_value_is_pinned() {
        // Regression guard: this exact string is produced by the spec-following
        // computation above for `sample()`. A change here means the ClientHello
        // shape (or the algorithm) drifted.
        assert_eq!(ja4(&sample()), "q13d0204h3_62ed6f6ca7ad_ef5f37ab036a");
    }

    #[test]
    fn no_sni_yields_i_and_no_alpn_yields_00() {
        let mut ch = sample();
        ch.has_sni = false;
        ch.extensions.retain(|&e| e != 0x0000);
        ch.alpn.clear();
        // q + 13 + i (no SNI) + 02 ciphers + 03 extensions + 00 (no ALPN).
        assert!(ja4(&ch).starts_with("q13i020300"), "got {}", ja4(&ch));
    }

    #[test]
    fn grease_signature_algorithms_are_ignored() {
        // A GREASE value inside signature_algorithms must not change the JA4.
        let a = sample();
        let mut b = sample();
        b.sig_algs = vec![0x0403, 0x0a0a, 0x0804]; // GREASE 0x0a0a in the middle
        assert_eq!(
            ja4(&a),
            ja4(&b),
            "GREASE signature algorithms must be dropped"
        );
    }
}
