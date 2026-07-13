//! No-log privacy invariants for the TUN<->datagram pump (source-level scan).
//!
//! The pump is the hot path that moves every user packet between the OS TUN
//! device and the QUIC datagram plane. It must be muted: it never logs a
//! decapsulated destination address, a full peer pubkey, a per-session
//! correlation handle, or a payload byte. The only identifiers it may emit are
//! non-correlating diagnostics (a `conn[idx]` label, a byte count, an error
//! message). This test anchors that at the source level so a future
//! `tracing::*` site cannot silently reintroduce a leak.
//!
//! See `warrenguard-server/tests/log_privacy.rs` for the rationale behind the
//! log-call-scoped (paren-balanced, `%` and `?` aware) approach.

use std::path::Path;

/// Forbidden anywhere: interpolation syntaxes that only appear when something
/// sensitive is being formatted into a log / format string.
const FORBIDDEN_GLOBAL_SUBSTRINGS: &[&str] = &[
    "{remote_addr}",
    "{client_addr}",
    "{peer_addr}",
    "{remote_address",
    // A decapsulated packet's destination is the user's browsing activity.
    "{dst_addr",
    "{dest_addr",
    "{dst_ip",
    "= %dst",
    "= %dest",
    // Raw Display of a full pubkey / key hex.
    "= %key",
    "= %pubkey",
    "= %pubkey_hex",
    "= %hex",
    "= %client_id",
    "{pubkey}",
    "{pubkey_hex",
    "{verifying_key",
    "{node_id",
    // Per-session correlation handles / HPKE material / payload bytes.
    "{encapsulated_key",
    "{exit_id:?}",
    "{ciphertext",
    "{aead_tag",
    "{payload",
    "{datagram",
    "{nonce",
];

/// Forbidden only *inside* a tracing macro's argument list. These identifiers
/// have legitimate non-logging uses elsewhere (reading a packet's destination
/// to route it, building a state-file key), so a global ban would
/// false-positive; inside a log they leak the user's address, the site they
/// are browsing, or their full identity regardless of the `%`/`?` sigil or
/// whether the value sits in the field or the value position.
const FORBIDDEN_IN_LOG_ARGS: &[&str] = &[
    "remote_address",
    "peer_addr",
    "peer_address",
    "dest_addr",
    "dst_addr",
    "dest_ip",
    "dst_ip",
    "destination",
    "to_hex(",
];

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn log_call_args(body: &str) -> Vec<String> {
    const MACROS: &[&str] = &["trace!", "debug!", "info!", "warn!", "error!"];
    let chars: Vec<char> = body.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let mut advanced = false;
        for m in MACROS {
            let mlen = m.chars().count();
            if i + mlen > n || chars[i..i + mlen].iter().collect::<String>() != *m {
                continue;
            }
            if i > 0 && is_ident_char(chars[i - 1]) {
                continue;
            }
            let mut j = i + mlen;
            while j < n && chars[j].is_whitespace() {
                j += 1;
            }
            if j >= n || chars[j] != '(' {
                continue;
            }
            let start = j + 1;
            let mut depth = 0usize;
            let mut k = j;
            let mut in_str = false;
            let mut escaped = false;
            while k < n {
                let c = chars[k];
                if in_str {
                    if escaped {
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                } else if c == '"' {
                    in_str = true;
                } else if c == '(' {
                    depth += 1;
                } else if c == ')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                k += 1;
            }
            out.push(chars[start..k].iter().collect());
            i = k + 1;
            advanced = true;
            break;
        }
        if !advanced {
            i += 1;
        }
    }
    out
}

fn strip_line_comments(body: &str) -> String {
    body.lines()
        .map(|l| match l.find("//") {
            Some(idx) => &l[..idx],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn violations_in(rel: &str, body: &str) -> Vec<String> {
    let code = strip_line_comments(body);
    let mut out = Vec::new();

    for substr in FORBIDDEN_GLOBAL_SUBSTRINGS {
        if code.contains(substr) {
            out.push(format!(
                "{rel}: forbidden log-leakage substring {substr:?} \
                 (client IP / destination / full pubkey / payload)"
            ));
        }
    }

    for args in log_call_args(&code) {
        for token in FORBIDDEN_IN_LOG_ARGS {
            if args.contains(token) {
                out.push(format!(
                    "{rel}: tracing macro interpolates {token:?} (leaks the user's real \
                     address or full identity).\n      {}",
                    args.trim()
                ));
            }
        }
    }
    out
}

fn collect_rs(dir: &Path, prefix: &str, acc: &mut Vec<(String, std::path::PathBuf)>) {
    for entry in std::fs::read_dir(dir).expect("read_dir src/") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if path.is_dir() {
            collect_rs(&path, &rel, acc);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            acc.push((rel, path));
        }
    }
}

/// Walks every `.rs` file under `src/` and fails if any leaks a client IP, a
/// decapsulated destination, a full pubkey, or a payload byte through a
/// `tracing` interpolation.
#[test]
fn no_pump_module_logs_client_address_or_payload() {
    let mut files = Vec::new();
    collect_rs(Path::new("src"), "", &mut files);
    assert!(
        !files.is_empty(),
        "walkdir must find at least one .rs file under src/"
    );

    let mut violations = Vec::new();
    for (rel, path) in files {
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        violations.extend(violations_in(&rel, &body));
    }

    assert!(
        violations.is_empty(),
        "warrenguard-pump no-log violations: the packet pump must never log a user address, \
         a decapsulated destination, a full pubkey, or a payload byte in cleartext:\n{}",
        violations.join("\n")
    );
}

// --- scanner self-tests: prove the guard is neither blind nor trigger-happy.

#[test]
fn scanner_flags_display_interpolation_of_destination() {
    let leaky = r#"tracing::trace!(dst = %parsed.dest_addr(), "egress");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_payload_format_capture() {
    let leaky = r#"tracing::trace!("pumped {payload:?}");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_full_pubkey_to_hex_inside_a_log() {
    let leaky = r#"tracing::debug!(who = %client_id.to_hex());"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_ignores_conn_label_and_byte_count() {
    // The exact shapes this crate uses must NOT be flagged.
    let benign = "tracing::trace!(conn = %conn_label_for_tun, \"tun send error\");\n\
                  tracing::warn!(bytes = dg.len(), \"dropped packet with spoofed source IP\");";
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "non-correlating diagnostics (conn[idx] label, byte count) must not be flagged"
    );
}

#[test]
fn scanner_ignores_error_display_in_a_log() {
    let benign = r#"tracing::trace!(error = %e, "send_datagram dropped (too large race)");"#;
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "logging an error message Display must not be flagged"
    );
}
