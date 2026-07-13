//! No-log privacy invariants for the exit data-plane (source-level scan).
//!
//! This crate hosts the parts of the engine a deployer points at the open
//! Internet: the accept loop (`exit/accept.rs`, `exit/mod.rs`), the in-band
//! handshake, the TUN<->datagram dispatch (`tun_dispatch.rs`), the per-session
//! reconnect/eviction state (`exit/session.rs`) and the on-disk state
//! persistence (`exit_state.rs`). It is the spine of Warren's public no-log
//! claim: the egress path never writes a user's real source IP, a full peer
//! pubkey, a per-session correlation handle, or any payload byte to a log.
//!
//! Since the data-plane was carved out of the product backend into this engine,
//! that claim can only be certified here. This test anchors it at the source
//! level so a future `tracing::*` site cannot silently reintroduce a leak.
//!
//! ## Why a log-call-scoped scanner
//!
//! The crate legitimately *uses* `remote_address()` outside any log: for
//! stateless-retry validation (`remote_address_validated()`) and per-IP
//! handshake rate limiting. A line-level `%`-match would either miss the Debug
//! (`?`) sigil or false-positive on those non-logging reads. So the forbidden
//! identifiers are checked against the paren-balanced argument span of each
//! `tracing::*!(...)` invocation, which:
//!
//! 1. catches Debug (`?remote_address()`) interpolation, not just Display (`%`)
//!    - both leak the IP just as fully;
//! 2. survives multi-line macro calls and never trips on a `?` try-operator
//!    that merely shares a line with a non-logging `remote_address()` read.
//!
//! Unambiguous leak *syntax* (format-string captures, raw Display of a hex
//! pubkey, payload/ciphertext field names) is matched globally, where it
//! carries no false positives.
//!
//! The full peer pubkey is safe under Debug because [`WarrenPubkey`]'s `Debug`
//! is truncated by construction; the leak vector is Display (`%pubkey`) or
//! `pubkey.to_hex()` inside a log. Both are caught below.

use std::path::Path;

/// Forbidden anywhere: interpolation syntaxes that only appear when something
/// sensitive is being formatted into a log / format string.
const FORBIDDEN_GLOBAL_SUBSTRINGS: &[&str] = &[
    // Format-string captures of the user's outbound address.
    "{remote_addr}",
    "{client_addr}",
    "{peer_addr}",
    "{remote_address",
    // Raw Display of a full pubkey / key hex. The sanctioned form for an
    // identifier in a log is `warrenguard_config::log_prefix(...)` (truncated)
    // or the already-truncated `WarrenPubkey` Debug.
    "= %key",
    "= %pubkey",
    "= %pubkey_hex",
    "= %hex",
    "= %node_key",
    "= %node_id",
    "= %client_id",
    "= %remote_id",
    "= %exit_id",
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
/// have legitimate non-logging uses in this crate (rate limiting, retry
/// validation, on-disk state-file keys), so a global ban would false-positive;
/// inside a log call they leak the user's real source address or full pubkey
/// regardless of the `%`/`?` sigil used.
const FORBIDDEN_IN_LOG_ARGS: &[&str] = &[
    "remote_address",
    "peer_addr",
    "peer_address",
    // `WarrenPubkey::to_hex()` is the full 64-char identity; legitimate only as
    // a state-file map key, never in a log. Debug (`?pk`) is truncated and OK.
    "to_hex(",
];

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Extract the argument text of every tracing-style macro invocation
/// (`trace!`/`debug!`/`info!`/`warn!`/`error!`, with or without a `tracing::`
/// path prefix), paren-balanced and string-literal-aware.
///
/// String awareness matters because log messages contain parentheses
/// (`"handshake OK (retry)"`); a naive depth counter would close the span
/// early and hide a trailing field. Raw strings (`r"..."`) are not handled -
/// they do not appear in this crate's log sites and would only ever widen a
/// span, never hide a token.
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
            // Reject a match embedded in a longer identifier (`reinfo!`).
            if i > 0 && is_ident_char(chars[i - 1]) {
                continue;
            }
            // Macro name must be followed (after spaces) by `(`.
            let mut j = i + mlen;
            while j < n && chars[j].is_whitespace() {
                j += 1;
            }
            if j >= n || chars[j] != '(' {
                continue;
            }
            // Capture the paren-balanced span, skipping string literals.
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

/// Strip `//`-comment tails so a documented pattern in a comment is not
/// mistaken for a real leak. Crude (ignores `//` inside strings) but the
/// global patterns it guards never legitimately appear in this crate's
/// string literals.
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
                 (client IP / full pubkey / correlation handle / payload)"
            ));
        }
    }

    for args in log_call_args(&code) {
        for token in FORBIDDEN_IN_LOG_ARGS {
            if args.contains(token) {
                out.push(format!(
                    "{rel}: tracing macro interpolates {token:?} (leaks the user's real \
                     source address or full identity). Identify the session by truncated \
                     pubkey (`?pk` / `log_prefix`) and internal tunnel IP instead.\n      {}",
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

/// Walks every `.rs` file under `src/` (so a newly added module cannot slip
/// past the invariant) and fails if any leaks a client IP / full pubkey /
/// correlation handle / payload through a `tracing` interpolation.
#[test]
fn no_exit_dataplane_module_logs_client_ip_or_full_identity() {
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
        "warrenguard-server no-log violations: the exit data-plane must never log a user \
         source IP, a full pubkey, a correlation handle, or a payload byte in cleartext. \
         Drop the source-IP field, wrap pubkey hex in `warrenguard_config::log_prefix(...)`, \
         or use the truncated `WarrenPubkey` Debug:\n{}",
        violations.join("\n")
    );
}

// --- scanner self-tests: prove the guard is neither blind nor trigger-happy,
// --- so it cannot silently rot into a no-op.

#[test]
fn scanner_flags_display_interpolation_of_client_ip() {
    let leaky = r#"tracing::info!(remote = %c.0.remote_address(), "client handshake OK");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_debug_interpolation_of_client_ip() {
    // The gap a `%`-only line scan misses: Debug formatting a SocketAddr leaks
    // the IP just as fully.
    let leaky = r#"tracing::debug!(peer = ?conn.remote_address());"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_full_pubkey_to_hex_inside_a_log() {
    // Debug of WarrenPubkey is truncated and safe; Display / to_hex is the full
    // 64-char identity and must never be logged.
    let leaky = r#"tracing::info!(pk = %client_id.to_hex(), "session");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_format_string_capture_of_payload() {
    let leaky = r#"tracing::trace!("forwarded {payload:?} to upstream");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_ignores_non_log_remote_address_uses() {
    // The exact shapes this crate uses must NOT be flagged.
    let benign = "let remote_ip = incoming.remote_address().ip();\n\
                  if !incoming.remote_address_validated() { retry(); }";
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "non-log remote_address() reads must not be flagged"
    );
}

#[test]
fn scanner_ignores_to_hex_used_as_state_file_key() {
    // Building the on-disk state-file map key from the pubkey hex is not a log.
    let benign = r#"let json_key = format!("{}:{}", pk.to_hex(), device_id_hex);"#;
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "non-log to_hex() (state-file key) must not be flagged"
    );
}

#[test]
fn scanner_ignores_try_operator_sharing_a_line_with_remote_address() {
    // A `?` try-operator on the same line as a non-logging remote_address()
    // read must not be mistaken for a Debug interpolation.
    let benign = "let s = sessions.get(incoming.remote_address().ip())?;";
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "try-operator `?` must not be read as a log Debug sigil"
    );
}

#[test]
fn scanner_ignores_truncated_pubkey_debug_in_a_log() {
    // The sanctioned form: WarrenPubkey Debug is truncated, so `?` of it is OK.
    let benign = r#"tracing::info!(client = ?key.0, "session evicted");"#;
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "truncated WarrenPubkey Debug is the sanctioned identifier form"
    );
}

#[test]
fn scanner_handles_parens_in_log_message_strings() {
    // A `)` inside the message string must not close the span early and hide a
    // trailing forbidden field.
    let leaky = r#"info!(msg = "ok (retry)", who = %c.remote_address());"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}
