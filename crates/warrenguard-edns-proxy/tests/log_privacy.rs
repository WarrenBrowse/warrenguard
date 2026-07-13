//! No-log privacy invariants for the eDNS proxy (source-level scan).
//!
//! The eDNS proxy answers DNS for tunnelled clients, so it sees both the
//! client's connecting address and (potentially) the queried name. Both are
//! browsing-activity that the no-log contract forbids writing to a log: the
//! proxy logs errors by kind only, never the peer address (it uses `peer.ip()`
//! purely for rate limiting) and never a QNAME / question / answer. This test
//! anchors that at the source level so a future `tracing::*` site cannot
//! silently reintroduce a leak.
//!
//! See `warrenguard-server/tests/log_privacy.rs` for the rationale behind the
//! log-call-scoped (paren-balanced, `%` and `?` aware) approach. Note `%addr`
//! and `%error` are deliberately allowed: the proxy logs its own health-server
//! bind address and connection error *kinds*, neither of which is user data.

use std::path::Path;

/// Forbidden anywhere: interpolation syntaxes that only appear when a queried
/// name, an answer, or a peer address is being formatted into a log.
const FORBIDDEN_GLOBAL_SUBSTRINGS: &[&str] = &[
    // The queried name and its question/answer are the user's DNS activity,
    // whether the name appears as a format-string capture or a log value.
    "{qname",
    "{question",
    "{query_name",
    "{domain",
    "{answer",
    "{rdata",
    "= %domain",
    // Peer address format-string captures.
    "{remote_addr}",
    "{client_addr}",
    "{peer_addr}",
    "{remote_address",
    // Payload bytes.
    "{payload",
    "{datagram",
];

/// Forbidden only *inside* a tracing macro's argument list. Each has a
/// legitimate non-logging use elsewhere (`peer.ip()` feeds the rate limiter;
/// the DNS accessors would parse a query for resolution, not logging), so a
/// global ban would false-positive; inside a log they leak the client's real
/// address or the queried name regardless of the `%`/`?` sigil or whether the
/// name sits in the field or the value position.
const FORBIDDEN_IN_LOG_ARGS: &[&str] = &[
    "remote_address",
    "peer_addr",
    "peer_address",
    "qname",
    "query_name",
    ".name()",
    "queries(",
    "questions(",
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
                 (queried name / answer / peer address / payload)"
            ));
        }
    }

    for args in log_call_args(&code) {
        for token in FORBIDDEN_IN_LOG_ARGS {
            if args.contains(token) {
                out.push(format!(
                    "{rel}: tracing macro interpolates {token:?} (leaks the client's real \
                     address). Use `peer.ip()` for rate limiting only, never in a log.\n      {}",
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

/// Walks every `.rs` file under `src/` and fails if any leaks a queried name,
/// a DNS answer, a peer address, or a payload byte through a `tracing`
/// interpolation.
#[test]
fn no_edns_module_logs_query_name_or_peer_address() {
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
        "warrenguard-edns-proxy no-log violations: the resolver must never log a queried name, \
         a DNS answer, a client peer address, or a payload byte in cleartext:\n{}",
        violations.join("\n")
    );
}

// --- scanner self-tests: prove the guard is neither blind nor trigger-happy.

#[test]
fn scanner_flags_query_name_display() {
    let leaky = r#"tracing::debug!(qname = %msg.queries()[0].name(), "resolving");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_query_name_format_capture() {
    let leaky = r#"tracing::info!("resolving {qname}");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_flags_peer_address_in_a_log() {
    let leaky = r#"tracing::warn!(who = ?client.peer_addr(), "connection ended");"#;
    assert!(!violations_in("t.rs", leaky).is_empty());
}

#[test]
fn scanner_ignores_upstream_and_error_and_bind_addr() {
    // The exact shapes this crate uses must NOT be flagged: the configured
    // upstream resolver, a connection error *kind*, and the health bind addr.
    let benign = "tracing::warn!(upstream = %config.upstream, %error, \"upstream connect failed\");\n\
                  tracing::debug!(%error, \"connection ended with error\");\n\
                  tracing::info!(%addr, \"health server listening\");";
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "upstream / error-kind / health-bind logging must not be flagged"
    );
}

#[test]
fn scanner_ignores_peer_ip_used_for_rate_limiting() {
    // `peer.ip()` feeds the rate limiter outside any log and must not flag.
    let benign = "if let Some(limiter) = &self.limiter && !limiter.check(peer_ip) { return; }\n\
                  self.accept(client, peer.ip());";
    assert!(
        violations_in("t.rs", benign).is_empty(),
        "non-log peer.ip() (rate limiting) must not be flagged"
    );
}
