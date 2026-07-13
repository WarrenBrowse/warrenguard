//! No-log privacy invariant for the NAT-PMP server (source-level scan).
//!
//! The NAT-PMP server runs on the exit and answers requests coming from a
//! client's tunnel-inner address (10.66.x.x). That address is a per-session
//! correlation handle that maps back to a subscriber pubkey, so the no-log
//! discipline forbids logging it in cleartext. Mirrors the equivalent
//! privacy scanners in the other engine crates.
//!
//! The scan is line-level and skips comments: it only flags a tracing
//! Display/Debug interpolation (`= %src`, `dst = %...`) of a client address,
//! not the many legitimate non-logging uses of the `src: SocketAddr` value.

use std::path::Path;

/// Tracing interpolations of a client source / destination address. Each is a
/// `name = %value` / `name = ?value` form that only appears inside a tracing
/// macro, never in ordinary `dispatch(frame, src)`-style call code.
const FORBIDDEN: &[&str] = &[
    "= %src",
    "= ?src",
    "dst = %",
    "src = %",
    "= %addr",
    "addr = %",
    "remote_address()",
    "{peer_addr}",
    "{client_addr}",
];

fn collect_rs(dir: &Path, acc: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir src/") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs(&path, acc);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            acc.push(path);
        }
    }
}

#[test]
fn natpmp_server_does_not_log_client_addresses() {
    let mut files = Vec::new();
    collect_rs(Path::new("src"), &mut files);
    assert!(!files.is_empty(), "walkdir must find .rs files under src/");

    let mut violations = Vec::new();
    for path in files {
        let body = std::fs::read_to_string(&path).expect("read source file");
        for (i, line) in body.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for pat in FORBIDDEN {
                if line.contains(pat) {
                    violations.push(format!(
                        "{}:{}: forbidden {pat:?}\n      {}",
                        path.display(),
                        i + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "NAT-PMP server no-log violations (CLAUDE.md § 6: never log a client's \
         tunnel-inner source/destination address in cleartext):\n{}",
        violations.join("\n")
    );
}
