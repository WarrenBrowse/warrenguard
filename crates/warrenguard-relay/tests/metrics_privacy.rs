//! Privacy invariants on what the relay is allowed to log.
//!
//! CLAUDE.md § 6 forbids the relay from logging client IPs, full peer
//! pubkeys, or HPKE ciphertext bytes. These tests anchor the rule at
//! the source level: any new `tracing::*` site that interpolates a
//! `SocketAddr`, a `WarrenPubkey`, an `ExitId` debug form, or a
//! ciphertext slice has to either remove the offending interpolation
//! or whitelist the file explicitly here (and justify the change in
//! the PR description).

const FORBIDDEN_LITERAL_SUBSTRINGS: &[&str] = &[
    // Direct interpolations that risk leaking client IP / port pairs.
    "{remote_addr}",
    "{client_addr}",
    "{peer_addr}",
    "{remote_address",
    "remote_address()",
    // Common naming for full pubkey logging.
    "{pubkey",
    "{verifying_key",
    // ExitId Debug form has no operational value in logs and adds a
    // correlation surface.
    "{exit_id:?}",
];

fn read_module(path: &str) -> String {
    std::fs::read_to_string(format!("src/{path}"))
        .unwrap_or_else(|e| panic!("read src/{path}: {e}"))
}

fn assert_no_forbidden_in(file: &str) {
    let body = read_module(file);
    for substr in FORBIDDEN_LITERAL_SUBSTRINGS {
        assert!(
            !body.contains(substr),
            "source file `{file}` contains forbidden log-leakage substring {substr:?}. \
             CLAUDE.md § 6 bans logging client IPs, full pubkeys, and ExitId Debug forms. \
             Either drop the interpolation or rewrite the log line."
        );
    }
}

#[test]
fn server_module_does_not_leak_client_identifiers() {
    assert_no_forbidden_in("server.rs");
}

#[test]
fn session_module_does_not_leak_client_identifiers() {
    assert_no_forbidden_in("session.rs");
}

#[test]
fn exit_pool_module_does_not_leak_peer_identifiers() {
    assert_no_forbidden_in("exit_pool.rs");
}

#[test]
fn forward_module_does_not_leak_payload_bytes() {
    let body = read_module("forward.rs");
    // The forwarder must never print bytes it forwards.
    for forbidden in ["{bytes", "{datagram", "{payload"] {
        assert!(
            !body.contains(forbidden),
            "src/forward.rs contains payload-leakage substring {forbidden:?}. \
             CLAUDE.md § 6 forbids logging HPKE ciphertext."
        );
    }
}
