//! No-log privacy invariants on the multi-hop session, supervisor and
//! supervised pump (moved into this crate when the client control
//! plane was delegated to the engine). Every `tracing::*` call site in these
//! modules must avoid interpolating the user's outbound IP/port, a full pubkey,
//! the destination exit_id Debug form, an HPKE encapsulated key, any
//! ciphertext/payload bytes, or a per-session tunnel address (inline or as a
//! structured field; shared no-log secrets discipline).
//!
//! These run at the source level: introducing a new `{remote_addr}` or
//! `{exit_id:?}` interpolation - or an `assigned = %spec.assigned` field -
//! fails this test before the binary ships.

const FORBIDDEN_LITERAL_SUBSTRINGS: &[&str] = &[
    "{remote_addr}",
    "{client_addr}",
    "{peer_addr}",
    "remote_address()",
    "{pubkey",
    "{verifying_key",
    "{exit_id:?}",
    "{encapsulated_key",
    "{bind_addr",
    "{relay_addr",
    "{relay_endpoint",
    "{client_signing",
    "{signing_key",
    "bind_local_ip = %",
    "local_addr = ?",
];

const FORBIDDEN_PAYLOAD_SUBSTRINGS: &[&str] = &[
    "{bytes",
    "{datagram",
    "{payload",
    "{ciphertext",
    "{aead_tag",
];

// Structured tracing FIELDS that name a per-session tunnel address. Those
// addresses are correlation handles across log lines (the client's assigned
// IPv4 is a per-session allocation, not a public/shared identifier), so no
// `tracing::*` event may carry one - on either address family, on the
// assigning side as well as on the release side. `prefix_len`, `dual_stack`,
// `error` and the event message carry all the operational signal.
//
// Two entries are quoted with their interpolation sigil because the bare
// `name = ` form collides with ordinary Rust code in the scanned modules (see
// the per-entry comments): the sigil is what makes a substring a tracing
// field rather than an assignment.
const FORBIDDEN_STRUCTURED_FIELDS: &[&str] = &[
    "assigned = ",
    "assigned_v4 = ",
    // `spec.assigned_v6 = Some(..)` appears in `supervised_pump.rs`'s own
    // `live_pump_tests` module, so the bare form would flag a test assignment.
    "assigned_v6 = %",
    "assigned_v6 = ?",
    "gateway = ",
    "gateway_v4 = ",
    "gateway_v6 = ",
    // `let old = std::mem::replace(..)` in `src/multihop.rs` is not a log
    // field, so the bare form would flag it.
    "old = %",
    "old = ?",
    "bootstrap = ",
    "local_addr = ",
    "src_addr = ",
    "tunnel_ip = ",
    "internal_ip = ",
];

// The modules that carry the client-facing multi-hop control plane. Each must
// stay leak-free; a walkdir over all of src/ would false-positive on unrelated
// engine modules with their own logging conventions, so the surface is explicit.
const SCANNED_MODULES: &[&str] = &[
    "supervisor.rs",
    "supervised_pump.rs",
    "multi_hop_pump.rs",
    "multihop.rs",
    "migration_watchdog.rs",
];

fn read_module(file: &str) -> String {
    std::fs::read_to_string(format!("src/{file}"))
        .unwrap_or_else(|e| panic!("read src/{file}: {e}"))
}

#[test]
fn multi_hop_modules_do_not_leak_user_identifiers_or_payload() {
    for file in SCANNED_MODULES {
        let body = read_module(file);
        for substr in FORBIDDEN_LITERAL_SUBSTRINGS
            .iter()
            .chain(FORBIDDEN_PAYLOAD_SUBSTRINGS)
            .chain(FORBIDDEN_STRUCTURED_FIELDS)
        {
            assert!(
                !body.contains(substr),
                "source file `{file}` contains forbidden log-leakage substring {substr:?}. \
                 The no-log rule bans logging client IPs, full pubkeys, ExitId Debug forms, \
                 HPKE encapsulated keys, or ciphertext/payload bytes, and bans per-session \
                 tunnel addresses from structured tracing fields (a `foo = %bar` field leaks \
                 the value exactly like an inline `{{bar}}` interpolation would)."
            );
        }
    }
}

#[test]
fn supervisor_logs_at_least_the_required_reconnect_banners() {
    // The supervisor must emit structured banners at the three milestones a user
    // (or a monitoring tool) needs to confirm the auto-reconnect flow, otherwise
    // the "transparent reconnect" UX claim silently regresses.
    let body = read_module("supervisor.rs");
    for banner in [
        "multi-hop session initially established",
        "multi-hop session lost, scheduling reconnect",
        "multi-hop session re-established",
    ] {
        assert!(
            body.contains(banner),
            "src/supervisor.rs no longer emits the `{banner}` banner. \
             If you renamed the message, update this test with the new exact wording."
        );
    }
}

#[test]
fn multihop_module_logs_at_least_the_required_session_banner() {
    let body = read_module("multihop.rs");
    assert!(
        body.contains("multi-hop session established"),
        "src/multihop.rs no longer emits the `multi-hop session established` banner. \
         If you renamed the message, update this test with the new exact wording."
    );
}
