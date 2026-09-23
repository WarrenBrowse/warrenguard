//! No-log privacy invariants on the exit-side IP-negotiation path
//! (`src/multihop.rs`), the counterpart of
//! `warrenguard-transport/tests/log_privacy.rs` for the release side.
//!
//! The exit is the component that *allocates* the per-session tunnel
//! addresses, so its IP-negotiation events are the most tempting place to
//! print them. They must not: the v4 pool is /24-scale, but the address is
//! still handed to exactly one session and therefore correlates log lines
//! across the exit exactly like the v6 one. `prefix_len`, `dual_stack`
//! (family presence only) and the event messages carry the operational
//! signal.
//!
//! This test reads the module as text; the integration-test working
//! directory is the crate root, hence the relative `src/multihop.rs`. It
//! complements - it does not replace - the wire-level e2e tests: a leak is
//! caught here before the binary ships.
//!
//! The file is scanned **read-only**: no test in this crate edits
//! `src/multihop.rs`.

/// Module under audit, relative to the crate root (integration-test cwd).
const MULTIHOP_SRC: &str = "src/multihop.rs";

/// The banner that must survive every redaction: a `setup` reply that did
/// assign an address has to remain observable, otherwise ops cannot tell an
/// exit that negotiated from one that never answered.
const IP_ASSIGN_BANNER: &str = "ip-nego: IpAssign sent over setup stream";

/// Same literal list as `warrenguard-transport/tests/log_privacy.rs`: user
/// identifiers (client IP/port, full pubkeys, ExitId Debug form, HPKE
/// encapsulated key) and bind/relay endpoints never appear in an event.
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

/// Ciphertext / inner-payload bytes never appear in an event.
const FORBIDDEN_PAYLOAD_SUBSTRINGS: &[&str] = &[
    "{bytes",
    "{datagram",
    "{payload",
    "{ciphertext",
    "{aead_tag",
];

/// Structured tracing FIELDS naming a per-session tunnel address.
///
/// The bare `name = ` form is deliberately NOT used here, unlike in the
/// transport test: in this 9k-line file it is indistinguishable from an
/// ordinary Rust assignment, and both of these are legitimate:
/// `let assigned = match pubkey { .. }` and
/// `let spec_gateway = guard.gateway();`.
///
/// Checking the two interpolation sigils instead loses nothing: an
/// `Ipv4Addr`/`Ipv6Addr` does not implement `tracing::Value`, so a log field
/// carrying one must be written `%value` (Display) or `?value` (Debug).
const FORBIDDEN_STRUCTURED_FIELDS: &[&str] = &[
    "assigned = %",
    "assigned = ?",
    "assigned_v4 = %",
    "assigned_v4 = ?",
    "assigned_v6 = %",
    "assigned_v6 = ?",
    "gateway = %",
    "gateway = ?",
    "gateway_v4 = %",
    "gateway_v4 = ?",
    "gateway_v6 = %",
    "gateway_v6 = ?",
    "old = %",
    "old = ?",
    "bootstrap = %",
    "bootstrap = ?",
    "local_addr = %",
    "local_addr = ?",
    "src_addr = %",
    "src_addr = ?",
    "tunnel_ip = %",
    "tunnel_ip = ?",
    "internal_ip = %",
    "internal_ip = ?",
];

/// The only non-logging line of this file that carries a forbidden
/// substring: the Port-Fail guard *collects* peer source addresses with
/// `.filter_map(|c| c.remote_address())`. It is not an event, so it is
/// exempt - and `the_only_exempted_line_is_the_port_fail_guard` pins that
/// exemption to a single line so it cannot rot into a blanket escape hatch.
const NON_LOGGING_EXEMPT_LINE: &str = ".filter_map(|c| c.remote_address())";

/// Read the audited module. Panics (test failure) if it cannot be read,
/// with the path in the message: a silently skipped scan is worse than a
/// red test.
fn read_multihop() -> String {
    std::fs::read_to_string(MULTIHOP_SRC).unwrap_or_else(|e| panic!("read {MULTIHOP_SRC}: {e}"))
}

/// Is this line one of the documented non-logging exemptions?
fn is_exempt(line: &str) -> bool {
    line.contains(NON_LOGGING_EXEMPT_LINE)
}

/// 1-based number of the first line that carries `needle` and is not
/// exempted, or `None` when the substring is absent (or only exempt).
fn violating_line(body: &str, needle: &str) -> Option<usize> {
    body.lines()
        .position(|line| line.contains(needle) && !is_exempt(line))
        .map(|i| i + 1)
}

#[test]
fn multihop_server_does_not_leak_tunnel_addresses_or_user_identifiers() {
    let body = read_multihop();
    for substr in FORBIDDEN_LITERAL_SUBSTRINGS
        .iter()
        .chain(FORBIDDEN_PAYLOAD_SUBSTRINGS)
        .chain(FORBIDDEN_STRUCTURED_FIELDS)
    {
        assert!(
            violating_line(&body, substr).is_none(),
            "{MULTIHOP_SRC}:{} contains forbidden log-leakage substring {substr:?}. \
             The no-log rule bans logging client IPs, full pubkeys, ExitId Debug forms, \
             HPKE encapsulated keys, ciphertext/payload bytes, and per-session tunnel \
             addresses (inline or as a structured tracing field): an assigned address is \
             a correlation handle across log lines, never an event field.",
            violating_line(&body, substr).unwrap_or(0)
        );
    }
}

#[test]
fn multihop_server_keeps_the_ip_assign_banner() {
    let body = read_multihop();
    assert!(
        body.contains(IP_ASSIGN_BANNER),
        "{MULTIHOP_SRC} no longer emits the `{IP_ASSIGN_BANNER}` banner. Redacting an \
         address must not silence the event itself: rename it deliberately and update \
         this test, or restore the banner."
    );
}

#[test]
fn the_only_exempted_line_is_the_port_fail_guard() {
    let body = read_multihop();
    let exempt: Vec<&str> = body.lines().filter(|line| is_exempt(line)).collect();
    assert_eq!(
        exempt.len(),
        1,
        "{MULTIHOP_SRC}: the non-logging exemption {NON_LOGGING_EXEMPT_LINE:?} must match \
         exactly one line (the Port-Fail peer-address collection); it now matches {}: {exempt:?}",
        exempt.len()
    );
}
