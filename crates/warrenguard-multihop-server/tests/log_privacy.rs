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

/// Per-session timing fields: a session's lifetime with the event timestamp is
/// a connection log (when a subscriber connected and for how long). Ops may
/// keep it at `debug`, never at `info` and above, which production retains.
const FORBIDDEN_SESSION_TIMING_FIELDS: &[&str] = &[
    "conn_secs",
    "duration_secs",
    "session_secs",
    "conn_start.elapsed()",
];

/// The `tracing` macros whose events a production exit retains (its filter
/// is `info`).
const RETAINED_LEVEL_MACROS: &[&str] = &["info!(", "warn!(", "error!("];

/// The bodies of every `info!`/`warn!`/`error!` invocation, with the 1-based
/// line where each starts. A body runs from the macro line to the first line
/// that closes it with `);`, which is how rustfmt lays out a multi-line event.
fn retained_events(body: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = body.lines().collect();
    let mut events = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if RETAINED_LEVEL_MACROS.iter().any(|m| lines[i].contains(m)) {
            let start = i;
            let mut text = String::new();
            while i < lines.len() {
                text.push_str(lines[i]);
                text.push('\n');
                if lines[i].trim_end().ends_with(");") {
                    break;
                }
                i += 1;
            }
            events.push((start + 1, text));
        }
        i += 1;
    }
    events
}

#[test]
fn multihop_server_keeps_session_timing_out_of_retained_levels() {
    let body = read_multihop();
    for (line, event) in retained_events(&body) {
        for field in FORBIDDEN_SESSION_TIMING_FIELDS {
            assert!(
                !event.contains(field),
                "{MULTIHOP_SRC}:{line} logs {field:?} at info or above. A per-session \
                 duration next to the event timestamp records when a subscriber was \
                 connected and for how long; production keeps info, so log it at debug."
            );
        }
    }
}

/// The exit's per-connection path probe writes below `info`: the client
/// variant, which logs at `info` for a client's own problem reports, would put
/// one activity timeline per subscriber session in the exit log.
#[test]
fn the_exit_spawns_only_the_server_path_probe() {
    for path in ["src/multihop.rs", "src/datapath.rs"] {
        let src = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            !src.contains("spawn_path_probe("),
            "{path} spawns the client path probe; an exit must use spawn_server_path_probe"
        );
    }
    let multihop = std::fs::read_to_string(MULTIHOP_SRC).expect("read src/multihop.rs");
    assert!(
        multihop.contains("spawn_server_path_probe("),
        "the exit still samples its legs, at debug"
    );
}

/// The macro that writes the event whose message is `msg` in `src`.
fn macro_of(src: &str, msg: &str) -> Option<String> {
    let at = src.find(msg)?;
    let head = &src[..at];
    let start = head.rfind("tracing::")?;
    let rest = &head[start + "tracing::".len()..];
    Some(
        rest.chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect(),
    )
}

/// One event per session setup, refusal or route change gives the exit log a
/// connect timeline at second resolution, and a refusal line names a fact
/// about one subscriber (banned, device limit, token in use). The node-level
/// admission counters carry the same facts without a timeline, so these
/// events stay at `debug`. A setup with no tunnel address is a node fault and
/// stays a warning.
#[test]
fn per_session_setup_events_stay_below_info() {
    let src = std::fs::read_to_string(MULTIHOP_SRC).expect("read src/multihop.rs");
    for msg in [
        "multihop: route setup refused; sealed detail + opaque close",
        "its serial holds a live session it does",
        "multihop: v7 setup rejected - token invalid/denied; sealed detail + opaque close",
        "multihop: setup rejected - account banned (CRL); sealed detail + opaque close",
        "multihop: setup rejected - client not authorized; sealed detail + opaque close",
        "multihop: setup rejected - pubkey revoked during setup (TOCTOU recheck)",
        "multihop: wallet session refused by the session gate; sealed detail + opaque close",
        IP_ASSIGN_BANNER,
        "multihop: bonded downlink route registered",
        "multihop: sticky-IP takeover, existing downlink owner(s) present; stale re-check armed",
        "multihop: evicted dead downlink predecessor(s) after sticky-IP takeover",
    ] {
        assert_eq!(
            macro_of(&src, msg).as_deref(),
            Some("debug"),
            "`{msg}` is a per-session event: it must be written at debug"
        );
    }
    assert_eq!(
        macro_of(&src, "ip-nego: no tunnel address at setup").as_deref(),
        Some("warn"),
        "a setup with no address is a node fault, not a session event"
    );
}

/// The black-hole warning names the failure, not the session's volume.
#[test]
fn the_blackhole_warning_carries_no_session_volume() {
    let src = std::fs::read_to_string("src/datapath.rs").expect("read src/datapath.rs");
    let end = src
        .find("this session black-holed")
        .expect("the black-hole warning exists");
    let start = src[..end]
        .rfind("tracing::warn!(")
        .expect("it is a warning");
    let event = &src[start..end];
    for field in ["datagrams =", "opened =", "to_tun ="] {
        assert!(
            !event.contains(field),
            "the black-hole warning carries `{field}`, a per-session volume at warn"
        );
    }
}
