//! Ordering invariant for the Linux dual-stack reassign path.
//!
//! Audit finding: [`run_reassign_loop`] used to apply the exit-allocated IPv6 to
//! the TUN and only THEN install the `::/1` + `8000::/1` split route. Two
//! problems followed. The address was reachable over the host's physical IPv6
//! default route for the whole window between the two steps, and a FAILED route
//! install left the address bound with nothing to capture it - the log line
//! said so itself ("v6 stays on the physical default route") - so v6 kept
//! egressing off tunnel for as long as the session lasted, unless an
//! independent IPv6 killswitch happened to be armed already.
//!
//! The repaired path is `cfg(target_os = "linux")` and installs routes by
//! shelling out to `ip`, which needs `CAP_NET_ADMIN`. It therefore cannot be
//! EXECUTED on the macOS development host, and CI running it on Linux would
//! still not pin the order: swapping the two steps back leaves every behavioral
//! test green because none of them can observe a root-only route install. This
//! source-level guard is the regression net. It is deliberately narrow: it
//! asserts the sequence inside `run_reassign_loop`, nothing about the rest of
//! the file.
//!
//! [`run_reassign_loop`]: ../src/supervised_pump/fn.run_reassign_loop.html

/// The module that owns the reassign loop, read from the crate root (a test
/// binary's working directory is the crate root).
fn supervised_pump_source() -> String {
    std::fs::read_to_string("src/supervised_pump.rs").expect("read src/supervised_pump.rs")
}

#[test]
fn the_v6_split_route_is_installed_before_the_exit_allocated_address() {
    let body = supervised_pump_source();
    let install = body.find("DefaultRouteSplitV6Guard::install").expect(
        "the reassign loop no longer installs the Linux v6 split route. If that moved \
             elsewhere, move this invariant with it: an exit-allocated v6 address applied \
             without ::/1 + 8000::/1 in place egresses over the physical default route.",
    );
    let gate = body.find("if route_ready {").expect(
        "the v6 address application is no longer gated on `route_ready`. Without that gate a \
         failed split-route install falls through to applying the address, which is the leak \
         this ordering exists to prevent.",
    );
    let apply = body
        .find("reassign_ipv6(v6, spec.prefix_len_v6)")
        .expect("the reassign loop no longer applies the exit-allocated v6");

    assert!(
        install < gate,
        "the v6 split route must be installed BEFORE the address application is even \
         considered (install at byte {install}, gate at {gate})"
    );
    assert!(
        gate < apply,
        "the address application must sit INSIDE the `route_ready` gate (gate at byte \
         {gate}, apply at {apply}); applying it first reintroduces the off-tunnel window and \
         the address-without-route failure mode"
    );
}

#[test]
fn a_failed_v6_split_route_install_refuses_the_address() {
    let body = supervised_pump_source();
    let decision = body
        .find("let route_ready = if cfg.install_v6_split_route")
        .expect("the route-readiness decision disappeared from the reassign loop");
    let gate = body
        .find("if route_ready {")
        .expect("the `route_ready` gate disappeared");
    let decision_site = &body[decision..gate];

    assert!(
        decision_site.contains("false"),
        "the failure arm of the route-readiness decision no longer yields `false`, so a \
         failed install would not refuse the address: {decision_site}"
    );
    assert!(
        decision_site.contains("refusing the exit-allocated"),
        "the refusal must stay explicit in the log line, so an operator can tell a refused \
         v6 session from a silent fallback to native v6: {decision_site}"
    );
}
