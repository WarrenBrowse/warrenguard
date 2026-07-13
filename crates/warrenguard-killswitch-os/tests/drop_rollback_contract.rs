//! Secondary source-level pin on the killswitch teardown contract.
//!
//! The contract itself is tested BEHAVIORALLY through the
//! `CommandRunner` / `PfOps` seams (see the `mod tests` of
//! `src/lib.rs` and `src/macos.rs`: exact `nft delete table inet
//! warrenguard_killswitch_os` invocation on drop, partial-install rollback,
//! no double teardown after an explicit uninstall). The greps below
//! only pin the *presence* of the Drop impls so a refactor that
//! deletes them outright fails fast with a pointed message; they
//! cannot detect an emptied Drop body - the behavioral tests do.
//!
//! Truthful failure semantics (do NOT re-document this as "rollback
//! on panic"): the workspace release profile sets `panic = "abort"`,
//! so NO destructor runs on a real panic in release builds. The rules
//! then stay installed and the host keeps blocking off-tunnel traffic
//! until manual cleanup or reboot - fail-closed, which is safer than
//! failing open. `Drop` covers the non-panic abnormal paths (early
//! `?` return, task abort, scope exit without `uninstall().await`)
//! plus debug-build unwinds.

fn read_lib() -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("read warren-killswitch src/lib.rs")
}

fn code_only(body: &str) -> String {
    body.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn killswitch_guard_implements_drop_for_rollback() {
    let src = code_only(&read_lib());
    assert!(
        src.contains("impl Drop"),
        "warren-killswitch/src/lib.rs MUST `impl Drop` on the guard \
         type so an abnormal (non-panic) exit best-effort removes the \
         firewall rules. The behavioral coverage lives in the lib.rs \
         mod tests (drop_invokes_the_exact_nft_teardown_command); this \
         grep is only a fast pointer for whoever deletes the impl."
    );
}

#[test]
fn killswitch_lib_documents_the_panic_abort_fail_closed_semantics() {
    let src = read_lib();
    // The crate doc must keep telling the truth about release builds:
    // panic = "abort" means no Drop runs on a panic and the rules stay
    // installed (fail-closed). A future edit re-claiming "rollback on
    // panic" would re-introduce the doc lie this pin removes.
    assert!(
        src.contains("panic = \"abort\""),
        "warren-killswitch crate doc must document that release builds \
         (panic = \"abort\") run NO Drop on panic and the firewall \
         stays installed fail-closed. Do not re-document the Drop as a \
         panic-path rollback."
    );
}
