//! QUIC stateless retry on the
//! exit's accept loop. A UDP source-spoofed flood (DDoS amplification
//! vector) hammers `Endpoint::accept().await` without any handshake
//! ever completing; without the retry token, every spoofed initial
//! spawns a tokio task that lives until the handshake timeout. Quinn
//! exposes `Incoming::remote_address_validated()` and
//! `Incoming::retry()` to issue a retry packet that forces the
//! caller to prove return-path reachability before accepting.
//!
//! Source-level test: verify the exit accept path consults
//! `remote_address_validated()` / `may_retry()` / calls `retry()`
//! before continuing to the full handshake.

fn read_exit() -> String {
    // Post-refactor: `src/exit.rs` was split into `src/exit/*.rs`.
    // Concatenate all module files so the source-level invariants below remain
    // detectable regardless of which submodule holds the call site.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/exit");
    let mut buf = String::new();
    for name in ["mod.rs", "accept.rs", "session.rs"] {
        let path = dir.join(name);
        let chunk = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        buf.push_str(&chunk);
        buf.push('\n');
    }
    buf
}

fn code_only(body: &str) -> String {
    body.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn handshake_only_consults_remote_address_validated() {
    let src = code_only(&read_exit());
    assert!(
        src.contains("remote_address_validated"),
        "warrenguard-server/src/exit/*.rs must call \
         `Incoming::remote_address_validated()` before completing \
         the handshake. Without it, UDP source-spoofed initial \
         packets each spawn an accept-task that lives until timeout."
    );
}

#[test]
fn handshake_only_issues_retry_on_unvalidated_remote() {
    let src = code_only(&read_exit());
    assert!(
        src.contains(".retry()"),
        "warrenguard-server/src/exit/*.rs must call `Incoming::retry()` when \
         the remote address has not been validated, to force the \
         peer to prove return-path reachability before resources are \
         spent on the handshake."
    );
}

#[test]
fn both_tun_and_non_tun_paths_share_the_stateless_retry_guard() {
    // BOTH accept paths must enforce the
    // stateless retry guard so a UDP source-spoofed flood is rejected
    // regardless of which mode the exit binary boots in (`--use-tun`
    // or handshake-only).
    //
    // A consolidation refactor turned `handle_one` (non-TUN) into
    // a thin wrapper over `handshake_only` (TUN). The invariant is
    // now expressed via source-level relationship rather than by
    // duplicated call sites: `handle_one` MUST delegate to
    // `handshake_only`, which holds the single
    // `remote_address_validated()` call. If a future change inlines
    // the body of `handle_one` again (re-duplicating the handshake),
    // this assertion fires.
    let src = code_only(&read_exit());
    assert!(
        src.contains("self.handshake_only()"),
        "warrenguard-server/src/exit/*.rs no longer shows a call to \
         `self.handshake_only()` from another method. Either the \
         refactor that factored `handle_one` over `handshake_only` \
         was reverted (re-introducing duplicated stateless retry / \
         allowlist code), or the function was renamed. The non-TUN \
         accept path must share the same \
         handshake helper as the TUN path."
    );
    assert!(
        src.contains("remote_address_validated"),
        "warrenguard-server/src/exit/*.rs lost its `remote_address_validated` \
         call site, meaning neither accept path enforces the QUIC \
         stateless retry guard."
    );
}

#[test]
fn accept_loops_cap_handshake_with_explicit_timeout() {
    // Both production accept loops
    // (`accept_forever` and `accept_forever_with_tun`) must wrap each
    // handshake in `tokio::time::timeout` keyed on
    // `WARREN_HANDSHAKE_TIMEOUT_SECS`. Without it a slow-loris client
    // that completes QUIC but never sends the Setup frame holds the
    // tokio task alive until Quinn's idle timeout (multiple minutes).
    let src = code_only(&read_exit());
    let timeout_calls = src.matches("WARREN_HANDSHAKE_TIMEOUT_SECS").count();
    assert!(
        timeout_calls >= 2,
        "warrenguard-server/src/exit/*.rs references \
         `WARREN_HANDSHAKE_TIMEOUT_SECS` only {timeout_calls} time(s). \
         Both `accept_forever` AND `accept_forever_with_tun` must wrap \
         their per-iteration handshake in a tokio::time::timeout keyed \
         on this constant."
    );
}
