//! Pin `#[inline]` annotations on identified hot helpers so a future
//! refactor that drops them is caught by CI.
//!
//! `#[inline]` is an attribute, not behaviour: no runtime assertion can observe
//! it, so these are deliberately source-level guards. They match on
//! whitespace-stripped source so reformatting cannot silently defeat them.
//!
//! Conservative scope: only the two helpers profiled as truly hot
//! (one call per multi-hop frame, in both directions, in the steady
//! state):
//!
//! - `compose_aad` - outbound + inbound, twice per packet at the exit.
//! - `ReplayWindow::check_and_record` - once per inbound multi-hop
//!   frame on the exit side.
//!
//! Other helpers (`ExitId::as_bytes`, `parse_exit_x25519_pubkey`) are
//! either `const fn` (auto-inlined) or cold (per-setup), so we leave
//! them to LLVM + LTO.

/// Strips every whitespace character so an attribute and the item it decorates
/// match regardless of indentation or line breaks.
fn without_whitespace(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
fn compose_aad_is_inlined() {
    let src = without_whitespace(include_str!("../src/session.rs"));
    assert!(
        src.contains("#[inline]pubfncompose_aad("),
        "compose_aad must carry #[inline] (called twice per multi-hop \
         packet, hot path)"
    );
}

#[test]
fn replay_window_check_and_record_is_inlined() {
    let src = without_whitespace(include_str!("../src/replay.rs"));
    assert!(
        src.contains("#[inline]pubfncheck_and_record("),
        "ReplayWindow::check_and_record must carry #[inline] (one call \
         per inbound multi-hop frame at the exit)"
    );
}

/// Negative guard: don't go #[inline(always)] crazy on non-hot
/// helpers. `#[inline(always)]` overrides LLVM cost analysis and can
/// pessimize binary size with no measured win.
#[test]
fn no_inline_always_in_session() {
    let src = without_whitespace(include_str!("../src/session.rs"));
    assert!(
        !src.contains("#[inline(always)]"),
        "#[inline(always)] is reserved for profiled hot spots; \
         session.rs has none today, keep it that way until profiling \
         data justifies an addition"
    );
}
