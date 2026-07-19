//! `TunnelError` variants whose `context` is populated from a string literal
//! must not allocate on every error path. An earlier `context: String` forced
//! `"literal".to_owned()` at every call site; the fix uses `Cow<'static, str>`
//! so literals stay zero-alloc while the few `format!("conn[{idx}]")` sites
//! still work via the `Owned` variant.
//!
//! Source-level test: verify the hot-path variants use `Cow` (or `&'static
//! str`) and that `String` is no longer present on these fields. `TunnelError`
//! lives in this crate's `src/error.rs` since the engine carve.

fn read_error_rs() -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/error.rs"))
        .expect("read warrenguard-transport-core src/error.rs")
}

fn code_only(body: &str) -> String {
    body.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn error_context_fields_avoid_string_for_zero_alloc_hot_path() {
    let src = code_only(&read_error_rs());

    // The four hot-path variants must use Cow<'static, str> (or
    // &'static str) instead of String for their `context` field.
    // We assert via the *negative* pattern: under each variant's
    // declaration, the context field MUST NOT type as `String`.
    //
    // We look for the substring `context: String,` and require it
    // to NOT appear in code (only QuicEndpoint and Protocol carry
    // their full message inline, not in a `context` field, so they
    // are unaffected).
    let forbidden = ["context", ": ", "String,"].concat();
    assert!(
        !src.contains(&forbidden),
        "TunnelError still has a `{forbidden}` field. The 4 hot-path variants \
         require Cow<'static, str> \
         (QuicStream, QuicSendDatagram, QuicReadDatagram, Tun) \
         so a string-literal call site does not allocate `String` per \
         error event."
    );
}

#[test]
fn error_context_uses_cow_static_str_or_static_str() {
    let src = code_only(&read_error_rs());
    let cow = src.contains("Cow<'static, str>");
    let static_str = src.contains("&'static str");
    assert!(
        cow || static_str,
        "TunnelError must use Cow<'static, str> or &'static str on the 5 \
         migrated context fields."
    );
}
