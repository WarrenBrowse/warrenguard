//! Anti-drift guard: every tuning knob declared in the central
//! `warrenguard_config::knobs::REGISTRY` must be documented in
//! `docs/35-ENV-KNOBS.md`. A new knob added to the registry without a
//! doc row fails this test, preventing the "0/N knobs documented" state
//! the registry was introduced to fix.

use warrenguard_config::knobs::REGISTRY;

/// Resolves `docs/35-ENV-KNOBS.md` from the workspace root. The crate
/// lives at `engine/warrenguard-config`, so the doc is two levels up.
fn doc_contents() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest)
        .join("..")
        .join("..")
        .join("docs")
        .join("35-ENV-KNOBS.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn every_registry_knob_is_documented() {
    let doc = doc_contents();
    for meta in REGISTRY {
        assert!(
            doc.contains(meta.name),
            "knob {} is in REGISTRY but absent from docs/35-ENV-KNOBS.md \
             (add a row to the tuning-knobs table)",
            meta.name
        );
    }
}

#[test]
fn doc_lists_no_unknown_registry_only_marker() {
    // Sanity: the registry is non-empty and the doc mentions the module.
    assert!(!REGISTRY.is_empty(), "REGISTRY must not be empty");
    let doc = doc_contents();
    assert!(
        doc.contains("knobs.rs"),
        "doc should point back to the registry module"
    );
}
