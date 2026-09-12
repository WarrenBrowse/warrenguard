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
fn every_documented_knob_carries_the_registry_default_and_clamp() {
    // Checking the NAME alone lets a value drift silently, which is the failure
    // this file exists to prevent one level down: `WARREN_DG_BDP_FLOOR` kept
    // advertising a 1 MiB default to operators for as long as a name check was
    // all that stood between the registry and the doc. An operator reads the
    // doc and tunes from it, so the doc's numbers are what must match.
    let doc = doc_contents();
    let mut drifted = Vec::new();
    for meta in REGISTRY {
        let Some(row) = doc
            .lines()
            .find(|line| line.contains(&format!("`{}`", meta.name)) && line.starts_with('|'))
        else {
            continue; // absence is the other test's verdict, not this one's
        };
        for (field, value) in [("default", meta.default), ("clamp", meta.clamp)] {
            if !row.contains(value) {
                drifted.push(format!(
                    "{}: doc row lacks the registry {field} {value:?}",
                    meta.name
                ));
            }
        }
    }
    assert!(
        drifted.is_empty(),
        "the doc and the registry disagree; the registry is the source of truth \
         (warrenguard-config/src/knobs.rs), so fix the doc rows:\n  {}",
        drifted.join("\n  ")
    );
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
