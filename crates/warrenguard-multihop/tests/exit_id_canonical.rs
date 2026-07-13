//! `warrenguard_multihop::ExitId` must be the exact same Rust type as
//! `warrenguard_wire::ExitId`, not a
//! distinct duplicate that happens to share the wire shape. With two
//! independent types, a function that takes one cannot accept the
//! other at the call site, silently forcing callers to maintain
//! parallel codepaths. Worse, a refactor that drifts one and not the
//! other re-introduces protocol mismatch with no compiler help.
//!
//! This test compiles only when `warrenguard_multihop::ExitId` resolves to
//! the same Rust `TypeId` as `warrenguard_wire::ExitId`. The body
//! exercises a value-level identity (assignment without `into()`),
//! which is the strictest possible Rust-level proof of canonicality.

use std::any::TypeId;

#[test]
fn warrenguard_multihop_exit_id_is_warrenguard_wire_exit_id() {
    assert_eq!(
        TypeId::of::<warrenguard_multihop::ExitId>(),
        TypeId::of::<warrenguard_wire::ExitId>(),
        "warrenguard_multihop::ExitId MUST be a `pub use` of warrenguard_wire::ExitId. \
         A duplicated definition is a latent protocol drift hazard."
    );
}

#[test]
fn warrenguard_multihop_exit_id_value_assigns_to_warrenguard_wire_exit_id() {
    let from_protocol = warrenguard_wire::ExitId::from_bytes([0xab; 16]);
    // If the two are the same type, this is a plain move, not an
    // `into()`. The compiler refuses if they are distinct types.
    let as_multihop: warrenguard_multihop::ExitId = from_protocol;
    assert_eq!(as_multihop.as_bytes(), &[0xab; 16]);
}
