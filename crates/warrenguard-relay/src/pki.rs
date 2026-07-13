//! Mini-PKI verification for the relay's exit pool.
//!
//! The exit descriptor type and signing primitives live in
//! `warrenguard-multihop` so they can also be consumed for client-side
//! verification. This module preserves the relay-facing API shape by
//! re-exporting the shared types under the historical names.
//!
//! The relay is version-agnostic about which PKI context signed a
//! descriptor: it re-exports the `/v1`, `/v2`, and post-quantum verifiers so
//! [`crate::config::RelayConfig::validate`] can cascade across all three
//! (the `verify_descriptor_any_version` helper in `crate::config`).

pub use warrenguard_multihop::{
    ExitDescriptorSigned, ExitPkiError as PkiError, exit_descriptor_signing_payload,
    verify_exit_descriptor, verify_exit_descriptor_pq, verify_exit_descriptor_v2,
};
