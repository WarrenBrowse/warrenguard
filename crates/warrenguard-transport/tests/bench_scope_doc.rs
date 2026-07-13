//! Regression guard: the `bench` module docstring must keep the "echo
//! loopback only" scope explicit and point readers at a deployer's own
//! multi-hop TUN client binary for TUN-mode benches, so a future reader
//! does not waste a server provisioning + tcpdump round diagnosing the
//! design-mismatch "stuck in-flight" symptom. Moved into this crate
//! when the bench session driver was promoted into the engine.

use std::fs;
use std::path::PathBuf;

#[test]
fn bench_module_declares_echo_only_scope() {
    let src = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bench.rs"))
        .expect("read src/bench.rs");
    assert!(
        src.contains("Exit mode requirement (echo loopback only)"),
        "bench.rs module docstring must declare the echo-only scope"
    );
    assert!(
        src.contains("multi-hop TUN client binary"),
        "bench.rs module docstring must point readers to a deployer's own \
         multi-hop TUN client binary for TUN-mode benches"
    );
}
