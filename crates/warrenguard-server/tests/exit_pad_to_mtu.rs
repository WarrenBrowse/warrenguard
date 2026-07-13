//! A Stealth-exit deployment can pad its downlink QUIC packets to the path MTU
//! via `ExitBindOpts::pad_to_mtu` (the exit-side counterpart of the client's
//! `ClientTunnel::with_pad_to_mtu`). This checks the opt-in default
//! and that the padded transport config is accepted and the exit binds.

use std::net::Ipv4Addr;

use warrenguard_server::{ExitBindOpts, ExitListener};

#[test]
fn pad_to_mtu_defaults_off() {
    assert!(
        !ExitBindOpts::default().pad_to_mtu,
        "exit downlink padding must be opt-in (it costs bandwidth for every client)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exit_binds_with_downlink_padding_enabled() {
    let opts = ExitBindOpts {
        pad_to_mtu: true,
        ..Default::default()
    };
    let exit = ExitListener::bind_with_opts((Ipv4Addr::LOCALHOST, 0).into(), opts)
        .await
        .expect("exit binds with downlink MTU padding enabled");
    assert!(
        exit.bound_addr().ip_addrs().next().is_some(),
        "the padded exit is bound to a socket"
    );
}
