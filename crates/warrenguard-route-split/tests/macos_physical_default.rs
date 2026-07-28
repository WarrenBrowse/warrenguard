//! Crate-boundary coverage of the tunnel-resistant macOS physical-default
//! discovery. A consumer re-resolves it AFTER the split capture has made
//! `route get default` point at the tunnel, so the property that matters is
//! observable only from outside the crate: the answer is never a tunnel.

#![cfg(target_os = "macos")]

use warrenguard_route_split::default_route_split_macos::{
    discover_physical_default, discover_physical_ifindex, is_tunnel_iface,
};

#[tokio::test]
async fn physical_default_is_never_a_tunnel_interface() {
    let Ok((iface, gateway)) = discover_physical_default().await else {
        // Offline, or only tunnels are up: the function fails closed by
        // contract, and there is no physical route to observe.
        eprintln!("skipped: no physical default route on this host");
        return;
    };
    assert!(
        !iface.is_empty(),
        "an empty interface name would silently bind nothing"
    );
    assert!(
        !is_tunnel_iface(&iface),
        "resolved {iface:?}: pinning the carrier to a tunnel loops it onto itself"
    );
    if let Some(gw) = &gateway {
        assert!(
            gw.parse::<std::net::IpAddr>().is_ok(),
            "the gateway must be a usable address, got {gw:?}"
        );
    }
    // The same resolution feeds `IP_BOUND_IF`, so the name must have a live
    // kernel index: a host with a physical default route that cannot produce
    // one would leave the carrier unbindable.
    let idx = discover_physical_ifindex()
        .await
        .expect("a physical default route must yield an interface index");
    assert_ne!(
        idx, 0,
        "0 is the unspecified index and would defeat IP_BOUND_IF"
    );
}
